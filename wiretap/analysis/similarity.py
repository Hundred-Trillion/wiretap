"""Similarity and candidate price detection engine.

Identifies relationship types between payloads in a family (identical, incremental, snapshot/delta)
and scans binary payload offsets for candidate numbers that behave like asset prices.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import UUID

from wiretap.analysis.classification import BinaryPacketFamily


@dataclass
class PriceCandidate:
    """A candidate price field identified in a binary family."""

    offset: int
    size: int
    endianness: str  # "LE" | "BE"
    value_type: str  # "float32" | "float64" | "scaled_int32" | "scaled_int64"
    scale_factor: float  # e.g., 100000.0 for scaled ints, 1.0 for floats
    confidence: float  # 0.0 to 1.0 based on criteria
    description: str
    score_breakdown: dict[str, int] = field(default_factory=dict)
    sample_values: list[float] = field(default_factory=list)
    json_path: Optional[str] = None



class SimilarityEngine:
    """Analyzes payload relationships within a packet family."""

    @staticmethod
    def analyze_similarity(family: BinaryPacketFamily) -> dict[str, Any]:
        """Classify family payload relationships: identical, incremental, snapshot/delta.

        Returns:
            Dictionary containing relationship classification and supporting metrics.
        """
        fingerprints = family.fingerprints
        if not fingerprints:
            return {"relationship": "unknown", "details": "No packets"}

        total_count = len(fingerprints)
        if total_count == 1:
            return {"relationship": "single_occurrence", "details": "Only one packet observed"}

        # 1. Check for Identical payloads
        unique_hashes = {fp.sha256 for fp in fingerprints}
        if len(unique_hashes) == 1:
            return {
                "relationship": "identical",
                "details": "All payloads are 100% identical duplicates.",
            }

        # 2. Check for Snapshot vs Delta
        lengths = [fp.length for fp in fingerprints]
        min_len = min(lengths)
        max_len = max(lengths)
        avg_len = sum(lengths) / total_count

        # If there are a few very large packets and many smaller packets
        large_packets = [l for l in lengths if l > avg_len * 2]
        if large_packets and len(large_packets) <= max(1, total_count * 0.2):
            return {
                "relationship": "snapshot_delta",
                "details": (
                    f"Snapshot/Delta pattern. A few large packets (max {max_len}B) "
                    f"followed by smaller updates (min {min_len}B)."
                ),
            }

        # 3. Check for Incremental
        # If lengths are identical and payloads differ only by 1-4 bytes (like counter/timestamp)
        if min_len == max_len:
            differing_bytes = set()
            first_payload = fingerprints[0].payload_raw
            for fp in fingerprints[1:]:
                for idx in range(min_len):
                    if fp.payload_raw[idx] != first_payload[idx]:
                        differing_bytes.add(idx)

            if len(differing_bytes) > 0 and len(differing_bytes) <= 8:
                return {
                    "relationship": "incremental",
                    "details": (
                        f"Incremental evolution. Payloads are identical except at "
                        f"offsets: {sorted(list(differing_bytes))}."
                    ),
                }

        return {
            "relationship": "dynamic",
            "details": "Dynamic payload variations. Multiple fields changing across packets.",
        }


class PriceCandidateDetector:
    """Scans binary offsets for fields containing values matching asset price behaviors."""

    def __init__(
        self,
        min_price: float = 0.001,
        max_price: float = 250000.0,
        max_tick_variance: float = 0.05,  # Prices typically change by < 5% per tick
    ) -> None:
        self.min_price = min_price
        self.max_price = max_price
        self.max_tick_variance = max_tick_variance

    def detect_prices(self, family: BinaryPacketFamily) -> list[PriceCandidate]:
        """Scan a binary family's payloads to identify candidate price fields."""
        fingerprints = family.fingerprints
        if len(fingerprints) < 3:
            return []

        # Find min length of payloads in this family to ensure we don't read out of bounds
        min_len = min(fp.length for fp in fingerprints)
        candidates: list[PriceCandidate] = []

        # 1. Scan float64 candidates (8 bytes)
        for offset in range(min_len - 7):
            for endian, fmt in [("BE", ">d"), ("LE", "<d")]:
                vals: list[float] = []
                try:
                    for fp in fingerprints:
                        buf = fp.payload_raw[offset : offset + 8]
                        vals.append(struct.unpack(fmt, buf)[0])
                except Exception:
                    continue

                if self._validate_price_sequence(vals):
                    breakdown = self._score_price_sequence_breakdown(vals)
                    confidence = float(sum(breakdown.values())) / 100.0
                    candidates.append(
                        PriceCandidate(
                            offset=offset,
                            size=8,
                            endianness=endian,
                            value_type="float64",
                            scale_factor=1.0,
                            sample_values=list(vals[:5]),
                            confidence=confidence,
                            score_breakdown=breakdown,
                            description=f"Double-precision float price ticker (confidence {confidence:.2f})",
                        )
                    )

        # 2. Scan float32 candidates (4 bytes)
        for offset in range(min_len - 3):
            for endian, fmt in [("BE", ">f"), ("LE", "<f")]:
                vals = []
                try:
                    for fp in fingerprints:
                        buf = fp.payload_raw[offset : offset + 4]
                        vals.append(struct.unpack(fmt, buf)[0])
                except Exception:
                    continue

                if self._validate_price_sequence(vals):
                    breakdown = self._score_price_sequence_breakdown(vals)
                    confidence = float(sum(breakdown.values())) / 100.0
                    candidates.append(
                        PriceCandidate(
                            offset=offset,
                            size=4,
                            endianness=endian,
                            value_type="float32",
                            scale_factor=1.0,
                            sample_values=list(vals[:5]),
                            confidence=confidence,
                            score_breakdown=breakdown,
                            description=f"Single-precision float price ticker (confidence {confidence:.2f})",
                        )
                    )

        # 3. Scan Scaled Integers (scaled by 100, 1000, 10000, 100000, 1000000, 100000000)
        # Scan int32 (4 bytes)
        scales = [100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 100000000.0]
        for offset in range(min_len - 3):
            for endian, fmt in [("BE", ">i"), ("LE", "<i"), ("BE", ">I"), ("LE", "<I")]:
                raw_vals = []
                try:
                    for fp in fingerprints:
                        buf = fp.payload_raw[offset : offset + 4]
                        raw_vals.append(struct.unpack(fmt, buf)[0])
                except Exception:
                    continue

                # Check each scale factor
                for scale in scales:
                    vals = [float(v) / scale for v in raw_vals]
                    if self._validate_price_sequence(vals):
                        breakdown = self._score_price_sequence_breakdown(vals)
                        # Slightly lower confidence for scaled integers compared to native floats
                        confidence = (float(sum(breakdown.values())) / 100.0) * 0.9
                        type_name = "int32" if "i" in fmt else "uint32"
                        candidates.append(
                            PriceCandidate(
                                offset=offset,
                                size=4,
                                endianness=endian,
                                value_type=f"scaled_{type_name}",
                                scale_factor=scale,
                                sample_values=list(vals[:5]),
                                confidence=confidence,
                                score_breakdown=breakdown,
                                description=f"Scaled {type_name} price ticker (scale 1/{int(scale)}, confidence {confidence:.2f})",
                            )
                        )
                        break  # Match only one scale per offset

        # 4. Scan JSON-encoded candidates (if payloads look like JSON or start with EIO control characters)
        json_paths_checked = False
        for fp in fingerprints[:3]:
            data = fp.payload_raw
            start_idx = -1
            for i, b in enumerate(data[:10]):  # only check first few bytes for JSON marker
                if b in (ord('{'), ord('[')):
                    start_idx = i
                    break
            if start_idx != -1:
                try:
                    import json
                    obj = json.loads(data[start_idx:].decode('utf-8', errors='ignore'))
                    if not json_paths_checked:
                        json_paths_checked = True
                        paths = list(self._traverse_json(obj))
                        for path, _ in paths:
                            vals = []
                            for fp_inner in fingerprints:
                                data_inner = fp_inner.payload_raw
                                start_idx_inner = -1
                                for i, b in enumerate(data_inner[:10]):
                                    if b in (ord('{'), ord('[')):
                                        start_idx_inner = i
                                        break
                                if start_idx_inner != -1:
                                    try:
                                        obj_inner = json.loads(data_inner[start_idx_inner:].decode('utf-8', errors='ignore'))
                                        val = self._resolve_json_path(obj_inner, path)
                                        if val is not None:
                                            vals.append(val)
                                    except Exception:
                                        pass
                            
                            # Validate sequence of values extracted from the JSON path
                            if len(vals) >= max(3, int(len(fingerprints) * 0.5)) and self._validate_price_sequence(vals):
                                breakdown = self._score_price_sequence_breakdown(vals)
                                confidence = float(sum(breakdown.values())) / 100.0
                                candidates.append(
                                    PriceCandidate(
                                        offset=0,
                                        size=0,
                                        endianness="JSON",
                                        value_type="json_numeric",
                                        scale_factor=1.0,
                                        sample_values=list(vals[:5]),
                                        confidence=confidence,
                                        score_breakdown=breakdown,
                                        description=f"JSON path '{path}' price ticker (confidence {confidence:.2f})",
                                        json_path=path
                                    )
                                )
                except Exception:
                    pass

        # Sort candidates by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def _traverse_json(self, val: Any, path: str = "") -> list[tuple[str, float]]:
        paths = []
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            paths.append((path, float(val)))
        elif isinstance(val, dict):
            for k, v in val.items():
                new_path = f"{path}.{k}" if path else k
                paths.extend(self._traverse_json(v, new_path))
        elif isinstance(val, list):
            for idx, v in enumerate(val):
                new_path = f"{path}[{idx}]"
                paths.extend(self._traverse_json(v, new_path))
        return paths

    def _resolve_json_path(self, obj: Any, path: str) -> float | None:
        import re
        tokens = re.findall(r'([^\[\.]+)|\[(\d+)\]', path)
        curr = obj
        for key, idx in tokens:
            if idx:
                try:
                    curr = curr[int(idx)]
                except (IndexError, TypeError, KeyError):
                    return None
            else:
                try:
                    curr = curr[key]
                except (TypeError, KeyError):
                    return None
        if isinstance(curr, (int, float)) and not isinstance(curr, bool):
            return float(curr)
        return None


    def _validate_price_sequence(self, vals: list[float]) -> bool:
        """Verify if a sequence of values behaves like asset price updates."""
        # Must not contain NaN or Inf
        for v in vals:
            if math.isnan(v) or math.isinf(v):
                return False

        # Must fit price bounds
        if not all(self.min_price <= v <= self.max_price for v in vals):
            return False

        # Price must change (not constant)
        if len(set(vals)) <= 1:
            return False

        # Consecutive variations should be bounded (not wild random values)
        tick_variances = []
        for i in range(1, len(vals)):
            prev = vals[i - 1]
            if prev == 0.0:
                return False
            variance = abs(vals[i] - prev) / prev
            tick_variances.append(variance)

        # Average variance must be small (prices usually update incrementally)
        avg_variance = sum(tick_variances) / len(tick_variances)
        if avg_variance > self.max_tick_variance:
            return False

        return True

    def _score_price_sequence_breakdown(self, vals: list[float]) -> dict[str, int]:
        """Compute point breakdown for a price candidate sequence (max 100 points)."""
        breakdown = {
            "dynamic_variance": 0,
            "bounds_monotonicity": 0,
            "representation_scale": 0,
            "precision_alignment": 0,
        }

        # 1. Dynamic variance (up to 30 points)
        unique_ratio = len(set(vals)) / len(vals)
        tick_variances = [abs(vals[i] - vals[i - 1]) / vals[i - 1] for i in range(1, len(vals))]
        non_zero_ticks = sum(1 for v in tick_variances if v > 0.0)
        tick_ratio = non_zero_ticks / len(tick_variances) if tick_variances else 0.0
        
        dynamic_score = int(unique_ratio * 15 + tick_ratio * 15)
        breakdown["dynamic_variance"] = min(30, max(5, dynamic_score))

        # 2. Bounds and monotonicity (up to 30 points)
        avg_variance = sum(tick_variances) / len(tick_variances) if tick_variances else 0.0
        if avg_variance < 0.01:
            breakdown["bounds_monotonicity"] = 30
        elif avg_variance < 0.05:
            breakdown["bounds_monotonicity"] = 20
        else:
            breakdown["bounds_monotonicity"] = 10

        # 3. Representation & Scale (up to 20 points)
        are_integers = all(v.is_integer() for v in vals)
        if not are_integers:
            breakdown["representation_scale"] = 20
        else:
            breakdown["representation_scale"] = 15

        # 4. Precision alignment (up to 20 points)
        breakdown["precision_alignment"] = 20 if not are_integers else 10

        return breakdown
