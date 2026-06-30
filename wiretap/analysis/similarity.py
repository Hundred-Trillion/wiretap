"""Similarity and candidate price detection engine.

Identifies relationship types between payloads in a family (identical, incremental, snapshot/delta)
and scans binary payload offsets for candidate numbers that behave like asset prices.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Any
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
    sample_values: list[float] = field(default_factory=list)


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
                    confidence = self._score_price_sequence(vals)
                    candidates.append(
                        PriceCandidate(
                            offset=offset,
                            size=8,
                            endianness=endian,
                            value_type="float64",
                            scale_factor=1.0,
                            sample_values=list(vals[:5]),
                            confidence=confidence,
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
                    confidence = self._score_price_sequence(vals)
                    candidates.append(
                        PriceCandidate(
                            offset=offset,
                            size=4,
                            endianness=endian,
                            value_type="float32",
                            scale_factor=1.0,
                            sample_values=list(vals[:5]),
                            confidence=confidence,
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
                        confidence = self._score_price_sequence(vals) * 0.9  # slightly lower confidence for scaled ints
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
                                description=f"Scaled {type_name} price ticker (scale 1/{int(scale)}, confidence {confidence:.2f})",
                            )
                        )
                        break  # Match only one scale per offset

        # Sort candidates by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

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

    def _score_price_sequence(self, vals: list[float]) -> float:
        """Assign confidence score to a price candidate sequence based on properties."""
        # 1. Dynamic check: how many unique values exist (more is better/dynamic)
        unique_ratio = len(set(vals)) / len(vals)

        # 2. Increment check: check if the sequence fluctuates like an asset ticker
        # (mostly consecutive changes, but stays in a bounded variance)
        tick_variances = [abs(vals[i] - vals[i - 1]) / vals[i - 1] for i in range(1, len(vals))]
        non_zero_ticks = sum(1 for v in tick_variances if v > 0.0)
        tick_ratio = non_zero_ticks / len(tick_variances) if tick_variances else 0.0

        # 3. Precision score: typical price feeds have multiple decimal digits.
        # Check if values are mostly integers. If all are perfect integers, it's less likely to be a price (unless crypto / high value).
        are_integers = all(v.is_integer() for v in vals)
        precision_bonus = 0.6 if are_integers else 1.0

        score = (unique_ratio * 0.4 + tick_ratio * 0.6) * precision_bonus
        return min(0.99, max(0.1, score))
