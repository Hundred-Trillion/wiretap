"""Structural analysis and field boundary detection engine.

Maps byte-level structures within a binary packet family to identify constant fields,
delimiters, counters, timestamps, integers, and float candidates.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from wiretap.analysis.classification import BinaryPacketFamily


@dataclass
class FieldMapEntry:
    """A detected structural field in a packet family."""

    offset: int
    size: int
    stability: str  # "constant" | "counter" | "timestamp" | "float" | "integer" | "variable"
    type_name: str  # e.g., "uint32 (LE)", "float64 (BE)", "constant byte"
    description: str
    sample_values: list[Any] = field(default_factory=list)


class StructuralAnalyzer:
    """Analyzes a family of binary packets to extract structural fields and byte stability."""

    def __init__(self, min_packets_for_analysis: int = 3) -> None:
        self.min_packets_for_analysis = min_packets_for_analysis

    def analyze_family(self, family: BinaryPacketFamily) -> list[FieldMapEntry]:
        """Generate a field map for a family of binary packets."""
        fingerprints = family.fingerprints
        if len(fingerprints) < self.min_packets_for_analysis:
            return []

        # Find maximum length to bound analysis
        max_len = max(fp.length for fp in fingerprints)
        if max_len == 0:
            return []

        # 1. Compute byte-level value sets for each offset to check basic stability
        byte_values_by_offset: dict[int, list[int]] = {i: [] for i in range(max_len)}
        for fp in fingerprints:
            for i in range(fp.length):
                byte_values_by_offset[i].append(fp.payload_raw[i])

        # Basic stability status per byte offset
        byte_stability: list[str] = ["variable"] * max_len
        for i in range(max_len):
            vals = byte_values_by_offset[i]
            if len(vals) == 0:
                continue
            if len(set(vals)) == 1:
                byte_stability[i] = "constant"

        field_map: list[FieldMapEntry] = []
        visited = set()

        # Helper to check if a range of offsets is already fully analyzed
        def is_analyzed(offset: int, size: int) -> bool:
            return any(o in visited for o in range(offset, offset + size))

        # Helper to mark a range as analyzed
        def mark_analyzed(offset: int, size: int) -> None:
            for o in range(offset, offset + size):
                visited.add(o)

        # 2. Match multi-byte fields (check larger sizes first for greediness)
        # Scan 8-byte structures (double floats, timestamps)
        for offset in range(max_len - 7):
            if is_analyzed(offset, 8):
                continue

            # Read 8-byte values across all packets
            vals_be_f64: list[float] = []
            vals_le_f64: list[float] = []
            vals_be_i64: list[int] = []
            vals_le_i64: list[int] = []

            for fp in fingerprints:
                if offset + 8 <= fp.length:
                    buf = fp.payload_raw[offset : offset + 8]
                    vals_be_f64.append(struct.unpack(">d", buf)[0])
                    vals_le_f64.append(struct.unpack("<d", buf)[0])
                    vals_be_i64.append(struct.unpack(">q", buf)[0])
                    vals_le_i64.append(struct.unpack("<q", buf)[0])

            if len(vals_be_i64) < len(fingerprints) * 0.7:
                continue  # Skip if too few packets are long enough

            # Check 8-byte Timestamps (milliseconds/microseconds in 2020-2030)
            # 2020-01-01 is 1577836800. 2031-01-01 is 1924982400.
            # Milliseconds: 1577836800000 to 1924982400000.
            for endian, int_vals in [("BE", vals_be_i64), ("LE", vals_le_i64)]:
                if all(1577836800000 <= val <= 1924982400000 for val in int_vals):
                    dates = [
                        datetime.fromtimestamp(val / 1000.0, tz=timezone.utc).isoformat()
                        for val in int_vals[:5]
                    ]
                    field_map.append(
                        FieldMapEntry(
                            offset=offset,
                            size=8,
                            stability="timestamp",
                            type_name=f"int64 ({endian} ms)",
                            description="Epoch millisecond timestamp",
                            sample_values=dates,
                        )
                    )
                    mark_analyzed(offset, 8)
                    break

            if is_analyzed(offset, 8):
                continue

            # Check 8-byte Floats (double precision)
            # Verify values are valid floating-points and have realistic ranges
            for endian, float_vals in [("BE", vals_be_f64), ("LE", vals_le_f64)]:
                valid_floats = [
                    v
                    for v in float_vals
                    if not math.isnan(v)
                    and not math.isinf(v)
                    and 1e-6 <= abs(v) <= 1e9
                ]
                if len(valid_floats) == len(float_vals) and len(set(float_vals)) > 1:
                    field_map.append(
                        FieldMapEntry(
                            offset=offset,
                            size=8,
                            stability="float",
                            type_name=f"float64 ({endian})",
                            description="Double-precision float candidate",
                            sample_values=list(float_vals[:5]),
                        )
                    )
                    mark_analyzed(offset, 8)
                    break

        # Scan 4-byte structures (floats, timestamps, integers, counters)
        for offset in range(max_len - 3):
            if is_analyzed(offset, 4):
                continue

            vals_be_f32: list[float] = []
            vals_le_f32: list[float] = []
            vals_be_i32: list[int] = []
            vals_le_i32: list[int] = []
            vals_be_u32: list[int] = []
            vals_le_u32: list[int] = []

            for fp in fingerprints:
                if offset + 4 <= fp.length:
                    buf = fp.payload_raw[offset : offset + 4]
                    vals_be_f32.append(struct.unpack(">f", buf)[0])
                    vals_le_f32.append(struct.unpack("<f", buf)[0])
                    vals_be_i32.append(struct.unpack(">i", buf)[0])
                    vals_le_i32.append(struct.unpack("<i", buf)[0])
                    vals_be_u32.append(struct.unpack(">I", buf)[0])
                    vals_le_u32.append(struct.unpack("<I", buf)[0])

            if len(vals_be_i32) < len(fingerprints) * 0.7:
                continue

            # Check 4-byte Timestamps (seconds in 2020-2030: 1577836800 to 1924982400)
            for endian, int_vals in [("BE", vals_be_u32), ("LE", vals_le_u32)]:
                if all(1577836800 <= val <= 1924982400 for val in int_vals):
                    dates = [
                        datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
                        for val in int_vals[:5]
                    ]
                    field_map.append(
                        FieldMapEntry(
                            offset=offset,
                            size=4,
                            stability="timestamp",
                            type_name=f"uint32 ({endian} s)",
                            description="Epoch second timestamp",
                            sample_values=dates,
                        )
                    )
                    mark_analyzed(offset, 4)
                    break

            if is_analyzed(offset, 4):
                continue

            # Check 4-byte Floats
            for endian, float_vals in [("BE", vals_be_f32), ("LE", vals_le_f32)]:
                valid_floats = [
                    v
                    for v in float_vals
                    if not math.isnan(v)
                    and not math.isinf(v)
                    and 1e-5 <= abs(v) <= 1e9
                ]
                # If they are valid floats and dynamic (changing value)
                if len(valid_floats) == len(float_vals) and len(set(float_vals)) > 1:
                    field_map.append(
                        FieldMapEntry(
                            offset=offset,
                            size=4,
                            stability="float",
                            type_name=f"float32 ({endian})",
                            description="Single-precision float candidate",
                            sample_values=list(float_vals[:5]),
                        )
                    )
                    mark_analyzed(offset, 4)
                    break

            if is_analyzed(offset, 4):
                continue

            # Check 4-byte Counters (monotonically increasing)
            for endian, int_vals in [("BE", vals_be_u32), ("LE", vals_le_u32)]:
                is_counter = True
                for idx in range(1, len(int_vals)):
                    if int_vals[idx] < int_vals[idx - 1] or int_vals[idx] > int_vals[idx - 1] + 100:
                        is_counter = False
                        break
                if is_counter and len(set(int_vals)) > 1:
                    field_map.append(
                        FieldMapEntry(
                            offset=offset,
                            size=4,
                            stability="counter",
                            type_name=f"uint32 ({endian})",
                            description="Monotonic counter field",
                            sample_values=list(int_vals[:5]),
                        )
                    )
                    mark_analyzed(offset, 4)
                    break

        # Scan 2-byte structures (uint16 counters, integers)
        for offset in range(max_len - 1):
            if is_analyzed(offset, 2):
                continue

            vals_be_u16: list[int] = []
            vals_le_u16: list[int] = []
            for fp in fingerprints:
                if offset + 2 <= fp.length:
                    buf = fp.payload_raw[offset : offset + 2]
                    vals_be_u16.append(struct.unpack(">H", buf)[0])
                    vals_le_u16.append(struct.unpack("<H", buf)[0])

            if len(vals_be_u16) < len(fingerprints) * 0.7:
                continue

            # Check 2-byte counters
            for endian, int_vals in [("BE", vals_be_u16), ("LE", vals_le_u16)]:
                is_counter = True
                for idx in range(1, len(int_vals)):
                    if int_vals[idx] < int_vals[idx - 1] or int_vals[idx] > int_vals[idx - 1] + 10:
                        is_counter = False
                        break
                if is_counter and len(set(int_vals)) > 1:
                    field_map.append(
                        FieldMapEntry(
                            offset=offset,
                            size=2,
                            stability="counter",
                            type_name=f"uint16 ({endian})",
                            description="16-bit monotonic counter",
                            sample_values=list(int_vals[:5]),
                        )
                    )
                    mark_analyzed(offset, 2)
                    break

        # Fill remaining bytes as 1-byte constants or general variables
        for offset in range(max_len):
            if is_analyzed(offset, 1):
                continue

            vals = byte_values_by_offset[offset]
            if not vals:
                continue

            if len(set(vals)) == 1:
                # Delimiter checks
                val = vals[0]
                desc = "Constant byte field"
                if val == 0x00:
                    desc = "Null delimiter (0x00)"
                elif val == 0x2C:
                    desc = "Comma delimiter (0x2C)"
                elif val == 0x3A:
                    desc = "Colon delimiter (0x3A)"
                elif val == 0x7B:
                    desc = "JSON open brace (0x7B)"

                field_map.append(
                    FieldMapEntry(
                        offset=offset,
                        size=1,
                        stability="constant",
                        type_name="uint8",
                        description=desc,
                        sample_values=[f"0x{val:02x}"],
                    )
                )
            else:
                # Variable 1-byte counter
                is_counter = True
                for idx in range(1, len(vals)):
                    if vals[idx] < vals[idx - 1] or vals[idx] > vals[idx - 1] + 5:
                        is_counter = False
                        break

                stability = "counter" if is_counter else "variable"
                type_name = "uint8"
                desc = "Monotonic byte counter" if is_counter else "Variable payload byte"

                field_map.append(
                    FieldMapEntry(
                        offset=offset,
                        size=1,
                        stability=stability,
                        type_name=type_name,
                        description=desc,
                        sample_values=list(vals[:5]),
                    )
                )

            mark_analyzed(offset, 1)

        # Sort field map by offset
        field_map.sort(key=lambda f: f.offset)
        return field_map
