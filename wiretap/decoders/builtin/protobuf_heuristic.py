"""Protocol Buffer wire format heuristic decoder.

This decoder does NOT require .proto files. It uses wire format
heuristics to detect and partially parse protobuf-encoded data.
"""

from __future__ import annotations

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult


class ProtobufHeuristicDecoder:
    """Heuristically detects Protocol Buffer wire format."""

    name: str = "protobuf_heuristic"
    priority: int = 300

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and ("protobuf" in content_type or "proto" in content_type):
            return 0.9
        if content_type and ("grpc" in content_type):
            return 0.85
        # Heuristic: try to parse wire format
        if len(data) < 2:
            return 0.0
        return self._estimate_protobuf_confidence(data)

    def decode(self, data: bytes) -> DecodeResult:
        try:
            fields = self._parse_wire_format(data)
            if fields:
                return DecodeResult(
                    status=DecoderStatus.PARTIAL,
                    data={"fields": fields},
                    confidence=0.6,
                    encoding="protobuf",
                    metadata={"note": "Heuristic parse — field names unknown without .proto"},
                )
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="protobuf",
                error="No valid protobuf fields found",
            )
        except Exception as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="protobuf",
                error=str(e),
            )

    def _estimate_protobuf_confidence(self, data: bytes) -> float:
        """Estimate probability that data is protobuf-encoded."""
        try:
            fields = self._parse_wire_format(data)
            if not fields:
                return 0.0
            # Valid field numbers are 1-536870911; wire types are 0-5
            valid = all(
                1 <= f["field_number"] <= 1000 and f["wire_type"] in (0, 1, 2, 5)
                for f in fields
            )
            if valid and len(fields) >= 1:
                return 0.4
            return 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _parse_wire_format(data: bytes) -> list[dict]:
        """Parse protobuf wire format into field descriptors."""
        fields = []
        pos = 0
        while pos < len(data):
            if pos >= len(data):
                break
            # Read varint tag
            tag, pos = _read_varint(data, pos)
            if tag is None:
                break
            wire_type = tag & 0x07
            field_number = tag >> 3

            if field_number <= 0 or field_number > 10000:
                break

            field_info: dict = {
                "field_number": field_number,
                "wire_type": wire_type,
            }

            if wire_type == 0:  # Varint
                value, pos = _read_varint(data, pos)
                if value is None:
                    break
                field_info["value"] = value
            elif wire_type == 1:  # 64-bit
                if pos + 8 > len(data):
                    break
                field_info["value"] = data[pos:pos + 8].hex()
                pos += 8
            elif wire_type == 2:  # Length-delimited
                length, pos = _read_varint(data, pos)
                if length is None or pos + length > len(data):
                    break
                field_info["value"] = data[pos:pos + length].hex()
                field_info["length"] = length
                pos += length
            elif wire_type == 5:  # 32-bit
                if pos + 4 > len(data):
                    break
                field_info["value"] = data[pos:pos + 4].hex()
                pos += 4
            else:
                break  # Unknown wire type

            fields.append(field_info)

        return fields


def _read_varint(data: bytes, pos: int) -> tuple[int | None, int]:
    """Read a protobuf varint from data at position pos."""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
        if shift > 63:
            return None, pos
    return None, pos
