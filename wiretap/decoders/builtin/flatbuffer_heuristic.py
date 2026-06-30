"""FlatBuffer heuristic decoder.

Detects FlatBuffer-encoded data by checking for valid root table
offset patterns. FlatBuffers have a 4-byte root table offset at
the start of the buffer.
"""

from __future__ import annotations

import struct

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult


class FlatBufferHeuristicDecoder:
    """Heuristically detects FlatBuffer wire format."""

    name: str = "flatbuffer_heuristic"
    priority: int = 310

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and "flatbuffer" in content_type.lower():
            return 0.9
        if len(data) < 8:
            return 0.0
        return self._estimate_confidence(data)

    def decode(self, data: bytes) -> DecodeResult:
        try:
            info = self._analyze_structure(data)
            if info:
                return DecodeResult(
                    status=DecoderStatus.PARTIAL,
                    data=info,
                    confidence=0.5,
                    encoding="flatbuffer",
                    metadata={"note": "Heuristic — schema required for full decode"},
                )
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="flatbuffer",
                error="Data does not match FlatBuffer structure",
            )
        except Exception as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="flatbuffer",
                error=str(e),
            )

    def _estimate_confidence(self, data: bytes) -> float:
        """Estimate probability that data is a FlatBuffer."""
        try:
            # FlatBuffers start with a 4-byte offset to the root table
            root_offset = struct.unpack_from("<I", data, 0)[0]
            if root_offset >= len(data) or root_offset < 4:
                return 0.0
            # The root table starts with a negative offset to its vtable
            vtable_offset = struct.unpack_from("<i", data, root_offset)[0]
            vtable_pos = root_offset - vtable_offset
            if vtable_pos < 0 or vtable_pos >= len(data) - 2:
                return 0.0
            # VTable starts with its size (uint16)
            vtable_size = struct.unpack_from("<H", data, vtable_pos)[0]
            if vtable_size < 4 or vtable_pos + vtable_size > len(data):
                return 0.0
            return 0.35
        except (struct.error, IndexError):
            return 0.0

    def _analyze_structure(self, data: bytes) -> dict | None:
        """Analyze FlatBuffer structure heuristically."""
        try:
            root_offset = struct.unpack_from("<I", data, 0)[0]
            if root_offset >= len(data):
                return None
            vtable_offset = struct.unpack_from("<i", data, root_offset)[0]
            vtable_pos = root_offset - vtable_offset
            if vtable_pos < 0 or vtable_pos >= len(data) - 4:
                return None
            vtable_size = struct.unpack_from("<H", data, vtable_pos)[0]
            table_size = struct.unpack_from("<H", data, vtable_pos + 2)[0]
            num_fields = (vtable_size - 4) // 2

            return {
                "root_offset": root_offset,
                "vtable_position": vtable_pos,
                "vtable_size": vtable_size,
                "table_size": table_size,
                "estimated_fields": num_fields,
                "buffer_size": len(data),
            }
        except (struct.error, IndexError):
            return None
