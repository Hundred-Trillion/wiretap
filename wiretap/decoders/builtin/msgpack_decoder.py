"""MessagePack decoder."""

from __future__ import annotations

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult

try:
    import msgpack
    _MSGPACK_AVAILABLE = True
except ImportError:
    _MSGPACK_AVAILABLE = False


class MsgpackDecoder:
    """Decodes MessagePack-encoded payloads."""

    name: str = "msgpack"
    priority: int = 200

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if not _MSGPACK_AVAILABLE:
            return 0.0
        if content_type and "msgpack" in content_type:
            return 0.9
        # Heuristic: msgpack has specific type markers
        if len(data) >= 1:
            first = data[0]
            # Common msgpack type markers for maps and arrays
            if first in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85,  # fixmap
                         0x90, 0x91, 0x92, 0x93, 0x94, 0x95,  # fixarray
                         0xDC, 0xDD, 0xDE, 0xDF):              # map/array 16/32
                return 0.3
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        if not _MSGPACK_AVAILABLE:
            return DecodeResult(
                status=DecoderStatus.SKIPPED,
                encoding="msgpack",
                error="msgpack package not installed",
            )
        try:
            parsed = msgpack.unpackb(data, raw=False)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=parsed,
                confidence=0.8,
                encoding="msgpack",
            )
        except Exception as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="msgpack",
                error=str(e),
            )
