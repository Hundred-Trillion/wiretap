"""CBOR decoder."""

from __future__ import annotations

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult

try:
    import cbor2
    _CBOR_AVAILABLE = True
except ImportError:
    _CBOR_AVAILABLE = False


class CBORDecoder:
    """Decodes CBOR-encoded payloads."""

    name: str = "cbor"
    priority: int = 210

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if not _CBOR_AVAILABLE:
            return 0.0
        if content_type and "cbor" in content_type:
            return 0.9
        # CBOR major types in the first byte
        if len(data) >= 1:
            major_type = (data[0] & 0xE0) >> 5
            if major_type in (4, 5):  # Array or Map
                return 0.2
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        if not _CBOR_AVAILABLE:
            return DecodeResult(
                status=DecoderStatus.SKIPPED,
                encoding="cbor",
                error="cbor2 package not installed",
            )
        try:
            parsed = cbor2.loads(data)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=parsed,
                confidence=0.8,
                encoding="cbor",
            )
        except Exception as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="cbor",
                error=str(e),
            )
