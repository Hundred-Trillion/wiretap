"""UTF-16 text decoder."""

from __future__ import annotations

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult


class UTF16Decoder:
    """Decodes payloads as UTF-16 text."""

    name: str = "utf16"
    priority: int = 110

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and "utf-16" in content_type.lower():
            return 0.9
        # Check for BOM
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return 0.8
        # Heuristic: alternating null bytes suggest UTF-16
        if len(data) >= 4 and (data[1] == 0 or data[0] == 0):
            return 0.3
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        try:
            text = data.decode("utf-16")
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=text,
                confidence=0.7,
                encoding="utf-16",
            )
        except (UnicodeDecodeError, ValueError) as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="utf-16",
                error=str(e),
            )
