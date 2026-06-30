"""UTF-8 text decoder."""

from __future__ import annotations

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult


class UTF8Decoder:
    """Decodes payloads as UTF-8 text."""

    name: str = "utf8"
    priority: int = 100

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and "text" in content_type:
            return 0.8
        # Heuristic: check if bytes are valid UTF-8
        try:
            data.decode("utf-8")
            return 0.5
        except (UnicodeDecodeError, ValueError):
            return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        try:
            text = data.decode("utf-8")
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=text,
                confidence=0.7,
                encoding="utf-8",
            )
        except (UnicodeDecodeError, ValueError) as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="utf-8",
                error=str(e),
            )
