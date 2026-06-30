"""Brotli decompression decoder."""

from __future__ import annotations

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult

try:
    import brotli
    _BROTLI_AVAILABLE = True
except ImportError:
    _BROTLI_AVAILABLE = False


class BrotliDecoder:
    """Decompresses brotli-encoded payloads."""

    name: str = "brotli"
    priority: int = 12

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if not _BROTLI_AVAILABLE:
            return 0.0
        if content_type and "br" in content_type:
            return 0.95
        # Brotli has no reliable magic bytes — rely on content-type
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        if not _BROTLI_AVAILABLE:
            return DecodeResult(
                status=DecoderStatus.SKIPPED,
                encoding="brotli",
                error="brotli package not installed",
            )
        try:
            decompressed = brotli.decompress(data)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=decompressed,
                confidence=0.9,
                encoding="brotli",
                metadata={"original_size": len(data), "decompressed_size": len(decompressed)},
            )
        except brotli.error as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="brotli",
                error=str(e),
            )
