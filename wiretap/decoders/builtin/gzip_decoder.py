"""Gzip decompression decoder."""

from __future__ import annotations

import gzip

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult


class GzipDecoder:
    """Decompresses gzip-encoded payloads."""

    name: str = "gzip"
    priority: int = 10  # Compression decoders run first

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and "gzip" in content_type:
            return 0.95
        # Gzip magic bytes: 1f 8b
        if len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B:
            return 0.95
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        try:
            decompressed = gzip.decompress(data)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=decompressed,
                confidence=0.95,
                encoding="gzip",
                metadata={"original_size": len(data), "decompressed_size": len(decompressed)},
            )
        except Exception as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="gzip",
                error=str(e),
            )
