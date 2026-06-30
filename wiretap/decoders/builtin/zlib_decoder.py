"""Zlib decompression decoder."""

from __future__ import annotations

import zlib

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult


class ZlibDecoder:
    """Decompresses zlib/deflate-encoded payloads."""

    name: str = "zlib"
    priority: int = 11

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and "deflate" in content_type:
            return 0.9
        # Zlib header: first byte is usually 0x78
        if len(data) >= 2 and data[0] == 0x78:
            return 0.7
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        try:
            decompressed = zlib.decompress(data)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=decompressed,
                confidence=0.9,
                encoding="zlib",
                metadata={"original_size": len(data), "decompressed_size": len(decompressed)},
            )
        except zlib.error as e:
            # Try raw deflate (no zlib header)
            try:
                decompressed = zlib.decompress(data, -15)
                return DecodeResult(
                    status=DecoderStatus.SUCCESS,
                    data=decompressed,
                    confidence=0.7,
                    encoding="deflate-raw",
                    metadata={"original_size": len(data), "decompressed_size": len(decompressed)},
                )
            except zlib.error:
                return DecodeResult(
                    status=DecoderStatus.FAILED,
                    encoding="zlib",
                    error=str(e),
                )
