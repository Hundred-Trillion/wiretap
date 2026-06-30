"""JSON decoder using orjson for speed."""

from __future__ import annotations

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult

try:
    import orjson

    def _loads(data: bytes) -> object:
        return orjson.loads(data)
except ImportError:
    import json

    def _loads(data: bytes) -> object:
        return json.loads(data)


class JSONDecoder:
    """Decodes payloads as JSON."""

    name: str = "json"
    priority: int = 50  # High priority — JSON is very common

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and "json" in content_type:
            return 0.95
        # Quick heuristic: starts with { or [
        stripped = data.lstrip()
        if stripped and stripped[0:1] in (b"{", b"["):
            return 0.7
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        try:
            parsed = _loads(data)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=parsed,
                confidence=0.95,
                encoding="json",
            )
        except Exception as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="json",
                error=str(e),
            )
