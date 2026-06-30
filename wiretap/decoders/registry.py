"""Decoder registry — discovers, registers, and invokes decoders.

Decoders are discovered via importlib.metadata entry points under the
'wiretap.decoders' group. Additional decoders can be registered manually.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

import structlog

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult, Decoder

logger = structlog.get_logger(__name__)


class DecoderRegistry:
    """Registry of all available decoders.

    Discovers decoders via entry points and provides a unified
    interface for decoding payloads against all registered decoders.

    Usage:
        registry = DecoderRegistry()
        registry.discover()  # Load from entry points
        results = registry.decode_payload(raw_bytes, content_type="application/json")
    """

    def __init__(self) -> None:
        self._decoders: list[Decoder] = []
        self._log = structlog.get_logger(component="DecoderRegistry")

    def discover(self) -> None:
        """Discover and load decoders from entry points.

        Entry points are registered under the 'wiretap.decoders' group
        in pyproject.toml. Each entry point should resolve to a class
        implementing the Decoder protocol.
        """
        eps = entry_points(group="wiretap.decoders")
        for ep in eps:
            try:
                decoder_cls = ep.load()
                decoder = decoder_cls()
                if isinstance(decoder, Decoder):
                    self.register(decoder)
                    self._log.info(
                        "decoder_loaded",
                        name=ep.name,
                        decoder=decoder.name,
                        priority=decoder.priority,
                    )
                else:
                    self._log.warning(
                        "decoder_invalid_protocol",
                        name=ep.name,
                    )
            except Exception:
                self._log.error(
                    "decoder_load_failed",
                    name=ep.name,
                    exc_info=True,
                )

    def register(self, decoder: Decoder) -> None:
        """Register a decoder manually.

        Args:
            decoder: A decoder instance implementing the Decoder protocol.
        """
        self._decoders.append(decoder)
        # Keep sorted by priority
        self._decoders.sort(key=lambda d: d.priority)

    def unregister(self, name: str) -> None:
        """Remove a decoder by name.

        Args:
            name: The name of the decoder to remove.
        """
        self._decoders = [d for d in self._decoders if d.name != name]

    @property
    def decoders(self) -> list[Decoder]:
        """All registered decoders, sorted by priority."""
        return list(self._decoders)

    def decode_payload(
        self,
        data: bytes,
        content_type: str | None = None,
    ) -> list[DecodeResult]:
        """Attempt to decode a payload with all registered decoders.

        Decoders are tried in priority order. Each decoder that reports
        a non-zero confidence via can_decode() is attempted. Failures
        are logged but never raise exceptions.

        Args:
            data: Raw payload bytes.
            content_type: Optional MIME type hint.

        Returns:
            List of DecodeResults from all decoders that attempted,
            sorted by confidence descending.
        """
        if not data:
            return []

        results: list[DecodeResult] = []

        for decoder in self._decoders:
            try:
                confidence = decoder.can_decode(data, content_type)
                if confidence <= 0.0:
                    continue

                result = decoder.decode(data)
                results.append(result)

            except Exception as e:
                results.append(
                    DecodeResult(
                        status=DecoderStatus.FAILED,
                        encoding=decoder.name,
                        error=f"Unhandled exception: {e}",
                    )
                )
                self._log.error(
                    "decoder_unhandled_exception",
                    decoder=decoder.name,
                    exc_info=True,
                )

        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def best_decode(
        self,
        data: bytes,
        content_type: str | None = None,
    ) -> DecodeResult | None:
        """Return the highest-confidence successful decode result.

        Args:
            data: Raw payload bytes.
            content_type: Optional MIME type hint.

        Returns:
            The best DecodeResult, or None if no decoder succeeded.
        """
        results = self.decode_payload(data, content_type)
        for result in results:
            if result.status in (DecoderStatus.SUCCESS, DecoderStatus.PARTIAL):
                return result
        return None
