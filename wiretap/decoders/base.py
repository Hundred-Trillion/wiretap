"""Base decoder protocol and types.

All decoders — built-in and third-party — implement the Decoder protocol.
This ensures a consistent interface for the decoder registry to invoke.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from wiretap.core.enums import DecoderStatus


@dataclass
class DecodeResult:
    """Result returned by a decoder attempt.

    Attributes:
        status: Whether decoding succeeded, partially succeeded, or failed.
        data: The decoded representation (dict, str, list, bytes, etc.).
        confidence: Confidence that the decoding is correct (0.0 to 1.0).
        encoding: The encoding/format name (e.g., 'utf-8', 'json', 'gzip').
        error: Error message if decoding failed.
        metadata: Additional decoder-specific metadata.
    """

    status: DecoderStatus = DecoderStatus.SKIPPED
    data: Any = None
    confidence: float = 0.0
    encoding: str = ""
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Decoder(Protocol):
    """Protocol that all decoders must implement.

    Decoders are attempted in priority order (lower number = higher priority).
    Each decoder first checks if it can handle the data via `can_decode`,
    then attempts actual decoding via `decode`.

    Attributes:
        name: Unique decoder identifier.
        priority: Execution priority (lower = earlier). Range: 0-1000.
    """

    name: str
    priority: int

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        """Check if this decoder can handle the given data.

        Args:
            data: Raw bytes to inspect.
            content_type: Optional MIME type hint from headers.

        Returns:
            Confidence score from 0.0 (cannot decode) to 1.0 (certain).
            Return 0.0 to skip this decoder entirely.
        """
        ...

    def decode(self, data: bytes) -> DecodeResult:
        """Attempt to decode the raw bytes.

        This method should never raise exceptions. All errors must be
        caught internally and returned as a DecodeResult with FAILED status.

        Args:
            data: Raw bytes to decode.

        Returns:
            A DecodeResult with the decoded data or error information.
        """
        ...
