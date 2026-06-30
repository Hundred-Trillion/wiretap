"""Domain models for the Wiretap framework.

These are pure domain dataclasses with no ORM or framework dependencies.
They represent the core data structures used throughout the capture,
analysis, and reporting pipeline. ORM mappings are defined separately
in the storage layer.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from wiretap.core.enums import DecoderStatus, Direction, EventType, ProtocolType


def _utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def _new_id() -> UUID:
    """Generate a new UUID4 identifier."""
    return uuid4()


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


@dataclass
class CaptureSession:
    """A complete capture session representing a browser observation period.

    A session begins when the user starts Wiretap, navigates to a target URL,
    and ends when capture is stopped. All connections, frames, and annotations
    are associated with exactly one session.

    Attributes:
        id: Unique session identifier.
        name: Human-readable session label.
        target_url: The URL navigated to at session start.
        started_at: UTC timestamp of session start.
        ended_at: UTC timestamp of session end, None if still active.
        metadata: Arbitrary key-value metadata (browser version, profile, etc.).
    """

    id: UUID = field(default_factory=_new_id)
    name: str = ""
    target_url: str = ""
    started_at: datetime = field(default_factory=_utc_now)
    ended_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


@dataclass
class TimingInfo:
    """Network timing breakdown for a connection or request.

    All durations are in milliseconds. A value of -1.0 indicates the
    timing phase was not applicable.

    Attributes:
        dns_start: DNS lookup start relative to request start.
        dns_end: DNS lookup end relative to request start.
        connect_start: TCP connection start.
        connect_end: TCP connection end.
        ssl_start: TLS handshake start (-1.0 if not HTTPS).
        ssl_end: TLS handshake end (-1.0 if not HTTPS).
        send_start: Request send start.
        send_end: Request send end.
        receive_start: First byte received.
        receive_end: Last byte received.
    """

    dns_start: float = -1.0
    dns_end: float = -1.0
    connect_start: float = -1.0
    connect_end: float = -1.0
    ssl_start: float = -1.0
    ssl_end: float = -1.0
    send_start: float = -1.0
    send_end: float = -1.0
    receive_start: float = -1.0
    receive_end: float = -1.0


@dataclass
class Connection:
    """A single network connection observed during a capture session.

    Represents an HTTP request/response, a WebSocket connection, an SSE
    stream, or any other browser networking connection.

    Attributes:
        id: Unique connection identifier.
        session_id: Parent session identifier.
        request_id: CDP-assigned request identifier for correlation.
        url: The target URL of this connection.
        protocol: The protocol type (HTTP, WEBSOCKET, SSE, etc.).
        method: HTTP method (GET, POST, etc.) or None for non-HTTP.
        status_code: HTTP status code or None.
        request_headers: Request headers as key-value pairs.
        response_headers: Response headers as key-value pairs.
        initiator: What initiated this request (script URL, parser, etc.).
        timing: Network timing information.
        started_at: UTC timestamp when the connection was initiated.
        ended_at: UTC timestamp when the connection was closed.
        metadata: Additional CDP-provided metadata.
    """

    id: UUID = field(default_factory=_new_id)
    session_id: UUID = field(default_factory=_new_id)
    request_id: str = ""
    url: str = ""
    protocol: ProtocolType = ProtocolType.HTTP
    method: str | None = None
    status_code: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    initiator: str = ""
    timing: TimingInfo = field(default_factory=TimingInfo)
    started_at: datetime = field(default_factory=_utc_now)
    ended_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


@dataclass
class Payload:
    """Raw payload bytes with integrity metadata.

    Every captured payload is stored exactly as received. The SHA256 hash
    enables deduplication and integrity verification. Binary payloads
    include hex dump and base64 representations for inspection.

    Attributes:
        id: Unique payload identifier.
        raw_bytes: The exact bytes captured, never modified.
        sha256: SHA-256 hex digest of raw_bytes.
        size: Size in bytes.
        content_type: MIME type if known from headers.
        encoding_detected: Encoding detected by decoders (e.g., 'utf-8').
        base64: Base64 representation of raw_bytes.
        hex_dump: Hex dump string for inspection.
    """

    id: UUID = field(default_factory=_new_id)
    raw_bytes: bytes = b""
    sha256: str = ""
    size: int = 0
    content_type: str | None = None
    encoding_detected: str | None = None
    base64: str = ""
    hex_dump: str = ""

    def __post_init__(self) -> None:
        """Compute derived fields from raw_bytes if not already set."""
        if self.raw_bytes and not self.sha256:
            self.sha256 = hashlib.sha256(self.raw_bytes).hexdigest()
        if self.raw_bytes and self.size == 0:
            self.size = len(self.raw_bytes)


# ---------------------------------------------------------------------------
# Frame
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    """A single protocol frame within a connection.

    For HTTP connections, there are typically two frames per connection
    (request and response). For WebSockets, there is one frame per
    sent or received message. For SSE, each event is a frame.

    Attributes:
        id: Unique frame identifier.
        connection_id: Parent connection identifier.
        direction: Whether this frame was SENT or RECEIVED.
        timestamp: UTC timestamp of frame capture.
        payload_id: Associated payload identifier.
        sequence: Sequence number within the connection (0-indexed).
        opcode: WebSocket opcode or None for non-WS frames.
        is_binary: True if the payload is binary (not text).
        metadata: Additional frame-level metadata.
    """

    id: UUID = field(default_factory=_new_id)
    connection_id: UUID = field(default_factory=_new_id)
    direction: Direction = Direction.RECEIVED
    timestamp: datetime = field(default_factory=_utc_now)
    payload_id: UUID | None = None
    sequence: int = 0
    opcode: int | None = None
    is_binary: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Decoder Result
# ---------------------------------------------------------------------------


@dataclass
class DecoderResult:
    """Result of applying a decoder to a payload.

    Stores the decoded output along with metadata about the decoding
    process. Multiple decoder results can exist for the same payload
    when multiple decoders succeed.

    Attributes:
        id: Unique result identifier.
        payload_id: The payload that was decoded.
        decoder_name: Name of the decoder that produced this result.
        status: Whether decoding succeeded, partially succeeded, or failed.
        decoded_data: The decoded representation (dict, str, list, etc.).
        confidence: Confidence score from 0.0 to 1.0.
        error: Error message if decoding failed.
        metadata: Additional decoder-specific metadata.
    """

    id: UUID = field(default_factory=_new_id)
    payload_id: UUID = field(default_factory=_new_id)
    decoder_name: str = ""
    status: DecoderStatus = DecoderStatus.SKIPPED
    decoded_data: Any = None
    confidence: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Annotation
# ---------------------------------------------------------------------------


@dataclass
class Annotation:
    """A user-provided annotation correlated with protocol activity.

    Users can add annotations during live capture (e.g., 'Clicked Login',
    'Opened Dashboard'). The framework correlates each annotation with
    nearby protocol activity by timestamp proximity.

    Attributes:
        id: Unique annotation identifier.
        session_id: Parent session identifier.
        timestamp: UTC timestamp when the annotation was created.
        text: User-provided annotation text.
        correlated_frame_ids: Frame IDs near this annotation's timestamp.
    """

    id: UUID = field(default_factory=_new_id)
    session_id: UUID = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utc_now)
    text: str = ""
    correlated_frame_ids: list[UUID] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Protocol Event
# ---------------------------------------------------------------------------


@dataclass
class ProtocolEvent:
    """A discovered protocol event with evidence.

    Represents a pattern identified through automated protocol analysis.
    Every event includes a confidence score and references to the frames
    that support the conclusion.

    Attributes:
        id: Unique event identifier.
        session_id: Session in which this event was discovered.
        event_type: Classification of the protocol event.
        confidence: Confidence score from 0.0 to 1.0.
        evidence: List of human-readable observations supporting this event.
        frame_refs: Frame IDs that evidence this event.
        description: Human-readable description of the discovered event.
        metadata: Additional analysis metadata.
    """

    id: UUID = field(default_factory=_new_id)
    session_id: UUID = field(default_factory=_new_id)
    event_type: EventType = EventType.UNKNOWN
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    frame_refs: list[UUID] = field(default_factory=list)
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
