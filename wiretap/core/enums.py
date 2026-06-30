"""Enumeration types used across the Wiretap framework.

These enums provide type-safe, self-documenting constants for protocol
classification, message direction, event categorization, and decoder
status tracking.
"""

from __future__ import annotations

from enum import Enum, auto, unique


@unique
class Direction(Enum):
    """Direction of a network frame relative to the browser.

    SENT indicates data flowing from the browser to the server.
    RECEIVED indicates data flowing from the server to the browser.
    """

    SENT = auto()
    RECEIVED = auto()

    def __str__(self) -> str:
        return self.name


@unique
class ProtocolType(Enum):
    """Classification of the network protocol used by a connection.

    Each value maps to a distinct browser networking API or transport
    mechanism captured via the Chrome DevTools Protocol.
    """

    HTTP = auto()
    WEBSOCKET = auto()
    SSE = auto()
    FETCH = auto()
    XHR = auto()
    WEBTRANSPORT = auto()

    def __str__(self) -> str:
        return self.name


@unique
class EventType(Enum):
    """Classification of discovered protocol events.

    These categories represent patterns identified through automated
    protocol analysis. Every classification carries a confidence
    score and supporting evidence.
    """

    AUTHENTICATION = auto()
    HEARTBEAT = auto()
    SESSION_INIT = auto()
    KEEP_ALIVE = auto()
    REQUEST_RESPONSE = auto()
    STREAMING = auto()
    BINARY_FAMILY = auto()
    UNKNOWN = auto()

    def __str__(self) -> str:
        return self.name


@unique
class DecoderStatus(Enum):
    """Result status of a decoder attempt on a payload.

    SUCCESS: Decoder fully decoded the payload.
    PARTIAL: Decoder decoded some content but not all.
    FAILED: Decoder attempted but could not decode the payload.
    SKIPPED: Decoder determined it cannot handle this payload type.
    """

    SUCCESS = auto()
    PARTIAL = auto()
    FAILED = auto()
    SKIPPED = auto()

    def __str__(self) -> str:
        return self.name
