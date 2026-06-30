"""Wiretap — Professional browser protocol analysis framework.

Wiretap observes how modern web applications communicate over HTTP,
WebSockets, Server-Sent Events (SSE), and related browser networking APIs.
It helps developers understand application protocols by observing their
own browser sessions with forensic accuracy.
"""

__version__ = "0.1.0"
__author__ = "Wiretap Contributors"

from wiretap.core.enums import DecoderStatus, Direction, EventType, ProtocolType

__all__ = [
    "__version__",
    "DecoderStatus",
    "Direction",
    "EventType",
    "ProtocolType",
]
