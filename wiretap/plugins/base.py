"""Base plugin protocol.

All plugins — built-in and third-party — implement the Plugin protocol.
Plugins can recognize protocol patterns, enhance reports, and add
protocol-specific decoders. Plugins must never modify captured data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from wiretap.core.models import Connection, Frame, Payload, ProtocolEvent


@dataclass
class PluginInfo:
    """Metadata about a plugin."""

    name: str = ""
    version: str = ""
    description: str = ""
    author: str = ""
    target_domains: list[str] = field(default_factory=list)


@runtime_checkable
class Plugin(Protocol):
    """Protocol that all plugins must implement.

    Plugins extend Wiretap's analysis capabilities for specific
    protocols or applications. They operate on captured data
    (read-only) and produce additional ProtocolEvents and
    enhanced reports.
    """

    @property
    def info(self) -> PluginInfo:
        """Plugin metadata."""
        ...

    def can_handle(self, connections: list[Connection]) -> bool:
        """Check if this plugin is relevant for the given connections.

        Plugins should check URLs, headers, or other connection metadata
        to determine if they can provide useful analysis.

        Args:
            connections: All connections in the session.

        Returns:
            True if this plugin should run on this data.
        """
        ...

    def analyze(
        self,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[Any, Payload],
    ) -> list[ProtocolEvent]:
        """Run plugin-specific analysis on captured data.

        Args:
            connections: All connections in the session.
            frames: All frames in the session.
            payloads: Mapping of payload_id → Payload.

        Returns:
            List of discovered ProtocolEvents.
        """
        ...
