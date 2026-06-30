"""Generic plugin — baseline protocol analysis for any website.

This plugin provides basic pattern recognition that works universally
without any target-specific knowledge.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from wiretap.core.enums import EventType
from wiretap.core.models import Connection, Frame, Payload, ProtocolEvent
from wiretap.plugins.base import Plugin, PluginInfo


class GenericPlugin:
    """Default plugin that provides baseline analysis for any site."""

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="generic",
            version="0.1.0",
            description="Baseline protocol analysis for any website",
            author="Wiretap",
            target_domains=[],  # Empty = matches everything
        )

    def can_handle(self, connections: list[Connection]) -> bool:
        """Always returns True — this plugin handles everything."""
        return True

    def analyze(
        self,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[Any, Payload],
    ) -> list[ProtocolEvent]:
        """Run generic analysis.

        Identifies:
        - API endpoint patterns
        - Static vs dynamic resource separation
        - WebSocket usage patterns
        """
        events: list[ProtocolEvent] = []

        # Identify API endpoints (URLs with common API patterns)
        api_connections = []
        for conn in connections:
            url_lower = conn.url.lower()
            if any(p in url_lower for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                api_connections.append(conn)

        if api_connections:
            unique_bases = set()
            for c in api_connections:
                # Extract API base path
                parts = c.url.split("/")
                for i, p in enumerate(parts):
                    if p.lower() in ("api", "v1", "v2", "v3", "graphql", "rest"):
                        unique_bases.add("/".join(parts[:i + 1]))
                        break

            events.append(ProtocolEvent(
                id=uuid4(),
                session_id=connections[0].session_id if connections else uuid4(),
                event_type=EventType.UNKNOWN,
                confidence=0.8,
                evidence=[
                    f"Found {len(api_connections)} API requests",
                    f"API bases: {', '.join(list(unique_bases)[:5])}",
                ],
                frame_refs=[],
                description=f"API endpoints identified ({len(unique_bases)} base paths)",
                metadata={"api_bases": list(unique_bases), "api_request_count": len(api_connections)},
            ))

        return events
