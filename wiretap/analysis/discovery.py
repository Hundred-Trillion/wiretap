"""Protocol discovery engine.

Automatically identifies protocol patterns (authentication, heartbeats,
session establishment, etc.) from captured traffic. Every finding
includes a confidence score and supporting evidence.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import structlog

from wiretap.core.enums import Direction, EventType, ProtocolType
from wiretap.core.models import Connection, Frame, Payload, ProtocolEvent

logger = structlog.get_logger(__name__)


class ProtocolDiscovery:
    """Analyzes captured traffic to identify protocol patterns.

    All analysis is evidence-based. Every ProtocolEvent returned
    includes frame references and human-readable evidence strings.
    """

    def __init__(self) -> None:
        self._log = structlog.get_logger(component="ProtocolDiscovery")

    def analyze(
        self,
        session_id: UUID,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[UUID, Payload],
        decoded: dict[UUID, Any] | None = None,
    ) -> list[ProtocolEvent]:
        """Run all discovery heuristics on a capture session.

        Args:
            session_id: The session being analyzed.
            connections: All connections in the session.
            frames: All frames in the session.
            payloads: Mapping of payload_id → Payload.
            decoded: Optional mapping of payload_id → decoded data.

        Returns:
            List of discovered ProtocolEvents.
        """
        events: list[ProtocolEvent] = []
        decoded = decoded or {}

        # Build lookup structures
        conn_map = {str(c.id): c for c in connections}
        frames_by_conn: dict[str, list[Frame]] = defaultdict(list)
        for f in frames:
            frames_by_conn[str(f.connection_id)].append(f)

        # Run detectors
        events.extend(self._detect_authentication(session_id, connections, frames, payloads, decoded))
        events.extend(self._detect_heartbeats(session_id, connections, frames_by_conn, payloads))
        events.extend(self._detect_session_init(session_id, connections, frames_by_conn))
        events.extend(self._detect_keepalive(session_id, frames_by_conn, payloads))
        events.extend(self._detect_request_response(session_id, connections, frames_by_conn, decoded))
        events.extend(self._detect_streaming(session_id, connections, frames_by_conn))
        events.extend(self._detect_binary_families(session_id, frames, payloads))

        return events

    def _detect_authentication(
        self,
        session_id: UUID,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[UUID, Payload],
        decoded: dict[UUID, Any],
    ) -> list[ProtocolEvent]:
        """Detect authentication flows."""
        events = []

        for conn in connections:
            evidence = []
            frame_refs = []
            confidence = 0.0

            # Check for auth-related URLs
            url_lower = conn.url.lower()
            auth_keywords = ["auth", "login", "signin", "token", "oauth", "session"]
            if any(kw in url_lower for kw in auth_keywords):
                evidence.append(f"URL contains auth keyword: {conn.url}")
                confidence += 0.3

            # Check for auth headers
            auth_headers = ["authorization", "x-auth-token", "x-csrf-token"]
            for h in auth_headers:
                if h in {k.lower() for k in conn.request_headers}:
                    evidence.append(f"Request contains header: {h}")
                    confidence += 0.2

            # Check response for token-like patterns
            conn_frames = [f for f in frames if f.connection_id == conn.id]
            for f in conn_frames:
                if f.payload_id and f.payload_id in decoded:
                    data = decoded[f.payload_id]
                    if isinstance(data, dict):
                        token_keys = ["token", "access_token", "jwt", "session_id", "refresh_token"]
                        for tk in token_keys:
                            if tk in {k.lower() for k in data}:
                                evidence.append(f"Response contains key: {tk}")
                                confidence += 0.2
                                frame_refs.append(f.id)

            # Check for 401/403 status codes
            if conn.status_code in (401, 403):
                evidence.append(f"HTTP status {conn.status_code} (auth-related)")
                confidence += 0.3
                frame_refs.extend(f.id for f in conn_frames)

            if confidence > 0.3:
                events.append(ProtocolEvent(
                    session_id=session_id,
                    event_type=EventType.AUTHENTICATION,
                    confidence=min(confidence, 1.0),
                    evidence=evidence,
                    frame_refs=frame_refs,
                    description=f"Authentication flow detected at {conn.url}",
                ))

        return events

    def _detect_heartbeats(
        self,
        session_id: UUID,
        connections: list[Connection],
        frames_by_conn: dict[str, list[Frame]],
        payloads: dict[UUID, Payload],
    ) -> list[ProtocolEvent]:
        """Detect heartbeat/ping patterns by interval regularity."""
        events = []

        for conn in connections:
            if conn.protocol not in (ProtocolType.WEBSOCKET, ProtocolType.SSE):
                continue

            conn_frames = frames_by_conn.get(str(conn.id), [])
            if len(conn_frames) < 4:
                continue

            # Group by payload hash to find repeated messages
            hash_groups: dict[str, list[Frame]] = defaultdict(list)
            for f in conn_frames:
                if f.payload_id and f.payload_id in payloads:
                    hash_groups[payloads[f.payload_id].sha256].append(f)

            for sha, group_frames in hash_groups.items():
                if len(group_frames) < 3:
                    continue

                # Check interval regularity
                sorted_frames = sorted(group_frames, key=lambda f: f.timestamp)
                intervals = []
                for i in range(1, len(sorted_frames)):
                    delta = (sorted_frames[i].timestamp - sorted_frames[i - 1].timestamp).total_seconds()
                    if delta > 0:
                        intervals.append(delta)

                if not intervals:
                    continue

                avg_interval = sum(intervals) / len(intervals)
                if avg_interval <= 0:
                    continue

                # Low variance = regular interval = likely heartbeat
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                cv = (variance ** 0.5) / avg_interval if avg_interval > 0 else float("inf")

                if cv < 0.3 and avg_interval < 120:  # Regular and < 2 min apart
                    confidence = max(0.0, 1.0 - cv)
                    events.append(ProtocolEvent(
                        session_id=session_id,
                        event_type=EventType.HEARTBEAT,
                        confidence=min(confidence, 0.95),
                        evidence=[
                            f"Repeated payload (SHA256: {sha[:16]}...) sent {len(group_frames)} times",
                            f"Average interval: {avg_interval:.1f}s (CV: {cv:.3f})",
                            f"Connection: {conn.url}",
                        ],
                        frame_refs=[f.id for f in group_frames],
                        description=f"Heartbeat detected on {conn.url} (~{avg_interval:.0f}s interval)",
                        metadata={"avg_interval_seconds": avg_interval, "count": len(group_frames)},
                    ))

        return events

    def _detect_session_init(
        self,
        session_id: UUID,
        connections: list[Connection],
        frames_by_conn: dict[str, list[Frame]],
    ) -> list[ProtocolEvent]:
        """Detect session initialization sequences."""
        events = []

        for conn in connections:
            if conn.protocol != ProtocolType.WEBSOCKET:
                continue

            conn_frames = sorted(
                frames_by_conn.get(str(conn.id), []),
                key=lambda f: f.timestamp,
            )

            if len(conn_frames) < 2:
                continue

            # First few frames after WS handshake are likely session init
            init_frames = conn_frames[:min(5, len(conn_frames))]

            # Look for a sent-then-received pattern at the start
            if (len(init_frames) >= 2
                    and init_frames[0].direction == Direction.SENT
                    and init_frames[1].direction == Direction.RECEIVED):
                events.append(ProtocolEvent(
                    session_id=session_id,
                    event_type=EventType.SESSION_INIT,
                    confidence=0.6,
                    evidence=[
                        "WebSocket opened with sent→received pattern",
                        f"Connection: {conn.url}",
                        f"First {len(init_frames)} frames analyzed",
                    ],
                    frame_refs=[f.id for f in init_frames],
                    description=f"Session initialization on {conn.url}",
                ))

        return events

    def _detect_keepalive(
        self,
        session_id: UUID,
        frames_by_conn: dict[str, list[Frame]],
        payloads: dict[UUID, Payload],
    ) -> list[ProtocolEvent]:
        """Detect keep-alive ping/pong patterns."""
        events = []

        for conn_id, conn_frames in frames_by_conn.items():
            sorted_frames = sorted(conn_frames, key=lambda f: f.timestamp)

            for i in range(len(sorted_frames) - 1):
                f1 = sorted_frames[i]
                f2 = sorted_frames[i + 1]

                # Ping/pong: opposite directions within a short window
                if (f1.direction != f2.direction
                        and (f2.timestamp - f1.timestamp).total_seconds() < 1.0):

                    # Check for small payloads (typical of ping/pong)
                    p1 = payloads.get(f1.payload_id) if f1.payload_id else None
                    p2 = payloads.get(f2.payload_id) if f2.payload_id else None

                    if p1 and p2 and p1.size < 50 and p2.size < 50:
                        events.append(ProtocolEvent(
                            session_id=session_id,
                            event_type=EventType.KEEP_ALIVE,
                            confidence=0.5,
                            evidence=[
                                "Small payload pair with opposite directions",
                                f"Sizes: {p1.size}B → {p2.size}B",
                                f"Interval: {(f2.timestamp - f1.timestamp).total_seconds():.3f}s",
                            ],
                            frame_refs=[f1.id, f2.id],
                            description="Keep-alive ping/pong pair",
                        ))
                        break  # One per connection to avoid spam

        return events

    def _detect_request_response(
        self,
        session_id: UUID,
        connections: list[Connection],
        frames_by_conn: dict[str, list[Frame]],
        decoded: dict[UUID, Any],
    ) -> list[ProtocolEvent]:
        """Detect request/response patterns in WebSocket traffic."""
        events = []

        for conn in connections:
            if conn.protocol != ProtocolType.WEBSOCKET:
                continue

            conn_frames = sorted(
                frames_by_conn.get(str(conn.id), []),
                key=lambda f: f.timestamp,
            )

            # Look for ID-correlated request/response pairs
            sent_ids: dict[str, Frame] = {}
            for f in conn_frames:
                if f.payload_id and f.payload_id in decoded:
                    data = decoded[f.payload_id]
                    if isinstance(data, dict):
                        # Common ID fields
                        for key in ("id", "request_id", "req_id", "rid", "seq", "msg_id"):
                            if key in data:
                                id_val = str(data[key])
                                if f.direction == Direction.SENT:
                                    sent_ids[id_val] = f
                                elif id_val in sent_ids:
                                    events.append(ProtocolEvent(
                                        session_id=session_id,
                                        event_type=EventType.REQUEST_RESPONSE,
                                        confidence=0.75,
                                        evidence=[
                                            f"Matching {key}={id_val} in sent and received frames",
                                            f"Connection: {conn.url}",
                                        ],
                                        frame_refs=[sent_ids[id_val].id, f.id],
                                        description=f"Request/response pair ({key}={id_val})",
                                    ))
                                    break

        return events

    def _detect_streaming(
        self,
        session_id: UUID,
        connections: list[Connection],
        frames_by_conn: dict[str, list[Frame]],
    ) -> list[ProtocolEvent]:
        """Detect streaming patterns (continuous unidirectional data)."""
        events = []

        for conn in connections:
            conn_frames = frames_by_conn.get(str(conn.id), [])
            if len(conn_frames) < 5:
                continue

            # Count direction distribution
            received_count = sum(1 for f in conn_frames if f.direction == Direction.RECEIVED)
            sent_count = len(conn_frames) - received_count

            # Streaming: heavily one-directional
            total = len(conn_frames)
            if received_count > total * 0.8 and received_count >= 10:
                events.append(ProtocolEvent(
                    session_id=session_id,
                    event_type=EventType.STREAMING,
                    confidence=0.7,
                    evidence=[
                        f"Server→Browser dominance: {received_count}/{total} frames received",
                        f"Connection: {conn.url}",
                        f"Protocol: {conn.protocol}",
                    ],
                    frame_refs=[f.id for f in conn_frames[:5]],
                    description=f"Server streaming on {conn.url}",
                ))

        return events

    def _detect_binary_families(
        self,
        session_id: UUID,
        frames: list[Frame],
        payloads: dict[UUID, Payload],
    ) -> list[ProtocolEvent]:
        """Group binary messages by header byte patterns."""
        events = []

        # Collect binary frames
        binary_frames = [f for f in frames if f.is_binary and f.payload_id]

        if len(binary_frames) < 3:
            return events

        # Group by first 2 bytes (common for protocol discriminators)
        prefix_groups: dict[str, list[Frame]] = defaultdict(list)
        for f in binary_frames:
            payload = payloads.get(f.payload_id)
            if payload and len(payload.raw_bytes) >= 2:
                prefix = payload.raw_bytes[:2].hex()
                prefix_groups[prefix].append(f)

        for prefix, group_frames in prefix_groups.items():
            if len(group_frames) >= 3:
                events.append(ProtocolEvent(
                    session_id=session_id,
                    event_type=EventType.BINARY_FAMILY,
                    confidence=0.6,
                    evidence=[
                        f"Binary prefix 0x{prefix}: {len(group_frames)} frames",
                        f"Consistent 2-byte header pattern",
                    ],
                    frame_refs=[f.id for f in group_frames[:10]],
                    description=f"Binary message family (prefix: 0x{prefix})",
                    metadata={"prefix": prefix, "count": len(group_frames)},
                ))

        return events
