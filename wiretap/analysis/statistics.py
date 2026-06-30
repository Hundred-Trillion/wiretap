"""Statistics engine for captured traffic analysis.

Generates comprehensive metrics from captured sessions including
connection counts, bandwidth, protocol breakdown, message frequency,
latency summaries, and endpoint rankings.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from wiretap.core.enums import Direction, ProtocolType
from wiretap.core.models import Connection, Frame, Payload


@dataclass
class LatencySummary:
    """Latency statistics for a set of connections."""

    min_ms: float = 0.0
    max_ms: float = 0.0
    mean_ms: float = 0.0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    sample_count: int = 0


@dataclass
class SessionStatistics:
    """Complete statistics for a capture session."""

    # Connection metrics
    total_connections: int = 0
    connections_by_protocol: dict[str, int] = field(default_factory=dict)
    connections_by_domain: dict[str, int] = field(default_factory=dict)

    # Frame metrics
    total_frames: int = 0
    frames_sent: int = 0
    frames_received: int = 0

    # Payload metrics
    total_bytes: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    binary_frame_count: int = 0
    text_frame_count: int = 0
    binary_text_ratio: float = 0.0

    # Bandwidth
    duration_seconds: float = 0.0
    bytes_per_second: float = 0.0
    messages_per_second: float = 0.0

    # Protocol breakdown
    protocol_breakdown: dict[str, float] = field(default_factory=dict)

    # Endpoint rankings
    top_endpoints: list[dict[str, Any]] = field(default_factory=list)

    # Event frequency
    event_frequency: dict[str, int] = field(default_factory=dict)

    # Latency
    latency: LatencySummary = field(default_factory=LatencySummary)

    # Payload size distribution
    payload_size_min: int = 0
    payload_size_max: int = 0
    payload_size_mean: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize statistics to a dictionary."""
        return {
            "total_connections": self.total_connections,
            "connections_by_protocol": self.connections_by_protocol,
            "connections_by_domain": self.connections_by_domain,
            "total_frames": self.total_frames,
            "frames_sent": self.frames_sent,
            "frames_received": self.frames_received,
            "total_bytes": self.total_bytes,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "binary_frame_count": self.binary_frame_count,
            "text_frame_count": self.text_frame_count,
            "binary_text_ratio": self.binary_text_ratio,
            "duration_seconds": self.duration_seconds,
            "bytes_per_second": self.bytes_per_second,
            "messages_per_second": self.messages_per_second,
            "protocol_breakdown": self.protocol_breakdown,
            "top_endpoints": self.top_endpoints,
            "event_frequency": self.event_frequency,
            "latency": {
                "min_ms": self.latency.min_ms,
                "max_ms": self.latency.max_ms,
                "mean_ms": self.latency.mean_ms,
                "p50_ms": self.latency.p50_ms,
                "p95_ms": self.latency.p95_ms,
                "p99_ms": self.latency.p99_ms,
                "sample_count": self.latency.sample_count,
            },
            "payload_size_min": self.payload_size_min,
            "payload_size_max": self.payload_size_max,
            "payload_size_mean": self.payload_size_mean,
        }


class StatisticsEngine:
    """Computes comprehensive statistics from captured session data."""

    def compute(
        self,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[UUID, Payload],
        session_start: datetime | None = None,
        session_end: datetime | None = None,
    ) -> SessionStatistics:
        """Compute all statistics for a session.

        Args:
            connections: All connections in the session.
            frames: All frames in the session.
            payloads: Mapping of payload_id → Payload.
            session_start: Session start timestamp.
            session_end: Session end timestamp.

        Returns:
            Complete SessionStatistics.
        """
        stats = SessionStatistics()

        # Connection metrics
        stats.total_connections = len(connections)
        proto_counter: Counter[str] = Counter()
        domain_counter: Counter[str] = Counter()
        for conn in connections:
            proto_counter[conn.protocol.name] += 1
            domain = self._extract_domain(conn.url)
            domain_counter[domain] += 1
        stats.connections_by_protocol = dict(proto_counter)
        stats.connections_by_domain = dict(domain_counter.most_common(50))

        # Frame metrics
        stats.total_frames = len(frames)
        stats.frames_sent = sum(1 for f in frames if f.direction == Direction.SENT)
        stats.frames_received = stats.total_frames - stats.frames_sent
        stats.binary_frame_count = sum(1 for f in frames if f.is_binary)
        stats.text_frame_count = stats.total_frames - stats.binary_frame_count
        if stats.text_frame_count > 0:
            stats.binary_text_ratio = stats.binary_frame_count / stats.text_frame_count
        else:
            stats.binary_text_ratio = float(stats.binary_frame_count) if stats.binary_frame_count else 0.0

        # Payload metrics
        sizes = []
        for f in frames:
            if f.payload_id and f.payload_id in payloads:
                p = payloads[f.payload_id]
                sizes.append(p.size)
                stats.total_bytes += p.size
                if f.direction == Direction.SENT:
                    stats.bytes_sent += p.size
                else:
                    stats.bytes_received += p.size

        if sizes:
            stats.payload_size_min = min(sizes)
            stats.payload_size_max = max(sizes)
            stats.payload_size_mean = sum(sizes) / len(sizes)

        # Duration and bandwidth
        if session_start and session_end:
            stats.duration_seconds = (session_end - session_start).total_seconds()
        elif frames:
            timestamps = [f.timestamp for f in frames]
            stats.duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()

        if stats.duration_seconds > 0:
            stats.bytes_per_second = stats.total_bytes / stats.duration_seconds
            stats.messages_per_second = stats.total_frames / stats.duration_seconds

        # Protocol breakdown (percentage)
        if stats.total_connections > 0:
            stats.protocol_breakdown = {
                k: round(v / stats.total_connections * 100, 1)
                for k, v in proto_counter.items()
            }

        # Top endpoints by frame count
        endpoint_frames: Counter[str] = Counter()
        conn_id_url = {str(c.id): c.url for c in connections}
        for f in frames:
            url = conn_id_url.get(str(f.connection_id), "unknown")
            endpoint_frames[url] += 1
        stats.top_endpoints = [
            {"url": url, "frame_count": count}
            for url, count in endpoint_frames.most_common(20)
        ]

        # Latency (from connection timing)
        latencies = []
        for conn in connections:
            if conn.timing.send_start >= 0 and conn.timing.receive_start >= 0:
                latency = conn.timing.receive_start - conn.timing.send_start
                if latency > 0:
                    latencies.append(latency)

        if latencies:
            latencies.sort()
            n = len(latencies)
            stats.latency = LatencySummary(
                min_ms=latencies[0],
                max_ms=latencies[-1],
                mean_ms=sum(latencies) / n,
                p50_ms=latencies[n // 2],
                p95_ms=latencies[int(n * 0.95)],
                p99_ms=latencies[int(n * 0.99)],
                sample_count=n,
            )

        return stats

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or url
        except Exception:
            return url
