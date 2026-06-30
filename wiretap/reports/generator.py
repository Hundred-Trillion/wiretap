"""Report generator — produces protocol documentation and data exports.

Generates:
- protocol.md: Markdown protocol documentation
- statistics.json: Full statistics dump
- event_map.json: Event type mapping
- traffic.jsonl: Raw traffic log
- metadata.json: Session metadata
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog

from wiretap.analysis.statistics import SessionStatistics
from wiretap.core.enums import Direction
from wiretap.core.models import (
    Annotation,
    CaptureSession,
    Connection,
    Frame,
    Payload,
    ProtocolEvent,
)
from wiretap.utils.formatting import format_bytes, format_duration, format_timestamp

logger = structlog.get_logger(__name__)


class ReportGenerator:
    """Generates comprehensive reports from capture session data."""

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir
        self._log = structlog.get_logger(component="ReportGenerator")

    def generate_all(
        self,
        session: CaptureSession,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[UUID, Payload],
        statistics: SessionStatistics,
        events: list[ProtocolEvent],
        annotations: list[Annotation],
    ) -> list[Path]:
        """Generate all report types.

        Returns:
            List of generated file paths.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        generated: list[Path] = []

        generated.append(self.generate_metadata(session, connections))
        generated.append(self.generate_statistics(statistics))
        generated.append(self.generate_event_map(events))
        generated.append(self.generate_protocol_doc(session, connections, events, statistics, annotations))
        generated.append(self.generate_traffic_log(connections, frames, payloads))

        return generated

    def generate_metadata(
        self, session: CaptureSession, connections: list[Connection]
    ) -> Path:
        """Generate session metadata JSON."""
        path = self._output_dir / "metadata.json"
        data = {
            "session_id": str(session.id),
            "name": session.name,
            "target_url": session.target_url,
            "started_at": session.started_at.isoformat(),
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "total_connections": len(connections),
            "metadata": session.metadata,
        }
        path.write_text(json.dumps(data, indent=2))
        return path

    def generate_statistics(self, statistics: SessionStatistics) -> Path:
        """Generate statistics JSON."""
        path = self._output_dir / "statistics.json"
        path.write_text(json.dumps(statistics.to_dict(), indent=2))
        return path

    def generate_event_map(self, events: list[ProtocolEvent]) -> Path:
        """Generate event map JSON."""
        path = self._output_dir / "event_map.json"
        data = [
            {
                "id": str(e.id),
                "type": e.event_type.name,
                "confidence": e.confidence,
                "description": e.description,
                "evidence": e.evidence,
                "frame_refs": [str(f) for f in e.frame_refs],
            }
            for e in events
        ]
        path.write_text(json.dumps(data, indent=2))
        return path

    def generate_traffic_log(
        self,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[UUID, Payload],
    ) -> Path:
        """Generate JSONL traffic log."""
        path = self._output_dir / "traffic.jsonl"
        conn_map = {str(c.id): c for c in connections}

        with open(path, "w") as f:
            for frame in sorted(frames, key=lambda x: x.timestamp):
                conn = conn_map.get(str(frame.connection_id))
                payload = payloads.get(frame.payload_id) if frame.payload_id else None
                entry = {
                    "timestamp": frame.timestamp.isoformat(),
                    "connection_url": conn.url if conn else "",
                    "protocol": conn.protocol.name if conn else "",
                    "direction": frame.direction.name,
                    "sequence": frame.sequence,
                    "is_binary": frame.is_binary,
                    "payload_size": payload.size if payload else 0,
                    "payload_sha256": payload.sha256 if payload else "",
                }
                f.write(json.dumps(entry) + "\n")

        return path

    def generate_protocol_doc(
        self,
        session: CaptureSession,
        connections: list[Connection],
        events: list[ProtocolEvent],
        statistics: SessionStatistics,
        annotations: list[Annotation],
    ) -> Path:
        """Generate Markdown protocol documentation."""
        path = self._output_dir / "protocol.md"
        lines: list[str] = []

        lines.append(f"# Protocol Analysis: {session.name}")
        lines.append("")
        lines.append(f"**Target:** {session.target_url}")
        lines.append(f"**Captured:** {format_timestamp(session.started_at)}")
        if session.ended_at:
            duration = (session.ended_at - session.started_at).total_seconds()
            lines.append(f"**Duration:** {format_duration(duration)}")
        lines.append("")

        # Statistics summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Connections | {statistics.total_connections} |")
        lines.append(f"| Total Frames | {statistics.total_frames} |")
        lines.append(f"| Total Bytes | {format_bytes(statistics.total_bytes)} |")
        lines.append(f"| Messages/sec | {statistics.messages_per_second:.1f} |")
        lines.append(f"| Bandwidth | {format_bytes(int(statistics.bytes_per_second))}/s |")
        lines.append("")

        # Protocol breakdown
        if statistics.connections_by_protocol:
            lines.append("## Protocol Breakdown")
            lines.append("")
            lines.append("| Protocol | Connections | % |")
            lines.append("|----------|------------|---|")
            for proto, count in statistics.connections_by_protocol.items():
                pct = statistics.protocol_breakdown.get(proto, 0)
                lines.append(f"| {proto} | {count} | {pct}% |")
            lines.append("")

        # Discovered events
        if events:
            lines.append("## Discovered Protocol Events")
            lines.append("")
            for event in sorted(events, key=lambda e: e.confidence, reverse=True):
                lines.append(f"### {event.event_type.name} (Confidence: {event.confidence:.0%})")
                lines.append("")
                lines.append(f"{event.description}")
                lines.append("")
                if event.evidence:
                    lines.append("**Evidence:**")
                    for ev in event.evidence:
                        lines.append(f"- {ev}")
                    lines.append("")

        # Top endpoints
        if statistics.top_endpoints:
            lines.append("## Top Endpoints")
            lines.append("")
            lines.append("| URL | Frames |")
            lines.append("|-----|--------|")
            for ep in statistics.top_endpoints[:15]:
                lines.append(f"| `{ep['url'][:80]}` | {ep['frame_count']} |")
            lines.append("")

        # Annotations
        if annotations:
            lines.append("## User Annotations")
            lines.append("")
            for ann in annotations:
                lines.append(f"- **{format_timestamp(ann.timestamp)}**: {ann.text}")
            lines.append("")

        path.write_text("\n".join(lines))
        return path
