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
from wiretap.analysis.classification import BinaryPacketFamily
from wiretap.analysis.structural import FieldMapEntry
from wiretap.analysis.similarity import PriceCandidate
from wiretap.analysis.correlation import CorrelationResult
from wiretap.analysis.protocol_graph import StateTransition, RequestResponseChain
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

    def generate_binary_discovery(
        self,
        session: CaptureSession,
        families: list[BinaryPacketFamily],
        field_maps: dict[str, list[FieldMapEntry]],
        price_candidates: dict[str, list[PriceCandidate]],
        correlations: list[CorrelationResult],
        transitions: list[StateTransition],
        chains: list[RequestResponseChain],
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[UUID, Payload],
    ) -> list[Path]:
        """Generate binary protocol discovery reports and visualizations."""
        self._output_dir.mkdir(parents=True, exist_ok=True)
        generated: list[Path] = []

        # 1. Generate protocol_discovery.md
        doc_path = self.generate_protocol_discovery_doc(
            session, families, field_maps, price_candidates, correlations, transitions, chains
        )
        generated.append(doc_path)

        # 2. Generate packet_explorer.html
        from wiretap.visualization.packet_explorer import generate_packet_explorer
        explorer_path = self._output_dir / "packet_explorer.html"
        generate_packet_explorer(
            explorer_path,
            session.name,
            families,
            field_maps,
            price_candidates,
            correlations,
            transitions,
            chains,
            connections,
            frames,
            payloads,
        )
        generated.append(explorer_path)

        return generated

    def generate_protocol_discovery_doc(
        self,
        session: CaptureSession,
        families: list[BinaryPacketFamily],
        field_maps: dict[str, list[FieldMapEntry]],
        price_candidates: dict[str, list[PriceCandidate]],
        correlations: list[CorrelationResult],
        transitions: list[StateTransition],
        chains: list[RequestResponseChain],
    ) -> Path:
        """Generate Markdown protocol discovery report."""
        path = self._output_dir / "protocol_discovery.md"
        lines: list[str] = []

        lines.append(f"# Binary Protocol Discovery: {session.name}")
        lines.append("")
        lines.append(f"**Target:** {session.target_url}")
        lines.append(f"**Captured:** {format_timestamp(session.started_at)}")
        lines.append("")
        lines.append("## Overview")
        lines.append(f"The binary discovery engine successfully classified **{len(families)}** stable message families from captured binary frames.")
        lines.append("")

        # 1. Families Table
        lines.append("## Discovered Packet Families")
        lines.append("")
        lines.append("| Family ID | Direction | Count | Avg Length | Avg Interval | Entropy | Purpose | Confidence |")
        lines.append("|-----------|-----------|-------|------------|--------------|---------|---------|------------|")
        for fam in families:
            lines.append(
                f"| `{fam.id}` | {fam.direction.name} | {fam.count} | {int(fam.avg_length)}B | {fam.avg_interval:.2f}s | {fam.entropy:.2f} | {fam.likely_purpose} | {fam.confidence:.0%} |"
            )
        lines.append("")

        # 2. Candidate Price Fields
        lines.append("## Price Candidate Scanner Results")
        lines.append("Numerical fields behaving like price tick updates (dynamic fluctuations within expected price bounds):")
        lines.append("")
        has_prices = False
        for fam_id, cands in price_candidates.items():
            if not cands:
                continue
            has_prices = True
            lines.append(f"### Family `{fam_id}` price Candidates")
            lines.append("")
            lines.append("| Offset | Size | Endianness | Type | Scale Factor | Confidence | Samples |")
            lines.append("|--------|------|------------|------|--------------|------------|---------|")
            for cand in cands:
                samples_str = ", ".join(f"{v:.4f}" for v in cand.sample_values[:3])
                lines.append(
                    f"| `0x{cand.offset:02x}` ({cand.offset}) | {cand.size}B | {cand.endianness} | {cand.value_type} | {cand.scale_factor} | {cand.confidence:.0%} | {samples_str} |"
                )
            lines.append("")
        if not has_prices:
            lines.append("*No numerical fields met the price candidate heuristic bounds.*")
            lines.append("")

        # 3. Request-Response Chains
        lines.append("## Inferred Request-Response Pairs")
        lines.append("")
        if chains:
            lines.append("| Request Family | Response Family | Match Count | Total | Avg Latency | Confidence | Description |")
            lines.append("|----------------|-----------------|-------------|-------|-------------|------------|-------------|")
            for ch in chains:
                lines.append(
                    f"| `{ch.request_family}` | `{ch.response_family}` | {ch.match_count} | {ch.total_requests} | {ch.avg_latency * 1000:.1f}ms | {ch.confidence:.0%} | {ch.description} |"
                )
        else:
            lines.append("*No request-response pairs were reliably inferred.*")
        lines.append("")

        # 4. State Transitions
        lines.append("## Transition Frequencies")
        lines.append("")
        if transitions:
            lines.append("| From Family | To Family | Transition Count | Avg Delay | Probability |")
            lines.append("|-------------|-----------|------------------|-----------|-------------|")
            for t in transitions[:15]:
                lines.append(
                    f"| `{t.from_family}` | `{t.to_family}` | {t.count} | {t.avg_interval:.2f}s | {t.probability:.1%} |"
                )
        else:
            lines.append("*No transitions recorded.*")
        lines.append("")

        # 5. Timeline Correlations
        lines.append("## Action Timeline Correlations")
        lines.append("")
        if correlations:
            lines.append("| User Action / Annotation | Correlated Family | Co-Occurrences | Total Action Count | Probability | Lift | Confidence |")
            lines.append("|--------------------------|-------------------|----------------|--------------------|-------------|------|------------|")
            for c in correlations:
                lines.append(
                    f"| \"{c.action_text}\" | `{c.family_id}` | {c.co_occurrences} | {c.total_actions} | {c.probability} | {c.lift} | {c.confidence:.0%} |"
                )
        else:
            lines.append("*No user annotations found or correlated.*")
        lines.append("")

        # 6. Detailed Byte Maps per Family
        lines.append("## Structural Byte Maps")
        lines.append("")
        for fam in families:
            f_map = field_maps.get(fam.id, [])
            if not f_map:
                continue
            lines.append(f"### Family `{fam.id}` Structure")
            lines.append("")
            lines.append("| Offset | Size | Stability | Type | Description | Sample Values |")
            lines.append("|--------|------|-----------|------|-------------|---------------|")
            for entry in f_map:
                samples_str = ", ".join(str(s) for s in entry.sample_values[:3])
                lines.append(
                    f"| `0x{entry.offset:02x}` ({entry.offset}) | {entry.size}B | **{entry.stability}** | {entry.type_name} | {entry.description} | `{samples_str}` |"
                )
            lines.append("")

        path.write_text("\n".join(lines))
        return path

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
