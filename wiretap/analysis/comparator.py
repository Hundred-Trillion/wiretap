"""Session comparator for diffing two capture sessions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from wiretap.core.models import Connection, Frame


@dataclass
class ComparisonResult:
    """Result of comparing two capture sessions."""

    session_a_id: UUID | None = None
    session_b_id: UUID | None = None

    # Endpoints
    endpoints_added: list[str] = field(default_factory=list)
    endpoints_removed: list[str] = field(default_factory=list)
    endpoints_common: list[str] = field(default_factory=list)

    # Frame count changes
    frame_count_a: int = 0
    frame_count_b: int = 0

    # Protocol changes
    protocols_added: list[str] = field(default_factory=list)
    protocols_removed: list[str] = field(default_factory=list)

    # Pattern differences
    pattern_differences: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "session_a": str(self.session_a_id),
            "session_b": str(self.session_b_id),
            "endpoints_added": self.endpoints_added,
            "endpoints_removed": self.endpoints_removed,
            "endpoints_common": self.endpoints_common,
            "frame_count_a": self.frame_count_a,
            "frame_count_b": self.frame_count_b,
            "protocols_added": self.protocols_added,
            "protocols_removed": self.protocols_removed,
            "pattern_differences": self.pattern_differences,
        }


class SessionComparator:
    """Compares two capture sessions to identify differences."""

    def compare(
        self,
        session_a_id: UUID,
        connections_a: list[Connection],
        frames_a: list[Frame],
        session_b_id: UUID,
        connections_b: list[Connection],
        frames_b: list[Frame],
    ) -> ComparisonResult:
        """Compare two sessions.

        Args:
            session_a_id: First session ID.
            connections_a: Connections from first session.
            frames_a: Frames from first session.
            session_b_id: Second session ID.
            connections_b: Connections from second session.
            frames_b: Frames from second session.

        Returns:
            ComparisonResult with differences.
        """
        result = ComparisonResult(
            session_a_id=session_a_id,
            session_b_id=session_b_id,
        )

        # Endpoint comparison
        urls_a = {c.url for c in connections_a}
        urls_b = {c.url for c in connections_b}
        result.endpoints_added = sorted(urls_b - urls_a)
        result.endpoints_removed = sorted(urls_a - urls_b)
        result.endpoints_common = sorted(urls_a & urls_b)

        # Frame counts
        result.frame_count_a = len(frames_a)
        result.frame_count_b = len(frames_b)

        # Protocol comparison
        protos_a = {c.protocol.name for c in connections_a}
        protos_b = {c.protocol.name for c in connections_b}
        result.protocols_added = sorted(protos_b - protos_a)
        result.protocols_removed = sorted(protos_a - protos_b)

        # Pattern differences
        if result.frame_count_b > result.frame_count_a * 1.5:
            result.pattern_differences.append(
                f"Session B has {result.frame_count_b - result.frame_count_a} more frames"
            )
        elif result.frame_count_a > result.frame_count_b * 1.5:
            result.pattern_differences.append(
                f"Session A has {result.frame_count_a - result.frame_count_b} more frames"
            )

        if result.endpoints_added:
            result.pattern_differences.append(
                f"{len(result.endpoints_added)} new endpoints in session B"
            )
        if result.endpoints_removed:
            result.pattern_differences.append(
                f"{len(result.endpoints_removed)} endpoints missing from session B"
            )

        return result
