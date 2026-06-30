"""Behavior correlation engine.

Analyzes the capture timeline to correlate specific user actions (e.g. annotations)
with subsequent bursts or occurrences of particular packet families.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from wiretap.analysis.classification import BinaryPacketFamily
from wiretap.core.models import Annotation, Frame


@dataclass
class CorrelationResult:
    """Correlation finding between an action and a packet family."""

    action_text: str
    family_id: str
    co_occurrences: int
    total_actions: int
    total_family_count: int
    probability: float  # P(Family | Action)
    lift: float  # Ratio of co-occurrence rate to baseline rate
    confidence: float  # Final confidence rating (0.0 to 1.0)
    description: str


class BehaviorCorrelator:
    """Correlates captured frames with user action annotations over the timeline."""

    def __init__(self, correlation_window_seconds: float = 5.0) -> None:
        self.window = timedelta(seconds=correlation_window_seconds)

    def correlate(
        self,
        annotations: list[Annotation],
        families: list[BinaryPacketFamily],
        frames: list[Frame],
    ) -> list[CorrelationResult]:
        """Correlate packet families with annotations.

        Returns:
            List of CorrelationResult objects with scores and descriptions.
        """
        if not annotations or not families or not frames:
            return []

        total_frames_count = len(frames)
        if total_frames_count == 0:
            return []

        # Map frame ID to its family ID for fast lookup
        frame_family_map: dict[UUID, str] = {}
        for fam in families:
            for fp in fam.fingerprints:
                frame_family_map[fp.frame_id] = fam.id

        # Group frames by their family
        family_counts: dict[str, int] = {fam.id: len(fam.fingerprints) for fam in families}

        # Find timestamp range of entire session to calculate baseline rate
        sorted_frames = sorted(frames, key=lambda f: f.timestamp)
        session_duration = (sorted_frames[-1].timestamp - sorted_frames[0].timestamp).total_seconds()
        if session_duration <= 0:
            session_duration = 1.0

        results: list[CorrelationResult] = []

        # Group annotations by their text patterns
        # Group identical/similar actions (e.g., "changed asset" or "logged in")
        actions_by_type: dict[str, list[Annotation]] = {}
        for ann in annotations:
            action_key = ann.text.strip().lower()
            if action_key not in actions_by_type:
                actions_by_type[action_key] = []
            actions_by_type[action_key].append(ann)

        for action_text, action_list in actions_by_type.items():
            total_actions = len(action_list)

            # Count families appearing in windows after this action type
            family_window_counts: dict[str, int] = {fam.id: 0 for fam in families}
            # Track which frame IDs we have counted to avoid double counting if windows overlap
            counted_frames: set[UUID] = set()

            for ann in action_list:
                start_time = ann.timestamp
                end_time = ann.timestamp + self.window

                # Find all frames in this window
                for frame in frames:
                    if start_time <= frame.timestamp <= end_time:
                        if frame.id not in counted_frames:
                            fam_id = frame_family_map.get(frame.id)
                            if fam_id:
                                family_window_counts[fam_id] += 1
                                counted_frames.add(frame.id)

            # Evaluate each family's correlation with this action
            for fam in families:
                co_occurrences = family_window_counts[fam.id]
                total_fam = family_counts[fam.id]

                if co_occurrences == 0:
                    continue

                # P(Family | Action): Probability that the family appears after the action
                # co_occurrences / total_actions
                prob = co_occurrences / total_actions

                # Baseline probability of this family appearing in a random 5s window
                # total_fam / (session_duration / window_seconds)
                window_duration = self.window.total_seconds()
                baseline_rate = (total_fam / session_duration) * window_duration
                # Prevent division by zero
                baseline_rate = max(1e-5, baseline_rate)

                # Lift: how much more likely the family is to appear after the action than randomly
                lift = (co_occurrences / total_actions) / baseline_rate

                # Confidence heuristic:
                # - High if fraction of the family's total packets occurring in the window is high
                # - Adjusted by co_occurrences count to prevent noise
                fraction_in_window = co_occurrences / total_fam
                confidence = fraction_in_window * min(1.0, co_occurrences / 5.0)

                # Cap confidence between 0.0 and 1.0
                confidence = min(1.0, max(0.0, confidence))

                if confidence > 0.1 or lift > 2.0:
                    description = (
                        f"Family {fam.id} shows high correlation with '{action_text}' "
                        f"({co_occurrences} co-occurrences, lift: {lift:.1f}x)"
                    )
                    results.append(
                        CorrelationResult(
                            action_text=action_text,
                            family_id=fam.id,
                            co_occurrences=co_occurrences,
                            total_actions=total_actions,
                            total_family_count=total_fam,
                            probability=prob,
                            lift=lift,
                            confidence=confidence,
                            description=description,
                        )
                    )

        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results
