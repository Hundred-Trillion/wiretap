"""Protocol transition graph builder.

Analyzes sequential packet flows and timing relationships to reconstruct the state machine
of the session and infer request-response dependencies.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from wiretap.analysis.classification import BinaryPacketFamily
from wiretap.core.models import Frame


@dataclass
class StateTransition:
    """A directed edge in the protocol state machine."""

    from_family: str
    to_family: str
    count: int
    avg_interval: float  # seconds
    probability: float  # transition probability from 'from_family'


@dataclass
class RequestResponseChain:
    """An inferred request-response packet pair."""

    request_family: str
    response_family: str
    match_count: int
    total_requests: int
    avg_latency: float  # average interval in seconds
    confidence: float
    description: str


class ProtocolGraphBuilder:
    """Builds state transition graphs and infers request-response chains from packet flow."""

    def build_graph(
        self,
        families: list[BinaryPacketFamily],
        frames: list[Frame],
    ) -> list[StateTransition]:
        """Construct the transition matrix/edges between packet families."""
        if not families or not frames:
            return []

        # Sort frames by timestamp
        sorted_frames = sorted(frames, key=lambda f: f.timestamp)

        # Map frame ID to family ID
        frame_to_family = {}
        for fam in families:
            for fp in fam.fingerprints:
                frame_to_family[fp.frame_id] = fam.id

        # Count state transitions
        transition_counts: dict[tuple[str, str], int] = defaultdict(int)
        transition_intervals: dict[tuple[str, str], list[float]] = defaultdict(list)
        family_out_counts: dict[str, int] = defaultdict(int)

        for i in range(len(sorted_frames) - 1):
            f1 = sorted_frames[i]
            f2 = sorted_frames[i + 1]

            fam1 = frame_to_family.get(f1.id)
            fam2 = frame_to_family.get(f2.id)

            if fam1 and fam2:
                edge = (fam1, fam2)
                transition_counts[edge] += 1
                family_out_counts[fam1] += 1

                interval = (f2.timestamp - f1.timestamp).total_seconds()
                transition_intervals[edge].append(max(0.0, interval))

        transitions: list[StateTransition] = []
        for edge, count in transition_counts.items():
            from_fam, to_fam = edge
            out_total = family_out_counts[from_fam]
            prob = count / out_total if out_total > 0 else 0.0

            intervals = transition_intervals[edge]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0.0

            transitions.append(
                StateTransition(
                    from_family=from_fam,
                    to_family=to_fam,
                    count=count,
                    avg_interval=avg_interval,
                    probability=prob,
                )
            )

        # Sort transitions by count descending
        transitions.sort(key=lambda t: t.count, reverse=True)
        return transitions

    def infer_chains(
        self,
        families: list[BinaryPacketFamily],
        frames: list[Frame],
        max_latency_seconds: float = 1.0,
    ) -> list[RequestResponseChain]:
        """Infer request-response pairings between outgoing and incoming packet families."""
        if not families or not frames:
            return []

        # Sort frames by timestamp
        sorted_frames = sorted(frames, key=lambda f: f.timestamp)

        # Map frame ID to family ID
        frame_to_family = {}
        for fam in families:
            for fp in fam.fingerprints:
                frame_to_family[fp.frame_id] = fam.id

        # Group frames by connection to isolate channels
        frames_by_conn: dict[UUID, list[Frame]] = defaultdict(list)
        for f in sorted_frames:
            frames_by_conn[f.connection_id].append(f)

        # Request -> Response candidate pairings
        # (ReqFamily, RespFamily) -> list of latencies
        pairings: dict[tuple[str, str], list[float]] = defaultdict(list)
        request_totals: dict[str, int] = defaultdict(int)

        for conn_id, conn_frames in frames_by_conn.items():
            # Sort connection frames chronologically
            conn_frames.sort(key=lambda f: f.timestamp)

            for i, f_req in enumerate(conn_frames):
                req_fam = frame_to_family.get(f_req.id)
                if not req_fam:
                    continue

                # We look for a SENT request triggering a RECEIVED response
                for fam in families:
                    if fam.id == req_fam:
                        if fam.direction != fam.direction.SENT:
                            break  # must be SENT to be a request
                        request_totals[req_fam] += 1

                        # Look forward in the connection for the first RECEIVED response
                        for j in range(i + 1, len(conn_frames)):
                            f_resp = conn_frames[j]
                            resp_fam = frame_to_family.get(f_resp.id)

                            if resp_fam:
                                # Check response properties
                                resp_family_obj = next((f for f in families if f.id == resp_fam), None)
                                if resp_family_obj and resp_family_obj.direction == resp_family_obj.direction.RECEIVED:
                                    latency = (f_resp.timestamp - f_req.timestamp).total_seconds()
                                    if 0.0 <= latency <= max_latency_seconds:
                                        pairings[(req_fam, resp_fam)].append(latency)
                                    break  # Only map to the immediate first response

        chains: list[RequestResponseChain] = []
        for (req_fam, resp_fam), latencies in pairings.items():
            match_count = len(latencies)
            total_reqs = request_totals[req_fam]

            if total_reqs == 0:
                continue

            # Confidence = ratio of requests that got this specific response
            confidence = match_count / total_reqs
            avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

            if confidence >= 0.3 and match_count >= 2:
                description = (
                    f"Request {req_fam} consistently triggers response {resp_fam} "
                    f"in {confidence * 100:.0f}% of cases (avg latency: {avg_latency * 1000:.1f}ms)"
                )
                chains.append(
                    RequestResponseChain(
                        request_family=req_fam,
                        response_family=resp_fam,
                        match_count=match_count,
                        total_requests=total_reqs,
                        avg_latency=avg_latency,
                        confidence=confidence,
                        description=description,
                    )
                )

        # Sort by confidence descending
        chains.sort(key=lambda c: c.confidence, reverse=True)
        return chains
