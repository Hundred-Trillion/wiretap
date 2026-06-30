"""Binary classification and clustering engine.

Groups binary packets into logical families based on structural and timing characteristics.
"""

from __future__ import annotations

import zlib
import math
import functools
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from wiretap.core.enums import Direction


@dataclass
class BinaryPacketFingerprint:
    """Fingerprint features of a single binary packet."""

    frame_id: UUID
    connection_id: UUID
    direction: Direction
    timestamp: datetime
    length: int
    entropy: float
    crc32: int
    prefix: bytes
    sha256: str
    payload_raw: bytes


@dataclass
class BinaryPacketFamily:
    """A logical family of similar binary packets."""

    id: str  # e.g., "family_0x045b_31B" or "family_1"
    direction: Direction
    common_prefix: str  # Hex string
    avg_length: float
    count: int
    avg_interval: float  # seconds
    entropy: float
    confidence: float
    likely_purpose: str
    fingerprints: list[BinaryPacketFingerprint] = field(default_factory=list)


class BinaryClusteringEngine:
    """Clusters binary frames into structural families using distance heuristics."""

    def __init__(self, distance_threshold: float = 0.25) -> None:
        self.distance_threshold = distance_threshold
        self._distance_cache: dict[tuple[UUID, UUID], float] = {}

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of bytes (value between 0.0 and 8.0)."""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        total = len(data)
        for count in counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    @functools.lru_cache(maxsize=16384)
    def byte_ngrams(data: bytes, n: int = 2) -> set[bytes]:
        """Generate sliding n-grams of bytes."""
        if len(data) < n:
            return {data}
        return {data[i : i + n] for i in range(len(data) - n + 1)}

    @classmethod
    def byte_jaccard_similarity(cls, data1: bytes, data2: bytes) -> float:
        """Calculate Jaccard similarity coefficient of byte 2-grams."""
        if not data1 or not data2:
            return 1.0 if (not data1 and not data2) else 0.0
        s1 = cls.byte_ngrams(data1)
        s2 = cls.byte_ngrams(data2)
        union = s1.union(s2)
        if not union:
            return 0.0
        return len(s1.intersection(s2)) / len(union)

    def compute_distance(self, f1: BinaryPacketFingerprint, f2: BinaryPacketFingerprint) -> float:
        """Compute structural distance between two packet fingerprints."""
        key = (f1.frame_id, f2.frame_id) if f1.frame_id < f2.frame_id else (f2.frame_id, f1.frame_id)
        if key in self._distance_cache:
            return self._distance_cache[key]

        # 1. Structural Similarity (Jaccard on byte n-grams)
        sim = self.byte_jaccard_similarity(f1.payload_raw, f2.payload_raw)

        # 2. Length difference ratio
        max_len = max(f1.length, f2.length)
        len_diff = abs(f1.length - f2.length) / max_len if max_len > 0 else 0.0

        # 3. Entropy difference ratio
        ent_diff = abs(f1.entropy - f2.entropy) / 8.0

        # 4. Direction mismatch penalty
        dir_penalty = 0.0 if f1.direction == f2.direction else 0.5

        # 5. Prefix match bonus (first 2 bytes)
        prefix_penalty = 0.0 if f1.prefix == f2.prefix else 0.3

        # Combine features into a weighted distance metric
        dist = (
            (1.0 - sim) * 0.4
            + len_diff * 0.2
            + ent_diff * 0.1
            + dir_penalty * 0.2
            + prefix_penalty * 0.1
        )
        res = min(1.0, max(0.0, dist))
        self._distance_cache[key] = res
        return res

    def fingerprint_packet(
        self,
        frame_id: UUID,
        connection_id: UUID,
        direction: Direction,
        timestamp: datetime,
        payload_raw: bytes,
        sha256: str,
    ) -> BinaryPacketFingerprint:
        """Build features for a raw payload."""
        entropy = self.calculate_entropy(payload_raw)
        crc32 = zlib.crc32(payload_raw)
        prefix = payload_raw[:4] if len(payload_raw) >= 4 else payload_raw

        return BinaryPacketFingerprint(
            frame_id=frame_id,
            connection_id=connection_id,
            direction=direction,
            timestamp=timestamp,
            length=len(payload_raw),
            entropy=entropy,
            crc32=crc32,
            prefix=prefix,
            sha256=sha256,
            payload_raw=payload_raw,
        )

    def cluster(self, fingerprints: list[BinaryPacketFingerprint]) -> list[BinaryPacketFamily]:
        """Perform Agglomerative Clustering to group packets into families."""
        if not fingerprints:
            return []

        # Start with each fingerprint in its own cluster
        clusters: list[list[BinaryPacketFingerprint]] = [[fp] for fp in fingerprints]

        while len(clusters) > 1:
            min_dist = float("inf")
            merge_idx = (-1, -1)

            # Find closest pair of clusters (using complete/average linkage)
            for i in range(len(clusters)):
                for j in range(i + 1, len(clusters)):
                    # Average distance between members of clusters i and j
                    dists = [
                        self.compute_distance(fp1, fp2)
                        for fp1 in clusters[i]
                        for fp2 in clusters[j]
                    ]
                    avg_dist = sum(dists) / len(dists)

                    if avg_dist < min_dist:
                        min_dist = avg_dist
                        merge_idx = (i, j)

            # Merge if distance is below threshold
            if min_dist < self.distance_threshold:
                i, j = merge_idx
                clusters[i].extend(clusters[j])
                clusters.pop(j)
            else:
                break

        # Convert clusters to BinaryPacketFamily domain objects
        families: list[BinaryPacketFamily] = []
        for index, cluster_members in enumerate(clusters):
            # Sort cluster members by timestamp
            members = sorted(cluster_members, key=lambda m: m.timestamp)

            # Determine dominant direction
            directions = [m.direction for m in members]
            dominant_dir = max(set(directions), key=directions.count)

            # Common prefix detection (prefix of the first member or most common)
            prefixes = [m.prefix.hex() for m in members if m.prefix]
            common_prefix = (
                max(set(prefixes), key=prefixes.count) if prefixes else ""
            )

            # Length features
            lengths = [m.length for m in members]
            avg_len = sum(lengths) / len(lengths)

            # Entropy features
            avg_entropy = sum(m.entropy for m in members) / len(members)

            # Compute timing intervals
            intervals = []
            for i in range(1, len(members)):
                delta = (members[i].timestamp - members[i - 1].timestamp).total_seconds()
                intervals.append(delta)
            avg_interval = sum(intervals) / len(intervals) if intervals else 0.0

            # Likely Purpose heuristics
            purpose = "Unknown/Unclassified"
            confidence = 0.5
            if len(members) >= 3:
                # Regular small packets
                if avg_len < 32 and avg_interval > 0.0:
                    # check interval variance
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                    cv = (variance ** 0.5) / avg_interval if avg_interval > 0 else float("inf")
                    if cv < 0.3:
                        purpose = "Heartbeat/Keep-alive Ping-Pong"
                        confidence = 0.9
                elif avg_len > 1000:
                    purpose = "Bulk/State Snapshot Update"
                    confidence = 0.75
                elif avg_interval < 2.0 and dominant_dir == Direction.RECEIVED:
                    purpose = "High-frequency Live Market Stream"
                    confidence = 0.8
                else:
                    purpose = "General Control/Data Exchange"
                    confidence = 0.65

            family_id = f"family_{dominant_dir.name.lower()}_{common_prefix[:4] or 'empty'}_{int(avg_len)}b"
            # Ensure unique ID if duplicates occur
            matching_count = sum(1 for f in families if f.id.startswith(family_id))
            if matching_count > 0:
                family_id = f"{family_id}_{matching_count + 1}"

            families.append(
                BinaryPacketFamily(
                    id=family_id,
                    direction=dominant_dir,
                    common_prefix=common_prefix,
                    avg_length=avg_len,
                    count=len(members),
                    avg_interval=avg_interval,
                    entropy=avg_entropy,
                    confidence=confidence,
                    likely_purpose=purpose,
                    fingerprints=members,
                )
            )

        return families
