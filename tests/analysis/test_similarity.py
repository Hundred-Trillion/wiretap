import pytest
import struct
from datetime import datetime, timezone
from uuid import uuid4
from wiretap.core.enums import Direction
from wiretap.analysis.classification import BinaryPacketFamily, BinaryPacketFingerprint
from wiretap.analysis.similarity import SimilarityEngine, PriceCandidateDetector


def test_similarity_classification():
    # 1. Identical payloads
    conn_id = uuid4()
    base_time = datetime.now(timezone.utc)
    raw_payload = b"\x01\x02\x03\x04"
    fps_identical = [
        BinaryPacketFingerprint(
            frame_id=uuid4(),
            connection_id=conn_id,
            direction=Direction.SENT,
            timestamp=base_time,
            length=4,
            entropy=1.0,
            crc32=1,
            prefix=b"\x01\x02",
            sha256="sha-1",
            payload_raw=raw_payload,
        )
        for _ in range(5)
    ]
    fam_identical = BinaryPacketFamily(
        id="fam_ident",
        direction=Direction.SENT,
        common_prefix="0102",
        avg_length=4.0,
        count=5,
        avg_interval=1.0,
        entropy=1.0,
        confidence=0.8,
        likely_purpose="test",
        fingerprints=fps_identical,
    )
    res_ident = SimilarityEngine.analyze_similarity(fam_identical)
    assert res_ident["relationship"] == "identical"

    # 2. Snapshot vs Delta
    fps_snapshot_delta = []
    # 1 large snapshot (100 bytes)
    fps_snapshot_delta.append(
        BinaryPacketFingerprint(
            frame_id=uuid4(),
            connection_id=conn_id,
            direction=Direction.RECEIVED,
            timestamp=base_time,
            length=100,
            entropy=1.0,
            crc32=1,
            prefix=b"\x01\x02",
            sha256="sha-large",
            payload_raw=b"\x00" * 100,
        )
    )
    # 4 small deltas (10 bytes)
    for i in range(4):
        fps_snapshot_delta.append(
            BinaryPacketFingerprint(
                frame_id=uuid4(),
                connection_id=conn_id,
                direction=Direction.RECEIVED,
                timestamp=base_time,
                length=10,
                entropy=1.0,
                crc32=1,
                prefix=b"\x01\x02",
                sha256=f"sha-delta-{i}",
                payload_raw=b"\x00" * 10,
            )
        )
    fam_snap = BinaryPacketFamily(
        id="fam_snap",
        direction=Direction.RECEIVED,
        common_prefix="0000",
        avg_length=28.0,
        count=5,
        avg_interval=1.0,
        entropy=1.0,
        confidence=0.8,
        likely_purpose="test",
        fingerprints=fps_snapshot_delta,
    )
    res_snap = SimilarityEngine.analyze_similarity(fam_snap)
    assert res_snap["relationship"] == "snapshot_delta"


def test_price_candidate_detector():
    detector = PriceCandidateDetector(min_price=10.0, max_price=150.0)

    # Encode a price sequence in packets
    # E.g. floating price starting at 100.5, fluctuating slightly (100.5, 100.6, 100.4, 100.7, 100.5)
    prices = [100.5, 100.6, 100.4, 100.7, 100.5]
    fps = []
    base_time = datetime.now(timezone.utc)
    conn_id = uuid4()

    for i, price in enumerate(prices):
        # Let's write the price as float64 BE at offset 0
        payload = struct.pack(">d", price)
        fps.append(
            BinaryPacketFingerprint(
                frame_id=uuid4(),
                connection_id=conn_id,
                direction=Direction.RECEIVED,
                timestamp=base_time,
                length=len(payload),
                entropy=3.0,
                crc32=12,
                prefix=payload[:4],
                sha256=f"sha-{i}",
                payload_raw=payload,
            )
        )

    family = BinaryPacketFamily(
        id="fam_price",
        direction=Direction.RECEIVED,
        common_prefix="4059",
        avg_length=8.0,
        count=5,
        avg_interval=1.0,
        entropy=3.0,
        confidence=0.9,
        likely_purpose="test",
        fingerprints=fps,
    )

    candidates = detector.detect_prices(family)
    assert len(candidates) >= 1
    best_cand = candidates[0]
    assert best_cand.offset == 0
    assert best_cand.size == 8
    assert best_cand.value_type == "float64"
    assert best_cand.endianness == "BE"
    assert best_cand.confidence > 0.5
