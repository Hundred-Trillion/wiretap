import pytest
from datetime import datetime, timezone
from uuid import uuid4
from wiretap.core.enums import Direction
from wiretap.analysis.classification import BinaryClusteringEngine


def test_binary_clustering():
    engine = BinaryClusteringEngine(distance_threshold=0.25)

    conn_id = uuid4()
    base_time = datetime.now(timezone.utc)

    # Group A: small sent ping-like packets
    fingerprints = []
    for i in range(5):
        fingerprints.append(
            engine.fingerprint_packet(
                frame_id=uuid4(),
                connection_id=conn_id,
                direction=Direction.SENT,
                timestamp=base_time,
                payload_raw=b"\x01\x02\x03" + bytes([i]),
                sha256=f"sha256-a-{i}",
            )
        )

    # Group B: larger received data-like packets
    for i in range(5):
        fingerprints.append(
            engine.fingerprint_packet(
                frame_id=uuid4(),
                connection_id=conn_id,
                direction=Direction.RECEIVED,
                timestamp=base_time,
                payload_raw=b"\xff\xee\xdd" + b"\x00" * 40 + bytes([i]),
                sha256=f"sha256-b-{i}",
            )
        )

    families = engine.cluster(fingerprints)

    # Should separate them into two distinct families
    assert len(families) == 2

    # Verify counts and properties
    family_a = next(f for f in families if f.direction == Direction.SENT)
    family_b = next(f for f in families if f.direction == Direction.RECEIVED)

    assert family_a.count == 5
    assert family_b.count == 5
    assert family_a.avg_length == 4.0
    assert family_b.avg_length == 44.0
    assert family_a.common_prefix.startswith("010203")
    assert family_b.common_prefix.startswith("ffee")
