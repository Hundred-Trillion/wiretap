import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from wiretap.core.enums import Direction
from wiretap.core.models import Annotation, Frame
from wiretap.analysis.classification import BinaryPacketFamily, BinaryPacketFingerprint
from wiretap.analysis.correlation import BehaviorCorrelator


def test_behavior_correlation():
    correlator = BehaviorCorrelator(correlation_window_seconds=2.0)

    # Let's create:
    # - 1 Annotation at T=2s ("Asset Change")
    # - Frame A at T=1s (outside window)
    # - Frame B at T=3s (inside window)
    # - Frame C at T=10s (outside window)
    session_id = uuid4()
    conn_id = uuid4()
    base_time = datetime.now(timezone.utc)

    ann = Annotation(
        id=uuid4(),
        session_id=session_id,
        timestamp=base_time + timedelta(seconds=2.0),
        text="Asset Change",
    )

    frame_a = Frame(
        id=uuid4(),
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=base_time + timedelta(seconds=1.0),
        payload_id=uuid4(),
        sequence=0,
    )
    frame_b = Frame(
        id=uuid4(),
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=base_time + timedelta(seconds=3.0),
        payload_id=uuid4(),
        sequence=1,
    )
    frame_c = Frame(
        id=uuid4(),
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=base_time + timedelta(seconds=10.0),
        payload_id=uuid4(),
        sequence=2,
    )

    frames = [frame_a, frame_b, frame_c]

    # Map frame B to our family
    fp_b = BinaryPacketFingerprint(
        frame_id=frame_b.id,
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=frame_b.timestamp,
        length=10,
        entropy=2.0,
        crc32=1,
        prefix=b"\x00",
        sha256="sha-b",
        payload_raw=b"\x00" * 10,
    )

    family = BinaryPacketFamily(
        id="fam_b",
        direction=Direction.SENT,
        common_prefix="0000",
        avg_length=10.0,
        count=1,
        avg_interval=0.0,
        entropy=2.0,
        confidence=0.8,
        likely_purpose="test",
        fingerprints=[fp_b],
    )

    results = correlator.correlate([ann], [family], frames)

    # We should have a result indicating correlation between Asset Change and fam_b
    assert len(results) >= 1
    corr = results[0]
    assert corr.action_text == "asset change"
    assert corr.family_id == "fam_b"
    assert corr.co_occurrences == 1
    assert corr.confidence > 0.0
