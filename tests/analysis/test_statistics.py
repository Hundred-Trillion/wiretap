import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from wiretap.core.enums import ProtocolType, Direction
from wiretap.core.models import Connection, Frame, Payload
from wiretap.analysis.statistics import StatisticsEngine

def test_statistics_computation():
    engine = StatisticsEngine()
    
    conn = Connection(
        id=uuid4(),
        url="https://example.com/api",
        protocol=ProtocolType.HTTP
    )
    
    p1 = Payload(id=uuid4(), raw_bytes=b"sent payload")
    p2 = Payload(id=uuid4(), raw_bytes=b"received payload response")
    
    base_time = datetime.now(timezone.utc)
    
    frames = [
        Frame(
            id=uuid4(),
            connection_id=conn.id,
            direction=Direction.SENT,
            timestamp=base_time,
            payload_id=p1.id,
            sequence=0
        ),
        Frame(
            id=uuid4(),
            connection_id=conn.id,
            direction=Direction.RECEIVED,
            timestamp=base_time + timedelta(seconds=2),
            payload_id=p2.id,
            sequence=1
        )
    ]
    
    payloads = {p1.id: p1, p2.id: p2}
    
    stats = engine.compute(
        [conn], frames, payloads,
        session_start=base_time,
        session_end=base_time + timedelta(seconds=2)
    )
    
    assert stats.total_connections == 1
    assert stats.total_frames == 2
    assert stats.frames_sent == 1
    assert stats.frames_received == 1
    assert stats.total_bytes == len(p1.raw_bytes) + len(p2.raw_bytes)
    assert stats.bytes_sent == len(p1.raw_bytes)
    assert stats.bytes_received == len(p2.raw_bytes)
    assert stats.duration_seconds == 2.0
