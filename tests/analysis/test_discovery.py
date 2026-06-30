import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from wiretap.core.enums import ProtocolType, Direction, EventType
from wiretap.core.models import Connection, Frame, Payload
from wiretap.analysis.discovery import ProtocolDiscovery

def test_heartbeat_detection():
    discovery = ProtocolDiscovery()
    session_id = uuid4()
    
    conn = Connection(
        id=uuid4(),
        session_id=session_id,
        url="wss://example.com/ws",
        protocol=ProtocolType.WEBSOCKET
    )
    
    # Generate 5 regular frames spaced by 10 seconds with the same payload
    payload = Payload(id=uuid4(), raw_bytes=b"ping")
    frames = []
    base_time = datetime.now(timezone.utc)
    for i in range(5):
        frames.append(Frame(
            id=uuid4(),
            connection_id=conn.id,
            direction=Direction.SENT,
            timestamp=base_time + timedelta(seconds=10 * i),
            payload_id=payload.id,
            sequence=i
        ))
        
    payloads = {payload.id: payload}
    
    events = discovery.analyze(session_id, [conn], frames, payloads)
    
    heartbeat_events = [e for e in events if e.event_type == EventType.HEARTBEAT]
    assert len(heartbeat_events) == 1
    assert heartbeat_events[0].confidence > 0.7
    assert "ping" in heartbeat_events[0].description or "heartbeat" in heartbeat_events[0].description.lower()
