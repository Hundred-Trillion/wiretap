import pytest
from uuid import UUID
from wiretap.core.models import CaptureSession, Connection, Payload, Frame
from wiretap.core.enums import ProtocolType, Direction

def test_capture_session_init():
    session = CaptureSession(name="Test Session", target_url="https://example.com")
    assert isinstance(session.id, UUID)
    assert session.name == "Test Session"
    assert session.target_url == "https://example.com"
    assert session.started_at is not None
    assert session.ended_at is None

def test_connection_init():
    session_id = CaptureSession().id
    conn = Connection(
        session_id=session_id,
        url="https://example.com/api",
        protocol=ProtocolType.HTTP,
        method="POST"
    )
    assert isinstance(conn.id, UUID)
    assert conn.session_id == session_id
    assert conn.protocol == ProtocolType.HTTP
    assert conn.method == "POST"

def test_payload_post_init():
    raw = b"hello world"
    payload = Payload(raw_bytes=raw)
    assert payload.size == len(raw)
    # sha256 of "hello world"
    assert payload.sha256 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

def test_frame_init():
    conn_id = Connection().id
    frame = Frame(
        connection_id=conn_id,
        direction=Direction.SENT,
        sequence=1
    )
    assert isinstance(frame.id, UUID)
    assert frame.connection_id == conn_id
    assert frame.direction == Direction.SENT
    assert frame.sequence == 1
