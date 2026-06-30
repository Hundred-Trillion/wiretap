import pytest
from datetime import datetime, timezone
from uuid import uuid4

from wiretap.core.enums import ProtocolType, Direction
from wiretap.core.models import CaptureSession, Connection, Payload, Frame
from wiretap.storage.repository import (
    SessionRepository,
    ConnectionRepository,
    PayloadRepository,
    FrameRepository,
)

@pytest.mark.asyncio
async def test_session_repository(db_session):
    session = CaptureSession(name="SQLite Test", target_url="https://localtest.com")
    
    # Create
    await SessionRepository.create(db_session, session)
    await db_session.commit()
    
    # Get
    retrieved = await SessionRepository.get(db_session, session.id)
    assert retrieved is not None
    assert retrieved.name == "SQLite Test"
    assert retrieved.target_url == "https://localtest.com"
    
    # List
    all_sessions = await SessionRepository.list_all(db_session)
    assert len(all_sessions) >= 1
    assert any(s.id == session.id for s in all_sessions)
    
    # Update ended
    now = datetime.now(timezone.utc)
    await SessionRepository.update_ended(db_session, session.id, now)
    await db_session.commit()
    
    updated = await SessionRepository.get(db_session, session.id)
    assert updated.ended_at is not None

@pytest.mark.asyncio
async def test_payload_deduplication(db_session):
    p1 = Payload(raw_bytes=b"duplicate data")
    p2 = Payload(raw_bytes=b"duplicate data")
    
    # Ensure they have identical sha256
    assert p1.sha256 == p2.sha256
    
    saved_p1 = await PayloadRepository.create_or_deduplicate(db_session, p1)
    saved_p2 = await PayloadRepository.create_or_deduplicate(db_session, p2)
    await db_session.commit()
    
    assert saved_p1.id == saved_p2.id
    
    # Retrieve
    retrieved = await PayloadRepository.get(db_session, saved_p1.id)
    assert retrieved is not None
    assert retrieved.raw_bytes == b"duplicate data"
