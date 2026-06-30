import pytest
import struct
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from wiretap.core.enums import ProtocolType, Direction
from wiretap.core.models import CaptureSession, Connection, Payload, Frame, Annotation
from wiretap.storage.repository import (
    SessionRepository,
    ConnectionRepository,
    PayloadRepository,
    FrameRepository,
    AnnotationRepository,
)
from wiretap.validators.price_validator import PriceValidator


@pytest.mark.asyncio
async def test_price_validator_alignment_and_score(db_session):
    # 1. Setup session
    session = CaptureSession(name="Validator Test", target_url="https://test.com")
    await SessionRepository.create(db_session, session)
    
    # 2. Setup connection
    conn = Connection(
        session_id=session.id,
        protocol=ProtocolType.WEBSOCKET,
        url="wss://test.com/stream",
        initiator="script",
    )
    await ConnectionRepository.create(db_session, conn)
    await db_session.commit()

    # 3. Create mock prices & frames
    mock_prices = [57300.0, 57300.5, 57301.2, 57300.8, 57302.1]
    base_time = datetime.now(timezone.utc)

    for i, price in enumerate(mock_prices):
        t_frame = base_time + timedelta(seconds=i * 2)
        # Encode price as double float Big-Endian at offset 4
        payload_data = b"HEAD" + struct.pack(">d", price)
        payload = Payload(raw_bytes=payload_data)
        
        saved_p = await PayloadRepository.create_or_deduplicate(db_session, payload)
        
        frame = Frame(
            connection_id=conn.id,
            direction=Direction.RECEIVED,
            timestamp=t_frame,
            payload_id=saved_p.id,
            sequence=i,
        )
        await FrameRepository.create(db_session, frame)

        # Log visible price annotation slightly offset by 10ms
        t_ann = t_frame + timedelta(milliseconds=10)
        annotation = Annotation(
            session_id=session.id,
            text=f"visible_price:{price}",
            timestamp=t_ann,
        )
        await AnnotationRepository.create(db_session, annotation)

    await db_session.commit()

    # 4. Validate correct configuration
    validator = PriceValidator(max_time_diff_seconds=0.5)
    report = await validator.validate_candidate(
        db=db_session,
        session_id=session.id,
        family_id="mock_family",
        offset=4,
        size=8,
        endianness="BE",
        value_type="float64",
        scale_factor=1.0,
    )

    assert report.is_valid is True
    assert report.correlation > 0.99
    assert report.avg_relative_error < 0.0001
    assert report.match_count == 5
    assert report.score >= 95
    assert report.score_breakdown["correlation_score"] == 40
    assert report.score_breakdown["error_score"] == 30

    # 5. Validate incorrect endianness (should fail/reject)
    bad_report = await validator.validate_candidate(
        db=db_session,
        session_id=session.id,
        family_id="mock_family",
        offset=4,
        size=8,
        endianness="LE",  # wrong
        value_type="float64",
        scale_factor=1.0,
    )
    assert bad_report.is_valid is False
    assert bad_report.correlation < 0.9  # Corrupt values won't correlate
