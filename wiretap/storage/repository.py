"""Repository pattern for async database operations.

Provides typed CRUD operations that convert between domain dataclasses
and ORM rows. All methods accept an AsyncSession and operate within
the caller's transaction boundary.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

import structlog

from wiretap.core.enums import DecoderStatus, Direction, ProtocolType
from wiretap.core.models import (
    Annotation,
    CaptureSession,
    Connection,
    DecoderResult,
    Frame,
    Payload,
    TimingInfo,
)
from wiretap.storage.schema import (
    AnnotationRow,
    ConnectionRow,
    DecoderResultRow,
    FrameRow,
    PayloadRow,
    SessionRow,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------


def _uuid_to_str(u: UUID) -> str:
    return str(u)


def _str_to_uuid(s: str) -> UUID:
    return UUID(s)


def _dt_or_none(dt: datetime | None) -> datetime | None:
    return dt


# ---------------------------------------------------------------------------
# SessionRepository
# ---------------------------------------------------------------------------


class SessionRepository:
    """CRUD operations for capture sessions."""

    @staticmethod
    async def create(session: AsyncSession, capture: CaptureSession) -> SessionRow:
        """Persist a new CaptureSession."""
        row = SessionRow(
            id=_uuid_to_str(capture.id),
            name=capture.name,
            target_url=capture.target_url,
            started_at=capture.started_at,
            ended_at=capture.ended_at,
            metadata_json=json.dumps(capture.metadata, default=str),
        )
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def get(session: AsyncSession, session_id: UUID) -> CaptureSession | None:
        """Retrieve a CaptureSession by ID."""
        result = await session.execute(
            select(SessionRow).where(SessionRow.id == str(session_id))
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return CaptureSession(
            id=_str_to_uuid(row.id),
            name=row.name,
            target_url=row.target_url,
            started_at=row.started_at,
            ended_at=row.ended_at,
            metadata=json.loads(row.metadata_json),
        )

    @staticmethod
    async def list_all(session: AsyncSession) -> list[CaptureSession]:
        """List all capture sessions ordered by start time descending."""
        result = await session.execute(
            select(SessionRow).order_by(SessionRow.started_at.desc())
        )
        rows = result.scalars().all()
        return [
            CaptureSession(
                id=_str_to_uuid(r.id),
                name=r.name,
                target_url=r.target_url,
                started_at=r.started_at,
                ended_at=r.ended_at,
                metadata=json.loads(r.metadata_json),
            )
            for r in rows
        ]

    @staticmethod
    async def update_ended(
        session: AsyncSession, session_id: UUID, ended_at: datetime
    ) -> None:
        """Mark a session as ended."""
        result = await session.execute(
            select(SessionRow).where(SessionRow.id == str(session_id))
        )
        row = result.scalar_one_or_none()
        if row:
            row.ended_at = ended_at
            await session.flush()


# ---------------------------------------------------------------------------
# ConnectionRepository
# ---------------------------------------------------------------------------


class ConnectionRepository:
    """CRUD operations for network connections."""

    @staticmethod
    async def create(session: AsyncSession, conn: Connection) -> ConnectionRow:
        """Persist a new Connection."""
        row = ConnectionRow(
            id=_uuid_to_str(conn.id),
            session_id=_uuid_to_str(conn.session_id),
            request_id=conn.request_id,
            url=conn.url,
            protocol=conn.protocol.name,
            method=conn.method,
            status_code=conn.status_code,
            request_headers_json=json.dumps(conn.request_headers),
            response_headers_json=json.dumps(conn.response_headers),
            initiator=conn.initiator,
            timing_json=json.dumps(asdict(conn.timing)),
            started_at=conn.started_at,
            ended_at=conn.ended_at,
            metadata_json=json.dumps(conn.metadata, default=str),
        )
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def get(session: AsyncSession, conn_id: UUID) -> Connection | None:
        """Retrieve a Connection by ID."""
        result = await session.execute(
            select(ConnectionRow).where(ConnectionRow.id == str(conn_id))
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        timing_data = json.loads(row.timing_json)
        return Connection(
            id=_str_to_uuid(row.id),
            session_id=_str_to_uuid(row.session_id),
            request_id=row.request_id,
            url=row.url,
            protocol=ProtocolType[row.protocol],
            method=row.method,
            status_code=row.status_code,
            request_headers=json.loads(row.request_headers_json),
            response_headers=json.loads(row.response_headers_json),
            initiator=row.initiator,
            timing=TimingInfo(**timing_data),
            started_at=row.started_at,
            ended_at=row.ended_at,
            metadata=json.loads(row.metadata_json),
        )

    @staticmethod
    async def list_by_session(
        session: AsyncSession, session_id: UUID
    ) -> list[Connection]:
        """List all connections for a session."""
        result = await session.execute(
            select(ConnectionRow)
            .where(ConnectionRow.session_id == str(session_id))
            .order_by(ConnectionRow.started_at)
        )
        rows = result.scalars().all()
        connections = []
        for row in rows:
            timing_data = json.loads(row.timing_json)
            connections.append(
                Connection(
                    id=_str_to_uuid(row.id),
                    session_id=_str_to_uuid(row.session_id),
                    request_id=row.request_id,
                    url=row.url,
                    protocol=ProtocolType[row.protocol],
                    method=row.method,
                    status_code=row.status_code,
                    request_headers=json.loads(row.request_headers_json),
                    response_headers=json.loads(row.response_headers_json),
                    initiator=row.initiator,
                    timing=TimingInfo(**timing_data),
                    started_at=row.started_at,
                    ended_at=row.ended_at,
                    metadata=json.loads(row.metadata_json),
                )
            )
        return connections

    @staticmethod
    async def update_response(
        session: AsyncSession,
        conn_id: UUID,
        status_code: int,
        response_headers: dict[str, str],
    ) -> None:
        """Update connection with response data."""
        result = await session.execute(
            select(ConnectionRow).where(ConnectionRow.id == str(conn_id))
        )
        row = result.scalar_one_or_none()
        if row:
            row.status_code = status_code
            row.response_headers_json = json.dumps(response_headers)
            await session.flush()


# ---------------------------------------------------------------------------
# PayloadRepository
# ---------------------------------------------------------------------------


class PayloadRepository:
    """CRUD operations for payloads with deduplication."""

    @staticmethod
    async def create(session: AsyncSession, payload: Payload) -> PayloadRow:
        """Persist a new Payload."""
        row = PayloadRow(
            id=_uuid_to_str(payload.id),
            raw_bytes=payload.raw_bytes,
            sha256=payload.sha256,
            size=payload.size,
            content_type=payload.content_type,
            encoding_detected=payload.encoding_detected,
            base64_repr=payload.base64 or base64.b64encode(payload.raw_bytes).decode(),
            hex_dump=payload.hex_dump or payload.raw_bytes[:512].hex(),
        )
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def get_by_sha256(
        session: AsyncSession, sha256: str
    ) -> Payload | None:
        """Retrieve a Payload by SHA256 hash for deduplication."""
        result = await session.execute(
            select(PayloadRow).where(PayloadRow.sha256 == sha256)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return Payload(
            id=_str_to_uuid(row.id),
            raw_bytes=row.raw_bytes,
            sha256=row.sha256,
            size=row.size,
            content_type=row.content_type,
            encoding_detected=row.encoding_detected,
            base64=row.base64_repr,
            hex_dump=row.hex_dump,
        )

    @staticmethod
    async def get(session: AsyncSession, payload_id: UUID) -> Payload | None:
        """Retrieve a Payload by ID."""
        result = await session.execute(
            select(PayloadRow).where(PayloadRow.id == str(payload_id))
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return Payload(
            id=_str_to_uuid(row.id),
            raw_bytes=row.raw_bytes,
            sha256=row.sha256,
            size=row.size,
            content_type=row.content_type,
            encoding_detected=row.encoding_detected,
            base64=row.base64_repr,
            hex_dump=row.hex_dump,
        )

    @staticmethod
    async def create_or_deduplicate(
        session: AsyncSession, payload: Payload
    ) -> Payload:
        """Create a payload or return existing if SHA256 matches."""
        existing = await PayloadRepository.get_by_sha256(session, payload.sha256)
        if existing:
            return existing
        await PayloadRepository.create(session, payload)
        return payload


# ---------------------------------------------------------------------------
# FrameRepository
# ---------------------------------------------------------------------------


class FrameRepository:
    """CRUD operations for protocol frames."""

    @staticmethod
    async def create(session: AsyncSession, frame: Frame) -> FrameRow:
        """Persist a new Frame."""
        row = FrameRow(
            id=_uuid_to_str(frame.id),
            connection_id=_uuid_to_str(frame.connection_id),
            direction=frame.direction.name,
            timestamp=frame.timestamp,
            payload_id=_uuid_to_str(frame.payload_id) if frame.payload_id else None,
            sequence=frame.sequence,
            opcode=frame.opcode,
            is_binary=frame.is_binary,
            metadata_json=json.dumps(frame.metadata, default=str),
        )
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def list_by_connection(
        session: AsyncSession, connection_id: UUID
    ) -> list[Frame]:
        """List all frames for a connection in sequence order."""
        result = await session.execute(
            select(FrameRow)
            .where(FrameRow.connection_id == str(connection_id))
            .order_by(FrameRow.sequence)
        )
        rows = result.scalars().all()
        return [
            Frame(
                id=_str_to_uuid(r.id),
                connection_id=_str_to_uuid(r.connection_id),
                direction=Direction[r.direction],
                timestamp=r.timestamp,
                payload_id=_str_to_uuid(r.payload_id) if r.payload_id else None,
                sequence=r.sequence,
                opcode=r.opcode,
                is_binary=r.is_binary,
                metadata=json.loads(r.metadata_json),
            )
            for r in rows
        ]

    @staticmethod
    async def count_by_session(session: AsyncSession, session_id: UUID) -> int:
        """Count total frames in a session."""
        result = await session.execute(
            select(func.count(FrameRow.id))
            .join(ConnectionRow)
            .where(ConnectionRow.session_id == str(session_id))
        )
        return result.scalar_one()

    @staticmethod
    async def list_by_session(
        session: AsyncSession,
        session_id: UUID,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[Frame]:
        """List frames across all connections in a session."""
        result = await session.execute(
            select(FrameRow)
            .join(ConnectionRow)
            .where(ConnectionRow.session_id == str(session_id))
            .order_by(FrameRow.timestamp)
            .limit(limit)
            .offset(offset)
        )
        rows = result.scalars().all()
        return [
            Frame(
                id=_str_to_uuid(r.id),
                connection_id=_str_to_uuid(r.connection_id),
                direction=Direction[r.direction],
                timestamp=r.timestamp,
                payload_id=_str_to_uuid(r.payload_id) if r.payload_id else None,
                sequence=r.sequence,
                opcode=r.opcode,
                is_binary=r.is_binary,
                metadata=json.loads(r.metadata_json),
            )
            for r in rows
        ]


# ---------------------------------------------------------------------------
# DecoderResultRepository
# ---------------------------------------------------------------------------


class DecoderResultRepository:
    """CRUD operations for decoder results."""

    @staticmethod
    async def create(
        session: AsyncSession, result: DecoderResult
    ) -> DecoderResultRow:
        """Persist a decoder result."""
        row = DecoderResultRow(
            id=_uuid_to_str(result.id),
            payload_id=_uuid_to_str(result.payload_id),
            decoder_name=result.decoder_name,
            status=result.status.name,
            decoded_data_json=json.dumps(result.decoded_data, default=str),
            confidence=result.confidence,
            error=result.error,
            metadata_json=json.dumps(result.metadata, default=str),
        )
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def list_by_payload(
        session: AsyncSession, payload_id: UUID
    ) -> list[DecoderResult]:
        """List all decoder results for a payload."""
        result = await session.execute(
            select(DecoderResultRow)
            .where(DecoderResultRow.payload_id == str(payload_id))
            .order_by(DecoderResultRow.confidence.desc())
        )
        rows = result.scalars().all()
        return [
            DecoderResult(
                id=_str_to_uuid(r.id),
                payload_id=_str_to_uuid(r.payload_id),
                decoder_name=r.decoder_name,
                status=DecoderStatus[r.status],
                decoded_data=json.loads(r.decoded_data_json),
                confidence=r.confidence,
                error=r.error,
                metadata=json.loads(r.metadata_json),
            )
            for r in rows
        ]


# ---------------------------------------------------------------------------
# AnnotationRepository
# ---------------------------------------------------------------------------


class AnnotationRepository:
    """CRUD operations for user annotations."""

    @staticmethod
    async def create(
        session: AsyncSession, annotation: Annotation
    ) -> AnnotationRow:
        """Persist a new Annotation."""
        row = AnnotationRow(
            id=_uuid_to_str(annotation.id),
            session_id=_uuid_to_str(annotation.session_id),
            timestamp=annotation.timestamp,
            text=annotation.text,
            correlated_frame_ids_json=json.dumps(
                [str(fid) for fid in annotation.correlated_frame_ids]
            ),
        )
        session.add(row)
        await session.flush()
        return row

    @staticmethod
    async def list_by_session(
        session: AsyncSession, session_id: UUID
    ) -> list[Annotation]:
        """List all annotations for a session."""
        result = await session.execute(
            select(AnnotationRow)
            .where(AnnotationRow.session_id == str(session_id))
            .order_by(AnnotationRow.timestamp)
        )
        rows = result.scalars().all()
        return [
            Annotation(
                id=_str_to_uuid(r.id),
                session_id=_str_to_uuid(r.session_id),
                timestamp=r.timestamp,
                text=r.text,
                correlated_frame_ids=[
                    UUID(fid) for fid in json.loads(r.correlated_frame_ids_json)
                ],
            )
            for r in rows
        ]
