"""SQLAlchemy ORM schema mapping domain models to SQLite tables.

These ORM models mirror the domain dataclasses in wiretap.core.models
but add persistence concerns (indexes, foreign keys, column types).
The repository layer handles conversion between domain and ORM objects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    Boolean,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


def _uuid_str() -> str:
    """Generate a UUID4 string for use as a primary key."""
    return str(uuid4())


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class SessionRow(Base):
    """ORM model for capture sessions."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    name: Mapped[str] = mapped_column(String(255), default="")
    target_url: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    # Relationships
    connections: Mapped[list[ConnectionRow]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    annotations: Mapped[list[AnnotationRow]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_sessions_started_at", "started_at"),
    )


class ConnectionRow(Base):
    """ORM model for network connections."""

    __tablename__ = "connections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True
    )
    request_id: Mapped[str] = mapped_column(String(255), default="")
    url: Mapped[str] = mapped_column(Text, default="")
    protocol: Mapped[str] = mapped_column(String(20), default="HTTP")
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_headers_json: Mapped[str] = mapped_column(Text, default="{}")
    response_headers_json: Mapped[str] = mapped_column(Text, default="{}")
    initiator: Mapped[str] = mapped_column(Text, default="")
    timing_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    # Relationships
    session: Mapped[SessionRow] = relationship(back_populates="connections")
    frames: Mapped[list[FrameRow]] = relationship(
        back_populates="connection", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_connections_session_id", "session_id"),
        Index("idx_connections_protocol", "protocol"),
        Index("idx_connections_started_at", "started_at"),
    )


class PayloadRow(Base):
    """ORM model for raw payloads."""

    __tablename__ = "payloads"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    raw_bytes: Mapped[bytes] = mapped_column(LargeBinary, default=b"")
    sha256: Mapped[str] = mapped_column(String(64), index=True, default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encoding_detected: Mapped[str | None] = mapped_column(String(50), nullable=True)
    base64_repr: Mapped[str] = mapped_column(Text, default="")
    hex_dump: Mapped[str] = mapped_column(Text, default="")

    # Relationships
    frames: Mapped[list[FrameRow]] = relationship(back_populates="payload")
    decoder_results: Mapped[list[DecoderResultRow]] = relationship(
        back_populates="payload", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_payloads_sha256", "sha256"),
    )


class FrameRow(Base):
    """ORM model for protocol frames."""

    __tablename__ = "frames"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    connection_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("connections.id"), index=True
    )
    direction: Mapped[str] = mapped_column(String(10), default="RECEIVED")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    payload_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("payloads.id"), nullable=True
    )
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    opcode: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_binary: Mapped[bool] = mapped_column(Boolean, default=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    # Relationships
    connection: Mapped[ConnectionRow] = relationship(back_populates="frames")
    payload: Mapped[PayloadRow | None] = relationship(back_populates="frames")

    __table_args__ = (
        Index("idx_frames_connection_id", "connection_id"),
        Index("idx_frames_timestamp", "timestamp"),
        Index("idx_frames_payload_id", "payload_id"),
    )


class DecoderResultRow(Base):
    """ORM model for decoder results."""

    __tablename__ = "decoder_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    payload_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("payloads.id"), index=True
    )
    decoder_name: Mapped[str] = mapped_column(String(100), default="")
    status: Mapped[str] = mapped_column(String(20), default="SKIPPED")
    decoded_data_json: Mapped[str] = mapped_column(Text, default="{}")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    # Relationships
    payload: Mapped[PayloadRow] = relationship(back_populates="decoder_results")

    __table_args__ = (
        Index("idx_decoder_results_payload_id", "payload_id"),
        Index("idx_decoder_results_decoder_name", "decoder_name"),
    )


class AnnotationRow(Base):
    """ORM model for user annotations."""

    __tablename__ = "annotations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    text: Mapped[str] = mapped_column(Text, default="")
    correlated_frame_ids_json: Mapped[str] = mapped_column(Text, default="[]")

    # Relationships
    session: Mapped[SessionRow] = relationship(back_populates="annotations")

    __table_args__ = (
        Index("idx_annotations_session_id", "session_id"),
        Index("idx_annotations_timestamp", "timestamp"),
    )


class ReportRow(Base):
    """ORM model for generated reports."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    report_type: Mapped[str] = mapped_column(String(50), default="")
    title: Mapped[str] = mapped_column(String(255), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)

    __table_args__ = (
        Index("idx_reports_session_id", "session_id"),
    )
