"""Async SQLAlchemy engine and session factory.

Provides database lifecycle management including creation, connection,
and teardown for the SQLite backend via aiosqlite.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import structlog

from wiretap.storage.schema import Base

logger = structlog.get_logger(__name__)


def build_engine(database_path: Path) -> AsyncEngine:
    """Create an async SQLAlchemy engine for the given SQLite database.

    Args:
        database_path: Path to the SQLite database file.
            The file is created if it does not exist.

    Returns:
        An AsyncEngine connected to the database.
    """
    url = f"sqlite+aiosqlite:///{database_path}"
    engine = create_async_engine(
        url,
        echo=False,
        pool_pre_ping=True,
    )
    return engine


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine.

    Args:
        engine: The AsyncEngine to bind sessions to.

    Returns:
        A factory callable that produces AsyncSession instances.
    """
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def init_database(engine: AsyncEngine) -> None:
    """Create all tables defined in the schema.

    This is idempotent — existing tables are not modified.

    Args:
        engine: The AsyncEngine to create tables on.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await logger.ainfo("database_initialized", tables=list(Base.metadata.tables.keys()))


async def close_database(engine: AsyncEngine) -> None:
    """Dispose of the engine and release all connections.

    Args:
        engine: The AsyncEngine to close.
    """
    await engine.dispose()
    await logger.ainfo("database_closed")
