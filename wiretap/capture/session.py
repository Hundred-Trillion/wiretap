"""Capture session orchestrator.

Coordinates the BrowserManager, NetworkCapture, and Storage layer
to provide a complete capture workflow with annotation support.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from wiretap.capture.browser import BrowserManager
from wiretap.capture.network import NetworkCapture
from wiretap.core.config import WiretapConfig
from wiretap.core.events import (
    AnnotationAdded,
    CaptureEnded,
    CaptureStarted,
    EventBus,
    FrameCaptured,
)
from wiretap.core.models import Annotation, CaptureSession as CaptureSessionModel
from wiretap.storage.repository import (
    AnnotationRepository,
    ConnectionRepository,
    FrameRepository,
    PayloadRepository,
    SessionRepository,
)

logger = structlog.get_logger(__name__)


class CaptureOrchestrator:
    """Orchestrates a complete capture session.

    Manages the lifecycle of browser → CDP → network capture → storage.
    Provides annotation support during live capture.

    Usage:
        orchestrator = CaptureOrchestrator(config, session_factory, event_bus)
        session_id = await orchestrator.start("https://example.com", name="my_session")
        await orchestrator.annotate("Logged in")
        ...
        await orchestrator.stop()
    """

    def __init__(
        self,
        config: WiretapConfig,
        session_factory: async_sessionmaker[AsyncSession],
        event_bus: EventBus,
    ) -> None:
        self._config = config
        self._session_factory = session_factory
        self._event_bus = event_bus
        self._log = structlog.get_logger(component="CaptureOrchestrator")

        self._browser_manager: BrowserManager | None = None
        self._network_capture: NetworkCapture | None = None
        self._capture_session: CaptureSessionModel | None = None
        self._running = False

    @property
    def session(self) -> CaptureSessionModel | None:
        """The current capture session model."""
        return self._capture_session

    @property
    def is_running(self) -> bool:
        """Whether a capture is currently active."""
        return self._running

    async def start(
        self,
        url: str,
        name: str = "",
        wait_for_load: bool = True,
    ) -> UUID:
        """Start a new capture session.

        Launches the browser, navigates to the URL, enables CDP
        network capture, and begins recording all traffic.

        Args:
            url: The target URL to navigate to.
            name: Human-readable session name.
            wait_for_load: Wait for the page to finish loading.

        Returns:
            The UUID of the created capture session.
        """
        # Create session model
        self._capture_session = CaptureSessionModel(
            name=name or url,
            target_url=url,
        )

        # Persist session
        async with self._session_factory() as db:
            await SessionRepository.create(db, self._capture_session)
            await db.commit()

        # Launch browser
        self._browser_manager = BrowserManager(self._config.browser)
        await self._browser_manager.start()

        # Create page and CDP session
        page = await self._browser_manager.new_page()
        cdp = await self._browser_manager.create_cdp_session(page)

        # Start network capture
        self._network_capture = NetworkCapture(
            cdp=cdp,
            session_id=self._capture_session.id,
            event_bus=self._event_bus,
        )
        await self._network_capture.enable()

        # Navigate to target
        self._running = True
        await self._event_bus.emit(
            CaptureStarted(
                session_id=self._capture_session.id,
                target_url=url,
            )
        )

        self._log.info(
            "capture_started",
            session_id=str(self._capture_session.id),
            url=url,
        )

        if wait_for_load:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception:
                self._log.warning("navigation_timeout", url=url)

        return self._capture_session.id

    async def annotate(self, text: str) -> Annotation:
        """Add a user annotation to the current capture session.

        The annotation is timestamped and will be correlated with
        nearby protocol activity during analysis.

        Args:
            text: The annotation text.

        Returns:
            The created Annotation domain object.

        Raises:
            RuntimeError: If no capture session is active.
        """
        if self._capture_session is None:
            raise RuntimeError("No active capture session.")

        annotation = Annotation(
            session_id=self._capture_session.id,
            text=text,
        )

        async with self._session_factory() as db:
            await AnnotationRepository.create(db, annotation)
            await db.commit()

        await self._event_bus.emit(
            AnnotationAdded(
                annotation_id=annotation.id,
                session_id=self._capture_session.id,
                text=text,
            )
        )

        self._log.info("annotation_added", text=text)
        return annotation

    async def stop(self) -> CaptureSessionModel | None:
        """Stop the capture session and persist all captured data.

        Disables network capture, saves all connections/frames/payloads
        to the database, closes the browser, and marks the session as ended.

        Returns:
            The completed CaptureSession model, or None if not active.
        """
        if not self._running or self._capture_session is None:
            return None

        self._running = False

        # Disable capture
        if self._network_capture:
            await self._network_capture.disable()

        # Persist all captured data
        await self._persist_captured_data()

        # Update session end time
        end_time = datetime.now(timezone.utc)
        self._capture_session.ended_at = end_time
        async with self._session_factory() as db:
            await SessionRepository.update_ended(
                db, self._capture_session.id, end_time
            )
            await db.commit()

        # Emit end event
        await self._event_bus.emit(
            CaptureEnded(session_id=self._capture_session.id)
        )

        # Close browser
        if self._browser_manager:
            await self._browser_manager.stop()
            self._browser_manager = None

        session = self._capture_session
        self._log.info(
            "capture_stopped",
            session_id=str(session.id),
            connections=len(self._network_capture.connections) if self._network_capture else 0,
            frames=len(self._network_capture.frames) if self._network_capture else 0,
        )

        self._network_capture = None
        self._capture_session = None

        return session

    async def _persist_captured_data(self) -> None:
        """Write all captured connections, frames, and payloads to storage."""
        if self._network_capture is None:
            return

        async with self._session_factory() as db:
            # Persist connections
            for conn in self._network_capture.connections:
                await ConnectionRepository.create(db, conn)

            # Persist payloads (with deduplication)
            for payload in self._network_capture.payloads:
                await PayloadRepository.create_or_deduplicate(db, payload)

            # Persist frames
            for frame in self._network_capture.frames:
                await FrameRepository.create(db, frame)

            await db.commit()

        self._log.info(
            "data_persisted",
            connections=len(self._network_capture.connections),
            frames=len(self._network_capture.frames),
            payloads=len(self._network_capture.payloads),
        )
