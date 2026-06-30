"""Internal async event bus for decoupled component communication.

Components emit events (e.g., FrameCaptured, ConnectionOpened) and other
components subscribe to handle them. This enables the capture engine,
storage layer, and analysis engine to operate independently.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine
from uuid import UUID

import structlog

from wiretap.core.enums import Direction, ProtocolType

logger = structlog.get_logger(__name__)

# Type alias for async event handlers
EventHandler = Callable[..., Coroutine[Any, Any, None]]


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaptureStarted:
    """Emitted when a capture session begins."""

    session_id: UUID
    target_url: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class CaptureEnded:
    """Emitted when a capture session ends."""

    session_id: UUID
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ConnectionOpened:
    """Emitted when a new network connection is observed."""

    connection_id: UUID
    session_id: UUID
    url: str
    protocol: ProtocolType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ConnectionClosed:
    """Emitted when a network connection is closed."""

    connection_id: UUID
    session_id: UUID
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class FrameCaptured:
    """Emitted when a new protocol frame is captured."""

    frame_id: UUID
    connection_id: UUID
    direction: Direction
    payload_size: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class AnnotationAdded:
    """Emitted when the user adds an annotation."""

    annotation_id: UUID
    session_id: UUID
    text: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Event Bus
# ---------------------------------------------------------------------------


class EventBus:
    """Async event bus supporting publish/subscribe with typed events.

    Events are dispatched to all subscribers of the event's type.
    Subscriber exceptions are caught and logged — a failing subscriber
    never blocks other subscribers or the emitter.

    Usage:
        bus = EventBus()
        bus.subscribe(FrameCaptured, my_handler)
        await bus.emit(FrameCaptured(frame_id=..., ...))
    """

    def __init__(self) -> None:
        self._subscribers: dict[type, list[EventHandler]] = defaultdict(list)
        self._log = structlog.get_logger(component="EventBus")

    def subscribe(self, event_type: type, handler: EventHandler) -> None:
        """Register a handler for a specific event type.

        Args:
            event_type: The event class to subscribe to.
            handler: An async callable that accepts the event as its argument.
        """
        self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: type, handler: EventHandler) -> None:
        """Remove a handler for a specific event type.

        Args:
            event_type: The event class to unsubscribe from.
            handler: The handler to remove.
        """
        handlers = self._subscribers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def emit(self, event: object) -> None:
        """Emit an event to all registered subscribers.

        All subscribers are invoked concurrently via asyncio.gather.
        Exceptions in individual handlers are caught and logged.

        Args:
            event: The event instance to emit.
        """
        event_type = type(event)
        handlers = self._subscribers.get(event_type, [])

        if not handlers:
            return

        tasks = []
        for handler in handlers:
            tasks.append(self._safe_call(handler, event))

        await asyncio.gather(*tasks)

    async def _safe_call(self, handler: EventHandler, event: object) -> None:
        """Invoke a handler, catching and logging any exceptions."""
        try:
            await handler(event)
        except Exception:
            await self._log.aerror(
                "event_handler_failed",
                event_type=type(event).__name__,
                handler=getattr(handler, "__qualname__", str(handler)),
                exc_info=True,
            )

    def clear(self) -> None:
        """Remove all subscribers."""
        self._subscribers.clear()
