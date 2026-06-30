"""Network traffic capture via Chrome DevTools Protocol.

This is the heart of Wiretap. It hooks into CDP Network domain events
to capture every HTTP request, response, WebSocket frame, and SSE event
with full payload preservation and timing information.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import structlog
from playwright.async_api import CDPSession

from wiretap.core.enums import Direction, ProtocolType
from wiretap.core.events import (
    ConnectionClosed,
    ConnectionOpened,
    EventBus,
    FrameCaptured,
)
from wiretap.core.models import Connection, Frame, Payload, TimingInfo


logger = structlog.get_logger(__name__)


class NetworkCapture:
    """Captures all network traffic via CDP Network domain events.

    Subscribes to CDP events for HTTP, WebSocket, and SSE traffic.
    Constructs domain model objects and emits events via the EventBus
    for downstream storage and analysis.

    Usage:
        capture = NetworkCapture(cdp_session, session_id, event_bus)
        await capture.enable()
        # ... browser navigates and traffic flows ...
        await capture.disable()
        # Access captured data via capture.connections, capture.frames, etc.
    """

    def __init__(
        self,
        cdp: CDPSession,
        session_id: UUID,
        event_bus: EventBus,
    ) -> None:
        self._cdp = cdp
        self._session_id = session_id
        self._event_bus = event_bus
        self._log = structlog.get_logger(component="NetworkCapture")

        # State tracking
        self._connections: dict[str, Connection] = {}  # request_id -> Connection
        self._ws_connections: dict[str, Connection] = {}  # request_id -> WS Connection
        self._frames: list[Frame] = []
        self._payloads: list[Payload] = []
        self._frame_sequences: dict[str, int] = {}  # connection request_id -> seq counter

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def enable(self) -> None:
        """Enable CDP Network domain and subscribe to all events."""
        await self._cdp.send("Network.enable", {
            "maxTotalBufferSize": 100 * 1024 * 1024,  # 100MB buffer
            "maxResourceBufferSize": 10 * 1024 * 1024,  # 10MB per resource
        })

        # HTTP events
        self._cdp.on("Network.requestWillBeSent", self._on_request)
        self._cdp.on("Network.responseReceived", self._on_response)
        self._cdp.on("Network.loadingFinished", self._on_loading_finished)
        self._cdp.on("Network.loadingFailed", self._on_loading_failed)

        # WebSocket events
        self._cdp.on("Network.webSocketCreated", self._on_ws_created)
        self._cdp.on(
            "Network.webSocketHandshakeResponseReceived",
            self._on_ws_handshake,
        )
        self._cdp.on("Network.webSocketFrameSent", self._on_ws_frame_sent)
        self._cdp.on("Network.webSocketFrameReceived", self._on_ws_frame_received)
        self._cdp.on("Network.webSocketClosed", self._on_ws_closed)

        # SSE events
        self._cdp.on(
            "Network.eventSourceMessageReceived",
            self._on_sse_message,
        )

        await self._log.ainfo("network_capture_enabled")

    async def disable(self) -> None:
        """Disable CDP Network domain."""
        try:
            await self._cdp.send("Network.disable")
        except Exception:
            pass  # Browser may already be closed
        await self._log.ainfo("network_capture_disabled")

    @property
    def connections(self) -> list[Connection]:
        """All captured connections (HTTP + WebSocket)."""
        return list(self._connections.values()) + list(self._ws_connections.values())

    @property
    def frames(self) -> list[Frame]:
        """All captured frames."""
        return list(self._frames)

    @property
    def payloads(self) -> list[Payload]:
        """All captured payloads."""
        return list(self._payloads)

    # -----------------------------------------------------------------------
    # HTTP Event Handlers
    # -----------------------------------------------------------------------

    def _on_request(self, params: dict[str, Any]) -> None:
        """Handle Network.requestWillBeSent — capture request metadata."""
        try:
            request = params.get("request", {})
            request_id = params.get("requestId", "")
            initiator = params.get("initiator", {})
            timestamp = params.get("wallTime", 0)

            # Determine protocol type from resource type
            resource_type = params.get("type", "Other")
            if resource_type == "Fetch":
                protocol = ProtocolType.FETCH
            elif resource_type == "XHR":
                protocol = ProtocolType.XHR
            else:
                protocol = ProtocolType.HTTP

            conn = Connection(
                id=uuid4(),
                session_id=self._session_id,
                request_id=request_id,
                url=request.get("url", ""),
                protocol=protocol,
                method=request.get("method"),
                request_headers=dict(request.get("headers", {})),
                initiator=self._format_initiator(initiator),
                started_at=self._wall_time_to_datetime(timestamp),
            )

            self._connections[request_id] = conn
            self._frame_sequences[request_id] = 0

            # Create a request frame with the post data if present
            post_data = request.get("postData")
            if post_data:
                payload = self._create_payload(post_data.encode("utf-8"))
                frame = Frame(
                    id=uuid4(),
                    connection_id=conn.id,
                    direction=Direction.SENT,
                    timestamp=conn.started_at,
                    payload_id=payload.id,
                    sequence=self._next_sequence(request_id),
                    is_binary=False,
                )
                self._frames.append(frame)
                self._payloads.append(payload)

        except Exception:
            # Never let a handler crash terminate capture
            self._log.error("request_handler_failed", exc_info=True)

    def _on_response(self, params: dict[str, Any]) -> None:
        """Handle Network.responseReceived — capture response metadata."""
        try:
            request_id = params.get("requestId", "")
            response = params.get("response", {})

            conn = self._connections.get(request_id)
            if conn is None:
                return

            conn.status_code = response.get("status")
            conn.response_headers = dict(response.get("headers", {}))

            # Parse timing info if available
            timing = response.get("timing")
            if timing:
                conn.timing = TimingInfo(
                    dns_start=timing.get("dnsStart", -1.0),
                    dns_end=timing.get("dnsEnd", -1.0),
                    connect_start=timing.get("connectStart", -1.0),
                    connect_end=timing.get("connectEnd", -1.0),
                    ssl_start=timing.get("sslStart", -1.0),
                    ssl_end=timing.get("sslEnd", -1.0),
                    send_start=timing.get("sendStart", -1.0),
                    send_end=timing.get("sendEnd", -1.0),
                    receive_start=timing.get("receiveHeadersStart", -1.0),
                    receive_end=timing.get("receiveHeadersEnd", -1.0),
                )

        except Exception:
            self._log.error("response_handler_failed", exc_info=True)

    def _on_loading_finished(self, params: dict[str, Any]) -> None:
        """Handle Network.loadingFinished — fetch response body."""
        try:
            request_id = params.get("requestId", "")
            conn = self._connections.get(request_id)
            if conn is None:
                return

            conn.ended_at = datetime.now(timezone.utc)

            # Schedule async body retrieval
            import asyncio
            asyncio.ensure_future(self._fetch_response_body(request_id, conn))

        except Exception:
            self._log.error("loading_finished_handler_failed", exc_info=True)

    def _on_loading_failed(self, params: dict[str, Any]) -> None:
        """Handle Network.loadingFailed — mark connection as failed."""
        try:
            request_id = params.get("requestId", "")
            conn = self._connections.get(request_id)
            if conn is None:
                return
            conn.ended_at = datetime.now(timezone.utc)
            conn.metadata["error"] = params.get("errorText", "Unknown error")
            conn.metadata["canceled"] = params.get("canceled", False)
        except Exception:
            self._log.error("loading_failed_handler_failed", exc_info=True)

    async def _fetch_response_body(
        self, request_id: str, conn: Connection
    ) -> None:
        """Fetch the response body via CDP and store as a payload."""
        try:
            result = await self._cdp.send(
                "Network.getResponseBody",
                {"requestId": request_id},
            )
            body = result.get("body", "")
            base64_encoded = result.get("base64Encoded", False)

            if body:
                if base64_encoded:
                    raw = base64.b64decode(body)
                else:
                    raw = body.encode("utf-8")

                payload = self._create_payload(
                    raw,
                    content_type=conn.response_headers.get("content-type"),
                )
                frame = Frame(
                    id=uuid4(),
                    connection_id=conn.id,
                    direction=Direction.RECEIVED,
                    timestamp=conn.ended_at or datetime.now(timezone.utc),
                    payload_id=payload.id,
                    sequence=self._next_sequence(request_id),
                    is_binary=base64_encoded,
                )
                self._frames.append(frame)
                self._payloads.append(payload)

                await self._event_bus.emit(
                    FrameCaptured(
                        frame_id=frame.id,
                        connection_id=conn.id,
                        direction=Direction.RECEIVED,
                        payload_size=payload.size,
                    )
                )

        except Exception:
            # Response body may not be available (e.g., redirects)
            await self._log.adebug(
                "response_body_unavailable", request_id=request_id
            )

    # -----------------------------------------------------------------------
    # WebSocket Event Handlers
    # -----------------------------------------------------------------------

    def _on_ws_created(self, params: dict[str, Any]) -> None:
        """Handle Network.webSocketCreated — track new WS connection."""
        try:
            request_id = params.get("requestId", "")
            url = params.get("url", "")

            conn = Connection(
                id=uuid4(),
                session_id=self._session_id,
                request_id=request_id,
                url=url,
                protocol=ProtocolType.WEBSOCKET,
                started_at=datetime.now(timezone.utc),
            )
            self._ws_connections[request_id] = conn
            self._frame_sequences[request_id] = 0

            import asyncio
            asyncio.ensure_future(
                self._event_bus.emit(
                    ConnectionOpened(
                        connection_id=conn.id,
                        session_id=self._session_id,
                        url=url,
                        protocol=ProtocolType.WEBSOCKET,
                    )
                )
            )

        except Exception:
            self._log.error("ws_created_handler_failed", exc_info=True)

    def _on_ws_handshake(self, params: dict[str, Any]) -> None:
        """Handle WebSocket handshake response."""
        try:
            request_id = params.get("requestId", "")
            response = params.get("response", {})
            conn = self._ws_connections.get(request_id)
            if conn is None:
                return

            conn.status_code = response.get("status")
            conn.response_headers = dict(response.get("headers", {}))
            conn.metadata["handshake_headers"] = response.get("headersText", "")

        except Exception:
            self._log.error("ws_handshake_handler_failed", exc_info=True)

    def _on_ws_frame_sent(self, params: dict[str, Any]) -> None:
        """Handle Network.webSocketFrameSent — capture outgoing WS frame."""
        self._handle_ws_frame(params, Direction.SENT)

    def _on_ws_frame_received(self, params: dict[str, Any]) -> None:
        """Handle Network.webSocketFrameReceived — capture incoming WS frame."""
        self._handle_ws_frame(params, Direction.RECEIVED)

    def _handle_ws_frame(
        self, params: dict[str, Any], direction: Direction
    ) -> None:
        """Common handler for sent and received WS frames."""
        try:
            request_id = params.get("requestId", "")
            response = params.get("response", {})
            payload_data = response.get("payloadData", "")
            opcode = response.get("opcode", 1)

            conn = self._ws_connections.get(request_id)
            if conn is None:
                return

            is_binary = opcode == 2

            if is_binary:
                try:
                    raw = base64.b64decode(payload_data)
                except Exception:
                    raw = payload_data.encode("utf-8")
            else:
                raw = payload_data.encode("utf-8")

            payload = self._create_payload(raw)
            frame = Frame(
                id=uuid4(),
                connection_id=conn.id,
                direction=direction,
                timestamp=datetime.now(timezone.utc),
                payload_id=payload.id,
                sequence=self._next_sequence(request_id),
                opcode=opcode,
                is_binary=is_binary,
            )
            self._frames.append(frame)
            self._payloads.append(payload)

            import asyncio
            asyncio.ensure_future(
                self._event_bus.emit(
                    FrameCaptured(
                        frame_id=frame.id,
                        connection_id=conn.id,
                        direction=direction,
                        payload_size=payload.size,
                    )
                )
            )

        except Exception:
            self._log.error("ws_frame_handler_failed", exc_info=True)

    def _on_ws_closed(self, params: dict[str, Any]) -> None:
        """Handle Network.webSocketClosed — mark WS connection as closed."""
        try:
            request_id = params.get("requestId", "")
            conn = self._ws_connections.get(request_id)
            if conn is None:
                return

            conn.ended_at = datetime.now(timezone.utc)

            import asyncio
            asyncio.ensure_future(
                self._event_bus.emit(
                    ConnectionClosed(
                        connection_id=conn.id,
                        session_id=self._session_id,
                    )
                )
            )

        except Exception:
            self._log.error("ws_closed_handler_failed", exc_info=True)

    # -----------------------------------------------------------------------
    # SSE Event Handler
    # -----------------------------------------------------------------------

    def _on_sse_message(self, params: dict[str, Any]) -> None:
        """Handle Network.eventSourceMessageReceived — capture SSE event."""
        try:
            request_id = params.get("requestId", "")
            event_name = params.get("eventName", "")
            event_id = params.get("eventId", "")
            data = params.get("data", "")

            # Find or create SSE connection
            conn = self._connections.get(request_id)
            if conn:
                conn.protocol = ProtocolType.SSE

            if conn is None:
                conn = Connection(
                    id=uuid4(),
                    session_id=self._session_id,
                    request_id=request_id,
                    protocol=ProtocolType.SSE,
                    started_at=datetime.now(timezone.utc),
                )
                self._connections[request_id] = conn
                self._frame_sequences[request_id] = 0

            raw = data.encode("utf-8")
            payload = self._create_payload(raw)
            frame = Frame(
                id=uuid4(),
                connection_id=conn.id,
                direction=Direction.RECEIVED,
                timestamp=datetime.now(timezone.utc),
                payload_id=payload.id,
                sequence=self._next_sequence(request_id),
                is_binary=False,
                metadata={
                    "event_name": event_name,
                    "event_id": event_id,
                },
            )
            self._frames.append(frame)
            self._payloads.append(payload)

        except Exception:
            self._log.error("sse_handler_failed", exc_info=True)

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _create_payload(
        self,
        raw: bytes,
        content_type: str | None = None,
    ) -> Payload:
        """Create a Payload domain object from raw bytes."""
        return Payload(
            id=uuid4(),
            raw_bytes=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
            content_type=content_type,
            base64=base64.b64encode(raw).decode("ascii"),
            hex_dump=raw[:512].hex(),
        )

    def _next_sequence(self, request_id: str) -> int:
        """Get the next frame sequence number for a connection."""
        seq = self._frame_sequences.get(request_id, 0)
        self._frame_sequences[request_id] = seq + 1
        return seq

    @staticmethod
    def _wall_time_to_datetime(wall_time: float) -> datetime:
        """Convert CDP wallTime (seconds since epoch) to datetime."""
        if wall_time <= 0:
            return datetime.now(timezone.utc)
        return datetime.fromtimestamp(wall_time, tz=timezone.utc)

    @staticmethod
    def _format_initiator(initiator: dict[str, Any]) -> str:
        """Format a CDP initiator object as a readable string."""
        init_type = initiator.get("type", "other")
        url = initiator.get("url", "")
        if url:
            line = initiator.get("lineNumber", "")
            return f"{init_type}:{url}:{line}"
        stack = initiator.get("stack")
        if stack:
            frames = stack.get("callFrames", [])
            if frames:
                top = frames[0]
                return f"{init_type}:{top.get('url', '')}:{top.get('lineNumber', '')}"
        return init_type
