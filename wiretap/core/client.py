import asyncio
import socket
import ssl
import time
import urllib.parse
from typing import AsyncGenerator, Optional, Union
import websockets
from websockets.exceptions import ConnectionClosed

from wiretap.core.state import ConnectionState
from wiretap.core.adapter import BaseProtocolAdapter
from wiretap.core.session import BaseSessionProvider
from wiretap.core.packets import Packet, Heartbeat, UnknownPacket
from wiretap.protocols.base import BaseProtocolImplementation
from wiretap.drift.drift_detector import DriftDetector

class ProtocolClient:
    def __init__(
        self,
        implementation: BaseProtocolImplementation,
        adapter: BaseProtocolAdapter,
        session_provider: BaseSessionProvider,
        trace_logger: Optional[list[dict]] = None
    ):
        self.impl = implementation
        self.adapter = adapter
        self.session_provider = session_provider
        self.state = ConnectionState.DISCONNECTED
        self.ws = None
        self.ping_task = None
        self.trace_logger = trace_logger if trace_logger is not None else []
        self.drift_detector = DriftDetector(self.impl)
        self._running = False
        self._ping_interval = 25.0
        self._ping_timeout = 5.0

    def _transition(self, new_state: ConnectionState):
        self.state = new_state
        self._log_trace("state_change", {"state": new_state.value})

    def _log_trace(self, event_type: str, details: dict):
        entry = {
            "timestamp": time.time(),
            "event": event_type,
            **details
        }
        self.trace_logger.append(entry)

    async def connect_and_stream(self, asset: Optional[str] = None, is_demo: bool = True) -> AsyncGenerator[Packet, None]:
        self._running = True
        backoff = 1.0
        
        while self._running:
            try:
                # 1. DNS Resolution State
                self._transition(ConnectionState.DNS)
                url = self.impl.protocol_spec["base_url"]
                parsed_url = urllib.parse.urlparse(url)
                hostname = parsed_url.hostname
                port = parsed_url.port or (443 if parsed_url.scheme == "wss" else 80)
                
                # Execute DNS check
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, socket.getaddrinfo, hostname, port)
                
                # 2. TCP State
                self._transition(ConnectionState.TCP)
                # 3. TLS State
                if parsed_url.scheme == "wss":
                    self._transition(ConnectionState.TLS)
                
                # Resolve token
                token = self.session_provider.resolve_token()
                if not token:
                    raise ValueError("Authentication token could not be resolved from session provider")
                
                # Setup WS Headers
                headers = {}
                cookies_dict = self.session_provider.resolve_cookies()
                if cookies_dict:
                    cookies_str = "; ".join(f"{k}={v}" for k, v in cookies_dict.items())
                    headers["Cookie"] = cookies_str
                
                headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                
                # Reconstruct full URL with query parameters
                params = self.impl.protocol_spec.get("query_params", {})
                query_str = urllib.parse.urlencode(params)
                full_url = f"{url}?{query_str}"
                
                # 4. Engine.IO Handshake State
                self._transition(ConnectionState.ENGINEIO_HANDSHAKE)
                
                # Establish WebSocket Connection
                async with websockets.connect(
                    full_url,
                    extra_headers=headers,
                    ssl=ssl.create_default_context() if parsed_url.scheme == "wss" else None
                ) as ws:
                    self.ws = ws
                    backoff = 1.0  # Reset backoff on successful connect
                    
                    # Read initial connection wrapper (open frame '0')
                    first_frame = await ws.recv()
                    self._log_trace("receive", {"is_binary": isinstance(first_frame, bytes), "size": len(first_frame)})
                    packet_type, payload = self.adapter.unpack(first_frame)
                    
                    if packet_type != 0:
                        raise ConnectionError(f"Expected Engine.IO open frame, got {packet_type}")
                        
                    # Extract ping parameters
                    try:
                        cfg = json.loads(payload)
                        self._ping_interval = cfg.get("pingInterval", 25000) / 1000.0
                        self._ping_timeout = cfg.get("pingTimeout", 5000) / 1000.0
                    except Exception:
                        pass
                    
                    # 5. Socket.IO Handshake State / Authenticating
                    self._transition(ConnectionState.AUTHENTICATING)
                    
                    # Send Authorization event
                    auth_payload = self.impl.get_auth_payload(token, is_demo)
                    # Pack authorization payload as message type 42 (Socket.IO event)
                    # For Engine.IO, 42 is event.
                    # Wait, our get_auth_payload helper returns the full Socket.IO frame starting with "42["
                    # So it already has Socket.IO event prefix. In Engine.IO terms, we pack it as message (type 4)
                    # since the "4" + "2" = "42" is standard Socket.IO event representation.
                    raw_auth = self.adapter.pack(4, auth_payload)
                    await ws.send(raw_auth)
                    self._log_trace("send", {"size": len(raw_auth)})
                    
                    # Transition to READY
                    self._transition(ConnectionState.READY)
                    
                    # Start Heartbeat scheduler
                    self.ping_task = asyncio.create_task(self._ping_loop())
                    
                    # 6. Subscribe State
                    if asset:
                        self._transition(ConnectionState.SUBSCRIBED)
                        sub_payload = self.impl.get_subscription_payload(asset)
                        raw_sub = self.adapter.pack(4, sub_payload)
                        await ws.send(raw_sub)
                        self._log_trace("send", {"size": len(raw_sub)})
                        
                        # Streaming State
                        self._transition(ConnectionState.STREAMING)
                    
                    # Receive Loop
                    while self._running:
                        frame = await ws.recv()
                        self._log_trace("receive", {"is_binary": isinstance(frame, bytes), "size": len(frame)})
                        
                        packet_type, payload = self.adapter.unpack(frame)
                        
                        # Route through protocol implementation
                        packet = self.impl.parse_payload(packet_type, payload)
                        
                        # Inspect for drift/validation
                        self.drift_detector.inspect(packet)
                        
                        # Automatically reply to keep-alive pings
                        if isinstance(packet, Heartbeat) and packet.direction == "ping":
                            pong_raw = self.adapter.pack(3, "")  # EIO pong is type 3
                            await ws.send(pong_raw)
                            self._log_trace("send", {"size": len(pong_raw)})
                            
                        yield packet
                        
            except ConnectionClosed:
                self._log_trace("disconnect", {"reason": "connection_closed"})
            except Exception as e:
                self._log_trace("error", {"error": str(e)})
            finally:
                self._transition(ConnectionState.DISCONNECTED)
                if self.ping_task:
                    self.ping_task.cancel()
                    self.ping_task = None
                self.ws = None
                
            # If running, wait and reconnect
            if self._running:
                self._log_trace("reconnect_wait", {"backoff": backoff})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    async def _ping_loop(self):
        """Sends ping keep-alive frames periodically if configured as client-sender,
        or monitors connection active state."""
        try:
            while self._running and self.ws:
                await asyncio.sleep(self._ping_interval)
                # In Engine.IO, ping is type 2
                ping_raw = self.adapter.pack(2, "")
                await self.ws.send(ping_raw)
                self._log_trace("send", {"size": len(ping_raw)})
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._log_trace("error", {"context": "ping_loop", "error": str(e)})

    async def disconnect(self):
        self._running = False
        if self.ws:
            await self.ws.close()
        if self.ping_task:
            self.ping_task.cancel()
            self.ping_task = None
        self._transition(ConnectionState.DISCONNECTED)
