from enum import Enum

class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    DNS = "dns_resolving"
    TCP = "tcp_connecting"
    TLS = "tls_handshake"
    ENGINEIO_HANDSHAKE = "engineio_handshake"
    SOCKETIO_HANDSHAKE = "socketio_handshake"
    AUTHENTICATING = "authenticating"
    READY = "ready"
    SUBSCRIBED = "subscribed"
    STREAMING = "streaming"
