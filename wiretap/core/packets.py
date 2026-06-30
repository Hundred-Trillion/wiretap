from dataclasses import dataclass, field, asdict
from typing import Any, Optional

@dataclass
class Packet:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class Heartbeat(Packet):
    direction: str  # "ping" or "pong"

@dataclass
class PriceTick(Packet):
    asset: str
    timestamp: float
    price: float
    direction: int

@dataclass
class HistoryPacket(Packet):
    asset: str
    period: int
    candles: list[list[Any]]

@dataclass
class DepthPacket(Packet):
    asset: str
    bids: list[list[float]]
    asks: list[list[float]]

@dataclass
class UnknownPacket(Packet):
    packet_type: int
    raw_payload: bytes
    error_msg: Optional[str] = None

@dataclass
class PlaceholderPacket(Packet):
    event_name: str

