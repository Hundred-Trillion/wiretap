from typing import Callable, Any, Type, Optional
from wiretap.core.packets import Packet, UnknownPacket

class PacketRegistry:
    def __init__(self):
        # Maps Socket.IO event names to packet classes or parsers
        self._event_parsers: dict[str, Callable[[Any], Packet]] = {}
        # Maps low-level Engine.IO payload signatures/predicates to packet classes/parsers
        self._structural_parsers: list[tuple[Callable[[Any], bool], Callable[[Any], Packet]]] = []

    def register_event(self, event_name: str, parser: Callable[[Any], Packet]):
        self._event_parsers[event_name] = parser

    def register_structure(self, predicate: Callable[[Any], bool], parser: Callable[[Any], Packet]):
        self._structural_parsers.append((predicate, parser))

    def parse_event(self, event_name: str, payload: Any) -> Optional[Packet]:
        if event_name in self._event_parsers:
            return self._event_parsers[event_name](payload)
        return None

    def parse_structure(self, payload: Any) -> Optional[Packet]:
        for predicate, parser in self._structural_parsers:
            try:
                if predicate(payload):
                    return parser(payload)
            except Exception:
                pass
        return None
