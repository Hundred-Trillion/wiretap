from collections import defaultdict
from typing import Any
from wiretap.core.packets import Packet, UnknownPacket, PriceTick, Heartbeat, HistoryPacket
from wiretap.protocols.base import BaseProtocolImplementation

class DriftDetector:
    def __init__(self, protocol: BaseProtocolImplementation):
        self.protocol = protocol
        self.total_processed = 0
        self.packet_counts: dict[str, int] = defaultdict(int)
        self.validation_failures: list[dict[str, Any]] = []
        self.unknown_payloads: list[tuple[int, bytes]] = []

    def inspect(self, packet: Packet) -> bool:
        self.total_processed += 1
        name = type(packet).__name__
        self.packet_counts[name] += 1
        
        # 1. Catch Unknown Packets
        if isinstance(packet, UnknownPacket):
            self.unknown_payloads.append((packet.packet_type, packet.raw_payload))
            return False
            
        # 2. Validate Known Packets against Specification
        success, errors = self.protocol.validate_packet(packet)
        if not success:
            self.validation_failures.append({
                "packet_type": name,
                "packet_data": packet.to_dict(),
                "errors": errors
            })
            return False
            
        return True

    def get_report(self) -> dict[str, Any]:
        unknown_percentage = (len(self.unknown_payloads) / self.total_processed * 100) if self.total_processed > 0 else 0
        failure_percentage = (len(self.validation_failures) / self.total_processed * 100) if self.total_processed > 0 else 0
        
        return {
            "total_processed": self.total_processed,
            "packet_counts": dict(self.packet_counts),
            "validation_failures_count": len(self.validation_failures),
            "validation_failures": self.validation_failures[:10],  # Limit to first 10 for readability
            "unknown_packets_count": len(self.unknown_payloads),
            "drift_score_percentage": max(0.0, 100.0 - unknown_percentage - failure_percentage)
        }
