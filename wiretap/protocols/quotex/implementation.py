import json
import re
from typing import Any, Union, Optional
from wiretap.protocols.base import BaseProtocolImplementation
from wiretap.core.packets import Packet, Heartbeat, PriceTick, HistoryPacket, UnknownPacket, PlaceholderPacket

class QuotexProtocolImplementation(BaseProtocolImplementation):
    def setup_registry(self):
        # Register structural parser for PriceTick
        # PriceTick has format: [["asset_name", timestamp_float, price_float, direction_int]]
        self.registry.register_structure(
            predicate=self._is_price_tick_structure,
            parser=self._parse_price_tick
        )
        
        # Register structural parser for HistoryPacket
        # HistoryPacket has keys: "asset", "period", "history"
        self.registry.register_structure(
            predicate=self._is_history_structure,
            parser=self._parse_history
        )

    def _is_price_tick_structure(self, payload: Any) -> bool:
        if isinstance(payload, list) and len(payload) >= 1:
            item = payload[0]
            if isinstance(item, list) and len(item) == 4:
                # First element should be a string (asset name)
                return isinstance(item[0], str)
        return False

    def _parse_price_tick(self, payload: Any) -> PriceTick:
        item = payload[0]
        return PriceTick(
            asset=item[0],
            timestamp=float(item[1]),
            price=float(item[2]),
            direction=int(item[3])
        )

    def _is_history_structure(self, payload: Any) -> bool:
        if isinstance(payload, dict):
            return "asset" in payload and "history" in payload and "period" in payload
        return False

    def _parse_history(self, payload: Any) -> HistoryPacket:
        return HistoryPacket(
            asset=payload["asset"],
            period=int(payload["period"]),
            candles=payload["history"]
        )

    def get_auth_payload(self, token: str, is_demo: bool) -> Union[str, bytes]:
        # Formulate authorization packet according to specs
        event_name = self.auth_spec["event_name"]
        payload_dict = {
            "session": token,
            "isDemo": 1 if is_demo else 0,
            "tournamentId": 0
        }
        # Pack into Socket.IO event format: 2["event_name", payload_dict]
        # (Engine.IO adapter will prepend the message packet type '4' to form '42')
        return f'2["{event_name}",{json.dumps(payload_dict, separators=(",", ":"))}]'

    def get_subscription_payload(self, asset: str) -> Union[str, bytes, list[Union[str, bytes]]]:
        # Formulate both instruments/update and depth/follow payloads
        # (Engine.IO adapter will prepend the message packet type '4' to form '42')
        payload_dict = {
            "asset": asset,
            "period": 60
        }
        inst_payload = f'2["instruments/update",{json.dumps(payload_dict, separators=(",", ":"))}]'
        depth_payload = f'2["depth/follow","{asset}"]'
        return [inst_payload, depth_payload]


    def parse_payload(self, packet_type: int, payload: Union[str, bytes]) -> Packet:
        # Standardize bytes vs string decoding
        raw_bytes = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        
        # 1. Handle keep-alive frames
        if packet_type == 2:
            return Heartbeat("ping")
        elif packet_type == 3:
            return Heartbeat("pong")

        # 2. Decode UTF-8 string for structured parsing
        try:
            text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        except Exception as e:
            return UnknownPacket(packet_type=packet_type, raw_payload=raw_bytes, error_msg=f"Decoding failed: {e}")

        # Check for binary placeholder metadata (starts with '5' + digits + '-')
        # e.g., "51-[\"quotes/stream\",{\"_placeholder\":true,\"num\":0}]"
        if text.startswith("5") and "-" in text:
            parts = text.split("-", 1)
            if parts[0][1:].isdigit():
                try:
                    placeholder_data = json.loads(parts[1])
                    if isinstance(placeholder_data, list) and len(placeholder_data) > 0:
                        return PlaceholderPacket(event_name=placeholder_data[0])
                except Exception:
                    pass

        # 3. Route Socket.IO events (type 42)
        if text.startswith("2[") or text.startswith("42["):
            # Strip prefixes to extract JSON array
            prefix_len = 2 if text.startswith("42[") else 1
            try:
                data = json.loads(text[prefix_len:])
                if isinstance(data, list) and len(data) >= 2:
                    event_name, event_data = data[0], data[1]
                    parsed = self.registry.parse_event(event_name, event_data)
                    if parsed:
                        return parsed
            except Exception as e:
                pass

        # 4. Route Engine.IO messages containing raw JSON arrays/objects (type 4)
        if text.startswith("[") or text.startswith("{"):
            try:
                data = json.loads(text)
                parsed = self.registry.parse_structure(data)
                if parsed:
                    return parsed
            except Exception:
                pass

        # Fallback to UnknownPacket
        return UnknownPacket(packet_type=packet_type, raw_payload=raw_bytes)

    def validate_packet(self, packet: Packet) -> tuple[bool, list[str]]:
        errors = []
        if isinstance(packet, PriceTick):
            spec = self.layout_spec["layouts"]["PriceTick"]["items"]["fields"]
            # Validate fields against JSON layout specification
            for field_spec in spec:
                name = field_spec["name"]
                val = getattr(packet, name)
                expected_type = field_spec["type"]
                
                # Type check
                if expected_type == "str" and not isinstance(val, str):
                    errors.append(f"Field '{name}' expected type str, got {type(val).__name__}")
                elif expected_type == "float" and not isinstance(val, (float, int)):
                    errors.append(f"Field '{name}' expected float, got {type(val).__name__}")
                elif expected_type == "int" and not isinstance(val, int):
                    errors.append(f"Field '{name}' expected int, got {type(val).__name__}")
                
                # Extra constraints
                if "regex" in field_spec and isinstance(val, str):
                    if not re.match(field_spec["regex"], val):
                        errors.append(f"Field '{name}' value '{val}' does not match regex '{field_spec['regex']}'")
                if "min_val" in field_spec and isinstance(val, (int, float)):
                    if val < field_spec["min_val"]:
                        errors.append(f"Field '{name}' value {val} is below minimum {field_spec['min_val']}")
                if "enum" in field_spec:
                    if val not in field_spec["enum"]:
                        errors.append(f"Field '{name}' value {val} is not in enum {field_spec['enum']}")
                        
        elif isinstance(packet, HistoryPacket):
            # Validate asset name and period
            if not re.match(r"^[A-Z]{3,8}(?:USD)?(?:_otc)?$", packet.asset):
                errors.append(f"Asset name '{packet.asset}' is invalid")
            if packet.period <= 0:
                errors.append(f"Expected positive history period, got {packet.period}")
                
        return len(errors) == 0, errors
