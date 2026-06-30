import os
import json
from typing import Any, Union, Optional
from wiretap.core.packets import Packet
from wiretap.core.registry import PacketRegistry

class BaseProtocolImplementation:
    def __init__(self, spec_dir: str):
        self.spec_dir = spec_dir
        self.protocol_spec = self._load_json("protocol.json")
        self.layout_spec = self._load_json("layout.json")
        self.heartbeat_spec = self._load_json("heartbeat.json")
        self.auth_spec = self._load_json("authentication.json")
        
        self.registry = PacketRegistry()
        self.setup_registry()

    def _load_json(self, filename: str) -> dict[str, Any]:
        path = os.path.join(self.spec_dir, filename)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Specification file not found: {path}")
        with open(path, "r") as f:
            return json.load(f)

    def setup_registry(self):
        """Register specific handlers for events or structures."""
        pass

    def get_auth_payload(self, token: str, is_demo: bool) -> Union[str, bytes]:
        raise NotImplementedError

    def get_subscription_payload(self, asset: str) -> Union[str, bytes]:
        raise NotImplementedError

    def parse_payload(self, packet_type: int, payload: Union[str, bytes]) -> Packet:
        raise NotImplementedError

    def validate_packet(self, packet: Packet) -> tuple[bool, list[str]]:
        """Validate a decoded packet object against layout specifications. Returns (success, errors)."""
        raise NotImplementedError
