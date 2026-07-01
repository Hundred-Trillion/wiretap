from typing import Union

class BaseProtocolAdapter:
    def pack(self, packet_type: int, payload: Union[str, bytes]) -> Union[str, bytes]:
        raise NotImplementedError

    def unpack(self, raw: Union[str, bytes]) -> tuple[int, Union[str, bytes]]:
        raise NotImplementedError

class EngineIOv3Adapter(BaseProtocolAdapter):
    """Engine.IO v3 packet framing adapter.
    
    Engine.IO v3 text frames always have a single-digit packet type prefix:
      0 = open, 1 = close, 2 = ping, 3 = pong, 4 = message, 5 = upgrade, 6 = noop
    
    The payload after the single-digit prefix may itself start with digits
    (e.g. Socket.IO event '42[...]' is EIO type 4 + SIO type 2 + data).
    This adapter correctly splits at the single-digit EIO boundary.
    """
    def pack(self, packet_type: int, payload: Union[str, bytes]) -> Union[str, bytes]:
        if isinstance(payload, str):
            return f"{packet_type}{payload}"
        elif isinstance(payload, bytes):
            return bytes([packet_type]) + payload
        else:
            raise TypeError("Payload must be str or bytes")

    def unpack(self, raw: Union[str, bytes]) -> tuple[int, Union[str, bytes]]:
        if not raw:
            raise ValueError("Empty frame")
            
        if isinstance(raw, str):
            # Engine.IO v3: first character is always the single-digit packet type
            packet_type = int(raw[0])
            payload = raw[1:]
            return packet_type, payload
        elif isinstance(raw, bytes):
            packet_type = raw[0]
            payload = raw[1:]
            return packet_type, payload
        else:
            raise TypeError("Raw frame must be str or bytes")

class EngineIOv4Adapter(BaseProtocolAdapter):
    """Engine.IO v4 packet framing adapter.
    
    Same text format as v3, but binary payloads are sent without a type
    prefix (implicitly type 4 = message).
    """
    def pack(self, packet_type: int, payload: Union[str, bytes]) -> Union[str, bytes]:
        if isinstance(payload, str):
            return f"{packet_type}{payload}"
        elif isinstance(payload, bytes):
            # In v4, binary data is sent directly without EIO prefix if it's a message
            if packet_type == 4:
                return payload
            return bytes([packet_type]) + payload
        else:
            raise TypeError("Payload must be str or bytes")

    def unpack(self, raw: Union[str, bytes]) -> tuple[int, Union[str, bytes]]:
        if not raw:
            raise ValueError("Empty frame")
            
        if isinstance(raw, str):
            packet_type = int(raw[0])
            payload = raw[1:]
            return packet_type, payload
        elif isinstance(raw, bytes):
            # In EIO v4, incoming binary is implicitly type 4 message
            return 4, raw
        else:
            raise TypeError("Raw frame must be str or bytes")
