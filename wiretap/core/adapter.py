from typing import Union

class BaseProtocolAdapter:
    def pack(self, packet_type: int, payload: Union[str, bytes]) -> Union[str, bytes]:
        raise NotImplementedError

    def unpack(self, raw: Union[str, bytes]) -> tuple[int, Union[str, bytes]]:
        raise NotImplementedError

class EngineIOv3Adapter(BaseProtocolAdapter):
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
    # EIOv4 uses same text format, but binary payloads are handled without type prefix at EIO level
    # (they are assumed to be type 4 message).
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
