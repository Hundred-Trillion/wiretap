import pytest
from wiretap.core.adapter import EngineIOv3Adapter, EngineIOv4Adapter
from wiretap.core.session import TokenSessionProvider, CookieSessionProvider
from wiretap.core.state import ConnectionState
from wiretap.core.packets import PriceTick, Heartbeat, UnknownPacket
from wiretap.protocols.quotex.implementation import QuotexProtocolImplementation

def test_adapters():
    v3 = EngineIOv3Adapter()
    v4 = EngineIOv4Adapter()
    
    # Test v3 text framing
    assert v3.pack(4, "message") == "4message"
    assert v3.unpack("4message") == (4, "message")
    
    # Test v3 binary framing
    assert v3.pack(4, b"message") == b"\x04message"
    assert v3.unpack(b"\x04message") == (4, b"message")
    
    # Test v4 text
    assert v4.pack(2, "ping") == "2ping"
    assert v4.unpack("3pong") == (3, "pong")

def test_session_providers():
    token_prov = TokenSessionProvider("my_token")
    assert token_prov.resolve_token() == "my_token"
    
    cookie_prov = CookieSessionProvider({"token": "cookie_token", "other": "val"})
    assert cookie_prov.resolve_token() == "cookie_token"
    assert cookie_prov.resolve_cookies() == {"token": "cookie_token", "other": "val"}

def test_quotex_implementation_parsing():
    # Setup implementation with actual specs
    import os
    spec_dir = os.path.join(os.getcwd(), "specs", "quotex", "v1")
    impl = QuotexProtocolImplementation(spec_dir)
    
    # 1. Parse PriceTick payload
    # Raw Engine.IO message (type 4) with binary frame payload JSON string:
    # '[["BTCUSD_otc",1782829846.783,191844.52,1]]'
    price_payload = '[["BTCUSD_otc",1782829846.783,191844.52,1]]'
    packet = impl.parse_payload(4, price_payload)
    
    assert isinstance(packet, PriceTick)
    assert packet.asset == "BTCUSD_otc"
    assert packet.timestamp == 1782829846.783
    assert packet.price == 191844.52
    assert packet.direction == 1
    
    # Validate packet against spec layout
    valid, errors = impl.validate_packet(packet)
    assert valid is True
    assert len(errors) == 0

def test_quotex_implementation_drift():
    import os
    spec_dir = os.path.join(os.getcwd(), "specs", "quotex", "v1")
    impl = QuotexProtocolImplementation(spec_dir)
    
    # Malformed PriceTick: timestamp too low or wrong type
    bad_packet = PriceTick(
        asset="INVALID_TAG_NAME_THAT_FAILS_REGEX_VALIDATION",
        timestamp=100.0,  # too low
        price=-0.5,       # negative
        direction=3       # invalid enum value
    )
    
    valid, errors = impl.validate_packet(bad_packet)
    assert valid is False
    assert len(errors) > 0
    print("Drift detection caught errors:", errors)
