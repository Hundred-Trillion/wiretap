import pytest
from wiretap.core.enums import DecoderStatus
from wiretap.decoders.registry import DecoderRegistry
from wiretap.decoders.base import Decoder, DecodeResult

class MockDecoder:
    name = "mock"
    priority = 10
    
    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type == "application/mock":
            return 1.0
        return 0.0
        
    def decode(self, data: bytes) -> DecodeResult:
        return DecodeResult(
            status=DecoderStatus.SUCCESS,
            data="mocked",
            confidence=1.0,
            encoding="mock"
        )

def test_decoder_registry_registration():
    reg = DecoderRegistry()
    mock_dec = MockDecoder()
    reg.register(mock_dec)
    
    assert mock_dec in reg.decoders
    
    # Try decoding matching payload
    results = reg.decode_payload(b"hello", "application/mock")
    assert len(results) == 1
    assert results[0].data == "mocked"
    
    # Try non-matching
    non_matching = reg.decode_payload(b"hello", "application/json")
    assert len(non_matching) == 0
