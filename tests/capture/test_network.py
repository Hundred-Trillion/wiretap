import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock

from wiretap.capture.network import NetworkCapture
from wiretap.core.events import EventBus
from wiretap.core.enums import ProtocolType

@pytest.mark.asyncio
async def test_network_capture_enable_disable():
    cdp_mock = AsyncMock()
    bus = EventBus()
    session_id = uuid4()
    
    capture = NetworkCapture(cdp_mock, session_id, bus)
    
    await capture.enable()
    cdp_mock.send.assert_called_with("Network.enable", {
        "maxTotalBufferSize": 100 * 1024 * 1024,
        "maxResourceBufferSize": 10 * 1024 * 1024
    })
    
    await capture.disable()
    cdp_mock.send.assert_called_with("Network.disable")

def test_network_capture_request_handling():
    cdp_mock = MagicMock()
    bus = EventBus()
    session_id = uuid4()
    
    capture = NetworkCapture(cdp_mock, session_id, bus)
    
    # Simulate a request event
    request_params = {
        "requestId": "123.45",
        "wallTime": 1719750000.0,
        "type": "XHR",
        "request": {
            "url": "https://example.com/api/data",
            "method": "GET",
            "headers": {"Accept": "application/json"}
        },
        "initiator": {"type": "script", "url": "https://example.com/main.js"}
    }
    
    capture._on_request(request_params)
    
    assert len(capture.connections) == 1
    conn = capture.connections[0]
    assert conn.request_id == "123.45"
    assert conn.url == "https://example.com/api/data"
    assert conn.protocol == ProtocolType.XHR
    assert conn.method == "GET"
    assert conn.request_headers == {"Accept": "application/json"}
