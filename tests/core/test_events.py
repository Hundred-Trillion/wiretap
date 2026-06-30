import pytest
import asyncio
from uuid import uuid4
from wiretap.core.events import EventBus, FrameCaptured
from wiretap.core.enums import Direction

@pytest.mark.asyncio
async def test_event_bus_subscribe_emit():
    bus = EventBus()
    called = []

    async def handler(event: FrameCaptured):
        called.append(event)

    bus.subscribe(FrameCaptured, handler)
    
    evt = FrameCaptured(
        frame_id=uuid4(),
        connection_id=uuid4(),
        direction=Direction.RECEIVED,
        payload_size=100
    )
    
    await bus.emit(evt)
    
    assert len(called) == 1
    assert called[0] == evt

@pytest.mark.asyncio
async def test_event_bus_handler_exception_safety():
    bus = EventBus()
    
    async def bad_handler(event: FrameCaptured):
        raise RuntimeError("Oops!")
        
    called = []
    async def good_handler(event: FrameCaptured):
        called.append(event)
        
    bus.subscribe(FrameCaptured, bad_handler)
    bus.subscribe(FrameCaptured, good_handler)
    
    evt = FrameCaptured(
        frame_id=uuid4(),
        connection_id=uuid4(),
        direction=Direction.RECEIVED,
        payload_size=50
    )
    
    # Should not raise exception
    await bus.emit(evt)
    
    assert len(called) == 1
    assert called[0] == evt
