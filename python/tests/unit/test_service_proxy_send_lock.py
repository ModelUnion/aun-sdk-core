import asyncio

import pytest

from aun_core.service_proxy.client import _SendLockedWebSocket


class _FakeWebSocket:
    def __init__(self):
        self.writes = []
        self.first_entered = asyncio.Event()
        self.release_first = asyncio.Event()

    async def send(self, data):
        self.writes.append(data)
        if data == "first":
            self.first_entered.set()
            await self.release_first.wait()


@pytest.mark.asyncio
async def test_send_locked_websocket_serializes_concurrent_sends():
    raw = _FakeWebSocket()
    ws = _SendLockedWebSocket(raw)

    first = asyncio.create_task(ws.send("first"))
    await raw.first_entered.wait()
    second = asyncio.create_task(ws.send("second"))
    await asyncio.sleep(0)

    assert raw.writes == ["first"]

    raw.release_first.set()
    await asyncio.gather(first, second)

    assert raw.writes == ["first", "second"]
