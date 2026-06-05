import json
from unittest.mock import AsyncMock

import pytest

from aun_core import AUNClient
from aun_core.events import EventDispatcher
from aun_core.transport import RPCTransport


class _FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, payload: str) -> None:
        self.sent.append(payload)


@pytest.mark.asyncio
async def test_transport_notify_sends_json_rpc_notification_without_id():
    ws = _FakeWS()
    transport = RPCTransport(event_dispatcher=EventDispatcher(), connection_factory=AsyncMock())
    transport._ws = ws
    transport._closed = False

    await transport.notify("notification/client.activity", {"state": "idle"})

    msg = json.loads(ws.sent[0])
    assert msg["jsonrpc"] == "2.0"
    assert msg["method"] == "notification/client.activity"
    assert msg["params"] == {"state": "idle"}
    assert "id" not in msg


@pytest.mark.asyncio
async def test_transport_event_app_is_published_directly():
    dispatcher = EventDispatcher()
    received = []
    dispatcher.subscribe("app.typing", lambda payload: received.append(payload))
    transport = RPCTransport(event_dispatcher=dispatcher, connection_factory=AsyncMock())

    await transport._route_message({
        "jsonrpc": "2.0",
        "method": "event/app.typing",
        "params": {"thread_id": "t1"},
    })

    assert received == [{"thread_id": "t1"}]


@pytest.mark.asyncio
async def test_client_notify_to_aid_wraps_route_notification():
    client = AUNClient()
    client._transport.notify = AsyncMock()

    await client.notify(
        "event/app.typing",
        {"thread_id": "t1"},
        to="bob.agentid.pub",
        device_id="dev-1",
        slot_id="slot-1",
        ttl_ms=5000,
    )

    client._transport.notify.assert_awaited_once()
    method, params = client._transport.notify.call_args.args
    assert method == "notification/route"
    assert params["target"] == {
        "type": "aid",
        "aid": "bob.agentid.pub",
        "device_id": "dev-1",
        "slot_id": "slot-1",
    }
    assert params["deliver"] == {
        "method": "event/app.typing",
        "params": {"thread_id": "t1"},
    }
    assert params["ttl_ms"] == 5000


@pytest.mark.asyncio
async def test_client_notify_group_wraps_group_route_notification():
    client = AUNClient()
    client._transport.notify = AsyncMock()

    await client.notify("event/app.presence", {"state": "active"}, group_id="g-room.agentid.pub")

    method, params = client._transport.notify.call_args.args
    assert method == "notification/group.route"
    assert params["group_id"] == "group.agentid.pub/g-room"
    assert params["deliver"] == {
        "method": "event/app.presence",
        "params": {"state": "active"},
    }
