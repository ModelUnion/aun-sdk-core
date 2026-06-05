import asyncio
import base64
import json

import pytest
import websockets
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestServer

from aun_core.service_proxy import ServiceProxyClient


class _AccessLogger:
    def __init__(self):
        self.events = []

    def info(self, _module, message, *args):
        text = message % args if args else message
        if text.startswith("ACCESS "):
            self.events.append(json.loads(text[len("ACCESS "):]))

    def warn(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


class _InteractiveTunnel:
    def __init__(self):
        self.sent = []
        self._incoming = asyncio.Queue()
        self._sent_event = asyncio.Event()

    async def send(self, payload):
        self.sent.append(json.loads(payload))
        self._sent_event.set()

    async def recv(self):
        return json.dumps(await self._incoming.get())

    def push(self, message):
        self._incoming.put_nowait(message)

    async def wait_sent(self, predicate, *, timeout=1.0):
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            for message in self.sent:
                if predicate(message):
                    return message
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise AssertionError(f"timed out waiting for sent message; sent={self.sent!r}")
            self._sent_event.clear()
            try:
                await asyncio.wait_for(self._sent_event.wait(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise AssertionError(f"timed out waiting for sent message; sent={self.sent!r}") from exc


class _ClosedBackendWebSocket:
    close_code = 1000

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration


class _ClosedTunnel:
    async def send(self, _payload):
        raise websockets.ConnectionClosedOK(None, None)


async def _start_ws_backend(handler):
    app = web.Application()
    app.router.add_get("/root/{tail:.*}", handler)
    server = TestServer(app)
    await server.start_server()
    return server


def _ws_url(server, path="/root"):
    return str(server.make_url(path)).replace("http://", "ws://", 1).replace("https://", "wss://", 1)


@pytest.mark.asyncio
async def test_service_proxy_client_ws_backend_relay_text_binary_and_close():
    captured = {}

    async def handler(request):
        captured["path_qs"] = request.path_qs
        captured["x_trace"] = request.headers.get("x-trace-id")
        ws = web.WebSocketResponse(protocols=("chat.v1",))
        await ws.prepare(request)
        captured["subprotocol"] = ws.ws_protocol
        async for message in ws:
            if message.type == WSMsgType.TEXT:
                await ws.send_str(f"echo:{message.data}")
            elif message.type == WSMsgType.BINARY:
                await ws.send_bytes(b"echo:" + message.data)
        captured["closed"] = True
        return ws

    backend = await _start_ws_backend(handler)
    try:
        logger = _AccessLogger()
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", logger=logger)
        client.register_service("chat", _ws_url(backend), service_type="websocket", visibility="public")
        tunnel = _InteractiveTunnel()
        task = asyncio.create_task(
            client.handle_ws_connect_message(
                {
                    "type": "ws_connect",
                    "connection_id": "ws-1",
                    "service_name": "chat",
                    "path": "/socket",
                    "query_string": "token=WSQUERYSECRET",
                    "headers": {"x-trace-id": "trace-1"},
                    "subprotocols": ["chat.v1"],
                },
                tunnel,
            )
        )

        connected = await tunnel.wait_sent(lambda item: item.get("type") == "ws_connected")
        assert connected == {"type": "ws_connected", "connection_id": "ws-1", "subprotocol": "chat.v1"}

        tunnel.push({"type": "ws_message", "connection_id": "ws-1", "text": "hello"})
        text_echo = await tunnel.wait_sent(lambda item: item.get("text") == "echo:hello")
        assert text_echo == {"type": "ws_message", "connection_id": "ws-1", "text": "echo:hello"}

        tunnel.push({
            "type": "ws_message",
            "connection_id": "ws-1",
            "data_base64": base64.b64encode(b"\x01\x02").decode("ascii"),
        })
        binary_echo = await tunnel.wait_sent(lambda item: item.get("data_base64") == base64.b64encode(b"echo:\x01\x02").decode("ascii"))
        assert binary_echo == {
            "type": "ws_message",
            "connection_id": "ws-1",
            "data_base64": base64.b64encode(b"echo:\x01\x02").decode("ascii"),
        }

        tunnel.push({"type": "ws_close", "connection_id": "ws-1", "code": 1000, "reason": "bye"})
        await asyncio.wait_for(task, timeout=1.0)
    finally:
        await backend.close()

    assert captured == {
        "path_qs": "/root/socket?token=WSQUERYSECRET",
        "x_trace": "trace-1",
        "subprotocol": "chat.v1",
        "closed": True,
    }
    assert [event["event"] for event in logger.events] == [
        "backend_ws_connect_start",
        "backend_ws_connected",
        "backend_ws_closed",
    ]
    start = logger.events[0]
    assert start["connection_id"] == "ws-1"
    assert start["provider_aid"] == "alice.agentid.pub"
    assert start["service_name"] == "chat"
    assert start["path"] == "/socket"
    assert start["has_query"] is True
    assert start["query_length"] == len("token=WSQUERYSECRET")
    assert logger.events[1]["subprotocol"] == "chat.v1"
    assert logger.events[2]["connected"] is True
    serialized = json.dumps(logger.events, ensure_ascii=False)
    assert "WSQUERYSECRET" not in serialized
    assert "hello" not in serialized
    assert "trace-1" not in serialized


@pytest.mark.asyncio
async def test_service_proxy_client_ws_backend_rejects_unknown_service():
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")
    tunnel = _InteractiveTunnel()

    await client.handle_ws_connect_message(
        {"type": "ws_connect", "connection_id": "ws-404", "service_name": "missing"},
        tunnel,
    )

    assert tunnel.sent == [
        {
            "type": "ws_error",
            "connection_id": "ws-404",
            "error": {
                "code": "service_not_registered",
                "message": "service is not registered",
            },
        }
    ]


@pytest.mark.asyncio
async def test_service_proxy_client_ws_backend_close_ignores_closed_tunnel():
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")

    await client._relay_backend_ws_to_tunnel(
        _ClosedBackendWebSocket(),
        _ClosedTunnel(),
        connection_id="ws-closed",
    )
