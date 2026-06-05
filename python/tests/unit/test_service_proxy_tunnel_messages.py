import asyncio
import json

import pytest

from aun_core.errors import AuthError
from aun_core.service_proxy import ServiceProxyClient


class _FakeWebSocket:
    def __init__(self, responses):
        self.sent = []
        self._responses = list(responses)
        self.closed = False

    async def send(self, payload):
        self.sent.append(json.loads(payload))

    async def recv(self):
        if not self._responses:
            await asyncio.sleep(3600)
        return json.dumps(self._responses.pop(0))

    async def close(self):
        self.closed = True


class _ConnectContext:
    def __init__(self, ws):
        self.ws = ws

    async def __aenter__(self):
        return self.ws

    async def __aexit__(self, exc_type, exc, tb):
        await self.ws.close()


class _FakeSubscription:
    def __init__(self, owner, event, handler):
        self.owner = owner
        self.event = event
        self.handler = handler

    def unsubscribe(self):
        handlers = self.owner.handlers.get(self.event, [])
        self.owner.handlers[self.event] = [item for item in handlers if item is not self.handler]


class _FakeAUNClient:
    def __init__(self, access_token="gateway-token"):
        self.access_token = access_token
        self.handlers = {}
        self.calls = []

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)
        return _FakeSubscription(self, event, handler)

    async def call(self, method, params=None, **kwargs):
        self.calls.append((method, params or {}, kwargs))
        if method == "proxy.register_services":
            return {"ok": True, "count": len((params or {}).get("services") or [])}
        if method == "proxy.unregister_services":
            return {"ok": True, "removed": list((params or {}).get("service_names") or [])}
        if method == "proxy.list_services":
            return {"provider_aid": (params or {}).get("provider_aid"), "services": []}
        return {}

    async def publish(self, event, payload):
        for handler in list(self.handlers.get(event, [])):
            result = handler(payload)
            if hasattr(result, "__await__"):
                await result


class _CollectingLogger:
    def __init__(self):
        self.warnings = []
        self.errors = []

    def warn(self, module, msg, *args):
        self.warnings.append((module, msg % args if args else msg))

    def error(self, module, msg, *args, err=None):
        self.errors.append((module, msg % args if args else msg, err))


@pytest.fixture(autouse=True)
def _stub_proxy_discovery(monkeypatch):
    async def _fake_discover_proxy_ws_url(self, *, force_refresh=False, timeout=5.0):
        return "wss://proxy.agentid.pub/ws/client"

    monkeypatch.setattr(ServiceProxyClient, "discover_proxy_ws_url", _fake_discover_proxy_ws_url)


@pytest.mark.asyncio
async def test_service_proxy_client_connect_once_auth_registers_and_heartbeats(monkeypatch):
    ws = _FakeWebSocket(
        [
            {"type": "service_proxy_auth_response", "request_id": "auth-1", "ok": True},
            {"type": "register_services_ack", "request_id": "reg-1", "ok": True, "count": 1},
            {"type": "heartbeat_ack", "request_id": "hb-1", "ok": True},
        ]
    )
    monkeypatch.setattr(
        "aun_core.service_proxy.client.websockets.connect",
        lambda *args, **kwargs: _ConnectContext(ws),
    )

    aun_client = _FakeAUNClient(access_token="gateway-token")
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)
    client.register_service("fileshare", "http://127.0.0.1:8080", visibility="public")

    result = await client.connect_once(
        auth_request_id="auth-1",
        register_request_id="reg-1",
        heartbeat_request_id="hb-1",
    )

    assert result == {"registered": 1, "heartbeat": True}
    assert client.is_running is False
    assert ws.closed is True
    assert ws.sent == [
        {
            "type": "service_proxy_auth",
            "request_id": "auth-1",
            "provider_aid": "alice.agentid.pub",
            "client_version": "python",
        },
        {
            "type": "register_services",
            "request_id": "reg-1",
            "services": [
                {
                    "service_name": "fileshare",
                    "service_type": "http",
                    "visibility": "public",
                    "metadata": {},
                }
            ],
        },
        {"type": "heartbeat", "request_id": "hb-1"},
    ]


@pytest.mark.asyncio
async def test_service_proxy_client_connect_once_reuses_gateway_access_token(monkeypatch):
    ws = _FakeWebSocket(
        [
            {"type": "service_proxy_auth_response", "request_id": "auth-1", "ok": True},
            {"type": "register_services_ack", "request_id": "reg-1", "ok": True, "count": 0},
        ]
    )
    captured = {}

    def fake_connect(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _ConnectContext(ws)

    monkeypatch.setattr("aun_core.service_proxy.client.websockets.connect", fake_connect)

    aun_client = _FakeAUNClient(access_token="gateway-token")
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)

    result = await client.connect_once(
        auth_request_id="auth-1",
        register_request_id="reg-1",
    )

    assert result == {"registered": 0, "heartbeat": False}
    assert aun_client.calls == [
        ("proxy.register_services", {"provider_aid": "alice.agentid.pub", "services": []}, {})
    ]
    assert captured["kwargs"]["additional_headers"] == {"Authorization": "Bearer gateway-token"}
    assert captured["kwargs"]["max_size"] == 64 * 1024 * 1024


@pytest.mark.asyncio
async def test_service_proxy_client_registers_with_gateway_and_proxy_server_in_order(monkeypatch):
    ws = _FakeWebSocket(
        [
            {"type": "service_proxy_auth_response", "request_id": "auth-1", "ok": True},
            {"type": "register_services_ack", "request_id": "reg-1", "ok": True, "count": 1},
        ]
    )
    monkeypatch.setattr(
        "aun_core.service_proxy.client.websockets.connect",
        lambda *args, **kwargs: _ConnectContext(ws),
    )

    aun_client = _FakeAUNClient(access_token="gateway-token")
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)
    client.register_service("fileshare", "http://127.0.0.1:8080", visibility="public")

    result = await client.connect_once(
        auth_request_id="auth-1",
        register_request_id="reg-1",
    )

    assert result == {"registered": 1, "heartbeat": False}
    assert aun_client.calls == [
        (
            "proxy.register_services",
            {
                "provider_aid": "alice.agentid.pub",
                "services": [
                    {
                        "service_name": "fileshare",
                        "service_type": "http",
                        "visibility": "public",
                        "metadata": {},
                    }
                ],
            },
            {},
        )
    ]
    assert ws.sent == [
        {
            "type": "service_proxy_auth",
            "request_id": "auth-1",
            "provider_aid": "alice.agentid.pub",
            "client_version": "python",
        },
        {
            "type": "register_services",
            "request_id": "reg-1",
            "services": [
                {
                    "service_name": "fileshare",
                    "service_type": "http",
                    "visibility": "public",
                    "metadata": {},
                }
            ],
        },
    ]


@pytest.mark.asyncio
async def test_service_proxy_client_explicit_gateway_service_methods():
    aun_client = _FakeAUNClient(access_token="gateway-token")
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)
    client.register_service("fileshare", "http://127.0.0.1:8080", visibility="public")

    registered = await client.register_services_with_gateway()
    listed = await client.list_gateway_services()
    removed = await client.unregister_services_from_gateway("fileshare")

    assert registered == {"ok": True, "count": 1}
    assert listed == {"provider_aid": "alice.agentid.pub", "services": []}
    assert removed == {"ok": True, "removed": ["fileshare"]}
    assert [call[0] for call in aun_client.calls] == [
        "proxy.register_services",
        "proxy.list_services",
        "proxy.unregister_services",
    ]


@pytest.mark.asyncio
async def test_service_proxy_client_on_demand_connects_after_wakeup(monkeypatch):
    ws = _FakeWebSocket(
        [
            {"type": "service_proxy_auth_response", "request_id": "auth", "ok": True},
            {"type": "register_services_ack", "request_id": "register-services", "ok": True, "count": 0},
        ]
    )
    captured = {}

    def fake_connect(*args, **kwargs):
        captured.setdefault("urls", []).append(args[0])
        captured["kwargs"] = kwargs
        return _ConnectContext(ws)

    monkeypatch.setattr("aun_core.service_proxy.client.websockets.connect", fake_connect)

    aun_client = _FakeAUNClient(access_token="gateway-token")
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)
    task = asyncio.create_task(
        client.serve_forever(
            connection_mode="on_demand",
            idle_timeout_seconds=0.01,
        )
    )
    await asyncio.sleep(0)

    await aun_client.publish("app.service_proxy.wakeup", {
        "type": "aun.service_proxy.wakeup",
        "provider_aid": "alice.agentid.pub",
        "service_name": "fileshare",
        "proxy_url": "wss://attacker.invalid/ws/client",
    })

    deadline = asyncio.get_running_loop().time() + 1.0
    while not captured.get("urls") and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.01)

    client.stop()
    result = await asyncio.wait_for(task, timeout=1.0)

    assert captured["urls"] == ["wss://proxy.agentid.pub/ws/client"]
    assert captured["kwargs"]["additional_headers"] == {"Authorization": "Bearer gateway-token"}
    assert result["connection_mode"] == "on_demand"
    assert result["wakeup_count"] == 1


@pytest.mark.asyncio
async def test_service_proxy_client_on_demand_logs_wakeup_connection_failure(monkeypatch):
    def fake_connect(*args, **kwargs):
        raise OSError("proxy unavailable")

    monkeypatch.setattr("aun_core.service_proxy.client.websockets.connect", fake_connect)

    logger = _CollectingLogger()
    aun_client = _FakeAUNClient(access_token="gateway-token")
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client, logger=logger)
    task = asyncio.create_task(
        client.serve_forever(
            connection_mode="on_demand",
            reconnect_delay_seconds=0.01,
        )
    )
    await asyncio.sleep(0)

    await aun_client.publish("app.service_proxy.wakeup", {
        "type": "aun.service_proxy.wakeup",
        "provider_aid": "alice.agentid.pub",
        "service_name": "fileshare",
        "proxy_url": "wss://attacker.invalid/ws/client",
    })

    deadline = asyncio.get_running_loop().time() + 1.0
    while not logger.warnings and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.01)

    client.stop()
    result = await asyncio.wait_for(task, timeout=1.0)

    assert result["wakeup_count"] == 1
    assert logger.warnings
    assert logger.warnings[0][0] == "service_proxy"
    assert "on-demand tunnel connection failed after wakeup" in logger.warnings[0][1]


@pytest.mark.asyncio
async def test_service_proxy_client_connect_once_auth_failure_resets_running(monkeypatch):
    ws = _FakeWebSocket(
        [
            {
                "type": "service_proxy_auth_response",
                "request_id": "auth-1",
                "ok": False,
                "error": {"code": "provider_aid_mismatch", "message": "denied"},
            }
        ]
    )
    monkeypatch.setattr(
        "aun_core.service_proxy.client.websockets.connect",
        lambda *args, **kwargs: _ConnectContext(ws),
    )

    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))

    with pytest.raises(AuthError, match="denied"):
        await client.connect_once(auth_request_id="auth-1")

    assert client.is_running is False
    assert ws.closed is True


@pytest.mark.asyncio
async def test_service_proxy_client_serve_once_handles_tunnel_request(monkeypatch):
    ws = _FakeWebSocket(
        [
            {"type": "service_proxy_auth_response", "request_id": "auth-1", "ok": True},
            {"type": "register_services_ack", "request_id": "reg-1", "ok": True, "count": 1},
            {
                "type": "service_proxy_request",
                "request_id": "req-1",
                "service_name": "fileshare",
                "method": "GET",
                "path": "/health",
                "query_string": "",
                "headers": {},
                "body_base64": "",
            },
        ]
    )
    monkeypatch.setattr(
        "aun_core.service_proxy.client.websockets.connect",
        lambda *args, **kwargs: _ConnectContext(ws),
    )

    aun_client = _FakeAUNClient(access_token="gateway-token")
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)
    client.register_service("fileshare", "http://127.0.0.1:8080", visibility="public")

    async def _fake_iter_request_messages(message):
        assert message["request_id"] == "req-1"
        yield {
            "type": "service_proxy_response",
            "request_id": "req-1",
            "status": 200,
            "headers": {"x-backend": "ok"},
            "body_base64": "",
        }

    monkeypatch.setattr(client, "iter_request_messages", _fake_iter_request_messages)

    result = await client.serve_once(
        auth_request_id="auth-1",
        register_request_id="reg-1",
        max_requests=1,
    )

    assert result == {"registered": 1, "handled_requests": 1}
    assert client.is_running is False
    assert ws.closed is True
    assert aun_client.calls == [
        (
            "proxy.register_services",
            {
                "provider_aid": "alice.agentid.pub",
                "services": [
                    {
                        "service_name": "fileshare",
                        "service_type": "http",
                        "visibility": "public",
                        "metadata": {},
                    }
                ],
            },
            {},
        )
    ]
    assert ws.sent[0] == {
        "type": "service_proxy_auth",
        "request_id": "auth-1",
        "provider_aid": "alice.agentid.pub",
        "client_version": "python",
    }
    assert ws.sent[1] == {
        "type": "register_services",
        "request_id": "reg-1",
        "services": [
            {
                "service_name": "fileshare",
                "service_type": "http",
                "visibility": "public",
                "metadata": {},
            }
        ],
    }
    assert ws.sent[-1] == {
        "type": "service_proxy_response",
        "request_id": "req-1",
        "status": 200,
        "headers": {"x-backend": "ok"},
        "body_base64": "",
    }


@pytest.mark.asyncio
async def test_service_proxy_client_serve_once_dispatches_ws_connect(monkeypatch):
    ws = _FakeWebSocket(
        [
            {"type": "service_proxy_auth_response", "request_id": "auth-1", "ok": True},
            {"type": "register_services_ack", "request_id": "reg-1", "ok": True, "count": 1},
            {
                "type": "ws_connect",
                "connection_id": "ws-1",
                "service_name": "chat",
                "path": "/socket",
                "query_string": "",
                "headers": {},
                "subprotocols": [],
            },
        ]
    )
    monkeypatch.setattr(
        "aun_core.service_proxy.client.websockets.connect",
        lambda *args, **kwargs: _ConnectContext(ws),
    )

    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
    client.register_service("chat", "ws://127.0.0.1:8080", service_type="websocket", visibility="public")
    seen = []

    async def _fake_handle_ws_connect(message, tunnel, *, inbound_queue=None):
        seen.append((message["connection_id"], tunnel is ws))

    monkeypatch.setattr(client, "handle_ws_connect_message", _fake_handle_ws_connect)

    result = await client.serve_once(
        auth_request_id="auth-1",
        register_request_id="reg-1",
        max_requests=1,
    )

    assert result == {"registered": 1, "handled_requests": 1}
    assert seen == [("ws-1", True)]


@pytest.mark.asyncio
async def test_service_proxy_client_serve_once_demuxes_concurrent_ws_connections(monkeypatch):
    ws = _FakeWebSocket(
        [
            {"type": "service_proxy_auth_response", "request_id": "auth-1", "ok": True},
            {"type": "register_services_ack", "request_id": "reg-1", "ok": True, "count": 1},
            {"type": "ws_connect", "connection_id": "ws-1", "service_name": "chat", "path": "/one"},
            {"type": "ws_connect", "connection_id": "ws-2", "service_name": "chat", "path": "/two"},
            {"type": "ws_message", "connection_id": "ws-2", "text": "two"},
            {"type": "ws_message", "connection_id": "ws-1", "text": "one"},
            {"type": "ws_close", "connection_id": "ws-2", "code": 1000, "reason": "done"},
            {"type": "ws_close", "connection_id": "ws-1", "code": 1000, "reason": "done"},
        ]
    )
    monkeypatch.setattr(
        "aun_core.service_proxy.client.websockets.connect",
        lambda *args, **kwargs: _ConnectContext(ws),
    )

    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
    client.register_service("chat", "ws://127.0.0.1:8080", service_type="websocket", visibility="public")
    seen = []

    async def _fake_handle_ws_connect(message, tunnel, *, inbound_queue=None):
        assert tunnel is ws
        assert inbound_queue is not None
        connection_id = message["connection_id"]
        seen.append(("start", connection_id))
        while True:
            item = await asyncio.wait_for(inbound_queue.get(), timeout=1.0)
            seen.append((connection_id, item["type"], item.get("text")))
            if item["type"] == "ws_close":
                break
        seen.append(("stop", connection_id))

    monkeypatch.setattr(client, "handle_ws_connect_message", _fake_handle_ws_connect)

    result = await client.serve_once(
        auth_request_id="auth-1",
        register_request_id="reg-1",
        max_requests=2,
    )

    assert result == {"registered": 1, "handled_requests": 2}
    assert ("start", "ws-1") in seen
    assert ("start", "ws-2") in seen
    assert ("ws-1", "ws_message", "one") in seen
    assert ("ws-2", "ws_message", "two") in seen
    assert ("ws-1", "ws_close", None) in seen
    assert ("ws-2", "ws_close", None) in seen
    assert ("stop", "ws-1") in seen
    assert ("stop", "ws-2") in seen
