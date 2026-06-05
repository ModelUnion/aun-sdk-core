import asyncio
import json
import time

import pytest

from aun_core.service_proxy import ServiceProxyClient


class _FakeTokenStore:
    def __init__(self):
        self.metadata = {}
        self.instance_state = {}

    def get_metadata_value(self, aid, key):
        return self.metadata.get((aid, key), "")

    def set_metadata_value(self, aid, key, value):
        self.metadata[(aid, key)] = value

    def load_instance_state(self, aid, device_id, slot_id=""):
        return dict(self.instance_state.get((aid, device_id, slot_id), {}))


class _FakeConfig:
    verify_ssl = True


class _FakeAUNClient:
    def __init__(self, *, access_token="", expires_at=None, token_store=None):
        self.access_token = access_token
        self.access_token_expires_at = expires_at
        self._token_store = token_store or _FakeTokenStore()
        self._config_model = _FakeConfig()
        self._device_id = "device-1"
        self._slot_id = "default"
        self.authenticate_calls = 0

    async def authenticate(self):
        self.authenticate_calls += 1
        return {
            "access_token": "fresh-token",
            "expires_at": time.time() + 3600,
        }


class _FakeWebSocket:
    def __init__(self):
        self.sent = []
        self._responses = [
            {"type": "service_proxy_auth_response", "request_id": "auth", "ok": True},
            {"type": "register_services_ack", "request_id": "register-services", "ok": True, "count": 0},
        ]

    async def send(self, payload):
        self.sent.append(json.loads(payload))

    async def recv(self):
        if not self._responses:
            await asyncio.sleep(3600)
        return json.dumps(self._responses.pop(0))

    async def close(self):
        pass


class _ConnectContext:
    def __init__(self, ws):
        self.ws = ws

    async def __aenter__(self):
        return self.ws

    async def __aexit__(self, exc_type, exc, tb):
        await self.ws.close()


@pytest.mark.asyncio
async def test_service_proxy_discovery_falls_back_and_reuses_sqlite_metadata_cache(monkeypatch):
    token_store = _FakeTokenStore()
    aun_client = _FakeAUNClient(token_store=token_store)
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)
    calls = []

    async def fake_fetch(url, *, timeout=5.0):
        calls.append(url)
        if len(calls) == 1:
            raise OSError("primary down")
        return {
            "issuer": "agentid.pub",
            "ws_url": "wss://proxy.agentid.pub:19890/ws/client",
            "source_url": url,
            "discovered_at": time.time(),
        }

    monkeypatch.setattr(client, "_fetch_proxy_well_known", fake_fetch)

    ws_url = await client.discover_proxy_ws_url()
    assert ws_url == "wss://proxy.agentid.pub:19890/ws/client"
    assert calls == [
        "https://alice.agentid.pub/.well-known/aun-proxy",
        "https://proxy.agentid.pub/.well-known/aun-proxy",
    ]

    calls.clear()
    cached_url = await client.discover_proxy_ws_url()
    assert cached_url == ws_url
    assert calls == []


@pytest.mark.asyncio
async def test_service_proxy_connect_authenticates_when_cached_token_missing(monkeypatch):
    ws = _FakeWebSocket()
    captured = {}

    def fake_connect(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _ConnectContext(ws)

    monkeypatch.setattr("aun_core.service_proxy.client.websockets.connect", fake_connect)

    aun_client = _FakeAUNClient()
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)

    async def fake_discover_proxy_ws_url(*, force_refresh=False, timeout=5.0):
        return "wss://proxy.agentid.pub:19890/ws/client"

    monkeypatch.setattr(client, "discover_proxy_ws_url", fake_discover_proxy_ws_url)

    result = await client.connect_once()

    assert result == {"registered": 0, "heartbeat": False}
    assert aun_client.authenticate_calls == 1
    assert captured["args"] == ("wss://proxy.agentid.pub:19890/ws/client",)
    assert captured["kwargs"]["additional_headers"] == {"Authorization": "Bearer fresh-token"}


@pytest.mark.asyncio
async def test_service_proxy_connect_authenticates_when_cached_token_expired(monkeypatch):
    ws = _FakeWebSocket()
    captured = {}

    def fake_connect(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _ConnectContext(ws)

    monkeypatch.setattr("aun_core.service_proxy.client.websockets.connect", fake_connect)

    aun_client = _FakeAUNClient(
        access_token="stale-token",
        expires_at=time.time() - 60,
    )
    client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=aun_client)

    async def fake_discover_proxy_ws_url(*, force_refresh=False, timeout=5.0):
        return "wss://proxy.agentid.pub:19890/ws/client"

    monkeypatch.setattr(client, "discover_proxy_ws_url", fake_discover_proxy_ws_url)

    result = await client.connect_once()

    assert result == {"registered": 0, "heartbeat": False}
    assert aun_client.authenticate_calls == 1
    assert captured["args"] == ("wss://proxy.agentid.pub:19890/ws/client",)
    assert captured["kwargs"]["additional_headers"] == {"Authorization": "Bearer fresh-token"}
