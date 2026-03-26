import asyncio

import pytest

from aun_core import AUNClient
from aun_core.errors import StateError


def test_construct_no_args():
    client = AUNClient()
    assert client.aid is None
    assert client.state == "idle"
    assert hasattr(client, "auth")
    assert not hasattr(client, "message")
    assert not hasattr(client, "group")
    assert not hasattr(client, "storage")


def test_construct_with_aun_path(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "test")})
    assert client.state == "idle"


def test_connect_requires_access_token():
    client = AUNClient()
    with pytest.raises(StateError, match="access_token"):
        asyncio.run(
            client.connect({"gateway": "ws://localhost/aun"})
        )


def test_connect_requires_gateway():
    client = AUNClient()
    with pytest.raises(StateError, match="gateway"):
        asyncio.run(
            client.connect({"access_token": "tok"})
        )


def test_connect_uses_cached_gateway():
    client = AUNClient()
    client._gateway_url = "ws://cached.example/aun"

    normalized = client._normalize_connect_params({"access_token": "tok"})
    assert normalized["gateway"] == "ws://cached.example/aun"


def test_create_aid_caches_discovered_gateway(monkeypatch):
    client = AUNClient()

    async def fake_discover(url: str) -> str:
        assert url == "https://demo.aid.com/.well-known/aun-gateway"
        return "ws://gateway.example/aun"

    async def fake_create_aid(gateway_url: str, aid: str) -> dict:
        assert gateway_url == "ws://gateway.example/aun"
        assert aid == "demo.aid.com"
        return {"aid": aid, "cert": "CERT"}

    monkeypatch.setattr(client._discovery, "discover", fake_discover)
    monkeypatch.setattr(client._auth, "create_aid", fake_create_aid)
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: None)

    result = asyncio.run(
        client.auth.create_aid({"aid": "demo.aid.com"})
    )

    assert result["gateway"] == "ws://gateway.example/aun"
    assert client._gateway_url == "ws://gateway.example/aun"


def test_authenticate_caches_discovered_gateway(monkeypatch):
    client = AUNClient()

    async def fake_discover(url: str) -> str:
        assert url == "https://demo.aid.com/.well-known/aun-gateway"
        return "ws://gateway.example/aun"

    async def fake_authenticate(gateway_url: str, *, aid=None) -> dict:
        assert gateway_url == "ws://gateway.example/aun"
        assert aid == "demo.aid.com"
        return {
            "aid": aid,
            "access_token": "tok",
            "refresh_token": "refresh",
            "expires_at": 123,
            "gateway": gateway_url,
        }

    monkeypatch.setattr(client._discovery, "discover", fake_discover)
    monkeypatch.setattr(client._auth, "authenticate", fake_authenticate)
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: None)

    result = asyncio.run(
        client.auth.authenticate({"aid": "demo.aid.com"})
    )

    assert result["gateway"] == "ws://gateway.example/aun"
    assert client._gateway_url == "ws://gateway.example/aun"


def test_create_aid_requires_aid_when_gateway_missing():
    client = AUNClient()

    with pytest.raises(Exception, match="auth.create_aid requires 'aid'"):
        asyncio.run(client.auth.create_aid({}))


def test_authenticate_requires_aid_when_gateway_missing():
    client = AUNClient()

    with pytest.raises(Exception, match="requires 'aid' when 'gateway' is not provided"):
        asyncio.run(client.auth.authenticate({}))


def test_call_not_connected():
    client = AUNClient()
    with pytest.raises(Exception):
        asyncio.run(
            client.call("meta.ping", {})
        )


def test_call_internal_only_blocked():
    """internal_only 方法应被阻止。"""
    from aun_core.client import _INTERNAL_ONLY_METHODS
    assert "auth.connect" in _INTERNAL_ONLY_METHODS
    assert "auth.aid_login1" in _INTERNAL_ONLY_METHODS


def test_no_callable_prefix_restriction():
    """Core 版本不应有 _CLIENT_CALLABLE_PREFIXES 限制。"""
    import aun_core.client as mod
    assert not hasattr(mod, "_CLIENT_CALLABLE_PREFIXES")
    assert not hasattr(mod, "_CLIENT_CALLABLE_METHODS")


def test_e2ee_property():
    client = AUNClient()
    assert client.e2ee is not None
