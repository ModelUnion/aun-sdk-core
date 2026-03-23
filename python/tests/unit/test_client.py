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
        import asyncio
        asyncio.get_event_loop().run_until_complete(
            client.connect({"gateway": "ws://localhost/aun"})
        )


def test_connect_requires_gateway():
    client = AUNClient()
    with pytest.raises(StateError, match="gateway"):
        import asyncio
        asyncio.get_event_loop().run_until_complete(
            client.connect({"access_token": "tok"})
        )


def test_call_not_connected():
    client = AUNClient()
    with pytest.raises(Exception):
        import asyncio
        asyncio.get_event_loop().run_until_complete(
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
