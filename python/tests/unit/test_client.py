import asyncio
import time

import pytest

from aun_core import AUNClient
from aun_core.errors import AUNError, NotFoundError, StateError, ValidationError
from aun_core.keystore.sqlite_backup import SQLiteBackup
import aun_core.namespaces.auth_namespace as auth_namespace_module


def test_construct_no_args():
    client = AUNClient({"sqlite_backup": False})
    assert client.aid is None
    assert client.state == "idle"
    assert hasattr(client, "auth")
    assert not hasattr(client, "message")
    assert not hasattr(client, "group")
    assert not hasattr(client, "storage")


def test_construct_with_aun_path(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "test"), "sqlite_backup": False})
    assert client.state == "idle"


def test_construct_default_sqlite_backup_uses_aun_path(tmp_path):
    root = tmp_path / "aun"
    client = AUNClient({"aun_path": str(root)})
    assert isinstance(client._keystore._sqlite_backup, SQLiteBackup)
    assert client._keystore._sqlite_backup._db_path == root / ".aun_backup" / "aun_backup.db"


def test_connect_requires_access_token():
    client = AUNClient({"sqlite_backup": False})
    with pytest.raises(StateError, match="access_token"):
        asyncio.run(
            client.connect({"gateway": "ws://localhost/aun"})
        )


def test_connect_requires_gateway():
    client = AUNClient({"sqlite_backup": False})
    with pytest.raises(StateError, match="gateway"):
        asyncio.run(
            client.connect({"access_token": "tok"})
        )


def test_connect_uses_cached_gateway():
    client = AUNClient({"sqlite_backup": False})
    client._gateway_url = "ws://cached.example/aun"

    normalized = client._normalize_connect_params({"access_token": "tok"})
    assert normalized["gateway"] == "ws://cached.example/aun"


def test_create_aid_caches_discovered_gateway(monkeypatch):
    client = AUNClient({"sqlite_backup": False})

    async def fake_discover(url: str) -> str:
        assert url == "https://gateway.agentid.pub/.well-known/aun-gateway"
        return "ws://gateway.example/aun"

    async def fake_create_aid(gateway_url: str, aid: str) -> dict:
        assert gateway_url == "ws://gateway.example/aun"
        assert aid == "demo.agentid.pub"
        return {"aid": aid, "cert": "CERT"}

    monkeypatch.setattr(client._discovery, "discover", fake_discover)
    monkeypatch.setattr(client._auth, "create_aid", fake_create_aid)
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: None)

    result = asyncio.run(
        client.auth.create_aid({"aid": "demo.agentid.pub"})
    )

    assert result["gateway"] == "ws://gateway.example/aun"
    assert client._gateway_url == "ws://gateway.example/aun"


def test_authenticate_caches_discovered_gateway(monkeypatch):
    client = AUNClient({"sqlite_backup": False})

    async def fake_discover(url: str) -> str:
        assert url == "https://gateway.agentid.pub/.well-known/aun-gateway"
        return "ws://gateway.example/aun"

    async def fake_authenticate(gateway_url: str, *, aid=None) -> dict:
        assert gateway_url == "ws://gateway.example/aun"
        assert aid == "demo.agentid.pub"
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
        client.auth.authenticate({"aid": "demo.agentid.pub"})
    )

    assert result["gateway"] == "ws://gateway.example/aun"
    assert client._gateway_url == "ws://gateway.example/aun"


def test_create_aid_requires_aid_when_gateway_missing():
    client = AUNClient({"sqlite_backup": False})

    with pytest.raises(Exception, match="auth.create_aid requires 'aid'"):
        asyncio.run(client.auth.create_aid({}))


def test_authenticate_requires_aid_when_gateway_missing():
    client = AUNClient({"sqlite_backup": False})

    with pytest.raises(Exception, match="unable to resolve gateway"):
        asyncio.run(client.auth.authenticate({}))


def test_upload_agent_md_uses_cached_access_token(monkeypatch):
    client = AUNClient({"sqlite_backup": False})
    client._aid = "alice.agentid.pub"
    client._gateway_url = "ws://gateway.agentid.pub/aun"

    monkeypatch.setattr(
        client._auth,
        "load_identity_or_none",
        lambda aid=None: {
            "aid": "alice.agentid.pub",
            "access_token": "cached-token",
            "access_token_expires_at": time.time() + 3600,
        },
    )

    class _FakeResponse:
        status = 201

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self):
            return {"aid": "alice.agentid.pub", "etag": '"etag"'}

        async def text(self):
            return ""

    class _FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def put(self, url, *, data=None, headers=None):
            assert url == "http://alice.agentid.pub/agent.md"
            assert data == b"# Alice\n"
            assert headers["Authorization"] == "Bearer cached-token"
            assert headers["Content-Type"] == "text/markdown; charset=utf-8"
            return _FakeResponse()

    monkeypatch.setattr(auth_namespace_module.aiohttp, "ClientSession", _FakeSession)

    result = asyncio.run(client.auth.upload_agent_md("# Alice\n"))

    assert result["aid"] == "alice.agentid.pub"


def test_upload_agent_md_falls_back_to_authenticate(monkeypatch):
    client = AUNClient({"sqlite_backup": False})
    client._aid = "alice.agentid.pub"
    client._gateway_url = "ws://gateway.agentid.pub/aun"

    monkeypatch.setattr(
        client._auth,
        "load_identity_or_none",
        lambda aid=None: {"aid": "alice.agentid.pub"},
    )

    async def _fake_authenticate(params=None):
        assert params == {"aid": "alice.agentid.pub"}
        return {
            "aid": "alice.agentid.pub",
            "access_token": "fresh-token",
            "gateway": "ws://gateway.agentid.pub/aun",
        }

    monkeypatch.setattr(client.auth, "authenticate", _fake_authenticate)

    class _FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self):
            return {"aid": "alice.agentid.pub", "etag": '"etag-2"'}

        async def text(self):
            return ""

    class _FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def put(self, url, *, data=None, headers=None):
            assert url == "http://alice.agentid.pub/agent.md"
            assert headers["Authorization"] == "Bearer fresh-token"
            return _FakeResponse()

    monkeypatch.setattr(auth_namespace_module.aiohttp, "ClientSession", _FakeSession)

    result = asyncio.run(client.auth.upload_agent_md("# Alice\n"))

    assert result["etag"] == '"etag-2"'


def test_upload_agent_md_refresh_failure_logs_and_falls_back_to_authenticate(monkeypatch, caplog):
    client = AUNClient({"sqlite_backup": False})
    client._aid = "alice.agentid.pub"
    client._gateway_url = "ws://gateway.agentid.pub/aun"

    monkeypatch.setattr(
        client._auth,
        "load_identity_or_none",
        lambda aid=None: {
            "aid": "alice.agentid.pub",
            "refresh_token": "stale-refresh-token",
        },
    )

    async def _fake_refresh(gateway_url, identity):
        assert gateway_url == "ws://gateway.agentid.pub/aun"
        assert identity["refresh_token"] == "stale-refresh-token"
        raise RuntimeError("refresh boom")

    async def _fake_authenticate(params=None):
        assert params == {"aid": "alice.agentid.pub"}
        return {
            "aid": "alice.agentid.pub",
            "access_token": "fresh-token",
            "gateway": "ws://gateway.agentid.pub/aun",
        }

    monkeypatch.setattr(client._auth, "refresh_cached_tokens", _fake_refresh)
    monkeypatch.setattr(client.auth, "authenticate", _fake_authenticate)

    class _FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self):
            return {"aid": "alice.agentid.pub", "etag": '"etag-3"'}

        async def text(self):
            return ""

    class _FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def put(self, url, *, data=None, headers=None):
            assert url == "http://alice.agentid.pub/agent.md"
            assert data == b"# Alice\n"
            assert headers["Authorization"] == "Bearer fresh-token"
            return _FakeResponse()

    monkeypatch.setattr(auth_namespace_module.aiohttp, "ClientSession", _FakeSession)

    with caplog.at_level("DEBUG", logger="aun_core"):
        result = asyncio.run(client.auth.upload_agent_md("# Alice\n"))

    assert result["etag"] == '"etag-3"'
    assert "agent.md upload refresh_token 失败" in caplog.text


def test_upload_agent_md_403_raises_aunerror(monkeypatch):
    client = AUNClient({"sqlite_backup": False})
    client._aid = "alice.agentid.pub"
    client._gateway_url = "ws://gateway.agentid.pub/aun"

    monkeypatch.setattr(
        client._auth,
        "load_identity_or_none",
        lambda aid=None: {
            "aid": "alice.agentid.pub",
            "access_token": "cached-token",
            "access_token_expires_at": time.time() + 3600,
        },
    )

    class _FakeResponse:
        status = 403

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self):
            return {}

        async def text(self):
            return "forbidden"

    class _FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def put(self, url, *, data=None, headers=None):
            assert url == "http://alice.agentid.pub/agent.md"
            assert headers["Authorization"] == "Bearer cached-token"
            return _FakeResponse()

    monkeypatch.setattr(auth_namespace_module.aiohttp, "ClientSession", _FakeSession)

    with pytest.raises(AUNError, match="upload agent.md failed: HTTP 403 - forbidden"):
        asyncio.run(client.auth.upload_agent_md("# Alice\n"))


def test_download_agent_md_is_anonymous(monkeypatch):
    client = AUNClient({"sqlite_backup": False, "discovery_port": 18443})
    client._gateway_url = "wss://gateway.agentid.pub/aun"

    class _FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self):
            return "# Bob\n"

    class _FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url, *, headers=None):
            assert url == "https://bob.agentid.pub:18443/agent.md"
            assert headers == {"Accept": "text/markdown"}
            return _FakeResponse()

    monkeypatch.setattr(auth_namespace_module.aiohttp, "ClientSession", _FakeSession)

    result = asyncio.run(client.auth.download_agent_md("bob.agentid.pub"))

    assert result == "# Bob\n"


def test_download_agent_md_404_raises_not_found(monkeypatch):
    client = AUNClient({"sqlite_backup": False})
    client._gateway_url = "wss://gateway.agentid.pub/aun"

    class _FakeResponse:
        status = 404

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self):
            return "not found"

    class _FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url, *, headers=None):
            assert url == "https://bob.agentid.pub/agent.md"
            assert headers == {"Accept": "text/markdown"}
            return _FakeResponse()

    monkeypatch.setattr(auth_namespace_module.aiohttp, "ClientSession", _FakeSession)

    with pytest.raises(NotFoundError, match="agent.md not found for aid: bob.agentid.pub"):
        asyncio.run(client.auth.download_agent_md("bob.agentid.pub"))


def test_call_not_connected():
    client = AUNClient({"sqlite_backup": False})
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
    client = AUNClient({"sqlite_backup": False})
    assert client.e2ee is not None


def test_sync_identity_after_connect_preserves_prekeys(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "aun"), "sqlite_backup": False})
    aid = "demo.agentid.pub"

    client._keystore.save_identity(aid, {
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
    })
    client._keystore.save_metadata(aid, {
        "aid": aid,
        "e2ee_prekeys": {
            "pk1": {"private_key_pem": "KEEP_ME", "created_at": 1},
        },
    })
    client._aid = aid

    client._sync_identity_after_connect("tok-connect")

    loaded = client._keystore.load_metadata(aid)
    assert loaded["access_token"] == "tok-connect"
    assert loaded["e2ee_prekeys"]["pk1"]["private_key_pem"] == "KEEP_ME"


def test_call_rejects_group_service_recipient():
    client = AUNClient({"sqlite_backup": False})
    client._state = "connected"

    with pytest.raises(
        ValidationError,
        match=r"message.send receiver cannot be group\.\{issuer\}; use group.send instead",
    ):
        asyncio.run(client.call("message.send", {
            "to": "group.remote.example",
            "payload": {"text": "hello"},
            "encrypt": False,
        }))


def test_fetch_peer_prekey_returns_none_when_missing():
    client = AUNClient({"sqlite_backup": False})

    async def _fake_call(method, params):
        assert method == "message.e2ee.get_prekey"
        assert params == {"aid": "bob.remote.example"}
        return {"found": False}

    client._transport.call = _fake_call

    result = asyncio.run(client._fetch_peer_prekey("bob.remote.example"))

    assert result is None


def test_fetch_peer_prekey_query_failure_raises_validation_error():
    client = AUNClient({"sqlite_backup": False})

    async def _fake_call(method, params):
        raise RuntimeError("network down")

    client._transport.call = _fake_call

    with pytest.raises(ValidationError, match="failed to fetch peer prekey for bob.remote.example: network down"):
        asyncio.run(client._fetch_peer_prekey("bob.remote.example"))


def test_fetch_peer_prekey_invalid_response_raises_validation_error():
    client = AUNClient({"sqlite_backup": False})

    async def _fake_call(method, params):
        return {"found": True}

    client._transport.call = _fake_call

    with pytest.raises(ValidationError, match="invalid prekey response for bob.remote.example"):
        asyncio.run(client._fetch_peer_prekey("bob.remote.example"))


def test_build_cert_url_with_cert_fingerprint():
    url = AUNClient._build_cert_url(
        "wss://gateway.example.com/aun",
        "bob.example.com",
        "sha256:abc",
    )
    assert url == "https://gateway.example.com/pki/cert/bob.example.com?cert_fingerprint=sha256%3Aabc"


def test_send_encrypted_fetches_peer_cert_by_prekey_fingerprint(monkeypatch):
    client = AUNClient({"sqlite_backup": False})
    client._gateway_url = "wss://gateway.example.com/aun"

    calls = []

    async def _fake_fetch_peer_prekey(peer_aid):
        assert peer_aid == "bob.example.com"
        return {
            "prekey_id": "pk-1",
            "public_key": "pub",
            "signature": "sig",
            "cert_fingerprint": "sha256:abc",
        }

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        calls.append((aid, cert_fingerprint))
        return b"PEM"

    def _fake_encrypt_outbound(**kwargs):
        assert kwargs["prekey"]["cert_fingerprint"] == "sha256:abc"
        return {"ciphertext": "ok"}, {"encrypted": True, "forward_secrecy": True, "mode": "prekey_ecdh_v2"}

    async def _fake_call(method, params):
        assert method == "message.send"
        return {"ok": True}

    monkeypatch.setattr(client, "_fetch_peer_prekey", _fake_fetch_peer_prekey)
    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)
    monkeypatch.setattr(client._e2ee, "encrypt_outbound", _fake_encrypt_outbound)
    client._transport.call = _fake_call

    result = asyncio.run(client._send_encrypted({
        "to": "bob.example.com",
        "payload": {"text": "hello"},
    }))

    assert result == {"ok": True}
    assert calls == [("bob.example.com", "sha256:abc")]


def test_schedule_prekey_replenish_only_once_per_consumed_prekey():
    client = AUNClient({"sqlite_backup": False})
    client._state = "connected"

    async def _case():
        client._loop = asyncio.get_running_loop()
        uploads: list[str] = []

        async def _fake_upload():
            uploads.append("ok")
            await asyncio.sleep(0)
            return {"ok": True}

        client._upload_prekey = _fake_upload
        consumed = {"e2ee": {"encryption_mode": "prekey_ecdh_v2", "prekey_id": "pk-1"}}
        client._schedule_prekey_replenish_if_consumed(consumed)
        client._schedule_prekey_replenish_if_consumed(consumed)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        client._schedule_prekey_replenish_if_consumed(consumed)
        await asyncio.sleep(0)
        return uploads

    uploads = asyncio.run(_case())

    assert uploads == ["ok"]
