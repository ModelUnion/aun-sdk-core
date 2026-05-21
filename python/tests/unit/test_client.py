import asyncio
import json
import time

import pytest

from aun_core import AUNClient, ProtectedHeaders
from aun_core.client import _CachedPeerCert, _PEER_CERT_CACHE_TTL, _PEER_PREKEYS_CACHE_TTL
from aun_core.errors import AUNError, ClientSignatureError, NotFoundError, StateError, ValidationError
import aun_core.namespaces.auth_namespace as auth_namespace_module


def _make_test_cert(cn: str) -> tuple[str, str]:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_fp = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
    return cert_pem, cert_fp


def test_peer_cert_cache_ttl_is_one_hour():
    assert _PEER_CERT_CACHE_TTL == 3600


def test_peer_prekeys_cache_ttl_is_one_hour():
    assert _PEER_PREKEYS_CACHE_TTL == 3600


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


def test_construct_default_sqlite_backup_uses_aun_path(tmp_path):
    """SQLCipher 迁移后不再使用 SQLiteBackup，改为验证 keystore 使用正确的 aun_path。"""
    root = tmp_path / "aun"
    client = AUNClient({"aun_path": str(root)})
    assert client._keystore._root == root


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


def test_heartbeat_interval_zero_disables_heartbeat():
    client = AUNClient()
    client._session_options["heartbeat_interval"] = 0

    client._start_heartbeat_task()

    assert client._heartbeat_task is None


@pytest.mark.asyncio
async def test_positive_heartbeat_interval_has_10s_floor():
    """interval 在 [10, 600] 内 clamp；< 10 被钳到 10。"""
    client = AUNClient()
    client._session_options["heartbeat_interval"] = 0.01

    client._start_heartbeat_task()
    await asyncio.sleep(0)

    # _start_heartbeat_task 通过 _clamp_heartbeat_interval 读 session_options，
    # 写回 session_options 由 _apply_server_heartbeat_interval 完成；这里只断言任务被启动
    assert client._heartbeat_task is not None
    client._closing = True
    if client._heartbeat_nudge is not None:
        client._heartbeat_nudge.set()
    try:
        await asyncio.wait_for(client._heartbeat_task, timeout=1.0)
    except asyncio.TimeoutError:
        client._heartbeat_task.cancel()


def test_clamp_heartbeat_interval_bounds():
    from aun_core.client import _clamp_heartbeat_interval
    assert _clamp_heartbeat_interval(0) == 0.0
    assert _clamp_heartbeat_interval(-5) == 0.0
    assert _clamp_heartbeat_interval(0.01) == 10.0
    assert _clamp_heartbeat_interval(30) == 30.0
    assert _clamp_heartbeat_interval(1000) == 600.0
    assert _clamp_heartbeat_interval("bad") == 0.0
    assert _clamp_heartbeat_interval(None) == 0.0


@pytest.mark.asyncio
async def test_apply_server_heartbeat_interval_writes_back():
    client = AUNClient()
    client._session_options["heartbeat_interval"] = 30.0
    client._apply_server_heartbeat_interval(60, source="pong")
    assert client._session_options["heartbeat_interval"] == 60.0
    # 服务端下发 0 → 关闭
    client._apply_server_heartbeat_interval(0, source="pong")
    assert client._session_options["heartbeat_interval"] == 0.0
    # 越界值 → clamp
    client._apply_server_heartbeat_interval(5, source="pong")
    assert client._session_options["heartbeat_interval"] == 10.0
    client._apply_server_heartbeat_interval(9999, source="pong")
    assert client._session_options["heartbeat_interval"] == 600.0
    # 收尾：取消可能启动的心跳 task
    if client._heartbeat_task is not None:
        client._closing = True
        if client._heartbeat_nudge is not None:
            client._heartbeat_nudge.set()
        try:
            await asyncio.wait_for(client._heartbeat_task, timeout=1.0)
        except asyncio.TimeoutError:
            client._heartbeat_task.cancel()


def test_normalize_connect_params_includes_slot_and_delivery_mode(tmp_path):
    client = AUNClient({
        "aun_path": str(tmp_path / "aun"),
    })

    normalized = client._normalize_connect_params({
        "access_token": "tok",
        "gateway": "wss://gateway.example.com/aun",
        "slot_id": "slot-a",
        "delivery_mode": "queue",
        "queue_routing": "sender_affinity",
        "affinity_ttl_ms": 900,
    })

    assert normalized["device_id"] == client._device_id
    assert normalized["slot_id"] == "slot-a"
    assert normalized["delivery_mode"] == {
        "mode": "queue",
        "routing": "sender_affinity",
        "affinity_ttl_ms": 900,
    }


def test_create_aid_caches_discovered_gateway(monkeypatch):
    client = AUNClient()

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
    client = AUNClient()

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
    client = AUNClient()

    with pytest.raises(Exception, match="auth.create_aid requires 'aid'"):
        asyncio.run(client.auth.create_aid({}))


def test_authenticate_requires_aid_when_gateway_missing():
    client = AUNClient()

    with pytest.raises(Exception, match="unable to resolve gateway"):
        asyncio.run(client.auth.authenticate({}))


def test_upload_agent_md_uses_cached_access_token(monkeypatch):
    client = AUNClient()
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
    client = AUNClient()
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


def test_upload_agent_md_refresh_failure_logs_and_falls_back_to_authenticate(monkeypatch):
    client = AUNClient()
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

    from unittest.mock import MagicMock
    mock_log = MagicMock()
    monkeypatch.setattr(client, "_log", mock_log)

    result = asyncio.run(client.auth.upload_agent_md("# Alice\n"))

    assert result["etag"] == '"etag-3"'
    debug_calls = [str(c) for c in mock_log.debug.call_args_list]
    assert any("agent.md upload refresh_token 失败" in c for c in debug_calls)


def test_upload_agent_md_403_raises_aunerror(monkeypatch):
    client = AUNClient()
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
    client = AUNClient()
    client._config_model.discovery_port = 18443
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
    client = AUNClient()
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
    """V1 E2EE Manager 已移除，e2ee property 不再存在。"""
    client = AUNClient()
    assert not hasattr(client, "e2ee")


def test_sync_identity_after_connect_preserves_prekeys(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    aid = "demo.agentid.pub"

    client._keystore.save_identity(aid, {
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
    })
    client._keystore.save_e2ee_prekey(aid, "pk1", {
        "private_key_pem": "KEEP_ME",
        "created_at": 1,
    }, device_id=client._device_id)
    client._aid = aid

    client._sync_identity_after_connect("tok-connect")

    loaded = client._keystore.load_identity(aid)
    slot_state = client._keystore.load_instance_state(aid, client._device_id, "")
    assert "access_token" not in loaded
    assert slot_state["access_token"] == "tok-connect"
    prekeys = client._keystore.load_e2ee_prekeys(aid, device_id=client._device_id)
    assert prekeys["pk1"]["private_key_pem"] == "KEEP_ME"


def test_call_rejects_group_service_recipient():
    client = AUNClient()
    client._state = "connected"

    with pytest.raises(
        ValidationError,
        match=r"message.send receiver cannot be group\.\{issuer\}; use group.send instead",
    ):
        asyncio.run(client.call("message.send", {
            "to": "group.remote.example",
            "payload": {"type": "text", "text": "hello"},
            "encrypt": False,
        }))


def test_call_rejects_message_send_persist_param():
    client = AUNClient()
    client._state = "connected"

    with pytest.raises(ValidationError, match="no longer accepts 'persist'"):
        asyncio.run(client.call("message.send", {
            "to": "bob.remote.example",
            "payload": {"type": "text", "text": "hello"},
            "encrypt": False,
            "persist": True,
        }))


def test_call_rejects_message_send_delivery_mode_param():
    client = AUNClient()
    client._state = "connected"

    with pytest.raises(ValidationError, match="does not accept delivery_mode"):
        asyncio.run(client.call("message.send", {
            "to": "bob.remote.example",
            "payload": {"type": "text", "text": "hello"},
            "encrypt": False,
            "delivery_mode": {"mode": "queue"},
        }))


def test_call_does_not_forward_message_send_delivery_mode():
    """message.send 明文路径应保留 protected_headers/headers（信封元数据，加密与否都保留）。"""
    client = AUNClient()
    client._state = "connected"
    client._connect_delivery_mode = {
        "mode": "queue",
        "routing": "sender_affinity",
        "affinity_ttl_ms": 1000,
    }
    protected_headers = ProtectedHeaders({"Device_ID": "dev-a", "slot_id": "slot-a"})
    calls = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    asyncio.run(client.call("message.send", {
        "to": "bob.remote.example",
        "payload": {"type": "text", "text": "hello"},
        "encrypt": False,
        "protected_headers": protected_headers,
        "headers": {"device_id": "dev-b"},
    }))

    assert calls == [("message.send", {
        "to": "bob.remote.example",
        "payload": {"type": "text", "text": "hello"},
        "protected_headers": protected_headers,
        "headers": {"device_id": "dev-b"},
    })]


def test_message_thought_put_plaintext_passes_through():
    """message.thought.put encrypt=false 应走通用 RPC 路径，保留 payload/protected_headers。"""
    client = AUNClient()
    client._state = "connected"
    calls = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    asyncio.run(client.call("message.thought.put", {
        "to": "bob.remote.example",
        "payload": {"type": "thought", "text": "明文 thought"},
        "encrypt": False,
        "protected_headers": {"purpose": "trace"},
        "context": {"type": "message", "id": "m-1"},
    }))

    assert len(calls) == 1
    method, params = calls[0]
    assert method == "message.thought.put"
    # encrypt 字段已被剥离
    assert "encrypt" not in params
    # 明文 payload 原样透传
    assert params["payload"] == {"type": "thought", "text": "明文 thought"}
    # protected_headers 保留
    assert params["protected_headers"] == {"purpose": "trace"}
    # context 保留
    assert params["context"] == {"type": "message", "id": "m-1"}


def test_group_thought_put_plaintext_passes_through():
    """group.thought.put encrypt=false 应走通用 RPC 路径，原样透传 payload。"""
    client = AUNClient()
    client._state = "connected"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    calls = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    asyncio.run(client.call("group.thought.put", {
        "group_id": "group.example.com/g-test",
        "payload": {"type": "thought", "text": "群明文 thought"},
        "encrypt": False,
        "protected_headers": {"trace": "t1"},
        "context": {"type": "group", "id": "g-1"},
    }))

    assert len(calls) == 1
    method, params = calls[0]
    assert method == "group.thought.put"
    assert "encrypt" not in params
    assert params["payload"] == {"type": "thought", "text": "群明文 thought"}
    assert params["protected_headers"] == {"trace": "t1"}


def test_group_send_plaintext_preserves_protected_headers():
    """group.send encrypt=false 明文路径应保留 protected_headers/headers。"""
    client = AUNClient()
    client._state = "connected"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    calls = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    asyncio.run(client.call("group.send", {
        "group_id": "group.example.com/g-test",
        "payload": {"type": "text", "text": "群明文"},
        "encrypt": False,
        "protected_headers": {"trace": "t1"},
        "headers": {"misc": "h"},
    }))

    assert len(calls) == 1
    method, params = calls[0]
    assert method == "group.send"
    assert "encrypt" not in params
    assert params["protected_headers"] == {"trace": "t1"}
    assert params["headers"] == {"misc": "h"}
    assert params["payload"] == {"type": "text", "text": "群明文"}


def test_protected_headers_from_params_accepts_wrapper():
    headers = ProtectedHeaders({"Device_ID": "dev-a", "slot_id": "slot-a"})

    assert AUNClient._protected_headers_from_params({"protected_headers": headers}) is headers
    assert AUNClient._protected_headers_from_params({"headers": headers}) is headers
    assert AUNClient._protected_headers_from_params({"protected_headers": {"Device_ID": "dev-a"}}) == {
        "Device_ID": "dev-a",
    }


def test_call_injects_message_slot_context():
    client = object.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._state = "connected"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._aid = "alice.agentid.pub"
    client._config_model = type("Config", (), {"group_e2ee": False})()
    calls = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.pull":
                return {"messages": [], "count": 0, "latest_seq": 0}
            return {"success": True, "ack_seq": 7}

    client._transport = _Transport()

    pull_result = asyncio.run(client.call("message.pull", {"after_seq": 1, "limit": 5}))
    ack_result = asyncio.run(client.call("message.ack", {"seq": 7}))

    assert pull_result["count"] == 0
    assert ack_result == {"success": True, "ack_seq": 7}
    assert calls[0][0] == "message.pull"
    assert calls[0][1]["device_id"] == client._device_id
    assert calls[0][1]["slot_id"] == "slot-a"
    assert calls[1][0] == "message.ack"
    assert calls[1][1]["device_id"] == client._device_id
    assert calls[1][1]["slot_id"] == "slot-a"


def test_message_pull_empty_result_applies_server_ack_floor():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._persist_seq = lambda ns: None
    calls = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.pull":
                return {"messages": [], "count": 0, "latest_seq": 7, "server_ack_seq": 7}
            return {"success": True, "ack_seq": params.get("seq")}

    client._transport = _Transport()

    result = asyncio.run(client.call("message.pull", {"after_seq": 0, "limit": 5}))

    assert result["server_ack_seq"] == 7
    assert client._seq_tracker.get_contiguous_seq("p2p:alice.agentid.pub") == 7
    assert calls[-1] == ("message.ack", {"seq": 7, "device_id": "device-1", "slot_id": "slot-a"})


def test_call_rejects_message_slot_context_override():
    client = object.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._state = "connected"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._aid = "alice.agentid.pub"
    client._config_model = type("Config", (), {"group_e2ee": False})()

    class _Transport:
        async def call(self, method, params):
            return {"messages": [], "count": 0, "latest_seq": 0}

    client._transport = _Transport()

    with pytest.raises(ValidationError, match="device_id must match"):
        asyncio.run(client.call("message.pull", {
            "after_seq": 0,
            "device_id": "other-device",
        }))

    with pytest.raises(ValidationError, match="slot_id must match"):
        asyncio.run(client.call("message.ack", {
            "seq": 1,
            "slot_id": "slot-b",
        }))


def test_build_cert_url_with_cert_fingerprint():
    url = AUNClient._build_cert_url(
        "wss://gateway.example.com/aun",
        "bob.example.com",
        "sha256:abc",
    )
    assert url == "https://gateway.example.com/pki/cert/bob.example.com?cert_fingerprint=sha256%3Aabc"


def test_thought_selector_validation_requires_context():
    client = AUNClient()
    client._validate_outbound_call("message.thought.put", {
        "to": "bob.example.com",
        "context": {"type": "run", "id": "run-1"},
    })

    with pytest.raises(ValidationError, match="context.type"):
        client._validate_outbound_call("message.thought.put", {
            "to": "bob.example.com",
        })


def test_ensure_sender_cert_cached_uses_local_fingerprint_cert(tmp_path, monkeypatch):
    """零信任语义：keystore 中即便有匹配指纹的证书，仍必须经过 _fetch_peer_cert
    完成 PKI 验证后方可信任；mock 让 _fetch_peer_cert 成功返回，验证流程通过即可。
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_fp = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()

    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    client._keystore.save_cert("alice.example.com", cert_pem, cert_fingerprint=cert_fp, make_active=False)

    called = {"fetch": 0, "last_fp": None}

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        called["fetch"] += 1
        called["last_fp"] = cert_fingerprint
        return cert_pem.encode("utf-8")

    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)

    ok = asyncio.run(client._ensure_sender_cert_cached("alice.example.com", cert_fp))

    assert ok is True
    # 零信任：必须调用 _fetch_peer_cert 做 PKI 验证，不能仅凭 keystore 信任
    assert called["fetch"] == 1
    assert called["last_fp"] == cert_fp


def test_get_verified_peer_cert_resolves_versioned_cache_without_fingerprint(tmp_path):
    cert_pem, cert_fp = _make_test_cert("bob.example.com")
    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    now = time.time()
    client._cert_cache[client._cert_cache_key("bob.example.com", cert_fp)] = _CachedPeerCert(
        cert_bytes=cert_pem.encode("utf-8"),
        validated_at=now,
        refresh_after=now + _PEER_CERT_CACHE_TTL,
    )

    assert client._get_verified_peer_cert("bob.example.com") == cert_pem


def test_seq_tracker_state_isolated_between_slots(tmp_path):
    root = tmp_path / "aun"
    aid = "demo.agentid.pub"
    base_identity = {
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
    }
    client_a = AUNClient({"aun_path": str(root)})
    client_b = AUNClient({"aun_path": str(root)})
    client_a._keystore.save_identity(aid, dict(base_identity))
    client_b._keystore.save_identity(aid, dict(base_identity))
    client_a._aid = aid
    client_b._aid = aid
    client_a._slot_id = "slot-a"
    client_b._slot_id = "slot-b"

    client_a._seq_tracker.restore_state({"p2p:demo": {"next_expected": 5}})
    client_a._save_seq_tracker_state()
    client_b._seq_tracker.restore_state({})
    client_b._restore_seq_tracker_state()

    assert client_b._seq_tracker.export_state() == {}


def test_seq_tracker_same_context_refresh_keeps_in_memory_state(tmp_path):
    aid = "alice.agentid.pub"
    client = AUNClient({"aun_path": str(tmp_path)})
    client._aid = aid
    client._slot_id = "slot-a"
    client._refresh_seq_tracking_context()
    client._seq_tracker.restore_state({"p2p:demo": 5})
    client._gap_fill_done["p2p:5"] = 0
    client._refresh_seq_tracking_context()

    assert client._seq_tracker.export_state() == {"p2p:demo": 5}
    assert "p2p:5" in client._gap_fill_done


def test_seq_tracker_slot_change_resets_in_memory_state_before_restore(tmp_path):
    aid = "alice.agentid.pub"
    root = tmp_path / "aun"
    client = AUNClient({"aun_path": str(root)})
    identity = {
        "aid": aid,
        "access_token": "token",
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
    }
    client._keystore.save_identity(aid, identity)
    client._aid = aid
    client._slot_id = "slot-a"
    client._seq_tracker.restore_state({"p2p:demo": 5})
    client._gap_fill_done["p2p:5"] = 0
    client._refresh_seq_tracking_context()
    client._save_seq_tracker_state()

    client._slot_id = "slot-b"
    client._refresh_seq_tracking_context()
    client._restore_seq_tracker_state()

    assert client._seq_tracker.export_state() == {}
    assert client._gap_fill_done == {}


# ── 重启全量拉取问题优化相关测试 ─────────────────────────────
# 见 docs/superpowers/specs/2026-04-17-restart-full-pull-mitigation-design.md


@pytest.mark.asyncio
async def test_group_changed_skips_fill_when_no_gap():
    """gap 检测：连续 event_seq 无需触发 _fill_group_event_gap。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._seq_tracker = SeqTracker()
    # 预置 contiguous = 5
    client._seq_tracker.restore_state({"group_event:G1": 5})
    client._loop = asyncio.get_running_loop()
    client._verify_event_signature = AsyncMock(return_value=True)
    fill_calls: list[str] = []

    async def fake_fill(gid):
        fill_calls.append(gid)

    client._fill_group_event_gap = fake_fill
    client._rotate_group_epoch = AsyncMock()

    data = {"group_id": "G1", "event_seq": 6, "action": "foo"}
    await client._on_raw_group_changed(data)
    # 给 create_task 机会运行
    await asyncio.sleep(0)
    assert fill_calls == []


@pytest.mark.asyncio
async def test_group_changed_triggers_fill_when_gap():
    """gap 检测：event_seq 跳跃触发 _fill_group_event_gap。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._seq_tracker = SeqTracker()
    client._seq_tracker.restore_state({"group_event:G1": 5})
    client._loop = asyncio.get_running_loop()
    client._verify_event_signature = AsyncMock(return_value=True)
    fill_calls: list[str] = []

    async def fake_fill(gid):
        fill_calls.append(gid)

    client._fill_group_event_gap = fake_fill
    client._rotate_group_epoch = AsyncMock()

    data = {"group_id": "G1", "event_seq": 10, "action": "foo"}
    await client._on_raw_group_changed(data)
    await asyncio.sleep(0)
    assert fill_calls == ["G1"]


@pytest.mark.asyncio
async def test_group_changed_first_event_gap_does_not_force_local_cursor():
    """首次看到 event_seq>1 时应补洞，不能用通知序号本地跳过历史事件。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._seq_tracker = SeqTracker()
    client._loop = asyncio.get_running_loop()
    client._verify_event_signature = AsyncMock(return_value=True)
    fill_calls: list[str] = []

    async def fake_fill(gid):
        fill_calls.append(gid)

    client._fill_group_event_gap = fake_fill

    await client._on_raw_group_changed({"group_id": "G1", "event_seq": 5, "action": "foo"})
    await asyncio.sleep(0)

    assert fill_calls == ["G1"]
    assert client._seq_tracker.get_contiguous_seq("group_event:G1") == 0


@pytest.mark.asyncio
async def test_group_changed_gap_fills_events_and_acks_contiguous_cursor():
    """group.changed event_seq gap 应真实触发 group.pull_events，并用 contiguous_seq ack。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._state = "connected"
    client._closing = False
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._seq_tracker = SeqTracker()
    client._gap_fill_done = {}
    client._pushed_seqs = {}
    client._loop = asyncio.get_running_loop()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._persist_seq = lambda ns: None
    client._verify_event_signature = AsyncMock(return_value=True)
    transport = MagicMock()
    calls: list[tuple[str, dict]] = []

    async def fake_transport_call(method, params):
        calls.append((method, dict(params)))
        if method == "group.pull_events":
            return {"events": [], "count": 0, "cursor": {"current_seq": 3}}
        if method == "group.ack_events":
            return {"ok": True}
        return {}

    transport.call = AsyncMock(side_effect=fake_transport_call)
    client._transport = transport

    await client._on_raw_group_changed({"group_id": "g1", "event_seq": 5, "action": "foo"})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not any(method == "group.ack_events" for method, _ in calls):
        await asyncio.sleep(0.01)

    pull_call = next(params for method, params in calls if method == "group.pull_events")
    assert pull_call == {
        "group_id": "g1",
        "after_event_seq": 0,
        "device_id": "device-1",
        "limit": 50,
        "slot_id": "slot-a",
    }
    ack_call = next(params for method, params in calls if method == "group.ack_events")
    assert ack_call == {"group_id": "g1", "event_seq": 3, "device_id": "device-1", "slot_id": "slot-a"}
    assert client._seq_tracker.get_contiguous_seq("group_event:g1") == 3
    assert client._gap_fill_done == {}


@pytest.mark.asyncio
async def test_group_create_blocks_until_v2_state_confirmed():
    from unittest.mock import AsyncMock

    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-alice"
    client._slot_id = "slot-a"
    client._v2_session = object()
    calls: list[tuple[str, dict]] = []
    group_id = "group.agentid.pub/g-create"

    async def fake_transport_call(method, params):
        calls.append((method, dict(params)))
        if method == "group.create":
            return {"group": {"group_id": group_id}}
        if method == "group.get_members":
            return {"members": [{"aid": "alice.agentid.pub", "role": "owner"}]}
        if method == "group.v2.bootstrap":
            return {
                "devices": [{"aid": "alice.agentid.pub", "device_id": "dev-alice", "ik_fp": "ik-a"}],
                "audit_recipients": [],
            }
        if method == "group.get_state":
            return {"state_version": 0, "state_hash": "", "key_epoch": 0, "membership_snapshot": ""}
        if method == "group.v2.propose_state":
            return {"proposal_id": "proposal-create"}
        if method == "group.v2.confirm_state":
            return {"ok": True}
        return {}

    client._transport.call = AsyncMock(side_effect=fake_transport_call)

    await client.call("group.create", {"name": "v2-create"})
    methods = [method for method, _ in calls]
    assert methods.index("group.create") < methods.index("group.v2.propose_state") < methods.index("group.v2.confirm_state")


@pytest.mark.asyncio
async def test_v2_auto_propose_leader_delay_uses_only_online_owner_admins(monkeypatch):
    from unittest.mock import AsyncMock

    client = AUNClient()
    client._state = "connected"
    client._aid = "z-owner.agentid.pub"
    client._device_id = "dev-owner"
    client._slot_id = "slot-a"
    client._v2_session = object()
    calls: list[str] = []

    async def fake_call(method, params):
        calls.append(method)
        if method == "group.get_online_members":
            return {
                "members": [
                    {"aid": "z-owner.agentid.pub", "role": "owner", "online": True},
                    {"aid": "m-member.agentid.pub", "role": "member", "online": True},
                ]
            }
        if method == "group.get_members":
            return {
                "members": [
                    {"aid": "a-offline-admin.agentid.pub", "role": "admin"},
                    {"aid": "z-owner.agentid.pub", "role": "owner"},
                ]
            }
        if method == "group.v2.bootstrap":
            return {
                "devices": [
                    {"aid": "a-offline-admin.agentid.pub", "device_id": "dev-offline", "ik_fp": "ik-a"},
                    {"aid": "z-owner.agentid.pub", "device_id": "dev-owner", "ik_fp": "ik-z"},
                ],
                "audit_recipients": [],
            }
        return {"ok": True}

    client.call = AsyncMock(side_effect=fake_call)

    async def fail_sleep(delay):
        raise AssertionError("leader delay should not sleep when only online owner/admin may participate")

    monkeypatch.setattr(asyncio, "sleep", fail_sleep)

    assert await client._v2_auto_propose_leader_delay("group.agentid.pub/12345") is True
    assert calls == ["group.get_online_members", "group.v2.bootstrap"]


@pytest.mark.asyncio
async def test_v2_auto_propose_verifies_committed_state_base_before_propose():
    from unittest.mock import AsyncMock

    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-alice"
    client._slot_id = "slot-a"
    client._v2_session = object()
    calls: list[str] = []

    async def fake_call(method, params):
        calls.append(method)
        if method == "group.get_members":
            return {"members": [
                {"aid": "alice.agentid.pub", "role": "owner"},
                {"aid": "bob.agentid.pub", "role": "member"},
            ]}
        if method == "group.v2.bootstrap":
            return {"devices": [], "audit_recipients": []}
        if method == "group.get_state":
            return {
                "state_version": 1,
                "state_hash": "not-a-valid-committed-hash",
                "key_epoch": 0,
                "membership_snapshot": json.dumps({
                    "members": [{"aid": "alice.agentid.pub", "devices": []}],
                    "audit_aids": [],
                    "admin_set": {"admin_aids": ["alice.agentid.pub"], "threshold": 1},
                    "join_policy_hash": None,
                    "recovery_quorum": None,
                    "history_policy": "recent_7_days",
                    "wrap_protocol": "3DH",
                }, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            }
        return {"ok": True}

    client.call = AsyncMock(side_effect=fake_call)

    await client._v2_auto_propose_state("group.agentid.pub/12345")

    assert "group.get_state" in calls
    assert "group.v2.propose_state" not in calls
    assert "group.v2.confirm_state" not in calls


@pytest.mark.asyncio
async def test_v2_pending_proposal_confirm_verifies_committed_base_and_hash():
    from unittest.mock import AsyncMock
    from aun_core.v2.state.commitment import compute_state_commitment

    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-alice"
    client._slot_id = "slot-a"
    client._v2_session = object()
    group_id = "group.agentid.pub/12345"
    base_payload = {
        "members": [{"aid": "alice.agentid.pub", "devices": []}],
        "audit_aids": [],
        "admin_set": {"admin_aids": ["alice.agentid.pub"], "threshold": 1},
        "join_policy_hash": None,
        "recovery_quorum": None,
        "history_policy": "recent_7_days",
        "wrap_protocol": "3DH",
    }
    next_payload = {
        **base_payload,
        "members": [
            {"aid": "alice.agentid.pub", "devices": []},
            {"aid": "bob.agentid.pub", "devices": []},
        ],
    }
    base_hash = compute_state_commitment(group_id, 1, base_payload)
    next_hash = compute_state_commitment(group_id, 2, next_payload)
    calls: list[str] = []

    async def fake_call(method, params):
        calls.append(method)
        if method == "group.v2.get_proposal":
            return {"proposal": {
                "proposal_id": "sp-1",
                "state_version": 2,
                "state_hash": next_hash,
                "prev_state_hash": base_hash,
                "membership_snapshot": json.dumps(next_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            }}
        if method == "group.get_state":
            return {
                "state_version": 1,
                "state_hash": base_hash,
                "key_epoch": 0,
                "membership_snapshot": json.dumps(base_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            }
        return {"ok": True}

    client.call = AsyncMock(side_effect=fake_call)

    assert await client._v2_confirm_pending_proposal(group_id) is True
    assert calls == ["group.v2.get_proposal", "group.get_state", "group.v2.confirm_state"]


@pytest.mark.asyncio
async def test_v2_state_retry_needed_triggers_leader_delay_reproposal():
    from unittest.mock import AsyncMock

    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-alice"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._v2_auto_propose_state = AsyncMock()

    await client._on_v2_state_retry_needed({"group_id": "group.agentid.pub/12345"})

    client._v2_auto_propose_state.assert_awaited_once_with("group.agentid.pub/12345", leader_delay=True)


@pytest.mark.asyncio
async def test_restore_before_transport_connect():
    """SeqTracker restore 必须在 transport.connect 之前被调用（避免启动期竞态）。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._seq_tracker = SeqTracker()
    client._seq_tracker_context = None
    client._gap_fill_done = set()
    client._gap_fill_active = False
    client._pushed_seqs = {}
    client._aid = "alice.aid.com"
    client._device_id = "dev1"
    client._slot_id = "s1"
    client._identity = {"aid": "alice.aid.com"}
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._session_params = None
    client._connect_delivery_mode = {}
    client._state = "idle"
    client._gateway_url = None
    client._loop = asyncio.get_running_loop()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._keystore = MagicMock()
    client._keystore.load_all_seqs = MagicMock(return_value={})
    client._auth = MagicMock()
    client._auth.set_instance_context = MagicMock()
    client._auth.connect_session = AsyncMock(
        return_value={"identity": {"aid": "alice.aid.com"}, "token": "t"}
    )
    client._transport = MagicMock()
    client._transport.connect = AsyncMock(return_value={"challenge": "x"})
    client._start_background_tasks = MagicMock()
    client._upload_prekey = AsyncMock()
    client._resolve_gateway = lambda p: "wss://gw"
    client._sync_identity_after_connect = MagicMock()

    # 记录调用次序
    call_order: list[str] = []
    original_restore = AUNClient._restore_seq_tracker_state.__get__(client, AUNClient)

    def traced_restore():
        call_order.append("restore")
        original_restore()

    original_connect = client._transport.connect

    async def traced_connect(url):
        call_order.append("transport.connect")
        return await original_connect(url)

    client._restore_seq_tracker_state = traced_restore
    client._transport.connect = traced_connect

    await client._connect_once(
        {"gateway": "wss://gw", "access_token": "t"}, allow_reauth=True
    )

    restore_idx = call_order.index("restore")
    connect_idx = call_order.index("transport.connect")
    assert restore_idx < connect_idx, f"call order: {call_order}"


@pytest.mark.asyncio
async def test_restore_after_aid_change_during_auth():
    """auth 阶段 aid 发生变化时，二次 restore 被触发。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._seq_tracker = SeqTracker()
    client._seq_tracker_context = None
    client._gap_fill_done = set()
    client._gap_fill_active = False
    client._pushed_seqs = {}
    client._aid = "alice.aid.com"
    client._device_id = "dev1"
    client._slot_id = "s1"
    client._identity = {"aid": "alice.aid.com"}
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._session_params = {"access_token": "t"}
    client._connect_delivery_mode = {}
    client._state = "idle"
    client._gateway_url = None
    client._loop = asyncio.get_running_loop()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._keystore = MagicMock()
    client._keystore.load_all_seqs = MagicMock(return_value={})
    client._auth = MagicMock()
    client._auth.set_instance_context = MagicMock()

    # auth 返回不同 aid，模拟身份覆盖（复现 client.py:1841 路径）
    async def fake_connect_session(transport, challenge, url, **kwargs):
        client._aid = "bob.aid.com"
        return {"identity": {"aid": "bob.aid.com"}, "token": "t"}

    client._auth.connect_session = fake_connect_session
    client._transport = MagicMock()
    client._transport.connect = AsyncMock(return_value={"challenge": "x"})
    client._start_background_tasks = MagicMock()
    client._upload_prekey = AsyncMock()
    client._resolve_gateway = lambda p: "wss://gw"
    client._sync_identity_after_connect = MagicMock()

    restore_count = {"n": 0}
    original_restore = AUNClient._restore_seq_tracker_state.__get__(client, AUNClient)

    def traced_restore():
        restore_count["n"] += 1
        original_restore()

    client._restore_seq_tracker_state = traced_restore

    await client._connect_once(
        {"gateway": "wss://gw", "access_token": "t"}, allow_reauth=True
    )

    assert restore_count["n"] == 2, f"expected 2 restores, got {restore_count['n']}"


# ── P2P push 解密失败仍应 auto-ack ────────────────────────────


@pytest.mark.asyncio
async def test_p2p_push_decrypt_failure_still_auto_acks():
    """P2P push 解密返回 None 时，若 SeqTracker 已推进 contiguous，仍应发送 message.ack。

    Bug 场景：_decrypt_single_message 返回 None（replay guard 判定重复或解密失败），
    代码直接 return，auto-ack 代码在 return 之后，导致 contiguous 已推进但 ack 未发送。
    """
    from unittest.mock import AsyncMock, MagicMock

    client = AUNClient({"aun_path": "/tmp/test_ack_on_decrypt_fail"})
    client._aid = "alice.aid.com"
    client._device_id = "dev-1"
    client._state = "connected"
    client._loop = asyncio.get_running_loop()

    # 记录 transport.call 的调用
    ack_calls: list[dict] = []

    async def fake_transport_call(method, params):
        if method == "message.ack":
            ack_calls.append({"method": method, "params": params})
        return {}

    client._transport.call = fake_transport_call

    # 模拟解密返回 None（replay guard 判定重复）
    async def fake_decrypt_single(msg, source=None):
        return None  # 返回 None 表示解密失败/重复消息

    client._decrypt_single_message = fake_decrypt_single

    # 模拟群组密钥消息拦截（返回 False，不拦截）
    async def fake_try_handle_group_key(msg):
        return False

    client._try_handle_group_key_message = fake_try_handle_group_key

    # 发送 seq=1 的消息（contiguous 会从 0 推进到 1）
    msg = {
        "message_id": "msg-1",
        "from": "bob.aid.com",
        "to": "alice.aid.com",
        "seq": 1,
        "payload": {"type": "e2ee.encrypted", "data": "ENCRYPTED"},
        "timestamp": 1000,
    }

    await client._process_and_publish_message(msg)
    # P1-17: auto-ack 改为 fire-and-forget，需让事件循环执行 pending task
    await asyncio.sleep(0)

    # contiguous 应已推进到 1
    ns = "p2p:alice.aid.com"
    assert client._seq_tracker.get_contiguous_seq(ns) == 1

    # 即使解密返回 None，也应发送 message.ack
    assert len(ack_calls) == 1, f"期望 1 次 ack，实际 {len(ack_calls)} 次: {ack_calls}"
    assert ack_calls[0]["params"]["seq"] == 1


@pytest.mark.asyncio
async def test_published_message_events_fallback_current_instance_context(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "published_instance_context")})
    client._device_id = "dev-1"
    client._slot_id = "slot-a"

    p2p_ns = "p2p:alice.aid.com"
    group_ns = "group:g1"
    client._seq_tracker.on_message_seq(p2p_ns, 1)
    client._seq_tracker.on_message_seq(group_ns, 1)

    p2p_events: list[dict] = []
    group_events: list[dict] = []
    client._dispatcher.subscribe("message.received", lambda data: p2p_events.append(data))
    client._dispatcher.subscribe("group.message_created", lambda data: group_events.append(data))

    assert await client._publish_ordered_message(
        "message.received", p2p_ns, 1, {"seq": 1, "payload": {"type": "text"}}
    )
    assert await client._publish_ordered_message(
        "group.message_created", group_ns, 1, {"group_id": "g1", "seq": 1, "payload": {"type": "text"}}
    )

    assert p2p_events[0]["device_id"] == "dev-1"
    assert p2p_events[0]["slot_id"] == "slot-a"
    assert group_events[0]["device_id"] == "dev-1"
    assert group_events[0]["slot_id"] == "slot-a"


@pytest.mark.asyncio
async def test_pulled_batch_publishes_internal_gap(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "pulled_batch_gap")})
    ns = "p2p:alice.aid.com"
    client._seq_tracker.on_message_seq(ns, 1)
    client._seq_tracker.force_contiguous_seq(ns, 2)

    published: list[int] = []
    client._dispatcher.subscribe("message.received", lambda data: published.append(int(data["seq"])))

    assert await client._publish_pulled_message("message.received", ns, 2, {"seq": 2})
    assert await client._publish_pulled_message("message.received", ns, 4, {"seq": 4})
    client._seq_tracker.force_contiguous_seq(ns, 4)

    assert published == [2, 4]
    assert client._is_published_seq(ns, 2)
    assert client._is_published_seq(ns, 4)
    client._prune_pushed_seqs(ns)
    assert client._is_published_seq(ns, 2)
    assert client._is_published_seq(ns, 4)


@pytest.mark.asyncio
async def test_p2p_push_ignores_other_slot_context(tmp_path):
    from unittest.mock import AsyncMock

    client = AUNClient({"aun_path": str(tmp_path / "p2p_other_slot")})
    client._aid = "alice.aid.com"
    client._device_id = "dev-1"
    client._slot_id = "slot-a"
    client._state = "connected"
    client._loop = asyncio.get_running_loop()

    published: list[dict] = []
    client._dispatcher.subscribe("message.received", lambda data: published.append(data))
    client._transport.call = AsyncMock(return_value={})
    client._try_handle_group_key_message = AsyncMock(return_value=False)
    client._decrypt_single_message = AsyncMock(side_effect=lambda msg, source=None: msg)

    await client._process_and_publish_message({
        "message_id": "m-other-slot",
        "from": "bob.aid.com",
        "to": "alice.aid.com",
        "seq": 1,
        "slot_id": "slot-b",
        "payload": {"type": "text", "text": "wrong slot"},
    })
    await asyncio.sleep(0)

    assert published == []
    assert not client._decrypt_single_message.called


def _make_disconnect_client():
    """构造用于 _handle_transport_disconnect 测试的 client 和参数捕获列表。"""
    from aun_core.logger import NullLogger
    client = object.__new__(AUNClient)
    client._log = NullLogger()
    client._closing = False
    client._state = "connected"
    client._reconnect_task = None
    client._server_kicked = False
    client._aid = None
    client._session_options = {
        "auto_reconnect": True,
        "retry": {"initial_delay": 1.0, "max_delay": 64.0},
    }

    captured_server_initiated = []

    class _FakeDispatcher:
        async def publish(self, event, data):
            pass

    client._dispatcher = _FakeDispatcher()

    async def fake_stop_background_tasks():
        pass

    client._stop_background_tasks = fake_stop_background_tasks

    async def fake_reconnect_loop(server_initiated=False):
        captured_server_initiated.append(server_initiated)

    client._reconnect_loop = fake_reconnect_loop

    return client, captured_server_initiated


@pytest.mark.asyncio
async def test_close_code_1000_not_server_initiated():
    """close_code=1000 是正常关闭（客户端主动），不应被标记为 server_initiated。
    server_initiated=True 会导致重连延迟从 16s 起跳。"""
    client, captured = _make_disconnect_client()

    await client._handle_transport_disconnect(error=None, close_code=1000)
    # 让 create_task 调度的协程得以执行
    await asyncio.sleep(0)

    assert len(captured) == 1
    assert captured[0] is False, \
        "close_code=1000（正常关闭）不应被标记为 server_initiated"


@pytest.mark.asyncio
async def test_close_code_1001_is_server_initiated():
    """close_code=1001（going away）应被视为 server_initiated。"""
    client, captured = _make_disconnect_client()

    await client._handle_transport_disconnect(error=None, close_code=1001)
    await asyncio.sleep(0)

    assert len(captured) == 1
    assert captured[0] is True, \
        "close_code=1001（going away）应被标记为 server_initiated"


@pytest.mark.asyncio
async def test_close_code_1006_not_server_initiated():
    """close_code=1006（异常断开）不应被视为 server_initiated。"""
    client, captured = _make_disconnect_client()

    await client._handle_transport_disconnect(error=None, close_code=1006)
    await asyncio.sleep(0)

    assert len(captured) == 1
    assert captured[0] is False, \
        "close_code=1006（异常断开）不应被标记为 server_initiated"


@pytest.mark.asyncio
async def test_close_code_none_not_server_initiated():
    """close_code=None（无 close frame）不应被视为 server_initiated。"""
    client, captured = _make_disconnect_client()

    await client._handle_transport_disconnect(error=None, close_code=None)
    await asyncio.sleep(0)

    assert len(captured) == 1
    assert captured[0] is False, \
        "close_code=None 不应被标记为 server_initiated"


def test_fetch_peer_cert_uses_explicit_timeout(monkeypatch):
    """PY-017: _fetch_peer_cert 应设置合理的 HTTP 超时，而非依赖 aiohttp 默认 300s。"""
    import aiohttp

    captured_timeouts = []
    original_init = aiohttp.ClientSession.__init__

    def patched_init(self, *args, **kwargs):
        captured_timeouts.append(kwargs.get("timeout"))
        original_init(self, *args, **kwargs)

    client = AUNClient()
    client._gateway_url = "https://gateway.example.com"

    # 拦截 aiohttp.ClientSession.__init__ 以捕获 timeout 参数
    monkeypatch.setattr(aiohttp.ClientSession, "__init__", patched_init)

    # 模拟 HTTP 响应，避免真实网络请求
    cert_pem, cert_fp = _make_test_cert("test.aid.com")

    class FakeResponse:
        status = 200
        async def text(self):
            return cert_pem
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            pass
        def raise_for_status(self):
            pass

    class FakeContextManager:
        """模拟 aiohttp session.get() 返回的异步上下文管理器。"""
        async def __aenter__(self):
            return FakeResponse()
        async def __aexit__(self, *a):
            pass

    def fake_get(self, url, **kwargs):
        return FakeContextManager()

    monkeypatch.setattr(aiohttp.ClientSession, "get", fake_get)

    # 跳过 PKI 验证
    async def fake_verify(gateway_url, cert_obj, aid):
        pass
    monkeypatch.setattr(client._auth, "verify_peer_certificate", fake_verify)

    asyncio.run(client._fetch_peer_cert("test.aid.com"))

    assert len(captured_timeouts) >= 1, "应至少创建一个 ClientSession"
    timeout_obj = captured_timeouts[0]
    assert timeout_obj is not None, (
        "PY-017: _fetch_peer_cert 必须显式设置 HTTP 超时，"
        "不能依赖 aiohttp 默认 300s"
    )
    # 超时不应超过 30s（合理范围）
    assert timeout_obj.total is not None and timeout_obj.total <= 30, (
        f"PY-017: HTTP 超时应不超过 30s，实际为 {timeout_obj.total}s"
    )


# ── PY-003: off() 事件注销方法 ────────────────────────────


class TestOffMethod:
    """PY-003: AUNClient 必须提供 off() 方法注销事件处理器。"""

    def test_off_removes_handler(self):
        """off() 后 handler 不再被调用。"""
        client = AUNClient()
        called = []

        def handler(data):
            called.append(data)

        client.on("test.event", handler)
        client.off("test.event", handler)
        asyncio.run(client._dispatcher.publish("test.event", {"x": 1}))
        assert called == [], "off() 后 handler 不应被调用"

    def test_off_only_removes_specific_handler(self):
        """off() 只移除指定的 handler，不影响其他 handler。"""
        client = AUNClient()
        called_a = []
        called_b = []

        def handler_a(data):
            called_a.append(data)

        def handler_b(data):
            called_b.append(data)

        client.on("test.event", handler_a)
        client.on("test.event", handler_b)
        client.off("test.event", handler_a)
        asyncio.run(client._dispatcher.publish("test.event", {"x": 1}))
        assert called_a == [], "handler_a 应被移除"
        assert len(called_b) == 1, "handler_b 不应受影响"

    def test_off_nonexistent_handler_no_error(self):
        """移除未注册的 handler 不应报错。"""
        client = AUNClient()

        def handler(data):
            pass

        # 不应抛出异常
        client.off("test.event", handler)

    def test_off_returns_none(self):
        """off() 返回 None（无返回值）。"""
        client = AUNClient()

        def handler(data):
            pass

        client.on("test.event", handler)
        result = client.off("test.event", handler)
        assert result is None


# ── PY-012: 签名失败抛出 ClientSignatureError ──────────────


class TestSignatureFailureRaises:
    """PY-012: _sign_client_operation 签名失败时必须抛出
    ClientSignatureError 而非静默降级或抛出其他异常类型。"""

    def test_sign_failure_raises_client_signature_error(self, tmp_path):
        """私钥损坏时签名应抛出 ClientSignatureError。"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._identity = {
            "aid": "test.example.com",
            "private_key_pem": "INVALID_KEY_DATA",
            "cert": "INVALID_CERT_DATA",
        }
        params = {"group_id": "g1", "content": "hello"}
        with pytest.raises(ClientSignatureError):
            client._sign_client_operation("group.send", params)

    def test_sign_failure_does_not_silently_continue(self, tmp_path):
        """签名失败后 params 中不应有 client_signature 字段。"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._identity = {
            "aid": "test.example.com",
            "private_key_pem": "BROKEN_PEM",
        }
        params = {"group_id": "g1"}
        try:
            client._sign_client_operation("group.send", params)
        except Exception:
            pass
        assert "client_signature" not in params, (
            "PY-012: 签名失败时 params 不应包含 client_signature"
        )

    def test_sign_failure_preserves_original_cause(self, tmp_path):
        """ClientSignatureError 应保留原始异常信息（__cause__）。"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._identity = {
            "aid": "test.example.com",
            "private_key_pem": "BAD_KEY",
        }
        params = {}
        with pytest.raises(ClientSignatureError) as exc_info:
            client._sign_client_operation("group.send", params)
        assert exc_info.value.__cause__ is not None, (
            "PY-012: ClientSignatureError 应通过 'from exc' 保留原始异常链"
        )


# ── PY-001: list_identities() 集成测试 ────────────────────


class TestClientListIdentities:
    """PY-001: AUNClient.list_identities() 必须能正常工作。"""

    def test_list_identities_returns_list(self, tmp_path):
        """list_identities() 返回列表类型。"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        result = client.list_identities()
        assert isinstance(result, list)

    def test_list_identities_with_saved_identity(self, tmp_path):
        """保存身份后 list_identities() 能返回它。"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._keystore.save_key_pair("test.agentid.pub", {
            "private_key_pem": "KEY",
            "public_key_der_b64": "PUB",
            "curve": "P-256",
        })
        result = client.list_identities()
        aids = [item["aid"] for item in result]
        assert "test.agentid.pub" in aids


# ── R1: max_attempts 支持 + health-fail 路径约束 ────────────


def _make_reconnect_client():
    """构造用于 _reconnect_loop 测试的 client。"""
    client = object.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._closing = False
    client._state = "connected"
    client._reconnect_task = None
    client._server_kicked = False
    client._gateway_url = "ws://gateway.example.com/aun"
    from aun_core.logger import NullLogger; client._log = NullLogger()

    published = []

    class _FakeDispatcher:
        async def publish(self, event, data):
            published.append((event, data))

    class _FakeDiscovery:
        async def check_health(self, url, timeout=5):
            return False  # 始终不健康

    class _FakeTransport:
        async def close(self):
            pass

    client._dispatcher = _FakeDispatcher()
    client._discovery = _FakeDiscovery()
    client._transport = _FakeTransport()

    async def _fast_reconnect_sleep(delay: float):
        await asyncio.sleep(0)

    client._reconnect_sleep = _fast_reconnect_sleep

    return client, published


@pytest.mark.asyncio
async def test_max_attempts_stops_reconnect_on_health_fail():
    """R1: max_attempts > 0 时，health 持续失败也应在达到上限后终止。"""
    client, published = _make_reconnect_client()
    client._session_options = {
        "auto_reconnect": True,
        "retry": {"initial_delay": 0.01, "max_delay": 0.01, "max_attempts": 3},
        "timeouts": {"connect": 5, "call": 10, "http": 30},
    }

    await client._reconnect_loop()

    assert client._state == "terminal_failed"
    # 应该发布 terminal_failed 事件
    terminal_events = [
        (e, d) for e, d in published
        if e == "connection.state" and d.get("state") == "terminal_failed"
    ]
    assert len(terminal_events) == 1
    assert terminal_events[0][1].get("reason") == "max_attempts_exhausted"


@pytest.mark.asyncio
async def test_max_attempts_zero_means_infinite():
    """max_attempts=0 表示无限重试（默认值），循环不应因 max_attempts 终止。"""
    client, published = _make_reconnect_client()
    client._session_options = {
        "auto_reconnect": True,
        "retry": {"initial_delay": 0.001, "max_delay": 0.001, "max_attempts": 0},
        "timeouts": {"connect": 5, "call": 10, "http": 30},
    }

    # 5 次 health-fail 后手动停止
    attempt_count = [0]
    orig_check = client._discovery.check_health

    async def counting_check(url, timeout=5):
        attempt_count[0] += 1
        if attempt_count[0] >= 5:
            client._closing = True
        return False

    client._discovery.check_health = counting_check

    await client._reconnect_loop()

    # 应该循环了 5 次，不是因为 max_attempts 终止
    assert attempt_count[0] >= 5
    assert client._state != "terminal_failed"


@pytest.mark.asyncio
async def test_max_attempts_stops_reconnect_on_connect_fail():
    """max_attempts > 0 时，连接失败也应在达到上限后终止。"""
    client, published = _make_reconnect_client()
    client._session_options = {
        "auto_reconnect": True,
        "retry": {"initial_delay": 0.01, "max_delay": 0.01, "max_attempts": 2},
        "timeouts": {"connect": 5, "call": 10, "http": 30},
    }

    # health 总是健康，但连接总是失败
    async def healthy_check(url, timeout=5):
        return True

    client._discovery.check_health = healthy_check

    async def failing_connect():
        raise ConnectionError("gateway down")

    client._invoke_reconnect_connect_once = failing_connect

    await client._reconnect_loop()

    assert client._state == "terminal_failed"
    terminal_events = [
        (e, d) for e, d in published
        if e == "connection.state" and d.get("state") == "terminal_failed"
    ]
    assert len(terminal_events) == 1
    assert terminal_events[0][1].get("reason") == "max_attempts_exhausted"


# ── R3: 批量路径解密失败不应出现在返回结果中 ──────────────────
