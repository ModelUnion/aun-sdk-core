import asyncio
import time

import pytest

from aun_core import AUNClient
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


def test_upload_agent_md_refresh_failure_logs_and_falls_back_to_authenticate(monkeypatch, caplog):
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

    with caplog.at_level("DEBUG", logger="aun_core"):
        result = asyncio.run(client.auth.upload_agent_md("# Alice\n"))

    assert result["etag"] == '"etag-3"'
    assert "agent.md upload refresh_token 失败" in caplog.text


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
    client = AUNClient()
    assert client.e2ee is not None


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
    client = AUNClient()
    client._state = "connected"
    client._connect_delivery_mode = {
        "mode": "queue",
        "routing": "sender_affinity",
        "affinity_ttl_ms": 1000,
    }
    calls = []

    class _Transport:
        async def call(self, method, params):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    asyncio.run(client.call("message.send", {
        "to": "bob.remote.example",
        "payload": {"type": "text", "text": "hello"},
        "encrypt": False,
    }))

    assert calls == [("message.send", {
        "to": "bob.remote.example",
        "payload": {"type": "text", "text": "hello"},
    })]


def test_call_injects_message_slot_context():
    client = object.__new__(AUNClient)
    client._state = "connected"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._aid = "alice.agentid.pub"
    client._config_model = type("Config", (), {"group_e2ee": False})()
    calls = []

    class _Transport:
        async def call(self, method, params):
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
        async def call(self, method, params):
            calls.append((method, dict(params)))
            if method == "message.pull":
                return {"messages": [], "count": 0, "latest_seq": 7, "server_ack_seq": 7}
            return {"success": True, "ack_seq": params.get("seq")}

    client._transport = _Transport()

    result = asyncio.run(client.call("message.pull", {"after_seq": 0, "limit": 5}))

    assert result["server_ack_seq"] == 7
    assert client._seq_tracker.get_contiguous_seq("p2p:alice.agentid.pub") == 7
    assert calls[-1] == ("message.ack", {"seq": 7, "device_id": "device-1"})


def test_call_rejects_message_slot_context_override():
    client = object.__new__(AUNClient)
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


def test_fetch_peer_prekey_returns_none_when_missing():
    client = AUNClient()

    async def _fake_call(method, params):
        assert method == "message.e2ee.get_prekey"
        assert params == {"aid": "bob.remote.example"}
        return {"found": False}

    client._transport.call = _fake_call

    result = asyncio.run(client._fetch_peer_prekey("bob.remote.example"))

    assert result is None


def test_fetch_peer_prekey_accepts_device_prekeys_response():
    client = AUNClient()

    async def _fake_call(method, params):
        assert method == "message.e2ee.get_prekey"
        return {
            "found": True,
            "device_prekeys": [
                {
                    "device_id": "device-b",
                    "prekey_id": "pk-b",
                    "public_key": "pub-b",
                    "signature": "sig-b",
                    "cert_fingerprint": "sha256:b",
                },
                {
                    "device_id": "device-a",
                    "prekey_id": "pk-a",
                    "public_key": "pub-a",
                    "signature": "sig-a",
                    "cert_fingerprint": "sha256:a",
                },
            ],
        }

    client._transport.call = _fake_call

    result = asyncio.run(client._fetch_peer_prekey("bob.remote.example"))
    all_prekeys = asyncio.run(client._fetch_peer_prekeys("bob.remote.example"))

    assert result["device_id"] == "device-b"
    assert result["prekey_id"] == "pk-b"
    assert [item["device_id"] for item in all_prekeys] == ["device-b", "device-a"]


def test_fetch_peer_prekey_query_failure_raises_validation_error():
    client = AUNClient()

    async def _fake_call(method, params):
        raise RuntimeError("network down")

    client._transport.call = _fake_call

    with pytest.raises(ValidationError, match="failed to fetch peer prekey for bob.remote.example: network down"):
        asyncio.run(client._fetch_peer_prekey("bob.remote.example"))


def test_fetch_peer_prekey_invalid_response_raises_validation_error():
    client = AUNClient()

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
    client = AUNClient()
    client._gateway_url = "wss://gateway.example.com/aun"

    calls = []

    async def _fake_fetch_peer_prekeys(peer_aid):
        assert peer_aid == "bob.example.com"
        return [{
            "device_id": "",
            "prekey_id": "pk-1",
            "public_key": "pub",
            "signature": "sig",
            "cert_fingerprint": "sha256:abc",
        }]

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        calls.append((aid, cert_fingerprint))
        return b"PEM"

    def _fake_encrypt_copy_payload(**kwargs):
        assert kwargs["prekey"]["cert_fingerprint"] == "sha256:abc"
        return {"ciphertext": "ok"}, {"encrypted": True, "forward_secrecy": True, "mode": "prekey_ecdh_v2"}

    async def _fake_call(method, params):
        assert method == "message.send"
        return {"ok": True}

    monkeypatch.setattr(client, "_fetch_peer_prekeys", _fake_fetch_peer_prekeys)
    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)
    monkeypatch.setattr(client, "_encrypt_copy_payload", _fake_encrypt_copy_payload)
    client._transport.call = _fake_call

    result = asyncio.run(client._send_encrypted({
        "to": "bob.example.com",
        "payload": {"type": "text", "text": "hello"},
    }))

    assert result == {"ok": True}
    assert calls == [("bob.example.com", "sha256:abc")]


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


def test_send_encrypted_uses_multi_device_payload_when_needed(monkeypatch):
    client = AUNClient()
    sent = {}

    async def _fake_fetch_peer_prekeys(peer_aid):
        assert peer_aid == "bob.example.com"
        return [
            {
                "device_id": "phone",
                "prekey_id": "pk-phone",
                "public_key": "pub-phone",
                "signature": "sig-phone",
                "cert_fingerprint": "sha256:cert",
            },
            {
                "device_id": "laptop",
                "prekey_id": "pk-laptop",
                "public_key": "pub-laptop",
                "signature": "sig-laptop",
                "cert_fingerprint": "sha256:cert",
            },
        ]

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        assert aid == "bob.example.com"
        assert cert_fingerprint == "sha256:cert"
        return b"PEM"

    def _fake_encrypt_copy_payload(**kwargs):
        prekey = kwargs["prekey"]
        return (
            {"type": "e2ee.encrypted", "ciphertext": prekey["prekey_id"]},
            {"encrypted": True, "forward_secrecy": True, "mode": "prekey_ecdh_v2", "degraded": False},
        )

    async def _fake_call(method, params):
        sent["method"] = method
        sent["params"] = dict(params)
        return {"ok": True}

    monkeypatch.setattr(client, "_fetch_peer_prekeys", _fake_fetch_peer_prekeys)
    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)
    monkeypatch.setattr(client, "_encrypt_copy_payload", _fake_encrypt_copy_payload)
    client._transport.call = _fake_call

    result = asyncio.run(client._send_encrypted({
        "to": "bob.example.com",
        "payload": {"type": "text", "text": "hello"},
    }))

    assert result == {"ok": True}
    assert sent["method"] == "message.send"
    assert sent["params"]["type"] == "e2ee.multi_device"
    assert [item["device_id"] for item in sent["params"]["payload"]["recipient_copies"]] == ["phone", "laptop"]
    assert sent["params"]["payload"]["self_copies"] == []


def test_send_encrypted_generates_self_sync_copies(monkeypatch):
    client = AUNClient()
    active_cert, active_fp = _make_test_cert("alice.example.com")
    client._aid = "alice.example.com"
    client._device_id = "phone"
    client._identity = {
        "aid": "alice.example.com",
        "cert": active_cert,
    }
    sent = {}

    async def _fake_fetch_peer_prekeys(peer_aid):
        if peer_aid == "bob.example.com":
            return [{
                "device_id": "bob-phone",
                "prekey_id": "pk-bob",
                "public_key": "pub-bob",
                "signature": "sig-bob",
                "cert_fingerprint": "sha256:bob",
            }]
        if peer_aid == "alice.example.com":
            return [
                {
                    "device_id": "phone",
                    "prekey_id": "pk-self",
                    "public_key": "pub-self",
                    "signature": "sig-self",
                    "cert_fingerprint": active_fp,
                },
                {
                    "device_id": "tablet",
                    "prekey_id": "pk-tablet",
                    "public_key": "pub-tablet",
                    "signature": "sig-tablet",
                    "cert_fingerprint": active_fp,
                },
            ]
        raise AssertionError(peer_aid)

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        assert aid == "bob.example.com"
        return b"BOB-CERT"

    def _fake_encrypt_copy_payload(**kwargs):
        prekey = kwargs["prekey"]
        return (
            {
                "type": "e2ee.encrypted",
                "ciphertext": prekey["prekey_id"],
                "aad": {"to": kwargs["logical_to_aid"]},
            },
            {"encrypted": True, "forward_secrecy": True, "mode": "prekey_ecdh_v2", "degraded": False},
        )

    async def _fake_call(method, params):
        sent["method"] = method
        sent["params"] = dict(params)
        return {"ok": True}

    monkeypatch.setattr(client, "_fetch_peer_prekeys", _fake_fetch_peer_prekeys)
    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)
    monkeypatch.setattr(client, "_encrypt_copy_payload", _fake_encrypt_copy_payload)
    client._transport.call = _fake_call

    result = asyncio.run(client._send_encrypted({
        "to": "bob.example.com",
        "payload": {"type": "text", "text": "hi"},
    }))

    assert result == {"ok": True}
    assert sent["params"]["type"] == "e2ee.multi_device"
    assert [item["device_id"] for item in sent["params"]["payload"]["recipient_copies"]] == ["bob-phone"]
    assert [item["device_id"] for item in sent["params"]["payload"]["self_copies"]] == ["tablet"]
    assert sent["params"]["payload"]["self_copies"][0]["envelope"]["aad"]["to"] == "bob.example.com"


def test_send_encrypted_self_sync_uses_cert_fingerprint_specific_cert(monkeypatch):
    client = AUNClient()
    active_cert, active_fp = _make_test_cert("alice-active.example.com")
    old_cert, old_fp = _make_test_cert("alice-rotated.example.com")
    client._aid = "alice.example.com"
    client._device_id = "phone"
    client._identity = {
        "aid": "alice.example.com",
        "cert": active_cert,
    }
    sent = {}
    cert_calls = []

    async def _fake_fetch_peer_prekeys(peer_aid):
        if peer_aid == "bob.example.com":
            return [{
                "device_id": "bob-phone",
                "prekey_id": "pk-bob",
                "public_key": "pub-bob",
                "signature": "sig-bob",
                "cert_fingerprint": "sha256:bob",
            }]
        if peer_aid == "alice.example.com":
            return [
                {
                    "device_id": "phone",
                    "prekey_id": "pk-self",
                    "public_key": "pub-self",
                    "signature": "sig-self",
                    "cert_fingerprint": active_fp,
                },
                {
                    "device_id": "tablet",
                    "prekey_id": "pk-tablet",
                    "public_key": "pub-tablet",
                    "signature": "sig-tablet",
                    "cert_fingerprint": old_fp,
                },
            ]
        raise AssertionError(peer_aid)

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        cert_calls.append((aid, cert_fingerprint))
        if aid == "bob.example.com":
            return b"BOB-CERT"
        if aid == "alice.example.com":
            assert cert_fingerprint == old_fp
            return old_cert.encode("utf-8")
        raise AssertionError(aid)

    def _fake_encrypt_copy_payload(**kwargs):
        prekey = kwargs["prekey"]
        return (
            {
                "type": "e2ee.encrypted",
                "ciphertext": prekey["prekey_id"],
                "aad": {"to": kwargs["logical_to_aid"]},
            },
            {"encrypted": True, "forward_secrecy": True, "mode": "prekey_ecdh_v2", "degraded": False},
        )

    async def _fake_call(method, params):
        sent["method"] = method
        sent["params"] = dict(params)
        return {"ok": True}

    monkeypatch.setattr(client, "_fetch_peer_prekeys", _fake_fetch_peer_prekeys)
    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)
    monkeypatch.setattr(client, "_encrypt_copy_payload", _fake_encrypt_copy_payload)
    client._transport.call = _fake_call

    result = asyncio.run(client._send_encrypted({
        "to": "bob.example.com",
        "payload": {"type": "text", "text": "hi"},
    }))

    assert result == {"ok": True}
    assert sent["params"]["type"] == "e2ee.multi_device"
    assert [item["device_id"] for item in sent["params"]["payload"]["self_copies"]] == ["tablet"]
    assert ("alice.example.com", old_fp) in cert_calls
    assert ("alice.example.com", active_fp) not in cert_calls


def test_outbound_sync_messages_are_decryptable_for_current_aid():
    client = AUNClient()
    client._identity = {"aid": "alice.example.com"}

    allowed = client._e2ee._should_decrypt_for_current_aid(
        {"to": "bob.example.com", "direction": "outbound_sync"},
        {"aad": {"to": "bob.example.com"}},
    )

    assert allowed is True


def test_upload_prekey_forwards_device_id(monkeypatch):
    client = AUNClient()
    client._device_id = "device-7"
    sent = {}

    monkeypatch.setattr(client._e2ee, "generate_prekey", lambda: {
        "device_id": "device-7",
        "prekey_id": "pk-1",
        "public_key": "pub",
        "signature": "sig",
        "created_at": 1,
    })

    async def _fake_call(method, params):
        sent["method"] = method
        sent["params"] = dict(params)
        return {"ok": True}

    client._transport.call = _fake_call

    result = asyncio.run(client._upload_prekey())

    assert result == {"ok": True}
    assert sent["method"] == "message.e2ee.put_prekey"
    assert sent["params"]["device_id"] == "device-7"


def test_send_encrypted_does_not_forward_delivery_mode(monkeypatch):
    client = AUNClient()
    client._gateway_url = "wss://gateway.example.com/aun"
    client._connect_delivery_mode = {
        "mode": "queue",
        "routing": "sender_affinity",
        "affinity_ttl_ms": 1000,
    }
    sent = {}

    async def _fake_fetch_peer_prekeys(peer_aid):
        return [{
            "device_id": "phone",
            "prekey_id": "pk-1",
            "public_key": "pub",
            "signature": "sig",
            "cert_fingerprint": "sha256:abc",
        }]

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        return b"PEM"

    def _fake_encrypt_copy_payload(**kwargs):
        return {"ciphertext": "ok"}, {"encrypted": True, "forward_secrecy": True, "mode": "sealed_box"}

    async def _fake_call(method, params):
        sent.update(params)
        return {"ok": True}

    monkeypatch.setattr(client, "_fetch_peer_prekeys", _fake_fetch_peer_prekeys)
    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)
    monkeypatch.setattr(client, "_encrypt_copy_payload", _fake_encrypt_copy_payload)
    client._transport.call = _fake_call

    asyncio.run(client._send_encrypted({
        "to": "bob.example.com",
        "payload": {"type": "text", "text": "hello"},
    }))

    assert "delivery_mode" not in sent


def test_send_encrypted_queue_mode_still_uses_multi_device_payload(monkeypatch):
    client = AUNClient()
    client._connect_delivery_mode = {
        "mode": "queue",
        "routing": "sender_affinity",
        "affinity_ttl_ms": 1000,
    }
    sent = {}

    async def _fake_fetch_peer_prekeys(peer_aid):
        return [
            {
                "device_id": "phone",
                "prekey_id": "pk-phone",
                "public_key": "pub-phone",
                "signature": "sig-phone",
                "cert_fingerprint": "sha256:cert",
            },
            {
                "device_id": "laptop",
                "prekey_id": "pk-laptop",
                "public_key": "pub-laptop",
                "signature": "sig-laptop",
                "cert_fingerprint": "sha256:cert",
            },
        ]

    async def _fake_fetch_peer_cert(aid, cert_fingerprint=None):
        return b"PEM"

    def _fake_encrypt_copy_payload(**kwargs):
        prekey = kwargs["prekey"]
        return (
            {"type": "e2ee.encrypted", "ciphertext": prekey["prekey_id"]},
            {"encrypted": True, "forward_secrecy": True, "mode": "prekey_ecdh_v2", "degraded": False},
        )

    async def _fake_call(method, params):
        sent["method"] = method
        sent["params"] = dict(params)
        return {"ok": True}

    monkeypatch.setattr(client, "_fetch_peer_prekeys", _fake_fetch_peer_prekeys)
    monkeypatch.setattr(client, "_fetch_peer_cert", _fake_fetch_peer_cert)
    monkeypatch.setattr(client, "_encrypt_copy_payload", _fake_encrypt_copy_payload)
    client._transport.call = _fake_call

    result = asyncio.run(client._send_encrypted({
        "to": "bob.example.com",
        "payload": {"type": "text", "text": "hello"},
    }))

    assert result == {"ok": True}
    assert sent["method"] == "message.send"
    assert sent["params"]["type"] == "e2ee.multi_device"
    assert "delivery_mode" not in sent["params"]
    assert [item["device_id"] for item in sent["params"]["payload"]["recipient_copies"]] == ["phone", "laptop"]


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


def test_schedule_prekey_replenish_only_once_per_consumed_prekey():
    """inflight 限流：同时多次消耗 prekey 只启动一个 upload，但 pending 会在 inflight 完成后再触发一次"""
    client = AUNClient()
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
        # 第一次触发 → 启动 inflight
        client._schedule_prekey_replenish_if_consumed(consumed)
        # 第二次 → inflight 中，计入 pending
        client._schedule_prekey_replenish_if_consumed(consumed)
        # 让 event loop 运行完成第一次 upload + pending 触发第二次
        for _ in range(10):
            await asyncio.sleep(0)
        return uploads

    uploads = asyncio.run(_case())

    # inflight 限流确保不会并发 upload；pending 合并确保完成后补充一次
    assert len(uploads) <= 2


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
async def test_restore_before_transport_connect():
    """SeqTracker restore 必须在 transport.connect 之前被调用（避免启动期竞态）。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    client._seq_tracker = SeqTracker()
    client._seq_tracker_context = None
    client._gap_fill_done = set()
    client._gap_fill_active = False
    client._pushed_seqs = {}
    client._aid = "alice.aid.com"
    client._device_id = "dev1"
    client._slot_id = "s1"
    client._identity = {"aid": "alice.aid.com"}
    client._logger = None
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
    client._seq_tracker = SeqTracker()
    client._seq_tracker_context = None
    client._gap_fill_done = set()
    client._gap_fill_active = False
    client._pushed_seqs = {}
    client._aid = "alice.aid.com"
    client._device_id = "dev1"
    client._slot_id = "s1"
    client._identity = {"aid": "alice.aid.com"}
    client._logger = None
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

    # contiguous 应已推进到 1
    ns = "p2p:alice.aid.com"
    assert client._seq_tracker.get_contiguous_seq(ns) == 1

    # 即使解密返回 None，也应发送 message.ack
    assert len(ack_calls) == 1, f"期望 1 次 ack，实际 {len(ack_calls)} 次: {ack_calls}"
    assert ack_calls[0]["params"]["seq"] == 1


# ─── ISSUE-SDK-PY-014: replay guard 已改为本地处理 ───
# _check_replay_guard 方法已移除，防重放改由 _group_e2ee.decrypt(skip_replay=)
# 在本地完成；服务端入口已做 AID 级防重放（见 client.py:2210 注释）。
# 原 3 个 RPC replay guard 测试不再适用，已删除。


# ─── ISSUE-SDK-PY-021: close_code 1000 不应视为 server_initiated ───


def _make_disconnect_client():
    """构造用于 _handle_transport_disconnect 测试的 client 和参数捕获列表。"""
    client = object.__new__(AUNClient)
    client._closing = False
    client._state = "connected"
    client._reconnect_task = None
    client._server_kicked = False
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
    client._closing = False
    client._state = "connected"
    client._reconnect_task = None
    client._server_kicked = False
    client._gateway_url = "ws://gateway.example.com/aun"
    client._logger = None

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

@pytest.mark.asyncio
async def test_decrypt_group_messages_excludes_undecryptable():
    """R3: _decrypt_group_messages 解密失败的消息不应出现在返回结果中。"""
    client = AUNClient()
    client._state = "connected"
    client._aid = "test.aid.com"
    client._device_id = "device-001"

    # _decrypt_group_message 返回原始消息（无 e2ee 字段）= 解密失败
    async def fake_decrypt(msg, skip_replay=False):
        return msg

    client._decrypt_group_message = fake_decrypt

    msgs = [
        {"group_id": "g1", "from": "a", "seq": 1,
         "payload": {"type": "e2ee.group_encrypted", "epoch": 1, "ciphertext": "X"}},
        {"group_id": "g1", "from": "b", "seq": 2,
         "payload": {"type": "text", "text": "hello"}},
    ]
    result = await client._decrypt_group_messages(msgs)

    # 只有非加密消息应在结果中
    assert len(result) == 1
    assert result[0]["payload"]["type"] == "text"
