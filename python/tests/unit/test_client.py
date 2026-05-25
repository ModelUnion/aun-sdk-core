import asyncio
import base64
import hashlib
import json
import time

import pytest

from aun_core import AUNClient, ProtectedHeaders
import aun_core.client as client_module
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


@pytest.mark.asyncio
async def test_v2_build_target_allows_explicit_empty_device_id():
    from unittest.mock import AsyncMock

    class FakeV2Session:
        def __init__(self):
            self.cached = []

        def cache_peer_ik(self, aid, device_id, pub_der):
            self.cached.append((aid, device_id, pub_der))

    client = AUNClient()
    fake_session = FakeV2Session()
    client._v2_session = fake_session
    client._v2_verify_spk_device = AsyncMock()
    ik_der = b"\x01\x02\x03"

    target = await client._v2_build_target_from_device(
        {"device_id": "", "ik_pk": base64.b64encode(ik_der).decode("ascii")},
        aid="bob.aid.com",
        device_id="",
        role="peer",
        default_key_source="peer_device_prekey",
    )

    assert target is not None
    assert target["aid"] == "bob.aid.com"
    assert target["device_id"] == ""
    assert fake_session.cached == [("bob.aid.com", "", ik_der)]


def test_v2_bootstrap_sender_ik_cache_allows_explicit_empty_device_id():
    class FakeV2Session:
        def __init__(self):
            self.cached = []

        def cache_peer_ik(self, aid, device_id, pub_der):
            self.cached.append((aid, device_id, pub_der))

    client = AUNClient()
    fake_session = FakeV2Session()
    client._v2_session = fake_session
    ik_der = b"\x01\x02\x03"

    client._v2_cache_peer_ik_from_device(
        {"device_id": "", "ik_pk": base64.b64encode(ik_der).decode("ascii")},
        "bob.aid.com",
    )

    assert fake_session.cached == [("bob.aid.com", "", ik_der)]


@pytest.mark.asyncio
async def test_v2_build_target_accepts_ik_in_spk_fields(monkeypatch):
    from unittest.mock import AsyncMock

    class FakeV2Session:
        def __init__(self):
            self.cached = []
            self.verified = []

        def cache_peer_ik(self, aid, device_id, pub_der):
            self.cached.append((aid, device_id, pub_der))

        def mark_peer_spk_verified(self, aid, device_id, spk_id):
            self.verified.append((aid, device_id, spk_id))

    client = AUNClient()
    fake_session = FakeV2Session()
    client._v2_session = fake_session
    ik_der = b"\x01\x02\x03"
    ik_b64 = base64.b64encode(ik_der).decode("ascii")
    ik_id = "sha256:" + hashlib.sha256(ik_der).hexdigest()[:16]
    monkeypatch.setattr(client, "_v2_trusted_ik_pub_der", AsyncMock(return_value=ik_der))

    target = await client._v2_build_target_from_device(
        {
            "device_id": "",
            "ik_pk": ik_b64,
            "spk_pk": ik_b64,
            "spk_id": ik_id,
            "key_source": "peer_device_prekey",
        },
        aid="bob.aid.com",
        device_id="",
        role="peer",
        default_key_source="peer_device_prekey",
    )

    assert target is not None
    assert target["aid"] == "bob.aid.com"
    assert target["device_id"] == ""
    assert target["spk_id"] == ik_id
    assert target["spk_pk_der"] == ik_der
    assert fake_session.cached == [("bob.aid.com", "", ik_der)]
    assert fake_session.verified == [("bob.aid.com", "", ik_id)]

@pytest.mark.asyncio
async def test_v2_auto_propose_leader_delay_treats_empty_device_id_as_candidate(monkeypatch):
    from unittest.mock import AsyncMock

    client = AUNClient()
    client._state = "connected"
    client._aid = "b-owner.aid.com"
    client._device_id = "dev-b"
    client._slot_id = "slot-b"
    client._v2_session = object()

    async def fake_call(method, params):
        if method == "group.get_online_members":
            return {"members": [
                {"aid": "a-owner.aid.com", "role": "owner", "online": True},
                {"aid": "b-owner.aid.com", "role": "owner", "online": True},
            ]}
        if method == "group.v2.bootstrap":
            return {"devices": [
                {"aid": "a-owner.aid.com", "device_id": "", "ik_fp": "ik-empty"},
                {"aid": "b-owner.aid.com", "device_id": "dev-b", "ik_fp": "ik-b"},
            ]}
        return {}

    sleep_calls = []

    async def fake_sleep(delay):
        sleep_calls.append(delay)

    client.call = AsyncMock(side_effect=fake_call)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    assert await client._v2_auto_propose_leader_delay("group.agentid.pub/12345") is True
    assert sleep_calls, "空 device_id 候选应排在当前设备前并触发 leader delay"

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


def test_connect_options_can_disable_background_sync():
    client = AUNClient()

    options = client._build_session_options({"background_sync": False})

    assert options["background_sync"] is False


def test_background_sync_false_disables_background_tasks():
    client = AUNClient()
    client._session_options["background_sync"] = False
    client._session_options["heartbeat_interval"] = 30

    client._start_background_tasks()

    assert client._heartbeat_task is None
    assert client._token_refresh_task is None


@pytest.mark.asyncio
async def test_group_spk_register_and_rotate_do_not_clear_bootstrap_cache():
    class FakeV2Session:
        def __init__(self):
            self.calls = []

        async def ensure_group_registered(self, group_id, _call):
            self.calls.append(("register", group_id))

        async def rotate_group_spk(self, group_id, _call):
            self.calls.append(("rotate", group_id))

    client = AUNClient()
    client._state = "connected"
    client._v2_session = FakeV2Session()
    client._v2_bootstrap_cache = {"group:group.agentid.pub/1": (["cached-device"], time.time())}

    client._schedule_group_spk_registration("group.agentid.pub/1", reason="unit")
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    client._schedule_group_spk_rotation("group.agentid.pub/1", reason="unit")
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert client._v2_bootstrap_cache["group:group.agentid.pub/1"][0] == ["cached-device"]
    assert client._v2_session.calls == [
        ("register", "group.agentid.pub/1"),
        ("rotate", "group.agentid.pub/1"),
    ]


@pytest.mark.asyncio
async def test_group_peer_prekey_fallback_does_not_rotate_p2p_spk(tmp_path, monkeypatch):
    class FakeV2Session:
        _last_uploaded_spk_id = "sha256:peer-spk"

        def __init__(self):
            self.rotate_called = False
            self.register_calls = []

        def get_group_decrypt_keys(self, group_id, spk_id):
            assert group_id == "group.agentid.pub/1"
            assert spk_id == "sha256:peer-spk"
            return (b"\x01" * 32, b"\x02" * 32)

        def get_peer_ik(self, _from_aid, _sender_device_id):
            return b"sender-public-key"

        def is_last_uploaded_group_spk(self, _group_id, _spk_id):
            return False

        def is_last_uploaded_spk(self, spk_id):
            return spk_id == "sha256:peer-spk"

        async def rotate_spk(self, _call):
            self.rotate_called = True

        async def ensure_group_registered(self, group_id, _call):
            self.register_calls.append(group_id)

    monkeypatch.setattr(
        client_module,
        "v2_decrypt_message",
        lambda **_kwargs: {"text": "group fallback"},
    )

    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    fake_session = FakeV2Session()
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-1"
    client._v2_session = fake_session
    client._state = "connected"

    envelope = {
        "type": "e2ee.group_encrypted",
        "group_id": "group.agentid.pub/1",
        "aad": {
            "from": "bob.agentid.pub",
            "from_device": "bob-dev",
            "group_id": "group.agentid.pub/1",
        },
        "recipient": {
            "aid": "alice.agentid.pub",
            "device_id": "dev-1",
            "key_source": "peer_device_prekey",
            "spk_id": "sha256:peer-spk",
        },
    }

    result = await client._decrypt_v2_message({
        "seq": 1,
        "message_id": "m1",
        "from_aid": "bob.agentid.pub",
        "group_id": "group.agentid.pub/1",
        "envelope_json": json.dumps(envelope),
        "t_server": 123,
    })
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    result2 = await client._decrypt_v2_message({
        "seq": 2,
        "message_id": "m2",
        "from_aid": "bob.agentid.pub",
        "group_id": "group.agentid.pub/1",
        "envelope_json": json.dumps(envelope),
        "t_server": 124,
    })
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert result["payload"] == {"text": "group fallback"}
    assert result2["payload"] == {"text": "group fallback"}
    assert fake_session.rotate_called is False
    assert fake_session.register_calls == ["group.agentid.pub/1"]



def test_v2_e2ee_metadata_exposes_payload_type_with_fallback():
    client = AUNClient()
    envelope = {
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "payload_type": "text",
        "protected_headers": {"payload_type": "fallback", "trace_id": "trace-1", "_auth": "secret"},
        "context": {"type": "run", "id": "run-1", "_auth": "secret"},
    }

    meta = client._v2_thought_e2ee_metadata(envelope)

    assert meta["payload_type"] == "text"
    assert meta["protected_headers"] == {"payload_type": "fallback", "trace_id": "trace-1"}
    assert meta["context"] == {"type": "run", "id": "run-1"}

    fallback_meta = client._v2_thought_e2ee_metadata({
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "protected_headers": {"payload_type": "fallback", "_auth": "secret"},
    })
    assert fallback_meta["payload_type"] == "fallback"


@pytest.mark.asyncio
async def test_decrypt_v2_message_exposes_payload_type_in_e2ee(tmp_path, monkeypatch):
    class FakeV2Session:
        def get_decrypt_keys(self, spk_id):
            assert spk_id == ""
            return (b"\\x01" * 32, None)

        def get_peer_ik(self, _from_aid, _sender_device_id):
            return b"sender-public-key"

        def is_last_uploaded_spk(self, _spk_id):
            return False

    monkeypatch.setattr(
        client_module,
        "v2_decrypt_message",
        lambda **_kwargs: {"type": "text", "text": "decrypted"},
    )

    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-1"
    client._v2_session = FakeV2Session()
    client._state = "connected"
    envelope = {
        "type": "e2ee.p2p_encrypted",
        "version": "v2",
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "payload_type": "text",
        "aad": {"from": "bob.agentid.pub", "from_device": "bob-dev"},
        "recipients": [["alice.agentid.pub", "dev-1", "peer", "aid_master", "fp", "", "n", "w"]],
        "protected_headers": {"payload_type": "text", "_auth": "secret"},
    }

    result = await client._decrypt_v2_message({
        "seq": 1,
        "message_id": "m1",
        "from_aid": "bob.agentid.pub",
        "envelope_json": json.dumps(envelope),
        "t_server": 123,
    })

    assert result["payload"] == {"type": "text", "text": "decrypted"}
    assert result["payload_type"] == "text"
    assert result["protected_headers"] == {"payload_type": "text"}
    assert result["e2ee"]["payload_type"] == "text"

@pytest.mark.asyncio
async def test_decrypt_v2_message_undecryptable_event_preserves_metadata(tmp_path):
    class FakeV2Session:
        def get_decrypt_keys(self, spk_id):
            assert spk_id == "missing-spk"
            raise RuntimeError("spk missing")

    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-1"
    client._v2_session = FakeV2Session()
    client._state = "connected"
    published: list[tuple[str, dict]] = []

    async def _publish(event, payload):
        published.append((event, payload))

    client._dispatcher.publish = _publish
    envelope = {
        "type": "e2ee.p2p_encrypted",
        "version": "v2",
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "payload_type": "text",
        "aad": {"from": "bob.agentid.pub", "from_device": "bob-dev"},
        "recipients": [["alice.agentid.pub", "dev-1", "peer", "peer_device_prekey", "fp", "missing-spk", "n", "w"]],
        "protected_headers": {"payload_type": "text", "trace_id": "trace-1", "_auth": "secret"},
    }

    result = await client._decrypt_v2_message({
        "seq": 1,
        "message_id": "m1",
        "from_aid": "bob.agentid.pub",
        "envelope_json": json.dumps(envelope),
        "t_server": 123,
    })

    assert result is None
    assert published[0][0] == "message.undecryptable"
    event = published[0][1]
    assert event["payload_type"] == "text"
    assert event["protected_headers"] == {"payload_type": "text", "trace_id": "trace-1"}
    assert "_auth" not in event["protected_headers"]

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


def test_message_send_content_alias_is_normalized_for_plaintext():
    client = AUNClient()
    client._state = "connected"
    calls = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    asyncio.run(client.call("message.send", {
        "to": "bob.remote.example",
        "content": {"text": "hello"},
        "encrypt": False,
    }))

    assert calls == [("message.send", {
        "to": "bob.remote.example",
        "payload": {"type": "text", "text": "hello"},
    })]


def test_message_send_content_alias_reaches_encrypted_payload():
    client = AUNClient()
    client._state = "connected"
    client._v2_session = object()
    captured = []

    async def _fake_send(params):
        captured.append(dict(params))
        return {"ok": True}

    client._send_encrypted_v2 = _fake_send

    asyncio.run(client.call("message.send", {
        "to": "bob.remote.example",
        "content": {"text": "hello"},
    }))

    assert captured == [{
        "to": "bob.remote.example",
        "payload": {"type": "text", "text": "hello"},
    }]


def test_group_send_text_payload_gets_default_payload_type():
    client = AUNClient()
    client._state = "connected"
    client._v2_session = object()
    captured = []

    async def _fake_send(params):
        captured.append(dict(params))
        return {"ok": True}

    client._send_group_encrypted_v2 = _fake_send

    asyncio.run(client.call("group.send", {
        "group_id": "g1.example.com",
        "payload": {"text": "hello group"},
    }))

    assert captured == [{
        "group_id": "group.example.com/g1",
        "payload": {"type": "text", "text": "hello group"},
        "device_id": client._device_id,
        "slot_id": client._slot_id,
    }]


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

@pytest.mark.asyncio
async def test_message_thought_get_decrypts_v2_envelope_and_preserves_metadata():
    client = AUNClient()
    client._state = "connected"
    client._aid = "bob.agentid.pub"
    client._device_id = "dev-b"
    client._slot_id = "slot-b"
    client._v2_session = object()

    calls: list[tuple[str, dict]] = []
    decrypt_calls: list[tuple[dict, str]] = []
    envelope = {
        "type": "e2ee.p2p_encrypted",
        "version": "v2",
        "suite": "x25519-hkdf-aesgcm",
        "payload_type": "thought",
        "protected_headers": {"payload_type": "thought", "trace_id": "trace-1", "_auth": "secret"},
        "context": {"type": "run", "id": "run-1", "_auth": "secret"},
    }
    raw_item = {
        "thought_id": "mt-1",
        "message_id": "m-1",
        "from": "alice.agentid.pub",
        "to": "bob.agentid.pub",
        "payload": envelope,
        "context": {"type": "run", "id": "run-1"},
        "created_at": 12345,
        "client_signature": {"sig": "keep"},
    }

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            return {
                "found": True,
                "sender_aid": "alice.agentid.pub",
                "peer_aid": "bob.agentid.pub",
                "thoughts": [dict(raw_item)],
            }

    async def _decrypt(envelope, from_aid):
        decrypt_calls.append((envelope, from_aid))
        return {"type": "thought", "text": "hello"}

    client._transport = _Transport()
    client._decrypt_v2_envelope_for_thought = _decrypt

    result = await client.call("message.thought.get", {
        "sender_aid": "alice.agentid.pub",
        "context": {"type": "run", "id": "run-1"},
    })

    thought = result["thoughts"][0]
    assert calls[0][0] == "message.thought.get"
    assert decrypt_calls == [(envelope, "alice.agentid.pub")]
    assert thought["payload"] == {"type": "thought", "text": "hello"}
    assert thought["thought_id"] == "mt-1"
    assert thought["message_id"] == "m-1"
    assert thought["from"] == "alice.agentid.pub"
    assert thought["to"] == "bob.agentid.pub"
    assert thought["context"] == {"type": "run", "id": "run-1"}
    assert thought["created_at"] == 12345
    assert thought["client_signature"] == {"sig": "keep"}
    assert thought["encrypted"] is True
    assert thought["payload_type"] == "thought"
    assert thought["protected_headers"] == {"payload_type": "thought", "trace_id": "trace-1"}
    assert thought["e2ee"]["version"] == "v2"
    assert thought["e2ee"]["payload_type"] == "thought"
    assert thought["e2ee"]["protected_headers"] == {"payload_type": "thought", "trace_id": "trace-1"}
    assert thought["e2ee"]["context"] == {"type": "run", "id": "run-1"}

    repeat = await client.call("message.thought.get", {
        "sender_aid": "alice.agentid.pub",
        "context": {"type": "run", "id": "run-1"},
    })
    assert repeat["thoughts"][0]["payload"]["text"] == "hello"
    assert len(decrypt_calls) == 2

@pytest.mark.asyncio
async def test_message_thought_get_decrypt_failed_preserves_metadata():
    client = AUNClient()
    client._state = "connected"
    client._aid = "bob.agentid.pub"
    client._device_id = "dev-b"
    client._v2_session = object()
    envelope = {
        "type": "e2ee.p2p_encrypted",
        "version": "v2",
        "suite": "x25519-hkdf-aesgcm",
        "payload_type": "thought",
        "protected_headers": {"payload_type": "thought", "trace_id": "trace-1", "_auth": "secret"},
    }

    class _Transport:
        async def call(self, method, params, **kwargs):
            return {
                "found": True,
                "sender_aid": "alice.agentid.pub",
                "peer_aid": "bob.agentid.pub",
                "thoughts": [{"thought_id": "mt-1", "payload": envelope}],
            }

    async def _decrypt(envelope, from_aid):
        return None

    client._transport = _Transport()
    client._decrypt_v2_envelope_for_thought = _decrypt

    result = await client.call("message.thought.get", {
        "sender_aid": "alice.agentid.pub",
        "context": {"type": "run", "id": "run-1"},
    })

    thought = result["thoughts"][0]
    assert thought["decrypt_failed"] is True
    assert thought["payload_type"] == "thought"
    assert thought["protected_headers"] == {"payload_type": "thought", "trace_id": "trace-1"}
    assert "_auth" not in thought["protected_headers"]

@pytest.mark.asyncio
async def test_group_thought_get_decrypts_v2_envelope_and_preserves_metadata():
    client = AUNClient()
    client._state = "connected"
    client._aid = "bob.agentid.pub"
    client._device_id = "dev-b"
    client._slot_id = "slot-b"
    client._v2_session = object()

    decrypt_calls: list[tuple[dict, str]] = []
    envelope = {
        "type": "e2ee.group_encrypted",
        "version": "v2",
        "suite": "x25519-hkdf-aesgcm",
        "context": {"type": "group", "id": "g-run"},
    }

    class _Transport:
        async def call(self, method, params, **kwargs):
            return {
                "found": True,
                "group_id": "group.agentid.pub/g-1",
                "sender_aid": "alice.agentid.pub",
                "thoughts": [{
                    "thought_id": "gt-1",
                    "message_id": "gm-1",
                    "sender_aid": "alice.agentid.pub",
                    "payload": envelope,
                    "context": {"type": "group", "id": "g-run"},
                    "created_at": 67890,
                    "audit": {"keep": True},
                }],
            }

    async def _decrypt(envelope, from_aid):
        decrypt_calls.append((envelope, from_aid))
        return {"type": "thought", "text": "group hello"}

    client._transport = _Transport()
    client._decrypt_v2_envelope_for_thought = _decrypt

    result = await client.call("group.thought.get", {
        "group_id": "group.agentid.pub/g-1",
        "sender_aid": "alice.agentid.pub",
        "context": {"type": "group", "id": "g-run"},
    })

    thought = result["thoughts"][0]
    assert decrypt_calls == [(envelope, "alice.agentid.pub")]
    assert thought["payload"] == {"type": "thought", "text": "group hello"}
    assert thought["thought_id"] == "gt-1"
    assert thought["message_id"] == "gm-1"
    assert thought["sender_aid"] == "alice.agentid.pub"
    assert thought["context"] == {"type": "group", "id": "g-run"}
    assert thought["created_at"] == 67890
    assert thought["audit"] == {"keep": True}
    assert thought["encrypted"] is True
    assert thought["e2ee"]["version"] == "v2"

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


def test_group_send_content_alias_is_normalized_for_plaintext():
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
        "content": {"text": "群明文"},
        "encrypt": False,
    }))

    assert len(calls) == 1
    method, params = calls[0]
    assert method == "group.send"
    assert "content" not in params
    assert params["payload"] == {"type": "text", "text": "群明文"}


def test_group_send_content_alias_reaches_encrypted_payload():
    client = AUNClient()
    client._state = "connected"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    captured = []

    async def _fake_send(params):
        captured.append(dict(params))
        return {"ok": True}

    client._send_group_encrypted_v2 = _fake_send

    asyncio.run(client.call("group.send", {
        "group_id": "group.example.com/g-test",
        "content": {"text": "群密文"},
    }))

    assert len(captured) == 1
    assert "content" not in captured[0]
    assert captured[0]["payload"] == {"type": "text", "text": "群密文"}


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


def test_message_pull_empty_result_applies_server_ack_floor_without_direct_ack():
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
    assert calls == [("message.pull", {
        "after_seq": 0,
        "limit": 5,
        "device_id": "device-1",
        "slot_id": "slot-a",
    })]


@pytest.mark.asyncio
async def test_v2_p2p_pull_batches_auto_ack_once_with_final_contiguous_seq():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": seq,
                            "message_id": f"m-{seq}",
                            "from_aid": "bob.agentid.pub",
                            "t_server": seq,
                            "legacy_v1": {
                                "to": "alice.agentid.pub",
                                "payload": {"type": "text", "text": f"m-{seq}"},
                            },
                        }
                        for seq in (1, 2, 3)
                    ],
                }
            if method == "message.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("message.pull", {"after_seq": 0, "limit": 10})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not any(method == "message.v2.ack" for method, _ in calls):
        await asyncio.sleep(0.01)

    ack_calls = [(method, params) for method, params in calls if method == "message.v2.ack"]
    assert [msg["seq"] for msg in result["messages"]] == [1, 2, 3]
    assert ack_calls == [("message.v2.ack", {"up_to_seq": 3})]


@pytest.mark.asyncio
async def test_v2_group_pull_batches_auto_ack_once_with_final_contiguous_seq():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "group.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": seq,
                            "message_id": f"gm-{seq}",
                            "from_aid": "bob.agentid.pub",
                            "t_server": seq,
                            "type": "message",
                            "payload": {"type": "text", "text": f"gm-{seq}"},
                        }
                        for seq in (1, 2, 3)
                    ],
                }
            if method == "group.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("group.pull", {"group_id": "group.agentid.pub/g1", "after_seq": 0, "limit": 10})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not any(method == "group.v2.ack" for method, _ in calls):
        await asyncio.sleep(0.01)

    ack_calls = [(method, params) for method, params in calls if method == "group.v2.ack"]
    assert [msg["seq"] for msg in result["messages"]] == [1, 2, 3]
    assert ack_calls == [("group.v2.ack", {"group_id": "group.agentid.pub/g1", "up_to_seq": 3})]


@pytest.mark.asyncio
async def test_v2_p2p_pull_continues_pages_and_acks_each_page():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                after_seq = int(params.get("after_seq") or 0)
                if after_seq == 0:
                    seqs = (1, 2)
                elif after_seq == 2:
                    seqs = (3,)
                else:
                    seqs = ()
                return {
                    "has_more": after_seq == 0,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": seq,
                            "message_id": f"m-{seq}",
                            "from_aid": "bob.agentid.pub",
                            "t_server": seq,
                            "legacy_v1": {
                                "to": "alice.agentid.pub",
                                "payload": {"type": "text", "text": f"m-{seq}"},
                            },
                        }
                        for seq in seqs
                    ],
                }
            if method == "message.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("message.pull", {"after_seq": 0, "limit": 2})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len([c for c in calls if c[0] == "message.v2.ack"]) < 2:
        await asyncio.sleep(0.01)

    pull_calls = [(method, params) for method, params in calls if method == "message.v2.pull"]
    ack_calls = [(method, params) for method, params in calls if method == "message.v2.ack"]
    assert [msg["seq"] for msg in result["messages"]] == [1, 2, 3]
    assert result["raw_count"] == 3
    assert result["latest_seq"] == 3
    assert pull_calls == [
        ("message.v2.pull", {"after_seq": 0, "limit": 2}),
        ("message.v2.pull", {"after_seq": 2, "limit": 2}),
    ]
    assert ack_calls == [
        ("message.v2.ack", {"up_to_seq": 2}),
        ("message.v2.ack", {"up_to_seq": 3}),
    ]


@pytest.mark.asyncio
async def test_v2_group_pull_continues_pages_and_acks_each_page():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "group.v2.pull":
                after_seq = int(params.get("after_seq") or 0)
                if after_seq == 0:
                    seqs = (1, 2)
                elif after_seq == 2:
                    seqs = (3,)
                else:
                    seqs = ()
                return {
                    "has_more": after_seq == 0,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": seq,
                            "message_id": f"gm-{seq}",
                            "from_aid": "bob.agentid.pub",
                            "t_server": seq,
                            "type": "message",
                            "payload": {"type": "text", "text": f"gm-{seq}"},
                        }
                        for seq in seqs
                    ],
                }
            if method == "group.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("group.pull", {"group_id": "group.agentid.pub/g1", "after_seq": 0, "limit": 2})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len([c for c in calls if c[0] == "group.v2.ack"]) < 2:
        await asyncio.sleep(0.01)

    pull_calls = [(method, params) for method, params in calls if method == "group.v2.pull"]
    ack_calls = [(method, params) for method, params in calls if method == "group.v2.ack"]
    assert [msg["seq"] for msg in result["messages"]] == [1, 2, 3]
    assert result["raw_count"] == 3
    assert result["latest_seq"] == 3
    assert pull_calls == [
        ("group.v2.pull", {
            "group_id": "group.agentid.pub/g1",
            "after_seq": 0,
            "limit": 2,
            "device_id": "device-1",
            "slot_id": "slot-a",
        }),
        ("group.v2.pull", {
            "group_id": "group.agentid.pub/g1",
            "after_seq": 2,
            "limit": 2,
            "device_id": "device-1",
            "slot_id": "slot-a",
        }),
    ]
    assert ack_calls == [
        ("group.v2.ack", {"group_id": "group.agentid.pub/g1", "up_to_seq": 2}),
        ("group.v2.ack", {"group_id": "group.agentid.pub/g1", "up_to_seq": 3}),
    ]


@pytest.mark.asyncio
async def test_v2_p2p_pull_empty_page_does_not_ack_existing_contiguous_seq():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    client._seq_tracker.force_contiguous_seq("p2p:alice.agentid.pub", 5)
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                return {"has_more": False, "messages": []}
            if method == "message.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("message.pull", {"after_seq": 5, "limit": 10})
    await asyncio.sleep(0.05)

    assert result["raw_count"] == 0
    assert [(method, params) for method, params in calls if method == "message.v2.ack"] == []


@pytest.mark.asyncio
async def test_v2_p2p_pull_stale_raw_without_contiguous_advance_does_not_ack():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    client._seq_tracker.force_contiguous_seq("p2p:alice.agentid.pub", 5)
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": 5,
                            "message_id": "m-5",
                            "from_aid": "bob.agentid.pub",
                            "legacy_v1": {"payload": {"type": "text", "text": "old"}},
                        },
                    ],
                }
            if method == "message.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("message.pull", {"after_seq": 5, "limit": 10})
    await asyncio.sleep(0.05)

    assert result["raw_count"] == 1
    assert client._seq_tracker.get_contiguous_seq("p2p:alice.agentid.pub") == 5
    assert [(method, params) for method, params in calls if method == "message.v2.ack"] == []


@pytest.mark.asyncio
async def test_v2_p2p_pull_publishes_after_contiguous_advance_and_acks_once():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    calls: list[tuple[str, dict]] = []
    observed_contig: list[int] = []
    client.on("message.received", lambda _msg: observed_contig.append(client._seq_tracker.get_contiguous_seq(ns)))

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": seq,
                            "message_id": f"m-event-{seq}",
                            "from_aid": "bob.agentid.pub",
                            "t_server": seq,
                            "legacy_v1": {
                                "to": "alice.agentid.pub",
                                "payload": {"type": "text", "text": f"m-event-{seq}"},
                            },
                        }
                        for seq in (1, 2, 3)
                    ],
                }
            if method == "message.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    await client.call("message.pull", {"after_seq": 0, "limit": 10})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not any(method == "message.v2.ack" for method, _ in calls):
        await asyncio.sleep(0.01)

    assert observed_contig == [3, 3, 3]
    assert [(method, params) for method, params in calls if method == "message.v2.ack"] == [
        ("message.v2.ack", {"up_to_seq": 3}),
    ]


@pytest.mark.asyncio
async def test_v2_group_pull_empty_page_does_not_ack_existing_contiguous_seq():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    client._seq_tracker.force_contiguous_seq("group:group.agentid.pub/g1", 5)
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "group.v2.pull":
                return {"has_more": False, "messages": []}
            if method == "group.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("group.pull", {"group_id": "group.agentid.pub/g1", "after_seq": 5, "limit": 10})
    await asyncio.sleep(0.05)

    assert result["raw_count"] == 0
    assert [(method, params) for method, params in calls if method == "group.v2.ack"] == []


@pytest.mark.asyncio
async def test_v2_group_pull_stale_raw_without_contiguous_advance_does_not_ack():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    client._seq_tracker.force_contiguous_seq("group:group.agentid.pub/g1", 5)
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "group.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": 5,
                            "message_id": "gm-5",
                            "from_aid": "bob.agentid.pub",
                            "payload": {"type": "text", "text": "old"},
                        },
                    ],
                }
            if method == "group.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client.call("group.pull", {"group_id": "group.agentid.pub/g1", "after_seq": 5, "limit": 10})
    await asyncio.sleep(0.05)

    assert result["raw_count"] == 1
    assert client._seq_tracker.get_contiguous_seq("group:group.agentid.pub/g1") == 5
    assert [(method, params) for method, params in calls if method == "group.v2.ack"] == []


@pytest.mark.asyncio
async def test_v2_group_pull_publishes_after_contiguous_advance_and_acks_once():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "group:group.agentid.pub/g1"
    calls: list[tuple[str, dict]] = []
    observed_contig: list[int] = []
    client.on("group.message_created", lambda _msg: observed_contig.append(client._seq_tracker.get_contiguous_seq(ns)))

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "group.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {
                            "version": "v1",
                            "seq": seq,
                            "message_id": f"gm-event-{seq}",
                            "from_aid": "bob.agentid.pub",
                            "t_server": seq,
                            "type": "message",
                            "payload": {"type": "text", "text": f"gm-event-{seq}"},
                        }
                        for seq in (1, 2, 3)
                    ],
                }
            if method == "group.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    await client.call("group.pull", {"group_id": "group.agentid.pub/g1", "after_seq": 0, "limit": 10})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not any(method == "group.v2.ack" for method, _ in calls):
        await asyncio.sleep(0.01)

    assert observed_contig == [3, 3, 3]
    assert [(method, params) for method, params in calls if method == "group.v2.ack"] == [
        ("group.v2.ack", {"group_id": "group.agentid.pub/g1", "up_to_seq": 3}),
    ]


@pytest.mark.asyncio
async def test_v2_p2p_payload_push_gap_falls_through_to_pull():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.on_message_seq(ns, 1)

    async def fake_decrypt(msg):
        return {
            "message_id": msg["message_id"],
            "from": msg["from_aid"],
            "to": "alice.agentid.pub",
            "seq": msg["seq"],
            "payload": {"type": "text", "text": "push-3"},
            "encrypted": True,
        }

    pull_calls: list[dict] = []

    async def fake_pull(params):
        pull_calls.append(dict(params))
        return {"messages": []}

    client._decrypt_v2_message = fake_decrypt
    client._pull_v2_internal = fake_pull

    await client._on_v2_push_notification({
        "seq": 3,
        "message_id": "m-push-3",
        "from_aid": "bob.agentid.pub",
        "envelope_json": "{}",
    })

    assert pull_calls == [{}]
    assert client._seq_tracker.get_contiguous_seq(ns) == 1
    assert client._seq_tracker.get_max_seen_seq(ns) == 3


@pytest.mark.asyncio
async def test_v2_p2p_payload_push_contiguous_publishes_without_pull():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.on_message_seq(ns, 1)
    events: list[dict] = []
    pull_calls: list[dict] = []

    client._dispatcher.subscribe("message.received", lambda data: events.append(data))

    async def fake_decrypt(msg):
        return {
            "message_id": msg["message_id"],
            "from": msg["from_aid"],
            "to": "alice.agentid.pub",
            "seq": msg["seq"],
            "payload": {"type": "text", "text": "push-2"},
            "encrypted": True,
        }

    async def fake_pull(params):
        pull_calls.append(dict(params))
        return {"messages": []}

    client._decrypt_v2_message = fake_decrypt
    client._pull_v2_internal = fake_pull

    await client._on_v2_push_notification({
        "seq": 2,
        "message_id": "m-push-2",
        "from_aid": "bob.agentid.pub",
        "envelope_json": "{}",
    })

    assert pull_calls == []
    assert client._seq_tracker.get_contiguous_seq(ns) == 2
    assert client._seq_tracker.get_max_seen_seq(ns) == 2
    assert [event["payload"]["text"] for event in events] == ["push-2"]


@pytest.mark.asyncio
async def test_v2_p2p_payload_push_inflight_gap_still_records_upper_bound_and_pending():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.on_message_seq(ns, 1)
    client._gap_fill_done[f"p2p_pull:{ns}"] = time.time()
    events: list[dict] = []
    pull_calls: list[dict] = []

    client._dispatcher.subscribe("message.received", lambda data: events.append(data))

    async def fake_decrypt(msg):
        return {
            "message_id": msg["message_id"],
            "from": msg["from_aid"],
            "to": "alice.agentid.pub",
            "seq": msg["seq"],
            "payload": {"type": "text", "text": "push-3"},
            "encrypted": True,
        }

    async def fake_pull(params):
        pull_calls.append(dict(params))
        return {"messages": []}

    client._decrypt_v2_message = fake_decrypt
    client._pull_v2_internal = fake_pull

    await client._on_v2_push_notification({
        "seq": 3,
        "message_id": "m-push-3",
        "from_aid": "bob.agentid.pub",
        "envelope_json": "{}",
    })

    assert pull_calls == []
    assert events == []
    assert client._seq_tracker.get_contiguous_seq(ns) == 1
    assert client._seq_tracker.get_max_seen_seq(ns) == 3
    assert client._is_pending_ordered_seq(ns, 3)


@pytest.mark.asyncio
async def test_v2_p2p_payload_push_decrypt_failure_with_gap_triggers_pull():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.on_message_seq(ns, 1)
    pull_calls: list[dict] = []

    async def fake_decrypt(msg):
        return None

    async def fake_pull(params):
        pull_calls.append(dict(params))
        return {"messages": []}

    client._decrypt_v2_message = fake_decrypt
    client._pull_v2_internal = fake_pull

    await client._on_v2_push_notification({
        "seq": 3,
        "message_id": "m-push-3",
        "from_aid": "bob.agentid.pub",
        "envelope_json": "{}",
    })

    assert pull_calls == [{}]
    assert client._seq_tracker.get_contiguous_seq(ns) == 1
    assert client._seq_tracker.get_max_seen_seq(ns) == 3


@pytest.mark.asyncio
async def test_v2_p2p_pull_preserves_raw_seq_metadata_when_decrypt_fails():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"

    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                return {
                    "has_more": False,
                    "server_ack_seq": 9,
                    "messages": [
                        {"seq": 2, "message_id": "m2", "from_aid": "bob.agentid.pub", "envelope_json": "{}"},
                        {"seq": 3, "message_id": "m3", "from_aid": "bob.agentid.pub", "envelope_json": "{}"},
                    ],
                }
            return {"ok": True}

    async def fake_decrypt(msg):
        return None

    client._transport = _Transport()
    client._decrypt_v2_message = fake_decrypt

    result = await client.call("message.pull", {"after_seq": 1, "limit": 10})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not any(method == "message.v2.ack" for method, _ in calls):
        await asyncio.sleep(0.01)

    assert result["messages"] == []
    assert result["latest_seq"] == 3
    assert result["raw_count"] == 2
    assert result["server_ack_seq"] == 9
    assert result["_contig_before"] == 0
    assert client._seq_tracker.get_contiguous_seq(ns) == 9
    assert client._seq_tracker.get_max_seen_seq(ns) == 9
    assert [(method, params) for method, params in calls if method == "message.v2.ack"] == [
        ("message.v2.ack", {"up_to_seq": 9})
    ]


@pytest.mark.asyncio
async def test_v2_p2p_pull_drains_pending_payload_after_gap_is_filled_and_acks_once():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.on_message_seq(ns, 1)
    client._seq_tracker.on_message_seq(ns, 3)
    client._enqueue_ordered_message(
        ns,
        "message.received",
        3,
        {
            "message_id": "m3",
            "from": "bob.agentid.pub",
            "to": "alice.agentid.pub",
            "seq": 3,
            "payload": {"type": "text", "text": "push-3"},
        },
    )
    events: list[dict] = []
    calls: list[tuple[str, dict]] = []
    client._dispatcher.subscribe("message.received", lambda data: events.append(data))

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {"seq": 2, "message_id": "m2", "from_aid": "bob.agentid.pub", "envelope_json": "{}"},
                    ],
                }
            if method == "message.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    async def fake_decrypt(msg):
        return {
            "message_id": msg["message_id"],
            "from": msg["from_aid"],
            "to": "alice.agentid.pub",
            "seq": msg["seq"],
            "payload": {"type": "text", "text": "pull-2"},
            "encrypted": True,
        }

    client._transport = _Transport()
    client._decrypt_v2_message = fake_decrypt

    result = await client.call("message.pull", {"after_seq": 1, "limit": 10})
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not any(method == "message.v2.ack" for method, _ in calls):
        await asyncio.sleep(0.01)

    assert [msg["seq"] for msg in result["messages"]] == [2]
    assert client._seq_tracker.get_contiguous_seq(ns) == 3
    assert [event["payload"]["text"] for event in events] == ["pull-2", "push-3"]
    assert not client._is_pending_ordered_seq(ns, 3)
    assert [(method, params) for method, params in calls if method == "message.v2.ack"] == [
        ("message.v2.ack", {"up_to_seq": 3})
    ]


@pytest.mark.asyncio
async def test_v2_p2p_pull_large_gap_skipped_rows_still_advances_to_max_seq():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "message.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {"version": "legacy", "seq": 10005, "message_id": "m-10005", "from_aid": "bob.agentid.pub"},
                        {"version": "legacy", "seq": 10008, "message_id": "m-10008", "from_aid": "bob.agentid.pub"},
                    ],
                }
            if method == "message.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client._pull_v2_internal({"after_seq": 0, "limit": 10})

    assert result["messages"] == []
    assert result["latest_seq"] == 10008
    assert result["raw_count"] == 2
    assert client._seq_tracker.get_contiguous_seq("p2p:alice.agentid.pub") == 10008


@pytest.mark.asyncio
async def test_v2_group_pull_large_gap_skipped_rows_still_advances_to_max_seq():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            if method == "group.v2.pull":
                return {
                    "has_more": False,
                    "messages": [
                        {"version": "v1", "seq": 10005, "message_id": "gm-10005", "from_aid": "bob.agentid.pub", "payload": {"type": "e2ee.group_encrypted"}},
                        {"version": "v1", "seq": 10008, "message_id": "gm-10008", "from_aid": "bob.agentid.pub", "payload": {"type": "e2ee.group_encrypted"}},
                    ],
                }
            if method == "group.v2.ack":
                return {"acked": params.get("up_to_seq", 0)}
            return {"ok": True}

    client._transport = _Transport()

    result = await client._pull_group_v2_internal({"group_id": "group.agentid.pub/g1", "after_seq": 0, "limit": 10})

    assert result["messages"] == []
    assert result["latest_seq"] == 10008
    assert result["raw_count"] == 2
    assert client._seq_tracker.get_contiguous_seq("group:group.agentid.pub/g1") == 10008


@pytest.mark.asyncio
async def test_v2_p2p_payload_push_repairs_dirty_contiguous_then_publishes():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    client._save_seq_tracker_state = lambda: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.force_contiguous_seq(ns, 99999)
    pull_calls: list[dict] = []
    ack_calls: list[tuple[str, dict]] = []
    events: list[dict] = []
    client._dispatcher.subscribe("message.received", lambda data: events.append(data))

    async def fake_decrypt(msg):
        return {
            "message_id": msg["message_id"],
            "from": msg["from_aid"],
            "to": "alice.agentid.pub",
            "seq": msg["seq"],
            "payload": {"type": "text", "text": "push-3"},
            "encrypted": True,
        }

    async def fake_pull(params):
        pull_calls.append({
            "params": dict(params),
            "contiguous_seq": client._seq_tracker.get_contiguous_seq(ns),
        })
        return {"messages": []}

    client._decrypt_v2_message = fake_decrypt
    client._pull_v2_internal = fake_pull
    client._fire_ack = lambda method, params, reason: ack_calls.append((method, dict(params)))

    await client._on_v2_push_notification({
        "seq": 3,
        "message_id": "m-push-3",
        "from_aid": "bob.agentid.pub",
        "envelope_json": "{}",
    })

    assert pull_calls == []
    assert [event["payload"]["text"] for event in events] == ["push-3"]
    assert client._seq_tracker.get_contiguous_seq(ns) == 3
    assert client._seq_tracker.get_max_seen_seq(ns) == 99999
    assert ack_calls == [("message.v2.ack", {"up_to_seq": 3})]


@pytest.mark.asyncio
async def test_v2_p2p_payload_push_equal_contiguous_is_idempotent():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.force_contiguous_seq(ns, 3)
    events: list[dict] = []
    pull_calls: list[dict] = []
    decrypt_calls: list[dict] = []
    ack_calls: list[tuple[str, dict]] = []
    client._dispatcher.subscribe("message.received", lambda data: events.append(data))

    async def fake_decrypt(msg):
        decrypt_calls.append(dict(msg))
        return {
            "message_id": msg["message_id"],
            "from": msg["from_aid"],
            "to": "alice.agentid.pub",
            "seq": msg["seq"],
            "payload": {"type": "text", "text": "push-3"},
            "encrypted": True,
        }

    async def fake_pull(params):
        pull_calls.append(dict(params))
        return {"messages": []}

    client._decrypt_v2_message = fake_decrypt
    client._pull_v2_internal = fake_pull
    client._fire_ack = lambda method, params, reason: ack_calls.append((method, dict(params)))

    await client._on_v2_push_notification({
        "seq": 3,
        "message_id": "m-push-3",
        "from_aid": "bob.agentid.pub",
        "envelope_json": "{}",
    })

    assert decrypt_calls == []
    assert pull_calls == []
    assert events == []
    assert ack_calls == []
    assert client._seq_tracker.get_contiguous_seq(ns) == 3
    assert client._seq_tracker.get_max_seen_seq(ns) == 3


@pytest.mark.asyncio
async def test_v2_p2p_notification_push_equal_contiguous_is_idempotent():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.force_contiguous_seq(ns, 3)
    pull_calls: list[dict] = []

    async def fake_pull(params):
        pull_calls.append(dict(params))
        return {"messages": []}

    client._pull_v2_internal = fake_pull

    await client._on_v2_push_notification({
        "seq": 3,
        "message_id": "m-push-3",
        "from_aid": "bob.agentid.pub",
    })

    assert pull_calls == []
    assert client._seq_tracker.get_contiguous_seq(ns) == 3
    assert client._seq_tracker.get_max_seen_seq(ns) == 3


@pytest.mark.asyncio
async def test_v2_p2p_notification_push_repairs_dirty_contiguous_below_push_then_pulls():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    ns = "p2p:alice.agentid.pub"
    client._seq_tracker.force_contiguous_seq(ns, 99999)
    pull_calls: list[dict] = []

    async def fake_pull(params):
        pull_calls.append({
            "params": dict(params),
            "contiguous_seq": client._seq_tracker.get_contiguous_seq(ns),
        })
        return {"messages": []}

    client._pull_v2_internal = fake_pull

    await client._on_v2_push_notification({
        "seq": 3,
        "message_id": "m-push-3",
        "from_aid": "bob.agentid.pub",
    })

    assert pull_calls == [{"params": {}, "contiguous_seq": 2}]
    assert client._seq_tracker.get_contiguous_seq(ns) == 2
    assert client._seq_tracker.get_max_seen_seq(ns) == 99999


@pytest.mark.asyncio
async def test_v2_group_notification_push_equal_contiguous_is_idempotent():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    group_id = "group.agentid.pub/g1"
    ns = f"group:{group_id}"
    client._seq_tracker.force_contiguous_seq(ns, 3)
    pull_calls: list[dict] = []

    async def fake_pull(params):
        pull_calls.append(dict(params))
        return {"messages": []}

    client._pull_group_v2_internal = fake_pull

    await client._on_raw_group_v2_message_created({
        "group_id": group_id,
        "seq": 3,
        "message_id": "gm-push-3",
        "sender_aid": "bob.agentid.pub",
    })

    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert pull_calls == []
    assert client._seq_tracker.get_contiguous_seq(ns) == 3
    assert client._seq_tracker.get_max_seen_seq(ns) == 3


@pytest.mark.asyncio
async def test_v2_group_notification_push_repairs_dirty_contiguous_below_push_then_pulls():
    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._persist_seq = lambda ns: None
    group_id = "group.agentid.pub/g1"
    ns = f"group:{group_id}"
    client._seq_tracker.force_contiguous_seq(ns, 99999)
    pull_calls: list[dict] = []

    async def fake_pull(params):
        pull_calls.append({
            "params": dict(params),
            "contiguous_seq": client._seq_tracker.get_contiguous_seq(ns),
        })
        return {"messages": []}

    client._pull_group_v2_internal = fake_pull

    await client._on_raw_group_v2_message_created({
        "group_id": group_id,
        "seq": 3,
        "message_id": "gm-push-3",
        "sender_aid": "bob.agentid.pub",
    })

    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not pull_calls:
        await asyncio.sleep(0.01)

    assert pull_calls == [{
        "params": {"group_id": group_id, "after_seq": 2, "limit": 50},
        "contiguous_seq": 2,
    }]
    assert client._seq_tracker.get_contiguous_seq(ns) == 2
    assert client._seq_tracker.get_max_seen_seq(ns) == 99999
@pytest.mark.asyncio
async def test_group_call_injects_empty_device_id_value(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "group_empty_device")})
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = ""
    client._slot_id = "slot-a"
    client._v2_session = None
    calls = []

    class _Transport:
        async def call(self, method, params):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    await client.call("group.get_state", {"group_id": "group.agentid.pub/1"})

    assert calls == [
        ("group.get_state", {
            "group_id": "group.agentid.pub/1",
            "device_id": "",
            "slot_id": "slot-a",
        }),
    ]


def test_attach_current_instance_context_includes_empty_device_id(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "attach_empty_device")})
    client._device_id = ""
    client._slot_id = "slot-a"

    payload = client._attach_current_instance_context({"seq": 1})

    assert "device_id" in payload
    assert payload["device_id"] == ""
    assert payload["slot_id"] == "slot-a"


def test_message_targets_current_instance_treats_empty_device_id_as_explicit(tmp_path):
    client = AUNClient({"aun_path": str(tmp_path / "target_empty_device")})
    client._device_id = "device-1"
    client._slot_id = "slot-a"

    assert client._message_targets_current_instance({}) is True
    assert client._message_targets_current_instance({"device_id": "device-1"}) is True
    assert client._message_targets_current_instance({"device_id": ""}) is False

    client._device_id = ""
    assert client._message_targets_current_instance({"device_id": ""}) is True


@pytest.mark.asyncio
async def test_p2p_gap_fill_empty_result_acks_server_ack_floor():
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

    await client._fill_p2p_gap()

    assert client._seq_tracker.get_contiguous_seq("p2p:alice.agentid.pub") == 7
    assert calls == [
        ("message.pull", {
            "after_seq": 0,
            "limit": 50,
            "device_id": "device-1",
            "slot_id": "slot-a",
        }),
        ("message.ack", {"seq": 7, "device_id": "device-1", "slot_id": "slot-a"}),
    ]


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
            return {
                "events": [{
                    "group_id": "g1",
                    "event_seq": 3,
                    "event_type": "group.announcement_updated",
                    "action": "announcement_updated",
                }],
                "count": 1,
                "cursor": {"current_seq": 3},
            }
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
async def test_group_pull_events_empty_page_advances_cursor_without_ack():
    """group.pull_events 空页可修正本地 cursor，但不应发送 ack_events。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._state = "connected"
    client._closing = False
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._seq_tracker = SeqTracker()
    client._seq_tracker.restore_state({"group_event:g1": 5})
    client._gap_fill_done = {}
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._persist_seq = lambda ns: None
    client._verify_event_signature = AsyncMock(return_value=True)
    transport = MagicMock()
    calls: list[tuple[str, dict]] = []

    async def fake_transport_call(method, params):
        calls.append((method, dict(params)))
        if method == "group.pull_events":
            return {"events": [], "count": 0, "cursor": {"current_seq": 9}}
        if method == "group.ack_events":
            return {"ok": True}
        return {}

    transport.call = AsyncMock(side_effect=fake_transport_call)
    client._transport = transport

    await client._fill_group_event_gap("g1")

    assert client._seq_tracker.get_contiguous_seq("group_event:g1") == 9
    assert [method for method, _ in calls].count("group.ack_events") == 0


@pytest.mark.asyncio
async def test_group_pull_events_acks_once_after_event_publish_final_contiguous():
    """事件发布阶段可继续推进 tracker，pull 结束后只 ack 一次最终 contiguous_seq。"""
    from unittest.mock import AsyncMock, MagicMock

    from aun_core.client import AUNClient
    from aun_core.seq_tracker import SeqTracker

    client = AUNClient.__new__(AUNClient)
    from aun_core.logger import NullLogger; client._log = NullLogger()
    client._state = "connected"
    client._closing = False
    client._device_id = "device-1"
    client._slot_id = "slot-a"
    client._seq_tracker = SeqTracker()
    ns = "group_event:g1"
    assert client._seq_tracker.on_message_seq(ns, 3) is True
    client._gap_fill_done = {}
    client._persist_seq = lambda ns: None
    client._verify_event_signature = AsyncMock(return_value=True)
    transport = MagicMock()
    calls: list[tuple[str, dict]] = []

    async def fake_transport_call(method, params):
        calls.append((method, dict(params)))
        if method == "group.pull_events":
            return {
                "events": [{
                    "group_id": "g1",
                    "event_seq": 2,
                    "event_type": "group.announcement_updated",
                    "action": "announcement_updated",
                }],
                "count": 1,
                "cursor": {"current_seq": 2},
            }
        if method == "group.ack_events":
            return {"ok": True}
        return {}

    async def fake_publish(event, payload):
        if event == "group.changed" and isinstance(payload, dict) and payload.get("_from_gap_fill"):
            client._seq_tracker.on_message_seq(ns, 4)

    transport.call = AsyncMock(side_effect=fake_transport_call)
    client._transport = transport
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock(side_effect=fake_publish)

    await client._fill_group_event_gap("g1")

    ack_calls = [params for method, params in calls if method == "group.ack_events"]
    assert ack_calls == [{"group_id": "g1", "event_seq": 4, "device_id": "device-1", "slot_id": "slot-a"}]
    assert client._seq_tracker.get_contiguous_seq(ns) == 4


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
async def test_group_changed_invite_code_used_triggers_v2_membership_recovery():
    from unittest.mock import AsyncMock, MagicMock

    client = AUNClient()
    client._state = "connected"
    client._aid = "alice.agentid.pub"
    client._device_id = "dev-alice"
    client._slot_id = "slot-a"
    client._v2_session = object()
    client._dispatcher.publish = AsyncMock()
    client._schedule_group_spk_rotation = MagicMock()
    client._schedule_group_spk_registration = MagicMock()
    client._v2_auto_propose_state = AsyncMock()

    await client._on_raw_group_changed({
        "group_id": "group.agentid.pub/12345",
        "action": "invite_code_used",
        "member_aid": "bob.agentid.pub",
        "actor_aid": "bob.agentid.pub",
    })
    await asyncio.sleep(0)

    client._schedule_group_spk_rotation.assert_called_once_with(
        "group.agentid.pub/12345", reason="group.changed:invite_code_used"
    )
    client._schedule_group_spk_registration.assert_not_called()
    client._v2_auto_propose_state.assert_awaited_once_with(
        "group.agentid.pub/12345", leader_delay=True
    )


@pytest.mark.asyncio
async def test_group_changed_joined_for_self_registers_group_spk():
    from unittest.mock import AsyncMock, MagicMock

    client = AUNClient()
    client._state = "connected"
    client._aid = "bob.agentid.pub"
    client._device_id = "dev-bob"
    client._slot_id = "slot-b"
    client._v2_session = object()
    client._dispatcher.publish = AsyncMock()
    client._schedule_group_spk_rotation = MagicMock()
    client._schedule_group_spk_registration = MagicMock()
    client._v2_auto_propose_state = AsyncMock()

    await client._on_raw_group_changed({
        "group_id": "group.agentid.pub/12345",
        "action": "joined",
        "member_aid": "bob.agentid.pub",
        "actor_aid": "bob.agentid.pub",
    })
    await asyncio.sleep(0)

    client._schedule_group_spk_registration.assert_called_once_with(
        "group.agentid.pub/12345", reason="group.changed:joined"
    )
    client._schedule_group_spk_rotation.assert_not_called()
    client._v2_auto_propose_state.assert_awaited_once_with(
        "group.agentid.pub/12345", leader_delay=True
    )


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
async def test_published_message_logs_content(tmp_path):
    class CaptureLogger:
        def __init__(self):
            self.debug_lines: list[str] = []

        def debug(self, module, msg, *args):
            self.debug_lines.append(msg % args if args else msg)

        def info(self, module, msg, *args):
            pass

        def warn(self, module, msg, *args):
            pass

        def error(self, module, msg, *args, err=None):
            pass

    client = AUNClient({"aun_path": str(tmp_path / "published_content_log")})
    logger = CaptureLogger()
    client._log = logger
    ns = "p2p:alice.aid.com"

    await client._publish_pulled_message(
        "message.received",
        ns,
        1,
        {"message_id": "m1", "from": "bob.aid.com", "seq": 1, "payload": {"type": "text", "text": "hello"}},
    )

    assert any('"source":"pull"' in line and '"payload":{"type":"text","text":"hello"}' in line for line in logger.debug_lines)


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
        async def read(self):
            return cert_pem.encode("utf-8")
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


@pytest.mark.asyncio
async def test_fetch_peer_cert_net_path_does_not_reference_removed_response(tmp_path, monkeypatch):
    client = AUNClient({"aun_path": str(tmp_path / "fetch_cert_net_path")})
    client._gateway_url = "wss://gateway.agentid.pub:20001/aun"
    cert_pem, _ = _make_test_cert("bob.agentid.pub")
    calls = []

    class FakeNet:
        async def http_get_text(self, url, *, timeout=5.0, headers=None):
            calls.append({"url": url, "timeout": timeout, "headers": headers})
            return cert_pem

    async def fake_verify(gateway_url, cert_obj, aid):
        assert gateway_url == "wss://gateway.agentid.pub:20001/aun"
        assert aid == "bob.agentid.pub"

    client._net = FakeNet()
    monkeypatch.setattr(client._auth, "verify_peer_certificate", fake_verify)

    cert_bytes = await client._fetch_peer_cert("bob.agentid.pub")

    assert cert_bytes == cert_pem.encode("utf-8")
    assert calls == [{
        "url": "https://gateway.agentid.pub:20001/pki/cert/bob.agentid.pub",
        "timeout": 10.0,
        "headers": None,
    }]


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
