from __future__ import annotations

import asyncio
import base64
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import aun_core.client as client_module
from aun_core import AIDStore, AUNClient, ConnectionState
from aun_core.errors import StateError


def _identity(aid: str) -> dict[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return {
        "aid": aid,
        "private_key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
        "public_key_der_b64": base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii"),
        "curve": "P-256",
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
    }


def _load_local_aid(tmp_path: Path, aid: str = "alice.agentid.pub"):
    store = AIDStore(tmp_path, "")
    store._keystore.save_identity(aid, _identity(aid))
    loaded = store.load(aid)
    assert loaded.ok
    return store, loaded.data["aid"]


def test_client_without_identity_starts_no_identity():
    client = AUNClient()

    assert client.state == ConnectionState.NO_IDENTITY
    assert client.slot_id == "default"
    assert client.has_identity is False
    assert client.can_sign is False
    assert client.can_connect is False
    assert client.can_send is False
    assert client.current_aid is None
    assert client.aun_path is None


def test_client_construct_with_aid_enters_standby(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)

    client = AUNClient(aid)
    client.set_protected_headers({"x-app": "demo"})

    assert client.state == ConnectionState.STANDBY
    assert client.current_aid is aid
    assert client.aid == aid.aid
    assert client.aun_path == aid.aun_path
    assert client.has_identity is True
    assert client.can_sign is True
    assert client.can_connect is True
    assert client.can_send is False
    assert client.get_protected_headers() == {"x-app": "demo"}

    store.close()


def test_client_construct_with_peer_only_aid_enters_no_identity(tmp_path: Path):
    """传入无私钥的 AID 应抛出 StateError（不允许静默降级）。"""
    store, _aid = _load_local_aid(tmp_path)
    peer_name = "peer.agentid.pub"
    store._keystore.save_cert(peer_name, _identity(peer_name)["cert"])
    peer = store.load(peer_name).data["aid"]

    assert peer.is_cert_valid() is True
    assert peer.is_private_key_valid() is False

    with pytest.raises(StateError):
        AUNClient(peer)

    store.close()


def test_client_load_identity_only_accepts_private_aid(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)
    store._keystore.save_cert("peer.agentid.pub", _identity("peer.agentid.pub")["cert"])
    peer = store.load("peer.agentid.pub").data["aid"]
    client = AUNClient()

    with pytest.raises(StateError, match="private key"):
        client.load_identity(peer)

    client.load_identity(aid)
    assert client.state == ConnectionState.STANDBY
    assert client.current_aid is aid
    assert client.aun_path == aid.aun_path
    assert client.config["aun_path"] == aid.aun_path

    with pytest.raises(StateError, match="load_identity"):
        client.load_identity(aid)

    store.close()


def test_client_peer_cache_methods_use_public_aid_objects(tmp_path: Path, monkeypatch):
    store, aid = _load_local_aid(tmp_path)
    peer_name = "peer.agentid.pub"
    store._keystore.save_cert(peer_name, _identity(peer_name)["cert"])
    peer = store.load(peer_name).data["aid"]
    client = AUNClient(aid)

    assert client.get_peer(peer_name) is None
    assert client.cache_peer(peer) is peer
    assert client.get_peer(peer_name) is peer
    assert client.peers() == [peer]

    class FakeStore:
        async def resolve(self, target, opts=None):
            assert target == "bob.agentid.pub"
            from aun_core import result_ok

            return result_ok({
                "aid": peer,
                "source": {"cert_from_cache": True, "agent_md_fetched": False},
            })

        def close(self):
            pass

    monkeypatch.setattr(client, "_make_aid_store", lambda: FakeStore())
    assert asyncio.run(client.lookup_peer(peer_name)) is peer
    resolver_client = AUNClient(aid)
    monkeypatch.setattr(resolver_client, "_make_aid_store", lambda: FakeStore())
    assert asyncio.run(resolver_client.lookup_peer("bob.agentid.pub")) is peer
    assert resolver_client.get_peer(peer.aid) is peer

    store.close()


def test_client_instance_protected_headers_merge_only_for_message_methods():
    client = AUNClient()
    client.set_protected_headers({"x-app": "demo", "trace": "base"})
    client._state = "ready"
    calls: list[tuple[str, dict]] = []

    class _Transport:
        async def call(self, method, params, **kwargs):
            calls.append((method, dict(params)))
            return {"ok": True}

    client._transport = _Transport()

    asyncio.run(client.call("message.send", {
        "to": "bob.agentid.pub",
        "payload": {"type": "text", "text": "hello"},
        "encrypt": False,
        "protected_headers": {"trace": "call"},
    }))
    asyncio.run(client.call("meta.ping", {}))

    assert calls[0][1]["protected_headers"] == {"x-app": "demo", "trace": "call"}
    assert "protected_headers" not in calls[1][1]


@pytest.mark.asyncio
async def test_authenticate_moves_standby_to_authenticated(tmp_path: Path, monkeypatch):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)

    from aun_core.discovery import GatewayDiscovery

    async def fake_discover(self, well_known_url: str, *, timeout: float = 5.0) -> str:
        return "ws://gateway.agentid.pub/aun"

    async def fake_authenticate(gateway_url: str, *, aid=None):
        return {"aid": aid, "access_token": "tok-auth", "gateway": gateway_url}

    monkeypatch.setattr(GatewayDiscovery, "discover", fake_discover)
    client._auth.authenticate = fake_authenticate
    client._auth.load_identity_or_none = lambda aid=None: {
        "aid": aid or client.aid,
        "access_token": "tok-auth",
    }

    result = await client.authenticate()

    assert result["access_token"] == "tok-auth"
    assert client.state == ConnectionState.AUTHENTICATED
    assert client.can_connect is True
    assert client.can_send is False

    store.close()


@pytest.mark.asyncio
async def test_connect_from_standby_authenticates_then_ready(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)
    seen: list[tuple[str, ConnectionState, str | None]] = []

    async def fake_authenticate(options=None):
        seen.append(("authenticate", client.state, None))
        client._identity = {"aid": aid.aid, "access_token": "tok-connect"}
        client._state = ConnectionState.AUTHENTICATED.value
        return {"aid": aid.aid, "access_token": "tok-connect", "gateway": "ws://gateway.agentid.pub/aun"}

    async def fake_connect_once(params, *, allow_reauth):
        seen.append(("connect_once", client.state, params.get("access_token")))
        client._state = ConnectionState.READY.value

    client.authenticate = fake_authenticate
    client._connect_once = fake_connect_once

    await client.connect({"background_sync": False})

    assert seen == [
        ("authenticate", ConnectionState.STANDBY, None),
        ("connect_once", ConnectionState.CONNECTING, "tok-connect"),
    ]
    assert client.state == ConnectionState.READY
    assert client.can_send is True

    store.close()


@pytest.mark.asyncio
async def test_connect_normalizes_empty_slot_id_to_default(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)
    observed: list[str] = []

    async def fake_authenticate(options=None):
        client._identity = {"aid": aid.aid, "access_token": "tok-connect"}
        client._state = ConnectionState.AUTHENTICATED.value
        return {"aid": aid.aid, "access_token": "tok-connect", "gateway": "ws://gateway.agentid.pub/aun"}

    async def fake_connect_once(params, *, allow_reauth):
        observed.append(params["slot_id"])
        client._slot_id = params["slot_id"]
        client._state = ConnectionState.READY.value

    client.authenticate = fake_authenticate
    client._connect_once = fake_connect_once

    await client.connect({"background_sync": False})

    assert observed == ["default"]
    assert client.slot_id == "default"

    store.close()


@pytest.mark.asyncio
async def test_disconnect_returns_to_standby_and_keeps_identity(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)
    client._state = ConnectionState.READY.value
    client._identity = {"aid": aid.aid, "access_token": "tok"}
    closed: list[bool] = []

    class _Transport:
        async def close(self):
            closed.append(True)

    client._transport = _Transport()

    await client.disconnect()

    assert closed == [True]
    assert client.state == ConnectionState.STANDBY
    assert client.current_aid is aid
    assert client._identity is None

    store.close()


@pytest.mark.asyncio
async def test_close_clears_identity_and_allows_reload(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)
    client._state = ConnectionState.AUTHENTICATED.value
    client._identity = {"aid": aid.aid, "access_token": "tok"}

    await client.close()

    assert client.state == ConnectionState.CLOSED
    assert client.current_aid is None
    assert client.has_identity is False

    client.load_identity(aid)
    assert client.state == ConnectionState.STANDBY
    assert client.current_aid is aid

    store.close()


@pytest.mark.asyncio
async def test_reconnect_loop_moves_through_backoff_and_reconnecting(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)
    client._state = ConnectionState.READY.value
    client._session_params = {"access_token": "tok", "gateway": "ws://gateway.agentid.pub/aun"}
    client._session_options["retry"] = {"initial_delay": 0.01, "max_delay": 0.01, "max_attempts": 2}
    sleep_states: list[tuple[ConnectionState, int, float | None]] = []
    connect_states: list[ConnectionState] = []

    async def fake_sleep(delay: float):
        sleep_states.append((client.state, client.retry_attempt, client.next_retry_in_seconds))

    class _Discovery:
        async def check_health(self, gateway_url):
            return True

    class _Transport:
        async def close(self):
            return None

    async def fake_connect_once():
        connect_states.append(client.state)
        if len(connect_states) == 1:
            raise RuntimeError("temporary")
        client._state = ConnectionState.READY.value

    client._reconnect_sleep = fake_sleep
    client._discovery = _Discovery()
    client._transport = _Transport()
    client._invoke_reconnect_connect_once = fake_connect_once

    await client._reconnect_loop()

    assert sleep_states[0][0] == ConnectionState.RETRY_BACKOFF
    assert connect_states == [ConnectionState.RECONNECTING, ConnectionState.RECONNECTING]
    assert client.state == ConnectionState.READY
    assert client.retry_attempt == 2
    assert client.next_retry_at is None
    assert client.last_error is None

    store.close()


@pytest.mark.asyncio
async def test_reconnect_loop_records_connection_failed_when_attempts_exhausted(tmp_path: Path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)
    client._state = ConnectionState.READY.value
    client._session_params = {"access_token": "tok", "gateway": "ws://gateway.agentid.pub/aun"}
    client._session_options["retry"] = {"initial_delay": 0.01, "max_delay": 0.01, "max_attempts": 1}
    failure = RuntimeError("down")

    async def fake_sleep(delay: float):
        return None

    class _Discovery:
        async def check_health(self, gateway_url):
            return True

    class _Transport:
        async def close(self):
            return None

    async def failing_connect_once():
        raise failure

    client._reconnect_sleep = fake_sleep
    client._discovery = _Discovery()
    client._transport = _Transport()
    client._invoke_reconnect_connect_once = failing_connect_once

    await client._reconnect_loop()

    assert client.state == ConnectionState.CONNECTION_FAILED
    assert client.last_error is failure
    assert client.last_error_code == "reconnect_failed"
    assert client.retry_attempt == 1

    store.close()


@pytest.mark.asyncio
async def test_token_refresh_loop_runs_in_ready_state_using_session_gateway(tmp_path: Path, monkeypatch):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)
    client._state = ConnectionState.READY.value
    client._session_params = {
        "access_token": "old-token",
        "gateway": "ws://gateway.agentid.pub/aun",
    }
    client._session_options["token_refresh_before"] = 3600
    client._identity = {
        "aid": aid.aid,
        "access_token": "old-token",
        "access_token_expires_at": time.time() - 1,
    }
    events: list[dict] = []
    client.on("token.refreshed", lambda payload: events.append(payload))
    monkeypatch.setattr(client_module, "_TOKEN_REFRESH_CHECK_INTERVAL", 0.01)

    async def fake_refresh_cached_tokens(gateway_url, identity):
        assert gateway_url == "ws://gateway.agentid.pub/aun"
        client._closing = True
        refreshed = dict(identity)
        refreshed["access_token"] = "new-token"
        refreshed["access_token_expires_at"] = time.time() + 7200
        return refreshed

    monkeypatch.setattr(client._auth, "refresh_cached_tokens", fake_refresh_cached_tokens)
    monkeypatch.setattr(
        client._auth,
        "get_access_token_expiry",
        lambda identity: identity.get("access_token_expires_at"),
    )

    await asyncio.wait_for(client._token_refresh_loop(), timeout=0.2)

    assert client.access_token == "new-token"
    assert client.access_token_expires_at is not None
    assert events and events[0]["aid"] == aid.aid

    store.close()
