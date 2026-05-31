from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AIDStore


def _identity(aid: str, *, key=None, valid_days: int = 30) -> dict[str, str]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=valid_days))
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


@pytest.mark.asyncio
async def test_store_exists_maps_pki_head_status(monkeypatch, tmp_path: Path):
    store = AIDStore(tmp_path, "", debug=True)
    monkeypatch.setattr(store, "_resolve_gateway", lambda aid: "wss://gateway.agentid.pub")

    seen_urls: list[str] = []

    async def fake_head(url: str, *, timeout: float = 5.0):
        seen_urls.append(url)
        if url.endswith("/alice.agentid.pub"):
            return 200, {}
        if url.endswith("/bobb.agentid.pub"):
            return 404, {}
        return 503, {}

    monkeypatch.setattr(store, "_http_head", fake_head)

    assert (await store.exists("alice.agentid.pub")).data == {"exists": True}
    assert (await store.exists("bobb.agentid.pub")).data == {"exists": False}
    failed = await store.exists("carol.agentid.pub")
    assert not failed.ok
    assert failed.error.code == "NETWORK_ERROR"
    assert seen_urls[0] == "https://gateway.agentid.pub/pki/cert/alice.agentid.pub"

    store.close()


@pytest.mark.asyncio
async def test_store_renew_cert_signs_server_nonce_and_persists_new_cert(monkeypatch, tmp_path: Path):
    aid = "alice.agentid.pub"
    key = ec.generate_private_key(ec.SECP256R1())
    old_identity = _identity(aid, key=key, valid_days=7)
    renewed_identity = _identity(aid, key=key, valid_days=90)
    store = AIDStore(tmp_path, "")
    store._keystore.save_identity(aid, old_identity)
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")

    calls: list[tuple[str, dict]] = []

    async def fake_verify_phase1(gateway_url: str, phase1: dict, client_nonce: str):
        assert gateway_url == "wss://gateway.agentid.pub"
        assert phase1["request_id"] == "renew-rid"
        assert client_nonce

    async def fake_short_rpc(gateway_url: str, method: str, params: dict):
        assert gateway_url == "wss://gateway.agentid.pub"
        calls.append((method, params))
        if method == "auth.aid_login1":
            assert params["aid"] == aid
            assert params["cert"] == old_identity["cert"]
            assert params["client_nonce"]
            return {"request_id": "renew-rid", "nonce": "renew-nonce"}
        if method == "auth.renew_cert":
            assert params["aid"] == aid
            assert params["request_id"] == "renew-rid"
            assert params["nonce"] == "renew-nonce"
            signature = base64.b64decode(params["signature"], validate=True)
            x509.load_pem_x509_certificate(old_identity["cert"].encode("utf-8")).public_key().verify(
                signature,
                b"renew-nonce",
                ec.ECDSA(hashes.SHA256()),
            )
            return {"status": "renewed", "cert": renewed_identity["cert"], "serial": "02"}
        raise AssertionError(method)

    monkeypatch.setattr(store._auth, "_verify_phase1_response", fake_verify_phase1)
    monkeypatch.setattr(store._auth, "_short_rpc", fake_short_rpc)

    result = await store.renew_cert(aid)

    assert result.ok
    assert result.data["renewed"] is True
    assert calls[0][0] == "auth.aid_login1"
    assert calls[1][0] == "auth.renew_cert"
    loaded = store.load(aid)
    assert loaded.ok
    assert loaded.data["aid"].is_private_key_valid()
    old_fingerprint = "sha256:" + x509.load_pem_x509_certificate(
        old_identity["cert"].encode("utf-8")
    ).fingerprint(hashes.SHA256()).hex()
    assert loaded.data["aid"].cert_fingerprint != old_fingerprint
    assert loaded.data["aid"].cert_not_after == result.data["new_cert_not_after"]

    store.close()


@pytest.mark.asyncio
async def test_store_rekey_signs_nonce_and_new_public_key_then_persists_new_keypair(monkeypatch, tmp_path: Path):
    aid = "alice.agentid.pub"
    old_key = ec.generate_private_key(ec.SECP256R1())
    old_identity = _identity(aid, key=old_key)
    new_key = ec.generate_private_key(ec.SECP256R1())
    new_identity = _identity(aid, key=new_key, valid_days=120)
    generated_identity = {
        "private_key_pem": new_identity["private_key_pem"],
        "public_key_der_b64": new_identity["public_key_der_b64"],
        "curve": new_identity["curve"],
    }
    store = AIDStore(tmp_path, "")
    store._keystore.save_identity(aid, old_identity)
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")
    monkeypatch.setattr(store._auth._crypto, "generate_identity", lambda: dict(generated_identity))

    async def fake_verify_phase1(gateway_url: str, phase1: dict, client_nonce: str):
        assert phase1["request_id"] == "rekey-rid"
        assert client_nonce

    async def fake_short_rpc(gateway_url: str, method: str, params: dict):
        assert gateway_url == "wss://gateway.agentid.pub"
        if method == "auth.aid_login1":
            assert params["aid"] == aid
            assert params["cert"] == old_identity["cert"]
            return {"request_id": "rekey-rid", "nonce": "rekey-nonce"}
        if method == "auth.rekey":
            assert params["aid"] == aid
            assert params["request_id"] == "rekey-rid"
            assert params["nonce"] == "rekey-nonce"
            assert params["new_public_key"] == new_identity["public_key_der_b64"]
            signature = base64.b64decode(params["signature"], validate=True)
            signed_payload = ("rekey-nonce" + new_identity["public_key_der_b64"]).encode("utf-8")
            x509.load_pem_x509_certificate(old_identity["cert"].encode("utf-8")).public_key().verify(
                signature,
                signed_payload,
                ec.ECDSA(hashes.SHA256()),
            )
            return {"status": "rekeyed", "cert": new_identity["cert"], "serial": "03"}
        raise AssertionError(method)

    monkeypatch.setattr(store._auth, "_verify_phase1_response", fake_verify_phase1)
    monkeypatch.setattr(store._auth, "_short_rpc", fake_short_rpc)

    result = await store.rekey(aid)

    assert result.ok
    assert result.data["rekeyed"] is True
    loaded = store.load(aid)
    assert loaded.ok
    loaded_aid = loaded.data["aid"]
    assert loaded_aid.is_private_key_valid()
    assert loaded_aid.public_key == new_identity["public_key_der_b64"]
    assert result.data["new_fingerprint"] == loaded_aid.cert_fingerprint
    assert store._keystore.load_key_pair(aid)["public_key_der_b64"] == new_identity["public_key_der_b64"]

    store.close()


@pytest.mark.asyncio
async def test_store_renew_and_rekey_require_private_key(tmp_path: Path):
    aid = "peer.agentid.pub"
    store = AIDStore(tmp_path, "")
    store._keystore.save_cert(aid, _identity(aid)["cert"])

    renewed = await store.renew_cert(aid)
    rekeyed = await store.rekey(aid)

    assert not renewed.ok
    assert renewed.error.code == "PRIVATE_KEY_REQUIRED"
    assert not rekeyed.ok
    assert rekeyed.error.code == "PRIVATE_KEY_REQUIRED"

    store.close()


@pytest.mark.asyncio
async def test_store_renew_and_rekey_map_rpc_failures(monkeypatch, tmp_path: Path):
    aid = "alice.agentid.pub"
    store = AIDStore(tmp_path, "")
    store._keystore.save_identity(aid, _identity(aid))
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")

    async def fake_verify_phase1(gateway_url: str, phase1: dict, client_nonce: str):
        return None

    async def fake_short_rpc(gateway_url: str, method: str, params: dict):
        if method == "auth.aid_login1":
            return {"request_id": f"{params['aid']}-rid", "nonce": "nonce"}
        raise RuntimeError(f"{method} failed")

    monkeypatch.setattr(store._auth, "_verify_phase1_response", fake_verify_phase1)
    monkeypatch.setattr(store._auth, "_short_rpc", fake_short_rpc)

    renewed = await store.renew_cert(aid)
    rekeyed = await store.rekey(aid)

    assert not renewed.ok
    assert renewed.error.code == "CERT_RENEWAL_FAILED"
    assert not rekeyed.ok
    assert rekeyed.error.code == "REKEY_FAILED"

    store.close()


@pytest.mark.asyncio
async def test_store_register_persists_identity_and_returns_registered(monkeypatch, tmp_path: Path):
    aid = "alice.agentid.pub"
    store = AIDStore(tmp_path, "seed")
    identity = _identity(aid)
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")

    async def fake_register(gateway_url: str, target: str):
        assert gateway_url == "wss://gateway.agentid.pub"
        assert target == aid
        return dict(identity)

    monkeypatch.setattr(store._register_flow, "register_aid", fake_register)

    result = await store.register(aid)

    assert result.ok
    assert result.data == {"registered": True}
    loaded = store.load(aid)
    assert loaded.ok
    assert loaded.data["aid"].is_private_key_valid()

    store.close()


@pytest.mark.asyncio
async def test_store_register_authflow_persists_generated_keypair(monkeypatch, tmp_path: Path):
    aid = "new-user.agentid.pub"
    store = AIDStore(tmp_path, "seed")
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")

    async def fake_download_registered_cert(gateway_url: str, target: str):
        assert gateway_url == "wss://gateway.agentid.pub"
        assert target == aid
        return None

    async def fake_create_aid(gateway_url: str, identity: dict):
        assert gateway_url == "wss://gateway.agentid.pub"
        assert identity["aid"] == aid
        private_key = serialization.load_pem_private_key(
            identity["private_key_pem"].encode("utf-8"),
            password=None,
        )
        return {"cert": _identity(aid, key=private_key)["cert"]}

    monkeypatch.setattr(store._register_flow, "_download_registered_cert", fake_download_registered_cert)
    monkeypatch.setattr(store._register_flow, "_create_aid", fake_create_aid)

    result = await store.register(aid)

    assert result.ok
    loaded = store.load(aid)
    assert loaded.ok
    assert loaded.data["aid"].is_private_key_valid()

    store.close()


@pytest.mark.asyncio
async def test_store_resolve_downloads_cert_and_can_skip_agent_md(monkeypatch, tmp_path: Path):
    aid = "bobb.agentid.pub"
    store = AIDStore(tmp_path, "")
    identity = _identity(aid)
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")

    async def fake_fetch_peer_cert(gateway_url: str, target: str):
        assert gateway_url == "wss://gateway.agentid.pub"
        assert target == aid
        return identity["cert"]

    monkeypatch.setattr(store._auth, "fetch_peer_cert", fake_fetch_peer_cert)

    result = await store.resolve(aid, {"skip_agent_md": True})

    assert result.ok
    peer = result.data["aid"]
    assert peer.aid == aid
    assert peer.is_cert_valid()
    assert not peer.is_private_key_valid()
    assert result.data["source"]["cert_from_cache"] is False
    assert result.data["source"]["agent_md_fetched"] is False
    assert store.load(aid).ok

    store.close()


@pytest.mark.asyncio
async def test_store_fetch_agent_md_downloads_and_verifies_signature(monkeypatch, tmp_path: Path):
    aid = "alice.agentid.pub"
    store = AIDStore(tmp_path, "")
    identity = _identity(aid)
    store._keystore.save_identity(aid, identity)
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")
    loaded = store.load(aid)
    signed = loaded.data["aid"].sign_agent_md("---\naid: alice.agentid.pub\n---\n# Alice\n").data["signed"]

    async def fake_get(url: str, *, headers=None, timeout: float = 30.0):
        assert url == "https://alice.agentid.pub/agent.md"
        return signed, {"ETag": '"alice-v1"', "Last-Modified": "Thu, 28 May 2026 00:00:00 GMT"}, 200

    monkeypatch.setattr(store, "_http_get_text_with_headers", fake_get)

    result = await store.fetch_agent_md(aid)

    assert result.ok
    assert result.data["aid"] == aid
    assert result.data["content"] == signed
    assert result.data["verification"]["status"] == "verified"
    assert result.data["cert_pem"] == identity["cert"]
    assert result.data["etag"] == '"alice-v1"'

    store.close()


@pytest.mark.asyncio
async def test_store_fetch_agent_md_unsigned_is_ok_with_verification_status(monkeypatch, tmp_path: Path):
    aid = "alice.agentid.pub"
    store = AIDStore(tmp_path, "")
    identity = _identity(aid)
    store._keystore.save_identity(aid, identity)
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")
    unsigned = "---\naid: alice.agentid.pub\n---\n# Alice\n"

    async def fake_get(url: str, *, headers=None, timeout: float = 30.0):
        return unsigned, {"ETag": '"unsigned-v1"'}, 200

    monkeypatch.setattr(store, "_http_get_text_with_headers", fake_get)

    result = await store.fetch_agent_md(aid)

    assert result.ok, result.error
    assert result.data["content"] == unsigned
    assert result.data["verification"]["status"] == "unsigned"
    assert result.data["cert_pem"] == identity["cert"]

    store.close()


@pytest.mark.asyncio
async def test_store_fetch_agent_md_invalid_is_ok_with_verification_status(monkeypatch, tmp_path: Path):
    aid = "alice.agentid.pub"
    store = AIDStore(tmp_path, "")
    identity = _identity(aid)
    store._keystore.save_identity(aid, identity)
    monkeypatch.setattr(store, "_resolve_gateway", lambda target: "wss://gateway.agentid.pub")
    loaded = store.load(aid)
    signed = loaded.data["aid"].sign_agent_md("---\naid: alice.agentid.pub\n---\n# Alice\n").data["signed"]
    tampered = signed.replace("# Alice", "# Mallory", 1)

    async def fake_get(url: str, *, headers=None, timeout: float = 30.0):
        return tampered, {"ETag": '"invalid-v1"'}, 200

    monkeypatch.setattr(store, "_http_get_text_with_headers", fake_get)

    result = await store.fetch_agent_md(aid)

    assert result.ok, result.error
    assert result.data["content"] == tampered
    assert result.data["verification"]["status"] == "invalid"
    assert result.data["verification"]["reason"]
    assert result.data["cert_pem"] == identity["cert"]

    store.close()


@pytest.mark.asyncio
async def test_store_head_agent_md_maps_status(monkeypatch, tmp_path: Path):
    store = AIDStore(tmp_path, "")
    monkeypatch.setattr(store, "_resolve_gateway", lambda aid: "wss://gateway.agentid.pub")

    async def fake_head(url: str, *, timeout: float = 15.0):
        if "alice" in url:
            return 200, {"ETag": '"a"', "Last-Modified": "Thu, 28 May 2026 00:00:00 GMT", "Content-Length": "12"}
        return 404, {}

    monkeypatch.setattr(store, "_http_head", fake_head)

    found = await store.head_agent_md("alice.agentid.pub")
    missing = await store.head_agent_md("bobb.agentid.pub")

    assert found.ok
    assert found.data["found"] is True
    assert found.data["etag"] == '"a"'
    assert found.data["content_length"] == 12
    assert not missing.ok
    assert missing.error.code == "AGENTMD_NOT_FOUND"

    store.close()


@pytest.mark.asyncio
async def test_store_diagnose_combines_local_and_remote(monkeypatch, tmp_path: Path):
    aid = "missing.agentid.pub"
    store = AIDStore(tmp_path, "")

    async def fake_exists(target: str):
        assert target == aid
        from aun_core import result_ok

        return result_ok({"exists": False})

    monkeypatch.setattr(store, "exists", fake_exists)

    result = await store.diagnose(aid)

    assert result.ok
    assert result.data["aid"] == aid
    assert result.data["local_valid"] is False
    assert result.data["remote_registered"] is False
    assert result.data["suggestions"]
    assert result.data["status"] == "available"

    store.close()


@pytest.mark.asyncio
async def test_store_gateway_resolution_isolated_by_issuer(monkeypatch, tmp_path: Path):
    store = AIDStore(tmp_path, "", verify_ssl=False)
    checked: list[str] = []

    async def fake_discover(url: str):
        checked.append(url)
        if "agentid.pub" in url:
            return "wss://gateway.agentid.pub/aun"
        if "aid.net" in url:
            return "wss://gateway.aid.net/aun"
        raise AssertionError(url)

    async def fake_head(url: str, *, timeout: float = 5.0):
        return 404, {}

    monkeypatch.setattr(store._discovery, "discover", fake_discover)
    monkeypatch.setattr(store, "_http_head", fake_head)

    await store.exists("alice.agentid.pub")
    await store.exists("dave.aid.net")

    assert checked == [
        "https://gateway.agentid.pub/.well-known/aun-gateway",
        "https://gateway.aid.net/.well-known/aun-gateway",
    ]

    store.close()
