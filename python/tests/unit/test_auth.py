import asyncio
import base64
import hashlib
import shutil
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from aun_core import __version__ as _aun_version
from aun_core.auth import AuthFlow
from aun_core.config import normalize_device_id
from aun_core.crypto import CryptoProvider
from aun_core.errors import AuthError
from aun_core.keystore.file import FileKeyStore


_SCRATCH_ROOT = Path(__file__).resolve().parents[2] / ".tmp-tests"


def _build_cert(subject_cn: str, issuer_cert=None, issuer_key=None, *, ca: bool):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer_name = issuer_cert.subject if issuer_cert is not None else subject
    signer = issuer_key or key
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(private_key=signer, algorithm=hashes.SHA256())
    )
    return key, cert, cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _make_auth_flow(root_pem: str) -> AuthFlow:
    temp_root = _SCRATCH_ROOT / f"auth-{uuid4().hex}"
    temp_root.mkdir(parents=True, exist_ok=True)
    root_path = temp_root / "root.pem"
    root_path.write_text(root_pem, encoding="utf-8")
    keystore = FileKeyStore(temp_root / "aun")
    return AuthFlow(
        token_store=keystore,
        crypto=CryptoProvider(),
        connection_factory=lambda url: None,
        root_ca_path=str(root_path),
    )


@pytest.mark.asyncio
async def test_default_connection_factory_respects_verify_ssl_false(monkeypatch, tmp_path: Path):
    captured: dict[str, object] = {}

    async def fake_connect(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("aun_core.auth.websockets.connect", fake_connect)
    flow = AuthFlow(
        token_store=FileKeyStore(tmp_path),
        crypto=CryptoProvider(),
        verify_ssl=False,
    )

    await flow._default_connection_factory("wss://gateway.agentid.pub/aun")

    assert captured["url"] == "wss://gateway.agentid.pub/aun"
    ssl_ctx = captured.get("ssl")
    assert isinstance(ssl_ctx, ssl.SSLContext)
    assert ssl_ctx.check_hostname is False
    assert ssl_ctx.verify_mode == ssl.CERT_NONE


@pytest.mark.asyncio
async def test_initialize_with_token_normalizes_empty_instance_context(tmp_path: Path):
    captured: dict[str, object] = {}

    class FakeTransport:
        async def call(self, method, params):
            captured["method"] = method
            captured["params"] = params
            return {"status": "ok"}

    flow = AuthFlow(
        token_store=FileKeyStore(tmp_path / "aun"),
        crypto=CryptoProvider(),
        verify_ssl=False,
    )

    await flow.initialize_with_token(
        FakeTransport(),
        {"params": {"nonce": "nonce-1"}},
        "access-token",
        device_id="",
        slot_id="",
    )

    params = captured["params"]
    assert isinstance(params, dict)
    assert params["device"]["id"]
    assert params["client"]["slot_id"] == "default"


def _build_ocsp_response(cert: x509.Certificate, issuer_cert: x509.Certificate, issuer_key, *, status: str) -> str:
    now = datetime.now(timezone.utc)
    if status == "good":
        cert_status = ocsp.OCSPCertStatus.GOOD
        revocation_time = None
    elif status == "revoked":
        cert_status = ocsp.OCSPCertStatus.REVOKED
        revocation_time = now
    elif status == "unknown":
        cert_status = ocsp.OCSPCertStatus.UNKNOWN
        revocation_time = None
    else:
        raise ValueError(f"unsupported status: {status}")
    issuer_name_hash = hashlib.sha256(issuer_cert.subject.public_bytes()).digest()
    issuer_key_hash = hashlib.sha256(
        issuer_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).digest()
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response_by_hash(
            issuer_name_hash=issuer_name_hash,
            issuer_key_hash=issuer_key_hash,
            serial_number=cert.serial_number,
            algorithm=hashes.SHA256(),
            cert_status=cert_status,
            this_update=now,
            next_update=now + timedelta(minutes=5),
            revocation_time=revocation_time,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer_cert)
        .sign(issuer_key, hashes.SHA256())
    )
    return base64.b64encode(response.public_bytes(serialization.Encoding.DER)).decode("ascii")


@pytest.fixture(autouse=True)
def _cleanup_scratch_root():
    yield
    if not _SCRATCH_ROOT.exists():
        return
    shutil.rmtree(_SCRATCH_ROOT, ignore_errors=True)


def test_verify_phase1_response_accepts_valid_identity_chain(monkeypatch):
    root_key, root_cert, root_pem = _build_cert("root.test", ca=True)
    issuer_key, issuer_cert, issuer_pem = _build_cert("issuer.test", issuer_cert=root_cert, issuer_key=root_key, ca=True)
    identity_key, identity_cert, identity_pem = _build_cert(
        "auth.identity",
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        ca=False,
    )

    flow = _make_auth_flow(root_pem)

    async def fake_fetch_gateway_ca_chain(gateway_url: str, chain_aid: str = "") -> list[str]:
        return [issuer_pem, root_pem]

    async def fake_fetch_gateway_crl(gateway_url: str, issuer_cert: x509.Certificate) -> dict:
        return {"revoked_serials": set(), "next_refresh_at": float("inf")}

    async def fake_fetch_gateway_ocsp_status(
        gateway_url: str,
        identity_cert_arg: x509.Certificate,
        issuer_cert_arg: x509.Certificate,
    ) -> dict:
        return {"status": "good", "next_refresh_at": float("inf")}

    monkeypatch.setattr(flow, "_fetch_gateway_ca_chain", fake_fetch_gateway_ca_chain)
    monkeypatch.setattr(flow, "_fetch_gateway_crl", fake_fetch_gateway_crl)
    monkeypatch.setattr(flow, "_fetch_gateway_ocsp_status", fake_fetch_gateway_ocsp_status)

    client_nonce = base64.b64encode(b"nonce-123").decode("ascii")
    signature = identity_key.sign(client_nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))

    asyncio.run(
        flow._verify_phase1_response(
            "wss://gw.example/aun",
            {
                "auth_cert": identity_pem,
                "client_nonce_signature": base64.b64encode(signature).decode("ascii"),
            },
            client_nonce,
        )
    )


def test_verify_phase1_response_rejects_bad_signature(monkeypatch):
    root_key, root_cert, root_pem = _build_cert("root.test", ca=True)
    issuer_key, issuer_cert, issuer_pem = _build_cert("issuer.test", issuer_cert=root_cert, issuer_key=root_key, ca=True)
    _, _, identity_pem = _build_cert(
        "auth.identity",
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        ca=False,
    )

    flow = _make_auth_flow(root_pem)

    async def fake_fetch_gateway_ca_chain(gateway_url: str, chain_aid: str = "") -> list[str]:
        return [issuer_pem, root_pem]

    async def fake_fetch_gateway_crl(gateway_url: str, issuer_cert: x509.Certificate) -> dict:
        return {"revoked_serials": set(), "next_refresh_at": float("inf")}

    async def fake_fetch_gateway_ocsp_status(
        gateway_url: str,
        identity_cert_arg: x509.Certificate,
        issuer_cert_arg: x509.Certificate,
    ) -> dict:
        return {"status": "good", "next_refresh_at": float("inf")}

    monkeypatch.setattr(flow, "_fetch_gateway_ca_chain", fake_fetch_gateway_ca_chain)
    monkeypatch.setattr(flow, "_fetch_gateway_crl", fake_fetch_gateway_crl)
    monkeypatch.setattr(flow, "_fetch_gateway_ocsp_status", fake_fetch_gateway_ocsp_status)

    with pytest.raises(AuthError, match="server auth signature verification failed"):
        asyncio.run(
            flow._verify_phase1_response(
                "wss://gw.example/aun",
                {
                    "auth_cert": identity_pem,
                    "client_nonce_signature": base64.b64encode(b"bad").decode("ascii"),
                },
                "nonce-123",
            )
        )


def test_verify_phase1_response_rejects_revoked_identity_cert(monkeypatch):
    root_key, root_cert, root_pem = _build_cert("root.test", ca=True)
    issuer_key, issuer_cert, issuer_pem = _build_cert("issuer.test", issuer_cert=root_cert, issuer_key=root_key, ca=True)
    identity_key, identity_cert, identity_pem = _build_cert(
        "auth.identity",
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        ca=False,
    )

    flow = _make_auth_flow(root_pem)

    async def fake_fetch_gateway_ca_chain(gateway_url: str, chain_aid: str = "") -> list[str]:
        return [issuer_pem, root_pem]

    async def fake_fetch_gateway_crl(gateway_url: str, issuer_cert: x509.Certificate) -> dict:
        return {
            "revoked_serials": {format(identity_cert.serial_number, "x").lower()},
            "next_refresh_at": float("inf"),
        }

    async def fake_fetch_gateway_ocsp_status(
        gateway_url: str,
        identity_cert_arg: x509.Certificate,
        issuer_cert_arg: x509.Certificate,
    ) -> dict:
        return {"status": "good", "next_refresh_at": float("inf")}

    monkeypatch.setattr(flow, "_fetch_gateway_ca_chain", fake_fetch_gateway_ca_chain)
    monkeypatch.setattr(flow, "_fetch_gateway_crl", fake_fetch_gateway_crl)
    monkeypatch.setattr(flow, "_fetch_gateway_ocsp_status", fake_fetch_gateway_ocsp_status)

    client_nonce = base64.b64encode(b"nonce-123").decode("ascii")
    signature = identity_key.sign(client_nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))

    with pytest.raises(AuthError, match="auth certificate has been revoked"):
        asyncio.run(
            flow._verify_phase1_response(
                "wss://gw.example/aun",
                {
                    "auth_cert": identity_pem,
                    "client_nonce_signature": base64.b64encode(signature).decode("ascii"),
                },
                client_nonce,
            )
        )


def test_fetch_gateway_ocsp_status_rejects_revoked_response():
    root_key, root_cert, root_pem = _build_cert("root.test", ca=True)
    issuer_key, issuer_cert, _issuer_pem = _build_cert("issuer.test", issuer_cert=root_cert, issuer_key=root_key, ca=True)
    _identity_key, identity_cert, _identity_pem = _build_cert(
        "auth.identity",
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        ca=False,
    )

    flow = _make_auth_flow(root_pem)
    response_b64 = _build_ocsp_response(identity_cert, issuer_cert, issuer_key, status="revoked")

    async def fake_fetch_json(url: str) -> dict:
        return {
            "status": "revoked",
            "ocsp_response": response_b64,
        }

    flow._fetch_json = fake_fetch_json  # type: ignore[method-assign]

    result = asyncio.run(
        flow._fetch_gateway_ocsp_status("wss://gw.example/aun", identity_cert, issuer_cert)
    )
    assert result["status"] == "revoked"


def test_fetch_gateway_ocsp_status_parses_unknown_response():
    root_key, root_cert, root_pem = _build_cert("root.test", ca=True)
    issuer_key, issuer_cert, _issuer_pem = _build_cert("issuer.test", issuer_cert=root_cert, issuer_key=root_key, ca=True)
    _identity_key, identity_cert, _identity_pem = _build_cert(
        "auth.identity",
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        ca=False,
    )

    flow = _make_auth_flow(root_pem)
    response_b64 = _build_ocsp_response(identity_cert, issuer_cert, issuer_key, status="unknown")

    async def fake_fetch_json(url: str) -> dict:
        return {
            "status": "unknown",
            "ocsp_response": response_b64,
        }

    flow._fetch_json = fake_fetch_json  # type: ignore[method-assign]

    result = asyncio.run(
        flow._fetch_gateway_ocsp_status("wss://gw.example/aun", identity_cert, issuer_cert)
    )
    assert result["status"] == "unknown"


# ── P0-1: verify_peer_certificate 测试 ──────────────────────


def test_verify_peer_cert_success():
    """完整 PKI 验证通过（链 + CRL + OCSP + CN）"""
    root_key, root_cert, root_pem = _build_cert("Test Root CA", ca=True)
    issuer_key, issuer_cert, issuer_pem = _build_cert(
        "Test Issuer CA", root_cert, root_key, ca=True
    )
    peer_key, peer_cert, peer_pem = _build_cert(
        "alice.example.com", issuer_cert, issuer_key, ca=False
    )

    flow = _make_auth_flow(root_pem)

    async def fake_chain(gw, chain_aid=""):
        return [issuer_pem, root_pem]

    # 直接 mock 顶层验证方法，避免内部网络调用
    async def fake_revocation(gw, cert, chain_aid=""):
        pass  # 未吊销

    async def fake_ocsp(gw, cert, chain_aid=""):
        pass  # OCSP good

    flow._fetch_gateway_ca_chain = fake_chain
    flow._verify_auth_cert_revocation = fake_revocation
    flow._verify_auth_cert_ocsp = fake_ocsp

    # 应该不抛异常
    asyncio.run(flow.verify_peer_certificate("wss://gw.example/aun", peer_cert, "alice.example.com"))


def test_verify_peer_cert_cn_mismatch():
    """CN 不匹配时抛出 AuthError"""
    root_key, root_cert, root_pem = _build_cert("Test Root CA", ca=True)
    issuer_key, issuer_cert, issuer_pem = _build_cert(
        "Test Issuer CA", root_cert, root_key, ca=True
    )
    peer_key, peer_cert, peer_pem = _build_cert(
        "alice.example.com", issuer_cert, issuer_key, ca=False
    )

    flow = _make_auth_flow(root_pem)

    async def fake_chain(gw, chain_aid=""):
        return [issuer_pem, root_pem]

    async def fake_revocation(gw, cert, chain_aid=""):
        pass

    async def fake_ocsp(gw, cert, chain_aid=""):
        pass

    flow._fetch_gateway_ca_chain = fake_chain
    flow._verify_auth_cert_revocation = fake_revocation
    flow._verify_auth_cert_ocsp = fake_ocsp

    with pytest.raises(AuthError, match="peer cert CN mismatch"):
        asyncio.run(flow.verify_peer_certificate("wss://gw.example/aun", peer_cert, "bob.example.com"))


def test_verify_peer_cert_revoked():
    """CRL 吊销的证书应被拒绝"""
    root_key, root_cert, root_pem = _build_cert("Test Root CA", ca=True)
    issuer_key, issuer_cert, issuer_pem = _build_cert(
        "Test Issuer CA", root_cert, root_key, ca=True
    )
    peer_key, peer_cert, peer_pem = _build_cert(
        "alice.example.com", issuer_cert, issuer_key, ca=False
    )

    flow = _make_auth_flow(root_pem)

    async def fake_chain(gw, chain_aid=""):
        return [issuer_pem, root_pem]

    async def fake_revocation(gw, cert, chain_aid=""):
        raise AuthError("auth certificate has been revoked")

    flow._fetch_gateway_ca_chain = fake_chain
    flow._verify_auth_cert_revocation = fake_revocation

    with pytest.raises(AuthError, match="revoked"):
        asyncio.run(flow.verify_peer_certificate("wss://gw.example/aun", peer_cert, "alice.example.com"))


def test_initialize_with_token_sends_device_slot_and_delivery_mode(tmp_path):
    keystore = FileKeyStore(tmp_path / "aun")
    flow = AuthFlow(
        token_store=keystore,
        crypto=CryptoProvider(),
        connection_factory=lambda url: None,
        device_id="device-1",
        slot_id="slot-a",
    )
    calls = []

    class _Transport:
        async def call(self, method, params):
            calls.append((method, params))
            return {"status": "ok"}

    asyncio.run(flow.initialize_with_token(
        _Transport(),
        {"params": {"nonce": "nonce-1"}},
        "token-1",
        device_id="device-1",
        slot_id="slot-a",
        delivery_mode={"mode": "queue", "routing": "sender_affinity", "affinity_ttl_ms": 800},
    ))

    assert calls[0][0] == "auth.connect"
    params = calls[0][1]
    assert params["device"] == {"id": "device-1", "type": "sdk"}
    assert params["client"] == {
        "slot_id": "slot-a",
        "sdk_lang": "python",
        "sdk_version": _aun_version,
    }
    assert params["delivery_mode"] == {"mode": "queue", "routing": "sender_affinity", "affinity_ttl_ms": 800}


def test_initialize_with_token_ignores_external_legacy_capability_override(tmp_path):
    keystore = FileKeyStore(tmp_path / "aun")
    flow = AuthFlow(
        token_store=keystore,
        crypto=CryptoProvider(),
        connection_factory=lambda url: None,
        device_id="device-1",
        slot_id="slot-a",
    )
    calls = []

    class _Transport:
        async def call(self, method, params):
            calls.append((method, params))
            return {"status": "ok"}

    asyncio.run(flow.initialize_with_token(
        _Transport(),
        {"params": {"nonce": "nonce-1"}},
        "token-1",
        device_id="device-1",
        slot_id="slot-a",
        extra_info={
            "_capabilities": {
                "e2ee": True,
                "group_e2ee": True,
                "supported_p2p_e2ee": ["e2ee"],
                "supported_group_e2ee": ["group_e2ee"],
            },
            "note": "kept",
        },
    ))

    params = calls[0][1]
    assert params["capabilities"]["supported_p2p_e2ee"] == ["e2ee_v2"]
    assert params["capabilities"]["supported_group_e2ee"] == ["group_e2ee_v2"]
    assert "e2ee" not in params["capabilities"]["supported_p2p_e2ee"]
    assert "group_e2ee" not in params["capabilities"]["supported_group_e2ee"]
    assert params["extra_info"] == {"note": "kept"}


def test_load_identity_prefers_instance_state_tokens(tmp_path):
    keystore = FileKeyStore(tmp_path / "aun")
    aid = "alice.example.aid"
    keystore.save_identity(aid, {
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
        "access_token": "shared-token",
        "refresh_token": "shared-refresh",
    })
    keystore.save_instance_state(aid, "device-1", "slot-a", {
        "access_token": "slot-token",
        "refresh_token": "slot-refresh",
        "access_token_expires_at": 123456,
    })
    flow = AuthFlow(
        token_store=keystore,
        crypto=CryptoProvider(),
        connection_factory=lambda url: None,
        device_id="device-1",
        slot_id="slot-a",
    )
    flow.set_identity({
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
    })

    loaded = flow.load_identity(aid)

    assert loaded["access_token"] == "slot-token"
    assert loaded["refresh_token"] == "slot-refresh"
    assert loaded["access_token_expires_at"] == 123456


def test_load_identity_empty_device_id_prefers_default_device_state_tokens(tmp_path):
    keystore = FileKeyStore(tmp_path / "aun")
    default_device_id = normalize_device_id("", tmp_path / "aun")
    aid = "alice-empty-device.example.aid"
    keystore.save_identity(aid, {
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
        "access_token": "shared-token",
        "refresh_token": "shared-refresh",
    })
    keystore.save_instance_state(aid, default_device_id, "slot-a", {
        "access_token": "empty-device-token",
        "refresh_token": "empty-device-refresh",
        "access_token_expires_at": 234567,
    })
    flow = AuthFlow(
        token_store=keystore,
        crypto=CryptoProvider(),
        connection_factory=lambda url: None,
        device_id="",
        slot_id="slot-a",
    )
    flow.set_identity({
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
    })

    loaded = flow.load_identity(aid)

    assert loaded["access_token"] == "empty-device-token"
    assert loaded["refresh_token"] == "empty-device-refresh"
    assert loaded["access_token_expires_at"] == 234567


def test_persist_identity_empty_device_id_saves_default_device_state(tmp_path):
    keystore = FileKeyStore(tmp_path / "aun")
    default_device_id = normalize_device_id("", tmp_path / "aun")
    aid = "persist-empty-device.example.aid"
    flow = AuthFlow(
        token_store=keystore,
        crypto=CryptoProvider(),
        connection_factory=lambda url: None,
        device_id="",
        slot_id="slot-a",
    )

    flow._persist_identity({
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "pub",
        "curve": "P-256",
        "access_token": "empty-device-token",
        "refresh_token": "empty-device-refresh",
        "access_token_expires_at": 345678,
    })

    instance_state = keystore.load_instance_state(aid, default_device_id, "slot-a")
    assert instance_state["access_token"] == "empty-device-token"
    assert instance_state["refresh_token"] == "empty-device-refresh"
    assert instance_state["access_token_expires_at"] == 345678

# ── P0-2: _validate_new_cert 测试 ───────────────────────────


def test_new_cert_accepted_valid():
    """合法的 new_cert 应被接受（无 gateway_url 时跳过链验证，只做 CN/公钥/时间）"""
    key = ec.generate_private_key(ec.SECP256R1())
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    root_key, _, root_pem = _build_cert("Root", ca=True)
    flow = _make_auth_flow(root_pem)
    identity = {
        "aid": "alice.test",
        "public_key_der_b64": base64.b64encode(pub_der).decode("ascii"),
        "_pending_new_cert": cert_pem,
    }
    asyncio.run(flow._validate_new_cert(identity))
    assert identity.get("cert") == cert_pem
    assert "_pending_new_cert" not in identity


def test_new_cert_rejected_cn_mismatch():
    """CN 不匹配时 new_cert 被拒绝"""
    key = ec.generate_private_key(ec.SECP256R1())
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bob.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    root_key, _, root_pem = _build_cert("Root", ca=True)
    flow = _make_auth_flow(root_pem)
    identity = {
        "aid": "alice.test",  # 与 cert CN "bob.test" 不匹配
        "public_key_der_b64": base64.b64encode(pub_der).decode("ascii"),
        "_pending_new_cert": cert_pem,
    }
    asyncio.run(flow._validate_new_cert(identity))
    assert "cert" not in identity  # 被拒绝
    assert "_pending_new_cert" not in identity  # 已清理


def test_new_cert_rejected_key_mismatch():
    """公钥不匹配时 new_cert 被拒绝"""
    key = ec.generate_private_key(ec.SECP256R1())
    different_key = ec.generate_private_key(ec.SECP256R1())
    different_pub_der = different_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
        .public_key(key.public_key())  # cert 的公钥与 identity 的不同
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    root_key, _, root_pem = _build_cert("Root", ca=True)
    flow = _make_auth_flow(root_pem)
    identity = {
        "aid": "alice.test",
        "public_key_der_b64": base64.b64encode(different_pub_der).decode("ascii"),
        "_pending_new_cert": cert_pem,
    }
    asyncio.run(flow._validate_new_cert(identity))
    assert "cert" not in identity  # 被拒绝
