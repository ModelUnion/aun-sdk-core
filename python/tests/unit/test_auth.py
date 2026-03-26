import asyncio
import base64
import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from aun_core.auth import AuthFlow
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
        keystore=keystore,
        crypto=CryptoProvider(),
        connection_factory=lambda url: None,
        root_ca_path=str(root_path),
    )


def _build_ocsp_response(cert: x509.Certificate, issuer_cert: x509.Certificate, issuer_key, *, status: str) -> str:
    now = datetime.now(timezone.utc)
    if status == "good":
        cert_status = ocsp.OCSPCertStatus.GOOD
        revocation_time = None
    elif status == "revoked":
        cert_status = ocsp.OCSPCertStatus.REVOKED
        revocation_time = now
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

    async def fake_fetch_gateway_ca_chain(gateway_url: str) -> list[str]:
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
                "identity_cert": identity_pem,
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

    async def fake_fetch_gateway_ca_chain(gateway_url: str) -> list[str]:
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

    with pytest.raises(AuthError, match="server identity signature verification failed"):
        asyncio.run(
            flow._verify_phase1_response(
                "wss://gw.example/aun",
                {
                    "identity_cert": identity_pem,
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

    async def fake_fetch_gateway_ca_chain(gateway_url: str) -> list[str]:
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

    with pytest.raises(AuthError, match="identity certificate has been revoked"):
        asyncio.run(
            flow._verify_phase1_response(
                "wss://gw.example/aun",
                {
                    "identity_cert": identity_pem,
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
