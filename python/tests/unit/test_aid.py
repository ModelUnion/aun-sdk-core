from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core.aid import AID


def _make_aid(aid: str = "alice.agentid.pub") -> AID:
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
    return AID._create(
        aid=aid,
        aun_path="/tmp/aun",
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        cert_obj=cert,
        private_key_obj=key,
        cert_valid=True,
        private_key_valid=True,
    )


def test_aid_sign_verify_roundtrip():
    aid = _make_aid()

    signed = aid.sign(b"payload")
    assert signed.ok

    verified = aid.verify(b"payload", signed.data["signature"])
    assert verified.ok
    assert verified.data == {"valid": True}

    tampered = aid.verify(b"tampered", signed.data["signature"])
    assert tampered.ok
    assert tampered.data == {"valid": False}


def test_aid_agent_md_sign_verify_roundtrip():
    aid = _make_aid()

    signed = aid.sign_agent_md('---\naid: "alice.agentid.pub"\n---\n# Alice\n')
    assert signed.ok
    assert "<!-- AUN-SIGNATURE" in signed.data["signed"]

    verified = aid.verify_agent_md(signed.data["signed"])
    assert verified.ok
    assert verified.data["status"] == "verified"
    assert verified.data["aid"] == "alice.agentid.pub"
    assert verified.data["payload"].startswith("---\n")


def test_peer_only_aid_cannot_sign():
    aid = _make_aid()
    peer = AID._create(
        aid=aid.aid,
        aun_path=aid.aun_path,
        cert_pem=aid.cert_pem,
        cert_obj=aid._cert_obj,
        private_key_obj=None,
        cert_valid=True,
        private_key_valid=False,
    )

    result = peer.sign(b"payload")

    assert not result.ok
    assert result.error.code == "PRIVATE_KEY_NOT_VALID"


def test_aid_exposes_public_key_der_base64_and_fingerprint():
    aid = _make_aid()

    assert base64.b64decode(aid.public_key)
    assert aid.cert_subject == "alice.agentid.pub"
    assert aid.cert_issuer == "alice.agentid.pub"
    assert aid.cert_fingerprint.startswith("sha256:")
