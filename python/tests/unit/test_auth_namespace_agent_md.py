import asyncio
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AUNClient


def _make_identity(aid: str) -> dict[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return {
        "aid": aid,
        "private_key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
    }


def _sample_agent_md(aid: str = "alice.agentid.pub") -> str:
    return (
        "---\n"
        f"aid: \"{aid}\"\n"
        "name: \"Alice\"\n"
        "type: \"assistant\"\n"
        "version: \"1.0.0\"\n"
        "description: \"Alice\"\n"
        "---\n"
        "\n"
        "# Alice\n"
    )


def test_sign_agent_md_appends_tail_signature(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))

    assert signed.startswith("---\n")
    assert signed.count("<!-- AUN-SIGNATURE") == 1
    assert signed.rstrip().endswith("-->")


def test_verify_agent_md_unsigned_returns_unsigned():
    client = AUNClient()
    result = asyncio.run(client.auth.verify_agent_md(_sample_agent_md()))

    assert result["status"] == "unsigned"
    assert result["verified"] is False


def test_verify_agent_md_roundtrip(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))
    result = asyncio.run(
        client.auth.verify_agent_md(
            signed,
            aid=identity["aid"],
            cert_pem=identity["cert"],
        )
    )

    assert result["status"] == "verified"
    assert result["verified"] is True
    assert result["aid"] == identity["aid"]
    assert result["payload"] == _sample_agent_md()


def test_verify_agent_md_rejects_tamper(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))
    tampered = signed.replace("Alice", "Mallory", 1)
    result = asyncio.run(
        client.auth.verify_agent_md(
            tampered,
            aid=identity["aid"],
            cert_pem=identity["cert"],
        )
    )

    assert result["status"] == "invalid"
    assert result["verified"] is False


def test_sign_agent_md_replaces_existing_signature(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed_once = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))
    signed_twice = asyncio.run(client.auth.sign_agent_md(signed_once))

    assert signed_twice.count("<!-- AUN-SIGNATURE") == 1
