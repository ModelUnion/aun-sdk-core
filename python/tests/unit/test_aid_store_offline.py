from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AIDStore
from aun_core.config import get_device_id
from aun_core.keystore.local_identity_store import LocalIdentityStore


def _identity(aid: str, *, key=None, not_after: datetime | None = None) -> dict[str, str]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(not_after or (now + timedelta(days=30)))
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


def test_store_load_local_identity_with_private_key(tmp_path):
    aid = "alice.agentid.pub"
    keystore = LocalIdentityStore(tmp_path, encryption_seed="seed")
    keystore.save_identity(aid, _identity(aid))

    result = AIDStore(str(tmp_path), "seed").load(aid)

    assert result.ok
    loaded = result.data["aid"]
    assert loaded.aid == aid
    assert loaded.is_cert_valid()
    assert loaded.is_private_key_valid()


def test_store_uses_device_id_file_and_normalizes_empty_slot_to_default(tmp_path):
    store = AIDStore(str(tmp_path), "", slot_id="")
    try:
        assert store.device_id == get_device_id(tmp_path)
        assert store.slot_id == "default"
    finally:
        store.close()

    store = AIDStore(str(tmp_path), "", slot_id="  ")
    try:
        assert store.device_id == get_device_id(tmp_path)
        assert store.slot_id == "default"
    finally:
        store.close()


def test_store_load_peer_only_certificate(tmp_path):
    aid = "bob.agentid.pub"
    identity = _identity(aid)
    keystore = LocalIdentityStore(tmp_path, encryption_seed="")
    keystore.save_cert(aid, identity["cert"])

    result = AIDStore(str(tmp_path), "").load(aid)

    assert result.ok
    peer = result.data["aid"]
    assert peer.is_cert_valid()
    assert not peer.is_private_key_valid()


def test_store_load_missing_cert_returns_result_error(tmp_path):
    result = AIDStore(str(tmp_path), "").load("missing.agentid.pub")

    assert not result.ok
    assert result.error.code == "CERT_NOT_FOUND"


def test_store_load_keypair_mismatch_returns_result_error(tmp_path):
    aid = "alice.agentid.pub"
    key_a = ec.generate_private_key(ec.SECP256R1())
    key_b = ec.generate_private_key(ec.SECP256R1())
    identity = _identity(aid, key=key_a)
    mismatched = dict(identity)
    mismatched["private_key_pem"] = key_b.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    keystore = LocalIdentityStore(tmp_path, encryption_seed="seed")
    keystore.save_identity(aid, mismatched)

    result = AIDStore(str(tmp_path), "seed").load(aid)

    assert not result.ok
    assert result.error.code == "KEYPAIR_MISMATCH"


def test_store_list_only_returns_identities_with_private_key(tmp_path):
    keystore = LocalIdentityStore(tmp_path, encryption_seed="")
    keystore.save_identity("alice.agentid.pub", _identity("alice.agentid.pub"))
    keystore.save_cert("bob.agentid.pub", _identity("bob.agentid.pub")["cert"])

    result = AIDStore(str(tmp_path), "").list()

    assert result.ok
    assert [item["aid"] for item in result.data["identities"]] == ["alice.agentid.pub"]
