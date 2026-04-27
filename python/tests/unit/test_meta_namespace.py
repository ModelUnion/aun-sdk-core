from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core.client import AUNClient
from aun_core.errors import ValidationError


def _make_ca_cert(common_name: str):
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
        .sign(key, hashes.SHA384())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return key, cert, cert_pem


def _signed_trust_list(authority_key, root_cert: x509.Certificate, root_pem: str, *, version: int = 1) -> dict:
    payload = {
        "version": version,
        "issued_at": "2026-03-15T10:00:00Z",
        "next_update": "2026-03-16T10:00:00Z",
        "root_cas": [
            {
                "id": "root-ca-test",
                "name": "AUN Test Root",
                "organization": "AUN",
                "certificate": root_pem,
                "fingerprint_sha256": root_cert.fingerprint(hashes.SHA256()).hex(),
                "status": "active",
            }
        ],
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = authority_key.sign(canonical, ec.ECDSA(hashes.SHA384()))
    payload["authority_signature"] = base64.b64encode(signature).decode("ascii")
    return payload


def test_meta_import_trust_roots_verifies_and_reloads(tmp_path: Path):
    authority_key, _, authority_pem = _make_ca_cert("AUN Root CA Authority")
    _, root_cert, root_pem = _make_ca_cert("AUN Test Root CA")
    trust_list = _signed_trust_list(authority_key, root_cert, root_pem)

    client = AUNClient({"aun_path": str(tmp_path)})
    result = client.meta.import_trust_roots(trust_list, authority_cert_pem=authority_pem)

    assert result["imported"] == 1
    bundle_path = Path(result["bundle_path"])
    assert bundle_path.exists()
    assert "BEGIN CERTIFICATE" in bundle_path.read_text(encoding="utf-8")
    imported_fp = root_cert.fingerprint(hashes.SHA256()).hex()
    assert imported_fp in result["fingerprints"]
    assert any(cert.fingerprint(hashes.SHA256()).hex() == imported_fp for cert in client._auth._root_certs)


def test_meta_import_trust_roots_rejects_unsigned_by_default(tmp_path: Path):
    _, root_cert, root_pem = _make_ca_cert("AUN Test Root CA")
    trust_list = {
        "version": 1,
        "root_cas": [
            {
                "id": "root-ca-test",
                "certificate": root_pem,
                "fingerprint_sha256": root_cert.fingerprint(hashes.SHA256()).hex(),
                "status": "active",
            }
        ],
    }

    client = AUNClient({"aun_path": str(tmp_path)})
    with pytest.raises(ValidationError, match="authority_signature"):
        client.meta.import_trust_roots(trust_list)


def test_meta_import_trust_roots_rejects_version_rollback(tmp_path: Path):
    authority_key, _, authority_pem = _make_ca_cert("AUN Root CA Authority")
    _, root_cert, root_pem = _make_ca_cert("AUN Test Root CA")

    client = AUNClient({"aun_path": str(tmp_path)})
    client.meta.import_trust_roots(
        _signed_trust_list(authority_key, root_cert, root_pem, version=2),
        authority_cert_pem=authority_pem,
    )

    with pytest.raises(ValidationError, match="version rollback"):
        client.meta.import_trust_roots(
            _signed_trust_list(authority_key, root_cert, root_pem, version=1),
            authority_cert_pem=authority_pem,
        )


def test_meta_gateway_trust_roots_url_uses_https_for_wss_and_https(tmp_path: Path):
    client = AUNClient({"aun_path": str(tmp_path)})

    assert (
        client.meta._gateway_trust_roots_url("wss://gateway.example/ws")
        == "https://gateway.example/pki/trust-roots.json"
    )
    assert (
        client.meta._gateway_trust_roots_url("https://gateway.example")
        == "https://gateway.example/pki/trust-roots.json"
    )


@pytest.mark.asyncio
async def test_meta_update_issuer_root_cert_verifies_against_trust_list(tmp_path: Path):
    authority_key, _, authority_pem = _make_ca_cert("AUN Root CA Authority")
    _, root_cert, root_pem = _make_ca_cert("AUN Test Root CA")
    trust_list = _signed_trust_list(authority_key, root_cert, root_pem, version=3)

    client = AUNClient({"aun_path": str(tmp_path)})
    result = await client.meta.update_issuer_root_cert(
        "issuer.example",
        cert_pem=root_pem,
        trust_list=trust_list,
        authority_cert_pem=authority_pem,
    )

    imported_fp = root_cert.fingerprint(hashes.SHA256()).hex()
    assert result["issuer"] == "issuer.example"
    assert result["fingerprint_sha256"] == imported_fp
    assert Path(result["cert_path"]).exists()
    assert any(cert.fingerprint(hashes.SHA256()).hex() == imported_fp for cert in client._auth._root_certs)


def test_meta_issuer_pki_urls_use_trust_root_and_root_crt(tmp_path: Path):
    client = AUNClient({"aun_path": str(tmp_path), "discovery_port": 9443})

    assert client.meta._issuer_trust_root_url("issuer.example") == "https://pki.issuer.example:9443/trust-root.json"
    assert client.meta._issuer_root_cert_url("issuer.example") == "https://pki.issuer.example:9443/root.crt"
