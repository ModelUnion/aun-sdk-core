from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from .errors import AuthError


AGENT_MD_SIGNATURE_MARKER = "<!-- AUN-SIGNATURE"
_AGENT_MD_SIGNATURE_RE = re.compile(
    r"<!-- AUN-SIGNATURE\r?\n(?P<body>.*?)\r?\n-->\s*\Z",
    re.DOTALL,
)
_FINGERPRINT_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def normalize_fingerprint_hex(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1]
    text = text.replace(":", "")
    if len(text) not in (16, 64) or not _FINGERPRINT_HEX_RE.fullmatch(text):
        return ""
    return text


def cert_fingerprint_hexes(cert: x509.Certificate) -> tuple[str, str]:
    cert_hex = cert.fingerprint(hashes.SHA256()).hex()
    spki_hex = hashlib.sha256(public_key_der(cert.public_key())).hexdigest()
    return cert_hex, spki_hex


def cert_matches_fingerprint(cert: x509.Certificate, fingerprint: str | None) -> bool:
    expected = normalize_fingerprint_hex(fingerprint)
    if not expected:
        return False
    cert_hex, spki_hex = cert_fingerprint_hexes(cert)
    if len(expected) == 16:
        return cert_hex[:16] == expected or spki_hex[:16] == expected
    return cert_hex == expected or spki_hex == expected


def public_key_matches_fingerprint(cert: x509.Certificate, fingerprint: str | None) -> bool:
    expected = normalize_fingerprint_hex(fingerprint)
    if not expected:
        return False
    _, spki_hex = cert_fingerprint_hexes(cert)
    if len(expected) == 16:
        return spki_hex[:16] == expected
    return spki_hex == expected


def parse_agent_md_tail_signature(content: str) -> tuple[str, dict[str, str] | None, str | None]:
    marker_index = content.rfind(AGENT_MD_SIGNATURE_MARKER)
    if marker_index < 0:
        return content, None, None
    if marker_index > 0 and content[marker_index - 1] not in "\r\n":
        return content, None, None

    tail = content[marker_index:]
    match = _AGENT_MD_SIGNATURE_RE.fullmatch(tail)
    if not match:
        return content[:marker_index], None, "malformed signature block"

    fields: dict[str, str] = {}
    for line in match.group("body").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ":" not in stripped:
            return content[:marker_index], None, f"malformed signature field: {stripped}"
        key, value = stripped.split(":", 1)
        fields[key.strip().lower()] = value.strip()

    for required in ("cert_fingerprint", "timestamp", "signature"):
        if not fields.get(required):
            return content[:marker_index], None, f"signature block missing {required}"
    if not normalize_fingerprint_hex(fields["cert_fingerprint"]):
        return content[:marker_index], None, "invalid cert_fingerprint"
    if fields.get("public_key_fingerprint") and not normalize_fingerprint_hex(fields["public_key_fingerprint"]):
        return content[:marker_index], None, "invalid public_key_fingerprint"
    try:
        int(fields["timestamp"])
    except ValueError:
        return content[:marker_index], None, "invalid timestamp"

    return content[:marker_index], fields, None


def extract_agent_md_aid(payload: str) -> str:
    lines = payload.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if stripped.startswith("aid:"):
            value = stripped.split(":", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            return value.strip()
    return ""


def build_agent_md_signature_block(
    *,
    cert_fingerprint: str,
    timestamp: int,
    signature_b64: str,
    public_key_fingerprint: str = "",
) -> str:
    lines = [
        "<!-- AUN-SIGNATURE",
        f"cert_fingerprint: {cert_fingerprint}",
    ]
    if public_key_fingerprint:
        lines.append(f"public_key_fingerprint: {public_key_fingerprint}")
    lines.extend([
        f"timestamp: {int(timestamp)}",
        f"signature: {signature_b64}",
        "-->",
    ])
    return "\n".join(lines)


def normalize_agent_md_payload(content: str) -> str:
    payload, _, _ = parse_agent_md_tail_signature(str(content or ""))
    if payload and not payload.endswith(("\n", "\r")):
        payload += "\n"
    return payload


def verify_signature(public_key: Any, sig_bytes: bytes, data_bytes: bytes) -> None:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(sig_bytes, data_bytes)
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if isinstance(public_key.curve, ec.SECP384R1):
            public_key.verify(sig_bytes, data_bytes, ec.ECDSA(hashes.SHA384()))
        else:
            public_key.verify(sig_bytes, data_bytes, ec.ECDSA(hashes.SHA256()))
        return
    raise AuthError(f"unsupported identity public key type: {type(public_key)!r}")


def sign_bytes(private_key: Any, payload: bytes) -> bytes:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(payload)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        if isinstance(private_key.curve, ec.SECP384R1):
            return private_key.sign(payload, ec.ECDSA(hashes.SHA384()))
        return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    raise AuthError(f"unsupported identity private key type: {type(private_key)!r}")


def verify_bytes(public_key: Any, payload: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(str(signature_b64 or ""), validate=True)
        verify_signature(public_key, signature, payload)
        return True
    except InvalidSignature:
        return False


def cert_common_name(cert: x509.Certificate, *, issuer: bool = False) -> str:
    name = cert.issuer if issuer else cert.subject
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def cert_fingerprint(cert: x509.Certificate) -> str:
    return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()


def public_key_fingerprint(cert: x509.Certificate) -> str:
    return "sha256:" + hashlib.sha256(public_key_der(cert.public_key())).hexdigest()


def public_key_der_b64(cert: x509.Certificate) -> str:
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def public_key_der(public_key: Any) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def payload_bytes(payload: bytes | str) -> bytes:
    if isinstance(payload, bytes):
        return payload
    return str(payload).encode("utf-8")


def cert_time_error(cert: x509.Certificate) -> str:
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        return "not_yet_valid"
    if now > cert.not_valid_after_utc:
        return "expired"
    return ""
