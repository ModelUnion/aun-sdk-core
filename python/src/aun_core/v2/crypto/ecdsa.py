"""
AUN E2EE V2: ECDSA-SHA256 RAW (RFC 6979 deterministic)

规范引用: §3.1
- ECDSA-SHA256
- RAW 编码: r (32B) || s (32B) = 64 字节定长
- MUST 使用 RFC 6979 deterministic 签名
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def ecdsa_sign_raw(private_key_scalar: bytes, message: bytes) -> bytes:
    """ECDSA-SHA256 签名，输出 RAW 编码 (r || s, 64 字节)。

    使用 RFC 6979 deterministic nonce（cryptography 库默认行为）。

    Args:
        private_key_scalar: P-256 私钥标量（32 字节 big-endian）
        message: 待签名消息

    Returns:
        64 字节签名（r 32B || s 32B）
    """
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_scalar, "big"),
        ec.SECP256R1(),
        default_backend(),
    )

    # cryptography 库 >= 41.0 支持 deterministic_signing=True (RFC 6979)
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))

    # DER → RAW (r || s)
    r, s = decode_dss_signature(der_sig)
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    return r_bytes + s_bytes


def ecdsa_verify_raw(public_key_der: bytes, signature_raw: bytes, message: bytes) -> bool:
    """ECDSA-SHA256 验签，输入 RAW 编码签名。

    Args:
        public_key_der: P-256 公钥（DER SubjectPublicKeyInfo 编码）
        signature_raw: 64 字节签名（r 32B || s 32B）
        message: 原始消息

    Returns:
        True 验签通过，False 失败
    """
    if len(signature_raw) != 64:
        return False

    try:
        public_key = serialization.load_der_public_key(public_key_der, default_backend())
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False

        # RAW → DER
        r = int.from_bytes(signature_raw[:32], "big")
        s = int.from_bytes(signature_raw[32:], "big")
        der_sig = encode_dss_signature(r, s)

        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
