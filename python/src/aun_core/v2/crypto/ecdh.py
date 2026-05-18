"""
AUN E2EE V2: ECDH P-256

规范引用: §3.1
- 曲线: P-256 (secp256r1)
- 输出: 椭圆曲线点 X 坐标字节（32 字节，无前缀）
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.backends import default_backend


def ecdh_compute_shared(private_key_scalar: bytes, peer_public_key_der: bytes) -> bytes:
    """计算 ECDH 共享秘密（P-256 X 坐标，32 字节）。

    Args:
        private_key_scalar: 私钥标量（32 字节 big-endian）
        peer_public_key_der: 对端公钥（DER SubjectPublicKeyInfo 编码）

    Returns:
        32 字节共享秘密（椭圆曲线点 X 坐标）
    """
    # 从 scalar 构造私钥对象
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_scalar, "big"),
        ec.SECP256R1(),
        default_backend(),
    )

    # 解析对端公钥
    peer_key = load_der_public_key(peer_public_key_der, default_backend())
    if not isinstance(peer_key, ec.EllipticCurvePublicKey):
        raise ValueError("peer_public_key_der is not an EC public key")

    # ECDH
    shared_key = private_key.exchange(ec.ECDH(), peer_key)

    # shared_key 已经是 X 坐标（32 字节）——cryptography 库的 ECDH 默认输出就是这个
    assert len(shared_key) == 32
    return shared_key


def generate_p256_keypair() -> tuple[bytes, bytes]:
    """生成 P-256 密钥对。

    Returns:
        (private_key_scalar: 32 bytes, public_key_der: DER SubjectPublicKeyInfo bytes)
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_scalar = private_key.private_numbers().private_value.to_bytes(32, "big")
    public_der = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return private_scalar, public_der


def private_to_public_der(private_key_scalar: bytes) -> bytes:
    """从私钥标量导出公钥 DER。

    Args:
        private_key_scalar: 32 字节私钥标量

    Returns:
        DER SubjectPublicKeyInfo 编码的公钥
    """
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_scalar, "big"),
        ec.SECP256R1(),
        default_backend(),
    )
    return private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
