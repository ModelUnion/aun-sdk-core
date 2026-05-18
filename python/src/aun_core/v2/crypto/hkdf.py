"""
AUN E2EE V2: HKDF-SHA256

规范引用: §3.1
- HKDF-SHA256 (RFC 5869)
- V2 wrap_key 长度固定 32 字节
- salt 取 recipients_digest 前 16 字节
- info: "AUN-V2-3DH" 或 "AUN-V2-1DH"
"""
from __future__ import annotations

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 密钥派生。

    Args:
        ikm: 输入密钥材料（ECDH 输出拼接）
        salt: 盐值（V2 中为 recipients_digest 前 16 字节）
        info: 上下文信息（"AUN-V2-3DH" 或 "AUN-V2-1DH"）
        length: 输出长度（V2 中固定 32）

    Returns:
        派生密钥（length 字节）
    """
    if not salt:
        # HKDF 规范：空 salt 等价于 HashLen 个零字节
        salt = b"\x00" * 32  # SHA-256 HashLen = 32

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(ikm)
