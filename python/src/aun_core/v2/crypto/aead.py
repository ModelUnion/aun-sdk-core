"""
AUN E2EE V2: AES-256-GCM (AEAD)

规范引用: §3.1
- AES-256-GCM
- nonce: 12 字节
- tag: 16 字节
- wrapped_key 字段 = ciphertext + tag 拼接（48 字节）
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM 加密。

    Args:
        key: 32 字节密钥
        nonce: 12 字节随机数
        plaintext: 明文
        aad: 附加认证数据

    Returns:
        (ciphertext, tag) — ciphertext 与 plaintext 等长；tag 16 字节
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"AES-256-GCM nonce must be 12 bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    # cryptography 库的 encrypt 返回 ciphertext + tag 拼接
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad if aad else None)

    # 拆分：最后 16 字节是 tag
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """AES-256-GCM 解密。

    Args:
        key: 32 字节密钥
        nonce: 12 字节随机数
        ciphertext: 密文
        tag: 16 字节认证标签
        aad: 附加认证数据

    Returns:
        明文

    Raises:
        Exception: 认证失败（密钥错误 / 数据被篡改）
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"AES-256-GCM nonce must be 12 bytes, got {len(nonce)}")
    if len(tag) != 16:
        raise ValueError(f"AES-256-GCM tag must be 16 bytes, got {len(tag)}")

    aesgcm = AESGCM(key)
    # cryptography 库的 decrypt 需要 ciphertext + tag 拼接
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, aad if aad else None)
