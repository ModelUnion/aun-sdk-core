"""
AUN E2EE V2 Conformance: AES-256-GCM (AEAD)

规范引用: §3.1
- AES-256-GCM
- nonce: 12 字节
- tag: 16 字节
- wrapped_key 字段 = ciphertext + tag 拼接
"""
import base64
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.aead import aes_gcm_encrypt, aes_gcm_decrypt


# 固定测试向量
KEY_32 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
NONCE_12 = bytes.fromhex("cafebabefacedbaddecaf888")
PLAINTEXT = b"hello aun v2 e2ee"
AAD = b'{"from":"alice.aid","to":"bob.aid"}'


class TestAEADEncrypt:
    """AES-256-GCM 加密"""

    def test_encrypt_produces_ciphertext_and_tag(self):
        ciphertext, tag = aes_gcm_encrypt(
            key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD
        )
        assert len(tag) == 16
        assert len(ciphertext) == len(PLAINTEXT)
        assert ciphertext != PLAINTEXT

    def test_encrypt_deterministic(self):
        """同输入同输出"""
        ct1, tag1 = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        ct2, tag2 = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        assert ct1 == ct2
        assert tag1 == tag2

    def test_different_nonce_different_output(self):
        ct1, _ = aes_gcm_encrypt(key=KEY_32, nonce=b"\x01" * 12, plaintext=PLAINTEXT, aad=AAD)
        ct2, _ = aes_gcm_encrypt(key=KEY_32, nonce=b"\x02" * 12, plaintext=PLAINTEXT, aad=AAD)
        assert ct1 != ct2

    def test_different_key_different_output(self):
        ct1, _ = aes_gcm_encrypt(key=b"\x01" * 32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        ct2, _ = aes_gcm_encrypt(key=b"\x02" * 32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        assert ct1 != ct2

    def test_empty_plaintext(self):
        """空明文加密（仅产生 tag）"""
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=b"", aad=AAD)
        assert ct == b""
        assert len(tag) == 16

    def test_empty_aad(self):
        """空 AAD"""
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=b"")
        assert len(ct) == len(PLAINTEXT)
        assert len(tag) == 16


class TestAEADDecrypt:
    """AES-256-GCM 解密"""

    def test_decrypt_roundtrip(self):
        """加密 → 解密 = 原文"""
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        result = aes_gcm_decrypt(key=KEY_32, nonce=NONCE_12, ciphertext=ct, tag=tag, aad=AAD)
        assert result == PLAINTEXT

    def test_wrong_key_fails(self):
        """错误密钥解密失败"""
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        with pytest.raises(Exception):
            aes_gcm_decrypt(key=b"\x00" * 32, nonce=NONCE_12, ciphertext=ct, tag=tag, aad=AAD)

    def test_wrong_nonce_fails(self):
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        with pytest.raises(Exception):
            aes_gcm_decrypt(key=KEY_32, nonce=b"\x00" * 12, ciphertext=ct, tag=tag, aad=AAD)

    def test_wrong_aad_fails(self):
        """AAD 不匹配 → 认证失败"""
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        with pytest.raises(Exception):
            aes_gcm_decrypt(key=KEY_32, nonce=NONCE_12, ciphertext=ct, tag=tag, aad=b"tampered")

    def test_tampered_ciphertext_fails(self):
        """篡改密文 → 认证失败"""
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            aes_gcm_decrypt(key=KEY_32, nonce=NONCE_12, ciphertext=bytes(tampered), tag=tag, aad=AAD)

    def test_tampered_tag_fails(self):
        """篡改 tag → 认证失败"""
        ct, tag = aes_gcm_encrypt(key=KEY_32, nonce=NONCE_12, plaintext=PLAINTEXT, aad=AAD)
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0xFF
        with pytest.raises(Exception):
            aes_gcm_decrypt(key=KEY_32, nonce=NONCE_12, ciphertext=ct, tag=bytes(tampered_tag), aad=AAD)


class TestAEADWrapKey:
    """模拟 V2 wrap master_key 场景"""

    def test_wrap_32byte_master_key(self):
        """包装 32 字节 master_key"""
        master_key = b"\xab" * 32
        wrap_key = b"\xcd" * 32
        wrap_nonce = b"\xef" * 12
        ct, tag = aes_gcm_encrypt(key=wrap_key, nonce=wrap_nonce, plaintext=master_key, aad=b"")
        # wrapped_key 字段 = ct + tag（48 字节）
        wrapped_key = ct + tag
        assert len(wrapped_key) == 48

    def test_unwrap_master_key(self):
        """解包 master_key"""
        master_key = b"\xab" * 32
        wrap_key = b"\xcd" * 32
        wrap_nonce = b"\xef" * 12
        ct, tag = aes_gcm_encrypt(key=wrap_key, nonce=wrap_nonce, plaintext=master_key, aad=b"")
        # 模拟接收方拆分 wrapped_key
        wrapped_key = ct + tag
        recovered = aes_gcm_decrypt(
            key=wrap_key, nonce=wrap_nonce,
            ciphertext=wrapped_key[:32], tag=wrapped_key[32:], aad=b""
        )
        assert recovered == master_key
