"""ECIES epoch key 加解密 + 服务端存储方案单元测试。"""

from __future__ import annotations

import base64
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from aun_core.e2ee import ecies_encrypt, ecies_decrypt, generate_group_secret


def _gen_ec_keypair():
    """生成 P-256 密钥对，返回 (private_key, public_key_bytes_uncompressed)。"""
    privkey = ec.generate_private_key(ec.SECP256R1())
    pubkey_bytes = privkey.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return privkey, pubkey_bytes


class TestECIESBasic:
    """ECIES 加解密基础功能测试。"""

    def test_encrypt_decrypt_roundtrip(self):
        """加密后解密应还原明文。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        plaintext = b"hello epoch secret 32 bytes!!!!!"
        ciphertext = ecies_encrypt(pubkey_bytes, plaintext)
        decrypted = ecies_decrypt(privkey, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_32_byte_secret(self):
        """32 字节 group_secret 加解密。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        group_secret = generate_group_secret()
        assert len(group_secret) == 32
        ciphertext = ecies_encrypt(pubkey_bytes, group_secret)
        decrypted = ecies_decrypt(privkey, ciphertext)
        assert decrypted == group_secret

    def test_ciphertext_format(self):
        """密文格式: ephemeral_pubkey(65B) || iv(12B) || ciphertext || tag(16B)。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        plaintext = secrets.token_bytes(32)
        ciphertext = ecies_encrypt(pubkey_bytes, plaintext)
        # 最小长度: 65 + 12 + 32 + 16 = 125
        assert len(ciphertext) >= 65 + 12 + 16
        # 前 65 字节是未压缩公钥（0x04 开头）
        assert ciphertext[0] == 0x04

    def test_different_ciphertext_each_time(self):
        """每次加密产生不同密文（临时密钥不同）。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        plaintext = secrets.token_bytes(32)
        ct1 = ecies_encrypt(pubkey_bytes, plaintext)
        ct2 = ecies_encrypt(pubkey_bytes, plaintext)
        assert ct1 != ct2

    def test_wrong_key_decrypt_fails(self):
        """用错误私钥解密应失败。"""
        _, pubkey_bytes = _gen_ec_keypair()
        wrong_privkey, _ = _gen_ec_keypair()
        plaintext = secrets.token_bytes(32)
        ciphertext = ecies_encrypt(pubkey_bytes, plaintext)
        with pytest.raises(Exception):
            ecies_decrypt(wrong_privkey, ciphertext)

    def test_tampered_ciphertext_fails(self):
        """篡改密文应解密失败。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        plaintext = secrets.token_bytes(32)
        ciphertext = ecies_encrypt(pubkey_bytes, plaintext)
        # 篡改最后一个字节
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        with pytest.raises(Exception):
            ecies_decrypt(privkey, tampered)

    def test_empty_plaintext(self):
        """空明文加解密。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        ciphertext = ecies_encrypt(pubkey_bytes, b"")
        decrypted = ecies_decrypt(privkey, ciphertext)
        assert decrypted == b""

    def test_large_plaintext(self):
        """较大明文加解密。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        plaintext = secrets.token_bytes(1024)
        ciphertext = ecies_encrypt(pubkey_bytes, plaintext)
        decrypted = ecies_decrypt(privkey, ciphertext)
        assert decrypted == plaintext


class TestECIESMultiMember:
    """模拟多成员场景：同一 group_secret 用不同公钥加密，各自能解密。"""

    def test_multi_member_encrypt_decrypt(self):
        """3 个成员各自用自己的私钥解密同一 group_secret。"""
        group_secret = generate_group_secret()
        members = [_gen_ec_keypair() for _ in range(3)]

        encrypted_keys: dict[str, bytes] = {}
        for i, (_, pubkey_bytes) in enumerate(members):
            encrypted_keys[f"member_{i}"] = ecies_encrypt(pubkey_bytes, group_secret)

        for i, (privkey, _) in enumerate(members):
            decrypted = ecies_decrypt(privkey, encrypted_keys[f"member_{i}"])
            assert decrypted == group_secret

    def test_cross_member_decrypt_fails(self):
        """成员 A 的密文不能被成员 B 解密。"""
        group_secret = generate_group_secret()
        privkey_a, pubkey_a = _gen_ec_keypair()
        privkey_b, pubkey_b = _gen_ec_keypair()

        ct_for_a = ecies_encrypt(pubkey_a, group_secret)
        with pytest.raises(Exception):
            ecies_decrypt(privkey_b, ct_for_a)


class TestECIESBase64Integration:
    """模拟实际传输场景：base64 编码/解码。"""

    def test_base64_roundtrip(self):
        """base64 编码传输后仍能正确解密。"""
        privkey, pubkey_bytes = _gen_ec_keypair()
        group_secret = generate_group_secret()

        ciphertext = ecies_encrypt(pubkey_bytes, group_secret)
        b64_encoded = base64.b64encode(ciphertext).decode("ascii")

        # 模拟从服务端拉取后解码
        decoded = base64.b64decode(b64_encoded)
        decrypted = ecies_decrypt(privkey, decoded)
        assert decrypted == group_secret
