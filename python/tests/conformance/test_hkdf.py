"""
AUN E2EE V2 Conformance: HKDF-SHA256

规范引用: §3.1 / §3.2
- HKDF-SHA256
- V2 wrap_key 长度固定 32 字节
- salt 取 recipients_digest 前 16 字节
- info: "AUN-V2-3DH" 或 "AUN-V2-1DH"
"""
import base64
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.hkdf import hkdf_sha256


# 固定测试向量（来自 RFC 5869 Test Case 1 适配）
IKM_1 = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
SALT_1 = bytes.fromhex("000102030405060708090a0b0c")
INFO_1 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
LENGTH_1 = 42
# RFC 5869 expected OKM for Test Case 1
EXPECTED_OKM_1 = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


class TestHKDF:
    """HKDF-SHA256 密钥派生"""

    def test_rfc5869_case1(self):
        """RFC 5869 Test Case 1"""
        okm = hkdf_sha256(ikm=IKM_1, salt=SALT_1, info=INFO_1, length=LENGTH_1)
        assert okm == EXPECTED_OKM_1

    def test_32_byte_output(self):
        """V2 wrap_key 固定 32 字节"""
        okm = hkdf_sha256(
            ikm=b"\x01" * 32,
            salt=b"\x02" * 16,
            info=b"AUN-V2-3DH",
            length=32,
        )
        assert len(okm) == 32

    def test_aun_v2_3dh_info(self):
        """使用 V2 3DH info 字符串"""
        okm = hkdf_sha256(
            ikm=b"\xaa" * 32,
            salt=b"\xbb" * 16,
            info=b"AUN-V2-3DH",
            length=32,
        )
        assert len(okm) == 32
        assert okm != b"\x00" * 32

    def test_aun_v2_1dh_info(self):
        """使用 V2 1DH info 字符串"""
        okm = hkdf_sha256(
            ikm=b"\xaa" * 32,
            salt=b"\xbb" * 16,
            info=b"AUN-V2-1DH",
            length=32,
        )
        assert len(okm) == 32

    def test_different_info_different_output(self):
        """不同 info 产生不同输出"""
        ikm = b"\xcc" * 32
        salt = b"\xdd" * 16
        okm_3dh = hkdf_sha256(ikm=ikm, salt=salt, info=b"AUN-V2-3DH", length=32)
        okm_1dh = hkdf_sha256(ikm=ikm, salt=salt, info=b"AUN-V2-1DH", length=32)
        assert okm_3dh != okm_1dh

    def test_different_salt_different_output(self):
        """不同 salt 产生不同输出"""
        ikm = b"\xee" * 32
        info = b"AUN-V2-3DH"
        okm1 = hkdf_sha256(ikm=ikm, salt=b"\x01" * 16, info=info, length=32)
        okm2 = hkdf_sha256(ikm=ikm, salt=b"\x02" * 16, info=info, length=32)
        assert okm1 != okm2

    def test_deterministic(self):
        """同输入同输出"""
        kwargs = dict(ikm=b"\xff" * 32, salt=b"\x00" * 16, info=b"AUN-V2-3DH", length=32)
        assert hkdf_sha256(**kwargs) == hkdf_sha256(**kwargs)

    def test_empty_salt(self):
        """空 salt（HKDF 规范允许，用全零替代）"""
        okm = hkdf_sha256(ikm=b"\x01" * 32, salt=b"", info=b"AUN-V2-3DH", length=32)
        assert len(okm) == 32
