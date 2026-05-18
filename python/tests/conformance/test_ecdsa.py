"""
AUN E2EE V2 Conformance: ECDSA-SHA256 RAW (RFC 6979 deterministic)

规范引用: §3.1
- ECDSA-SHA256
- RAW 编码: r (32B) || s (32B) = 64 字节
- MUST 使用 RFC 6979 deterministic 签名
"""
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.ecdsa import ecdsa_sign_raw, ecdsa_verify_raw

# ── 固定测试密钥 ──
from .fixtures import ALICE_PRIV, ALICE_PUB_DER, BOB_PUB_DER

MESSAGE_1 = b"hello aun v2"
MESSAGE_2 = b"different message"


class TestECDSASign:
    """ECDSA-SHA256 RAW 签名"""

    def test_sign_produces_64_bytes(self):
        """签名输出 64 字节（r || s）"""
        sig = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        assert len(sig) == 64

    def test_sign_deterministic_rfc6979(self):
        """RFC 6979: 同一私钥 + 同一消息 → 同一签名（确定性）"""
        sig1 = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        sig2 = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        assert sig1 == sig2

    def test_different_message_different_sig(self):
        """不同消息 → 不同签名"""
        sig1 = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        sig2 = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_2)
        assert sig1 != sig2

    def test_sign_not_der_encoded(self):
        """输出是 RAW (r||s)，不是 DER 编码"""
        sig = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        assert len(sig) == 64


class TestECDSAVerify:
    """ECDSA-SHA256 RAW 验签"""

    def test_verify_valid_signature(self):
        """有效签名验证通过"""
        sig = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        assert ecdsa_verify_raw(ALICE_PUB_DER, sig, MESSAGE_1) is True

    def test_verify_wrong_message_fails(self):
        """消息不匹配 → 验签失败"""
        sig = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        assert ecdsa_verify_raw(ALICE_PUB_DER, sig, MESSAGE_2) is False

    def test_verify_tampered_sig_fails(self):
        """篡改签名 → 验签失败"""
        sig = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        tampered = bytearray(sig)
        tampered[0] ^= 0xFF
        assert ecdsa_verify_raw(ALICE_PUB_DER, bytes(tampered), MESSAGE_1) is False

    def test_verify_wrong_key_fails(self):
        """错误公钥 → 验签失败"""
        sig = ecdsa_sign_raw(ALICE_PRIV, MESSAGE_1)
        assert ecdsa_verify_raw(BOB_PUB_DER, sig, MESSAGE_1) is False


class TestECDSAV2SignInput:
    """模拟 V2 sender_signature 签名输入"""

    def test_sign_v2_sign_input(self):
        """V2 sign_input = ciphertext || tag || canonical_json(aad) || recipients_digest_bytes"""
        ciphertext = b"\x01" * 100
        tag = b"\x02" * 16
        aad_bytes = b'{"from":"alice.aid","message_id":"gm-123"}'
        recipients_digest_bytes = b"\x03" * 32

        sign_input = ciphertext + tag + aad_bytes + recipients_digest_bytes
        sig = ecdsa_sign_raw(ALICE_PRIV, sign_input)
        assert len(sig) == 64
        assert ecdsa_verify_raw(ALICE_PUB_DER, sig, sign_input) is True

    def test_sign_empty_message(self):
        """空消息签名"""
        sig = ecdsa_sign_raw(ALICE_PRIV, b"")
        assert len(sig) == 64
        assert ecdsa_verify_raw(ALICE_PUB_DER, sig, b"") is True
