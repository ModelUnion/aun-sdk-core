"""
AUN E2EE V2 Conformance: ECDH (P-256)

规范引用: §3.1
- 曲线: P-256 (secp256r1)
- ECDH 输出: 椭圆曲线点 X 坐标字节（32 字节，无前缀）
"""
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.ecdh import ecdh_compute_shared

# ── 固定测试密钥 ──
from .fixtures import (
    ALICE_PRIV, ALICE_PUB_DER,
    BOB_PRIV, BOB_PUB_DER,
    CAROL_PUB_DER,
    SENDER_SESSION_PRIV, SENDER_SESSION_PUB_DER,
)


class TestECDH:
    """ECDH P-256 共享秘密计算"""

    def test_alice_bob_shared_secret(self):
        """Alice 私钥 × Bob 公钥 = 共享秘密（32 字节 X 坐标）"""
        shared = ecdh_compute_shared(ALICE_PRIV, BOB_PUB_DER)
        assert len(shared) == 32
        # 对称性：Bob 私钥 × Alice 公钥 = 同一共享秘密
        shared2 = ecdh_compute_shared(BOB_PRIV, ALICE_PUB_DER)
        assert shared == shared2

    def test_output_is_x_coordinate_only(self):
        """输出是 X 坐标（32 字节），不含 04 前缀或 Y 坐标"""
        shared = ecdh_compute_shared(ALICE_PRIV, BOB_PUB_DER)
        assert len(shared) == 32

    def test_different_keys_different_shared(self):
        """不同密钥对产生不同共享秘密"""
        shared1 = ecdh_compute_shared(ALICE_PRIV, BOB_PUB_DER)
        shared2 = ecdh_compute_shared(ALICE_PRIV, CAROL_PUB_DER)
        assert shared1 != shared2

    def test_deterministic(self):
        """同输入同输出（确定性）"""
        shared1 = ecdh_compute_shared(ALICE_PRIV, BOB_PUB_DER)
        shared2 = ecdh_compute_shared(ALICE_PRIV, BOB_PUB_DER)
        assert shared1 == shared2

    def test_session_key_ecdh(self):
        """发送方 session 私钥 × 接收方 IK 公钥"""
        shared = ecdh_compute_shared(SENDER_SESSION_PRIV, ALICE_PUB_DER)
        assert len(shared) == 32
