"""
AUN E2EE V2 Conformance: 1DH 完整路径

规范引用: §3.2 / §5.2
1DH（SPK 缺失时的降级路径）:
  DH1 = ECDH(sender_session_priv, recv_IK)
  shared = HKDF-SHA256(DH1, salt, info="AUN-V2-1DH")
  wrap_key = shared[:32]
"""
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.dh_path import compute_1dh_wrap
from aun_core.v2.crypto.ecdh import ecdh_compute_shared, private_to_public_der
from aun_core.v2.crypto.hkdf import hkdf_sha256
from aun_core.v2.crypto.aead import aes_gcm_encrypt, aes_gcm_decrypt

# ── 固定测试密钥 ──
from .fixtures import (
    ALICE_PRIV, ALICE_PUB_DER,   # recv_IK
    BOB_PUB_DER,                  # 另一个 IK（差异测试）
    CAROL_PRIV, CAROL_PUB_DER,   # aid_master 模拟
    SENDER_SESSION_PRIV, SENDER_SESSION_PUB_DER,
)

# 加密参数
MASTER_KEY = b"\xab" * 32
WRAP_NONCE = b"\xcd" * 12
SALT = b"\xef" * 16


class TestCompute1DH:
    """1DH 共享秘密推导"""

    def test_1dh_produces_32_byte_wrap_key(self):
        """1DH → HKDF → 32 字节 wrap_key"""
        result = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )
        assert len(result["wrap_key"]) == 32

    def test_1dh_deterministic(self):
        """同输入同输出"""
        r1 = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )
        r2 = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )
        assert r1["wrap_key"] == r2["wrap_key"]

    def test_1dh_uses_correct_info(self):
        """info = 'AUN-V2-1DH'"""
        dh1 = ecdh_compute_shared(SENDER_SESSION_PRIV, ALICE_PUB_DER)
        expected = hkdf_sha256(
            ikm=dh1,
            salt=SALT,
            info=b"AUN-V2-1DH",
            length=32,
        )
        result = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )
        assert result["wrap_key"] == expected

    def test_1dh_different_from_3dh(self):
        """1DH 与 3DH 使用同一 IK 但结果不同（info 不同 + 少两步 DH）"""
        r_1dh = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )
        # 手动用 1DH 的 DH1 但 info="AUN-V2-3DH"
        dh1 = ecdh_compute_shared(SENDER_SESSION_PRIV, ALICE_PUB_DER)
        fake_3dh = hkdf_sha256(ikm=dh1, salt=SALT, info=b"AUN-V2-3DH", length=32)
        assert r_1dh["wrap_key"] != fake_3dh

    def test_1dh_different_ik_different_result(self):
        """不同 IK → 不同 wrap_key"""
        r1 = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )
        r2 = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=BOB_PUB_DER,
            salt=SALT,
        )
        assert r1["wrap_key"] != r2["wrap_key"]


class TestWrapMasterKey1DH:
    """1DH 路径完整 wrap master_key"""

    def test_wrap_and_unwrap(self):
        """发送方 wrap → 接收方 unwrap = 原 master_key"""
        result = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )
        wrap_key = result["wrap_key"]

        ct, tag = aes_gcm_encrypt(key=wrap_key, nonce=WRAP_NONCE, plaintext=MASTER_KEY, aad=b"")
        wrapped_key = ct + tag
        assert len(wrapped_key) == 48

        recovered = aes_gcm_decrypt(
            key=wrap_key, nonce=WRAP_NONCE,
            ciphertext=wrapped_key[:32], tag=wrapped_key[32:], aad=b""
        )
        assert recovered == MASTER_KEY


class TestReceiverSide1DH:
    """接收方 1DH 解密路径——验证对称性"""

    def test_receiver_computes_same_wrap_key(self):
        """
        发送方: ECDH(session_priv, recv_IK_pub)
        接收方: ECDH(recv_IK_priv, session_pub)
        两者 wrap_key 必须相同
        """
        sender_session_pub = private_to_public_der(SENDER_SESSION_PRIV)

        # 发送方侧
        sender_result = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            salt=SALT,
        )

        # 接收方侧
        dh1_recv = ecdh_compute_shared(ALICE_PRIV, sender_session_pub)
        recv_wrap_key = hkdf_sha256(
            ikm=dh1_recv,
            salt=SALT,
            info=b"AUN-V2-1DH",
            length=32,
        )

        assert sender_result["wrap_key"] == recv_wrap_key


class TestAidMasterFallback:
    """aid_master 降级场景（设备未发布 Device IK，用 AID 主公钥）"""

    def test_aid_master_uses_1dh(self):
        """key_source=aid_master 时走 1DH，用 AID 主公钥作为 recv_ik_pub"""
        result = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=CAROL_PUB_DER,  # 模拟 AID 主公钥
            salt=SALT,
        )
        assert len(result["wrap_key"]) == 32

    def test_aid_master_same_key_same_result(self):
        """同一 AID 多设备用 aid_master → 同一 wrap_key（因为公钥相同）"""
        r1 = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=CAROL_PUB_DER,
            salt=SALT,
        )
        r2 = compute_1dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            recv_ik_pub=CAROL_PUB_DER,
            salt=SALT,
        )
        assert r1["wrap_key"] == r2["wrap_key"]
