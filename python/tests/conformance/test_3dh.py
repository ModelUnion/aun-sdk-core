"""
AUN E2EE V2 Conformance: 3DH 完整路径

规范引用: §3.2 / §5.2
3DH:
  DH1 = ECDH(sender_session_priv, recv_IK)
  DH2 = ECDH(sender_master_priv,  recv_SPK)
  DH3 = ECDH(sender_session_priv, recv_SPK)
  shared = HKDF-SHA256(DH1 || DH2 || DH3, salt, info="AUN-V2-3DH")
  wrap_key = shared[:32]
"""
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.dh_path import compute_3dh_wrap
from aun_core.v2.crypto.ecdh import ecdh_compute_shared
from aun_core.v2.crypto.hkdf import hkdf_sha256
from aun_core.v2.crypto.aead import aes_gcm_encrypt, aes_gcm_decrypt

# ── 固定测试密钥 ──
from .fixtures import (
    ALICE_PRIV, ALICE_PUB_DER,   # recv_IK
    BOB_PRIV, BOB_PUB_DER,       # recv_SPK
    CAROL_PUB_DER,                # 另一个 SPK（用于差异测试）
    SENDER_SESSION_PRIV,          # sender_session
)

# 用 ALICE_PRIV 同时模拟 sender_master_priv（仅测试用）
SENDER_MASTER_PRIV = ALICE_PRIV

# 加密参数
MASTER_KEY = b"\xab" * 32
WRAP_NONCE = b"\xcd" * 12
SALT = b"\xef" * 16  # recipients_digest 前 16 字节


class TestCompute3DH:
    """3DH 共享秘密推导"""

    def test_3dh_produces_32_byte_wrap_key(self):
        """3DH → HKDF → 32 字节 wrap_key"""
        result = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
            salt=SALT,
        )
        assert len(result["wrap_key"]) == 32

    def test_3dh_deterministic(self):
        """同输入同输出"""
        r1 = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
            salt=SALT,
        )
        r2 = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
            salt=SALT,
        )
        assert r1["wrap_key"] == r2["wrap_key"]

    def test_3dh_uses_correct_info(self):
        """info = 'AUN-V2-3DH'"""
        dh1 = ecdh_compute_shared(SENDER_SESSION_PRIV, ALICE_PUB_DER)
        dh2 = ecdh_compute_shared(SENDER_MASTER_PRIV, BOB_PUB_DER)
        dh3 = ecdh_compute_shared(SENDER_SESSION_PRIV, BOB_PUB_DER)
        expected = hkdf_sha256(
            ikm=dh1 + dh2 + dh3,
            salt=SALT,
            info=b"AUN-V2-3DH",
            length=32,
        )
        result = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
            salt=SALT,
        )
        assert result["wrap_key"] == expected

    def test_3dh_different_spk_different_result(self):
        """不同 SPK → 不同 wrap_key"""
        r1 = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
            salt=SALT,
        )
        r2 = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=CAROL_PUB_DER,
            salt=SALT,
        )
        assert r1["wrap_key"] != r2["wrap_key"]


class TestWrapMasterKey3DH:
    """3DH 路径完整 wrap master_key"""

    def test_wrap_and_unwrap(self):
        """发送方 wrap → 接收方 unwrap = 原 master_key"""
        result = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
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

    def test_wrong_wrap_key_fails(self):
        """错误 wrap_key → 解密失败"""
        result = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
            salt=SALT,
        )
        wrap_key = result["wrap_key"]
        ct, tag = aes_gcm_encrypt(key=wrap_key, nonce=WRAP_NONCE, plaintext=MASTER_KEY, aad=b"")
        wrapped_key = ct + tag

        wrong_key = b"\x00" * 32
        with pytest.raises(Exception):
            aes_gcm_decrypt(
                key=wrong_key, nonce=WRAP_NONCE,
                ciphertext=wrapped_key[:32], tag=wrapped_key[32:], aad=b""
            )


class TestReceiverSide3DH:
    """接收方 3DH 解密路径——验证对称性"""

    def test_receiver_computes_same_wrap_key(self):
        """
        发送方: ECDH(session_priv, recv_IK) + ECDH(master_priv, recv_SPK) + ECDH(session_priv, recv_SPK)
        接收方: ECDH(recv_IK_priv, session_pub) + ECDH(recv_SPK_priv, master_pub) + ECDH(recv_SPK_priv, session_pub)
        两者 wrap_key 必须相同
        """
        from aun_core.v2.crypto.ecdh import private_to_public_der

        sender_session_pub = private_to_public_der(SENDER_SESSION_PRIV)
        sender_master_pub = private_to_public_der(SENDER_MASTER_PRIV)

        # 发送方侧
        sender_result = compute_3dh_wrap(
            sender_session_priv=SENDER_SESSION_PRIV,
            sender_master_priv=SENDER_MASTER_PRIV,
            recv_ik_pub=ALICE_PUB_DER,
            recv_spk_pub=BOB_PUB_DER,
            salt=SALT,
        )

        # 接收方侧（手动计算）
        recv_ik_priv = ALICE_PRIV   # 接收方 IK 私钥
        recv_spk_priv = BOB_PRIV    # 接收方 SPK 私钥

        dh1_recv = ecdh_compute_shared(recv_ik_priv, sender_session_pub)
        dh2_recv = ecdh_compute_shared(recv_spk_priv, sender_master_pub)
        dh3_recv = ecdh_compute_shared(recv_spk_priv, sender_session_pub)

        recv_wrap_key = hkdf_sha256(
            ikm=dh1_recv + dh2_recv + dh3_recv,
            salt=SALT,
            info=b"AUN-V2-3DH",
            length=32,
        )

        assert sender_result["wrap_key"] == recv_wrap_key
