"""
AUN E2EE V2: DH 路径（3DH / 1DH）

规范引用: §3.2 / §5.2
3DH:
  DH1 = ECDH(sender_session_priv, recv_IK)
  DH2 = ECDH(sender_master_priv,  recv_SPK)
  DH3 = ECDH(sender_session_priv, recv_SPK)
  shared = HKDF-SHA256(DH1 || DH2 || DH3, salt, info="AUN-V2-3DH")
  wrap_key = shared[:32]

1DH:
  DH1 = ECDH(sender_session_priv, recv_IK)
  shared = HKDF-SHA256(DH1, salt, info="AUN-V2-1DH")
  wrap_key = shared[:32]
"""
from __future__ import annotations

from .ecdh import ecdh_compute_shared
from .hkdf import hkdf_sha256


INFO_3DH = b"AUN-V2-3DH"
INFO_1DH = b"AUN-V2-1DH"
WRAP_KEY_LENGTH = 32


def compute_3dh_wrap(
    sender_session_priv: bytes,
    sender_master_priv: bytes,
    recv_ik_pub: bytes,
    recv_spk_pub: bytes,
    salt: bytes,
) -> dict:
    """计算 3DH 路径的 wrap_key。

    Args:
        sender_session_priv: 发送方一次性会话私钥（32 字节）
        sender_master_priv: 发送方 AID 主私钥（32 字节）
        recv_ik_pub: 接收方 IK 公钥（DER）
        recv_spk_pub: 接收 SPK 公钥（DER）
        salt: recipients_digest 前 16 字节

    Returns:
        {"wrap_key": bytes(32)}
    """
    dh1 = ecdh_compute_shared(sender_session_priv, recv_ik_pub)
    dh2 = ecdh_compute_shared(sender_master_priv, recv_spk_pub)
    dh3 = ecdh_compute_shared(sender_session_priv, recv_spk_pub)

    ikm = dh1 + dh2 + dh3  # 96 字节
    wrap_key = hkdf_sha256(ikm=ikm, salt=salt, info=INFO_3DH, length=WRAP_KEY_LENGTH)

    return {"wrap_key": wrap_key}


def compute_1dh_wrap(
    sender_session_priv: bytes,
    recv_ik_pub: bytes,
    salt: bytes,
) -> dict:
    """计算 1DH 路径的 wrap_key（SPK 缺失时的降级路径）。

    Args:
        sender_session_priv: 发送方一次性会话私钥（32 字节）
        recv_ik_pub: 接收方 IK 公钥（DER）——可以是 device IK 或 AID 主公钥
        salt: recipients_digest 前 16 字节

    Returns:
        {"wrap_key": bytes(32)}
    """
    dh1 = ecdh_compute_shared(sender_session_priv, recv_ik_pub)

    wrap_key = hkdf_sha256(ikm=dh1, salt=salt, info=INFO_1DH, length=WRAP_KEY_LENGTH)

    return {"wrap_key": wrap_key}
