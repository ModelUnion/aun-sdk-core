"""
AUN E2EE V2: 统一解密引擎

支持 P2P 和 Group 消息解密（按 envelope.type 分流）。
纯计算，无 IO。

规范引用: §4.6 / §5.5
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from ..crypto.canonical import canonical_json
from ..crypto.ecdsa import ecdsa_verify_raw
from ..crypto.ecdh import ecdh_compute_shared
from ..crypto.hkdf import hkdf_sha256
from ..crypto.aead import aes_gcm_decrypt


def decrypt_message(
    envelope: dict[str, Any],
    self_aid: str,
    self_device_id: str,
    self_ik_priv: bytes,
    self_spk_priv: bytes | None,
    sender_pub_der: bytes,
) -> dict[str, Any] | None:
    """解密 V2 加密消息（P2P 或 Group）。

    Args:
        envelope: 完整 envelope dict
        self_aid: 接收方 AID
        self_device_id: 接收方 device_id
        self_ik_priv: 接收方 IK 私钥（32B scalar）
        self_spk_priv: 接收方 SPK 私钥（32B scalar）；None 表示无 SPK（1DH）
        sender_pub_der: 发送方 AID 主公钥（DER），用于验签

    Returns:
        解密后的 payload dict；None 表示找不到自己的 recipient 行
    Raises:
        Exception: 验签失败 / 解密失败 / digest 不匹配
    """
    # 1. 验 sender_signature
    _verify_sender_signature(envelope, sender_pub_der)

    # 2. 判断 envelope 格式：完整（recipients 数组）或 per-device（recipient 单数 dict）
    if "recipients" in envelope:
        # 完整 envelope：验 digest + 查找自己的行
        _verify_recipients_digest(envelope)
        row = _find_my_row(envelope["recipients"], self_aid, self_device_id)
        if row is None:
            return None
    elif "recipient" in envelope:
        # per-device envelope（服务端拆分后存储）：用 Merkle proof 验证 wrap 在签名集中
        r = envelope["recipient"]
        row = [r["aid"], r["device_id"], r["role"], r.get("key_source", ""),
               r.get("fp", ""), r.get("spk_id", ""), r.get("wrap_nonce", ""),
               r.get("wrapped_key", "")]
        # 若服务端提供了 Merkle proof，则验证；缺失则记录但不阻止（向后兼容）
        proof = envelope.get("merkle_proof")
        expected_root = envelope.get("recipients_digest", "")
        if proof is not None and expected_root:
            from ..crypto.recipients import compute_leaf_hash, verify_merkle_proof
            leaf = compute_leaf_hash(row)
            if not verify_merkle_proof(leaf, proof, expected_root):
                # 服务端篡改/替换 wrap，拒绝
                return None
    else:
        return None

    # 4. 解 wrap_key（salt 同 encrypt 侧推导）
    sender_session_pk_der = base64.b64decode(envelope["sender_session_pk"])
    aad_bytes_for_salt = canonical_json(envelope["aad"])
    suite_str = envelope.get("suite", "P256_HKDF_SHA256_AES_256_GCM")
    wrap_salt = hashlib.sha256(
        aad_bytes_for_salt + sender_session_pk_der + suite_str.encode("utf-8")
    ).digest()[:16]
    wrap_key = _compute_wrap_key(row, self_ik_priv, self_spk_priv, sender_session_pk_der, sender_pub_der, wrap_salt)

    # 5. 解 master_key
    wrap_nonce = base64.b64decode(row[6])
    wrapped_key = base64.b64decode(row[7])
    # wrapped_key = ciphertext(32B) + tag(16B) = 48B
    master_key = aes_gcm_decrypt(
        key=wrap_key,
        nonce=wrap_nonce,
        ciphertext=wrapped_key[:32],
        tag=wrapped_key[32:],
        aad=b"",
    )

    # 6. 解密正文
    msg_nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    tag = base64.b64decode(envelope["tag"])
    aad_bytes = canonical_json(envelope["aad"])

    plaintext = aes_gcm_decrypt(
        key=master_key,
        nonce=msg_nonce,
        ciphertext=ciphertext,
        tag=tag,
        aad=aad_bytes,
    )

    # 7. 解析 payload
    import json
    return json.loads(plaintext)


def _verify_sender_signature(envelope: dict, sender_pub_der: bytes):
    """验证 sender_signature。"""
    sig = base64.b64decode(envelope["sender_signature"])
    ct = base64.b64decode(envelope["ciphertext"])
    tag = base64.b64decode(envelope["tag"])
    aad_bytes = canonical_json(envelope["aad"])
    digest_bytes = bytes.fromhex(envelope["recipients_digest"])

    sign_input = ct + tag + aad_bytes + digest_bytes
    if not ecdsa_verify_raw(sender_pub_der, sig, sign_input):
        raise ValueError("sender_signature verification failed")


def _verify_recipients_digest(envelope: dict):
    """验证 recipients_digest（Merkle root）与 recipients 一致。"""
    from ..crypto.recipients import compute_merkle_root
    expected = compute_merkle_root(envelope["recipients"])
    if expected != envelope["recipients_digest"]:
        raise ValueError("recipients_digest mismatch")


def _find_my_row(recipients: list, self_aid: str, self_device_id: str) -> list | None:
    """在 recipients 中找到自己的行。"""
    for row in recipients:
        if row[0] == self_aid and row[1] == self_device_id:
            return row
    return None


def _compute_wrap_key(
    row: list,
    self_ik_priv: bytes,
    self_spk_priv: bytes | None,
    sender_session_pk_der: bytes,
    sender_master_pk_der: bytes,
    salt: bytes,
) -> bytes:
    """根据 row 的 spk_id 分流 3DH / 1DH，计算 wrap_key。"""
    spk_id = row[5]  # 第 6 字段
    # salt 由调用方传入（SHA256(canonical_aad || sender_session_pk || suite)[:16]）

    if spk_id and self_spk_priv is not None:
        # 3DH 接收方路径
        dh1 = ecdh_compute_shared(self_ik_priv, sender_session_pk_der)
        dh2 = ecdh_compute_shared(self_spk_priv, sender_master_pk_der)
        dh3 = ecdh_compute_shared(self_spk_priv, sender_session_pk_der)
        ikm = dh1 + dh2 + dh3
        wrap_key = hkdf_sha256(ikm=ikm, salt=salt, info=b"AUN-V2-3DH", length=32)
    else:
        # 1DH 接收方路径
        dh1 = ecdh_compute_shared(self_ik_priv, sender_session_pk_der)
        wrap_key = hkdf_sha256(ikm=dh1, salt=salt, info=b"AUN-V2-1DH", length=32)

    return wrap_key
