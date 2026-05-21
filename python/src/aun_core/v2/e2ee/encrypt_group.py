"""
AUN E2EE V2: Group 加密引擎

构造完整的 e2ee.group_encrypted envelope。
纯计算，无 IO。与 P2P 引擎同构，差异在 AAD（含 group_id/epoch）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import os
import time
import uuid
from typing import Any

from ..crypto.canonical import canonical_json
from ..crypto.ecdh import generate_p256_keypair
from ..crypto.ecdsa import ecdsa_sign_raw
from ..crypto.aead import aes_gcm_encrypt
from ..crypto.dh_path import compute_3dh_wrap, compute_1dh_wrap
from ..crypto.recipients import sort_recipients, compute_recipients_digest


def encrypt_group_message(
    sender: dict[str, Any],
    group_id: str,
    epoch: int,
    targets: list[dict[str, Any]],
    payload: dict[str, Any],
    *,
    message_id: str | None = None,
    timestamp: int | None = None,
    state_commitment: dict[str, Any] | None = None,
    protected_headers: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造完整的 V2 Group 加密 envelope。

    Args:
        sender: 发送方身份
            - aid: str
            - device_id: str
            - ik_priv: bytes (32B AID 主私钥 scalar)
            - ik_pub_der: bytes (DER 公钥)
        group_id: 群 ID
        epoch: 当前加密 epoch
        targets: 所有接收设备列表
            每个含 aid/device_id/role/key_source/ik_pk_der/spk_pk_der/spk_id
        payload: 业务 payload（将被加密）
        message_id: 可选，不传则自动生成 m-{uuid4}
        timestamp: 可选，不传则用当前时间（毫秒）
        state_commitment: 可选，绑定到 AAD 的 state 信息
            { "state_version": int, "state_hash": str, "state_chain": str }
            缺省 → 写入 sv=0 的占位（兼容未启用 state 的群）

    Returns:
        完整 envelope dict（可直接 JSON 序列化发送）
    """
    master_key = os.urandom(32)
    msg_nonce = os.urandom(12)

    if message_id is None:
        message_id = f"m-{uuid.uuid4().hex}"
    if timestamp is None:
        timestamp = int(time.time() * 1000)

    # 计算 wrap_protocol_set：根据 targets 的 key_source 推断
    protocols: set[str] = set()
    for t in targets:
        if t.get("spk_pk_der") and t.get("key_source") in ("peer_device_prekey", "group_device_prekey"):
            protocols.add("3DH")
        else:
            protocols.add("1DH")
    wrap_protocol_str = "+".join(sorted(protocols)) if protocols else "1DH"

    sc = state_commitment or {}
    state_commitment_aad = {
        "state_version": int(sc.get("state_version", 0) or 0),
        "state_hash": str(sc.get("state_hash", "") or ""),
        "state_chain": str(sc.get("state_chain", "") or ""),
    }

    aad = {
        "from": sender["aid"],
        "from_device": sender["device_id"],
        "group_id": group_id,
        "epoch": epoch,
        "message_id": message_id,
        "timestamp": timestamp,
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "wrap_protocol": wrap_protocol_str,
        "state_commitment": state_commitment_aad,
    }

    plaintext = canonical_json(payload)
    aad_bytes = canonical_json(aad)
    ciphertext, tag = aes_gcm_encrypt(
        key=master_key, nonce=msg_nonce, plaintext=plaintext, aad=aad_bytes
    )

    sender_session_priv, sender_session_pub_der = generate_p256_keypair()

    # wrap salt: SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
    suite_str = "P256_HKDF_SHA256_AES_256_GCM"
    wrap_salt = hashlib.sha256(
        aad_bytes + sender_session_pub_der + suite_str.encode("utf-8")
    ).digest()[:16]

    recipients_rows = []
    for target in targets:
        row = _wrap_for_recipient(
            target=target,
            master_key=master_key,
            sender_session_priv=sender_session_priv,
            sender_master_priv=sender["ik_priv"],
            wrap_salt=wrap_salt,
        )
        recipients_rows.append(row)

    recipients_rows = sort_recipients(recipients_rows)
    recipients_digest = compute_recipients_digest(recipients_rows)

    digest_bytes = bytes.fromhex(recipients_digest)
    sign_input = ciphertext + tag + aad_bytes + digest_bytes
    sender_signature = ecdsa_sign_raw(sender["ik_priv"], sign_input)

    cert_fp = "sha256:" + hashlib.sha256(sender["ik_pub_der"]).hexdigest()[:16]

    envelope = {
        "type": "e2ee.group_encrypted",
        "version": "v2",
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "msg_type": "original",
        "group_id": group_id,
        "epoch": epoch,
        "t_send": timestamp,
        "t_server": None,
        "nonce": base64.b64encode(msg_nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "sender_signature": base64.b64encode(sender_signature).decode("ascii"),
        "sender_cert_fingerprint": cert_fp,
        "sender_session_pk": base64.b64encode(sender_session_pub_der).decode("ascii"),
        "recipients_digest": recipients_digest,
        "recipients": recipients_rows,
        "aad": aad,
    }

    # protected_headers / context：HMAC 签名（与 V1 对齐），不进 AAD
    if isinstance(protected_headers, dict) and protected_headers:
        from .encrypt_p2p import _with_metadata_auth, _normalize_headers, _PROTECTED_HEADERS_DOMAIN
        headers = _normalize_headers(protected_headers, payload_type=payload.get("type") if isinstance(payload, dict) else None)
        if headers:
            envelope["protected_headers"] = _with_metadata_auth(
                headers, key=master_key, domain=_PROTECTED_HEADERS_DOMAIN,
            )
    elif isinstance(payload, dict) and payload.get("type"):
        from .encrypt_p2p import _with_metadata_auth, _normalize_headers, _PROTECTED_HEADERS_DOMAIN
        headers = _normalize_headers({}, payload_type=payload.get("type"))
        if headers:
            envelope["protected_headers"] = _with_metadata_auth(
                headers, key=master_key, domain=_PROTECTED_HEADERS_DOMAIN,
            )
    if isinstance(context, dict) and context:
        from .encrypt_p2p import _with_metadata_auth, _PROTECTED_CONTEXT_DOMAIN
        ctx_body = {k: v for k, v in context.items() if k != "_auth"}
        if ctx_body:
            envelope["context"] = _with_metadata_auth(
                ctx_body, key=master_key, domain=_PROTECTED_CONTEXT_DOMAIN,
            )

    return envelope


def _wrap_for_recipient(
    target: dict[str, Any],
    master_key: bytes,
    sender_session_priv: bytes,
    sender_master_priv: bytes,
    wrap_salt: bytes,
) -> list:
    """为单个 recipient 生成 wrap 行（与 P2P 同构）。"""
    aid = target["aid"]
    device_id = target.get("device_id", "")
    role = target.get("role", "member")
    key_source = target.get("key_source", "aid_master")
    ik_pk_der = target["ik_pk_der"]
    spk_pk_der = target.get("spk_pk_der")
    spk_id = target.get("spk_id", "")

    fp = "sha256:" + hashlib.sha256(ik_pk_der).hexdigest()[:16]

    salt = wrap_salt
    wrap_nonce = os.urandom(12)

    if spk_pk_der and key_source in ("peer_device_prekey", "group_device_prekey"):
        result = compute_3dh_wrap(
            sender_session_priv=sender_session_priv,
            sender_master_priv=sender_master_priv,
            recv_ik_pub=ik_pk_der,
            recv_spk_pub=spk_pk_der,
            salt=salt,
        )
    else:
        result = compute_1dh_wrap(
            sender_session_priv=sender_session_priv,
            recv_ik_pub=ik_pk_der,
            salt=salt,
        )

    wrap_key = result["wrap_key"]
    ct, wrap_tag = aes_gcm_encrypt(key=wrap_key, nonce=wrap_nonce, plaintext=master_key, aad=b"")
    wrapped_key = ct + wrap_tag

    return [
        aid,
        device_id,
        role,
        key_source,
        fp,
        spk_id,
        base64.b64encode(wrap_nonce).decode("ascii"),
        base64.b64encode(wrapped_key).decode("ascii"),
    ]
