"""
AUN E2EE V2: P2P 加密引擎

构造完整的 e2ee.p2p_encrypted envelope。
纯计算，无 IO。

规范引用: §4 / §5
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
from ..crypto.ecdh import generate_p256_keypair, private_to_public_der
from ..crypto.ecdsa import ecdsa_sign_raw
from ..crypto.aead import aes_gcm_encrypt
from ..crypto.dh_path import compute_3dh_wrap, compute_1dh_wrap
from ..crypto.recipients import sort_recipients, compute_recipients_digest

_METADATA_KEY_DOMAIN = b"aun-envelope-metadata-key-v1"
_PROTECTED_HEADERS_DOMAIN = b"aun-protected-headers-v1"
_PROTECTED_CONTEXT_DOMAIN = b"aun-protected-context-v1"


def _metadata_auth_tag(key: bytes, domain: bytes, body: dict[str, Any]) -> bytes:
    metadata_key = _hmac.digest(key, _METADATA_KEY_DOMAIN, "sha256")
    sign_input = domain + b"\0" + canonical_json(body)
    return _hmac.digest(metadata_key, sign_input, "sha256")


def _with_metadata_auth(metadata: dict[str, Any], *, key: bytes, domain: bytes) -> dict[str, Any]:
    body = {k: v for k, v in metadata.items() if k != "_auth"}
    if not body:
        return {}
    tag = _metadata_auth_tag(key, domain, body)
    result = dict(body)
    result["_auth"] = {
        "alg": "HMAC-SHA256",
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    return result


def _normalize_headers(headers: dict[str, Any], payload_type: str | None = None) -> dict[str, str]:
    """与 V1 对齐：所有 value 转 string，自动注入 payload_type。"""
    normalized: dict[str, str] = {}
    for k, v in headers.items():
        if k == "_auth":
            continue
        sv = str(v) if v is not None else ""
        if sv:
            normalized[k] = sv
    if payload_type:
        normalized.setdefault("payload_type", payload_type)
    return normalized


def encrypt_p2p_message(
    sender: dict[str, Any],
    target_set: dict[str, Any],
    payload: dict[str, Any],
    *,
    message_id: str | None = None,
    timestamp: int | None = None,
    protected_headers: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造完整的 V2 P2P 加密 envelope。

    Args:
        sender: 发送方身份
            - aid: str
            - device_id: str
            - ik_priv: bytes (32B AID 主私钥 scalar)
            - ik_pub_der: bytes (DER 公钥)
        target_set: 接收方集合
            - targets: list[dict] 每个含 aid/device_id/role/key_source/ik_pk_der/spk_pk_der/spk_id
            - audit_recipients: list[dict] 监管方（同结构）
        payload: 业务 payload（将被加密）
        message_id: 可选，不传则自动生成 m-{uuid4}
        timestamp: 可选，不传则用当前时间（毫秒）

    Returns:
        完整 envelope dict（可直接 JSON 序列化发送）
    """
    # 1. 生成 master_key + msg_nonce
    master_key = os.urandom(32)
    msg_nonce = os.urandom(12)

    # 2. 构造 AAD
    if message_id is None:
        message_id = f"m-{uuid.uuid4().hex}"
    if timestamp is None:
        timestamp = int(time.time() * 1000)

    # 确定 to（第一个非 audit 的 aid）
    peer_aid = ""
    for t in target_set["targets"]:
        if t.get("role") != "audit":
            peer_aid = t["aid"]
            break

    # 计算 wrap_protocol_set（防服务端篡改 key_source 引导接收方走 1DH）
    all_targets_for_proto = target_set["targets"] + target_set.get("audit_recipients", [])
    protocols: set[str] = set()
    for t in all_targets_for_proto:
        if t.get("spk_pk_der") and t.get("key_source") in ("peer_device_prekey", "group_device_prekey"):
            protocols.add("3DH")
        else:
            protocols.add("1DH")
    wrap_protocol_str = "+".join(sorted(protocols)) if protocols else "1DH"

    aad = {
        "from": sender["aid"],
        "from_device": sender["device_id"],
        "to": peer_aid,
        "message_id": message_id,
        "timestamp": timestamp,
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "wrap_protocol": wrap_protocol_str,
    }

    # 3. 加密正文
    plaintext = canonical_json(payload)
    aad_bytes = canonical_json(aad)
    ciphertext, tag = aes_gcm_encrypt(
        key=master_key, nonce=msg_nonce, plaintext=plaintext, aad=aad_bytes
    )

    # 4. 生成共享 sender_session keypair
    sender_session_priv, sender_session_pub_der = generate_p256_keypair()

    # 计算 wrap salt（切断 recipients_digest 循环依赖）
    # salt = SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
    suite_str = "P256_HKDF_SHA256_AES_256_GCM"
    wrap_salt = hashlib.sha256(
        aad_bytes + sender_session_pub_der + suite_str.encode("utf-8")
    ).digest()[:16]

    # 5. 为每个 recipient wrap master_key
    all_targets = target_set["targets"] + target_set.get("audit_recipients", [])
    recipients_rows = []

    for target in all_targets:
        row = _wrap_for_recipient(
            target=target,
            master_key=master_key,
            sender_session_priv=sender_session_priv,
            sender_master_priv=sender["ik_priv"],
            wrap_salt=wrap_salt,
        )
        recipients_rows.append(row)

    # 6. 排序 recipients
    recipients_rows = sort_recipients(recipients_rows)

    # 7. 计算 recipients_digest
    recipients_digest = compute_recipients_digest(recipients_rows)

    # 8. sender_signature
    digest_bytes = bytes.fromhex(recipients_digest)
    sign_input = ciphertext + tag + aad_bytes + digest_bytes
    sender_signature = ecdsa_sign_raw(sender["ik_priv"], sign_input)

    # 9. 计算 sender_cert_fingerprint
    cert_fp = "sha256:" + hashlib.sha256(sender["ik_pub_der"]).hexdigest()[:16]

    # 10. 组装 envelope
    envelope = {
        "type": "e2ee.p2p_encrypted",
        "version": "v2",
        "suite": "P256_HKDF_SHA256_AES_256_GCM",
        "msg_type": "original",
        "t_send": timestamp,
        "t_supplement": None,
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
        headers = _normalize_headers(protected_headers, payload_type=payload.get("type") if isinstance(payload, dict) else None)
        if headers:
            envelope["protected_headers"] = _with_metadata_auth(
                headers, key=master_key, domain=_PROTECTED_HEADERS_DOMAIN,
            )
    elif isinstance(payload, dict) and payload.get("type"):
        headers = _normalize_headers({}, payload_type=payload.get("type"))
        if headers:
            envelope["protected_headers"] = _with_metadata_auth(
                headers, key=master_key, domain=_PROTECTED_HEADERS_DOMAIN,
            )
    if isinstance(context, dict) and context:
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
    """为单个 recipient 生成 wrap 行。

    Returns:
        [aid, device_id, role, key_source, fp, spk_id, wrap_nonce_b64, wrapped_key_b64]
    """
    aid = target["aid"]
    device_id = target.get("device_id", "")
    role = target.get("role", "peer")
    key_source = target.get("key_source", "aid_master")
    ik_pk_der = target["ik_pk_der"]
    spk_pk_der = target.get("spk_pk_der")
    spk_id = target.get("spk_id", "")

    # 计算 fp（IK 公钥指纹）
    fp = "sha256:" + hashlib.sha256(ik_pk_der).hexdigest()[:16]

    # wrap salt: SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
    # 切断 recipients_digest 循环依赖；绑定到 sender_session_pk + AAD 防跨消息重放
    salt = wrap_salt

    # 选择 DH 路径
    wrap_nonce = os.urandom(12)

    if spk_pk_der and key_source in ("peer_device_prekey", "group_device_prekey"):
        # 3DH
        result = compute_3dh_wrap(
            sender_session_priv=sender_session_priv,
            sender_master_priv=sender_master_priv,
            recv_ik_pub=ik_pk_der,
            recv_spk_pub=spk_pk_der,
            salt=salt,
        )
    else:
        # 1DH
        result = compute_1dh_wrap(
            sender_session_priv=sender_session_priv,
            recv_ik_pub=ik_pk_der,
            salt=salt,
        )

    wrap_key = result["wrap_key"]

    # AES-GCM wrap master_key
    ct, wrap_tag = aes_gcm_encrypt(key=wrap_key, nonce=wrap_nonce, plaintext=master_key, aad=b"")
    wrapped_key = ct + wrap_tag  # 48 bytes

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
