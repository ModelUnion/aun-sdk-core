"""PY-002(pushed_seqs) / PY-005(epoch wait) 修复验证测试。

每个 ISSUE 一个测试类，覆盖修复逻辑的关键路径。
PY-003 (seed TOCTOU) 和 PY-004 (SQLCipher 读操作重试) 测试已随 sqlcipher_db 模块移除。
"""
from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aun_core import AUNClient
from aun_core.client import _CachedPeerCert, _PEER_CERT_CACHE_TTL, _PUSHED_SEQS_LIMIT
from aun_core.e2ee import (
    compute_membership_commitment,
    encrypt_group_message,
    generate_group_secret,
    store_group_secret,
)
from aun_core.errors import StateError


# ── 辅助函数 ──────────────────────────────────────────────

_AID_ALICE = "alice.agentid.pub"
_AID_BOB = "bob.agentid.pub"
_GRP = "grp_test_batch3"
_MEMBERS = [_AID_ALICE, _AID_BOB]


def _make_signing_identity(cn: str):
    """生成签名密钥对 + 证书 PEM（测试用）。"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import datetime, timedelta, timezone

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pk_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return pk_pem, cert_pem


_SIGNING_IDENTITIES: dict[str, tuple[str, bytes]] = {}


def _get_signing_identity(aid: str):
    if aid not in _SIGNING_IDENTITIES:
        _SIGNING_IDENTITIES[aid] = _make_signing_identity(aid)
    return _SIGNING_IDENTITIES[aid]


def _make_client(tmp_path, aid=_AID_BOB):
    """创建 mock 好的 AUNClient 用于测试。"""
    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    client._aid = aid
    pk_pem, cert_pem = _get_signing_identity(aid)
    client._identity = {"aid": aid, "private_key_pem": pk_pem, "cert": cert_pem.decode("utf-8")}
    client._state = "connected"
    client._device_id = "test-device"
    now = time.time()
    for peer_aid in _MEMBERS:
        if peer_aid == aid:
            continue
        _, peer_cert = _get_signing_identity(peer_aid)
        client._cert_cache[peer_aid] = _CachedPeerCert(
            cert_bytes=peer_cert, validated_at=now, refresh_after=now + _PEER_CERT_CACHE_TTL,
        )
        cert_str = peer_cert.decode("utf-8") if isinstance(peer_cert, bytes) else peer_cert
        client._keystore.save_cert(peer_aid, cert_str)
    return client


def _store_secret(client, group_id=_GRP, epoch=1, gs=None, members=None):
    gs = gs or secrets.token_bytes(32)
    members = members or _MEMBERS
    commitment = compute_membership_commitment(members, epoch, group_id, gs)
    store_group_secret(client._keystore, client._aid, group_id, epoch, gs, commitment, members)
    return gs


def _make_encrypted_group_msg(gs, group_id=_GRP, from_aid=_AID_ALICE, seq=1, epoch=1):
    """构建一条加密群消息。"""
    pk_pem, _ = _get_signing_identity(from_aid)
    msg_id = f"gm-{uuid.uuid4()}"
    ts = 1710504000000 + seq
    envelope = encrypt_group_message(
        group_id=group_id, epoch=epoch, group_secret=gs,
        payload={"type": "text", "text": f"消息-{seq}"}, from_aid=from_aid,
        message_id=msg_id, timestamp=ts,
        sender_private_key_pem=pk_pem,
    )
    return {
        "group_id": group_id,
        "from": from_aid,
        "sender_aid": from_aid,
        "message_id": msg_id,
        "timestamp": ts,
        "seq": seq,
        "payload": envelope,
        "encrypted": True,
    }


# ── PY-002: P2P 推送路径 pushed_seqs 应调用 _enforce_pushed_seqs_limit ──


