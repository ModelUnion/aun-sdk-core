"""PY-001 / PY-002 / PY-003 / PY-005 / PY-006 修复验证测试。

按 TDD RED→GREEN 流程，每个 ISSUE 一个测试类。
"""
from __future__ import annotations

import asyncio
import base64
import secrets
import time
import uuid
from collections import OrderedDict
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aun_core import AUNClient
from aun_core.client import _CachedPeerCert, _PEER_CERT_CACHE_TTL
from aun_core.e2ee import (
    build_key_distribution,
    build_membership_manifest,
    compute_epoch_chain,
    sign_membership_manifest,
    compute_membership_commitment,
    encrypt_group_message,
    generate_group_secret,
    load_group_secret,
    store_group_secret,
)
from aun_core.seq_tracker import SeqTracker


_AID_ALICE = "alice.agentid.pub"
_AID_BOB = "bob.agentid.pub"
_AID_CHARLIE = "charlie.agentid.pub"
_GRP = "grp_test_batch2"
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


# ── PY-001: 解密失败后仍应 auto-ack ──────────────────────────


class TestPY006PushedSeqsLimit:
    """PY-006: pushed_seqs 集合应有硬上限，超出时清理最旧条目。"""

    def test_pushed_seqs_bounded(self, tmp_path):
        """pushed_seqs 超过硬上限时应自动清理。"""
        client = _make_client(tmp_path)
        ns = "group:test_group"

        # 塞入大量 seq
        pushed = set()
        for i in range(60000):
            pushed.add(i)
        client._pushed_seqs[ns] = pushed

        # 触发清理（通过 _prune_pushed_seqs 或直接检查限制）
        client._enforce_pushed_seqs_limit(ns)

        assert len(client._pushed_seqs.get(ns, set())) <= 50000, \
            f"pushed_seqs 应被限制在 50000 以内，实际 {len(client._pushed_seqs.get(ns, set()))}"

    def test_pushed_seqs_preserves_recent(self, tmp_path):
        """清理时应保留最近（最大）的条目。"""
        client = _make_client(tmp_path)
        ns = "group:test_group"

        # 塞入超限数据
        pushed = set(range(60000))
        client._pushed_seqs[ns] = pushed

        client._enforce_pushed_seqs_limit(ns)

        remaining = client._pushed_seqs.get(ns, set())
        # 最大的 seq 应该被保留
        assert 59999 in remaining, "应保留最大的 seq"
        # 最小的 seq 应该被清理
        assert 0 not in remaining, "应清理最旧的 seq"


# ── SeqTracker.remove_namespace ──────────────────────────────


class TestSeqTrackerRemoveNamespace:
    """SeqTracker 应支持 remove_namespace 方法。"""

    def test_remove_namespace(self):
        tracker = SeqTracker()
        tracker.on_message_seq("group:g1", 1)
        tracker.on_message_seq("group:g1", 2)
        tracker.on_message_seq("group:g2", 1)

        assert tracker.get_contiguous_seq("group:g1") == 2
        tracker.remove_namespace("group:g1")
        assert tracker.get_contiguous_seq("group:g1") == 0, \
            "remove_namespace 后 contiguous_seq 应为 0"
        assert tracker.get_contiguous_seq("group:g2") == 1, \
            "不应影响其他 namespace"

    def test_remove_nonexistent_namespace(self):
        """移除不存在的 namespace 不应报错。"""
        tracker = SeqTracker()
        tracker.remove_namespace("nonexistent")  # 不应抛异常
