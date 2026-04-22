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
from aun_core.client import _CachedPeerCert
from aun_core.e2ee import (
    build_key_distribution,
    build_membership_manifest,
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
            cert_bytes=peer_cert, validated_at=now, refresh_after=now + 600,
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
        payload={"text": f"消息-{seq}"}, from_aid=from_aid,
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


# ── PY-001: 解密失败后不应 auto-ack ──────────────────────────


class TestPY001DecryptFailNoAutoAck:
    """PY-001: 群消息解密失败后不应执行 auto-ack，消息应进入待重试队列。"""

    @pytest.mark.asyncio
    async def test_decrypt_fail_no_auto_ack(self, tmp_path):
        """解密失败时不应调用 group.ack_messages。"""
        client = _make_client(tmp_path)
        # 不存储 group secret → 解密会失败
        gs = secrets.token_bytes(32)
        msg = _make_encrypted_group_msg(gs, seq=1)

        ack_calls = []
        original_call = client._transport.call

        async def capture_call(method, params=None):
            if method == "group.ack_messages":
                ack_calls.append(params)
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=capture_call)

        await client._process_and_publish_group_message(msg)

        assert len(ack_calls) == 0, \
            f"解密失败时不应调用 auto-ack，但被调用了 {len(ack_calls)} 次"

    @pytest.mark.asyncio
    async def test_decrypt_fail_adds_to_pending_queue(self, tmp_path):
        """解密失败的消息应被添加到 _pending_decrypt_msgs 队列。"""
        client = _make_client(tmp_path)
        # 不存储 group secret → 解密会失败
        gs = secrets.token_bytes(32)
        msg = _make_encrypted_group_msg(gs, seq=1)

        client._transport = MagicMock()
        client._transport.call = AsyncMock(return_value={})

        await client._process_and_publish_group_message(msg)

        ns = f"group:{_GRP}"
        assert hasattr(client, "_pending_decrypt_msgs"), \
            "client 应有 _pending_decrypt_msgs 属性"
        pending = client._pending_decrypt_msgs.get(ns, [])
        assert len(pending) == 1, \
            f"应有 1 条待重试消息，实际有 {len(pending)}"

    @pytest.mark.asyncio
    async def test_decrypt_success_still_auto_acks(self, tmp_path):
        """解密成功时应正常 auto-ack。"""
        client = _make_client(tmp_path)
        gs = _store_secret(client)
        msg = _make_encrypted_group_msg(gs, seq=1)

        ack_calls = []

        async def capture_call(method, params=None):
            if method == "group.ack_messages":
                ack_calls.append(params)
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=capture_call)

        await client._process_and_publish_group_message(msg)

        assert len(ack_calls) == 1, \
            f"解密成功时应调用 auto-ack 1 次，实际 {len(ack_calls)} 次"

    @pytest.mark.asyncio
    async def test_pending_queue_has_size_limit(self, tmp_path):
        """待重试队列应有大小上限，防止无限增长。"""
        client = _make_client(tmp_path)
        gs = secrets.token_bytes(32)

        client._transport = MagicMock()
        client._transport.call = AsyncMock(return_value={})

        # 发送大量解密失败的消息
        for i in range(200):
            msg = _make_encrypted_group_msg(gs, seq=i + 1)
            await client._process_and_publish_group_message(msg)

        ns = f"group:{_GRP}"
        pending = client._pending_decrypt_msgs.get(ns, [])
        assert len(pending) <= 100, \
            f"待重试队列应有上限（<=100），实际有 {len(pending)}"


# ── PY-002: 密钥恢复后重试解密 ────────────────────────────────


class TestPY002KeyRecoveryRetry:
    """PY-002: 收到密钥恢复响应后，应重试之前解密失败的消息。"""

    @pytest.mark.asyncio
    async def test_key_recovery_triggers_retry(self, tmp_path):
        """密钥恢复成功后，应重试并清空待重试队列。"""
        client = _make_client(tmp_path)
        gs = generate_group_secret()

        client._transport = MagicMock()
        client._transport.call = AsyncMock(return_value={})

        # 先构建一条消息，但不存储密钥 → 解密失败
        msg = _make_encrypted_group_msg(gs, seq=1)
        await client._process_and_publish_group_message(msg)

        ns = f"group:{_GRP}"
        assert len(client._pending_decrypt_msgs.get(ns, [])) == 1, \
            "应有 1 条待重试消息"

        # 现在模拟收到密钥分发（存储密钥）
        commitment = compute_membership_commitment(_MEMBERS, 1, _GRP, gs)
        store_group_secret(client._keystore, client._aid, _GRP, 1, gs, commitment, _MEMBERS)

        # 触发重试
        published = []
        client._dispatcher.subscribe("group.message_created", lambda data: published.append(data))

        await client._retry_pending_decrypt_msgs(_GRP)

        # 应成功解密并发布
        assert len(published) >= 1, "密钥恢复后应重试解密并发布消息"
        # 待重试队列应被清空
        assert len(client._pending_decrypt_msgs.get(ns, [])) == 0, \
            "成功解密后应从待重试队列中移除"

    @pytest.mark.asyncio
    async def test_key_distribution_triggers_retry(self, tmp_path):
        """收到 e2ee.group_key_distribution 后，应触发重试。"""
        client = _make_client(tmp_path)
        gs = generate_group_secret()

        client._transport = MagicMock()
        client._transport.call = AsyncMock(return_value={})

        # 先构建解密失败的消息
        msg = _make_encrypted_group_msg(gs, seq=1)
        await client._process_and_publish_group_message(msg)

        ns = f"group:{_GRP}"
        assert len(client._pending_decrypt_msgs.get(ns, [])) == 1

        # 构建密钥分发消息
        pk_pem, _ = _get_signing_identity(_AID_ALICE)
        manifest = sign_membership_manifest(
            build_membership_manifest(_GRP, 1, None, _MEMBERS, initiator_aid=_AID_ALICE),
            pk_pem,
        )
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID_ALICE, manifest=manifest)
        key_msg = {"from": _AID_ALICE, "message_id": "key-dist-1", "payload": dist}

        # 处理密钥分发消息（应触发 _retry_pending_decrypt_msgs）
        handled = await client._try_handle_group_key_message(key_msg)
        assert handled is True

        # 给一点时间让后台任务运行
        await asyncio.sleep(0.05)

        # 待重试队列应被处理
        remaining = client._pending_decrypt_msgs.get(ns, [])
        assert len(remaining) == 0, \
            f"密钥分发后应触发重试，清空待重试队列，剩余 {len(remaining)}"


# ── PY-003: dissolve 后清理本地状态 ────────────────────────────


class TestPY003DissolveCleanup:
    """PY-003: 收到群组 dissolved 事件后，应清理本地 epoch key、seq_tracker 和 pushed_seqs。"""

    @pytest.mark.asyncio
    async def test_dissolved_clears_epoch_keys(self, tmp_path):
        """dissolve 后应清理 keystore 中该群组的 epoch key。"""
        client = _make_client(tmp_path)
        _store_secret(client)

        # 确认密钥已存储
        loaded = load_group_secret(client._keystore, client._aid, _GRP)
        assert loaded is not None, "密钥应已存储"

        # 模拟 dissolved 事件
        event = {"group_id": _GRP, "action": "dissolved"}
        await client._on_raw_group_changed(event)

        # 密钥应被清理
        loaded = load_group_secret(client._keystore, client._aid, _GRP)
        assert loaded is None, "dissolve 后应清理 epoch key"

    @pytest.mark.asyncio
    async def test_dissolved_clears_seq_tracker(self, tmp_path):
        """dissolve 后应清理 seq_tracker 中该群组的记录。"""
        client = _make_client(tmp_path)
        ns_msg = f"group:{_GRP}"
        ns_evt = f"group_event:{_GRP}"

        # 模拟有 seq 数据
        client._seq_tracker.on_message_seq(ns_msg, 1)
        client._seq_tracker.on_message_seq(ns_msg, 2)
        client._seq_tracker.on_message_seq(ns_evt, 1)
        assert client._seq_tracker.get_contiguous_seq(ns_msg) == 2
        assert client._seq_tracker.get_contiguous_seq(ns_evt) == 1

        # 模拟 dissolved 事件
        event = {"group_id": _GRP, "action": "dissolved"}
        await client._on_raw_group_changed(event)

        # seq_tracker 应被清理
        assert client._seq_tracker.get_contiguous_seq(ns_msg) == 0, \
            "dissolve 后应清理群消息 seq_tracker"
        assert client._seq_tracker.get_contiguous_seq(ns_evt) == 0, \
            "dissolve 后应清理群事件 seq_tracker"

    @pytest.mark.asyncio
    async def test_dissolved_clears_pushed_seqs(self, tmp_path):
        """dissolve 后应清理 pushed_seqs 中该群组的记录。"""
        client = _make_client(tmp_path)
        ns = f"group:{_GRP}"
        client._pushed_seqs[ns] = {1, 2, 3}

        event = {"group_id": _GRP, "action": "dissolved"}
        await client._on_raw_group_changed(event)

        assert ns not in client._pushed_seqs, \
            "dissolve 后应清理 pushed_seqs"

    @pytest.mark.asyncio
    async def test_dissolved_clears_pending_decrypt_msgs(self, tmp_path):
        """dissolve 后应清理待重试解密队列。"""
        client = _make_client(tmp_path)
        ns = f"group:{_GRP}"
        # 手动塞入待重试消息
        client._pending_decrypt_msgs[ns] = [{"group_id": _GRP, "seq": 1}]

        event = {"group_id": _GRP, "action": "dissolved"}
        await client._on_raw_group_changed(event)

        assert ns not in client._pending_decrypt_msgs, \
            "dissolve 后应清理待重试解密队列"


# ── PY-005: 定时轮换 loop leader 选举 ──────────────────────────


class TestPY005RotateLoopLeaderElection:
    """PY-005: 定时轮换 loop 应使用 leader 选举，只有 leader 才执行轮换。"""

    @pytest.mark.asyncio
    async def test_leader_election_by_aid_sort(self, tmp_path):
        """按 AID 字典序选 leader，最小的 AID 为 leader。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret(client, members=[_AID_ALICE, _AID_BOB, _AID_CHARLIE])

        rotated = []

        async def fake_call(method, params=None):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "admin"},
                    {"aid": _AID_BOB, "role": "admin"},
                    {"aid": _AID_CHARLIE, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1}
            if method == "group.e2ee.cas_epoch":
                rotated.append(params)
                return {"epoch": 2}
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=fake_call)

        # alice < bob 字典序，alice 应该是 leader
        assert _AID_ALICE < _AID_BOB

        # 调用 _is_rotation_leader 判断
        is_leader = await client._is_rotation_leader(_GRP)
        assert is_leader is True, "AID 字典序最小的 admin 应是 leader"

    @pytest.mark.asyncio
    async def test_non_leader_skips_rotation(self, tmp_path):
        """非 leader admin 不应主动执行定时轮换。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret(client, members=[_AID_ALICE, _AID_BOB])

        async def fake_call(method, params=None):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "admin"},
                    {"aid": _AID_BOB, "role": "admin"},
                ]}
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=fake_call)

        # bob > alice 字典序，bob 不是 leader
        is_leader = await client._is_rotation_leader(_GRP)
        assert is_leader is False, "AID 字典序非最小的 admin 不应是 leader"

    @pytest.mark.asyncio
    async def test_member_not_leader(self, tmp_path):
        """普通成员（非 admin/owner）不参与 leader 选举。"""
        client = _make_client(tmp_path, aid=_AID_BOB)

        async def fake_call(method, params=None):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "admin"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=fake_call)

        is_leader = await client._is_rotation_leader(_GRP)
        assert is_leader is False, "普通 member 不参与 leader 选举"


# ── PY-006: pushed_seqs 硬上限 ─────────────────────────────────


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
