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
from aun_core.client import _CachedPeerCert, _PUSHED_SEQS_LIMIT
from aun_core.e2ee import (
    compute_membership_commitment,
    encrypt_group_message,
    generate_group_secret,
    store_group_secret,
)


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


class TestPY002PushedSeqsLimit:
    """PY-002: P2P push 路径在添加 pushed_seqs 后必须调用 _enforce_pushed_seqs_limit，防止内存泄漏。"""

    @pytest.mark.asyncio
    async def test_p2p_push_enforces_pushed_seqs_limit(self, tmp_path):
        """P2P 推送路径应在每次 add 后调用 _enforce_pushed_seqs_limit。"""
        client = _make_client(tmp_path)
        client._transport = MagicMock()
        client._transport.call = AsyncMock(return_value={})

        # 记录 _enforce_pushed_seqs_limit 被调用次数
        enforce_calls = []
        original_enforce = client._enforce_pushed_seqs_limit

        def tracking_enforce(ns):
            enforce_calls.append(ns)
            return original_enforce(ns)

        client._enforce_pushed_seqs_limit = tracking_enforce

        # 模拟收到一条 P2P push 消息（明文，无加密）
        msg = {
            "from": _AID_ALICE,
            "to": client._aid,
            "message_id": "test-msg-1",
            "seq": 1,
            "payload": {"type": "text", "text": "hello"},
        }
        ns = f"p2p:{client._aid}"

        # 直接调用 _process_and_publish_message（绕过 create_task 异步问题）
        await client._process_and_publish_message(msg)

        p2p_ns = f"p2p:{client._aid}"
        p2p_enforce_calls = [c for c in enforce_calls if c == p2p_ns]
        assert len(p2p_enforce_calls) >= 1, \
            f"P2P push 路径应调用 _enforce_pushed_seqs_limit，实际调用了 {len(p2p_enforce_calls)} 次"

    def test_enforce_limit_prunes_excess(self, tmp_path):
        """超过 _PUSHED_SEQS_LIMIT 时应裁剪到上限。"""
        client = _make_client(tmp_path)
        ns = "p2p:test"
        # 塞入超限数据
        excess = _PUSHED_SEQS_LIMIT + 1000
        client._pushed_seqs[ns] = set(range(excess))

        client._enforce_pushed_seqs_limit(ns)

        remaining = client._pushed_seqs.get(ns, set())
        assert len(remaining) <= _PUSHED_SEQS_LIMIT, \
            f"应保留最多 {_PUSHED_SEQS_LIMIT} 个条目，实际 {len(remaining)}"
        # 最大的 seq 应保留
        assert excess - 1 in remaining, "应保留最新的 seq"
        # 最小的 seq 应被清理
        assert 0 not in remaining, "应清理最旧的 seq"


# ── PY-005: 群消息 epoch 落后时等待密钥恢复 ────────────────────────


class TestPY005EpochWait:
    """PY-005: 发现 epoch 落后后应 await 等待密钥请求完成，超时后降级使用旧 epoch。"""

    @pytest.mark.asyncio
    async def test_waits_for_key_recovery_before_send(self, tmp_path):
        """epoch 落后时应等待密钥恢复完成后再发送。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        # 存入旧 epoch=1 的密钥
        gs_old = _store_secret(client, epoch=1)

        key_request_sent = False
        gs_new = secrets.token_bytes(32)

        async def mock_call(method, params=None):
            nonlocal key_request_sent
            if method == "group.e2ee.get_epoch":
                return {"epoch": 2, "owner_aid": _AID_ALICE}
            if method == "group.send":
                return {}
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=mock_call)

        # mock _request_group_key_from：模拟密钥请求后异步收到密钥
        original_request = client._request_group_key_from

        async def mock_request(group_id, target_aid):
            nonlocal key_request_sent
            key_request_sent = True
            # 模拟请求发出后短暂延迟，密钥到达
            await asyncio.sleep(0.05)
            _store_secret(client, epoch=2, gs=gs_new)

        client._request_group_key_from = mock_request

        # 缩短等待时间
        with patch("aun_core.client._KEY_WAIT_TIMEOUT_S", 2.0), \
             patch("aun_core.client._KEY_WAIT_POLL_INTERVAL_S", 0.05):
            await client._send_group_encrypted({
                "group_id": _GRP,
                "payload": {"type": "text", "text": "test"},
            })

        # 应调用过密钥请求
        assert key_request_sent, "应发送密钥请求"
        # epoch 应已更新
        assert client._group_e2ee.current_epoch(_GRP) == 2, "epoch 应已更新为 2"

    @pytest.mark.asyncio
    async def test_timeout_degrades_with_old_epoch(self, tmp_path):
        """等待超时后应降级使用旧 epoch 发送。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs_old = _store_secret(client, epoch=1)

        send_called = False

        async def mock_call(method, params=None):
            nonlocal send_called
            if method == "group.e2ee.get_epoch":
                return {"epoch": 2, "owner_aid": _AID_ALICE}
            if method == "group.send":
                send_called = True
                return {}
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=mock_call)

        # mock _request_group_key_from：不存入新密钥（模拟恢复失败）
        async def mock_request_fail(group_id, target_aid):
            pass  # 不做任何事，密钥恢复将超时

        client._request_group_key_from = mock_request_fail

        # 缩短等待时间
        with patch("aun_core.client._KEY_WAIT_TIMEOUT_S", 0.3), \
             patch("aun_core.client._KEY_WAIT_POLL_INTERVAL_S", 0.05):
            await client._send_group_encrypted({
                "group_id": _GRP,
                "payload": {"type": "text", "text": "test"},
            })

        # 即使超时，也应最终发送消息
        assert send_called, "超时后应降级使用旧 epoch 发送"

    @pytest.mark.asyncio
    async def test_same_epoch_no_wait(self, tmp_path):
        """本地 epoch 与服务端一致时不应等待。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret(client, epoch=1)

        key_request_sent = False

        async def mock_call(method, params=None):
            nonlocal key_request_sent
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1}  # 与本地一致
            if method == "group.send":
                return {}
            if method == "message.send":
                key_request_sent = True
                return {}
            return {}

        client._transport = MagicMock()
        client._transport.call = AsyncMock(side_effect=mock_call)

        start = time.time()
        await client._send_group_encrypted({
            "group_id": _GRP,
            "payload": {"type": "text", "text": "test"},
        })
        elapsed = time.time() - start

        assert not key_request_sent, "epoch 一致时不应发送密钥请求"
        assert elapsed < 1.0, "epoch 一致时不应有等待延迟"
