"""阶段 3：Client 群组 E2EE 自动加解密单元测试。"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization

from aun_core import AUNClient
from aun_core.client import _CachedPeerCert, _KEY_WAIT_TIMEOUT_S, _PEER_CERT_CACHE_TTL
from aun_core.e2ee import (
    build_key_distribution,
    build_membership_manifest,
    sign_membership_manifest,
    compute_membership_commitment,
    compute_epoch_chain,
    ecies_encrypt,
    encrypt_group_message,
    generate_group_secret,
    GroupReplayGuard,
    load_all_group_secrets,
    load_group_secret,
    store_group_secret,
)
from aun_core.errors import E2EEGroupSecretMissingError, StateError


_AID_ALICE = "alice.agentid.pub"
_AID_BOB = "bob.agentid.pub"
_AID_CAROL = "carol.agentid.pub"
_GRP = "grp_test1"
_MEMBERS = [_AID_ALICE, _AID_BOB]


def _make_signing_identity(cn: str):
    """生成签名密钥对 + 证书 PEM（测试用）。返回 (private_key_pem, cert_pem_bytes)。"""
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


# 预生成各成员的签名身份（模块级缓存，所有测试共用）
_SIGNING_IDENTITIES: dict[str, tuple[str, bytes]] = {}


def _get_signing_identity(aid: str):
    """获取或创建指定 AID 的签名身份"""
    if aid not in _SIGNING_IDENTITIES:
        _SIGNING_IDENTITIES[aid] = _make_signing_identity(aid)
    return _SIGNING_IDENTITIES[aid]


def _make_client(tmp_path, aid=_AID_ALICE):
    """创建一个 mock 好的 AUNClient 用于测试。"""
    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    pk_pem, cert_pem = _get_signing_identity(aid)
    cert_str = cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else cert_pem
    client._aid = aid
    client._identity = {"aid": aid, "private_key_pem": pk_pem, "cert": cert_str}
    client._keystore.save_identity(aid, client._identity)
    client._state = "connected"
    # 为所有已知成员预填充 PKI 验证过的证书缓存
    now = time.time()
    for peer_aid in _MEMBERS:
        if peer_aid == aid:
            continue
        _, cert_pem = _get_signing_identity(peer_aid)
        client._cert_cache[peer_aid] = _CachedPeerCert(
            cert_bytes=cert_pem, validated_at=now, refresh_after=now + _PEER_CERT_CACHE_TTL,
        )
        cert_str = cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else cert_pem
        client._keystore.save_cert(peer_aid, cert_str)
    return client


def _aid_public_key_bytes(client):
    key_pair = client._auth._keystore.load_key_pair(client._aid)
    private_key = serialization.load_pem_private_key(
        key_pair["private_key_pem"].encode("utf-8"), password=None,
    )
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _store_secret_for_client(client, group_id=_GRP, epoch=1, gs=None, epoch_chain=None):
    gs = gs or secrets.token_bytes(32)
    commitment = compute_membership_commitment(_MEMBERS, epoch, group_id, gs)
    store_group_secret(
        client._keystore, client._aid, group_id, epoch, gs, commitment, _MEMBERS,
        epoch_chain=epoch_chain,
    )
    return gs


# ── group.send encrypt=True ──────────────────────────────

class TestGroupSendEncrypt:
    def test_sender_membership_floor_error_is_retryable_epoch_error(self, tmp_path):
        """服务端 membership floor 拒绝应触发群 epoch 恢复重试。"""
        client = _make_client(tmp_path)
        err = StateError("e2ee epoch below sender membership floor: epoch=1 floor=2")

        assert client._is_group_epoch_too_old_error(err) is True
        assert client._is_recoverable_group_epoch_error(err) is True

    def test_epoch_changed_during_send_is_retryable_epoch_error(self, tmp_path):
        """发送落库前 epoch 被推进应触发群 epoch 恢复重试。"""
        client = _make_client(tmp_path)
        err = StateError("e2ee epoch changed during send: expected 1, current 2")

        assert client._is_group_epoch_changed_during_send_error(err) is True
        assert client._is_recoverable_group_epoch_error(err) is True

    def test_calls_encrypt_group_message(self, tmp_path, monkeypatch):
        """group.send(encrypt=True) 触发群组加密"""
        client = _make_client(tmp_path)
        gs = _store_secret_for_client(client)

        sent_params = {}

        async def fake_call(method, params):
            sent_params["method"] = method
            sent_params["params"] = params
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            return {"ok": True}

        monkeypatch.setattr(client._transport, "call", fake_call)

        asyncio.run(client.call("group.send", {
            "group_id": _GRP,
            "payload": {"type": "text", "text": "加密消息"},
            "encrypt": True,
        }))

        assert sent_params["method"] == "group.send"
        p = sent_params["params"]
        assert p["encrypted"] is True
        assert p["payload"]["type"] == "e2ee.group_encrypted"
        assert p["payload"]["encryption_mode"] == "epoch_group_key"

    def test_plaintext_group_send_waits_for_membership_floor(self, tmp_path, monkeypatch):
        """明文群消息也必须等待成员 epoch floor，避免服务端拒绝旧 epoch。"""
        client = _make_client(tmp_path)
        call_order = []

        async def fake_wait(group_id, *, timeout_s, strict=False):
            call_order.append(("wait", group_id, strict))

        async def fake_transport(method, params):
            call_order.append(("send", method, params.get("group_id")))
            return {"ok": True}

        monkeypatch.setattr(client, "_wait_for_group_membership_epoch_floor", fake_wait)
        monkeypatch.setattr(client._transport, "call", fake_transport)

        asyncio.run(client.call("group.send", {
            "group_id": _GRP,
            "payload": {"type": "text", "text": "明文"},
            "encrypt": False,
        }))

        assert call_order[0] == ("wait", _GRP, True)
        assert call_order[1] == ("send", "group.send", _GRP)

    def test_membership_floor_above_committed_uses_committed_epoch(self, tmp_path, monkeypatch):
        """成员 floor 高于 committed epoch 时只记录诊断，不阻断发送。"""
        client = _make_client(tmp_path)

        async def fake_call(method, params=None):
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner", "min_read_epoch": 1},
                    {"aid": _AID_BOB, "role": "member", "min_read_epoch": 2},
                ]}
            raise AssertionError(f"unmocked: {method}")

        monkeypatch.setattr(client, "call", fake_call)

        asyncio.run(client._wait_for_group_membership_epoch_floor(
            _GRP,
            timeout_s=0.0,
            strict=True,
        ))

    def test_group_send_refuses_uncommitted_pending_secret(self, tmp_path, monkeypatch):
        """本地 pending epoch key 与服务端 committed rotation 不匹配时不得用于发送。"""
        client = _make_client(tmp_path)
        old_secret = _store_secret_for_client(client, epoch=1)
        pending_secret = secrets.token_bytes(32)
        pending_commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, pending_secret)
        store_group_secret(
            client._keystore,
            client._aid,
            _GRP,
            2,
            pending_secret,
            pending_commitment,
            _MEMBERS,
            pending_rotation_id="rot-local-pending",
            allow_pending_overwrite=True,
        )
        assert old_secret
        client._group_synced.add(_GRP)

        async def no_wait(*args, **kwargs):
            return None

        async def no_recover(*args, **kwargs):
            return False

        async def fake_transport(method, params):
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "committed_rotation": {
                        "rotation_id": "rot-other",
                        "key_commitment": "other-commitment",
                    },
                }
            if method == "group.send":
                raise AssertionError("不应使用未提交或不匹配的 pending key 发送群消息")
            return {}

        monkeypatch.setattr(client, "_wait_for_group_membership_epoch_floor", no_wait)
        monkeypatch.setattr(client, "_recover_group_epoch_key", no_recover)
        monkeypatch.setattr(client._transport, "call", fake_transport)

        with pytest.raises(StateError, match="refuse to send with uncommitted group key"):
            asyncio.run(client.call("group.send", {
                "group_id": _GRP,
                "payload": {"type": "text", "text": "should not send"},
                "encrypt": True,
            }))

    def test_group_send_refuses_commitment_mismatch_without_pending_marker(self, tmp_path, monkeypatch):
        """本地 target epoch 没有 pending 标记时仍必须匹配 committed key_commitment。"""
        client = _make_client(tmp_path)
        wrong_secret = secrets.token_bytes(32)
        wrong_commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, wrong_secret)
        store_group_secret(
            client._keystore,
            client._aid,
            _GRP,
            2,
            wrong_secret,
            wrong_commitment,
            _MEMBERS,
        )
        client._group_synced.add(_GRP)

        async def no_wait(*args, **kwargs):
            return None

        async def no_recover(*args, **kwargs):
            return False

        async def fake_transport(method, params):
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "committed_rotation": {
                        "rotation_id": "rot-committed",
                        "key_commitment": "different-commitment",
                    },
                }
            if method == "group.send":
                raise AssertionError("commitment 不匹配时不得发送")
            return {}

        monkeypatch.setattr(client, "_wait_for_group_membership_epoch_floor", no_wait)
        monkeypatch.setattr(client, "_recover_group_epoch_key", no_recover)
        monkeypatch.setattr(client._transport, "call", fake_transport)

        with pytest.raises(StateError, match="refuse to send with uncommitted group key"):
            asyncio.run(client.call("group.send", {
                "group_id": _GRP,
                "payload": {"type": "text", "text": "blocked"},
                "encrypt": True,
            }))

    def test_group_send_rechecks_committed_epoch_after_recovery_wait(self, tmp_path, monkeypatch):
        """恢复等待期间服务端 epoch 再推进时，应改用最新 committed epoch 发送。"""
        client = _make_client(tmp_path)
        client._group_synced.add(_GRP)
        c2 = "commitment-2"
        get_epoch_calls = 0
        sent_params = {}
        recovered_epochs = []

        async def no_wait(*args, **kwargs):
            return None

        async def fake_recover(group_id, epoch, **kwargs):
            recovered_epochs.append(epoch)
            return True

        def fake_load_secret(group_id, epoch=None):
            if epoch == 1:
                return {"epoch": 1, "pending_rotation_id": "rot-local-1", "commitment": "c1"}
            if epoch == 2:
                return {"epoch": 2, "pending_rotation_id": "rot-2", "commitment": c2}
            return None

        def fake_encrypt_with_epoch(group_id, epoch, payload, **kwargs):
            return {
                "type": "e2ee.group_encrypted",
                "epoch": epoch,
                "payload": payload,
                **kwargs,
            }

        async def fake_transport(method, params):
            nonlocal get_epoch_calls
            if method == "group.e2ee.get_epoch":
                get_epoch_calls += 1
                if get_epoch_calls == 1:
                    return {
                        "epoch": 1,
                        "committed_epoch": 1,
                        "committed_rotation": {"rotation_id": "rot-other", "key_commitment": "other"},
                    }
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "committed_rotation": {"rotation_id": "rot-2", "key_commitment": c2},
                }
            if method == "group.send":
                sent_params.update(params)
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "_ensure_group_epoch_ready", no_wait)
        monkeypatch.setattr(client, "_wait_for_group_membership_epoch_floor", no_wait)
        monkeypatch.setattr(client, "_recover_group_epoch_key", fake_recover)
        monkeypatch.setattr(client._group_e2ee, "load_secret", fake_load_secret)
        monkeypatch.setattr(client._group_e2ee, "encrypt_with_epoch", fake_encrypt_with_epoch)
        monkeypatch.setattr(client._transport, "call", fake_transport)

        asyncio.run(client.call("group.send", {
            "group_id": _GRP,
            "payload": {"type": "text", "text": "use latest epoch"},
            "encrypt": True,
        }))

        assert sent_params["payload"]["epoch"] == 2
        assert recovered_epochs == [1, 2]

    def test_group_send_repairs_when_self_missing_from_committed_membership(self, tmp_path, monkeypatch):
        """自己已是当前成员但不在 committed rotation 成员快照中，应先触发轮换再发送。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        client._group_synced.add(_GRP)
        epoch1_secret = secrets.token_bytes(32)
        local_commitment = compute_membership_commitment(_MEMBERS, 1, _GRP, epoch1_secret)
        old_commitment = compute_membership_commitment([_AID_ALICE], 1, _GRP, epoch1_secret)
        store_group_secret(client._keystore, client._aid, _GRP, 1, epoch1_secret, local_commitment, _MEMBERS)
        epoch2_secret = secrets.token_bytes(32)
        epoch2_commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, epoch2_secret)
        repaired = False
        rotate_calls = []
        sent_params = {}

        async def no_wait(*args, **kwargs):
            return None

        async def fake_rotate(group_id, **kwargs):
            nonlocal repaired
            rotate_calls.append((group_id, kwargs))
            store_group_secret(client._keystore, client._aid, _GRP, 2, epoch2_secret, epoch2_commitment, _MEMBERS)
            repaired = True

        async def fake_transport(method, params):
            if method == "group.get_join_requirements":
                return {"join_mode": "open"}
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                if repaired:
                    return {
                        "epoch": 2,
                        "committed_epoch": 2,
                        "committed_rotation": {
                            "target_epoch": 2,
                            "key_commitment": epoch2_commitment,
                            "expected_members": list(_MEMBERS),
                        },
                    }
                return {
                    "epoch": 1,
                    "committed_epoch": 1,
                    "committed_rotation": {
                        "target_epoch": 1,
                        "key_commitment": old_commitment,
                        "expected_members": [_AID_ALICE],
                    },
                }
            if method == "group.send":
                sent_params.update(params)
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "_ensure_group_epoch_ready", no_wait)
        monkeypatch.setattr(client, "_wait_for_group_membership_epoch_floor", no_wait)
        monkeypatch.setattr(client, "_maybe_lead_rotate_group_epoch", fake_rotate)
        monkeypatch.setattr(client._transport, "call", fake_transport)

        asyncio.run(client.call("group.send", {
            "group_id": _GRP,
            "payload": {"type": "text", "text": "after repair"},
            "encrypt": True,
        }))

        assert rotate_calls == [(_GRP, {
            "reason": "membership_changed",
            "trigger_id": f"{_GRP}:committed_membership_gap:aid:{_AID_BOB}:epoch:1",
            "expected_epoch": 1,
            "allow_member": True,
        })]
        assert sent_params["payload"]["epoch"] == 2

    def test_group_send_repairs_when_any_active_member_missing_from_committed_membership(self, tmp_path, monkeypatch):
        """自己在 committed 快照中，但当前成员集中有新成员缺失，也必须先轮换再发送。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        client._group_synced.add(_GRP)
        old_members = [_AID_ALICE, _AID_BOB]
        new_members = [_AID_ALICE, _AID_BOB, _AID_CAROL]
        epoch1_secret = secrets.token_bytes(32)
        old_commitment = compute_membership_commitment(old_members, 1, _GRP, epoch1_secret)
        store_group_secret(client._keystore, client._aid, _GRP, 1, epoch1_secret, old_commitment, old_members)
        epoch2_secret = secrets.token_bytes(32)
        epoch2_commitment = compute_membership_commitment(new_members, 2, _GRP, epoch2_secret)
        repaired = False
        rotate_calls = []
        sent_params = {}

        async def no_wait(*args, **kwargs):
            return None

        async def fake_rotate(group_id, **kwargs):
            nonlocal repaired
            rotate_calls.append((group_id, kwargs))
            store_group_secret(client._keystore, client._aid, _GRP, 2, epoch2_secret, epoch2_commitment, new_members)
            repaired = True

        async def fake_transport(method, params):
            if method == "group.get_join_requirements":
                return {"join_mode": "open"}
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                    {"aid": _AID_CAROL, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                if repaired:
                    return {
                        "epoch": 2,
                        "committed_epoch": 2,
                        "committed_rotation": {
                            "target_epoch": 2,
                            "key_commitment": epoch2_commitment,
                            "expected_members": list(new_members),
                        },
                    }
                return {
                    "epoch": 1,
                    "committed_epoch": 1,
                    "committed_rotation": {
                        "target_epoch": 1,
                        "key_commitment": old_commitment,
                        "expected_members": list(old_members),
                    },
                }
            if method == "group.send":
                sent_params.update(params)
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "_ensure_group_epoch_ready", no_wait)
        monkeypatch.setattr(client, "_wait_for_group_membership_epoch_floor", no_wait)
        monkeypatch.setattr(client, "_maybe_lead_rotate_group_epoch", fake_rotate)
        monkeypatch.setattr(client._transport, "call", fake_transport)

        asyncio.run(client.call("group.send", {
            "group_id": _GRP,
            "payload": {"type": "text", "text": "after repair"},
            "encrypt": True,
        }))

        assert rotate_calls == [(_GRP, {
            "reason": "membership_changed",
            "trigger_id": f"{_GRP}:committed_membership_gap:aid:{_AID_BOB}:epoch:1",
            "expected_epoch": 1,
            "allow_member": True,
        })]
        assert sent_params["payload"]["epoch"] == 2

    def test_without_secret_raises_error(self, tmp_path, monkeypatch):
        """无 group_secret 时抛 E2EEGroupSecretMissingError"""
        client = _make_client(tmp_path)

        async def fake_call(method, params):
            return {}

        monkeypatch.setattr(client._transport, "call", fake_call)

        with pytest.raises(E2EEGroupSecretMissingError):
            asyncio.run(client.call("group.send", {
                "group_id": _GRP,
                "payload": {"type": "text", "text": "test"},
                "encrypt": True,
            }))


class TestGroupThoughtE2EE:
    def test_group_thought_put_encrypts_and_signs(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        _store_secret_for_client(client)
        sent_params = {}

        async def fake_call(method, params):
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            sent_params["method"] = method
            sent_params["params"] = params
            return {"ok": True}

        monkeypatch.setattr(client._transport, "call", fake_call)

        asyncio.run(client.call("group.thought.put", {
            "group_id": _GRP,
            "context": {"type": "run", "id": "run-root"},
            "payload": {"type": "thought", "text": "推理片段"},
        }))

        assert sent_params["method"] == "group.thought.put"
        params = sent_params["params"]
        assert params["context"] == {"type": "run", "id": "run-root"}
        assert params["encrypted"] is True
        assert params["payload"]["type"] == "e2ee.group_encrypted"
        assert params["thought_id"].startswith("gt-")
        assert "client_signature" in params

        asyncio.run(client.call("group.thought.put", {
            "group_id": _GRP,
            "context": {"type": "run", "id": "run-1"},
            "payload": {"type": "thought", "text": "自主推理片段"},
        }))

        params = sent_params["params"]
        assert params["context"] == {"type": "run", "id": "run-1"}
        assert "reply_to" not in params
        assert params["encrypted"] is True

    def test_group_thought_get_auto_decrypts(self, tmp_path, monkeypatch):
        alice = _make_client(tmp_path, aid=_AID_ALICE)
        bob = _make_client(tmp_path, aid=_AID_BOB)
        shared_secret = secrets.token_bytes(32)
        _store_secret_for_client(alice, gs=shared_secret)
        _store_secret_for_client(bob, gs=shared_secret)
        envelope = alice._group_e2ee.encrypt(
            _GRP,
            {"type": "thought", "text": "只给感兴趣的人看"},
            message_id="gt-1",
            timestamp=1710504000000,
            context={"type": "run", "id": "run-root"},
        )

        async def fake_call(method, params):
            assert method == "group.thought.get"
            return {
                "found": True,
                "group_id": _GRP,
                "sender_aid": _AID_ALICE,
                "context": {"type": "run", "id": "run-root"},
                "thoughts": [
                    {
                        "thought_id": "gt-1",
                        "context": {"type": "run", "id": "run-root"},
                        "payload": envelope,
                        "created_at": 1710504000000,
                    }
                ],
            }

        monkeypatch.setattr(bob._transport, "call", fake_call)

        result = asyncio.run(bob.call("group.thought.get", {
            "group_id": _GRP,
            "sender_aid": _AID_ALICE,
            "context": {"type": "run", "id": "run-root"},
        }))

        assert result["found"] is True
        assert result["thoughts"][0]["thought_id"] == "gt-1"
        assert result["thoughts"][0]["payload"]["type"] == "thought"
        assert result["thoughts"][0]["payload"]["text"] == "只给感兴趣的人看"
        assert result["thoughts"][0]["context"] == {"type": "run", "id": "run-root"}
        assert result["thoughts"][0]["e2ee"]["encryption_mode"] == "epoch_group_key"
        assert result["thoughts"][0]["e2ee"]["context"] == {"type": "run", "id": "run-root"}

    def test_group_thought_get_is_not_replay_or_republish_guarded(self, tmp_path, monkeypatch):
        """thought 是 RPC 查询结果，重复读取不应受 replay/republish guard 影响。"""
        alice = _make_client(tmp_path, aid=_AID_ALICE)
        bob = _make_client(tmp_path, aid=_AID_BOB)
        shared_secret = secrets.token_bytes(32)
        _store_secret_for_client(alice, gs=shared_secret)
        _store_secret_for_client(bob, gs=shared_secret)
        thought_id = "gt-rpc-repeat"
        envelope = alice._group_e2ee.encrypt(
            _GRP,
            {"type": "thought", "text": "重复读取也应解密"},
            message_id=thought_id,
            timestamp=1710504000000,
            context={"type": "run", "id": "run-repeat"},
        )

        bob._group_e2ee._replay_guard.record(_GRP, _AID_ALICE, thought_id)
        bob._pushed_seqs[f"group:{_GRP}"] = {1, 2, 3}

        async def fake_call(method, params):
            assert method == "group.thought.get"
            return {
                "found": True,
                "group_id": _GRP,
                "sender_aid": _AID_ALICE,
                "context": {"type": "run", "id": "run-repeat"},
                "thoughts": [{
                    "thought_id": thought_id,
                    "context": {"type": "run", "id": "run-repeat"},
                    "payload": envelope,
                    "created_at": 1710504000000,
                }],
            }

        monkeypatch.setattr(bob._transport, "call", fake_call)

        first = asyncio.run(bob.call("group.thought.get", {
            "group_id": _GRP,
            "sender_aid": _AID_ALICE,
            "context": {"type": "run", "id": "run-repeat"},
        }))
        second = asyncio.run(bob.call("group.thought.get", {
            "group_id": _GRP,
            "sender_aid": _AID_ALICE,
            "context": {"type": "run", "id": "run-repeat"},
        }))

        assert first["thoughts"][0]["payload"]["text"] == "重复读取也应解密"
        assert second["thoughts"][0]["payload"]["text"] == "重复读取也应解密"
        assert first["thoughts"][0]["e2ee"]["encryption_mode"] == "epoch_group_key"
        assert second["thoughts"][0]["e2ee"]["encryption_mode"] == "epoch_group_key"

    def test_group_thought_get_recovers_missing_epoch_key(self, tmp_path, monkeypatch):
        """thought.get 遇到缺失 epoch key 时应先恢复，再返回明文 thought。"""
        alice = _make_client(tmp_path, aid=_AID_ALICE)
        bob = _make_client(tmp_path, aid=_AID_BOB)
        epoch2_secret = secrets.token_bytes(32)
        _store_secret_for_client(alice, epoch=2, gs=epoch2_secret)
        _store_secret_for_client(bob, epoch=1)
        envelope = alice._group_e2ee.encrypt_with_epoch(
            _GRP,
            2,
            {"type": "thought", "text": "恢复后可见"},
            message_id="gt-recover-2",
            timestamp=1710504000000,
            context={"type": "run", "id": "run-recover"},
        )
        recover_calls = []

        async def fake_recover(group_id, epoch, **kwargs):
            recover_calls.append((group_id, epoch, kwargs))
            _store_secret_for_client(bob, epoch=2, gs=epoch2_secret)
            return True

        async def fake_call(method, params):
            assert method == "group.thought.get"
            return {
                "found": True,
                "group_id": _GRP,
                "sender_aid": _AID_ALICE,
                "context": {"type": "run", "id": "run-recover"},
                "thoughts": [{
                    "thought_id": "gt-recover-2",
                    "context": {"type": "run", "id": "run-recover"},
                    "payload": envelope,
                    "created_at": 1710504000000,
                }],
            }

        monkeypatch.setattr(bob, "_recover_group_epoch_key", fake_recover)
        monkeypatch.setattr(bob._transport, "call", fake_call)

        result = asyncio.run(bob.call("group.thought.get", {
            "group_id": _GRP,
            "sender_aid": _AID_ALICE,
            "context": {"type": "run", "id": "run-recover"},
        }))

        assert recover_calls == [(_GRP, 2, {"sender_aid": _AID_ALICE, "timeout_s": 5.0})]
        assert result["thoughts"][0]["payload"]["text"] == "恢复后可见"
        assert result["thoughts"][0]["e2ee"]["epoch"] == 2


# ── 群组消息自动解密 ─────────────────────────────────────

class TestGroupMessageAutoDecrypt:
    def _make_encrypted_group_msg(self, gs, from_aid=_AID_ALICE):
        pk_pem, _ = _get_signing_identity(from_aid)
        msg_id = f"gm-{uuid.uuid4()}"
        ts = 1710504000000
        envelope = encrypt_group_message(
            group_id=_GRP, epoch=1, group_secret=gs,
            payload={"type": "text", "text": "秘密"}, from_aid=from_aid,
            message_id=msg_id, timestamp=ts,
            sender_private_key_pem=pk_pem,
        )
        return {
            "group_id": _GRP,
            "from": from_aid,
            "sender_aid": from_aid,
            "message_id": msg_id,
            "timestamp": ts,
            "payload": envelope,
            "encrypted": True,
        }

    def test_auto_decrypted_on_event(self, tmp_path):
        """push 事件中的 e2ee.group_encrypted 自动解密"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        msg = self._make_encrypted_group_msg(gs)
        msg["dispatch_mode"] = "mention"
        result = asyncio.run(client._decrypt_group_message(msg))
        assert result["payload"]["type"] == "text"
        assert result["payload"]["text"] == "秘密"
        assert result["payload"]["dispatch_mode"] == "mention"
        assert result["dispatch_mode"] == "mention"
        assert result["e2ee"]["encryption_mode"] == "epoch_group_key"

    def test_auto_decrypted_on_pull(self, tmp_path):
        """pull 消息中的 e2ee.group_encrypted 能被解密"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        msg = self._make_encrypted_group_msg(gs)
        # 模拟 pull 返回的消息解密
        result = asyncio.run(client._decrypt_group_message(msg))
        assert result["payload"]["text"] == "秘密"
        assert result["payload"]["dispatch_mode"] == "broadcast"
        assert result["dispatch_mode"] == "broadcast"

    def test_plaintext_passthrough(self, tmp_path):
        """非加密群消息正常通过"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        msg = {
            "group_id": _GRP,
            "from": _AID_ALICE,
            "message_id": "gm-123",
            "timestamp": 1710504000000,
            "payload": {"type": "text", "text": "明文消息"},
            "dispatch_mode": "mention",
        }
        result = asyncio.run(client._decrypt_group_message(msg))
        assert result["payload"]["text"] == "明文消息"
        assert result["payload"]["dispatch_mode"] == "mention"

    def test_plaintext_default_dispatch_mode_is_broadcast(self, tmp_path):
        """服务端缺省 dispatch_mode 时 SDK 默认按 broadcast 交付"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        msg = {
            "group_id": _GRP,
            "from": _AID_ALICE,
            "message_id": "gm-default-dispatch",
            "timestamp": 1710504000000,
            "payload": {"type": "text", "text": "明文消息"},
        }
        result = asyncio.run(client._decrypt_group_message(msg))
        assert result["payload"]["dispatch_mode"] == "broadcast"
        assert result["dispatch_mode"] == "broadcast"

    def test_attach_dispatch_mode_default_is_broadcast_without_tmp_path(self):
        """缺省 dispatch_mode 的兜底不依赖本地 keystore。"""
        result = AUNClient._attach_group_dispatch_mode_to_payload({
            "group_id": _GRP,
            "payload": {"type": "text", "text": "明文消息"},
        })
        assert result["payload"]["dispatch_mode"] == "broadcast"
        assert result["dispatch_mode"] == "broadcast"


# ── 密钥分发自动处理 ─────────────────────────────────────

class TestKeyDistributionAutoHandled:
    def test_distribution_handled(self, tmp_path, monkeypatch):
        """收到 e2ee.group_key_distribution P2P 消息 → 自动存储"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = generate_group_secret()
        # 构建带签名 manifest 的分发消息
        pk_pem, _ = _get_signing_identity(_AID_ALICE)
        manifest = sign_membership_manifest(
            build_membership_manifest(_GRP, 1, None, _MEMBERS, initiator_aid=_AID_ALICE),
            pk_pem,
        )
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID_ALICE, manifest=manifest)

        # 模拟收到未加密的 P2P 消息（payload 直接是分发消息）
        message = {
            "from": _AID_ALICE,
            "message_id": "msg-dist-1",
            "payload": dist,
        }

        async def fake_call(method, params):
            assert method == "group.e2ee.get_epoch"
            return {"epoch": 1, "committed_epoch": 1}

        monkeypatch.setattr(client, "call", fake_call)

        handled = asyncio.run(client._try_handle_group_key_message(message))
        assert handled is True

        loaded = load_group_secret(client._keystore, _AID_BOB, _GRP)
        assert loaded is not None
        assert loaded["secret"] == gs


# ── 密钥请求自动回复 ─────────────────────────────────────

class TestKeyRequestAutoResponded:
    def test_responds_to_request(self, tmp_path, monkeypatch):
        """收到 e2ee.group_key_request → 自动回复"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        gs = _store_secret_for_client(client, epoch=2)

        sent_messages = []

        # mock call 来捕获发出的回复
        original_call = client.call

        async def capture_call(method, params=None):
            if method == "message.send":
                sent_messages.append(params)
                return {"ok": True}
            return await original_call(method, params)

        monkeypatch.setattr(client, "call", capture_call)

        request_payload = {
            "type": "e2ee.group_key_request",
            "group_id": _GRP,
            "epoch": 2,
            "requester_aid": _AID_BOB,
        }
        message = {
            "from": _AID_BOB,
            "message_id": "msg-req-1",
            "payload": request_payload,
        }

        asyncio.run(client._try_handle_group_key_message(message))

        assert len(sent_messages) == 1
        reply = sent_messages[0]
        assert reply["to"] == _AID_BOB
        assert reply["encrypt"] is True
        assert reply["payload"]["type"] == "e2ee.group_key_response"
        assert reply["payload"]["epoch"] == 2


# ── config 关闭 ──────────────────────────────────────────

class TestConfigGroupE2EEDisabled:
    def test_config_defaults(self, tmp_path):
        """默认 group_e2ee=True（必选能力）"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        assert client._config_model.group_e2ee is True
        assert client._config_model.epoch_auto_rotate_interval == 0
        assert client._config_model.old_epoch_retention_seconds == 604800

    def test_config_group_e2ee_always_true(self, tmp_path):
        """group_e2ee 是必选能力，即使用户传 False 也始终为 True"""
        client = AUNClient({
            "aun_path": str(tmp_path / "aun"),
            "epoch_auto_rotate_interval": 86400,
        })
        assert client._config_model.group_e2ee is True
        assert client._config_model.epoch_auto_rotate_interval == 86400


# ══════════════════════════════════════════════════════════════
# 阶段 4：安全增强
# ══════════════════════════════════════════════════════════════

class TestKeyRequestRateLimited:
    def test_request_throttled(self, tmp_path):
        """同群 30 秒内不重复发 key_request"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(client, epoch=1)

        # 第一次 → 通过
        r1 = client._group_e2ee.build_recovery_request(_GRP, 2)
        assert r1 is not None

        # 第二次 → 被限制
        r2 = client._group_e2ee.build_recovery_request(_GRP, 2)
        assert r2 is None

    def test_different_epoch_not_throttled(self, tmp_path):
        """不同 epoch 的请求不互相限制"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(client, epoch=1)

        r1 = client._group_e2ee.build_recovery_request(_GRP, 2)
        r2 = client._group_e2ee.build_recovery_request(_GRP, 3)
        assert r1 is not None
        assert r2 is not None


class TestKeyResponseRateLimited:
    def test_response_throttled(self, tmp_path, monkeypatch):
        """同请求者同群 30 秒内不重复回复"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=2)

        sent_messages = []

        async def capture_call(method, params=None):
            if method == "message.send":
                sent_messages.append(params)
                return {"ok": True}
            raise Exception("not connected")

        monkeypatch.setattr(client, "call", capture_call)

        request_payload = {
            "type": "e2ee.group_key_request",
            "group_id": _GRP,
            "epoch": 2,
            "requester_aid": _AID_BOB,
        }
        message = {
            "from": _AID_BOB,
            "message_id": "msg-req-1",
            "payload": request_payload,
        }

        # 第一次 → 回复
        asyncio.run(client._try_handle_group_key_message(message))
        assert len(sent_messages) == 1

        # 第二次 → 被限制
        message["message_id"] = "msg-req-2"
        asyncio.run(client._try_handle_group_key_message(message))
        assert len(sent_messages) == 1


# ══════════════════════════════════════════════════════════════
# 安全修复回归测试
# ══════════════════════════════════════════════════════════════

def _make_encrypted_group_msg(gs, group_id=_GRP, from_aid=_AID_ALICE):
    import uuid
    pk_pem, _ = _get_signing_identity(from_aid)
    msg_id = f"gm-{uuid.uuid4()}"
    ts = 1710504000000
    envelope = encrypt_group_message(
        group_id=group_id, epoch=1, group_secret=gs,
        payload={"type": "text", "text": "test"}, from_aid=from_aid,
        message_id=msg_id, timestamp=ts,
        sender_private_key_pem=pk_pem,
    )
    return {
        "group_id": group_id,
        "from": from_aid,
        "sender_aid": from_aid,
        "message_id": msg_id,
        "timestamp": ts,
        "payload": envelope,
        "encrypted": True,
    }


class TestEpochDowngradeAttack:
    def test_old_epoch_distribution_rejected(self, tmp_path):
        """本地 epoch=3 时，收到 epoch=1 的分发消息应被拒绝"""
        from aun_core.e2ee import handle_key_distribution
        client = _make_client(tmp_path, aid=_AID_BOB)

        # 先存 epoch=3
        _store_secret_for_client(client, epoch=3)

        # 构造 epoch=1 的分发（降级攻击）
        gs_old = secrets.token_bytes(32)
        dist = build_key_distribution(_GRP, 1, gs_old, _MEMBERS, _AID_ALICE)
        result = handle_key_distribution(dist, client._keystore, _AID_BOB)

        # 验证本地 epoch 仍为 3
        loaded = load_group_secret(client._keystore, _AID_BOB, _GRP)
        assert loaded["epoch"] == 3


class TestOuterFieldTampering:
    def test_tampered_outer_group_id_rejected(self, tmp_path):
        """外层 group_id 被篡改 → 解密失败"""
        from aun_core.e2ee import decrypt_group_message
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client)

        msg = _make_encrypted_group_msg(gs)
        # 篡改外层 group_id
        msg["group_id"] = "grp_fake"

        all_secrets = load_all_group_secrets(client._keystore, _AID_BOB, _GRP)
        result = decrypt_group_message(msg, all_secrets)
        assert result is None

    def test_tampered_outer_from_rejected(self, tmp_path):
        """外层 from 被篡改 → 解密失败"""
        from aun_core.e2ee import decrypt_group_message
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client)

        msg = _make_encrypted_group_msg(gs)
        msg["from"] = "mallory.agentid.pub"

        all_secrets = load_all_group_secrets(client._keystore, _AID_BOB, _GRP)
        result = decrypt_group_message(msg, all_secrets)
        assert result is None

    def test_tampered_outer_sender_aid_rejected(self, tmp_path):
        """外层 sender_aid 被篡改（from 正常）→ 解密失败"""
        from aun_core.e2ee import decrypt_group_message
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client)

        msg = _make_encrypted_group_msg(gs)
        # from 保持正确，sender_aid 被篡改
        msg["sender_aid"] = "mallory.agentid.pub"

        all_secrets = load_all_group_secrets(client._keystore, _AID_BOB, _GRP)
        result = decrypt_group_message(msg, all_secrets)
        assert result is None


class TestZeroStateKeyRecovery:
    def test_recovery_from_message_sender(self, tmp_path):
        """本地无任何密钥时，从消息 sender 发起恢复请求"""
        client = _make_client(tmp_path, aid=_AID_BOB)

        recovery = client._group_e2ee.build_recovery_request(
            _GRP, 1, sender_aid=_AID_ALICE,
        )

        assert recovery is not None
        assert recovery["to"] == _AID_ALICE
        assert recovery["payload"]["type"] == "e2ee.group_key_request"

    def test_no_recovery_without_sender(self, tmp_path):
        """本地无密钥且无 sender 信息时，返回 None"""
        client = _make_client(tmp_path, aid=_AID_BOB)

        recovery = client._group_e2ee.build_recovery_request(_GRP, 1)
        assert recovery is None


# ══════════════════════════════════════════════════════════════
# 两阶段轮换链路测试
# ══════════════════════════════════════════════════════════════

class TestRotateGroupEpochCAS:
    """_rotate_group_epoch 必须走服务端两阶段轮换，不能绕过。"""

    def _setup(self, tmp_path, monkeypatch, *, join_mode: str = "approval"):
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []
        active_rotation = {}

        async def fake_call(method, params=None):
            params = params or {}
            rpc_log.append({"method": method, "params": params})
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1, "group_id": _GRP}
            if method == "group.e2ee.begin_rotation":
                active_rotation.clear()
                active_rotation.update({
                    "rotation_id": params.get("rotation_id", "rot-test"),
                    "group_id": _GRP,
                    "base_epoch": params.get("base_epoch", 1),
                    "target_epoch": params.get("target_epoch", 2),
                    "status": "distributing",
                    "key_commitment": params.get("key_commitment", ""),
                })
                return {"success": True, "rotation": dict(active_rotation)}
            if method == "group.e2ee.heartbeat_rotation":
                return {"success": True, "rotation": dict(active_rotation)}
            if method == "group.e2ee.ack_rotation_key":
                return {"success": True}
            if method == "group.e2ee.commit_rotation":
                return {
                    "success": True,
                    "epoch": active_rotation.get("target_epoch", 2),
                    "rotation": {**active_rotation, "status": "committed"},
                }
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.get_join_requirements":
                return {"group_id": _GRP, "join_requirements": {"mode": join_mode}}
            if method == "message.send":
                return {"ok": True}
            raise Exception(f"unmocked: {method}")

        monkeypatch.setattr(client, "call", fake_call)
        return client, rpc_log

    def test_calls_cas_rpcs(self, tmp_path, monkeypatch):
        """_rotate_group_epoch 必须依次调 get_epoch → begin → ack → commit"""
        client, rpc_log = self._setup(tmp_path, monkeypatch)
        asyncio.run(client._rotate_group_epoch(_GRP))

        methods = [r["method"] for r in rpc_log]
        assert "group.e2ee.get_epoch" in methods
        assert "group.e2ee.begin_rotation" in methods
        assert "group.e2ee.ack_rotation_key" in methods
        assert "group.e2ee.commit_rotation" in methods
        idx_get = methods.index("group.e2ee.get_epoch")
        idx_begin = methods.index("group.e2ee.begin_rotation")
        idx_ack = methods.index("group.e2ee.ack_rotation_key")
        idx_commit = methods.index("group.e2ee.commit_rotation")
        assert idx_get < idx_begin < idx_ack < idx_commit

    def test_cas_success_distributes(self, tmp_path, monkeypatch):
        """begin 成功 → 分发 → self-ack → commit → 本地 key 转为 committed"""
        client, rpc_log = self._setup(tmp_path, monkeypatch)
        asyncio.run(client._rotate_group_epoch(_GRP))

        # 应调 message.send 分发给 Bob
        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert len(sends) >= 1
        assert sends[0]["params"]["to"] == _AID_BOB
        # 本地 epoch 已更新
        assert client._group_e2ee.current_epoch(_GRP) == 2

    def test_private_rotation_does_not_upload_encrypted_keys(self, tmp_path, monkeypatch):
        """非 open/invite code 群 commit 不应携带服务端托管 epoch key。"""
        client, rpc_log = self._setup(tmp_path, monkeypatch, join_mode="approval")
        asyncio.run(client._rotate_group_epoch(_GRP))

        commit_params = next(r["params"] for r in rpc_log if r["method"] == "group.e2ee.commit_rotation")
        assert "encrypted_keys" not in commit_params

    def test_open_rotation_uploads_encrypted_keys(self, tmp_path, monkeypatch):
        """open 群 commit 可携带 per-member ECIES epoch key。"""
        client, rpc_log = self._setup(tmp_path, monkeypatch, join_mode="open")
        asyncio.run(client._rotate_group_epoch(_GRP))

        commit_params = next(r["params"] for r in rpc_log if r["method"] == "group.e2ee.commit_rotation")
        assert set(commit_params.get("encrypted_keys", {}).keys()) == set(_MEMBERS)

    def test_cas_failure_no_distribute(self, tmp_path, monkeypatch):
        """begin 失败 → 不分发、不 ack、不 commit"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []

        async def fake_call(method, params=None):
            params = params or {}
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1, "group_id": _GRP}
            if method == "group.e2ee.begin_rotation":
                return {"success": False, "rotation": None}
            raise Exception(f"unmocked: {method}")

        monkeypatch.setattr(client, "call", fake_call)
        asyncio.run(client._rotate_group_epoch(_GRP))

        # 不应有 message.send（不分发）
        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert len(sends) == 0
        assert "group.e2ee.ack_rotation_key" not in [r["method"] for r in rpc_log]
        assert "group.e2ee.commit_rotation" not in [r["method"] for r in rpc_log]

    def test_membership_change_aborts_stale_pending_and_restarts(self, tmp_path, monkeypatch):
        """pending 期间成员又变化：旧 expected_members 过期，应 abort 后用最新成员重新 begin。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []
        now_ms = int(time.time() * 1000)
        old_pending = {
            "rotation_id": "rot-old",
            "group_id": _GRP,
            "base_epoch": 1,
            "target_epoch": 2,
            "status": "distributing",
            "expected_members": [_AID_ALICE, _AID_BOB],
            "key_commitment": "old-commitment",
            "lease_expires_at": now_ms + 60000,
        }
        active_rotation = {}

        async def fake_call(method, params=None):
            params = params or {}
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                    {"aid": _AID_CAROL, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 1,
                    "committed_epoch": 1,
                    "pending_rotation": dict(old_pending),
                }
            if method == "group.e2ee.abort_rotation":
                return {"success": True, "rotation": {**old_pending, "status": "aborted"}}
            if method == "group.e2ee.begin_rotation":
                active_rotation.clear()
                active_rotation.update({
                    "rotation_id": params["rotation_id"],
                    "group_id": _GRP,
                    "base_epoch": params["base_epoch"],
                    "target_epoch": params["target_epoch"],
                    "status": "distributing",
                    "key_commitment": params["key_commitment"],
                })
                return {"success": True, "rotation": dict(active_rotation)}
            if method == "message.send":
                return {"ok": True}
            if method == "group.e2ee.heartbeat_rotation":
                return {"success": True, "rotation": dict(active_rotation)}
            if method == "group.e2ee.ack_rotation_key":
                return {"success": True}
            if method == "group.e2ee.commit_rotation":
                return {
                    "success": True,
                    "epoch": 2,
                    "committed_epoch": 2,
                    "rotation": {**active_rotation, "status": "committed"},
                }
            raise AssertionError(f"unmocked: {method}")

        monkeypatch.setattr(client, "call", fake_call)
        asyncio.run(client._rotate_group_epoch(
            _GRP,
            reason="membership_changed",
            trigger_id="join-carol",
            expected_epoch=1,
        ))

        methods = [r["method"] for r in rpc_log]
        assert methods.index("group.e2ee.abort_rotation") < methods.index("group.e2ee.begin_rotation")
        assert "group.e2ee.commit_rotation" in methods
        abort_params = next(r["params"] for r in rpc_log if r["method"] == "group.e2ee.abort_rotation")
        assert abort_params["rotation_id"] == "rot-old"
        assert abort_params["reason"] == "membership_changed_during_rotation"

        begin_params = next(r["params"] for r in rpc_log if r["method"] == "group.e2ee.begin_rotation")
        assert begin_params["base_epoch"] == 1
        assert begin_params["target_epoch"] == 2
        assert begin_params["expected_members"] == sorted([_AID_ALICE, _AID_BOB, _AID_CAROL])
        assert "join-carol" in client._group_membership_rotation_done

    def test_membership_change_keeps_non_stale_pending_and_retries(self, tmp_path, monkeypatch):
        """pending 的 expected_members 仍匹配当前成员时，不应抢跑新轮换，只排队重试。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []
        retry_calls = []
        pending = {
            "rotation_id": "rot-active",
            "group_id": _GRP,
            "base_epoch": 1,
            "target_epoch": 2,
            "status": "distributing",
            "expected_members": [_AID_ALICE, _AID_BOB],
            "lease_expires_at": int(time.time() * 1000) + 60000,
        }

        async def fake_call(method, params=None):
            params = params or {}
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1, "pending_rotation": dict(pending)}
            raise AssertionError(f"unmocked: {method}")

        def fake_schedule(group_id, **kwargs):
            retry_calls.append({"group_id": group_id, **kwargs})

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_schedule_group_rotation_retry", fake_schedule)
        asyncio.run(client._rotate_group_epoch(
            _GRP,
            reason="membership_changed",
            trigger_id="member-update",
            expected_epoch=1,
        ))

        methods = [r["method"] for r in rpc_log]
        assert "group.e2ee.abort_rotation" not in methods
        assert "group.e2ee.begin_rotation" not in methods
        assert "message.send" not in methods
        assert len(retry_calls) == 1
        assert retry_calls[0]["pending"]["rotation_id"] == "rot-active"

    def test_begin_race_with_stale_pending_aborts_and_schedules_retry(self, tmp_path, monkeypatch):
        """get_epoch 未见 pending，但 begin 时撞上 stale pending：应 abort 并排队重试，不能分发新 key。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []
        retry_calls = []
        stale_rotation = {
            "rotation_id": "rot-race-stale",
            "group_id": _GRP,
            "base_epoch": 1,
            "target_epoch": 2,
            "status": "distributing",
            "expected_members": [_AID_ALICE, _AID_BOB],
            "lease_expires_at": int(time.time() * 1000) + 60000,
        }

        async def fake_call(method, params=None):
            params = params or {}
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                    {"aid": _AID_CAROL, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1, "pending_rotation": None}
            if method == "group.e2ee.begin_rotation":
                return {"success": False, "rotation": dict(stale_rotation)}
            if method == "group.e2ee.abort_rotation":
                return {"success": True, "rotation": {**stale_rotation, "status": "aborted"}}
            raise AssertionError(f"unmocked: {method}")

        def fake_schedule(group_id, **kwargs):
            retry_calls.append({"group_id": group_id, **kwargs})

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_schedule_group_rotation_retry", fake_schedule)
        asyncio.run(client._rotate_group_epoch(
            _GRP,
            reason="membership_changed",
            trigger_id="join-carol-race",
            expected_epoch=1,
        ))

        methods = [r["method"] for r in rpc_log]
        assert methods.index("group.e2ee.begin_rotation") < methods.index("group.e2ee.abort_rotation")
        assert "message.send" not in methods
        assert "group.e2ee.ack_rotation_key" not in methods
        assert "group.e2ee.commit_rotation" not in methods
        assert len(retry_calls) == 1
        assert retry_calls[0]["pending"] is None

        local_pending = client._group_e2ee.load_secret(_GRP, 2)
        assert local_pending is None
        assert client._group_e2ee.load_secret(_GRP, 1) is not None

    def test_distribution_failure_aborts_before_ack_or_commit(self, tmp_path, monkeypatch):
        """begin 成功但 key 分发失败：必须 abort，不能 self-ack 或 commit。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []
        retry_calls = []
        active_rotation = {}

        async def fake_call(method, params=None):
            params = params or {}
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            if method == "group.e2ee.begin_rotation":
                active_rotation.update({
                    "rotation_id": params["rotation_id"],
                    "group_id": _GRP,
                    "base_epoch": 1,
                    "target_epoch": 2,
                    "status": "distributing",
                    "key_commitment": params["key_commitment"],
                })
                return {"success": True, "rotation": dict(active_rotation)}
            if method == "group.e2ee.abort_rotation":
                return {"success": True, "rotation": {**active_rotation, "status": "aborted"}}
            raise AssertionError(f"unmocked: {method}")

        async def fake_distribute(info, *, rotation_id=""):
            return {"sent": [], "failed": [_AID_BOB]}

        def fake_schedule(group_id, **kwargs):
            retry_calls.append({"group_id": group_id, **kwargs})

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_distribute_group_epoch_key", fake_distribute)
        monkeypatch.setattr(client, "_schedule_group_rotation_retry", fake_schedule)
        asyncio.run(client._rotate_group_epoch(_GRP))

        methods = [r["method"] for r in rpc_log]
        assert "group.e2ee.abort_rotation" in methods
        assert "group.e2ee.ack_rotation_key" not in methods
        assert "group.e2ee.commit_rotation" not in methods
        assert len(retry_calls) == 1
        assert retry_calls[0]["pending"] is None

    def test_commit_failure_keeps_pending_key_and_schedules_retry(self, tmp_path, monkeypatch):
        """commit 失败后本地 target epoch 仍是 pending key，只能等待后续重试/恢复。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []
        retry_calls = []
        active_rotation = {}

        async def fake_call(method, params=None):
            params = params or {}
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            if method == "group.e2ee.begin_rotation":
                active_rotation.update({
                    "rotation_id": params["rotation_id"],
                    "group_id": _GRP,
                    "base_epoch": 1,
                    "target_epoch": 2,
                    "status": "distributing",
                    "key_commitment": params["key_commitment"],
                })
                return {"success": True, "rotation": dict(active_rotation)}
            if method == "message.send":
                return {"ok": True}
            if method == "group.e2ee.heartbeat_rotation":
                return {"success": True, "rotation": dict(active_rotation)}
            if method == "group.e2ee.ack_rotation_key":
                return {"success": True}
            if method == "group.e2ee.commit_rotation":
                return {
                    "success": False,
                    "reason": "missing_required_acks",
                    "rotation": {**active_rotation, "status": "aborted"},
                }
            raise AssertionError(f"unmocked: {method}")

        def fake_schedule(group_id, **kwargs):
            retry_calls.append({"group_id": group_id, **kwargs})

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_schedule_group_rotation_retry", fake_schedule)
        asyncio.run(client._rotate_group_epoch(_GRP))

        methods = [r["method"] for r in rpc_log]
        assert "group.e2ee.commit_rotation" in methods
        assert len(retry_calls) == 1
        assert retry_calls[0]["pending"]["rotation_id"] == active_rotation["rotation_id"]

        local_pending = client._group_e2ee.load_secret(_GRP, 2)
        assert local_pending is None
        assert client._group_e2ee.load_secret(_GRP, 1) is not None

    def test_kick_waits_for_member_removed_event_to_rotate(self, tmp_path, monkeypatch):
        """group.kick 成功返回后通过 RPC 兜底触发一次 CAS 轮换。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def track_rotate(group_id, *args, **kwargs):
            rotate_called.append(group_id)

        monkeypatch.setattr(client, "_rotate_group_epoch", track_rotate)

        async def fake_transport_call(method, params=None):
            if method == "group.kick":
                return {"group": {"group_id": _GRP}}
            if method == "group.get_members":
                return {
                    "members": [
                        {"aid": _AID_ALICE, "role": "admin"},
                        {"aid": _AID_BOB, "role": "member"},
                    ]
                }
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport_call)

        async def run():
            await client.call("group.kick", {"group_id": _GRP, "aid": _AID_BOB})
            await asyncio.sleep(0.2)
            assert rotate_called == [_GRP], "group.kick 成功后应触发一次轮换兜底"

        asyncio.run(run())

    def test_leave_triggers_cas_rotation(self, tmp_path, monkeypatch):
        """group.leave 后离开者不轮换；收到 group.changed(member_left) 事件时自动触发 CAS 轮换"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def track_rotate(group_id, *args, **kwargs):
            rotate_called.append(group_id)

        monkeypatch.setattr(client, "_rotate_group_epoch", track_rotate)

        async def fake_transport_call(method, params=None):
            if method == "group.leave":
                return {"group": {"group_id": _GRP}, "left_aid": _AID_ALICE}
            if method == "group.get_members":
                # Alice 已离开，不再参与轮换
                return {
                    "members": [
                        {"aid": _AID_BOB, "role": "admin"},
                    ]
                }
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport_call)

        async def run():
            # 1. group.leave 本身不应触发轮换
            await client.call("group.leave", {"group_id": _GRP})
            await asyncio.sleep(0.2)
            assert _GRP not in rotate_called, "离开者自身不应触发轮换"

        asyncio.run(run())

        remaining = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(remaining, epoch=1)
        remaining_rotated = []

        async def track_remaining_rotate(group_id, *args, **kwargs):
            remaining_rotated.append(group_id)

        monkeypatch.setattr(remaining, "_rotate_group_epoch", track_remaining_rotate)

        async def fake_remaining_transport_call(method, params=None):
            if method == "group.get_members":
                return {"members": [{"aid": _AID_BOB, "role": "admin"}]}
            return {}

        monkeypatch.setattr(remaining._transport, "call", fake_remaining_transport_call)

        async def remaining_run():
            await remaining._on_raw_group_changed({
                "module_id": "group",
                "action": "member_left",
                "group_id": _GRP,
                "old_epoch": 1,
            })
            await asyncio.sleep(0.2)

        asyncio.run(remaining_run())
        assert remaining_rotated == [_GRP], "剩余 admin 收到 member_left 事件后应触发轮换"

    def test_member_left_only_admin_rotates(self, tmp_path, monkeypatch):
        """收到 member_left/member_removed 事件时，仅 admin/owner 触发轮换，普通 member 不触发"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def track_rotate(group_id, *args, **kwargs):
            rotate_called.append(group_id)

        monkeypatch.setattr(client, "_rotate_group_epoch", track_rotate)

        async def fake_transport_call(method, params=None):
            if method == "group.get_members":
                # 模拟返回成员列表：bob 是 owner，alice 是普通 member
                return {
                    "members": [
                        {"aid": _AID_BOB, "role": "owner"},
                        {"aid": _AID_ALICE, "role": "member"},
                    ]
                }
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport_call)

        async def run():
            # 普通 member 收到 member_removed 事件 → 不应触发轮换
            await client._on_raw_group_changed({
                "module_id": "group",
                "action": "member_removed",
                "group_id": _GRP,
            })
            await asyncio.sleep(0.2)
            assert _GRP not in rotate_called, "普通 member 不应触发轮换"

        asyncio.run(run())


# ══════════════════════════════════════════════════════════════
# 自动编排完整测试
# ══════════════════════════════════════════════════════════════

class TestAutoOrchestrationCreate:
    def test_create_auto_epoch(self, tmp_path, monkeypatch):
        """group.create 成功后自动 create_epoch"""
        client = _make_client(tmp_path, aid=_AID_ALICE)

        async def fake_call(method, params):
            if method == "group.create":
                return {"group": {"group_id": _GRP}}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_call)
        asyncio.run(client.call("group.create", {"name": "test"}))

        assert client._group_e2ee.has_secret(_GRP)
        assert client._group_e2ee.current_epoch(_GRP) == 1

    def test_create_idempotent(self, tmp_path, monkeypatch):
        """重复 group.create 不覆盖已有 secret"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=3)

        async def fake_call(method, params):
            if method == "group.create":
                return {"group": {"group_id": _GRP}}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_call)
        asyncio.run(client.call("group.create", {"name": "test"}))

        # epoch 仍为 3，不应被重置为 1
        assert client._group_e2ee.current_epoch(_GRP) == 3


class TestAutoOrchestrationAddMember:
    def test_add_member_distributes_with_server_members(self, tmp_path, monkeypatch):
        """add_member 补发时先拉服务端成员列表、更新本地、再分发"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        gs = _store_secret_for_client(client, epoch=1)
        local_secret = load_group_secret(client._keystore, _AID_ALICE, _GRP)
        assert local_secret is not None
        epoch_chain = "11" * 32
        store_group_secret(
            client._keystore,
            _AID_ALICE,
            _GRP,
            1,
            gs,
            local_secret["commitment"],
            _MEMBERS,
            epoch_chain=epoch_chain,
            allow_pending_overwrite=True,
        )

        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "message.send":
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "call", fake_call)

        # 直接调用 _distribute_key_to_new_member（绕过 create_task）
        asyncio.run(client._distribute_key_to_new_member(_GRP, _AID_BOB))

        methods = [r["method"] for r in rpc_log]
        assert "group.get_members" in methods
        assert "message.send" in methods
        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert any(s["params"]["to"] == _AID_BOB for s in sends)
        assert all(s["params"].get("persist_required") is True for s in sends)
        assert all(s["params"]["payload"].get("epoch_chain") == epoch_chain for s in sends)

        # 验证本地 member_aids 已更新
        local = client._group_e2ee.get_member_aids(_GRP)
        assert _AID_ALICE in local
        assert _AID_BOB in local

    def test_add_member_triggers_epoch_rotation(self, tmp_path, monkeypatch):
        """成员加入默认走 CAS 轮换而非补发当前 epoch"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._aid = _AID_ALICE
        client._identity = {"aid": _AID_ALICE}
        client._state = "connected"
        _store_secret_for_client(client, epoch=1)

        rotate_called = []

        async def mock_rotate(gid, *args, **kwargs):
            rotate_called.append(gid)

        monkeypatch.setattr(client, "_rotate_group_epoch", mock_rotate)

        async def fake_transport(method, params):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            return {"ok": True}
        monkeypatch.setattr(client._transport, "call", fake_transport)

        asyncio.run(client.call("group.add_member", {"group_id": _GRP, "aid": _AID_BOB}))
        asyncio.run(asyncio.sleep(0.1))

        assert _GRP in rotate_called


class TestAutoOrchestrationReview:
    def test_review_approved_distributes(self, tmp_path, monkeypatch):
        """review_join_request approved → 分发密钥"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)

        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append({"method": method, "params": params})
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "message.send":
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "call", fake_call)
        asyncio.run(client._distribute_key_to_new_member(_GRP, _AID_BOB))

        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert len(sends) >= 1
        assert all(s["params"].get("persist_required") is True for s in sends)

    def test_review_rejected_no_distribute(self, tmp_path, monkeypatch):
        """review_join_request rejected → 不分发"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)

        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append({"method": method})
            if method == "group.review_join_request":
                return {"approved": False, "status": "rejected"}
            return {}

        monkeypatch.setattr(client, "call", fake_call)

        async def run():
            await client.call("group.review_join_request", {
                "group_id": _GRP, "aid": _AID_BOB, "approve": False,
            })
            await asyncio.sleep(0.2)

        asyncio.run(run())

        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert len(sends) == 0


class TestAutoOrchestrationBatchReview:
    def test_batch_review_distributes_to_approved_only(self, tmp_path, monkeypatch):
        """batch_review 只要有 approved 成员就触发 epoch 轮换，不补发旧 epoch 密钥"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        _CAROL = "carol.agentid.pub"

        rotated = []
        distributed = []

        async def track_rotate(group_id, *args, **kwargs):
            rotated.append(group_id)

        async def track_distribute(group_id, new_aid):
            distributed.append(new_aid)

        monkeypatch.setattr(client, "_rotate_group_epoch", track_rotate)
        monkeypatch.setattr(client, "_distribute_key_to_new_member", track_distribute)

        async def fake_transport(method, params):
            if method == "group.batch_review_join_request":
                return {"results": [
                    {"aid": _AID_BOB, "ok": True, "status": "approved"},
                    {"aid": _CAROL, "ok": True, "status": "rejected"},
                ]}
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        async def run():
            await client.call("group.batch_review_join_request", {
                "group_id": _GRP,
                "requests": [
                    {"aid": _AID_BOB, "approve": True},
                    {"aid": _CAROL, "approve": False, "reason": "rejected"},
                ],
            })
            await asyncio.sleep(0.2)

        asyncio.run(run())

        assert rotated == [_GRP]
        assert distributed == []

    def test_batch_review_triggers_epoch_rotation(self, tmp_path, monkeypatch):
        """batch_review 批准成员加入时默认触发轮换而非补发当前 epoch"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)

        rotated = []
        distributed = []

        async def track_rotate(group_id, *args, **kwargs):
            rotated.append(group_id)

        async def track_distribute(group_id, new_aid):
            distributed.append(new_aid)

        monkeypatch.setattr(client, "_rotate_group_epoch", track_rotate)
        monkeypatch.setattr(client, "_distribute_key_to_new_member", track_distribute)

        async def fake_transport(method, params):
            if method == "group.batch_review_join_request":
                return {"results": [
                    {"aid": _AID_BOB, "ok": True, "status": "approved"},
                    {"aid": "carol.agentid.pub", "ok": True, "status": "approved"},
                ]}
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                    {"aid": "carol.agentid.pub", "role": "member"},
                ]}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        async def run():
            await client.call("group.batch_review_join_request", {
                "group_id": _GRP,
                "requests": [
                    {"aid": _AID_BOB, "approve": True},
                    {"aid": "carol.agentid.pub", "approve": True},
                ],
            })
            await asyncio.sleep(0.2)

        asyncio.run(run())

        assert _GRP in rotated
        assert len(distributed) == 0  # 不应该补发


class TestAutoOrchestrationErrorObservability:
    def test_error_publishes_event(self, tmp_path, monkeypatch):
        """自动编排失败时发布 e2ee.orchestration_error 事件"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        errors = []
        client.on("e2ee.orchestration_error", lambda data: errors.append(data))

        # 直接调用 _log_e2ee_error 验证事件发布
        async def run():
            client._loop = asyncio.get_running_loop()
            client._log_e2ee_error("test_stage", "grp_fail", "bob", RuntimeError("test"))
            await asyncio.sleep(0.1)

        asyncio.run(run())

        assert len(errors) >= 1
        assert errors[0]["stage"] == "test_stage"
        assert "test" in errors[0]["error"]


class TestKeyRequestFallbackToServer:
    """group_key_request 响应端：请求者不在本地成员列表时回源查询服务端"""

    def test_unknown_requester_triggers_server_lookup(self, tmp_path, monkeypatch):
        """P0 历史隔离：Carol 是当前成员但不在 epoch 1 的 member_aids 中，
        回源查询服务端确认当前成员身份，但因 epoch 成员校验拒绝响应。"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        gs = _store_secret_for_client(client, epoch=1)
        _CAROL = "carol.agentid.pub"

        # Carol 不在本地 member_aids（只有 alice, bob）
        assert _CAROL not in _MEMBERS

        server_lookup_called = []
        sent_messages = []

        async def fake_transport(method, params):
            if method == "group.get_members":
                server_lookup_called.append(params)
                return {"members": [
                    {"aid": _AID_ALICE}, {"aid": _AID_BOB}, {"aid": _CAROL},
                ]}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        # mock _send_encrypted 避免 P2P E2EE 依赖
        async def fake_send_encrypted(params):
            sent_messages.append(params)
            return {}

        monkeypatch.setattr(client, "_send_encrypted", fake_send_encrypted)

        # 模拟 Carol 发送 group_key_request
        request_payload = {
            "type": "e2ee.group_key_request",
            "group_id": _GRP,
            "epoch": 1,
            "requester_aid": _CAROL,
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._try_handle_group_key_message({"payload": request_payload})

        asyncio.run(run())

        # 验证：回源查询了服务端（确认 Carol 是当前成员）
        assert len(server_lookup_called) == 1
        assert server_lookup_called[0]["group_id"] == _GRP
        # 验证：因 epoch 成员校验拒绝响应（Carol 不属于 epoch 1 成员集）
        assert len(sent_messages) == 0

    def test_known_requester_no_server_lookup(self, tmp_path, monkeypatch):
        """请求者已在本地 member_aids，不应回源查询"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        gs = _store_secret_for_client(client, epoch=1)

        server_lookup_called = []
        sent_messages = []

        async def fake_transport(method, params):
            if method == "group.get_members":
                server_lookup_called.append(params)
                return {"members": [{"aid": _AID_ALICE}, {"aid": _AID_BOB}]}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        async def fake_send_encrypted(params):
            sent_messages.append(params)
            return {}

        monkeypatch.setattr(client, "_send_encrypted", fake_send_encrypted)

        # Bob 在本地 member_aids 中
        request_payload = {
            "type": "e2ee.group_key_request",
            "group_id": _GRP,
            "epoch": 1,
            "requester_aid": _AID_BOB,
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._try_handle_group_key_message({"payload": request_payload})

        asyncio.run(run())

        # 验证：没有回源查询
        assert len(server_lookup_called) == 0
        # 验证：正常响应了
        assert len(sent_messages) == 1
        assert sent_messages[0]["to"] == _AID_BOB

    def test_non_member_rejected_even_after_lookup(self, tmp_path, monkeypatch):
        """请求者不在本地也不在服务端成员列表，应拒绝响应"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        gs = _store_secret_for_client(client, epoch=1)
        _DAVE = "dave.agentid.pub"

        sent_messages = []

        async def fake_transport(method, params):
            if method == "group.get_members":
                # 服务端也不包含 Dave
                return {"members": [{"aid": _AID_ALICE}, {"aid": _AID_BOB}]}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        async def fake_send_encrypted(params):
            sent_messages.append(params)
            return {}

        monkeypatch.setattr(client, "_send_encrypted", fake_send_encrypted)

        request_payload = {
            "type": "e2ee.group_key_request",
            "group_id": _GRP,
            "epoch": 1,
            "requester_aid": _DAVE,
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._try_handle_group_key_message({"payload": request_payload})

        asyncio.run(run())

        # 验证：没有发送响应（Dave 不是成员）
        assert len(sent_messages) == 0


# ── 群消息推送管道 ─────────────────────────────────────

class TestGroupMessagePushPipeline:
    """测试 group.message_created 事件推送管道。"""

    def _make_encrypted_group_msg(self, gs, from_aid=_AID_ALICE, seq=1):
        pk_pem, _ = _get_signing_identity(from_aid)
        msg_id = f"gm-{uuid.uuid4()}"
        ts = 1710504000000
        envelope = encrypt_group_message(
            group_id=_GRP, epoch=1, group_secret=gs,
            payload={"type": "text", "text": "推送消息"}, from_aid=from_aid,
            message_id=msg_id, timestamp=ts,
            sender_private_key_pem=pk_pem,
        )
        return {
            "group_id": _GRP,
            "seq": seq,
            "from": from_aid,
            "sender_aid": from_aid,
            "message_id": msg_id,
            "timestamp": ts,
            "payload": envelope,
            "encrypted": True,
        }

    def test_push_with_payload_decrypts_and_updates_seq(self, tmp_path):
        """带 payload 的推送事件：自动解密 + 更新本地游标。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        published = []
        client._dispatcher.subscribe("group.message_created", lambda data: published.append(data))

        msg = self._make_encrypted_group_msg(gs, seq=1)

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(msg)

        asyncio.run(run())

        assert len(published) == 1
        assert published[0]["payload"] == {
            "type": "text",
            "text": "推送消息",
            "dispatch_mode": "broadcast",
        }
        assert published[0]["e2ee"]["encryption_mode"] == "epoch_group_key"
        # 游标更新
        ns = f"group:{_GRP}"
        assert client._seq_tracker.get_contiguous_seq(ns) == 1
        assert client._seq_tracker.get_max_seen_seq(ns) == 1

    def test_push_without_payload_triggers_auto_pull(self, tmp_path):
        """不带 payload 的通知：触发 auto pull。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        published = []
        client._dispatcher.subscribe("group.message_created", lambda data: published.append(data))

        # mock group.pull 返回
        pull_msg = self._make_encrypted_group_msg(gs, seq=1)
        pull_called = {}

        async def fake_call(method, params):
            if method == "group.pull":
                pull_called["params"] = params
                return {"messages": [pull_msg]}
            return {}

        client._transport.call = fake_call

        notification = {
            "module_id": "group",
            "group_id": _GRP,
            "seq": 1,
            "message_id": "gm-notify",
            "sender_aid": _AID_ALICE,
            "type": "text",
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(notification)

        asyncio.run(run())

        # 验证 pull 被调用
        assert "params" in pull_called
        assert pull_called["params"]["group_id"] == _GRP
        # 验证 pull 的消息被发布
        assert len(published) >= 1

    def test_auto_pull_uses_local_cursor(self, tmp_path):
        """auto pull 使用本地游标 after_message_seq。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(client, epoch=1)
        # 模拟已知 seq = 10（通过 seq_tracker 录入 1..10）
        for s in range(1, 11):
            client._seq_tracker.on_message_seq(f"group:{_GRP}", s)

        pull_called = {}

        async def fake_call(method, params):
            if method == "group.pull":
                pull_called["params"] = params
                return {"messages": []}
            return {}

        import types
        client.call = types.MethodType(lambda self, m, p: fake_call(m, p), client)

        notification = {
            "group_id": _GRP,
            "seq": 12,
            "sender_aid": _AID_ALICE,
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._auto_pull_group_messages(notification)

        asyncio.run(run())

        assert pull_called["params"]["after_message_seq"] == 10

    def test_notification_auto_pull_does_not_advance_notified_seq(self, tmp_path):
        """无 payload 通知只触发 pull，不应先推进通知 seq。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(client, epoch=1)

        pull_called = {}

        async def fake_call(method, params):
            if method == "group.pull":
                pull_called["params"] = params
                return {"messages": []}
            return {}

        import types
        client.call = types.MethodType(lambda self, m, p: fake_call(m, p), client)

        notification = {
            "group_id": _GRP,
            "seq": 1,
            "sender_aid": _AID_ALICE,
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(notification)

        asyncio.run(run())

        assert pull_called["params"]["after_message_seq"] == 0
        assert client._seq_tracker.get_contiguous_seq(f"group:{_GRP}") == 0

    def test_seq_tracking_across_push_messages(self, tmp_path):
        """多条推送消息后 SeqTracker 正确跟踪序列号。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        for seq in [1, 3, 5, 2]:  # 无序到达
            msg = self._make_encrypted_group_msg(gs, seq=seq)
            asyncio.run(client._process_and_publish_group_message(msg))

        ns = "group:" + _GRP
        # seq=1 正常推进, seq=3 记入 received, seq=5 记入 received,
        # seq=2 推进到 2 → received 有 3 → 推到 3（4 缺失停止）
        assert client._seq_tracker.get_contiguous_seq(ns) == 3
        assert client._seq_tracker.get_max_seen_seq(ns) == 5

    def test_notification_with_empty_payload_triggers_pull(self, tmp_path):
        """payload 为空 dict 也视为通知，触发 auto pull。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(client, epoch=1)

        pull_called = {}

        async def fake_call(method, params):
            if method == "group.pull":
                pull_called["called"] = True
                return {"messages": []}
            return {}

        import types
        client.call = types.MethodType(lambda self, m, p: fake_call(m, p), client)

        notification = {
            "group_id": _GRP,
            "seq": 1,
            "sender_aid": _AID_ALICE,
            "payload": {},  # 空 payload
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(notification)

        asyncio.run(run())

        assert pull_called.get("called") is True

    def test_push_with_payload_gap_is_pending_until_gap_pull_fills_contiguous(self, tmp_path):
        """带完整 payload 的 push 发现 gap 时应先挂起，补洞 pull 后再按序发布。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        published = []
        client._dispatcher.subscribe("group.message_created", lambda data: published.append(data))
        # 已知 seq=1，下一条 seq=3 → gap [2]
        client._seq_tracker.on_message_seq(f"group:{_GRP}", 1)

        fill_gap_called = []
        fill_gap_done = asyncio.Event()
        original_fill_group_gap = AUNClient._fill_group_gap.__get__(client, AUNClient)

        async def fake_fill_group_gap(group_id):
            fill_gap_called.append(group_id)
            fill_gap_done.set()

        client._fill_group_gap = fake_fill_group_gap

        msg = self._make_encrypted_group_msg(gs, seq=3)

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(msg)
            await asyncio.wait_for(fill_gap_done.wait(), timeout=1)

        asyncio.run(run())

        # gap 未补齐前不应直接发布
        assert published == []
        # 补洞必须被触发
        assert fill_gap_called == [_GRP]

        async def fake_call(method, params):
            if method == "group.pull":
                pulled = [
                    {"group_id": _GRP, "seq": 2, "from": _AID_ALICE,
                     "payload": {"type": "text", "text": "二"}},
                    {"group_id": _GRP, "seq": 3, "from": _AID_ALICE,
                     "payload": {"type": "text", "text": "三"}},
                ]
                client._seq_tracker.on_pull_result(f"group:{_GRP}", pulled)
                return {"messages": pulled}
            return {}

        async def run_release_by_pull():
            client._loop = asyncio.get_running_loop()
            client.call = fake_call
            client._fill_group_gap = original_fill_group_gap
            await client._fill_group_gap(_GRP)

        asyncio.run(run_release_by_pull())

        assert [m["seq"] for m in published] == [2, 3]
        assert f"group:{_GRP}" not in client._pending_ordered_msgs

    def test_group_pull_decrypt_skips_replay_after_pending_push(self, tmp_path):
        """push 已解密但因 gap 挂起时，后续 group.pull 不应被本地 replay guard 吃掉。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        published = []
        client._dispatcher.subscribe("group.message_created", lambda data: published.append(data))
        # 已知 seq=1，seq=3 会因缺 seq=2 被挂起；解密时已记录 replay guard。
        client._seq_tracker.on_message_seq(f"group:{_GRP}", 1)

        async def fake_fill_group_gap(group_id):
            return None

        client._fill_group_gap = fake_fill_group_gap
        msg = self._make_encrypted_group_msg(gs, seq=3)

        async def run_push_then_pull():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(msg)
            pulled = await client._decrypt_group_messages([msg])
            return pulled

        pulled = asyncio.run(run_push_then_pull())

        assert published == []
        assert 3 in client._pending_ordered_msgs[f"group:{_GRP}"]
        assert len(pulled) == 1
        assert pulled[0].get("e2ee", {}).get("encryption_mode") == "epoch_group_key"

    def test_gap_pull_uses_republish_guard_after_pending_push(self, tmp_path):
        """push 挂起后 pull 补洞重取同一 seq，应只按序发布一次。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        published = []
        client._dispatcher.subscribe("group.message_created", lambda data: published.append(data))
        ns = f"group:{_GRP}"
        client._seq_tracker.on_message_seq(ns, 1)

        async def fake_fill_group_gap(group_id):
            return None

        client._fill_group_gap = fake_fill_group_gap
        msg2 = self._make_encrypted_group_msg(gs, seq=2)
        msg3 = self._make_encrypted_group_msg(gs, seq=3)

        async def run_push_then_gap_pull():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(msg3)
            assert published == []
            pulled = await client._decrypt_group_messages([msg2, msg3])
            client._seq_tracker.on_pull_result(ns, pulled)
            for msg in pulled:
                await client._publish_ordered_message(
                    "group.message_created",
                    ns,
                    msg["seq"],
                    msg,
                )
            # 后续重复 pull 同一个窗口，不应重复发布 seq=2/3。
            replayed = await client._decrypt_group_messages([msg2, msg3])
            client._seq_tracker.on_pull_result(ns, replayed)
            for msg in replayed:
                await client._publish_ordered_message(
                    "group.message_created",
                    ns,
                    msg["seq"],
                    msg,
                )

        asyncio.run(run_push_then_gap_pull())

        assert [m["seq"] for m in published] == [2, 3]
        assert client._is_published_seq(ns, 2) is True
        assert client._is_published_seq(ns, 3) is True

    def test_duplicate_pending_push_is_republish_guarded(self, tmp_path):
        """同一 seq 已解密挂起后重复 push，不应触发 replay 失败副作用。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        published = []
        undecryptable = []
        client._dispatcher.subscribe("group.message_created", lambda data: published.append(data))
        client._dispatcher.subscribe("group.message_undecryptable", lambda data: undecryptable.append(data))
        ns = f"group:{_GRP}"
        client._seq_tracker.on_message_seq(ns, 1)

        async def fake_fill_group_gap(group_id):
            return None

        client._fill_group_gap = fake_fill_group_gap
        msg = self._make_encrypted_group_msg(gs, seq=3)

        async def run_duplicate_push():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(msg)
            await client._process_and_publish_group_message(msg)

        asyncio.run(run_duplicate_push())

        assert published == []
        assert undecryptable == []
        assert 3 in client._pending_ordered_msgs[ns]


# ══════════════════════════════════════════════════════════════
# replay guard 语义测试
# ══════════════════════════════════════════════════════════════

class TestReplayGuardSemantics:
    """接收侧 replay guard 使用 SDK 实例内本地 seen set。"""

    def test_duplicate_returns_false(self, tmp_path):
        """同一 group/sender/message_id 第二次记录应被判定为重放。"""
        guard = GroupReplayGuard()
        assert guard.check_and_record(_GRP, _AID_ALICE, "msg-dup-1") is True
        assert guard.check_and_record(_GRP, _AID_ALICE, "msg-dup-1") is False

    def test_non_duplicate_returns_true(self, tmp_path):
        """不同 message_id 应正常通过本地 replay guard。"""
        guard = GroupReplayGuard()
        assert guard.check_and_record(_GRP, _AID_ALICE, "msg-new-1") is True
        assert guard.check_and_record(_GRP, _AID_ALICE, "msg-new-2") is True

    def test_rpc_exception_fail_open_returns_true(self, tmp_path):
        """接收侧不再调用服务端 replay guard，传输层异常不影响本地判定。"""
        async def transport_call(method, params=None):
            raise RuntimeError("should not be called")

        client = _make_client(tmp_path, aid=_AID_BOB)
        client._transport.call = transport_call
        assert client._group_e2ee._replay_guard.check_and_record(
            _GRP, _AID_ALICE, "msg-local-1",
        ) is True


class TestGroupPushDecryptFailureAutoAck:
    """group push 解密失败时，若 SeqTracker 已推进 contiguous，仍应发送 group.ack_messages。"""

    def _make_client_with_ack_tracking(self, tmp_path):
        """创建带 ack 追踪的客户端。"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        ack_calls: list[dict] = []

        async def fake_transport_call(method, params=None):
            if method == "group.ack_messages":
                ack_calls.append({"method": method, "params": params})
            return {}

        client._transport.call = fake_transport_call
        client._ack_calls = ack_calls
        return client

    def test_group_push_decrypt_failure_still_auto_acks(self, tmp_path):
        """解密失败仍应 auto-ack，并进入 _pending_decrypt_msgs 等待密钥恢复后补发。"""
        client = self._make_client_with_ack_tracking(tmp_path)

        # mock _decrypt_group_message 让它抛出异常（模拟解密失败）
        async def fake_decrypt_group_message(msg, **kw):
            raise Exception("群消息解密失败：密钥不匹配")

        client._decrypt_group_message = fake_decrypt_group_message

        # 构造一个带 payload 的群消息（seq=1），payload type 为 e2ee.group_encrypted
        msg = {
            "module_id": "group",
            "group_id": _GRP,
            "message_id": "gm-1",
            "from": _AID_ALICE,
            "sender_aid": _AID_ALICE,
            "seq": 1,
            "payload": {"type": "e2ee.group_encrypted", "epoch": 1, "data": "INVALID"},
            "timestamp": 1000,
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(msg)

        asyncio.run(run())

        # contiguous 应已推进到 1
        ns = f"group:{_GRP}"
        assert client._seq_tracker.get_contiguous_seq(ns) == 1

        assert len(client._ack_calls) == 1, (
            f"解密失败时仍应 auto-ack，实际 {len(client._ack_calls)} 次: {client._ack_calls}"
        )
        assert client._ack_calls[0]["params"]["msg_seq"] == 1
        # 消息应进入待重试队列
        pending = client._pending_decrypt_msgs.get(ns, [])
        assert len(pending) == 1, f"解密失败的消息应进入待重试队列，实际 {len(pending)}"

    def test_group_push_decrypt_failure_no_ack_when_contiguous_zero(self, tmp_path):
        """group push 解密失败且 contiguous=0 时，不应发送 ack（避免无效 ack）。"""
        client = self._make_client_with_ack_tracking(tmp_path)

        # mock _decrypt_group_message 让它抛出异常
        async def fake_decrypt_group_message(msg):
            raise Exception("群消息解密失败")

        client._decrypt_group_message = fake_decrypt_group_message

        # seq=None 的消息不会推进 contiguous
        msg = {
            "module_id": "group",
            "group_id": _GRP,
            "message_id": "gm-no-seq",
            "from": _AID_ALICE,
            "sender_aid": _AID_ALICE,
            # 无 seq 字段
            "payload": {"type": "e2ee.group_encrypted", "epoch": 1, "data": "INVALID"},
            "timestamp": 1000,
        }

        async def run():
            client._loop = asyncio.get_running_loop()
            await client._process_and_publish_group_message(msg)

        asyncio.run(run())

        # 没有 seq，contiguous 仍为 0，不应发送 ack
        assert len(client._ack_calls) == 0


class TestGroupEpochRaceHardening:
    def test_membership_trigger_id_prefers_aid_and_epoch_over_event_seq(self, tmp_path):
        payload = {
            "action": "member_added",
            "event_seq": 101,
            "member": {"aid": _AID_CAROL},
            "old_epoch": 2,
        }
        assert AUNClient._membership_rotation_trigger_id(_GRP, payload) == (
            f"{_GRP}:member_added:aid:{_AID_CAROL}:epoch:2"
        )

    def test_membership_trigger_id_batch_review_uses_approved_aid_set(self, tmp_path):
        first = {
            "action": "join_request_reviewed",
            "status": "approved",
            "old_epoch": 3,
            "results": [
                {"status": "approved", "request": {"aid": _AID_BOB}},
                {"status": "rejected", "request": {"aid": "ignored.agentid.pub"}},
            ],
        }
        second = {
            **first,
            "results": [{"status": "approved", "request": {"aid": _AID_CAROL}}],
        }

        assert AUNClient._membership_rotation_trigger_id(_GRP, first) == (
            f"{_GRP}:join_request_reviewed:aid:{_AID_BOB}:epoch:3"
        )
        assert AUNClient._membership_rotation_trigger_id(_GRP, second) == (
            f"{_GRP}:join_request_reviewed:aid:{_AID_CAROL}:epoch:3"
        )

    def test_retry_pending_decrypt_keeps_messages_enqueued_during_retry(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        ns = f"group:{_GRP}"
        first = {
            "group_id": _GRP,
            "seq": 1,
            "payload": {"type": "e2ee.group_encrypted", "epoch": 1},
        }
        second = {
            "group_id": _GRP,
            "seq": 2,
            "payload": {"type": "e2ee.group_encrypted", "epoch": 1},
        }
        client._pending_decrypt_msgs[ns] = [first]

        async def fake_decrypt(msg, **kwargs):
            client._enqueue_pending_decrypt(_GRP, second)
            return {"group_id": _GRP, "seq": msg.get("seq"), "payload": {"type": "text"}, "e2ee": {"ok": True}}

        monkeypatch.setattr(client, "_decrypt_group_message", fake_decrypt)

        asyncio.run(client._retry_pending_decrypt_msgs(_GRP))

        assert client._pending_decrypt_msgs[ns] == [second]

    def test_distribution_without_rotation_id_rejects_future_epoch(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)

        async def fake_call(method, params):
            assert method == "group.e2ee.get_epoch"
            return {"epoch": 1, "committed_epoch": 1, "pending_rotation": None}

        monkeypatch.setattr(client, "call", fake_call)

        accepted = asyncio.run(client._verify_active_group_rotation_distribution({
            "type": "e2ee.group_key_distribution",
            "group_id": _GRP,
            "epoch": 2,
            "commitment": "c2",
        }))

        assert accepted is False

    def test_initial_epoch_zero_with_local_epoch_one_triggers_create_sync(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        client._group_e2ee.create_epoch(_GRP, [_AID_ALICE])
        sync_calls = []
        get_epoch_calls = 0

        async def fake_sync(group_id):
            sync_calls.append(group_id)

        async def fake_call(method, params):
            nonlocal get_epoch_calls
            assert method == "group.e2ee.get_epoch"
            get_epoch_calls += 1
            if get_epoch_calls == 1:
                return {"epoch": 0, "committed_epoch": 0}
            return {"epoch": 1, "committed_epoch": 1}

        monkeypatch.setattr(client, "_sync_epoch_to_server", fake_sync)
        monkeypatch.setattr(client, "call", fake_call)

        asyncio.run(client._ensure_group_epoch_ready(_GRP, strict=False))

        assert sync_calls == [_GRP]
        assert get_epoch_calls == 2

    def test_initial_epoch_zero_with_local_epoch_one_refuses_when_sync_not_completed(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        client._group_e2ee.create_epoch(_GRP, [_AID_ALICE])

        async def fake_sync(group_id):
            return None

        async def fake_call(method, params):
            assert method == "group.e2ee.get_epoch"
            return {"epoch": 0, "committed_epoch": 0}

        monkeypatch.setattr(client, "_sync_epoch_to_server", fake_sync)
        monkeypatch.setattr(client, "call", fake_call)

        with pytest.raises(StateError, match="initial epoch sync has not completed"):
            asyncio.run(client._ensure_group_epoch_ready(_GRP, strict=False))

    def test_local_epoch_behind_server_uses_recovery_inflight_path(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        _store_secret_for_client(client, epoch=1)
        recover_calls = []

        async def fake_call(method, params):
            assert method == "group.e2ee.get_epoch"
            return {"epoch": 2, "committed_epoch": 2}

        async def fake_recover(group_id, epoch, **kwargs):
            recover_calls.append((group_id, epoch, kwargs))
            _store_secret_for_client(client, epoch=2)
            return True

        async def fail_request(*args, **kwargs):
            raise AssertionError("不应绕过 _recover_group_epoch_key 直接发送 P2P 恢复请求")

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_recover_group_epoch_key", fake_recover)
        monkeypatch.setattr(client, "_request_group_key_from_candidates", fail_request)

        asyncio.run(client._ensure_group_epoch_ready(_GRP, strict=False))

        assert recover_calls == [(_GRP, 2, {"timeout_s": _KEY_WAIT_TIMEOUT_S})]

    def test_pending_target_epoch_does_not_trigger_send_recovery(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        _store_secret_for_client(client, epoch=1)
        recover_calls = []

        async def fake_call(method, params):
            assert method == "group.e2ee.get_epoch"
            return {
                "epoch": 2,
                "committed_epoch": 1,
                "pending_rotation": {
                    "rotation_id": "rot-pending",
                    "base_epoch": 1,
                    "target_epoch": 2,
                },
            }

        async def fake_recover(group_id, epoch, **kwargs):
            recover_calls.append((group_id, epoch, kwargs))
            return False

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_recover_group_epoch_key", fake_recover)

        asyncio.run(client._ensure_group_epoch_ready(_GRP, strict=False))

        assert recover_calls == []

    def test_committed_epoch_behind_pending_target_recovers_committed_only(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        _store_secret_for_client(client, epoch=1)
        recover_calls = []

        async def fake_call(method, params):
            assert method == "group.e2ee.get_epoch"
            return {
                "epoch": 3,
                "committed_epoch": 2,
                "pending_rotation": {
                    "rotation_id": "rot-pending",
                    "base_epoch": 2,
                    "target_epoch": 3,
                },
            }

        async def fake_recover(group_id, epoch, **kwargs):
            recover_calls.append((group_id, epoch, kwargs))
            _store_secret_for_client(client, epoch=epoch)
            return True

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_recover_group_epoch_key", fake_recover)

        asyncio.run(client._ensure_group_epoch_ready(_GRP, strict=False))

        assert recover_calls == [(_GRP, 2, {"timeout_s": _KEY_WAIT_TIMEOUT_S})]
        assert client._group_e2ee.current_epoch(_GRP) == 2

    def test_recover_group_epoch_key_ignores_stale_pending_secret(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        get_epoch_calls = []
        recovery_requests = []

        monkeypatch.setattr(
            client._group_e2ee,
            "load_secret",
            lambda group_id, epoch=None: {
                "epoch": epoch,
                "pending_rotation_id": "rot-stale",
                "commitment": "c2",
            },
        )

        async def fake_call(method, params):
            if method == "group.e2ee.get_epoch":
                get_epoch_calls.append(params)
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "committed_rotation": {
                        "rotation_id": "rot-committed",
                        "key_commitment": "c2",
                    },
                }
            if method == "group.get_online_members":
                return {"members": [{"aid": _AID_BOB, "online": True}]}
            raise AssertionError(method)

        async def fake_request(group_id, epoch, online_aids, epoch_result):
            recovery_requests.append((group_id, epoch, online_aids, epoch_result))

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_request_group_key_from_online", fake_request)

        ok = asyncio.run(client._recover_group_epoch_key(_GRP, 2, timeout_s=0))

        assert ok is False
        assert get_epoch_calls
        assert len(recovery_requests) == 1

    def test_recover_group_epoch_key_schedules_pending_retry_after_poll_success(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)
        ns = f"group:{_GRP}"
        client._pending_decrypt_msgs[ns] = [{
            "group_id": _GRP,
            "seq": 7,
            "payload": {"type": "e2ee.group_encrypted", "epoch": 2},
        }]
        load_calls = 0
        scheduled = []

        def fake_load_secret(group_id, epoch=None):
            nonlocal load_calls
            load_calls += 1
            if load_calls == 1:
                return None
            return {"epoch": epoch, "commitment": "c2"}

        async def fake_call(method, params):
            if method == "group.e2ee.get_epoch":
                return {"epoch": 2, "committed_epoch": 2}
            if method == "group.get_online_members":
                return {"members": [{"aid": _AID_BOB, "online": True}]}
            raise AssertionError(method)

        async def fake_request(group_id, epoch, epoch_result, **kwargs):
            return None

        monkeypatch.setattr(client._group_e2ee, "load_secret", fake_load_secret)
        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr(client, "_request_group_key_from_candidates", fake_request)
        monkeypatch.setattr(client, "_schedule_retry_pending_decrypt_msgs", lambda group_id: scheduled.append(group_id))

        ok = asyncio.run(client._recover_group_epoch_key(_GRP, 2, timeout_s=0))

        assert ok is True
        assert scheduled == [_GRP]

    def test_key_response_rejects_uncommitted_epoch(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path)

        async def fake_call(method, params):
            assert method == "group.e2ee.get_epoch"
            return {"epoch": 1, "committed_epoch": 1}

        monkeypatch.setattr(client, "call", fake_call)

        accepted = asyncio.run(client._verify_group_key_response_epoch({
            "type": "e2ee.group_key_response",
            "group_id": _GRP,
            "epoch": 2,
            "commitment": "c2",
        }))

        assert accepted is False


# ══════════════════════════════════════════════════════════════
# 入群密钥恢复策略：在线优先恢复 + 按 action 区分延迟/立即轮换
# ══════════════════════════════════════════════════════════════


class TestOnlinePriorityRecovery:
    """密钥恢复时应先查 group.get_online_members，只向在线成员请求。"""

    def test_recovery_calls_get_online_members(self, tmp_path, monkeypatch):
        """_do_recover_group_epoch_key 应先调 group.get_online_members 获取在线列表"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append(method)
            if method == "group.get_online_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner", "online": True},
                    {"aid": _AID_BOB, "role": "member", "online": True},
                    {"aid": _AID_CAROL, "role": "member", "online": False},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 2, "committed_epoch": 2, "owner_aid": _AID_ALICE}
            if method == "message.send":
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "call", fake_call)

        asyncio.run(client._do_recover_group_epoch_key(_GRP, 2, timeout_s=0.1))

        assert "group.get_online_members" in rpc_log

    def test_recovery_only_requests_from_online_members(self, tmp_path, monkeypatch):
        """恢复时只向 online=true 的成员发送密钥请求"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        request_targets = []

        async def fake_call(method, params=None):
            if method == "group.get_online_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner", "online": True},
                    {"aid": _AID_CAROL, "role": "member", "online": False},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 2, "committed_epoch": 2, "owner_aid": _AID_ALICE}
            if method == "message.send":
                request_targets.append(params.get("to"))
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "call", fake_call)

        asyncio.run(client._do_recover_group_epoch_key(_GRP, 2, timeout_s=0.1))

        # 只向在线的 Alice 发送请求，不向离线的 Carol 发送
        assert _AID_ALICE in request_targets
        assert _AID_CAROL not in request_targets

    def test_recovery_fallback_when_no_online_members(self, tmp_path, monkeypatch):
        """所有成员离线时，恢复失败（不发送请求）"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        request_targets = []

        async def fake_call(method, params=None):
            if method == "group.get_online_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner", "online": False},
                    {"aid": _AID_CAROL, "role": "member", "online": False},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 2, "committed_epoch": 2, "owner_aid": _AID_ALICE}
            if method == "message.send":
                request_targets.append(params.get("to"))
                return {"ok": True}
            return {}

        monkeypatch.setattr(client, "call", fake_call)

        result = asyncio.run(client._do_recover_group_epoch_key(_GRP, 2, timeout_s=0.1))

        assert result is False
        assert len(request_targets) == 0


class TestServerEpochKeyRecovery:
    """服务端 ECIES epoch key 恢复必须校验 committed commitment 后再落库。"""

    def test_recovery_uses_server_key_for_open_group_before_p2p(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)
        group_secret = secrets.token_bytes(32)
        commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, group_secret)
        encrypted_key = ecies_encrypt(_aid_public_key_bytes(client), group_secret)
        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append(method)
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "members": list(_MEMBERS),
                    "committed_rotation": {
                        "target_epoch": 2,
                        "key_commitment": commitment,
                        "expected_members": list(_MEMBERS),
                    },
                }
            if method == "group.get_join_requirements":
                return {"group_id": _GRP, "join_requirements": {"mode": "open"}}
            if method == "group.e2ee.get_epoch_key":
                return {
                    "group_id": _GRP,
                    "epoch": 2,
                    "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
                }
            raise AssertionError(method)

        monkeypatch.setattr(client, "call", fake_call)

        assert asyncio.run(client._do_recover_group_epoch_key(_GRP, 2, timeout_s=0.1)) is True
        assert "group.e2ee.get_epoch_key" in rpc_log
        loaded = client._group_e2ee.load_secret(_GRP, 2)
        assert loaded is not None
        assert loaded["secret"] == group_secret

    def test_recovery_skips_server_key_for_private_group_and_uses_p2p(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)
        request_targets = []
        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append(method)
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "owner_aid": _AID_ALICE,
                    "members": list(_MEMBERS),
                }
            if method == "group.get_join_requirements":
                return {"group_id": _GRP, "join_requirements": {"mode": "approval"}}
            if method == "group.get_online_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner", "online": True},
                    {"aid": _AID_BOB, "role": "member", "online": True},
                ]}
            if method == "message.send":
                request_targets.append(params.get("to"))
                return {"ok": True}
            if method == "group.e2ee.get_epoch_key":
                raise AssertionError("private/approval 群不应从服务端拉取 epoch key")
            return {}

        monkeypatch.setattr(client, "call", fake_call)

        assert asyncio.run(client._do_recover_group_epoch_key(_GRP, 2, timeout_s=0.1)) is False
        assert "group.e2ee.get_epoch_key" not in rpc_log
        assert request_targets == [_AID_ALICE]

    def test_server_epoch_key_recovery_stores_verified_committed_secret(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(client, epoch=1, epoch_chain="0" * 64)
        group_secret = secrets.token_bytes(32)
        commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, group_secret)
        epoch_chain = compute_epoch_chain("0" * 64, 2, commitment, _AID_ALICE)
        encrypted_key = ecies_encrypt(_aid_public_key_bytes(client), group_secret)

        async def fake_call(method, params=None):
            if method == "group.e2ee.get_epoch_key":
                return {
                    "group_id": _GRP,
                    "epoch": 2,
                    "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
                }
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "members": list(_MEMBERS),
                    "committed_rotation": {
                        "target_epoch": 2,
                        "key_commitment": commitment,
                        "expected_members": list(_MEMBERS),
                        "epoch_chain": epoch_chain,
                        "rotated_by": _AID_ALICE,
                    },
                }
            raise AssertionError(method)

        monkeypatch.setattr(client, "call", fake_call)

        assert asyncio.run(client._try_recover_epoch_key_from_server(_GRP, 2)) is True
        loaded = client._group_e2ee.load_secret(_GRP, 2)
        assert loaded is not None
        assert loaded["secret"] == group_secret
        assert loaded["commitment"] == commitment
        assert sorted(loaded["member_aids"]) == sorted(_MEMBERS)
        assert loaded["epoch_chain"] == epoch_chain
        assert loaded["epoch_chain_unverified"] is not True

    def test_server_epoch_key_recovery_rejects_commitment_mismatch(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)
        group_secret = secrets.token_bytes(32)
        wrong_secret = secrets.token_bytes(32)
        wrong_commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, wrong_secret)
        encrypted_key = ecies_encrypt(_aid_public_key_bytes(client), group_secret)

        async def fake_call(method, params=None):
            if method == "group.e2ee.get_epoch_key":
                return {
                    "group_id": _GRP,
                    "epoch": 2,
                    "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
                }
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "members": list(_MEMBERS),
                    "committed_rotation": {
                        "target_epoch": 2,
                        "key_commitment": wrong_commitment,
                        "expected_members": list(_MEMBERS),
                    },
                }
            raise AssertionError(method)

        monkeypatch.setattr(client, "call", fake_call)

        assert asyncio.run(client._try_recover_epoch_key_from_server(_GRP, 2)) is False
        assert client._group_e2ee.load_secret(_GRP, 2) is None

    def test_server_epoch_key_recovery_rejects_epoch_chain_mismatch(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)
        _store_secret_for_client(client, epoch=1, epoch_chain="1" * 64)
        group_secret = secrets.token_bytes(32)
        commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, group_secret)
        wrong_chain = compute_epoch_chain("2" * 64, 2, commitment, _AID_ALICE)
        encrypted_key = ecies_encrypt(_aid_public_key_bytes(client), group_secret)

        async def fake_call(method, params=None):
            if method == "group.e2ee.get_epoch_key":
                return {
                    "group_id": _GRP,
                    "epoch": 2,
                    "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
                }
            if method == "group.e2ee.get_epoch":
                return {
                    "epoch": 2,
                    "committed_epoch": 2,
                    "members": list(_MEMBERS),
                    "committed_rotation": {
                        "target_epoch": 2,
                        "key_commitment": commitment,
                        "expected_members": list(_MEMBERS),
                        "epoch_chain": wrong_chain,
                        "rotated_by": _AID_ALICE,
                    },
                }
            raise AssertionError(method)

        monkeypatch.setattr(client, "call", fake_call)

        assert asyncio.run(client._try_recover_epoch_key_from_server(_GRP, 2)) is False
        assert client._group_e2ee.load_secret(_GRP, 2) is None

    def test_server_epoch_key_recovery_requires_membership_snapshot(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)
        group_secret = secrets.token_bytes(32)
        encrypted_key = ecies_encrypt(_aid_public_key_bytes(client), group_secret)

        async def fake_call(method, params=None):
            if method == "group.e2ee.get_epoch_key":
                return {
                    "group_id": _GRP,
                    "epoch": 2,
                    "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
                }
            if method == "group.e2ee.get_epoch":
                return {"epoch": 2, "committed_epoch": 2}
            raise AssertionError(method)

        monkeypatch.setattr(client, "call", fake_call)

        assert asyncio.run(client._try_recover_epoch_key_from_server(_GRP, 2)) is False
        assert client._group_e2ee.load_secret(_GRP, 2) is None


class TestOpenJoinRotationLeaderElection:
    """open/邀请码入群轮换的在线候选与 rank 延迟规则。"""

    def test_ranked_candidates_use_online_owner_admin_member_order(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)

        async def fake_call(method, params=None):
            if method == "group.get_online_members":
                return {"members": [
                    {"aid": "member-z.agentid.pub", "role": "member", "online": True},
                    {"aid": "admin-b.agentid.pub", "role": "admin", "online": True},
                    {"aid": "owner-c.agentid.pub", "role": "owner", "online": True},
                    {"aid": "owner-a.agentid.pub", "role": "owner", "online": False},
                    {"aid": "admin-a.agentid.pub", "role": "admin", "online": False},
                ]}
            raise AssertionError(method)

        monkeypatch.setattr(client, "call", fake_call)

        candidates = asyncio.run(client._ranked_group_rotation_candidates(_GRP, allow_member=True))

        assert candidates == [
            "owner-c.agentid.pub",
            "admin-b.agentid.pub",
            "member-z.agentid.pub",
        ]

    def test_new_member_can_rotate_when_no_other_online_member(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)

        async def fake_call(method, params=None):
            if method == "group.get_online_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner", "online": False},
                    {"aid": _AID_BOB, "role": "member", "online": False},
                ]}
            raise AssertionError(method)

        monkeypatch.setattr(client, "call", fake_call)

        candidates = asyncio.run(client._ranked_group_rotation_candidates(_GRP, allow_member=True))

        assert candidates == [_AID_BOB]

    def test_open_join_rank_delay_is_3s_staggered(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_BOB)
        sleeps = []
        rotate_calls = []

        async def fake_call(method, params=None):
            if method == "group.get_online_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner", "online": True},
                    {"aid": _AID_BOB, "role": "member", "online": True},
                    {"aid": _AID_CAROL, "role": "member", "online": True},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            return {}

        async def fake_sleep(delay):
            sleeps.append(delay)

        async def fake_rotate(group_id, **kwargs):
            rotate_calls.append((group_id, kwargs))

        monkeypatch.setattr(client, "call", fake_call)
        monkeypatch.setattr("aun_core.client.random.random", lambda: 0.0)
        monkeypatch.setattr("aun_core.client.asyncio.sleep", fake_sleep)
        monkeypatch.setattr(client, "_rotate_group_epoch", fake_rotate)

        asyncio.run(client._maybe_lead_rotate_group_epoch(
            _GRP, reason="membership_changed", trigger_id="t-open", expected_epoch=1,
            allow_member=True,
        ))

        assert sleeps == [3.0]
        assert rotate_calls == [(_GRP, {
            "reason": "membership_changed",
            "trigger_id": "t-open",
            "expected_epoch": 1,
        })]


class TestJoinActionDelayedRotation:
    """open/invite_code 入群（joined/invite_code_used）应延迟轮换，先让新成员恢复。"""

    def test_joined_action_delays_rotation(self, tmp_path, monkeypatch):
        """action=joined 时 admin 不立即轮换，而是延迟"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def mock_rotate(gid, *args, **kwargs):
            rotate_called.append(gid)

        monkeypatch.setattr(client, "_rotate_group_epoch", mock_rotate)

        async def fake_transport(method, params=None):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        # 模拟 group.changed 事件：action=joined（open 群）
        event_data = {
            "action": "joined",
            "group_id": _GRP,
            "member": {"aid": _AID_BOB},
            "old_epoch": 1,
            "event_seq": 10,
        }

        async def run():
            await client._on_raw_group_changed(event_data)
            # 不等待延迟，立即检查
            await asyncio.sleep(0.05)

        asyncio.run(run())

        # joined 不应立即触发轮换
        assert _GRP not in rotate_called

    def test_invite_code_used_action_delays_rotation(self, tmp_path, monkeypatch):
        """action=invite_code_used 时 admin 不立即轮换"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def mock_rotate(gid, *args, **kwargs):
            rotate_called.append(gid)

        monkeypatch.setattr(client, "_rotate_group_epoch", mock_rotate)

        async def fake_transport(method, params=None):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        event_data = {
            "action": "invite_code_used",
            "group_id": _GRP,
            "member": {"aid": _AID_BOB},
            "old_epoch": 1,
            "event_seq": 11,
        }

        async def run():
            await client._on_raw_group_changed(event_data)
            await asyncio.sleep(0.05)

        asyncio.run(run())

        assert _GRP not in rotate_called

    def test_member_added_still_rotates_immediately(self, tmp_path, monkeypatch):
        """action=member_added（私密群）仍立即轮换"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def mock_rotate(gid, *args, **kwargs):
            rotate_called.append(gid)

        monkeypatch.setattr(client, "_rotate_group_epoch", mock_rotate)

        async def fake_transport(method, params=None):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        event_data = {
            "action": "member_added",
            "group_id": _GRP,
            "member": {"aid": _AID_BOB},
            "old_epoch": 1,
            "event_seq": 12,
        }

        async def run():
            await client._on_raw_group_changed(event_data)
            await asyncio.sleep(0.3)

        asyncio.run(run())

        assert _GRP in rotate_called

    def test_join_approved_still_rotates_immediately(self, tmp_path, monkeypatch):
        """action=join_approved（审批群）仍立即轮换"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def mock_rotate(gid, *args, **kwargs):
            rotate_called.append(gid)

        monkeypatch.setattr(client, "_rotate_group_epoch", mock_rotate)

        async def fake_transport(method, params=None):
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "committed_epoch": 1}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport)

        event_data = {
            "action": "join_approved",
            "group_id": _GRP,
            "member": {"aid": _AID_BOB},
            "old_epoch": 1,
            "event_seq": 13,
        }

        async def run():
            await client._on_raw_group_changed(event_data)
            await asyncio.sleep(0.3)

        asyncio.run(run())

        assert _GRP in rotate_called


class TestNewMemberJoinTriggersRotation:
    """新成员入群后（open/invite_code）应直接触发延迟轮换。"""

    def test_new_member_triggers_delayed_rotation_on_joined(self, tmp_path, monkeypatch):
        """新成员收到自己的 joined 事件时，触发延迟轮换"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        rotate_called = []

        async def mock_delayed_rotate(group_id, **kwargs):
            rotate_called.append(group_id)

        monkeypatch.setattr(client, "_delayed_rotate_after_join", mock_delayed_rotate)

        # Bob 收到自己入群的事件
        event_data = {
            "action": "joined",
            "group_id": _GRP,
            "member": {"aid": _AID_BOB},
            "old_epoch": 2,
            "event_seq": 20,
        }

        async def run():
            await client._on_raw_group_changed(event_data)
            await asyncio.sleep(0.3)

        asyncio.run(run())

        # 新成员应触发延迟轮换
        assert _GRP in rotate_called

    def test_new_member_does_not_backfill_to_self(self, tmp_path, monkeypatch):
        """新成员收到自己的 joined 事件时，不触发 backfill（backfill 是给其他在线成员做的）"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        backfill_called = []

        async def mock_backfill(group_id, data, trigger_id):
            backfill_called.append(group_id)

        monkeypatch.setattr(client, "_maybe_backfill_key_to_joined_member", mock_backfill)

        async def mock_delayed_rotate(group_id, **kwargs):
            pass

        monkeypatch.setattr(client, "_delayed_rotate_after_join", mock_delayed_rotate)

        event_data = {
            "action": "joined",
            "group_id": _GRP,
            "member": {"aid": _AID_BOB},
            "old_epoch": 2,
            "event_seq": 21,
        }

        async def run():
            await client._on_raw_group_changed(event_data)
            await asyncio.sleep(0.3)

        asyncio.run(run())

        # 新成员自身入群不触发 backfill
        assert _GRP not in backfill_called
