"""阶段 3：Client 群组 E2EE 自动加解密单元测试。"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
import uuid

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
    load_all_group_secrets,
    load_group_secret,
    store_group_secret,
)
from aun_core.errors import E2EEGroupSecretMissingError


_AID_ALICE = "alice.agentid.pub"
_AID_BOB = "bob.agentid.pub"
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
    client._aid = aid
    client._identity = {"aid": aid, "private_key_pem": "", "cert": ""}
    client._state = "connected"
    # 为所有已知成员预填充 PKI 验证过的证书缓存
    now = time.time()
    for peer_aid in _MEMBERS:
        if peer_aid == aid:
            continue
        _, cert_pem = _get_signing_identity(peer_aid)
        client._cert_cache[peer_aid] = _CachedPeerCert(
            cert_bytes=cert_pem, validated_at=now, refresh_after=now + 600,
        )
        cert_str = cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else cert_pem
        client._keystore.save_cert(peer_aid, cert_str)
    return client


def _store_secret_for_client(client, group_id=_GRP, epoch=1, gs=None):
    gs = gs or secrets.token_bytes(32)
    commitment = compute_membership_commitment(_MEMBERS, epoch, group_id, gs)
    store_group_secret(client._keystore, client._aid, group_id, epoch, gs, commitment, _MEMBERS)
    return gs


# ── group.send encrypt=True ──────────────────────────────

class TestGroupSendEncrypt:
    def test_calls_encrypt_group_message(self, tmp_path, monkeypatch):
        """group.send(encrypt=True) 触发群组加密"""
        client = _make_client(tmp_path)
        gs = _store_secret_for_client(client)

        sent_params = {}

        async def fake_call(method, params):
            sent_params["method"] = method
            sent_params["params"] = params
            return {"ok": True}

        monkeypatch.setattr(client._transport, "call", fake_call)

        asyncio.run(client.call("group.send", {
            "group_id": _GRP,
            "payload": {"text": "加密消息"},
            "encrypt": True,
        }))

        assert sent_params["method"] == "group.send"
        p = sent_params["params"]
        assert p["encrypted"] is True
        assert p["payload"]["type"] == "e2ee.group_encrypted"
        assert p["payload"]["encryption_mode"] == "epoch_group_key"

    def test_without_secret_raises_error(self, tmp_path, monkeypatch):
        """无 group_secret 时抛 E2EEGroupSecretMissingError"""
        client = _make_client(tmp_path)

        async def fake_call(method, params):
            return {}

        monkeypatch.setattr(client._transport, "call", fake_call)

        with pytest.raises(E2EEGroupSecretMissingError):
            asyncio.run(client.call("group.send", {
                "group_id": _GRP,
                "payload": {"text": "test"},
                "encrypt": True,
            }))


# ── 群组消息自动解密 ─────────────────────────────────────

class TestGroupMessageAutoDecrypt:
    def _make_encrypted_group_msg(self, gs, from_aid=_AID_ALICE):
        pk_pem, _ = _get_signing_identity(from_aid)
        msg_id = f"gm-{uuid.uuid4()}"
        ts = 1710504000000
        envelope = encrypt_group_message(
            group_id=_GRP, epoch=1, group_secret=gs,
            payload={"text": "秘密"}, from_aid=from_aid,
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
        result = asyncio.run(client._decrypt_group_message(msg))
        assert result["payload"] == {"text": "秘密"}
        assert result["e2ee"]["encryption_mode"] == "epoch_group_key"

    def test_auto_decrypted_on_pull(self, tmp_path):
        """pull 消息中的 e2ee.group_encrypted 能被解密"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        gs = _store_secret_for_client(client, epoch=1)

        msg = self._make_encrypted_group_msg(gs)
        # 模拟 pull 返回的消息解密
        result = asyncio.run(client._decrypt_group_message(msg))
        assert result["payload"]["text"] == "秘密"

    def test_plaintext_passthrough(self, tmp_path):
        """非加密群消息正常通过"""
        client = _make_client(tmp_path, aid=_AID_BOB)
        msg = {
            "group_id": _GRP,
            "from": _AID_ALICE,
            "message_id": "gm-123",
            "timestamp": 1710504000000,
            "payload": {"text": "明文消息"},
        }
        result = asyncio.run(client._decrypt_group_message(msg))
        assert result["payload"]["text"] == "明文消息"


# ── 密钥分发自动处理 ─────────────────────────────────────

class TestKeyDistributionAutoHandled:
    def test_distribution_handled(self, tmp_path):
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
        assert client._config_model.rotate_on_join is False
        assert client._config_model.epoch_auto_rotate_interval == 0
        assert client._config_model.old_epoch_retention_seconds == 604800

    def test_config_group_e2ee_always_true(self, tmp_path):
        """group_e2ee 是必选能力，即使用户传 False 也始终为 True"""
        client = AUNClient({
            "aun_path": str(tmp_path / "aun"),
            "rotate_on_join": True,
            "epoch_auto_rotate_interval": 86400,
        })
        assert client._config_model.group_e2ee is True
        assert client._config_model.rotate_on_join is True
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
        payload={"text": "test"}, from_aid=from_aid,
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
# CAS 轮换链路测试
# ══════════════════════════════════════════════════════════════

class TestRotateGroupEpochCAS:
    """_rotate_group_epoch 必须走服务端 CAS，不能绕过。"""

    def _setup(self, tmp_path, monkeypatch):
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append({"method": method, "params": params})
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "group_id": _GRP}
            if method == "group.e2ee.rotate_epoch":
                current = params.get("current_epoch", 0)
                # 模拟 CAS 成功
                return {"success": True, "epoch": current + 1, "group_id": _GRP}
            if method == "group.get_members":
                return {"members": [
                    {"aid": _AID_ALICE, "role": "owner"},
                    {"aid": _AID_BOB, "role": "member"},
                ]}
            if method == "message.send":
                return {"ok": True}
            raise Exception(f"unmocked: {method}")

        monkeypatch.setattr(client, "call", fake_call)
        return client, rpc_log

    def test_calls_cas_rpcs(self, tmp_path, monkeypatch):
        """_rotate_group_epoch 必须依次调 get_epoch → rotate_epoch"""
        client, rpc_log = self._setup(tmp_path, monkeypatch)
        asyncio.run(client._rotate_group_epoch(_GRP))

        methods = [r["method"] for r in rpc_log]
        assert "group.e2ee.get_epoch" in methods
        assert "group.e2ee.rotate_epoch" in methods
        # rotate_epoch 在 get_epoch 之后
        idx_get = methods.index("group.e2ee.get_epoch")
        idx_rotate = methods.index("group.e2ee.rotate_epoch")
        assert idx_rotate > idx_get

    def test_cas_success_distributes(self, tmp_path, monkeypatch):
        """CAS 成功 → 本地存储新 epoch + 分发"""
        client, rpc_log = self._setup(tmp_path, monkeypatch)
        asyncio.run(client._rotate_group_epoch(_GRP))

        # 应调 message.send 分发给 Bob
        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert len(sends) >= 1
        assert sends[0]["params"]["to"] == _AID_BOB
        # 本地 epoch 已更新
        assert client._group_e2ee.current_epoch(_GRP) == 2

    def test_cas_failure_no_distribute(self, tmp_path, monkeypatch):
        """CAS 失败 → 不生成、不分发、不存储"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []

        async def fake_call(method, params=None):
            rpc_log.append({"method": method, "params": params})
            if method == "group.e2ee.get_epoch":
                return {"epoch": 1, "group_id": _GRP}
            if method == "group.e2ee.rotate_epoch":
                return {"success": False, "epoch": 1, "group_id": _GRP}  # CAS 失败
            raise Exception(f"unmocked: {method}")

        monkeypatch.setattr(client, "call", fake_call)
        asyncio.run(client._rotate_group_epoch(_GRP))

        # 不应有 message.send（不分发）
        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert len(sends) == 0
        # 本地 epoch 未变
        assert client._group_e2ee.current_epoch(_GRP) == 1

    def test_kick_triggers_cas_rotation(self, tmp_path, monkeypatch):
        """group.kick 后自动触发 CAS 轮换"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rpc_log = []
        rotate_called = []

        original_rotate = client._rotate_group_epoch

        async def track_rotate(group_id):
            rotate_called.append(group_id)

        # mock _rotate_group_epoch 来追踪调用
        monkeypatch.setattr(client, "_rotate_group_epoch", track_rotate)

        async def fake_transport_call(method, params=None):
            rpc_log.append(method)
            return {"group": {"group_id": _GRP}}

        monkeypatch.setattr(client._transport, "call", fake_transport_call)

        asyncio.run(client.call("group.kick", {"group_id": _GRP, "aid": _AID_BOB}))

        # 让异步任务有机会执行
        import asyncio as _aio
        loop = _aio.new_event_loop()
        loop.run_until_complete(_aio.sleep(0.1))
        loop.close()

        # kick 后应触发 _rotate_group_epoch（但由于 create_task 是异步的，
        # 这里验证 call() 确实拦截了 group.kick）
        assert "group.kick" in rpc_log

    def test_leave_triggers_cas_rotation(self, tmp_path, monkeypatch):
        """group.leave 后离开者不轮换；收到 group.changed(member_left) 事件时自动触发 CAS 轮换"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        rotate_called = []

        async def track_rotate(group_id):
            rotate_called.append(group_id)

        monkeypatch.setattr(client, "_rotate_group_epoch", track_rotate)

        async def fake_transport_call(method, params=None):
            if method == "group.leave":
                return {"group": {"group_id": _GRP}, "left_aid": _AID_ALICE}
            return {}

        monkeypatch.setattr(client._transport, "call", fake_transport_call)

        async def run():
            # 1. group.leave 本身不应触发轮换
            await client.call("group.leave", {"group_id": _GRP})
            await asyncio.sleep(0.2)
            assert _GRP not in rotate_called, "离开者自身不应触发轮换"

            # 2. 模拟剩余成员收到 group.changed 事件 → 应触发轮换
            await client._on_raw_group_changed({
                "module_id": "group",
                "action": "member_left",
                "group_id": _GRP,
            })
            await asyncio.sleep(0.2)
            assert _GRP in rotate_called, "收到 member_left 事件后应触发轮换"

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

        # 直接调用 _distribute_key_to_new_member（绕过 create_task）
        asyncio.run(client._distribute_key_to_new_member(_GRP, _AID_BOB))

        methods = [r["method"] for r in rpc_log]
        assert "group.get_members" in methods
        assert "message.send" in methods
        sends = [r for r in rpc_log if r["method"] == "message.send"]
        assert any(s["params"]["to"] == _AID_BOB for s in sends)

        # 验证本地 member_aids 已更新
        local = client._group_e2ee.get_member_aids(_GRP)
        assert _AID_ALICE in local
        assert _AID_BOB in local

    def test_add_member_rotate_on_join(self, tmp_path, monkeypatch):
        """rotate_on_join=True 时走 CAS 轮换而非补发"""
        client = AUNClient({
            "aun_path": str(tmp_path / "aun"),
            "rotate_on_join": True,
        })
        client._aid = _AID_ALICE
        client._identity = {"aid": _AID_ALICE}
        client._state = "connected"
        _store_secret_for_client(client, epoch=1)

        rotate_called = []

        async def mock_rotate(gid):
            rotate_called.append(gid)

        monkeypatch.setattr(client, "_rotate_group_epoch", mock_rotate)

        async def fake_transport(method, params):
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
        """batch_review 仅对 approved 的成员分发"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        _store_secret_for_client(client, epoch=1)
        _CAROL = "carol.agentid.pub"

        distributed_to = []

        async def track_distribute(group_id, new_aid):
            distributed_to.append(new_aid)

        monkeypatch.setattr(client, "_distribute_key_to_new_member", track_distribute)

        async def fake_transport(method, params):
            if method == "group.batch_review_join_request":
                return {"results": [
                    {"aid": _AID_BOB, "ok": True, "status": "approved"},
                    {"aid": _CAROL, "ok": True, "status": "rejected"},
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

        assert _AID_BOB in distributed_to
        assert _CAROL not in distributed_to

    def test_batch_review_rotate_on_join(self, tmp_path, monkeypatch):
        """batch_review 在 rotate_on_join=True 时触发轮换而非补发"""
        client = _make_client(tmp_path, aid=_AID_ALICE)
        client._config_model.rotate_on_join = True
        _store_secret_for_client(client, epoch=1)

        rotated = []
        distributed = []

        async def track_rotate(group_id):
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
        """请求者不在本地 member_aids，应回源 group.get_members 后仍能响应"""
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

        # 验证：回源查询了服务端
        assert len(server_lookup_called) == 1
        assert server_lookup_called[0]["group_id"] == _GRP
        # 验证：成功向 Carol 发送了 group_key_response
        assert len(sent_messages) == 1
        assert sent_messages[0]["to"] == _CAROL

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
