"""阶段 0：群组 E2EE 基础密码学单元测试。"""

from __future__ import annotations

import copy
import base64
import json
import secrets
import time
import uuid

import pytest

from aun_core.e2ee import (
    AAD_FIELDS_GROUP,
    MODE_EPOCH_GROUP_KEY,
    SUITE,
    GroupReplayGuard,
    _aad_bytes_group,
    _aad_matches_group,
    _derive_group_msg_key,
    check_epoch_downgrade,
    cleanup_old_epochs,
    compute_epoch_chain,
    compute_membership_commitment,
    decrypt_group_message,
    encrypt_group_message,
    load_all_group_secrets,
    load_group_secret,
    store_group_secret,
    verify_membership_commitment,
)
from aun_core.errors import (
    E2EEGroupCommitmentInvalidError,
    E2EEGroupDecryptFailedError,
    E2EEGroupEpochMismatchError,
    E2EEGroupNotMemberError,
    E2EEGroupSecretMissingError,
)
from aun_core.keystore.file import FileKeyStore
from aun_core.e2ee import (
    GroupKeyRequestThrottle,
    build_key_distribution,
    build_key_request,
    generate_group_secret,
    handle_key_distribution,
    handle_key_request,
    handle_key_response,
    build_membership_manifest,
    sign_membership_manifest,
    verify_membership_manifest,
)


# ── 辅助 ───────────────────────────────────────────────────

def _random_secret() -> bytes:
    return secrets.token_bytes(32)


# 模块级签名身份缓存
_default_signing_pk_pem: str | None = None
_default_signing_cert_pem: bytes | None = None


def _ensure_default_signing_identity():
    """获取默认签名身份（延迟初始化）"""
    global _default_signing_pk_pem, _default_signing_cert_pem
    if _default_signing_pk_pem is None:
        _default_signing_pk_pem, _default_signing_cert_pem = _make_signing_identity()
    return _default_signing_pk_pem, _default_signing_cert_pem


def _default_cert():
    """获取默认发送方证书（用于 decrypt_group_message 调用）"""
    _, cert = _ensure_default_signing_identity()
    return cert


def _make_group_msg(
    group_id: str = "grp_test1",
    from_aid: str = "alice.agentid.pub",
    epoch: int = 1,
    group_secret: bytes | None = None,
    payload: dict | None = None,
    sender_private_key_pem: str | None = "AUTO",
) -> tuple[dict, bytes, str]:
    """加密一条群消息，返回 (完整 message, group_secret, message_id)。

    sender_private_key_pem="AUTO" 时使用默认签名身份。传 None 生成无签名消息。
    """
    gs = group_secret or _random_secret()
    msg_id = f"gm-{uuid.uuid4()}"
    ts = 1710504000000
    pl = payload or {"type": "text", "text": "hello group"}

    pk_pem = sender_private_key_pem
    if pk_pem == "AUTO":
        pk_pem, _ = _ensure_default_signing_identity()

    envelope = encrypt_group_message(
        group_id=group_id,
        epoch=epoch,
        group_secret=gs,
        payload=pl,
        from_aid=from_aid,
        message_id=msg_id,
        timestamp=ts,
        sender_private_key_pem=pk_pem,
    )
    message = {
        "group_id": group_id,
        "from": from_aid,
        "sender_aid": from_aid,
        "message_id": msg_id,
        "timestamp": ts,
        "created_at": ts,
        "payload": envelope,
        "encrypted": True,
    }
    return message, gs, msg_id


# ── 密钥派生 ───────────────────────────────────────────────

class TestDeriveGroupMsgKey:
    def test_deterministic(self):
        gs = _random_secret()
        k1 = _derive_group_msg_key(gs, "grp_1", "msg_1")
        k2 = _derive_group_msg_key(gs, "grp_1", "msg_1")
        assert k1 == k2
        assert len(k1) == 32

    def test_different_message_id(self):
        gs = _random_secret()
        k1 = _derive_group_msg_key(gs, "grp_1", "msg_1")
        k2 = _derive_group_msg_key(gs, "grp_1", "msg_2")
        assert k1 != k2


# ── 加密信封 ───────────────────────────────────────────────

class TestEncryptGroupMessage:
    def test_envelope_structure(self):
        gs = _random_secret()
        envelope = encrypt_group_message(
            group_id="grp_test",
            epoch=3,
            group_secret=gs,
            payload={"type": "text", "text": "test"},
            from_aid="alice.agentid.pub",
            message_id="gm-123",
            timestamp=1710504000000,
        )
        # 必需字段
        assert envelope["type"] == "e2ee.group_encrypted"
        assert envelope["version"] == "1"
        assert envelope["encryption_mode"] == MODE_EPOCH_GROUP_KEY
        assert envelope["suite"] == SUITE
        assert envelope["epoch"] == 3
        assert "nonce" in envelope
        assert "ciphertext" in envelope
        assert "tag" in envelope
        assert isinstance(envelope["aad"], dict)

        # nonce 12 bytes, tag 16 bytes
        assert len(base64.b64decode(envelope["nonce"])) == 12
        assert len(base64.b64decode(envelope["tag"])) == 16


# ── 加解密往返 ─────────────────────────────────────────────

class TestEncryptDecryptRoundtrip:
    def test_roundtrip(self):
        original = {"type": "text", "text": "秘密消息", "data": [1, 2, 3]}
        message, gs, _ = _make_group_msg(payload=original)
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=_default_cert())
        assert result is not None
        assert result["payload"] == original
        assert result["encrypted"] is True
        assert result["e2ee"]["encryption_mode"] == MODE_EPOCH_GROUP_KEY
        assert result["e2ee"]["epoch"] == 1

    def test_wrong_epoch_fails(self):
        message, gs, _ = _make_group_msg(epoch=2)
        # 只有 epoch=1 的密钥
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=_default_cert())
        assert result is None

    def test_wrong_group_secret_fails(self):
        message, gs, _ = _make_group_msg()
        wrong_secret = _random_secret()
        result = decrypt_group_message(message, {1: wrong_secret}, sender_cert_pem=_default_cert())
        assert result is None

    def test_tampered_ciphertext_fails(self):
        message, gs, _ = _make_group_msg()
        # 篡改密文
        ct = base64.b64decode(message["payload"]["ciphertext"])
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        message["payload"]["ciphertext"] = base64.b64encode(tampered).decode("ascii")
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=_default_cert())
        assert result is None

    def test_tampered_aad_field_fails(self):
        message, gs, _ = _make_group_msg()
        # 篡改 AAD 中的 group_id
        message["payload"]["aad"]["group_id"] = "grp_hacked"
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=_default_cert())
        assert result is None


# ── AAD 工具 ───────────────────────────────────────────────

class TestAADGroup:
    def test_has_7_fields(self):
        assert len(AAD_FIELDS_GROUP) == 7

    def test_deterministic_serialization(self):
        aad = {
            "group_id": "grp_1",
            "from": "alice",
            "message_id": "msg_1",
            "timestamp": 100,
            "epoch": 1,
            "encryption_mode": MODE_EPOCH_GROUP_KEY,
            "suite": SUITE,
        }
        b1 = _aad_bytes_group(aad)
        b2 = _aad_bytes_group(aad)
        assert b1 == b2
        # 验证是 sorted keys
        parsed = json.loads(b1.decode("utf-8"))
        keys = list(parsed.keys())
        assert keys == sorted(keys)


# ── Membership Commitment ──────────────────────────────────

class TestMembershipCommitment:
    def test_deterministic(self):
        aids = ["alice.agentid.pub", "bob.agentid.pub"]
        gs = _random_secret()
        c1 = compute_membership_commitment(aids, 1, "grp_1", gs)
        c2 = compute_membership_commitment(aids, 1, "grp_1", gs)
        assert c1 == c2
        assert len(c1) == 64  # SHA-256 hex

    def test_order_independent(self):
        aids_1 = ["carol.agentid.pub", "alice.agentid.pub", "bob.agentid.pub"]
        aids_2 = ["bob.agentid.pub", "carol.agentid.pub", "alice.agentid.pub"]
        gs = _random_secret()
        c1 = compute_membership_commitment(aids_1, 1, "grp_1", gs)
        c2 = compute_membership_commitment(aids_2, 1, "grp_1", gs)
        assert c1 == c2

    def test_verify_success(self):
        aids = ["alice.agentid.pub", "bob.agentid.pub"]
        gs = _random_secret()
        commitment = compute_membership_commitment(aids, 1, "grp_1", gs)
        assert verify_membership_commitment(commitment, aids, 1, "grp_1", "alice.agentid.pub", gs)

    def test_verify_ghost_member(self):
        aids_real = ["alice.agentid.pub", "bob.agentid.pub"]
        gs = _random_secret()
        commitment = compute_membership_commitment(aids_real, 1, "grp_1", gs)
        # 服务端注入额外成员
        aids_tampered = ["alice.agentid.pub", "bob.agentid.pub", "evil.agentid.pub"]
        assert not verify_membership_commitment(commitment, aids_tampered, 1, "grp_1", "alice.agentid.pub", gs)

    def test_verify_self_not_in_list(self):
        aids = ["alice.agentid.pub", "bob.agentid.pub"]
        gs = _random_secret()
        commitment = compute_membership_commitment(aids, 1, "grp_1", gs)
        # carol 不在列表中
        assert not verify_membership_commitment(commitment, aids, 1, "grp_1", "carol.agentid.pub", gs)

    def test_different_secret_different_commitment(self):
        """不同 group_secret 产生不同 commitment（防止密钥替换攻击）"""
        aids = ["alice.agentid.pub", "bob.agentid.pub"]
        gs1 = _random_secret()
        gs2 = _random_secret()
        c1 = compute_membership_commitment(aids, 1, "grp_1", gs1)
        c2 = compute_membership_commitment(aids, 1, "grp_1", gs2)
        assert c1 != c2


# ── 错误码 ─────────────────────────────────────────────────

class TestGroupErrorCodes:
    def test_error_codes_exist(self):
        assert E2EEGroupSecretMissingError().code == -32040
        assert E2EEGroupEpochMismatchError().code == -32041
        assert E2EEGroupCommitmentInvalidError().code == -32042
        assert E2EEGroupNotMemberError().code == -32043
        assert E2EEGroupDecryptFailedError().code == -32044

        # local_code 存在
        assert E2EEGroupSecretMissingError().local_code == "E2EE_GROUP_SECRET_MISSING"
        assert E2EEGroupDecryptFailedError().local_code == "E2EE_GROUP_DECRYPT_FAILED"


# ══════════════════════════════════════════════════════════════
# 阶段 1：Group Secret 本地存储与生命周期
# ══════════════════════════════════════════════════════════════

_AID = "alice.agentid.pub"
_GRP = "grp_test1"
_MEMBERS = ["alice.agentid.pub", "bob.agentid.pub"]


def _make_keystore(tmp_path):
    return FileKeyStore(root=tmp_path / "aun-test")


def _store_secret(ks, epoch=1, gs=None):
    gs = gs or _random_secret()
    commitment = compute_membership_commitment(_MEMBERS, epoch, _GRP, gs)
    store_group_secret(ks, _AID, _GRP, epoch, gs, commitment, _MEMBERS)
    return gs


class StructuredGroupKeystore:
    def __init__(self):
        self._groups = {}

    def list_group_secret_ids(self, aid):
        return sorted(self._groups.get(aid, {}).keys())

    def load_group_secret_epoch(self, aid, group_id, epoch=None):
        entry = self._groups.get(aid, {}).get(group_id)
        if not isinstance(entry, dict):
            return None
        if epoch is None or int(entry.get("epoch") or 0) == int(epoch):
            return copy.deepcopy(entry)
        for old in entry.get("old_epochs", []):
            if isinstance(old, dict) and int(old.get("epoch") or 0) == int(epoch):
                return copy.deepcopy(old)
        return None

    def load_group_secret_epochs(self, aid, group_id):
        entry = self._groups.get(aid, {}).get(group_id)
        if not isinstance(entry, dict):
            return []
        return copy.deepcopy([entry, *[old for old in entry.get("old_epochs", []) if isinstance(old, dict)]])

    def store_group_secret_transition(
        self, aid, group_id, *, epoch, secret, commitment, member_aids,
        epoch_chain=None, pending_rotation_id="", epoch_chain_unverified=None,
        epoch_chain_unverified_reason=None, old_epoch_retention_ms=7 * 24 * 3600 * 1000,
    ):
        now_ms = int(time.time() * 1000)
        epoch_i = int(epoch)
        members = sorted(member_aids or [])
        groups = self._groups.setdefault(aid, {})
        existing = groups.get(group_id)

        if isinstance(existing, dict):
            local_epoch = int(existing.get("epoch") or 0)
            if epoch_i < local_epoch:
                return False
            if epoch_i == local_epoch and existing.get("secret"):
                if existing.get("secret") != secret:
                    if not str(existing.get("pending_rotation_id") or "").strip():
                        return False
                    groups[group_id] = self._build_group_entry(
                        epoch_i, secret, commitment, members, now_ms,
                        copy.deepcopy(existing.get("old_epochs", [])),
                        epoch_chain, pending_rotation_id,
                        epoch_chain_unverified, epoch_chain_unverified_reason,
                    )
                    return True
                groups[group_id] = self._merge_group_metadata(
                    existing, commitment, members, now_ms, epoch_chain,
                    pending_rotation_id, epoch_chain_unverified,
                    epoch_chain_unverified_reason,
                )
                return True
            old_entry = copy.deepcopy(existing)
            old_entry["expires_at"] = int(existing.get("updated_at") or now_ms) + int(old_epoch_retention_ms)
            old_epochs = copy.deepcopy(existing.get("old_epochs", []))
            old_epochs.append(old_entry)
            groups[group_id] = self._build_group_entry(
                epoch_i, secret, commitment, members, now_ms, old_epochs,
                epoch_chain, pending_rotation_id,
                epoch_chain_unverified, epoch_chain_unverified_reason,
            )
            return True

        groups[group_id] = self._build_group_entry(
            epoch_i, secret, commitment, members, now_ms, [],
            epoch_chain, pending_rotation_id,
            epoch_chain_unverified, epoch_chain_unverified_reason,
        )
        return True

    def store_group_secret_epoch(
        self, aid, group_id, *, epoch, secret, commitment, member_aids,
        epoch_chain=None, pending_rotation_id="", epoch_chain_unverified=None,
        epoch_chain_unverified_reason=None, old_epoch_retention_ms=7 * 24 * 3600 * 1000,
    ):
        now_ms = int(time.time() * 1000)
        epoch_i = int(epoch)
        members = sorted(member_aids or [])
        groups = self._groups.setdefault(aid, {})
        existing = groups.get(group_id)

        if not isinstance(existing, dict):
            groups[group_id] = self._build_group_entry(
                epoch_i, secret, commitment, members, now_ms, [],
                epoch_chain, pending_rotation_id,
                epoch_chain_unverified, epoch_chain_unverified_reason,
            )
            return True

        local_epoch = int(existing.get("epoch") or 0)
        if epoch_i > local_epoch:
            return False
        if epoch_i == local_epoch:
            existing_secret = str(existing.get("secret") or "")
            if existing_secret and existing_secret != secret and not str(existing.get("pending_rotation_id") or "").strip():
                return False
            groups[group_id] = self._build_group_entry(
                epoch_i, secret, commitment, members, now_ms,
                copy.deepcopy(existing.get("old_epochs", [])),
                epoch_chain, pending_rotation_id,
                epoch_chain_unverified, epoch_chain_unverified_reason,
            )
            return True

        old_epochs = [copy.deepcopy(old) for old in existing.get("old_epochs", []) if isinstance(old, dict)]
        replacement = self._build_group_entry(
            epoch_i, secret, commitment, members, now_ms, [],
            epoch_chain, pending_rotation_id,
            epoch_chain_unverified, epoch_chain_unverified_reason,
        )
        replacement.pop("old_epochs", None)
        replacement["expires_at"] = now_ms + int(old_epoch_retention_ms)
        for index, old in enumerate(old_epochs):
            if int(old.get("epoch") or 0) != epoch_i:
                continue
            if old.get("secret") and old.get("secret") != secret:
                return False
            old_epochs[index] = replacement
            break
        else:
            old_epochs.append(replacement)
        groups[group_id] = {**copy.deepcopy(existing), "old_epochs": old_epochs}
        return True

    def discard_pending_group_secret_state(self, aid, group_id, epoch, rotation_id):
        entry = self._groups.get(aid, {}).get(group_id)
        if not isinstance(entry, dict):
            return False
        if int(entry.get("epoch") or 0) != int(epoch):
            return False
        if str(entry.get("pending_rotation_id") or "").strip() != str(rotation_id or "").strip():
            return False
        old_epochs = [copy.deepcopy(old) for old in entry.get("old_epochs", []) if isinstance(old, dict)]
        restore_index = -1
        restore_epoch = -1
        for index, old in enumerate(old_epochs):
            old_epoch = int(old.get("epoch") or 0)
            if old_epoch < int(epoch) and old_epoch > restore_epoch and old.get("secret"):
                restore_index = index
                restore_epoch = old_epoch
        if restore_index >= 0:
            restored = copy.deepcopy(old_epochs[restore_index])
            restored["old_epochs"] = [old for index, old in enumerate(old_epochs) if index != restore_index]
            self._groups[aid][group_id] = restored
        else:
            self._groups.get(aid, {}).pop(group_id, None)
        return True

    def cleanup_group_old_epochs_state(self, aid, group_id, cutoff_ms):
        entry = self._groups.get(aid, {}).get(group_id)
        if not isinstance(entry, dict):
            return 0
        old_epochs = entry.get("old_epochs")
        if not isinstance(old_epochs, list):
            return 0
        removed = 0
        remaining = []
        for old in old_epochs:
            if not isinstance(old, dict):
                continue
            marker = old.get("updated_at") or old.get("expires_at") or 0
            if isinstance(marker, (int, float)) and int(marker) < cutoff_ms:
                removed += 1
                continue
            remaining.append(copy.deepcopy(old))
        entry["old_epochs"] = remaining
        return removed

    def _build_group_entry(
        self, epoch, secret, commitment, members, updated_at, old_epochs,
        epoch_chain, pending_rotation_id, epoch_chain_unverified,
        epoch_chain_unverified_reason,
    ):
        entry = {
            "epoch": int(epoch),
            "secret": secret,
            "commitment": commitment,
            "member_aids": sorted(members),
            "updated_at": updated_at,
            "old_epochs": copy.deepcopy(old_epochs),
        }
        if epoch_chain is not None:
            entry["epoch_chain"] = epoch_chain
        if pending_rotation_id:
            entry["pending_rotation_id"] = pending_rotation_id
            entry["pending_created_at"] = updated_at
        if epoch_chain_unverified is True:
            entry["epoch_chain_unverified"] = True
            if epoch_chain_unverified_reason:
                entry["epoch_chain_unverified_reason"] = epoch_chain_unverified_reason
        return entry

    def _merge_group_metadata(
        self, existing, commitment, members, updated_at, epoch_chain,
        pending_rotation_id, epoch_chain_unverified,
        epoch_chain_unverified_reason,
    ):
        updated = copy.deepcopy(existing)
        updated["updated_at"] = updated_at
        if members and sorted(updated.get("member_aids") or []) != sorted(members):
            updated["member_aids"] = sorted(members)
            updated["commitment"] = commitment
        if epoch_chain is not None:
            updated["epoch_chain"] = epoch_chain
        if pending_rotation_id:
            updated["pending_rotation_id"] = pending_rotation_id
            updated["pending_created_at"] = updated_at
        else:
            updated.pop("pending_rotation_id", None)
            updated.pop("pending_created_at", None)
        if epoch_chain_unverified is True:
            updated["epoch_chain_unverified"] = True
            if epoch_chain_unverified_reason:
                updated["epoch_chain_unverified_reason"] = epoch_chain_unverified_reason
        elif epoch_chain_unverified is False:
            updated.pop("epoch_chain_unverified", None)
            updated.pop("epoch_chain_unverified_reason", None)
        return updated


class TestStoreGroupSecret:
    def test_store_group_secret_protected(self, tmp_path):
        """group_secret 存储在 SQLCipher 加密的 aun.db 中，不出现在明文文件"""
        ks = _make_keystore(tmp_path)
        gs = _store_secret(ks)
        gs_b64 = base64.b64encode(gs).decode("ascii")

        safe_aid = _AID.replace("/", "_").replace("\\", "_").replace(":", "_")
        db_file = tmp_path / "aun-test" / "AIDs" / safe_aid / "aun.db"
        assert db_file.exists(), "aun.db 应该存在"
        meta_path = tmp_path / "aun-test" / "AIDs" / safe_aid / "tokens" / "meta.json"
        if meta_path.exists():
            raw = meta_path.read_text(encoding="utf-8")
            assert gs_b64 not in raw

    def test_load_group_secret_current_epoch(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs = _store_secret(ks, epoch=3)
        loaded = load_group_secret(ks, _AID, _GRP)
        assert loaded is not None
        assert loaded["epoch"] == 3
        assert loaded["secret"] == gs

    def test_load_group_secret_old_epoch(self, tmp_path):
        """轮换后旧 epoch 仍可读取"""
        ks = _make_keystore(tmp_path)
        gs1 = _store_secret(ks, epoch=1)
        gs2 = _store_secret(ks, epoch=2)

        # 当前 epoch
        current = load_group_secret(ks, _AID, _GRP)
        assert current["epoch"] == 2
        assert current["secret"] == gs2

        # 旧 epoch
        old = load_group_secret(ks, _AID, _GRP, epoch=1)
        assert old is not None
        assert old["epoch"] == 1
        assert old["secret"] == gs1

    def test_load_all_group_secrets(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs1 = _store_secret(ks, epoch=1)
        gs2 = _store_secret(ks, epoch=2)
        gs3 = _store_secret(ks, epoch=3)

        all_secrets = load_all_group_secrets(ks, _AID, _GRP)
        assert len(all_secrets) == 3
        assert all_secrets[1] == gs1
        assert all_secrets[2] == gs2
        assert all_secrets[3] == gs3


class TestCleanupOldEpochs:
    def test_removes_expired(self, tmp_path):
        ks = _make_keystore(tmp_path)
        _store_secret(ks, epoch=1)
        _store_secret(ks, epoch=2)
        _store_secret(ks, epoch=3)

        # retention_seconds=0 → 所有旧的都过期
        removed = cleanup_old_epochs(ks, _AID, _GRP, retention_seconds=0)
        assert removed == 2

        # 只剩当前 epoch
        all_secrets = load_all_group_secrets(ks, _AID, _GRP)
        assert len(all_secrets) == 1
        assert 3 in all_secrets

    def test_keeps_recent(self, tmp_path):
        ks = _make_keystore(tmp_path)
        _store_secret(ks, epoch=1)
        _store_secret(ks, epoch=2)

        # 保留期足够长
        removed = cleanup_old_epochs(ks, _AID, _GRP, retention_seconds=999999)
        assert removed == 0

        all_secrets = load_all_group_secrets(ks, _AID, _GRP)
        assert len(all_secrets) == 2


class TestStructuredGroupStateKeystore:
    def test_store_load_and_cleanup_without_metadata_roundtrip(self):
        """group secret 生命周期应优先走结构化接口。"""
        ks = StructuredGroupKeystore()
        gs1 = _store_secret(ks, epoch=1)
        gs2 = _store_secret(ks, epoch=2)
        ks._groups[_AID][_GRP]["old_epochs"][0]["updated_at"] = 0
        ks._groups[_AID][_GRP]["old_epochs"][0]["expires_at"] = int(time.time() * 1000) - 1

        current = load_group_secret(ks, _AID, _GRP)
        assert current["epoch"] == 2
        assert current["secret"] == gs2

        old = load_group_secret(ks, _AID, _GRP, epoch=1)
        assert old is not None
        assert old["secret"] == gs1

        removed = cleanup_old_epochs(ks, _AID, _GRP, retention_seconds=0)
        assert removed == 1

        all_secrets = load_all_group_secrets(ks, _AID, _GRP)
        assert all_secrets == {2: gs2}


class TestGroupReplayGuardUnit:
    def test_blocks_duplicate(self):
        guard = GroupReplayGuard(max_size=100)
        assert guard.check_and_record("grp_1", "alice", "msg_1") is True
        assert guard.check_and_record("grp_1", "alice", "msg_1") is False
        # 不同 message_id 通过
        assert guard.check_and_record("grp_1", "alice", "msg_2") is True

    def test_lru_trim(self):
        guard = GroupReplayGuard(max_size=10)
        for i in range(15):
            guard.check_and_record("grp_1", "alice", f"msg_{i}")
        # 裁剪到 80% = 8
        assert guard.size <= 10


class TestEpochDowngrade:
    def test_rejected(self):
        assert check_epoch_downgrade(1, 3) is False

    def test_allowed_same(self):
        assert check_epoch_downgrade(3, 3) is True

    def test_allowed_newer(self):
        assert check_epoch_downgrade(4, 3) is True

    def test_allowed_with_old_key(self):
        assert check_epoch_downgrade(1, 3, allow_old_epoch=True) is True


class TestStoreEncryptDecryptRoundtrip:
    def test_full_roundtrip(self, tmp_path):
        """存储 → 读取 → 加解密完整流程"""
        ks = _make_keystore(tmp_path)
        gs = _store_secret(ks, epoch=2)
        pk_pem, cert_pem = _ensure_default_signing_identity()

        # 加密
        payload = {"type": "text", "text": "通过 keystore 存取的密钥加解密"}
        msg_id = f"gm-{uuid.uuid4()}"
        envelope = encrypt_group_message(
            group_id=_GRP, epoch=2, group_secret=gs,
            payload=payload, from_aid=_AID, message_id=msg_id, timestamp=1710504000000,
            sender_private_key_pem=pk_pem,
        )

        # 从 keystore 读取所有密钥
        all_secrets = load_all_group_secrets(ks, _AID, _GRP)
        message = {
            "group_id": _GRP, "from": _AID, "message_id": msg_id,
            "timestamp": 1710504000000, "payload": envelope, "encrypted": True,
        }
        result = decrypt_group_message(message, all_secrets, sender_cert_pem=cert_pem)
        assert result is not None
        assert result["payload"] == payload


# ══════════════════════════════════════════════════════════════
# 阶段 2：Group Key 分发与恢复协议
# ══════════════════════════════════════════════════════════════

_BOB = "bob.agentid.pub"
_CAROL = "carol.agentid.pub"
_MEMBERS3 = [_AID, _BOB, _CAROL]


class TestBuildKeyDistribution:
    def test_fields(self):
        gs = generate_group_secret()
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS3, _AID)
        assert dist["type"] == "e2ee.group_key_distribution"
        assert dist["group_id"] == _GRP
        assert dist["epoch"] == 1
        assert "group_secret" in dist
        assert "commitment" in dist
        assert dist["member_aids"] == sorted(_MEMBERS3)
        assert dist["distributed_by"] == _AID
        assert "distributed_at" in dist


class TestHandleKeyDistribution:
    def test_stores_secret(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs = generate_group_secret()
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID)

        result = handle_key_distribution(dist, ks, _BOB)
        assert result is True

        loaded = load_group_secret(ks, _BOB, _GRP)
        assert loaded is not None
        assert loaded["epoch"] == 1
        assert loaded["secret"] == gs

    def test_invalid_commitment(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs = generate_group_secret()
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID)
        dist["commitment"] = "0" * 64  # 伪造

        result = handle_key_distribution(dist, ks, _BOB)
        assert result is False

    def test_self_not_member(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs = generate_group_secret()
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID)

        # carol 不在 _MEMBERS 中
        result = handle_key_distribution(dist, ks, _CAROL)
        assert result is False

    def test_rejects_distribution_below_current_epoch(self, tmp_path):
        """key distribution 低于 current epoch 应拒绝防降级"""
        ks = _make_keystore(tmp_path)
        current_secret = generate_group_secret()
        current_commitment = compute_membership_commitment(_MEMBERS, 5, _GRP, current_secret)
        assert store_group_secret(ks, _BOB, _GRP, 5, current_secret, current_commitment, _MEMBERS)

        stale_secret = generate_group_secret()
        dist = build_key_distribution(_GRP, 3, stale_secret, _MEMBERS, _AID)
        assert handle_key_distribution(dist, ks, _BOB) is False
        assert load_group_secret(ks, _BOB, _GRP)["epoch"] == 5
        assert load_group_secret(ks, _BOB, _GRP, epoch=3) is None

    def test_epoch_update(self, tmp_path):
        """新 epoch 覆盖旧 epoch，旧的进入 old_epochs"""
        ks = _make_keystore(tmp_path)
        gs1 = generate_group_secret()
        gs2 = generate_group_secret()
        dist1 = build_key_distribution(_GRP, 1, gs1, _MEMBERS, _AID)
        dist2 = build_key_distribution(_GRP, 2, gs2, _MEMBERS, _AID)

        handle_key_distribution(dist1, ks, _BOB)
        handle_key_distribution(dist2, ks, _BOB)

        current = load_group_secret(ks, _BOB, _GRP)
        assert current["epoch"] == 2
        old = load_group_secret(ks, _BOB, _GRP, epoch=1)
        assert old is not None
        assert old["secret"] == gs1

    def test_rotation_id_rejects_chain_mismatch_with_trusted_prev(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs1 = generate_group_secret()
        commitment1 = compute_membership_commitment(_MEMBERS, 1, _GRP, gs1)
        chain1 = compute_epoch_chain(None, 1, commitment1, _AID)
        assert store_group_secret(ks, _BOB, _GRP, 1, gs1, commitment1, _MEMBERS, epoch_chain=chain1)

        gs2 = generate_group_secret()
        dist = build_key_distribution(_GRP, 2, gs2, _MEMBERS, _AID, epoch_chain="00" * 32)
        dist["rotation_id"] = "rot-test"

        assert handle_key_distribution(dist, ks, _BOB) is False
        assert load_group_secret(ks, _BOB, _GRP)["epoch"] == 1

    def test_new_rotation_replaces_stale_pending_same_epoch(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs1 = generate_group_secret()
        commitment1 = compute_membership_commitment(_MEMBERS, 1, _GRP, gs1)
        chain1 = compute_epoch_chain(None, 1, commitment1, _AID)
        assert store_group_secret(ks, _BOB, _GRP, 1, gs1, commitment1, _MEMBERS, epoch_chain=chain1)

        old_secret = generate_group_secret()
        old_commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, old_secret)
        old_chain = compute_epoch_chain(chain1, 2, old_commitment, _AID)
        assert store_group_secret(
            ks, _BOB, _GRP, 2, old_secret, old_commitment, _MEMBERS,
            epoch_chain=old_chain, pending_rotation_id="rot-old",
        )

        new_secret = generate_group_secret()
        new_commitment = compute_membership_commitment(_MEMBERS, 2, _GRP, new_secret)
        new_chain = compute_epoch_chain(chain1, 2, new_commitment, _AID)
        dist = build_key_distribution(_GRP, 2, new_secret, _MEMBERS, _AID, epoch_chain=new_chain)
        dist["rotation_id"] = "rot-new"

        assert handle_key_distribution(dist, ks, _BOB) is True
        loaded = load_group_secret(ks, _BOB, _GRP)
        assert loaded["secret"] == new_secret
        assert loaded["epoch_chain"] == new_chain
        assert loaded["pending_rotation_id"] == "rot-new"

    def test_missing_prev_chain_is_marked_unverified(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs = generate_group_secret()
        dist = build_key_distribution(_GRP, 2, gs, _MEMBERS, _AID, epoch_chain="00" * 32)

        assert handle_key_distribution(dist, ks, _BOB) is True
        loaded = load_group_secret(ks, _BOB, _GRP)
        assert loaded["epoch"] == 2
        assert loaded["epoch_chain_unverified"] is True
        assert loaded["epoch_chain_unverified_reason"] == "missing_prev_chain"

    def test_rotation_id_requires_epoch_chain(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs = generate_group_secret()
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID)
        dist["rotation_id"] = "rot-test"

        assert handle_key_distribution(dist, ks, _BOB) is False


class TestBuildKeyRequest:
    def test_fields(self):
        req = build_key_request(_GRP, 3, _BOB)
        assert req["type"] == "e2ee.group_key_request"
        assert req["group_id"] == _GRP
        assert req["epoch"] == 3
        assert req["requester_aid"] == _BOB


class TestHandleKeyRequest:
    def test_validates_membership(self, tmp_path):
        ks = _make_keystore(tmp_path)
        _store_secret(ks, epoch=1)
        req = build_key_request(_GRP, 1, "evil.agentid.pub")

        resp = handle_key_request(req, ks, _AID, _MEMBERS)
        assert resp is None

    def test_returns_response(self, tmp_path):
        ks = _make_keystore(tmp_path)
        gs = _store_secret(ks, epoch=2)
        req = build_key_request(_GRP, 2, _BOB)

        resp = handle_key_request(req, ks, _AID, _MEMBERS)
        assert resp is not None
        assert resp["type"] == "e2ee.group_key_response"
        assert resp["epoch"] == 2
        assert base64.b64decode(resp["group_secret"]) == gs
        assert "commitment" in resp
        assert "member_aids" in resp

    def test_response_expands_stale_epoch_membership_for_current_member(self, tmp_path):
        ks_alice = _make_keystore(tmp_path / "alice")
        ks_bob = _make_keystore(tmp_path / "bob")
        old_members = [_AID]
        gs = _random_secret()
        old_commitment = compute_membership_commitment(old_members, 1, _GRP, gs)
        store_group_secret(ks_alice, _AID, _GRP, 1, gs, old_commitment, old_members)

        req = build_key_request(_GRP, 1, _BOB)
        resp = handle_key_request(req, ks_alice, _AID, _MEMBERS)

        assert resp is not None
        assert resp["member_aids"] == sorted(_MEMBERS)
        assert resp["commitment"] == compute_membership_commitment(_MEMBERS, 1, _GRP, gs)
        assert handle_key_response(resp, ks_bob, _BOB) is True
        loaded = load_group_secret(ks_bob, _BOB, _GRP, 1)
        assert loaded is not None
        assert loaded["member_aids"] == sorted(_MEMBERS)


class TestHandleKeyResponse:
    def test_stores_secret(self, tmp_path):
        """收到响应后存储成功"""
        ks_alice = _make_keystore(tmp_path / "alice")
        ks_bob = _make_keystore(tmp_path / "bob")

        # Alice 有密钥
        gs = _store_secret(ks_alice, epoch=3)

        # Bob 发请求，Alice 回复
        req = build_key_request(_GRP, 3, _BOB)
        resp = handle_key_request(req, ks_alice, _AID, _MEMBERS)
        assert resp is not None

        # Bob 处理响应
        result = handle_key_response(resp, ks_bob, _BOB)
        assert result is True

        loaded = load_group_secret(ks_bob, _BOB, _GRP)
        assert loaded is not None
        assert loaded["epoch"] == 3
        assert loaded["secret"] == gs

    def test_key_response_backfills_old_epoch_without_overwriting_current(self, tmp_path):
        """key response 补旧 epoch 只写 old epoch，不覆盖 current。"""
        ks = _make_keystore(tmp_path)
        current_secret = generate_group_secret()
        current_commitment = compute_membership_commitment(_MEMBERS, 5, _GRP, current_secret)
        assert store_group_secret(ks, _BOB, _GRP, 5, current_secret, current_commitment, _MEMBERS)

        old_secret = generate_group_secret()
        old_commitment = compute_membership_commitment(_MEMBERS, 3, _GRP, old_secret)
        response = {
            "type": "e2ee.group_key_response",
            "group_id": _GRP,
            "epoch": 3,
            "group_secret": base64.b64encode(old_secret).decode("ascii"),
            "commitment": old_commitment,
            "member_aids": _MEMBERS,
            "requester_aid": _BOB,
            "responder_aid": _AID,
            "request_id": "req-old",
        }

        assert handle_key_response(response, ks, _BOB) is True
        assert load_group_secret(ks, _BOB, _GRP)["epoch"] == 5
        assert load_group_secret(ks, _BOB, _GRP, epoch=3)["secret"] == old_secret

    def test_key_response_rejects_future_epoch(self, tmp_path):
        """key response 不能绕过轮换推进到 future epoch。"""
        ks = _make_keystore(tmp_path)
        current_secret = generate_group_secret()
        current_commitment = compute_membership_commitment(_MEMBERS, 5, _GRP, current_secret)
        assert store_group_secret(ks, _BOB, _GRP, 5, current_secret, current_commitment, _MEMBERS)

        future_secret = generate_group_secret()
        future_commitment = compute_membership_commitment(_MEMBERS, 6, _GRP, future_secret)
        response = {
            "type": "e2ee.group_key_response",
            "group_id": _GRP,
            "epoch": 6,
            "group_secret": base64.b64encode(future_secret).decode("ascii"),
            "commitment": future_commitment,
            "member_aids": _MEMBERS,
            "requester_aid": _BOB,
            "responder_aid": _AID,
            "request_id": "req-future",
        }

        assert handle_key_response(response, ks, _BOB) is False
        assert load_group_secret(ks, _BOB, _GRP)["epoch"] == 5
        assert load_group_secret(ks, _BOB, _GRP, epoch=6) is None


class TestKeyDistributionP2PRoundtrip:
    def test_roundtrip(self, tmp_path):
        """分发消息经模拟 P2P 传输后内容完整可处理"""
        ks_alice = _make_keystore(tmp_path / "alice")
        ks_bob = _make_keystore(tmp_path / "bob")

        gs = generate_group_secret()
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID)

        # 模拟 P2P 传输：序列化 → 反序列化
        serialized = json.dumps(dist, ensure_ascii=False)
        deserialized = json.loads(serialized)

        result = handle_key_distribution(deserialized, ks_bob, _BOB)
        assert result is True

        loaded = load_group_secret(ks_bob, _BOB, _GRP)
        assert loaded["secret"] == gs

        # Bob 现在可以解密 Alice 发的群消息
        pk_pem, cert_pem = _ensure_default_signing_identity()
        msg_id = f"gm-{uuid.uuid4()}"
        envelope = encrypt_group_message(
            group_id=_GRP, epoch=1, group_secret=gs,
            payload={"type": "text", "text": "P2P 分发后的加密消息"},
            from_aid=_AID, message_id=msg_id, timestamp=1710504000000,
            sender_private_key_pem=pk_pem,
        )
        message = {
            "group_id": _GRP, "from": _AID, "message_id": msg_id,
            "timestamp": 1710504000000, "payload": envelope, "encrypted": True,
        }
        decrypted = decrypt_group_message(message, {1: gs}, sender_cert_pem=cert_pem)
        assert decrypted is not None
        assert decrypted["payload"]["text"] == "P2P 分发后的加密消息"


# ══════════════════════════════════════════════════════════════
# 阶段 4：安全增强与边界情况
# ══════════════════════════════════════════════════════════════

class TestEncryptFailureNoFallback:
    def test_encrypt_failure_does_not_fallback_plaintext(self):
        """加密异常 → 抛异常，不返回明文"""
        # 传入非法 group_secret（长度不对）→ HKDF 还是会生成 key，
        # 但如果传 None 会直接报错
        with pytest.raises(Exception):
            encrypt_group_message(
                group_id=_GRP, epoch=1,
                group_secret=None,  # type: ignore
                payload={"type": "text", "text": "test"},
                from_aid=_AID, message_id="gm-1", timestamp=100,
            )


class TestKeyRequestThrottle:
    def test_rate_limited(self):
        throttle = GroupKeyRequestThrottle(cooldown=30.0)
        assert throttle.allow("grp_1:epoch_3") is True
        assert throttle.allow("grp_1:epoch_3") is False
        # 不同 key 不受影响
        assert throttle.allow("grp_2:epoch_1") is True

    def test_reset(self):
        throttle = GroupKeyRequestThrottle(cooldown=30.0)
        throttle.allow("key1")
        throttle.reset("key1")
        assert throttle.allow("key1") is True


class TestNonceUniqueness:
    def test_nonce_uniqueness_per_message(self):
        """两条消息 nonce 不同"""
        gs = _random_secret()
        e1 = encrypt_group_message(
            group_id=_GRP, epoch=1, group_secret=gs,
            payload={"type": "text", "text": "a"}, from_aid=_AID, message_id="gm-1", timestamp=100,
        )
        e2 = encrypt_group_message(
            group_id=_GRP, epoch=1, group_secret=gs,
            payload={"type": "text", "text": "a"}, from_aid=_AID, message_id="gm-2", timestamp=100,
        )
        assert e1["nonce"] != e2["nonce"]


class TestGroupSecretNotInRepr:
    def test_not_leaked(self):
        """E2EEManager 不泄露 group_secret"""
        from aun_core.e2ee import E2EEManager

        mgr = E2EEManager(identity_fn=lambda: {}, keystore=None)
        r = repr(mgr)
        assert "group_secret" not in r.lower()


# ══════════════════════════════════════════════════════════════
# GroupE2EEManager 封装测试
# ══════════════════════════════════════════════════════════════

from aun_core.e2ee import GroupE2EEManager


# 用于 GroupE2EEManager 测试的签名身份缓存（AID → (pk_pem, cert_pem)）
_test_identities: dict[str, tuple[str, bytes]] = {}


def _get_test_identity(aid: str) -> tuple[str, bytes]:
    """获取指定 AID 的签名身份（延迟创建）"""
    if aid not in _test_identities:
        _test_identities[aid] = _make_signing_identity()
    return _test_identities[aid]


def _test_cert_resolver(aid: str) -> bytes | None:
    """测试用证书解析器 — 返回与签名私钥匹配的证书"""
    _, cert_pem = _get_test_identity(aid)
    return cert_pem


def _make_manager(tmp_path, aid=_AID):
    pk_pem, cert_pem = _get_test_identity(aid)
    ks = _make_keystore(tmp_path)
    return GroupE2EEManager(
        identity_fn=lambda: {"aid": aid, "private_key_pem": pk_pem},
        keystore=ks,
        sender_cert_resolver=_test_cert_resolver,
        initiator_cert_resolver=_test_cert_resolver,
    ), ks


class TestGroupE2EEManagerCreateEpoch:
    def test_create_and_store(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        info = mgr.create_epoch(_GRP, _MEMBERS)
        assert info["epoch"] == 1
        assert mgr.has_secret(_GRP)
        assert mgr.current_epoch(_GRP) == 1

    def test_returns_distributions(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        info = mgr.create_epoch(_GRP, _MEMBERS)
        # 不包含自己
        assert len(info["distributions"]) == len(_MEMBERS) - 1
        for d in info["distributions"]:
            assert "to" in d and "payload" in d
            assert d["payload"]["type"] == "e2ee.group_key_distribution"


class TestGroupE2EEManagerEncryptDecrypt:
    def test_roundtrip(self, tmp_path):
        alice_mgr, _ = _make_manager(tmp_path / "a")
        bob_mgr, bob_ks = _make_manager(tmp_path / "b", aid=_BOB)

        # Alice 创建 epoch
        info = alice_mgr.create_epoch(_GRP, _MEMBERS)

        # Bob 处理分发
        bob_mgr.handle_incoming(info["distributions"][0]["payload"])

        # Alice 加密
        envelope = alice_mgr.encrypt(_GRP, {"type": "text", "text": "via manager"})
        assert envelope["type"] == "e2ee.group_encrypted"

        # Bob 解密
        message = {
            "group_id": _GRP, "from": _AID, "sender_aid": _AID,
            "message_id": "gm-test", "timestamp": 100,
            "payload": envelope,
        }
        result = bob_mgr.decrypt(message)
        assert result is not None
        assert result["payload"]["text"] == "via manager"

    def test_encrypt_without_secret_raises(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        from aun_core.errors import E2EEGroupSecretMissingError
        with pytest.raises(E2EEGroupSecretMissingError):
            mgr.encrypt("grp_none", {"type": "text", "text": "fail"})

    def test_decrypt_with_replay_guard(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        mgr.create_epoch(_GRP, _MEMBERS)
        envelope = mgr.encrypt(_GRP, {"type": "text", "text": "replay"})
        message = {
            "group_id": _GRP, "from": _AID, "sender_aid": _AID,
            "message_id": "gm-replay-1", "timestamp": 100,
            "payload": envelope,
        }
        r1 = mgr.decrypt(message)
        assert r1 is not None and r1.get("e2ee")
        # 同 message_id 第二次 → 返回原始（重放）
        r2 = mgr.decrypt(message)
        assert r2.get("e2ee") is None  # 未解密

    def test_decrypt_batch(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        mgr.create_epoch(_GRP, _MEMBERS)
        msgs = []
        for i in range(3):
            env = mgr.encrypt(_GRP, {"type": "text", "text": f"batch_{i}"})
            msgs.append({
                "group_id": _GRP, "from": _AID, "sender_aid": _AID,
                "message_id": f"gm-batch-{i}", "timestamp": 100,
                "payload": env,
            })
        results = mgr.decrypt_batch(msgs)
        assert len(results) == 3
        assert all(r["payload"]["text"].startswith("batch_") for r in results)


class TestGroupE2EEManagerRotateEpoch:
    def test_rotate(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        mgr.create_epoch(_GRP, _MEMBERS)
        info = mgr.rotate_epoch(_GRP, _MEMBERS)
        assert info["epoch"] == 2
        assert mgr.current_epoch(_GRP) == 2
        # 旧 epoch 保留
        old = mgr.load_secret(_GRP, epoch=1)
        assert old is not None

    def test_downgrade_rejected(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        mgr.create_epoch(_GRP, _MEMBERS)
        mgr.rotate_epoch(_GRP, _MEMBERS)
        # 尝试手动存 epoch=1
        result = mgr.store_secret(_GRP, 1, _random_secret(), "fake", _MEMBERS)
        assert result is False
        assert mgr.current_epoch(_GRP) == 2


class TestGroupE2EEManagerHandleIncoming:
    def test_distribution(self, tmp_path):
        alice_mgr, _ = _make_manager(tmp_path / "a")
        bob_mgr, _ = _make_manager(tmp_path / "b", aid=_BOB)
        info = alice_mgr.create_epoch(_GRP, _MEMBERS)

        result = bob_mgr.handle_incoming(info["distributions"][0]["payload"])
        assert result == "distribution"
        assert bob_mgr.has_secret(_GRP)

    def test_request(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        req = {"type": "e2ee.group_key_request", "group_id": _GRP, "epoch": 1, "requester_aid": _BOB}
        result = mgr.handle_incoming(req)
        assert result == "request"

    def test_response(self, tmp_path):
        alice_mgr, _ = _make_manager(tmp_path / "a")
        bob_mgr, _ = _make_manager(tmp_path / "b", aid=_BOB)
        alice_mgr.create_epoch(_GRP, _MEMBERS)
        # Alice 手动构建 response
        req = {"type": "e2ee.group_key_request", "group_id": _GRP, "epoch": 1, "requester_aid": _BOB, "request_id": "test-req-1"}
        resp = alice_mgr.handle_key_request_msg(req, _MEMBERS)
        assert resp is not None

        # Bob 必须先注册 pending 请求，handle_incoming 才会接受响应
        bob_mgr.remember_key_request(req)
        result = bob_mgr.handle_incoming(resp)
        assert result == "response"
        assert bob_mgr.has_secret(_GRP)

    def test_unknown_type(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        result = mgr.handle_incoming({"type": "some.other"})
        assert result is None

    def test_distribution_rejected_on_epoch_downgrade(self, tmp_path):
        """旧 epoch 分发 → 返回 distribution_rejected"""
        bob_mgr, _ = _make_manager(tmp_path, aid=_BOB)
        # Bob 先有 epoch=3
        bob_mgr.create_epoch(_GRP, _MEMBERS)
        bob_mgr.rotate_epoch(_GRP, _MEMBERS)
        bob_mgr.rotate_epoch(_GRP, _MEMBERS)
        assert bob_mgr.current_epoch(_GRP) == 3

        # 构造 epoch=1 的分发消息
        alice_mgr, _ = _make_manager(tmp_path / "alice")
        info = alice_mgr.create_epoch(_GRP, _MEMBERS)
        result = bob_mgr.handle_incoming(info["distributions"][0]["payload"])
        assert result == "distribution_rejected"
        assert bob_mgr.current_epoch(_GRP) == 3  # 未被覆盖

    def test_response_rejected_on_epoch_downgrade(self, tmp_path):
        """旧 epoch 响应 → 返回 response_rejected"""
        bob_mgr, _ = _make_manager(tmp_path, aid=_BOB)
        bob_mgr.create_epoch(_GRP, _MEMBERS)
        bob_mgr.rotate_epoch(_GRP, _MEMBERS)
        assert bob_mgr.current_epoch(_GRP) == 2

        # 构造 epoch=1 的 response
        alice_mgr, _ = _make_manager(tmp_path / "alice")
        alice_mgr.create_epoch(_GRP, _MEMBERS)
        req = {"type": "e2ee.group_key_request", "group_id": _GRP, "epoch": 1, "requester_aid": _BOB}
        resp = alice_mgr.handle_key_request_msg(req, _MEMBERS)
        assert resp is not None

        result = bob_mgr.handle_incoming(resp)
        assert result == "response_rejected"
        assert bob_mgr.current_epoch(_GRP) == 2


class TestGroupE2EEManagerRecovery:
    def test_throttled(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        mgr.create_epoch(_GRP, _MEMBERS)
        r1 = mgr.build_recovery_request(_GRP, 2)
        assert r1 is not None
        r2 = mgr.build_recovery_request(_GRP, 2)
        assert r2 is None  # 限流


class TestGroupE2EEManagerState:
    def test_member_aids(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        mgr.create_epoch(_GRP, _MEMBERS)
        assert sorted(mgr.get_member_aids(_GRP)) == sorted(_MEMBERS)

    def test_no_secret(self, tmp_path):
        mgr, _ = _make_manager(tmp_path)
        assert not mgr.has_secret("grp_nonexist")
        assert mgr.current_epoch("grp_nonexist") is None
        assert mgr.get_member_aids("grp_nonexist") == []


# ── P2-1: 群消息发送方签名测试 ──────────────────────────────

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone


def _make_signing_identity():
    """生成用于签名测试的 identity (私钥 + 自签证书)。"""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _AID)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pk_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return pk_pem, cert_pem


class TestGroupSenderSignature:
    def test_encrypt_with_signature(self):
        pk_pem, cert_pem = _make_signing_identity()
        gs = _random_secret()
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "hello"}, from_aid=_AID,
            message_id="msg-1", timestamp=1000,
            sender_private_key_pem=pk_pem,
            sender_cert_pem=cert_pem,
        )
        assert "sender_signature" in envelope
        assert "sender_cert_fingerprint" in envelope
        assert envelope["sender_cert_fingerprint"].startswith("sha256:"), \
            "sender_cert_fingerprint 必须带 sha256: 前缀"

    def test_decrypt_verifies_signature(self):
        pk_pem, cert_pem = _make_signing_identity()
        gs = _random_secret()
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "secret"}, from_aid=_AID,
            message_id="msg-2", timestamp=2000,
            sender_private_key_pem=pk_pem,
        )
        message = {"group_id": _GRP, "from": _AID, "message_id": "msg-2", "payload": envelope}
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=cert_pem)
        assert result is not None
        assert result["e2ee"]["sender_verified"] is True

    def test_decrypt_no_signature_rejected_zero_trust(self):
        """零信任模式（默认）：无签名无证书 → 拒绝"""
        gs = _random_secret()
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "plain"}, from_aid=_AID,
            message_id="msg-3", timestamp=3000,
        )
        message = {"group_id": _GRP, "from": _AID, "message_id": "msg-3", "payload": envelope}
        # 默认 require_signature=True，无签名 → 拒绝
        result = decrypt_group_message(message, {1: gs})
        assert result is None

    def test_decrypt_no_signature_compat_mode(self):
        """非零信任模式（require_signature=False）：无签名无证书 → 兼容放行"""
        gs = _random_secret()
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "plain"}, from_aid=_AID,
            message_id="msg-3b", timestamp=3000,
        )
        message = {"group_id": _GRP, "from": _AID, "message_id": "msg-3b", "payload": envelope}
        result = decrypt_group_message(message, {1: gs}, require_signature=False)
        assert result is not None
        assert result["e2ee"]["sender_verified"] is False

    def test_decrypt_has_signature_but_no_cert_rejected(self):
        """有签名但无证书可验证 → 零信任模式拒绝"""
        pk_pem, cert_pem = _make_signing_identity()
        gs = _random_secret()
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "signed"}, from_aid=_AID,
            message_id="msg-nocert", timestamp=3500,
            sender_private_key_pem=pk_pem,
        )
        message = {"group_id": _GRP, "from": _AID, "message_id": "msg-nocert", "payload": envelope}
        # 有签名但 sender_cert_pem=None → 无法验证 → 拒绝
        result = decrypt_group_message(message, {1: gs})
        assert result is None

    def test_no_signature_rejected_when_cert_provided(self):
        """有证书但无签名 → 拒绝（零信任强制验签）"""
        pk_pem, cert_pem = _make_signing_identity()
        gs = _random_secret()
        # 不传 sender_private_key_pem → 无签名
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "no sig"}, from_aid=_AID,
            message_id="msg-nosig", timestamp=4000,
        )
        message = {"group_id": _GRP, "from": _AID, "message_id": "msg-nosig", "payload": envelope}
        # 传入 cert → 强制要求签名
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=cert_pem)
        assert result is None

    def test_wrong_cert_rejected(self):
        """错误的发送方证书 → 签名验证失败 → 拒绝"""
        pk_pem, cert_pem = _make_signing_identity()
        # 生成另一个身份的证书
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        wrong_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.aid")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
            .public_key(wrong_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .sign(wrong_key, hashes.SHA256())
        ).public_bytes(serialization.Encoding.PEM)

        gs = _random_secret()
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "test"}, from_aid=_AID,
            message_id="msg-wrong", timestamp=5000,
            sender_private_key_pem=pk_pem,
        )
        message = {"group_id": _GRP, "from": _AID, "message_id": "msg-wrong", "payload": envelope}
        # 用错误的证书验证 → 应拒绝
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=wrong_cert)
        assert result is None

    def test_sender_impersonation_rejected(self):
        """群成员 B 冒充 A 发消息 → 签名与 A 的证书不匹配 → 拒绝"""
        alice_pk, alice_cert = _make_signing_identity()
        bob_key = ec.generate_private_key(ec.SECP256R1())
        bob_pk = bob_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")

        gs = _random_secret()
        # Bob 用自己的私钥签名，但 from 写成 Alice
        envelope = encrypt_group_message(
            _GRP, 1, gs, {"type": "text", "text": "fake"}, from_aid=_AID,
            message_id="msg-impersonate", timestamp=6000,
            sender_private_key_pem=bob_pk,
        )
        message = {"group_id": _GRP, "from": _AID, "message_id": "msg-impersonate", "payload": envelope}
        # 用 Alice 的证书验证 → Bob 的签名不匹配 → 拒绝
        result = decrypt_group_message(message, {1: gs}, sender_cert_pem=alice_cert)
        assert result is None


# ── P2-3: Membership Manifest 测试 ──────────────────────────


class TestMembershipManifest:
    def test_build_manifest(self):
        manifest = build_membership_manifest(
            _GRP, 2, 1, _MEMBERS, added=[_BOB], removed=[], initiator_aid=_AID,
        )
        assert manifest["group_id"] == _GRP
        assert manifest["epoch"] == 2
        assert manifest["prev_epoch"] == 1
        assert _AID in manifest["initiator_aid"]

    def test_sign_and_verify(self):
        pk_pem, cert_pem = _make_signing_identity()
        manifest = build_membership_manifest(
            _GRP, 1, None, _MEMBERS, initiator_aid=_AID,
        )
        signed = sign_membership_manifest(manifest, pk_pem)
        assert "signature" in signed
        assert verify_membership_manifest(signed, cert_pem)

    def test_tampered_manifest_rejected(self):
        pk_pem, cert_pem = _make_signing_identity()
        manifest = build_membership_manifest(
            _GRP, 1, None, _MEMBERS, initiator_aid=_AID,
        )
        signed = sign_membership_manifest(manifest, pk_pem)
        signed["member_aids"] = ["mallory.test"]  # 篡改
        assert not verify_membership_manifest(signed, cert_pem)

    def test_distribution_with_manifest(self, tmp_path):
        pk_pem, cert_pem = _make_signing_identity()
        gs = _random_secret()
        manifest = build_membership_manifest(
            _GRP, 1, None, _MEMBERS, initiator_aid=_AID,
        )
        signed = sign_membership_manifest(manifest, pk_pem)
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID, manifest=signed)
        assert "manifest" in dist
        ks = _make_keystore(tmp_path)
        result = handle_key_distribution(dist, ks, _BOB, initiator_cert_pem=cert_pem)
        assert result is True


# ══════════════════════════════════════════════════════════════
# 安全修复测试：零信任攻击向量覆盖
# ══════════════════════════════════════════════════════════════


class TestReplayGuardUsesAADMessageId:
    """P0-2: 防重放必须使用 AAD 内 message_id，而非外层路由 ID。"""

    def test_server_rewritten_outer_id_detected_as_replay(self, tmp_path):
        """服务端改写外层 message_id 后重放同一密文 → 被拦截"""
        pk_pem, cert_pem = _make_signing_identity()
        mgr, ks = _make_manager(tmp_path)
        # 让 mgr 能验签
        ks.save_cert(_AID, cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else cert_pem)
        mgr._sender_cert_resolver = lambda aid: ks.load_cert(aid)

        mgr.create_epoch(_GRP, _MEMBERS)
        # 获取 identity 私钥用于签名
        secret_data = mgr.load_secret(_GRP)
        envelope = encrypt_group_message(
            _GRP, 1, secret_data["secret"], {"type": "text", "text": "hello"},
            from_aid=_AID, message_id="aad-msg-1", timestamp=1000,
            sender_private_key_pem=pk_pem,
        )
        msg1 = {
            "group_id": _GRP, "from": _AID, "sender_aid": _AID,
            "message_id": "outer-1",  # 外层 ID
            "timestamp": 1000, "payload": envelope,
        }
        r1 = mgr.decrypt(msg1)
        assert r1 is not None and r1.get("e2ee")

        # 服务端改写外层 message_id 后重放
        msg2 = dict(msg1)
        msg2["message_id"] = "outer-2"  # 不同的外层 ID
        r2 = mgr.decrypt(msg2)
        # 应被拦截（AAD 内 message_id 相同）
        assert r2 is not None and r2.get("e2ee") is None

    def test_different_aad_message_id_passes(self, tmp_path):
        """不同 AAD message_id 的消息不互相阻拦"""
        pk_pem, cert_pem = _make_signing_identity()
        mgr, ks = _make_manager(tmp_path)
        ks.save_cert(_AID, cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else cert_pem)
        mgr._sender_cert_resolver = lambda aid: ks.load_cert(aid)

        mgr.create_epoch(_GRP, _MEMBERS)
        secret_data = mgr.load_secret(_GRP)
        for i in range(3):
            envelope = encrypt_group_message(
                _GRP, 1, secret_data["secret"], {"type": "text", "text": f"msg-{i}"},
                from_aid=_AID, message_id=f"aad-msg-{i}", timestamp=1000 + i,
                sender_private_key_pem=pk_pem,
            )
            msg = {
                "group_id": _GRP, "from": _AID, "sender_aid": _AID,
                "message_id": f"outer-{i}", "timestamp": 1000 + i, "payload": envelope,
            }
            r = mgr.decrypt(msg)
            assert r is not None and r.get("e2ee"), f"msg-{i} should decrypt"


class TestDistributionManifestMandatory:
    """P0-4: 有 cert resolver 时分发必须带 manifest。"""

    def test_distribution_without_manifest_rejected(self, tmp_path):
        """有 initiator_cert 但无 manifest → 拒绝"""
        pk_pem, cert_pem = _make_signing_identity()
        ks = _make_keystore(tmp_path)
        gs = generate_group_secret()
        # 不带 manifest 的分发
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID)
        assert "manifest" not in dist
        # 传入 cert → 强制要求 manifest
        result = handle_key_distribution(dist, ks, _BOB, initiator_cert_pem=cert_pem)
        assert result is False

    def test_distribution_with_wrong_signer_rejected(self, tmp_path):
        """manifest 签名者与发起者不匹配 → 拒绝"""
        pk_pem, cert_pem = _make_signing_identity()
        # 用另一个密钥签名
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_pk = wrong_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        gs = generate_group_secret()
        manifest = build_membership_manifest(_GRP, 1, None, _MEMBERS, initiator_aid=_AID)
        signed = sign_membership_manifest(manifest, wrong_pk)  # 用错误的密钥签名
        dist = build_key_distribution(_GRP, 1, gs, _MEMBERS, _AID, manifest=signed)
        ks = _make_keystore(tmp_path)
        # 用正确的证书验证 → 签名不匹配 → 拒绝
        result = handle_key_distribution(dist, ks, _BOB, initiator_cert_pem=cert_pem)
        assert result is False

    def test_manager_auto_signs_manifest(self, tmp_path):
        """GroupE2EEManager.create_epoch 自动签名 manifest"""
        pk_pem, cert_pem = _make_signing_identity()
        ks = _make_keystore(tmp_path)
        mgr = GroupE2EEManager(
            identity_fn=lambda: {"aid": _AID, "private_key_pem": pk_pem},
            keystore=ks,
        )
        info = mgr.create_epoch(_GRP, _MEMBERS)
        for d in info["distributions"]:
            assert "manifest" in d["payload"]
            assert "signature" in d["payload"]["manifest"]

    def test_manager_handle_incoming_verifies_manifest(self, tmp_path):
        """handle_incoming 有 resolver 时验证 manifest 签名"""
        pk_pem, cert_pem = _make_signing_identity()
        alice_ks = _make_keystore(tmp_path / "alice")
        bob_ks = _make_keystore(tmp_path / "bob")
        # Bob 的 keystore 有 Alice 的证书
        bob_ks.save_cert(_AID, cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else cert_pem)

        alice_mgr = GroupE2EEManager(
            identity_fn=lambda: {"aid": _AID, "private_key_pem": pk_pem},
            keystore=alice_ks,
        )
        bob_mgr = GroupE2EEManager(
            identity_fn=lambda: {"aid": _BOB},
            keystore=bob_ks,
            initiator_cert_resolver=lambda aid: bob_ks.load_cert(aid),
        )
        info = alice_mgr.create_epoch(_GRP, _MEMBERS)
        result = bob_mgr.handle_incoming(info["distributions"][0]["payload"])
        assert result == "distribution"
        assert bob_mgr.has_secret(_GRP)


class TestCommitmentBindsGroupSecret:
    """P0-3: commitment 必须绑定 group_secret，替换密钥会被检测。"""

    def test_replaced_secret_detected(self, tmp_path):
        """恶意服务端替换 group_secret → commitment 不匹配 → 拒绝"""
        pk_pem, cert_pem = _make_signing_identity()
        gs_real = generate_group_secret()
        gs_fake = generate_group_secret()
        # 用真实密钥生成 commitment
        commitment = compute_membership_commitment(_MEMBERS, 1, _GRP, gs_real)
        manifest = sign_membership_manifest(
            build_membership_manifest(_GRP, 1, None, _MEMBERS, initiator_aid=_AID),
            pk_pem,
        )
        # 构造分发消息但替换 group_secret
        dist = {
            "type": "e2ee.group_key_distribution",
            "group_id": _GRP, "epoch": 1,
            "group_secret": base64.b64encode(gs_fake).decode("ascii"),  # 替换
            "commitment": commitment,  # 用原始 commitment
            "member_aids": sorted(_MEMBERS),
            "distributed_by": _AID,
            "distributed_at": 1000,
            "manifest": manifest,
        }
        ks = _make_keystore(tmp_path)
        result = handle_key_distribution(dist, ks, _BOB, initiator_cert_pem=cert_pem)
        assert result is False  # commitment 不匹配
