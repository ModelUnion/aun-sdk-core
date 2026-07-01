"""KeyStore 完备测试。

覆盖场景：
- _CompositeLocalStore: 身份完整生命周期（创建→保存→重启→加载）
- 数据持久化: Token（通过 CRUD API）
"""

import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from aun_core.keystore.local_identity_store import LocalIdentityStore, _METADATA_LOCKS_LIMIT
from aun_core.keystore.local_token_store import LocalTokenStore
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class _CompositeLocalStore:
    """测试专用组合器：生产代码不再暴露混合 KeyStore。"""

    def __init__(self, root=None, *, encryption_seed=None, logger=None) -> None:
        self.identity = LocalIdentityStore(root, encryption_seed=encryption_seed, logger=logger)
        self.token = LocalTokenStore(root, logger=logger)
        self._root = self.identity._root
        self._aids_root = self.identity._aids_root
        self._metadata_locks = self.identity._metadata_locks

    def close(self) -> None:
        self.identity.close()
        self.token.close()

    def _get_metadata_lock(self, aid: str):
        return self.identity._get_metadata_lock(aid)

    def save_cert(self, aid: str, cert_pem: str, cert_fingerprint: str | None = None, *, make_active: bool = True) -> None:
        self.token.save_cert(aid, cert_pem, cert_fingerprint, make_active=make_active)

    def load_cert(self, aid: str, cert_fingerprint: str | None = None) -> str | None:
        return self.token.load_cert(aid, cert_fingerprint)

    def __getattr__(self, name: str):
        if hasattr(self.identity, name):
            return getattr(self.identity, name)
        return getattr(self.token, name)



# ── (已删除) FileSecretStore / VolatileSecretStore 测试 ───
# secret_store 模块已在 Phase 3 中删除，相关测试随之移除。


# ── _CompositeLocalStore 测试 ─────────────────────────────────────


class Test_CompositeLocalStore:
    """测试 _CompositeLocalStore 完整的身份生命周期。"""

    SAMPLE_KEY_PAIR = {
        "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----",
        "public_key_der_b64": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        "curve": "P-256",
    }
    SAMPLE_CERT = "-----BEGIN CERTIFICATE-----\nMIIBxjCC...\n-----END CERTIFICATE-----"
    SAMPLE_AID = "test-user.agentid.pub"

    def test_save_and_load_key_pair(self, tmp_path):
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        loaded = ks.load_key_pair(self.SAMPLE_AID)
        assert loaded is not None
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]
        assert loaded["public_key_der_b64"] == self.SAMPLE_KEY_PAIR["public_key_der_b64"]
        assert loaded["curve"] == self.SAMPLE_KEY_PAIR["curve"]

    def test_key_pair_survives_restart(self, tmp_path):
        """模拟进程重启：新实例能恢复私钥。"""
        ks1 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks1.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        # 新实例（模拟重启）
        ks2 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        loaded = ks2.load_key_pair(self.SAMPLE_AID)
        assert loaded is not None
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

    def test_key_pair_survives_restart_auto_seed(self, tmp_path):
        """不提供 encryption_seed，自动生成种子，重启后仍可恢复。"""
        ks1 = _CompositeLocalStore(tmp_path)
        ks1.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        ks2 = _CompositeLocalStore(tmp_path)
        loaded = ks2.load_key_pair(self.SAMPLE_AID)
        assert loaded is not None
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

    def test_save_and_load_cert(self, tmp_path):
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks.save_cert(self.SAMPLE_AID, self.SAMPLE_CERT)

        loaded = ks.load_cert(self.SAMPLE_AID)
        assert loaded == self.SAMPLE_CERT

    def test_save_and_load_identity(self, tmp_path):
        """save_identity 拆分保存 key_pair + cert + tokens，均能恢复。"""
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        identity = {
            **self.SAMPLE_KEY_PAIR,
            "cert": self.SAMPLE_CERT,
            "aid": self.SAMPLE_AID,
            "access_token": "tok_abc",
        }
        ks.save_identity(self.SAMPLE_AID, identity)

        loaded_identity = ks.load_identity(self.SAMPLE_AID)
        assert loaded_identity is not None

        loaded_kp = ks.load_key_pair(self.SAMPLE_AID)
        assert loaded_kp["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

        loaded_cert = ks.load_cert(self.SAMPLE_AID)
        assert loaded_cert == self.SAMPLE_CERT

    def test_identity_survives_restart(self, tmp_path):
        """完整身份（私钥 + 证书 + token）跨重启恢复。"""
        identity = {
            **self.SAMPLE_KEY_PAIR,
            "cert": self.SAMPLE_CERT,
            "aid": self.SAMPLE_AID,
            "access_token": "tok_abc",
        }

        ks1 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks1.save_identity(self.SAMPLE_AID, identity)

        ks2 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        loaded_kp = ks2.load_key_pair(self.SAMPLE_AID)
        assert loaded_kp is not None
        assert loaded_kp["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

        loaded_cert = ks2.load_cert(self.SAMPLE_AID)
        assert loaded_cert == self.SAMPLE_CERT

    def test_multiple_aids(self, tmp_path):
        """多个 AID 互不干扰。"""
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        kp_alice = {**self.SAMPLE_KEY_PAIR, "private_key_pem": "ALICE_KEY"}
        kp_bob = {**self.SAMPLE_KEY_PAIR, "private_key_pem": "BOB_KEY"}

        ks.save_key_pair("alice.agentid.pub", kp_alice)
        ks.save_key_pair("bob.agentid.pub", kp_bob)

        assert ks.load_key_pair("alice.agentid.pub")["private_key_pem"] == "ALICE_KEY"
        assert ks.load_key_pair("bob.agentid.pub")["private_key_pem"] == "BOB_KEY"

    def test_volatile_secret_store_rejected(self, tmp_path):
        """SQLCipher 迁移后 secret_store 参数被忽略，不再需要检查 persisted。
        改为验证无 seed 时自动生成 .seed，仍可正常保存和读取私钥。
        """
        ks = _CompositeLocalStore(tmp_path)
        ks.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())
        loaded = ks.load_key_pair(self.SAMPLE_AID)
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

    def test_key_pair_file_does_not_contain_plaintext_private_key(self, tmp_path):
        """key.json 文件中不应出现明文私钥。"""
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        # 读取磁盘上的 key.json
        import json
        safe_aid = self.SAMPLE_AID.replace("/", "_").replace("\\", "_")
        key_file = tmp_path / "AIDs" / safe_aid / "private" / "key.json"
        raw = json.loads(key_file.read_text(encoding="utf-8"))

        assert "private_key_pem" not in raw, "明文私钥不应出现在 key.json 中"
        assert "private_key_protection" in raw
        assert raw["private_key_protection"]["persisted"] is True

    def test_load_key_pair_migrates_legacy_plaintext_key_json(self, tmp_path):
        """历史明文 key.json 首次加载后应立即加密回写。"""
        aid = "legacy-plaintext.agentid.pub"
        key_file = tmp_path / "AIDs" / aid / "private" / "key.json"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(json.dumps({
            "private_key_pem": "LEGACY_PLAINTEXT_PRIVATE",
            "public_key_der_b64": "pub",
            "curve": "P-256",
        }), encoding="utf-8")

        ks = _CompositeLocalStore(tmp_path, encryption_seed="new-seed")
        loaded = ks.load_key_pair(aid)
        assert loaded["private_key_pem"] == "LEGACY_PLAINTEXT_PRIVATE"

        raw_text = key_file.read_text(encoding="utf-8")
        raw = json.loads(raw_text)
        assert "private_key_pem" not in raw
        assert "LEGACY_PLAINTEXT_PRIVATE" not in raw_text
        assert raw["private_key_protection"]["scheme"] == "file_aes"

    def test_load_key_pair_wrong_seed_preserves_key_json(self, tmp_path):
        """seed_password 不匹配可报错，但不能破坏原 key.json。"""
        aid = "wrong-load-seed.agentid.pub"
        ks = _CompositeLocalStore(tmp_path, encryption_seed="correct-seed")
        ks.save_key_pair(aid, {
            "private_key_pem": "CORRECT_SEED_PRIVATE",
            "public_key_der_b64": "pub",
            "curve": "P-256",
        })
        key_file = tmp_path / "AIDs" / aid / "private" / "key.json"
        before = key_file.read_text(encoding="utf-8")

        wrong = _CompositeLocalStore(tmp_path, encryption_seed="wrong-seed")
        with pytest.raises(ValueError, match="private key decrypt failed"):
            wrong.load_key_pair(aid)
        assert key_file.read_text(encoding="utf-8") == before
        assert ks.load_key_pair(aid)["private_key_pem"] == "CORRECT_SEED_PRIVATE"

    def test_load_pending_key_pair_migrates_legacy_plaintext(self, tmp_path):
        """pending key.json 即使是历史明文，也应在读取时加密回写。"""
        aid = "pending-legacy.agentid.pub"
        ks = _CompositeLocalStore(tmp_path, encryption_seed="pending-seed")
        pending_dir = ks.pending_identity_dir(aid)
        key_file = pending_dir / "private" / "key.json"
        key_file.write_text(json.dumps({
            "private_key_pem": "PENDING_PLAINTEXT_PRIVATE",
            "public_key_der_b64": "pub",
            "curve": "P-256",
        }), encoding="utf-8")

        loaded = ks.load_pending_key_pair(pending_dir, aid)
        assert loaded["private_key_pem"] == "PENDING_PLAINTEXT_PRIVATE"
        raw_text = key_file.read_text(encoding="utf-8")
        raw = json.loads(raw_text)
        assert "private_key_pem" not in raw
        assert "PENDING_PLAINTEXT_PRIVATE" not in raw_text
        assert raw["private_key_protection"]["scheme"] == "file_aes"

    def test_load_pending_key_pair_wrong_seed_preserves_pending(self, tmp_path):
        """pending 私钥 seed 不匹配时保留 pending 数据，供正确 seed 后续恢复。"""
        aid = "pending-wrong-seed.agentid.pub"
        correct = _CompositeLocalStore(tmp_path, encryption_seed="correct-seed")
        pending_dir = correct.pending_identity_dir(aid)
        correct.save_pending_key_pair(pending_dir, aid, {
            "private_key_pem": "PENDING_CORRECT_PRIVATE",
            "public_key_der_b64": "pub",
            "curve": "P-256",
        })
        key_file = pending_dir / "private" / "key.json"
        before = key_file.read_text(encoding="utf-8")

        wrong = _CompositeLocalStore(tmp_path, encryption_seed="wrong-seed")
        with pytest.raises(ValueError, match="private key decrypt failed"):
            wrong.load_pending_key_pair(pending_dir, aid)
        assert key_file.exists()
        assert key_file.read_text(encoding="utf-8") == before

    def test_load_nonexistent_aid(self, tmp_path):
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        assert ks.load_key_pair("nonexistent.agentid.pub") is None
        assert ks.load_cert("nonexistent.agentid.pub") is None
        assert ks.load_identity("nonexistent.agentid.pub") is None

    def test_identity_merge_not_overwrite(self, tmp_path):
        """save_identity 应合并 KV 字段，不覆盖已有字段。"""
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")

        # 第一次保存
        ks.save_identity(self.SAMPLE_AID, {
            **self.SAMPLE_KEY_PAIR,
            "aid": self.SAMPLE_AID,
            "field_a": "value_a",
        })

        # 第二次保存（不含 field_a）
        ks.save_identity(self.SAMPLE_AID, {
            "aid": self.SAMPLE_AID,
            "field_b": "value_b",
        })

        loaded = ks.load_identity(self.SAMPLE_AID)
        assert loaded.get("field_a") == "value_a", "field_a 不应被覆盖"
        assert loaded.get("field_b") == "value_b", "field_b 应被新增"


# ── Token 持久化测试 ──────────────────────────────────────


class TestTokenPersistence:
    """测试 access_token / refresh_token / kite_token 的加密持久化。
    通过 save_identity / load_identity 间接验证 token 持久化。"""

    AID = "token-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return _CompositeLocalStore(tmp_path, encryption_seed=seed)

    def test_tokens_saved_and_restored(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at_abc123",
            "refresh_token": "rt_xyz789",
            "kite_token": "kt_000",
        })

        loaded = ks.load_identity(self.AID)
        assert loaded["access_token"] == "at_abc123"
        assert loaded["refresh_token"] == "rt_xyz789"
        assert loaded["kite_token"] == "kt_000"

    def test_tokens_survive_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at_persist",
            "refresh_token": "rt_persist",
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_identity(self.AID)
        assert loaded["access_token"] == "at_persist"
        assert loaded["refresh_token"] == "rt_persist"

    def test_tokens_not_plaintext_on_disk(self, tmp_path):
        """token 存储在 SQLCipher 加密的 aun.db 中，不应出现在 meta.json。"""
        ks = self._make_ks(tmp_path)
        ks.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at_secret",
            "refresh_token": "rt_secret",
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        db_file = tmp_path / "AIDs" / safe_aid / "aun.db"
        assert db_file.exists(), "aun.db 应该存在"
        # meta.json 不应存在或不应包含明文 token
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        if meta_file.exists():
            raw = json.loads(meta_file.read_text(encoding="utf-8"))
            assert "access_token" not in raw
            assert "refresh_token" not in raw

    def test_token_update_preserves_other_tokens(self, tmp_path):
        """更新一个 token 不丢失其他 token。"""
        ks = self._make_ks(tmp_path)
        ks.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at_old",
            "refresh_token": "rt_keep",
        })
        # 仅更新 access_token
        ks.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at_new",
        })

        loaded = ks.load_identity(self.AID)
        assert loaded["access_token"] == "at_new"
        assert loaded["refresh_token"] == "rt_keep"

    def test_instance_state_isolated_between_slots(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_instance_state(self.AID, "device-1", "slot-a", {
            "access_token": "token-a",
            "seq_tracker_state": {"p2p:alice": {"next_expected": 3}},
        })
        ks.save_instance_state(self.AID, "device-1", "slot-b", {
            "access_token": "token-b",
            "seq_tracker_state": {"p2p:alice": {"next_expected": 7}},
        })

        slot_a = ks.load_instance_state(self.AID, "device-1", "slot-a")
        slot_b = ks.load_instance_state(self.AID, "device-1", "slot-b")

        assert slot_a["access_token"] == "token-a"
        assert slot_b["access_token"] == "token-b"
        assert slot_a["seq_tracker_state"]["p2p:alice"]["next_expected"] == 3
        assert slot_b["seq_tracker_state"]["p2p:alice"]["next_expected"] == 7

    def test_legacy_instance_state_schema_without_slot_id_full_is_migrated(self, tmp_path):
        aid = "legacy-slot-schema.agentid.pub"
        aid_dir = tmp_path / "AIDs" / aid
        aid_dir.mkdir(parents=True)
        db_path = aid_dir / "aun.db"
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """CREATE TABLE instance_state (
                    device_id TEXT NOT NULL,
                    slot_id TEXT NOT NULL DEFAULT '_singleton',
                    data TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (device_id, slot_id)
                )"""
            )
            conn.execute(
                """CREATE TABLE seq_tracker (
                    device_id TEXT NOT NULL,
                    slot_id TEXT NOT NULL DEFAULT '_singleton',
                    namespace TEXT NOT NULL,
                    contiguous_seq INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (device_id, slot_id, namespace)
                )"""
            )
            conn.commit()
        finally:
            conn.close()

        ks = LocalTokenStore(tmp_path)
        try:
            ks.save_instance_state(aid, "device-1", "slot-a", {"access_token": "token-a"})
            assert ks.load_instance_state(aid, "device-1", "slot-a")["access_token"] == "token-a"
        finally:
            ks.close()

        conn = sqlite3.connect(db_path)
        try:
            instance_columns = {row[1] for row in conn.execute("PRAGMA table_info(instance_state)").fetchall()}
            seq_columns = {row[1] for row in conn.execute("PRAGMA table_info(seq_tracker)").fetchall()}
        finally:
            conn.close()

        assert "slot_id_full" in instance_columns
        assert "slot_id_full" in seq_columns




# ── Peer 证书持久化测试 ──────────────────────────────────


class TestPeerCertPersistence:
    """测试对方证书的持久化存储。"""

    def test_peer_cert_saved_and_loaded(self, tmp_path):
        """通过 save_cert/load_cert 存储和读取对方证书。"""
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        peer_cert = "-----BEGIN CERTIFICATE-----\nPEER_CERT_DATA\n-----END CERTIFICATE-----"
        ks.save_cert("peer.agentid.pub", peer_cert)

        loaded = ks.load_cert("peer.agentid.pub")
        assert loaded == peer_cert

    def test_peer_cert_survives_restart(self, tmp_path):
        ks1 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks1.save_cert("peer.agentid.pub", "PEER_CERT")

        ks2 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        assert ks2.load_cert("peer.agentid.pub") == "PEER_CERT"

    def test_multiple_peer_certs(self, tmp_path):
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks.save_cert("alice.agentid.pub", "CERT_ALICE")
        ks.save_cert("bob.agentid.pub", "CERT_BOB")

        assert ks.load_cert("alice.agentid.pub") == "CERT_ALICE"
        assert ks.load_cert("bob.agentid.pub") == "CERT_BOB"

    def test_own_cert_and_peer_cert_coexist(self, tmp_path):
        """自己的证书和对方的证书可以共存。"""
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        ks.save_cert("myself.agentid.pub", "MY_CERT")
        ks.save_cert("peer.agentid.pub", "PEER_CERT")

        assert ks.load_cert("myself.agentid.pub") == "MY_CERT"
        assert ks.load_cert("peer.agentid.pub") == "PEER_CERT"

    def test_peer_cert_versions_saved_by_fingerprint(self, tmp_path):
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        old_cert = _make_real_cert("peer.agentid.pub")
        new_cert = _make_real_cert("peer.agentid.pub")
        old_fp = _fingerprint_of_cert(old_cert)
        new_fp = _fingerprint_of_cert(new_cert)

        ks.save_cert("peer.agentid.pub", old_cert, cert_fingerprint=old_fp, make_active=False)
        ks.save_cert("peer.agentid.pub", new_cert)

        assert ks.load_cert("peer.agentid.pub") == new_cert
        assert ks.load_cert("peer.agentid.pub", old_fp) == old_cert
        assert ks.load_cert("peer.agentid.pub", new_fp) == new_cert

    def test_peer_cert_versions_survive_restart(self, tmp_path):
        ks1 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        old_cert = _make_real_cert("peer.agentid.pub")
        new_cert = _make_real_cert("peer.agentid.pub")
        old_fp = _fingerprint_of_cert(old_cert)
        new_fp = _fingerprint_of_cert(new_cert)

        ks1.save_cert("peer.agentid.pub", old_cert, cert_fingerprint=old_fp, make_active=False)
        ks1.save_cert("peer.agentid.pub", new_cert)

        ks2 = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        assert ks2.load_cert("peer.agentid.pub", old_fp) == old_cert
        assert ks2.load_cert("peer.agentid.pub", new_fp) == new_cert

    def test_peer_cert_fingerprint_mismatch_does_not_fallback_to_active(self, tmp_path):
        ks = _CompositeLocalStore(tmp_path, encryption_seed="seed")
        active_cert = _make_real_cert("peer.agentid.pub")
        other_cert = _make_real_cert("peer.agentid.pub")
        other_fp = _fingerprint_of_cert(other_cert)

        ks.save_cert("peer.agentid.pub", active_cert)

        assert ks.load_cert("peer.agentid.pub", other_fp) is None


def _make_real_cert(cn: str) -> str:
    from datetime import datetime, timedelta, timezone

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _fingerprint_of_cert(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()


class TestListIdentitiesAndLoadMetadata:
    """PY-001: _CompositeLocalStore 必须实现 list_identities() 和 load_metadata()。"""

    AID_1 = "alice.agentid.pub"
    AID_2 = "bob.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return _CompositeLocalStore(tmp_path, encryption_seed=seed)

    def test_list_identities_empty(self, tmp_path):
        """无身份时返回空列表。"""
        ks = self._make_ks(tmp_path)
        assert ks.list_identities() == []

    def test_list_identities_single(self, tmp_path):
        """保存一个身份后能列出。"""
        ks = self._make_ks(tmp_path)
        ks.save_key_pair(self.AID_1, {
            "private_key_pem": "KEY_1",
            "public_key_der_b64": "PUB_1",
            "curve": "P-256",
        })
        result = ks.list_identities()
        assert self.AID_1 in result

    def test_list_identities_multiple(self, tmp_path):
        """多个身份全部列出。"""
        ks = self._make_ks(tmp_path)
        ks.save_key_pair(self.AID_1, {
            "private_key_pem": "KEY_1",
            "public_key_der_b64": "PUB_1",
            "curve": "P-256",
        })
        ks.save_key_pair(self.AID_2, {
            "private_key_pem": "KEY_2",
            "public_key_der_b64": "PUB_2",
            "curve": "P-256",
        })
        result = ks.list_identities()
        assert self.AID_1 in result
        assert self.AID_2 in result
        assert len(result) >= 2

    def test_list_identities_survives_restart(self, tmp_path):
        """重启后 list_identities 结果不变。"""
        ks1 = self._make_ks(tmp_path)
        ks1.save_key_pair(self.AID_1, {
            "private_key_pem": "KEY_1",
            "public_key_der_b64": "PUB_1",
            "curve": "P-256",
        })
        ks2 = self._make_ks(tmp_path)
        assert self.AID_1 in ks2.list_identities()

    def test_load_metadata_basic(self, tmp_path):
        """load_metadata 返回 AID 的基本元数据。"""
        ks = self._make_ks(tmp_path)
        ks.save_identity(self.AID_1, {
            "aid": self.AID_1,
            "private_key_pem": "KEY",
            "public_key_der_b64": "PUB",
            "curve": "P-256",
            "custom_field": "test_value",
        })
        md = ks.load_metadata(self.AID_1)
        assert md is not None
        assert isinstance(md, dict)

    def test_load_metadata_nonexistent(self, tmp_path):
        """不存在的 AID 返回 None 或空字典。"""
        ks = self._make_ks(tmp_path)
        md = ks.load_metadata("nonexistent.agentid.pub")
        assert md is None or md == {}

    def test_load_metadata_has_cert_fingerprint(self, tmp_path):
        """有证书时 metadata 包含 cert_fingerprint。"""
        cert_pem = _make_real_cert(self.AID_1)
        fp = _fingerprint_of_cert(cert_pem)
        ks = self._make_ks(tmp_path)
        ks.save_key_pair(self.AID_1, {
            "private_key_pem": "KEY",
            "public_key_der_b64": "PUB",
            "curve": "P-256",
        })
        ks.save_cert(self.AID_1, cert_pem)
        md = ks.load_metadata(self.AID_1)
        assert md is not None
        assert md.get("cert_fingerprint") == fp


class TestMetadataLocksBounded:
    """PY-016: _metadata_locks 应为实例变量，不同实例互不干扰。"""

    def test_metadata_locks_bounded(self, tmp_path):
        """大量不同 AID 访问后，_metadata_locks 应有上限。"""
        

        ks = _CompositeLocalStore(root=str(tmp_path))
        # 触发大量不同 AID 的锁创建
        for i in range(_METADATA_LOCKS_LIMIT + 100):
            ks._get_metadata_lock(f"aid-{i}.test")

        assert len(ks._metadata_locks) <= _METADATA_LOCKS_LIMIT

    def test_metadata_locks_are_instance_level(self, tmp_path):
        """不同 aun_path 的实例拥有独立的 _metadata_locks，互不竞争。"""
        dir_a = tmp_path / "store_a"
        dir_b = tmp_path / "store_b"
        ks_a = _CompositeLocalStore(root=str(dir_a), encryption_seed="seed_a")
        ks_b = _CompositeLocalStore(root=str(dir_b), encryption_seed="seed_b")

        # 在实例 A 中获取锁
        lock_a = ks_a._get_metadata_lock("shared.aid")
        # 在实例 B 中获取同名 AID 的锁
        lock_b = ks_b._get_metadata_lock("shared.aid")

        # 两个实例的锁应该是不同对象（实例隔离）
        assert lock_a is not lock_b, "_metadata_locks 应为实例变量，不同实例不共享锁"

        # 各实例的锁字典独立
        assert "shared.aid" in ks_a._metadata_locks
        assert "shared.aid" in ks_b._metadata_locks
        assert ks_a._metadata_locks is not ks_b._metadata_locks

    def test_metadata_locks_no_class_level_dict(self, tmp_path):
        """确保 _metadata_locks 不再是类变量（不通过类访问）。"""
        ks = _CompositeLocalStore(root=str(tmp_path))
        # 实例应有自己的 _metadata_locks
        assert hasattr(ks, '_metadata_locks')
        assert isinstance(ks._metadata_locks, dict)
        # _get_metadata_lock 应该是实例方法，不是类方法
        import inspect
        assert not isinstance(
            inspect.getattr_static(_CompositeLocalStore, '_get_metadata_lock'),
            classmethod
        ), "_get_metadata_lock 不应再是 classmethod"

