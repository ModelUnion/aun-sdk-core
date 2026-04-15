"""KeyStore 完备测试。

覆盖场景：
- FileKeyStore: 身份完整生命周期（创建→保存→重启→加载）
- 数据持久化: Token、Prekey、Group Secret（通过各自的 CRUD API）
"""

import json
import threading
import time
from pathlib import Path

import pytest

from aun_core.keystore.file import FileKeyStore
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


# ── (已删除) FileSecretStore / VolatileSecretStore 测试 ───
# secret_store 模块已在 Phase 3 中删除，相关测试随之移除。


# ── FileKeyStore 测试 ─────────────────────────────────────


class TestFileKeyStore:
    """测试 FileKeyStore 完整的身份生命周期。"""

    SAMPLE_KEY_PAIR = {
        "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----",
        "public_key_der_b64": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        "curve": "P-256",
    }
    SAMPLE_CERT = "-----BEGIN CERTIFICATE-----\nMIIBxjCC...\n-----END CERTIFICATE-----"
    SAMPLE_AID = "test-user.agentid.pub"

    def test_save_and_load_key_pair(self, tmp_path):
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        ks.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        loaded = ks.load_key_pair(self.SAMPLE_AID)
        assert loaded is not None
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]
        assert loaded["public_key_der_b64"] == self.SAMPLE_KEY_PAIR["public_key_der_b64"]
        assert loaded["curve"] == self.SAMPLE_KEY_PAIR["curve"]

    def test_key_pair_survives_restart(self, tmp_path):
        """模拟进程重启：新实例能恢复私钥。"""
        ks1 = FileKeyStore(tmp_path, encryption_seed="seed")
        ks1.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        # 新实例（模拟重启）
        ks2 = FileKeyStore(tmp_path, encryption_seed="seed")
        loaded = ks2.load_key_pair(self.SAMPLE_AID)
        assert loaded is not None
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

    def test_key_pair_survives_restart_auto_seed(self, tmp_path):
        """不提供 encryption_seed，自动生成种子，重启后仍可恢复。"""
        ks1 = FileKeyStore(tmp_path)
        ks1.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        ks2 = FileKeyStore(tmp_path)
        loaded = ks2.load_key_pair(self.SAMPLE_AID)
        assert loaded is not None
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

    def test_save_and_load_cert(self, tmp_path):
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        ks.save_cert(self.SAMPLE_AID, self.SAMPLE_CERT)

        loaded = ks.load_cert(self.SAMPLE_AID)
        assert loaded == self.SAMPLE_CERT

    def test_save_and_load_identity(self, tmp_path):
        """save_identity 拆分保存 key_pair + cert + tokens，均能恢复。"""
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
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

        ks1 = FileKeyStore(tmp_path, encryption_seed="seed")
        ks1.save_identity(self.SAMPLE_AID, identity)

        ks2 = FileKeyStore(tmp_path, encryption_seed="seed")
        loaded_kp = ks2.load_key_pair(self.SAMPLE_AID)
        assert loaded_kp is not None
        assert loaded_kp["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

        loaded_cert = ks2.load_cert(self.SAMPLE_AID)
        assert loaded_cert == self.SAMPLE_CERT

    def test_multiple_aids(self, tmp_path):
        """多个 AID 互不干扰。"""
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
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
        ks = FileKeyStore(tmp_path)
        ks.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())
        loaded = ks.load_key_pair(self.SAMPLE_AID)
        assert loaded["private_key_pem"] == self.SAMPLE_KEY_PAIR["private_key_pem"]

    def test_key_pair_file_does_not_contain_plaintext_private_key(self, tmp_path):
        """key.json 文件中不应出现明文私钥。"""
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        ks.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

        # 读取磁盘上的 key.json
        import json
        safe_aid = self.SAMPLE_AID.replace("/", "_").replace("\\", "_")
        key_file = tmp_path / "AIDs" / safe_aid / "private" / "key.json"
        raw = json.loads(key_file.read_text(encoding="utf-8"))

        assert "private_key_pem" not in raw, "明文私钥不应出现在 key.json 中"
        assert "private_key_protection" in raw
        assert raw["private_key_protection"]["persisted"] is True

    def test_load_nonexistent_aid(self, tmp_path):
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        assert ks.load_key_pair("nonexistent.agentid.pub") is None
        assert ks.load_cert("nonexistent.agentid.pub") is None
        assert ks.load_identity("nonexistent.agentid.pub") is None

    def test_identity_merge_not_overwrite(self, tmp_path):
        """save_identity 应合并 KV 字段，不覆盖已有字段。"""
        ks = FileKeyStore(tmp_path, encryption_seed="seed")

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
        return FileKeyStore(tmp_path, encryption_seed=seed)

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


# ── Prekey 持久化测试 ─────────────────────────────────────


class TestPrekeyPersistence:
    """测试 E2EE prekey 私钥的加密持久化。通过 save_e2ee_prekey / load_e2ee_prekeys 验证。"""

    AID = "prekey-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_prekey_saved_and_restored(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_e2ee_prekey(self.AID, "pk_001", {
            "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nPK001...\n-----END EC PRIVATE KEY-----",
            "public_key_der_b64": "MFkw...",
            "created_at": 1700000000,
            "expires_at": 1700604800,
        })
        ks.save_e2ee_prekey(self.AID, "pk_002", {
            "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nPK002...\n-----END EC PRIVATE KEY-----",
            "public_key_der_b64": "MFky...",
            "created_at": 1700000001,
        })

        prekeys = ks.load_e2ee_prekeys(self.AID)
        assert prekeys["pk_001"]["private_key_pem"].endswith("PK001...\n-----END EC PRIVATE KEY-----")
        assert prekeys["pk_002"]["private_key_pem"].endswith("PK002...\n-----END EC PRIVATE KEY-----")
        assert prekeys["pk_001"]["created_at"] == 1700000000

    def test_prekey_survives_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_e2ee_prekey(self.AID, "pk_r1", {
            "private_key_pem": "RESTART_KEY",
            "public_key_der_b64": "pub",
        })

        ks2 = self._make_ks(tmp_path)
        prekeys = ks2.load_e2ee_prekeys(self.AID)
        assert prekeys["pk_r1"]["private_key_pem"] == "RESTART_KEY"

    def test_prekey_private_key_not_plaintext_on_disk(self, tmp_path):
        """prekey 私钥存储在 SQLCipher 加密的 aun.db 中。"""
        ks = self._make_ks(tmp_path)
        ks.save_e2ee_prekey(self.AID, "pk_x", {
            "private_key_pem": "SECRET_PK",
            "public_key_der_b64": "pub",
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        db_file = tmp_path / "AIDs" / safe_aid / "aun.db"
        assert db_file.exists(), "aun.db 应该存在"
        # meta.json 不应存在或不应包含 prekey 明文
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        if meta_file.exists():
            raw_text = meta_file.read_text(encoding="utf-8")
            assert "SECRET_PK" not in raw_text

    def test_multiple_prekeys_independent(self, tmp_path):
        """多个 prekey 各自独立加密，互不干扰。"""
        ks = self._make_ks(tmp_path)
        ks.save_e2ee_prekey(self.AID, "a", {"private_key_pem": "KEY_A", "public_key_der_b64": "pub_a"})
        ks.save_e2ee_prekey(self.AID, "b", {"private_key_pem": "KEY_B", "public_key_der_b64": "pub_b"})
        ks.save_e2ee_prekey(self.AID, "c", {"private_key_pem": "KEY_C", "public_key_der_b64": "pub_c"})

        prekeys = ks.load_e2ee_prekeys(self.AID)
        assert prekeys["a"]["private_key_pem"] == "KEY_A"
        assert prekeys["b"]["private_key_pem"] == "KEY_B"
        assert prekeys["c"]["private_key_pem"] == "KEY_C"

    def test_device_prekeys_are_isolated_between_devices(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_e2ee_prekey(self.AID, "pk-dev-1", {
            "private_key_pem": "DEVICE_1_KEY",
            "public_key_der_b64": "pub_1",
            "created_at": 1700000100,
        }, device_id="device-1")
        ks.save_e2ee_prekey(self.AID, "pk-dev-2", {
            "private_key_pem": "DEVICE_2_KEY",
            "public_key_der_b64": "pub_2",
            "created_at": 1700000200,
        }, device_id="device-2")

        dev1 = ks.load_e2ee_prekeys(self.AID, device_id="device-1")
        dev2 = ks.load_e2ee_prekeys(self.AID, device_id="device-2")
        legacy = ks.load_e2ee_prekeys(self.AID)

        assert dev1["pk-dev-1"]["private_key_pem"] == "DEVICE_1_KEY"
        assert "pk-dev-2" not in dev1
        assert dev2["pk-dev-2"]["private_key_pem"] == "DEVICE_2_KEY"
        assert "pk-dev-1" not in dev2
        assert legacy == {}


# ── Group Secret 持久化测试 ───────────────────────────────


class TestGroupSecretPersistence:
    """测试群组 E2EE 密钥（当前 epoch + 旧 epoch）的加密持久化。
    通过 save_group_secret_state / load_group_secret_state 验证。"""

    AID = "group-test.agentid.pub"
    GRP = "grp_test1"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_group_secret_saved_and_restored(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_group_secret_state(self.AID, self.GRP, {
            "epoch": 3,
            "secret": "current_epoch_secret_b64",
            "commitment": "hash_abc",
            "member_aids": ["alice", "bob"],
        })

        loaded = ks.load_group_secret_state(self.AID, self.GRP)
        assert loaded is not None
        assert loaded["secret"] == "current_epoch_secret_b64"
        assert loaded["epoch"] == 3
        assert loaded["commitment"] == "hash_abc"
        assert loaded["member_aids"] == ["alice", "bob"]

    def test_group_secret_survives_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_group_secret_state(self.AID, self.GRP, {
            "epoch": 1,
            "secret": "RESTART_SECRET",
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_group_secret_state(self.AID, self.GRP)
        assert loaded is not None
        assert loaded["secret"] == "RESTART_SECRET"

    def test_group_secret_not_plaintext_on_disk(self, tmp_path):
        """group secret 存储在 SQLCipher 加密的 aun.db 中。"""
        ks = self._make_ks(tmp_path)
        ks.save_group_secret_state(self.AID, self.GRP, {
            "epoch": 1,
            "secret": "TOP_SECRET_GROUP",
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        db_file = tmp_path / "AIDs" / safe_aid / "aun.db"
        assert db_file.exists(), "aun.db 应该存在"
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        if meta_file.exists():
            raw_text = meta_file.read_text(encoding="utf-8")
            assert "TOP_SECRET_GROUP" not in raw_text

    def test_old_epoch_secrets_saved_and_restored(self, tmp_path):
        """旧 epoch 密钥也应加密持久化。"""
        ks = self._make_ks(tmp_path)
        ks.save_group_secret_state(self.AID, self.GRP, {
            "epoch": 3,
            "secret": "epoch3_secret",
            "old_epochs": [
                {"epoch": 1, "secret": "epoch1_secret", "expired_at": 1700000000},
                {"epoch": 2, "secret": "epoch2_secret", "expired_at": 1700100000},
            ],
        })

        loaded = ks.load_group_secret_state(self.AID, self.GRP)
        assert loaded is not None
        assert loaded["secret"] == "epoch3_secret"
        old = loaded["old_epochs"]
        assert len(old) == 2
        assert old[0]["secret"] == "epoch1_secret"
        assert old[0]["epoch"] == 1
        assert old[1]["secret"] == "epoch2_secret"

    def test_old_epoch_not_plaintext_on_disk(self, tmp_path):
        """旧 epoch 密钥存储在 SQLCipher 加密的 aun.db 中。"""
        ks = self._make_ks(tmp_path)
        ks.save_group_secret_state(self.AID, self.GRP, {
            "epoch": 2,
            "secret": "current",
            "old_epochs": [
                {"epoch": 1, "secret": "old_secret"},
            ],
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        db_file = tmp_path / "AIDs" / safe_aid / "aun.db"
        assert db_file.exists(), "aun.db 应该存在"
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        if meta_file.exists():
            raw_text = meta_file.read_text(encoding="utf-8")
            assert "old_secret" not in raw_text

    def test_old_epoch_survives_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_group_secret_state(self.AID, self.GRP, {
            "epoch": 2,
            "secret": "cur",
            "old_epochs": [
                {"epoch": 1, "secret": "old_persist"},
            ],
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_group_secret_state(self.AID, self.GRP)
        assert loaded is not None
        assert loaded["old_epochs"][0]["secret"] == "old_persist"

    def test_multiple_groups(self, tmp_path):
        """多个群组密钥互不干扰。"""
        ks = self._make_ks(tmp_path)
        ks.save_group_secret_state(self.AID, "g1", {"epoch": 1, "secret": "S1"})
        ks.save_group_secret_state(self.AID, "g2", {"epoch": 2, "secret": "S2"})
        ks.save_group_secret_state(self.AID, "g3", {"epoch": 1, "secret": "S3"})

        assert ks.load_group_secret_state(self.AID, "g1")["secret"] == "S1"
        assert ks.load_group_secret_state(self.AID, "g2")["secret"] == "S2"
        assert ks.load_group_secret_state(self.AID, "g3")["secret"] == "S3"


# ── Peer 证书持久化测试 ──────────────────────────────────


class TestPeerCertPersistence:
    """测试对方证书的持久化存储。"""

    def test_peer_cert_saved_and_loaded(self, tmp_path):
        """通过 save_cert/load_cert 存储和读取对方证书。"""
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        peer_cert = "-----BEGIN CERTIFICATE-----\nPEER_CERT_DATA\n-----END CERTIFICATE-----"
        ks.save_cert("peer.agentid.pub", peer_cert)

        loaded = ks.load_cert("peer.agentid.pub")
        assert loaded == peer_cert

    def test_peer_cert_survives_restart(self, tmp_path):
        ks1 = FileKeyStore(tmp_path, encryption_seed="seed")
        ks1.save_cert("peer.agentid.pub", "PEER_CERT")

        ks2 = FileKeyStore(tmp_path, encryption_seed="seed")
        assert ks2.load_cert("peer.agentid.pub") == "PEER_CERT"

    def test_multiple_peer_certs(self, tmp_path):
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        ks.save_cert("alice.agentid.pub", "CERT_ALICE")
        ks.save_cert("bob.agentid.pub", "CERT_BOB")

        assert ks.load_cert("alice.agentid.pub") == "CERT_ALICE"
        assert ks.load_cert("bob.agentid.pub") == "CERT_BOB"

    def test_own_cert_and_peer_cert_coexist(self, tmp_path):
        """自己的证书和对方的证书可以共存。"""
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        ks.save_cert("myself.agentid.pub", "MY_CERT")
        ks.save_cert("peer.agentid.pub", "PEER_CERT")

        assert ks.load_cert("myself.agentid.pub") == "MY_CERT"
        assert ks.load_cert("peer.agentid.pub") == "PEER_CERT"

    def test_peer_cert_versions_saved_by_fingerprint(self, tmp_path):
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
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
        ks1 = FileKeyStore(tmp_path, encryption_seed="seed")
        old_cert = _make_real_cert("peer.agentid.pub")
        new_cert = _make_real_cert("peer.agentid.pub")
        old_fp = _fingerprint_of_cert(old_cert)
        new_fp = _fingerprint_of_cert(new_cert)

        ks1.save_cert("peer.agentid.pub", old_cert, cert_fingerprint=old_fp, make_active=False)
        ks1.save_cert("peer.agentid.pub", new_cert)

        ks2 = FileKeyStore(tmp_path, encryption_seed="seed")
        assert ks2.load_cert("peer.agentid.pub", old_fp) == old_cert
        assert ks2.load_cert("peer.agentid.pub", new_fp) == new_cert

    def test_peer_cert_fingerprint_mismatch_does_not_fallback_to_active(self, tmp_path):
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
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


# ── 完整身份生命周期测试 ─────────────────────────────────


class TestFullIdentityLifecycle:
    """测试一个 AID 从创建到重启恢复的完整生命周期，
    验证所有持久化数据（私钥+证书+token+prekey+group）全部正确恢复。"""

    AID = "lifecycle.agentid.pub"
    PEER = "peer-lc.agentid.pub"

    def test_full_lifecycle(self, tmp_path):
        ks1 = FileKeyStore(tmp_path, encryption_seed="lifecycle_seed")

        # === 阶段 1: 创建 AID，保存身份 ===
        ks1.save_identity(self.AID, {
            "private_key_pem": "MY_PRIVATE_KEY",
            "public_key_der_b64": "MY_PUBLIC_KEY",
            "curve": "P-256",
            "cert": "MY_CERT_PEM",
            "aid": self.AID,
            "access_token": "at_lifecycle",
            "refresh_token": "rt_lifecycle",
        })

        # === 阶段 2: E2EE 通信，积累 prekeys 和 group secrets ===
        ks1.save_e2ee_prekey(self.AID, "pk_lc1", {
            "private_key_pem": "PREKEY_1",
            "public_key_der_b64": "pub1",
            "created_at": 1700000000,
        })
        ks1.save_e2ee_prekey(self.AID, "pk_lc2", {
            "private_key_pem": "PREKEY_2",
            "public_key_der_b64": "pub2",
            "created_at": 1700000001,
        })
        ks1.save_group_secret_state(self.AID, "grp_lc", {
            "epoch": 2,
            "secret": "GRP_SECRET_CURRENT",
            "commitment": "commit_hash",
            "member_aids": [self.AID, self.PEER],
            "old_epochs": [
                {"epoch": 1, "secret": "GRP_SECRET_OLD", "expired_at": 1700050000},
            ],
        })

        # 保存对方证书
        ks1.save_cert(self.PEER, "PEER_CERT_PEM")

        # === 阶段 3: 模拟进程重启 ===
        ks2 = FileKeyStore(tmp_path, encryption_seed="lifecycle_seed")

        # 验证私钥
        kp = ks2.load_key_pair(self.AID)
        assert kp["private_key_pem"] == "MY_PRIVATE_KEY"
        assert kp["public_key_der_b64"] == "MY_PUBLIC_KEY"

        # 验证自己的证书
        assert ks2.load_cert(self.AID) == "MY_CERT_PEM"

        # 验证对方证书
        assert ks2.load_cert(self.PEER) == "PEER_CERT_PEM"

        # 验证 token（通过 load_identity）
        identity = ks2.load_identity(self.AID)
        assert identity["access_token"] == "at_lifecycle"
        assert identity["refresh_token"] == "rt_lifecycle"

        # 验证 prekey（通过 load_e2ee_prekeys）
        prekeys = ks2.load_e2ee_prekeys(self.AID)
        assert prekeys["pk_lc1"]["private_key_pem"] == "PREKEY_1"
        assert prekeys["pk_lc2"]["private_key_pem"] == "PREKEY_2"
        assert prekeys["pk_lc1"]["created_at"] == 1700000000

        # 验证 group secret（通过 load_group_secret_state）
        grp = ks2.load_group_secret_state(self.AID, "grp_lc")
        assert grp is not None
        assert grp["secret"] == "GRP_SECRET_CURRENT"
        assert grp["epoch"] == 2
        assert grp["commitment"] == "commit_hash"
        assert grp["member_aids"] == [self.AID, self.PEER]

        # 验证 group secret（旧 epoch）
        assert grp["old_epochs"][0]["secret"] == "GRP_SECRET_OLD"
        assert grp["old_epochs"][0]["epoch"] == 1

    def test_split_files_do_not_contain_plaintext_secrets(self, tmp_path):
        """验证非 DB 拆分文件不暴露明文敏感数据。"""
        ks = FileKeyStore(tmp_path, encryption_seed="disk_check")
        ks.save_identity(self.AID, {
            "private_key_pem": "IDENTITY_SECRET_KEY",
            "public_key_der_b64": "pub",
            "curve": "P-256",
            "aid": self.AID,
            "access_token": "TOKEN_SECRET",
        })
        ks.save_e2ee_prekey(self.AID, "pk", {
            "private_key_pem": "PREKEY_SECRET",
            "public_key_der_b64": "pub",
        })
        ks.save_group_secret_state(self.AID, "g1", {
            "epoch": 1,
            "secret": "GROUP_SECRET",
            "old_epochs": [{"epoch": 0, "secret": "OLD_SECRET"}],
        })

        # 扫描所有磁盘文件
        secrets = ["IDENTITY_SECRET_KEY", "TOKEN_SECRET", "PREKEY_SECRET", "GROUP_SECRET", "OLD_SECRET"]
        for file_path in tmp_path.rglob("*"):
            if not file_path.is_file() or file_path.suffix in {".seed", ".db", ".db-wal", ".db-shm", ".wal", ".shm"}:
                continue
            content = file_path.read_text(encoding="utf-8", errors="replace")
            for secret in secrets:
                assert secret not in content, (
                    f"明文 '{secret}' 出现在磁盘文件 {file_path.relative_to(tmp_path)} 中！"
                )


# ── 数据独立性测试 ────────────────────────────────────────


class TestDataIndependence:
    """测试各类型数据之间互不干扰（tokens / prekeys / groups 各自独立 CRUD）。"""

    AID = "independence-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_save_prekeys_does_not_lose_tokens(self, tmp_path):
        """先保存 token，再保存 prekey，token 不应丢失。"""
        ks = self._make_ks(tmp_path)

        # 步骤 1: 保存 token
        ks.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at_keep",
            "refresh_token": "rt_keep",
        })

        # 步骤 2: 保存 prekey（通过独立 API，不影响 token）
        ks.save_e2ee_prekey(self.AID, "pk1", {
            "private_key_pem": "PK1",
            "public_key_der_b64": "pub",
        })

        # 验证 token 没丢
        loaded = ks.load_identity(self.AID)
        assert loaded["access_token"] == "at_keep"
        assert loaded["refresh_token"] == "rt_keep"
        prekeys = ks.load_e2ee_prekeys(self.AID)
        assert prekeys["pk1"]["private_key_pem"] == "PK1"

    def test_save_group_does_not_lose_prekeys(self, tmp_path):
        """先保存 prekey，再保存 group secret，prekey 不应丢失。"""
        ks = self._make_ks(tmp_path)

        # 步骤 1: 保存 prekey
        ks.save_e2ee_prekey(self.AID, "pk_x", {
            "private_key_pem": "KEEP_ME",
            "public_key_der_b64": "pub",
        })

        # 步骤 2: 保存 group secret
        ks.save_group_secret_state(self.AID, "grp1", {
            "epoch": 1,
            "secret": "GS1",
        })

        # 验证 prekey 没丢
        prekeys = ks.load_e2ee_prekeys(self.AID)
        assert prekeys["pk_x"]["private_key_pem"] == "KEEP_ME"
        grp = ks.load_group_secret_state(self.AID, "grp1")
        assert grp["secret"] == "GS1"

    def test_save_identity_preserves_existing_prekeys(self, tmp_path):
        """save_identity 更新 token 时不应覆盖已有 e2ee_prekeys。"""
        ks = self._make_ks(tmp_path)
        ks.save_e2ee_prekey(self.AID, "pk1", {
            "private_key_pem": "KEEP_ME",
            "public_key_der_b64": "pub1",
        })

        ks.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "tok_new",
            "refresh_token": "rt_new",
        })

        loaded = ks.load_identity(self.AID)
        assert loaded["access_token"] == "tok_new"
        assert loaded["refresh_token"] == "rt_new"
        prekeys = ks.load_e2ee_prekeys(self.AID)
        assert prekeys["pk1"]["private_key_pem"] == "KEEP_ME"

    def test_full_load_modify_save_cycle(self, tmp_path):
        """完整的 load→修改→save 循环不会丢失任何数据。"""
        ks = self._make_ks(tmp_path)

        # 初始写入所有类型的数据
        ks.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at_v1",
            "refresh_token": "rt_v1",
            "custom_field": "keep_me",
        })
        ks.save_e2ee_prekey(self.AID, "pk1", {"private_key_pem": "PK1", "public_key_der_b64": "pub1"})
        ks.save_e2ee_prekey(self.AID, "pk2", {"private_key_pem": "PK2", "public_key_der_b64": "pub2"})
        ks.save_group_secret_state(self.AID, "g1", {
            "epoch": 2,
            "secret": "GS1",
            "old_epochs": [{"epoch": 1, "secret": "GS1_OLD"}],
        })

        # 模拟 5 次 token 更新
        for i in range(5):
            ks.save_identity(self.AID, {
                "aid": self.AID,
                "access_token": f"at_v{i+2}",
            })
            ks.save_e2ee_prekey(self.AID, f"pk_new_{i}", {
                "private_key_pem": f"NEW_PK_{i}",
                "public_key_der_b64": f"pub_new_{i}",
            })

        # 最终验证：所有数据完整
        final = ks.load_identity(self.AID)
        assert final["access_token"] == "at_v6"
        assert final["refresh_token"] == "rt_v1"
        assert final["custom_field"] == "keep_me"

        prekeys = ks.load_e2ee_prekeys(self.AID)
        assert prekeys["pk1"]["private_key_pem"] == "PK1"
        assert prekeys["pk2"]["private_key_pem"] == "PK2"
        for i in range(5):
            assert prekeys[f"pk_new_{i}"]["private_key_pem"] == f"NEW_PK_{i}"

        grp = ks.load_group_secret_state(self.AID, "g1")
        assert grp["secret"] == "GS1"
        assert grp["old_epochs"][0]["secret"] == "GS1_OLD"

    def test_survives_restart_between_writes(self, tmp_path):
        """在不同阶段写入不同类型数据，每次重启后数据完整。"""
        # 阶段 1: 创建身份
        ks1 = self._make_ks(tmp_path)
        ks1.save_identity(self.AID, {
            "aid": self.AID,
            "access_token": "at1",
        })

        # 阶段 2: 重启，添加 prekey
        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_identity(self.AID)
        assert loaded["access_token"] == "at1"
        ks2.save_e2ee_prekey(self.AID, "pk1", {
            "private_key_pem": "PK1",
            "public_key_der_b64": "pub",
        })

        # 阶段 3: 再次重启，添加 group
        ks3 = self._make_ks(tmp_path)
        loaded = ks3.load_identity(self.AID)
        assert loaded["access_token"] == "at1"
        prekeys = ks3.load_e2ee_prekeys(self.AID)
        assert prekeys["pk1"]["private_key_pem"] == "PK1"
        ks3.save_group_secret_state(self.AID, "g1", {"epoch": 1, "secret": "GS"})

        # 阶段 4: 最终重启验证
        ks4 = self._make_ks(tmp_path)
        final = ks4.load_identity(self.AID)
        assert final["access_token"] == "at1"
        prekeys = ks4.load_e2ee_prekeys(self.AID)
        assert prekeys["pk1"]["private_key_pem"] == "PK1"
        grp = ks4.load_group_secret_state(self.AID, "g1")
        assert grp["secret"] == "GS"
