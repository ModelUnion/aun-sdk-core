"""KeyStore 和 SecretStore 完备测试。

覆盖场景：
- FileSecretStore: 加解密、持久化、重启恢复、种子管理、错误处理
- VolatileSecretStore: 非持久化验证
- FileKeyStore: 身份完整生命周期（创建→保存→重启→加载）
- FileKeyStore + 各 SecretStore 组合
- 持久化强制检查
- Metadata 持久化: Token、Prekey、E2EE Session、Group Secret
"""

import copy
import json
from pathlib import Path

import pytest

from aun_core.keystore.file import FileKeyStore
from aun_core.secret_store.file_store import FileSecretStore
from aun_core.secret_store.volatile import VolatileSecretStore


# ── FileSecretStore 测试 ──────────────────────────────────


class TestFileSecretStore:
    """测试基于文件的 AES-256-GCM 加密存储。"""

    def test_protect_returns_persisted_true(self, tmp_path):
        store = FileSecretStore(tmp_path)
        record = store.protect("scope1", "key1", b"secret_data")
        assert record["scheme"] == "file_aes"
        assert record["persisted"] is True
        assert record["name"] == "key1"

    def test_protect_and_reveal_roundtrip(self, tmp_path):
        store = FileSecretStore(tmp_path)
        plaintext = b"my_private_key_pem_content"
        record = store.protect("aid1", "identity/private_key", plaintext)
        recovered = store.reveal("aid1", "identity/private_key", record)
        assert recovered == plaintext

    def test_reveal_after_restart_with_seed(self, tmp_path):
        """用 encryption_seed 创建 → 重启后用同一 seed 能恢复。"""
        store1 = FileSecretStore(tmp_path, encryption_seed="my_seed")
        record = store1.protect("aid1", "identity/private_key", b"KEY_DATA")

        # 模拟进程重启
        store2 = FileSecretStore(tmp_path, encryption_seed="my_seed")
        assert store2.reveal("aid1", "identity/private_key", record) == b"KEY_DATA"

    def test_reveal_after_restart_without_seed(self, tmp_path):
        """不提供 seed → 自动生成 .seed 文件 → 重启后仍可恢复。"""
        store1 = FileSecretStore(tmp_path)
        record = store1.protect("aid1", "identity/private_key", b"AUTO_SEED_KEY")

        # 验证 .seed 文件已创建
        assert (tmp_path / ".seed").exists()

        # 模拟进程重启
        store2 = FileSecretStore(tmp_path)
        assert store2.reveal("aid1", "identity/private_key", record) == b"AUTO_SEED_KEY"

    def test_wrong_seed_cannot_decrypt(self, tmp_path):
        """错误的 seed 无法解密。"""
        store1 = FileSecretStore(tmp_path, encryption_seed="correct")
        record = store1.protect("aid1", "identity/private_key", b"DATA")

        store2 = FileSecretStore(tmp_path, encryption_seed="wrong")
        assert store2.reveal("aid1", "identity/private_key", record) is None

    def test_different_scopes_are_isolated(self, tmp_path):
        """不同 scope 的密钥互相隔离。"""
        store = FileSecretStore(tmp_path, encryption_seed="seed")
        record = store.protect("alice", "identity/private_key", b"ALICE_KEY")

        # 用 bob 的 scope 尝试解密 → 失败
        assert store.reveal("bob", "identity/private_key", record) is None

    def test_different_names_are_isolated(self, tmp_path):
        """不同 name 的密钥互相隔离。"""
        store = FileSecretStore(tmp_path, encryption_seed="seed")
        record = store.protect("aid1", "key_a", b"DATA_A")

        # 用不同 name 尝试解密 → 返回 None（name 不匹配）
        assert store.reveal("aid1", "key_b", record) is None

    def test_reveal_with_wrong_scheme_returns_none(self, tmp_path):
        store = FileSecretStore(tmp_path)
        assert store.reveal("s", "n", {"scheme": "dpapi", "name": "n"}) is None

    def test_reveal_with_missing_fields_returns_none(self, tmp_path):
        store = FileSecretStore(tmp_path)
        assert store.reveal("s", "n", {"scheme": "file_aes", "name": "n"}) is None

    def test_reveal_with_corrupt_ciphertext_returns_none(self, tmp_path):
        """篡改密文后解密失败。"""
        store = FileSecretStore(tmp_path, encryption_seed="seed")
        record = store.protect("aid1", "key1", b"original")
        # 篡改密文
        import base64
        tampered = base64.b64encode(b"TAMPERED_DATA").decode("ascii")
        record["ciphertext"] = tampered
        assert store.reveal("aid1", "key1", record) is None

    def test_multiple_keys_same_store(self, tmp_path):
        """同一个 store 可以保护多个不同的密钥。"""
        store = FileSecretStore(tmp_path, encryption_seed="seed")
        r1 = store.protect("aid1", "identity/private_key", b"KEY1")
        r2 = store.protect("aid2", "identity/private_key", b"KEY2")
        r3 = store.protect("aid1", "e2ee/session_key", b"KEY3")

        assert store.reveal("aid1", "identity/private_key", r1) == b"KEY1"
        assert store.reveal("aid2", "identity/private_key", r2) == b"KEY2"
        assert store.reveal("aid1", "e2ee/session_key", r3) == b"KEY3"

    def test_overwrite_same_key(self, tmp_path):
        """覆盖同一 scope/name 后能解密最新值。"""
        store = FileSecretStore(tmp_path, encryption_seed="seed")
        r1 = store.protect("aid1", "key", b"OLD")
        r2 = store.protect("aid1", "key", b"NEW")

        assert store.reveal("aid1", "key", r2) == b"NEW"

    def test_large_plaintext(self, tmp_path):
        """大尺寸明文也能正确处理。"""
        store = FileSecretStore(tmp_path, encryption_seed="seed")
        big = b"X" * 100_000
        record = store.protect("aid1", "key", big)
        assert store.reveal("aid1", "key", record) == big

    def test_seed_file_permissions_unix(self, tmp_path):
        """Unix 上 .seed 文件权限应为 0o600。"""
        import sys
        if sys.platform == "win32":
            pytest.skip("Windows 不检查文件权限")
        store = FileSecretStore(tmp_path)
        store.protect("aid1", "key", b"data")
        import os
        mode = os.stat(tmp_path / ".seed").st_mode & 0o777
        assert mode == 0o600


# ── VolatileSecretStore 测试 ──────────────────────────────


class TestVolatileSecretStore:
    """验证 VolatileSecretStore 的行为和限制。"""

    def test_protect_returns_not_persisted(self):
        store = VolatileSecretStore()
        record = store.protect("scope", "name", b"data")
        assert record["scheme"] == "volatile"
        assert record["persisted"] is False

    def test_roundtrip_within_same_instance(self):
        """同一实例内可以 reveal。"""
        store = VolatileSecretStore()
        record = store.protect("s", "n", b"secret")
        assert store.reveal("s", "n", record) == b"secret"

    def test_lost_after_new_instance(self):
        """新实例模拟重启 → 私钥丢失。"""
        store1 = VolatileSecretStore()
        record = store1.protect("s", "n", b"secret")

        store2 = VolatileSecretStore()
        assert store2.reveal("s", "n", record) is None

    def test_clear_removes_secret(self):
        store = VolatileSecretStore()
        record = store.protect("s", "n", b"secret")
        store.clear("s", "n")
        assert store.reveal("s", "n", record) is None


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
        """save_identity 拆分保存 key_pair + cert + metadata，均能恢复。"""
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
        """完整身份（私钥 + 证书 + 元数据）跨重启恢复。"""
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

    def test_delete_identity(self, tmp_path):
        ks = FileKeyStore(tmp_path, encryption_seed="seed")
        ks.save_identity(self.SAMPLE_AID, {
            **self.SAMPLE_KEY_PAIR,
            "cert": self.SAMPLE_CERT,
            "aid": self.SAMPLE_AID,
        })
        ks.delete_identity(self.SAMPLE_AID)

        assert ks.load_key_pair(self.SAMPLE_AID) is None
        assert ks.load_cert(self.SAMPLE_AID) is None

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
        """VolatileSecretStore 传入时，save_key_pair 必须拒绝。"""
        ks = FileKeyStore(tmp_path, secret_store=VolatileSecretStore())
        with pytest.raises(RuntimeError, match="无法持久化"):
            ks.save_key_pair(self.SAMPLE_AID, self.SAMPLE_KEY_PAIR.copy())

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

    def test_metadata_merge_not_overwrite(self, tmp_path):
        """save_identity 应合并 metadata，不覆盖已有字段。"""
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

        meta = ks.load_metadata(self.SAMPLE_AID)
        assert meta.get("field_a") == "value_a", "field_a 不应被覆盖"
        assert meta.get("field_b") == "value_b", "field_b 应被新增"


# ── Token 持久化测试 ──────────────────────────────────────


class TestTokenPersistence:
    """测试 access_token / refresh_token / kite_token 的加密持久化。"""

    AID = "token-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_tokens_saved_and_restored(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "aid": self.AID,
            "access_token": "at_abc123",
            "refresh_token": "rt_xyz789",
            "kite_token": "kt_000",
        })

        loaded = ks.load_metadata(self.AID)
        assert loaded["access_token"] == "at_abc123"
        assert loaded["refresh_token"] == "rt_xyz789"
        assert loaded["kite_token"] == "kt_000"

    def test_tokens_survive_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_metadata(self.AID, {
            "access_token": "at_persist",
            "refresh_token": "rt_persist",
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_metadata(self.AID)
        assert loaded["access_token"] == "at_persist"
        assert loaded["refresh_token"] == "rt_persist"

    def test_tokens_not_plaintext_on_disk(self, tmp_path):
        """meta.json 中不应出现明文 token。"""
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "access_token": "at_secret",
            "refresh_token": "rt_secret",
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        raw = json.loads(meta_file.read_text(encoding="utf-8"))

        assert "access_token" not in raw
        assert "refresh_token" not in raw
        assert "access_token_protection" in raw
        assert "refresh_token_protection" in raw
        assert raw["access_token_protection"]["persisted"] is True

    def test_token_update_preserves_other_tokens(self, tmp_path):
        """更新一个 token 不丢失其他 token。"""
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "access_token": "at_old",
            "refresh_token": "rt_keep",
        })
        # 仅更新 access_token
        existing = ks.load_metadata(self.AID)
        existing["access_token"] = "at_new"
        ks.save_metadata(self.AID, existing)

        loaded = ks.load_metadata(self.AID)
        assert loaded["access_token"] == "at_new"
        assert loaded["refresh_token"] == "rt_keep"


# ── Prekey 持久化测试 ─────────────────────────────────────


class TestPrekeyPersistence:
    """测试 E2EE prekey 私钥的加密持久化。"""

    AID = "prekey-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_prekey_saved_and_restored(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "e2ee_prekeys": {
                "pk_001": {
                    "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nPK001...\n-----END EC PRIVATE KEY-----",
                    "public_key_der_b64": "MFkw...",
                    "created_at": 1700000000,
                    "expires_at": 1700604800,
                },
                "pk_002": {
                    "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nPK002...\n-----END EC PRIVATE KEY-----",
                    "public_key_der_b64": "MFky...",
                    "created_at": 1700000001,
                },
            }
        })

        loaded = ks.load_metadata(self.AID)
        prekeys = loaded["e2ee_prekeys"]
        assert prekeys["pk_001"]["private_key_pem"].endswith("PK001...\n-----END EC PRIVATE KEY-----")
        assert prekeys["pk_002"]["private_key_pem"].endswith("PK002...\n-----END EC PRIVATE KEY-----")
        assert prekeys["pk_001"]["public_key_der_b64"] == "MFkw..."
        assert prekeys["pk_001"]["created_at"] == 1700000000

    def test_prekey_survives_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_metadata(self.AID, {
            "e2ee_prekeys": {
                "pk_r1": {"private_key_pem": "RESTART_KEY", "public_key_der_b64": "pub"},
            }
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_metadata(self.AID)
        assert loaded["e2ee_prekeys"]["pk_r1"]["private_key_pem"] == "RESTART_KEY"

    def test_prekey_private_key_not_plaintext_on_disk(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "e2ee_prekeys": {
                "pk_x": {"private_key_pem": "SECRET_PK", "public_key_der_b64": "pub"},
            }
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        raw = json.loads(meta_file.read_text(encoding="utf-8"))

        pk_raw = raw["e2ee_prekeys"]["pk_x"]
        assert "private_key_pem" not in pk_raw
        assert "private_key_protection" in pk_raw
        assert pk_raw["private_key_protection"]["persisted"] is True
        # 公钥应该是明文
        assert pk_raw["public_key_der_b64"] == "pub"

    def test_multiple_prekeys_independent(self, tmp_path):
        """多个 prekey 各自独立加密，互不干扰。"""
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "e2ee_prekeys": {
                "a": {"private_key_pem": "KEY_A", "public_key_der_b64": "pub_a"},
                "b": {"private_key_pem": "KEY_B", "public_key_der_b64": "pub_b"},
                "c": {"private_key_pem": "KEY_C", "public_key_der_b64": "pub_c"},
            }
        })

        loaded = ks.load_metadata(self.AID)
        assert loaded["e2ee_prekeys"]["a"]["private_key_pem"] == "KEY_A"
        assert loaded["e2ee_prekeys"]["b"]["private_key_pem"] == "KEY_B"
        assert loaded["e2ee_prekeys"]["c"]["private_key_pem"] == "KEY_C"


# ── E2EE Session Key 持久化测试 ───────────────────────────


class TestE2EESessionPersistence:
    """测试 E2EE 会话密钥的加密持久化。"""

    AID = "session-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_session_key_saved_and_restored(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "e2ee_sessions": [
                {
                    "session_id": "sess_001",
                    "peer_aid": "bob.agentid.pub",
                    "key": "shared_secret_base64_encoded",
                    "direction": "outbound",
                },
            ]
        })

        loaded = ks.load_metadata(self.AID)
        sessions = loaded["e2ee_sessions"]
        assert len(sessions) == 1
        assert sessions[0]["key"] == "shared_secret_base64_encoded"
        assert sessions[0]["peer_aid"] == "bob.agentid.pub"

    def test_session_key_survives_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_metadata(self.AID, {
            "e2ee_sessions": [
                {"session_id": "s1", "key": "RESTART_SESSION_KEY"},
            ]
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_metadata(self.AID)
        assert loaded["e2ee_sessions"][0]["key"] == "RESTART_SESSION_KEY"

    def test_session_key_not_plaintext_on_disk(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "e2ee_sessions": [
                {"session_id": "s_secret", "key": "TOP_SECRET"},
            ]
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        raw = json.loads(meta_file.read_text(encoding="utf-8"))

        sess = raw["e2ee_sessions"][0]
        assert "key" not in sess
        assert "key_protection" in sess
        assert sess["key_protection"]["persisted"] is True

    def test_multiple_sessions(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "e2ee_sessions": [
                {"session_id": "s1", "key": "KEY1", "peer_aid": "alice"},
                {"session_id": "s2", "key": "KEY2", "peer_aid": "bob"},
                {"session_id": "s3", "key": "KEY3", "peer_aid": "carol"},
            ]
        })

        loaded = ks.load_metadata(self.AID)
        keys = {s["session_id"]: s["key"] for s in loaded["e2ee_sessions"]}
        assert keys == {"s1": "KEY1", "s2": "KEY2", "s3": "KEY3"}


# ── Group Secret 持久化测试 ───────────────────────────────


class TestGroupSecretPersistence:
    """测试群组 E2EE 密钥（当前 epoch + 旧 epoch）的加密持久化。"""

    AID = "group-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_group_secret_saved_and_restored(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "group_secrets": {
                "grp_001": {
                    "epoch": 3,
                    "secret": "current_epoch_secret_b64",
                    "commitment": "hash_abc",
                    "member_aids": ["alice", "bob"],
                }
            }
        })

        loaded = ks.load_metadata(self.AID)
        grp = loaded["group_secrets"]["grp_001"]
        assert grp["secret"] == "current_epoch_secret_b64"
        assert grp["epoch"] == 3
        assert grp["commitment"] == "hash_abc"
        assert grp["member_aids"] == ["alice", "bob"]

    def test_group_secret_survives_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_metadata(self.AID, {
            "group_secrets": {
                "grp_r": {"epoch": 1, "secret": "RESTART_SECRET"},
            }
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_metadata(self.AID)
        assert loaded["group_secrets"]["grp_r"]["secret"] == "RESTART_SECRET"

    def test_group_secret_not_plaintext_on_disk(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "group_secrets": {
                "grp_x": {"epoch": 1, "secret": "TOP_SECRET_GROUP"},
            }
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        raw = json.loads(meta_file.read_text(encoding="utf-8"))

        grp = raw["group_secrets"]["grp_x"]
        assert "secret" not in grp
        assert "secret_protection" in grp
        assert grp["secret_protection"]["persisted"] is True
        # epoch 和 commitment 应该是明文
        assert grp["epoch"] == 1

    def test_old_epoch_secrets_saved_and_restored(self, tmp_path):
        """旧 epoch 密钥也应加密持久化。"""
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "group_secrets": {
                "grp_old": {
                    "epoch": 3,
                    "secret": "epoch3_secret",
                    "old_epochs": [
                        {"epoch": 1, "secret": "epoch1_secret", "expired_at": 1700000000},
                        {"epoch": 2, "secret": "epoch2_secret", "expired_at": 1700100000},
                    ],
                }
            }
        })

        loaded = ks.load_metadata(self.AID)
        grp = loaded["group_secrets"]["grp_old"]
        assert grp["secret"] == "epoch3_secret"
        old = grp["old_epochs"]
        assert len(old) == 2
        assert old[0]["secret"] == "epoch1_secret"
        assert old[0]["epoch"] == 1
        assert old[1]["secret"] == "epoch2_secret"

    def test_old_epoch_not_plaintext_on_disk(self, tmp_path):
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "group_secrets": {
                "grp_o": {
                    "epoch": 2,
                    "secret": "current",
                    "old_epochs": [
                        {"epoch": 1, "secret": "old_secret"},
                    ],
                }
            }
        })

        safe_aid = self.AID.replace("/", "_").replace("\\", "_")
        meta_file = tmp_path / "AIDs" / safe_aid / "tokens" / "meta.json"
        raw = json.loads(meta_file.read_text(encoding="utf-8"))

        old_raw = raw["group_secrets"]["grp_o"]["old_epochs"][0]
        assert "secret" not in old_raw
        assert "secret_protection" in old_raw

    def test_old_epoch_survives_restart(self, tmp_path):
        ks1 = self._make_ks(tmp_path)
        ks1.save_metadata(self.AID, {
            "group_secrets": {
                "grp_r2": {
                    "epoch": 2,
                    "secret": "cur",
                    "old_epochs": [
                        {"epoch": 1, "secret": "old_persist"},
                    ],
                }
            }
        })

        ks2 = self._make_ks(tmp_path)
        loaded = ks2.load_metadata(self.AID)
        assert loaded["group_secrets"]["grp_r2"]["old_epochs"][0]["secret"] == "old_persist"

    def test_multiple_groups(self, tmp_path):
        """多个群组密钥互不干扰。"""
        ks = self._make_ks(tmp_path)
        ks.save_metadata(self.AID, {
            "group_secrets": {
                "g1": {"epoch": 1, "secret": "S1"},
                "g2": {"epoch": 2, "secret": "S2"},
                "g3": {"epoch": 1, "secret": "S3"},
            }
        })

        loaded = ks.load_metadata(self.AID)
        assert loaded["group_secrets"]["g1"]["secret"] == "S1"
        assert loaded["group_secrets"]["g2"]["secret"] == "S2"
        assert loaded["group_secrets"]["g3"]["secret"] == "S3"


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


# ── 完整身份生命周期测试 ─────────────────────────────────


class TestFullIdentityLifecycle:
    """测试一个 AID 从创建到重启恢复的完整生命周期，
    验证所有持久化数据（私钥+证书+token+prekey+session+group）全部正确恢复。"""

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

        # === 阶段 2: E2EE 通信，积累会话和密钥 ===
        meta = ks1.load_metadata(self.AID) or {}
        meta["e2ee_prekeys"] = {
            "pk_lc1": {"private_key_pem": "PREKEY_1", "public_key_der_b64": "pub1", "created_at": 1700000000},
            "pk_lc2": {"private_key_pem": "PREKEY_2", "public_key_der_b64": "pub2", "created_at": 1700000001},
        }
        meta["e2ee_sessions"] = [
            {"session_id": "sess_lc1", "key": "SESSION_KEY_1", "peer_aid": self.PEER},
        ]
        meta["group_secrets"] = {
            "grp_lc": {
                "epoch": 2,
                "secret": "GRP_SECRET_CURRENT",
                "commitment": "commit_hash",
                "member_aids": [self.AID, self.PEER],
                "old_epochs": [
                    {"epoch": 1, "secret": "GRP_SECRET_OLD", "expired_at": 1700050000},
                ],
            }
        }
        ks1.save_metadata(self.AID, meta)

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

        # 验证 token
        meta2 = ks2.load_metadata(self.AID)
        assert meta2["access_token"] == "at_lifecycle"
        assert meta2["refresh_token"] == "rt_lifecycle"

        # 验证 prekey
        assert meta2["e2ee_prekeys"]["pk_lc1"]["private_key_pem"] == "PREKEY_1"
        assert meta2["e2ee_prekeys"]["pk_lc2"]["private_key_pem"] == "PREKEY_2"
        assert meta2["e2ee_prekeys"]["pk_lc1"]["created_at"] == 1700000000

        # 验证 session
        assert meta2["e2ee_sessions"][0]["key"] == "SESSION_KEY_1"
        assert meta2["e2ee_sessions"][0]["peer_aid"] == self.PEER

        # 验证 group secret（当前 epoch）
        grp = meta2["group_secrets"]["grp_lc"]
        assert grp["secret"] == "GRP_SECRET_CURRENT"
        assert grp["epoch"] == 2
        assert grp["commitment"] == "commit_hash"
        assert grp["member_aids"] == [self.AID, self.PEER]

        # 验证 group secret（旧 epoch）
        assert grp["old_epochs"][0]["secret"] == "GRP_SECRET_OLD"
        assert grp["old_epochs"][0]["epoch"] == 1

    def test_disk_files_contain_no_plaintext_secrets(self, tmp_path):
        """验证磁盘上所有文件都不包含明文敏感数据。"""
        ks = FileKeyStore(tmp_path, encryption_seed="disk_check")
        ks.save_identity(self.AID, {
            "private_key_pem": "IDENTITY_SECRET_KEY",
            "public_key_der_b64": "pub",
            "curve": "P-256",
            "aid": self.AID,
            "access_token": "TOKEN_SECRET",
        })
        meta = ks.load_metadata(self.AID) or {}
        meta["e2ee_prekeys"] = {"pk": {"private_key_pem": "PREKEY_SECRET", "public_key_der_b64": "pub"}}
        meta["e2ee_sessions"] = [{"session_id": "s1", "key": "SESSION_SECRET"}]
        meta["group_secrets"] = {
            "g1": {"epoch": 1, "secret": "GROUP_SECRET", "old_epochs": [{"epoch": 0, "secret": "OLD_SECRET"}]}
        }
        ks.save_metadata(self.AID, meta)

        # 扫描所有磁盘文件
        secrets = ["IDENTITY_SECRET_KEY", "TOKEN_SECRET", "PREKEY_SECRET", "SESSION_SECRET", "GROUP_SECRET", "OLD_SECRET"]
        for file_path in tmp_path.rglob("*"):
            if not file_path.is_file() or file_path.suffix == ".seed":
                continue
            content = file_path.read_text(encoding="utf-8", errors="replace")
            for secret in secrets:
                assert secret not in content, (
                    f"明文 '{secret}' 出现在磁盘文件 {file_path.relative_to(tmp_path)} 中！"
                )


# ── Metadata 互不覆盖测试 ────────────────────────────────


class TestMetadataNoOverwrite:
    """测试 save_metadata 的防覆盖机制：
    不同类型的数据在不同时间点写入 metadata 后不互相丢失。"""

    AID = "overwrite-test.agentid.pub"

    def _make_ks(self, tmp_path, seed="seed"):
        return FileKeyStore(tmp_path, encryption_seed=seed)

    def test_save_prekeys_does_not_lose_tokens(self, tmp_path):
        """先保存 token，再保存 prekey，token 不应丢失。"""
        ks = self._make_ks(tmp_path)

        # 步骤 1: 保存 token
        ks.save_metadata(self.AID, {
            "access_token": "at_keep",
            "refresh_token": "rt_keep",
        })

        # 步骤 2: 模拟 e2ee.py 的 generate_prekey 流程
        # 先 load，再修改 prekeys，再 save
        meta = ks.load_metadata(self.AID) or {}
        meta["e2ee_prekeys"] = {"pk1": {"private_key_pem": "PK1", "public_key_der_b64": "pub"}}
        ks.save_metadata(self.AID, meta)

        # 验证 token 没丢
        loaded = ks.load_metadata(self.AID)
        assert loaded["access_token"] == "at_keep"
        assert loaded["refresh_token"] == "rt_keep"
        assert loaded["e2ee_prekeys"]["pk1"]["private_key_pem"] == "PK1"

    def test_save_group_does_not_lose_prekeys(self, tmp_path):
        """先保存 prekey，再保存 group secret，prekey 不应丢失。"""
        ks = self._make_ks(tmp_path)

        # 步骤 1: 保存 prekey
        meta = ks.load_metadata(self.AID) or {}
        meta["e2ee_prekeys"] = {"pk_x": {"private_key_pem": "KEEP_ME", "public_key_der_b64": "pub"}}
        ks.save_metadata(self.AID, meta)

        # 步骤 2: 保存 group secret
        meta2 = ks.load_metadata(self.AID) or {}
        meta2.setdefault("group_secrets", {})["grp1"] = {"epoch": 1, "secret": "GS1"}
        ks.save_metadata(self.AID, meta2)

        # 验证 prekey 没丢
        loaded = ks.load_metadata(self.AID)
        assert loaded["e2ee_prekeys"]["pk_x"]["private_key_pem"] == "KEEP_ME"
        assert loaded["group_secrets"]["grp1"]["secret"] == "GS1"

    def test_save_sessions_does_not_lose_groups(self, tmp_path):
        """先保存 group secret，再保存 session，group 不应丢失。"""
        ks = self._make_ks(tmp_path)

        meta = ks.load_metadata(self.AID) or {}
        meta["group_secrets"] = {"g1": {"epoch": 1, "secret": "KEEP_GROUP"}}
        ks.save_metadata(self.AID, meta)

        meta2 = ks.load_metadata(self.AID) or {}
        meta2["e2ee_sessions"] = [{"session_id": "s1", "key": "SK1"}]
        ks.save_metadata(self.AID, meta2)

        loaded = ks.load_metadata(self.AID)
        assert loaded["group_secrets"]["g1"]["secret"] == "KEEP_GROUP"
        assert loaded["e2ee_sessions"][0]["key"] == "SK1"

    def test_defensive_merge_when_caller_forgets_load(self, tmp_path):
        """调用方忘记先 load 就直接 save 部分数据，关键字段应被自动保留。"""
        ks = self._make_ks(tmp_path)

        # 先写入完整数据
        ks.save_metadata(self.AID, {
            "access_token": "at_orig",
            "e2ee_prekeys": {"pk1": {"private_key_pem": "PK_ORIG", "public_key_der_b64": "pub"}},
            "group_secrets": {"g1": {"epoch": 1, "secret": "GS_ORIG"}},
            "e2ee_sessions": [{"session_id": "s1", "key": "SK_ORIG"}],
        })

        # 调用方只传了 token 更新，没有 load 旧数据（危险操作）
        ks.save_metadata(self.AID, {
            "access_token": "at_new",
        })

        # 关键字段应被防御性合并保留
        loaded = ks.load_metadata(self.AID)
        assert loaded["access_token"] == "at_new"
        assert loaded["e2ee_prekeys"]["pk1"]["private_key_pem"] == "PK_ORIG"
        assert loaded["group_secrets"]["g1"]["secret"] == "GS_ORIG"
        assert loaded["e2ee_sessions"][0]["key"] == "SK_ORIG"

    def test_full_load_modify_save_cycle(self, tmp_path):
        """完整的 load→修改→save 循环不会丢失任何数据。"""
        ks = self._make_ks(tmp_path)

        # 初始写入所有类型的数据
        ks.save_metadata(self.AID, {
            "access_token": "at_v1",
            "refresh_token": "rt_v1",
            "e2ee_prekeys": {
                "pk1": {"private_key_pem": "PK1", "public_key_der_b64": "pub1"},
                "pk2": {"private_key_pem": "PK2", "public_key_der_b64": "pub2"},
            },
            "e2ee_sessions": [
                {"session_id": "s1", "key": "SK1"},
            ],
            "group_secrets": {
                "g1": {
                    "epoch": 2, "secret": "GS1",
                    "old_epochs": [{"epoch": 1, "secret": "GS1_OLD"}],
                },
            },
            "custom_field": "keep_me",
        })

        # 模拟 5 次 load→修改→save
        for i in range(5):
            meta = ks.load_metadata(self.AID) or {}
            meta["access_token"] = f"at_v{i+2}"
            meta["e2ee_prekeys"][f"pk_new_{i}"] = {
                "private_key_pem": f"NEW_PK_{i}", "public_key_der_b64": f"pub_new_{i}",
            }
            ks.save_metadata(self.AID, meta)

        # 最终验证：所有数据完整
        final = ks.load_metadata(self.AID)
        assert final["access_token"] == "at_v6"
        assert final["refresh_token"] == "rt_v1"
        assert final["e2ee_prekeys"]["pk1"]["private_key_pem"] == "PK1"
        assert final["e2ee_prekeys"]["pk2"]["private_key_pem"] == "PK2"
        for i in range(5):
            assert final["e2ee_prekeys"][f"pk_new_{i}"]["private_key_pem"] == f"NEW_PK_{i}"
        assert final["e2ee_sessions"][0]["key"] == "SK1"
        assert final["group_secrets"]["g1"]["secret"] == "GS1"
        assert final["group_secrets"]["g1"]["old_epochs"][0]["secret"] == "GS1_OLD"
        assert final["custom_field"] == "keep_me"

    def test_survives_restart_between_writes(self, tmp_path):
        """在不同阶段写入不同类型数据，每次重启后数据完整。"""
        # 阶段 1: 创建身份
        ks1 = self._make_ks(tmp_path)
        ks1.save_metadata(self.AID, {
            "access_token": "at1",
            "aid": self.AID,
        })

        # 阶段 2: 重启，添加 prekey
        ks2 = self._make_ks(tmp_path)
        meta = ks2.load_metadata(self.AID) or {}
        assert meta["access_token"] == "at1"
        meta["e2ee_prekeys"] = {"pk1": {"private_key_pem": "PK1", "public_key_der_b64": "pub"}}
        ks2.save_metadata(self.AID, meta)

        # 阶段 3: 再次重启，添加 group
        ks3 = self._make_ks(tmp_path)
        meta = ks3.load_metadata(self.AID) or {}
        assert meta["access_token"] == "at1"
        assert meta["e2ee_prekeys"]["pk1"]["private_key_pem"] == "PK1"
        meta.setdefault("group_secrets", {})["g1"] = {"epoch": 1, "secret": "GS"}
        ks3.save_metadata(self.AID, meta)

        # 阶段 4: 最终重启验证
        ks4 = self._make_ks(tmp_path)
        final = ks4.load_metadata(self.AID)
        assert final["access_token"] == "at1"
        assert final["e2ee_prekeys"]["pk1"]["private_key_pem"] == "PK1"
        assert final["group_secrets"]["g1"]["secret"] == "GS"
