"""M3-A1: 多设备注册与 Bootstrap 验证（Mock 测试）

验证：
- 同一 AID 两个 device_id 各自注册 IK+SPK
- V2Session 按 device_id 隔离密钥
- V2KeyStore 多设备存储不冲突
"""
import hashlib
import pytest
from pathlib import Path
from unittest.mock import AsyncMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from aun_core.v2.session import V2Session
from aun_core.v2.keystore import V2KeyStore
from aun_core.v2.crypto.ecdh import generate_p256_keypair


def _session(tmp_db, device_id: str, aid_keypair: tuple[bytes, bytes] | None = None) -> V2Session:
    aid_priv, aid_pub = aid_keypair or generate_p256_keypair()
    return V2Session(
        tmp_db,
        device_id,
        "alice.agentid.pub",
        aid_priv_der=aid_priv,
        aid_pub_der=aid_pub,
    )


@pytest.fixture
def tmp_db(tmp_path):
    """创建临时 SQLite 数据库，模拟 AIDDatabase。"""
    import sqlite3
    db_path = tmp_path / "aun.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS v2_device_keys (
        device_id TEXT NOT NULL,
        key_type TEXT NOT NULL,
        key_id TEXT NOT NULL DEFAULT '',
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, key_type, key_id)
    )""")
    conn.commit()

    class FakeDB:
        def _get_conn(self):
            return conn
    return FakeDB()


class TestMultiDeviceKeyStore:
    """V2KeyStore 多设备隔离测试"""

    def test_two_devices_independent_ik(self, tmp_db):
        """两个 device_id 各自保存独立的 IK"""
        store = V2KeyStore(tmp_db)
        priv1, pub1 = generate_p256_keypair()
        priv2, pub2 = generate_p256_keypair()

        store.save_ik("dev-1", priv1, pub1)
        store.save_ik("dev-2", priv2, pub2)

        loaded1 = store.load_ik("dev-1")
        loaded2 = store.load_ik("dev-2")

        assert loaded1 == (priv1, pub1)
        assert loaded2 == (priv2, pub2)
        assert loaded1 != loaded2

    def test_two_devices_independent_spk(self, tmp_db):
        """两个 device_id 各自保存独立的 SPK"""
        store = V2KeyStore(tmp_db)
        priv1, pub1 = generate_p256_keypair()
        priv2, pub2 = generate_p256_keypair()
        spk_id1 = "sha256:" + hashlib.sha256(pub1).hexdigest()[:16]
        spk_id2 = "sha256:" + hashlib.sha256(pub2).hexdigest()[:16]

        store.save_spk("dev-1", spk_id1, priv1, pub1)
        store.save_spk("dev-2", spk_id2, priv2, pub2)

        assert store.load_spk("dev-1", spk_id1) == priv1
        assert store.load_spk("dev-2", spk_id2) == priv2
        assert store.load_spk("dev-1", spk_id2) is None
        assert store.load_spk("dev-2", spk_id1) is None

    def test_current_spk_per_device(self, tmp_db):
        """load_current_spk 按 device_id 隔离"""
        store = V2KeyStore(tmp_db)
        priv1, pub1 = generate_p256_keypair()
        priv2, pub2 = generate_p256_keypair()
        spk_id1 = "sha256:aaaa"
        spk_id2 = "sha256:bbbb"

        store.save_spk("dev-1", spk_id1, priv1, pub1)
        store.save_spk("dev-2", spk_id2, priv2, pub2)

        result1 = store.load_current_spk("dev-1")
        result2 = store.load_current_spk("dev-2")

        assert result1[0] == spk_id1
        assert result2[0] == spk_id2


class TestMultiDeviceSession:
    """V2Session 多设备隔离测试"""

    def test_two_sessions_different_device_id(self, tmp_db):
        """同一 AID 两个 V2Session 使用不同 device_id；IK 共享，SPK 独立"""
        aid_keypair = generate_p256_keypair()
        session1 = _session(tmp_db, "dev-1", aid_keypair)
        session2 = _session(tmp_db, "dev-2", aid_keypair)

        session1.ensure_keys()
        session2.ensure_keys()

        assert session1._ik_priv == session2._ik_priv
        assert session1._ik_pub_der == session2._ik_pub_der
        assert session1._spk_id != session2._spk_id

    def test_session_persists_and_reloads(self, tmp_db):
        """V2Session 密钥持久化后重新加载一致"""
        aid_keypair = generate_p256_keypair()
        session1 = _session(tmp_db, "dev-1", aid_keypair)
        session1.ensure_keys()
        ik_priv = session1._ik_priv
        spk_id = session1._spk_id

        # 模拟重启：新建 session 实例
        session1_reload = _session(tmp_db, "dev-1", aid_keypair)
        session1_reload.ensure_keys()

        assert session1_reload._ik_priv == ik_priv
        assert session1_reload._spk_id == spk_id

    @pytest.mark.asyncio
    async def test_two_sessions_register_independently(self, tmp_db):
        """两个 session 各自注册到服务端，SPK 独立"""
        aid_keypair = generate_p256_keypair()
        session1 = _session(tmp_db, "dev-1", aid_keypair)
        session2 = _session(tmp_db, "dev-2", aid_keypair)

        calls = []

        async def mock_call(method, params):
            calls.append((method, params))
            return {"ok": True}

        await session1.ensure_registered(mock_call)
        await session2.ensure_registered(mock_call)

        assert len(calls) == 2
        assert calls[0][0] == "message.v2.put_peer_pk"
        assert calls[1][0] == "message.v2.put_peer_pk"
        assert calls[0][1]["peer_aid"] == "alice.agentid.pub"
        assert calls[1][1]["peer_aid"] == "alice.agentid.pub"
        assert calls[0][1]["spk_id"] != calls[1][1]["spk_id"]

    def test_get_decrypt_keys_cross_device(self, tmp_db):
        """dev-1 的 SPK 不能被 dev-2 的 session 解密"""
        aid_keypair = generate_p256_keypair()
        session1 = _session(tmp_db, "dev-1", aid_keypair)
        session2 = _session(tmp_db, "dev-2", aid_keypair)
        session1.ensure_keys()
        session2.ensure_keys()

        # dev-2 尝试用 dev-1 的 spk_id 解密，应准确报告缺失 SPK
        with pytest.raises(ValueError, match="spk_missing"):
            session2.get_decrypt_keys(session1._spk_id)

    def test_get_decrypt_keys_falls_back_to_matching_ik_id(self, tmp_db):
        """spk_id 命中本设备 IK 指纹时，按 IK-as-SPK 路径返回 IK 私钥。"""
        session = _session(tmp_db, "dev-1")
        session.ensure_keys()
        ik_id = "sha256:" + hashlib.sha256(session._ik_pub_der).hexdigest()[:16]

        ik_priv, spk_priv = session.get_decrypt_keys(ik_id)

        assert ik_priv == session._ik_priv
        assert spk_priv == session._ik_priv

    def test_get_group_decrypt_keys_falls_back_to_matching_ik_id(self, tmp_db):
        """group 解密 lookup 顺序应覆盖 group SPK、device SPK、IK。"""
        session = _session(tmp_db, "dev-1")
        session.ensure_keys()
        ik_id = "sha256:" + hashlib.sha256(session._ik_pub_der).hexdigest()[:16]

        ik_priv, spk_priv = session.get_group_decrypt_keys("group.agentid.pub/1", ik_id)

        assert ik_priv == session._ik_priv
        assert spk_priv == session._ik_priv

    def test_get_group_decrypt_keys_falls_back_to_device_spk(self, tmp_db):
        """group 消息未命中 group SPK 时，应继续按 device SPK 查找。"""
        session = _session(tmp_db, "dev-1")
        session.ensure_keys()

        ik_priv, spk_priv = session.get_group_decrypt_keys("group.agentid.pub/1", session._spk_id)

        assert ik_priv == session._ik_priv
        assert spk_priv == session._spk_priv

    def test_spk_rotation_preserves_old(self, tmp_db):
        """SPK 轮换后旧 SPK 仍可用于解密"""
        session = _session(tmp_db, "dev-1")
        session.ensure_keys()
        old_spk_id = session._spk_id
        old_spk_priv = session._spk_priv

        # 手动轮换
        from aun_core.v2.crypto.ecdh import generate_p256_keypair
        new_priv, new_pub = generate_p256_keypair()
        new_spk_id = "sha256:" + hashlib.sha256(new_pub).hexdigest()[:16]
        store = V2KeyStore(tmp_db)
        store.save_spk("dev-1", new_spk_id, new_priv, new_pub)
        session._spk_id = new_spk_id
        session._spk_priv = new_priv
        session._spk_pub_der = new_pub

        # 旧 SPK 仍可解密
        ik_priv, spk_priv = session.get_decrypt_keys(old_spk_id)
        assert spk_priv == old_spk_priv

        # 新 SPK 也可解密
        ik_priv, spk_priv = session.get_decrypt_keys(new_spk_id)
        assert spk_priv == new_priv
