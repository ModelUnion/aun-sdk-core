"""M3-A5: V2 缓存优化测试

验证：
- 对端 IK 公钥缓存命中时不重复 bootstrap
- 缓存过期后重新获取
- SPK 已验证标记的存取
"""
import time
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from aun_core.v2.session import V2Session
from aun_core.v2.crypto.ecdh import generate_p256_keypair


@pytest.fixture
def tmp_db(tmp_path):
    """创建临时 SQLite 数据库。"""
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


class TestPeerIKCache:
    """对端 IK 公钥缓存测试"""

    def test_cache_hit_returns_value(self, tmp_db):
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        _, peer_ik = generate_p256_keypair()
        session.cache_peer_ik("bobb.agentid.pub", "bob-dev", peer_ik)
        assert session.get_peer_ik("bobb.agentid.pub", "bob-dev") == peer_ik

    def test_cache_miss_returns_none(self, tmp_db):
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        assert session.get_peer_ik("bobb.agentid.pub", "bob-dev") is None

    def test_cache_expires_after_ttl(self, tmp_db):
        """缓存超过 TTL 后视为失效"""
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        _, peer_ik = generate_p256_keypair()

        session.cache_peer_ik("bobb.agentid.pub", "bob-dev", peer_ik)
        # 直接修改缓存项的时间戳为 1 小时前
        key = "bobb.agentid.pub#bob-dev"
        ik, _cached_at = session._peer_ik_cache[key]
        session._peer_ik_cache[key] = (ik, time.time() - 3700)

        assert session.get_peer_ik("bobb.agentid.pub", "bob-dev") is None
        # 过期后应从缓存中清除
        assert key not in session._peer_ik_cache

    def test_cache_within_ttl(self, tmp_db):
        """TTL 内缓存有效"""
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        _, peer_ik = generate_p256_keypair()

        session.cache_peer_ik("bobb.agentid.pub", "bob-dev", peer_ik)
        # 改时间戳为 30 分钟前（仍在 TTL 内）
        key = "bobb.agentid.pub#bob-dev"
        ik, _ = session._peer_ik_cache[key]
        session._peer_ik_cache[key] = (ik, time.time() - 1800)

        assert session.get_peer_ik("bobb.agentid.pub", "bob-dev") == peer_ik

    def test_multiple_peer_devices(self, tmp_db):
        """多个对端设备各自缓存独立"""
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        _, ik1 = generate_p256_keypair()
        _, ik2 = generate_p256_keypair()
        session.cache_peer_ik("bobb.agentid.pub", "bob-1", ik1)
        session.cache_peer_ik("bobb.agentid.pub", "bob-2", ik2)
        assert session.get_peer_ik("bobb.agentid.pub", "bob-1") == ik1
        assert session.get_peer_ik("bobb.agentid.pub", "bob-2") == ik2
        assert ik1 != ik2


class TestSpkVerifiedCache:
    """SPK 已验证标记测试"""

    def test_default_not_verified(self, tmp_db):
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        assert not session.is_peer_spk_verified("bobb.agentid.pub", "bob-1", "sha256:aaa")

    def test_mark_then_check(self, tmp_db):
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        session.mark_peer_spk_verified("bobb.agentid.pub", "bob-1", "sha256:aaa")
        assert session.is_peer_spk_verified("bobb.agentid.pub", "bob-1", "sha256:aaa")

    def test_different_spk_id_not_verified(self, tmp_db):
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        session.mark_peer_spk_verified("bobb.agentid.pub", "bob-1", "sha256:aaa")
        assert not session.is_peer_spk_verified("bobb.agentid.pub", "bob-1", "sha256:bbb")

    def test_different_device_not_verified(self, tmp_db):
        session = V2Session(tmp_db, "dev-1", "alice.agentid.pub")
        session.mark_peer_spk_verified("bobb.agentid.pub", "bob-1", "sha256:aaa")
        assert not session.is_peer_spk_verified("bobb.agentid.pub", "bob-2", "sha256:aaa")
