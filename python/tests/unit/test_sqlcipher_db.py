"""AIDDatabase (SQLCipher) 单元测试。"""

import hashlib
import tempfile
import threading
import time
from pathlib import Path

import pytest

from aun_core.keystore.sqlcipher_db import (
    AIDDatabase,
    derive_sqlcipher_key,
    load_or_create_seed,
)


def _make_db(tmp_path: Path) -> AIDDatabase:
    seed = b"test-seed-32-bytes-padding-xxxxx"
    key = derive_sqlcipher_key(seed)
    db = AIDDatabase(tmp_path / "aun.db", key)
    return db


# ── Key 派生 ─────────────────────────────────────────────────


def test_derive_sqlcipher_key_deterministic():
    seed = b"same-seed"
    assert derive_sqlcipher_key(seed) == derive_sqlcipher_key(seed)


def test_derive_sqlcipher_key_format():
    key = derive_sqlcipher_key(b"seed")
    assert key.startswith("x'")
    assert key.endswith("'")
    assert len(key) == 2 + 64 + 1  # x' + 64 hex + '


def test_derive_sqlcipher_key_different_from_file_aes():
    seed = b"same-seed"
    sqlcipher_key = hashlib.pbkdf2_hmac("sha256", seed, b"aun_sqlcipher_v1", 100_000)
    file_aes_key = hashlib.pbkdf2_hmac("sha256", seed, b"aun_file_secret_store_v1", 100_000)
    assert sqlcipher_key != file_aes_key


# ── Seed 管理 ────────────────────────────────────────────────


def test_load_or_create_seed_from_param(tmp_path):
    seed = load_or_create_seed(tmp_path, encryption_seed="my-password")
    assert seed == b"my-password"
    assert not (tmp_path / ".seed").exists()


def test_load_or_create_seed_creates_file(tmp_path):
    seed = load_or_create_seed(tmp_path)
    assert len(seed) == 32
    assert (tmp_path / ".seed").exists()


def test_load_or_create_seed_reads_existing(tmp_path):
    (tmp_path / ".seed").write_bytes(b"x" * 32)
    seed = load_or_create_seed(tmp_path)
    assert seed == b"x" * 32


def test_load_or_create_seed_param_ignores_file(tmp_path):
    (tmp_path / ".seed").write_bytes(b"file-seed" + b"\x00" * 23)
    seed = load_or_create_seed(tmp_path, encryption_seed="override")
    assert seed == b"override"


# ── Schema 初始化 ────────────────────────────────────────────


def test_schema_version(tmp_path):
    db = _make_db(tmp_path)
    assert db.get_schema_version() == 1
    db.close()


def test_db_file_created(tmp_path):
    db = _make_db(tmp_path)
    db.get_schema_version()
    assert (tmp_path / "aun.db").exists()
    db.close()


def test_db_not_readable_without_key(tmp_path):
    """aun.db 不能用普通 sqlite3 打开（SQLCipher 加密验证）。"""
    db = _make_db(tmp_path)
    db.get_schema_version()
    db.close()

    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "aun.db"))
    with pytest.raises(Exception):
        conn.execute("SELECT * FROM _schema_version").fetchall()
    conn.close()


# ── Tokens ───────────────────────────────────────────────────


def test_tokens_crud(tmp_path):
    db = _make_db(tmp_path)
    assert db.get_token("access_token") is None
    db.set_token("access_token", "tok-abc")
    assert db.get_token("access_token") == "tok-abc"
    db.set_token("access_token", "tok-xyz")
    assert db.get_token("access_token") == "tok-xyz"
    db.delete_token("access_token")
    assert db.get_token("access_token") is None
    db.close()


def test_get_all_tokens(tmp_path):
    db = _make_db(tmp_path)
    db.set_token("access_token", "a")
    db.set_token("refresh_token", "b")
    tokens = db.get_all_tokens()
    assert tokens == {"access_token": "a", "refresh_token": "b"}
    db.close()


# ── Prekeys ──────────────────────────────────────────────────


def test_prekeys_crud(tmp_path):
    db = _make_db(tmp_path)
    db.save_prekey("pk-1", "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----")
    prekeys = db.load_prekeys()
    assert "pk-1" in prekeys
    assert prekeys["pk-1"]["private_key_pem"].startswith("-----BEGIN")
    db.delete_prekey("pk-1")
    assert db.load_prekeys() == {}
    db.close()


def test_prekeys_device_id_isolation(tmp_path):
    db = _make_db(tmp_path)
    db.save_prekey("pk-1", "KEY-A", device_id="device-1")
    db.save_prekey("pk-2", "KEY-B", device_id="device-2")
    assert "pk-1" in db.load_prekeys("device-1")
    assert "pk-2" not in db.load_prekeys("device-1")
    assert "pk-2" in db.load_prekeys("device-2")
    db.close()


def test_prekeys_cleanup(tmp_path):
    db = _make_db(tmp_path)
    now = int(time.time() * 1000)
    old = now - 10 * 24 * 3600 * 1000  # 10 天前
    for i in range(10):
        db.save_prekey(f"pk-{i}", f"KEY-{i}", created_at=old + i * 1000)
    # 保留最新 7 个，删除 3 个旧的
    deleted = db.cleanup_prekeys(now - 1000, keep_latest=7)
    assert len(deleted) == 3
    assert len(db.load_prekeys()) == 7
    db.close()


def test_prekeys_cleanup_keeps_latest_even_if_old(tmp_path):
    db = _make_db(tmp_path)
    now = int(time.time() * 1000)
    old = now - 30 * 24 * 3600 * 1000
    for i in range(5):
        db.save_prekey(f"pk-{i}", f"KEY-{i}", created_at=old + i * 1000)
    # 只有 5 个，keep_latest=7，不应删除任何
    deleted = db.cleanup_prekeys(now, keep_latest=7)
    assert deleted == []
    assert len(db.load_prekeys()) == 5
    db.close()


# ── Group Secrets ────────────────────────────────────────────


def test_group_current_crud(tmp_path):
    db = _make_db(tmp_path)
    db.save_group_current("grp-1", epoch=1, secret="secret-1", data={"members": ["a", "b"]})
    state = db.load_group_current("grp-1")
    assert state is not None
    assert state["epoch"] == 1
    assert state["secret"] == "secret-1"
    assert state["members"] == ["a", "b"]
    # 更新 epoch
    db.save_group_current("grp-1", epoch=2, secret="secret-2", data={"members": ["a", "b", "c"]})
    state = db.load_group_current("grp-1")
    assert state["epoch"] == 2
    assert state["secret"] == "secret-2"
    db.close()


def test_load_all_group_current(tmp_path):
    db = _make_db(tmp_path)
    db.save_group_current("grp-1", epoch=1, secret="s1", data={})
    db.save_group_current("grp-2", epoch=3, secret="s3", data={})
    all_groups = db.load_all_group_current()
    assert set(all_groups.keys()) == {"grp-1", "grp-2"}
    db.close()


def test_group_old_epochs_crud(tmp_path):
    db = _make_db(tmp_path)
    now = int(time.time() * 1000)
    db.save_group_old_epoch("grp-1", epoch=0, secret="old-secret", data={}, expires_at=now + 86400000)
    epochs = db.load_group_old_epochs("grp-1")
    assert len(epochs) == 1
    assert epochs[0]["epoch"] == 0
    assert epochs[0]["secret"] == "old-secret"
    db.close()


def test_group_old_epochs_cleanup(tmp_path):
    db = _make_db(tmp_path)
    now = int(time.time() * 1000)
    db.save_group_old_epoch("grp-1", epoch=0, secret="s0", data={}, expires_at=now - 1000)
    db.save_group_old_epoch("grp-1", epoch=1, secret="s1", data={}, expires_at=now + 86400000)
    deleted = db.cleanup_group_old_epochs("grp-1", now)
    assert deleted == 1
    epochs = db.load_group_old_epochs("grp-1")
    assert len(epochs) == 1
    assert epochs[0]["epoch"] == 1
    db.close()


# ── E2EE Sessions ────────────────────────────────────────────


def test_sessions_crud(tmp_path):
    db = _make_db(tmp_path)
    db.save_session("sess-1", {"key": "session-key", "peer": "bob.aid.com"})
    sess = db.load_session("sess-1")
    assert sess is not None
    assert sess["key"] == "session-key"
    assert sess["peer"] == "bob.aid.com"
    db.close()


def test_load_all_sessions(tmp_path):
    db = _make_db(tmp_path)
    db.save_session("sess-1", {"key": "k1"})
    db.save_session("sess-2", {"key": "k2"})
    sessions = db.load_all_sessions()
    assert len(sessions) == 2
    db.close()


# ── Instance State ───────────────────────────────────────────


def test_instance_state_crud(tmp_path):
    db = _make_db(tmp_path)
    db.save_instance_state("dev-1", "", {"access_token": "tok-1"})
    state = db.load_instance_state("dev-1")
    assert state is not None
    assert state["access_token"] == "tok-1"
    db.close()


def test_instance_state_slot_isolation(tmp_path):
    db = _make_db(tmp_path)
    db.save_instance_state("dev-1", "slot-a", {"token": "a"})
    db.save_instance_state("dev-1", "slot-b", {"token": "b"})
    assert db.load_instance_state("dev-1", "slot-a")["token"] == "a"
    assert db.load_instance_state("dev-1", "slot-b")["token"] == "b"
    db.close()


# ── Metadata KV ──────────────────────────────────────────────


def test_metadata_kv_crud(tmp_path):
    db = _make_db(tmp_path)
    assert db.get_metadata("foo") is None
    db.set_metadata("foo", "bar")
    assert db.get_metadata("foo") == "bar"
    db.delete_metadata("foo")
    assert db.get_metadata("foo") is None
    db.close()


def test_get_all_metadata(tmp_path):
    db = _make_db(tmp_path)
    db.set_metadata("k1", "v1")
    db.set_metadata("k2", "v2")
    assert db.get_all_metadata() == {"k1": "v1", "k2": "v2"}
    db.close()


# ── 并发安全 ─────────────────────────────────────────────────


def test_concurrent_writes_no_corruption(tmp_path):
    db = _make_db(tmp_path)
    errors = []

    def writer(i: int):
        try:
            with db._lock:
                db.save_prekey(f"pk-{i}", f"KEY-{i}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(db.load_prekeys()) == 20
    db.close()


def test_get_conn_recovers_from_disk_io_error_and_removes_journal(tmp_path, monkeypatch):
    db = _make_db(tmp_path)
    db_path = tmp_path / "aun.db"
    journal_path = tmp_path / "aun.db-journal"
    db_path.write_bytes(b"")
    journal_path.write_bytes(b"stale-journal")

    class _Conn:
        def close(self):
            return None

    attempts = {"count": 0}

    def _open_and_init():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("disk I/O error")
        return _Conn()

    monkeypatch.setattr(db, "_open_and_init", _open_and_init)

    conn = db._get_conn()

    assert isinstance(conn, _Conn)
    assert attempts["count"] == 2
    assert not db_path.exists()
    assert not journal_path.exists()
    db.close()


def test_open_and_init_falls_back_to_exclusive_locking(tmp_path, monkeypatch):
    db = _make_db(tmp_path)
    calls = []

    class _Cursor:
        def __init__(self, row=None):
            self._row = row

        def fetchone(self):
            return self._row

    class _Conn:
        def __init__(self, fail_init: bool):
            self.fail_init = fail_init
            self.closed = False

        def execute(self, stmt, params=None):
            calls.append(stmt)
            if self.fail_init and stmt.startswith("CREATE TABLE IF NOT EXISTS _schema_version"):
                raise RuntimeError("disk I/O error")
            if stmt.startswith("SELECT version FROM _schema_version"):
                return _Cursor(None)
            return _Cursor()

        def commit(self):
            calls.append("COMMIT")

        def close(self):
            self.closed = True
            calls.append("CLOSE")

    created = {"count": 0}

    def _fake_connect(*args, **kwargs):
        created["count"] += 1
        return _Conn(fail_init=created["count"] == 1)

    import aun_core.keystore.sqlcipher_db as module
    monkeypatch.setattr(module._sqlite_mod, "connect", _fake_connect)

    conn = db._open_and_init()

    assert created["count"] == 2
    assert db._use_exclusive_locking is True
    assert isinstance(conn, _Conn)
    assert "PRAGMA journal_mode = WAL" in calls
    assert "PRAGMA locking_mode = EXCLUSIVE" in calls
    assert "PRAGMA journal_mode = DELETE" in calls


# ── 持久化验证 ───────────────────────────────────────────────


def test_data_survives_close_reopen(tmp_path):
    db = _make_db(tmp_path)
    db.set_token("access_token", "persistent-token")
    db.save_prekey("pk-1", "PERSISTENT-KEY")
    db.close()

    # 重新打开
    db2 = _make_db(tmp_path)
    assert db2.get_token("access_token") == "persistent-token"
    assert "pk-1" in db2.load_prekeys()
    db2.close()


# ── _get_conn 早期抛错不触发 UnboundLocalError ────────────────


def test_get_conn_open_and_init_raises_immediately_no_unbound_error(tmp_path, monkeypatch):
    """_open_and_init() 直接抛出异常时，_get_conn() 不应触发 UnboundLocalError。

    Bug 场景：_open_and_init() 在赋值 conn = ... 之前就抛出，
    except 块中 conn.close() 引用未定义的 conn，导致 UnboundLocalError 掩盖原始异常。
    修复后应直接抛出原始异常（RuntimeError），而不是 UnboundLocalError。
    """
    db = _make_db(tmp_path)

    original_error = RuntimeError("模拟 _open_and_init 早期失败")

    def _open_and_init_raises():
        raise original_error

    monkeypatch.setattr(db, "_open_and_init", _open_and_init_raises)

    # 应抛出原始异常，而不是 UnboundLocalError
    with pytest.raises(RuntimeError, match="模拟 _open_and_init 早期失败"):
        db._get_conn()


def test_get_conn_unbound_error_not_raised_on_non_recoverable(tmp_path, monkeypatch):
    """非可恢复错误时，_get_conn() 应直接 raise 原始异常，不触发 UnboundLocalError。"""
    db = _make_db(tmp_path)

    class _SpecificError(Exception):
        pass

    def _open_and_init_raises():
        raise _SpecificError("hmac check failed")

    monkeypatch.setattr(db, "_open_and_init", _open_and_init_raises)

    # 应抛出 _SpecificError，而不是 UnboundLocalError
    with pytest.raises(_SpecificError):
        db._get_conn()


def test_open_and_init_logs_close_failure(tmp_path, monkeypatch, caplog):
    db = _make_db(tmp_path)

    class _FakeConn:
        def execute(self, _sql):
            raise RuntimeError("boom during init")

        def close(self):
            raise RuntimeError("close failed")

    from aun_core.keystore import sqlcipher_db as module

    monkeypatch.setattr(module._sqlite_mod, "connect", lambda *args, **kwargs: _FakeConn())

    with caplog.at_level("DEBUG"):
        with pytest.raises(RuntimeError, match="boom during init"):
            db._open_and_init_once(exclusive_locking=False)

    assert "关闭失败连接时出错: close failed" in caplog.text


def test_retry_on_locked_logs_close_failure(tmp_path, caplog):
    db = _make_db(tmp_path)

    class _FakeConn:
        def close(self):
            raise RuntimeError("close failed")

    db._conn = _FakeConn()
    db._cleanup_broken_files = lambda: None

    with caplog.at_level("DEBUG"):
        with pytest.raises(RuntimeError, match="database disk image is malformed"):
            db._retry_on_locked(
                lambda: (_ for _ in ()).throw(RuntimeError("database disk image is malformed")),
                max_retries=2,
                delay=0,
            )

    assert "关闭失败连接时出错: close failed" in caplog.text
