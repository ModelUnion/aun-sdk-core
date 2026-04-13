"""Per-AID SQLCipher 加密数据库 — prekeys/tokens/groups/sessions/instance_state 的单一存储源。

密钥派生：
  seed_bytes → PBKDF2-HMAC-SHA256(salt=b"aun_sqlcipher_v1", iterations=100_000) → 32 字节 raw key
  连接时通过 PRAGMA key = "x'<hex>'" 传入，跳过 SQLCipher 内部 KDF。

零共享代码依赖：仅依赖 sqlcipher3（或降级 sqlite3）和标准库。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

_log = logging.getLogger("aun_core.keystore")

# SQLCipher / SQLite 模块选择
try:
    import sqlcipher3 as _sqlite_mod

    SQLCIPHER_AVAILABLE = True
except ImportError:
    import sqlite3 as _sqlite_mod  # type: ignore[no-redef]

    SQLCIPHER_AVAILABLE = False
    _log.warning(
        "sqlcipher3 未安装，数据库将不加密。安装方法: pip install sqlcipher3"
    )

_SCHEMA_VERSION = 1
_BUSY_TIMEOUT_MS = 5000


# ── Key 派生 ─────────────────────────────────────────────────


def derive_sqlcipher_key(seed_bytes: bytes) -> str:
    """从 seed 派生 SQLCipher raw hex key。

    使用与 key.json 不同的 salt，确保两个密钥独立。
    返回格式：x'<64 hex chars>'（SQLCipher raw key 格式）。
    """
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        seed_bytes,
        b"aun_sqlcipher_v1",
        iterations=100_000,
    )
    return f"x'{derived.hex()}'"


def load_or_create_seed(root: Path, *, encryption_seed: str | None = None) -> bytes:
    """加载或生成 .seed 文件。

    优先级：encryption_seed 参数 > .seed 文件 > 新生成。
    """
    if encryption_seed:
        return encryption_seed.encode("utf-8")

    seed_path = root / ".seed"
    if seed_path.exists():
        return seed_path.read_bytes()

    # 生成新 seed
    seed = os.urandom(32)
    root.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(seed)
    if sys.platform != "win32":
        try:
            os.chmod(seed_path, 0o600)
        except OSError:
            pass
    _log.info("新 seed 已生成: %s", seed_path)
    return seed


# ── Schema DDL ───────────────────────────────────────────────

_DDL_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS _schema_version (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS tokens (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS prekeys (
        prekey_id TEXT NOT NULL,
        device_id TEXT NOT NULL DEFAULT '',
        private_key_pem TEXT NOT NULL,
        created_at INTEGER,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        PRIMARY KEY (prekey_id, device_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_prekeys_device ON prekeys (device_id, created_at)",
    """CREATE TABLE IF NOT EXISTS group_current (
        group_id TEXT PRIMARY KEY,
        epoch INTEGER NOT NULL,
        secret TEXT NOT NULL,
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS group_old_epochs (
        group_id TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        secret TEXT NOT NULL,
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        PRIMARY KEY (group_id, epoch)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_group_old_expires ON group_old_epochs (group_id, expires_at)",
    """CREATE TABLE IF NOT EXISTS e2ee_sessions (
        session_id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS instance_state (
        device_id TEXT NOT NULL,
        slot_id TEXT NOT NULL DEFAULT '_singleton',
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, slot_id)
    )""",
    """CREATE TABLE IF NOT EXISTS metadata_kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )""",
]


# ── AIDDatabase ──────────────────────────────────────────────


class AIDDatabase:
    """单个 AID 的 SQLCipher 数据库。

    持有一个持久连接，WAL 模式，线程安全由外部 RLock 保证。
    """

    def __init__(self, db_path: Path, sqlcipher_key: str) -> None:
        self._db_path = db_path
        self._key = sqlcipher_key
        self._conn: Any | None = None
        self._lock = threading.RLock()

    # ── 连接管理 ─────────────────────────────────────────────

    def _get_conn(self) -> Any:
        if self._conn is not None:
            return self._conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = _sqlite_mod.connect(
            str(self._db_path),
            timeout=_BUSY_TIMEOUT_MS / 1000,
            check_same_thread=False,
        )
        if SQLCIPHER_AVAILABLE:
            conn.execute(f"PRAGMA key = \"{self._key}\"")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema(conn)
        self._conn = conn
        return conn

    def _init_schema(self, conn: Any) -> None:
        for ddl in _DDL_STATEMENTS:
            conn.execute(ddl)
        # 初始化 schema version
        cur = conn.execute("SELECT version FROM _schema_version WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO _schema_version (id, version) VALUES (1, ?)",
                (_SCHEMA_VERSION,),
            )
        conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def get_schema_version(self) -> int:
        conn = self._get_conn()
        cur = conn.execute("SELECT version FROM _schema_version WHERE id = 1")
        row = cur.fetchone()
        return int(row[0]) if row else 0

    # ── Tokens ───────────────────────────────────────────────

    def get_token(self, key: str) -> str | None:
        conn = self._get_conn()
        cur = conn.execute("SELECT value FROM tokens WHERE key = ?", (key,))
        row = cur.fetchone()
        return str(row[0]) if row else None

    def set_token(self, key: str, value: str) -> None:
        conn = self._get_conn()
        now = _now_ms()
        conn.execute(
            "INSERT INTO tokens (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, now),
        )
        conn.commit()

    def delete_token(self, key: str) -> None:
        conn = self._get_conn()
        conn.execute("DELETE FROM tokens WHERE key = ?", (key,))
        conn.commit()

    def get_all_tokens(self) -> dict[str, str]:
        conn = self._get_conn()
        cur = conn.execute("SELECT key, value FROM tokens")
        return {row[0]: row[1] for row in cur.fetchall()}

    # ── Prekeys ──────────────────────────────────────────────

    def save_prekey(
        self,
        prekey_id: str,
        private_key_pem: str,
        *,
        device_id: str = "",
        created_at: int | None = None,
        expires_at: int | None = None,
    ) -> None:
        conn = self._get_conn()
        now = _now_ms()
        conn.execute(
            "INSERT INTO prekeys (prekey_id, device_id, private_key_pem, created_at, updated_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(prekey_id, device_id) DO UPDATE SET "
            "private_key_pem = excluded.private_key_pem, updated_at = excluded.updated_at, "
            "expires_at = excluded.expires_at",
            (prekey_id, device_id, private_key_pem, created_at or now, now, expires_at),
        )
        conn.commit()

    def load_prekeys(self, device_id: str = "") -> dict[str, dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT prekey_id, private_key_pem, created_at, updated_at, expires_at "
            "FROM prekeys WHERE device_id = ?",
            (device_id,),
        )
        result: dict[str, dict[str, Any]] = {}
        for row in cur.fetchall():
            result[row[0]] = {
                "private_key_pem": row[1],
                "created_at": row[2],
                "updated_at": row[3],
                "expires_at": row[4],
            }
        return result

    def delete_prekey(self, prekey_id: str, device_id: str = "") -> None:
        conn = self._get_conn()
        conn.execute(
            "DELETE FROM prekeys WHERE prekey_id = ? AND device_id = ?",
            (prekey_id, device_id),
        )
        conn.commit()

    def cleanup_prekeys(
        self, cutoff_ms: int, *, keep_latest: int = 7, device_id: str = ""
    ) -> list[str]:
        """删除过期 prekeys，保留最新 N 个。返回被删除的 prekey_id 列表。"""
        conn = self._get_conn()
        # 查出该 device 的所有 prekeys，按 created_at 降序
        cur = conn.execute(
            "SELECT prekey_id, created_at FROM prekeys WHERE device_id = ? "
            "ORDER BY created_at DESC",
            (device_id,),
        )
        all_rows = cur.fetchall()
        if not all_rows:
            return []
        # 保留最新 N 个的 ID
        latest_ids = {row[0] for row in all_rows[:keep_latest]}
        # 找出需要删除的
        to_delete = []
        for prekey_id, created_at in all_rows:
            if prekey_id in latest_ids:
                continue
            if created_at is not None and created_at < cutoff_ms:
                to_delete.append(prekey_id)
        if to_delete:
            placeholders = ",".join("?" for _ in to_delete)
            conn.execute(
                f"DELETE FROM prekeys WHERE device_id = ? AND prekey_id IN ({placeholders})",
                [device_id, *to_delete],
            )
            conn.commit()
        return to_delete

    # ── Group Secrets ────────────────────────────────────────

    def save_group_current(
        self, group_id: str, epoch: int, secret: str, data: dict[str, Any]
    ) -> None:
        conn = self._get_conn()
        now = _now_ms()
        data_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        conn.execute(
            "INSERT INTO group_current (group_id, epoch, secret, data, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(group_id) DO UPDATE SET "
            "epoch = excluded.epoch, secret = excluded.secret, "
            "data = excluded.data, updated_at = excluded.updated_at",
            (group_id, epoch, secret, data_json, now),
        )
        conn.commit()

    def load_group_current(self, group_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT epoch, secret, data, updated_at FROM group_current WHERE group_id = ?",
            (group_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "group_id": group_id,
            "epoch": row[0],
            "secret": row[1],
            **json.loads(row[2]),
            "updated_at": row[3],
        }

    def load_all_group_current(self) -> dict[str, dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute("SELECT group_id, epoch, secret, data, updated_at FROM group_current")
        result: dict[str, dict[str, Any]] = {}
        for row in cur.fetchall():
            result[row[0]] = {
                "group_id": row[0],
                "epoch": row[1],
                "secret": row[2],
                **json.loads(row[3]),
                "updated_at": row[4],
            }
        return result

    def save_group_old_epoch(
        self,
        group_id: str,
        epoch: int,
        secret: str,
        data: dict[str, Any],
        *,
        expires_at: int | None = None,
    ) -> None:
        conn = self._get_conn()
        now = _now_ms()
        data_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        conn.execute(
            "INSERT INTO group_old_epochs (group_id, epoch, secret, data, updated_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(group_id, epoch) DO UPDATE SET "
            "secret = excluded.secret, data = excluded.data, "
            "updated_at = excluded.updated_at, expires_at = excluded.expires_at",
            (group_id, epoch, secret, data_json, now, expires_at),
        )
        conn.commit()

    def load_group_old_epochs(self, group_id: str) -> list[dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT epoch, secret, data, updated_at, expires_at "
            "FROM group_old_epochs WHERE group_id = ? ORDER BY epoch DESC",
            (group_id,),
        )
        result = []
        for row in cur.fetchall():
            result.append({
                "epoch": row[0],
                "secret": row[1],
                **json.loads(row[2]),
                "updated_at": row[3],
                "expires_at": row[4],
            })
        return result

    def cleanup_group_old_epochs(self, group_id: str, cutoff_ms: int) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM group_old_epochs WHERE group_id = ? AND expires_at IS NOT NULL AND expires_at < ?",
            (group_id, cutoff_ms),
        )
        conn.commit()
        return cur.rowcount

    # ── E2EE Sessions ────────────────────────────────────────

    def save_session(self, session_id: str, data: dict[str, Any]) -> None:
        conn = self._get_conn()
        now = _now_ms()
        data_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        conn.execute(
            "INSERT INTO e2ee_sessions (session_id, data, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
            (session_id, data_json, now),
        )
        conn.commit()

    def load_session(self, session_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT data, updated_at FROM e2ee_sessions WHERE session_id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {**json.loads(row[0]), "session_id": session_id, "updated_at": row[1]}

    def load_all_sessions(self) -> list[dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute("SELECT session_id, data, updated_at FROM e2ee_sessions")
        return [
            {**json.loads(row[1]), "session_id": row[0], "updated_at": row[2]}
            for row in cur.fetchall()
        ]

    # ── Instance State ───────────────────────────────────────

    def save_instance_state(
        self, device_id: str, slot_id: str, state: dict[str, Any]
    ) -> None:
        conn = self._get_conn()
        now = _now_ms()
        slot = slot_id or "_singleton"
        data_json = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        conn.execute(
            "INSERT INTO instance_state (device_id, slot_id, data, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(device_id, slot_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
            (device_id, slot, data_json, now),
        )
        conn.commit()

    def load_instance_state(
        self, device_id: str, slot_id: str = ""
    ) -> dict[str, Any] | None:
        conn = self._get_conn()
        slot = slot_id or "_singleton"
        cur = conn.execute(
            "SELECT data, updated_at FROM instance_state WHERE device_id = ? AND slot_id = ?",
            (device_id, slot),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    # ── Metadata KV ──────────────────────────────────────────

    def get_metadata(self, key: str) -> str | None:
        conn = self._get_conn()
        cur = conn.execute("SELECT value FROM metadata_kv WHERE key = ?", (key,))
        row = cur.fetchone()
        return str(row[0]) if row else None

    def set_metadata(self, key: str, value: str) -> None:
        conn = self._get_conn()
        now = _now_ms()
        conn.execute(
            "INSERT INTO metadata_kv (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, now),
        )
        conn.commit()

    def delete_metadata(self, key: str) -> None:
        conn = self._get_conn()
        conn.execute("DELETE FROM metadata_kv WHERE key = ?", (key,))
        conn.commit()

    def get_all_metadata(self) -> dict[str, str]:
        conn = self._get_conn()
        cur = conn.execute("SELECT key, value FROM metadata_kv")
        return {row[0]: row[1] for row in cur.fetchall()}


# ── 工具函数 ─────────────────────────────────────────────────


def _now_ms() -> int:
    return int(time.time() * 1000)
