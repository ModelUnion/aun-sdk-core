"""Per-AID SQLCipher 加密数据库 — prekeys/tokens/groups/sessions/instance_state 的单一存储源。

密钥派生：
  seed_bytes → PBKDF2-HMAC-SHA256(salt=b"aun_sqlcipher_v1", iterations=100_000) → 32 字节 raw key
  连接时通过 PRAGMA key = "x'<hex>'" 传入，跳过 SQLCipher 内部 KDF。

零共享代码依赖：仅依赖 sqlcipher3 和标准库。
"""

from __future__ import annotations

import gc
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

import sqlcipher3 as _sqlite_mod  # 硬性依赖，不降级到 sqlite3

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
        data TEXT NOT NULL DEFAULT '{}',
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
    """CREATE TABLE IF NOT EXISTS seq_tracker (
        device_id TEXT NOT NULL,
        slot_id TEXT NOT NULL DEFAULT '_singleton',
        namespace TEXT NOT NULL,
        contiguous_seq INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, slot_id, namespace)
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

    持有一个持久连接，优先使用 WAL；若当前文件系统对默认锁模式返回
    disk I/O error，则自动回退到 EXCLUSIVE + DELETE 模式。
    线程安全由外部 RLock 保证。
    """

    def __init__(self, db_path: Path, sqlcipher_key: str) -> None:
        self._db_path = db_path
        self._key = sqlcipher_key
        self._conn: Any | None = None
        self._lock = threading.RLock()
        self._use_exclusive_locking = False

    _MAX_CONNECT_RETRIES = 3
    _RETRY_DELAY_S = 0.1

    @staticmethod
    def _is_recoverable_db_error(err_msg: str) -> bool:
        # S3: 不能把 "hmac check failed" 视为可恢复 — 这是密码错误的明确信号，
        # 误把它当成"文件损坏"会导致主上下文吞掉错误并把合法数据库重建/清空。
        # 该类错误必须向上抛出，由调用方提示用户重试密码。
        lowered = str(err_msg or "").lower()
        return any(
            token in lowered
            for token in (
                "malformed",
                "corrupt",
                "not a database",
                "disk i/o error",
            )
        )

    def _cleanup_broken_files(self) -> None:
        last_err: OSError | None = None
        for attempt in range(1, 4):
            gc.collect()
            blocked = False
            for suffix in ("", "-wal", "-shm", "-journal"):
                p = Path(str(self._db_path) + suffix)
                if not p.exists():
                    continue
                try:
                    p.unlink(missing_ok=True)
                except PermissionError as exc:
                    last_err = exc
                    blocked = True
            if not blocked:
                return
            time.sleep(0.05 * attempt)
        if last_err is not None:
            raise last_err

    def _should_enable_exclusive_fallback(self, exc: Exception) -> bool:
        return (not self._use_exclusive_locking) and ("disk i/o error" in str(exc).lower())

    # ── 连接管理 ─────────────────────────────────────────────

    def _get_conn(self) -> Any:
        if self._conn is not None:
            return self._conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        last_exc: Exception | None = None
        for attempt in range(1, self._MAX_CONNECT_RETRIES + 1):
            try:
                conn = self._open_and_init()
                self._conn = conn
                return conn
            except Exception as exc:
                last_exc = exc
                err_msg = str(exc).lower()
                is_malformed = self._is_recoverable_db_error(err_msg)
                # 尝试关闭已损坏的连接
                try:
                    conn.close()  # type: ignore[possibly-undefined]
                except Exception:
                    pass
                if is_malformed and attempt < self._MAX_CONNECT_RETRIES:
                    _log.warning(
                        "数据库文件损坏 (attempt %d/%d)，删除并重建: %s — %s",
                        attempt, self._MAX_CONNECT_RETRIES, self._db_path, exc,
                    )
                    try:
                        self._cleanup_broken_files()
                    except OSError as rm_err:
                        _log.warning("删除损坏数据库文件失败: %s", rm_err)
                    continue
                if "database is locked" in err_msg and attempt < self._MAX_CONNECT_RETRIES:
                    _log.warning(
                        "数据库被锁定 (attempt %d/%d)，%ss 后重试: %s",
                        attempt, self._MAX_CONNECT_RETRIES, self._RETRY_DELAY_S, self._db_path,
                    )
                    import time as _time
                    _time.sleep(self._RETRY_DELAY_S)
                    continue
                raise
        raise last_exc  # type: ignore[misc]

    def _open_and_init(self) -> Any:
        """打开数据库连接并初始化 schema。"""
        try:
            return self._open_and_init_once(exclusive_locking=self._use_exclusive_locking)
        except Exception as exc:
            if self._should_enable_exclusive_fallback(exc):
                _log.warning(
                    "数据库初始化命中 disk I/O error，切换为 EXCLUSIVE locking 回退: %s",
                    self._db_path,
                )
                conn = self._open_and_init_once(exclusive_locking=True)
                self._use_exclusive_locking = True
                return conn
            raise

    def _open_and_init_once(self, *, exclusive_locking: bool) -> Any:
        """打开数据库连接并按指定锁模式初始化 schema。"""
        conn = _sqlite_mod.connect(
            str(self._db_path),
            timeout=_BUSY_TIMEOUT_MS / 1000,
            check_same_thread=False,
        )
        try:
            conn.execute(f"PRAGMA key = \"{self._key}\"")
            if exclusive_locking:
                conn.execute("PRAGMA locking_mode = EXCLUSIVE")
                conn.execute("PRAGMA journal_mode = DELETE")
            else:
                conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA foreign_keys = ON")
            self._init_schema(conn)
            return conn
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            del conn
            gc.collect()
            raise

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

    def _retry_on_locked(self, fn, *args, max_retries: int = 3, delay: float = 0.05):
        """对 database is locked 和 malformed 异常自动重试。"""
        for attempt in range(1, max_retries + 1):
            try:
                return fn(*args)
            except Exception as exc:
                err_msg = str(exc).lower()
                if "database is locked" in err_msg and attempt < max_retries:
                    _log.debug("数据库 locked (attempt %d/%d)，重试", attempt, max_retries)
                    time.sleep(delay * attempt)
                    continue
                if self._is_recoverable_db_error(err_msg) and attempt < max_retries:
                    _log.warning("数据库损坏 (attempt %d/%d)，重建连接", attempt, max_retries)
                    if self._conn is not None:
                        try:
                            self._conn.close()
                        except Exception:
                            pass
                    self._conn = None  # 清除连接，下次 _get_conn 重建
                    try:
                        self._cleanup_broken_files()
                    except OSError as rm_err:
                        _log.warning("删除损坏数据库文件失败: %s", rm_err)
                    continue
                raise

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
        def _do():
            conn = self._get_conn()
            now = _now_ms()
            conn.execute(
                "INSERT INTO tokens (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, value, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def delete_token(self, key: str) -> None:
        def _do():
            conn = self._get_conn()
            conn.execute("DELETE FROM tokens WHERE key = ?", (key,))
            conn.commit()
        self._retry_on_locked(_do)

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
        extra_data: dict[str, Any] | None = None,
    ) -> None:
        def _do():
            conn = self._get_conn()
            now = _now_ms()
            data_json = json.dumps(extra_data or {}, ensure_ascii=False, separators=(",", ":"))
            conn.execute(
                "INSERT INTO prekeys (prekey_id, device_id, private_key_pem, data, created_at, updated_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(prekey_id, device_id) DO UPDATE SET "
                "private_key_pem = excluded.private_key_pem, data = excluded.data, "
                "updated_at = excluded.updated_at, expires_at = excluded.expires_at",
                (prekey_id, device_id, private_key_pem, data_json, created_at or now, now, expires_at),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_prekeys(self, device_id: str = "") -> dict[str, dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT prekey_id, private_key_pem, data, created_at, updated_at, expires_at "
            "FROM prekeys WHERE device_id = ?",
            (device_id,),
        )
        result: dict[str, dict[str, Any]] = {}
        for row in cur.fetchall():
            entry: dict[str, Any] = {
                "private_key_pem": row[1],
                "created_at": row[3],
                "updated_at": row[4],
                "expires_at": row[5],
            }
            # 合并 data 列中的额外字段
            try:
                extra = json.loads(row[2]) if row[2] else {}
            except (json.JSONDecodeError, TypeError):
                extra = {}
            if isinstance(extra, dict):
                entry.update(extra)
            result[row[0]] = entry
        return result

    def load_prekey_by_id(self, prekey_id: str) -> dict[str, Any] | None:
        """按 prekey_id 精确查找，不限 device_id（用于解密回退）。"""
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT prekey_id, private_key_pem, data, created_at, updated_at, expires_at "
            "FROM prekeys WHERE prekey_id = ? LIMIT 1",
            (prekey_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        entry: dict[str, Any] = {
            "private_key_pem": row[1],
            "created_at": row[3],
            "updated_at": row[4],
            "expires_at": row[5],
        }
        try:
            extra = json.loads(row[2]) if row[2] else {}
        except (json.JSONDecodeError, TypeError):
            extra = {}
        if isinstance(extra, dict):
            entry.update(extra)
        return entry

    def delete_prekey(self, prekey_id: str, device_id: str = "") -> None:
        def _do():
            conn = self._get_conn()
            conn.execute(
                "DELETE FROM prekeys WHERE prekey_id = ? AND device_id = ?",
                (prekey_id, device_id),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def cleanup_prekeys(
        self, cutoff_ms: int, *, keep_latest: int = 7, device_id: str = ""
    ) -> list[str]:
        """删除过期 prekeys，保留最新 N 个。返回被删除的 prekey_id 列表。"""
        def _do():
            conn = self._get_conn()
            cur = conn.execute(
                "SELECT prekey_id, created_at FROM prekeys WHERE device_id = ? "
                "ORDER BY created_at DESC",
                (device_id,),
            )
            all_rows = cur.fetchall()
            if not all_rows:
                return []
            latest_ids = {row[0] for row in all_rows[:keep_latest]}
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
        return self._retry_on_locked(_do)

    # ── Group Secrets ────────────────────────────────────────

    def save_group_current(
        self, group_id: str, epoch: int, secret: str, data: dict[str, Any]
    ) -> None:
        def _do():
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
        self._retry_on_locked(_do)

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

    def delete_group_current(self, group_id: str) -> None:
        def _do():
            conn = self._get_conn()
            conn.execute("DELETE FROM group_current WHERE group_id = ?", (group_id,))
            conn.commit()
        self._retry_on_locked(_do)

    def save_group_old_epoch(
        self,
        group_id: str,
        epoch: int,
        secret: str,
        data: dict[str, Any],
        *,
        updated_at: int | None = None,
        expires_at: int | None = None,
    ) -> None:
        def _do():
            conn = self._get_conn()
            now = updated_at if updated_at is not None else _now_ms()
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
        self._retry_on_locked(_do)

    def load_group_old_epochs(self, group_id: str) -> list[dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT epoch, secret, data, updated_at, expires_at "
            "FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC",
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

    def delete_all_group_old_epochs(self, group_id: str) -> None:
        def _do():
            conn = self._get_conn()
            conn.execute("DELETE FROM group_old_epochs WHERE group_id = ?", (group_id,))
            conn.commit()
        self._retry_on_locked(_do)

    def load_all_group_ids_with_old_epochs(self) -> list[str]:
        conn = self._get_conn()
        cur = conn.execute("SELECT DISTINCT group_id FROM group_old_epochs")
        return [str(row[0]) for row in cur.fetchall()]

    def cleanup_group_old_epochs(self, group_id: str, cutoff_ms: int) -> int:
        """删除过期旧 epochs。判断逻辑：有 expires_at 就用 expires_at，否则用 updated_at。"""
        def _do():
            conn = self._get_conn()
            cur = conn.execute(
                "DELETE FROM group_old_epochs WHERE group_id = ? "
                "AND (CASE WHEN expires_at IS NOT NULL THEN expires_at ELSE updated_at END) < ?",
                (group_id, cutoff_ms),
            )
            conn.commit()
            return cur.rowcount
        return self._retry_on_locked(_do)

    # ── E2EE Sessions ────────────────────────────────────────

    def save_session(self, session_id: str, data: dict[str, Any]) -> None:
        def _do():
            conn = self._get_conn()
            now = _now_ms()
            data_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            conn.execute(
                "INSERT INTO e2ee_sessions (session_id, data, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
                (session_id, data_json, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

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

    def delete_session(self, session_id: str) -> None:
        def _do():
            conn = self._get_conn()
            conn.execute("DELETE FROM e2ee_sessions WHERE session_id = ?", (session_id,))
            conn.commit()
        self._retry_on_locked(_do)

    # ── Instance State ───────────────────────────────────────

    def save_instance_state(
        self, device_id: str, slot_id: str, state: dict[str, Any]
    ) -> None:
        def _do():
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
        self._retry_on_locked(_do)

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

    # ── Seq Tracker ─────────────────────────────────────────

    def save_seq(self, device_id: str, slot_id: str, namespace: str, contiguous_seq: int) -> None:
        def _do():
            conn = self._get_conn()
            now = _now_ms()
            slot = slot_id or "_singleton"
            conn.execute(
                "INSERT INTO seq_tracker (device_id, slot_id, namespace, contiguous_seq, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(device_id, slot_id, namespace) "
                "DO UPDATE SET contiguous_seq = excluded.contiguous_seq, updated_at = excluded.updated_at",
                (device_id, slot, namespace, contiguous_seq, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_seq(self, device_id: str, slot_id: str, namespace: str) -> int:
        conn = self._get_conn()
        slot = slot_id or "_singleton"
        cur = conn.execute(
            "SELECT contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?",
            (device_id, slot, namespace),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def load_all_seqs(self, device_id: str, slot_id: str) -> dict[str, int]:
        conn = self._get_conn()
        slot = slot_id or "_singleton"
        cur = conn.execute(
            "SELECT namespace, contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ?",
            (device_id, slot),
        )
        return {row[0]: int(row[1]) for row in cur.fetchall()}

    # ── Metadata KV ──────────────────────────────────────────

    def get_metadata(self, key: str) -> str | None:
        conn = self._get_conn()
        cur = conn.execute("SELECT value FROM metadata_kv WHERE key = ?", (key,))
        row = cur.fetchone()
        return str(row[0]) if row else None

    def set_metadata(self, key: str, value: str) -> None:
        def _do():
            conn = self._get_conn()
            now = _now_ms()
            conn.execute(
                "INSERT INTO metadata_kv (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, value, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def delete_metadata(self, key: str) -> None:
        def _do():
            conn = self._get_conn()
            conn.execute("DELETE FROM metadata_kv WHERE key = ?", (key,))
            conn.commit()
        self._retry_on_locked(_do)

    def get_all_metadata(self) -> dict[str, str]:
        conn = self._get_conn()
        cur = conn.execute("SELECT key, value FROM metadata_kv")
        return {row[0]: row[1] for row in cur.fetchall()}


# ── 工具函数 ─────────────────────────────────────────────────


def _now_ms() -> int:
    return int(time.time() * 1000)
