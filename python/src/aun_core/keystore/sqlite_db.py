"""Per-AID SQLite3 数据库 — tokens/group_state/instance_state/v2_device_keys 的单一存储源。

零共享代码依赖：仅依赖 Python 标准库 sqlite3。
"""

from __future__ import annotations

import gc
import json
import os
import sqlite3 as _sqlite_mod
import sys
import threading
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from ..group_id import convert_to_group_aid

if TYPE_CHECKING:
    from ..logger import AUNLogger, NullLogger

_SCHEMA_VERSION = 3
_BUSY_TIMEOUT_MS = 5000


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
    """CREATE TABLE IF NOT EXISTS group_state (
        group_id TEXT PRIMARY KEY,
        state_version INTEGER NOT NULL DEFAULT 0,
        state_hash TEXT NOT NULL DEFAULT '',
        key_epoch INTEGER NOT NULL DEFAULT 0,
        membership_json TEXT NOT NULL DEFAULT '',
        policy_json TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS instance_state (
        device_id TEXT NOT NULL,
        slot_id TEXT NOT NULL DEFAULT '_singleton',
        slot_id_full TEXT NOT NULL DEFAULT '',
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, slot_id)
    )""",
    """CREATE TABLE IF NOT EXISTS seq_tracker (
        device_id TEXT NOT NULL,
        slot_id TEXT NOT NULL DEFAULT '_singleton',
        slot_id_full TEXT NOT NULL DEFAULT '',
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
    """CREATE TABLE IF NOT EXISTS v2_device_keys (
        device_id TEXT NOT NULL,
        key_type TEXT NOT NULL,
        group_id TEXT NOT NULL DEFAULT '',
        key_id TEXT NOT NULL DEFAULT '',
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, key_type, group_id, key_id)
    )""",
]


# ── AIDDatabase ──────────────────────────────────────────────


class AIDDatabase:
    """单个 AID 的 SQLite3 数据库。

    持有一个持久连接，优先使用 WAL；若当前文件系统对默认锁模式返回
    disk I/O error，则自动回退到 EXCLUSIVE + DELETE 模式。
    线程安全由外部 RLock 保证。
    """

    def __init__(self, db_path: Path, logger=None) -> None:
        from ..logger import NullLogger as _NL
        self._log = logger or _NL()
        self._db_path = db_path
        self._scope = db_path.parent.name
        self._conn: Any | None = None
        self._lock = threading.RLock()
        self._use_exclusive_locking = False

    _MAX_CONNECT_RETRIES = 3
    _RETRY_DELAY_S = 0.1

    @staticmethod
    def _is_recoverable_db_error(err_msg: str) -> bool:
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

    @staticmethod
    def _group_lookup_candidates(group_id: str, *, local_issuer: str = "") -> list[str]:
        raw = str(group_id or "").strip()
        if not raw:
            return []
        normalized = convert_to_group_aid(raw, local_issuer=local_issuer)
        candidates: list[str] = []

        def add(value: str) -> None:
            value = str(value or "").strip()
            if value and value not in candidates:
                candidates.append(value)

        add(raw)
        add(normalized)
        if "." in normalized:
            base, _, issuer = normalized.partition(".")
            if base and issuer:
                add(f"group.{issuer}/{base}")
                add(f"{base}@{issuer}")
                if local_issuer and issuer == str(local_issuer).strip().strip(".").lower():
                    add(base)
        return candidates

    @staticmethod
    def _group_aid_from_candidate(group_id: str, *, local_issuer: str = "") -> str:
        return convert_to_group_aid(group_id, local_issuer=local_issuer)

    @staticmethod
    def _canonical_group_key(group_id: str, *, local_issuer: str = "") -> str:
        normalized = convert_to_group_aid(group_id, local_issuer=local_issuer)
        return normalized or str(group_id or "").strip()

    def _backup_broken_files(self, *, tag: str = "corrupt") -> bool:
        """将损坏的数据库文件重命名为 .{tag}_{timestamp}.bak，保留数据以便后续恢复。
        返回 True 表示所有文件备份成功（或无文件需要备份），False 表示有备份失败。"""
        import shutil
        ts = time.strftime("%Y%m%d_%H%M%S")
        all_ok = True
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = Path(str(self._db_path) + suffix)
            if not p.exists():
                continue
            bak = p.with_suffix(f"{p.suffix}.{tag}_{ts}.bak")
            try:
                shutil.copy2(str(p), str(bak))
                self._log.warn("keystore", "database file backed up: %s -> %s", p, bak)
            except OSError as exc:
                self._log.warn("keystore", "database file backup failed: %s - %s", p, exc)
                all_ok = False
        return all_ok

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
            conn: Any | None = None
            try:
                conn = self._open_and_init()
                self._conn = conn
                self._log.debug(
                    "keystore",
                    "AIDDatabase connection ready: path=%s exclusive_locking=%s",
                    self._db_path, self._use_exclusive_locking,
                )
                return conn
            except Exception as exc:
                last_exc = exc
                err_msg = str(exc).lower()
                is_malformed = self._is_recoverable_db_error(err_msg)
                # 尝试关闭已损坏的连接
                if conn is not None:
                    try:
                        conn.close()
                    except Exception as close_exc:
                        self._log.debug("keystore", "error closing failed connection: %s", close_exc)
                if is_malformed and attempt < self._MAX_CONNECT_RETRIES:
                    self._log.warn("keystore",
                        "database file corrupted (attempt %d/%d), backup and rebuild: %s — %s",
                        attempt, self._MAX_CONNECT_RETRIES, self._db_path, exc,
                    )
                    try:
                        backup_ok = self._backup_broken_files()
                        if backup_ok:
                            self._cleanup_broken_files()
                        else:
                            self._log.warn("keystore", "backup incomplete, skipping delete to prevent data loss: %s", self._db_path)
                    except OSError as rm_err:
                        self._log.warn("keystore", "failed to delete corrupted database file: %s", rm_err)
                    continue
                if "database is locked" in err_msg and attempt < self._MAX_CONNECT_RETRIES:
                    self._log.warn("keystore",
                        "database locked (attempt %d/%d), retrying in %ss: %s",
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
                self._log.warn("keystore",
                    "database init hit disk I/O error, switching to EXCLUSIVE locking fallback: %s",
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
            except Exception as close_exc:
                self._log.debug("keystore", "error closing failed connection: %s", close_exc)
            del conn
            gc.collect()
            raise

    def _init_schema(self, conn: Any) -> None:
        for ddl in _DDL_STATEMENTS:
            conn.execute(ddl)
        self._migrate_legacy_columns(conn)
        # 初始化或迁移 schema version
        cur = conn.execute("SELECT version FROM _schema_version WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO _schema_version (id, version) VALUES (1, ?)",
                (_SCHEMA_VERSION,),
            )
        else:
            ver = int(row[0])
            if ver < _SCHEMA_VERSION:
                self._migrate_schema(conn, ver, _SCHEMA_VERSION)
                conn.execute("UPDATE _schema_version SET version = ? WHERE id = 1", (_SCHEMA_VERSION,))
        conn.commit()

    @staticmethod
    def _migrate_schema(conn: Any, from_ver: int, to_ver: int) -> None:
        for v in range(from_ver, to_ver):
            if v == 1:
                # v1 → v2：instance_state / seq_tracker 加 slot_id_full 列
                AIDDatabase._add_column_if_missing(conn, "instance_state", "slot_id_full", "TEXT NOT NULL DEFAULT ''")
                AIDDatabase._add_column_if_missing(conn, "seq_tracker", "slot_id_full", "TEXT NOT NULL DEFAULT ''")
            elif v == 2:
                # v2 → v3：删除废弃的 agent_md_cache 表
                conn.execute("DROP TABLE IF EXISTS agent_md_cache")

    def _migrate_legacy_columns(self, conn: Any) -> None:
        self._add_column_if_missing(conn, "instance_state", "slot_id_full", "TEXT NOT NULL DEFAULT ''")
        self._add_column_if_missing(conn, "seq_tracker", "slot_id_full", "TEXT NOT NULL DEFAULT ''")
        self._migrate_v2_device_keys(conn)

    @staticmethod
    def _migrate_v2_device_keys(conn: Any) -> None:
        rows = conn.execute("PRAGMA table_info(v2_device_keys)").fetchall()
        if not rows:
            return
        columns = {str(row[1]) for row in rows}
        pk_columns = [str(row[1]) for row in sorted((r for r in rows if int(r[5] or 0) > 0), key=lambda r: int(r[5]))]
        if "group_id" in columns and pk_columns == ["device_id", "key_type", "group_id", "key_id"]:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_v2_device_keys_scope_created "
                "ON v2_device_keys(device_id, key_type, group_id, created_at)"
            )
            return

        conn.execute("ALTER TABLE v2_device_keys RENAME TO v2_device_keys_legacy")
        conn.execute(
            """CREATE TABLE v2_device_keys (
                device_id TEXT NOT NULL,
                key_type TEXT NOT NULL,
                group_id TEXT NOT NULL DEFAULT '',
                key_id TEXT NOT NULL DEFAULT '',
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (device_id, key_type, group_id, key_id)
            )"""
        )
        legacy_has_group_id = "group_id" in columns
        select_cols = "device_id, key_type, group_id, key_id, private_key, public_key, created_at" if legacy_has_group_id else "device_id, key_type, '' AS group_id, key_id, private_key, public_key, created_at"
        legacy_rows = conn.execute(f"SELECT {select_cols} FROM v2_device_keys_legacy").fetchall()

        # Import normalize function
        from ..group_id import normalize_group_id

        for device_id, key_type, group_id, key_id, private_key, public_key, created_at in legacy_rows:
            migrated_group_id = str(group_id or "")
            migrated_key_id = str(key_id or "")
            if key_type in ("group_spk", "group_spk_uploaded") and "\0" in migrated_key_id:
                migrated_group_id, migrated_key_id = migrated_key_id.split("\0", 1)
            # Normalize group_id for consistency with all other operations
            if migrated_group_id and key_type in ("group_spk", "group_spk_uploaded", "group_identity"):
                migrated_group_id = normalize_group_id(migrated_group_id) or str(migrated_group_id or "").strip()
            if private_key is None or public_key is None:
                if key_type not in ("spk_uploaded", "group_spk_uploaded"):
                    continue
                if private_key is None:
                    private_key = b""
                if public_key is None:
                    public_key = b""
            conn.execute(
                "INSERT OR REPLACE INTO v2_device_keys "
                "(device_id, key_type, group_id, key_id, private_key, public_key, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (device_id, key_type, migrated_group_id, migrated_key_id, private_key, public_key, created_at),
            )
        conn.execute("DROP TABLE v2_device_keys_legacy")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_v2_device_keys_scope_created "
            "ON v2_device_keys(device_id, key_type, group_id, created_at)"
        )

    @staticmethod
    def _add_column_if_missing(conn: Any, table: str, column: str, definition: str) -> None:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        columns = {str(row[1]) for row in rows}
        if rows and column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
                self._log.debug("keystore", "AIDDatabase closed: path=%s", self._db_path)

    def _retry_on_locked(self, fn, *args, max_retries: int = 3, delay: float = 0.05):
        """对 database is locked 和 malformed 异常自动重试。"""
        for attempt in range(1, max_retries + 1):
            try:
                return fn(*args)
            except Exception as exc:
                err_msg = str(exc).lower()
                if "database is locked" in err_msg and attempt < max_retries:
                    self._log.debug("keystore", "database locked (attempt %d/%d), retrying", attempt, max_retries)
                    time.sleep(delay * attempt)
                    continue
                if self._is_recoverable_db_error(err_msg) and attempt < max_retries:
                    self._log.warn("keystore", "database corrupted (attempt %d/%d), rebuilding connection", attempt, max_retries)
                    if self._conn is not None:
                        try:
                            self._conn.close()
                        except Exception as close_exc:
                            self._log.debug("keystore", "error closing failed connection: %s", close_exc)
                    self._conn = None  # 清除连接，下次 _get_conn 重建
                    try:
                        backup_ok = self._backup_broken_files()
                        if backup_ok:
                            self._cleanup_broken_files()
                        else:
                            self._log.warn("keystore", "backup incomplete, skipping delete to prevent data loss: %s", self._db_path)
                    except OSError as rm_err:
                        self._log.warn("keystore", "backup/delete corrupted database file failed: %s", rm_err)
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

    # ── Group State (state_hash) ──────────────────────────────

    def save_group_state(
        self, *, group_id: str, state_version: int, state_hash: str,
        key_epoch: int, membership_json: str, policy_json: str,
    ) -> None:
        """保存/更新群组 state_hash 状态"""
        group_id = self._canonical_group_key(group_id)

        def _do():
            conn = self._get_conn()
            now = _now_ms()
            conn.execute(
                "INSERT INTO group_state (group_id, state_version, state_hash, key_epoch, membership_json, policy_json, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(group_id) DO UPDATE SET "
                "state_version=excluded.state_version, state_hash=excluded.state_hash, "
                "key_epoch=excluded.key_epoch, membership_json=excluded.membership_json, "
                "policy_json=excluded.policy_json, updated_at=excluded.updated_at",
                (group_id, state_version, state_hash, key_epoch, membership_json, policy_json, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_group_state(self, group_id: str, *, local_issuer: str = "") -> dict | None:
        """加载群组 state_hash 状态"""
        conn = self._get_conn()
        row = None
        stored_group_id = ""
        for candidate in self._group_lookup_candidates(group_id, local_issuer=local_issuer):
            row = conn.execute(
                "SELECT group_id, state_version, state_hash, key_epoch, membership_json, policy_json, updated_at "
                "FROM group_state WHERE group_id = ?", (candidate,)
            ).fetchone()
            if row:
                stored_group_id = str(row[0])
                break
        if not row:
            return None
        return {
            "group_id": stored_group_id,
            "group_aid": self._group_aid_from_candidate(stored_group_id, local_issuer=local_issuer),
            "state_version": row[1],
            "state_hash": row[2],
            "key_epoch": row[3],
            "membership_json": row[4],
            "policy_json": row[5],
            "updated_at": row[6],
        }

    # ── Instance State ───────────────────────────────────────

    def save_instance_state(
        self, device_id: str, slot_id: str, state: dict[str, Any]
    ) -> None:
        from ..config import slot_isolation_key
        def _do():
            conn = self._get_conn()
            now = _now_ms()
            slot_key = slot_isolation_key(slot_id) if slot_id else "_singleton"
            slot_full = slot_id or ""
            data_json = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
            conn.execute(
                "INSERT INTO instance_state (device_id, slot_id, slot_id_full, data, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(device_id, slot_id) DO UPDATE SET slot_id_full = excluded.slot_id_full, data = excluded.data, updated_at = excluded.updated_at",
                (device_id, slot_key, slot_full, data_json, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_instance_state(
        self, device_id: str, slot_id: str = ""
    ) -> dict[str, Any] | None:
        from ..config import slot_isolation_key
        conn = self._get_conn()
        slot_key = slot_isolation_key(slot_id) if slot_id else "_singleton"
        cur = conn.execute(
            "SELECT data, updated_at FROM instance_state WHERE device_id = ? AND slot_id = ?",
            (device_id, slot_key),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    # ── Seq Tracker ─────────────────────────────────────────

    def save_seq(self, device_id: str, slot_id: str, namespace: str, contiguous_seq: int) -> None:
        self.save_seqs(device_id, slot_id, {namespace: contiguous_seq})

    def save_seqs(self, device_id: str, slot_id: str, seqs: dict[str, int]) -> None:
        if not seqs:
            return
        from ..config import slot_isolation_key
        def _do():
            conn = self._get_conn()
            now = _now_ms()
            slot_key = slot_isolation_key(slot_id) if slot_id else "_singleton"
            slot_full = slot_id or ""
            rows = [
                (device_id, slot_key, slot_full, str(namespace), int(contiguous_seq), now)
                for namespace, contiguous_seq in seqs.items()
            ]
            if not rows:
                return
            conn.executemany(
                "INSERT INTO seq_tracker (device_id, slot_id, slot_id_full, namespace, contiguous_seq, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(device_id, slot_id, namespace) "
                "DO UPDATE SET slot_id_full = excluded.slot_id_full, contiguous_seq = excluded.contiguous_seq, updated_at = excluded.updated_at",
                rows,
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_seq(self, device_id: str, slot_id: str, namespace: str) -> int:
        from ..config import slot_isolation_key
        conn = self._get_conn()
        slot_key = slot_isolation_key(slot_id) if slot_id else "_singleton"
        cur = conn.execute(
            "SELECT contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?",
            (device_id, slot_key, namespace),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def load_all_seqs(self, device_id: str, slot_id: str) -> dict[str, int]:
        from ..config import slot_isolation_key
        conn = self._get_conn()
        slot_key = slot_isolation_key(slot_id) if slot_id else "_singleton"
        cur = conn.execute(
            "SELECT namespace, contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ?",
            (device_id, slot_key),
        )
        return {row[0]: int(row[1]) for row in cur.fetchall()}

    def delete_seq(self, device_id: str, slot_id: str, namespace: str) -> None:
        from ..config import slot_isolation_key
        def _do():
            conn = self._get_conn()
            slot_key = slot_isolation_key(slot_id) if slot_id else "_singleton"
            conn.execute(
                "DELETE FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?",
                (device_id, slot_key, namespace),
            )
            conn.commit()
        self._retry_on_locked(_do)

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
