"""SQLite 状态层。

当前职责分两部分：
1. 兼容旧实现，继续保存 key_pair / cert / metadata blob 等冗余备份。
2. 对 prekeys / group secrets 提供结构化主存，避免整块 metadata JSON 的读改写竞态。
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

_log = logging.getLogger("aun_core.sqlite_backup")

_BUSY_ERROR_MARKERS = (
    "database is locked",
    "database table is locked",
    "database schema is locked",
    "database is busy",
)
_PREKEY_MIN_KEEP_COUNT = 7


def _prekey_created_marker(
    created_at: Any,
    updated_at: Any,
    expires_at: Any,
) -> int:
    for marker in (created_at, updated_at, expires_at):
        if isinstance(marker, (int, float)):
            return int(marker)
    return 0


class SQLiteBackup:
    """私密数据的 SQLite 状态层。"""

    _SCHEMA_VERSION = 2
    _BUSY_TIMEOUT_MS = 5000
    _MAX_BUSY_RETRIES = 4

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            db_dir = Path.cwd() / ".aun_backup"
        else:
            db_dir = db_path.parent
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
            self._db_path = db_dir / "aun_backup.db" if db_path is None else db_path
            self._init_tables()
            self._available = True
        except Exception as exc:
            _log.warning("SQLite 状态层初始化失败，降级为无 SQLite 模式: %s", exc)
            self._db_path = None
            self._available = False

    def close(self) -> None:
        if not self._available or self._db_path is None:
            return
        try:
            conn = sqlite3.connect(self._db_path)
            conn.close()
        except Exception:
            pass

    # ── seed 备份 ────────────────────────────────────────────

    def backup_seed(self, seed: bytes) -> None:
        self._exec(
            "INSERT OR REPLACE INTO seed_backup (id, seed, updated_at) VALUES (1, ?, ?)",
            (seed, _now()),
        )

    def restore_seed(self) -> bytes | None:
        row = self._query_one("SELECT seed FROM seed_backup WHERE id = 1")
        return row[0] if row else None

    # ── device_id 备份 ───────────────────────────────────────

    def backup_device_id(self, device_id: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO device_id_backup (id, device_id, updated_at) VALUES (1, ?, ?)",
            (device_id, _now()),
        )

    def restore_device_id(self) -> str | None:
        row = self._query_one("SELECT device_id FROM device_id_backup WHERE id = 1")
        return row[0] if row else None

    # ── key_pair / cert / metadata blob 兼容备份 ─────────────

    def backup_key_pair(self, aid: str, data: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO key_pairs (aid, data, updated_at) VALUES (?, ?, ?)",
            (aid, data, _now()),
        )

    def restore_key_pair(self, aid: str) -> str | None:
        row = self._query_one("SELECT data FROM key_pairs WHERE aid = ?", (aid,))
        return row[0] if row else None

    def backup_cert(self, aid: str, cert_pem: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO certs (aid, cert_pem, updated_at) VALUES (?, ?, ?)",
            (aid, cert_pem, _now()),
        )

    def restore_cert(self, aid: str) -> str | None:
        row = self._query_one("SELECT cert_pem FROM certs WHERE aid = ?", (aid,))
        return row[0] if row else None

    def backup_metadata(self, aid: str, data: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO metadata (aid, data, updated_at) VALUES (?, ?, ?)",
            (aid, data, _now()),
        )

    def restore_metadata(self, aid: str) -> str | None:
        row = self._query_one("SELECT data FROM metadata WHERE aid = ?", (aid,))
        return row[0] if row else None

    # ── prekeys 结构化主存 ──────────────────────────────────

    def load_prekeys(self, aid: str) -> dict[str, dict[str, Any]]:
        rows = self._query_all(
            """
            SELECT prekey_id, data
            FROM prekeys
            WHERE aid = ?
            ORDER BY created_at ASC, prekey_id ASC
            """,
            (aid,),
        )
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                payload = json.loads(row[1])
            except Exception:
                continue
            if isinstance(payload, dict):
                result[str(row[0])] = payload
        return result

    def replace_prekeys(self, aid: str, prekeys: dict[str, dict[str, Any]]) -> None:
        if not self._available:
            return

        def _replace(conn: sqlite3.Connection) -> None:
            for prekey_id, data in prekeys.items():
                created_at = _int_or_none(data.get("created_at"))
                updated_at = _int_or_default(data.get("updated_at"), created_at or _now())
                expires_at = _int_or_none(data.get("expires_at"))
                deleted_at = _int_or_none(data.get("deleted_at"))
                conn.execute(
                    """
                    INSERT OR REPLACE INTO prekeys
                      (aid, prekey_id, data, created_at, updated_at, expires_at, deleted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        aid,
                        prekey_id,
                        json.dumps(data, ensure_ascii=False),
                        created_at,
                        updated_at,
                        expires_at,
                        deleted_at,
                    ),
                )

        self._transaction(_replace, "replace_prekeys")

    def upsert_prekey(self, aid: str, prekey_id: str, data: dict[str, Any]) -> None:
        self._exec(
            """
            INSERT OR REPLACE INTO prekeys
              (aid, prekey_id, data, created_at, updated_at, expires_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                aid,
                prekey_id,
                json.dumps(data, ensure_ascii=False),
                _int_or_none(data.get("created_at")),
                _int_or_default(data.get("updated_at"), _int_or_default(data.get("created_at"), _now())),
                _int_or_none(data.get("expires_at")),
                _int_or_none(data.get("deleted_at")),
            ),
        )

    def cleanup_prekeys_before(
        self,
        aid: str,
        cutoff_ms: int,
        keep_latest: int = _PREKEY_MIN_KEEP_COUNT,
    ) -> list[str]:
        rows = self._query_all(
            """
            SELECT prekey_id, created_at, updated_at, expires_at
            FROM prekeys
            WHERE aid = ?
            """,
            (aid,),
        )
        markers: dict[str, int] = {}
        for row in rows:
            prekey_id = str(row[0])
            markers[prekey_id] = _prekey_created_marker(row[1], row[2], row[3])
        if keep_latest > 0:
            ordered = sorted(markers.items(), key=lambda item: (item[1], item[0]), reverse=True)
            retained_ids = {prekey_id for prekey_id, _marker in ordered[:keep_latest]}
        else:
            retained_ids = set()
        prekey_ids = [
            prekey_id
            for prekey_id, marker in markers.items()
            if marker < cutoff_ms and prekey_id not in retained_ids
        ]
        if not prekey_ids:
            return []

        def _cleanup(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "DELETE FROM prekeys WHERE aid = ? AND prekey_id = ?",
                [(aid, pid) for pid in prekey_ids],
            )

        self._transaction(_cleanup, "cleanup_prekeys")
        return prekey_ids

    # ── group secrets 结构化主存 ────────────────────────────

    def load_group_entry(self, aid: str, group_id: str) -> dict[str, Any] | None:
        current_row = self._query_one(
            """
            SELECT data
            FROM group_current
            WHERE aid = ? AND group_id = ?
            """,
            (aid, group_id),
        )
        old_rows = self._query_all(
            """
            SELECT data
            FROM group_old_epochs
            WHERE aid = ? AND group_id = ?
            ORDER BY epoch ASC
            """,
            (aid, group_id),
        )

        if current_row is None and not old_rows:
            return None

        entry: dict[str, Any] = {}
        if current_row is not None:
            try:
                raw = json.loads(current_row[0])
                if isinstance(raw, dict):
                    entry = raw
            except Exception:
                entry = {}
        old_epochs: list[dict[str, Any]] = []
        for row in old_rows:
            try:
                payload = json.loads(row[0])
            except Exception:
                continue
            if isinstance(payload, dict):
                old_epochs.append(payload)
        if old_epochs:
            entry = dict(entry)
            entry["old_epochs"] = old_epochs
        return entry or None

    def load_group_entries(self, aid: str) -> dict[str, dict[str, Any]]:
        groups: dict[str, dict[str, Any]] = {}
        current_rows = self._query_all(
            """
            SELECT group_id, data
            FROM group_current
            WHERE aid = ?
            ORDER BY group_id ASC
            """,
            (aid,),
        )
        for row in current_rows:
            try:
                payload = json.loads(row[1])
            except Exception:
                continue
            if isinstance(payload, dict):
                groups[str(row[0])] = payload

        old_rows = self._query_all(
            """
            SELECT group_id, data
            FROM group_old_epochs
            WHERE aid = ?
            ORDER BY group_id ASC, epoch ASC
            """,
            (aid,),
        )
        for row in old_rows:
            try:
                payload = json.loads(row[1])
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            group_id = str(row[0])
            entry = groups.setdefault(group_id, {})
            old_epochs = entry.setdefault("old_epochs", [])
            if isinstance(old_epochs, list):
                old_epochs.append(payload)
        return groups

    def save_group_entry(self, aid: str, group_id: str, entry: dict[str, Any]) -> None:
        if not self._available:
            return
        current_entry = dict(entry)
        old_epochs = current_entry.pop("old_epochs", [])
        if not isinstance(old_epochs, list):
            old_epochs = []
        epoch = _int_or_none(current_entry.get("epoch"))
        updated_at = _int_or_default(current_entry.get("updated_at"), _now())

        def _save(conn: sqlite3.Connection) -> None:
            if epoch is not None:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO group_current
                      (aid, group_id, epoch, data, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        aid,
                        group_id,
                        epoch,
                        json.dumps(current_entry, ensure_ascii=False),
                        updated_at,
                    ),
                )

            for old in old_epochs:
                if not isinstance(old, dict):
                    continue
                old_epoch = _int_or_none(old.get("epoch"))
                if old_epoch is None:
                    continue
                conn.execute(
                    """
                    INSERT OR REPLACE INTO group_old_epochs
                      (aid, group_id, epoch, data, updated_at, expires_at, deleted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        aid,
                        group_id,
                        old_epoch,
                        json.dumps(old, ensure_ascii=False),
                        _int_or_default(old.get("updated_at"), updated_at),
                        _int_or_none(old.get("expires_at")),
                        _int_or_none(old.get("deleted_at")),
                    ),
                )

        self._transaction(_save, "save_group_entry")

    def replace_group_entries(self, aid: str, entries: dict[str, dict[str, Any]]) -> None:
        if not self._available:
            return

        def _replace(conn: sqlite3.Connection) -> None:
            for group_id, entry in entries.items():
                current_entry = dict(entry)
                old_epochs = current_entry.pop("old_epochs", [])
                if not isinstance(old_epochs, list):
                    old_epochs = []
                epoch = _int_or_none(current_entry.get("epoch"))
                updated_at = _int_or_default(current_entry.get("updated_at"), _now())
                if epoch is not None:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO group_current
                          (aid, group_id, epoch, data, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            aid,
                            group_id,
                            epoch,
                            json.dumps(current_entry, ensure_ascii=False),
                            updated_at,
                        ),
                    )
                for old in old_epochs:
                    if not isinstance(old, dict):
                        continue
                    old_epoch = _int_or_none(old.get("epoch"))
                    if old_epoch is None:
                        continue
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO group_old_epochs
                          (aid, group_id, epoch, data, updated_at, expires_at, deleted_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            aid,
                            group_id,
                            old_epoch,
                            json.dumps(old, ensure_ascii=False),
                            _int_or_default(old.get("updated_at"), updated_at),
                            _int_or_none(old.get("expires_at")),
                            _int_or_none(old.get("deleted_at")),
                        ),
                    )

        self._transaction(_replace, "replace_group_entries")

    def cleanup_group_old_epochs(self, aid: str, group_id: str, cutoff_ms: int) -> list[int]:
        rows = self._query_all(
            """
            SELECT epoch
            FROM group_old_epochs
            WHERE aid = ?
              AND group_id = ?
              AND COALESCE(NULLIF(updated_at, 0), expires_at, 0) < ?
            """,
            (aid, group_id, cutoff_ms),
        )
        epochs = [int(row[0]) for row in rows]
        if not epochs:
            return []

        def _cleanup(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "DELETE FROM group_old_epochs WHERE aid = ? AND group_id = ? AND epoch = ?",
                [(aid, group_id, epoch) for epoch in epochs],
            )

        self._transaction(_cleanup, "cleanup_group_old_epochs")
        return epochs

    # ── 内部方法 ─────────────────────────────────────────────

    def _init_tables(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS _schema_version (
                    id INTEGER PRIMARY KEY,
                    version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seed_backup (
                    id INTEGER PRIMARY KEY,
                    seed BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_id_backup (
                    id INTEGER PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS key_pairs (
                    aid TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS certs (
                    aid TEXT PRIMARY KEY,
                    cert_pem TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata (
                    aid TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS prekeys (
                    aid TEXT NOT NULL,
                    prekey_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at INTEGER,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    deleted_at INTEGER,
                    PRIMARY KEY (aid, prekey_id)
                );
                CREATE TABLE IF NOT EXISTS group_current (
                    aid TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (aid, group_id)
                );
                CREATE TABLE IF NOT EXISTS group_old_epochs (
                    aid TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    deleted_at INTEGER,
                    PRIMARY KEY (aid, group_id, epoch)
                );
                CREATE INDEX IF NOT EXISTS idx_prekeys_aid_expires
                    ON prekeys (aid, expires_at, created_at, updated_at);
                CREATE INDEX IF NOT EXISTS idx_group_old_epochs_aid_group_expires
                    ON group_old_epochs (aid, group_id, expires_at, updated_at);
            """)
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT version FROM _schema_version WHERE id = 1").fetchone()
        current = row[0] if row else 0

        if current < 2:
            conn.execute(
                "INSERT OR REPLACE INTO _schema_version (id, version) VALUES (1, ?)",
                (self._SCHEMA_VERSION,),
            )
        elif current != self._SCHEMA_VERSION:
            conn.execute(
                "INSERT OR REPLACE INTO _schema_version (id, version) VALUES (1, ?)",
                (self._SCHEMA_VERSION,),
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=self._BUSY_TIMEOUT_MS / 1000)
        conn.execute(f"PRAGMA busy_timeout = {self._BUSY_TIMEOUT_MS}")
        return conn

    def _exec(self, sql: str, params: tuple = ()) -> None:
        if not self._available:
            return
        try:
            self._run_with_retry(
                lambda: self._execute(sql, params),
                action="write",
            )
        except Exception as exc:
            _log.warning("SQLite 写入失败: %s", exc)

    def _query_one(self, sql: str, params: tuple = ()) -> tuple | None:
        if not self._available:
            return None
        try:
            return self._run_with_retry(
                lambda: self._execute_fetchone(sql, params),
                action="read",
            )
        except Exception as exc:
            _log.warning("SQLite 读取失败: %s", exc)
            return None

    def _query_all(self, sql: str, params: tuple = ()) -> list[tuple]:
        if not self._available:
            return []
        try:
            rows = self._run_with_retry(
                lambda: self._execute_fetchall(sql, params),
                action="read",
            )
            return rows or []
        except Exception as exc:
            _log.warning("SQLite 读取失败: %s", exc)
            return []

    def _transaction(self, fn: Callable[[sqlite3.Connection], None], action: str) -> None:
        if not self._available:
            return
        try:
            self._run_with_retry(lambda: self._run_transaction(fn), action=action)
        except Exception as exc:
            _log.warning("SQLite 事务失败 (%s): %s", action, exc)

    def _run_transaction(self, fn: Callable[[sqlite3.Connection], None]) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                fn(conn)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def _execute(self, sql: str, params: tuple) -> None:
        with self._connect() as conn:
            conn.execute(sql, params)

    def _execute_fetchone(self, sql: str, params: tuple) -> tuple | None:
        with self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
            return tuple(row) if row else None

    def _execute_fetchall(self, sql: str, params: tuple) -> list[tuple]:
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [tuple(row) for row in rows]

    def _run_with_retry(self, fn: Callable[[], Any], *, action: str) -> Any:
        for attempt in range(self._MAX_BUSY_RETRIES + 1):
            try:
                return fn()
            except sqlite3.OperationalError as exc:
                if not self._is_busy_error(exc) or attempt >= self._MAX_BUSY_RETRIES:
                    raise
                delay = 0.02 * (2 ** attempt)
                _log.debug("SQLite %s 遇到 busy，%.0fms 后重试", action, delay * 1000)
                time.sleep(delay)

    @staticmethod
    def _is_busy_error(exc: sqlite3.OperationalError) -> bool:
        text = str(exc).lower()
        return any(marker in text for marker in _BUSY_ERROR_MARKERS)


def _now() -> int:
    return int(time.time() * 1000)


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    return None


def _int_or_default(value: Any, default: int) -> int:
    parsed = _int_or_none(value)
    return default if parsed is None else parsed
