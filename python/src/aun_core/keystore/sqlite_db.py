"""Per-AID SQLite3 数据库 — prekeys/tokens/groups/sessions/instance_state 的单一存储源。

零共享代码依赖：仅依赖 Python 标准库 sqlite3。
"""

from __future__ import annotations

import gc
import base64
import hashlib
import hmac
import json
import logging
import os
import sqlite3 as _sqlite_mod
import sys
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_log = logging.getLogger("aun_core.keystore")

_SCHEMA_VERSION = 1
_BUSY_TIMEOUT_MS = 5000


# ── Seed 管理 ─────────────────────────────────────────────────


def derive_sqlite_key(seed_bytes: bytes) -> bytes:
    """保留旧调用点的 seed 传递语义；SQLite3 不再使用数据库加密密钥。"""
    return seed_bytes


def _derive_master_key(seed_bytes: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", seed_bytes, b"aun_file_secret_store_v1", 100_000)


def _derive_field_key(master_key: bytes, scope: str, name: str) -> bytes:
    if ":" in scope or ":" in name:
        raise ValueError(f"scope/name 不能包含 ':'（scope={scope!r}, name={name!r}）")
    msg = f"aun:{scope}:{name}\x01".encode("utf-8")
    return hmac.new(master_key, msg, hashlib.sha256).digest()


def _decode_secret_part(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return bytes.fromhex(value)


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
        private_key_enc TEXT NOT NULL DEFAULT '',
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
        secret_enc TEXT NOT NULL DEFAULT '',
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS group_old_epochs (
        group_id TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        secret_enc TEXT NOT NULL DEFAULT '',
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        PRIMARY KEY (group_id, epoch)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_group_old_expires ON group_old_epochs (group_id, expires_at)",
    """CREATE TABLE IF NOT EXISTS e2ee_sessions (
        session_id TEXT PRIMARY KEY,
        data_enc TEXT NOT NULL DEFAULT '{}',
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
    """单个 AID 的 SQLite3 数据库。

    持有一个持久连接，优先使用 WAL；若当前文件系统对默认锁模式返回
    disk I/O error，则自动回退到 EXCLUSIVE + DELETE 模式。
    线程安全由外部 RLock 保证。
    """

    def __init__(self, db_path: Path, sqlite_key: bytes | str | None = None) -> None:
        self._db_path = db_path
        if isinstance(sqlite_key, str):
            self._seed_bytes = sqlite_key.encode("utf-8")
        else:
            self._seed_bytes = sqlite_key or b""
        self._scope = db_path.parent.name
        self._conn: Any | None = None
        self._lock = threading.RLock()
        self._use_exclusive_locking = False
        # 缓存 PBKDF2 派生的 master_key，避免每次加解密都重复 100K 次迭代
        self._master_key: bytes | None = None

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
                _log.warning("已备份数据库文件: %s → %s", p, bak)
            except OSError as exc:
                _log.warning("备份数据库文件失败: %s — %s", p, exc)
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
                        _log.debug("关闭失败连接时出错: %s", close_exc)
                if is_malformed and attempt < self._MAX_CONNECT_RETRIES:
                    _log.warning(
                        "数据库文件损坏 (attempt %d/%d)，备份后重建: %s — %s",
                        attempt, self._MAX_CONNECT_RETRIES, self._db_path, exc,
                    )
                    try:
                        backup_ok = self._backup_broken_files()
                        if backup_ok:
                            self._cleanup_broken_files()
                        else:
                            _log.warning("备份不完整，跳过删除以防数据丢失: %s", self._db_path)
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
                _log.debug("关闭失败连接时出错: %s", close_exc)
            del conn
            gc.collect()
            raise

    def _init_schema(self, conn: Any) -> None:
        for ddl in _DDL_STATEMENTS:
            conn.execute(ddl)
        self._migrate_legacy_columns(conn)
        # 初始化 schema version
        cur = conn.execute("SELECT version FROM _schema_version WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO _schema_version (id, version) VALUES (1, ?)",
                (_SCHEMA_VERSION,),
            )
        conn.commit()

    def _migrate_legacy_columns(self, conn: Any) -> None:
        self._rename_column_if_exists(conn, "prekeys", "private_key_pem", "private_key_enc")
        self._rename_column_if_exists(conn, "group_current", "secret", "secret_enc")
        self._rename_column_if_exists(conn, "group_old_epochs", "secret", "secret_enc")
        self._rename_column_if_exists(conn, "e2ee_sessions", "data", "data_enc")

    @staticmethod
    def _rename_column_if_exists(conn: Any, table: str, old_name: str, new_name: str) -> None:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        columns = {str(row[1]) for row in rows}
        if old_name in columns and new_name not in columns:
            conn.execute(f"ALTER TABLE {table} RENAME COLUMN {old_name} TO {new_name}")

    def _get_master_key(self) -> bytes:
        """获取缓存的 master_key，避免每次都重复 100K 次 PBKDF2 迭代。"""
        if self._master_key is None:
            self._master_key = _derive_master_key(self._seed_bytes)
        return self._master_key

    def _protect_text(self, name: str, plaintext: str) -> str:
        if not self._seed_bytes or not plaintext:
            return plaintext
        try:
            master_key = self._get_master_key()
            field_key = _derive_field_key(master_key, self._scope, name)
            nonce = os.urandom(12)
            sealed = AESGCM(field_key).encrypt(nonce, plaintext.encode("utf-8"), None)
            record = {
                "scheme": "file_aes",
                "name": name,
                "persisted": True,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(sealed[:-16]).decode("ascii"),
                "tag": base64.b64encode(sealed[-16:]).decode("ascii"),
            }
            return json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        except Exception as exc:
            _log.warning("字段加密失败 (scope=%s, name=%s)，降级明文存储: %s", self._scope, name, exc)
            return plaintext

    def _reveal_text(self, name: str, stored: str) -> str:
        if not stored or not self._seed_bytes:
            return stored
        try:
            record = json.loads(stored)
        except (json.JSONDecodeError, TypeError):
            return stored
        if not isinstance(record, dict) or record.get("scheme") != "file_aes":
            return stored
        if str(record.get("name") or "") != name:
            return stored
        try:
            master_key = self._get_master_key()
            field_key = _derive_field_key(master_key, self._scope, name)
            nonce = _decode_secret_part(str(record.get("nonce") or ""))
            ciphertext = _decode_secret_part(str(record.get("ciphertext") or ""))
            tag = _decode_secret_part(str(record.get("tag") or ""))
            return AESGCM(field_key).decrypt(nonce, ciphertext + tag, None).decode("utf-8")
        except Exception as exc:
            _log.warning("字段解密失败 (scope=%s, name=%s): %s", self._scope, name, exc)
            return stored

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
                        except Exception as close_exc:
                            _log.debug("关闭失败连接时出错: %s", close_exc)
                    self._conn = None  # 清除连接，下次 _get_conn 重建
                    try:
                        backup_ok = self._backup_broken_files()
                        if backup_ok:
                            self._cleanup_broken_files()
                        else:
                            _log.warning("备份不完整，跳过删除以防数据丢失: %s", self._db_path)
                    except OSError as rm_err:
                        _log.warning("备份/删除损坏数据库文件失败: %s", rm_err)
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
            stored_key = self._protect_text(f"prekey/{prekey_id}", private_key_pem)
            conn.execute(
                "INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(prekey_id, device_id) DO UPDATE SET "
                "private_key_enc = excluded.private_key_enc, data = excluded.data, "
                "updated_at = excluded.updated_at, expires_at = excluded.expires_at",
                (prekey_id, device_id, stored_key, data_json, created_at or now, now, expires_at),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_prekeys(self, device_id: str = "") -> dict[str, dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at "
            "FROM prekeys WHERE device_id = ?",
            (device_id,),
        )
        result: dict[str, dict[str, Any]] = {}
        for row in cur.fetchall():
            prekey_id = str(row[0])
            entry: dict[str, Any] = {
                "private_key_pem": self._reveal_text(f"prekey/{prekey_id}", str(row[1] or "")),
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
            result[prekey_id] = entry
        return result

    def load_prekey_by_id(self, prekey_id: str) -> dict[str, Any] | None:
        """按 prekey_id 精确查找，不限 device_id（用于解密回退）。"""
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at "
            "FROM prekeys WHERE prekey_id = ? LIMIT 1",
            (prekey_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        entry: dict[str, Any] = {
            "private_key_pem": self._reveal_text(f"prekey/{prekey_id}", str(row[1] or "")),
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
            stored_secret = self._protect_text(f"group/{group_id}/current", secret)
            conn.execute(
                "INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(group_id) DO UPDATE SET "
                "epoch = excluded.epoch, secret_enc = excluded.secret_enc, "
                "data = excluded.data, updated_at = excluded.updated_at",
                (group_id, epoch, stored_secret, data_json, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_group_current(self, group_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?",
            (group_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "group_id": group_id,
            "epoch": row[0],
            "secret": self._reveal_text(f"group/{group_id}/current", str(row[1] or "")),
            **json.loads(row[2]),
            "updated_at": row[3],
        }

    def load_all_group_current(self) -> dict[str, dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute("SELECT group_id, epoch, secret_enc, data, updated_at FROM group_current")
        result: dict[str, dict[str, Any]] = {}
        for row in cur.fetchall():
            group_id = str(row[0])
            result[row[0]] = {
                "group_id": group_id,
                "epoch": row[1],
                "secret": self._reveal_text(f"group/{group_id}/current", str(row[2] or "")),
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
            stored_secret = self._protect_text(f"group/{group_id}/epoch/{epoch}", secret)
            conn.execute(
                "INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(group_id, epoch) DO UPDATE SET "
                "secret_enc = excluded.secret_enc, data = excluded.data, "
                "updated_at = excluded.updated_at, expires_at = excluded.expires_at",
                (group_id, epoch, stored_secret, data_json, now, expires_at),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_group_old_epochs(self, group_id: str) -> list[dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT epoch, secret_enc, data, updated_at, expires_at "
            "FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC",
            (group_id,),
        )
        result = []
        for row in cur.fetchall():
            result.append({
                "epoch": row[0],
                "secret": self._reveal_text(f"group/{group_id}/epoch/{row[0]}", str(row[1] or "")),
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
            stored_data = self._protect_text(f"session/{session_id}", data_json)
            conn.execute(
                "INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(session_id) DO UPDATE SET data_enc = excluded.data_enc, updated_at = excluded.updated_at",
                (session_id, stored_data, now),
            )
            conn.commit()
        self._retry_on_locked(_do)

    def load_session(self, session_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT data_enc, updated_at FROM e2ee_sessions WHERE session_id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        data_json = self._reveal_text(f"session/{session_id}", str(row[0] or "{}"))
        return {**json.loads(data_json), "session_id": session_id, "updated_at": row[1]}

    def load_all_sessions(self) -> list[dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.execute("SELECT session_id, data_enc, updated_at FROM e2ee_sessions")
        result: list[dict[str, Any]] = []
        for row in cur.fetchall():
            session_id = str(row[0])
            data_json = self._reveal_text(f"session/{session_id}", str(row[1] or "{}"))
            result.append({**json.loads(data_json), "session_id": session_id, "updated_at": row[2]})
        return result

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
