"""V2 E2EE 设备密钥存储。

每个 (aid, device_id) 持有一对 IK 和若干 SPK（按 spk_id 索引）。
底层复用 AID 的 aun.db（v2_device_keys 表，DDL 在 sqlite_db.py 中定义）。
"""
from __future__ import annotations

import hashlib
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..keystore.sqlite_db import AIDDatabase


class V2KeyStore:
    """V2 E2EE 设备密钥持久化，复用 AIDDatabase 连接。

    key_type: "ik"、"spk" 或 "group_spk"
    key_id: IK 主记录为空字符串；IK fallback alias 使用 sha256:<16hex>，但仍保持 key_type='ik'
    """

    def __init__(self, db: "AIDDatabase"):
        self._db = db
        self._ensure_schema()

    @staticmethod
    def _ik_spk_id(ik_pub_der: bytes) -> str:
        return "sha256:" + hashlib.sha256(ik_pub_der).hexdigest()[:16]

    def _ensure_schema(self) -> None:
        conn = self._db._get_conn()
        conn.execute(
            """CREATE TABLE IF NOT EXISTS v2_device_keys (
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
        rows = conn.execute("PRAGMA table_info(v2_device_keys)").fetchall()
        columns = {str(row[1]) for row in rows}
        pk_columns = [str(row[1]) for row in sorted((r for r in rows if int(r[5] or 0) > 0), key=lambda r: int(r[5]))]
        if "group_id" not in columns or pk_columns != ["device_id", "key_type", "group_id", "key_id"]:
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
            select_cols = (
                "device_id, key_type, group_id, key_id, private_key, public_key, created_at"
                if legacy_has_group_id
                else "device_id, key_type, '' AS group_id, key_id, private_key, public_key, created_at"
            )
            legacy_rows = conn.execute(f"SELECT {select_cols} FROM v2_device_keys_legacy").fetchall()
            for device_id, key_type, group_id, key_id, private_key, public_key, created_at in legacy_rows:
                migrated_group_id = str(group_id or "")
                migrated_key_id = str(key_id or "")
                if key_type in ("group_spk", "group_spk_uploaded") and "\0" in migrated_key_id:
                    migrated_group_id, migrated_key_id = migrated_key_id.split("\0", 1)
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
        conn.commit()

    def save_ik(self, device_id: str, ik_priv: bytes, ik_pub_der: bytes) -> None:
        conn = self._db._get_conn()
        now_ms = int(time.time() * 1000)
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'ik', '', '', ?, ?, ?)",
            (device_id, ik_priv, ik_pub_der, now_ms),
        )
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'ik', '', ?, ?, ?, ?)",
            (device_id, self._ik_spk_id(ik_pub_der), ik_priv, ik_pub_der, now_ms),
        )
        conn.commit()

    def load_ik(self, device_id: str) -> tuple[bytes, bytes] | None:
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT private_key, public_key FROM v2_device_keys WHERE device_id=? AND key_type='ik' AND group_id='' AND key_id=''",
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        return (bytes(row[0]), bytes(row[1]))

    def load_ik_spk(self, device_id: str, spk_id: str) -> tuple[bytes, bytes] | None:
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT private_key, public_key FROM v2_device_keys WHERE device_id=? AND key_type='ik' AND group_id='' AND key_id=?",
            (device_id, spk_id),
        ).fetchone()
        if row is None:
            return None
        return (bytes(row[0]), bytes(row[1]))

    def save_spk(self, device_id: str, spk_id: str, spk_priv: bytes, spk_pub_der: bytes) -> None:
        conn = self._db._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'spk', '', ?, ?, ?, ?)",
            (device_id, spk_id, spk_priv, spk_pub_der, int(time.time() * 1000)),
        )
        conn.commit()

    def load_spk(self, device_id: str, spk_id: str) -> bytes | None:
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT private_key FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND group_id='' AND key_id=?",
            (device_id, spk_id),
        ).fetchone()
        if row is None:
            return None
        return bytes(row[0])

    def save_group_spk(self, device_id: str, group_id: str, spk_id: str, spk_priv: bytes, spk_pub_der: bytes) -> None:
        conn = self._db._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'group_spk', ?, ?, ?, ?, ?)",
            (device_id, group_id, spk_id, spk_priv, spk_pub_der, int(time.time() * 1000)),
        )
        conn.commit()

    def load_group_spk(self, device_id: str, group_id: str, spk_id: str) -> bytes | None:
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT private_key FROM v2_device_keys WHERE device_id=? AND key_type='group_spk' AND group_id=? AND key_id=?",
            (device_id, group_id, spk_id),
        ).fetchone()
        if row is None:
            return None
        return bytes(row[0])

    def load_current_group_spk(self, device_id: str, group_id: str) -> tuple[str, bytes, bytes] | None:
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT key_id, private_key, public_key FROM v2_device_keys "
            "WHERE device_id=? AND key_type='group_spk' AND group_id=? "
            "ORDER BY created_at DESC LIMIT 1",
            (device_id, group_id),
        ).fetchone()
        if row is None:
            return None
        return (str(row[0]), bytes(row[1]), bytes(row[2]))

    def load_current_spk(self, device_id: str) -> tuple[str, bytes, bytes] | None:
        """加载最新的 SPK（按 created_at 降序）。返回 (spk_id, priv, pub) 或 None。"""
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT key_id, private_key, public_key FROM v2_device_keys "
            "WHERE device_id=? AND key_type='spk' AND group_id='' ORDER BY created_at DESC LIMIT 1",
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        return (row[0], bytes(row[1]), bytes(row[2]))

    def delete_spk(self, device_id: str, spk_id: str) -> None:
        """销毁指定 SPK 的私钥（用于 PFS），并清理对应上传成功标记。"""
        conn = self._db._get_conn()
        conn.execute(
            "DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND group_id='' AND key_id=?",
            (device_id, spk_id),
        )
        conn.execute(
            "DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk_uploaded' AND group_id='' AND key_id=?",
            (device_id, spk_id),
        )
        conn.commit()

    def mark_spk_uploaded(self, device_id: str, spk_id: str) -> None:
        """记录指定 P2P SPK 已成功上传到服务端。"""
        conn = self._db._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'spk_uploaded', '', ?, ?, ?, ?)",
            (device_id, spk_id, b"", b"", int(time.time() * 1000)),
        )
        conn.commit()

    def load_latest_uploaded_spk_id(self, device_id: str) -> str | None:
        """返回本设备最近一次上传成功且本地私钥仍存在的 P2P SPK ID。"""
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT marker.key_id FROM v2_device_keys AS marker "
            "WHERE marker.device_id=? AND marker.key_type='spk_uploaded' AND marker.group_id='' "
            "AND EXISTS ("
            "  SELECT 1 FROM v2_device_keys AS key "
            "  WHERE key.device_id=marker.device_id AND key.key_type='spk' AND key.group_id='' AND key.key_id=marker.key_id"
            ") "
            "ORDER BY marker.created_at DESC LIMIT 1",
            (device_id,),
        ).fetchone()
        return str(row[0]) if row is not None else None

    def mark_group_spk_uploaded(self, device_id: str, group_id: str, spk_id: str) -> None:
        """记录指定群 SPK 已成功上传到服务端。"""
        conn = self._db._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'group_spk_uploaded', ?, ?, ?, ?, ?)",
            (device_id, group_id, spk_id, b"", b"", int(time.time() * 1000)),
        )
        conn.commit()

    def load_latest_uploaded_group_spk_id(self, device_id: str, group_id: str) -> str | None:
        """返回本群最近一次上传成功且本地私钥仍存在的 group SPK ID。"""
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT marker.key_id FROM v2_device_keys AS marker "
            "WHERE marker.device_id=? AND marker.key_type='group_spk_uploaded' AND marker.group_id=? "
            "AND EXISTS ("
            "  SELECT 1 FROM v2_device_keys AS key "
            "  WHERE key.device_id=marker.device_id AND key.key_type='group_spk' AND key.group_id=marker.group_id AND key.key_id=marker.key_id"
            ") "
            "ORDER BY marker.created_at DESC LIMIT 1",
            (device_id, group_id),
        ).fetchone()
        return str(row[0]) if row is not None else None

    def list_recent_spk_ids(self, device_id: str, n: int) -> list[str]:
        """返回最近 N 代 SPK 的 spk_id 列表（按 created_at 降序）。

        用于销毁判定时的"最近 N 代保留窗口"——这些 SPK 即使其它条件满足也不销毁。
        """
        if n <= 0:
            return []
        conn = self._db._get_conn()
        rows = conn.execute(
            "SELECT key_id FROM v2_device_keys "
            "WHERE device_id=? AND key_type='spk' AND group_id='' ORDER BY created_at DESC LIMIT ?",
            (device_id, int(n)),
        ).fetchall()
        return [str(r[0]) for r in rows]

    def list_expired_spk_ids(self, device_id: str, max_age_seconds: float) -> list[str]:
        """返回 created_at 超过 max_age_seconds 的 SPK key_id 列表（不含当前 SPK）。"""
        import time
        cutoff = time.time() - max_age_seconds
        conn = self._db._get_conn()
        rows = conn.execute(
            "SELECT key_id FROM v2_device_keys "
            "WHERE device_id=? AND key_type='spk' AND group_id='' AND created_at < ?",
            (device_id, cutoff),
        ).fetchall()
        return [str(r[0]) for r in rows]
