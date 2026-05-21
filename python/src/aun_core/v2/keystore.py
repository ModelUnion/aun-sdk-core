"""V2 E2EE 设备密钥存储。

每个 (aid, device_id) 持有一对 IK 和若干 SPK（按 spk_id 索引）。
底层复用 AID 的 aun.db（v2_device_keys 表，DDL 在 sqlite_db.py 中定义）。
"""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keystore.sqlite_db import AIDDatabase


class V2KeyStore:
    """V2 E2EE 设备密钥持久化，复用 AIDDatabase 连接。

    key_type: "ik" 或 "spk"
    key_id: IK 为空字符串，SPK 为 spk_id
    """

    def __init__(self, db: "AIDDatabase"):
        self._db = db

    def save_ik(self, device_id: str, ik_priv: bytes, ik_pub_der: bytes) -> None:
        conn = self._db._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'ik', '', ?, ?, ?)",
            (device_id, ik_priv, ik_pub_der, int(time.time() * 1000)),
        )
        conn.commit()

    def load_ik(self, device_id: str) -> tuple[bytes, bytes] | None:
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT private_key, public_key FROM v2_device_keys WHERE device_id=? AND key_type='ik' AND key_id=''",
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        return (bytes(row[0]), bytes(row[1]))

    def save_spk(self, device_id: str, spk_id: str, spk_priv: bytes, spk_pub_der: bytes) -> None:
        conn = self._db._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at) "
            "VALUES (?, 'spk', ?, ?, ?, ?)",
            (device_id, spk_id, spk_priv, spk_pub_der, int(time.time() * 1000)),
        )
        conn.commit()

    def load_spk(self, device_id: str, spk_id: str) -> bytes | None:
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT private_key FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND key_id=?",
            (device_id, spk_id),
        ).fetchone()
        if row is None:
            return None
        return bytes(row[0])

    def load_current_spk(self, device_id: str) -> tuple[str, bytes, bytes] | None:
        """加载最新的 SPK（按 created_at 降序）。返回 (spk_id, priv, pub) 或 None。"""
        conn = self._db._get_conn()
        row = conn.execute(
            "SELECT key_id, private_key, public_key FROM v2_device_keys "
            "WHERE device_id=? AND key_type='spk' ORDER BY created_at DESC LIMIT 1",
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        return (row[0], bytes(row[1]), bytes(row[2]))

    def delete_spk(self, device_id: str, spk_id: str) -> None:
        """销毁指定 SPK 的私钥（用于 PFS）。"""
        conn = self._db._get_conn()
        conn.execute(
            "DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND key_id=?",
            (device_id, spk_id),
        )
        conn.commit()

    def list_recent_spk_ids(self, device_id: str, n: int) -> list[str]:
        """返回最近 N 代 SPK 的 spk_id 列表（按 created_at 降序）。

        用于销毁判定时的"最近 N 代保留窗口"——这些 SPK 即使其它条件满足也不销毁。
        """
        if n <= 0:
            return []
        conn = self._db._get_conn()
        rows = conn.execute(
            "SELECT key_id FROM v2_device_keys "
            "WHERE device_id=? AND key_type='spk' ORDER BY created_at DESC LIMIT ?",
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
            "WHERE device_id=? AND key_type='spk' AND created_at < ?",
            (device_id, cutoff),
        ).fetchall()
        return [str(r[0]) for r in rows]
