"""V2 P2P 消息 GC Mixin"""
from __future__ import annotations
import time


class V2GCMixin:
    """V2 P2P 消息 GC 方法（混入 MessageDB）"""

    async def v2_gc_peer_consumed(self, batch_size: int = 500) -> dict:
        """消费驱动 GC：删除所有 wraps 已消费的 messages。"""
        self._require_pool()
        deleted_wraps = 0
        deleted_messages = 0
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                # 找到所有 wraps 都已消费的 message_id
                await cur.execute("""
                    SELECT m.`message_id`
                    FROM `v2_peer_messages` m
                    WHERE NOT EXISTS (
                        SELECT 1 FROM `v2_peer_wraps` w
                        WHERE w.`message_id` = m.`message_id` AND w.`consumed_at` IS NULL
                    )
                    AND EXISTS (
                        SELECT 1 FROM `v2_peer_wraps` w2
                        WHERE w2.`message_id` = m.`message_id`
                    )
                    LIMIT %s
                """, (batch_size,))
                rows = await cur.fetchall()
                if not rows:
                    return {"deleted_messages": 0, "deleted_wraps": 0}
                msg_ids = [r[0] if isinstance(r, (list, tuple)) else r.get("message_id", "") for r in rows]
                if not msg_ids:
                    return {"deleted_messages": 0, "deleted_wraps": 0}
                placeholders = ",".join(["%s"] * len(msg_ids))
                await cur.execute(
                    f"DELETE FROM `v2_peer_wraps` WHERE `message_id` IN ({placeholders})",
                    tuple(msg_ids),
                )
                deleted_wraps = cur.rowcount
                await cur.execute(
                    f"DELETE FROM `v2_peer_messages` WHERE `message_id` IN ({placeholders})",
                    tuple(msg_ids),
                )
                deleted_messages = cur.rowcount
        return {"deleted_messages": deleted_messages, "deleted_wraps": deleted_wraps}

    async def v2_gc_peer_expired(self, retention_ms: int, batch_size: int = 500) -> dict:
        """TTL 驱动 GC：删除超过 retention 的消息。"""
        self._require_pool()
        now_ms = int(time.time() * 1000)
        cutoff_ms = now_ms - retention_ms
        deleted_wraps = 0
        deleted_messages = 0
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    SELECT `message_id` FROM `v2_peer_messages`
                    WHERE `t_server` > 0 AND `t_server` < %s
                    LIMIT %s
                """, (cutoff_ms, batch_size))
                rows = await cur.fetchall()
                if not rows:
                    return {"deleted_messages": 0, "deleted_wraps": 0}
                msg_ids = [r[0] if isinstance(r, (list, tuple)) else r.get("message_id", "") for r in rows]
                if not msg_ids:
                    return {"deleted_messages": 0, "deleted_wraps": 0}
                placeholders = ",".join(["%s"] * len(msg_ids))
                await cur.execute(
                    f"DELETE FROM `v2_peer_wraps` WHERE `message_id` IN ({placeholders})",
                    tuple(msg_ids),
                )
                deleted_wraps = cur.rowcount
                await cur.execute(
                    f"DELETE FROM `v2_peer_messages` WHERE `message_id` IN ({placeholders})",
                    tuple(msg_ids),
                )
                deleted_messages = cur.rowcount
        return {"deleted_messages": deleted_messages, "deleted_wraps": deleted_wraps}
