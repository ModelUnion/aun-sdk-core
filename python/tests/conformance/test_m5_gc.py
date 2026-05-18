"""
M5-A: V2 消息 GC 单元测试（TDD）

测试 P2P 和 Group 的两层 GC：
1. 消费驱动：所有 wraps consumed → 删除 messages
2. TTL 驱动：超过 retention 的消息强制删除
"""
import asyncio
import time
import pytest
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class FakePool:
    """模拟 asyncmy 连接池"""
    def __init__(self):
        self.queries = []
        self.results = []
        self._result_idx = 0

    def set_results(self, results):
        self.results = results
        self._result_idx = 0

    def acquire(self):
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, pool):
        self._pool = pool

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def cursor(self, *args, **kwargs):
        return FakeCursor(self._pool)

    async def begin(self):
        pass

    async def commit(self):
        pass

    async def rollback(self):
        pass


class FakeCursor:
    def __init__(self, pool):
        self._pool = pool
        self.rowcount = 0
        self._rows = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def execute(self, sql, params=None):
        self._pool.queries.append((sql.strip(), params))
        if self._pool._result_idx < len(self._pool.results):
            result = self._pool.results[self._pool._result_idx]
            self._pool._result_idx += 1
            if isinstance(result, int):
                self.rowcount = result
                self._rows = []
            elif isinstance(result, list):
                self._rows = result
                self.rowcount = len(result)
        else:
            self.rowcount = 0
            self._rows = []

    async def fetchall(self):
        return self._rows

    async def fetchone(self):
        return self._rows[0] if self._rows else None


# ── P2P GC Tests ──────────────────────────────────────────────

class TestPeerGCConsumed:
    """消费驱动 GC：所有 wraps consumed → 删除 messages"""

    @pytest.fixture
    def db(self):
        from aun_core.message_db_gc import V2GCMixin
        # 创建一个带 GC mixin 的 mock DB
        db = MagicMock()
        db._pool = FakePool()
        db._require_pool = MagicMock()
        # 绑定 GC 方法
        db.v2_gc_peer_consumed = V2GCMixin.v2_gc_peer_consumed.__get__(db)
        return db

    @pytest.mark.asyncio
    async def test_peer_gc_consumed_deletes_fully_consumed(self, db):
        """所有 wraps 都已消费的 message 应被删除"""
        # 模拟：找到 2 个全部消费的 message_id
        db._pool.set_results([
            [{"message_id": "m-001"}, {"message_id": "m-002"}],  # 查询全消费的 message_ids
            2,  # 删除 wraps
            2,  # 删除 messages
        ])
        result = await db.v2_gc_peer_consumed(batch_size=100)
        assert result["deleted_messages"] >= 1

    @pytest.mark.asyncio
    async def test_peer_gc_partial_consumed_not_deleted(self, db):
        """部分设备未消费的 message 不应被删除"""
        db._pool.set_results([
            [],  # 没有全部消费的 message_id
        ])
        result = await db.v2_gc_peer_consumed(batch_size=100)
        assert result["deleted_messages"] == 0


class TestPeerGCExpired:
    """TTL 驱动 GC：超过 retention 的消息强制删除"""

    @pytest.fixture
    def db(self):
        from aun_core.message_db_gc import V2GCMixin
        db = MagicMock()
        db._pool = FakePool()
        db._require_pool = MagicMock()
        db.v2_gc_peer_expired = V2GCMixin.v2_gc_peer_expired.__get__(db)
        return db

    @pytest.mark.asyncio
    async def test_peer_gc_expired_deletes_old_messages(self, db):
        """超过 retention 的消息应被强制删除"""
        retention_ms = 7 * 24 * 3600 * 1000
        db._pool.set_results([
            [{"message_id": "m-old-1"}, {"message_id": "m-old-2"}],  # 过期 message_ids
            2,  # 删除 wraps
            2,  # 删除 messages
        ])
        result = await db.v2_gc_peer_expired(retention_ms=retention_ms, batch_size=100)
        assert result["deleted_messages"] >= 1

    @pytest.mark.asyncio
    async def test_peer_gc_expired_no_old_messages(self, db):
        """没有过期消息时不删除"""
        retention_ms = 7 * 24 * 3600 * 1000
        db._pool.set_results([
            [],  # 没有过期的
        ])
        result = await db.v2_gc_peer_expired(retention_ms=retention_ms, batch_size=100)
        assert result["deleted_messages"] == 0


# ── Group GC Tests ────────────────────────────────────────────

class TestGroupGCConsumed:
    """群消息消费驱动 GC"""

    @pytest.fixture
    def repo(self):
        from aun_core.group_repo_gc import V2GroupGCMixin
        repo = MagicMock()
        repo._pool = FakePool()
        repo.v2_gc_group_consumed = V2GroupGCMixin.v2_gc_group_consumed.__get__(repo)
        return repo

    @pytest.mark.asyncio
    async def test_group_gc_consumed(self, repo):
        """所有 wraps consumed 的群消息应被删除"""
        repo._pool.set_results([
            [{"message_id": "gm-001"}],
            1,  # 删除 wraps
            1,  # 删除 messages
        ])
        result = await repo.v2_gc_group_consumed(batch_size=100)
        assert result["deleted_messages"] >= 1
