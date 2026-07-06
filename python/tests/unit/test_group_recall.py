"""群组消息撤回 — delivery 层单元测试（TDD）。

不需要 Docker；测试 delivery.py 中 group recall tombstone 归一化与去重逻辑。
"""
from __future__ import annotations

import asyncio
import pytest
from aun_core._client import MessageDeliveryEngine


# ── 归一化：recall_event_from_group_message ─────────────────────────────────

def test_recall_from_group_message_payload_type():
    """message_type=group.message_recalled 的行，应被识别为撤回 tombstone。"""
    msg = {
        "message_id": "recall-notice-1",
        "group_id": "grp-1",
        "seq": 5,
        "type": "group.message_recalled",
        "payload": {
            "type": "group.message_recalled",
            "message_ids": ["m-aaa"],
            "target_message_seqs": [3],
            "sender_aid": "alice.agentid.pub",
            "recalled_by": "alice.agentid.pub",
            "recalled_at": 1000,
        },
    }
    result = MessageDeliveryEngine.recall_event_from_group_message(msg)
    assert result is not None
    assert result["type"] == "group.message_recalled"
    assert result["kind"] == "group.message_recalled"
    assert result["group_id"] == "grp-1"
    assert result["message_ids"] == ["m-aaa"]
    assert result["tombstone_message_id"] == "recall-notice-1"
    assert result["seq"] == 5


def test_recall_from_group_message_placeholder():
    """原 seq 占位 tombstone（payload 也携带 type=group.message_recalled）同样被识别。"""
    msg = {
        "message_id": "placeholder-1",
        "group_id": "grp-1",
        "seq": 3,
        "type": "group.message_recalled",
        "payload": {
            "type": "group.message_recalled",
            "message_ids": ["m-aaa"],
            "target_message_seqs": [3],
            "recalled_at": 1000,
        },
    }
    result = MessageDeliveryEngine.recall_event_from_group_message(msg)
    assert result is not None
    assert result["type"] == "group.message_recalled"
    assert result["message_ids"] == ["m-aaa"]


def test_recall_from_group_message_non_recall():
    """普通群消息不应被识别为撤回。"""
    msg = {
        "message_id": "m-1",
        "group_id": "grp-1",
        "seq": 1,
        "type": "text",
        "payload": {"type": "text", "text": "hello"},
    }
    assert MessageDeliveryEngine.recall_event_from_group_message(msg) is None


def test_recall_from_group_message_none():
    assert MessageDeliveryEngine.recall_event_from_group_message(None) is None
    assert MessageDeliveryEngine.recall_event_from_group_message("bad") is None


def test_recall_from_group_message_preserves_extra_fields():
    """recalled_by / reason 等额外字段应保留。"""
    msg = {
        "message_id": "tbs-2",
        "group_id": "grp-x",
        "seq": 10,
        "type": "group.message_recalled",
        "payload": {
            "type": "group.message_recalled",
            "message_ids": ["m-bbb"],
            "target_message_seqs": [7],
            "recalled_by": "alice.agentid.pub",
            "sender_aid": "alice.agentid.pub",
            "recalled_at": 2000,
            "reason": "oops",
        },
    }
    result = MessageDeliveryEngine.recall_event_from_group_message(msg)
    assert result["recalled_by"] == "alice.agentid.pub"
    assert result["reason"] == "oops"


def test_recall_from_group_message_top_level_fields():
    """在线 push 只在顶层携带 recall 字段时，也应归一化出原消息 id。"""
    msg = {
        "message_id": "notice-1",
        "group_id": "grp-1",
        "seq": 5,
        "type": "group.message_recalled",
        "message_ids": ["m-aaa"],
        "target_message_seqs": [3],
        "recalled_by": "alice.agentid.pub",
        "recalled_at": 1000,
    }
    result = MessageDeliveryEngine.recall_event_from_group_message(msg)
    assert result is not None
    assert result["message_ids"] == ["m-aaa"]
    assert result["target_message_seqs"] == [3]
    assert result["recalled_by"] == "alice.agentid.pub"


def test_recall_from_message_top_level_fields():
    """P2P 在线 push 只在顶层携带 recall 字段时，也应归一化出原消息 id。"""
    msg = {
        "message_id": "notice-1",
        "seq": 5,
        "type": "message.recalled",
        "message_ids": ["m-aaa"],
        "target_message_seqs": [3],
        "recalled_by": "alice.agentid.pub",
        "recalled_at": 1000,
    }
    result = MessageDeliveryEngine.recall_event_from_message(msg)
    assert result is not None
    assert result["message_ids"] == ["m-aaa"]
    assert result["target_message_seqs"] == [3]
    assert result["recalled_by"] == "alice.agentid.pub"


# ── 去重：同一 (group_id, original_message_id) 只回调一次 ──────────────────

@pytest.mark.asyncio
async def test_group_recall_dedup_suppresses_duplicate():
    """占位 tombstone（seq=3）和通知 tombstone（seq=5）共同携带 message_ids=["m-aaa"]；
    应用层只应收到一次 group.message_recalled。
    """
    published: list[tuple] = []

    class FakeClient:
        _device_id = "dev-1"
        _slot_id = ""
        _log = type("L", (), {
            "debug": lambda *a, **k: None,
            "warn": lambda *a, **k: None,
            "info": lambda *a, **k: None,
        })()

        async def _publish_app_event(self, event, payload, *, source="direct"):
            published.append((event, payload))

        def _normalize_published_message_payload(self, event, payload):
            return payload

        def _is_instance_scoped_message_event(self, e):
            return MessageDeliveryEngine.is_instance_scoped_message_event(e)

    engine = MessageDeliveryEngine(FakeClient())

    placeholder = {
        "message_id": "ph-1", "group_id": "grp-1", "seq": 3,
        "type": "group.message_recalled",
        "payload": {"type": "group.message_recalled", "message_ids": ["m-aaa"],
                    "recalled_at": 1000},
    }
    notice = {
        "message_id": "notice-1", "group_id": "grp-1", "seq": 5,
        "type": "group.message_recalled",
        "payload": {"type": "group.message_recalled", "message_ids": ["m-aaa"],
                    "recalled_at": 1000},
    }

    await engine.publish_group_recall_tombstone("grp-1", 3, placeholder)
    await engine.publish_group_recall_tombstone("grp-1", 5, notice)

    # 只应发布一次
    recall_events = [(e, p) for e, p in published if e == "group.message_recalled"]
    assert len(recall_events) == 1, f"期望 1 次 recall 回调，实际 {len(recall_events)}"


@pytest.mark.asyncio
async def test_group_recall_dedup_different_messages_both_published():
    """两条不同 message_id 的撤回，各自只发布一次（共 2 次）。"""
    published: list = []

    class FakeClient:
        _device_id = "dev-1"
        _slot_id = ""
        _log = type("L", (), {
            "debug": lambda *a, **k: None,
            "warn": lambda *a, **k: None,
            "info": lambda *a, **k: None,
        })()

        async def _publish_app_event(self, event, payload, *, source="direct"):
            published.append((event, payload))

        def _normalize_published_message_payload(self, event, payload):
            return payload

        def _is_instance_scoped_message_event(self, e):
            return MessageDeliveryEngine.is_instance_scoped_message_event(e)

    engine = MessageDeliveryEngine(FakeClient())

    for msg_id, seq in [("m-aaa", 3), ("m-bbb", 4)]:
        await engine.publish_group_recall_tombstone("grp-1", seq, {
            "message_id": f"ph-{msg_id}", "group_id": "grp-1", "seq": seq,
            "type": "group.message_recalled",
            "payload": {"type": "group.message_recalled", "message_ids": [msg_id],
                        "recalled_at": 1000},
        })

    recall_events = [p for e, p in published if e == "group.message_recalled"]
    assert len(recall_events) == 2
    ids = {p["message_ids"][0] for p in recall_events}
    assert ids == {"m-aaa", "m-bbb"}


# ── is_instance_scoped_message_event 包含 group.message_recalled ─────────────

def test_group_message_recalled_is_instance_scoped():
    assert MessageDeliveryEngine.is_instance_scoped_message_event("group.message_recalled")


# ── #1 回归：push 与 pull 的 recalled_at 不同源，去重键仍须合并为一次回调 ─────

def test_group_recall_dedup_key_ignores_recalled_at():
    """去重键不含 recalled_at：同一组 message_ids 不同 recalled_at 必须映射到同一键。

    回归 #1：push 在事务后用 time.time() 重取 recalled_at，与 pull tombstone 的
    事务内 now_ms 不同源。若去重键含 recalled_at（旧实现），push 与 pull 算出不同键
    → 应用层重复回调。修复后去重键只用 group_id|sorted(message_ids)，两者一致。
    """
    key_pull = MessageDeliveryEngine.group_recall_dedup_key(
        "grp-1", {"message_ids": ["m-aaa"], "recalled_at": 1000},
    )
    key_push = MessageDeliveryEngine.group_recall_dedup_key(
        "grp-1", {"message_ids": ["m-aaa"], "recalled_at": 1007},  # push 重取，晚几毫秒
    )
    assert key_pull == key_push == "grp-1|id:m-aaa"


def test_group_recall_dedup_key_falls_back_to_target_seq():
    key_placeholder = MessageDeliveryEngine.group_recall_dedup_key(
        "grp-1", {"message_id": "ph-1", "target_message_seqs": [3]},
    )
    key_notice = MessageDeliveryEngine.group_recall_dedup_key(
        "grp-1", {"message_id": "notice-1", "target_message_seqs": [3]},
    )
    assert key_placeholder == key_notice == "grp-1|seq:3"


def test_message_recall_dedup_key_ignores_recalled_at():
    key_push = MessageDeliveryEngine.message_recall_dedup_key(
        {"message_ids": ["m-aaa"], "recalled_at": 1007},
    )
    key_pull = MessageDeliveryEngine.message_recall_dedup_key(
        {"message_ids": ["m-aaa"], "recalled_at": 1000},
    )
    assert key_push == key_pull == "p2p|id:m-aaa"


@pytest.mark.asyncio
async def test_message_recall_dedup_across_push_and_pull():
    published: list = []

    class FakeClient:
        _device_id = "dev-1"
        _slot_id = ""
        _log = type("L", (), {
            "debug": lambda *a, **k: None,
            "warn": lambda *a, **k: None,
            "info": lambda *a, **k: None,
        })()

        async def _publish_app_event(self, event, payload, *, source="direct"):
            published.append((event, payload))

    engine = MessageDeliveryEngine(FakeClient())

    await engine.publish_message_recall_tombstone(5, {
        "message_id": "recall-push",
        "seq": 5,
        "type": "message.recalled",
        "payload": {"type": "message.recalled", "message_ids": ["m-aaa"], "recalled_at": 1007},
    })
    await engine.publish_message_recall_tombstone(6, {
        "message_id": "recall-pull",
        "seq": 6,
        "type": "message.recalled",
        "payload": {"type": "message.recalled", "message_ids": ["m-aaa"], "recalled_at": 1000},
    })

    recall_events = [p for e, p in published if e == "message.recalled"]
    assert len(recall_events) == 1
    assert recall_events[0]["message_ids"] == ["m-aaa"]


@pytest.mark.asyncio
async def test_group_recall_dedup_across_push_and_pull_different_recalled_at():
    """模拟在线 push（recalled_at=T2）+ 后续 pull tombstone（recalled_at=T1），
    T1≠T2，应用层仍只应收到一次 group.message_recalled。这是 #1 的端到端去重回归。
    """
    published: list = []

    class FakeClient:
        _device_id = "dev-1"
        _slot_id = ""
        _log = type("L", (), {
            "debug": lambda *a, **k: None,
            "warn": lambda *a, **k: None,
            "info": lambda *a, **k: None,
        })()

        async def _publish_app_event(self, event, payload, *, source="direct"):
            published.append((event, payload))

        def _normalize_published_message_payload(self, event, payload):
            return payload

        def _is_instance_scoped_message_event(self, e):
            return MessageDeliveryEngine.is_instance_scoped_message_event(e)

    engine = MessageDeliveryEngine(FakeClient())

    # push 路径：recalled_at=T2（事务后重取）
    await engine.publish_group_recall_tombstone("grp-1", 5, {
        "message_id": "notice-1", "group_id": "grp-1", "seq": 5,
        "type": "group.message_recalled",
        "payload": {"type": "group.message_recalled", "message_ids": ["m-aaa"],
                    "recalled_at": 1007},
    })
    # pull 路径：占位 tombstone recalled_at=T1（事务内 now_ms）
    await engine.publish_group_recall_tombstone("grp-1", 3, {
        "message_id": "ph-1", "group_id": "grp-1", "seq": 3,
        "type": "group.message_recalled",
        "payload": {"type": "group.message_recalled", "message_ids": ["m-aaa"],
                    "recalled_at": 1000},
    })

    recall_events = [p for e, p in published if e == "group.message_recalled"]
    assert len(recall_events) == 1, f"push/pull recalled_at 不同源仍应只回调一次，实际 {len(recall_events)}"


@pytest.mark.asyncio
async def test_group_recall_dedup_normalizes_group_identifier():
    published: list = []

    class FakeClient:
        _device_id = "dev-1"
        _slot_id = ""
        _log = type("L", (), {
            "debug": lambda *a, **k: None,
            "warn": lambda *a, **k: None,
            "info": lambda *a, **k: None,
        })()

        async def _publish_app_event(self, event, payload, *, source="direct"):
            published.append((event, payload))

        def _normalize_published_message_payload(self, event, payload):
            return payload

        def _is_instance_scoped_message_event(self, e):
            return MessageDeliveryEngine.is_instance_scoped_message_event(e)

    engine = MessageDeliveryEngine(FakeClient())
    await engine.publish_group_recall_tombstone("group.example.com/room1", 5, {
        "message_id": "notice-1", "group_id": "group.example.com/room1", "seq": 5,
        "type": "group.message_recalled",
        "payload": {"type": "group.message_recalled", "message_ids": ["m-aaa"]},
    })
    await engine.publish_group_recall_tombstone("room1.example.com", 3, {
        "message_id": "ph-1", "group_id": "room1.example.com", "seq": 3,
        "type": "group.message_recalled",
        "payload": {"type": "group.message_recalled", "message_ids": ["m-aaa"]},
    })

    recall_events = [p for e, p in published if e == "group.message_recalled"]
    assert len(recall_events) == 1
    assert recall_events[0]["group_id"] == "room1.example.com"
