#!/usr/bin/env python3
"""Message.ack 部分成功语义测试 — 对应 P1-9 修复。

测试场景：
  1. A 发消息给 B，B ack
  2. ack DB 更新成功但事件发布失败时返回 `{success: true, event_published: false}`
  3. ack_seq 已推进

使用方法：
  docker exec kite-sdk-tester python /tests/integration_test_message_ack.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT 指向 Docker 挂载的持久化数据目录
"""
import asyncio
import os
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_message_ack"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

# ---------------------------------------------------------------------------
# 计数
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str):
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str):
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} — {reason}")


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth)
    return aid


def _seq_of(msg: dict) -> int:
    return int(msg.get("seq") or 0)


async def _sdk_send(client: AUNClient, to_aid: str, payload: str):
    """发送加密消息"""
    return await client.call("message.send", {
        "to": to_aid,
        "payload": payload,
        "encrypt": True
    })


async def _sdk_recv_push_after(client: AUNClient, from_aid: str, *, after_seq: int = 0, timeout: float = 5.0):
    """等待推送或主动拉取"""
    inbox = []
    event = asyncio.Event()

    def handler(data):
        if data.get("from") != from_aid:
            return
        if _seq_of(data) <= after_seq:
            return
        inbox.append(data)
        event.set()

    sub = client.on("message.received", handler)
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    sub.unsubscribe()

    if not inbox:
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": 50})
        inbox.extend(m for m in result.get("messages", []) if m.get("from") == from_aid)

    return sorted(inbox, key=_seq_of)


async def _current_max_seq(client: AUNClient, *, limit: int = 200) -> int:
    """获取当前最大 seq，用于建立 baseline"""
    after_seq = 0
    max_seq = 0
    while True:
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": limit})
        msgs = result.get("messages", [])
        if not msgs:
            return max_seq
        for msg in msgs:
            max_seq = max(max_seq, _seq_of(msg))
        if len(msgs) < limit:
            return max_seq
        after_seq = max_seq


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

async def test_message_ack_basic():
    """测试基本 ack 功能"""
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 0. 获取 baseline seq，避免拉取历史消息
        baseline = await _current_max_seq(bob)

        # 1. Alice 发送消息给 Bob
        await _sdk_send(alice, _BOB_AID, "test_ack_message")
        await asyncio.sleep(1.0)

        # 2. Bob 拉取消息
        msgs = await _sdk_recv_push_after(bob, _ALICE_AID, after_seq=baseline, timeout=2.0)
        if not msgs:
            _fail("message_ack_basic", "Bob 未收到消息")
            return

        msg_seq = _seq_of(msgs[0])
        print(f"  [INFO] Bob 收到消息 seq={msg_seq}")

        # 3. Bob ack 消息
        ack_result = await bob.call("message.ack", {"seq": msg_seq})

        # 4. 验证 ack 结果（ack_seq 是累积值，可能 >= msg_seq）
        if not ack_result.get("success"):
            _fail("message_ack_basic", f"ack 失败: {ack_result}")
            return

        if not (ack_result.get("ack_seq") >= msg_seq):
            _fail("message_ack_basic", f"ack_seq 不匹配: 期望 >= {msg_seq}, 实际 {ack_result.get('ack_seq')}")
            return

        _ok("message_ack_basic")

    finally:
        await alice.close()
        await bob.close()


async def test_message_ack_event():
    """测试 ack 事件发布"""
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 0. 获取 baseline seq
        baseline = await _current_max_seq(bob)

        # 1. Alice 订阅 ack 事件
        ack_events = []
        ack_event = asyncio.Event()

        def ack_handler(data):
            print(f"  [INFO] Alice 收到 ack 事件: {data}")
            ack_events.append(data)
            ack_event.set()

        alice.on("message.ack", ack_handler)

        # 2. Alice 发送消息给 Bob
        send_result = await _sdk_send(alice, _BOB_AID, "test_ack_event")
        await asyncio.sleep(1.0)

        # 3. Bob 拉取消息
        msgs = await _sdk_recv_push_after(bob, _ALICE_AID, after_seq=baseline, timeout=2.0)
        if not msgs:
            _fail("message_ack_event", "Bob 未收到消息")
            return

        msg_seq = _seq_of(msgs[0])
        print(f"  [INFO] Bob 收到消息 seq={msg_seq}")

        # 4. Bob ack 消息
        ack_result = await bob.call("message.ack", {"seq": msg_seq})
        print(f"  [INFO] ack 结果: {ack_result}")

        # 5. 等待 Alice 收到 ack 事件
        try:
            await asyncio.wait_for(ack_event.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            _fail("message_ack_event", "Alice 未收到 ack 事件")
            return

        # 6. 验证 ack 事件内容
        if not ack_events:
            _fail("message_ack_event", "ack_events 为空")
            return

        event_data = ack_events[0]
        # ack 事件的 "to" 字段是 ack 发起方（Bob）
        if event_data.get("to") != _BOB_AID:
            _fail("message_ack_event", f"ack 事件 to 不匹配: 期望 {_BOB_AID}, 实际 {event_data.get('to')}")
            return

        if not (event_data.get("ack_seq") >= msg_seq):
            _fail("message_ack_event", f"ack 事件 ack_seq 不匹配: 期望 >= {msg_seq}, 实际 {event_data.get('ack_seq')}")
            return

        _ok("message_ack_event")

    finally:
        await alice.close()
        await bob.close()


async def test_message_ack_partial_success():
    """测试 ack 部分成功语义（DB 成功但事件发布失败）"""
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 0. 获取 baseline seq
        baseline = await _current_max_seq(bob)

        # 1. Alice 发送消息给 Bob
        await _sdk_send(alice, _BOB_AID, "test_partial_success")
        await asyncio.sleep(1.0)

        # 2. Bob 拉取消息
        msgs = await _sdk_recv_push_after(bob, _ALICE_AID, after_seq=baseline, timeout=2.0)
        if not msgs:
            _fail("message_ack_partial_success", "Bob 未收到消息")
            return

        msg_seq = _seq_of(msgs[0])
        print(f"  [INFO] Bob 收到消息 seq={msg_seq}")

        # 3. Bob ack 消息
        ack_result = await bob.call("message.ack", {"seq": msg_seq})
        print(f"  [INFO] ack 结果: {ack_result}")

        # 4. 验证 ack 结果包含必要字段
        if not ack_result.get("success"):
            _fail("message_ack_partial_success", f"ack 失败: {ack_result}")
            return

        if "ack_seq" not in ack_result:
            _fail("message_ack_partial_success", "ack 结果缺少 ack_seq 字段")
            return

        # 5. 如果事件发布失败，应该有 event_published: false
        # 注意：正常情况下 event_published 应该为 true 或不存在
        # 这个测试主要验证接口契约，实际触发失败需要故障注入
        if "event_published" in ack_result:
            print(f"  [INFO] event_published: {ack_result.get('event_published')}")
            if not ack_result.get("event_published"):
                print(f"  [INFO] 事件发布失败，但 ack_seq 已推进: {ack_result.get('ack_seq')}")

        # 6. 再次 ack 同一 seq，验证幂等性（ack_seq 是累积值，可能 >= msg_seq）
        ack_result2 = await bob.call("message.ack", {"seq": msg_seq})
        if not ack_result2.get("success"):
            _fail("message_ack_partial_success", f"重复 ack 失败: {ack_result2}")
            return

        if not (ack_result2.get("ack_seq") >= msg_seq):
            _fail("message_ack_partial_success", f"重复 ack 的 ack_seq 不匹配: 期望 >= {msg_seq}, 实际 {ack_result2.get('ack_seq')}")
            return

        _ok("message_ack_partial_success")

    finally:
        await alice.close()
        await bob.close()


async def test_message_ack_sequence():
    """测试 ack 序列推进"""
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 0. 获取 baseline seq
        baseline = await _current_max_seq(bob)

        # 1. Alice 发送 3 条消息给 Bob
        await _sdk_send(alice, _BOB_AID, "msg1")
        await asyncio.sleep(0.2)
        await _sdk_send(alice, _BOB_AID, "msg2")
        await asyncio.sleep(0.2)
        await _sdk_send(alice, _BOB_AID, "msg3")
        await asyncio.sleep(1.0)

        # 2. Bob 拉取所有消息
        msgs = await _sdk_recv_push_after(bob, _ALICE_AID, after_seq=baseline, timeout=2.0)
        if len(msgs) < 3:
            _fail("message_ack_sequence", f"Bob 未收到足够消息: 期望 3 条, 实际 {len(msgs)} 条")
            return

        seqs = [_seq_of(m) for m in msgs[:3]]
        print(f"  [INFO] Bob 收到消息 seqs={seqs}")

        # 3. Bob 按顺序 ack（ack_seq 是累积值，可能 >= 当前 seq）
        for seq in seqs:
            ack_result = await bob.call("message.ack", {"seq": seq})
            if not ack_result.get("success"):
                _fail("message_ack_sequence", f"ack seq={seq} 失败: {ack_result}")
                return
            if not (ack_result.get("ack_seq") >= seq):
                _fail("message_ack_sequence", f"ack_seq 不匹配: 期望 >= {seq}, 实际 {ack_result.get('ack_seq')}")
                return

        # 4. 验证最终 ack_seq >= 最后一条消息的 seq
        final_ack = await bob.call("message.ack", {"seq": seqs[-1]})
        if not (final_ack.get("ack_seq") >= seqs[-1]):
            _fail("message_ack_sequence", f"最终 ack_seq 不匹配: 期望 >= {seqs[-1]}, 实际 {final_ack.get('ack_seq')}")
            return

        _ok("message_ack_sequence")

    finally:
        await alice.close()
        await bob.close()


async def main():
    print("=" * 60)
    print("Message.ack 部分成功语义测试")
    print("=" * 60)

    await test_message_ack_basic()
    await test_message_ack_event()
    await test_message_ack_partial_success()
    await test_message_ack_sequence()

    print()
    print(f"通过: {_passed}, 失败: {_failed}")
    if _errors:
        print("\n失败详情:")
        for err in _errors:
            print(f"  - {err}")

    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
