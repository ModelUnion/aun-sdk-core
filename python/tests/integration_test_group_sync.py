#!/usr/bin/env python3
"""Group 消息/事件同步集成测试。

覆盖重点：
  1. group.pull 分页、cursor、ack_messages 单调推进和 future ack 上界 clamp
  2. group.pull_events、ack_events 单调推进和 future ack 上界 clamp
  3. 多 device_id/slot_id 游标隔离、list_devices、unregister_device

使用方法（Docker 容器内）：
  python /tests/integration_test_group_sync.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_sync"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

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
    print(f"  [FAIL] {name} - {reason}")


def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            await client.connect(auth)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


async def _create_group_with_bobb(alice: AUNClient, name: str) -> str:
    created = await alice.call("group.create", {"name": name, "visibility": "private"})
    group_id = (created.get("group") or {}).get("group_id", "")
    if not group_id:
        raise AssertionError(f"group.create 未返回 group_id: {created}")
    await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})
    await asyncio.sleep(1.0)
    return group_id


async def _send_plain_group_message(client: AUNClient, group_id: str, text: str) -> int:
    sent = await client.call("group.send", {
        "group_id": group_id,
        "payload": {"type": "text", "text": text},
        "encrypt": False,
    })
    seq = int((sent.get("message") or {}).get("seq") or 0)
    if seq <= 0:
        raise AssertionError(f"group.send 未返回 seq: {sent}")
    return seq


async def _cleanup_group(owner: AUNClient, group_id: str):
    if not group_id:
        return
    try:
        await owner.call("group.dissolve", {"group_id": group_id})
        print(f"  已解散群 {group_id}")
    except Exception as exc:
        print(f"  清理群失败（忽略）: {exc}")


def _seqs(items: list[dict], key: str = "seq") -> list[int]:
    return [int(item.get(key) or 0) for item in items]


async def test_message_cursor_ack_and_device_slots():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bobb = _make_client()
    group_id = ""
    device_a = f"sync-dev-a-{rid}"
    device_b = f"sync-dev-b-{rid}"
    slot_a = "slot-a"
    slot_b = "slot-b"

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)
        group_id = await _create_group_with_bobb(alice, f"sync-msg-{rid}")
        _ok("创建群并添加 Bob")

        for index in range(1, 4):
            await _send_plain_group_message(alice, group_id, f"sync-msg-{rid}-{index}")
        await asyncio.sleep(0.8)
        _ok("发送 3 条明文群消息")

        first = await bobb._transport.call("group.pull", {
            "group_id": group_id,
            "after_message_seq": 0,
            "limit": 2,
            "device_id": device_a,
            "slot_id": slot_a,
            "device_name": "同步测试设备 A",
            "device_type": "test",
        })
        messages = first.get("messages", [])
        if len(messages) != 2 or not first.get("has_more"):
            raise AssertionError(f"limit=2 分页异常: {first}")
        msg_seqs = _seqs(messages)
        if msg_seqs[1] != msg_seqs[0] + 1:
            raise AssertionError(f"消息 seq 不连续: {msg_seqs}")
        if int((first.get("cursor") or {}).get("unread_count") or 0) < 3:
            raise AssertionError(f"首次 pull cursor unread_count 异常: {first.get('cursor')}")
        _ok("group.pull 分页与 cursor 正确")

        ack_seq = msg_seqs[-1]
        ack = await bobb._transport.call("group.ack_messages", {
            "group_id": group_id,
            "msg_seq": ack_seq,
            "device_id": device_a,
            "slot_id": slot_a,
        })
        if int(ack.get("cursor") or 0) != ack_seq:
            raise AssertionError(f"ack_messages 未推进到 {ack_seq}: {ack}")
        _ok("ack_messages 推进游标")

        lower_ack = await bobb._transport.call("group.ack_messages", {
            "group_id": group_id,
            "msg_seq": msg_seqs[0],
            "device_id": device_a,
            "slot_id": slot_a,
        })
        if int(lower_ack.get("cursor") or 0) != ack_seq:
            raise AssertionError(f"ack_messages 不应回退: {lower_ack}")
        _ok("ack_messages 单调不回退")

        cursor = await bobb._transport.call("group.get_cursor", {
            "group_id": group_id,
            "device_id": device_a,
            "slot_id": slot_a,
        })
        if int((cursor.get("msg_cursor") or {}).get("current_seq") or 0) != ack_seq:
            raise AssertionError(f"get_cursor current_seq 异常: {cursor}")
        _ok("get_cursor 反映消息 ack")

        rest = await bobb._transport.call("group.pull", {
            "group_id": group_id,
            "after_message_seq": ack_seq,
            "limit": 10,
            "device_id": device_a,
            "slot_id": slot_a,
        })
        if len(rest.get("messages", [])) != 1:
            raise AssertionError(f"ack 后应只剩 1 条未拉消息: {rest}")
        _ok("ack 后增量 pull 正确")

        await bobb._transport.call("group.pull", {
            "group_id": group_id,
            "after_message_seq": 0,
            "limit": 1,
            "device_id": device_b,
            "slot_id": slot_b,
            "device_name": "同步测试设备 B",
            "device_type": "test",
        })
        devices = await bobb._transport.call("group.list_devices", {"group_id": group_id})
        device_keys = {
            (item.get("device_id"), item.get("slot_id"))
            for item in devices.get("devices", [])
        }
        if (device_a, slot_a) not in device_keys or (device_b, slot_b) not in device_keys:
            raise AssertionError(f"list_devices 未体现两个 slot: {devices}")
        _ok("多 device_id/slot_id 游标隔离")

        await bobb._transport.call("group.unregister_device", {
            "group_id": group_id,
            "device_id": device_b,
            "slot_id": slot_b,
        })
        after_unregister = await bobb._transport.call("group.list_devices", {"group_id": group_id})
        remaining = {
            (item.get("device_id"), item.get("slot_id"))
            for item in after_unregister.get("devices", [])
        }
        if (device_b, slot_b) in remaining:
            raise AssertionError(f"unregister_device 未删除 slot_b: {after_unregister}")
        _ok("unregister_device 删除指定 slot")

        latest = int((cursor.get("msg_cursor") or {}).get("latest_seq") or 0)
        future_ack = await bobb._transport.call("group.ack_messages", {
            "group_id": group_id,
            "msg_seq": latest + 100,
            "device_id": device_a,
            "slot_id": slot_a,
        })
        if int(future_ack.get("cursor") or 0) != latest:
            raise AssertionError(f"future msg ack 应 clamp 到 latest={latest}: {future_ack}")
        _ok("future msg ack clamp 到 latest")
    finally:
        await _cleanup_group(alice, group_id)
        await alice.close()
        await bobb.close()


async def test_event_cursor_ack_and_future_guard():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bobb = _make_client()
    group_id = ""
    device = f"sync-event-dev-{rid}"
    slot = "events"

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)
        group_id = await _create_group_with_bobb(alice, f"sync-event-{rid}")
        _ok("创建事件同步群")

        await alice.call("group.update", {
            "group_id": group_id,
            "description": f"event-desc-{rid}",
        })
        await _send_plain_group_message(alice, group_id, f"event-msg-{rid}")
        await asyncio.sleep(0.8)
        _ok("产生 group.changed 与 message_created 事件")

        pulled = await bobb._transport.call("group.pull_events", {
            "group_id": group_id,
            "after_event_seq": 0,
            "limit": 20,
            "device_id": device,
            "slot_id": slot,
            "device_name": "事件测试设备",
            "device_type": "test",
        })
        events = pulled.get("events", [])
        if not events:
            raise AssertionError(f"pull_events 未返回事件: {pulled}")
        event_seq_key = "event_seq" if "event_seq" in events[0] else "seq"
        event_seqs = _seqs(events, event_seq_key)
        if max(event_seqs) <= 0:
            raise AssertionError(f"事件 seq 异常: {events}")
        event_types = {str(item.get("event_type") or item.get("type") or "") for item in events}
        if not any("group." in item for item in event_types):
            raise AssertionError(f"未看到 group.* 事件类型: {event_types}")
        _ok("group.pull_events 返回增量事件")

        ack_event_seq = max(event_seqs)
        ack = await bobb._transport.call("group.ack_events", {
            "group_id": group_id,
            "event_seq": ack_event_seq,
            "device_id": device,
            "slot_id": slot,
        })
        if int(ack.get("cursor") or 0) != ack_event_seq:
            raise AssertionError(f"ack_events 未推进: {ack}")
        _ok("ack_events 推进游标")

        lower = await bobb._transport.call("group.ack_events", {
            "group_id": group_id,
            "event_seq": min(event_seqs),
            "device_id": device,
            "slot_id": slot,
        })
        if int(lower.get("cursor") or 0) != ack_event_seq:
            raise AssertionError(f"ack_events 不应回退: {lower}")
        _ok("ack_events 单调不回退")

        cursor = await bobb._transport.call("group.get_cursor", {
            "group_id": group_id,
            "device_id": device,
            "slot_id": slot,
        })
        event_cursor = cursor.get("event_cursor") or {}
        if int(event_cursor.get("current_seq") or 0) != ack_event_seq:
            raise AssertionError(f"event cursor current_seq 异常: {cursor}")
        _ok("get_cursor 反映事件 ack")

        latest_event_seq = int(event_cursor.get("latest_seq") or 0)
        future_ack = await bobb._transport.call("group.ack_events", {
            "group_id": group_id,
            "event_seq": latest_event_seq + 100,
            "device_id": device,
            "slot_id": slot,
        })
        if int(future_ack.get("cursor") or 0) != latest_event_seq:
            raise AssertionError(f"future event ack 应 clamp 到 latest={latest_event_seq}: {future_ack}")
        _ok("future event ack clamp 到 latest")
    finally:
        await _cleanup_group(alice, group_id)
        await alice.close()
        await bobb.close()


async def _run_test(name: str, func):
    print(f"\n=== {name} ===")
    try:
        await func()
    except Exception as exc:
        _fail(name, str(exc))
        import traceback
        traceback.print_exc()


async def main():
    print("=== group.sync 集成测试 ===\n")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOBB_AID}")
    print()

    await _run_test("消息 cursor/ack/device slot", test_message_cursor_ack_and_device_slots)
    await _run_test("事件 cursor/ack/future guard", test_event_cursor_ack_and_future_guard)

    print(f"\n{'=' * 50}")
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        print("失败详情:")
        for item in _errors:
            print(f"  - {item}")
    if _failed:
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
