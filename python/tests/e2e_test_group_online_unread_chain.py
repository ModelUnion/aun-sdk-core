#!/usr/bin/env python3
"""Group online unread 多群链式续拉 E2E。"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path


_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_online_unread_chain"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} - {reason}")


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


async def _connect(
    client: AUNClient,
    aid: str,
    *,
    slot_id: str,
    background_sync: bool,
) -> None:
    await ensure_connected_identity(
        client,
        aid,
        connect_options={
            "slot_id": slot_id,
            "auto_reconnect": False,
            "background_sync": background_sync,
        },
        attempts=4,
    )


async def _wait_for(
    label: str,
    predicate: Callable[[], bool],
    *,
    timeout: float = 25.0,
    interval: float = 0.1,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(interval)
    raise AssertionError(f"等待超时: {label}")


async def _wait_v2_group_ready(client: AUNClient, aid: str, group_id: str, *, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        try:
            last = await client.call("group.v2.bootstrap", {"group_id": group_id})
            committed = set(last.get("committed_member_aids") or last.get("member_aids") or [])
            pending_adds = last.get("pending_adds") or []
            pending_removes = last.get("pending_removes") or []
            if aid in committed and not pending_adds and not pending_removes:
                return
        except Exception as exc:
            last = exc
        await asyncio.sleep(0.5)
    raise AssertionError(f"{aid} 未看到群 {group_id} 成员状态就绪: {last}")


async def _create_group_with_bob(alice: AUNClient, bob: AUNClient, name: str) -> str:
    created = await alice.call("group.create", {
        "name": name,
        "visibility": "private",
        "group_e2ee_protocol": "group_e2ee_v2",
    })
    group_id = (created.get("group") or {}).get("group_id", "")
    if not group_id:
        raise AssertionError(f"group.create 未返回 group_id: {created}")
    await alice.call("group.add_member", {"group_id": group_id, "aid": _BOB_AID})
    await _wait_v2_group_ready(bob, _BOB_AID, group_id)
    await _prime_bob_cursors(bob, group_id)
    return group_id


async def _prime_bob_cursors(bob: AUNClient, group_id: str) -> None:
    await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 10})
    events_result = await bob.call("group.pull_events", {
        "group_id": group_id,
        "after_event_seq": 0,
        "limit": 100,
        "device_id": bob.device_id,
        "slot_id": bob.slot_id,
    })
    events = events_result.get("events", []) if isinstance(events_result, dict) else []
    event_seq = 0
    for event in events:
        if isinstance(event, dict):
            event_seq = max(event_seq, int(event.get("event_seq") or event.get("seq") or 0))
    latest_seq = int((events_result.get("cursor") or {}).get("latest_seq") or 0) if isinstance(events_result, dict) else 0
    event_seq = max(event_seq, latest_seq)
    if event_seq > 0:
        await bob.call("group.ack_events", {
            "group_id": group_id,
            "event_seq": event_seq,
            "device_id": bob.device_id,
            "slot_id": bob.slot_id,
        })


async def _cleanup_groups(alice: AUNClient, group_ids: list[str]) -> None:
    for group_id in group_ids:
        if not group_id:
            continue
        try:
            await alice.call("group.dissolve", {"group_id": group_id})
        except Exception as exc:
            print(f"  清理群失败（忽略）: {group_id} {exc}")


def _group_ids(items: list[dict[str, Any]]) -> set[str]:
    return {str(item.get("group_id") or "") for item in items if isinstance(item, dict)}


async def _wait_cursor_synced(
    client: AUNClient,
    group_ids: list[str],
    cursor_name: str,
    *,
    timeout: float = 20.0,
) -> None:
    expected = set(group_ids)
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        synced: set[str] = set()
        last = {}
        for group_id in group_ids:
            cursor = await client.call("group.get_cursor", {
                "group_id": group_id,
                "device_id": client.device_id,
                "slot_id": client.slot_id,
            })
            detail = cursor.get(cursor_name) if isinstance(cursor, dict) else None
            detail = detail if isinstance(detail, dict) else {}
            current_seq = int(detail.get("current_seq") or 0)
            latest_seq = int(detail.get("latest_seq") or 0)
            unread_count = int(detail.get("unread_count") or 0)
            last[group_id] = detail
            if latest_seq > 0 and current_seq >= latest_seq and unread_count == 0:
                synced.add(group_id)
        if expected.issubset(synced):
            return
        await asyncio.sleep(0.2)
    raise AssertionError(f"{cursor_name} 未同步到最新: expected={expected} last={last}")


async def test_message_online_unread_chains_next_group() -> None:
    rid = uuid.uuid4().hex[:10]
    slot_id = f"online-msg-{rid}"
    alice = _make_client()
    bob_seed = _make_client()
    bob = _make_client()
    group_ids: list[str] = []
    received: list[dict[str, Any]] = []

    try:
        await _connect(alice, _ALICE_AID, slot_id=f"alice-msg-{rid}", background_sync=False)
        await _connect(bob_seed, _BOB_AID, slot_id=slot_id, background_sync=False)
        for index in range(2):
            group_ids.append(await _create_group_with_bob(alice, bob_seed, f"online-unread-msg-{rid}-{index}"))
        expected = set(group_ids)
        _ok("消息用例预建两个群和 Bob cursor")

        await bob_seed.disconnect()
        for index, group_id in enumerate(group_ids):
            await alice.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": f"online-unread-msg-{rid}-{index}"},
                "encrypt": False,
            })
            await asyncio.sleep(0.2)
        _ok("Bob 离线期间制造两个群的未读消息")

        bob.on("group.message_created", lambda data: received.append(data) if isinstance(data, dict) and data.get("group_id") in expected else None)

        await _connect(bob, _BOB_AID, slot_id=slot_id, background_sync=True)
        await _wait_for("两个群的未读消息均被拉取", lambda: expected.issubset(_group_ids(received)), timeout=35.0)
        await _wait_cursor_synced(bob, group_ids, "msg_cursor", timeout=20.0)
        _ok("消息在线续拉后公开 cursor 已同步到最新")
    finally:
        await _cleanup_groups(alice, group_ids)
        await alice.close()
        await bob_seed.close()
        await bob.close()


async def test_event_online_unread_chains_next_group() -> None:
    rid = uuid.uuid4().hex[:10]
    slot_id = f"online-evt-{rid}"
    alice = _make_client()
    bob_seed = _make_client()
    bob = _make_client()
    group_ids: list[str] = []
    changes: list[dict[str, Any]] = []

    try:
        await _connect(alice, _ALICE_AID, slot_id=f"alice-evt-{rid}", background_sync=False)
        await _connect(bob_seed, _BOB_AID, slot_id=slot_id, background_sync=False)
        for index in range(2):
            group_ids.append(await _create_group_with_bob(alice, bob_seed, f"online-unread-evt-{rid}-{index}"))
        expected = set(group_ids)
        _ok("事件用例预建两个群和 Bob cursor")

        await bob_seed.disconnect()
        for index, group_id in enumerate(group_ids):
            await alice.call("group.update", {
                "group_id": group_id,
                "description": f"online-unread-event-{rid}-{index}",
            })
            await asyncio.sleep(0.2)
        _ok("Bob 离线期间制造两个群的未读事件")

        bob.on("group.changed", lambda data: changes.append(data) if isinstance(data, dict) and data.get("group_id") in expected and data.get("action") == "update" else None)
        await _connect(bob, _BOB_AID, slot_id=slot_id, background_sync=True)
        await _wait_for("两个群的未读事件均被处理", lambda: expected.issubset(_group_ids(changes)), timeout=35.0)
        await _wait_cursor_synced(bob, group_ids, "event_cursor", timeout=20.0)
        _ok("事件在线续拉后公开 cursor 已同步到最新")
    finally:
        await _cleanup_groups(alice, group_ids)
        await alice.close()
        await bob_seed.close()
        await bob.close()


async def _run_test(name: str, func: Callable[[], Any]) -> None:
    print(f"\n=== {name} ===")
    try:
        await func()
    except Exception as exc:
        _fail(name, str(exc))
        import traceback
        traceback.print_exc()


async def main() -> None:
    print("=== group online unread 链式续拉 E2E ===\n")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOB_AID}")
    await _run_test("消息 hint -> pull -> ack -> next hint", test_message_online_unread_chains_next_group)
    await _run_test("事件 hint -> ack -> next hint", test_event_online_unread_chains_next_group)

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
