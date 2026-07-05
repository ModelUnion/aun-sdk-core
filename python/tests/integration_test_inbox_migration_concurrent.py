#!/usr/bin/env python3
"""Docker 单域环境的 inbox 迁移并发 smoke 测试。

该测试在服务端 inbox 历史回填可能运行时验证正常 P2P 和 group 业务。
测试本身只使用公开 SDK/RPC API；新旧表落点由调用方用只读 MySQL 查询校验。
"""

import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from weakref import WeakKeyDictionary

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient  # noqa: E402
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path  # noqa: E402


_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_inbox_migration_concurrent"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
_CHARLIE_AID = os.environ.get("AUN_TEST_CHARLIE_AID", f"charlie.{_ISSUER}").strip()
_CLIENT_SLOT_IDS: WeakKeyDictionary[AUNClient, str] = WeakKeyDictionary()


def _make_client(tag: str) -> AUNClient:
    client = make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)
    _CLIENT_SLOT_IDS[client] = f"inbox-migration-{tag}-{uuid.uuid4().hex[:12]}"
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    slot_id = str(_CLIENT_SLOT_IDS.get(client, "") or "")
    options = {"auto_reconnect": False}
    if slot_id:
        options["slot_id"] = slot_id
    await ensure_connected_identity(client, aid, connect_options=options)


def _seq_of(msg: dict) -> int:
    try:
        return int(msg.get("seq") or 0)
    except (TypeError, ValueError):
        return 0


def _payload_text(msg: dict) -> str:
    payload = msg.get("payload")
    if isinstance(payload, dict):
        return str(payload.get("text") or payload.get("content") or "")
    return str(payload or "")


async def _current_message_max_seq(client: AUNClient, *, limit: int = 200) -> int:
    after_seq = 0
    max_seq = 0
    for _ in range(50):
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": limit})
        max_seq = max(
            max_seq,
            int(result.get("server_ack_seq") or 0),
            int(result.get("latest_seq") or 0),
        )
        for msg in result.get("messages", []) or []:
            max_seq = max(max_seq, _seq_of(msg))
        raw_count = int(result.get("raw_count") or 0)
        if raw_count <= 0 or max_seq <= after_seq:
            return max_seq
        after_seq = max_seq
    return max_seq


def _subscribe_p2p(client: AUNClient, from_aid: str, marker: str, *, after_seq: int):
    inbox: list[dict] = []
    event = asyncio.Event()

    def handler(data):
        if not isinstance(data, dict):
            return
        if str(data.get("from") or data.get("from_aid") or "") != from_aid:
            return
        if _seq_of(data) <= after_seq:
            return
        if _payload_text(data) != marker:
            return
        inbox.append(data)
        event.set()

    sub = client.on("message.received", handler)
    return inbox, event, sub


async def _wait_p2p_marker(client: AUNClient, from_aid: str, marker: str, *, after_seq: int) -> dict:
    inbox, event, sub = _subscribe_p2p(client, from_aid, marker, after_seq=after_seq)
    try:
        try:
            await asyncio.wait_for(event.wait(), timeout=8.0)
        except asyncio.TimeoutError:
            pass
        for msg in inbox:
            if _payload_text(msg) == marker:
                return msg
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": 100})
        for msg in result.get("messages", []) or []:
            if str(msg.get("from") or msg.get("from_aid") or "") == from_aid and _payload_text(msg) == marker:
                return msg
    finally:
        sub.unsubscribe()
    raise AssertionError(f"P2P marker not received: {marker}")


def _subscribe_group(client: AUNClient, group_id: str, sender_aid: str, marker: str):
    inbox: list[dict] = []
    event = asyncio.Event()

    def handler(data):
        if not isinstance(data, dict):
            return
        if data.get("group_id") != group_id:
            return
        sender = str(data.get("sender_aid") or data.get("from") or data.get("from_aid") or "")
        if sender != sender_aid:
            return
        if _payload_text(data) != marker:
            return
        inbox.append(data)
        event.set()

    sub = client.on("group.message_created", handler)
    return inbox, event, sub


async def _wait_group_marker(client: AUNClient, group_id: str, sender_aid: str, marker: str) -> dict:
    inbox, event, sub = _subscribe_group(client, group_id, sender_aid, marker)
    try:
        try:
            await asyncio.wait_for(event.wait(), timeout=8.0)
        except asyncio.TimeoutError:
            pass
        for msg in inbox:
            if _payload_text(msg) == marker:
                return msg
        result = await client.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 100})
        for msg in result.get("messages", []) or []:
            sender = str(msg.get("sender_aid") or msg.get("from") or msg.get("from_aid") or "")
            if sender == sender_aid and _payload_text(msg) == marker:
                return msg
    finally:
        sub.unsubscribe()
    raise AssertionError(f"group marker not received: {marker}")


async def main() -> None:
    marker = f"inbox-migration-{int(time.time())}-{uuid.uuid4().hex[:10]}"
    alice = _make_client("alice")
    bob = _make_client("bob")
    charlie = _make_client("charlie")
    try:
        print("[setup] connecting fixed identities")
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)

        print("[p2p] sending while backfill may be active")
        baseline = await _current_message_max_seq(bob)
        send_result = await alice.call("message.send", {
            "to": _BOB_AID,
            "payload": {"type": "text", "text": marker},
            "encrypt": True,
        })
        p2p_message_id = str(send_result.get("message_id") or "")
        if not p2p_message_id:
            raise AssertionError(f"message.send did not return message_id: {send_result}")
        p2p_msg = await _wait_p2p_marker(bob, _ALICE_AID, marker, after_seq=baseline)
        if _payload_text(p2p_msg) != marker:
            raise AssertionError("P2P payload mismatch")

        print("[group] sending plain group message while backfill may be active")
        group_result = await alice.call("group.create", {"name": f"Inbox Migration {marker}"})
        group_id = (group_result.get("group", {}) or {}).get("group_id") or group_result.get("group_id")
        if not group_id:
            raise AssertionError(f"group.create did not return group_id: {group_result}")
        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOB_AID})
        await alice.call("group.add_member", {"group_id": group_id, "aid": _CHARLIE_AID})
        await asyncio.sleep(1.5)
        group_send = await alice.call("group.send", {
            "group_id": group_id,
            "payload": marker,
            "encrypt": False,
        })
        group_message_id = str(group_send.get("message_id") or "")
        group_msg = await _wait_group_marker(bob, group_id, _ALICE_AID, marker)
        if _payload_text(group_msg) != marker:
            raise AssertionError("group payload mismatch")
        if not group_message_id:
            group_message_id = str(group_msg.get("message_id") or "")

        result = {
            "marker": marker,
            "p2p_message_id": p2p_message_id,
            "p2p_seq": _seq_of(p2p_msg),
            "group_id": group_id,
            "group_message_id": group_message_id,
            "group_seq": _seq_of(group_msg),
        }
        print("RESULT_JSON:" + json.dumps(result, ensure_ascii=False, sort_keys=True))
        print("[PASS] inbox migration concurrent SDK smoke")
    finally:
        await alice.close()
        await bob.close()
        await charlie.close()


if __name__ == "__main__":
    asyncio.run(main())
