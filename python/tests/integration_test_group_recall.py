#!/usr/bin/env python3
"""群组消息撤回集成测试。

Python SDK 默认 V2-only：group.send encrypt=False 走明文（group_messages V1 行），
encrypt=True 走 V2 加密（v2_group_messages）。两者共享 per-group message_seq。

撤回后 SDK 把 tombstone 归一化为 group.message_recalled 事件（不在 pull 消息列表里出现），
并按 (group_id, message_ids, recalled_at) 去重，应用层只回调一次。

覆盖：
  test_group_recall_plaintext — 明文消息撤回（双 tombstone + SDK 事件去重）
  test_group_recall_encrypted — V2 加密消息撤回（密文删除 + tombstone 事件）
  test_group_recall_errors    — not_found / not_sender / already_recalled

运行（Docker 容器内）：
  python /tests/integration_test_group_recall.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_recall"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = f"alice.{_ISSUER}"
_BOBB_AID = f"bobb.{_ISSUER}"

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str, detail: str = ""):
    global _passed
    _passed += 1
    print(f"  [PASS] {name}{': ' + detail if detail else ''}")


def _fail(name: str, reason: str):
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} — {reason}")


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    await ensure_connected_identity(client, aid, connect_options={"auto_reconnect": False})


async def _close(*clients: AUNClient):
    for c in clients:
        try:
            await c.close()
        except Exception:
            pass


def _extract_msg(send_result: dict) -> tuple[str, int]:
    """兼容 V2 send（顶层 message_id/seq）和明文 send（message.{message_id,seq}）两种返回。"""
    if not isinstance(send_result, dict):
        return "", 0
    nested = send_result.get("message")
    if isinstance(nested, dict) and nested.get("message_id"):
        return str(nested.get("message_id")), int(nested.get("seq") or 0)
    return str(send_result.get("message_id") or ""), int(send_result.get("seq") or 0)


async def _create_group(client: AUNClient) -> str:
    result = await client.call("group.create", {
        "name": f"recall-{uuid.uuid4().hex[:8]}",
        "visibility": "private",
    })
    return (result.get("group") or {}).get("group_id", "")


async def _add_member(client: AUNClient, group_id: str, aid: str) -> None:
    await client.call("group.add_member", {"group_id": group_id, "aid": aid})


# ─────────────────────────────────────────────────────────────────────────────
# test_group_recall_plaintext: 明文消息撤回，bob 收到 group.message_recalled 事件一次
# ─────────────────────────────────────────────────────────────────────────────

async def test_group_recall_plaintext():
    print("\n── test_group_recall_plaintext ──")
    alice = _make_client()
    bob = _make_client()
    recall_events: list[dict] = []
    bob.on("group.message_recalled", lambda d: recall_events.append(d))

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice)
        if not group_id:
            _fail("create group", "group_id empty")
            return
        await _add_member(alice, group_id, _BOBB_AID)
        await asyncio.sleep(1.0)

        # 明文消息
        send_result = await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"recall-plain-{uuid.uuid4().hex[:8]}"},
            "encrypt": False,
        })
        msg_id, orig_seq = _extract_msg(send_result)
        if not msg_id:
            _fail("send plaintext msg", f"no message_id: {send_result}")
            return
        print(f"  sent msg_id={msg_id} seq={orig_seq}")
        await asyncio.sleep(0.5)

        # bob 先 pull 收一次，确保已读过原消息（这样它对应"已读客户端"路径）
        await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50, "force": True})
        await asyncio.sleep(0.3)

        # Alice 撤回
        recall_result = await alice.call("group.recall", {
            "group_id": group_id, "message_ids": [msg_id],
        })
        print(f"  recall_result recalled={recall_result.get('recalled')} errors={recall_result.get('errors')}")
        if msg_id not in (recall_result.get("recalled") or []):
            _fail("recall plaintext msg", f"not recalled: {recall_result}")
            return
        _ok("recall plaintext msg")

        # 等待 push 到达 + bob 再 pull 兜底
        await asyncio.sleep(1.0)
        await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50, "force": True})
        await asyncio.sleep(0.5)

        # SDK 去重：group.message_recalled 恰好一次
        if len(recall_events) == 1:
            _ok("SDK dedup one callback", f"message_ids={recall_events[0].get('message_ids')}")
            if msg_id in (recall_events[0].get("message_ids") or []):
                _ok("recall event carries original message_id")
            else:
                _fail("recall event carries original message_id", f"event={recall_events[0]}")
        elif len(recall_events) == 0:
            _fail("SDK dedup one callback", "no group.message_recalled callback received")
        else:
            _fail("SDK dedup one callback", f"expected 1 callback, got {len(recall_events)}: {recall_events}")

        # 验证服务端双 tombstone：用 raw_call 直查 group.v2.pull 原始消息
        # （V2-only SDK 的规范读取路径，会合并 group_messages 的 V1 明文行）
        raw = await bob._rpc().raw_call("group.v2.pull", {
            "group_id": group_id, "after_seq": 0, "limit": 50, "force": True,
            "device_id": bob.device_id, "slot_id": bob.slot_id,
        })
        raw_msgs = raw.get("messages", []) if isinstance(raw, dict) else []
        tombstones = [m for m in raw_msgs if str(m.get("type") or m.get("message_type") or "") == "group.message_recalled"]
        print(f"  raw tombstones: {[(m.get('seq'), m.get('message_id')) for m in tombstones]}")
        if len(tombstones) >= 2:
            _ok("server double tombstone", f"{len(tombstones)} tombstones")
        else:
            _fail("server double tombstone", f"expected >=2, got {len(tombstones)}")
        # 占位 tombstone 在 orig_seq
        if any(int(m.get("seq") or 0) == orig_seq for m in tombstones):
            _ok("placeholder tombstone at original seq")
        else:
            _fail("placeholder tombstone at original seq",
                  f"orig_seq={orig_seq}, seqs={[m.get('seq') for m in tombstones]}")

    except Exception as exc:
        _fail("test_group_recall_plaintext", str(exc))
        import traceback; traceback.print_exc()
    finally:
        await _close(alice, bob)


# ─────────────────────────────────────────────────────────────────────────────
# test_group_recall_errors: not_found / not_sender / already_recalled
# ─────────────────────────────────────────────────────────────────────────────

async def test_group_recall_errors():
    print("\n── test_group_recall_errors ──")
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice)
        await _add_member(alice, group_id, _BOBB_AID)
        await asyncio.sleep(1.0)

        # 1. not_found
        r1 = await alice.call("group.recall", {
            "group_id": group_id, "message_ids": [f"nonexistent-{uuid.uuid4().hex}"],
        })
        if any(e.get("error") == "not_found" for e in (r1.get("errors") or [])):
            _ok("not_found error")
        else:
            _fail("not_found error", f"errors={r1.get('errors')}")

        # 2. not_sender — Bob 撤 Alice 的明文消息
        send2 = await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "bob-cannot-recall"},
            "encrypt": False,
        })
        msg_id2, _ = _extract_msg(send2)
        await asyncio.sleep(0.3)
        r2 = await bob.call("group.recall", {"group_id": group_id, "message_ids": [msg_id2]})
        if any(e.get("error") == "not_sender" for e in (r2.get("errors") or [])):
            _ok("not_sender error")
        else:
            _fail("not_sender error", f"errors={r2.get('errors')}, recalled={r2.get('recalled')}")

        # 3. already_recalled — Alice 重复撤回
        send3 = await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "dup-recall"},
            "encrypt": False,
        })
        msg_id3, _ = _extract_msg(send3)
        await asyncio.sleep(0.3)
        r3a = await alice.call("group.recall", {"group_id": group_id, "message_ids": [msg_id3]})
        r3b = await alice.call("group.recall", {"group_id": group_id, "message_ids": [msg_id3]})
        if msg_id3 in (r3a.get("recalled") or []):
            _ok("first recall succeeds")
        else:
            _fail("first recall succeeds", f"result={r3a}")
        if any(e.get("error") == "already_recalled" for e in (r3b.get("errors") or [])):
            _ok("already_recalled on dup")
        else:
            _fail("already_recalled on dup", f"errors={r3b.get('errors')}, recalled={r3b.get('recalled')}")

        # 4. V2 加密消息重复撤回也应返回 already_recalled（#8 回归）
        #    V2 撤回会删原行、占位用新 mid，旧实现因 not_found 判定先于 already_recalled
        #    导致二次撤回误报 not_found。
        send4 = await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "v2-dup-recall"},
            "encrypt": True,
        })
        msg_id4, _ = _extract_msg(send4)
        await asyncio.sleep(0.5)
        r4a = await alice.call("group.recall", {"group_id": group_id, "message_ids": [msg_id4]})
        r4b = await alice.call("group.recall", {"group_id": group_id, "message_ids": [msg_id4]})
        if msg_id4 in (r4a.get("recalled") or []):
            _ok("V2 first recall succeeds")
        else:
            _fail("V2 first recall succeeds", f"result={r4a}")
        v2_dup_errs = [e.get("error") for e in (r4b.get("errors") or [])]
        if "already_recalled" in v2_dup_errs:
            _ok("V2 already_recalled on dup (not not_found)")
        else:
            _fail("V2 already_recalled on dup (not not_found)",
                  f"errors={r4b.get('errors')}, recalled={r4b.get('recalled')}")

        # 5. 全空白 message_ids 应被服务端干净拒绝（#4 回归），而非 SQL IN () 崩溃
        try:
            r5 = await alice.call("group.recall", {"group_id": group_id, "message_ids": ["", "  "]})
            # 若没抛错，至少不应 success 撤回任何消息
            if not (r5.get("recalled") or []):
                _ok("empty message_ids rejected cleanly", f"result={r5}")
            else:
                _fail("empty message_ids rejected cleanly", f"unexpected recalled: {r5}")
        except Exception as ex:
            # 业务级 ValueError（经 RPC 包装）属预期；不应是 DB 语法错误/500
            msg = str(ex).lower()
            if "in ()" in msg or "syntax" in msg or "1064" in msg:
                _fail("empty message_ids rejected cleanly", f"DB syntax error leaked: {ex}")
            else:
                _ok("empty message_ids rejected cleanly", f"business error: {type(ex).__name__}")

    except Exception as exc:
        _fail("test_group_recall_errors", str(exc))
        import traceback; traceback.print_exc()
    finally:
        await _close(alice, bob)


# ─────────────────────────────────────────────────────────────────────────────
# test_group_recall_encrypted: V2 加密消息撤回，密文删除 + tombstone 事件
# ─────────────────────────────────────────────────────────────────────────────

async def test_group_recall_encrypted():
    print("\n── test_group_recall_encrypted ──")
    alice = _make_client()
    bob = _make_client()
    recall_events_bob: list[dict] = []
    bob.on("group.message_recalled", lambda d: recall_events_bob.append(d))

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice)
        await _add_member(alice, group_id, _BOBB_AID)
        await asyncio.sleep(1.5)  # 等待 epoch + state commit

        text = f"enc-recall-{uuid.uuid4().hex[:8]}"
        send_result = await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": text},
            "encrypt": True,
        })
        msg_id, orig_seq = _extract_msg(send_result)
        if not msg_id:
            _fail("send encrypted msg", f"no message_id: {send_result}")
            return
        print(f"  enc msg_id={msg_id} seq={orig_seq}")

        # bob 收一次
        await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50, "force": True})
        await asyncio.sleep(0.5)

        # Alice 撤回
        recall_result = await alice.call("group.recall", {
            "group_id": group_id, "message_ids": [msg_id],
        })
        if msg_id in (recall_result.get("recalled") or []):
            _ok("recall encrypted msg")
        else:
            _fail("recall encrypted msg", f"result={recall_result}")
            return

        await asyncio.sleep(1.0)
        await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50, "force": True})
        await asyncio.sleep(0.5)

        # 服务端 raw 校验：密文已删，占位 tombstone 顶替
        raw = await bob._rpc().raw_call("group.v2.pull", {
            "group_id": group_id, "after_seq": 0, "limit": 50, "force": True,
        })
        raw_msgs = raw.get("messages", []) if isinstance(raw, dict) else []
        # 原始密文（envelope_json 且 message_id 匹配）不应再出现
        ciphertext_present = any(
            str(m.get("message_id") or "") == msg_id and m.get("envelope_json")
            for m in raw_msgs
        )
        tombstones = [m for m in raw_msgs if str(m.get("type") or m.get("message_type") or "") == "group.message_recalled"]
        if ciphertext_present:
            _fail("V2 ciphertext deleted", "original encrypted message still in v2.pull")
        else:
            _ok("V2 ciphertext deleted")
        if tombstones:
            _ok("V2 placeholder tombstone present", f"{len(tombstones)} tombstones")
        else:
            _fail("V2 placeholder tombstone present", f"no tombstone: seqs={[m.get('seq') for m in raw_msgs]}")

        # SDK 去重
        if len(recall_events_bob) <= 1:
            _ok("SDK dedup (<=1 callback)", f"count={len(recall_events_bob)}")
        else:
            _fail("SDK dedup", f"expected <=1, got {len(recall_events_bob)}")

    except Exception as exc:
        _fail("test_group_recall_encrypted", str(exc))
        import traceback; traceback.print_exc()
    finally:
        await _close(alice, bob)


# ─────────────────────────────────────────────────────────────────────────────
# test_group_recall_push_pull_recalled_at_consistency (#1):
#   在线 push 与 pull tombstone 的 recalled_at 必须一致，且在线成员只回调一次
# ─────────────────────────────────────────────────────────────────────────────

async def test_group_recall_push_pull_recalled_at_consistency():
    print("\n── test_group_recall_push_pull_recalled_at_consistency ──")
    alice = _make_client()
    bob = _make_client()
    recall_events: list[dict] = []
    raw_push_events: list[dict] = []
    bob.on("group.message_recalled", lambda d: recall_events.append(d))
    # 捕获服务端原始 push 事件，读取其 recalled_at
    try:
        bob.on("_raw.group.message_recalled", lambda d: raw_push_events.append(d))
    except Exception:
        pass

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        group_id = await _create_group(alice)
        await _add_member(alice, group_id, _BOBB_AID)
        await asyncio.sleep(1.0)

        send_result = await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"consistency-{uuid.uuid4().hex[:8]}"},
            "encrypt": False,
        })
        msg_id, orig_seq = _extract_msg(send_result)
        await asyncio.sleep(0.3)
        # bob 先读原消息，模拟在线已读成员
        await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50, "force": True})
        await asyncio.sleep(0.3)

        await alice.call("group.recall", {"group_id": group_id, "message_ids": [msg_id]})
        # 等 push 到达
        await asyncio.sleep(1.2)
        # 再 pull 兜底（即使已 ack，force pull 取回通知 tombstone）
        await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50, "force": True})
        await asyncio.sleep(0.5)

        # #1 核心：push 与 pull tombstone 的 recalled_at 一致 → SDK 只回调一次
        if len(recall_events) == 1:
            _ok("online member recall callback exactly once", f"count=1")
        else:
            _fail("online member recall callback exactly once",
                  f"expected 1, got {len(recall_events)} (push/pull recalled_at 可能不一致)")

        # 直接对比：raw push 的 recalled_at 应等于服务端 tombstone 的 recalled_at
        push_recalled_at = None
        for ev in raw_push_events:
            if msg_id in (ev.get("message_ids") or []):
                push_recalled_at = ev.get("recalled_at")
                break
        raw = await bob._rpc().raw_call("group.v2.pull", {
            "group_id": group_id, "after_seq": 0, "limit": 50, "force": True,
            "device_id": bob.device_id, "slot_id": bob.slot_id,
        })
        raw_msgs = raw.get("messages", []) if isinstance(raw, dict) else []
        tombstone_recalled_ats = set()
        for m in raw_msgs:
            if str(m.get("type") or m.get("message_type") or "") == "group.message_recalled":
                payload = m.get("payload") if isinstance(m.get("payload"), dict) else {}
                ra = payload.get("recalled_at") or m.get("recalled_at")
                if ra:
                    tombstone_recalled_ats.add(int(ra))
        print(f"  push_recalled_at={push_recalled_at} tombstone_recalled_ats={tombstone_recalled_ats}")
        if push_recalled_at is not None and tombstone_recalled_ats:
            if int(push_recalled_at) in tombstone_recalled_ats:
                _ok("push recalled_at == tombstone recalled_at")
            else:
                _fail("push recalled_at == tombstone recalled_at",
                      f"push={push_recalled_at} not in tombstones={tombstone_recalled_ats}")
        else:
            print(f"  [SKIP] 无法取到 push 或 tombstone recalled_at（push={push_recalled_at}）")

    except Exception as exc:
        _fail("test_group_recall_push_pull_recalled_at_consistency", str(exc))
        import traceback; traceback.print_exc()
    finally:
        await _close(alice, bob)


# ─────────────────────────────────────────────────────────────────────────────
# test_group_recall_late_joiner_not_notified (#3):
#   原消息之后才加入的成员，不应收到该消息被撤回的通知（泄漏旧消息存在）
# ─────────────────────────────────────────────────────────────────────────────

async def test_group_recall_late_joiner_not_notified():
    print("\n── test_group_recall_late_joiner_not_notified ──")
    alice = _make_client()
    bob = _make_client()
    bob_recall_events: list[dict] = []
    bob.on("group.message_recalled", lambda d: bob_recall_events.append(d))

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        group_id = await _create_group(alice)
        await asyncio.sleep(0.8)

        # Alice 先发消息（此时 bob 还没入群）
        send_result = await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"before-join-{uuid.uuid4().hex[:8]}"},
            "encrypt": False,
        })
        msg_id, orig_seq = _extract_msg(send_result)
        await asyncio.sleep(0.3)

        # 之后 bob 才加入（join_msg_seq >= orig_seq，原消息对其不可见）
        await _add_member(alice, group_id, _BOBB_AID)
        await asyncio.sleep(1.0)
        bob_recall_events.clear()

        # Alice 撤回那条 bob 看不到的旧消息
        await alice.call("group.recall", {"group_id": group_id, "message_ids": [msg_id]})
        await asyncio.sleep(1.2)
        # bob force pull 兜底
        await bob.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50, "force": True})
        await asyncio.sleep(0.5)

        # #3：bob 不应收到指向旧消息的撤回通知
        leaked = [e for e in bob_recall_events if msg_id in (e.get("message_ids") or [])]
        if not leaked:
            _ok("late joiner not notified of recall", f"callbacks={len(bob_recall_events)}")
        else:
            _fail("late joiner not notified of recall",
                  f"late joiner saw recall of pre-join msg: {leaked}")

        # pull 兜底也不应把该撤回 tombstone 投给 bob
        raw = await bob._rpc().raw_call("group.v2.pull", {
            "group_id": group_id, "after_seq": 0, "limit": 50, "force": True,
            "device_id": bob.device_id, "slot_id": bob.slot_id,
        })
        raw_msgs = raw.get("messages", []) if isinstance(raw, dict) else []
        leaked_tombstones = [
            m for m in raw_msgs
            if str(m.get("type") or m.get("message_type") or "") == "group.message_recalled"
            and msg_id in ((m.get("payload") or {}).get("message_ids") or [])
        ]
        if not leaked_tombstones:
            _ok("late joiner pull excludes pre-join recall tombstone")
        else:
            _fail("late joiner pull excludes pre-join recall tombstone",
                  f"leaked tombstones: {[(m.get('seq'), m.get('message_id')) for m in leaked_tombstones]}")

    except Exception as exc:
        _fail("test_group_recall_late_joiner_not_notified", str(exc))
        import traceback; traceback.print_exc()
    finally:
        await _close(alice, bob)


async def main():
    await test_group_recall_plaintext()
    await test_group_recall_errors()
    await test_group_recall_encrypted()
    await test_group_recall_push_pull_recalled_at_consistency()
    await test_group_recall_late_joiner_not_notified()

    print(f"\n{'='*50}")
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        print("失败项:")
        for e in _errors:
            print(f"  - {e}")
    if _failed:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
