#!/usr/bin/env python3
"""Notify 单域集成测试。

运行环境：
  docker exec kite-sdk-tester python /tests/integration_test_notify.py

覆盖：
  - AID 在线 notify 实时投递
  - group notify 只通知在线群成员
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

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
    return "./.aun_test_notify"


_TEST_AUN_PATH = Path(os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip())
_BASE_PATH = _TEST_AUN_PATH.parent
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"

_passed = 0
_failed = 0
_errors: list[str] = []


def _rid() -> str:
    return uuid.uuid4().hex[:10]


def _make_client(tag: str) -> AUNClient:
    root = _BASE_PATH / f"notify-it-{tag}-{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    return make_client_for_path(str(root), debug=False, require_forward_secrecy=False)


async def _connect(client: AUNClient, aid: str, *, slot_id: str = "") -> None:
    options: dict[str, Any] = {"auto_reconnect": False}
    if slot_id:
        options["slot_id"] = slot_id
    await ensure_connected_identity(client, aid, connect_options=options)
    await asyncio.sleep(0.3)


async def _close_all(*clients: AUNClient) -> None:
    for client in clients:
        try:
            await client.close()
        except Exception:
            pass


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name}: {reason}")


def _subscribe_app_event(client: AUNClient, event: str, token: str):
    ready = asyncio.Event()
    inbox: list[dict[str, Any]] = []

    def _handler(payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        if payload.get("token") != token:
            return
        inbox.append(payload)
        ready.set()

    sub = client.on(event, _handler)
    return inbox, ready, sub


async def _wait_event(ready: asyncio.Event, inbox: list[dict[str, Any]], *, timeout: float = 8.0) -> dict[str, Any]:
    await asyncio.wait_for(ready.wait(), timeout=timeout)
    return inbox[-1]


async def test_aid_online_notify() -> bool:
    name = "AID 在线 notify 实时投递"
    rid = _rid()
    alice_aid = f"notify-a-{rid}.{_ISSUER}"
    bob_aid = f"notify-b-{rid}.{_ISSUER}"
    token = f"aid-{rid}"
    alice = _make_client("aid-alice")
    bob = _make_client("aid-bob")
    try:
        await _connect(alice, alice_aid, slot_id=f"alice-{rid}")
        await _connect(bob, bob_aid, slot_id=f"bob-{rid}")

        inbox, ready, sub = _subscribe_app_event(bob, "app.typing", token)
        try:
            await alice.notify(
                "event/app.typing",
                {"token": token, "thread_id": f"thread-{rid}"},
                to=bob_aid,
                ttl_ms=5000,
            )
            payload = await _wait_event(ready, inbox)
        finally:
            sub.unsubscribe()

        notify_meta = payload.get("_notify") if isinstance(payload.get("_notify"), dict) else {}
        if payload.get("thread_id") != f"thread-{rid}":
            _fail(name, f"payload 不匹配: {payload}")
            return False
        if notify_meta.get("from_aid") != alice_aid:
            _fail(name, f"_notify.from_aid 不匹配: {notify_meta}")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, repr(exc))
        return False
    finally:
        await _close_all(alice, bob)


async def test_group_online_notify() -> bool:
    name = "group notify 投递在线成员"
    rid = _rid()
    alice_aid = f"notify-ga-{rid}.{_ISSUER}"
    bob_aid = f"notify-gb-{rid}.{_ISSUER}"
    token = f"group-{rid}"
    alice = _make_client("group-alice")
    bob = _make_client("group-bob")
    try:
        await _connect(alice, alice_aid, slot_id=f"ga-{rid}")
        await _connect(bob, bob_aid, slot_id=f"gb-{rid}")

        created = await alice.call("group.create", {"name": f"notify-group-{rid}"})
        group_id = str((created.get("group") or {}).get("group_id") or "")
        if not group_id:
            _fail(name, f"group.create 未返回 group_id: {created}")
            return False
        await alice.call("group.add_member", {"group_id": group_id, "aid": bob_aid})
        await asyncio.sleep(1.0)

        inbox, ready, sub = _subscribe_app_event(bob, "app.presence", token)
        try:
            await alice.notify(
                "event/app.presence",
                {"token": token, "state": "active"},
                group_id=group_id,
            )
            payload = await _wait_event(ready, inbox)
        finally:
            sub.unsubscribe()

        if payload.get("state") != "active" or payload.get("group_id") != group_id:
            _fail(name, f"group notify payload 不匹配: {payload}")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, repr(exc))
        return False
    finally:
        await _close_all(alice, bob)


async def main() -> int:
    print("=" * 64)
    print("Notify 单域集成测试")
    print(f"AUN_TEST_AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER            = {_ISSUER}")
    print("=" * 64)

    tests = [test_aid_online_notify, test_group_online_notify]
    for test in tests:
        await test()

    print("\n" + "=" * 64)
    print(f"Passed: {_passed}, Failed: {_failed}")
    if _errors:
        print("Errors:")
        for item in _errors:
            print(f"  - {item}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
