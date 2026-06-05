#!/usr/bin/env python3
"""Notify 端到端边界测试。

运行环境：
  docker exec kite-sdk-tester python /tests/e2e_test_notify.py

覆盖：
  - device_id + slot_id 精确投递
  - 离线目标不存储，重连后不补发
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
from aun_refactor_helpers import ensure_connected_identity, ensure_registered_identity, make_client_for_path


_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_notify_e2e"


_TEST_AUN_PATH = Path(os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip())
_BASE_PATH = _TEST_AUN_PATH.parent
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"

_passed = 0
_failed = 0
_errors: list[str] = []


def _rid() -> str:
    return uuid.uuid4().hex[:10]


def _make_path(tag: str) -> str:
    root = _BASE_PATH / f"notify-e2e-{tag}-{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _make_client(path_or_tag: str, *, is_path: bool = False) -> AUNClient:
    root = path_or_tag if is_path else _make_path(path_or_tag)
    return make_client_for_path(root, debug=False, require_forward_secrecy=False)


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


def _subscribe(client: AUNClient, event: str, token: str):
    inbox: list[dict[str, Any]] = []
    ready = asyncio.Event()

    def _handler(payload: Any) -> None:
        if isinstance(payload, dict) and payload.get("token") == token:
            inbox.append(payload)
            ready.set()

    sub = client.on(event, _handler)
    return inbox, ready, sub


async def _maybe_wait(ready: asyncio.Event, *, timeout: float) -> bool:
    try:
        await asyncio.wait_for(ready.wait(), timeout=timeout)
        return True
    except asyncio.TimeoutError:
        return False


async def test_notify_targets_exact_slot() -> bool:
    name = "device_id + slot_id 精确投递"
    rid = _rid()
    alice_aid = f"notify-slot-a-{rid}.{_ISSUER}"
    bob_aid = f"notify-slot-b-{rid}.{_ISSUER}"
    bob_path = _make_path("slot-bob-shared")
    alice = _make_client("slot-alice")
    bob_target = _make_client(bob_path, is_path=True)
    bob_other = _make_client(bob_path, is_path=True)
    target_slot = f"target-{rid}"
    other_slot = f"other-{rid}"
    token = f"slot-{rid}"
    try:
        await _connect(alice, alice_aid, slot_id=f"alice-{rid}")
        await _connect(bob_target, bob_aid, slot_id=target_slot)
        await _connect(bob_other, bob_aid, slot_id=other_slot)

        current_aid = bob_target.current_aid
        device_id = str(getattr(current_aid, "device_id", "") or "")
        if not device_id:
            _fail(name, "无法读取目标 device_id")
            return False

        target_inbox, target_ready, target_sub = _subscribe(bob_target, "app.slot_probe", token)
        other_inbox, other_ready, other_sub = _subscribe(bob_other, "app.slot_probe", token)
        try:
            await alice.notify(
                "event/app.slot_probe",
                {"token": token, "slot": target_slot},
                to=bob_aid,
                device_id=device_id,
                slot_id=target_slot,
                ttl_ms=8000,
            )
            target_ok = await _maybe_wait(target_ready, timeout=8.0)
            other_ok = await _maybe_wait(other_ready, timeout=1.5)
        finally:
            target_sub.unsubscribe()
            other_sub.unsubscribe()

        if not target_ok or not target_inbox:
            _fail(name, "目标 slot 未收到 notify")
            return False
        if other_ok or other_inbox:
            _fail(name, f"非目标 slot 收到 notify: {other_inbox}")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, repr(exc))
        return False
    finally:
        await _close_all(alice, bob_target, bob_other)


async def test_offline_notify_is_not_stored() -> bool:
    name = "离线 notify 不存储不补发"
    rid = _rid()
    alice_aid = f"notify-off-a-{rid}.{_ISSUER}"
    bob_aid = f"notify-off-b-{rid}.{_ISSUER}"
    bob_path = _make_path("offline-bob")
    token = f"offline-{rid}"
    alice = _make_client("offline-alice")
    bob_setup = _make_client(bob_path, is_path=True)
    bob_late = _make_client(bob_path, is_path=True)
    try:
        await _connect(alice, alice_aid, slot_id=f"alice-{rid}")
        await ensure_registered_identity(bob_setup, bob_aid, slot_id=f"late-{rid}")
        await bob_setup.close()

        inbox, ready, sub = _subscribe(bob_late, "app.offline_probe", token)
        try:
            await alice.notify(
                "event/app.offline_probe",
                {"token": token, "phase": "while-offline"},
                to=bob_aid,
                ttl_ms=3000,
            )
            await _connect(bob_late, bob_aid, slot_id=f"late-{rid}")
            received = await _maybe_wait(ready, timeout=3.0)
        finally:
            sub.unsubscribe()

        if received or inbox:
            _fail(name, f"离线 notify 被补发: {inbox}")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, repr(exc))
        return False
    finally:
        await _close_all(alice, bob_setup, bob_late)


async def main() -> int:
    print("=" * 64)
    print("Notify 端到端边界测试")
    print(f"AUN_TEST_AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER            = {_ISSUER}")
    print("=" * 64)

    for test in (test_notify_targets_exact_slot, test_offline_notify_is_not_stored):
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
