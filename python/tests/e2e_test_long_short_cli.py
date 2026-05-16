#!/usr/bin/env python3
"""长短连接 E2E 测试 — 同身份 (aid, device_id, slot_id) 共存场景。

核心拓扑：
  alice 长连接（daemon，常驻收件箱）+ alice 短连接（CLI，发件）共享同一 (aid, device, slot)。
  bob 长连接作为接收方。

E2E 场景列表：
  E2E 1: CLI 顺序发 5 条消息给 bob — RPC 原路返回短连接，bob 收齐，alice 长连接无感
  E2E 2: 5 个并发 CLI 短连接同时发 — 全部成功，bob 收齐
  E2E 3: bob 回复 alice — alice 长连接收到入站消息（验证长连接收件箱功能正常）
  E2E 4: CLI 异常退出（ttl 兜底）— alice 长连接不受影响，仍能收 bob 回复
  E2E 5: 短连接断开后 alice 长连接仍能收到新消息（验证短连接生命周期不影响长连接）

使用方法（必须在 kite-sdk-tester 容器内运行）：
  MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/e2e_test_long_short_cli.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT=/data/aun，AUN_TEST_AUN_PATH=/data/aun/single-domain/persistent
  - kite-app 已部署 gateway 长短连接改动
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

from aun_core import AUNClient
from aun_core.errors import AUNError

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_long_short_e2e"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"


def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _new_aun_path(tag: str) -> str:
    root = Path(_TEST_AUN_PATH).parent / f"e2e_{tag}_{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _make_client(aun_path: str) -> AUNClient:
    client = AUNClient({"aun_path": aun_path}, debug=False)
    client._config_model.require_forward_secrecy = False
    return client


# ---------------------------------------------------------------------------
# 计数
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"[PASS] {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    msg = f"{name}: {reason}"
    _errors.append(msg)
    print(f"[FAIL] {msg}")


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

async def _connect_long(client: AUNClient, aid: str, *, slot_id: str = "main") -> None:
    await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth, {"auto_reconnect": False, "heartbeat_interval": 30.0, "slot_id": slot_id})


async def _connect_short(client: AUNClient, aid: str, *, slot_id: str = "main",
                         short_ttl_ms: int = 0) -> None:
    auth = await client.auth.authenticate({"aid": aid})
    opts: dict = {"connection_kind": "short", "auto_reconnect": False, "slot_id": slot_id}
    if short_ttl_ms > 0:
        opts["short_ttl_ms"] = short_ttl_ms
    await client.connect(auth, opts)


# ---------------------------------------------------------------------------
# E2E 1: CLI 顺序发 5 条 — 同身份，RPC 原路返回，bob 收齐，alice 长连接无感
# ---------------------------------------------------------------------------

async def e2e_sequential_same_identity() -> bool:
    name = "E2E 1: same identity CLI sequential 5 sends"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"e2e1-a-{rid}.{_ISSUER}"
    bob_aid = f"e2e1-b-{rid}.{_ISSUER}"

    alice_path = _new_aun_path("e1-alice")
    bob_path = _new_aun_path("e1-bob")

    alice_long = _make_client(alice_path)
    bob_long = _make_client(bob_path)
    try:
        await _connect_long(alice_long, alice_aid)
        await _connect_long(bob_long, bob_aid)

        # alice 长连接监听（不应收到自己发出的消息）
        alice_unexpected: list = []
        alice_long.on("message.received", lambda d: alice_unexpected.append(d))

        # bob 监听
        bob_received: list = []
        bob_event = asyncio.Event()
        texts = [f"e2e1-msg-{i}-{rid}" for i in range(5)]

        def _bob_handler(data):
            if isinstance(data, dict):
                payload = data.get("payload") or {}
                if isinstance(payload, dict) and payload.get("text", "").startswith(f"e2e1-msg-"):
                    bob_received.append(data)
                    if len(bob_received) >= 5:
                        bob_event.set()

        bob_long.on("message.received", _bob_handler)

        # CLI 短连接顺序发 5 条（每次新建短连接，同 aid/device/slot）
        for text in texts:
            cli = _make_client(alice_path)
            try:
                await _connect_short(cli, alice_aid)
                result = await cli.call("message.send", {
                    "to": bob_aid,
                    "payload": {"type": "text", "text": text},
                })
                if not isinstance(result, dict) or result.get("status") not in {"sent", "delivered"}:
                    _fail(name, f"message.send failed: {result}")
                    return False
            finally:
                await cli.close()

        # 验证 bob 收齐
        try:
            await asyncio.wait_for(bob_event.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            _fail(name, f"bob received {len(bob_received)}/5 messages")
            return False

        received_texts = {m.get("payload", {}).get("text") for m in bob_received if isinstance(m, dict)}
        missing = set(texts) - received_texts
        if missing:
            _fail(name, f"bob missing: {missing}")
            return False
        print(f"  [OK] bob received all 5 messages")

        # 验证 alice 长连接无感
        await asyncio.sleep(2.0)
        if alice_unexpected:
            _fail(name, f"alice long received {len(alice_unexpected)} unexpected msgs")
            return False
        print(f"  [OK] alice long received nothing (same device+slot, no self-sync)")

        # 验证 alice 长连接仍活
        await alice_long.call("meta.ping")
        print(f"  [OK] alice long still alive")

        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (alice_long, bob_long):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# E2E 2: 5 个并发 CLI 短连接同时发（同身份）
# ---------------------------------------------------------------------------

async def e2e_concurrent_same_identity() -> bool:
    name = "E2E 2: same identity 5 concurrent CLI shorts"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"e2e2-a-{rid}.{_ISSUER}"
    bob_aid = f"e2e2-b-{rid}.{_ISSUER}"

    alice_path = _new_aun_path("e2-alice")
    bob_path = _new_aun_path("e2-bob")

    alice_long = _make_client(alice_path)
    bob_long = _make_client(bob_path)
    try:
        await _connect_long(alice_long, alice_aid)
        await _connect_long(bob_long, bob_aid)

        bob_received: list = []
        bob_event = asyncio.Event()

        def _bob_handler(data):
            if isinstance(data, dict):
                payload = data.get("payload") or {}
                if isinstance(payload, dict) and payload.get("text", "").startswith(f"e2e2-msg-"):
                    bob_received.append(data)
                    if len(bob_received) >= 5:
                        bob_event.set()

        bob_long.on("message.received", _bob_handler)

        # 5 个并发短连接（同 aid，不同 slot 避免容量冲突）
        async def _one(i: int) -> dict:
            cli = _make_client(alice_path)
            try:
                await _connect_short(cli, alice_aid, slot_id=f"cli-{i}")
                result = await cli.call("message.send", {
                    "to": bob_aid,
                    "payload": {"type": "text", "text": f"e2e2-msg-{i}-{rid}"},
                })
                return result if isinstance(result, dict) else {}
            finally:
                await cli.close()

        results = await asyncio.gather(*[_one(i) for i in range(5)], return_exceptions=True)
        bad = [r for r in results if isinstance(r, Exception)]
        if bad:
            _fail(name, f"{len(bad)} CLI failed: {bad[:2]!r}")
            return False
        for r in results:
            if not isinstance(r, dict) or r.get("status") not in {"sent", "delivered"}:
                _fail(name, f"unexpected result: {r}")
                return False
        print(f"  [OK] all 5 RPC responses returned to short connections")

        try:
            await asyncio.wait_for(bob_event.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            _fail(name, f"bob received {len(bob_received)}/5")
            return False
        print(f"  [OK] bob received all 5 messages")

        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (alice_long, bob_long):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# E2E 3: bob 回复 alice — alice 长连接收到入站消息（收件箱功能验证）
# ---------------------------------------------------------------------------

async def e2e_long_receives_inbound() -> bool:
    """验证 alice 长连接作为收件箱能正常收到 bob 发来的消息。
    这证明短连接的存在/退出不影响长连接的接收能力。"""
    name = "E2E 3: alice long receives bob's reply (inbox works)"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"e2e3-a-{rid}.{_ISSUER}"
    bob_aid = f"e2e3-b-{rid}.{_ISSUER}"

    alice_path = _new_aun_path("e3-alice")
    bob_path = _new_aun_path("e3-bob")

    alice_long = _make_client(alice_path)
    bob_long = _make_client(bob_path)
    try:
        await _connect_long(alice_long, alice_aid)
        await _connect_long(bob_long, bob_aid)

        # alice 先用短连接给 bob 发一条（建立 prekey 交换）
        cli = _make_client(alice_path)
        try:
            await _connect_short(cli, alice_aid)
            await cli.call("message.send", {
                "to": bob_aid,
                "payload": {"type": "text", "text": f"e2e3-init-{rid}"},
            })
        finally:
            await cli.close()

        await asyncio.sleep(1.0)

        # bob 回复 alice
        reply_text = f"e2e3-reply-{rid}"
        alice_received = asyncio.Event()
        alice_captured: list = []

        def _alice_handler(data):
            if isinstance(data, dict):
                payload = data.get("payload") or {}
                if isinstance(payload, dict) and payload.get("text") == reply_text:
                    alice_captured.append(data)
                    alice_received.set()

        alice_long.on("message.received", _alice_handler)

        result = await bob_long.call("message.send", {
            "to": alice_aid,
            "payload": {"type": "text", "text": reply_text},
        })
        if not isinstance(result, dict) or result.get("status") not in {"sent", "delivered"}:
            _fail(name, f"bob send failed: {result}")
            return False

        try:
            await asyncio.wait_for(alice_received.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            _fail(name, "alice long timed out waiting for bob's reply")
            return False

        if not alice_captured:
            _fail(name, "alice captured empty")
            return False
        print(f"  [OK] alice long received bob's reply: text={alice_captured[0].get('payload', {}).get('text')}")

        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (alice_long, bob_long):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# E2E 4: CLI 异常退出（ttl 兜底）— alice 长连接不受影响
# ---------------------------------------------------------------------------

async def e2e_cli_crash_long_unaffected() -> bool:
    """CLI 短连接不主动 close（模拟崩溃），ttl 兜底关闭。
    期间 alice 长连接仍能正常收 bob 的消息。"""
    name = "E2E 4: CLI crash + ttl, alice long still receives"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"e2e4-a-{rid}.{_ISSUER}"
    bob_aid = f"e2e4-b-{rid}.{_ISSUER}"

    alice_path = _new_aun_path("e4-alice")
    bob_path = _new_aun_path("e4-bob")

    alice_long = _make_client(alice_path)
    bob_long = _make_client(bob_path)
    cli_crash: AUNClient | None = None
    try:
        await _connect_long(alice_long, alice_aid)
        await _connect_long(bob_long, bob_aid)

        # CLI 短连接：建立但不 close（模拟崩溃），ttl=2s
        cli_crash = _make_client(alice_path)
        await _connect_short(cli_crash, alice_aid, short_ttl_ms=2000)
        if cli_crash.state != "connected":
            _fail(name, f"short connect failed: {cli_crash.state}")
            return False
        print(f"  [OK] CLI short connected with ttl=2000ms")

        # 等 ttl 触发
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if cli_crash.state in ("disconnected", "closed", "terminal_failed"):
                break
            await asyncio.sleep(0.3)
        if cli_crash.state == "connected":
            _fail(name, "CLI short still connected after ttl")
            return False
        print(f"  [OK] CLI short evicted by ttl (state={cli_crash.state})")

        # alice 长连接仍活
        await alice_long.call("meta.ping")
        print(f"  [OK] alice long still alive after CLI crash")

        # bob 给 alice 发消息 — alice 长连接应收到
        reply_text = f"e2e4-after-crash-{rid}"
        alice_received = asyncio.Event()
        alice_captured: list = []

        def _handler(data):
            if isinstance(data, dict):
                payload = data.get("payload") or {}
                if isinstance(payload, dict) and payload.get("text") == reply_text:
                    alice_captured.append(data)
                    alice_received.set()

        alice_long.on("message.received", _handler)

        await bob_long.call("message.send", {
            "to": alice_aid,
            "payload": {"type": "text", "text": reply_text},
        })

        try:
            await asyncio.wait_for(alice_received.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            _fail(name, "alice long timed out after CLI crash")
            return False
        print(f"  [OK] alice long received bob's message after CLI crash")

        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        if cli_crash is not None:
            try:
                await cli_crash.close()
            except Exception:
                pass
        for c in (alice_long, bob_long):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# E2E 5: 短连接断开后 alice 长连接仍能收新消息
# ---------------------------------------------------------------------------

async def e2e_long_survives_short_lifecycle() -> bool:
    """完整生命周期：CLI 短连接建立 → 发消息 → 断开 → alice 长连接继续收 bob 回复。
    验证短连接的整个生命周期不影响长连接的推送接收。"""
    name = "E2E 5: long survives full short lifecycle"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"e2e5-a-{rid}.{_ISSUER}"
    bob_aid = f"e2e5-b-{rid}.{_ISSUER}"

    alice_path = _new_aun_path("e5-alice")
    bob_path = _new_aun_path("e5-bob")

    alice_long = _make_client(alice_path)
    bob_long = _make_client(bob_path)
    try:
        await _connect_long(alice_long, alice_aid)
        await _connect_long(bob_long, bob_aid)

        # Phase 1: CLI 短连接发消息给 bob
        cli = _make_client(alice_path)
        try:
            await _connect_short(cli, alice_aid)
            result = await cli.call("message.send", {
                "to": bob_aid,
                "payload": {"type": "text", "text": f"e2e5-outbound-{rid}"},
            })
            if not isinstance(result, dict) or result.get("status") not in {"sent", "delivered"}:
                _fail(name, f"CLI send failed: {result}")
                return False
            print(f"  [OK] Phase 1: CLI short sent message to bob")
        finally:
            await cli.close()
            print(f"  [OK] Phase 1: CLI short disconnected")

        await asyncio.sleep(1.0)

        # Phase 2: bob 回复 alice — alice 长连接应收到
        reply_text = f"e2e5-reply-{rid}"
        alice_received = asyncio.Event()
        alice_captured: list = []

        def _handler(data):
            if isinstance(data, dict):
                payload = data.get("payload") or {}
                if isinstance(payload, dict) and payload.get("text") == reply_text:
                    alice_captured.append(data)
                    alice_received.set()

        alice_long.on("message.received", _handler)

        await bob_long.call("message.send", {
            "to": alice_aid,
            "payload": {"type": "text", "text": reply_text},
        })

        try:
            await asyncio.wait_for(alice_received.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            _fail(name, "alice long timed out waiting for bob's reply after short disconnected")
            return False
        print(f"  [OK] Phase 2: alice long received bob's reply after short lifecycle complete")

        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (alice_long, bob_long):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

async def main() -> int:
    print("=" * 64)
    print("Long+Short connection E2E — same identity (aid, device, slot)")
    print(f"AUN_TEST_AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER            = {_ISSUER}")
    print("=" * 64)

    tests = [
        ("same identity CLI sequential 5 sends",    e2e_sequential_same_identity),
        ("same identity 5 concurrent CLI shorts",   e2e_concurrent_same_identity),
        ("alice long receives bob's reply (inbox)",  e2e_long_receives_inbound),
        ("CLI crash + ttl, alice long still receives", e2e_cli_crash_long_unaffected),
        ("long survives full short lifecycle",       e2e_long_survives_short_lifecycle),
    ]

    results: list[tuple[str, bool]] = []
    for label, fn in tests:
        try:
            ok = await fn()
        except Exception as exc:
            print(f"[FAIL] {label}: unexpected outer exception: {exc!r}")
            ok = False
        results.append((label, ok))
        await asyncio.sleep(0.5)

    print("\n" + "=" * 64)
    print("Summary")
    print("=" * 64)
    for label, ok in results:
        print(f"  {'[PASS]' if ok else '[FAIL]'} {label}")
    if _errors:
        print("\nErrors:")
        for e in _errors:
            print(f"  - {e}")
    print(f"\nPassed: {_passed}, Failed: {_failed}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
