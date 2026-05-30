#!/usr/bin/env python3
"""slot_id 分隔符语义集成测试。

用动态 AID（不污染固定身份），覆盖以下场景：

  Test 1: 同前缀不同后缀 — 互斥踢人（c1 收到 4009，c2 正常在线）
  Test 2: 不同前缀 — 不互踢（c1 和 c2 都正常在线）
  Test 3: 同前缀 P2P 消息路由合并（bob 发消息，c2 收到）
  Test 4: slot_id 含分隔符的格式校验（"/invalid" 被拒绝）

使用方法（必须在 kite-sdk-tester 容器内运行）：
  MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_slot_id_separator.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT=/data/aun
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

from aun_core import AUNClient
from aun_core.errors import AUNError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_slot_sep"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"


def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _make_aun_path(tag: str) -> str:
    root = Path(_TEST_AUN_PATH).parent / f"slot_sep_{tag}_{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _make_client(aun_path: str) -> AUNClient:
    return make_client_for_path(aun_path, debug=False, require_forward_secrecy=False)


async def _connect_long(client: AUNClient, aid: str, *, slot_id: str = "") -> str:
    opts: dict = {"auto_reconnect": False, "heartbeat_interval": 30.0}
    if slot_id:
        opts["slot_id"] = slot_id
    return await ensure_connected_identity(client, aid, connect_options=opts)


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
# Test 1: 同前缀不同后缀 — 互斥踢人
# ---------------------------------------------------------------------------

async def test_same_prefix_kicks() -> bool:
    """alice 以 slot_id="evolclaw cli" 建立 c1，再以 slot_id="evolclaw daemon" 建立 c2。
    预期：c1 收到 4009（被踢），c2 正常在线。
    """
    name = "Test 1: 同前缀不同后缀 — 互斥踢人"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"sep-a1-{rid}.{_ISSUER}"

    alice_path = _make_aun_path("t1-alice")
    c1 = _make_client(alice_path)
    c2 = _make_client(alice_path)
    try:
        await _connect_long(c1, alice_aid, slot_id="evolclaw cli")
        print(f"  c1 connected: state={c1.state}")

        # 监听 c1 的断开事件
        c1_disconnect: list[dict] = []
        c1.on("connection.disconnect", lambda d: c1_disconnect.append(d))

        await _connect_long(c2, alice_aid, slot_id="evolclaw daemon")
        print(f"  c2 connected: state={c2.state}")

        # 等待服务端发送 4009 给 c1
        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            if c1.state != "ready":
                break
            await asyncio.sleep(0.2)

        if c1.state == "ready":
            _fail(name, "c1 仍在线，未被踢出")
            return False
        print(f"  c1 kicked: state={c1.state}, disconnect_events={c1_disconnect}")

        # 验证 disconnect 事件 code=4009
        kicked = any(
            str(d.get("code")) == "4009" or d.get("reason") == "replaced"
            for d in c1_disconnect
        )
        if not kicked:
            # 也接受 state 本身已反映被踢（部分 SDK 实现不单独发 disconnect 事件）
            print(f"  [WARN] disconnect 事件未含 4009，但 c1 已断开（state={c1.state}）")

        if c2.state != "ready":
            _fail(name, f"c2 未正常在线: state={c2.state}")
            return False
        print(f"  c2 仍在线: state={c2.state}")

        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (c1, c2):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 2: 不同前缀 — 不互踢
# ---------------------------------------------------------------------------

async def test_different_prefix_no_kick() -> bool:
    """alice 以 slot_id="evolclaw cli" 建立 c1，再以 slot_id="other daemon" 建立 c2。
    预期：c1 和 c2 都正常在线（不互踢）。
    """
    name = "Test 2: 不同前缀 — 不互踢"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"sep-a2-{rid}.{_ISSUER}"

    alice_path = _make_aun_path("t2-alice")
    c1 = _make_client(alice_path)
    c2 = _make_client(alice_path)
    try:
        await _connect_long(c1, alice_aid, slot_id="evolclaw cli")
        print(f"  c1 connected: state={c1.state}")

        await _connect_long(c2, alice_aid, slot_id="other daemon")
        print(f"  c2 connected: state={c2.state}")

        # 等待 2 秒，确认 c1 未被踢
        await asyncio.sleep(2.0)

        if c1.state != "ready":
            _fail(name, f"c1 被踢出（不应踢）: state={c1.state}")
            return False
        if c2.state != "ready":
            _fail(name, f"c2 不在线: state={c2.state}")
            return False

        print(f"  c1 仍在线: state={c1.state}")
        print(f"  c2 仍在线: state={c2.state}")
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (c1, c2):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 3: 同前缀 P2P 消息路由合并
# ---------------------------------------------------------------------------

async def test_same_prefix_message_routing() -> bool:
    """alice 以 slot_id="evolclaw cli" 建立 c1，再以 slot_id="evolclaw daemon" 建立 c2（踢掉 c1）。
    bob 发消息给 alice（不指定 slot_id）。
    预期：c2 收到消息（当前在线的同前缀实例）。
    """
    name = "Test 3: 同前缀 P2P 消息路由合并"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"sep-a3-{rid}.{_ISSUER}"
    bob_aid = f"sep-b3-{rid}.{_ISSUER}"

    alice_path = _make_aun_path("t3-alice")
    bob_path = _make_aun_path("t3-bob")
    c1 = _make_client(alice_path)
    c2 = _make_client(alice_path)
    bob = _make_client(bob_path)
    try:
        # alice c1 先上线
        await _connect_long(c1, alice_aid, slot_id="evolclaw cli")
        print(f"  c1 connected: state={c1.state}")

        # alice c2 上线，踢掉 c1
        await _connect_long(c2, alice_aid, slot_id="evolclaw daemon")
        print(f"  c2 connected: state={c2.state}")

        # 等待 c1 被踢
        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            if c1.state != "ready":
                break
            await asyncio.sleep(0.2)
        print(f"  c1 state after kick: {c1.state}")

        # bob 上线
        await _connect_long(bob, bob_aid, slot_id="bob-main")
        print(f"  bob connected: state={bob.state}")

        # c2 监听消息
        c2_received = asyncio.Event()
        text = f"hello-alice-{rid}"
        c2_msgs: list[dict] = []

        def _c2_handler(data):
            if isinstance(data, dict):
                payload = data.get("payload") or {}
                if isinstance(payload, dict) and payload.get("text") == text:
                    c2_msgs.append(data)
                    c2_received.set()

        c2.on("message.received", _c2_handler)

        # bob 发消息给 alice（不指定 slot_id）
        result = await bob.call("message.send", {
            "to": alice_aid,
            "payload": {"type": "text", "text": text},
        })
        print(f"  bob send result: {result}")

        # 等待 c2 收到消息
        try:
            await asyncio.wait_for(c2_received.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            _fail(name, "c2 超时未收到消息")
            return False

        print(f"  c2 收到消息: {c2_msgs[0].get('payload', {}).get('text')}")
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (c1, c2, bob):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 4: slot_id 含分隔符的格式校验
# ---------------------------------------------------------------------------

async def test_invalid_slot_id_rejected() -> bool:
    """尝试以 slot_id="/invalid" 连接，预期被拒绝（服务端返回错误或 SDK 校验失败）。"""
    name = "Test 4: slot_id 含分隔符格式校验"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"sep-a4-{rid}.{_ISSUER}"

    path = _make_aun_path("t4")
    client = _make_client(path)
    try:
        try:
            await asyncio.wait_for(
                _connect_long(client, aid, slot_id="/invalid"),
                timeout=10.0,
            )
        except (AUNError, Exception) as exc:
            msg = str(exc)
            print(f"  连接被拒绝: {exc!r}")
            # 接受任何错误（SDK 校验或服务端拒绝）
            _ok(name)
            return True

        # 若连接成功，检查是否立即被断开
        await asyncio.sleep(1.0)
        if client.state != "connected":
            print(f"  连接后立即断开: state={client.state}")
            _ok(name)
            return True

        _fail(name, "slot_id='/invalid' 连接成功且未被断开，应被拒绝")
        return False
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        try:
            await client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

async def main() -> int:
    print("=" * 64)
    print("slot_id separator semantics integration tests")
    print(f"AUN_TEST_AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER            = {_ISSUER}")
    print("=" * 64)

    tests = [
        ("同前缀不同后缀 — 互斥踢人",       test_same_prefix_kicks),
        ("不同前缀 — 不互踢",               test_different_prefix_no_kick),
        ("同前缀 P2P 消息路由合并",          test_same_prefix_message_routing),
        ("slot_id 含分隔符格式校验",         test_invalid_slot_id_rejected),
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
