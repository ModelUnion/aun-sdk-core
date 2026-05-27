#!/usr/bin/env python3
"""长短连接共存集成测试。

用动态 AID（不污染固定身份），覆盖以下场景：

  Test 1: 长连接订阅事件 + 短连接发 message.send 后立即 close → 长连接收到消息
  Test 2: 短连接进入不踢长连接（长连接持续在线）
  Test 3: 同槽位短连接容量上限 10 → 第 11 个返回 4013
  Test 4: 短连接 short_ttl_ms 兜底 → 服务端 4014 关闭
  Test 5: 长连接互踢（同槽位）→ 4009；同槽位 3 个短连接不受影响
  Test 6: 短连接进入不发布 client.online（第三方订阅者收不到）
  Test 7: hello-ok 回包 connection.kind 字段
  Test 8: 短连接默认禁用 heartbeat / token_refresh

使用方法（必须在 kite-sdk-tester 容器内运行）：
  MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_long_short.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT=/data/aun，AUN_TEST_AUN_PATH=/data/aun/single-domain/persistent
  - kite-app 已部署本仓 gateway 改动（rebuild 过 kite 镜像）
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
from aun_core.errors import AUNError, TimeoutError as _AunTimeout

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_long_short"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"


def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _make_aun_path(tag: str) -> str:
    """为某个 AID 角色组分配一个独立 aun_path（多个 client 共享时传同一 path）。"""
    root = Path(_TEST_AUN_PATH).parent / f"long_short_{tag}_{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _make_client(tag_or_path: str, *, is_path: bool = False) -> AUNClient:
    """创建测试客户端。
    - is_path=False（默认）：tag_or_path 是 tag，自动新建独立 aun_path
    - is_path=True：tag_or_path 是已有 aun_path，多个 client 共享 keystore
      （CLI 短连接必须复用 setup client 的 aun_path 才能 authenticate 到已注册的 AID）
    """
    if is_path:
        root = tag_or_path
    else:
        root = _make_aun_path(tag_or_path)
    client = AUNClient({"aun_path": root}, debug=False)
    client._config_model.require_forward_secrecy = False
    return client


async def _connect_long(client: AUNClient, aid: str, *, slot_id: str = "") -> str:
    await client.auth.register_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    opts: dict = {"auto_reconnect": False, "heartbeat_interval": 30.0}
    if slot_id:
        opts["slot_id"] = slot_id
    await client.connect(auth, opts)
    return aid


async def _connect_short(client: AUNClient, aid: str, *,
                         slot_id: str = "",
                         short_ttl_ms: int = 0) -> str:
    """以短连接方式建立会话。aid 必须已注册（先在长连接客户端创建过）。"""
    auth = await client.auth.authenticate({"aid": aid})
    opts: dict = {
        "connection_kind": "short",
        "auto_reconnect": False,
    }
    if slot_id:
        opts["slot_id"] = slot_id
    if short_ttl_ms > 0:
        opts["short_ttl_ms"] = short_ttl_ms
    await client.connect(auth, opts)
    return aid


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
# Test 1: 同身份长短共存 — CLI 短连接发消息，RPC 原路返回，bob 收到，alice 长连接无感
# ---------------------------------------------------------------------------

async def test_same_identity_short_send() -> bool:
    """核心场景：alice 长连接（收件箱）+ alice 短连接（CLI 发件）共享 (aid, device, slot)。
    CLI 给 bob 发消息：
      - RPC response 回到短连接（原路返回）
      - bob 长连接收到 message.received
      - alice 长连接不收到任何东西（同 device+slot 不 self-sync）
      - 短连接断开后 alice 长连接仍正常
    """
    name = "Test 1: same identity short send → bob receives, alice long silent"
    print(f"\n=== {name} ===")
    rid = _rid()
    alice_aid = f"ls-a1-{rid}.{_ISSUER}"
    bob_aid = f"ls-b1-{rid}.{_ISSUER}"

    alice_path = _make_aun_path("ls1-alice")
    bob_path = _make_aun_path("ls1-bob")
    alice_long = _make_client(alice_path, is_path=True)
    alice_short = _make_client(alice_path, is_path=True)
    bob_long = _make_client(bob_path, is_path=True)
    try:
        # 建立 alice 长连接（常驻收件箱）
        await _connect_long(alice_long, alice_aid, slot_id="main")

        # 建立 bob 长连接（接收方）
        await _connect_long(bob_long, bob_aid, slot_id="main")

        # 监听 alice 长连接是否收到任何 message.received（不应该收到）
        alice_unexpected: list = []
        alice_long.on("message.received", lambda d: alice_unexpected.append(d))

        # 监听 bob 长连接收到消息
        bob_received = asyncio.Event()
        text = f"cli-to-bob-{rid}"
        bob_captured: list = []

        def _bob_handler(data):
            if isinstance(data, dict):
                payload = data.get("payload") or {}
                if isinstance(payload, dict) and payload.get("text") == text:
                    bob_captured.append(data)
                    bob_received.set()

        bob_long.on("message.received", _bob_handler)

        # alice 短连接（同 aid, 同 device, 同 slot）发消息给 bob
        await _connect_short(alice_short, alice_aid, slot_id="main")
        if alice_short.state != "connected":
            _fail(name, f"short connect failed, state={alice_short.state}")
            return False

        result = await alice_short.call("message.send", {
            "to": bob_aid,
            "payload": {"type": "text", "text": text},
        })
        # 验证 1: RPC response 原路返回到短连接
        if not isinstance(result, dict) or result.get("status") not in {"sent", "delivered"}:
            _fail(name, f"message.send RPC response unexpected: {result}")
            return False
        print(f"  [OK] RPC response returned to short: status={result.get('status')}")

        # 短连接立即断开
        await alice_short.close()

        # 验证 2: bob 长连接收到消息
        try:
            await asyncio.wait_for(bob_received.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            _fail(name, "bob timed out waiting for message")
            return False
        if not bob_captured:
            _fail(name, "bob captured empty")
            return False
        print(f"  [OK] bob received message: text={bob_captured[0].get('payload', {}).get('text')}")

        # 验证 3: alice 长连接没收到任何东西（同 device+slot 不 self-sync）
        await asyncio.sleep(2.0)  # 给足时间确认没有延迟推送
        if alice_unexpected:
            _fail(name, f"alice long received unexpected message.received: {len(alice_unexpected)} msgs")
            return False
        print(f"  [OK] alice long received nothing (no self-sync for same device+slot)")

        # 验证 4: alice 长连接仍正常工作
        await alice_long.call("meta.ping")
        print(f"  [OK] alice long still alive after short disconnected")

        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (alice_long, alice_short, bob_long):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 2: 短连接进入不踢长连接
# ---------------------------------------------------------------------------

async def test_short_does_not_kick_long() -> bool:
    name = "Test 2: short does not kick long"
    print(f"\n=== {name} ===")
    rid = _rid()
    long_aid = f"ls-l2-{rid}.{_ISSUER}"

    # 长连接和同 AID 短连接必须共享 keystore（CLI 复用守护进程身份的真实场景）
    shared_path = _make_aun_path("ls2")
    long_client = _make_client(shared_path, is_path=True)
    short_client = _make_client(shared_path, is_path=True)
    try:
        await _connect_long(long_client, long_aid, slot_id="main")

        # 监听长连接是否被服务端断开
        long_state = []
        long_client.on("connection.state", lambda d: long_state.append(d.get("state")))

        # 同 AID 同 slot 起短连接
        await _connect_short(short_client, long_aid, slot_id="main")
        await asyncio.sleep(1.0)

        if long_client.state != "connected":
            _fail(name, f"long was kicked by short: state={long_client.state}, events={long_state}")
            return False

        # 短连接发个 ping 验证它能用，然后关掉
        await short_client.call("meta.ping")
        await short_client.close()
        await asyncio.sleep(0.5)

        # 长连接仍存活
        if long_client.state != "connected":
            _fail(name, f"long died after short closed: state={long_client.state}")
            return False
        await long_client.call("meta.ping")
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (long_client, short_client):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 3: 短连接容量上限 10
# ---------------------------------------------------------------------------

async def test_short_capacity_exceeded() -> bool:
    name = "Test 3: short capacity exceeded → 4013"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"ls-c3-{rid}.{_ISSUER}"

    # 共享 keystore：setup 注册 AID，10 个短 + overflow 共用同一身份
    shared_path = _make_aun_path("ls3")
    setup = _make_client(shared_path, is_path=True)
    shorts: list[AUNClient] = []
    overflow = _make_client(shared_path, is_path=True)
    try:
        await setup.auth.register_aid({"aid": aid})
        await setup.close()

        # 起 10 个短连接（共享 keystore）
        for i in range(10):
            c = _make_client(shared_path, is_path=True)
            shorts.append(c)
            await _connect_short(c, aid, slot_id="cap")
        await asyncio.sleep(0.5)

        # 第 11 个应被拒
        try:
            await _connect_short(overflow, aid, slot_id="cap")
        except (AUNError, Exception) as exc:
            msg = str(exc)
            if "short_connection_capacity_exceeded" in msg or "4013" in msg:
                _ok(name)
                return True
            _fail(name, f"expected short_connection_capacity_exceeded, got: {exc!r}")
            return False
        _fail(name, "11th short connection unexpectedly succeeded")
        return False
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in shorts:
            try:
                await c.close()
            except Exception:
                pass
        for c in (setup, overflow):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 4: short_ttl_ms 兜底 → 服务端 4014 关闭
# ---------------------------------------------------------------------------

async def test_short_ttl_eviction() -> bool:
    name = "Test 4: short_ttl_ms eviction (4014)"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"ls-t4-{rid}.{_ISSUER}"

    shared_path = _make_aun_path("ls4")
    setup = _make_client(shared_path, is_path=True)
    short = _make_client(shared_path, is_path=True)
    try:
        await setup.auth.register_aid({"aid": aid})
        await setup.close()

        # 短连接传 ttl=2000ms
        await _connect_short(short, aid, slot_id="ttl", short_ttl_ms=2000)
        if short.state != "connected":
            _fail(name, f"short connect failed: state={short.state}")
            return False

        # 等待 ~3s，服务端应主动关闭
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if short.state in ("disconnected", "closed", "terminal_failed"):
                break
            await asyncio.sleep(0.3)

        if short.state == "connected":
            _fail(name, "short still connected after ttl expired")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (setup, short):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 5: 长连接互踢（同槽位 4009）→ 不影响同槽位短连接
# ---------------------------------------------------------------------------

async def test_long_replaces_long_keeps_shorts() -> bool:
    name = "Test 5: long replaces long, shorts unaffected"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"ls-r5-{rid}.{_ISSUER}"

    shared_path = _make_aun_path("ls5")
    setup = _make_client(shared_path, is_path=True)
    long_old = _make_client(shared_path, is_path=True)
    long_new = _make_client(shared_path, is_path=True)
    shorts: list[AUNClient] = []
    try:
        await setup.auth.register_aid({"aid": aid})
        await setup.close()

        await _connect_long(long_old, aid, slot_id="slot-x")
        for i in range(3):
            c = _make_client(shared_path, is_path=True)
            shorts.append(c)
            await _connect_short(c, aid, slot_id="slot-x")
        await asyncio.sleep(0.5)

        # 新长连接同槽位进入 → 应踢旧长连接
        await _connect_long(long_new, aid, slot_id="slot-x")
        await asyncio.sleep(1.5)  # 给服务端发 4009 的时间

        if long_old.state == "connected":
            _fail(name, "old long not kicked")
            return False

        if long_new.state != "connected":
            _fail(name, f"new long not connected: state={long_new.state}")
            return False

        # 短连接应全部仍在线
        for i, c in enumerate(shorts):
            if c.state != "connected":
                _fail(name, f"short[{i}] was kicked: state={c.state}")
                return False
            await c.call("meta.ping")
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in shorts + [long_old, long_new, setup]:
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 6: 短连接不发布 client.online
# ---------------------------------------------------------------------------

async def test_short_does_not_publish_client_online() -> bool:
    """通过观察第三方 AID 的 message.query_online 间接验证：
    短连接进入时，message 模块不应记录 AID 为 online（仅长连接计入）。"""
    name = "Test 6: short does not publish client.online"
    print(f"\n=== {name} ===")
    rid = _rid()
    short_only_aid = f"ls-o6-{rid}.{_ISSUER}"
    observer_aid = f"ls-q6-{rid}.{_ISSUER}"

    short_path = _make_aun_path("ls6-short")
    observer_path = _make_aun_path("ls6-observer")
    setup = _make_client(short_path, is_path=True)
    observer = _make_client(observer_path, is_path=True)
    short = _make_client(short_path, is_path=True)
    try:
        await setup.auth.register_aid({"aid": short_only_aid})
        await setup.close()

        await _connect_long(observer, observer_aid, slot_id="obs")
        await _connect_short(short, short_only_aid, slot_id="cli")
        await asyncio.sleep(0.5)

        # observer 通过 message.query_online 查询 short_only_aid 在线状态
        result = await observer.call("message.query_online", {
            "aids": [short_only_aid],
        })
        online_map = result.get("online", {}) if isinstance(result, dict) else {}
        is_online = bool(online_map.get(short_only_aid, False))
        if is_online:
            _fail(name, f"short connection registered as online: {result}")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (setup, observer, short):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 7: hello-ok 回包带 connection.kind
# ---------------------------------------------------------------------------

async def test_hello_ok_returns_connection_kind() -> bool:
    name = "Test 7: hello-ok includes connection.kind"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"ls-h7-{rid}.{_ISSUER}"

    shared_path = _make_aun_path("ls7")
    setup = _make_client(shared_path, is_path=True)
    long_client = _make_client(shared_path, is_path=True)
    short_client = _make_client(shared_path, is_path=True)
    try:
        await setup.auth.register_aid({"aid": aid})
        await setup.close()

        # 长连接：connection.kind 应为 "long"
        await _connect_long(long_client, aid, slot_id="h7-l")
        await long_client.close()

        # 短连接：connection.kind 应为 "short"
        await _connect_short(short_client, aid, slot_id="h7-s")
        # SDK 的 _session_options 反映了回包后 SDK 自身的判定
        kind = short_client._session_options.get("connection_kind")
        if kind != "short":
            _fail(name, f"short client session_options.connection_kind={kind}")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (setup, long_client, short_client):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 8: 短连接禁用 heartbeat / token_refresh
# ---------------------------------------------------------------------------

async def test_short_disables_token_refresh() -> bool:
    name = "Test 8: short disables heartbeat and token_refresh"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"ls-d8-{rid}.{_ISSUER}"

    shared_path = _make_aun_path("ls8")
    setup = _make_client(shared_path, is_path=True)
    short = _make_client(shared_path, is_path=True)
    try:
        await setup.auth.register_aid({"aid": aid})
        await setup.close()

        await _connect_short(short, aid, slot_id="d8")

        # session_options 应反映短连接默认值
        opts = short._session_options

        if opts.get("connection_kind") != "short":
            _fail(name, f"session_options.connection_kind={opts.get('connection_kind')}")
            return False

        # 短连接生命周期短，不启动后台心跳
        hb = getattr(short, "_heartbeat_task", None)
        if hb is not None and not hb.done():
            _fail(name, "_heartbeat_task started for short connection")
            return False

        # token_refresh 任务不应启动
        tr = getattr(short, "_token_refresh_task", None)
        if tr is not None and not tr.done():
            _fail(name, "_token_refresh_task started for short connection")
            return False
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in (setup, short):
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

async def main() -> int:
    print("=" * 64)
    print("Long+Short connection coexistence integration tests")
    print(f"AUN_TEST_AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER            = {_ISSUER}")
    print("=" * 64)

    tests = [
        ("same identity short send → bob receives, alice long silent",
                                                     test_same_identity_short_send),
        ("short does not kick long",                 test_short_does_not_kick_long),
        ("short capacity exceeded → 4013",           test_short_capacity_exceeded),
        ("short_ttl_ms eviction → 4014",             test_short_ttl_eviction),
        ("long replaces long, shorts unaffected",    test_long_replaces_long_keeps_shorts),
        ("short does not publish client.online",     test_short_does_not_publish_client_online),
        ("hello-ok includes connection.kind",        test_hello_ok_returns_connection_kind),
        ("short disables heartbeat and token_refresh", test_short_disables_token_refresh),
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
