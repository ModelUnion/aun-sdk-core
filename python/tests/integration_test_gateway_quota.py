#!/usr/bin/env python3
"""Gateway 长连接配额 + 短连接 idle TTL 集成测试。

覆盖以下场景（默认 limit=10）：

  Test 1: (aid, device, slot) — 同 aid+device、11 个不同 slot 长连接
          → 第 11 个进入时第 1 个被踢，detail.quota_kind=aid_device_slot_quota_exceeded
  Test 2: aid → device 数 — 同 aid、11 个不同 device 各 1 个长连接
          → 第 11 个 device 进入时第 1 个 device 被踢，detail.quota_kind=aid_devices_quota_exceeded
  Test 3: device → aid 数 — 同 device、11 个不同 aid 各 1 个长连接
          → 第 11 个 aid 进入时第 1 个 aid 被踢，detail.quota_kind=device_aids_quota_exceeded
  Test 4: 短连接 idle TTL 滑动窗口 — 持续 RPC 保活不被踢，停止 RPC ~2s 后被 4014 踢

使用方法（容器内运行）：
  MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_gateway_quota.py

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
from aun_core.errors import AUNError

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_quota"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"

# 默认配额（与 GATEWAY_LONG_*_QUOTA 默认值一致）。不要假设可改。
_QUOTA_LIMIT = 10


def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _make_aun_path(tag: str, *, device_id: str | None = None) -> str:
    """为某个角色分配独立 aun_path。可选预写 .device_id 以指定设备 ID。"""
    root = Path(_TEST_AUN_PATH).parent / f"qta_{tag}_{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    if device_id is not None:
        (root / ".device_id").write_text(device_id, encoding="utf-8")
    return str(root)


def _make_client(tag_or_path: str, *, is_path: bool = False,
                 device_id: str | None = None) -> AUNClient:
    """创建测试客户端。
    - is_path=False：tag_or_path 是 tag，自动新建独立 aun_path
    - is_path=True：tag_or_path 是已有 aun_path，多个 client 共享 keystore
    - device_id：仅 is_path=False 时生效，预写 .device_id 让客户端使用指定设备 ID
    """
    if is_path:
        root = tag_or_path
    else:
        root = _make_aun_path(tag_or_path, device_id=device_id)
    client = AUNClient({"aun_path": root}, debug=False)
    client._config_model.require_forward_secrecy = False
    return client


async def _connect_long(client: AUNClient, aid: str, *, slot_id: str = "") -> str:
    await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    opts: dict = {"auto_reconnect": False, "heartbeat_interval": 30.0}
    if slot_id:
        opts["slot_id"] = slot_id
    await client.connect(auth, opts)
    return aid


async def _connect_short(client: AUNClient, aid: str, *,
                         slot_id: str = "",
                         short_ttl_ms: int = 0) -> str:
    """短连接（aid 必须已注册）。"""
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
# 工具：监听某个 client 的 disconnect 信息
# ---------------------------------------------------------------------------

class _DisconnectWatcher:
    """订阅一个 client 的 gateway.disconnect 事件并缓存最近一次 detail。"""

    def __init__(self, client: AUNClient, label: str = ""):
        self.label = label
        self.events: list[dict] = []
        self.kicked = asyncio.Event()
        client.on("gateway.disconnect", self._on)

    def _on(self, data) -> None:
        if isinstance(data, dict):
            self.events.append(data)
            self.kicked.set()

    @property
    def last_code(self) -> int | None:
        if not self.events:
            return None
        v = self.events[-1].get("code")
        return int(v) if isinstance(v, int) else None

    @property
    def last_detail(self) -> dict:
        if not self.events:
            return {}
        d = self.events[-1].get("detail")
        return d if isinstance(d, dict) else {}

    @property
    def last_quota_kind(self) -> str:
        return str(self.last_detail.get("quota_kind") or "")


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
# Test 1: (aid, device) → slot 数超限 → 4015 + aid_device_slot_quota_exceeded
# ---------------------------------------------------------------------------

async def test_aid_device_slot_quota() -> bool:
    name = f"Test 1: (aid,device) → slot count > {_QUOTA_LIMIT} → 4015"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"qta-s1-{rid}.{_ISSUER}"

    # 同 aun_path → 同 device_id → 同 keystore（同 aid 同私钥）
    shared_path = _make_aun_path("s1")
    setup = _make_client(shared_path, is_path=True)
    clients: list[AUNClient] = []
    watchers: list[_DisconnectWatcher] = []
    try:
        await setup.auth.create_aid({"aid": aid})
        await setup.close()

        # 建 _QUOTA_LIMIT 个长连接（不同 slot 名）
        for i in range(_QUOTA_LIMIT):
            c = _make_client(shared_path, is_path=True)
            w = _DisconnectWatcher(c, f"slot-{i}")
            clients.append(c)
            watchers.append(w)
            await _connect_long(c, aid, slot_id=f"slot-{i}")
            # 每个连接 created_at 拉开间隔，确保最早的是 slot-0
            await asyncio.sleep(0.15)
        print(f"  [OK] {_QUOTA_LIMIT} long connections established (slot-0 .. slot-{_QUOTA_LIMIT-1})")

        # 第 _QUOTA_LIMIT+1 个 slot 进入 → 第 0 个应被踢
        overflow = _make_client(shared_path, is_path=True)
        clients.append(overflow)
        watchers.append(_DisconnectWatcher(overflow, "slot-NEW"))
        await _connect_long(overflow, aid, slot_id="slot-NEW")

        # 等待 slot-0 收到 4015
        try:
            await asyncio.wait_for(watchers[0].kicked.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            _fail(name, f"slot-0 did not receive disconnect; events={watchers[0].events}")
            return False

        if watchers[0].last_code != 4015:
            _fail(name, f"slot-0 close code != 4015, got {watchers[0].last_code}, detail={watchers[0].last_detail}")
            return False
        kind = watchers[0].last_quota_kind
        if kind != "aid_device_slot_quota_exceeded":
            _fail(name, f"slot-0 quota_kind={kind}, expected aid_device_slot_quota_exceeded; detail={watchers[0].last_detail}")
            return False
        print(f"  [OK] slot-0 evicted: code=4015 detail={watchers[0].last_detail}")

        # slot-1..slot-9 应仍然在线
        for i in range(1, _QUOTA_LIMIT):
            if clients[i].state != "connected":
                _fail(name, f"slot-{i} unexpectedly kicked, state={clients[i].state}, events={watchers[i].events}")
                return False
        # overflow 应连接成功
        if overflow.state != "connected":
            _fail(name, f"overflow new slot not connected, state={overflow.state}")
            return False
        print(f"  [OK] all other slots survive, overflow connected")
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in clients:
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 2: aid → device 数超限 → 4015 + aid_devices_quota_exceeded
# ---------------------------------------------------------------------------

async def test_aid_devices_quota() -> bool:
    name = f"Test 2: aid → device count > {_QUOTA_LIMIT} → 4015"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"qta-d2-{rid}.{_ISSUER}"

    # 思路：所有 client 共享同一 aun_path（共享 keystore，同私钥），
    # 但每次 connect 前覆写 .device_id 文件，让 client 在构造时读到不同的 device_id。
    shared_path = _make_aun_path("d2")
    device_id_file = Path(shared_path) / ".device_id"

    # 先在 device-0 创建 AID（cert 跟随 keystore，与 device_id 无关）
    device_id_file.write_text(f"qta-dev0-{rid}", encoding="utf-8")
    setup = _make_client(shared_path, is_path=True)
    clients: list[AUNClient] = []
    watchers: list[_DisconnectWatcher] = []
    try:
        await setup.auth.create_aid({"aid": aid})
        await setup.close()

        # 占满 _QUOTA_LIMIT 个不同 device 的长连接（同 aid，slot 任意但保持唯一以避开 slot 配额）
        for i in range(_QUOTA_LIMIT):
            dev_id = f"qta-dev{i}-{rid}"
            device_id_file.write_text(dev_id, encoding="utf-8")
            c = _make_client(shared_path, is_path=True)
            # 防御性校验：client 真的读到了我们写的 device_id
            if c._device_id != dev_id:
                _fail(name, f"client device_id mismatch: expected {dev_id}, got {c._device_id}")
                return False
            w = _DisconnectWatcher(c, f"dev-{i}")
            clients.append(c)
            watchers.append(w)
            await _connect_long(c, aid, slot_id=f"dev{i}-main")
            await asyncio.sleep(0.15)
        print(f"  [OK] {_QUOTA_LIMIT} devices established for aid={aid}")

        # 第 _QUOTA_LIMIT+1 个 device 进入
        new_dev = f"qta-devNEW-{rid}"
        device_id_file.write_text(new_dev, encoding="utf-8")
        overflow = _make_client(shared_path, is_path=True)
        if overflow._device_id != new_dev:
            _fail(name, f"overflow device_id mismatch: expected {new_dev}, got {overflow._device_id}")
            return False
        clients.append(overflow)
        watchers.append(_DisconnectWatcher(overflow, "dev-NEW"))
        await _connect_long(overflow, aid, slot_id="devNEW-main")

        try:
            await asyncio.wait_for(watchers[0].kicked.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            _fail(name, f"dev-0 did not receive disconnect; events={watchers[0].events}")
            return False

        if watchers[0].last_code != 4015:
            _fail(name, f"dev-0 close code != 4015, got {watchers[0].last_code}; detail={watchers[0].last_detail}")
            return False
        kind = watchers[0].last_quota_kind
        if kind != "aid_devices_quota_exceeded":
            _fail(name, f"dev-0 quota_kind={kind}, expected aid_devices_quota_exceeded; detail={watchers[0].last_detail}")
            return False
        print(f"  [OK] dev-0 evicted: code=4015 detail={watchers[0].last_detail}")

        # dev-1 .. dev-(N-1) 仍在线
        for i in range(1, _QUOTA_LIMIT):
            if clients[i].state != "connected":
                _fail(name, f"dev-{i} unexpectedly kicked, state={clients[i].state}, events={watchers[i].events}")
                return False
        if overflow.state != "connected":
            _fail(name, f"overflow not connected, state={overflow.state}")
            return False
        print(f"  [OK] other devices survive, overflow connected")
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in clients:
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 3: device → aid 数超限 → 4015 + device_aids_quota_exceeded
# ---------------------------------------------------------------------------

async def test_device_aids_quota() -> bool:
    name = f"Test 3: device → aid count > {_QUOTA_LIMIT} → 4015"
    print(f"\n=== {name} ===")
    rid = _rid()

    # 同 aun_path = 同 device_id = 同 keystore（多个 AID 私钥并存）
    shared_path = _make_aun_path("a3")
    aids: list[str] = []
    clients: list[AUNClient] = []
    watchers: list[_DisconnectWatcher] = []
    try:
        # 注册 _QUOTA_LIMIT+1 个 AID（共享 keystore）
        register = _make_client(shared_path, is_path=True)
        for i in range(_QUOTA_LIMIT + 1):
            aid = f"qta-a3-{i}-{rid}.{_ISSUER}"
            await register.auth.create_aid({"aid": aid})
            aids.append(aid)
        await register.close()

        # 占满 _QUOTA_LIMIT 个 aid 的长连接（同 device，每 aid 1 个 slot）
        for i in range(_QUOTA_LIMIT):
            c = _make_client(shared_path, is_path=True)
            w = _DisconnectWatcher(c, f"aid-{i}")
            clients.append(c)
            watchers.append(w)
            await _connect_long(c, aids[i], slot_id="main")
            await asyncio.sleep(0.15)
        print(f"  [OK] {_QUOTA_LIMIT} aids established on shared device")

        # 第 _QUOTA_LIMIT+1 个 aid 进入
        overflow = _make_client(shared_path, is_path=True)
        clients.append(overflow)
        watchers.append(_DisconnectWatcher(overflow, "aid-NEW"))
        await _connect_long(overflow, aids[_QUOTA_LIMIT], slot_id="main")

        try:
            await asyncio.wait_for(watchers[0].kicked.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            _fail(name, f"aid-0 did not receive disconnect; events={watchers[0].events}")
            return False

        if watchers[0].last_code != 4015:
            _fail(name, f"aid-0 close code != 4015, got {watchers[0].last_code}; detail={watchers[0].last_detail}")
            return False
        kind = watchers[0].last_quota_kind
        if kind != "device_aids_quota_exceeded":
            _fail(name, f"aid-0 quota_kind={kind}, expected device_aids_quota_exceeded; detail={watchers[0].last_detail}")
            return False
        print(f"  [OK] aid-0 evicted: code=4015 detail={watchers[0].last_detail}")

        # aid-1 .. aid-(N-1) 仍在线
        for i in range(1, _QUOTA_LIMIT):
            if clients[i].state != "connected":
                _fail(name, f"aid-{i} unexpectedly kicked, state={clients[i].state}, events={watchers[i].events}")
                return False
        if overflow.state != "connected":
            _fail(name, f"overflow not connected, state={overflow.state}")
            return False
        print(f"  [OK] other aids survive, overflow connected")
        _ok(name)
        return True
    except Exception as exc:
        _fail(name, f"unexpected: {exc!r}")
        return False
    finally:
        for c in clients:
            try:
                await c.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 4: 短连接 idle TTL 滑动窗口 — 保活不被踢，停活后被 4014 踢
# ---------------------------------------------------------------------------

async def test_short_ttl_sliding_window() -> bool:
    name = "Test 4: short_ttl_ms sliding window (heartbeat keeps alive, stop → 4014)"
    print(f"\n=== {name} ===")
    rid = _rid()
    aid = f"qta-t4-{rid}.{_ISSUER}"

    shared_path = _make_aun_path("t4")
    setup = _make_client(shared_path, is_path=True)
    short = _make_client(shared_path, is_path=True)
    watcher = _DisconnectWatcher(short, "short")
    try:
        await setup.auth.create_aid({"aid": aid})
        await setup.close()

        # 短连接 ttl=2000ms
        await _connect_short(short, aid, slot_id="t4-cli", short_ttl_ms=2000)
        if short.state != "connected":
            _fail(name, f"short connect failed, state={short.state}")
            return False
        print(f"  [OK] short connection established with ttl=2000ms")

        # 第一阶段：每 1s 发 1 个 RPC，共 5s（ttl=2s 内有活动 → 不应被踢）
        keepalive_window = 5.0
        deadline = time.time() + keepalive_window
        ping_count = 0
        while time.time() < deadline:
            await short.call("meta.ping")
            ping_count += 1
            await asyncio.sleep(1.0)
        if short.state != "connected":
            _fail(name, f"short kicked despite keepalive, state={short.state}, events={watcher.events}")
            return False
        if watcher.events:
            _fail(name, f"short received unexpected disconnect during keepalive: {watcher.events}")
            return False
        print(f"  [OK] survived {keepalive_window}s keepalive ({ping_count} pings)")

        # 第二阶段：停止 RPC，等待 idle TTL 触发关闭
        # 服务端 poll 间隔 max(0.2, min(ttl_ms/1000/4, 5)) = max(0.2, 0.5) = 0.5s
        # 所以最多 ttl(2s) + poll(0.5s) + 网络 + notify_and_close(0.2s 延迟) ≈ 3.5s
        try:
            await asyncio.wait_for(watcher.kicked.wait(), timeout=8.0)
        except asyncio.TimeoutError:
            _fail(name, f"short not kicked after idle, state={short.state}, events={watcher.events}")
            return False

        if watcher.last_code != 4014:
            _fail(name, f"close code != 4014, got {watcher.last_code}; detail={watcher.last_detail}")
            return False
        det = watcher.last_detail
        if int(det.get("ttl_ms") or 0) != 2000:
            _fail(name, f"detail.ttl_ms != 2000, detail={det}")
            return False
        if int(det.get("idle_ms") or 0) <= 0:
            _fail(name, f"detail.idle_ms not positive, detail={det}")
            return False
        print(f"  [OK] short idle-evicted: code=4014 detail={det}")

        # 短连接现在应处于 disconnected/terminal_failed
        # gateway.disconnect 通知先到，再等 ~200ms 才发 ws.close（_notify_and_close delay）
        # 给 transport 几秒时间处理关闭并触发状态迁移
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if short.state in ("disconnected", "closed", "terminal_failed"):
                break
            await asyncio.sleep(0.1)
        if short.state not in ("disconnected", "closed", "terminal_failed"):
            _fail(name, f"unexpected state after eviction: {short.state}")
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
    print("Gateway long-connection quota + short idle-TTL integration tests")
    print(f"AUN_TEST_AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER            = {_ISSUER}")
    print(f"QUOTA_LIMIT       = {_QUOTA_LIMIT} (gateway default)")
    print("=" * 64)

    tests = [
        ("(aid,device) → slot quota → 4015",   test_aid_device_slot_quota),
        ("aid → device quota → 4015",          test_aid_devices_quota),
        ("device → aid quota → 4015",          test_device_aids_quota),
        ("short idle TTL sliding window 4014", test_short_ttl_sliding_window),
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
