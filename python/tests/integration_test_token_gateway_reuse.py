#!/usr/bin/env python3
"""Token + gateway_url 复用集成测试（同 keystore 跨实例场景）。

验证 CLI 工具典型场景：每次启动 CLI 都创建新 AUNClient 但共享 aun_path。
第一次走完整 discovery + login，第二次开始直接复用 keystore 缓存。

用例：
  Test 1: 首次 authenticate 后 keystore 里有 access_token / refresh_token / gateway_url
  Test 2: 同 aun_path 重新 new client，authenticate 不发起任何网络调用直接返回
  Test 3: 复用 cached token 能直接 connect + meta.ping
  Test 4: cached token 过期时回退到完整 login

使用方法（必须在 kite-sdk-tester 容器内运行）：
  MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_token_gateway_reuse.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT=/data/aun
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

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_token_gw"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"


def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _new_aun_path(tag: str) -> str:
    root = Path(_TEST_AUN_PATH).parent / f"token_gw_{tag}_{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _make_client(aun_path: str) -> AUNClient:
    client = AUNClient({"aun_path": aun_path}, debug=False)
    client._config_model.require_forward_secrecy = False
    return client


_passed = 0
_failed = 0


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"[PASS] {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    print(f"[FAIL] {name}: {reason}")


# ── Test 1: 首次 authenticate 后 keystore 里写入了 token + gateway_url ────

async def test_first_authenticate_persists_token_and_gateway() -> bool:
    name = "Test 1: first authenticate persists token + gateway_url"
    print(f"\n=== {name} ===")
    aid = f"tgw-t1-{_rid()}.{_ISSUER}"
    path = _new_aun_path("t1")

    client = _make_client(path)
    try:
        await client.auth.create_aid({"aid": aid})
        result = await client.auth.authenticate({"aid": aid})

        if not result.get("access_token"):
            _fail(name, "authenticate returned no access_token")
            return False

        # 验证 keystore 里有 access_token
        identity = client._auth.load_identity_or_none(aid)
        if not identity or not identity.get("access_token"):
            _fail(name, "keystore did not persist access_token")
            return False

        # 验证 keystore 里有 gateway_url
        cached_gw = client.auth._load_cached_gateway_url(aid)
        if not cached_gw:
            _fail(name, "keystore did not persist gateway_url")
            return False

        print(f"  [OK] access_token persisted (length={len(identity['access_token'])})")
        print(f"  [OK] gateway_url persisted: {cached_gw}")
        _ok(name)
        return True
    finally:
        try:
            await client.close()
        except Exception:
            pass


# ── Test 2: 第二次 new client (同 aun_path) authenticate 不走网络 ────────

async def test_second_authenticate_reuses_cached_no_network() -> bool:
    name = "Test 2: second authenticate (same aun_path) skips network"
    print(f"\n=== {name} ===")
    aid = f"tgw-t2-{_rid()}.{_ISSUER}"
    path = _new_aun_path("t2")

    # 第一次：完整流程
    client1 = _make_client(path)
    try:
        await client1.auth.create_aid({"aid": aid})
        first = await client1.auth.authenticate({"aid": aid})
        first_token = first.get("access_token")
        first_gw = first.get("gateway")
    finally:
        await client1.close()

    # 第二次：新 client 同 aun_path（模拟 CLI 重启）
    client2 = _make_client(path)
    try:
        # 拦截 _login（不应被调用）+ discovery（不应被调用）
        login_calls = []
        discover_calls = []

        original_login = client2._auth._login
        async def _login_intercept(*args, **kwargs):
            login_calls.append(args)
            return await original_login(*args, **kwargs)
        client2._auth._login = _login_intercept

        original_discover = client2._discovery.discover
        async def _discover_intercept(*args, **kwargs):
            discover_calls.append(args)
            return await original_discover(*args, **kwargs)
        client2._discovery.discover = _discover_intercept

        second = await client2.auth.authenticate({"aid": aid})

        # 验证 token 一致（说明复用，没重新 login）
        if second.get("access_token") != first_token:
            _fail(name, f"second token differs from first (login was triggered)")
            return False

        # 验证 _login 没被调用
        if login_calls:
            _fail(name, f"_login was called {len(login_calls)} times (should be 0)")
            return False

        # 验证 discover 没被调用
        if discover_calls:
            _fail(name, f"discover was called {len(discover_calls)} times (should be 0)")
            return False

        # 验证 gateway 也复用了
        if second.get("gateway") != first_gw:
            _fail(name, f"gateway differs: {first_gw} -> {second.get('gateway')}")
            return False

        print(f"  [OK] _login not called (cached token reused)")
        print(f"  [OK] discover not called (cached gateway_url reused)")
        print(f"  [OK] token + gateway match first call")
        _ok(name)
        return True
    finally:
        await client2.close()


# ── Test 3: 复用 cached 直接 connect + RPC 成功 ──────────────────────────

async def test_reused_cached_can_connect_and_rpc() -> bool:
    name = "Test 3: reused cached token connects and runs RPC"
    print(f"\n=== {name} ===")
    aid = f"tgw-t3-{_rid()}.{_ISSUER}"
    path = _new_aun_path("t3")

    # 第一次创建 + authenticate
    client1 = _make_client(path)
    try:
        await client1.auth.create_aid({"aid": aid})
        await client1.auth.authenticate({"aid": aid})
    finally:
        await client1.close()

    # 第二次：完全重新 new client，复用 keystore，直接 connect
    client2 = _make_client(path)
    try:
        auth = await client2.auth.authenticate({"aid": aid})
        await client2.connect(auth, {"auto_reconnect": False})

        if client2.state != "connected":
            _fail(name, f"connect failed, state={client2.state}")
            return False

        ping_result = await client2.call("meta.ping")
        if not isinstance(ping_result, dict):
            _fail(name, f"ping returned unexpected: {ping_result}")
            return False

        print(f"  [OK] reused cached → connect + ping success")
        _ok(name)
        return True
    finally:
        await client2.close()


# ── Test 4: cached token 过期时 fallback 到完整 login ────────────────────

async def test_expired_cached_falls_back_to_login() -> bool:
    name = "Test 4: expired cached token falls back to login"
    print(f"\n=== {name} ===")
    aid = f"tgw-t4-{_rid()}.{_ISSUER}"
    path = _new_aun_path("t4")

    # 第一次完整 authenticate
    client1 = _make_client(path)
    try:
        await client1.auth.create_aid({"aid": aid})
        first = await client1.auth.authenticate({"aid": aid})
        first_token = first.get("access_token")
    finally:
        await client1.close()

    # 手动把 keystore 里的 expires_at 改成已过期
    client_for_edit = _make_client(path)
    try:
        identity = client_for_edit._auth.load_identity_or_none(aid)
        identity["access_token_expires_at"] = int(time.time()) - 100  # 100s 前过期
        client_for_edit._auth._persist_identity(identity)
    finally:
        await client_for_edit.close()

    # 第二次：authenticate 应走完整 login（cached token 过期）
    client2 = _make_client(path)
    try:
        login_calls = []
        original_login = client2._auth._login
        async def _login_intercept(*args, **kwargs):
            login_calls.append(args)
            return await original_login(*args, **kwargs)
        client2._auth._login = _login_intercept

        second = await client2.auth.authenticate({"aid": aid})

        # 验证 _login 被调用了
        if not login_calls:
            _fail(name, "_login was NOT called even though cached token expired")
            return False

        # 验证拿到了新 token
        if second.get("access_token") == first_token:
            _fail(name, "got same expired token (refresh did not happen)")
            return False

        print(f"  [OK] cached expired → _login called {len(login_calls)} times → fresh token issued")
        _ok(name)
        return True
    finally:
        await client2.close()


# ── 主入口 ──────────────────────────────────────────────────────────────

async def main() -> int:
    print("=" * 64)
    print("Token + gateway_url reuse integration tests (CLI restart scenario)")
    print(f"AUN_TEST_AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER            = {_ISSUER}")
    print("=" * 64)

    tests = [
        ("first authenticate persists",            test_first_authenticate_persists_token_and_gateway),
        ("second authenticate reuses cached",      test_second_authenticate_reuses_cached_no_network),
        ("reused cached connects and RPC",         test_reused_cached_can_connect_and_rpc),
        ("expired cached falls back to login",     test_expired_cached_falls_back_to_login),
    ]

    for label, fn in tests:
        try:
            await fn()
        except Exception as exc:
            _fail(label, f"unexpected: {exc!r}")
        await asyncio.sleep(0.3)

    print("\n" + "=" * 64)
    print(f"Passed: {_passed}, Failed: {_failed}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
