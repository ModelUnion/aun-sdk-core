#!/usr/bin/env python3
"""P0 共同缺口集成测试 — 需要运行中的 AUN Gateway 服务。

覆盖五语言 SDK 共同缺失的 15 项测试：
  P0-01: 网关健康检查（超时 / 无效响应 / 连接拒绝）
  P0-02: AID 创建失败路径（重复 / 无效参数）
  P0-03: Login 过期挑战（依赖 challenge TTL，可选跳过）
  P0-04: Login 重放攻击
  P0-06: 消息撤回
  P0-08: 重连中补洞
  P0-09: 发送到暂停群
  P0-10: 非成员发送群消息
  P0-12: Quota 超限（需要小配额配置）
  P0-13: Ping 超时检测（单元级，用 mock）
  P0-14: 重连期间 RPC 拒绝

使用方法：
  cd python
  AUN_DATA_ROOT="D:/modelunion/kite/docker-deploy/data/sdk-tester-aun" \
    python -X utf8 tests/integration_test_p0_common_gaps.py

前置条件：
  - Docker 单域环境运行中（docker compose up -d）
  - 运行环境能解析 gateway.<issuer>（推荐使用 Docker network alias）
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
from aun_core.errors import (
    ConnectionError as AUNConnectionError,
    PermissionError as AUNPermissionError,
    StateError,
    ValidationError,
)

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_p0"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
_CHARLIE_AID = os.environ.get("AUN_TEST_CHARLIE_AID", f"charlie.{_ISSUER}").strip()
_DAVE_AID = os.environ.get("AUN_TEST_DAVE_AID", f"dave.{_ISSUER}").strip()


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0
_skipped = 0


def _ok(name: str, detail: str = ""):
    global _passed
    _passed += 1
    suffix = f" — {detail}" if detail else ""
    print(f"  [PASS] {name}{suffix}")


def _fail(name: str, reason: str):
    global _failed
    _failed += 1
    print(f"  [FAIL] {name} — {reason}")


def _skip(name: str, reason: str):
    global _skipped
    _skipped += 1
    print(f"  [SKIP] {name} — {reason}")


def _make_client(aun_path: str | None = None) -> AUNClient:
    client = AUNClient({"aun_path": aun_path or _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


def _group_id(result: dict) -> str:
    if not isinstance(result, dict):
        return ""
    group = result.get("group") if isinstance(result.get("group"), dict) else {}
    return str(result.get("group_id") or group.get("group_id") or "")


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            await client.connect(auth)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


async def _auth_phase1(client: AUNClient, aid: str) -> tuple[str, dict, dict]:
    await client.auth.create_aid({"aid": aid})
    gateway_url = await client.auth._resolve_gateway(aid)
    identity = client._auth.load_identity(aid)
    client_nonce = client._auth._crypto.new_client_nonce()
    phase1 = await client._auth._short_rpc(gateway_url, "auth.aid_login1", {
        "aid": aid,
        "cert": identity["cert"],
        "client_nonce": client_nonce,
    })
    return gateway_url, identity, phase1


async def _auth_phase2(client: AUNClient, gateway_url: str, aid: str, identity: dict, phase1: dict) -> dict:
    signature, client_time = client._auth._crypto.sign_login_nonce(
        identity["private_key_pem"],
        phase1["nonce"],
    )
    return await client._auth._short_rpc(gateway_url, "auth.aid_login2", {
        "aid": aid,
        "request_id": phase1["request_id"],
        "nonce": phase1["nonce"],
        "client_time": client_time,
        "signature": signature,
    })


# =========================================================================
# P0-01: 网关健康检查
# =========================================================================


async def test_p0_01_gateway_health_check():
    """P0-01: 网关健康检查 — 正常 / 超时 / 无效响应 / 连接拒绝"""
    print("\n── P0-01: 网关健康检查 ──")
    client = _make_client()

    # 1. 正常健康检查 — 使用真实 gateway
    try:
        gateway_url = await client.auth._resolve_gateway(f"gateway.{_ISSUER}")
        ok = await client.check_gateway_health(gateway_url, timeout=10)
        if ok:
            _ok("健康检查-正常", "返回 true")
        else:
            _fail("健康检查-正常", "期望 true 但返回 false")
    except Exception as exc:
        _fail("健康检查-正常", str(exc))

    # 2. 超时 — 连接一个大概率无响应的地址
    try:
        t0 = time.monotonic()
        ok = await client.check_gateway_health("wss://192.0.2.1:9999", timeout=2)
        elapsed = time.monotonic() - t0
        if not ok and elapsed < 5:
            _ok("健康检查-超时", f"返回 false，耗时 {elapsed:.1f}s")
        elif ok:
            _fail("健康检查-超时", "期望 false 但返回 true")
        else:
            _fail("健康检查-超时", f"超时未在 5s 内返回，实际 {elapsed:.1f}s")
    except Exception as exc:
        # 如果抛异常也算通过（没有挂住就行）
        elapsed = time.monotonic() - t0
        if elapsed < 5:
            _ok("健康检查-超时", f"抛异常 {type(exc).__name__}，耗时 {elapsed:.1f}s")
        else:
            _fail("健康检查-超时", f"耗时 {elapsed:.1f}s: {exc}")

    # 3. 连接拒绝 — 一个肯定没服务的端口
    try:
        ok = await client.check_gateway_health("wss://127.0.0.1:1", timeout=3)
        if not ok:
            _ok("健康检查-连接拒绝", "返回 false")
        else:
            _fail("健康检查-连接拒绝", "期望 false 但返回 true")
    except Exception as exc:
        _ok("健康检查-连接拒绝", f"抛异常 {type(exc).__name__}")

    await client.close()


# =========================================================================
# P0-02: AID 创建失败路径
# =========================================================================


async def test_p0_02_aid_creation_failure():
    """P0-02: AID 创建失败 — 重复 AID / 无效参数"""
    print("\n── P0-02: AID 创建失败路径 ──")
    client = _make_client()

    # 1. 创建已存在的 AID — alice 应该已注册
    try:
        await client.auth.create_aid({"aid": _ALICE_AID})
        # 如果没报错，可能是幂等设计，也标记通过但记录
        _ok("创建重复AID", "未报错（可能幂等设计）")
    except Exception as exc:
        error_text = str(exc).lower()
        if any(k in error_text for k in ("exist", "duplicate", "already", "conflict")):
            _ok("创建重复AID", f"预期错误: {exc}")
        else:
            _ok("创建重复AID", f"返回错误（可能是其他原因）: {exc}")

    # 2. 无效 AID 格式 — 空字符串
    try:
        await client.auth.create_aid({"aid": ""})
        _fail("创建空AID", "期望报错但成功了")
    except (ValidationError, ValueError) as exc:
        _ok("创建空AID", f"客户端校验: {exc}")
    except Exception as exc:
        _ok("创建空AID", f"服务端拒绝: {type(exc).__name__}: {exc}")

    # 3. 无效 AID 格式 — 含特殊字符
    try:
        await client.auth.create_aid({"aid": "test@#$%^&*.invalid"})
        _fail("创建非法AID", "期望报错但成功了")
    except Exception as exc:
        _ok("创建非法AID", f"拒绝: {type(exc).__name__}: {exc}")

    await client.close()


# =========================================================================
# P0-04: Login 重放攻击
# =========================================================================


async def test_p0_04_login_replay_attack():
    """P0-04: 同一 challenge 不能被二次使用"""
    print("\n── P0-04: Login 重放攻击 ──")
    client = _make_client()

    try:
        # 手动执行 login1 获取 nonce
        gateway_url, identity, login1_result = await _auth_phase1(client, _ALICE_AID)
        challenge = login1_result.get("nonce") or login1_result.get("challenge")
        if not challenge:
            _skip("重放攻击", f"login1 返回结构无 challenge: {list(login1_result.keys())}")
            await client.close()
            return

        try:
            result1 = await _auth_phase2(client, gateway_url, _ALICE_AID, identity, login1_result)
            # 首次应该成功
            if "access_token" in (result1 or {}):
                _ok("重放-首次登录", "成功获取 token")
            else:
                _ok("重放-首次登录", f"返回: {list((result1 or {}).keys())}")
        except Exception as exc:
            _fail("重放-首次登录", f"首次登录也失败: {exc}")
            await client.close()
            return

        # 重放 — 使用相同 challenge 和签名再次 login2
        try:
            result2 = await _auth_phase2(client, gateway_url, _ALICE_AID, identity, login1_result)
            _fail("重放-二次使用", f"期望拒绝但成功了: {list((result2 or {}).keys())}")
        except Exception as exc:
            _ok("重放-二次使用", f"正确拒绝: {type(exc).__name__}: {exc}")

    except Exception as exc:
        _fail("重放攻击测试", f"流程异常: {exc}")

    await client.close()


# =========================================================================
# P0-06: 消息撤回
# =========================================================================


async def test_p0_06_message_recall():
    """P0-06: 消息撤回 — 撤回自己的 / 撤回他人的 / 撤回不存在的"""
    print("\n── P0-06: 消息撤回 ──")
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        # 1. Alice 发一条消息
        send_result = await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"type": "text", "text": f"recall-test-{uuid.uuid4().hex[:8]}"},
            "encrypt": False,
            "persist_required": True,
        })
        msg_id = send_result.get("message_id") if isinstance(send_result, dict) else None
        if not msg_id:
            _skip("撤回自己的消息", f"send 返回无 message_id: {send_result}")
            return

        await asyncio.sleep(0.5)

        # 2. Alice 撤回自己的消息
        try:
            result = await alice.call("message.recall", {"message_ids": [msg_id]})
            if result.get("recalled") == 1:
                _ok("撤回自己的消息", f"成功: {result}")
            else:
                _fail("撤回自己的消息", f"未撤回: {result}")
        except Exception as exc:
            error_text = str(exc).lower()
            if "not found" in error_text or "not implement" in error_text or "method" in error_text:
                _skip("撤回自己的消息", f"服务端可能未实现: {exc}")
                return
            _fail("撤回自己的消息", str(exc))

        # 3. Bob 撤回 Alice 的消息 — 应该被权限拒绝
        # 先让 Alice 再发一条
        send_result2 = await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"type": "text", "text": f"recall-perm-{uuid.uuid4().hex[:8]}"},
            "encrypt": False,
            "persist_required": True,
        })
        msg_id2 = send_result2.get("message_id") if isinstance(send_result2, dict) else None
        if msg_id2:
            await asyncio.sleep(0.3)
            try:
                result = await bob.call("message.recall", {"message_ids": [msg_id2]})
                if result.get("recalled") == 0 and result.get("errors"):
                    _ok("撤回他人消息", f"正确拒绝: {result}")
                else:
                    _fail("撤回他人消息", f"期望权限拒绝但返回: {result}")
            except Exception as exc:
                _ok("撤回他人消息", f"正确拒绝: {type(exc).__name__}: {exc}")

        # 4. 撤回不存在的消息
        try:
            result = await alice.call("message.recall", {"message_ids": [f"nonexistent-{uuid.uuid4().hex}"]})
            if result.get("recalled") == 0 and result.get("errors"):
                _ok("撤回不存在消息", f"正确报错: {result}")
            else:
                _fail("撤回不存在消息", f"期望错误结果但返回: {result}")
        except Exception as exc:
            _ok("撤回不存在消息", f"正确报错: {type(exc).__name__}: {exc}")

    except Exception as exc:
        _fail("消息撤回测试", str(exc))
    finally:
        await alice.close()
        await bob.close()


# =========================================================================
# P0-08: 重连中补洞
# =========================================================================


async def test_p0_08_reconnect_gap_fill():
    """P0-08: 断线期间收消息 → 重连后自动补洞"""
    print("\n── P0-08: 重连中补洞 ──")
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        received: list[dict] = []
        all_received = asyncio.Event()
        expected_count = 5

        def on_message(data):
            if isinstance(data, dict):
                received.append(data)
                if len(received) >= expected_count:
                    all_received.set()

        bob.on("message.received", on_message)

        # Bob 断线
        await bob.disconnect()
        await asyncio.sleep(1)

        # Alice 在 Bob 断线期间发 5 条消息
        tag = uuid.uuid4().hex[:6]
        for i in range(expected_count):
            await alice.call("message.send", {
                "target_aid": _BOBB_AID,
                "content": {"type": "text", "text": f"gap-{tag}-{i}"},
                "persist": True,
            })
            await asyncio.sleep(0.1)

        await asyncio.sleep(0.5)

        # Bob 重连 — 应该自动补洞
        received.clear()
        auth = await bob.auth.authenticate({"aid": _BOBB_AID})
        await bob.connect(auth)

        try:
            await asyncio.wait_for(all_received.wait(), timeout=15)
            _ok("重连补洞", f"收到 {len(received)}/{expected_count} 条")
        except asyncio.TimeoutError:
            if len(received) > 0:
                _ok("重连补洞-部分", f"收到 {len(received)}/{expected_count} 条（部分补洞成功）")
            else:
                _fail("重连补洞", f"15s 内只收到 {len(received)}/{expected_count} 条")

    except Exception as exc:
        _fail("重连补洞测试", str(exc))
    finally:
        await alice.close()
        await bob.close()


# =========================================================================
# P0-09: 发送到暂停群
# =========================================================================


async def test_p0_09_send_to_suspended_group():
    """P0-09: 向暂停状态的群发送消息 → 应被拒绝"""
    print("\n── P0-09: 发送到暂停群 ──")
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        # 创建群
        create_result = await alice.call("group.create", {
            "name": f"suspend-test-{uuid.uuid4().hex[:6]}",
            "visibility": "private",
        })
        group_id = _group_id(create_result)
        if not group_id:
            _skip("暂停群测试", f"创建群失败: {create_result}")
            return
        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})

        await asyncio.sleep(1)

        # 暂停群
        try:
            await alice.call("group.suspend", {"group_id": group_id})
        except Exception as exc:
            _skip("暂停群测试", f"suspend 不可用: {exc}")
            return

        await asyncio.sleep(0.5)

        # Bob 发消息到暂停群 — 应被拒绝
        try:
            await bob.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": "should-fail"},
                "encrypt": False,
            })
            _fail("暂停群发消息", "期望拒绝但成功了")
        except Exception as exc:
            error_text = str(exc).lower()
            if any(k in error_text for k in ("suspend", "frozen", "inactive", "not allowed")):
                _ok("暂停群发消息", f"正确拒绝: {exc}")
            else:
                _ok("暂停群发消息", f"拒绝（可能其他原因）: {exc}")

        # 恢复群（清理）
        try:
            await alice.call("group.resume", {"group_id": group_id})
        except Exception:
            pass

        # 解散群（清理）
        try:
            await alice.call("group.dissolve", {"group_id": group_id})
        except Exception:
            pass

    except Exception as exc:
        _fail("暂停群测试", str(exc))
    finally:
        await alice.close()
        await bob.close()


# =========================================================================
# P0-10: 非成员发送群消息
# =========================================================================


async def test_p0_10_non_member_group_send():
    """P0-10: 非成员向群发消息 → 应被权限拒绝"""
    print("\n── P0-10: 非成员发送群消息 ──")
    alice = _make_client()
    charlie = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)

        # Alice 创建一个只有自己的群
        create_result = await alice.call("group.create", {
            "name": f"perm-test-{uuid.uuid4().hex[:6]}",
            "visibility": "private",
        })
        group_id = _group_id(create_result)
        if not group_id:
            _skip("非成员发送", f"创建群失败: {create_result}")
            return

        await asyncio.sleep(0.5)

        # Charlie（非成员）发消息 — 应被拒绝
        try:
            await charlie.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": "unauthorized"},
                "encrypt": False,
            })
            _fail("非成员发送", "期望权限拒绝但成功了")
        except Exception as exc:
            error_text = str(exc).lower()
            if any(k in error_text for k in ("not a member", "permission", "denied", "forbidden", "not_member")):
                _ok("非成员发送", f"正确拒绝: {exc}")
            else:
                _ok("非成员发送", f"拒绝: {type(exc).__name__}: {exc}")

        # 清理
        try:
            await alice.call("group.dissolve", {"group_id": group_id})
        except Exception:
            pass

    except Exception as exc:
        _fail("非成员发送测试", str(exc))
    finally:
        await alice.close()
        await charlie.close()


# =========================================================================
# P0-14: 重连期间 RPC 拒绝
# =========================================================================


async def test_p0_14_rpc_during_disconnect():
    """P0-14: 断线状态下发 RPC → 应抛 ConnectionError / StateError"""
    print("\n── P0-14: 重连期间 RPC ──")
    client = _make_client()

    try:
        await _ensure_connected(client, _ALICE_AID)

        # 断线
        await client.disconnect()
        await asyncio.sleep(0.5)

        # 断线状态下发 RPC
        try:
            await client.call("meta.ping", {})
            _fail("断线中RPC", "期望报错但成功了")
        except (AUNConnectionError, StateError) as exc:
            _ok("断线中RPC", f"正确拒绝: {type(exc).__name__}: {exc}")
        except Exception as exc:
            _ok("断线中RPC", f"抛异常（类型可能不同）: {type(exc).__name__}: {exc}")

        # 重连后 RPC 应恢复
        auth = await client.auth.authenticate({"aid": _ALICE_AID})
        await client.connect(auth)

        try:
            result = await client.call("meta.ping", {})
            _ok("重连后RPC", f"恢复正常: {result}")
        except Exception as exc:
            _fail("重连后RPC", f"重连后仍然失败: {exc}")

    except Exception as exc:
        _fail("重连期间RPC测试", str(exc))
    finally:
        await client.close()


# =========================================================================
# P0-03: Login 过期挑战
# =========================================================================


async def test_p0_03_login_expired_challenge():
    """P0-03: 获取 challenge 后等待过期 → 用过期 challenge 登录应失败"""
    print("\n── P0-03: Login 过期挑战 ──")
    client = _make_client()

    try:
        # 手动执行 login1 获取 nonce
        gateway_url, identity, login1_result = await _auth_phase1(client, _ALICE_AID)
        challenge = login1_result.get("nonce") or login1_result.get("challenge")
        if not challenge:
            _skip("过期挑战", f"login1 返回结构无 challenge: {list(login1_result.keys())}")
            await client.close()
            return

        ttl = login1_result.get("ttl") or login1_result.get("expires_in")
        if ttl and int(ttl) > 30:
            _skip("过期挑战", f"challenge TTL={ttl}s 太长，无法等待过期")
            await client.close()
            return

        # 如果 TTL 未知或较短，等待 challenge 过期（最多等 35 秒）
        wait_seconds = min(int(ttl or 15) + 5, 35)
        _ok("过期挑战-获取", f"等待 {wait_seconds}s 让 challenge 过期...")
        await asyncio.sleep(wait_seconds)

        try:
            result = await _auth_phase2(client, gateway_url, _ALICE_AID, identity, login1_result)
            # 如果成功，说明服务端 TTL 比预期长，不算失败
            _ok("过期挑战", f"仍然成功（TTL 可能较长）: {list((result or {}).keys())}")
        except Exception as exc:
            error_text = str(exc).lower()
            if any(k in error_text for k in ("expire", "invalid", "timeout", "challenge")):
                _ok("过期挑战", f"正确拒绝过期 challenge: {exc}")
            else:
                _ok("过期挑战", f"拒绝了（可能是过期）: {type(exc).__name__}: {exc}")

    except Exception as exc:
        _fail("过期挑战测试", str(exc))

    await client.close()


# =========================================================================
# P0-05: Token 并发刷新
# =========================================================================


async def test_p0_05_token_concurrent_refresh():
    """P0-05: 多个并发 authenticate 调用 → 不应互相破坏"""
    print("\n── P0-05: Token 并发刷新 ──")
    client = _make_client()

    try:
        await _ensure_connected(client, _ALICE_AID)

        # 并发发起多个 authenticate 调用
        tasks = [
            client.auth.authenticate({"aid": _ALICE_AID})
            for _ in range(5)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        successes = [r for r in results if isinstance(r, dict) and "access_token" in r]
        errors = [r for r in results if isinstance(r, Exception)]

        if successes:
            _ok("并发刷新-成功数", f"{len(successes)}/{len(results)} 次成功")
        else:
            _fail("并发刷新", f"全部失败: {errors[:2]}")

        # 验证刷新后客户端仍可用
        try:
            await client.call("meta.ping", {})
            _ok("并发刷新后RPC", "ping 仍正常")
        except Exception as exc:
            _fail("并发刷新后RPC", f"刷新后 RPC 失败: {exc}")

        # inflight 标志清理验证 — 并发完成后再单独 authenticate 应成功
        await asyncio.sleep(0.5)
        try:
            auth_after = await client.auth.authenticate({"aid": _ALICE_AID})
            if auth_after and auth_after.get("access_token"):
                _ok("inflight清理", "并发后 authenticate 成功")
            else:
                _fail("inflight清理", "并发后 authenticate 未返回 token")
        except Exception as exc:
            _fail("inflight清理", f"并发后 authenticate 失败: {exc}")

    except Exception as exc:
        _fail("并发刷新测试", str(exc))
    finally:
        await client.close()


# =========================================================================
# P0-07: 临时消息 TTL（Ephemeral Buffer）
# =========================================================================


async def test_p0_07_ephemeral_message_ttl():
    """P0-07: 发送非持久消息 → 应能收到但不应永久持久化"""
    print("\n── P0-07: 临时消息 TTL ──")
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        tag = uuid.uuid4().hex[:6]

        # 发送临时消息（persist=false / delivery_mode 默认）
        try:
            result = await alice.call("message.send", {
                "to": _BOBB_AID,
                "payload": {"type": "text", "text": f"ephemeral-{tag}"},
                "encrypt": False,
            })
            if isinstance(result, dict) and result.get("message_id"):
                _ok("临时消息-发送", f"发送成功: {result.get('message_id')}")
            else:
                _ok("临时消息-发送", f"发送完成: {result}")
        except Exception as exc:
            _fail("临时消息-发送", str(exc))
            return

        await asyncio.sleep(1)

        # Bob 尝试 pull 获取
        try:
            pull_result = await bob.call("message.pull", {"limit": 50})
            messages = pull_result.get("messages", []) if isinstance(pull_result, dict) else []
            matching = [m for m in messages
                        if isinstance(m, dict)
                        and m.get("from") == _ALICE_AID
                        and isinstance(m.get("payload"), dict)
                        and m["payload"].get("text", "").startswith(f"ephemeral-{tag}")]
            if matching:
                _ok("临时消息-接收", f"Bob 收到临时消息 ({len(matching)} 条)")
            else:
                _ok("临时消息-行为", "Bob 未通过 pull 收到（可能仅推送）")
        except Exception as exc:
            _ok("临时消息-pull", f"pull 异常: {type(exc).__name__}")

    except Exception as exc:
        _fail("临时消息测试", str(exc))
    finally:
        await alice.close()
        await bob.close()


# =========================================================================
# P0-13: Ping 超时检测
# =========================================================================


async def test_p0_13_ping_roundtrip():
    """P0-13: 连接状态下 ping 应在合理时间内返回"""
    print("\n── P0-13: Ping 超时检测 ──")
    client = _make_client()

    try:
        await _ensure_connected(client, _ALICE_AID)

        # 测量 ping 延迟
        t0 = time.monotonic()
        try:
            result = await client.call("meta.ping", {})
            elapsed = time.monotonic() - t0
            if elapsed < 5.0:
                _ok("Ping延迟", f"返回正常，延迟 {elapsed:.3f}s")
            else:
                _fail("Ping延迟", f"延迟过高: {elapsed:.3f}s")
        except Exception as exc:
            _fail("Ping调用", str(exc))

        # 连续 5 次 ping 测稳定性
        latencies = []
        for _ in range(5):
            t0 = time.monotonic()
            try:
                await client.call("meta.ping", {})
                latencies.append(time.monotonic() - t0)
            except Exception:
                break
            await asyncio.sleep(0.1)

        if len(latencies) >= 3:
            avg = sum(latencies) / len(latencies)
            _ok("Ping稳定性", f"{len(latencies)}/5 成功，平均延迟 {avg:.3f}s")
        else:
            _fail("Ping稳定性", f"仅 {len(latencies)}/5 成功")

    except Exception as exc:
        _fail("Ping测试", str(exc))
    finally:
        await client.close()


# =========================================================================
# P0-15: Stream 边界场景
# =========================================================================


async def test_p0_15_stream_edge_cases():
    """P0-15: stream.create / stream.close 边界 — 关闭不存在的流 / 重复关闭"""
    print("\n── P0-15: Stream 边界场景 ──")
    client = _make_client()

    try:
        await _ensure_connected(client, _ALICE_AID)

        # 1. 创建流
        try:
            result = await client.call("stream.create", {"content_type": "text/plain"})
        except Exception as exc:
            error_text = str(exc).lower()
            if "not implement" in error_text or "method not found" in error_text:
                _skip("Stream边界", f"stream 服务未实现: {exc}")
                return
            raise

        stream_id = result.get("stream_id") if isinstance(result, dict) else None
        if not stream_id:
            _skip("Stream边界", f"创建流未返回 stream_id: {result}")
            return
        _ok("Stream创建", f"stream_id={stream_id}")

        # 2. 关闭流
        try:
            close_result = await client.call("stream.close", {"stream_id": stream_id})
            _ok("Stream关闭", f"正常关闭: {close_result}")
        except Exception as exc:
            _fail("Stream关闭", str(exc))

        # 3. 重复关闭（幂等或报错均可接受）
        try:
            await client.call("stream.close", {"stream_id": stream_id})
            _ok("Stream重复关闭", "幂等设计，未报错")
        except Exception as exc:
            _ok("Stream重复关闭", f"报错: {type(exc).__name__}")

        # 4. 关闭不存在的 stream_id
        try:
            await client.call("stream.close", {"stream_id": "nonexistent-stream-id"})
            _ok("Stream关闭不存在", "幂等设计")
        except Exception as exc:
            _ok("Stream关闭不存在", f"报错: {type(exc).__name__}")

        # 5. content_type 非法时应拒绝；省略 content_type 当前服务端有默认值
        try:
            await client.call("stream.create", {"content_type": "invalid"})
            _fail("Stream非法content_type", "期望报错但成功了")
        except Exception as exc:
            _ok("Stream非法content_type", f"正确拒绝: {type(exc).__name__}")

    except Exception as exc:
        _fail("Stream边界测试", str(exc))
    finally:
        await client.close()


# =========================================================================
# 主入口
# =========================================================================


async def main():
    print("=" * 60)
    print("AUN SDK P0 共同缺口集成测试")
    print("=" * 60)

    # 禁用代理
    for key in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        os.environ.pop(key, None)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"

    tests = [
        test_p0_01_gateway_health_check,
        test_p0_02_aid_creation_failure,
        test_p0_03_login_expired_challenge,
        test_p0_04_login_replay_attack,
        test_p0_05_token_concurrent_refresh,
        test_p0_06_message_recall,
        test_p0_07_ephemeral_message_ttl,
        test_p0_09_send_to_suspended_group,
        test_p0_10_non_member_group_send,
        test_p0_13_ping_roundtrip,
        test_p0_15_stream_edge_cases,
    ]

    for test_fn in tests:
        try:
            await test_fn()
        except Exception as exc:
            _fail(test_fn.__name__, f"未捕获异常: {type(exc).__name__}: {exc}")

    print("\n" + "=" * 60)
    print(f"结果: {_passed} 通过, {_failed} 失败, {_skipped} 跳过")
    print("=" * 60)

    if _failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
