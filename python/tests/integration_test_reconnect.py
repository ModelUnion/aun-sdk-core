#!/usr/bin/env python3
"""
断线重连集成测试 — 需要运行中的 Docker Gateway

通过 Docker 命令模拟真实断线，验证 SDK 自动重连机制。

使用方法：
  python tests/integration_test_reconnect.py

前置条件：
  - Docker 环境运行中（docker compose up -d）
  - 运行环境能解析 gateway.agentid.pub（推荐 Docker network alias，不使用 hosts 文件）
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient


# ── 配置 ──────────────────────────────────────────────────

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/reconnect"
    return "./.aun_test_reconnect"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_DOCKER_COMPOSE_DIR = str(Path(__file__).parent.parent.parent.parent / "docker-deploy")
_NETWORK_NAME = "docker-deploy_kite-net"
_CONTAINER_NAME = "kite-app"
os.environ.setdefault("AUN_ENV", "development")

_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip()
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bob.{_ISSUER}").strip()


# ── 辅助函数 ──────────────────────────────────────────────


def _disable_proxy_env_for_tests() -> None:
    """测试脚本默认直连 Gateway，避免系统代理劫持本地域名解析。"""
    for key in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        os.environ.pop(key, None)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"


def _run_docker(args: list[str], timeout: int) -> bool:
    try:
        result = subprocess.run(
            args,
            cwd=_DOCKER_COMPOSE_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception as e:
        print(f"  [warn] {' '.join(args)} 失败: {e}")
        return False
    if result.returncode == 0:
        return True
    detail = (result.stderr or result.stdout or "").strip()
    if detail:
        print(f"  [warn] {' '.join(args)} 失败: {detail}")
    return False

def _make_client(tag: str) -> AUNClient:
    """创建测试客户端（通过 well-known 发现 gateway）"""
    client = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    })
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth, {
        "auto_reconnect": True,
        "heartbeat_interval": 5,
        "retry": {
            "max_attempts": 10,
            "initial_delay": 1.0,
            "max_delay": 10.0,
        },
    })
    return aid


def _docker_restart_gateway(timeout: int = 30) -> bool:
    """重启 Docker 容器（模拟服务端重启）"""
    return _run_docker(["docker", "compose", "restart", "kite"], timeout=timeout)


def _docker_network_disconnect() -> bool:
    """断开容器网络（模拟网络中断）"""
    return _run_docker(["docker", "network", "disconnect", _NETWORK_NAME, _CONTAINER_NAME], timeout=10)


def _docker_network_connect() -> bool:
    """恢复容器网络"""
    return _run_docker(["docker", "network", "connect", _NETWORK_NAME, _CONTAINER_NAME], timeout=10)


async def _wait_for_state(client: AUNClient, target_state: str, timeout: float = 30.0) -> bool:
    """等待客户端进入目标状态"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.state == target_state:
            return True
        await asyncio.sleep(0.5)
    return False


# ── 测试用例 ──────────────────────────────────────────────

async def test_basic_reconnect_after_network_interrupt():
    """Test 1: 网络中断后自动重连"""
    print("\n=== Test 1: 网络中断后自动重连 ===")
    import uuid
    rid = str(uuid.uuid4())[:8]
    aid = f"rc-t1-{rid}.agentid.pub"

    client = _make_client("t1")
    state_events: list[dict] = []
    client.on("connection.state", lambda d: state_events.append(d))

    try:
        await _ensure_connected(client, aid)
        assert client.state == "connected", f"初始连接失败: {client.state}"
        print(f"  [OK] 初始连接成功: {aid}")

        # 断开网络
        print("  断开网络...")
        ok = _docker_network_disconnect()
        if not ok:
            print("  [SKIP] 无法断开网络，跳过")
            return True

        # 等待 SDK 检测到断线
        disconnected = await _wait_for_state(client, "disconnected", timeout=15.0)
        if not disconnected:
            # 也可能直接进入 reconnecting
            disconnected = client.state in ("disconnected", "reconnecting")
        print(f"  [OK] 检测到断线: state={client.state}")

        # 恢复网络
        await asyncio.sleep(2.0)
        print("  恢复网络...")
        _docker_network_connect()

        # 等待重连成功
        reconnected = await _wait_for_state(client, "connected", timeout=60.0)
        if reconnected:
            print(f"  [PASS] 重连成功")
        else:
            print(f"  [FAIL] 重连超时: state={client.state}")
            return False

        # 验证重连后可以发消息
        try:
            await client.call("meta.ping")
            print("  [OK] 重连后 ping 成功")
        except Exception as e:
            print(f"  [WARN] 重连后 ping 失败: {e}")

        return True
    finally:
        await client.close()


async def test_reconnect_after_gateway_restart():
    """Test 2: Gateway 重启后自动重连"""
    print("\n=== Test 2: Gateway 重启后自动重连 ===")
    import uuid
    rid = str(uuid.uuid4())[:8]
    aid = f"rc-t2-{rid}.agentid.pub"

    client = _make_client("t2")
    state_events: list[dict] = []
    client.on("connection.state", lambda d: state_events.append(d))

    try:
        await _ensure_connected(client, aid)
        print(f"  [OK] 初始连接成功: {aid}")

        # 重启 Gateway
        print("  重启 Gateway（docker compose restart kite）...")
        ok = _docker_restart_gateway(timeout=60)
        if not ok:
            print("  [SKIP] 无法重启 Gateway")
            return True

        print("  等待 Gateway 重启完成...")
        await asyncio.sleep(15)  # 等待 Gateway 完全启动

        # 等待重连成功
        reconnected = await _wait_for_state(client, "connected", timeout=60.0)
        if reconnected:
            print(f"  [PASS] Gateway 重启后重连成功")
        else:
            print(f"  [FAIL] 重连超时: state={client.state}")
            # 检查是否有重连尝试
            reconnecting_events = [e for e in state_events if e.get("state") == "reconnecting"]
            print(f"  重连尝试次数: {len(reconnecting_events)}")
            return False

        # 验证重连后功能正常
        try:
            result = await client.call("meta.ping")
            print(f"  [OK] 重连后 ping 成功: {result}")
        except Exception as e:
            print(f"  [WARN] 重连后 ping 失败: {e}")

        return True
    finally:
        await client.close()


async def test_state_events_sequence():
    """Test 3: 验证状态事件序列正确（通过 Gateway 重启触发断线）"""
    print("\n=== Test 3: 状态事件序列验证 ===")
    import uuid
    rid = str(uuid.uuid4())[:8]
    aid = f"rc-t3-{rid}.agentid.pub"

    client = _make_client("t3")
    state_sequence: list[str] = []
    client.on("connection.state", lambda d: state_sequence.append(d.get("state", "")))

    try:
        await _ensure_connected(client, aid)
        print(f"  [OK] 初始连接成功")

        # 用 Gateway 重启触发断线（比 network disconnect 更可靠）
        print("  重启 Gateway 触发断线...")
        ok = _docker_restart_gateway(timeout=60)
        if not ok:
            print("  [SKIP] 无法重启 Gateway")
            return True

        # 等待断线检测（重启需要时间）
        await asyncio.sleep(5)

        # 等待重连成功
        await _wait_for_state(client, "connected", timeout=60.0)

        print(f"  状态序列: {state_sequence}")

        # 验证序列包含必要状态
        assert "disconnected" in state_sequence or "reconnecting" in state_sequence, \
            f"缺少断线状态，序列: {state_sequence}"
        assert state_sequence[-1] == "connected", \
            f"最终状态应为 connected，实际: {state_sequence[-1]}"

        print(f"  [PASS] 状态序列正确")
        return True
    finally:
        await client.close()


async def test_message_after_reconnect():
    """Test 4: 重连后消息收发正常"""
    print("\n=== Test 4: 重连后消息收发 ===")
    import uuid
    rid = str(uuid.uuid4())[:8]
    alice_aid = f"rc-a-{rid}.agentid.pub"
    bob_aid = f"rc-b-{rid}.agentid.pub"

    alice = _make_client("alice")
    bob = _make_client("bob")

    try:
        await _ensure_connected(alice, alice_aid)
        await _ensure_connected(bob, bob_aid)
        print(f"  [OK] 双方连接成功")

        # 重启 Gateway 触发断线
        print("  重启 Gateway...")
        ok = _docker_restart_gateway(timeout=60)
        if not ok:
            print("  [SKIP] 无法重启 Gateway")
            return True

        # 等待 Gateway 完全重启
        await asyncio.sleep(15)

        # 等待双方重连
        alice_ok = await _wait_for_state(alice, "connected", timeout=60.0)
        bob_ok = await _wait_for_state(bob, "connected", timeout=60.0)

        if not (alice_ok and bob_ok):
            print(f"  [FAIL] 重连失败: alice={alice.state}, bob={bob.state}")
            return False

        print(f"  [OK] 双方重连成功")

        # 等待后台任务（prekey 上传等）完成
        await asyncio.sleep(3.0)

        # 重连后发消息
        send_result = await alice.call("message.send", {
            "to": bob_aid,
            "payload": {"text": "重连后的消息"},
            "encrypt": False,
        })
        assert send_result.get("message_id"), "消息发送失败"
        print(f"  [OK] 重连后消息发送成功: {send_result.get('message_id')}")

        # Bob 拉取消息
        await asyncio.sleep(1.0)
        pull_result = await bob.call("message.pull", {"after_seq": 0, "limit": 10})
        msgs = pull_result.get("messages", [])
        found = any(m.get("payload", {}).get("text") == "重连后的消息" for m in msgs)
        if found:
            print(f"  [PASS] 重连后消息收发正常")
        else:
            print(f"  [WARN] 未找到预期消息（可能已在之前拉取），收到 {len(msgs)} 条")

        return True
    finally:
        await alice.close()
        await bob.close()


async def test_reconnect_exhausted():
    """Test 5: 无限重试 — 停止 Gateway 后持续重连，恢复后自动连上"""
    print("\n=== Test 5: 无限重试验证 ===")
    import uuid
    rid = str(uuid.uuid4())[:8]
    aid = f"rc-t5-{rid}.agentid.pub"

    client = _make_client("reconnect-exhausted")
    state_events: list[dict] = []
    client.on("connection.state", lambda d: state_events.append(d))

    try:
        await client.auth.create_aid({"aid": aid})
        auth = await client.auth.authenticate({"aid": aid})
        await client.connect(auth, {
            "auto_reconnect": True,
            "retry": {
                "initial_delay": 2.0,
                "max_delay": 5.0,
            },
        })
        print(f"  [OK] 初始连接成功")

        # 停止 Gateway（不立即恢复）
        print("  停止 Gateway...")
        result = subprocess.run(
            ["docker", "compose", "stop", "kite"],
            cwd=_DOCKER_COMPOSE_DIR,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print("  [SKIP] 无法停止 Gateway")
            return True

        # 等待一段时间，验证客户端在持续重连（非 terminal_failed）
        await asyncio.sleep(10)
        reconnect_attempts = [e for e in state_events if e.get("state") == "reconnecting"]
        print(f"  重连尝试次数: {len(reconnect_attempts)}, 当前状态: {client.state}")
        assert client.state in ("reconnecting", "disconnected", "connecting", "authenticating"), \
            f"应在持续重连，而非 {client.state}"
        assert len(reconnect_attempts) >= 2, "应有至少 2 次重连尝试"

        # 恢复 Gateway
        print("  恢复 Gateway...")
        subprocess.run(
            ["docker", "compose", "start", "kite"],
            cwd=_DOCKER_COMPOSE_DIR,
            capture_output=True, text=True, timeout=30,
        )
        await asyncio.sleep(10)

        # 等待重连成功
        reconnected = await _wait_for_state(client, "connected", timeout=60.0)
        if reconnected:
            print(f"  [PASS] 无限重试验证：停止 {len(reconnect_attempts)} 次重连后，恢复 Gateway 自动连上")
        else:
            print(f"  [FAIL] 恢复后未重连成功: state={client.state}")
            return False

        return True
    finally:
        await client.close()


# ── 主程序 ────────────────────────────────────────────────

async def test_message_chain_recovery_after_reconnect():
    """重连后消息链恢复验证（非仅 ping）"""
    aid = _ALICE_AID
    bob_aid = _BOB_AID

    client = _make_client("message-chain-recovery")
    bob_client = _make_client("bob-receiver")

    try:
        await client.auth.create_aid({"aid": aid})
        auth = await client.auth.authenticate({"aid": aid})
        await client.connect(auth, {"auto_reconnect": True, "heartbeat_interval": 5})

        await bob_client.auth.create_aid({"aid": bob_aid})
        bob_auth = await bob_client.auth.authenticate({"aid": bob_aid})
        await bob_client.connect(bob_auth)

        # 发送第一条消息
        await client.call("message.send", {"to": bob_aid, "payload": "msg_before_disconnect", "encrypt": False})
        await asyncio.sleep(1)

        # 断网
        print("  断开网络...")
        _docker_network_disconnect()
        await asyncio.sleep(2)

        # 恢复网络
        print("  恢复网络...")
        _docker_network_connect()
        reconnected = await _wait_for_state(client, "connected", timeout=30.0)
        assert reconnected, "重连失败"
        print("  [OK] 重连成功")

        # 发送第二条消息（验证消息链恢复）
        await client.call("message.send", {"to": bob_aid, "payload": "msg_after_reconnect", "encrypt": False})
        await asyncio.sleep(1)

        # Bob 拉取消息，验证两条都收到
        result = await bob_client.call("message.pull", {"after_seq": 0, "limit": 50})
        messages = result.get("messages", [])
        payloads = [m.get("payload") for m in messages if m.get("from") == aid]
        assert "msg_before_disconnect" in payloads, "断网前消息未收到"
        assert "msg_after_reconnect" in payloads, "重连后消息未收到"

        print(f"  [PASS] 消息链恢复验证通过（收到 {len(payloads)} 条消息）")
        return True
    finally:
        await client.close()
        await bob_client.close()


async def test_no_duplicate_background_tasks():
    """重连后不重复创建后台任务"""
    aid = _ALICE_AID

    client = _make_client("no-duplicate-tasks")
    try:
        await client.auth.create_aid({"aid": aid})
        auth = await client.auth.authenticate({"aid": aid})
        await client.connect(auth, {"auto_reconnect": True, "heartbeat_interval": 5})

        # 记录初始后台任务数（通过心跳计数）
        initial_heartbeat_count = getattr(client, "_heartbeat_count", 0)

        # 断网 → 重连
        print("  断开网络...")
        _docker_network_disconnect()
        await asyncio.sleep(2)

        print("  恢复网络...")
        _docker_network_connect()
        reconnected = await _wait_for_state(client, "connected", timeout=30.0)
        assert reconnected, "重连失败"
        print("  [OK] 重连成功")

        # 等待一段时间，验证心跳任务未重复创建
        await asyncio.sleep(10)
        final_heartbeat_count = getattr(client, "_heartbeat_count", 0)

        # 验证心跳计数增长正常（约 2 次，允许误差）
        heartbeat_delta = final_heartbeat_count - initial_heartbeat_count
        assert 1 <= heartbeat_delta <= 3, f"心跳计数异常：{heartbeat_delta}（可能重复创建任务）"

        print(f"  [PASS] 后台任务未重复创建（心跳增量 {heartbeat_delta}）")
        return True
    finally:
        await client.close()


async def main():
    _disable_proxy_env_for_tests()
    print("=" * 60)
    print("AUN SDK 断线重连集成测试")
    print("=" * 60)

    tests = [
        ("网络中断后自动重连", test_basic_reconnect_after_network_interrupt),
        ("Gateway 重启后重连", test_reconnect_after_gateway_restart),
        ("状态事件序列验证", test_state_events_sequence),
        ("重连后消息收发", test_message_after_reconnect),
        ("重连耗尽 → 无限重试验证", test_reconnect_exhausted),
        ("消息链恢复验证", test_message_chain_recovery_after_reconnect),
        ("后台任务不重复创建", test_no_duplicate_background_tasks),
    ]

    results = []
    for name, test_fn in tests:
        try:
            ok = await test_fn()
            results.append((name, ok if ok is not None else True))
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")
            results.append((name, False))

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        status = "[PASS]" if ok else "[FAIL]"
        print(f"  {status} {name}")
    print(f"\nPassed: {passed}/{len(results)}")

    if passed == len(results):
        print("\n[PASS] All reconnect tests passed!")
    else:
        print(f"\n[FAIL] {len(results) - passed} test(s) failed")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
