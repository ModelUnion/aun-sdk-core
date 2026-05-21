#!/usr/bin/env python3
"""Echo 链路追踪 E2E 测试 — 需要运行中的 AUN Gateway 服务。

验证明文消息经过 SDK.send → Gateway.route → Message.relay → SDK.receive 的完整 trace 链。

使用方法：
  docker exec kite-sdk-tester python /tests/e2e_test_echo.py

前置条件：
  - Docker 单域环境运行中（docker compose up -d）
  - 固定身份 alice / bobb 已创建
"""
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


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _make_client(tag: str) -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH}, debug=True)
    client._config_model.require_forward_secrecy = False
    # 固定 slot_id，确保 SeqTracker cursor 持久化，避免每次从 seq=0 拉全量历史
    client._test_slot_id = f"echo-{tag}"
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            connect_params = dict(auth)
            slot_id = getattr(client, "_test_slot_id", "")
            if slot_id:
                connect_params["slot_id"] = slot_id
            connect_params["auto_reconnect"] = False
            await client.connect(connect_params)
            # 清空旧 V2 inbox（ack 到最大 seq），避免历史 gap 卡住 ordered queue
            try:
                result = await client.call("message.v2.pull", {"after_seq": 0, "limit": 200})
                msgs = result.get("messages", [])
                if msgs:
                    max_seq = max(m.get("seq", 0) for m in msgs)
                    await client.call("message.v2.ack", {"up_to_seq": max_seq})
                    if aid and client._aid:
                        ns = f"p2p:{client._aid}"
                        tracker = client._seq_tracker._get(ns)
                        tracker.contiguous_seq = max_seq
                        tracker.max_seen_seq = max_seq
                        tracker.received_seqs.clear()
                        tracker.pending_gaps.clear()
            except Exception:
                pass
            await asyncio.sleep(0.5)
            return
        except (AuthError, RateLimitError) as exc:
            if attempt >= 3:
                raise
            await asyncio.sleep(1.5 * (attempt + 1))
    raise RuntimeError("connect failed after retries")


async def _safe_close(client: AUNClient) -> None:
    try:
        await client.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"  ✓ {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    print(f"  ✗ {name}: {reason}")


async def test_p2p_echo_trace() -> None:
    """P2P 明文 echo 消息应包含完整 trace 链"""
    name = "P2P echo trace"
    alice = _make_client("alice-echo")
    bob = _make_client("bob-echo")
    received: list[dict] = []
    event = asyncio.Event()
    echo_marker = f"echo 测试-{_rid()}"

    def on_msg(msg: dict) -> None:
        payload = msg.get("payload", {})
        text = payload.get("text", "") if isinstance(payload, dict) else ""
        if echo_marker in text:
            received.append(msg)
            event.set()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        bob.on("message.received", on_msg)
        await _ensure_connected(bob, _BOBB_AID)

        await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"type": "text", "text": echo_marker},
            "encrypt": False,
        })
        print(f"    发送: {echo_marker}")

        try:
            await asyncio.wait_for(event.wait(), timeout=15)
        except asyncio.TimeoutError:
            _fail(name, "bob 未收到消息（超时 15s）")
            return

        msg = received[0]
        payload = msg.get("payload", {})
        text = payload.get("text", "")
        print(f"    收到: {text[:300]}")

        checks = [
            ("[AUN-SDK.send]", "SDK 发送端 trace"),
            ("[AUN-Gateway.route]", "Gateway trace"),
            ("[AUN-Message.relay]", "Message 服务 trace"),
            ("[AUN-SDK.receive]", "SDK 接收端 trace"),
        ]
        all_ok = True
        for marker, desc in checks:
            if marker not in text:
                _fail(name, f"缺少 {desc}: {marker}")
                all_ok = False
        if all_ok:
            _ok(name)
    except Exception as exc:
        _fail(name, f"异常: {exc!r}")
    finally:
        await _safe_close(alice)
        await _safe_close(bob)


async def test_encrypted_no_echo() -> None:
    """加密消息不应包含 echo trace"""
    name = "加密消息无 echo"
    alice = _make_client("alice-noecho")
    bob = _make_client("bob-noecho")
    received: list[dict] = []
    event = asyncio.Event()

    def on_msg(msg: dict) -> None:
        received.append(msg)
        event.set()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        bob.on("message.received", on_msg)

        echo_text = f"echo 加密测试-{_rid()}"
        await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"type": "text", "text": echo_text},
            "encrypt": True,
        })
        print(f"    发送加密: {echo_text}")

        try:
            await asyncio.wait_for(event.wait(), timeout=15)
        except asyncio.TimeoutError:
            _fail(name, "bob 未收到消息（超时 15s）")
            return

        msg = received[0]
        payload = msg.get("payload", {})
        text = payload.get("text", "") if isinstance(payload, dict) else ""

        if "[AUN-SDK.send]" in text or "[AUN-Gateway.route]" in text:
            _fail(name, f"加密消息不应包含 echo trace，但收到: {text[:100]}")
        else:
            _ok(name)
    except Exception as exc:
        _fail(name, f"异常: {exc!r}")
    finally:
        await _safe_close(alice)
        await _safe_close(bob)


async def test_non_echo_no_trace() -> None:
    """非 echo 明文消息不应包含 trace"""
    name = "非 echo 无 trace"
    alice = _make_client("alice-nontrace")
    bob = _make_client("bob-nontrace")
    received: list[dict] = []
    event = asyncio.Event()
    normal_marker = f"普通消息-{_rid()}"

    def on_msg(msg: dict) -> None:
        payload = msg.get("payload", {})
        text = payload.get("text", "") if isinstance(payload, dict) else ""
        if normal_marker in text:
            received.append(msg)
            event.set()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        bob.on("message.received", on_msg)
        await _ensure_connected(bob, _BOBB_AID)

        await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"type": "text", "text": normal_marker},
            "encrypt": False,
        })
        print(f"    发送: {normal_marker}")

        try:
            await asyncio.wait_for(event.wait(), timeout=15)
        except asyncio.TimeoutError:
            _fail(name, "bob 未收到消息（超时 15s）")
            return

        text = received[0].get("payload", {}).get("text", "") if isinstance(received[0].get("payload"), dict) else ""

        if "[AUN-SDK.send]" in text or "[AUN-Gateway.route]" in text:
            _fail(name, f"非 echo 消息不应有 trace: {text[:100]}")
        else:
            _ok(name)
    except Exception as exc:
        _fail(name, f"异常: {exc!r}")
    finally:
        await _safe_close(alice)
        await _safe_close(bob)


async def test_echo_trace_order() -> None:
    """Echo trace 行应按 send → gateway → message → receive 顺序排列"""
    name = "Echo trace 顺序"
    alice = _make_client("alice-order")
    bob = _make_client("bob-order")
    received: list[dict] = []
    event = asyncio.Event()
    echo_marker = f"echo order-{_rid()}"

    def on_msg(msg: dict) -> None:
        payload = msg.get("payload", {})
        text = payload.get("text", "") if isinstance(payload, dict) else ""
        if echo_marker in text:
            received.append(msg)
            event.set()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        bob.on("message.received", on_msg)
        await _ensure_connected(bob, _BOBB_AID)

        await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"type": "text", "text": echo_marker},
            "encrypt": False,
        })

        try:
            await asyncio.wait_for(event.wait(), timeout=15)
        except asyncio.TimeoutError:
            _fail(name, "bob 未收到消息（超时 15s）")
            return

        text = received[0].get("payload", {}).get("text", "") if isinstance(received[0].get("payload"), dict) else ""
        lines = text.split("\n")

        markers = ["[AUN-SDK.send]", "[AUN-Gateway.route]", "[AUN-Message.relay]", "[AUN-SDK.receive]"]
        positions = []
        for marker in markers:
            for i, line in enumerate(lines):
                if marker in line:
                    positions.append(i)
                    break
            else:
                positions.append(-1)

        if -1 in positions:
            missing = [m for m, p in zip(markers, positions) if p == -1]
            _fail(name, f"缺少 trace: {missing}")
        elif positions == sorted(positions):
            _ok(name)
        else:
            _fail(name, f"trace 顺序错误: positions={positions}")
    except Exception as exc:
        _fail(name, f"异常: {exc!r}")
    finally:
        await _safe_close(alice)
        await _safe_close(bob)


async def test_echo_conn_uptime() -> None:
    """Echo trace 中 conn_uptime 应为非负整数"""
    name = "Echo conn_uptime 格式"
    alice = _make_client("alice-uptime")
    bob = _make_client("bob-uptime")
    received: list[dict] = []
    event = asyncio.Event()
    echo_marker = f"echo uptime-{_rid()}"

    def on_msg(msg: dict) -> None:
        payload = msg.get("payload", {})
        text = payload.get("text", "") if isinstance(payload, dict) else ""
        if echo_marker in text:
            received.append(msg)
            event.set()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        bob.on("message.received", on_msg)
        await _ensure_connected(bob, _BOBB_AID)

        await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"type": "text", "text": echo_marker},
            "encrypt": False,
        })

        try:
            await asyncio.wait_for(event.wait(), timeout=15)
        except asyncio.TimeoutError:
            _fail(name, "bob 未收到消息（超时 15s）")
            return

        text = received[0].get("payload", {}).get("text", "") if isinstance(received[0].get("payload"), dict) else ""
        import re
        uptimes = re.findall(r"conn_uptime=(\d+)s", text)
        if len(uptimes) < 2:
            _fail(name, f"conn_uptime 不足 2 个: found {len(uptimes)}, text={text[:200]}")
        else:
            all_valid = all(int(u) >= 0 for u in uptimes)
            if all_valid:
                _ok(name)
            else:
                _fail(name, f"conn_uptime 含负值: {uptimes}")
    except Exception as exc:
        _fail(name, f"异常: {exc!r}")
    finally:
        await _safe_close(alice)
        await _safe_close(bob)


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

async def main() -> None:
    print(f"\n{'='*60}")
    print(f"Echo 链路追踪 E2E 测试")
    print(f"  AUN_PATH: {_TEST_AUN_PATH}")
    print(f"  ISSUER: {_ISSUER}")
    print(f"  ALICE: {_ALICE_AID}")
    print(f"  BOB: {_BOBB_AID}")
    print(f"{'='*60}\n")

    tests = [
        test_p2p_echo_trace,
        test_encrypted_no_echo,
        test_non_echo_no_trace,
        test_echo_trace_order,
        test_echo_conn_uptime,
    ]

    for test_fn in tests:
        print(f"  运行: {test_fn.__doc__ or test_fn.__name__}")
        await test_fn()
        print()

    print(f"\n{'='*60}")
    print(f"结果: {_passed} passed, {_failed} failed")
    print(f"{'='*60}")
    if _failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
