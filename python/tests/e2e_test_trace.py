#!/usr/bin/env python3
"""分布式 Trace E2E 测试 — 需要运行中的 AUN Gateway 服务。

验证 trace 协议全链路：
1. diag 模式：response 携带完整 spans（sdk→gateway→service→gateway）
2. log 模式：response 不携带 _trace
3. 事件 trace：接收方 observer 收到 trace_id

使用方法：
  docker exec kite-sdk-tester python /tests/e2e_test_trace.py

前置条件：
  - Docker 单域环境运行中（docker compose up -d）
  - 固定身份 alice / bobb 已创建
  - 服务端已 rebuild（含 trace 改动）
"""
import asyncio
import os
import sys
import time
from pathlib import Path
from weakref import WeakKeyDictionary

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
    return "./.aun_test"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
_CLIENT_SLOT_IDS: WeakKeyDictionary[AUNClient, str] = WeakKeyDictionary()


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _make_client(tag: str) -> AUNClient:
    client = make_client_for_path(_TEST_AUN_PATH, debug=True, require_forward_secrecy=False)
    _CLIENT_SLOT_IDS[client] = f"trace-{tag}"
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    for attempt in range(4):
        try:
            connect_params: dict = {}
            slot_id = _CLIENT_SLOT_IDS.get(client, "")
            if slot_id:
                connect_params["slot_id"] = slot_id
            connect_params["auto_reconnect"] = False
            await ensure_connected_identity(client, aid, connect_options=connect_params, attempts=1)
            # 等待 V2 初始化后台任务完成
            await asyncio.sleep(1.0)
            return
        except Exception as e:
            if attempt < 3:
                print(f"  [retry {attempt+1}] {aid} connect failed: {e}")
                await asyncio.sleep(1)
            else:
                raise


# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

passed = 0
failed = 0


def _ok(name: str):
    global passed
    passed += 1
    print(f"  PASS: {name}")


def _fail(name: str, reason: str):
    global failed
    failed += 1
    print(f"  FAIL: {name} — {reason}")


async def test_diag_mode_returns_spans():
    """diag 模式：message.send response 应携带 _trace 含完整 spans 链"""
    print("\n[TEST] diag 模式 — response 携带 spans")
    alice = _make_client("alice-diag")
    traces_received = []

    try:
        await _ensure_connected(alice, _ALICE_AID)
        alice.set_trace_mode("diag")
        alice.set_trace_observer(lambda info: traces_received.append(info))

        # 清空 V2 初始化期间可能产生的 trace
        traces_received.clear()

        # 发送一条明文消息（不需要对端在线）
        result = await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"text": "trace-diag-test"},
            "encrypt": False,
        })
        print(f"    send result: {result}")

        # 找到 message.send 的 trace
        send_traces = [t for t in traces_received if t.get("method") == "message.send"]
        if not send_traces:
            _fail("diag_spans", f"message.send 的 trace observer 未被调用 (total traces: {len(traces_received)})")
            return
        trace_info = send_traces[0]
        print(f"    trace_info: {trace_info}")

        if trace_info.get("type") != "rpc":
            _fail("diag_spans", f"type 应为 rpc，实际: {trace_info.get('type')}")
            return

        trace = trace_info.get("trace", {})
        if trace.get("mode") != "diag":
            _fail("diag_spans", f"mode 应为 diag，实际: {trace.get('mode')}")
            return

        spans = trace.get("spans", [])
        print(f"    spans count: {len(spans)}")
        for i, s in enumerate(spans):
            print(f"      [{i}] node={s.get('node')} action={s.get('action')} ts={s.get('ts')} ms={s.get('ms')}")

        # 至少应有 3 个 span：sdk(send) + gateway(relay_in) + message(process) + gateway(relay_out)
        # 但 sdk send span 是客户端注入的，gateway relay_in 在转发时追加，service process 在处理时追加，gateway relay_out 在回传时追加
        # 最终 response 中应有：gateway(relay_in) + message(process) + gateway(relay_out) = 至少 3 个
        if len(spans) < 3:
            _fail("diag_spans", f"spans 数量不足，期望>=3，实际: {len(spans)}")
            return

        # 验证 span 节点包含 gateway 和 message
        nodes = [s.get("node") for s in spans]
        if "gateway" not in nodes:
            _fail("diag_spans", f"spans 中缺少 gateway 节点: {nodes}")
            return
        if "message" not in nodes:
            _fail("diag_spans", f"spans 中缺少 message 节点: {nodes}")
            return

        # 验证 relay_out span 有 ms > 0
        relay_out = [s for s in spans if s.get("action") == "relay_out"]
        if not relay_out:
            _fail("diag_spans", "spans 中缺少 relay_out action")
            return
        if relay_out[0].get("ms", 0) <= 0:
            _fail("diag_spans", f"relay_out ms 应 > 0，实际: {relay_out[0].get('ms')}")
            return

        _ok("diag_spans")
    finally:
        await alice.disconnect()


async def test_log_mode_no_trace_in_response():
    """log 模式：response 不应携带 _trace"""
    print("\n[TEST] log 模式 — response 无 _trace")
    alice = _make_client("alice-log")
    traces_received = []

    try:
        await _ensure_connected(alice, _ALICE_AID)
        alice.set_trace_mode("log")
        alice.set_trace_observer(lambda info: traces_received.append(info))

        result = await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"text": "trace-log-test"},
            "encrypt": False,
        })
        print(f"    send result: {result}")

        # log 模式下 observer 不应被调用（response 不带 _trace）
        if traces_received:
            _fail("log_no_trace", f"log 模式下 observer 不应被调用，但收到: {traces_received}")
        else:
            _ok("log_no_trace")
    finally:
        await alice.disconnect()


async def test_per_call_trace_override():
    """调用级 trace='diag' 覆盖会话级 'off'"""
    print("\n[TEST] 调用级 trace 覆盖")
    alice = _make_client("alice-override")
    traces_received = []

    try:
        await _ensure_connected(alice, _ALICE_AID)
        # 会话级 off
        alice.set_trace_mode("off")
        alice.set_trace_observer(lambda info: traces_received.append(info))

        # 单次调用 diag
        traces_received.clear()
        result = await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"text": "trace-override-test"},
            "encrypt": False,
        }, trace="diag")
        print(f"    send result: {result}")

        if not traces_received:
            _fail("per_call_override", "trace='diag' 覆盖后 observer 应被调用")
        else:
            send_traces = [t for t in traces_received if t.get("method") == "message.send"]
            if not send_traces:
                _fail("per_call_override", f"message.send trace 未找到 (got: {[t.get('method') for t in traces_received]})")
            else:
                trace = send_traces[0].get("trace", {})
                if trace.get("mode") == "diag" and trace.get("spans"):
                    _ok("per_call_override")
                else:
                    _fail("per_call_override", f"trace 内容不符预期: {trace}")
    finally:
        await alice.disconnect()


async def test_event_trace_propagation():
    """事件 trace 传播：bobb 收到消息事件时 observer 收到 trace_id"""
    print("\n[TEST] 事件 trace 传播")
    alice = _make_client("alice-evt")
    bobb = _make_client("bobb-evt")
    event_traces = []

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)

        # bobb 注册 trace observer
        bobb.set_trace_observer(lambda info: event_traces.append(info))

        # alice 用 log 模式发消息（事件中应携带 trace_id）
        alice.set_trace_mode("log")
        await alice.call("message.send", {
            "to": _BOBB_AID,
            "payload": {"text": "trace-event-test"},
            "encrypt": False,
        })

        # 等待 bobb 收到事件
        await asyncio.sleep(2.0)

        if event_traces:
            evt_trace = event_traces[0]
            print(f"    event trace: {evt_trace}")
            if evt_trace.get("type") == "event" and evt_trace.get("trace", {}).get("trace_id"):
                _ok("event_trace")
            else:
                _fail("event_trace", f"事件 trace 格式不符: {evt_trace}")
        else:
            _fail("event_trace", "bobb 未收到事件 trace")
    finally:
        await alice.disconnect()
        await bobb.disconnect()


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("AUN 分布式 Trace E2E 测试")
    print(f"  AUN_PATH: {_TEST_AUN_PATH}")
    print(f"  ISSUER: {_ISSUER}")
    print(f"  ALICE: {_ALICE_AID}")
    print(f"  BOBB: {_BOBB_AID}")
    print("=" * 60)

    await test_diag_mode_returns_spans()
    await test_log_mode_no_trace_in_response()
    await test_per_call_trace_override()
    await test_event_trace_propagation()

    print("\n" + "=" * 60)
    print(f"结果: {passed} passed, {failed} failed")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())

