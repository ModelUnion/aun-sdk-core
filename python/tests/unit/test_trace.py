"""单元测试：分布式 Trace 协议 — SDK 侧注入/提取/observer 逻辑"""

import asyncio
import json
import secrets
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))
from aun_core.transport import RPCTransport
from aun_core.events import EventDispatcher


class FakeWS:
    """模拟 WebSocket 连接"""
    def __init__(self):
        self.sent: list[str] = []
        self.response_queue: asyncio.Queue = asyncio.Queue()

    async def send(self, data: str):
        self.sent.append(data)
        # 模拟立即返回 response
        msg = json.loads(data)
        rpc_id = msg.get("id")
        if rpc_id:
            resp = {"jsonrpc": "2.0", "id": rpc_id, "result": {"status": "ok"}}
            await self.response_queue.put(resp)

    async def recv(self):
        return json.dumps(await self.response_queue.get())

    async def close(self):
        pass


@pytest_asyncio.fixture
async def transport():
    dispatcher = EventDispatcher()
    t = RPCTransport(event_dispatcher=dispatcher, connection_factory=AsyncMock(), logger=MagicMock())
    t._ws = FakeWS()
    t._closed = False

    async def _fake_reader():
        while not t._closed:
            try:
                resp = await asyncio.wait_for(t._ws.response_queue.get(), timeout=0.1)
                rpc_id = resp.get("id")
                future = t._pending.get(rpc_id)
                if future and not future.done():
                    future.set_result(resp)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    t._reader_task = asyncio.create_task(_fake_reader())
    yield t
    t._closed = True
    t._reader_task.cancel()
    try:
        await t._reader_task
    except (asyncio.CancelledError, Exception):
        pass


@pytest.mark.asyncio
async def test_trace_off_no_injection(transport):
    """mode=off 时 params 中不应有 _trace"""
    # 默认 mode 是 off
    ws = transport._ws
    # 直接发送，不走 reader（手动 resolve）
    async def _call():
        return await transport.call("test.method", {"key": "val"})

    task = asyncio.create_task(_call())
    await asyncio.sleep(0.05)
    assert len(ws.sent) == 1
    sent_msg = json.loads(ws.sent[0])
    assert "_trace" not in sent_msg["params"]
    task.cancel()


@pytest.mark.asyncio
async def test_trace_log_injects_id_and_mode(transport):
    """mode=log 时注入 trace_id + mode，无 spans"""
    transport.set_trace_mode("log")
    ws = transport._ws

    task = asyncio.create_task(transport.call("test.method", {"key": "val"}))
    await asyncio.sleep(0.05)
    sent_msg = json.loads(ws.sent[0])
    trace = sent_msg["params"]["_trace"]
    assert trace["mode"] == "log"
    assert len(trace["trace_id"]) == 32
    assert "spans" not in trace
    task.cancel()


@pytest.mark.asyncio
async def test_trace_diag_injects_spans(transport):
    """mode=diag 时注入 spans 数组含 send span"""
    transport.set_trace_mode("diag")
    ws = transport._ws

    task = asyncio.create_task(transport.call("test.method", {}))
    await asyncio.sleep(0.05)
    sent_msg = json.loads(ws.sent[0])
    trace = sent_msg["params"]["_trace"]
    assert trace["mode"] == "diag"
    assert len(trace["spans"]) == 1
    span = trace["spans"][0]
    assert span["node"] == "sdk"
    assert span["action"] == "send"
    assert isinstance(span["ts"], int)
    task.cancel()


@pytest.mark.asyncio
async def test_trace_per_call_override(transport):
    """call(trace='diag') 覆盖 session-level 'log'"""
    transport.set_trace_mode("log")
    ws = transport._ws

    task = asyncio.create_task(transport.call("test.method", {}, trace="diag"))
    await asyncio.sleep(0.05)
    sent_msg = json.loads(ws.sent[0])
    trace = sent_msg["params"]["_trace"]
    assert trace["mode"] == "diag"
    assert "spans" in trace
    task.cancel()


@pytest.mark.asyncio
async def test_trace_observer_on_diag_response(transport):
    """response 含 _trace 时 observer 被调用"""
    observed = []
    transport.set_trace_observer(lambda info: observed.append(info))
    transport.set_trace_mode("diag")

    # 停掉默认 reader，手动 resolve pending future
    transport._reader_task.cancel()

    async def _call_and_resolve():
        # 启动 call（会 send 并等待 future）
        call_task = asyncio.create_task(transport.call("test.method", {}))
        await asyncio.sleep(0.05)
        # 手动 resolve pending future（模拟带 _trace 的 response）
        for rpc_id, future in list(transport._pending.items()):
            if not future.done():
                future.set_result({
                    "jsonrpc": "2.0", "id": rpc_id,
                    "result": {"status": "ok"},
                    "_trace": {"trace_id": "abc123", "mode": "diag", "spans": [
                        {"node": "gateway", "ts": 1000, "action": "relay_in", "ms": 1}
                    ]},
                })
        return await call_task

    result = await _call_and_resolve()
    assert result == {"status": "ok"}
    assert len(observed) == 1
    assert observed[0]["type"] == "rpc"
    assert observed[0]["trace"]["trace_id"] == "abc123"
    assert any(
        call.args[0] == "transport"
        and call.args[1] == "%s"
        and "[TRACE][test.method][ok]" in call.args[2]
        and "gateway.relay_in" in call.args[2]
        and "sdk.recv" in call.args[2]
        for call in transport._log.info.call_args_list
    )


@pytest.mark.asyncio
async def test_trace_printed_without_observer(transport):
    """只开启 trace=diag、不注册 observer 时，SDK 仍应打印完整 trace。"""
    transport.set_trace_mode("diag")
    transport._reader_task.cancel()

    async def _call_and_resolve():
        call_task = asyncio.create_task(transport.call("test.method", {}))
        await asyncio.sleep(0.05)
        for rpc_id, future in list(transport._pending.items()):
            if not future.done():
                future.set_result({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"status": "ok"},
                    "_trace": {"trace_id": "abc123", "mode": "diag", "spans": [
                        {"node": "gateway", "ts": 1000, "action": "relay_in", "method": "test.method", "route": "service_plane"},
                        {"node": "service", "ts": 1005, "action": "enter", "method": "test.method", "caller_aid": "alice.aid.com"},
                        {"node": "service", "ts": 1010, "action": "exit", "status": "ok", "ms": 5},
                        {"node": "gateway", "ts": 1015, "action": "relay_out", "status": "ok", "ms": 15},
                    ]},
                })
        return await call_task

    result = await _call_and_resolve()
    assert result == {"status": "ok"}
    trace_logs = [
        call.args[2]
        for call in transport._log.info.call_args_list
        if len(call.args) >= 3 and call.args[0] == "transport" and call.args[1] == "%s"
    ]
    assert len(trace_logs) == 1
    trace_log = trace_logs[0]
    assert "[TRACE][test.method][ok]" in trace_log
    assert "gateway.relay_in method=test.method route=service_plane" in trace_log
    assert "service.enter method=test.method caller_aid=alice.aid.com" in trace_log
    assert "service.exit status=ok dur=5ms" in trace_log
    assert "sdk.recv" in trace_log


@pytest.mark.asyncio
async def test_debug_logs_full_rpc_request_and_response(transport):
    result = await transport.call("test.method", {"payload": {"text": "hello"}})

    assert result == {"status": "ok"}
    debug_lines = [
        call.args[1] % call.args[2:]
        for call in transport._log.debug.call_args_list
        if call.args and call.args[0] == "transport"
    ]
    assert any("RPC request full:" in line and '"method":"test.method"' in line and '"text":"hello"' in line for line in debug_lines)
    assert any("RPC response full:" in line and '"result":{"status":"ok"}' in line for line in debug_lines)


@pytest.mark.asyncio
async def test_trace_event_stripped_from_params(transport):
    """事件 params 传给用户前已剥离 _trace"""
    received_params = []

    async def handler(params):
        received_params.append(params)

    transport._dispatcher.subscribe("_raw.message.received", handler)

    # 模拟收到带 _trace 的事件
    event_msg = {
        "jsonrpc": "2.0",
        "method": "event/message.received",
        "params": {
            "from": "alice.aid.com",
            "body": "hello",
            "_trace": {"trace_id": "xyz789", "mode": "log"},
        },
    }
    await transport._route_message(event_msg)
    await asyncio.sleep(0.05)
    assert len(received_params) == 1
    assert "_trace" not in received_params[0]
    assert received_params[0]["from"] == "alice.aid.com"


@pytest.mark.asyncio
async def test_trace_event_observer_can_filter_after_background_rpc(transport):
    """observer 同时收到后台 RPC 与事件 trace 时，目标事件仍可按 type/event 筛选。"""
    observed = []
    transport.set_trace_observer(lambda info: observed.append(info))

    observed.append({
        "type": "rpc",
        "method": "group.v2.get_proposal",
        "trace": {"trace_id": "background", "mode": "diag"},
    })
    await transport._route_message({
        "jsonrpc": "2.0",
        "method": "event/message.received",
        "params": {
            "from": "alice.aid.com",
            "payload": {"text": "hello"},
            "_trace": {"trace_id": "event123", "mode": "log"},
        },
    })

    message_events = [
        item for item in observed
        if item.get("type") == "event" and item.get("event") == "message.received"
    ]
    assert len(message_events) == 1
    assert message_events[0]["trace"]["trace_id"] == "event123"


@pytest.mark.asyncio
async def test_debug_logs_full_rpc_event(transport):
    event_msg = {
        "jsonrpc": "2.0",
        "method": "event/group.message_created",
        "params": {
            "group_id": "group.agentid.pub/11455",
            "payload": {"text": "hello group"},
        },
    }

    await transport._route_message(event_msg)

    debug_lines = [
        call.args[1] % call.args[2:]
        for call in transport._log.debug.call_args_list
        if call.args and call.args[0] == "transport"
    ]
    assert any("RPC event full:" in line and '"method":"event/group.message_created"' in line and '"hello group"' in line for line in debug_lines)


@pytest.mark.asyncio
async def test_set_trace_mode_validation(transport):
    """无效 mode 应抛 ValueError"""
    with pytest.raises(ValueError):
        transport.set_trace_mode("invalid")
    # 有效值不抛
    transport.set_trace_mode("off")
    transport.set_trace_mode("log")
    transport.set_trace_mode("diag")


def test_mode_cap_logic():
    """min(client, server) 各组合"""
    _ORDER = {"off": 0, "log": 1, "diag": 2}

    def _cap(client, server):
        return client if _ORDER[client] <= _ORDER[server] else server

    assert _cap("off", "log") == "off"
    assert _cap("log", "log") == "log"
    assert _cap("diag", "log") == "log"
    assert _cap("diag", "diag") == "diag"
    assert _cap("log", "off") == "off"
    assert _cap("off", "off") == "off"
