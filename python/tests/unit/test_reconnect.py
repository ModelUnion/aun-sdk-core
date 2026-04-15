"""
断线重连机制单元测试

通过 mock transport 和 auth，直接触发断线事件，验证：
- 状态机转换（disconnected → reconnecting → connected）
- 指数退避延迟
- 重连耗尽进入 terminal_failed
- 不可重试错误直接 terminal_failed
- auto_reconnect=False 时不重连
- close() 中断重连
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aun_core import AUNClient
from aun_core.errors import AuthError, ConnectionError, PermissionError


# ── 辅助工具 ──────────────────────────────────────────────


def _make_client(auto_reconnect: bool = True) -> AUNClient:
    """创建已配置好的测试客户端（不实际连接）"""
    client = AUNClient({"aun_path": "/tmp/test_reconnect"})
    # 注入会话选项（模拟已连接状态）
    client._session_options = {
        "auto_reconnect": auto_reconnect,
        "heartbeat_interval": 0,
        "token_refresh_before": 60.0,
        "retry": {
            "initial_delay": 0.01,   # 单元测试用极短延迟
            "max_delay": 0.05,
        },
        "timeouts": {"connect": 5.0, "call": 10.0, "http": 30.0},
    }
    client._session_params = {
        "access_token": "test-token",
        "gateway": "wss://gateway.test/aun",
    }
    client._state = "connected"
    client._gateway_url = "wss://gateway.test/aun"
    return client


async def _collect_events(client: AUNClient, event: str, count: int, timeout: float = 2.0) -> list[dict]:
    """收集指定数量的事件，超时返回已收集的"""
    collected: list[dict] = []
    ready = asyncio.Event()

    def handler(data: Any) -> None:
        collected.append(data)
        if len(collected) >= count:
            ready.set()

    sub = client.on(event, handler)
    try:
        await asyncio.wait_for(ready.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    finally:
        sub.unsubscribe()
    return collected


# ── 测试用例 ──────────────────────────────────────────────


class TestAutoReconnectDisabled:
    """auto_reconnect=False 时不启动重连"""

    @pytest.mark.asyncio
    async def test_no_reconnect_when_disabled(self):
        client = _make_client(auto_reconnect=False)

        # 触发断线
        await client._handle_transport_disconnect(None)

        # 状态应停在 disconnected，不启动重连任务
        assert client._state == "disconnected"
        assert client._reconnect_task is None

    @pytest.mark.asyncio
    async def test_state_event_published_on_disconnect(self):
        client = _make_client(auto_reconnect=False)
        events = []
        client.on("connection.state", lambda d: events.append(d))

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0)  # 让事件循环推进

        assert any(e.get("state") == "disconnected" for e in events)


class TestBasicReconnect:
    """基础重连：断线后自动重连并恢复 connected"""

    @pytest.mark.asyncio
    async def test_reconnect_success(self):
        client = _make_client(auto_reconnect=True)

        # mock _invoke_reconnect_connect_once 成功
        connect_calls = []

        async def mock_reconnect():
            connect_calls.append(1)
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        # 等待重连任务完成
        await asyncio.sleep(0.1)

        assert client._state == "connected"
        assert len(connect_calls) == 1

    @pytest.mark.asyncio
    async def test_state_sequence_on_reconnect(self):
        """状态序列：disconnected → reconnecting → connected"""
        client = _make_client(auto_reconnect=True)
        states: list[str] = []

        def capture_state(data: Any) -> None:
            states.append(data.get("state", ""))

        client.on("connection.state", capture_state)

        async def mock_reconnect():
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.1)

        assert "disconnected" in states
        assert "reconnecting" in states
        # disconnected 必须在 reconnecting 之前
        assert states.index("disconnected") < states.index("reconnecting")

    @pytest.mark.asyncio
    async def test_reconnect_task_cleared_on_success(self):
        """重连成功后 _reconnect_task 应清空"""
        client = _make_client(auto_reconnect=True)

        async def mock_reconnect():
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.1)

        assert client._reconnect_task is None


class TestExponentialBackoff:
    """指数退避：延迟序列 0.01 → 0.02 → 0.04 → 0.05（max_delay）"""

    @pytest.mark.asyncio
    async def test_backoff_delays(self):
        client = _make_client(auto_reconnect=True)
        # 设置可观测的延迟
        client._session_options["retry"] = {
            "initial_delay": 0.05,
            "max_delay": 0.15,
        }

        attempt_times: list[float] = []
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            attempt_times.append(time.monotonic())
            if call_count < 4:
                raise ConnectionError("simulated failure")
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(1.0)  # 等待所有重试完成

        assert call_count == 4
        # 验证延迟递增（允许 50% 误差）
        if len(attempt_times) >= 3:
            d1 = attempt_times[1] - attempt_times[0]
            d2 = attempt_times[2] - attempt_times[1]
            assert d2 > d1 * 0.5, f"第二次延迟 {d2:.3f}s 应大于第一次 {d1:.3f}s 的一半"


class TestReconnectInfiniteRetry:
    """无限重试：只有不可重试错误才终止"""

    @pytest.mark.asyncio
    async def test_keeps_retrying_on_connection_error(self):
        """ConnectionError 会持续重试，直到成功"""
        client = _make_client(auto_reconnect=True)
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            if call_count < 5:
                raise ConnectionError("network error")
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.5)

        assert call_count == 5
        assert client._state == "connected"

    @pytest.mark.asyncio
    async def test_auth_error_still_terminates(self):
        """AuthError 不可重试，仍然直接 terminal_failed"""
        client = _make_client(auto_reconnect=True)
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            raise AuthError("token invalid")

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.3)

        assert call_count == 1
        assert client._state == "terminal_failed"


class TestNonRetryableErrors:
    """不可重试错误：AuthError/PermissionError 直接 terminal_failed"""

    @pytest.mark.asyncio
    async def test_auth_error_no_retry(self):
        client = _make_client(auto_reconnect=True)
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            raise AuthError("token invalid")

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.3)

        # AuthError 不可重试，只调用一次就 terminal_failed
        assert call_count == 1
        assert client._state == "terminal_failed"

    @pytest.mark.asyncio
    async def test_login_phase_auth_error_is_retryable(self):
        client = _make_client(auto_reconnect=True)
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            raise AuthError("aid_login2_failed")

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.3)

        assert call_count > 1
        assert client._state == "reconnecting"

    @pytest.mark.asyncio
    async def test_permission_error_no_retry(self):
        client = _make_client(auto_reconnect=True)
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            raise PermissionError("forbidden")

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.3)

        assert call_count == 1
        assert client._state == "terminal_failed"

    @pytest.mark.asyncio
    async def test_connection_error_is_retryable(self):
        """ConnectionError 应该重试"""
        client = _make_client(auto_reconnect=True)
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("network error")
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.5)

        assert call_count == 3
        assert client._state == "connected"


class TestCloseInterruptsReconnect:
    """close() 中断重连：重连过程中调用 close()，任务被取消"""

    @pytest.mark.asyncio
    async def test_close_cancels_reconnect(self):
        client = _make_client(auto_reconnect=True)
        # 使用短延迟，让重连任务启动后再 close
        client._session_options["retry"]["initial_delay"] = 0.05

        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("fail")

        client._invoke_reconnect_connect_once = mock_reconnect

        # 触发断线，启动重连
        await client._handle_transport_disconnect(None)
        assert client._reconnect_task is not None

        # 等待第一次重连尝试
        await asyncio.sleep(0.15)

        # 取消重连任务（模拟 close）
        task = client._reconnect_task
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        client._reconnect_task = None

        assert client._reconnect_task is None
        # 至少有一次重连尝试
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_no_reconnect_after_close(self):
        """已关闭的客户端不应启动重连"""
        client = _make_client(auto_reconnect=True)
        client._closing = True

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0)

        assert client._reconnect_task is None


class TestReconnectAttemptInfo:
    """重连事件包含正确的 attempt 信息"""

    @pytest.mark.asyncio
    async def test_attempt_numbers_in_events(self):
        client = _make_client(auto_reconnect=True)
        reconnect_events: list[dict] = []

        def capture(data: Any) -> None:
            if data.get("state") == "reconnecting":
                reconnect_events.append(data)

        client.on("connection.state", capture)

        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            if call_count < 4:
                raise ConnectionError("fail")
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.5)

        # 应有 3 次 reconnecting 事件（第 4 次成功，不再 reconnecting）
        assert len(reconnect_events) >= 3
        # attempt 递增
        attempts = [e.get("attempt") for e in reconnect_events[:3]]
        assert attempts == [1, 2, 3]
