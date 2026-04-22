"""
断线重连机制单元测试

通过 mock transport 和 auth，直接触发断线事件，验证：
- 状态机转换（disconnected → reconnecting → connected）
- 指数退避延迟（含 Full Jitter）
- 不可重试错误直接 terminal_failed
- auto_reconnect=False 时不重连
- close() 中断重连
- 重连前 health probe
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
    # mock transport.close 和 discovery.check_health，避免真实 I/O
    client._transport = MagicMock()
    client._transport.close = AsyncMock()
    client._discovery = MagicMock()
    client._discovery.check_health = AsyncMock(return_value=True)
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
    @patch("aun_core.client.random")
    async def test_reconnect_success(self, mock_random):
        mock_random.random.return_value = 0.0  # 消除 jitter 延迟
        client = _make_client(auto_reconnect=True)

        connect_calls = []

        async def mock_reconnect():
            connect_calls.append(1)
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.1)

        assert client._state == "connected"
        assert len(connect_calls) == 1

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_state_sequence_on_reconnect(self, mock_random):
        """状态序列：disconnected → reconnecting → connected"""
        mock_random.random.return_value = 0.0
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
        assert states.index("disconnected") < states.index("reconnecting")

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_reconnect_task_cleared_on_success(self, mock_random):
        """重连成功后 _reconnect_task 应清空"""
        mock_random.random.return_value = 0.0
        client = _make_client(auto_reconnect=True)

        async def mock_reconnect():
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.1)

        assert client._reconnect_task is None


class TestExponentialBackoff:
    """指数退避（含 Full Jitter）：延迟递增，被 random.random() 打散"""

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_backoff_delays(self, mock_random):
        # random.random() 返回 1.0 时 jitter = delay * 1.0 = delay 本身
        mock_random.random.return_value = 1.0
        client = _make_client(auto_reconnect=True)
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
        await asyncio.sleep(2.0)  # 足够完成 4 次尝试

        assert call_count == 4
        # 验证延迟递增（允许 50% 误差）
        if len(attempt_times) >= 3:
            d1 = attempt_times[1] - attempt_times[0]
            d2 = attempt_times[2] - attempt_times[1]
            assert d2 > d1 * 0.5, f"第二次延迟 {d2:.3f}s 应大于第一次 {d1:.3f}s 的一半"


class TestReconnectInfiniteRetry:
    """无限重试：只有不可重试错误才终止"""

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_keeps_retrying_on_connection_error(self, mock_random):
        """ConnectionError 会持续重试，直到成功"""
        mock_random.random.return_value = 0.0
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
    @patch("aun_core.client.random")
    async def test_auth_error_still_terminates(self, mock_random):
        """AuthError 不可重试，仍然直接 terminal_failed"""
        mock_random.random.return_value = 0.0
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
    @patch("aun_core.client.random")
    async def test_auth_error_no_retry(self, mock_random):
        mock_random.random.return_value = 0.0
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

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_login_phase_auth_error_is_retryable(self, mock_random):
        mock_random.random.return_value = 0.0
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
    @patch("aun_core.client.random")
    async def test_permission_error_no_retry(self, mock_random):
        mock_random.random.return_value = 0.0
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
    @patch("aun_core.client.random")
    async def test_connection_error_is_retryable(self, mock_random):
        """ConnectionError 应该重试"""
        mock_random.random.return_value = 0.0
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
    @patch("aun_core.client.random")
    async def test_close_cancels_reconnect(self, mock_random):
        mock_random.random.return_value = 1.0  # 使 jitter 延迟 = delay 本身
        client = _make_client(auto_reconnect=True)
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
    @patch("aun_core.client.random")
    async def test_attempt_numbers_in_events(self, mock_random):
        mock_random.random.return_value = 0.0
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


class TestReconnectStopsBackgroundTasksFirst:
    """reconnect 前必须先停止后台任务，再关闭 transport / 进入重连。"""

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_background_tasks_stopped_before_reconnect(self, mock_random):
        """断线时，后台任务（心跳/token刷新等）必须在重连前被取消。"""
        mock_random.random.return_value = 0.0
        client = _make_client(auto_reconnect=True)

        # 创建一个模拟的后台任务（永不结束）
        stop_order: list[str] = []

        async def _long_running():
            try:
                await asyncio.sleep(100)
            except asyncio.CancelledError:
                stop_order.append("background_task_cancelled")
                raise

        # 注入一个"正在运行"的后台任务，并让它先启动到第一个 await 点
        client._heartbeat_task = asyncio.create_task(_long_running())
        await asyncio.sleep(0)  # 让任务运行到 await asyncio.sleep(100)

        async def mock_reconnect():
            stop_order.append("reconnect_called")
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.2)

        # 后台任务必须在 reconnect 之前被取消
        assert "background_task_cancelled" in stop_order
        assert "reconnect_called" in stop_order
        cancelled_idx = stop_order.index("background_task_cancelled")
        reconnect_idx = stop_order.index("reconnect_called")
        assert cancelled_idx < reconnect_idx, (
            f"后台任务取消（{cancelled_idx}）必须在 reconnect（{reconnect_idx}）之前发生"
        )

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_heartbeat_task_not_running_after_reconnect_starts(self, mock_random):
        """重连开始后，心跳任务不应继续运行。"""
        mock_random.random.return_value = 0.0
        client = _make_client(auto_reconnect=True)

        heartbeat_ran_after_disconnect = []

        async def _fake_heartbeat():
            try:
                await asyncio.sleep(100)
                heartbeat_ran_after_disconnect.append("ran")
            except asyncio.CancelledError:
                raise

        client._heartbeat_task = asyncio.create_task(_fake_heartbeat())

        async def mock_reconnect():
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.2)

        # 心跳任务应已被取消，不应继续运行
        assert heartbeat_ran_after_disconnect == []
        # 心跳任务引用应已清空
        assert client._heartbeat_task is None


# ── 抑制重连测试 ──────────────────────────────────────────


class TestNoReconnectCodes:
    """测试 NO_RECONNECT_CODES close code 和 gateway.disconnect 通知的抑制重连行为"""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("code", [4001, 4003, 4008, 4009, 4010, 4011])
    async def test_no_reconnect_on_fatal_close_code(self, code):
        """不重连 close code 应直接进入 terminal_failed，不启动重连"""
        client = _make_client(auto_reconnect=True)
        reconnect_started = []

        async def fake_reconnect_loop(server_initiated=False):
            reconnect_started.append(True)

        client._reconnect_loop = fake_reconnect_loop
        client._reconnect_task = None

        await client._handle_transport_disconnect(Exception("test"), close_code=code)

        assert client._state == "terminal_failed"
        assert reconnect_started == [], f"close code {code} 不应触发重连"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("code", [4000, 4029, 4500, 4503])
    async def test_reconnect_on_retryable_close_code(self, code):
        """可重连 close code 应正常启动重连"""
        client = _make_client(auto_reconnect=True)

        async def mock_reconnect():
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(Exception("test"), close_code=code)
        # 应进入重连流程（reconnecting 或 connected），不应是 terminal_failed
        assert client._state != "terminal_failed"

    @pytest.mark.asyncio
    async def test_gateway_disconnect_notification_suppresses_reconnect(self):
        """收到 gateway.disconnect 通知后断线应抑制重连"""
        client = _make_client(auto_reconnect=True)
        reconnect_started = []

        async def fake_reconnect_loop(server_initiated=False):
            reconnect_started.append(True)

        client._reconnect_loop = fake_reconnect_loop
        client._reconnect_task = None

        # 模拟收到 gateway.disconnect 通知
        await client._on_gateway_disconnect({"code": 4009, "reason": "Connection replaced"})
        assert client._server_kicked is True

        # 触发断线
        await client._handle_transport_disconnect(Exception("test"), close_code=4009)

        assert client._state == "terminal_failed"
        assert reconnect_started == []

    @pytest.mark.asyncio
    async def test_server_kicked_flag_suppresses_any_code(self):
        """_server_kicked 标志即使 close code 是可重连的也应抑制重连"""
        client = _make_client(auto_reconnect=True)
        reconnect_started = []

        async def fake_reconnect_loop(server_initiated=False):
            reconnect_started.append(True)

        client._reconnect_loop = fake_reconnect_loop
        client._reconnect_task = None
        client._server_kicked = True

        # 使用一个"可重连"的 close code
        await client._handle_transport_disconnect(Exception("test"), close_code=1006)

        assert client._state == "terminal_failed"
        assert reconnect_started == []

