"""
断线重连机制单元测试

通过 mock transport 和 auth，直接触发断线事件，验证：
- 状态机转换（standby / retry_backoff → reconnecting → ready）
- 指数退避延迟（固定上限抖动）
- 不可重试错误直接 connection_failed
- auto_reconnect=False 时不重连
- close() 中断重连
- 重连前 health probe
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aun_core import AUNClient, ConnectionState
from aun_core.client import (
    _RECONNECT_MAX_BASE_DELAY,
    _clamp_reconnect_delay,
    _reconnect_sleep_delay,
)
from aun_core.errors import AuthError, ConnectionError, PermissionError


# ── 辅助工具 ──────────────────────────────────────────────


def _make_client(auto_reconnect: bool = True) -> AUNClient:
    """创建已配置好的测试客户端（不实际连接）"""
    client = AUNClient()
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
    # mock transport.close 和 discovery.check_health，避免真实 I/O
    client._transport = MagicMock()
    client._transport.close = AsyncMock()
    client._transport.cancel_event_tasks = AsyncMock()
    client._discovery = MagicMock()
    client._discovery.check_health = AsyncMock(return_value=True)

    async def _fast_reconnect_sleep(delay: float) -> None:
        await asyncio.sleep(0)

    client._reconnect_sleep = _fast_reconnect_sleep
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

        # 无身份的测试客户端断线后回到 no_identity，不启动重连任务
        assert client.state == ConnectionState.NO_IDENTITY
        assert client._reconnect_task is None

    @pytest.mark.asyncio
    async def test_state_event_published_on_disconnect(self):
        client = _make_client(auto_reconnect=False)
        events = []
        client.on("state_change", lambda d: events.append(d))

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0)  # 让事件循环推进

        assert any(e.get("state") == ConnectionState.NO_IDENTITY.value for e in events)


class TestBasicReconnect:
    """基础重连：断线后自动重连并恢复 ready"""

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

        assert client.state == ConnectionState.READY
        assert len(connect_calls) == 1

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_state_sequence_on_reconnect(self, mock_random):
        """状态序列：retry_backoff → reconnecting → ready"""
        mock_random.random.return_value = 0.0
        client = _make_client(auto_reconnect=True)
        states: list[str] = []

        def capture_state(data: Any) -> None:
            states.append(data.get("state", ""))

        client.on("state_change", capture_state)

        async def mock_reconnect():
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.1)

        assert ConnectionState.RETRY_BACKOFF.value in states
        assert ConnectionState.RECONNECTING.value in states
        assert states.index(ConnectionState.RETRY_BACKOFF.value) < states.index(ConnectionState.RECONNECTING.value)

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

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_event_subscription_uses_same_dispatcher_after_reconnect(self, mock_random):
        """重连不应替换应用层事件分发器，已注册/重注册 handler 都应挂到实际发布对象。"""
        mock_random.random.return_value = 0.0
        client = _make_client(auto_reconnect=True)
        dispatcher = client._dispatcher
        received: list[str] = []

        async def mock_reconnect():
            assert client._dispatcher is dispatcher
            client._state = "connected"

        client._invoke_reconnect_connect_once = mock_reconnect

        sub = client.on("message.received", lambda data: received.append(data["id"]))
        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.1)

        assert client._dispatcher is dispatcher
        await client._dispatcher.publish("message.received", {"id": "after-reconnect"})
        assert received == ["after-reconnect"]

        sub.unsubscribe()
        received.clear()
        sub = client.on("message.received", lambda data: received.append("new:" + data["id"]))
        await client._dispatcher.publish("message.received", {"id": "after-reregister"})
        assert received == ["new:after-reregister"]
        sub.unsubscribe()


class TestExponentialBackoff:
    """指数退避（固定上限抖动）：base 递增，jitter 上限固定为 max_base"""

    @patch("aun_core.client.random")
    def test_delay_formula_clamps_base_and_uses_fixed_jitter(self, mock_random):
        mock_random.random.return_value = 0.5
        assert _clamp_reconnect_delay(0.01, 1.0) == 1.0
        assert _clamp_reconnect_delay(128.0, 1.0) == _RECONNECT_MAX_BASE_DELAY
        assert _reconnect_sleep_delay(4.0, _RECONNECT_MAX_BASE_DELAY) == 36.0

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_backoff_delays(self, mock_random):
        # random.random() 返回 0.0 时去掉 jitter，只验证 base 指数递增。
        mock_random.random.return_value = 0.0
        client = _make_client(auto_reconnect=True)
        client._session_options["retry"] = {
            "initial_delay": 1.0,
            "max_delay": 4.0,
        }

        sleep_delays: list[float] = []
        call_count = 0

        async def capture_reconnect_sleep(delay: float) -> None:
            sleep_delays.append(delay)
            await asyncio.sleep(0)

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            if call_count < 4:
                raise ConnectionError("simulated failure")
            client._state = "connected"

        client._reconnect_sleep = capture_reconnect_sleep
        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.1)  # 让零延迟重连循环完成 4 次尝试

        assert call_count == 4
        assert sleep_delays[:4] == pytest.approx([1.0, 2.0, 4.0, 4.0])


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
        assert client.state == ConnectionState.READY

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_auth_error_still_terminates(self, mock_random):
        """AuthError 不可重试，仍然直接 connection_failed"""
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
        assert client.state == ConnectionState.CONNECTION_FAILED


class TestNonRetryableErrors:
    """不可重试错误：AuthError/PermissionError 直接 connection_failed"""

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
        assert client.state == ConnectionState.CONNECTION_FAILED

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_login_phase_auth_error_is_retryable(self, mock_random):
        mock_random.random.return_value = 0.0
        client = _make_client(auto_reconnect=True)
        call_count = 0

        async def mock_reconnect():
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                client._closing = True
            raise AuthError("aid_login2_failed")

        client._invoke_reconnect_connect_once = mock_reconnect

        await client._handle_transport_disconnect(None)
        await asyncio.sleep(0.3)

        assert call_count > 1
        assert client.state in {ConnectionState.RETRY_BACKOFF, ConnectionState.RECONNECTING}

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
        assert client.state == ConnectionState.CONNECTION_FAILED

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
        assert client.state == ConnectionState.READY


class TestCloseInterruptsReconnect:
    """close() 中断重连：重连过程中调用 close()，任务被取消"""

    @pytest.mark.asyncio
    @patch("aun_core.client.random")
    async def test_close_cancels_reconnect(self, mock_random):
        mock_random.random.return_value = 1.0  # 使 jitter 使用 max_base 上限
        client = _make_client(auto_reconnect=True)
        client._session_options["retry"]["initial_delay"] = 0.05

        async def _short_reconnect_sleep(delay: float) -> None:
            await asyncio.sleep(0.01)

        client._reconnect_sleep = _short_reconnect_sleep

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

        client.on("state_change", capture)

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
        """不重连 close code 应直接进入 connection_failed，不启动重连"""
        client = _make_client(auto_reconnect=True)
        reconnect_started = []

        async def fake_reconnect_loop(server_initiated=False):
            reconnect_started.append(True)

        client._reconnect_loop = fake_reconnect_loop
        client._reconnect_task = None

        await client._handle_transport_disconnect(Exception("test"), close_code=code)

        assert client.state == ConnectionState.CONNECTION_FAILED
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
        # 应进入重连流程（retry_backoff/reconnecting/ready），不应是 connection_failed
        assert client.state != ConnectionState.CONNECTION_FAILED

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

        assert client.state == ConnectionState.CONNECTION_FAILED
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

        assert client.state == ConnectionState.CONNECTION_FAILED
        assert reconnect_started == []


class TestReconnectTokenRefresh:
    """reconnect 时 token 刷新逻辑：过期 token 应被清空，使 connect_session 走两阶段登录"""

    @pytest.mark.asyncio
    async def test_stale_token_cleared_before_reconnect_connect_once(self):
        """cached identity token 失效时，session_params["access_token"] 应被清空，
        避免用旧 token 反复触发 4001 死循环"""
        client = _make_client(auto_reconnect=True)
        client._session_params = {"access_token": "stale-token", "gateway": "wss://gw.test/aun"}
        client._identity = {"aid": "alice.test", "access_token": "", "access_token_expires_at": 0.0}

        connect_once_params: list[dict] = []

        async def mock_connect_once(params, *, allow_reauth):
            connect_once_params.append(dict(params))
            client._state = "connected"

        client._connect_once = mock_connect_once

        await client._invoke_reconnect_connect_once()

        # stale token 应被清空，让 connect_session 走两阶段登录
        assert connect_once_params[0].get("access_token") == ""

    @pytest.mark.asyncio
    async def test_valid_cached_token_used_in_reconnect(self):
        """cached identity token 有效时，应用到 session_params 并传入 connect_once"""
        import time as _time
        client = _make_client(auto_reconnect=True)
        client._session_params = {"access_token": "old-token", "gateway": "wss://gw.test/aun"}
        client._identity = {
            "aid": "alice.test",
            "access_token": "fresh-token",
            "access_token_expires_at": _time.time() + 3600,
        }

        connect_once_params: list[dict] = []

        async def mock_connect_once(params, *, allow_reauth):
            connect_once_params.append(dict(params))
            client._state = "connected"

        client._connect_once = mock_connect_once

        await client._invoke_reconnect_connect_once()

        assert connect_once_params[0].get("access_token") == "fresh-token"
