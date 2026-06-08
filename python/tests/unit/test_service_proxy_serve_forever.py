"""
service_proxy.serve_forever 重连策略单元测试

验证：
- 连接失败时使用指数退避
- 连接成功后退避 delay 重置
- AuthError 触发重新登录（_authenticate_for_access_token）再重连
- stop() 中断循环
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from aun_core.errors import AuthError
from aun_core.service_proxy import ServiceProxyClient


def _make_proxy(aun_client=None):
    proxy = ServiceProxyClient(provider_aid="holder.test")
    proxy._aun_client = aun_client
    return proxy


class TestServeForeverBackoff:
    """指数退避：失败延迟递增，成功后重置"""

    @pytest.mark.asyncio
    async def test_backoff_increases_on_repeated_failure(self):
        proxy = _make_proxy()
        call_count = 0
        sleep_delays: list[float] = []

        async def _sleep(secs):
            sleep_delays.append(secs)
            if len(sleep_delays) >= 3:
                proxy.stop()

        proxy._sleep_or_stop = _sleep
        proxy._auto_register_services_with_gateway = AsyncMock(return_value=0)

        async def _connect():
            nonlocal call_count
            call_count += 1
            raise OSError("refused")

        proxy._connect_proxy_ws = _connect

        await proxy.serve_forever(reconnect_delay_seconds=1.0)

        # delay 应该递增：1.0, 2.0, 4.0 ...
        assert sleep_delays[0] < sleep_delays[1]
        assert sleep_delays[1] < sleep_delays[2] or sleep_delays[1] == sleep_delays[2]  # 允许到达上限后平稳

    @pytest.mark.asyncio
    async def test_backoff_resets_after_successful_connection(self):
        proxy = _make_proxy()
        sleep_delays: list[float] = []
        attempt = 0

        async def _sleep(secs):
            sleep_delays.append(secs)
            if len(sleep_delays) >= 2:
                proxy.stop()

        proxy._sleep_or_stop = _sleep
        proxy._auto_register_services_with_gateway = AsyncMock(return_value=0)

        async def _connect():
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                raise OSError("first fail")
            # 第二次"连接"成功后 serve_tunnel 正常返回，再第三次连接失败
            if attempt == 2:
                class FakeWS:
                    async def __aenter__(self): return self
                    async def __aexit__(self, *a): pass
                return FakeWS()
            raise OSError("third fail")

        async def _fake_serve_tunnel(ws, **_):
            return {"registered": 0, "handled_requests": 0}

        proxy._connect_proxy_ws = _connect
        proxy._serve_tunnel = _fake_serve_tunnel

        await proxy.serve_forever(reconnect_delay_seconds=1.0)

        # 成功连接后的失败 delay 应重置为初始值，不应继续增长
        assert sleep_delays[-1] == pytest.approx(1.0, abs=0.1)


class TestServeForeverAuthRetry:
    """AuthError 触发重新登录"""

    @pytest.mark.asyncio
    async def test_auth_error_triggers_reauthentication(self):
        """连接时 AuthError → 调用 _authenticate_for_access_token → 继续重连"""
        proxy = _make_proxy()
        reauth_calls = 0
        attempt = 0
        sleep_count = 0

        async def _sleep(secs):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                proxy.stop()

        proxy._sleep_or_stop = _sleep
        proxy._auto_register_services_with_gateway = AsyncMock(return_value=0)

        async def _connect():
            nonlocal attempt
            attempt += 1
            if attempt <= 2:
                raise AuthError("token expired")
            raise OSError("stop")

        async def _reauth():
            nonlocal reauth_calls
            reauth_calls += 1
            return "new-token"

        proxy._connect_proxy_ws = _connect
        proxy._authenticate_for_access_token = _reauth

        await proxy.serve_forever(reconnect_delay_seconds=0.01)

        # 每次 AuthError 都应触发重新登录
        assert reauth_calls >= 2

    @pytest.mark.asyncio
    async def test_non_auth_error_does_not_trigger_reauthentication(self):
        """网络错误不应调用 _authenticate_for_access_token"""
        proxy = _make_proxy()
        reauth_calls = 0
        sleep_count = 0

        async def _sleep(secs):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                proxy.stop()

        proxy._sleep_or_stop = _sleep
        proxy._auto_register_services_with_gateway = AsyncMock(return_value=0)

        async def _connect():
            raise OSError("network error")

        async def _reauth():
            nonlocal reauth_calls
            reauth_calls += 1
            return "new-token"

        proxy._connect_proxy_ws = _connect
        proxy._authenticate_for_access_token = _reauth

        await proxy.serve_forever(reconnect_delay_seconds=0.01)

        assert reauth_calls == 0
