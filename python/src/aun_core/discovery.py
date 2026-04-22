from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .errors import ConnectionError, ValidationError

_discovery_log = logging.getLogger("aun_core.discovery")


class GatewayDiscovery:
    def __init__(self, *, verify_ssl: bool = True) -> None:
        self._verify_ssl = verify_ssl
        self._last_healthy: bool | None = None
        # 持有后台 Task 引用，防止被 GC 回收
        self._background_tasks: set = set()

    @property
    def last_healthy(self) -> bool | None:
        """最近一次 health check 结果，None 表示尚未检查。"""
        return self._last_healthy

    async def check_health(self, gateway_url: str, *, timeout: float = 5.0) -> bool:
        """向 gateway_url 对应的 /health 端点发送 HEAD 请求，检查网关可用性。"""
        import re
        health_url = re.sub(r'^wss?://', lambda m: 'https://' if m.group() == 'wss://' else 'http://', gateway_url)
        health_url = health_url.rstrip('/') + '/health'
        try:
            ssl_param = None if self._verify_ssl else False
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.head(health_url, ssl=ssl_param) as resp:
                    self._last_healthy = resp.status == 200
        except Exception as exc:
            _discovery_log.warning("check_health 异常 (%s): %s", health_url, exc)
            self._last_healthy = False
        return self._last_healthy  # type: ignore[return-value]

    async def discover(self, well_known_url: str, *, timeout: float = 5.0) -> str:
        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            ssl_param = None if self._verify_ssl else False
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.get(well_known_url, ssl=ssl_param) as response:
                    response.raise_for_status()
                    payload: dict[str, Any] = await response.json()
        except Exception as exc:
            raise ConnectionError(
                f"gateway discovery failed for {well_known_url}: {exc}",
                retryable=True,
            ) from exc

        gateways = payload.get("gateways", [])
        if not gateways:
            raise ValidationError("well-known returned empty gateways")

        gateways = sorted(gateways, key=lambda item: item.get("priority", 999))
        url = gateways[0].get("url")
        if not url:
            raise ValidationError("well-known missing gateway url")

        # 发现后异步触发 health check（不阻塞），保留 Task 引用防止 GC 回收
        import asyncio
        task = asyncio.create_task(self.check_health(str(url), timeout=timeout))
        task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return str(url)
