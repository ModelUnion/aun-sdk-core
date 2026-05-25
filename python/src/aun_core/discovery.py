from __future__ import annotations

import asyncio
from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

import aiohttp

from .errors import ConnectionError, ValidationError

if TYPE_CHECKING:
    from .logger import AUNLogger, NullLogger
    from .net import DnsResilientNet


class GatewayDiscovery:
    def __init__(self, *, verify_ssl: bool = True, logger: "AUNLogger | NullLogger | None" = None,
                 net: "DnsResilientNet | None" = None) -> None:
        from .logger import NullLogger as _NL
        self._log = logger or _NL()
        self._verify_ssl = verify_ssl
        self._last_healthy: bool | None = None
        self._background_tasks: set = set()
        self._net = net

    @property
    def last_healthy(self) -> bool | None:
        """最近一次 health check 结果，None 表示尚未检查。"""
        return self._last_healthy

    async def check_health(self, gateway_url: str, *, timeout: float = 5.0) -> bool:
        """向 gateway_url 对应的 /health 端点发送 GET 请求，检查网关可用性。"""
        import time as _t
        _t_start = _t.time()
        parsed = urlparse(gateway_url)
        scheme = "https" if parsed.scheme == "wss" else "http"
        health_url = urlunparse((scheme, parsed.netloc, "/health", "", "", ""))
        self._log.debug("discovery", "check_health enter: url=%s", health_url)
        try:
            if self._net:
                self._last_healthy = await self._net.http_get_ok(health_url, timeout=timeout)
            else:
                ssl_param = None if self._verify_ssl else False
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                    async with session.get(health_url, ssl=ssl_param) as resp:
                        self._last_healthy = resp.status == 200
        except Exception as exc:
            self._log.warn("discovery", "health check error: url=%s err=%s", health_url, exc)
            self._last_healthy = False
        if self._last_healthy:
            self._log.debug("discovery", "check_health exit: elapsed=%.3fs url=%s healthy=true", _t.time() - _t_start, health_url)
        else:
            self._log.warn("discovery", "check_health exit: elapsed=%.3fs url=%s healthy=false", _t.time() - _t_start, health_url)
        return self._last_healthy  # type: ignore[return-value]

    async def discover(self, well_known_url: str, *, timeout: float = 5.0) -> str:
        """发现优先级最高的单个网关 URL。"""
        urls = await self.discover_all(well_known_url, timeout=timeout)
        return urls[0]

    async def discover_all(self, well_known_url: str, *, timeout: float = 5.0) -> list[str]:
        """发现所有网关 URL（按 priority 排序）。"""
        import time as _t
        _t_start = _t.time()
        self._log.debug("discovery", "discover_all enter: well_known_url=%s", well_known_url)
        try:
            if self._net:
                payload = await self._net.http_get_json(well_known_url, timeout=timeout)
            else:
                client_timeout = aiohttp.ClientTimeout(total=timeout)
                ssl_param = None if self._verify_ssl else False
                async with aiohttp.ClientSession(timeout=client_timeout) as session:
                    async with session.get(well_known_url, ssl=ssl_param) as response:
                        response.raise_for_status()
                        payload = await response.json()
        except Exception as exc:
            self._log.warn("discovery", "discover_all exit (error): elapsed=%.3fs url=%s err=%s", _t.time() - _t_start, well_known_url, exc)
            raise ConnectionError(
                f"gateway discovery failed for {well_known_url}: {exc}",
                retryable=True,
            ) from exc

        gateways = payload.get("gateways", [])
        if not gateways:
            self._log.warn("discovery", "discover_all exit (empty list): elapsed=%.3fs url=%s", _t.time() - _t_start, well_known_url)
            raise ValidationError("well-known returned empty gateways")

        gateways = sorted(gateways, key=lambda item: item.get("priority", 999))
        urls = [g["url"] for g in gateways if g.get("url")]
        if not urls:
            self._log.warn("discovery", "discover_all exit (missing url): elapsed=%.3fs url=%s", _t.time() - _t_start, well_known_url)
            raise ValidationError("well-known missing gateway url")

        self._log.debug("discovery", "discover_all exit: elapsed=%.3fs gateway_urls=%s", _t.time() - _t_start, urls)

        # 异步触发 health check（不阻塞）
        task = asyncio.create_task(self.check_health(urls[0], timeout=timeout))
        task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return urls
