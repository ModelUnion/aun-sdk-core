"""DNS-Resilient 网络层。

所有 HTTP/WebSocket 请求统一经过此模块，提供 DNS 容灾能力：
- 正常走域名（利用系统 DNS 缓存和 CDN 调度）
- 连接成功后刷新 DNS→IP 映射到 SQLite
- DNS 失败时 fallback 到持久化的最后一次成功 IP
- IP 直连时设置 TLS SNI + Host header
"""
from __future__ import annotations

import socket
import sqlite3
import ssl
import time
import threading
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

import aiohttp

if TYPE_CHECKING:
    from .logger import AUNLogger, NullLogger


_DNS_CACHE_DDL = """CREATE TABLE IF NOT EXISTS dns_cache (
    hostname TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    updated_at INTEGER NOT NULL
)"""


def _is_dns_error(exc: BaseException) -> bool:
    if isinstance(exc, socket.gaierror):
        return True
    if isinstance(exc, OSError) and "Name or service not known" in str(exc):
        return True
    if isinstance(exc, aiohttp.ClientConnectorError):
        inner = exc.__cause__
        if inner and _is_dns_error(inner):
            return True
        msg = str(exc).lower()
        if "name or service not known" in msg or "nodename nor servname" in msg or "getaddrinfo failed" in msg:
            return True
    return False


def _parse_host_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if parsed.port:
        port = parsed.port
    elif parsed.scheme in ("https", "wss"):
        port = 443
    else:
        port = 80
    return hostname, port


def _replace_host_with_ip(url: str, ip: str) -> str:
    parsed = urlparse(url)
    if ":" in ip:
        netloc_host = f"[{ip}]"
    else:
        netloc_host = ip
    if parsed.port:
        netloc = f"{netloc_host}:{parsed.port}"
    else:
        netloc = netloc_host
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def _resolve_ip(hostname: str, port: int) -> str | None:
    try:
        results = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


class DnsResilientNet:
    """统一 DNS 容灾网络层。

    使用独立的 SQLite 文件 `{aun_path}/dns_cache.db` 持久化 DNS 缓存，
    不依赖 per-AID 数据库，在连接建立之前即可使用。
    """

    def __init__(self, aun_path: str | Path | None = None, *,
                 verify_ssl: bool = True,
                 logger: "AUNLogger | NullLogger | None" = None) -> None:
        from .logger import NullLogger as _NL
        self._verify_ssl = verify_ssl
        self._log = logger or _NL()
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        if aun_path:
            db_path = Path(aun_path) / "dns_cache.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute(_DNS_CACHE_DDL)
                self._conn.commit()
            except Exception as exc:
                self._log.warn("net", "dns_cache.db init failed: %s", exc)
                self._conn = None

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def _ssl_param(self) -> Any:
        return None if self._verify_ssl else False

    def _save_dns_cache(self, hostname: str, ip: str, port: int) -> None:
        if not self._conn or not hostname or not ip:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO dns_cache (hostname, ip, port, updated_at) VALUES (?, ?, ?, ?)",
                    (hostname, ip, port, int(time.time())),
                )
                self._conn.commit()
        except Exception as exc:
            self._log.debug("net", "save_dns_cache failed: %s", exc)

    def _load_dns_cache(self, hostname: str) -> tuple[str, int] | None:
        if not self._conn or not hostname:
            return None
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT ip, port FROM dns_cache WHERE hostname = ?", (hostname,)
                )
                row = cur.fetchone()
            if row:
                return (str(row[0]), int(row[1]))
        except Exception as exc:
            self._log.debug("net", "load_dns_cache failed: %s", exc)
        return None

    def _refresh_dns_cache_after_success(self, url: str) -> None:
        hostname, port = _parse_host_port(url)
        if not hostname:
            return
        ip = _resolve_ip(hostname, port)
        if ip:
            self._save_dns_cache(hostname, ip, port)

    async def http_get(self, url: str, *, timeout: float = 5.0,
                       headers: dict[str, str] | None = None) -> bytes:
        hostname, port = _parse_host_port(url)
        client_timeout = aiohttp.ClientTimeout(total=timeout)

        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.get(url, ssl=self._ssl_param(), headers=headers) as resp:
                    resp.raise_for_status()
                    data = await resp.read()
            self._refresh_dns_cache_after_success(url)
            return data
        except Exception as exc:
            if not _is_dns_error(exc):
                raise

        self._log.debug("net", "DNS failed for %s, trying cached IP", hostname)
        cached = self._load_dns_cache(hostname)
        if not cached:
            from .errors import ConnectionError as AUNConnectionError
            raise AUNConnectionError(
                f"DNS failed and no cached IP for {hostname}",
                retryable=True,
            )

        ip, cached_port = cached
        ip_url = _replace_host_with_ip(url, ip)
        req_headers = dict(headers or {})
        req_headers["Host"] = hostname if port in (80, 443) else f"{hostname}:{port}"

        ssl_ctx: Any = self._ssl_param()
        if self._verify_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = True
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
            async with session.get(ip_url, ssl=ssl_ctx, headers=req_headers,
                                   server_hostname=hostname) as resp:
                resp.raise_for_status()
                return await resp.read()

    async def http_get_json(self, url: str, *, timeout: float = 5.0,
                            headers: dict[str, str] | None = None) -> dict[str, Any]:
        import json
        data = await self.http_get(url, timeout=timeout, headers=headers)
        return json.loads(data)

    async def http_get_text(self, url: str, *, timeout: float = 5.0,
                            headers: dict[str, str] | None = None) -> str:
        data = await self.http_get(url, timeout=timeout, headers=headers)
        return data.decode("utf-8")

    async def http_get_ok(self, url: str, *, timeout: float = 5.0) -> bool:
        hostname, port = _parse_host_port(url)
        client_timeout = aiohttp.ClientTimeout(total=timeout)

        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.get(url, ssl=self._ssl_param()) as resp:
                    ok = resp.status == 200
            if ok:
                self._refresh_dns_cache_after_success(url)
            return ok
        except Exception as exc:
            if not _is_dns_error(exc):
                return False

        cached = self._load_dns_cache(hostname)
        if not cached:
            return False

        ip, _ = cached
        ip_url = _replace_host_with_ip(url, ip)
        req_headers = {"Host": hostname if port in (80, 443) else f"{hostname}:{port}"}

        try:
            ssl_ctx: Any = self._ssl_param()
            if self._verify_ssl:
                ssl_ctx = ssl.create_default_context()
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
                async with session.get(ip_url, ssl=ssl_ctx, headers=req_headers,
                                       server_hostname=hostname) as resp:
                    return resp.status == 200
        except Exception:
            return False
