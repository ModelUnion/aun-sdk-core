from __future__ import annotations

import asyncio
import json
import base64
import ssl
import time
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp
from aiohttp import WSMsgType
from aiohttp import web
import websockets

from ..errors import AuthError, ConnectionError, ValidationError
from ..logger import NullLogger
from .protocol_detection import (
    detect_request_protocol,
    is_stream_response_headers,
    stream_type_from_response,
)
from .registry import EmbeddedServiceRegistry, EndpointPolicy, ServiceRecord


_LOG_MODULE = "service_proxy"
_HOP_BY_HOP_HEADERS = {
    "connection",
    "upgrade",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
}
_AUTO_RESPONSE_HEADERS = {
    "content-length",
    "date",
    "server",
}
_PROXY_DISCOVERY_CACHE_KEY = "service_proxy_discovery"
_PROXY_DISCOVERY_CACHE_TTL_SECONDS = 3600.0
_TOKEN_EXPIRY_SKEW_SECONDS = 30.0


class _ResponseBodyTooLarge(Exception):
    pass


class _RequestBodyStreamError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = str(code or "invalid_body_stream")
        self.message = str(message or "request body stream is invalid")


class ServiceProxyClient:
    def __init__(
        self,
        *,
        provider_aid: str,
        registry: EmbeddedServiceRegistry | None = None,
        endpoint_policy: EndpointPolicy | None = None,
        logger: Any = None,
        aun_client: Any = None,
        max_response_body_bytes: int = 16 * 1024 * 1024,
        max_tunnel_message_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.provider_aid = str(provider_aid or "").strip()
        self.registry = registry or EmbeddedServiceRegistry(endpoint_policy=endpoint_policy)
        self._log = logger or NullLogger()
        self._aun_client = aun_client
        self.max_response_body_bytes = max(1, int(max_response_body_bytes or 1))
        self.max_tunnel_message_bytes = max(1, int(max_tunnel_message_bytes or 1))
        self._running = False
        self._stop_event: asyncio.Event | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    def stop(self) -> None:
        self._running = False
        if self._stop_event is not None:
            self._stop_event.set()

    def _log_warning(self, message: str, *args: object) -> None:
        self._call_logger("warn", message, *args)

    def _log_error(self, message: str, *args: object, err: BaseException | None = None) -> None:
        self._call_logger("error", message, *args, err=err)

    def _log_info(self, message: str, *args: object) -> None:
        self._call_logger("info", message, *args)

    def _log_access(self, event: str, **fields: object) -> None:
        payload: dict[str, object] = {
            "event": str(event or ""),
            "ts_ms": int(time.time() * 1000),
        }
        for key, value in fields.items():
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)):
                payload[str(key)] = value
            elif isinstance(value, (list, tuple)):
                payload[str(key)] = [str(item) for item in value]
            else:
                payload[str(key)] = str(value)
        try:
            self._log_info("ACCESS %s", json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str))
        except Exception:
            pass

    def _call_logger(self, level: str, message: str, *args: object, err: BaseException | None = None) -> None:
        method = getattr(self._log, level, None)
        if not callable(method):
            return
        try:
            if level == "error":
                method(_LOG_MODULE, message, *args, err=err)
            else:
                method(_LOG_MODULE, message, *args)
        except TypeError:
            text = message % args if args else message
            try:
                method(text)
            except Exception:
                pass
        except Exception:
            pass

    @staticmethod
    def _duration_ms(started_at: float) -> int:
        return max(0, int((time.monotonic() - started_at) * 1000))

    @staticmethod
    def _query_log_fields(query_string: object) -> dict[str, object]:
        text = str(query_string or "")
        return {
            "has_query": bool(text),
            "query_length": len(text),
        }

    @staticmethod
    def _endpoint_log_fields(endpoint: str) -> dict[str, object]:
        parsed = urlparse(str(endpoint or ""))
        try:
            port = parsed.port or 0
        except ValueError:
            port = 0
        return {
            "endpoint_scheme": parsed.scheme,
            "endpoint_host": parsed.hostname or "",
            "endpoint_port": port,
            "endpoint_base_path": parsed.path or "/",
        }

    def register_service(
        self,
        service_name: str,
        endpoint: str,
        *,
        service_type: str = "http",
        visibility: str = "private",
        metadata: dict[str, Any] | None = None,
    ) -> ServiceRecord:
        return self.registry.register(
            service_name,
            endpoint,
            service_type=service_type,
            visibility=visibility,
            metadata=metadata,
        )

    def unregister_service(self, service_name: str) -> bool:
        return self.registry.unregister(service_name)

    def list_service_summaries(self) -> list[dict[str, Any]]:
        return self.registry.list_summaries()

    def _gateway_call_method(self, *, required: bool = False):
        call = getattr(self._aun_client, "call", None) if self._aun_client is not None else None
        if callable(call):
            return call
        if required:
            raise ValidationError("Gateway service registration requires aun_client with call()")
        return None

    async def register_services_with_gateway(self, services: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """通过 AUN Gateway 的 proxy.* 控制面注册当前 provider 的服务列表。"""
        call = self._gateway_call_method(required=True)
        payload_services = self.list_service_summaries() if services is None else list(services)
        result = call("proxy.register_services", {
            "provider_aid": self.provider_aid,
            "services": payload_services,
        })
        if hasattr(result, "__await__"):
            result = await result
        if not isinstance(result, dict):
            result = {}
        if result.get("ok") is False:
            raise ValidationError(str(result.get("error") or "Gateway service registration failed"))
        return result

    async def unregister_services_from_gateway(self, service_names: list[str] | str | None = None) -> dict[str, Any]:
        """从 AUN Gateway 的 proxy.* 控制面注销当前连接上的服务列表。"""
        call = self._gateway_call_method(required=True)
        params: dict[str, Any] = {"provider_aid": self.provider_aid}
        if isinstance(service_names, str):
            params["service_names"] = [service_names]
        elif service_names is not None:
            params["service_names"] = [str(name) for name in service_names]
        result = call("proxy.unregister_services", params)
        if hasattr(result, "__await__"):
            result = await result
        return result if isinstance(result, dict) else {}

    async def list_gateway_services(self) -> dict[str, Any]:
        """查询 Gateway 当前连接记录的 proxy 服务列表。"""
        call = self._gateway_call_method(required=True)
        result = call("proxy.list_services", {"provider_aid": self.provider_aid})
        if hasattr(result, "__await__"):
            result = await result
        return result if isinstance(result, dict) else {}

    async def _auto_register_services_with_gateway(self) -> dict[str, Any]:
        call = self._gateway_call_method(required=False)
        if call is None:
            return {"skipped": True}
        return await self.register_services_with_gateway()

    @staticmethod
    def _issuer_domain_for_aid(aid: str) -> str:
        target = str(aid or "").strip().lower()
        if "." not in target:
            return ""
        return target.split(".", 1)[1].strip(".")

    def _should_verify_ssl(self) -> bool:
        cfg = getattr(self._aun_client, "_config_model", None)
        if cfg is not None and hasattr(cfg, "verify_ssl"):
            return bool(getattr(cfg, "verify_ssl"))
        current_aid = getattr(self._aun_client, "current_aid", None)
        if current_aid is not None and hasattr(current_aid, "verify_ssl"):
            return bool(getattr(current_aid, "verify_ssl"))
        return True

    def _proxy_well_known_urls(self) -> list[str]:
        provider_aid = self.provider_aid
        issuer = self._issuer_domain_for_aid(provider_aid)
        if not provider_aid or not issuer:
            raise ValidationError("provider_aid must be a full AID for Service Proxy discovery")
        return [
            f"https://{provider_aid}/.well-known/aun-proxy",
            f"https://proxy.{issuer}/.well-known/aun-proxy",
        ]

    def _normalize_proxy_ws_url(self, raw_url: str) -> str:
        url = str(raw_url or "").strip()
        if not url:
            return ""
        try:
            parsed = urlparse(url)
        except Exception:
            return ""
        if parsed.scheme == "ws" and self._should_verify_ssl():
            return ""
        if parsed.scheme not in {"wss", "ws"}:
            return ""
        if parsed.username or parsed.password or not parsed.netloc or not parsed.hostname:
            return ""
        if not parsed.path or parsed.path == "/":
            return ""
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))

    def _select_proxy_ws_url(self, payload: dict[str, Any]) -> str:
        direct = self._normalize_proxy_ws_url(str(payload.get("ws_url") or ""))
        if direct:
            return direct
        servers = payload.get("proxy_servers")
        if isinstance(servers, list):
            normalized = [item for item in servers if isinstance(item, dict)]
            normalized.sort(key=lambda item: item.get("priority", 999))
            for item in normalized:
                ws_url = self._normalize_proxy_ws_url(str(item.get("ws_url") or ""))
                if ws_url:
                    return ws_url
        return ""

    async def _fetch_proxy_well_known(self, well_known_url: str, *, timeout: float = 5.0) -> dict[str, Any]:
        client_timeout = aiohttp.ClientTimeout(total=max(0.1, float(timeout or 5.0)))
        ssl_param = None if self._should_verify_ssl() else False
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.get(well_known_url, ssl=ssl_param) as response:
                response.raise_for_status()
                payload = await response.json()
        if not isinstance(payload, dict):
            raise ValidationError("Service Proxy well-known returned invalid payload")
        ws_url = self._select_proxy_ws_url(payload)
        if not ws_url:
            raise ValidationError("Service Proxy well-known missing valid ws_url")
        discovered = dict(payload)
        discovered["ws_url"] = ws_url
        discovered["source_url"] = well_known_url
        discovered["discovered_at"] = time.time()
        return discovered

    def _load_cached_proxy_discovery(self) -> dict[str, Any] | None:
        token_store = getattr(self._aun_client, "_token_store", None)
        if token_store is None:
            return None
        try:
            getter = getattr(token_store, "get_metadata_value", None)
            if callable(getter):
                raw = str(getter(self.provider_aid, _PROXY_DISCOVERY_CACHE_KEY) or "").strip()
            else:
                metadata = token_store.load_metadata(self.provider_aid) or {}
                fields = metadata.get("fields") if isinstance(metadata, dict) else {}
                raw = str((fields or {}).get(_PROXY_DISCOVERY_CACHE_KEY) or "").strip()
        except Exception:
            return None
        if not raw:
            return None
        try:
            cached = json.loads(raw)
        except Exception:
            return None
        if not isinstance(cached, dict):
            return None
        ws_url = self._normalize_proxy_ws_url(str(cached.get("ws_url") or ""))
        if not ws_url:
            return None
        try:
            discovered_at = float(cached.get("discovered_at") or 0.0)
        except (TypeError, ValueError):
            return None
        if time.time() - discovered_at >= _PROXY_DISCOVERY_CACHE_TTL_SECONDS:
            return None
        cached["ws_url"] = ws_url
        cached["cached"] = True
        return cached

    def _persist_proxy_discovery(self, discovery: dict[str, Any]) -> None:
        token_store = getattr(self._aun_client, "_token_store", None)
        if token_store is None or not self.provider_aid:
            return
        try:
            setter = getattr(token_store, "set_metadata_value", None)
            if callable(setter):
                setter(
                    self.provider_aid,
                    _PROXY_DISCOVERY_CACHE_KEY,
                    json.dumps(discovery, ensure_ascii=False, separators=(",", ":")),
                )
        except Exception as exc:
            self._log_warning("Service Proxy discovery cache write failed: %s", exc)

    async def discover_proxy_server(self, *, force_refresh: bool = False, timeout: float = 5.0) -> dict[str, Any]:
        if not force_refresh:
            cached = self._load_cached_proxy_discovery()
            if cached is not None:
                return cached

        errors: list[str] = []
        for url in self._proxy_well_known_urls():
            try:
                discovery = await self._fetch_proxy_well_known(url, timeout=timeout)
                self._persist_proxy_discovery(discovery)
                return discovery
            except Exception as exc:
                errors.append(f"{url}: {exc}")
                self._log_warning("Service Proxy discovery failed: url=%s err=%s", url, exc)
        raise ConnectionError("Service Proxy discovery failed: " + "; ".join(errors), retryable=True)

    async def discover_proxy_ws_url(self, *, force_refresh: bool = False, timeout: float = 5.0) -> str:
        discovery = await self.discover_proxy_server(force_refresh=force_refresh, timeout=timeout)
        return str(discovery.get("ws_url") or "").strip()

    async def connect_once(
        self,
        *,
        auth_request_id: str = "auth",
        register_request_id: str = "register-services",
        heartbeat_request_id: str | None = None,
    ) -> dict[str, Any]:
        self._running = True
        try:
            await self._auto_register_services_with_gateway()
            async with await self._connect_proxy_ws() as ws:
                await ws.send(json.dumps({
                    "type": "service_proxy_auth",
                    "request_id": auth_request_id,
                    "provider_aid": self.provider_aid,
                    "client_version": "python",
                }, ensure_ascii=False))
                auth_response = json.loads(await ws.recv())
                if not auth_response.get("ok"):
                    error = auth_response.get("error") if isinstance(auth_response.get("error"), dict) else {}
                    raise AuthError(str(error.get("message") or "Service Proxy auth failed"))

                registered = await self.register_services_with_proxy_server(
                    ws,
                    register_request_id=register_request_id,
                )

                heartbeat_ok = False
                if heartbeat_request_id:
                    await ws.send(json.dumps({
                        "type": "heartbeat",
                        "request_id": heartbeat_request_id,
                    }, ensure_ascii=False))
                    heartbeat_response = json.loads(await ws.recv())
                    heartbeat_ok = bool(heartbeat_response.get("ok"))

                return {
                    "registered": registered,
                    "heartbeat": heartbeat_ok,
                }
        finally:
            self._running = False

    async def serve_once(
        self,
        *,
        auth_request_id: str = "auth",
        register_request_id: str = "register-services",
        max_requests: int = 1,
    ) -> dict[str, Any]:
        self._running = True
        try:
            await self._auto_register_services_with_gateway()
            async with await self._connect_proxy_ws() as ws:
                result = await self._serve_tunnel(
                    ws,
                    auth_request_id=auth_request_id,
                    register_request_id=register_request_id,
                    max_requests=max_requests,
                )
                return result
        finally:
            self._running = False

    async def serve_forever(
        self,
        *,
        connection_mode: str = "persistent",
        auth_request_id: str = "auth",
        register_request_id: str = "register-services",
        idle_timeout_seconds: float = 60.0,
        reconnect_delay_seconds: float = 1.0,
    ) -> dict[str, Any]:
        mode = str(connection_mode or "persistent").strip().lower()
        if mode not in {"persistent", "on_demand"}:
            raise ValidationError("connection_mode must be persistent or on_demand")
        self._running = True
        self._stop_event = asyncio.Event()
        stats = {
            "connection_mode": mode,
            "connections": 0,
            "registered": 0,
            "handled_requests": 0,
            "wakeup_count": 0,
        }
        _proxy_reconnect_max_delay = 60.0
        try:
            if mode == "persistent":
                _delay = reconnect_delay_seconds
                while self._running:
                    try:
                        await self._auto_register_services_with_gateway()
                        async with await self._connect_proxy_ws() as ws:
                            result = await self._serve_tunnel(
                                ws,
                                auth_request_id=auth_request_id,
                                register_request_id=register_request_id,
                                idle_timeout_seconds=None,
                            )
                            stats["connections"] += 1
                            stats["registered"] = int(result.get("registered", stats["registered"]))
                            stats["handled_requests"] += int(result.get("handled_requests", 0))
                            _delay = reconnect_delay_seconds  # 连接成功后重置退避
                    except asyncio.CancelledError:
                        raise
                    except AuthError as exc:
                        if not self._running:
                            break
                        self._log_warning("persistent tunnel auth error, re-authenticating: %s", exc)
                        try:
                            await self._authenticate_for_access_token()
                        except Exception as reauth_exc:
                            self._log_warning("re-authentication failed: %s", reauth_exc)
                        await self._sleep_or_stop(_delay)
                        _delay = min(_delay * 2, _proxy_reconnect_max_delay)
                    except Exception as exc:
                        if not self._running:
                            break
                        self._log_warning("persistent tunnel reconnect scheduled after error: %s", exc)
                        await self._sleep_or_stop(_delay)
                        _delay = min(_delay * 2, _proxy_reconnect_max_delay)
                return stats
            return await self._serve_on_demand(
                stats=stats,
                auth_request_id=auth_request_id,
                register_request_id=register_request_id,
                idle_timeout_seconds=idle_timeout_seconds,
                reconnect_delay_seconds=reconnect_delay_seconds,
            )
        finally:
            self._running = False
            if self._stop_event is not None:
                self._stop_event.set()

    async def _serve_on_demand(
        self,
        *,
        stats: dict[str, Any],
        auth_request_id: str,
        register_request_id: str,
        idle_timeout_seconds: float,
        reconnect_delay_seconds: float,
    ) -> dict[str, Any]:
        if self._aun_client is None or not hasattr(self._aun_client, "on"):
            raise ValidationError("on_demand mode requires aun_client with on()")
        await self._auto_register_services_with_gateway()
        queue: asyncio.Queue = asyncio.Queue()

        def _on_wakeup(payload: Any) -> None:
            if not isinstance(payload, dict):
                return
            if str(payload.get("type") or "") != "aun.service_proxy.wakeup":
                return
            provider_aid = str(payload.get("provider_aid") or "").strip()
            if provider_aid and provider_aid != self.provider_aid:
                return
            queue.put_nowait(dict(payload))

        subscription = self._aun_client.on("app.service_proxy.wakeup", _on_wakeup)
        try:
            while self._running:
                wakeup = await self._wait_queue_or_stop(queue)
                if wakeup is None:
                    break
                stats["wakeup_count"] += 1
                try:
                    await self._auto_register_services_with_gateway()
                    async with await self._connect_proxy_ws() as ws:
                        result = await self._serve_tunnel(
                            ws,
                            auth_request_id=auth_request_id,
                            register_request_id=register_request_id,
                            idle_timeout_seconds=idle_timeout_seconds,
                        )
                        stats["connections"] += 1
                        stats["registered"] = int(result.get("registered", stats["registered"]))
                        stats["handled_requests"] += int(result.get("handled_requests", 0))
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if not self._running:
                        break
                    self._log_warning("on-demand tunnel connection failed after wakeup: %s", exc)
                    await self._sleep_or_stop(reconnect_delay_seconds)
            return stats
        finally:
            unsubscribe = getattr(subscription, "unsubscribe", None)
            if callable(unsubscribe):
                unsubscribe()

    async def _serve_tunnel(
        self,
        ws,
        *,
        auth_request_id: str,
        register_request_id: str,
        max_requests: int | None = None,
        idle_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        handled_requests = 0
        active_ws_queues: dict[str, asyncio.Queue] = {}
        active_ws_tasks: dict[str, asyncio.Task] = {}

        def _cleanup_done_ws_tasks() -> None:
            for connection_id, task in list(active_ws_tasks.items()):
                if not task.done():
                    continue
                active_ws_tasks.pop(connection_id, None)
                active_ws_queues.pop(connection_id, None)
                try:
                    task.result()
                except Exception as exc:
                    if not self._is_websocket_connection_closed(exc):
                        self._log_error(
                            "websocket backend task failed: connection_id=%s err=%s",
                            connection_id,
                            exc,
                            err=exc,
                        )
                        raise

        registered = await self._auth_and_register(
            ws,
            auth_request_id=auth_request_id,
            register_request_id=register_request_id,
        )
        try:
            while self._running:
                _cleanup_done_ws_tasks()
                if max_requests is not None and handled_requests >= max_requests and not active_ws_tasks:
                    break
                if max_requests is not None and handled_requests >= max_requests and active_ws_tasks:
                    await asyncio.wait(
                        set(active_ws_tasks.values()),
                        timeout=0.01,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    _cleanup_done_ws_tasks()
                    if not active_ws_tasks:
                        break

                try:
                    raw = await self._recv_tunnel_message(ws, idle_timeout_seconds, bool(active_ws_tasks))
                except asyncio.TimeoutError:
                    if not active_ws_tasks:
                        break
                    continue
                if raw is None:
                    break
                message = json.loads(raw)
                if not isinstance(message, dict):
                    continue
                msg_type = message.get("type")
                if msg_type == "service_proxy_request":
                    request_id = str(message.get("request_id") or "")
                    body_iter = None
                    if bool(message.get("body_stream")):
                        body_iter = self._iter_request_body_chunks(
                            ws,
                            request_id=request_id,
                            active_ws_queues=active_ws_queues,
                        )
                    if body_iter is None:
                        async for response in self.iter_request_messages(message):
                            await ws.send(json.dumps(response, ensure_ascii=False))
                    else:
                        async for response in self.iter_request_messages(message, body_iter=body_iter):
                            await ws.send(json.dumps(response, ensure_ascii=False))
                    handled_requests += 1
                elif msg_type == "ws_connect":
                    connection_id = str(message.get("connection_id") or "")
                    if not connection_id:
                        await self._send_tunnel_message(ws, self._ws_error_message(
                            "",
                            "missing_connection_id",
                            "connection_id is required",
                        ))
                        continue
                    queue: asyncio.Queue = asyncio.Queue()
                    active_ws_queues[connection_id] = queue
                    active_ws_tasks[connection_id] = asyncio.create_task(
                        self.handle_ws_connect_message(message, ws, inbound_queue=queue)
                    )
                    handled_requests += 1
                elif msg_type in ("ws_message", "ws_close", "ws_error"):
                    connection_id = str(message.get("connection_id") or "")
                    queue = active_ws_queues.get(connection_id)
                    if queue is not None:
                        queue.put_nowait(message)
                    elif connection_id:
                        await self._send_tunnel_message(ws, self._ws_error_message(
                            connection_id,
                            "unknown_ws_connection",
                            "WebSocket connection is not active",
                        ))
                elif msg_type == "heartbeat_ack":
                    continue
                else:
                    await ws.send(json.dumps(self._error_message(
                        str(message.get("request_id") or ""),
                        "unsupported_message",
                        "unsupported Service Proxy tunnel message",
                    ), ensure_ascii=False))
            return {"registered": registered, "handled_requests": handled_requests}
        finally:
            for task in active_ws_tasks.values():
                task.cancel()
            if active_ws_tasks:
                results = await asyncio.gather(*active_ws_tasks.values(), return_exceptions=True)
                for connection_id, result in zip(active_ws_tasks.keys(), results):
                    if not isinstance(result, BaseException):
                        continue
                    if isinstance(result, asyncio.CancelledError) or self._is_websocket_connection_closed(result):
                        continue
                    self._log_error(
                        "websocket backend task cleanup observed error: connection_id=%s err=%s",
                        connection_id,
                        result,
                        err=result,
                    )

    async def _recv_tunnel_message(self, ws, idle_timeout_seconds: float | None, has_active_ws: bool) -> str | None:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        recv_task = asyncio.create_task(ws.recv())
        stop_task = asyncio.create_task(self._stop_event.wait())
        tasks = {recv_task, stop_task}
        try:
            timeout = None
            if idle_timeout_seconds is not None:
                timeout = max(0.0, float(idle_timeout_seconds or 0.0))
                if has_active_ws:
                    timeout = max(timeout, 0.01)
            done, pending = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            if not done:
                raise asyncio.TimeoutError()
            if stop_task in done:
                recv_task.cancel()
                return None
            stop_task.cancel()
            return await recv_task
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def _wait_queue_or_stop(self, queue: asyncio.Queue) -> dict[str, Any] | None:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        get_task = asyncio.create_task(queue.get())
        stop_task = asyncio.create_task(self._stop_event.wait())
        tasks = {get_task, stop_task}
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if stop_task in done:
                get_task.cancel()
                return None
            stop_task.cancel()
            value = await get_task
            return value if isinstance(value, dict) else {}
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def _sleep_or_stop(self, seconds: float) -> None:
        if seconds <= 0:
            return
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            return

    @staticmethod
    def _mapping_access_token(mapping: dict[str, Any]) -> str:
        token = str(mapping.get("access_token") or mapping.get("token") or mapping.get("kite_token") or "").strip()
        if not token:
            return ""
        expires_at = mapping.get("access_token_expires_at", mapping.get("expires_at"))
        if isinstance(expires_at, (int, float)) and float(expires_at) <= time.time() + _TOKEN_EXPIRY_SKEW_SECONDS:
            return ""
        return token

    def _resolve_cached_access_token(self) -> str:
        aun_client = self._aun_client
        if aun_client is not None:
            token = str(getattr(aun_client, "access_token", "") or "").strip()
            expires_at = getattr(aun_client, "access_token_expires_at", None)
            if token and not (
                isinstance(expires_at, (int, float))
                and float(expires_at) <= time.time() + _TOKEN_EXPIRY_SKEW_SECONDS
            ):
                return token
            identity = getattr(aun_client, "_identity", None)
            if isinstance(identity, dict):
                token = self._mapping_access_token(identity)
                if token:
                    return token
            auth_flow = getattr(aun_client, "_auth", None)
            load_identity = getattr(auth_flow, "load_identity_or_none", None)
            if callable(load_identity):
                try:
                    identity = load_identity(self.provider_aid)
                    if isinstance(identity, dict):
                        token = self._mapping_access_token(identity)
                        if token:
                            return token
                except Exception:
                    pass
            token_store = getattr(aun_client, "_token_store", None)
            load_state = getattr(token_store, "load_instance_state", None)
            if callable(load_state):
                try:
                    device_id = str(getattr(aun_client, "device_id", "") or getattr(aun_client, "_device_id", "") or "")
                    slot_id = str(getattr(aun_client, "slot_id", "") or getattr(aun_client, "_slot_id", "") or "")
                    state = load_state(self.provider_aid, device_id, slot_id)
                    if isinstance(state, dict):
                        token = self._mapping_access_token(state)
                        if token:
                            return token
                except Exception:
                    pass
        return ""

    async def _authenticate_for_access_token(self) -> str:
        aun_client = self._aun_client
        if aun_client is None:
            raise AuthError("Service Proxy tunnel requires aun_client for AUN token authentication")
        authenticate = getattr(aun_client, "authenticate", None)
        if not callable(authenticate):
            raise AuthError("Service Proxy tunnel requires aun_client.authenticate() for AUN token authentication")
        try:
            result = authenticate()
            if hasattr(result, "__await__"):
                result = await result
        except Exception as exc:
            raise AuthError("AUNClient authenticate failed for Service Proxy tunnel") from exc
        if isinstance(result, dict):
            token = self._mapping_access_token(result)
            if token:
                return token
        raise AuthError("AUNClient authenticate did not return a valid access_token")

    async def _ensure_access_token(self) -> str:
        token = self._resolve_cached_access_token()
        if token:
            return token
        return await self._authenticate_for_access_token()

    def _proxy_ws_ssl_context(self, proxy_url: str):
        if not str(proxy_url or "").strip().lower().startswith("wss://"):
            return None
        if self._should_verify_ssl():
            return None
        return ssl._create_unverified_context()

    async def _connect_proxy_ws(self):
        proxy_url = await self.discover_proxy_ws_url()
        token = await self._ensure_access_token()
        if not token:
            raise AuthError("AUN access_token is required for Service Proxy tunnel")
        kwargs: dict[str, Any] = {
            "max_size": self.max_tunnel_message_bytes,
            "additional_headers": {"Authorization": f"Bearer {token}"},
        }
        ssl_context = self._proxy_ws_ssl_context(proxy_url)
        if ssl_context is not None:
            kwargs["ssl"] = ssl_context
        return websockets.connect(proxy_url, **kwargs)

    def _should_stream_request(self, message: dict[str, Any]) -> bool:
        service_name = str(message.get("service_name") or "")
        try:
            record = self.registry.get(service_name)
        except ValidationError:
            return False
        if record is None:
            return False
        return detect_request_protocol(message, record).is_stream

    @staticmethod
    def _is_stream_response_headers(headers: dict[str, Any]) -> bool:
        return is_stream_response_headers(headers)

    async def register_services_with_proxy_server(
        self,
        ws,
        *,
        register_request_id: str = "register-services",
        services: list[dict[str, Any]] | None = None,
    ) -> int:
        """通过已连接的 proxy-server 隧道注册数据面服务列表。"""
        payload_services = self.list_service_summaries() if services is None else list(services)
        await ws.send(json.dumps({
            "type": "register_services",
            "request_id": register_request_id,
            "services": payload_services,
        }, ensure_ascii=False))
        register_response = json.loads(await ws.recv())
        if not register_response.get("ok"):
            raise ValidationError("Service Proxy service registration failed")
        return int(register_response.get("count", len(payload_services)))

    async def _auth_and_register(self, ws, *, auth_request_id: str, register_request_id: str) -> int:
        await ws.send(json.dumps({
            "type": "service_proxy_auth",
            "request_id": auth_request_id,
            "provider_aid": self.provider_aid,
            "client_version": "python",
        }, ensure_ascii=False))
        auth_response = json.loads(await ws.recv())
        if not auth_response.get("ok"):
            error = auth_response.get("error") if isinstance(auth_response.get("error"), dict) else {}
            raise AuthError(str(error.get("message") or "Service Proxy auth failed"))

        return await self.register_services_with_proxy_server(
            ws,
            register_request_id=register_request_id,
        )

    async def _iter_request_body_chunks(
        self,
        ws,
        *,
        request_id: str,
        active_ws_queues: dict[str, asyncio.Queue] | None = None,
    ):
        while True:
            raw = await ws.recv()
            try:
                message = json.loads(raw)
            except Exception as exc:
                raise _RequestBodyStreamError("invalid_body_stream", "request body stream message is invalid") from exc
            if not isinstance(message, dict):
                raise _RequestBodyStreamError("invalid_body_stream", "request body stream message is invalid")

            msg_type = message.get("type")
            if msg_type in ("ws_message", "ws_close", "ws_error"):
                connection_id = str(message.get("connection_id") or "")
                queue = (active_ws_queues or {}).get(connection_id)
                if queue is not None:
                    queue.put_nowait(message)
                    continue

            if msg_type != "service_proxy_request_body":
                raise _RequestBodyStreamError("invalid_body_stream", "unexpected tunnel message while reading body")
            if str(message.get("request_id") or "") != request_id:
                raise _RequestBodyStreamError("invalid_body_stream", "request body stream request_id mismatch")

            error = message.get("error") if isinstance(message.get("error"), dict) else {}
            if error:
                raise _RequestBodyStreamError(
                    str(error.get("code") or "request_body_stream_error"),
                    str(error.get("message") or "request body stream failed"),
                )

            data_text = str(message.get("data_base64") or "")
            if data_text:
                try:
                    data = base64.b64decode(data_text, validate=True)
                except Exception as exc:
                    raise _RequestBodyStreamError("invalid_body", "data_base64 is invalid") from exc
                if data:
                    yield data
            if bool(message.get("done")):
                return

    async def handle_request_message(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id = str(message.get("request_id") or "")
        service_name = str(message.get("service_name") or "")
        record = self.registry.get(service_name)
        if record is None:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                error="service_not_registered",
            )
            return self._error_message(request_id, "service_not_registered", "service is not registered")

        method = str(message.get("method") or "GET").upper()
        path = str(message.get("path") or "/")
        if not path.startswith("/"):
            path = "/" + path
        query_string = str(message.get("query_string") or "")
        target_url = urljoin(record.endpoint.rstrip("/") + "/", path.lstrip("/"))
        if query_string:
            target_url = f"{target_url}?{query_string}"

        try:
            body = base64.b64decode(str(message.get("body_base64") or ""), validate=True) if message.get("body_base64") else b""
        except Exception:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                error="invalid_body",
            )
            return self._error_message(request_id, "invalid_body", "body_base64 is invalid")

        headers = self._backend_headers(message.get("headers") if isinstance(message.get("headers"), dict) else {})
        started_at = time.monotonic()
        request_fields = {
            "request_id": request_id,
            "provider_aid": self.provider_aid,
            "service_name": service_name,
            "method": method,
            "path": path,
            "service_type": record.service_type,
            "stream": False,
            "body_stream": bool(message.get("body_stream")),
        }
        request_fields.update(self._query_log_fields(query_string))
        request_fields.update(self._endpoint_log_fields(record.endpoint))
        self._log_access("backend_request_start", **request_fields)
        backend_status = 0
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(method, target_url, headers=headers, data=body) as response:
                    backend_status = int(response.status)
                    response_body = await self._read_response_body_limited(response)
                    self._log_access(
                        "backend_response",
                        request_id=request_id,
                        provider_aid=self.provider_aid,
                        service_name=service_name,
                        method=method,
                        path=path,
                        status=backend_status,
                        stream=False,
                        duration_ms=self._duration_ms(started_at),
                    )
                    return {
                        "type": "service_proxy_response",
                        "request_id": request_id,
                        "status": int(response.status),
                        "headers": self._response_headers(dict(response.headers)),
                        "body_base64": base64.b64encode(response_body).decode("ascii"),
                    }
        except _ResponseBodyTooLarge:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                status=backend_status,
                error="response_body_too_large",
                duration_ms=self._duration_ms(started_at),
            )
            return self._error_message(
                request_id,
                "response_body_too_large",
                "backend response body is too large",
            )
        except Exception as exc:
            self._log_warning("backend request failed: request_id=%s service_name=%s", request_id, service_name)
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                status=backend_status,
                error="backend_unreachable",
                error_type=type(exc).__name__,
                duration_ms=self._duration_ms(started_at),
            )
            return self._error_message(request_id, "backend_unreachable", "backend request failed")

    async def iter_request_messages(self, message: dict[str, Any], *, chunk_size: int = 65536, body_iter: Any = None):
        request_id = str(message.get("request_id") or "")
        service_name = str(message.get("service_name") or "")
        record = self.registry.get(service_name)
        if record is None:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                error="service_not_registered",
            )
            yield self._error_message(request_id, "service_not_registered", "service is not registered")
            return

        method = str(message.get("method") or "GET").upper()
        path = str(message.get("path") or "/")
        if not path.startswith("/"):
            path = "/" + path
        query_string = str(message.get("query_string") or "")
        target_url = urljoin(record.endpoint.rstrip("/") + "/", path.lstrip("/"))
        if query_string:
            target_url = f"{target_url}?{query_string}"

        body_stream = bool(message.get("body_stream"))
        if body_stream:
            if body_iter is None:
                self._log_access(
                    "backend_request_error",
                    request_id=request_id,
                    provider_aid=self.provider_aid,
                    service_name=service_name,
                    method=method,
                    path=path,
                    error="missing_body_stream",
                )
                yield self._error_message(request_id, "missing_body_stream", "request body stream is missing")
                return
            request_body = body_iter
        else:
            try:
                request_body = (
                    base64.b64decode(str(message.get("body_base64") or ""), validate=True)
                    if message.get("body_base64")
                    else b""
                )
            except Exception:
                self._log_access(
                    "backend_request_error",
                    request_id=request_id,
                    provider_aid=self.provider_aid,
                    service_name=service_name,
                    method=method,
                    path=path,
                    error="invalid_body",
                )
                yield self._error_message(request_id, "invalid_body", "body_base64 is invalid")
                return

        headers = self._backend_headers(message.get("headers") if isinstance(message.get("headers"), dict) else {})
        started_at = time.monotonic()
        request_fields = {
            "request_id": request_id,
            "provider_aid": self.provider_aid,
            "service_name": service_name,
            "method": method,
            "path": path,
            "service_type": record.service_type,
            "stream": bool(message.get("stream") or message.get("is_stream")),
            "body_stream": body_stream,
        }
        request_fields.update(self._query_log_fields(query_string))
        request_fields.update(self._endpoint_log_fields(record.endpoint))
        self._log_access("backend_request_start", **request_fields)
        backend_status = 0
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(method, target_url, headers=headers, data=request_body) as response:
                    backend_status = int(response.status)
                    response_headers = self._response_headers(dict(response.headers))
                    request_detection = detect_request_protocol(message, record)
                    response_header_stream = (
                        request_detection.stream_mode != "no_stream"
                        and self._is_stream_response_headers(response_headers)
                    )
                    should_stream = request_detection.is_stream or response_header_stream
                    if not should_stream:
                        response_body = await self._read_response_body_limited(response)
                        self._log_access(
                            "backend_response",
                            request_id=request_id,
                            provider_aid=self.provider_aid,
                            service_name=service_name,
                            method=method,
                            path=path,
                            status=backend_status,
                            stream=False,
                            stream_type=request_detection.service_type,
                            duration_ms=self._duration_ms(started_at),
                        )
                        yield {
                            "type": "service_proxy_response",
                            "request_id": request_id,
                            "status": int(response.status),
                            "headers": response_headers,
                            "body_base64": base64.b64encode(response_body).decode("ascii"),
                        }
                        return

                    stream_type = stream_type_from_response(response_headers, fallback=request_detection.service_type)
                    response_headers.setdefault("x-stream-type", stream_type)
                    self._log_access(
                        "backend_response",
                        request_id=request_id,
                        provider_aid=self.provider_aid,
                        service_name=service_name,
                        method=method,
                        path=path,
                        status=backend_status,
                        stream=True,
                        stream_type=stream_type,
                        duration_ms=self._duration_ms(started_at),
                    )
                    pending_chunk: bytes | None = None
                    index = 0
                    async for chunk in response.content.iter_chunked(max(1, int(chunk_size or 65536))):
                        if pending_chunk is not None:
                            yield {
                                "type": "service_proxy_stream",
                                "request_id": request_id,
                                "index": index,
                                "status": int(response.status) if index == 0 else None,
                                "headers": response_headers if index == 0 else {},
                                "data_base64": base64.b64encode(pending_chunk).decode("ascii"),
                                "done": False,
                            }
                            index += 1
                        pending_chunk = bytes(chunk)
                    if pending_chunk is not None:
                        yield {
                            "type": "service_proxy_stream",
                            "request_id": request_id,
                            "index": index,
                            "status": int(response.status) if index == 0 else None,
                            "headers": response_headers if index == 0 else {},
                            "data_base64": base64.b64encode(pending_chunk).decode("ascii"),
                            "done": True,
                        }
                    elif index == 0:
                        yield {
                            "type": "service_proxy_stream",
                            "request_id": request_id,
                            "index": 0,
                            "status": int(response.status),
                            "headers": response_headers,
                            "data_base64": "",
                            "done": True,
                        }
        except _ResponseBodyTooLarge:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                status=backend_status,
                error="response_body_too_large",
                duration_ms=self._duration_ms(started_at),
            )
            yield self._error_message(
                request_id,
                "response_body_too_large",
                "backend response body is too large",
            )
        except _RequestBodyStreamError as exc:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                status=backend_status,
                error=exc.code,
                duration_ms=self._duration_ms(started_at),
            )
            yield self._error_message(request_id, exc.code, exc.message)
        except Exception as exc:
            self._log_warning("backend request failed: request_id=%s service_name=%s", request_id, service_name)
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                status=backend_status,
                error="backend_unreachable",
                error_type=type(exc).__name__,
                duration_ms=self._duration_ms(started_at),
            )
            yield self._error_message(request_id, "backend_unreachable", "backend request failed")

    async def stream_request_message(self, message: dict[str, Any], *, chunk_size: int = 65536):
        request_id = str(message.get("request_id") or "")
        service_name = str(message.get("service_name") or "")
        record = self.registry.get(service_name)
        if record is None:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                error="service_not_registered",
            )
            yield self._error_message(request_id, "service_not_registered", "service is not registered")
            return

        method = str(message.get("method") or "GET").upper()
        path = str(message.get("path") or "/")
        if not path.startswith("/"):
            path = "/" + path
        query_string = str(message.get("query_string") or "")
        target_url = urljoin(record.endpoint.rstrip("/") + "/", path.lstrip("/"))
        if query_string:
            target_url = f"{target_url}?{query_string}"

        try:
            body = base64.b64decode(str(message.get("body_base64") or ""), validate=True) if message.get("body_base64") else b""
        except Exception:
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                error="invalid_body",
            )
            yield self._error_message(request_id, "invalid_body", "body_base64 is invalid")
            return

        index = 0
        headers = self._backend_headers(message.get("headers") if isinstance(message.get("headers"), dict) else {})
        started_at = time.monotonic()
        request_fields = {
            "request_id": request_id,
            "provider_aid": self.provider_aid,
            "service_name": service_name,
            "method": method,
            "path": path,
            "service_type": record.service_type,
            "stream": True,
            "body_stream": False,
        }
        request_fields.update(self._query_log_fields(query_string))
        request_fields.update(self._endpoint_log_fields(record.endpoint))
        self._log_access("backend_request_start", **request_fields)
        backend_status = 0
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(method, target_url, headers=headers, data=body) as response:
                    backend_status = int(response.status)
                    response_headers = self._response_headers(dict(response.headers))
                    request_detection = detect_request_protocol(message, record)
                    stream_type = stream_type_from_response(response_headers, fallback=request_detection.service_type)
                    response_headers.setdefault("x-stream-type", stream_type)
                    self._log_access(
                        "backend_response",
                        request_id=request_id,
                        provider_aid=self.provider_aid,
                        service_name=service_name,
                        method=method,
                        path=path,
                        status=backend_status,
                        stream=True,
                        stream_type=stream_type,
                        duration_ms=self._duration_ms(started_at),
                    )
                    pending_chunk: bytes | None = None
                    async for chunk in response.content.iter_chunked(max(1, int(chunk_size or 65536))):
                        if pending_chunk is not None:
                            yield {
                                "type": "service_proxy_stream",
                                "request_id": request_id,
                                "index": index,
                                "status": int(response.status) if index == 0 else None,
                                "headers": response_headers if index == 0 else {},
                                "data_base64": base64.b64encode(pending_chunk).decode("ascii"),
                                "done": False,
                            }
                            index += 1
                        pending_chunk = bytes(chunk)
                    if pending_chunk is not None:
                        yield {
                            "type": "service_proxy_stream",
                            "request_id": request_id,
                            "index": index,
                            "status": int(response.status) if index == 0 else None,
                            "headers": response_headers if index == 0 else {},
                            "data_base64": base64.b64encode(pending_chunk).decode("ascii"),
                            "done": True,
                        }
                    elif index == 0:
                        yield {
                            "type": "service_proxy_stream",
                            "request_id": request_id,
                            "index": 0,
                            "status": int(response.status),
                            "headers": response_headers,
                            "data_base64": "",
                            "done": True,
                        }
        except Exception as exc:
            self._log_warning("backend request failed: request_id=%s service_name=%s", request_id, service_name)
            self._log_access(
                "backend_request_error",
                request_id=request_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                method=method,
                path=path,
                status=backend_status,
                error="backend_unreachable",
                error_type=type(exc).__name__,
                duration_ms=self._duration_ms(started_at),
            )
            yield self._error_message(request_id, "backend_unreachable", "backend request failed")

    async def handle_ws_connect_message(
        self,
        message: dict[str, Any],
        tunnel: Any,
        *,
        inbound_queue: asyncio.Queue | None = None,
    ) -> None:
        started_at = time.monotonic()
        connection_id = str(message.get("connection_id") or "")
        service_name = str(message.get("service_name") or "")
        try:
            record = self.registry.get(service_name)
        except ValidationError:
            record = None
        if record is None:
            self._log_access(
                "backend_ws_error",
                connection_id=connection_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                error="service_not_registered",
            )
            await self._send_tunnel_message(tunnel, self._ws_error_message(
                connection_id,
                "service_not_registered",
                "service is not registered",
            ))
            return

        path = str(message.get("path") or "/")
        if not path.startswith("/"):
            path = "/" + path
        query_string = str(message.get("query_string") or "")
        target_url = urljoin(record.endpoint.rstrip("/") + "/", path.lstrip("/"))
        if query_string:
            target_url = f"{target_url}?{query_string}"

        headers = self._backend_headers(message.get("headers") if isinstance(message.get("headers"), dict) else {})
        subprotocols = [
            str(item).strip()
            for item in (message.get("subprotocols") if isinstance(message.get("subprotocols"), list) else [])
            if str(item).strip()
        ]
        request_fields = {
            "connection_id": connection_id,
            "provider_aid": self.provider_aid,
            "service_name": service_name,
            "path": path,
            "service_type": record.service_type,
            "subprotocols": subprotocols,
        }
        request_fields.update(self._query_log_fields(query_string))
        request_fields.update(self._endpoint_log_fields(record.endpoint))
        self._log_access("backend_ws_connect_start", **request_fields)
        connected = False
        error_code = ""
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(target_url, headers=headers, protocols=subprotocols) as backend_ws:
                    await self._send_tunnel_message(tunnel, {
                        "type": "ws_connected",
                        "connection_id": connection_id,
                        "subprotocol": str(backend_ws.protocol or ""),
                    })
                    connected = True
                    self._log_access(
                        "backend_ws_connected",
                        connection_id=connection_id,
                        provider_aid=self.provider_aid,
                        service_name=service_name,
                        path=path,
                        subprotocol=str(backend_ws.protocol or ""),
                        duration_ms=self._duration_ms(started_at),
                    )

                    backend_to_tunnel = asyncio.create_task(
                        self._relay_backend_ws_to_tunnel(backend_ws, tunnel, connection_id=connection_id)
                    )
                    tunnel_to_backend = asyncio.create_task(
                        self._relay_tunnel_to_backend_ws(
                            tunnel,
                            backend_ws,
                            connection_id=connection_id,
                            inbound_queue=inbound_queue,
                        )
                    )
                    done, pending = await asyncio.wait(
                        {backend_to_tunnel, tunnel_to_backend},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    for task in done:
                        try:
                            task.result()
                        except Exception as exc:
                            if not self._is_websocket_connection_closed(exc):
                                error_code = type(exc).__name__
                                self._log_error(
                                    "websocket relay task failed: connection_id=%s err=%s",
                                    connection_id,
                                    exc,
                                    err=exc,
                                )
                                raise
        except Exception as exc:
            if not self._is_websocket_connection_closed(exc):
                error_code = "backend_ws_unreachable"
                self._log_warning("backend websocket bridge failed: connection_id=%s", connection_id)
            try:
                await self._send_tunnel_message(tunnel, self._ws_error_message(
                    connection_id,
                    "backend_ws_unreachable",
                    "backend websocket request failed",
                ))
            except Exception as send_exc:
                if not self._is_websocket_connection_closed(send_exc):
                    raise
        finally:
            self._log_access(
                "backend_ws_closed" if connected and not error_code else "backend_ws_error",
                connection_id=connection_id,
                provider_aid=self.provider_aid,
                service_name=service_name,
                path=path if record is not None else "",
                connected=connected,
                error=error_code,
                duration_ms=self._duration_ms(started_at),
            )

    async def _read_response_body_limited(self, response: Any) -> bytes:
        chunks: list[bytes] = []
        total = 0
        limit = self.max_response_body_bytes
        async for chunk in response.content.iter_chunked(65536):
            data = bytes(chunk)
            total += len(data)
            if total > limit:
                raise _ResponseBodyTooLarge()
            chunks.append(data)
        return b"".join(chunks)

    async def _relay_backend_ws_to_tunnel(self, backend_ws: Any, tunnel: Any, *, connection_id: str) -> None:
        async for message in backend_ws:
            if message.type == WSMsgType.TEXT:
                await self._send_tunnel_message(tunnel, {
                    "type": "ws_message",
                    "connection_id": connection_id,
                    "text": str(message.data),
                })
            elif message.type == WSMsgType.BINARY:
                await self._send_tunnel_message(tunnel, {
                    "type": "ws_message",
                    "connection_id": connection_id,
                    "data_base64": base64.b64encode(bytes(message.data)).decode("ascii"),
                })
            elif message.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                break
            elif message.type == WSMsgType.ERROR:
                raise RuntimeError(str(backend_ws.exception() or "backend WebSocket error"))
        try:
            await self._send_tunnel_message(tunnel, {
                "type": "ws_close",
                "connection_id": connection_id,
                "code": int(backend_ws.close_code or 1000),
                "reason": "",
            })
        except Exception as exc:
            if not self._is_websocket_connection_closed(exc):
                raise

    async def _relay_tunnel_to_backend_ws(
        self,
        tunnel: Any,
        backend_ws: Any,
        *,
        connection_id: str,
        inbound_queue: asyncio.Queue | None = None,
    ) -> None:
        while True:
            if inbound_queue is None:
                raw = await tunnel.recv()
                try:
                    message = json.loads(raw)
                except Exception:
                    continue
            else:
                message = await inbound_queue.get()
            if not isinstance(message, dict) or str(message.get("connection_id") or "") != connection_id:
                continue
            msg_type = message.get("type")
            if msg_type == "ws_message":
                if message.get("text") is not None:
                    await backend_ws.send_str(str(message.get("text")))
                elif message.get("data_base64") is not None:
                    try:
                        data = base64.b64decode(str(message.get("data_base64") or ""), validate=True)
                    except Exception:
                        await self._send_tunnel_message(tunnel, self._ws_error_message(
                            connection_id,
                            "invalid_ws_frame",
                            "data_base64 is invalid",
                        ))
                        await backend_ws.close()
                        return
                    await backend_ws.send_bytes(data)
            elif msg_type == "ws_close":
                reason = str(message.get("reason") or "")
                await backend_ws.close(code=int(message.get("code") or 1000), message=reason.encode("utf-8"))
                return
            elif msg_type == "ws_error":
                await backend_ws.close()
                return

    @staticmethod
    def _backend_headers(headers: dict[str, Any]) -> dict[str, str]:
        result: dict[str, str] = {}
        for key, value in headers.items():
            name = str(key).lower()
            if name in _HOP_BY_HOP_HEADERS:
                continue
            if name == "host":
                continue
            result[name] = str(value)
        return result

    @staticmethod
    def _response_headers(headers: dict[str, Any]) -> dict[str, str]:
        result: dict[str, str] = {}
        for key, value in headers.items():
            name = str(key).lower()
            if name in _HOP_BY_HOP_HEADERS or name in _AUTO_RESPONSE_HEADERS:
                continue
            result[name] = str(value)
        return result

    @staticmethod
    def _error_message(request_id: str, code: str, message: str) -> dict[str, Any]:
        return {
            "type": "service_proxy_error",
            "request_id": request_id,
            "error": {
                "code": code,
                "message": message,
            },
        }

    @staticmethod
    async def _send_tunnel_message(tunnel: Any, message: dict[str, Any]) -> None:
        await tunnel.send(json.dumps(message, ensure_ascii=False))

    @staticmethod
    def _is_websocket_connection_closed(exc: BaseException) -> bool:
        closed_types = []
        for name in ("ConnectionClosed", "ConnectionClosedOK", "ConnectionClosedError"):
            candidate = getattr(websockets, name, None)
            if isinstance(candidate, type):
                closed_types.append(candidate)
        exceptions_module = getattr(websockets, "exceptions", None)
        if exceptions_module is not None:
            for name in ("ConnectionClosed", "ConnectionClosedOK", "ConnectionClosedError"):
                candidate = getattr(exceptions_module, name, None)
                if isinstance(candidate, type) and candidate not in closed_types:
                    closed_types.append(candidate)
        return bool(closed_types) and isinstance(exc, tuple(closed_types))

    @staticmethod
    def _ws_error_message(connection_id: str, code: str, message: str) -> dict[str, Any]:
        return {
            "type": "ws_error",
            "connection_id": connection_id,
            "error": {
                "code": code,
                "message": message,
            },
        }

    def create_admin_app(self, *, admin_token: str) -> web.Application:
        token = str(admin_token or "").strip()
        app = web.Application()
        client = self

        def _authorized(request: web.Request) -> bool:
            if not token:
                return False
            return request.headers.get("Authorization", "") == f"Bearer {token}"

        @web.middleware
        async def _auth_middleware(request: web.Request, handler):
            if not _authorized(request):
                return web.json_response({"error": "unauthorized"}, status=401)
            return await handler(request)

        app.middlewares.append(_auth_middleware)

        async def _health(_request: web.Request) -> web.Response:
            return web.json_response(
                {
                    "status": "ok",
                    "provider_aid": client.provider_aid,
                    "running": client.is_running,
                    "services": len(client.registry.list_records()),
                }
            )

        async def _list_services(_request: web.Request) -> web.Response:
            return web.json_response({"services": client.list_service_summaries()})

        async def _register_service(request: web.Request) -> web.Response:
            try:
                payload = await request.json()
            except Exception:
                return web.json_response({"error": "invalid JSON"}, status=400)
            if not isinstance(payload, dict):
                return web.json_response({"error": "payload must be an object"}, status=400)
            try:
                record = client.register_service(
                    str(payload.get("service_name") or ""),
                    str(payload.get("endpoint") or ""),
                    service_type=str(payload.get("service_type") or "http"),
                    visibility=str(payload.get("visibility") or "private"),
                    metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else None,
                )
            except ValidationError as exc:
                return web.json_response({"error": str(exc)}, status=400)
            return web.json_response(record.summary())

        async def _unregister_service(request: web.Request) -> web.Response:
            removed = client.unregister_service(request.match_info.get("service_name", ""))
            return web.json_response({"removed": removed})

        app.router.add_get("/health", _health)
        app.router.add_get("/services", _list_services)
        app.router.add_post("/services", _register_service)
        app.router.add_delete("/services/{service_name}", _unregister_service)
        return app
