from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Callable
from typing import Any

import websockets

from .auth import AuthFlow
from .config import AUNConfig
from .crypto import CryptoProvider
from .discovery import GatewayDiscovery
from .e2ee import E2EEManager
from .errors import (
    AUNError,
    AuthError,
    ConnectionError,
    PermissionError as AUNPermissionError,
    StateError,
    ValidationError,
)
from .events import EventDispatcher, Subscription
from .keystore.file import FileKeyStore
from .namespaces.auth_namespace import AuthNamespace
from .transport import RPCTransport

_INTERNAL_ONLY_METHODS = {
    "auth.login1",
    "auth.aid_login1",
    "auth.login2",
    "auth.aid_login2",
    "auth.connect",
    "auth.refresh_token",
    "initialize",
}

_DEFAULT_SESSION_OPTIONS: dict[str, Any] = {
    "auto_reconnect": False,
    "heartbeat_interval": 30.0,
    "token_refresh_before": 60.0,
    "retry": {
        "max_attempts": 3,
        "initial_delay": 0.5,
        "max_delay": 5.0,
    },
    "timeouts": {
        "connect": 5.0,
        "call": 10.0,
        "http": 30.0,
    },
}


async def _default_connection_factory(url: str) -> Any:
    return await websockets.connect(url, open_timeout=5, close_timeout=5, ping_interval=None)


class AUNClient:
    """AUN Core SDK — 连接、认证、密钥管理、E2EE。"""

    def __init__(self, config: dict | None = None) -> None:
        raw_config = dict(config or {})
        self._config_model = AUNConfig.from_dict(raw_config)
        self.config = raw_config
        self._aid: str | None = None
        self._identity: dict[str, Any] | None = None
        self._state = "idle"
        self._gateway_url: str | None = None
        self._closing = False
        self._reconnect_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._token_refresh_task: asyncio.Task | None = None
        self._session_params: dict[str, Any] | None = None
        self._session_options: dict[str, Any] = dict(_DEFAULT_SESSION_OPTIONS)
        self._dispatcher = EventDispatcher()
        self._discovery = GatewayDiscovery()

        connection_factory = raw_config.get("connection_factory", _default_connection_factory)
        keystore = raw_config.get("keystore") or FileKeyStore(
            self._config_model.aun_path,
            secret_store=raw_config.get("secret_store"),
        )
        self._auth = AuthFlow(
            keystore=keystore,
            crypto=raw_config.get("crypto") or CryptoProvider(),
            aid=None,
            connection_factory=connection_factory,
            root_ca_path=raw_config.get("root_ca_path"),
        )
        self._transport = RPCTransport(
            event_dispatcher=self._dispatcher,
            connection_factory=connection_factory,
            timeout=_DEFAULT_SESSION_OPTIONS["timeouts"]["call"],
            on_disconnect=self._handle_transport_disconnect,
        )
        self._e2ee = E2EEManager(self)

        self.auth = AuthNamespace(self)

    # ── 属性 ──────────────────────────────────────────────

    @property
    def aid(self) -> str | None:
        return self._aid

    @property
    def state(self) -> str:
        return self._state

    @property
    def e2ee(self) -> E2EEManager:
        return self._e2ee

    # ── 生命周期 ──────────────────────────────────────────

    async def connect(self, params: dict[str, Any]) -> None:
        if self._state not in {"idle", "closed"}:
            raise StateError(f"connect not allowed in state {self._state}")
        normalized = self._normalize_connect_params(params)
        self._session_params = normalized
        self._session_options = self._build_session_options(normalized)
        self._transport.set_timeout(self._session_options["timeouts"]["call"])
        self._closing = False
        await self._connect_once(normalized, allow_reauth=False)

    async def close(self) -> None:
        self._closing = True
        await self._stop_background_tasks()
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None
        if self._state in {"idle", "closed"}:
            self._state = "closed"
            return
        await self._transport.close()
        self._state = "closed"
        await self._dispatcher.publish("connection.state", {"state": self._state})

    # ── RPC ───────────────────────────────────────────────

    async def call(self, method: str, params: dict | None = None) -> Any:
        if self._state != "connected":
            raise ConnectionError("client is not connected")
        if self._is_internal_only_method(method):
            raise AUNPermissionError(f"method is internal_only: {method}")
        return await self._transport.call(method, params or {})

    # ── 便利方法 ──────────────────────────────────────────

    async def ping(self, params: dict | None = None) -> Any:
        return await self.call("meta.ping", params or {})

    async def status(self, params: dict | None = None) -> Any:
        return await self.call("meta.status", params or {})

    async def trust_roots(self, params: dict | None = None) -> Any:
        return await self.call("meta.trust_roots", params or {})

    # ── 事件 ──────────────────────────────────────────────

    def on(self, event: str, handler: Callable[[Any], Any]) -> Subscription:
        return self._dispatcher.subscribe(event, handler)

    # ── 内部：连接 ────────────────────────────────────────

    async def _connect_once(self, params: dict[str, Any], *, allow_reauth: bool) -> None:
        gateway_url = self._resolve_gateway(params)
        self._gateway_url = gateway_url
        self._loop = asyncio.get_running_loop()
        self._state = "connecting"
        challenge = await self._transport.connect(gateway_url)
        self._state = "authenticating"
        if allow_reauth:
            auth_context = await self._auth.connect_session(
                self._transport,
                challenge,
                gateway_url,
                access_token=params.get("access_token"),
            )
            identity = auth_context.get("identity") if isinstance(auth_context, dict) else None
            if isinstance(identity, dict):
                self._identity = identity
                self._aid = identity.get("aid", self._aid)
                if self._session_params is not None:
                    self._session_params["access_token"] = auth_context.get("token", params.get("access_token"))
        else:
            await self._auth.initialize_with_token(self._transport, challenge, str(params["access_token"]))
            self._sync_identity_after_connect(str(params["access_token"]))
        self._state = "connected"
        await self._dispatcher.publish("connection.state", {"state": self._state, "gateway": gateway_url})
        self._start_background_tasks()

    def _resolve_gateway(self, params: dict[str, Any]) -> str:
        topology = params.get("topology")
        if isinstance(topology, dict):
            mode = str(topology.get("mode") or "gateway")
            if mode == "peer":
                peer = str(topology.get("peer") or "")
                if not peer:
                    raise ValidationError("peer topology requires 'peer'")
                raise ValidationError("peer topology is not implemented in the Python SDK")
            if mode == "relay":
                relay = str(topology.get("relay") or "")
                target = str(topology.get("target") or "")
                if not relay or not target:
                    raise ValidationError("relay topology requires 'relay' and 'target'")
                raise ValidationError("relay topology is not implemented in the Python SDK")
        gateway = str(params.get("gateway") or "")
        if not gateway:
            raise StateError("missing gateway in connect params")
        return gateway

    @staticmethod
    def _is_internal_only_method(method: str) -> bool:
        if method in _INTERNAL_ONLY_METHODS:
            return True
        return method.startswith("federation.")

    # ── 内部：后台任务 ────────────────────────────────────

    def _start_background_tasks(self) -> None:
        self._start_heartbeat_task()
        self._start_token_refresh_task()

    async def _stop_background_tasks(self) -> None:
        for attr in ("_heartbeat_task", "_token_refresh_task"):
            task = getattr(self, attr)
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            setattr(self, attr, None)

    def _start_heartbeat_task(self) -> None:
        if self._heartbeat_task is not None and not self._heartbeat_task.done():
            return
        interval = float(self._session_options["heartbeat_interval"])
        if interval <= 0:
            return
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(interval))

    def _start_token_refresh_task(self) -> None:
        if self._token_refresh_task is not None and not self._token_refresh_task.done():
            return
        self._token_refresh_task = asyncio.create_task(self._token_refresh_loop())

    async def _heartbeat_loop(self, interval: float) -> None:
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                if self._state != "connected":
                    continue
                try:
                    await self._transport.call("meta.ping", {})
                except Exception as exc:
                    await self._dispatcher.publish("connection.error", {"error": exc})
        except asyncio.CancelledError:
            raise

    async def _token_refresh_loop(self) -> None:
        lead = float(self._session_options.get("token_refresh_before", 60.0))
        minimum_sleep = 1.0
        try:
            while not self._closing:
                if self._state != "connected" or not self._gateway_url:
                    await asyncio.sleep(minimum_sleep)
                    continue
                identity = self._identity or self._auth.load_identity_or_none()
                if identity is None:
                    await asyncio.sleep(minimum_sleep)
                    continue
                self._identity = identity
                expires_at = self._auth.get_access_token_expiry(identity)
                if expires_at is None:
                    await asyncio.sleep(minimum_sleep)
                    continue
                delay = max(expires_at - lead - time.time(), minimum_sleep)
                await asyncio.sleep(delay)
                if self._state != "connected" or not self._gateway_url:
                    continue
                try:
                    identity = await self._auth.refresh_cached_tokens(self._gateway_url, identity)
                    self._identity = identity
                    if self._session_params is not None and identity.get("access_token"):
                        self._session_params["access_token"] = identity["access_token"]
                    await self._dispatcher.publish("token.refreshed", {
                        "aid": identity.get("aid"),
                        "expires_at": identity.get("access_token_expires_at"),
                    })
                except AuthError:
                    continue
                except Exception as exc:
                    await self._dispatcher.publish("connection.error", {"error": exc})
        except asyncio.CancelledError:
            raise

    # ── 内部：断线重连 ────────────────────────────────────

    async def _handle_transport_disconnect(self, error: Exception | None) -> None:
        if self._closing or self._state == "closed":
            return
        self._state = "disconnected"
        await self._dispatcher.publish("connection.state", {"state": self._state, "error": error})
        if not bool(self._session_options["auto_reconnect"]):
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        retry = dict(self._session_options["retry"])
        max_attempts = int(retry.get("max_attempts", 3))
        initial_delay = float(retry.get("initial_delay", 0.5))
        max_delay = float(retry.get("max_delay", 5.0))
        delay = initial_delay

        for attempt in range(1, max_attempts + 1):
            self._state = "reconnecting"
            await self._dispatcher.publish("connection.state", {
                "state": self._state,
                "attempt": attempt,
                "max_attempts": max_attempts,
            })
            try:
                await asyncio.sleep(delay)
                await self._transport.close()
                await self._invoke_reconnect_connect_once()
                self._reconnect_task = None
                return
            except asyncio.CancelledError:
                self._reconnect_task = None
                raise
            except Exception as exc:
                await self._dispatcher.publish("connection.error", {
                    "error": exc,
                    "attempt": attempt,
                })
                if not self._should_retry_reconnect(exc):
                    self._state = "terminal_failed"
                    self._reconnect_task = None
                    await self._dispatcher.publish("connection.state", {
                        "state": self._state,
                        "error": exc,
                        "attempt": attempt,
                    })
                    return
                delay = min(delay * 2, max_delay)

        self._state = "terminal_failed"
        self._reconnect_task = None
        await self._dispatcher.publish("connection.state", {"state": self._state})

    # ── 内部：参数处理 ────────────────────────────────────

    def _normalize_connect_params(self, params: dict[str, Any]) -> dict[str, Any]:
        request = dict(params)
        access_token = str(request.get("access_token") or "")
        if not access_token:
            raise StateError("connect requires non-empty access_token")
        gateway = str(request.get("gateway") or self._gateway_url or "")
        if not gateway:
            raise StateError("connect requires non-empty gateway")
        request["access_token"] = access_token
        request["gateway"] = gateway
        topology = request.get("topology")
        if topology is not None and not isinstance(topology, dict):
            raise ValidationError("topology must be a dict")
        if "retry" in request and not isinstance(request["retry"], dict):
            raise ValidationError("retry must be a dict")
        if "timeouts" in request and not isinstance(request["timeouts"], dict):
            raise ValidationError("timeouts must be a dict")
        return request

    def _build_session_options(self, params: dict[str, Any]) -> dict[str, Any]:
        options: dict[str, Any] = {
            "auto_reconnect": _DEFAULT_SESSION_OPTIONS["auto_reconnect"],
            "heartbeat_interval": _DEFAULT_SESSION_OPTIONS["heartbeat_interval"],
            "token_refresh_before": _DEFAULT_SESSION_OPTIONS["token_refresh_before"],
            "retry": dict(_DEFAULT_SESSION_OPTIONS["retry"]),
            "timeouts": dict(_DEFAULT_SESSION_OPTIONS["timeouts"]),
        }
        if "auto_reconnect" in params:
            options["auto_reconnect"] = bool(params["auto_reconnect"])
        if "heartbeat_interval" in params:
            options["heartbeat_interval"] = float(params["heartbeat_interval"])
        if "token_refresh_before" in params:
            options["token_refresh_before"] = float(params["token_refresh_before"])
        if "retry" in params:
            options["retry"].update(params["retry"])
        if "timeouts" in params:
            options["timeouts"].update(params["timeouts"])
        return options

    def _sync_identity_after_connect(self, access_token: str) -> None:
        identity = self._auth.load_identity_or_none(self._aid)
        if identity is None:
            self._identity = None
            return
        identity["access_token"] = access_token
        self._identity = identity
        self._aid = identity.get("aid", self._aid)
        self._auth._keystore.save_identity(identity["aid"], identity)

    async def _invoke_reconnect_connect_once(self) -> None:
        if self._session_params is None:
            raise StateError("missing connect params for reconnect")
        await self._connect_once(self._session_params, allow_reauth=True)

    @staticmethod
    def _should_retry_reconnect(error: Exception) -> bool:
        if isinstance(error, (AuthError, AUNPermissionError, ValidationError, StateError)):
            return False
        if isinstance(error, ConnectionError):
            return True
        if isinstance(error, AUNError):
            return bool(error.retryable)
        if isinstance(error, (TimeoutError, OSError, ConnectionResetError, websockets.ConnectionClosed)):
            return True
        return True
