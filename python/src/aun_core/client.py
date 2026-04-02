from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

import aiohttp
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
    E2EEError,
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


import ssl as _ssl

_NO_VERIFY_SSL = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
_NO_VERIFY_SSL.check_hostname = False
_NO_VERIFY_SSL.verify_mode = _ssl.CERT_NONE


async def _default_connection_factory(url: str) -> Any:
    kw: dict[str, Any] = {"open_timeout": 5, "close_timeout": 5, "ping_interval": None}
    if url.startswith("wss://"):
        kw["ssl"] = _NO_VERIFY_SSL
    return await websockets.connect(url, **kw)


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
        self._prekey_refresh_task: asyncio.Task | None = None
        self._session_params: dict[str, Any] | None = None
        self._session_options: dict[str, Any] = dict(_DEFAULT_SESSION_OPTIONS)
        self._dispatcher = EventDispatcher()
        self._discovery = GatewayDiscovery()

        # E2EE 编排状态（内存缓存，进程退出即清空）
        self._cert_cache: dict[str, bytes] = {}

        connection_factory = raw_config.get("connection_factory", _default_connection_factory)
        keystore = raw_config.get("keystore") or FileKeyStore(
            self._config_model.aun_path,
            secret_store=raw_config.get("secret_store"),
        )
        self._keystore = keystore
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
        self._e2ee = E2EEManager(
            identity_fn=lambda: self._identity or {},
            keystore=keystore,
        )

        self.auth = AuthNamespace(self)

        # 内部订阅：推送消息自动解密后 re-publish 给用户
        self._dispatcher.subscribe("_raw.message.received", self._on_raw_message_received)
        # 其他事件直接透传
        for evt in ("message.recalled", "message.ack", "group.changed"):
            self._dispatcher.subscribe(f"_raw.{evt}", lambda data, e=evt: self._dispatcher.publish(e, data))

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

    async def connect(self, auth: dict[str, Any], options: dict[str, Any] | None = None) -> None:
        if self._state not in {"idle", "closed"}:
            raise StateError(f"connect not allowed in state {self._state}")
        params = dict(auth)
        if options:
            params.update(options)
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

        params = dict(params) if params else {}

        # 自动加密：message.send + encrypt=True
        if method == "message.send" and params.pop("encrypt", None) is True:
            return await self._send_encrypted(params)

        result = await self._transport.call(method, params)

        # 自动解密：message.pull 返回的消息
        if method == "message.pull" and isinstance(result, dict):
            messages = result.get("messages")
            if isinstance(messages, list) and messages:
                result["messages"] = await self._decrypt_messages(messages)

        return result

    async def _send_encrypted(self, params: dict[str, Any]) -> Any:
        """自动加密并发送消息。"""
        import time as _time
        import uuid as _uuid

        to_aid = params.get("to")
        payload = params.get("payload")
        message_id = params.get("message_id") or str(_uuid.uuid4())
        timestamp = params.get("timestamp") or int(_time.time() * 1000)

        # 获取对方证书
        peer_cert_pem = await self._fetch_peer_cert(to_aid)

        # 获取对方 prekey（可能没有）
        prekey = await self._fetch_peer_prekey(to_aid)

        envelope, encrypted = self._e2ee.encrypt_outbound(
            peer_aid=to_aid,
            payload=payload,
            peer_cert_pem=peer_cert_pem,
            prekey=prekey,
            message_id=message_id,
            timestamp=timestamp,
        )
        if not encrypted:
            raise E2EEError(f"failed to encrypt message to {to_aid}")

        send_params: dict[str, Any] = {
            "to": to_aid,
            "payload": envelope,
            "type": "e2ee.encrypted",
            "encrypted": True,
            "message_id": message_id,
            "timestamp": timestamp,
            "persist": params.get("persist", True),
        }
        return await self._transport.call("message.send", send_params)

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

    async def _on_raw_message_received(self, data: Any) -> None:
        """处理 transport 层推送的原始消息：解密后 re-publish 给用户。"""
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._process_and_publish_message(data))

    async def _process_and_publish_message(self, data: Any) -> None:
        """实际处理推送消息的异步任务。"""
        try:
            if not isinstance(data, dict):
                await self._dispatcher.publish("message.received", data)
                return
            msg = dict(data)
            decrypted = await self._decrypt_single_message(msg)
            await self._dispatcher.publish("message.received", decrypted)
        except Exception:
            pass

    # ── E2EE 编排（从 E2EEManager 上提）─────────────────

    async def _fetch_peer_cert(self, aid: str) -> bytes:
        """获取对方证书（带缓存）"""
        if aid in self._cert_cache:
            return self._cert_cache[aid]
        gateway_url = self._gateway_url
        if not gateway_url:
            raise ValidationError("gateway url unavailable for e2ee cert fetch")
        cert_url = self._build_cert_url(gateway_url, aid)
        async with aiohttp.ClientSession() as session:
            async with session.get(cert_url, ssl=False) as response:
                response.raise_for_status()
                cert_pem = await response.text()
        cert_bytes = cert_pem.encode("utf-8")
        self._cert_cache[aid] = cert_bytes
        return cert_bytes

    async def _fetch_peer_prekey(self, peer_aid: str) -> dict[str, Any] | None:
        """获取对方的 prekey（通过 E2EEManager 缓存）"""
        cached = self._e2ee.get_cached_prekey(peer_aid)
        if cached is not None:
            return cached
        try:
            result = await self._transport.call("message.e2ee.get_prekey", {"aid": peer_aid})
            if isinstance(result, dict) and result.get("found"):
                prekey = result.get("prekey")
                if prekey:
                    self._e2ee.cache_prekey(peer_aid, prekey)
                return prekey
        except Exception:
            pass
        return None

    async def _upload_prekey(self) -> dict[str, Any]:
        """生成 prekey 并上传到服务端"""
        prekey_material = self._e2ee.generate_prekey()
        result = await self._transport.call("message.e2ee.put_prekey", prekey_material)
        return result if isinstance(result, dict) else {"ok": True}

    async def _check_replay_guard(
        self, message_id: str, sender_aid: str, encryption_mode: str, message: dict[str, Any],
    ) -> bool:
        """服务端防重放检查（可通过 config.server_replay_guard=False 关闭）。

        本地防重放由 E2EEManager._seen_messages 处理，无需此方法。
        此方法提供跨进程/跨重启的持久化防重放增强。
        """
        if not self.config.get("server_replay_guard", False):
            return True
        if not message_id:
            return True

        from cryptography.hazmat.primitives import hashes as _hashes

        timestamp_ms = int(message.get("timestamp") or 0)
        ephemeral_pk_hash = None
        payload = message.get("payload", {})
        epk = payload.get("ephemeral_public_key")
        if epk:
            digest = _hashes.Hash(_hashes.SHA256())
            digest.update(epk.encode("utf-8") if isinstance(epk, str) else epk)
            ephemeral_pk_hash = digest.finalize().hex()[:32]

        try:
            result = await self._transport.call("message.e2ee.record_replay_guard", {
                "sender_aid": sender_aid,
                "message_id": message_id,
                "encryption_mode": encryption_mode,
                "timestamp_ms": timestamp_ms,
                "ephemeral_pk_hash": ephemeral_pk_hash,
            })
            if isinstance(result, dict) and result.get("duplicate"):
                return False
        except Exception:
            pass
        return True

    async def _decrypt_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """批量解密消息（用于 message.pull）。

        直接解密，不经过 E2EEManager 的 seen set（避免与推送冲突）。
        同一批次内按 message_id 去重。
        """
        seen_in_batch: set[str] = set()
        result = []
        for msg in messages:
            mid = msg.get("message_id", "")
            if mid and mid in seen_in_batch:
                continue
            if mid:
                seen_in_batch.add(mid)
            payload = msg.get("payload")
            if (isinstance(payload, dict)
                and payload.get("type") == "e2ee.encrypted"
                and (msg.get("encrypted") is True or "encrypted" not in msg)):
                decrypted = self._e2ee._decrypt_message(msg)
                result.append(decrypted if decrypted is not None else msg)
            else:
                result.append(msg)
        return result

    async def _decrypt_single_message(self, message: dict[str, Any]) -> dict[str, Any]:
        """解密单条消息：服务端 replay guard + 密码学解密（含本地防重放）"""
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return message
        if payload.get("type") != "e2ee.encrypted":
            return message
        if message.get("encrypted") is not True and "encrypted" in message:
            return message

        # 服务端 replay guard（增强保护，E2EEManager 内部还有本地 seen set）
        message_id = message.get("message_id", "")
        from_aid = message.get("from", "")
        encryption_mode = payload.get("encryption_mode", "")
        if not await self._check_replay_guard(message_id, from_aid, encryption_mode, message):
            return message

        # 密码学解密（E2EEManager.decrypt_message 内含本地防重放）
        decrypted = self._e2ee.decrypt_message(message)
        return decrypted if decrypted is not None else message

    @staticmethod
    def _build_cert_url(gateway_url: str, aid: str) -> str:
        parsed = urlparse(gateway_url)
        scheme = "https" if parsed.scheme == "wss" else "http"
        netloc = parsed.netloc
        path = f"/pki/cert/{quote(aid, safe='')}"
        return urlunparse((scheme, netloc, path, "", "", ""))

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

        # 上线后自动上传 prekey（静默失败）
        try:
            await self._upload_prekey()
        except Exception:
            pass

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
        return method in _INTERNAL_ONLY_METHODS

    # ── 内部：后台任务 ────────────────────────────────────

    def _start_background_tasks(self) -> None:
        self._start_heartbeat_task()
        self._start_token_refresh_task()
        self._start_prekey_refresh_task()

    async def _stop_background_tasks(self) -> None:
        for attr in ("_heartbeat_task", "_token_refresh_task", "_prekey_refresh_task"):
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

    def _start_prekey_refresh_task(self) -> None:
        if self._prekey_refresh_task is not None and not self._prekey_refresh_task.done():
            return
        interval = float(self.config.get("prekey_refresh_interval", 3600))
        self._prekey_refresh_task = asyncio.create_task(self._prekey_refresh_loop(interval))

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

    async def _prekey_refresh_loop(self, interval: float) -> None:
        """定时轮换 prekey"""
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                if self._state != "connected":
                    continue
                try:
                    await self._upload_prekey()
                except Exception:
                    pass
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
