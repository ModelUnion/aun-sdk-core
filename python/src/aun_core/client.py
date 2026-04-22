from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse, urlunparse

import aiohttp
import websockets

from .auth import AuthFlow
from .config import AUNConfig, normalize_instance_id
from .logger import AUNLogger, AUNLogHandler
from .crypto import CryptoProvider
from .discovery import GatewayDiscovery
from .e2ee import E2EEManager, GroupE2EEManager
from .errors import (
    AUNError,
    AuthError,
    ClientSignatureError,
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
from .seq_tracker import SeqTracker
from .types import ConnectionState

_INTERNAL_ONLY_METHODS = {
    "auth.login1",
    "auth.aid_login1",
    "auth.login2",
    "auth.aid_login2",
    "auth.connect",
    "auth.refresh_token",
    "initialize",
}

# token 刷新连续失败次数上限，超过后发布 exhausted 事件
_TOKEN_REFRESH_MAX_FAILURES = 3

# PY-001: 解密失败的群消息待重试队列上限
_PENDING_DECRYPT_LIMIT = 100

# PY-006: pushed_seqs 单 namespace 硬上限
_PUSHED_SEQS_LIMIT = 50000

_DEFAULT_SESSION_OPTIONS: dict[str, Any] = {
    "auto_reconnect": True,
    "heartbeat_interval": 30.0,
    "token_refresh_before": 60.0,
    "retry": {
        "initial_delay": 1.0,
        "max_delay": 64.0,
    },
    "timeouts": {
        "connect": 5.0,
        "call": 10.0,
        "http": 30.0,
    },
}


import ssl as _ssl
import logging as _logging

_client_log = _logging.getLogger("aun_core.client")
_ssl_warning_emitted = False

# SSL 上下文延迟创建，避免模块加载时即创建不安全的 SSL 上下文
_no_verify_ssl_ctx: _ssl.SSLContext | None = None


def _get_no_verify_ssl() -> _ssl.SSLContext:
    """延迟创建跳过证书验证的 SSL 上下文（仅在实际需要时创建）。"""
    global _no_verify_ssl_ctx
    if _no_verify_ssl_ctx is None:
        _no_verify_ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        _no_verify_ssl_ctx.check_hostname = False
        _no_verify_ssl_ctx.verify_mode = _ssl.CERT_NONE
    return _no_verify_ssl_ctx


def _make_connection_factory(verify_ssl: bool = True):
    """根据 verify_ssl 配置创建 WebSocket 连接工厂"""
    async def _factory(url: str) -> Any:
        global _ssl_warning_emitted
        kw: dict[str, Any] = {"open_timeout": 5, "close_timeout": 5, "ping_interval": None}
        if url.startswith("wss://"):
            if verify_ssl:
                pass  # 使用默认 SSL 上下文（验证证书）
            else:
                kw["ssl"] = _get_no_verify_ssl()
                if not _ssl_warning_emitted:
                    _client_log.warning(
                        "TLS 证书验证已禁用（verify_ssl=False）。"
                        "生产环境应设为 True 以防止中间人攻击。"
                    )
                    _ssl_warning_emitted = True
        return await websockets.connect(url, **kw)
    return _factory


async def _default_connection_factory(url: str) -> Any:
    kw: dict[str, Any] = {"open_timeout": 5, "close_timeout": 5, "ping_interval": None}
    if url.startswith("wss://"):
        kw["ssl"] = _get_no_verify_ssl()
    return await websockets.connect(url, **kw)


_PEER_CERT_CACHE_TTL = 600  # 10 分钟


@dataclass(slots=True)
class _CachedPeerCert:
    cert_bytes: bytes
    validated_at: float
    refresh_after: float


def _is_group_service_aid(value: Any) -> bool:
    text = str(value or "").strip()
    if "." not in text:
        return False
    name, issuer = text.split(".", 1)
    return name == "group" and bool(issuer)


def _normalize_delivery_mode_config(
    raw: Any,
    *,
    default_mode: str = "fanout",
    default_routing: str = "round_robin",
    default_affinity_ttl_ms: int = 0,
) -> dict[str, Any]:
    if isinstance(raw, str):
        raw = {"mode": raw}
    elif not isinstance(raw, dict):
        raw = {}
    mode = str(raw.get("mode") or default_mode).strip().lower() or "fanout"
    if mode not in {"fanout", "queue"}:
        raise ValidationError("delivery_mode must be 'fanout' or 'queue'")
    default_routing_value = default_routing if mode == "queue" else ""
    routing = str(raw.get("routing") or default_routing_value).strip().lower()
    if mode != "queue":
        routing = ""
    elif routing not in {"", "round_robin", "sender_affinity"}:
        raise ValidationError("queue_routing must be 'round_robin' or 'sender_affinity'")
    if mode == "queue" and not routing:
        routing = "round_robin"
    ttl_raw = raw.get("affinity_ttl_ms", default_affinity_ttl_ms if mode == "queue" else 0)
    try:
        affinity_ttl_ms = max(0, int(ttl_raw or 0))
    except (TypeError, ValueError) as exc:
        raise ValidationError("affinity_ttl_ms must be an integer") from exc
    return {
        "mode": mode,
        "routing": routing,
        "affinity_ttl_ms": affinity_ttl_ms,
    }


class AUNClient:
    """AUN Core SDK — 连接、认证、密钥管理、E2EE。"""

    def __init__(self, config: dict | None = None, debug: bool = False) -> None:
        raw_config = dict(config or {})
        self._config_model = AUNConfig.from_dict(raw_config)
        self._logger: AUNLogger | None = AUNLogger() if debug else None
        if self._logger:
            _logging.getLogger("aun_core").setLevel(_logging.DEBUG)
            aun_logger = _logging.getLogger("aun_core")
            # 避免重复注册（多个 AUNClient 实例共享同一 logger）
            if not any(isinstance(h, AUNLogHandler) for h in aun_logger.handlers):
                handler = AUNLogHandler(self._logger)
                handler.setFormatter(_logging.Formatter("%(levelname)s %(name)s: %(message)s"))
                aun_logger.addHandler(handler)
            _client_log.info("AUNClient 初始化完成 (debug=True, aun_path=%s)", self._config_model.aun_path)
        self.config = {
            "aun_path": str(self._config_model.aun_path),
            "root_ca_path": self._config_model.root_ca_path,
            "seed_password": self._config_model.seed_password,
        }
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
        self._discovery = GatewayDiscovery(verify_ssl=self._config_model.verify_ssl)

        # E2EE 编排状态（内存缓存，进程退出即清空）
        self._cert_cache: dict[str, _CachedPeerCert] = {}
        self._peer_prekeys_cache: dict[str, tuple[list[dict[str, Any]], float]] = {}
        self._prekey_replenish_inflight: bool = False
        self._prekey_pending_replenish: int = 0

        connection_factory = _make_connection_factory(self._config_model.verify_ssl)
        keystore = FileKeyStore(
            self._config_model.aun_path,
            encryption_seed=self._config_model.seed_password,
        )
        self._keystore = keystore
        # 获取并缓存 device_id
        from .config import get_device_id
        self._device_id = get_device_id(self._config_model.aun_path)
        self._slot_id = ""
        self._connect_delivery_mode = _normalize_delivery_mode_config({"mode": "fanout"})
        self._default_connect_delivery_mode = dict(self._connect_delivery_mode)
        self._auth = AuthFlow(
            keystore=keystore,
            crypto=CryptoProvider(),
            aid=None,
            device_id=self._device_id,
            slot_id=self._slot_id,
            connection_factory=connection_factory,
            root_ca_path=self._config_model.root_ca_path,
            verify_ssl=self._config_model.verify_ssl,
        )
        self._transport = RPCTransport(
            event_dispatcher=self._dispatcher,
            connection_factory=connection_factory,
            timeout=_DEFAULT_SESSION_OPTIONS["timeouts"]["call"],
            on_disconnect=self._handle_transport_disconnect,
        )
        self._e2ee = E2EEManager(
            identity_fn=lambda: self._identity or {},
            device_id_fn=lambda: self._device_id,
            keystore=keystore,
            replay_window_seconds=self._config_model.replay_window_seconds,
        )
        self._group_e2ee = GroupE2EEManager(
            identity_fn=lambda: self._identity or {},
            keystore=keystore,
            sender_cert_resolver=lambda aid: self._get_verified_peer_cert(aid),
            initiator_cert_resolver=lambda aid: self._get_verified_peer_cert(aid),
        )
        self._token_refresh_failures = 0  # token 刷新连续失败计数
        self._group_epoch_rotate_task: asyncio.Task | None = None
        self._group_epoch_cleanup_task: asyncio.Task | None = None
        self._cache_cleanup_task: asyncio.Task | None = None
        # 消息序列号跟踪器（群消息 + P2P 共用，按命名空间隔离）
        self._seq_tracker = SeqTracker()
        self._seq_tracker_context: tuple[str, str, str] | None = None
        self._gap_fill_done: dict[str, float] = {}  # 补洞去重：进行中的 key -> 开始时间戳
        self._gap_fill_active: bool = False  # 当前是否在补洞中（用于标记 pull 来源）
        # 推送路径已分发的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发
        self._pushed_seqs: dict[str, set[int]] = {}
        # PY-001: 解密失败的群消息待重试队列（按 namespace 分组）
        self._pending_decrypt_msgs: dict[str, list[dict[str, Any]]] = {}

        self.auth = AuthNamespace(self)
        # 内部订阅：推送消息自动解密后 re-publish 给用户
        self._dispatcher.subscribe("_raw.message.received", self._on_raw_message_received)
        # 群组消息推送：自动解密后 re-publish
        self._dispatcher.subscribe("_raw.group.message_created", self._on_raw_group_message_created)
        # 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
        self._dispatcher.subscribe("_raw.group.changed", self._on_raw_group_changed)
        # 其他事件直接透传
        for evt in ("message.recalled", "message.ack"):
            self._dispatcher.subscribe(f"_raw.{evt}", lambda data, e=evt: self._dispatcher.publish(e, data))
        # 服务端主动断开通知：记录日志并标记不重连
        self._server_kicked = False
        self._dispatcher.subscribe("_raw.gateway.disconnect", self._on_gateway_disconnect)

    # ── 属性 ──────────────────────────────────────────────

    @property
    def aid(self) -> str | None:
        return self._aid

    @property
    def state(self) -> ConnectionState:
        return ConnectionState(self._state)

    @property
    def e2ee(self) -> E2EEManager:
        return self._e2ee

    @property
    def group_e2ee(self) -> GroupE2EEManager:
        return self._group_e2ee

    # ── 生命周期 ──────────────────────────────────────────

    @property
    def gateway_health(self) -> bool | None:
        """最近一次 health check 结果，None 表示尚未检查。"""
        return self._discovery.last_healthy

    async def check_gateway_health(self, gateway_url: str, *, timeout: float = 5.0) -> bool:
        """向 gateway_url 的 /health 端点发送 HEAD 请求，检查网关可用性。"""
        return await self._discovery.check_health(gateway_url, timeout=timeout)

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

    async def disconnect(self) -> None:
        """断开连接但不关闭客户端（可重新 connect，对齐 C++ Disconnect）"""
        # 若 close() 已在执行中，跳过 disconnect 避免竞态
        if self._closing:
            return
        if self._state not in {"connected", "reconnecting"}:
            return
        self._save_seq_tracker_state()
        await self._stop_background_tasks()
        await self._transport.close()
        self._state = "disconnected"
        await self._dispatcher.publish("connection.state", {"state": self._state})

    def list_identities(self) -> list[dict[str, Any]]:
        """列出本地所有已存储的身份摘要（对齐 C++ ListIdentities）"""
        aids = self._keystore.list_identities()
        summaries: list[dict[str, Any]] = []
        for aid in sorted(aids):
            summary: dict[str, Any] = {"aid": aid}
            md = self._keystore.load_metadata(aid)
            if md:
                summary["metadata"] = md
            summaries.append(summary)
        return summaries

    async def close(self) -> None:
        self._closing = True
        # 关闭前保存 SeqTracker 状态
        self._save_seq_tracker_state()
        await self._stop_background_tasks()
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass  # 任务取消，正常清理
            self._reconnect_task = None
        if self._state in {"idle", "closed"}:
            self._state = "closed"
            self._reset_seq_tracking_state()
            return
        await self._transport.close()
        self._state = "closed"
        await self._dispatcher.publish("connection.state", {"state": self._state})
        self._reset_seq_tracking_state()

    # ── RPC ───────────────────────────────────────────────

    # 需要客户端签名的关键方法（渐进式部署：服务端有签名则验，无签名则放行）
    _SIGNED_METHODS = frozenset({
        "group.send", "group.kick", "group.add_member",
        "group.leave", "group.remove_member", "group.update_rules",
        "group.update", "group.update_announcement",
        "group.update_join_requirements", "group.set_role",
        "group.transfer_owner", "group.review_join_request",
        "group.batch_review_join_request",
        "group.request_join", "group.use_invite_code",
        "group.resources.put", "group.resources.update",
        "group.resources.delete", "group.resources.request_add",
        "group.resources.direct_add", "group.resources.approve_request",
        "group.resources.reject_request",
    })

    def _sign_client_operation(self, method: str, params: dict[str, Any]) -> None:
        """为关键操作附加客户端 ECDSA 签名（_client_signature 字段）。"""
        identity = self._identity
        if not identity or not identity.get("private_key_pem"):
            return
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
            aid = identity.get("aid", "")
            ts = str(int(time.time()))
            # 计算 params hash
            # 约定：签名覆盖所有非 _ 前缀且非 client_signature 的业务字段
            params_for_hash = {k: v for k, v in params.items()
                               if k != "client_signature" and not k.startswith("_")}
            params_json = json.dumps(params_for_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            params_hash = hashlib.sha256(params_json.encode("utf-8")).hexdigest()
            sign_data = f"{method}|{aid}|{ts}|{params_hash}".encode("utf-8")
            pk = _ser.load_pem_private_key(
                identity["private_key_pem"].encode("utf-8"), password=None,
            )
            sig = pk.sign(sign_data, _ec.ECDSA(_hashes.SHA256()))
            # 证书指纹：用于锁定签名时使用的证书版本
            cert_fingerprint = ""
            cert_pem = identity.get("cert", "")
            if cert_pem:
                from cryptography import x509 as _x509
                cert_obj = _x509.load_pem_x509_certificate(cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem)
                cert_fingerprint = "sha256:" + cert_obj.fingerprint(_hashes.SHA256()).hex()
            params["client_signature"] = {
                "aid": aid,
                "cert_fingerprint": cert_fingerprint,
                "timestamp": ts,
                "params_hash": params_hash,
                "signature": base64.b64encode(sig).decode("ascii"),
            }
        except Exception as exc:
            raise ClientSignatureError(f"客户端签名失败，拒绝发送无签名请求: {exc}") from exc

    async def call(self, method: str, params: dict | None = None) -> Any:
        if self._state != "connected":
            raise ConnectionError("client is not connected")
        if self._is_internal_only_method(method):
            raise AUNPermissionError(f"method is internal_only: {method}")

        params = dict(params) if params else {}
        self._validate_outbound_call(method, params)
        self._inject_message_cursor_context(method, params)

        # group.* 方法注入 device_id（服务端用于多设备消息路由）
        if method.startswith("group.") and self._device_id and "device_id" not in params:
            params["device_id"] = self._device_id

        # 自动加密：message.send 默认加密（encrypt 默认 True）
        if method == "message.send":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                return await self._send_encrypted(params)

        # 自动加密：group.send 默认加密（encrypt 默认 True）
        if method == "group.send":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                return await self._send_group_encrypted(params)

        # 关键操作自动附加客户端签名
        if method in self._SIGNED_METHODS:
            self._sign_client_operation(method, params)

        result = await self._transport.call(method, params)

        # 自动解密：message.pull 返回的消息
        if method == "message.pull" and isinstance(result, dict):
            messages = result.get("messages")
            if isinstance(messages, list) and messages:
                pull_source = "gap_fill" if getattr(self, "_gap_fill_active", False) else "pull"
                result["messages"] = await self._decrypt_messages(messages, source=pull_source)
                if self._aid:
                    ns = f"p2p:{self._aid}"
                    self._seq_tracker.on_pull_result(ns, messages)
                    # ⚠️ 逻辑边界 L1/L3：P2P retention floor 通道 = server_ack_seq
                    # 服务端在持久化/设备视图分支返回 server_ack_seq，客户端若本地 contiguous_seq 落后，
                    # 必须调用 force_contiguous_seq 跳过服务端已清理掉的不连续区间（retention window 外的消息）。
                    # 这是跳过"服务端允许起始位置之前"空洞的唯一手段，与 S2 引入的 [1,seq-1] 历史 gap 配合使用。
                    # 若这里不 force，首条消息建的 [1,N-1] gap 会永远悬挂，触发无限 pull 重试。
                    # 注意：临时消息淘汰走另一字段 ephemeral_earliest_available_seq（当前不 force，仅提示），与此互斥。
                    # 修改前请复核 docs/bug-audit-2026-04-17-review.md 的 S2 条款。
                    server_ack = int(result.get("server_ack_seq") or 0)
                    if server_ack > 0:
                        contig = self._seq_tracker.get_contiguous_seq(ns)
                        if contig < server_ack:
                            _client_log.info(
                                "message.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d",
                                ns, contig, server_ack,
                            )
                            self._seq_tracker.force_contiguous_seq(ns, server_ack)
                    self._persist_seq(ns)
                # auto-ack：ack contiguous_seq
                if self._aid:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        try:
                            await self._transport.call("message.ack", {
                                "seq": contig, "device_id": self._device_id,
                            })
                        except Exception as _ack_exc:
                            _client_log.debug("message.pull auto-ack 失败: %s", _ack_exc)

        # 自动解密：group.pull 返回的群消息
        if method == "group.pull" and isinstance(result, dict):
            messages = result.get("messages")
            if isinstance(messages, list) and messages:
                result["messages"] = await self._decrypt_group_messages(messages)
                gid = (params or {}).get("group_id", "")
                if gid:
                    ns = f"group:{gid}"
                    self._seq_tracker.on_pull_result(ns, messages)
                    # ⚠️ 逻辑边界 L4：group retention floor 通道 = cursor.current_seq
                    # 群路径目前"服务端允许起始位置"仅由 cursor.current_seq 表达（= server_ack_seq 语义），
                    # 没有独立的 earliest_available_seq 字段。若未来在 group/entry.py 引入 retention 淘汰，
                    # 需要新增独立字段并同步更新这里；否则群消息 retention 窗外的空洞会永远悬挂。
                    # 与 S2 [1,seq-1] 历史 gap 配合使用，force_contiguous_seq 是跳过空洞的唯一手段。
                    cursor = result.get("cursor")
                    if isinstance(cursor, dict):
                        server_ack = int(cursor.get("current_seq") or 0)
                        if server_ack > 0:
                            contig = self._seq_tracker.get_contiguous_seq(ns)
                            if contig < server_ack:
                                _client_log.info(
                                    "group.pull retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                                    ns, contig, server_ack,
                                )
                                self._seq_tracker.force_contiguous_seq(ns, server_ack)
                    self._persist_seq(ns)
                    # auto-ack：ack contiguous_seq
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        try:
                            await self._transport.call("group.ack_messages", {
                                "group_id": gid, "msg_seq": contig,
                                "device_id": self._device_id,
                            })
                        except Exception as _ack_exc:
                            _client_log.debug("group.pull auto-ack 失败: group=%s %s", gid, _ack_exc)

        # ── Group E2EE 自动编排 ────────────────────────────
        # 群组 E2EE 是必备能力，始终启用自动编排
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()

        # 建群后自动创建 epoch（幂等：已有 secret 时跳过）
        # 同步到服务端确保 epoch 一致
        if method == "group.create" and isinstance(result, dict):
            group = result.get("group", {})
            gid = group.get("group_id", "")
            if gid and self._aid and not self._group_e2ee.has_secret(gid):
                try:
                    self._group_e2ee.create_epoch(gid, [self._aid])
                    # 同步到服务端：将服务端 epoch 从 0 推到 1（await 确保完成后再返回）
                    await self._sync_epoch_to_server(gid)
                except Exception as exc:
                    self._log_e2ee_error("create_epoch", gid, "", exc)

        # 加人后自动分发密钥给新成员（如 rotate_on_join 则先轮换）
        # 必须检查返回结果是否成功，失败时禁止分发密钥（安全：防止泄漏 epoch key）
        if method == "group.add_member" and isinstance(result, dict):
            if not result.get("error"):
                group_id = params.get("group_id", "")
                new_aid = params.get("aid", "")
                if group_id and new_aid:
                    if self._config_model.rotate_on_join:
                        loop.create_task(self._rotate_group_epoch(group_id))
                    else:
                        loop.create_task(self._distribute_key_to_new_member(group_id, new_aid))

        # group.kick / group.leave：由 group.changed(member_removed/member_left)
        # 事件侧统一驱动剩余 admin/owner 补位轮换，避免 RPC 返回路径与事件路径双重触发。

        # 审批通过后自动分发密钥给新成员
        if method == "group.review_join_request" and isinstance(result, dict):
            if result.get("approved") is True or result.get("status") == "approved":
                group_id = params.get("group_id", "")
                new_aid = params.get("aid", "")
                if group_id and new_aid:
                    loop.create_task(self._distribute_key_to_new_member(group_id, new_aid))

        # 批量审批通过后分发密钥（根据 rotate_on_join 决定轮换或补发）
        if method == "group.batch_review_join_request" and isinstance(result, dict):
            group_id = params.get("group_id", "")
            approved_aids = [
                item.get("aid", "")
                for item in result.get("results", [])
                if item.get("ok") and item.get("status") == "approved" and item.get("aid")
            ]
            if group_id and approved_aids:
                if self._config_model.rotate_on_join:
                    # 批量审批触发一次轮换（覆盖所有新成员）
                    loop.create_task(self._rotate_group_epoch(group_id))
                else:
                    # 逐个补发当前密钥
                    for aid in approved_aids:
                        loop.create_task(self._distribute_key_to_new_member(group_id, aid))

        return result

    def _log_e2ee_error(self, stage: str, group_id: str, aid: str, exc: Exception) -> None:
        """记录 E2EE 自动编排错误（发布事件，不吞掉异常信息）。"""
        try:
            loop = getattr(self, "_loop", None)
            if loop and loop.is_running():
                loop.create_task(self._dispatcher.publish(
                    "e2ee.orchestration_error",
                    {"stage": stage, "group_id": group_id, "aid": aid, "error": str(exc)},
                ))
        except Exception as _pub_exc:
            _client_log.warning("发布 e2ee 编排事件失败: %s", _pub_exc)

    async def _send_encrypted(self, params: dict[str, Any]) -> Any:
        """自动加密并发送消息。"""
        import time as _time
        import uuid as _uuid

        to_aid = params.get("to")
        self._validate_message_recipient(to_aid)
        payload = params.get("payload")
        message_id = params.get("message_id") or str(_uuid.uuid4())
        timestamp = params.get("timestamp") or int(_time.time() * 1000)

        recipient_prekeys = await self._fetch_peer_prekeys(to_aid)
        self_sync_copies = await self._build_self_sync_copies(
            logical_to_aid=to_aid,
            payload=payload,
            message_id=message_id,
            timestamp=timestamp,
        )

        # 仅在确实需要多设备语义时切到 e2ee.multi_device，单设备路径继续兼容旧语义。
        if (not recipient_prekeys or len(recipient_prekeys) <= 1) and not self_sync_copies:
            return await self._send_encrypted_single(
                to_aid=to_aid,
                payload=payload,
                message_id=message_id,
                timestamp=timestamp,
                prekey=recipient_prekeys[0] if recipient_prekeys else None,
            )

        recipient_copies = await self._build_recipient_device_copies(
            to_aid=to_aid,
            payload=payload,
            message_id=message_id,
            timestamp=timestamp,
            prekeys=recipient_prekeys,
        )
        send_params: dict[str, Any] = {
            "to": to_aid,
            "payload": {
                "type": "e2ee.multi_device",
                "logical_message_id": message_id,
                "recipient_copies": recipient_copies,
                "self_copies": self_sync_copies,
            },
            "type": "e2ee.multi_device",
            "encrypted": True,
            "message_id": message_id,
            "timestamp": timestamp,
        }
        return await self._transport.call("message.send", send_params)

    async def _send_encrypted_single(
        self,
        *,
        to_aid: str,
        payload: dict[str, Any],
        message_id: str,
        timestamp: int,
        prekey: dict[str, Any] | None = None,
    ) -> Any:
        if prekey is None:
            prekey = await self._fetch_peer_prekey(to_aid)

        peer_cert_fingerprint = ""
        if isinstance(prekey, dict):
            peer_cert_fingerprint = str(prekey.get("cert_fingerprint", "") or "").strip().lower()
        peer_cert_pem = await self._fetch_peer_cert(to_aid, peer_cert_fingerprint or None)

        envelope, encrypt_result = self._encrypt_copy_payload(
            logical_to_aid=to_aid,
            payload=payload,
            peer_cert_pem=peer_cert_pem,
            prekey=prekey,
            message_id=message_id,
            timestamp=timestamp,
        )
        self._ensure_encrypt_result(to_aid, encrypt_result)

        send_params: dict[str, Any] = {
            "to": to_aid,
            "payload": envelope,
            "type": "e2ee.encrypted",
            "encrypted": True,
            "message_id": message_id,
            "timestamp": timestamp,
        }
        return await self._transport.call("message.send", send_params)

    async def _build_recipient_device_copies(
        self,
        *,
        to_aid: str,
        payload: dict[str, Any],
        message_id: str,
        timestamp: int,
        prekeys: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        recipient_copies: list[dict[str, Any]] = []
        cert_cache: dict[str, bytes] = {}
        for prekey in prekeys:
            device_id = str(prekey.get("device_id") or "").strip()
            peer_cert_fingerprint = str(prekey.get("cert_fingerprint", "") or "").strip().lower()
            cache_key = peer_cert_fingerprint or "__default__"
            peer_cert_pem = cert_cache.get(cache_key)
            if peer_cert_pem is None:
                peer_cert_pem = await self._fetch_peer_cert(to_aid, peer_cert_fingerprint or None)
                cert_cache[cache_key] = peer_cert_pem
            envelope, encrypt_result = self._encrypt_copy_payload(
                logical_to_aid=to_aid,
                payload=payload,
                peer_cert_pem=peer_cert_pem,
                prekey=prekey,
                message_id=message_id,
                timestamp=timestamp,
            )
            self._ensure_encrypt_result(to_aid, encrypt_result)
            recipient_copies.append({
                "device_id": device_id,
                "envelope": envelope,
            })
        if not recipient_copies:
            raise E2EEError(f"no recipient device copies generated for {to_aid}")
        return recipient_copies

    @staticmethod
    def _cert_sha256_fingerprint(cert_pem: bytes | str | None) -> str:
        if not cert_pem:
            return ""
        try:
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives import hashes as _hashes

            cert_bytes = cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode("utf-8")
            cert_obj = _x509.load_pem_x509_certificate(cert_bytes)
            return "sha256:" + cert_obj.fingerprint(_hashes.SHA256()).hex()
        except Exception as _fp_exc:
            _client_log.debug("提取证书指纹失败: %s", _fp_exc)
            return ""

    async def _resolve_self_copy_peer_cert(self, cert_fingerprint: str | None = None) -> bytes:
        """为 self_copies 选择目标设备对应的证书版本。"""
        my_aid = self._aid
        if not my_aid:
            raise E2EEError("self sync copy requires current aid")

        normalized_fp = str(cert_fingerprint or "").strip().lower()
        identity_cert = (self._identity or {}).get("cert")
        if isinstance(identity_cert, str) and identity_cert:
            identity_cert_fp = self._cert_sha256_fingerprint(identity_cert)
            if not normalized_fp or identity_cert_fp == normalized_fp:
                return identity_cert.encode("utf-8")

        local_cert = None
        try:
            local_cert = self._keystore.load_cert(my_aid, normalized_fp or None)
        except TypeError:
            local_cert = self._keystore.load_cert(my_aid)
        except Exception as _lc_exc:
            _client_log.debug("加载本地证书失败: %s", _lc_exc)
            local_cert = None
        if local_cert:
            return local_cert.encode("utf-8") if isinstance(local_cert, str) else local_cert

        return await self._fetch_peer_cert(my_aid, normalized_fp or None)

    async def _build_self_sync_copies(
        self,
        *,
        logical_to_aid: str,
        payload: dict[str, Any],
        message_id: str,
        timestamp: int,
    ) -> list[dict[str, Any]]:
        my_aid = self._aid
        if not my_aid:
            return []
        prekeys = await self._fetch_peer_prekeys(my_aid)
        if not prekeys:
            return []
        copies: list[dict[str, Any]] = []
        for prekey in prekeys:
            device_id = str(prekey.get("device_id") or "").strip()
            if device_id == self._device_id:
                continue
            peer_cert_pem = await self._resolve_self_copy_peer_cert(
                str(prekey.get("cert_fingerprint", "") or "").strip().lower() or None,
            )
            envelope, encrypt_result = self._encrypt_copy_payload(
                logical_to_aid=logical_to_aid,
                payload=payload,
                peer_cert_pem=peer_cert_pem,
                prekey=prekey,
                message_id=message_id,
                timestamp=timestamp,
            )
            self._ensure_encrypt_result(my_aid, encrypt_result)
            copies.append({
                "device_id": device_id,
                "envelope": envelope,
            })
        return copies

    def _encrypt_copy_payload(
        self,
        *,
        logical_to_aid: str,
        payload: dict[str, Any],
        peer_cert_pem: bytes,
        prekey: dict[str, Any] | None,
        message_id: str,
        timestamp: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if prekey is not None:
            try:
                envelope, _ = self._e2ee._encrypt_with_prekey(
                    logical_to_aid,
                    payload,
                    prekey,
                    peer_cert_pem,
                    message_id=message_id,
                    timestamp=timestamp,
                )
                return envelope, {
                    "encrypted": True,
                    "forward_secrecy": True,
                    "mode": "prekey_ecdh_v2",
                    "degraded": False,
                }
            except Exception as exc:
                _client_log.warning("prekey 加密失败，降级到 long_term_key: %s", exc)

        envelope, _ = self._e2ee._encrypt_with_long_term_key(
            logical_to_aid,
            payload,
            peer_cert_pem,
            message_id=message_id,
            timestamp=timestamp,
        )
        degraded = prekey is not None
        return envelope, {
            "encrypted": True,
            "forward_secrecy": False,
            "mode": "long_term_key",
            "degraded": degraded,
            "degradation_reason": "prekey_encrypt_failed" if degraded else "no_prekey_available",
        }

    def _ensure_encrypt_result(self, peer_aid: str, encrypt_result: dict[str, Any]) -> None:
        if not encrypt_result.get("encrypted"):
            raise E2EEError(f"failed to encrypt message to {peer_aid}")

        if self._config_model.require_forward_secrecy and not encrypt_result.get("forward_secrecy"):
            raise E2EEError(
                f"forward secrecy required but unavailable for {peer_aid} "
                f"(mode={encrypt_result.get('mode')})"
            )

        if encrypt_result.get("degraded"):
            loop = getattr(self, "_loop", None)
            payload = {
                "peer_aid": peer_aid,
                "mode": encrypt_result.get("mode"),
                "reason": encrypt_result.get("degradation_reason"),
            }
            try:
                if loop and loop.is_running():
                    loop.create_task(self._dispatcher.publish("e2ee.degraded", payload))
                else:
                    _client_log.warning("e2ee.degraded 事件未发布：事件循环未运行")
            except Exception as exc:
                _client_log.warning("发布 e2ee.degraded 事件失败: %s", exc)

    async def _send_group_encrypted(self, params: dict[str, Any]) -> Any:
        """自动加密并发送群组消息。发送前预检本地 epoch 是否与服务端一致。"""
        group_id = params.get("group_id")
        payload = params.get("payload")
        if not group_id:
            raise ValidationError("group.send requires group_id")

        # 预检：本地 epoch 是否与服务端一致，不一致则等待密钥恢复
        local_epoch = self._group_e2ee.current_epoch(group_id)
        if local_epoch is not None:
            try:
                epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
                server_epoch = epoch_result.get("epoch", 0)
                if server_epoch > local_epoch:
                    _client_log.warning(
                        "群 %s 本地 epoch=%d < 服务端 epoch=%d，触发密钥恢复",
                        group_id, local_epoch, server_epoch,
                    )
                    # 向 owner 请求最新密钥
                    owner_aid = epoch_result.get("owner_aid", "")
                    if not owner_aid:
                        try:
                            info = await self.call("group.get_info", {"group_id": group_id})
                            owner_aid = info.get("owner_aid", "")
                        except Exception:
                            pass
                    if owner_aid and owner_aid != self._aid:
                        await self._request_group_key_from(group_id, owner_aid)
                    # 不阻塞发送：使用当前本地 epoch 发送，服务端若拒绝由上层处理
            except Exception as _exc:
                _client_log.warning("群 %s epoch 预检失败: %s", group_id, _exc)

        envelope = self._group_e2ee.encrypt(group_id, payload)

        send_params: dict[str, Any] = {
            "group_id": group_id,
            "payload": envelope,
            "type": "e2ee.group_encrypted",
            "encrypted": True,
        }
        self._sign_client_operation("group.send", send_params)
        return await self._transport.call("group.send", send_params)

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

    def off(self, event: str, handler: Callable[[Any], Any]) -> None:
        """注销事件处理器（对齐 C++ RemoveEventHandler / JS off）。"""
        self._dispatcher.unsubscribe(event, handler)

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

            # 拦截 P2P 传输的群组密钥分发/请求/响应消息
            if await self._try_handle_group_key_message(msg):
                return

            # P2P 空洞检测
            seq = msg.get("seq")
            if seq is not None and self._aid:
                ns = f"p2p:{self._aid}"
                old_contig = self._seq_tracker.get_contiguous_seq(ns)
                need_pull = self._seq_tracker.on_message_seq(ns, int(seq))
                new_contig = self._seq_tracker.get_contiguous_seq(ns)
                _client_log.debug("P2P push seq 跟踪: seq=%d contig=%d→%d need_pull=%s",
                                  int(seq), old_contig, new_contig, need_pull)
                self._persist_seq(ns)
                if need_pull:
                    loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(self._fill_p2p_gap())

            decrypted = await self._decrypt_single_message(msg, source="push")
            if decrypted is None:
                # 解密返回 None（replay guard 判定重复或解密失败），不投递消息，
                # 但 SeqTracker 已推进 contiguous，仍需 auto-ack 避免服务端重推。
                if seq is not None and self._aid:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        try:
                            await self._transport.call("message.ack", {
                                "seq": contig, "device_id": self._device_id,
                            })
                        except Exception as _ack_exc:
                            _client_log.debug("P2P auto-ack（解密None）失败: %s", _ack_exc)
                return
            # 记录已推送的 seq，补洞路径据此去重
            if seq is not None and self._aid:
                self._pushed_seqs.setdefault(ns, set()).add(int(seq))
            await self._dispatcher.publish("message.received", decrypted)

            # auto-ack push 消息：ack contiguous_seq（连续确认到的最高位置，避免空洞时跳跃推进）
            if seq is not None and self._aid:
                contig = self._seq_tracker.get_contiguous_seq(ns)
                if contig > 0:
                    try:
                        await self._transport.call("message.ack", {
                            "seq": contig, "device_id": self._device_id,
                        })
                    except Exception as _ack_exc:
                        _client_log.debug("P2P auto-ack 失败: %s", _ack_exc)
        except Exception as _exc:
            _client_log.warning("P2P push 处理失败: %s", _exc)
            if isinstance(data, dict) and data.get("seq") is not None and self._aid:
                _exc_ns = f"p2p:{self._aid}"
                _exc_contig = self._seq_tracker.get_contiguous_seq(_exc_ns)
                if _exc_contig > 0:
                    try:
                        await self._transport.call("message.ack", {
                            "seq": _exc_contig, "device_id": self._device_id,
                        })
                    except Exception as _ack_exc:
                        _client_log.debug("P2P auto-ack（异常路径）失败: %s", _ack_exc)
            # H26: 解密失败不再投递原始密文 payload（避免元数据泄漏 + 语义混淆），
            # 改为发布 message.undecryptable 事件，仅携带安全的 header 信息。
            if isinstance(data, dict):
                safe_event = {
                    "message_id": data.get("message_id"),
                    "from": data.get("from"),
                    "to": data.get("to"),
                    "seq": data.get("seq"),
                    "timestamp": data.get("timestamp"),
                    "_decrypt_error": str(_exc),
                }
                await self._dispatcher.publish("message.undecryptable", safe_event)

    async def _on_raw_group_message_created(self, data: Any) -> None:
        """处理群组消息推送：自动解密后 re-publish。"""
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._process_and_publish_group_message(data))

    async def _on_raw_group_changed(self, data: Any) -> None:
        """处理群组变更事件：验签 → 透传给用户 → 基于 gap 检测补齐 → epoch 轮换。

        验签策略：有 client_signature 就验，没有默认安全（兼容旧版）。
        """
        if isinstance(data, dict):
            # 验签：有签名就验证操作者身份
            cs = data.get("client_signature")
            if cs and isinstance(cs, dict):
                data["_verified"] = await self._verify_event_signature(data, cs)
            # 发布给用户（publish 流程保持不变）
            await self._dispatcher.publish("group.changed", data)

            group_id = data.get("group_id", "")

            # event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq
            # 用 on_message_seq 返回值决定是否补拉，与 P2P / group.message 路径对齐
            need_pull = False
            raw_event_seq = data.get("event_seq")
            if raw_event_seq is not None and group_id:
                try:
                    es = int(raw_event_seq)
                    ns = f"group_event:{group_id}"
                    need_pull = self._seq_tracker.on_message_seq(ns, es)
                except (ValueError, TypeError):
                    pass

            # 仅真实存在 gap 时才补拉（补洞回来的事件不再触发新补洞）
            if need_pull and group_id and not data.get("_from_gap_fill"):
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._fill_group_event_gap(group_id))

            # 成员退出或被踢 → 剩余 admin/owner 自动补位轮换
            if data.get("action") in ("member_left", "member_removed") and group_id:
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._maybe_lead_rotate_group_epoch(group_id))

            # PY-003: 群组解散 → 清理本地 epoch key、seq_tracker 等状态
            if data.get("action") == "dissolved" and group_id:
                self._cleanup_group_state(group_id)
        else:
            await self._dispatcher.publish("group.changed", data)

    async def _verify_event_signature(self, event: dict, cs: dict) -> str | bool:
        """验证群事件中的 client_signature。返回 True/False/"pending"。"""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives import hashes as _hashes
            from cryptography import x509 as _x509
            sig_aid = cs.get("aid", "")
            method = cs.get("_method", "")
            expected_fp = str(cs.get("cert_fingerprint", "") or "").strip().lower()
            if not sig_aid or not method:
                return "pending"
            # 优先用缓存，没有则限时拉取（避免网络阻塞卡住事件推送）
            cert_pem = self._get_verified_peer_cert(sig_aid, expected_fp or None)
            if not cert_pem:
                try:
                    cert_bytes = await asyncio.wait_for(
                        self._fetch_peer_cert(sig_aid, expected_fp or None), timeout=3.0
                    )
                    cert_pem = cert_bytes.decode("utf-8") if isinstance(cert_bytes, bytes) else cert_bytes
                except (asyncio.TimeoutError, Exception):
                    return "pending"
            if not cert_pem:
                return "pending"
            cert_obj = _x509.load_pem_x509_certificate(
                cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem
            )
            # cert_fingerprint 校验
            if expected_fp:
                actual_fp = "sha256:" + cert_obj.fingerprint(_hashes.SHA256()).hex()
                if actual_fp != expected_fp:
                    _client_log.warning("验签失败：证书指纹不匹配 aid=%s", sig_aid)
                    return False
            # 验签
            params_hash = cs.get("params_hash", "")
            timestamp = cs.get("timestamp", "")
            sign_data = f"{method}|{sig_aid}|{timestamp}|{params_hash}".encode("utf-8")
            sig_bytes = base64.b64decode(cs.get("signature", ""))
            pub_key = cert_obj.public_key()
            pub_key.verify(sig_bytes, sign_data, _ec.ECDSA(_hashes.SHA256()))
            return True
        except Exception as exc:
            sig_aid = cs.get("aid", "?")
            method = cs.get("_method", "?")
            _client_log.debug("群事件验签失败 aid=%s method=%s: %s", sig_aid, method, exc)
            return False

    async def _process_and_publish_group_message(self, data: Any) -> None:
        """处理群组推送消息的异步任务。

        带 payload 的事件（消息推送）：解密后 re-publish。
        不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。

        PY-001: 解密失败的消息不 auto-ack，加入待重试队列等待密钥恢复。
        """
        try:
            if not isinstance(data, dict):
                await self._dispatcher.publish("group.message_created", data)
                return
            msg = dict(data)
            group_id = msg.get("group_id", "")
            seq = msg.get("seq")
            payload = msg.get("payload")

            payload_present = payload is not None and (not isinstance(payload, dict) or bool(payload))

            # 空洞检测（无论带不带 payload 都检查）
            if group_id and seq is not None:
                ns = f"group:{group_id}"
                need_pull = self._seq_tracker.on_message_seq(ns, int(seq))
                self._persist_seq(ns)
                if need_pull:
                    loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(self._fill_group_gap(group_id))

            if payload is None or (isinstance(payload, dict) and not payload):
                # 不带 payload 的通知：自动 pull 最新消息
                await self._auto_pull_group_messages(msg)
                return
            decrypted = await self._decrypt_group_message(msg)

            # PY-001: 检查解密是否成功（成功时有 e2ee 字段）
            is_encrypted_payload = isinstance(payload, dict) and payload.get("type") == "e2ee.group_encrypted"
            decrypt_success = not is_encrypted_payload or (isinstance(decrypted, dict) and decrypted.get("e2ee"))

            if decrypt_success:
                # 解密成功：记录 pushed_seq + 发布 + auto-ack
                if group_id and seq is not None:
                    ns_key = f"group:{group_id}"
                    self._pushed_seqs.setdefault(ns_key, set()).add(int(seq))
                    self._enforce_pushed_seqs_limit(ns_key)
                await self._dispatcher.publish("group.message_created", decrypted)

                # auto-ack：ack contiguous_seq（避免空洞时跳跃推进）
                if group_id and seq is not None:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        try:
                            await self._transport.call("group.ack_messages", {
                                "group_id": group_id, "msg_seq": contig,
                                "device_id": self._device_id,
                            })
                        except Exception as _ack_exc:
                            _client_log.debug("群消息 auto-ack 失败: group=%s %s", group_id, _ack_exc)
            else:
                # PY-001: 解密失败 → 不 auto-ack，加入待重试队列
                self._enqueue_pending_decrypt(group_id, msg)
                # 发布 undecryptable 事件（安全：不含密文 payload）
                safe_event = {
                    "message_id": msg.get("message_id"),
                    "group_id": group_id,
                    "from": msg.get("from"),
                    "seq": seq,
                    "timestamp": msg.get("timestamp"),
                    "_decrypt_error": "group secret unavailable",
                }
                await self._dispatcher.publish("group.message_undecryptable", safe_event)
        except Exception as _exc:
            _client_log.warning("群消息 push 处理失败: %s", _exc)
            # H26: 解密失败改发 group.message_undecryptable 事件，不投递原始密文 payload
            if isinstance(data, dict):
                safe_event = {
                    "message_id": data.get("message_id"),
                    "group_id": data.get("group_id"),
                    "from": data.get("from"),
                    "seq": data.get("seq"),
                    "timestamp": data.get("timestamp"),
                    "_decrypt_error": str(_exc),
                }
                await self._dispatcher.publish("group.message_undecryptable", safe_event)
                # PY-001: 异常路径也不 auto-ack，加入待重试队列
                _exc_group_id = data.get("group_id", "")
                if _exc_group_id:
                    self._enqueue_pending_decrypt(_exc_group_id, dict(data))

    async def _auto_pull_group_messages(self, notification: dict[str, Any]) -> None:
        """收到不带 payload 的 group.message_created 通知后，自动 pull 最新消息。"""
        group_id = notification.get("group_id", "")
        if not group_id:
            await self._dispatcher.publish("group.message_created", notification)
            return
        after_seq = self._seq_tracker.get_contiguous_seq(f"group:{group_id}")
        try:
            result = await self.call("group.pull", {
                "group_id": group_id,
                "after_message_seq": after_seq,
                "device_id": self._device_id,
                "limit": 50,
            })
            if isinstance(result, dict):
                messages = result.get("messages", [])
                if isinstance(messages, list):
                    # seq_tracker 更新和 auto-ack 已在 call() 拦截器中完成
                    ns_key = f"group:{group_id}"
                    pushed = self._pushed_seqs.get(ns_key)
                    for msg in messages:
                        if isinstance(msg, dict):
                            s = msg.get("seq")
                            if pushed and s is not None and int(s) in pushed:
                                continue  # 已通过推送路径分发，跳过
                            await self._dispatcher.publish("group.message_created", msg)
                    self._prune_pushed_seqs(ns_key)
                    return
        except Exception as _exc:
            _client_log.warning("自动 pull 群消息失败: %s", _exc)
        # pull 失败时仍透传原始通知
        await self._dispatcher.publish("group.message_created", notification)

    async def _fill_group_gap(self, group_id: str) -> None:
        """后台补齐群消息空洞。"""
        if self._state != "connected" or self._closing:
            return
        after_seq = self._seq_tracker.get_contiguous_seq(f"group:{group_id}")
        # 新设备（seq=0）没有历史 epoch key，拉旧消息也解不了
        if after_seq == 0 and not self._group_e2ee.has_secret(group_id):
            return
        dedup_key = f"group_msg:{group_id}:{after_seq}"
        if dedup_key in self._gap_fill_done:
            return
        self._gap_fill_done[dedup_key] = time.time()
        # S1: dedup 键必须在所有出口（成功/异常/空返）清理，避免"成功但返回 0 条"永久占位。
        # 真实空洞下次 push 还会触发；同窗口内并发由 add 前的 in 检查保证幂等。
        try:
            _client_log.info("群消息补洞开始: group=%s after_seq=%d", group_id, after_seq)
            result = await self.call("group.pull", {
                "group_id": group_id,
                "after_message_seq": after_seq,
                "device_id": self._device_id,
                "limit": 50,
            })
            if isinstance(result, dict):
                messages = result.get("messages", [])
                if isinstance(messages, list):
                    _client_log.info("群消息补洞完成: group=%s after_seq=%d 拉取=%d条", group_id, after_seq, len(messages))
                    ns_key = f"group:{group_id}"
                    pushed = self._pushed_seqs.get(ns_key)
                    # seq_tracker 在 call() 中自动处理；ack 由 push 路径负责
                    for msg in messages:
                        if isinstance(msg, dict):
                            s = msg.get("seq")
                            if pushed and s is not None and int(s) in pushed:
                                continue  # 已通过推送路径分发，跳过
                            await self._dispatcher.publish("group.message_created", msg)
                    # 清理 pushed_seqs 中 <= contiguous_seq 的条目
                    self._prune_pushed_seqs(ns_key)
        except Exception as exc:
            _client_log.warning("群消息补洞失败: group=%s after_seq=%d error=%s", group_id, after_seq, exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)

    async def _fill_group_event_gap(self, group_id: str) -> None:
        """后台补齐群事件空洞。"""
        if self._state != "connected" or self._closing:
            return
        ns = f"group_event:{group_id}"
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        dedup_key = f"group_evt:{group_id}:{after_seq}"
        if dedup_key in self._gap_fill_done:
            return
        self._gap_fill_done[dedup_key] = time.time()
        # S1: try/finally 保证 dedup 键在所有出口清理
        try:
            _client_log.info("群事件补洞开始: group=%s after_seq=%d", group_id, after_seq)
            result = await self.call("group.pull_events", {
                "group_id": group_id,
                "after_event_seq": after_seq,
                "device_id": self._device_id,
                "limit": 50,
            })
            if isinstance(result, dict):
                events = result.get("events", [])
                if isinstance(events, list):
                    _client_log.info("群事件补洞完成: group=%s after_seq=%d 拉取=%d条", group_id, after_seq, len(events))
                    self._seq_tracker.on_pull_result(ns, events)
                    self._persist_seq(ns)
                    # auto-ack contiguous_seq
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        try:
                            await self._transport.call("group.ack_events", {
                                "group_id": group_id, "event_seq": contig,
                                "device_id": self._device_id,
                            })
                        except Exception as _ack_exc:
                            _client_log.debug("群事件 auto-ack 失败: group=%s %s", group_id, _ack_exc)
                    for evt in events:
                        if isinstance(evt, dict):
                            evt["_from_gap_fill"] = True
                            et = evt.get("event_type", "")
                            # 消息事件由 _fill_group_gap 负责，事件补洞不重复投递
                            if et == "group.message_created":
                                continue
                            # 验签：有 client_signature 就验（与实时事件路径对齐）
                            cs = evt.get("client_signature")
                            if cs and isinstance(cs, dict):
                                evt["_verified"] = await self._verify_event_signature(evt, cs)
                            # group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
                            await self._dispatcher.publish("group.changed", evt)
        except Exception as exc:
            _client_log.warning("群事件补洞失败: group=%s after_seq=%d error=%s", group_id, after_seq, exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)

    async def _sync_all_groups_once(self) -> None:
        """上线/重连后一次性同步所有已加入群：
        1. 无 epoch key 的群 → 向 owner 发密钥恢复请求
        2. 有 epoch key 的群 → 补消息 + 补事件
        3. 所有群 → 补事件（事件不加密）
        """
        if self._state != "connected" or self._closing:
            return
        if not self._aid:
            return
        try:
            result = await self.call("group.list_my", {})
            groups = result.get("items", []) if isinstance(result, dict) else []
            _client_log.info("群全量同步: 共 %d 个群", len(groups))
            for g in groups:
                gid = g.get("group_id", "") if isinstance(g, dict) else ""
                if not gid:
                    continue
                has_secret = self._group_e2ee.has_secret(gid)
                if not has_secret:
                    # 没有 epoch key → 主动向 owner 请求密钥恢复
                    owner_aid = g.get("owner_aid", "") if isinstance(g, dict) else ""
                    if owner_aid and owner_aid != self._aid:
                        await self._request_group_key_from(gid, owner_aid)
                    else:
                        _client_log.debug("群 %s 无 epoch key 且无法确定 owner，等待推送触发恢复", gid)
                else:
                    # 有 epoch key → 补消息
                    await self._fill_group_gap(gid)
                # 所有群都补事件（事件不加密）
                await self._fill_group_event_gap(gid)
        except Exception as exc:
            _client_log.warning("群全量同步失败: %s", exc)

    async def _pull_all_group_events_once(self) -> None:
        """兼容旧调用，委托给 _sync_all_groups_once。"""
        await self._sync_all_groups_once()

    async def _request_group_key_from(self, group_id: str, target_aid: str) -> None:
        """主动向指定成员请求群组密钥（用于重连时无 epoch key 的群）。"""
        try:
            from .e2ee import build_key_request
            req_payload = build_key_request(group_id, 0, self._aid or "")
            await self.call("message.send", {
                "to": target_aid,
                "payload": req_payload,
                "encrypt": True,
            })
            _client_log.info("已向 %s 请求群 %s 的密钥", target_aid, group_id)
        except Exception as exc:
            _client_log.warning("向 %s 请求群 %s 密钥失败: %s", target_aid, group_id, exc)

    async def _fill_p2p_gap(self) -> None:
        """后台补齐 P2P 消息空洞。"""
        if self._state != "connected" or self._closing:
            return
        if not self._aid:
            return
        ns = f"p2p:{self._aid}"
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        # 新设备（seq=0）没有历史 prekey，拉旧消息也解不了，直接跳过
        if after_seq == 0:
            return
        dedup_key = f"p2p:{after_seq}"
        if dedup_key in self._gap_fill_done:
            return
        self._gap_fill_done[dedup_key] = time.time()
        # S1: try/finally 保证 dedup 键在所有出口清理
        try:
            _client_log.info("P2P 消息补洞开始: after_seq=%d device_id=%s", after_seq, self._device_id)
            self._gap_fill_active = True
            try:
                result = await self.call("message.pull", {
                    "after_seq": after_seq,
                    "limit": 50,
                })
            finally:
                self._gap_fill_active = False
            if isinstance(result, dict):
                messages = result.get("messages", [])
                if isinstance(messages, list):
                    # 统计解密成功/失败
                    ok_count = sum(1 for m in messages if isinstance(m, dict) and m.get("encrypted"))
                    fail_count = len(messages) - ok_count
                    seq_list = [int(m.get("seq") or 0) for m in messages if isinstance(m, dict)]
                    _client_log.info("P2P 消息补洞完成: after_seq=%d 拉取=%d条 解密成功=%d 失败=%d seq范围=%s",
                                    after_seq, len(messages), ok_count, fail_count,
                                    f"{min(seq_list)}~{max(seq_list)}" if seq_list else "空")
                    ns_key = f"p2p:{self._aid}"
                    pushed = self._pushed_seqs.get(ns_key)
                    # seq_tracker 在 call() 中自动处理；ack 由 push 路径负责
                    for msg in messages:
                        if isinstance(msg, dict):
                            s = msg.get("seq")
                            if pushed and s is not None and int(s) in pushed:
                                continue  # 已通过推送路径分发，跳过
                            await self._dispatcher.publish("message.received", msg)
                    # 清理 pushed_seqs 中 <= contiguous_seq 的条目
                    self._prune_pushed_seqs(ns_key)
        except Exception as exc:
            _client_log.warning("P2P 消息补洞失败: after_seq=%d error=%s", after_seq, exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)

    def _prune_pushed_seqs(self, ns: str) -> None:
        """清理 pushed_seqs 中 <= contiguous_seq 的条目，防止无限增长。"""
        pushed = self._pushed_seqs.get(ns)
        if not pushed:
            return
        contig = self._seq_tracker.get_contiguous_seq(ns)
        pushed.difference_update(s for s in list(pushed) if s <= contig)
        if not pushed:
            del self._pushed_seqs[ns]

    def _enforce_pushed_seqs_limit(self, ns: str) -> None:
        """PY-006: pushed_seqs 超过硬上限时清理最旧条目。"""
        pushed = self._pushed_seqs.get(ns)
        if not pushed or len(pushed) <= _PUSHED_SEQS_LIMIT:
            return
        # 保留最大（最新）的 _PUSHED_SEQS_LIMIT 个条目
        sorted_seqs = sorted(pushed)
        keep = set(sorted_seqs[-_PUSHED_SEQS_LIMIT:])
        self._pushed_seqs[ns] = keep

    def _enqueue_pending_decrypt(self, group_id: str, msg: dict[str, Any]) -> None:
        """PY-001: 将解密失败的消息加入待重试队列（有大小上限）。"""
        ns = f"group:{group_id}"
        queue = self._pending_decrypt_msgs.setdefault(ns, [])
        queue.append(msg)
        # 超过上限时丢弃最旧的
        if len(queue) > _PENDING_DECRYPT_LIMIT:
            self._pending_decrypt_msgs[ns] = queue[-_PENDING_DECRYPT_LIMIT:]

    async def _retry_pending_decrypt_msgs(self, group_id: str) -> None:
        """PY-002: 密钥恢复后重试待解密队列中的消息。

        成功解密的消息发布到 group.message_created 并 auto-ack。
        仍然失败的消息保留在队列中。
        """
        ns = f"group:{group_id}"
        queue = self._pending_decrypt_msgs.get(ns)
        if not queue:
            return
        # 取出队列，逐条重试
        pending = list(queue)
        self._pending_decrypt_msgs[ns] = []
        still_pending: list[dict[str, Any]] = []

        for msg in pending:
            try:
                decrypted = await self._decrypt_group_message(msg, skip_replay=True)
                is_encrypted = isinstance(msg.get("payload"), dict) and msg["payload"].get("type") == "e2ee.group_encrypted"
                if is_encrypted and (not isinstance(decrypted, dict) or not decrypted.get("e2ee")):
                    # 仍然解密失败
                    still_pending.append(msg)
                    continue
                # 解密成功
                seq = msg.get("seq")
                if group_id and seq is not None:
                    ns_key = f"group:{group_id}"
                    self._pushed_seqs.setdefault(ns_key, set()).add(int(seq))
                    self._enforce_pushed_seqs_limit(ns_key)
                await self._dispatcher.publish("group.message_created", decrypted)
                # auto-ack
                if group_id and seq is not None:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        try:
                            await self._transport.call("group.ack_messages", {
                                "group_id": group_id, "msg_seq": contig,
                                "device_id": self._device_id,
                            })
                        except Exception as _ack_exc:
                            _client_log.debug("重试 auto-ack 失败: group=%s %s", group_id, _ack_exc)
            except Exception as _exc:
                _client_log.debug("重试解密失败: group=%s seq=%s: %s", group_id, msg.get("seq"), _exc)
                still_pending.append(msg)

        if still_pending:
            self._pending_decrypt_msgs[ns] = still_pending
        else:
            self._pending_decrypt_msgs.pop(ns, None)

    def _cleanup_group_state(self, group_id: str) -> None:
        """PY-003: 群组 dissolve/leave 后清理该群组的全部本地状态。

        包括 epoch key、seq_tracker、pushed_seqs、待重试解密队列。
        """
        ns_msg = f"group:{group_id}"
        ns_evt = f"group_event:{group_id}"

        # 清理 keystore 中的 epoch key
        if self._aid:
            try:
                db = self._keystore._get_db(self._aid)
                db.delete_group_current(group_id)
                db.delete_all_group_old_epochs(group_id)
            except Exception as _exc:
                _client_log.debug("清理群 %s epoch key 失败: %s", group_id, _exc)

        # 清理 seq_tracker
        self._seq_tracker.remove_namespace(ns_msg)
        self._seq_tracker.remove_namespace(ns_evt)

        # 清理 pushed_seqs
        self._pushed_seqs.pop(ns_msg, None)

        # 清理待重试解密队列
        self._pending_decrypt_msgs.pop(ns_msg, None)

        # 清理补洞去重状态
        for k in list(self._gap_fill_done):
            if group_id in k:
                self._gap_fill_done.pop(k, None)

        _client_log.info("已清理群组 %s 本地状态（epoch key + seq + pushed_seqs）", group_id)

    async def _decrypt_group_message(self, message: dict[str, Any], *, skip_replay: bool = False) -> dict[str, Any]:
        """解密单条群组消息。"""
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "e2ee.group_encrypted":
            return message

        # 确保发送方证书已缓存（签名验证需要）— 失败时拒绝解密
        sender_aid = message.get("from", message.get("sender_aid", ""))
        if sender_aid:
            cert_ok = await self._ensure_sender_cert_cached(sender_aid)
            if not cert_ok:
                _client_log.warning("群消息解密跳过：发送方 %s 证书不可用", sender_aid)
                return message

        # 先尝试直接解密
        result = self._group_e2ee.decrypt(message, skip_replay=skip_replay)
        if result is not None and result.get("e2ee"):
            return result

        # 解密失败，尝试密钥恢复后重试
        group_id = message.get("group_id", "")
        sender = message.get("from", message.get("sender_aid", ""))
        epoch = payload.get("epoch")
        if epoch is not None and group_id:
            recovery = self._group_e2ee.build_recovery_request(
                group_id, epoch, sender_aid=sender,
            )
            if recovery:
                # 向主候选人 + 最多 2 个备选候选人发送密钥请求
                targets = [recovery["to"]] + recovery.get("fallback_targets", [])[:2]
                for target in targets:
                    try:
                        await self.call("message.send", {
                            "to": target,
                            "payload": recovery["payload"],
                            "encrypt": True,
                        })
                    except Exception as _exc:
                        _client_log.warning("向 %s 请求密钥恢复失败: %s", target, _exc)

        return message

    async def _decrypt_group_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """批量解密群组消息（用于 group.pull）。跳过防重放检查。"""
        result = []
        for msg in messages:
            decrypted = await self._decrypt_group_message(msg, skip_replay=True)
            result.append(decrypted)
        return result

    async def _try_handle_group_key_message(self, message: dict[str, Any]) -> bool:
        """尝试处理 P2P 传输的群组密钥消息。返回 True 表示已处理（不再传播）。

        S14: 一旦识别为群组密钥控制面信封（type ∈ {e2ee.group_key_distribution,
        e2ee.group_key_request, e2ee.group_key_response} 或 P2P 加密信封解密后内层
        是这些类型），无论后续解密/校验是否成功都返回 True，避免控制面消息被当作
        普通业务消息发布给应用层。
        """
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return False

        _GROUP_KEY_TYPES = (
            "e2ee.group_key_distribution",
            "e2ee.group_key_request",
            "e2ee.group_key_response",
        )

        # S14: 明文控制面消息（payload.type 直接命中）— 立即识别为控制面
        outer_type = payload.get("type")
        is_control_plane = outer_type in _GROUP_KEY_TYPES

        # 先解密 P2P E2EE（如果是加密的）
        # 注意：用 _decrypt_message 而非 decrypt_message，避免消耗 seen set
        actual_payload = payload
        if outer_type == "e2ee.encrypted":
            # 确保发送方证书已缓存（签名验证需要）
            from_aid = message.get("from", "")
            if from_aid:
                sender_fp = str(
                    payload.get("sender_cert_fingerprint")
                    or (payload.get("aad") or {}).get("sender_cert_fingerprint")
                    or ""
                ).strip().lower()
                await self._ensure_sender_cert_cached(from_aid, sender_fp or None)
            decrypted = self._e2ee._decrypt_message(message, source="push:group_key")
            if decrypted is None:
                # S14: P2P 解密失败时，无法识别是否为控制面 — 保持原行为返回 False
                return False
            self._schedule_prekey_replenish_if_consumed(decrypted)
            actual_payload = decrypted.get("payload", {})
            if not isinstance(actual_payload, dict):
                return False
            inner_type = actual_payload.get("type")
            if inner_type in _GROUP_KEY_TYPES:
                is_control_plane = True

        if not is_control_plane:
            # 不是控制面消息，交给原 handle_incoming 兜底（其只对 group_key_* 返回非 None）
            result = self._group_e2ee.handle_incoming(actual_payload)
            if result is None:
                return False
        else:
            result = self._group_e2ee.handle_incoming(actual_payload)

        if result == "request":
            # 处理密钥请求并回复
            group_id = actual_payload.get("group_id", "")
            requester = actual_payload.get("requester_aid", "")
            members = self._group_e2ee.get_member_aids(group_id)

            # 请求者不在本地成员列表时，回源查询服务端最新成员列表
            # （覆盖 use_invite_code 等不经过 owner 客户端的入群路径）
            if requester and requester not in members:
                try:
                    members_result = await self.call("group.get_members", {"group_id": group_id})
                    members = [m["aid"] for m in members_result.get("members", [])]
                    # 更新本地当前 epoch 的 member_aids/commitment
                    if requester in members:
                        secret_data = self._group_e2ee.load_secret(group_id)
                        if secret_data:
                            from .e2ee import compute_membership_commitment, store_group_secret
                            epoch = secret_data["epoch"]
                            commitment = compute_membership_commitment(members, epoch, group_id, secret_data["secret"])
                            store_group_secret(
                                self._keystore, self._aid, group_id, epoch,
                                secret_data["secret"], commitment, members,
                            )
                except Exception as exc:
                    _client_log.warning("群组 %s 成员列表回源失败: %s", group_id, exc)

            response = self._group_e2ee.handle_key_request_msg(actual_payload, members)
            if response:
                if requester:
                    try:
                        await self.call("message.send", {
                            "to": requester,
                            "payload": response,
                            "encrypt": True,
                        })
                    except Exception as exc:
                        _client_log.warning("向 %s 回复群组密钥失败: %s", requester, exc)

        # PY-002: 密钥分发/响应成功后，触发待解密消息重试
        if result in ("distribution", "response"):
            group_id_for_retry = actual_payload.get("group_id", "")
            if group_id_for_retry:
                ns_check = f"group:{group_id_for_retry}"
                if self._pending_decrypt_msgs.get(ns_check):
                    loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(self._retry_pending_decrypt_msgs(group_id_for_retry))

        # S14: 控制面消息无论 handle_incoming 是否返回 rejected/None 都吞掉，
        # 避免发布到业务消息流。
        return True

    # ── E2EE 编排（从 E2EEManager 上提）─────────────────

    @staticmethod
    def _cert_cache_key(aid: str, cert_fingerprint: str | None = None) -> str:
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        return aid if not normalized_fp else f"{aid}#{normalized_fp}"

    async def _fetch_peer_cert(self, aid: str, cert_fingerprint: str | None = None) -> bytes:
        """获取对方证书（带缓存 + 完整 PKI 验证：链 + CRL + OCSP + AID 绑定）

        跨域时自动将请求路由到 peer 所在域的 Gateway（URL 替换），
        同时 Gateway 侧也有代理 fallback。
        """
        cache_key = self._cert_cache_key(aid, cert_fingerprint)
        cached = self._cert_cache.get(cache_key)
        if cached and time.time() < cached.refresh_after:
            return cached.cert_bytes
        gateway_url = self._gateway_url
        if not gateway_url:
            raise ValidationError("gateway url unavailable for e2ee cert fetch")

        # 跨域时用 peer 所在域的 Gateway URL
        peer_gateway_url = self._resolve_peer_gateway_url(gateway_url, aid)
        cert_url = self._build_cert_url(peer_gateway_url, aid, cert_fingerprint)
        ssl_param = None if self._config_model.verify_ssl else False
        # PY-017: 显式设置 HTTP 超时，避免 aiohttp 默认 300s 阻塞
        http_timeout = aiohttp.ClientTimeout(total=10.0)
        async with aiohttp.ClientSession(timeout=http_timeout) as session:
            async with session.get(cert_url, ssl=ssl_param) as response:
                response.raise_for_status()
                cert_pem = await response.text()
        cert_bytes = cert_pem.encode("utf-8")

        # 完整 PKI 验证：链 + CRL + OCSP + AID 绑定
        # 验证时也用 peer 的 Gateway URL（链/OCSP/CRL 都从 peer 域获取）
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _hashes
        cert_obj = _x509.load_pem_x509_certificate(cert_bytes)

        # H7: 严格校验指纹（DER SHA-256 或 SPKI SHA-256 任一匹配即可）
        expected_fp = str(cert_fingerprint or "").strip().lower()
        if expected_fp:
            if not expected_fp.startswith("sha256:"):
                raise ValidationError(f"unsupported cert_fingerprint format for {aid}: {expected_fp[:24]}")
            expected_hex = expected_fp.split(":", 1)[1]
            der_hex = cert_obj.fingerprint(_hashes.SHA256()).hex()
            spki_hex = ""
            try:
                from cryptography.hazmat.primitives import serialization as _serialization
                spki_der = cert_obj.public_key().public_bytes(
                    encoding=_serialization.Encoding.DER,
                    format=_serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                spki_hex = hashlib.sha256(spki_der).hexdigest()
            except Exception:
                spki_hex = ""
            if expected_hex != der_hex and (not spki_hex or expected_hex != spki_hex):
                raise ValidationError(
                    f"peer cert fingerprint mismatch for {aid}: expected={expected_fp[:24]}..."
                )

        try:
            await self._auth.verify_peer_certificate(peer_gateway_url, cert_obj, aid)
        except Exception as exc:
            raise ValidationError(f"peer cert verification failed for {aid}: {exc}")

        now = time.time()
        self._cert_cache[cache_key] = _CachedPeerCert(
            cert_bytes=cert_bytes,
            validated_at=now,
            refresh_after=now + _PEER_CERT_CACHE_TTL,
        )
        # peer 证书只存到版本目录，不覆盖 cert.pem（防止破坏自身身份证书）
        try:
            self._keystore.save_cert(
                aid,
                cert_pem,
                cert_fingerprint=cert_fingerprint,
                make_active=False,
            )
        except TypeError:
            # 兼容旧 keystore 实现
            pass
        except Exception as exc:
            _client_log.error("写入 peer 证书到 keystore 失败 (aid=%s, fp=%s): %s", aid, cert_fingerprint or "", exc)
        return cert_bytes

    async def _fetch_peer_prekeys(self, peer_aid: str) -> list[dict[str, Any]]:
        """获取对方所有设备的 prekey 列表。"""
        cached_list = self._peer_prekeys_cache.get(peer_aid)
        if cached_list is not None:
            items, expire_at = cached_list
            if time.time() < expire_at:
                return [dict(item) for item in items]
            self._peer_prekeys_cache.pop(peer_aid, None)
        cached = self._e2ee.get_cached_prekey(peer_aid)
        if cached is not None:
            return [cached]
        try:
            result = await self._transport.call("message.e2ee.get_prekey", {"aid": peer_aid})
        except Exception as exc:
            raise ValidationError(f"failed to fetch peer prekey for {peer_aid}: {exc}") from exc
        if not isinstance(result, dict):
            raise ValidationError(f"invalid prekey response for {peer_aid}")
        if result.get("found") is False:
            return []

        device_prekeys = result.get("device_prekeys")
        if isinstance(device_prekeys, list):
            normalized: list[dict[str, Any]] = []
            for item in device_prekeys:
                if not isinstance(item, dict):
                    continue
                prekey_id = str(item.get("prekey_id") or "").strip()
                public_key = str(item.get("public_key") or "").strip()
                signature = str(item.get("signature") or "").strip()
                if not prekey_id or not public_key or not signature:
                    continue
                normalized.append(dict(item))
            if normalized:
                self._peer_prekeys_cache[peer_aid] = (
                    [dict(item) for item in normalized],
                    time.time() + 300.0,
                )
                self._e2ee.cache_prekey(peer_aid, normalized[0])
                return normalized

        prekey = result.get("prekey")
        if isinstance(prekey, dict):
            self._peer_prekeys_cache[peer_aid] = ([dict(prekey)], time.time() + 300.0)
            self._e2ee.cache_prekey(peer_aid, prekey)
            return [prekey]
        if result.get("found"):
            raise ValidationError(f"invalid prekey response for {peer_aid}")
        return []

    async def _fetch_peer_prekey(self, peer_aid: str) -> dict[str, Any] | None:
        """获取对方的单个 prekey（兼容接口，优先返回第一条 device prekey）。"""
        cached_list = self._peer_prekeys_cache.get(peer_aid)
        if cached_list is not None:
            items, expire_at = cached_list
            if time.time() < expire_at and items:
                return dict(items[0])
            self._peer_prekeys_cache.pop(peer_aid, None)
        cached = self._e2ee.get_cached_prekey(peer_aid)
        if cached is not None:
            return cached
        prekeys = await self._fetch_peer_prekeys(peer_aid)
        return dict(prekeys[0]) if prekeys else None

    async def _upload_prekey(self) -> dict[str, Any]:
        """生成 prekey 并上传到服务端"""
        prekey_material = self._e2ee.generate_prekey()
        prekey_id = prekey_material.get("prekey_id", "?")
        _client_log.info("prekey 上传中: prekey_id=%s", prekey_id)
        result = await self._transport.call("message.e2ee.put_prekey", prekey_material)
        _client_log.info("prekey 上传完成: prekey_id=%s result=%s", prekey_id, result)
        return result if isinstance(result, dict) else {"ok": True}

    async def _check_replay_guard(
        self, message_id: str, sender_aid: str, encryption_mode: str, message: dict[str, Any],
    ) -> bool:
        """服务端防重放检查。

        本地防重放由 E2EEManager._seen_messages 处理，无需此方法。
        此方法提供跨进程/跨重启的持久化防重放增强。
        """
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
            return True
        except Exception as _exc:
            import logging as _logging
            _logging.getLogger("aun_core").warning(
                "replay guard RPC 调用失败，允许消息通过: %s", _exc,
            )
            return True

    async def _decrypt_messages(self, messages: list[dict[str, Any]], *, source: str = "pull") -> list[dict[str, Any]]:
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
                if not self._e2ee._should_decrypt_for_current_aid(msg, payload):
                    result.append(msg)
                    continue
                # prekey 预检查：prekey_ecdh_v2 模式下，本地无 prekey 私钥则跳过解密
                enc_mode = payload.get("encryption_mode", "")
                prekey_id = payload.get("prekey_id") or (payload.get("aad") or {}).get("prekey_id") or ""
                if enc_mode == "prekey_ecdh_v2" and prekey_id:
                    if prekey_id in self._e2ee._missing_prekey_ids:
                        result.append(msg)
                        continue
                # 确保发送方证书已缓存（签名验证需要）
                from_aid = msg.get("from", "")
                sender_cert_fingerprint = str(
                    payload.get("sender_cert_fingerprint")
                    or (payload.get("aad") or {}).get("sender_cert_fingerprint")
                    or ""
                ).strip().lower()
                if from_aid:
                    cert_ready = await self._ensure_sender_cert_cached(
                        from_aid, sender_cert_fingerprint or None,
                    )
                    if not cert_ready:
                        _client_log.warning("无法获取发送方 %s 的证书，跳过解密", from_aid)
                        result.append(msg)
                        continue
                decrypted = self._e2ee._decrypt_message(msg, source=source)
                mid = msg.get("message_id", "")
                seq_val = msg.get("seq", "?")
                if decrypted is not None:
                    _client_log.debug("[%s] P2P 解密成功: message_id=%s seq=%s from=%s", source, mid, seq_val, from_aid)
                else:
                    _client_log.debug("[%s] P2P 解密失败: message_id=%s seq=%s from=%s", source, mid, seq_val, from_aid)
                # pull 路径不触发 prekey 补充（历史消息，prekey 早在推送时消耗过）
                result.append(decrypted if decrypted is not None else msg)
            else:
                result.append(msg)
        return result

    async def _decrypt_single_message(self, message: dict[str, Any], *, source: str = "push") -> dict[str, Any] | None:
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
        sender_cert_fingerprint = str(
            payload.get("sender_cert_fingerprint")
            or (payload.get("aad") or {}).get("sender_cert_fingerprint")
            or ""
        ).strip().lower()
        if not await self._check_replay_guard(message_id, from_aid, encryption_mode, message):
            _client_log.warning("[%s] 服务端 replay guard 判定重复消息，丢弃分发: message_id=%s seq=%s from=%s",
                                source, message_id, message.get("seq"), from_aid)
            return None

        # 确保发送方证书已缓存到 keystore（三路 ECDH + 签名验证需要）
        if from_aid:
            cert_ready = await self._ensure_sender_cert_cached(
                from_aid, sender_cert_fingerprint or None,
            )
            if not cert_ready:
                _client_log.warning("无法获取发送方 %s 的证书，跳过解密", from_aid)
                return message

        # 密码学解密（E2EEManager.decrypt_message 内含本地防重放）
        decrypted = self._e2ee.decrypt_message(message, source=source)
        if decrypted is None:
            _client_log.warning("[%s] 消息解密返回 None: message_id=%s seq=%s from=%s encryption_mode=%s",
                                source, message_id, message.get("seq"), from_aid, encryption_mode)
        else:
            e2ee_info = decrypted.get("e2ee", {}) if isinstance(decrypted, dict) else {}
            _client_log.debug("[%s] P2P 解密成功: message_id=%s seq=%s from=%s mode=%s prekey=%s",
                              source, message_id, message.get("seq"), from_aid,
                              e2ee_info.get("encryption_mode", "?"), e2ee_info.get("prekey_id", "?"))
        self._schedule_prekey_replenish_if_consumed(decrypted)
        return decrypted if decrypted is not None else message

    async def _ensure_sender_cert_cached(self, aid: str, cert_fingerprint: str | None = None) -> bool:
        """确保发送方证书在本地 keystore 中可用且未过期。

        安全要点：不能永久信任旧证书，必须按 TTL 刷新并重新做 PKI 验证
        （链 + CRL + OCSP + AID 绑定），以使证书吊销和轮换及时生效。

        返回 True 表示证书已就绪（PKI 验证通过），False 表示不可用。
        """
        # 内存缓存未过期 → 跳过（_fetch_peer_cert 已做完整 PKI 验证）
        cache_key = self._cert_cache_key(aid, cert_fingerprint)
        cached = self._cert_cache.get(cache_key)
        if cached and time.time() < cached.refresh_after:
            return True
        try:
            local_cert = self._keystore.load_cert(aid, cert_fingerprint)
        except TypeError:
            local_cert = self._keystore.load_cert(aid)
        except Exception as _lc_exc:
            _client_log.debug("加载对端证书失败 (%s): %s", aid, _lc_exc)
            local_cert = None
        if local_cert:
            # keystore 中有证书，但不直接信任 — 仍需通过 _fetch_peer_cert 做 PKI 验证
            # 仅在网络不可用时作为降级（见下方 except 分支）
            pass
        try:
            # _fetch_peer_cert 内部：下载 → 完整 PKI 验证 → 更新内存缓存
            cert_bytes = await self._fetch_peer_cert(aid, cert_fingerprint)
            # _fetch_peer_cert 内部已保存到版本目录，此处无需重复保存
            return True
        except Exception as exc:
            # 刷新失败时：若内存缓存有 PKI 验证过的证书（未过期 × 2 倍 TTL）则继续用
            if cached and time.time() < cached.validated_at + _PEER_CERT_CACHE_TTL * 2:
                _client_log.debug("刷新发送方 %s 证书失败，继续使用已验证的内存缓存: %s", aid, exc)
                return True
            # 超出宽限期或从未验证过 → 不可信
            _client_log.warning(
                "获取发送方 %s 证书失败且无已验证缓存，拒绝信任 (fp=%s): %s",
                aid,
                cert_fingerprint or "",
                exc,
            )
            return False

    def _get_verified_peer_cert(self, aid: str, cert_fingerprint: str | None = None) -> str | None:
        """获取经过 PKI 验证的 peer 证书（仅信任内存缓存中已验证的证书）。

        零信任要求：只返回经 _fetch_peer_cert 完整 PKI 验证后缓存的证书，
        不直接信任 keystore 中可能由恶意服务端注入的证书。
        """
        cache_key = self._cert_cache_key(aid, cert_fingerprint)
        cached = self._cert_cache.get(cache_key)
        if cached and time.time() < cached.validated_at + _PEER_CERT_CACHE_TTL * 2:
            return cached.cert_bytes.decode("utf-8") if isinstance(cached.cert_bytes, bytes) else cached.cert_bytes
        return None

    @staticmethod
    def _build_cert_url(gateway_url: str, aid: str, cert_fingerprint: str | None = None) -> str:
        parsed = urlparse(gateway_url)
        scheme = "https" if parsed.scheme == "wss" else "http"
        netloc = parsed.netloc
        path = f"/pki/cert/{quote(aid, safe='')}"
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        query = urlencode({"cert_fingerprint": normalized_fp}) if normalized_fp else ""
        return urlunparse((scheme, netloc, path, "", query, ""))

    @staticmethod
    def _resolve_peer_gateway_url(local_gateway_url: str, peer_aid: str) -> str:
        """跨域时将 Gateway URL 替换为 peer 所在域的 Gateway URL。

        例: local=wss://gateway.aid.com:20001/aun, peer=bob.aid.net
        → wss://gateway.aid.net:20001/aun
        """
        if "." not in peer_aid:
            return local_gateway_url
        _, peer_issuer = peer_aid.split(".", 1)
        import re
        m = re.search(r"gateway\.([^:/]+)", local_gateway_url)
        if not m:
            return local_gateway_url
        local_issuer = m.group(1)
        if local_issuer == peer_issuer:
            return local_gateway_url
        return local_gateway_url.replace(f"gateway.{local_issuer}", f"gateway.{peer_issuer}")

    # ── 内部：连接 ────────────────────────────────────────

    async def _connect_once(self, params: dict[str, Any], *, allow_reauth: bool) -> None:
        gateway_url = self._resolve_gateway(params)
        self._gateway_url = gateway_url
        self._loop = asyncio.get_running_loop()
        self._slot_id = str(params.get("slot_id") or "")
        self._connect_delivery_mode = dict(params.get("delivery_mode") or self._connect_delivery_mode)
        self._auth.set_instance_context(device_id=self._device_id, slot_id=self._slot_id)
        self._state = "connecting"

        # ── 前置 restore：在 transport.connect 启动 reader 之前完成
        # 避免 reader 把积压 push 交给空 tracker 的 handler，触发 S2 历史 gap 误补拉
        self._refresh_seq_tracking_context()
        self._restore_seq_tracker_state()

        challenge = await self._transport.connect(gateway_url)
        self._state = "authenticating"
        if allow_reauth:
            auth_context = await self._auth.connect_session(
                self._transport,
                challenge,
                gateway_url,
                access_token=params.get("access_token"),
                device_id=self._device_id,
                slot_id=self._slot_id,
                delivery_mode=self._connect_delivery_mode,
            )
            identity = auth_context.get("identity") if isinstance(auth_context, dict) else None
            if isinstance(identity, dict):
                self._identity = identity
                self._aid = identity.get("aid", self._aid)
                if self._logger and self._aid:
                    self._logger.set_aid(self._aid)
                if self._session_params is not None:
                    self._session_params["access_token"] = auth_context.get("token", params.get("access_token"))
        else:
            await self._auth.initialize_with_token(
                self._transport,
                challenge,
                str(params["access_token"]),
                device_id=self._device_id,
                slot_id=self._slot_id,
                delivery_mode=self._connect_delivery_mode,
            )
            self._sync_identity_after_connect(str(params["access_token"]))
        self._state = "connected"
        await self._dispatcher.publish("connection.state", {"state": self._state, "gateway": gateway_url})

        # auth 阶段 aid 可能被 identity 覆盖（上方 self._aid = identity.get(...)）；
        # 若 context 发生变化，重新 refresh + restore，保持 tracker 与真实身份一致
        if self._seq_tracker_context != self._current_seq_tracker_context():
            self._refresh_seq_tracking_context()
            self._restore_seq_tracker_state()

        self._start_background_tasks()

        # 上线后自动上传 prekey（最多重试 3 次，指数退避）
        for _prekey_attempt in range(3):
            try:
                await self._upload_prekey()
                break
            except Exception as exc:
                _client_log.warning("prekey 上传失败 (attempt %d/3): %s", _prekey_attempt + 1, exc)
                if _prekey_attempt < 2:
                    await asyncio.sleep(0.5 * (2 ** _prekey_attempt))

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
        self._start_group_epoch_tasks()
        # 上线/重连后一次性同步所有群（epoch key + 事件 + 消息）
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._sync_all_groups_once())

    async def _stop_background_tasks(self) -> None:
        current_task = asyncio.current_task()
        for attr in ("_heartbeat_task", "_token_refresh_task", "_prekey_refresh_task",
                      "_group_epoch_rotate_task", "_group_epoch_cleanup_task",
                      "_cache_cleanup_task"):
            task = getattr(self, attr, None)
            if task is None:
                continue
            task.cancel()
            if task is current_task:
                setattr(self, attr, None)
                continue
            try:
                await task
            except asyncio.CancelledError:
                pass  # 任务取消，正常清理
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
        interval = 3600.0  # 每小时检查一次 prekey 是否需要补充
        self._prekey_refresh_task = asyncio.get_event_loop().create_task(
            self._prekey_refresh_loop(interval)
        )

    async def _heartbeat_loop(self, interval: float) -> None:
        consecutive_failures = 0
        max_failures = 3  # 连续失败 3 次触发重连
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                if self._state != "connected":
                    consecutive_failures = 0
                    continue
                try:
                    await self._transport.call("meta.ping", {})
                    consecutive_failures = 0
                except Exception as exc:
                    consecutive_failures += 1
                    _client_log.warning("心跳失败 (%d/%d): %s", consecutive_failures, max_failures, exc)
                    await self._dispatcher.publish("connection.error", {"error": exc})
                    if consecutive_failures >= max_failures:
                        _client_log.warning("连续 %d 次心跳失败，触发断线重连", max_failures)
                        await self._handle_transport_disconnect(exc)
                        return
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
                    self._token_refresh_failures = 0  # 刷新成功，重置连续失败计数
                except AuthError as exc:
                    self._token_refresh_failures += 1
                    if self._token_refresh_failures >= _TOKEN_REFRESH_MAX_FAILURES:
                        _client_log.warning(
                            "token 刷新连续失败 %d 次，发布 exhausted 事件",
                            self._token_refresh_failures,
                        )
                        await self._dispatcher.publish("token.refresh_exhausted", {
                            "aid": self._identity.get("aid") if self._identity else None,
                            "consecutive_failures": self._token_refresh_failures,
                            "last_error": str(exc),
                        })
                        self._token_refresh_failures = 0
                    else:
                        _client_log.debug(
                            "token 刷新失败 (%d/%d)，下次重试: %s",
                            self._token_refresh_failures,
                            _TOKEN_REFRESH_MAX_FAILURES,
                            exc,
                        )
                    continue
                except Exception as exc:
                    await self._dispatcher.publish("connection.error", {"error": exc})
        except asyncio.CancelledError:
            raise

    async def _prekey_refresh_loop(self, interval: float) -> None:
        """定期检查并补充 prekey，防止长时间无通信后 prekey 耗尽。"""
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                if self._state != "connected":
                    continue
                try:
                    await self._upload_prekey()
                except Exception as exc:
                    _client_log.warning("prekey 定期刷新失败: %s", exc)
        except asyncio.CancelledError:
            raise

    @staticmethod
    def _extract_consumed_prekey_id(message: dict[str, Any] | None) -> str:
        if not isinstance(message, dict):
            return ""
        e2ee = message.get("e2ee")
        if not isinstance(e2ee, dict):
            return ""
        if e2ee.get("encryption_mode") != "prekey_ecdh_v2":
            return ""
        return str(e2ee.get("prekey_id") or "").strip()

    def _validate_message_recipient(self, to_aid: Any) -> None:
        if _is_group_service_aid(to_aid):
            raise ValidationError("message.send receiver cannot be group.{issuer}; use group.send instead")

    def _validate_outbound_call(self, method: str, params: dict[str, Any]) -> None:
        if method == "message.send":
            self._validate_message_recipient(params.get("to"))
            if "persist" in params:
                raise ValidationError("message.send no longer accepts 'persist'; configure delivery_mode during connect")
            if "delivery_mode" in params or "queue_routing" in params or "affinity_ttl_ms" in params:
                raise ValidationError("message.send does not accept delivery_mode; configure delivery_mode during connect")
        if method == "group.send":
            if "persist" in params:
                raise ValidationError("group.send does not accept 'persist'; group messages are always fanout")
            if "delivery_mode" in params or "queue_routing" in params or "affinity_ttl_ms" in params:
                raise ValidationError("group.send does not accept delivery_mode; group messages are always fanout")

    def _current_message_delivery_mode(self) -> dict[str, Any]:
        return dict(self._connect_delivery_mode)

    def _inject_message_cursor_context(self, method: str, params: dict[str, Any]) -> None:
        if method not in {"message.pull", "message.ack"}:
            return
        if "device_id" in params and str(params.get("device_id") or "").strip() != self._device_id:
            raise ValidationError("message.pull/message.ack device_id must match the current client instance")
        slot_id = normalize_instance_id(params.get("slot_id", self._slot_id), "slot_id", allow_empty=True)
        if slot_id != self._slot_id:
            raise ValidationError("message.pull/message.ack slot_id must match the current client instance")
        params["device_id"] = self._device_id
        params["slot_id"] = self._slot_id

    def _schedule_prekey_replenish_if_consumed(self, message: dict[str, Any] | None) -> None:
        prekey_id = self._extract_consumed_prekey_id(message)
        if not prekey_id or self._state != "connected":
            return
        # 全局只允许一个 put_prekey 请求 inflight，避免淹没 RPC 通道
        if self._prekey_replenish_inflight:
            self._prekey_pending_replenish += 1
            return
        self._prekey_replenish_inflight = True

        async def _replenish() -> None:
            try:
                await self._upload_prekey()
            except Exception as exc:
                _client_log.warning("消费 prekey 后补充失败: %s", exc)
            finally:
                self._prekey_replenish_inflight = False
                # 如果有待补充的请求积压，再触发一次
                if self._prekey_pending_replenish > 0 and self._state == "connected":
                    self._prekey_pending_replenish = 0
                    # 直接再次触发补充（不传 message，避免旧 prekey_id 重复触发）
                    self._prekey_replenish_inflight = True
                    loop2 = getattr(self, "_loop", None)
                    if loop2 and loop2.is_running():
                        loop2.create_task(_replenish())
                    else:
                        try:
                            asyncio.get_running_loop().create_task(_replenish())
                        except RuntimeError:
                            self._prekey_replenish_inflight = False

        loop = getattr(self, "_loop", None)
        if loop and loop.is_running():
            loop.create_task(_replenish())
            return
        try:
            asyncio.get_running_loop().create_task(_replenish())
        except RuntimeError:
            self._prekey_replenish_inflight = False

    def _restore_seq_tracker_state(self) -> None:
        """从 keystore seq_tracker 表按行恢复 SeqTracker 状态。"""
        if not self._aid:
            return
        try:
            loader = getattr(self._keystore, "load_all_seqs", None)
            if callable(loader):
                state = loader(self._aid, self._device_id, self._slot_id)
                if state:
                    self._seq_tracker.restore_state(state)
                    _client_log.info("SeqTracker 已恢复: %d 个命名空间", len(state))
                else:
                    _client_log.info("SeqTracker 无持久化状态，从零开始")
            else:
                # 旧版 fallback：从 instance_state 的 seq_tracker_state 字段读
                inst_loader = getattr(self._keystore, "load_instance_state", None)
                if callable(inst_loader):
                    instance_state = inst_loader(self._aid, self._device_id, self._slot_id)
                    if isinstance(instance_state, dict):
                        state = instance_state.get("seq_tracker_state")
                        if isinstance(state, dict):
                            self._seq_tracker.restore_state(state)
                            _client_log.info("SeqTracker 从旧版 instance_state 恢复: %d 个命名空间", len(state))
        except Exception as exc:
            _client_log.warning("恢复 SeqTracker 状态失败: %s", exc)

    def _current_seq_tracker_context(self) -> tuple[str, str, str] | None:
        aid = str(self._aid or "").strip()
        if not aid:
            return None
        return (aid, self._device_id, self._slot_id)

    def _reset_seq_tracking_state(self) -> None:
        self._seq_tracker = SeqTracker()
        self._seq_tracker_context = None
        self._gap_fill_done.clear()
        self._gap_fill_active = False
        self._pushed_seqs.clear()

    def _refresh_seq_tracking_context(self) -> None:
        next_context = self._current_seq_tracker_context()
        if next_context == self._seq_tracker_context:
            return
        self._seq_tracker = SeqTracker()
        self._gap_fill_done.clear()
        self._gap_fill_active = False
        self._pushed_seqs.clear()
        self._seq_tracker_context = next_context

    def _persist_seq(self, ns: str, *, force_seq: int | None = None) -> None:
        """即时持久化单个 namespace 的 seq（行级写入）。
        force_seq: 强制写入指定 seq（用于 auto-ack 后跳过空洞）。"""
        if not self._aid:
            return
        seq = force_seq if force_seq is not None else self._seq_tracker.get_contiguous_seq(ns)
        if seq <= 0:
            return
        _client_log.debug("persist_seq: ns=%s seq=%d (force=%s)", ns, seq, force_seq is not None)
        if force_seq is not None:
            # 同时更新内存中的 SeqTracker
            self._seq_tracker.restore_state({ns: seq})
        try:
            saver = getattr(self._keystore, "save_seq", None)
            if callable(saver):
                saver(self._aid, self._device_id, self._slot_id, ns, seq)
        except Exception as _seq_exc:
            _client_log.debug("保存 seq 失败: %s", _seq_exc)

    def _save_seq_tracker_state(self) -> None:
        """将 SeqTracker 状态按行保存到 keystore seq_tracker 表。"""
        if not self._aid:
            return
        state = self._seq_tracker.export_state()
        if not state:
            return
        try:
            saver = getattr(self._keystore, "save_seq", None)
            if callable(saver):
                for ns, seq in state.items():
                    if isinstance(seq, int) and seq > 0:
                        saver(self._aid, self._device_id, self._slot_id, ns, seq)
            else:
                # 旧版 fallback
                updater = getattr(self._keystore, "update_instance_state", None)
                if callable(updater):
                    def _merge_seq(m: dict) -> dict:
                        m["seq_tracker_state"] = state
                        return m
                    updater(self._aid, self._device_id, self._slot_id, _merge_seq)
        except Exception as exc:
            _client_log.warning("保存 SeqTracker 状态失败: %s", exc)

    def _build_rotation_signature(self, group_id: str, current_epoch: int, new_epoch: int = 0) -> dict[str, str]:
        """构建 epoch 轮换签名参数。"""
        identity = self._identity
        if not identity or not identity.get("private_key_pem"):
            return {}
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
            aid = identity.get("aid", "")
            ts = str(int(time.time()))
            sign_data = f"{group_id}|{current_epoch}|{new_epoch}|{aid}|{ts}".encode("utf-8")
            pk = _ser.load_pem_private_key(
                identity["private_key_pem"].encode("utf-8"), password=None,
            )
            sig = pk.sign(sign_data, _ec.ECDSA(_hashes.SHA256()))
            return {
                "rotation_signature": base64.b64encode(sig).decode("ascii"),
                "rotation_timestamp": ts,
            }
        except Exception as _sig_exc:
            _client_log.warning("构建轮换签名失败: %s", _sig_exc)
            return {}

    async def _sync_epoch_to_server(self, group_id: str) -> None:
        """建群后将本地 epoch 1 同步到服务端（服务端初始为 0），最多重试 3 次。"""
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                rotate_params = {
                    "group_id": group_id,
                    "current_epoch": 0,
                }
                rotate_params.update(self._build_rotation_signature(group_id, 0, 1))
                await self.call("group.e2ee.rotate_epoch", rotate_params)
                return
            except Exception as exc:
                if attempt < max_retries:
                    delay = 0.5 * (2 ** (attempt - 1))
                    _client_log.warning(
                        "同步 epoch 到服务端失败 (group=%s, 第%d/%d次): %s, %.1fs后重试",
                        group_id, attempt, max_retries, exc, delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    _client_log.error(
                        "同步 epoch 到服务端最终失败 (group=%s, 已重试%d次): %s",
                        group_id, max_retries, exc,
                    )

    async def _maybe_lead_rotate_group_epoch(self, group_id: str) -> None:
        """基于"排序最小 admin = leader"选举，其他 admin 走 jitter 兜底重试。

        避免所有剩余 admin 同时触发 _rotate_group_epoch 造成 CAS 风暴。
        普通 member 直接返回，不参与轮换。
        """
        my_aid = self._aid
        if not my_aid:
            return
        try:
            # 1. 获取成员列表
            members_resp = await self.call("group.get_members", {"group_id": group_id})
            if not isinstance(members_resp, dict):
                return
            raw_list = members_resp.get("members") or members_resp.get("items")
            if not isinstance(raw_list, list):
                return

            # 2. 提取所有 admin/owner
            admins = []
            for m in raw_list:
                if not isinstance(m, dict):
                    continue
                role = str(m.get("role", ""))
                aid = str(m.get("aid", ""))
                if aid and role in ("admin", "owner"):
                    admins.append(aid)

            if len(admins) == 0:
                return

            # 3. 排序选出 leader
            admins.sort()
            leader = admins[0]

            if leader == my_aid:
                # 我是 leader，直接发起
                await self._rotate_group_epoch(group_id)
                return

            # 4. 非 leader：随机 jitter（2~6s）后查询服务端 epoch 是否已被 leader 推进
            import random
            jitter_ms = 2000 + random.randint(0, 4000)
            # 记录 jitter 前的服务端 epoch
            try:
                before_resp = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
                before_epoch = before_resp.get("epoch", 0) if isinstance(before_resp, dict) else 0
            except Exception:
                before_epoch = self._group_e2ee.current_epoch(group_id) or 0
            await asyncio.sleep(jitter_ms / 1000.0)
            # jitter 后查询服务端 epoch
            try:
                after_resp = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
                after_epoch = after_resp.get("epoch", 0) if isinstance(after_resp, dict) else 0
            except Exception:
                after_epoch = self._group_e2ee.current_epoch(group_id) or 0

            if after_epoch > before_epoch:
                return  # leader 已完成

            _client_log.info(
                "[H21] leader 未完成 epoch 轮换，非 leader 兜底: group=%s myAid=%s",
                group_id, my_aid
            )
            await self._rotate_group_epoch(group_id)
        except Exception as exc:
            _client_log.warning("_maybe_lead_rotate_group_epoch 失败: %s", exc)

    async def _rotate_group_epoch(self, group_id: str) -> None:
        """为指定群组轮换 epoch 并分发新密钥。

        使用服务端 CAS 保证只有一方成功。
        服务端同时校验 owner/admin 角色。
        """
        try:
            # 1. 读取服务端当前 epoch
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
            current_epoch = epoch_result.get("epoch", 0)

            # 2. CAS 尝试递增（服务端校验角色 + 原子递增）
            rotate_params = {
                "group_id": group_id,
                "current_epoch": current_epoch,
            }
            rotate_params.update(self._build_rotation_signature(group_id, current_epoch, current_epoch + 1))
            cas_result = await self.call("group.e2ee.rotate_epoch", rotate_params)
            if not cas_result.get("success"):
                return  # CAS 失败（别人先轮换了或角色不符），放弃

            new_epoch = cas_result["epoch"]

            # 3. 获取最新成员列表
            members_result = await self.call("group.get_members", {"group_id": group_id})
            member_aids = [m["aid"] for m in members_result.get("members", [])]

            # 4. 本地生成密钥 + 存储 + 分发
            info = self._group_e2ee.rotate_epoch_to(group_id, new_epoch, member_aids)
            for dist in info["distributions"]:
                for _attempt in range(3):
                    try:
                        await self.call("message.send", {
                            "to": dist["to"],
                            "payload": dist["payload"],
                            "encrypt": True,
                        })
                        break  # 成功则跳出重试循环
                    except Exception as _exc:
                        if _attempt < 2:
                            await asyncio.sleep(1.0 * (_attempt + 1))
                        else:
                            _client_log.warning("epoch 密钥分发失败 (to=%s): %s", dist["to"], _exc)
        except Exception as exc:
            self._log_e2ee_error("rotate_epoch", group_id, "", exc)

    async def _distribute_key_to_new_member(self, group_id: str, new_member_aid: str) -> None:
        """将当前 group_secret 通过 P2P E2EE 分发给新成员。

        先拉服务端最新成员列表，更新本地 member_aids/commitment，构建签名 manifest，再分发。
        """
        try:
            secret_data = self._group_e2ee.load_secret(group_id)
            if secret_data is None:
                return

            # 拉服务端最新成员列表（确保一致性）
            members_result = await self.call("group.get_members", {"group_id": group_id})
            member_aids = [m["aid"] for m in members_result.get("members", [])]

            # 用最新成员列表更新本地当前 epoch 的 member_aids/commitment
            from .e2ee import (
                compute_membership_commitment, store_group_secret,
                build_key_distribution, build_membership_manifest, sign_membership_manifest,
            )
            epoch = secret_data["epoch"]
            commitment = compute_membership_commitment(member_aids, epoch, group_id, secret_data["secret"])
            store_group_secret(
                self._keystore, self._aid, group_id, epoch,
                secret_data["secret"], commitment, member_aids,
            )

            # 构建并签名 manifest
            manifest = build_membership_manifest(
                group_id=group_id,
                epoch=epoch,
                prev_epoch=epoch,
                member_aids=member_aids,
                added=[new_member_aid],
                removed=[],
                initiator_aid=self._aid or "",
            )
            identity = self._identity
            if identity and identity.get("private_key_pem"):
                manifest = sign_membership_manifest(manifest, identity["private_key_pem"])

            dist_payload = build_key_distribution(
                group_id, epoch, secret_data["secret"],
                member_aids, self._aid or "",
                manifest=manifest,
            )
            for _attempt in range(3):
                try:
                    await self.call("message.send", {
                        "to": new_member_aid,
                        "payload": dist_payload,
                        "encrypt": True,
                    })
                    break
                except Exception as _send_exc:
                    if _attempt < 2:
                        await asyncio.sleep(1.0 * (_attempt + 1))
                    else:
                        raise _send_exc
        except Exception as exc:
            self._log_e2ee_error("distribute_key", group_id, new_member_aid, exc)

    def _start_group_epoch_tasks(self) -> None:
        """启动群组 epoch 相关后台任务"""
        # 旧 epoch 清理（每小时检查一次）
        if self._group_epoch_cleanup_task is None or self._group_epoch_cleanup_task.done():
            self._group_epoch_cleanup_task = asyncio.create_task(
                self._group_epoch_cleanup_loop(3600.0)
            )
        # 定时 epoch 轮换
        rotate_interval = self._config_model.epoch_auto_rotate_interval
        if rotate_interval > 0:
            if self._group_epoch_rotate_task is None or self._group_epoch_rotate_task.done():
                self._group_epoch_rotate_task = asyncio.create_task(
                    self._group_epoch_rotate_loop(float(rotate_interval))
                )
        # 内存缓存定时清理（每小时扫描过期条目）
        if self._cache_cleanup_task is None or self._cache_cleanup_task.done():
            self._cache_cleanup_task = asyncio.create_task(
                self._cache_cleanup_loop(3600.0)
            )

    async def _is_rotation_leader(self, group_id: str) -> bool:
        """PY-005: 判断自己是否为该群组定时轮换的 leader。

        规则：所有 admin/owner 按 AID 字典序排序，最小的为 leader。
        普通 member 始终返回 False。
        """
        my_aid = self._aid
        if not my_aid:
            return False
        try:
            members_resp = await self._transport.call("group.get_members", {"group_id": group_id})
            if not isinstance(members_resp, dict):
                return False
            raw_list = members_resp.get("members") or members_resp.get("items")
            if not isinstance(raw_list, list):
                return False
            admins = []
            for m in raw_list:
                if not isinstance(m, dict):
                    continue
                role = str(m.get("role", ""))
                aid = str(m.get("aid", ""))
                if aid and role in ("admin", "owner"):
                    admins.append(aid)
            if not admins or my_aid not in admins:
                return False
            admins.sort()
            return admins[0] == my_aid
        except Exception as _exc:
            _client_log.debug("leader 选举查询失败: group=%s: %s", group_id, _exc)
            return False

    async def _group_epoch_rotate_loop(self, interval: float) -> None:
        """定时轮换所有已知群组的 epoch。

        PY-005: 只有 leader admin 执行定时轮换，避免多 admin 同时竞争。
        """
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                if self._state != "connected":
                    continue
                my_aid = self._aid
                if not my_aid:
                    continue
                try:
                    all_groups = self._keystore.load_all_group_secret_states(my_aid)
                    for gid in list(all_groups.keys()):
                        # PY-005: 只有 leader 执行定时轮换
                        if await self._is_rotation_leader(gid):
                            await self._rotate_group_epoch(gid)
                        else:
                            _client_log.debug("非 leader，跳过定时轮换: group=%s", gid)
                except Exception as _exc:
                    _client_log.warning("epoch 轮换失败: %s", _exc)
        except asyncio.CancelledError:
            raise

    async def _group_epoch_cleanup_loop(self, interval: float) -> None:
        """定时清理过期的旧 epoch 密钥"""
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                if self._state != "connected":
                    continue
                my_aid = self._aid
                if not my_aid:
                    continue
                try:
                    all_groups = self._keystore.load_all_group_secret_states(my_aid)
                    retention = self._config_model.old_epoch_retention_seconds
                    for gid in list(all_groups.keys()):
                        self._group_e2ee.cleanup(gid, retention)
                except Exception as _exc:
                    _client_log.warning("epoch 轮换失败: %s", _exc)
        except asyncio.CancelledError:
            raise

    async def _cache_cleanup_loop(self, interval: float) -> None:
        """定时清理过期的内存缓存条目"""
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                now = time.time()
                # 证书缓存
                for k in list(self._cert_cache):
                    if now >= self._cert_cache[k].refresh_after:
                        del self._cert_cache[k]
                # prekey 列表缓存
                for k in list(self._peer_prekeys_cache):
                    _, expire_at = self._peer_prekeys_cache[k]
                    if now >= expire_at:
                        del self._peer_prekeys_cache[k]
                # 补洞去重：清理超过 5 分钟的旧条目（可能是卡住的补洞）
                gap_cutoff = now - 300
                stale_keys = [k for k, ts in self._gap_fill_done.items() if ts < gap_cutoff]
                for k in stale_keys:
                    self._gap_fill_done.pop(k, None)
                # e2ee prekey 缓存
                self._e2ee.clean_expired_caches()
                self._group_e2ee.clean_expired_caches()
                # auth gateway 缓存
                self._auth.clean_expired_caches()
        except asyncio.CancelledError:
            raise

    # ── 内部：断线重连 ────────────────────────────────────

    # 不重连 close code 集合：客户端/认证/权限错误，重连无意义
    _NO_RECONNECT_CODES = frozenset({4001, 4003, 4008, 4009, 4010, 4011})

    async def _on_gateway_disconnect(self, data: Any) -> None:
        """处理服务端主动断开通知 event/gateway.disconnect。"""
        code = data.get("code") if isinstance(data, dict) else None
        reason = data.get("reason", "") if isinstance(data, dict) else ""
        _client_log.warning("服务端主动断开: code=%s, reason=%s", code, reason)
        self._server_kicked = True

    async def _handle_transport_disconnect(self, error: Exception | None, close_code: int | None = None) -> None:
        if self._closing or self._state == "closed":
            return
        self._state = "disconnected"
        # 断线时保存 SeqTracker 状态，防止进程崩溃后 seq 回退
        try:
            self._save_seq_tracker_state()
        except Exception as exc:
            _client_log.debug("断线时保存 SeqTracker 失败: %s", exc)
        await self._dispatcher.publish("connection.state", {"state": self._state, "error": error})
        if not bool(self._session_options["auto_reconnect"]):
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        # 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
        if self._server_kicked or (close_code is not None and close_code in self._NO_RECONNECT_CODES):
            self._state = "terminal_failed"
            reason = "server kicked" if self._server_kicked else f"close code {close_code}"
            _client_log.warning("抑制自动重连: %s", reason)
            await self._dispatcher.publish("connection.state", {
                "state": self._state, "error": error, "reason": reason,
            })
            return
        await self._stop_background_tasks()
        # 1006 = 网络异常断开（无 close frame），1000 = 正常关闭（客户端主动）
        # 其他 code = 服务端主动关闭
        server_initiated = close_code is not None and close_code not in (1000, 1006)
        self._reconnect_task = asyncio.create_task(self._reconnect_loop(server_initiated))

    async def _reconnect_loop(self, server_initiated: bool = False) -> None:
        retry = dict(self._session_options["retry"])
        max_delay = float(retry.get("max_delay", 64.0))
        # 服务端主动关闭时从 16s 起跳，避免重连风暴；网络断开从 initial_delay 起跳
        base_delay = 16.0 if server_initiated else float(retry.get("initial_delay", 1.0))
        delay = base_delay
        attempt = 0

        while not self._closing:
            attempt += 1
            self._state = "reconnecting"
            await self._dispatcher.publish("connection.state", {
                "state": self._state,
                "attempt": attempt,
            })
            try:
                # Full Jitter: random(0, delay) 打散重连时机
                await asyncio.sleep(random.random() * delay)
                # 重连前先 HEAD /health 探测，不健康则跳过本轮
                if self._gateway_url:
                    healthy = await self._discovery.check_health(self._gateway_url)
                    if not healthy:
                        delay = min(delay * 2, max_delay)
                        continue
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
        request["device_id"] = self._device_id
        request["slot_id"] = normalize_instance_id(
            request.get("slot_id", self._slot_id),
            "slot_id",
            allow_empty=True,
        )
        delivery_mode_raw = request.get("delivery_mode")
        if delivery_mode_raw is None:
            delivery_mode_raw = dict(self._default_connect_delivery_mode)
        elif not isinstance(delivery_mode_raw, dict):
            delivery_mode_raw = {"mode": delivery_mode_raw}
        if "queue_routing" in request:
            delivery_mode_raw["routing"] = request["queue_routing"]
        if "affinity_ttl_ms" in request:
            delivery_mode_raw["affinity_ttl_ms"] = request["affinity_ttl_ms"]
        request["delivery_mode"] = _normalize_delivery_mode_config(delivery_mode_raw)
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
        if self._logger and self._aid:
            self._logger.set_aid(self._aid)
        persist_identity = getattr(self._auth, "_persist_identity", None)
        if callable(persist_identity):
            persist_identity(identity)
        else:
            self._auth._keystore.save_identity(identity["aid"], identity)

    async def _invoke_reconnect_connect_once(self) -> None:
        if self._session_params is None:
            raise StateError("missing connect params for reconnect")
        # 从持久化 identity 刷新 token，避免用过期/失败的旧 token 反复重试
        fresh_identity = self._auth.load_identity_or_none(self._aid)
        if fresh_identity:
            fresh_token = self._auth._get_cached_access_token(fresh_identity)
            if fresh_token:
                self._session_params["access_token"] = fresh_token
        await self._connect_once(self._session_params, allow_reauth=True)

    @staticmethod
    def _should_retry_reconnect(error: Exception) -> bool:
        if isinstance(error, AuthError):
            message = str(error).strip().lower()
            if "aid_login1_failed" in message or "aid_login2_failed" in message:
                return True
            return False
        if isinstance(error, (AUNPermissionError, ValidationError, StateError)):
            return False
        if isinstance(error, ConnectionError):
            return True
        if isinstance(error, AUNError):
            return bool(error.retryable)
        if isinstance(error, (TimeoutError, OSError, ConnectionResetError, websockets.ConnectionClosed)):
            return True
        return True
