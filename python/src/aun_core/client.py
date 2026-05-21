from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse, urlunparse

import aiohttp
import websockets

from .auth import AuthFlow
from .config import AUNConfig, normalize_instance_id
from .logger import AUNLogger, NullLogger
from .crypto import CryptoProvider
from .discovery import GatewayDiscovery
from .e2ee import ProtectedHeaders
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
from .group_id import normalize_group_id as _normalize_group_id
from .keystore.file import FileKeyStore
from .namespaces.auth_namespace import AuthNamespace
from .namespaces.custody_namespace import CustodyNamespace
from .namespaces.meta_namespace import MetaNamespace
from .transport import RPCTransport
from .seq_tracker import SeqTracker
from .types import ConnectionState
from .v2.session import V2Session
from .v2.e2ee.encrypt_p2p import encrypt_p2p_message
from .v2.e2ee.decrypt import decrypt_message as v2_decrypt_message

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
_TOKEN_REFRESH_CHECK_INTERVAL = 30.0
_TOKEN_REFRESH_DEFAULT_LEAD = 1800.0
# 心跳间隔下/上限（秒）。0 = 关闭心跳；负值视为 0；其余值 clamp 到 [10, 600]。
# 服务端通过 hello.heartbeat_interval 与 meta.ping pong 中的同名字段下发，
# 客户端可在运行时被该值覆盖（仍受 clamp 约束）。
_HEARTBEAT_MIN_INTERVAL = 10.0
_HEARTBEAT_MAX_INTERVAL = 600.0


def _clamp_heartbeat_interval(value: Any) -> float:
    """统一归一化心跳间隔；0 / 负值 / 非有限值 → 0（关闭心跳）。"""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(v) or v <= 0:
        return 0.0
    if v < _HEARTBEAT_MIN_INTERVAL:
        return _HEARTBEAT_MIN_INTERVAL
    if v > _HEARTBEAT_MAX_INTERVAL:
        return _HEARTBEAT_MAX_INTERVAL
    return v

# PY-001: 解密失败的群消息待重试队列上限
_PENDING_DECRYPT_LIMIT = 100

# republish guard 单 namespace 硬上限。变量名仍沿用 pushed_seqs，避免扩大改动面。
_PUSHED_SEQS_LIMIT = 50000
# 越过空洞的 push 消息先挂起，等 contiguous_seq 推进后再按序放行
_PENDING_ORDERED_LIMIT = 50000
_RECONNECT_MIN_BASE_DELAY = 1.0
_RECONNECT_MAX_BASE_DELAY = 64.0
_GROUP_ROTATION_LEASE_MS = 120000
_GROUP_ROTATION_RETRY_MAX_DELAY = 300.0
_GROUP_JOIN_ROTATION_STAGGER_S = 3.0
_KEY_WAIT_TIMEOUT_S = 5.0
_KEY_WAIT_POLL_INTERVAL_S = 0.15

# P1-23: 非幂等方法使用更长超时（35s），避免 SDK 10s 超时 < gateway 30s 处理时间
_NON_IDEMPOTENT_TIMEOUT = 35.0
_NON_IDEMPOTENT_METHODS = frozenset({
    "message.send", "group.send", "group.create", "group.invite",
    "group.kick", "group.remove_member", "group.leave", "group.dissolve",
    "group.update_name", "group.update_avatar", "group.update_announcement",
    "group.update_settings", "group.rotate_epoch",
    "storage.upload", "storage.complete_upload", "storage.delete",
    "auth.create_aid", "auth.renew_cert", "auth.rekey",
    "message.thought.put", "group.thought.put",
    "group.add_member",
})

_DEFAULT_SESSION_OPTIONS: dict[str, Any] = {
    "auto_reconnect": True,
    "heartbeat_interval": 30.0,
    "token_refresh_before": _TOKEN_REFRESH_DEFAULT_LEAD,
    "retry": {
        "initial_delay": 1.0,
        "max_delay": 64.0,
        "max_attempts": 0,
    },
    "timeouts": {
        "connect": 5.0,
        "call": 35.0,
        "http": 30.0,
    },
}


def _clamp_reconnect_delay(value: Any, fallback: float, upper: float = _RECONNECT_MAX_BASE_DELAY) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = fallback
    if not math.isfinite(parsed):
        parsed = fallback
    return min(max(parsed, _RECONNECT_MIN_BASE_DELAY), upper)


def _reconnect_sleep_delay(base_delay: float, max_base_delay: float) -> float:
    return base_delay + random.random() * max_base_delay


import ssl as _ssl

_ssl_warning_emitted = False
_PREKEY_FALLBACK_DEVICE_ID = "aun_device_id"


def _debug_group_e2ee(message: str, **fields: Any) -> None:
    _ = (message, fields)


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


def _make_connection_factory(verify_ssl: bool = True, logger: AUNLogger | NullLogger | None = None):
    """根据 verify_ssl 配置创建 WebSocket 连接工厂"""
    _log = logger or NullLogger()

    async def _factory(url: str) -> Any:
        global _ssl_warning_emitted
        kw: dict[str, Any] = {"open_timeout": 5, "close_timeout": 5, "ping_interval": None}
        if url.startswith("wss://"):
            if verify_ssl:
                pass  # 使用默认 SSL 上下文（验证证书）
            else:
                kw["ssl"] = _get_no_verify_ssl()
                if not _ssl_warning_emitted:
                    _log.warn(
                        "client",
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


_PEER_CERT_CACHE_TTL = 3600  # 1 小时
_PEER_PREKEYS_CACHE_TTL = 3600  # 1 小时


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


def _is_retryable_peer_material_error(error: BaseException) -> bool:
    """判断是否为可重试的对端材料错误（证书/prekey 指纹不匹配或签名验证失败）。"""
    local_code = getattr(error, 'local_code', '') or getattr(error, 'code', '') or ''
    if str(local_code).strip() in (
        'PEER_CERT_FINGERPRINT_MISMATCH',
        'PREKEY_CERT_FINGERPRINT_MISMATCH',
        'PREKEY_SIGNATURE_VERIFY_FAILED',
    ):
        return True
    msg = str(error)
    return ('peer cert fingerprint mismatch for ' in msg
            or 'prekey cert fingerprint mismatch' in msg
            or 'prekey 签名验证失败' in msg)


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
        init_aid = str(raw_config.get("aid") or "").strip() or None
        # AUNLogger 自身已处理 debug=False：INFO/WARN/ERROR 输出 stderr，DEBUG 不输出，无文件日志
        # 不再用 NullLogger 整个静默掉，否则用户排查问题时看不到任何 SDK 异常
        self._log: AUNLogger | NullLogger = AUNLogger(
            debug=debug, aun_path=str(self._config_model.aun_path)
        )
        self._log.info(
            "client",
            "AUNClient initialized: debug=%s aun_path=%s aid=%s",
            debug, self._config_model.aun_path, init_aid or "-",
        )
        self.config = {
            "aun_path": str(self._config_model.aun_path),
            "root_ca_path": self._config_model.root_ca_path,
            "seed_password": self._config_model.seed_password,
        }
        self._aid: str | None = init_aid
        self._identity: dict[str, Any] | None = None
        self._state = "idle"
        self._gateway_url: str | None = None
        self._closing = False
        self._reconnect_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._heartbeat_nudge: asyncio.Event | None = None  # 用于唤醒心跳循环（间隔变更/状态变化）
        self._loop: asyncio.AbstractEventLoop | None = None  # connect 时绑定，未连接时由各调用方 fallback 到 get_running_loop()
        self._token_refresh_task: asyncio.Task | None = None
        self._prekey_refresh_task: asyncio.Task | None = None
        self._session_params: dict[str, Any] | None = None
        self._session_options: dict[str, Any] = dict(_DEFAULT_SESSION_OPTIONS)
        self._dispatcher = EventDispatcher(logger=self._log)
        self._discovery = GatewayDiscovery(verify_ssl=self._config_model.verify_ssl, logger=self._log)

        # E2EE 编排状态（内存缓存，进程退出即清空）
        self._cert_cache: dict[str, _CachedPeerCert] = {}
        # V2 验签结果缓存（进程内 TTL，命中即视为已通过 ECDSA 验签）
        self._v2_sig_cache: dict[bytes, float] = {}
        # 群安全等级追踪（变化时发布 group.v2.security_level 事件）
        self._v2_group_security_levels: dict[str, str] = {}
        # V2 session 与 bootstrap 缓存：只在 _initialize_v2_session() 中真正构造，
        # 但 epoch rotation 等路径会无条件访问，需先以空值占位避免 AttributeError。
        self._v2_session = None
        self._v2_bootstrap_cache: dict[str, tuple] = {}
        self._peer_prekeys_cache: dict[str, tuple[list[dict[str, Any]], float]] = {}
        self._prekey_replenish_inflight: bool = False
        self._prekey_pending_replenish: int = 0
        # 本地 agent.md 文件路径与对应 etag（quoted sha256 hex，与服务端 _agent_md_etag 一致）。
        # 由 publish_agent_md() / fetch_agent_md(自身 aid) 写入；用于跟服务端 RPC 注入的
        # _meta.agent_md_etag 比对，触发"本地未发布到服务端"或"服务端版本更新"的 UI 提示。
        self._local_agent_md_path: str = ""
        self._local_agent_md_etag: str = ""
        # gateway 在 RPC envelope._meta.agent_md_etag 注入的服务端 etag；纯观察，无下游依赖。
        self._remote_agent_md_etag: str = ""
        # 当前活跃 prekey：只有这个 prekey 被消费时才触发 replenish 上传。
        # connect 成功后上传的 prekey 记录为活跃；历史 prekey 被消费不触发上传。
        self._active_prekey_id: str = ""

        connection_factory = _make_connection_factory(self._config_model.verify_ssl, self._log)
        keystore = FileKeyStore(
            self._config_model.aun_path,
            encryption_seed=self._config_model.seed_password,
            logger=self._log,
        )
        self._keystore = keystore
        # 获取并缓存 device_id
        from .config import get_device_id
        self._device_id = get_device_id(self._config_model.aun_path)
        self._slot_id = ""
        self._connect_delivery_mode = _normalize_delivery_mode_config({"mode": "fanout"})
        self._default_connect_delivery_mode = dict(self._connect_delivery_mode)
        # 当前连接的能力声明（来自 connect 参数 extra_info._capabilities），
        # 用于按 V1/V2 路由 RPC 调用。None 视为"双向兼容"（同时支持 V1 与 V2）。
        self._connect_capabilities: dict[str, Any] | None = None
        self._auth = AuthFlow(
            keystore=keystore,
            crypto=CryptoProvider(),
            aid=init_aid,
            device_id=self._device_id,
            slot_id=self._slot_id,
            connection_factory=connection_factory,
            root_ca_path=self._config_model.root_ca_path,
            verify_ssl=self._config_model.verify_ssl,
            logger=self._log,
        )
        self._transport = RPCTransport(
            event_dispatcher=self._dispatcher,
            connection_factory=connection_factory,
            timeout=_DEFAULT_SESSION_OPTIONS["timeouts"]["call"],
            on_disconnect=self._handle_transport_disconnect,
            logger=self._log,
        )
        self._transport.set_meta_observer(self._observe_rpc_meta)
        self._token_refresh_failures = 0  # token 刷新连续失败计数
        self._cache_cleanup_task: asyncio.Task | None = None
        # 消息序列号跟踪器（群消息 + P2P 共用，按命名空间隔离）
        self._seq_tracker = SeqTracker()
        self._seq_tracker_context: tuple[str, str, str] | None = None
        self._gap_fill_done: dict[str, float] = {}  # 补洞去重：进行中的 key -> 开始时间戳
        self._gap_fill_active: bool = False  # 当前是否在补洞中（用于标记 pull 来源）
        # 已发布到应用层的 seq 集合（按命名空间），补洞/pull 路径 publish 前检查以避免重复分发。
        # 字段名保留 _pushed_seqs 以兼容既有测试和内部引用。
        self._pushed_seqs: dict[str, set[int]] = {}
        # 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq）
        self._pending_ordered_msgs: dict[str, dict[int, tuple[str, Any]]] = {}
        # 群惰性同步标志：只有收到推送或主动 pull 后才标记为已同步
        # 发送消息前如果未同步，先做一次 pull
        self._group_synced: set[str] = set()

        self.auth = AuthNamespace(self)
        self.custody = CustodyNamespace(self)
        self.meta = MetaNamespace(self)
        # V2 E2EE session（延迟初始化，connect 后才有 aid）
        self._v2_session: V2Session | None = None
        # V2 state chain 本地存储（分叉检测）：group_id -> (state_version, state_chain)
        self._v2_state_chains: dict[str, tuple[int, str]] = {}
        # 同一 group 的 V2 自动提案必须串行，避免 group.create 与后续成员变更抢同一 state_version。
        self._v2_auto_propose_locks: dict[str, asyncio.Lock] = {}
        self._v2_auto_propose_locks_guard = asyncio.Lock()
        self._v2_auto_propose_last_snapshot: dict[str, str] = {}
        self._v2_lazy_propose_triggered: dict[str, float] = {}
        # 内部订阅：推送消息自动解密后 re-publish 给用户
        self._dispatcher.subscribe("_raw.message.received", self._on_raw_message_received)
        # V2 P2P 推送通知
        self._dispatcher.subscribe("_raw.peer.v2.message_received", self._on_v2_push_notification)
        # 群组消息推送（明文 / 兼容）：直接透传给应用层
        self._dispatcher.subscribe("_raw.group.message_created", self._on_raw_group_message_created)
        # V2 群组消息推送：服务端发的 group.v2.message_created 事件，触发自动 pull + 解密
        self._dispatcher.subscribe("_raw.group.v2.message_created", self._on_raw_group_v2_message_created)
        # 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
        self._dispatcher.subscribe("_raw.group.changed", self._on_raw_group_changed)
        # V2 epoch 轮换事件：清除 bootstrap 缓存 + 触发 SPK rotation
        self._dispatcher.subscribe("_raw.group.v2.epoch_rotated", self._on_v2_epoch_rotated)
        # V2 state proposal 服务平面事件：owner/admin 负责确认或重新提案
        self._dispatcher.subscribe("_raw.group.v2.state_proposed", self._on_v2_state_proposed)
        self._dispatcher.subscribe("_raw.group.v2.state_retry_needed", self._on_v2_state_retry_needed)
        self._dispatcher.subscribe("_raw.group.v2.state_confirmed", self._on_v2_state_confirmed)
        # 群组状态提交事件：验证 state_hash 链并更新本地存储
        self._dispatcher.subscribe("_raw.group.state_committed", self._on_group_state_committed)
        # 其他事件直接透传
        for evt in ("message.recalled", "message.ack", "storage.object_changed"):
            self._dispatcher.subscribe(f"_raw.{evt}", lambda data, e=evt: self._dispatcher.publish(e, data))
        # 服务端主动断开通知：记录日志并标记不重连
        self._server_kicked = False
        self._dispatcher.subscribe("_raw.gateway.disconnect", self._on_gateway_disconnect)

    # ── 属性 ──────────────────────────────────────────────

    @property
    def aid(self) -> str | None:
        return self._aid

    def get_remote_agent_md_etag(self) -> str:
        """返回 gateway 在最近一次 RPC envelope._meta 注入的服务端 agent.md etag。

        未收到过则为空串；不阻塞调用，纯内存读。
        """
        return getattr(self, "_remote_agent_md_etag", "") or ""

    async def publish_agent_md(self, path: str) -> dict[str, Any]:
        """读取本地 agent.md → 签名 → 上传到服务端，并刷新内部 _local_agent_md_etag。

        Args:
            path: 本地 agent.md 文件路径（必填，不可为空）

        Returns:
            auth.upload_agent_md 的原始返回（含 aid / etag / last_modified / agent_md_url 等）

        Raises:
            ValidationError: path 为空
            FileNotFoundError: 文件不存在
            StateError: 本地无身份
            AUNError: 上传失败
        """
        raw_path = str(path or "").strip()
        if not raw_path:
            raise ValidationError("publish_agent_md requires non-empty path")
        with open(raw_path, "rb") as f:
            data = f.read()
        content = data.decode("utf-8")
        signed = await self.auth.sign_agent_md(content)
        result = await self.auth.upload_agent_md(signed)
        digest = hashlib.sha256(signed.encode("utf-8")).hexdigest()
        self._local_agent_md_etag = f'"{digest}"'
        self._local_agent_md_path = raw_path
        return result

    async def fetch_agent_md(
        self,
        aid: str | None = None,
        save_path: str | None = None,
    ) -> dict[str, Any]:
        """下载 agent.md 并自动验签；可选写盘；若 aid 是自己则更新本地 etag。

        Args:
            aid: 目标 AID；为空时取本地身份
            save_path: 写盘路径；不传则不写盘（浏览器版本无此参数）

        Returns:
            {
              "aid": str,
              "content": str,
              "signature": dict,                # auth.verify_agent_md 的返回
              "in_sync": bool | None,           # aid 是自己时给出 True/False；否则 None
              "saved_to": str | None,
              "save_error": str | None,
            }

        Raises:
            ValidationError: aid 为空且无本地身份
            NotFoundError: 服务端 404
            AUNError: 其它非 2xx
        """
        target = (aid or self._aid or "").strip()
        if not target:
            raise ValidationError("fetch_agent_md requires aid (or local AID)")

        content = await self.auth.download_agent_md(target)
        signature = await self.auth.verify_agent_md(content, aid=target)

        is_self = target == (self._aid or "")
        in_sync: bool | None = None
        if is_self:
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            self._local_agent_md_etag = f'"{digest}"'
            local = self._local_agent_md_etag or ""
            remote = self._remote_agent_md_etag or ""
            in_sync = (local == remote) if (local and remote) else False

        saved_to: str | None = None
        save_error: str | None = None
        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(content.encode("utf-8"))
                saved_to = save_path
            except OSError as exc:
                save_error = str(exc)

        return {
            "aid": target,
            "content": content,
            "signature": signature,
            "in_sync": in_sync,
            "saved_to": saved_to,
            "save_error": save_error,
        }

    def _observe_rpc_meta(self, meta: dict) -> None:
        """transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。"""
        if not isinstance(meta, dict):
            return
        etag = str(meta.get("agent_md_etag") or "").strip()
        if etag:
            self._remote_agent_md_etag = etag

    def set_trace_mode(self, mode: str) -> None:
        """设置会话级 trace mode（off/log/diag），影响后续所有 RPC 调用。"""
        self._transport.set_trace_mode(mode)

    def set_trace_observer(self, observer) -> None:
        """注册 trace observer，签名 observer(trace_info: dict)。diag 模式下 RPC response 和事件会回调。"""
        self._transport.set_trace_observer(observer)

    def _local_issuer_domain(self) -> str:
        """从本地 AID 提取 issuer 域名（{name}.{issuer}）。"""
        aid = self._aid or ""
        if not aid or "." not in aid:
            return ""
        return aid.split(".", 1)[1].strip(".").lower()

    @property
    def state(self) -> ConnectionState:
        return ConnectionState(self._state)

    # ── 生命周期 ──────────────────────────────────────────

    @property
    def gateway_health(self) -> bool | None:
        """最近一次 health check 结果，None 表示尚未检查。"""
        return self._discovery.last_healthy

    async def check_gateway_health(self, gateway_url: str, *, timeout: float = 5.0) -> bool:
        """向 gateway_url 的 /health 端点发送 GET 请求，检查网关可用性。"""
        return await self._discovery.check_health(gateway_url, timeout=timeout)

    async def connect(self, auth: dict[str, Any], options: dict[str, Any] | None = None) -> None:
        _t_start = time.time()
        if self._state not in {"idle", "closed", "disconnected"}:
            raise StateError(f"connect not allowed in state {self._state}")
        self._state = "connecting"
        params = dict(auth)
        if options:
            params.update(options)
        normalized = self._normalize_connect_params(params)
        self._session_params = normalized
        self._session_options = self._build_session_options(normalized)
        self._transport.set_timeout(self._session_options["timeouts"]["call"])
        self._closing = False
        self._log.debug("client", "connect enter: gateway=%s", normalized.get("gateway", "-"))
        try:
            await self._connect_once(normalized, allow_reauth=False)
            self._log.debug("client", "connect exit: elapsed=%.3fs gateway=%s aid=%s", time.time() - _t_start, self._gateway_url, self._aid or "-")
        except BaseException as exc:
            # 连接失败时回退状态，允许重试
            if self._state in ("connecting", "authenticating"):
                self._state = "disconnected"
            self._log.warn("client", "connect exit (error): elapsed=%.3fs gateway=%s err=%s", time.time() - _t_start, normalized.get("gateway", "-"), exc)
            raise

    async def disconnect(self) -> None:
        """断开连接但不关闭客户端（可重新 connect，对齐 C++ Disconnect）"""
        _t_start = time.time()
        self._log.debug("client", "disconnect enter: state=%s closing=%s", self._state, self._closing)
        # 若 close() 已在执行中，跳过 disconnect 避免竞态
        if self._closing:
            self._log.debug("client", "disconnect exit (close-in-progress): elapsed=%.3fs", time.time() - _t_start)
            return
        if self._state not in {"connected", "reconnecting"}:
            self._log.debug("client", "disconnect exit (not-connected): elapsed=%.3fs state=%s", time.time() - _t_start, self._state)
            return
        self._save_seq_tracker_state()
        await self._stop_background_tasks()
        # 取消重连任务，防止 disconnect 后僵尸重连
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None
        await self._transport.close()
        self._state = "disconnected"
        await self._dispatcher.publish("connection.state", {"state": self._state})
        self._log.debug("client", "disconnect exit: elapsed=%.3fs state=%s", time.time() - _t_start, self._state)

    def list_identities(self) -> list[dict[str, Any]]:
        """列出本地所有已存储的身份摘要（仅返回有有效私钥的 AID）"""
        aids = self._keystore.list_identities()
        summaries: list[dict[str, Any]] = []
        for aid in sorted(aids):
            identity = self._keystore.load_identity(aid)
            if not identity or not identity.get("private_key_pem"):
                continue
            summary: dict[str, Any] = {"aid": aid}
            md = self._keystore.load_metadata(aid)
            if md:
                summary["metadata"] = md
            summaries.append(summary)
        return summaries

    async def close(self) -> None:
        _t_start = time.time()
        self._log.debug("client", "close enter: state=%s", self._state)
        self._closing = True
        try:
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
                self._log.debug("client", "close exit (was idle/closed): elapsed=%.3fs state=%s", time.time() - _t_start, self._state)
                return
            await self._transport.close()
            self._state = "closed"
            await self._dispatcher.publish("connection.state", {"state": self._state})
            self._reset_seq_tracking_state()
            self._log.debug("client", "close exit: elapsed=%.3fs state=%s", time.time() - _t_start, self._state)
        finally:
            close_keystore = getattr(self._keystore, "close", None)
            if callable(close_keystore):
                close_keystore()

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
        "group.thought.put",
        "message.thought.put",
        "group.set_settings",
        "group.commit_state",
        "group.e2ee.begin_rotation", "group.e2ee.commit_rotation",
        "group.e2ee.abort_rotation",
        "group.ban", "group.unban",
        "group.dissolve", "group.suspend", "group.resume",
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

    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None) -> Any:
        _t_call_start = time.time()
        if self._state != "connected":
            raise ConnectionError("client is not connected")
        if self._is_internal_only_method(method):
            raise AUNPermissionError(f"method is internal_only: {method}")

        params = dict(params) if params else {}
        self._log.debug("client", "call enter: method=%s", method)
        self._validate_outbound_call(method, params)
        self._inject_message_cursor_context(method, params)

        # group.* 方法的 group_id 归一化为 canonical 格式（兼容老/污染数据）
        # 不对无域输入补本域——保持与历史行为兼容，交给服务端归一化
        if method.startswith("group.") and "group_id" in params:
            raw_gid = params.get("group_id")
            if raw_gid:
                normalized_gid = _normalize_group_id(str(raw_gid))
                if normalized_gid != str(raw_gid):
                    self._log.debug("client", "call group_id normalized: %s -> %s method=%s", raw_gid, normalized_gid, method)
                params["group_id"] = normalized_gid

        # group.* 方法注入 device_id（服务端用于多设备消息路由）
        if method.startswith("group.") and self._device_id and "device_id" not in params:
            params["device_id"] = self._device_id
        if method.startswith("group.") and "slot_id" not in params:
            params["slot_id"] = self._slot_id

        # 自动加密：message.send 默认加密（encrypt 默认 True）— V2-only 客户端必须走 V2 路径
        if method == "message.send":
            encrypt = params.pop("encrypt", True)
            self._log.info("client", "DEBUG call message.send: to=%s encrypt=%s payload_keys=%s",
                           params.get("to", "-"), encrypt,
                           list(params.get("payload", {}).keys()) if isinstance(params.get("payload"), dict) else type(params.get("payload")).__name__)
            if encrypt:
                if not self._v2_session:
                    raise StateError("V2 session not initialized; encrypted message.send requires V2 (V1 E2EE removed)")
                self._log.debug("client", "call encrypt branch: method=message.send to=%s v2=True", params.get("to", "-"))
                try:
                    result = await self._send_encrypted_v2(params)
                    self._log.debug("client", "call exit (encrypted): elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
                    return result
                except Exception as exc:
                    self._log.debug("client", "call exit (encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                    raise
            # encrypt=false：明文走通用 RPC 路径；protected_headers/headers 是信封元数据，加密与否都保留
            self._maybe_append_echo_trace_send(params)

        # 自动加密：group.send 默认加密（encrypt 默认 True）— V2-only 客户端必须走 V2 路径
        if method == "group.send":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                if not self._v2_session:
                    raise StateError("V2 session not initialized; encrypted group.send requires V2 (V1 E2EE removed)")
                self._log.debug("client", "call encrypt branch: method=group.send group_id=%s v2=True", params.get("group_id", "-"))
                try:
                    result = await self._send_group_encrypted_v2(params)
                    self._log.debug("client", "call exit (group-encrypted): elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
                    return result
                except Exception as exc:
                    self._log.debug("client", "call exit (group-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                    raise
            # encrypt=false：明文走通用 RPC 路径，不受 group epoch 轮换/恢复约束
            self._maybe_append_echo_trace_send(params)

        # message.pull：V2 就绪时走 V2 pull（V2-only：跳过 V1 envelope）
        if method == "message.pull" and getattr(self, "_v2_session", None):
            self._log.debug("client", "call route: message.pull → V2 pull")
            return await self._pull_v2_internal(params)

        # message.ack：V2 就绪时走 V2 ack
        if method == "message.ack" and getattr(self, "_v2_session", None):
            self._log.debug("client", "call route: message.ack → V2 ack")
            return await self._ack_v2_internal(params)

        # group.pull：V2 就绪时走 V2 pull
        if method == "group.pull" and self._v2_session and params.get("group_id"):
            self._log.debug("client", "call route: group.pull → V2 pull")
            return await self._pull_group_v2_internal(params)

        # group.ack_messages：V2 就绪时走 V2 ack
        if method == "group.ack_messages" and self._v2_session and params.get("group_id"):
            self._log.debug("client", "call route: group.ack_messages → V2 ack")
            return await self._ack_group_v2_internal(params)
        if method == "group.thought.put":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                if not self._v2_session or not params.get("group_id"):
                    raise StateError("V2 session not initialized; encrypted group.thought.put requires V2 (V1 E2EE removed)")
                try:
                    self._log.debug("client", "call route: group.thought.put → V2 encrypted put")
                    result = await self._put_group_thought_encrypted_v2(params)
                    self._log.debug("client", "call exit (thought-encrypted): elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
                    return result
                except Exception as exc:
                    self._log.debug("client", "call exit (thought-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                    raise
            # encrypt=false：明文走通用 RPC 路径
        if method == "message.thought.put":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                if not self._v2_session or not params.get("to"):
                    raise StateError("V2 session not initialized; encrypted message.thought.put requires V2 (V1 E2EE removed)")
                try:
                    self._log.debug("client", "call route: message.thought.put → V2 encrypted put")
                    result = await self._put_message_thought_encrypted_v2(params)
                    self._log.debug("client", "call exit (msg-thought-encrypted): elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
                    return result
                except Exception as exc:
                    self._log.debug("client", "call exit (msg-thought-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                    raise
            # encrypt=false：明文走通用 RPC 路径

        # 关键操作自动附加客户端签名
        if method in self._SIGNED_METHODS:
            self._sign_client_operation(method, params)

        # P1-23: 非幂等方法使用更长超时
        call_kwargs: dict[str, Any] = {}
        if method in _NON_IDEMPOTENT_METHODS:
            call_kwargs["timeout"] = _NON_IDEMPOTENT_TIMEOUT
        if trace:
            call_kwargs["trace"] = trace
        try:
            result = await self._transport.call(method, params, **call_kwargs)
        except TypeError as exc:
            if call_kwargs and "unexpected keyword argument" in str(exc):
                call_kwargs.pop("timeout", None)
                call_kwargs.pop("trace", None)
                result = await self._transport.call(method, params, **call_kwargs) if call_kwargs else await self._transport.call(method, params)
            else:
                self._log.debug("client", "call exit (error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                raise
        except Exception as exc:
            self._log.debug("client", "call exit (error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
            raise

        # 自动解密：message.pull 返回的消息（V2 路径已在 call() 开头路由，此处为 plaintext pull 的 seq 跟踪）
        if method == "message.pull" and isinstance(result, dict):
            ns = f"p2p:{self._aid}" if self._aid else ""
            messages = result.get("messages")
            contig_before = self._seq_tracker.get_contiguous_seq(ns) if self._aid and getattr(self, "_seq_tracker", None) is not None else 0
            if isinstance(messages, list) and messages and self._aid and getattr(self, "_seq_tracker", None) is not None:
                self._seq_tracker.on_pull_result(ns, messages, after_seq=int((params or {}).get("after_seq", 0) or 0))
            if self._aid and getattr(self, "_seq_tracker", None) is not None:
                server_ack = int(result.get("server_ack_seq") or 0)
                if server_ack > 0:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig < server_ack:
                        self._log.info("client",
                            "message.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d",
                            ns, contig, server_ack,
                        )
                        self._seq_tracker.force_contiguous_seq(ns, server_ack)
                contig = self._seq_tracker.get_contiguous_seq(ns)
                if contig != contig_before:
                    self._persist_seq(ns)
                # auto-ack 延迟到 publish 完成后（由 _fill_p2p_gap 负责）
                result["_contig_before"] = contig_before

        # 自动解密：group.pull 返回的群消息（V2 路径已在 call() 开头路由，此处为 plaintext pull 的 seq 跟踪）
        if method == "group.pull" and isinstance(result, dict):
            messages = result.get("messages")
            gid = (params or {}).get("group_id", "")
            ns = f"group:{gid}" if gid else ""
            contig_before = self._seq_tracker.get_contiguous_seq(ns) if gid and getattr(self, "_seq_tracker", None) is not None else 0
            if isinstance(messages, list) and messages and gid and getattr(self, "_seq_tracker", None) is not None:
                self._seq_tracker.on_pull_result(ns, messages, after_seq=int((params or {}).get("after_seq", 0) or 0))
            if gid and getattr(self, "_seq_tracker", None) is not None:
                cursor = result.get("cursor")
                if isinstance(cursor, dict):
                    server_ack = int(cursor.get("current_seq") or 0)
                    if server_ack > 0:
                        contig = self._seq_tracker.get_contiguous_seq(ns)
                        if contig < server_ack:
                            self._log.info("client",
                                "group.pull retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                                ns, contig, server_ack,
                            )
                            self._seq_tracker.force_contiguous_seq(ns, server_ack)
                contig = self._seq_tracker.get_contiguous_seq(ns)
                if contig != contig_before:
                    self._persist_seq(ns)
                # auto-ack 延迟到 publish 完成后（由 _fill_group_gap / _fill_p2p_gap 负责）
                result["_contig_before"] = contig_before

        # ── Group E2EE 自动编排 ────────────────────────────
        # V2-only 客户端：群密钥/状态由 group.v2.bootstrap + group.v2.propose_state 体系管理，
        # V1 group.e2ee.* RPC 已移除，所有 V1 编排路径已删除。
        # 建群/成员变更后同步 propose+confirm（保证返回后 committed state 已推进）
        if method in {
            "group.create", "group.add_member", "group.kick", "group.remove_member", "group.leave",
            "group.review_join_request", "group.batch_review_join_request",
            "group.use_invite_code", "group.request_join",
        } and isinstance(result, dict) and getattr(self, "_v2_session", None):
            gid = ""
            if isinstance(result.get("group"), dict):
                gid = str(result["group"].get("group_id") or "").strip()
            if not gid:
                gid = str(params.get("group_id") or "").strip()
            if gid:
                try:
                    await self._v2_auto_propose_state(gid)
                except Exception as exc:
                    self._log.debug("client", "V2 post-membership propose failed (non-fatal): group=%s err=%s", gid, exc)

        self._log.debug("client", "call exit: elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
        return result



    @staticmethod
    def _protected_headers_from_params(params: dict[str, Any]) -> dict[str, Any] | ProtectedHeaders | None:
        headers = params.get("protected_headers")
        if headers is None:
            headers = params.get("headers")
        if isinstance(headers, (dict, ProtectedHeaders)):
            return headers
        to_dict = getattr(headers, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
            return value if isinstance(value, dict) else None
        return None

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
            self._log.debug("client", "failed to extract cert fingerprint: %s", _fp_exc)
            return ""

    async def _lazy_sync_group(self, group_id: str) -> None:
        """惰性同步：首次激活群时 pull 最近消息，建立 seq 基线。"""
        self._group_synced.add(group_id)
        try:
            ns = f"group:{group_id}"
            after_seq = self._seq_tracker.get_contiguous_seq(ns)
            result = await self._transport.call("group.pull", {
                "group_id": group_id,
                "after_message_seq": after_seq,
                "limit": 200,
            })
            messages = result.get("messages", []) if isinstance(result, dict) else []
            for msg in messages:
                seq = msg.get("seq")
                if seq is not None:
                    self._seq_tracker.on_message_seq(ns, int(seq))
            if messages:
                self._persist_seq(ns)
                self._log.info("client", "lazy sync group %s: pulled %d messages, after_seq=%d", group_id, len(messages), after_seq)
        except Exception as exc:
            self._log.warn("client", "lazy sync group %s failed: %s", group_id, exc)


    def _join_mode_allows_member_epoch_rotation(mode: str) -> bool:
        return str(mode or "").strip().lower() in {"open", "invite_only", "invite_code"}

    def _group_secret_matches_committed_rotation(
        secret_data: dict[str, Any] | None,
        committed_rotation: dict[str, Any] | None,
        *,
        local_aid: str = "",
    ) -> bool:
        if not isinstance(secret_data, dict):
            return False
        committed_commitment = ""
        if isinstance(committed_rotation, dict):
            committed_commitment = str(committed_rotation.get("key_commitment") or "").strip()
        local_commitment = str(secret_data.get("commitment") or "").strip()
        if committed_commitment and committed_commitment != local_commitment:
            return False
        pending_rotation_id = str(secret_data.get("pending_rotation_id") or "").strip()
        if not pending_rotation_id:
            return True
        if not isinstance(committed_rotation, dict):
            return False
        if str(committed_rotation.get("rotation_id") or "").strip() != pending_rotation_id:
            return False
        return True

    async def ping(self, params: dict | None = None) -> Any:
        return await self.meta.ping(params or {})

    async def status(self, params: dict | None = None) -> Any:
        return await self.meta.status(params or {})

    async def trust_roots(self, params: dict | None = None) -> Any:
        return await self.meta.trust_roots(params or {})

    # ── 事件 ──────────────────────────────────────────────

    def on(self, event: str, handler: Callable[[Any], Any]) -> Subscription:
        return self._dispatcher.subscribe(event, handler)

    def off(self, event: str, handler: Callable[[Any], Any]) -> None:
        """注销事件处理器（对齐 C++ RemoveEventHandler / JS off）。"""
        self._dispatcher.unsubscribe(event, handler)

    # ── P1-17: auto-ack fire-and-forget 辅助 ──────────────────
    def _fire_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        """将 ack RPC 以 fire-and-forget 方式发送，不阻塞消息事件分发。"""
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._safe_ack(method, params, label))

    async def _safe_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        """安全执行 ack RPC，失败仅记录日志。"""
        try:
            await self._transport.call(method, params)
        except Exception as exc:
            self._log.debug("client", "%s auto-ack failed: %s", label or method, exc)

    async def _on_raw_message_received(self, data: Any) -> None:
        """处理 transport 层推送的原始消息：解密后 re-publish 给用户。"""
        _t_start = time.time()
        if isinstance(data, dict):
            self._log.debug(
                "client",
                "_on_raw_message_received enter: message_id=%s seq=%s from=%s",
                data.get("message_id", "-"), data.get("seq", "-"), data.get("from", "-"),
            )
        else:
            self._log.debug("client", "_on_raw_message_received enter (non-dict): type=%s", type(data).__name__)
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._process_and_publish_message(data))
        self._log.debug("client", "_on_raw_message_received exit: elapsed=%.3fs", time.time() - _t_start)

    async def _process_and_publish_message(self, data: Any) -> None:
        """实际处理推送消息的异步任务。"""
        _t_start = time.time()
        try:
            if not isinstance(data, dict):
                await self._publish_app_event("message.received", data)
                return
            msg = dict(data)
            self._log.info(
                "client",
                "DEBUG _process_and_publish_message enter: message_id=%s seq=%s from=%s device_id=%s slot_id=%s",
                msg.get("message_id"), msg.get("seq"), msg.get("from"),
                msg.get("device_id"), msg.get("slot_id"),
            )
            if not self._message_targets_current_instance(msg):
                self._log.info(
                    "client",
                    "DEBUG _process_and_publish_message FILTERED (instance mismatch): "
                    "msg_device=%s self_device=%s msg_slot=%s self_slot=%s",
                    msg.get("device_id"), self._device_id,
                    msg.get("slot_id"), self._slot_id,
                )
                return

            # P2P 空洞检测
            seq = msg.get("seq")
            if seq is not None and self._aid:
                ns = f"p2p:{self._aid}"
                old_contig = self._seq_tracker.get_contiguous_seq(ns)
                need_pull = self._seq_tracker.on_message_seq(ns, int(seq))
                new_contig = self._seq_tracker.get_contiguous_seq(ns)
                self._log.debug("client", "P2P push seq tracking: seq=%d contig=%d->%d need_pull=%s",
                                  int(seq), old_contig, new_contig, need_pull)
                self._persist_seq(ns)
                if need_pull:
                    loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(self._fill_p2p_gap())

            # 明文消息直接透传（V2 加密消息走 _on_v2_push_notification）
            if seq is not None and self._aid:
                self._log.info(
                    "client",
                    "DEBUG publish ordered: ns=%s seq=%s message_id=%s",
                    ns, seq, msg.get("message_id", "?"),
                )
                await self._publish_ordered_message("message.received", ns, seq, msg)
            else:
                self._log.info(
                    "client",
                    "DEBUG publish app event (no seq): message_id=%s",
                    msg.get("message_id", "?"),
                )
                await self._publish_app_event("message.received", msg)

            # auto-ack push 消息：ack contiguous_seq（连续确认到的最高位置，避免空洞时跳跃推进）
            if seq is not None and self._aid:
                contig = self._seq_tracker.get_contiguous_seq(ns)
                if contig > 0:
                    self._fire_ack("message.ack", {
                        "seq": contig, "device_id": self._device_id, "slot_id": self._slot_id,
                    }, "P2P auto-ack")
        except Exception as _exc:
            self._log.warn("client", "P2P push processing failed: %s", _exc)
            if isinstance(data, dict) and data.get("seq") is not None and self._aid:
                _exc_ns = f"p2p:{self._aid}"
                _exc_contig = self._seq_tracker.get_contiguous_seq(_exc_ns)
                if _exc_contig > 0:
                    self._fire_ack("message.ack", {
                        "seq": _exc_contig, "device_id": self._device_id, "slot_id": self._slot_id,
                    }, "P2P auto-ack（异常路径）")
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
                await self._publish_app_event("message.undecryptable", safe_event)

    async def _on_raw_group_message_created(self, data: Any) -> None:
        """处理 group.message_created 推送。
        V2-only 模式：推送不带 payload，触发 group.v2.pull 获取完整消息。
        V1 兼容模式：直接透传（payload 已在推送中）。
        """
        if not isinstance(data, dict):
            await self._publish_app_event("group.message_created", data)
            return
        group_id = data.get("group_id", "")
        seq = data.get("seq")
        if group_id:
            self._group_synced.add(group_id)

        # V2-only 模式：V1 明文推送不带 payload，需要通过 group.v2.pull 获取完整消息
        if getattr(self, "_v2_session", None) and group_id and seq is not None:
            ns = f"group:{group_id}"
            seq_i = int(seq)
            if self._is_published_seq(ns, seq_i) or self._is_pending_ordered_seq(ns, seq_i):
                return
            # 复用 V2 push 的 pull 逻辑
            async def _v1_pull_and_publish() -> None:
                try:
                    dedup_key = f"group_pull:{ns}"
                    if dedup_key in self._gap_fill_done:
                        return
                    self._gap_fill_done[dedup_key] = time.time()
                    try:
                        contig = self._seq_tracker.get_contiguous_seq(ns)
                        after_seq = max(0, contig)
                        await self._pull_group_v2_internal({"group_id": group_id, "after_seq": after_seq, "limit": 50})
                    finally:
                        self._gap_fill_done.pop(dedup_key, None)
                except Exception as exc:
                    self._log.warn("client", "_on_raw_group_message_created v2 pull failed group=%s: %s", group_id, exc)
            loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
            loop.create_task(_v1_pull_and_publish())
            return

        # V1 兼容路径（非 V2-only 模式）
        if group_id and seq is not None:
            ns = f"group:{group_id}"
            seq_i = int(seq)
            if self._is_published_seq(ns, seq_i) or self._is_pending_ordered_seq(ns, seq_i):
                return
            self._seq_tracker.on_message_seq(ns, seq_i)
            self._persist_seq(ns)
            await self._publish_ordered_message("group.message_created", ns, seq, data)
            contig = self._seq_tracker.get_contiguous_seq(ns)
            if contig > 0:
                self._fire_ack("group.ack_messages", {
                    "group_id": group_id, "msg_seq": contig,
                    "device_id": self._device_id,
                    "slot_id": self._slot_id,
                }, f"群消息 auto-ack group={group_id}")
        else:
            await self._publish_app_event("group.message_created", data)

    async def _on_raw_group_v2_message_created(self, data: Any) -> None:
        """处理 V2 群消息推送：服务端 push 仅携带 seq + message_id + sender_aid + group_id，
        SDK 收到后主动 group.v2.pull 拉取 envelope 并自动解密，转发为 group.message_created
        事件给应用层（与 V1 群路径对齐）。
        """
        _t_start = time.time()
        if not isinstance(data, dict):
            self._log.debug("client", "_on_raw_group_v2_message_created skipped (non-dict): type=%s", type(data).__name__)
            return
        group_id = str(data.get("group_id") or "").strip()
        seq = int(data.get("seq", 0) or 0)
        message_id = str(data.get("message_id") or "").strip()
        sender_aid = str(data.get("sender_aid") or "").strip()
        self._log.debug("client",
            "_on_raw_group_v2_message_created group=%s seq=%d message_id=%s sender=%s",
            group_id, seq, message_id, sender_aid,
        )
        if not group_id or seq <= 0:
            self._log.debug("client", "_on_raw_group_v2_message_created skipped: missing group_id or seq")
            return
        if not getattr(self, "_v2_session", None):
            self._log.debug("client", "_on_raw_group_v2_message_created skipped: V2 session not initialized")
            return

        async def _pull_and_publish() -> None:
            try:
                ns = f"group:{group_id}"
                # per-namespace 去重：同一 group namespace 只允许 1 个 in-flight pull
                dedup_key = f"group_pull:{ns}"
                if dedup_key in self._gap_fill_done:
                    return
                self._gap_fill_done[dedup_key] = time.time()
                try:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    after_seq = max(0, contig)
                    pull_params = {"group_id": group_id, "after_seq": after_seq, "limit": 50}
                    self._log.debug("client",
                        "_on_raw_group_v2_message_created -> group.v2.pull group=%s after_seq=%d",
                        group_id, after_seq,
                    )
                    pulled = await self._pull_group_v2_internal(pull_params)
                    msgs = pulled.get("messages", []) if isinstance(pulled, dict) else []
                    self._log.debug("client",
                        "_on_raw_group_v2_message_created pulled %d msgs for group=%s",
                        len(msgs), group_id,
                    )
                finally:
                    self._gap_fill_done.pop(dedup_key, None)
            except Exception as exc:
                self._log.warn("client",
                    "_on_raw_group_v2_message_created pull failed group=%s: %s", group_id, exc,
                )

        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(_pull_and_publish())
        self._log.debug("client", "_on_raw_group_v2_message_created exit: elapsed=%.3fs", time.time() - _t_start)

    async def _on_raw_group_changed(self, data: Any) -> None:
        """处理群组变更事件：验签 → 透传给用户 → 基于 gap 检测补齐 → epoch 轮换。

        验签策略：有 client_signature 就验，没有默认安全（兼容旧版）。
        """
        _t_start = time.time()
        if isinstance(data, dict):
            action = data.get("action", "")
            group_id = data.get("group_id", "")
            self._log.debug("client", "_on_raw_group_changed enter: group=%s action=%s event_seq=%s", group_id, action, data.get("event_seq", "-"))
            # 验签：有签名就验证操作者身份
            cs = data.get("client_signature")
            if cs and isinstance(cs, dict):
                data["_verified"] = await self._verify_event_signature(data, cs)
            # 发布给用户（publish 流程保持不变）
            await self._dispatcher.publish("group.changed", data)

            group_id = data.get("group_id", "")

            # V2 bootstrap 缓存失效：成员变更可能导致 epoch 递增或设备列表变化
            if group_id:
                bootstrap_cache = getattr(self, "_v2_bootstrap_cache", None)
                if bootstrap_cache is not None:
                    bootstrap_cache.pop(f"group:{group_id}", None)

            # V2 自动 propose_state：owner/admin 在成员变更后自动提交 state proposal
            if group_id and action in ("upsert",) and getattr(self, "_v2_session", None):
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._v2_auto_propose_state(group_id, leader_delay=True))

            # event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq
            # 用 on_message_seq 返回值决定是否补拉，与 P2P / group.message 路径对齐
            need_pull = False
            raw_event_seq = data.get("event_seq")
            if raw_event_seq is not None and group_id:
                try:
                    es = int(raw_event_seq)
                    ns = f"group_event:{group_id}"
                    need_pull = self._seq_tracker.on_message_seq(ns, es)
                except (ValueError, TypeError) as exc:
                    self._log.debug(
                        "client",
                        "group.changed event_seq parse failed: group=%s event_seq=%r err=%s",
                        group_id, raw_event_seq, exc,
                    )

            # 仅真实存在 gap 时才补拉（补洞回来的事件不再触发新补洞）
            if need_pull and group_id and not data.get("_from_gap_fill"):
                self._log.debug("client", "group.changed event gap detected, triggering gap fill: group=%s event_seq=%s", group_id, raw_event_seq)
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._fill_group_event_gap(group_id))

            self._log.debug("client", "_on_raw_group_changed exit: elapsed=%.3fs group=%s action=%s", time.time() - _t_start, group_id, action)
        else:
            await self._dispatcher.publish("group.changed", data)
            self._log.debug("client", "_on_raw_group_changed exit (non-dict): elapsed=%.3fs", time.time() - _t_start)

    async def _on_v2_epoch_rotated(self, data: Any) -> None:
        """处理 V2 epoch 轮换事件：清除 bootstrap 缓存 + 触发 SPK rotation。"""
        if not isinstance(data, dict):
            return
        group_id = str(data.get("group_id") or "").strip()
        if not group_id:
            return
        new_epoch = data.get("epoch", 0)
        self._log.debug("client", "_on_v2_epoch_rotated: group=%s epoch=%s", group_id, new_epoch)
        # 清除 bootstrap 缓存
        self._v2_bootstrap_cache.pop(f"group:{group_id}", None)
        # 触发 SPK rotation
        if self._v2_session:
            try:
                await self._v2_session.rotate_spk(self.call)
                self._log.info("client", "SPK rotated after epoch change: group=%s epoch=%s", group_id, new_epoch)
            except Exception as exc:
                self._log.debug("client", "SPK rotation after epoch change failed (non-fatal): %s", exc)

    async def _on_group_state_committed(self, data: Any) -> None:
        """处理 event/group.state_committed：验签 → 验证 state_hash 链 → 更新本地存储"""
        _t_start = time.time()
        if not isinstance(data, dict):
            return
        group_id = str(data.get("group_id") or "").strip()
        if not group_id:
            return
        self._log.debug("client", "_on_group_state_committed enter: group=%s state_version=%s", group_id, data.get("state_version", "-"))

        # 0. 验证提交者签名
        cs = data.get("client_signature")
        if cs and isinstance(cs, dict):
            verified = await self._verify_event_signature(data, cs)
            if verified is False:
                self._log.warn("client", 
                    "state_committed 提交者签名验证失败 group=%s actor=%s",
                    group_id, data.get("actor_aid"),
                )
                return
            data["_verified"] = verified

        state_version = int(data.get("state_version") or 0)
        state_hash = str(data.get("state_hash") or "").strip()
        prev_state_hash = str(data.get("prev_state_hash") or "").strip()
        key_epoch = int(data.get("key_epoch") or 0)
        membership_snapshot = str(data.get("membership_snapshot") or "").strip()
        policy_snapshot = str(data.get("policy_snapshot") or "").strip()

        # 1. 验证 prev_state_hash 连续性
        local_state = self._keystore.load_group_state(self._aid, group_id)
        if local_state and local_state["state_hash"] and local_state["state_hash"] != prev_state_hash:
            self._log.warn("client", 
                "state_hash 链不连续 group=%s local_sv=%d event_sv=%d",
                group_id, local_state["state_version"], state_version,
            )
            # 回源同步
            try:
                server_state = await self._transport.call("group.get_state", {"group_id": group_id})
                if server_state and "state_version" in server_state:
                    # 回源也做 hash 验证
                    sv = int(server_state["state_version"])
                    s_hash = str(server_state.get("state_hash", ""))
                    s_epoch = int(server_state.get("key_epoch", 0))
                    s_members_json = str(server_state.get("membership_snapshot", ""))
                    s_policy_json = str(server_state.get("policy_snapshot", ""))
                    s_prev = str(server_state.get("prev_state_hash", ""))
                    if s_members_json and s_hash:
                        import json as _json2
                        from .e2ee import compute_state_hash as _csh
                        s_members = _json2.loads(s_members_json) if s_members_json else []
                        s_policy = _json2.loads(s_policy_json) if s_policy_json else {}
                        computed = _csh(
                            group_id=group_id, state_version=sv, key_epoch=s_epoch,
                            members=s_members, policy=s_policy, prev_state_hash=s_prev,
                        )
                        if computed != s_hash:
                            self._log.warn("client", 
                                "回源 state_hash 验证失败 group=%s sv=%d expected=%s got=%s",
                                group_id, sv, s_hash, computed,
                            )
                            return
                    self._keystore.save_group_state(
                        self._aid,
                        group_id=group_id,
                        state_version=sv,
                        state_hash=s_hash,
                        key_epoch=s_epoch,
                        membership_json=s_members_json or membership_snapshot,
                        policy_json=s_policy_json or policy_snapshot,
                    )
            except Exception as exc:
                self._log.warn("client", "state origin fetch failed group=%s: %s", group_id, exc)
            return

        # 2. 本地重算验证
        import json as _json
        members = _json.loads(membership_snapshot) if membership_snapshot else []
        policy = _json.loads(policy_snapshot) if policy_snapshot else {}
        from .e2ee import compute_state_hash
        computed = compute_state_hash(
            group_id=group_id, state_version=state_version, key_epoch=key_epoch,
            members=members, policy=policy, prev_state_hash=prev_state_hash,
        )
        if computed != state_hash:
            self._log.warn("client", 
                "state_hash 重算不匹配 group=%s sv=%d expected=%s got=%s",
                group_id, state_version, state_hash, computed,
            )
            return

        # 3. 更新本地存储
        self._keystore.save_group_state(
            self._aid,
            group_id=group_id, state_version=state_version, state_hash=state_hash,
            key_epoch=key_epoch, membership_json=membership_snapshot, policy_json=policy_snapshot,
        )
        self._log.debug("client", "_on_group_state_committed exit: elapsed=%.3fs group=%s state_version=%d", time.time() - _t_start, group_id, state_version)

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
                    self._log.warn("client", "signature verification failed: cert fingerprint mismatch aid=%s", sig_aid)
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
            self._log.warn("client", "group event signature verification failed aid=%s method=%s: %s", sig_aid, method, exc)
            # P1-16: 签名失败统一发布事件
            loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
            loop.create_task(self._dispatcher.publish("signature.verification_failed", {
                "aid": sig_aid, "method": method, "error": str(exc),
            }))
            return False

    async def _fill_group_event_gap(self, group_id: str) -> None:
        """后台补齐群事件空洞。"""
        if self._state != "connected" or self._closing:
            return
        ns = f"group_event:{group_id}"
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        dedup_key = f"group_event_pull:{ns}"
        if dedup_key in self._gap_fill_done:
            return
        self._gap_fill_done[dedup_key] = time.time()
        # S1: try/finally 保证 dedup 键在所有出口清理
        try:
            self._log.info("client", "group event gap fill start: group=%s after_seq=%d", group_id, after_seq)
            result = await self.call("group.pull_events", {
                "group_id": group_id,
                "after_event_seq": after_seq,
                "device_id": self._device_id,
                "limit": 50,
            })
            if isinstance(result, dict):
                events = result.get("events", [])
                if isinstance(events, list):
                    self._log.info("client", "group event gap fill done: group=%s after_seq=%d pulled=%d", group_id, after_seq, len(events))
                    contig_before = self._seq_tracker.get_contiguous_seq(ns)
                    self._seq_tracker.on_pull_result(ns, events, after_seq=after_seq)
                    cursor = result.get("cursor")
                    server_ack = int(cursor.get("current_seq") or 0) if isinstance(cursor, dict) else 0
                    if server_ack > 0:
                        contig_before = self._seq_tracker.get_contiguous_seq(ns)
                        if contig_before < server_ack:
                            self._log.info("client", 
                                "group.pull_events retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                                ns, contig_before, server_ack,
                            )
                            self._seq_tracker.force_contiguous_seq(ns, server_ack)
                    # auto-ack contiguous_seq
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig != contig_before:
                        self._persist_seq(ns)
                    if contig > 0 and contig != contig_before:
                        try:
                            await self._transport.call("group.ack_events", {
                                "group_id": group_id, "event_seq": contig,
                                "device_id": self._device_id,
                                "slot_id": self._slot_id,
                            })
                        except Exception as _ack_exc:
                            self._log.debug("client", "group event auto-ack failed: group=%s %s", group_id, _ack_exc)
                    for evt in events:
                        if isinstance(evt, dict):
                            evt["_from_gap_fill"] = True
                            et = evt.get("event_type", "")
                            # 消息事件由群消息 pull 负责，事件补洞不重复投递
                            if et == "group.message_created":
                                continue
                            # 验签：有 client_signature 就验（与实时事件路径对齐）
                            cs = evt.get("client_signature")
                            if cs and isinstance(cs, dict):
                                evt["_verified"] = await self._verify_event_signature(evt, cs)
                            # group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
                            await self._dispatcher.publish("group.changed", evt)
        except Exception as exc:
            self._log.warn("client", "group event gap fill failed: group=%s after_seq=%d error=%s", group_id, after_seq, exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)

    async def _fill_p2p_gap(self) -> None:
        """后台补齐 P2P 消息空洞。"""
        if self._state != "connected" or self._closing:
            return
        if not self._aid:
            return
        ns = f"p2p:{self._aid}"
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        dedup_key = f"p2p_pull:{ns}"
        if dedup_key in self._gap_fill_done:
            return
        self._gap_fill_done[dedup_key] = time.time()
        # S1: try/finally 保证 dedup 键在所有出口清理
        try:
            self._log.info("client", "P2P message gap fill start: after_seq=%d device_id=%s", after_seq, self._device_id)
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
                    self._log.info("client", "P2P message gap fill done: after_seq=%d pulled=%d decrypt_ok=%d decrypt_fail=%d seq_range=%s",
                                    after_seq, len(messages), ok_count, fail_count,
                                    f"{min(seq_list)}~{max(seq_list)}" if seq_list else "empty")
                    ns_key = f"p2p:{self._aid}"
                    pushed = self._pushed_seqs.get(ns_key)
                    # seq_tracker 在 call() 中自动处理；ack 由 push 路径负责
                    for msg in messages:
                        if isinstance(msg, dict):
                            s = msg.get("seq")
                            if pushed and s is not None and int(s) in pushed:
                                continue  # 已发布到应用层，跳过重复投递
                            if s is not None:
                                await self._publish_pulled_message("message.received", ns_key, s, msg)
                            else:
                                await self._publish_app_event("message.received", msg)
                            # 每条消息处理后让出事件循环，避免大量历史消息解密阻塞 ws 握手等 IO
                            await asyncio.sleep(0)
                    # 维护 republish guard 上限
                    self._prune_pushed_seqs(ns_key)
                    # publish 完成后 auto-ack
                    contig_before = int(result.get("_contig_before", 0) or 0)
                    contig = self._seq_tracker.get_contiguous_seq(ns_key)
                    if contig > 0 and contig != contig_before:
                        try:
                            await self._transport.call("message.ack", {
                                "seq": contig, "device_id": self._device_id, "slot_id": self._slot_id,
                            })
                        except Exception as _ack_exc:
                            self._log.debug("client", "P2P gap fill auto-ack failed: %s", _ack_exc)
        except Exception as exc:
            self._log.warn("client", "P2P message gap fill failed: after_seq=%d error=%s", after_seq, exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)

    def _mark_published_seq(self, ns: str, seq: int) -> None:
        """记录已发布到应用层的 seq，供 push/pull/补洞路径统一去重。"""
        self._pushed_seqs.setdefault(ns, set()).add(seq)
        self._enforce_pushed_seqs_limit(ns)

    def _is_published_seq(self, ns: str, seq: int) -> bool:
        """republish guard：同一 namespace + seq 在应用层只发布一次。"""
        return seq in self._pushed_seqs.get(ns, set())

    def _is_pending_ordered_seq(self, ns: str, seq: int) -> bool:
        """同一 namespace + seq 已解密并等待有序发布。"""
        return seq in self._pending_ordered().get(ns, {})

    def _pending_ordered(self) -> dict[str, dict[int, tuple[str, Any]]]:
        pending = getattr(self, "_pending_ordered_msgs", None)
        if pending is None:
            pending = {}
            self._pending_ordered_msgs = pending
        return pending

    def _enqueue_ordered_message(self, ns: str, event: str, seq: int, payload: Any) -> None:
        pending = self._pending_ordered()
        queue = pending.setdefault(ns, {})
        queue[seq] = (event, payload)
        if len(queue) > _PENDING_ORDERED_LIMIT:
            for old_seq in sorted(queue)[: len(queue) - _PENDING_ORDERED_LIMIT]:
                queue.pop(old_seq, None)

    @staticmethod
    def _is_instance_scoped_message_event(event: str) -> bool:
        return event in {
            "message.received",
            "message.undecryptable",
            "group.message_created",
            "group.message_undecryptable",
        }

    def _attach_current_instance_context(self, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        result = dict(payload)
        if self._device_id and not str(result.get("device_id") or "").strip():
            result["device_id"] = self._device_id
        if self._slot_id and not str(result.get("slot_id") or "").strip():
            result["slot_id"] = self._slot_id
        return result

    def _normalize_published_message_payload(self, event: str, payload: Any) -> Any:
        if not self._is_instance_scoped_message_event(event):
            return payload
        return self._attach_current_instance_context(payload)

    async def _publish_app_event(self, event: str, payload: Any) -> None:
        if event in ("message.received", "group.message_created") and isinstance(payload, dict):
            self._maybe_append_echo_trace_receive(payload)
        # 注入本地/远端 agent.md etag，让应用层判断版本一致性；失败不影响业务。
        if isinstance(payload, dict):
            try:
                local_etag = self._local_agent_md_etag or ""
                remote_etag = self._remote_agent_md_etag or ""
                if local_etag or remote_etag:
                    payload.setdefault("_agent_md", {
                        "local_etag": local_etag,
                        "remote_etag": remote_etag,
                    })
            except Exception as exc:
                self._log.debug("client", "agent_md etag inject skipped: %s", exc)
        await self._dispatcher.publish(
            event,
            self._normalize_published_message_payload(event, payload),
        )

    def _message_targets_current_instance(self, message: Any) -> bool:
        if not isinstance(message, dict):
            return True
        target_device_id = str(message.get("device_id") or "").strip()
        if target_device_id and self._device_id and target_device_id != self._device_id:
            return False
        target_slot_id = str(message.get("slot_id") or "").strip()
        if target_slot_id and self._slot_id and target_slot_id != self._slot_id:
            return False
        return True

    async def _drain_ordered_messages(self, ns: str, *, before_seq: int | None = None) -> None:
        """把已经落在 contiguous_seq 内的挂起消息按 seq 升序放行。"""
        pending = self._pending_ordered().get(ns)
        if not pending:
            return
        contig = self._seq_tracker.get_contiguous_seq(ns)
        ready = sorted(
            seq for seq in pending
            if seq <= contig and (before_seq is None or seq < before_seq)
        )
        for seq in ready:
            event, payload = pending.pop(seq)
            if self._is_published_seq(ns, seq):
                continue
            await self._publish_app_event(event, payload)
            self._mark_published_seq(ns, seq)
        if not pending:
            self._pending_ordered().pop(ns, None)

    async def _publish_ordered_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        """按 contiguous_seq 对应用层事件做有序放行。

        返回 True 表示本次调用实际发布了 payload；False 表示已挂起或已去重。
        """
        try:
            seq_i = int(seq)
        except (TypeError, ValueError):
            await self._publish_app_event(event, payload)
            return True
        if seq_i <= 0:
            await self._publish_app_event(event, payload)
            return True
        if self._is_published_seq(ns, seq_i):
            # 如果同 seq 也曾挂起，顺手清理，避免后续 drain 重复处理。
            self._log.debug(
                "client",
                "DIAG publish_ordered already published: ns=%s seq=%d (republish guard hit)",
                ns, seq_i,
            )
            pending = self._pending_ordered().get(ns)
            if pending:
                pending.pop(seq_i, None)
                if not pending:
                    self._pending_ordered().pop(ns, None)
            return False

        contig = self._seq_tracker.get_contiguous_seq(ns)
        if seq_i > contig:
            self._log.debug(
                "client",
                "DIAG publish_ordered enqueue (gap): ns=%s seq=%d contig=%d",
                ns, seq_i, contig,
            )
            self._enqueue_ordered_message(ns, event, seq_i, payload)
            return False

        await self._drain_ordered_messages(ns, before_seq=seq_i)
        if self._is_published_seq(ns, seq_i):
            return False
        pending = self._pending_ordered().get(ns)
        if pending:
            pending.pop(seq_i, None)
            if not pending:
                self._pending_ordered().pop(ns, None)
        await self._publish_app_event(event, payload)
        self._mark_published_seq(ns, seq_i)
        await self._drain_ordered_messages(ns)
        return True

    async def _publish_pulled_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        """发布 pull 批中的消息，只按 namespace+seq 去重，不受批内部空洞阻塞。"""
        try:
            seq_i = int(seq)
        except (TypeError, ValueError):
            await self._publish_app_event(event, payload)
            return True
        if seq_i <= 0 or not ns:
            await self._publish_app_event(event, payload)
            return True
        if self._is_published_seq(ns, seq_i):
            pending = self._pending_ordered().get(ns)
            if pending:
                pending.pop(seq_i, None)
                if not pending:
                    self._pending_ordered().pop(ns, None)
            return False
        pending = self._pending_ordered().get(ns)
        if pending:
            pending.pop(seq_i, None)
            if not pending:
                self._pending_ordered().pop(ns, None)
        await self._publish_app_event(event, payload)
        self._mark_published_seq(ns, seq_i)
        return True

    def _prune_pushed_seqs(self, ns: str) -> None:
        """维护已发布 seq 集合的内存上限。

        这里不能按 contiguous_seq 清理。pull/补洞可能在 contiguous_seq 已推进后再次拿到
        已发布消息，去重状态必须保留到硬上限裁剪，否则会重复 publish。
        """
        pushed = self._pushed_seqs.get(ns)
        if not pushed:
            return
        self._enforce_pushed_seqs_limit(ns)

    def _enforce_pushed_seqs_limit(self, ns: str) -> None:
        """PY-006: pushed_seqs 超过硬上限时清理最旧条目。"""
        pushed = self._pushed_seqs.get(ns)
        if not pushed or len(pushed) <= _PUSHED_SEQS_LIMIT:
            return
        # 保留最大（最新）的 _PUSHED_SEQS_LIMIT 个条目
        sorted_seqs = sorted(pushed)
        keep = set(sorted_seqs[-_PUSHED_SEQS_LIMIT:])
        self._pushed_seqs[ns] = keep

    def _attach_group_dispatch_mode_to_payload(message: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(message, dict):
            return message
        mode = str(message.get("dispatch_mode") or "broadcast").strip().lower()
        if mode not in {"broadcast", "mention"}:
            mode = "broadcast"
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return message
        result = dict(message)
        payload_view = dict(payload)
        payload_view["dispatch_mode"] = mode
        result["payload"] = payload_view
        result["dispatch_mode"] = mode
        return result

    @staticmethod
    def _cert_cache_key(aid: str, cert_fingerprint: str | None = None) -> str:
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        return aid if not normalized_fp else f"{aid}#{normalized_fp}"

    async def _fetch_peer_cert(self, aid: str, cert_fingerprint: str | None = None) -> bytes:
        """获取对方证书（带缓存 + 完整 PKI 验证：链 + CRL + OCSP + AID 绑定）

        跨域时自动将请求路由到 peer 所在域的 Gateway（URL 替换），
        同时 Gateway 侧也有代理 fallback。
        """
        _t_start = time.time()
        cache_key = self._cert_cache_key(aid, cert_fingerprint)
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        self._log.debug("client", "_fetch_peer_cert enter: peer=%s fp=%s", aid, normalized_fp or "-")
        _debug_group_e2ee(
            "peer_cert_fetch_enter",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            cache_key=cache_key,
        )
        cached = self._cert_cache.get(cache_key)
        if cached and time.time() < cached.refresh_after:
            _debug_group_e2ee(
                "peer_cert_fetch_cache_hit",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=cache_key,
            )
            self._log.debug("client", "_fetch_peer_cert exit (cache-hit): elapsed=%.3fs peer=%s", time.time() - _t_start, aid)
            return cached.cert_bytes
        if cached:
            _debug_group_e2ee(
                "peer_cert_fetch_cache_refresh_needed",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=cache_key,
            )
        gateway_url = self._gateway_url
        if not gateway_url:
            _debug_group_e2ee(
                "peer_cert_fetch_no_gateway",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
            )
            raise ValidationError("gateway url unavailable for e2ee cert fetch")

        # 跨域时用 peer 所在域的 Gateway URL
        peer_gateway_url = self._resolve_peer_gateway_url(gateway_url, aid)
        cert_url = self._build_cert_url(peer_gateway_url, aid, cert_fingerprint)
        _debug_group_e2ee(
            "peer_cert_fetch_http",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            url=cert_url,
        )
        ssl_param = None if self._config_model.verify_ssl else False
        # PY-017: 显式设置 HTTP 超时，避免 aiohttp 默认 300s 阻塞
        http_timeout = aiohttp.ClientTimeout(total=10.0)
        async with aiohttp.ClientSession(timeout=http_timeout) as session:
            async with session.get(cert_url, ssl=ssl_param) as response:
                response.raise_for_status()
                cert_pem = await response.text()
                _debug_group_e2ee(
                    "peer_cert_fetch_http_result",
                    aid=self._aid or "-",
                    peer=aid,
                    fp=normalized_fp or "-",
                    status=response.status,
                    bytes=len(cert_pem),
                )
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
            _debug_group_e2ee(
                "peer_cert_fetch_verify_failed",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                error=type(exc).__name__,
            )
            raise ValidationError(f"peer cert verification failed for {aid}: {exc}")

        now = time.time()
        self._cert_cache[cache_key] = _CachedPeerCert(
            cert_bytes=cert_bytes,
            validated_at=now,
            refresh_after=now + _PEER_CERT_CACHE_TTL,
        )
        _debug_group_e2ee(
            "peer_cert_fetch_cached",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            cache_key=cache_key,
        )
        # peer 证书只存到版本目录，不覆盖 cert.pem（防止破坏自身身份证书）
        try:
            self._keystore.save_cert(
                aid,
                cert_pem,
                cert_fingerprint=cert_fingerprint,
                make_active=False,
            )
            _debug_group_e2ee(
                "peer_cert_fetch_saved",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
            )
        except TypeError:
            # 兼容旧 keystore 实现
            _debug_group_e2ee(
                "peer_cert_fetch_save_skipped_legacy",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
            )
            pass
        except Exception as exc:
            _debug_group_e2ee(
                "peer_cert_fetch_save_failed",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                error=type(exc).__name__,
            )
            self._log.error("client", "failed to write peer cert to keystore (aid=%s, fp=%s): %s", aid, cert_fingerprint or "", exc)
        self._log.debug("client", "_fetch_peer_cert exit: elapsed=%.3fs peer=%s fp=%s", time.time() - _t_start, aid, normalized_fp or "-")
        return cert_bytes

    @staticmethod
    def _list_contains_token(value: Any, token: str) -> bool:
        if not isinstance(value, list):
            return False
        return token in value

    def _client_uses_v2_p2p(self) -> bool:
        """当前连接是否被服务端按 V2 P2P 客户端处理（与 gateway _client_p2p_version 对齐）。

        gateway 口径：capabilities.supported_p2p_e2ee 含 'e2ee_v2' 即 V2，否则 V1。
        capabilities 缺失时按 SDK 默认值（含 e2ee_v2）→ V2。
        """
        caps = getattr(self, "_connect_capabilities", None)
        if not isinstance(caps, dict):
            return True
        return self._list_contains_token(caps.get("supported_p2p_e2ee"), "e2ee_v2")

    def _client_uses_v2_group(self) -> bool:
        """当前连接是否被服务端按 V2 Group 客户端处理（与 gateway _client_group_version 对齐）。"""
        caps = getattr(self, "_connect_capabilities", None)
        if not isinstance(caps, dict):
            return True
        return self._list_contains_token(caps.get("supported_group_e2ee"), "group_e2ee_v2")

    # 兼容别名：旧调用点仍可用
    async def _ensure_sender_cert_cached(self, aid: str, cert_fingerprint: str | None = None) -> bool:
        """确保发送方证书在本地 keystore 中可用且未过期。

        安全要点：不能永久信任旧证书，必须按 TTL 刷新并重新做 PKI 验证
        （链 + CRL + OCSP + AID 绑定），以使证书吊销和轮换及时生效。

        返回 True 表示证书已就绪（PKI 验证通过），False 表示不可用。
        """
        # 内存缓存未过期 → 跳过（_fetch_peer_cert 已做完整 PKI 验证）
        cache_key = self._cert_cache_key(aid, cert_fingerprint)
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        _debug_group_e2ee(
            "ensure_sender_cert_enter",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            cache_key=cache_key,
        )
        cached = self._cert_cache.get(cache_key)
        if cached and time.time() < cached.refresh_after:
            _debug_group_e2ee(
                "ensure_sender_cert_cache_hit",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=cache_key,
            )
            return True
        if cached:
            _debug_group_e2ee(
                "ensure_sender_cert_cache_stale",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=cache_key,
            )
        try:
            local_cert = self._keystore.load_cert(aid, cert_fingerprint)
        except TypeError:
            local_cert = self._keystore.load_cert(aid)
        except Exception as _lc_exc:
            _debug_group_e2ee(
                "ensure_sender_cert_keystore_error",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                error=type(_lc_exc).__name__,
            )
            self._log.debug("client", "failed to load peer cert (%s): %s", aid, _lc_exc)
            local_cert = None
        if local_cert:
            _debug_group_e2ee(
                "ensure_sender_cert_keystore_hit",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
            )
            # keystore 中有证书，但不直接信任 — 仍需通过 _fetch_peer_cert 做 PKI 验证
            # 仅在网络不可用时作为降级（见下方 except 分支）
            pass
        else:
            _debug_group_e2ee(
                "ensure_sender_cert_keystore_miss",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
            )
        try:
            # _fetch_peer_cert 内部：下载 → 完整 PKI 验证 → 更新内存缓存
            cert_bytes = await self._fetch_peer_cert(aid, cert_fingerprint)
            # _fetch_peer_cert 内部已保存到版本目录，此处无需重复保存
            _debug_group_e2ee(
                "ensure_sender_cert_fetch_ok",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                bytes=len(cert_bytes or b""),
            )
            return True
        except Exception as exc:
            # 刷新失败时：若内存缓存有 PKI 验证过的证书（未过期 × 2 倍 TTL）则继续用
            if cached and time.time() < cached.validated_at + _PEER_CERT_CACHE_TTL * 2:
                _debug_group_e2ee(
                    "ensure_sender_cert_fetch_failed_use_grace",
                    aid=self._aid or "-",
                    peer=aid,
                    fp=normalized_fp or "-",
                    error=type(exc).__name__,
                )
                self._log.debug("client", "refresh sender %s cert failed, continuing with verified memory cache: %s", aid, exc)
                return True
            # 超出宽限期或从未验证过 → 不可信
            _debug_group_e2ee(
                "ensure_sender_cert_fetch_failed_no_cache",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                error=type(exc).__name__,
            )
            self._log.warn("client", 
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
        now = time.time()
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        cache_key = self._cert_cache_key(aid, cert_fingerprint)
        _debug_group_e2ee(
            "verified_peer_cert_enter",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            cache_key=cache_key,
            cache_size=len(self._cert_cache),
        )
        cached = self._cert_cache.get(cache_key)
        if cached and now < cached.validated_at + _PEER_CERT_CACHE_TTL * 2:
            _debug_group_e2ee(
                "verified_peer_cert_hit_exact",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=cache_key,
            )
            return cached.cert_bytes.decode("utf-8") if isinstance(cached.cert_bytes, bytes) else cached.cert_bytes
        if cached:
            _debug_group_e2ee(
                "verified_peer_cert_expired_exact",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=cache_key,
            )
        # 带 fingerprint 查不到时，降级用 aid 再查一次。
        if cert_fingerprint:
            bare_key = self._cert_cache_key(aid, None)
            bare_cached = self._cert_cache.get(bare_key)
            if bare_cached and now < bare_cached.validated_at + _PEER_CERT_CACHE_TTL * 2:
                _debug_group_e2ee(
                    "verified_peer_cert_hit_bare",
                    aid=self._aid or "-",
                    peer=aid,
                    fp=normalized_fp or "-",
                    cache_key=bare_key,
                )
                return bare_cached.cert_bytes.decode("utf-8") if isinstance(bare_cached.cert_bytes, bytes) else bare_cached.cert_bytes
            if bare_cached:
                _debug_group_e2ee(
                    "verified_peer_cert_expired_bare",
                    aid=self._aid or "-",
                    peer=aid,
                    fp=normalized_fp or "-",
                    cache_key=bare_key,
                )
        # 恢复/验签路径通常只知道 responder_aid，证书却可能按 aid#fingerprint 缓存。
        # 只从已通过 PKI 验证的内存缓存中选取仍在宽限期内的最新版本。
        prefix = f"{aid}#"
        versioned: tuple[str, _CachedPeerCert] | None = None
        expired_versioned = 0
        for key, entry in self._cert_cache.items():
            if not key.startswith(prefix):
                continue
            if now < entry.validated_at + _PEER_CERT_CACHE_TTL * 2:
                if versioned is None or entry.validated_at > versioned[1].validated_at:
                    versioned = (key, entry)
            else:
                expired_versioned += 1
        if versioned is not None:
            key, entry = versioned
            _debug_group_e2ee(
                "verified_peer_cert_hit_versioned",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=key,
            )
            return entry.cert_bytes.decode("utf-8") if isinstance(entry.cert_bytes, bytes) else entry.cert_bytes
        if expired_versioned:
            _debug_group_e2ee(
                "verified_peer_cert_expired_versioned",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                count=expired_versioned,
            )
        _debug_group_e2ee(
            "verified_peer_cert_miss",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
        )
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
        _t_start = time.time()
        gateway_url = self._resolve_gateway(params)
        self._gateway_url = gateway_url
        self._loop = asyncio.get_running_loop()
        self._slot_id = str(params.get("slot_id") or "")
        self._connect_delivery_mode = dict(params.get("delivery_mode") or self._connect_delivery_mode)
        connection_kind = str(params.get("connection_kind") or "long")
        short_ttl_ms = int(params.get("short_ttl_ms") or 0)
        extra_info = params.get("extra_info") if isinstance(params.get("extra_info"), dict) else None
        # 记录 connect 时声明的 capabilities，供后续按 V1/V2 路由 RPC 调用
        if extra_info and isinstance(extra_info.get("_capabilities"), dict):
            self._connect_capabilities = dict(extra_info["_capabilities"])
        else:
            # 默认能力（与 auth.py initialize_with_token 中的默认值保持一致）
            self._connect_capabilities = {
                "e2ee": True,
                "group_e2ee": True,
                "supported_p2p_e2ee": ["e2ee", "e2ee_v2"],
                "supported_group_e2ee": ["group_e2ee", "group_e2ee_v2"],
            }
        self._auth.set_instance_context(device_id=self._device_id, slot_id=self._slot_id)
        self._state = "connecting"
        self._log.debug("client", "_connect_once enter: gateway=%s allow_reauth=%s kind=%s",
                        gateway_url, allow_reauth, connection_kind)

        try:
            # ── 前置 restore：在 transport.connect 启动 reader 之前完成
            # 避免 reader 把积压 push 交给空 tracker 的 handler，触发 S2 历史 gap 误补拉
            self._refresh_seq_tracking_context()
            self._restore_seq_tracker_state()

            self._log.debug("client", "transport.connect start: gateway=%s allow_reauth=%s", gateway_url, allow_reauth)
            challenge = await self._transport.connect(gateway_url)
            self._state = "authenticating"
            self._log.debug("client", "auth phase start: mode=%s", "reauth" if allow_reauth else "token")
            if allow_reauth:
                auth_context = await self._auth.connect_session(
                    self._transport,
                    challenge,
                    gateway_url,
                    access_token=params.get("access_token"),
                    device_id=self._device_id,
                    slot_id=self._slot_id,
                    delivery_mode=self._connect_delivery_mode,
                    connection_kind=connection_kind,
                    short_ttl_ms=short_ttl_ms,
                    extra_info=extra_info,
                )
                identity = auth_context.get("identity") if isinstance(auth_context, dict) else None
                if isinstance(identity, dict):
                    self._identity = identity
                    self._aid = identity.get("aid", self._aid)
                    if self._session_params is not None:
                        self._session_params["access_token"] = auth_context.get("token", params.get("access_token"))
                hello = auth_context.get("hello") if isinstance(auth_context, dict) else None
                if isinstance(hello, dict) and "heartbeat_interval" in hello:
                    self._apply_server_heartbeat_interval(hello.get("heartbeat_interval"), source="auth")
            else:
                hello = await self._auth.initialize_with_token(
                    self._transport,
                    challenge,
                    str(params["access_token"]),
                    device_id=self._device_id,
                    slot_id=self._slot_id,
                    delivery_mode=self._connect_delivery_mode,
                    connection_kind=connection_kind,
                    short_ttl_ms=short_ttl_ms,
                    extra_info=extra_info,
                )
                self._sync_identity_after_connect(str(params["access_token"]))
                if isinstance(hello, dict) and "heartbeat_interval" in hello:
                    self._apply_server_heartbeat_interval(hello.get("heartbeat_interval"), source="auth")
            self._state = "connected"
            self._connected_at = time.time()
            self._log.debug("client", "auth complete, state changed to connected: gateway=%s aid=%s", gateway_url, self._aid or "-")
            await self._dispatcher.publish("connection.state", {"state": self._state, "gateway": gateway_url})

            # auth 阶段 aid 可能被 identity 覆盖（上方 self._aid = identity.get(...)）；
            # 若 context 发生变化，重新 refresh + restore，保持 tracker 与真实身份一致
            if self._seq_tracker_context != self._current_seq_tracker_context():
                self._refresh_seq_tracking_context()
                self._restore_seq_tracker_state()

            self._start_background_tasks()

            # connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压
            # 群消息按惰性触发，不在此处主动 pull
            try:
                loop = self._loop or asyncio.get_running_loop()
                loop.create_task(self._fill_p2p_gap())
            except Exception as exc:
                self._log.warn("client", "schedule post-connect P2P gap fill failed: %s", exc)

            # V2 E2EE: 初始化 session 并注册设备密钥
            try:
                await self._init_v2_session()
            except Exception as exc:
                self._log.warn("client", "V2 session init failed (non-fatal): %s", exc)

            # V2: Owner 上线时自动确认 pending state proposals
            # （兼容测试用 __new__ 绕过 __init__ 直接调 _connect_once 的场景）
            if getattr(self, "_v2_session", None):
                loop = self._loop or asyncio.get_running_loop()
                loop.create_task(self._v2_auto_confirm_pending_proposals())
            self._log.debug("client", "_connect_once exit: elapsed=%.3fs gateway=%s aid=%s", time.time() - _t_start, gateway_url, self._aid or "-")
        except Exception as exc:
            self._log.debug("client", "_connect_once exit (error): elapsed=%.3fs gateway=%s err=%s", time.time() - _t_start, gateway_url, exc)
            raise

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
        # 短连接生命周期短，禁用心跳与 token 刷新（不接收推送、不需要长期会话维护）
        if self._session_options.get("connection_kind") != "short":
            self._start_heartbeat_task()
            self._start_token_refresh_task()

    async def _stop_background_tasks(self) -> None:
        current_task = asyncio.current_task()
        for attr in ("_heartbeat_task", "_token_refresh_task",
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
                pass
            setattr(self, attr, None)

    def _start_heartbeat_task(self) -> None:
        if self._heartbeat_task is not None and not self._heartbeat_task.done():
            return
        # interval=0 时不启动 task（避免空转）；服务端下发非零值时会通过
        # _apply_server_heartbeat_interval 触发启动。
        interval = _clamp_heartbeat_interval(self._session_options.get("heartbeat_interval"))
        if interval <= 0:
            return
        if self._heartbeat_nudge is None:
            self._heartbeat_nudge = asyncio.Event()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def _start_token_refresh_task(self) -> None:
        if self._token_refresh_task is not None and not self._token_refresh_task.done():
            return
        self._token_refresh_task = asyncio.create_task(self._token_refresh_loop())

    async def _heartbeat_loop(self) -> None:
        consecutive_failures = 0
        max_failures = 3  # 连续失败 3 次触发重连
        try:
            while not self._closing:
                interval = _clamp_heartbeat_interval(self._session_options.get("heartbeat_interval"))
                if interval <= 0:
                    # 心跳被服务端动态关闭：退出循环，task 终止；后续若再下发非零值会重新 start
                    return
                self._heartbeat_nudge.clear()
                try:
                    # 用 nudge.wait 实现"可中断 sleep"：interval 改变可立即生效
                    await asyncio.wait_for(self._heartbeat_nudge.wait(), timeout=interval)
                    # nudge 触发：重读 interval，不发心跳
                    continue
                except asyncio.TimeoutError:
                    pass  # 正常到点，发心跳
                if self._state != "connected":
                    consecutive_failures = 0
                    continue
                try:
                    pong = await self._transport.call("meta.ping", {})
                    consecutive_failures = 0
                    # 服务端可在 pong 中下发新的 heartbeat_interval
                    if isinstance(pong, dict) and "heartbeat_interval" in pong:
                        self._apply_server_heartbeat_interval(pong.get("heartbeat_interval"), source="pong")
                except Exception as exc:
                    consecutive_failures += 1
                    self._log.warn("client", "heartbeat failed (%d/%d): %s", consecutive_failures, max_failures, exc)
                    await self._dispatcher.publish("connection.error", {"error": exc})
                    if consecutive_failures >= max_failures:
                        self._log.warn("client", "%d consecutive heartbeat failures, triggering reconnect", max_failures)
                        await self._handle_transport_disconnect(exc)
                        return
        except asyncio.CancelledError:
            raise

    def _apply_server_heartbeat_interval(self, raw: Any, *, source: str) -> None:
        """读取服务端下发的 heartbeat_interval 并写入 session_options，唤醒/启动/停止心跳循环。"""
        new_interval = _clamp_heartbeat_interval(raw)
        old_interval = _clamp_heartbeat_interval(self._session_options.get("heartbeat_interval"))
        if new_interval == old_interval:
            return
        self._session_options["heartbeat_interval"] = new_interval
        self._log.debug("client", "heartbeat_interval updated by %s: %s -> %s", source, old_interval, new_interval)
        # 唤醒已在跑的循环（让它重读 interval；若新值=0 会自然退出）
        if self._heartbeat_nudge is not None:
            self._heartbeat_nudge.set()
        # 之前 interval=0 没起任务，新值为正时需要启动
        if new_interval > 0 and (self._heartbeat_task is None or self._heartbeat_task.done()):
            self._start_heartbeat_task()

    async def _token_refresh_loop(self) -> None:
        lead = float(self._session_options.get("token_refresh_before", _TOKEN_REFRESH_DEFAULT_LEAD))
        if not math.isfinite(lead) or lead <= 0:
            lead = _TOKEN_REFRESH_DEFAULT_LEAD
        try:
            while not self._closing:
                if self._state != "connected" or not self._gateway_url:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                identity = self._identity or self._auth.load_identity_or_none()
                if identity is None:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                self._identity = identity
                expires_at = self._auth.get_access_token_expiry(identity)
                if expires_at is None:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                if expires_at - time.time() > lead:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
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
                        self._log.warn("client", 
                            "token 刷新连续失败 %d 次，停止刷新循环并触发重连",
                            self._token_refresh_failures,
                        )
                        await self._dispatcher.publish("token.refresh_exhausted", {
                            "aid": self._identity.get("aid") if self._identity else None,
                            "consecutive_failures": self._token_refresh_failures,
                            "last_error": str(exc),
                        })
                        self._token_refresh_failures = 0
                        # 主动触发断线重连，让 connect_session 的 fallback 链
                        # （cached_token → refresh_token → 完整两阶段登录）接管
                        await self._handle_transport_disconnect(
                            ConnectionError("token refresh exhausted, triggering reconnect")
                        )
                        return
                    else:
                        self._log.debug("client", 
                            "token 刷新失败 (%d/%d)，下次检查后重试: %s",
                            self._token_refresh_failures,
                            _TOKEN_REFRESH_MAX_FAILURES,
                            exc,
                        )
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                except Exception as exc:
                    await self._dispatcher.publish("connection.error", {"error": exc})
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
        except asyncio.CancelledError:
            raise

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

    def _maybe_append_echo_trace_send(self, params: dict[str, Any]) -> None:
        """明文 echo 消息发送时追加 SDK.send trace"""
        payload = params.get("payload")
        if not isinstance(payload, dict):
            self._log.info("client", "DEBUG echo_trace_send skip: payload not dict, type=%s", type(payload).__name__)
            return
        text = payload.get("text")
        if not isinstance(text, str) or len(text) > 4096:
            self._log.info("client", "DEBUG echo_trace_send skip: text invalid, type=%s len=%s", type(text).__name__, len(text) if isinstance(text, str) else "?")
            return
        first_line = text.split("\n", 1)[0].lower()
        if "echo" not in first_line:
            self._log.info("client", "DEBUG echo_trace_send skip: no 'echo' in first line=%r", first_line[:80])
            return
        import datetime
        now = datetime.datetime.now()
        ts = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"
        uptime = int(time.time() - getattr(self, "_connected_at", time.time()))
        trace = f"{ts} [AUN-SDK.send] aid={self._aid or '-'} conn_uptime={uptime}s"
        params["payload"] = {**payload, "text": text + "\n" + trace}
        self._log.info("client", "DEBUG echo_trace_send appended: %s", trace)

    def _maybe_append_echo_trace_receive(self, msg: dict[str, Any]) -> None:
        """明文 echo 消息接收时追加 SDK.receive trace"""
        if msg.get("encrypted"):
            return
        payload = msg.get("payload")
        if not isinstance(payload, dict):
            return
        text = payload.get("text")
        if not isinstance(text, str) or len(text) > 4096:
            return
        if "echo" not in text.split("\n", 1)[0].lower():
            return
        import datetime
        now = datetime.datetime.now()
        ts = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"
        uptime = int(time.time() - getattr(self, "_connected_at", time.time()))
        trace = f"{ts} [AUN-SDK.receive] aid={self._aid or '-'} conn_uptime={uptime}s"
        msg["payload"] = {**payload, "text": text + "\n" + trace}

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
        if method in {"group.thought.put", "group.thought.get", "message.thought.put", "message.thought.get"}:
            context = params.get("context")
            has_context = (
                isinstance(context, dict)
                and bool(str(context.get("type") or "").strip())
                and bool(str(context.get("id") or "").strip())
            )
            if not has_context:
                raise ValidationError(f"{method} requires context.type + context.id")
        if method == "group.thought.get" and not str(params.get("sender_aid") or "").strip():
            raise ValidationError("group.thought.get requires sender_aid")
        if method == "message.thought.put":
            self._validate_message_recipient(params.get("to"))
            if not str(params.get("to") or "").strip():
                raise ValidationError("message.thought.put requires to")
        if method == "message.thought.get":
            if not str(params.get("sender_aid") or "").strip():
                raise ValidationError("message.thought.get requires sender_aid")

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

    def _restore_seq_tracker_state(self) -> None:
        """从 keystore seq_tracker 表按行恢复 SeqTracker 状态。

        启动时顺带做一次 group_id 归一化迁移：把 ns 前缀为 group_event: / group_msg:
        的老/污染 group_id 重写为新 canonical；如与新 ns 冲突，取 max 合并。
        """
        if not self._aid:
            return
        try:
            loader = getattr(self._keystore, "load_all_seqs", None)
            if callable(loader):
                state = loader(self._aid, self._device_id, self._slot_id)
                if state:
                    state = self._migrate_seq_state_group_ids(state)
                    self._seq_tracker.restore_state(state)
                    self._log.info("client", "SeqTracker restored: %d namespaces", len(state))
                else:
                    self._log.info("client", "SeqTracker no persisted state, starting from zero")
            else:
                # 旧版 fallback：从 instance_state 的 seq_tracker_state 字段读
                inst_loader = getattr(self._keystore, "load_instance_state", None)
                if callable(inst_loader):
                    instance_state = inst_loader(self._aid, self._device_id, self._slot_id)
                    if isinstance(instance_state, dict):
                        state = instance_state.get("seq_tracker_state")
                        if isinstance(state, dict):
                            state = self._migrate_seq_state_group_ids(state)
                            self._seq_tracker.restore_state(state)
                            self._log.info("client", "SeqTracker restored from legacy instance_state: %d namespaces", len(state))
        except Exception as exc:
            self._log.warn("client", "failed to restore SeqTracker state: %s", exc)

    def _migrate_seq_state_group_ids(self, state: dict[str, int]) -> dict[str, int]:
        """把 seq_tracker state 里老/污染 group_id 归一化。冲突取 max。

        同时把迁移后的结果落盘（删除老 ns 行，覆盖写入新 ns 行），避免下次启动重复迁移。
        """
        if not isinstance(state, dict) or not state:
            return state
        rename_map: dict[str, str] = {}  # old_ns → new_ns
        for ns in list(state.keys()):
            if not isinstance(ns, str):
                continue
            for prefix in ("group_event:", "group_msg:"):
                if ns.startswith(prefix):
                    old_gid = ns[len(prefix):]
                    # 迁移不对无域输入强行补域，避免误伤
                    new_gid = _normalize_group_id(old_gid)
                    if new_gid and new_gid != old_gid:
                        rename_map[ns] = f"{prefix}{new_gid}"
                    break
        if not rename_map:
            return state

        new_state: dict[str, int] = dict(state)
        for old_ns, new_ns in rename_map.items():
            old_val = int(new_state.pop(old_ns, 0) or 0)
            cur_val = int(new_state.get(new_ns, 0) or 0)
            new_state[new_ns] = max(old_val, cur_val)

        self._log.info(
            "client",
            "SeqTracker group_id migration: %d namespaces rewritten → %s",
            len(rename_map),
            {k: rename_map[k] for k in list(rename_map)[:3]},
        )

        # 落盘：删老 ns，写新 ns。删除接口缺失时只写新不删老（下次启动仍会再跑一次，幂等）
        deleter = getattr(self._keystore, "delete_seq", None)
        saver = getattr(self._keystore, "save_seq", None)
        if callable(saver):
            for old_ns, new_ns in rename_map.items():
                if callable(deleter):
                    try:
                        deleter(self._aid, self._device_id, self._slot_id, old_ns)
                    except Exception as exc:
                        self._log.debug("client", "delete old seq ns failed: ns=%s err=%s", old_ns, exc)
                try:
                    saver(self._aid, self._device_id, self._slot_id, new_ns, new_state[new_ns])
                except Exception as exc:
                    self._log.debug("client", "write new seq ns failed: ns=%s err=%s", new_ns, exc)
        return new_state

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
        self._pending_ordered().clear()
        if hasattr(self, "_group_synced"):
            self._group_synced.clear()

    def _refresh_seq_tracking_context(self) -> None:
        next_context = self._current_seq_tracker_context()
        if next_context == self._seq_tracker_context:
            return
        prev = self._seq_tracker_context
        old_state = self._seq_tracker.export_state() if prev else {}
        self._log.info("client", 
            "SeqTracker 上下文切换 %s → %s, 旧 state=%s",
            prev, next_context, old_state,
        )
        self._seq_tracker = SeqTracker()
        self._gap_fill_done.clear()
        self._gap_fill_active = False
        self._pushed_seqs.clear()
        self._pending_ordered().clear()
        if hasattr(self, "_group_synced"):
            self._group_synced.clear()
        self._seq_tracker_context = next_context

    def _persist_seq(self, ns: str, *, force_seq: int | None = None) -> None:
        """即时持久化单个 namespace 的 seq（行级写入）。
        force_seq: 强制写入指定 seq（用于 auto-ack 后跳过空洞）。"""
        if not self._aid:
            return
        seq = force_seq if force_seq is not None else self._seq_tracker.get_contiguous_seq(ns)
        if seq <= 0:
            return
        self._log.debug("client", "persist_seq: ns=%s seq=%d (force=%s)", ns, seq, force_seq is not None)
        if force_seq is not None:
            # 同时更新内存中的 SeqTracker
            self._seq_tracker.restore_state({ns: seq})
        try:
            saver = getattr(self._keystore, "save_seq", None)
            if callable(saver):
                saver(self._aid, self._device_id, self._slot_id, ns, seq)
        except Exception as _seq_exc:
            self._log.debug("client", "save seq failed: %s", _seq_exc)

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
            self._log.warn("client", "failed to save SeqTracker state: %s", exc)

    def _attach_rotation_id(info: dict[str, Any], rotation_id: str) -> None:
        if not rotation_id:
            return
        for dist in info.get("distributions", []):
            if not isinstance(dist, dict):
                continue
            payload = dist.get("payload")
            if isinstance(payload, dict):
                payload["rotation_id"] = rotation_id

    def _rotation_expected_members_stale(rotation: dict[str, Any], member_aids: list[str]) -> bool:
        expected = rotation.get("expected_members")
        if not isinstance(expected, list) or not expected:
            return False
        expected_members = sorted({str(item) for item in expected if str(item or "").strip()})
        current_members = sorted({str(item) for item in member_aids if str(item or "").strip()})
        return bool(expected_members and current_members and expected_members != current_members)

    def _rotation_retry_delay_s(pending: dict[str, Any] | None) -> float:
        now_ms = int(time.time() * 1000)
        lease_expires_at = 0
        if isinstance(pending, dict):
            if pending.get("expired") or str(pending.get("status") or "") not in ("", "distributing"):
                lease_expires_at = 0
            else:
                try:
                    lease_expires_at = int(pending.get("lease_expires_at") or 0)
                except (TypeError, ValueError):
                    lease_expires_at = 0
        base = max(1.0, (lease_expires_at - now_ms) / 1000.0 + 1.0) if lease_expires_at else 5.0
        return min(base + random.random() * 2.0, _GROUP_ROTATION_RETRY_MAX_DELAY)

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
                # auth gateway 缓存
                self._auth.clean_expired_caches()
        except asyncio.CancelledError:
            raise

    # ── 内部：断线重连 ────────────────────────────────────

    # 不重连 close code 集合：客户端/认证/权限错误，重连无意义
    # 4014: 短连接 idle TTL 兜底（不重连）
    # 4015: 长连接配额超限被踢（aid_device_slot / aid_devices / device_aids）
    _NO_RECONNECT_CODES = frozenset({4001, 4003, 4008, 4009, 4010, 4011, 4012, 4013, 4014, 4015})

    async def _on_gateway_disconnect(self, data: Any) -> None:
        """处理服务端主动断开通知 event/gateway.disconnect。

        服务端可能附带结构化 detail 字段（如配额超限时含 aid/device_id/slot_id/quota_kind/evicted_by）。
        透传到应用层可订阅事件 'gateway.disconnect'，方便业务定位被踢原因。
        """
        if not isinstance(data, dict):
            data = {}
        code = data.get("code")
        reason = data.get("reason", "")
        detail = data.get("detail") if isinstance(data.get("detail"), dict) else {}
        self._log.warn(
            "client",
            "server initiated disconnect: code=%s, reason=%s, detail=%s",
            code, reason, detail,
        )
        self._server_kicked = True
        # 缓存最近一次 disconnect 信息，让后续 connection.state(terminal_failed) 也能带 detail
        self._last_disconnect_info = {"code": code, "reason": reason, "detail": detail}
        # 透传给应用层订阅者
        try:
            await self._dispatcher.publish("gateway.disconnect", {
                "code": code,
                "reason": reason,
                "detail": detail,
            })
        except Exception as exc:
            self._log.debug("client", "publish gateway.disconnect failed: %s", exc)

    async def _handle_transport_disconnect(self, error: Exception | None, close_code: int | None = None) -> None:
        if self._closing or self._state == "closed":
            return
        self._state = "disconnected"
        # 断线时保存 SeqTracker 状态，防止进程崩溃后 seq 回退
        try:
            self._save_seq_tracker_state()
        except Exception as exc:
            self._log.debug("client", "failed to save SeqTracker on disconnect: %s", exc)
        await self._dispatcher.publish("connection.state", {"state": self._state, "error": error})
        if not bool(self._session_options["auto_reconnect"]):
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        # 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
        if self._server_kicked or (close_code is not None and close_code in self._NO_RECONNECT_CODES):
            self._state = "terminal_failed"
            reason = "server kicked" if self._server_kicked else f"close code {close_code}"
            self._log.warn("client", "suppressing auto-reconnect: %s", reason)
            disconnect_info = getattr(self, "_last_disconnect_info", None) or {}
            event_payload = {
                "state": self._state, "error": error, "reason": reason,
            }
            # 把服务端附带的结构化 detail（如配额超限信息）也带给应用层
            if disconnect_info.get("detail"):
                event_payload["detail"] = disconnect_info["detail"]
            if disconnect_info.get("code") is not None:
                event_payload["code"] = disconnect_info["code"]
            await self._dispatcher.publish("connection.state", event_payload)
            return
        await self._stop_background_tasks()
        # 1006 = 网络异常断开（无 close frame），1000 = 正常关闭（客户端主动）
        # 其他 code = 服务端主动关闭
        server_initiated = close_code is not None and close_code not in (1000, 1006)
        self._reconnect_task = asyncio.create_task(self._reconnect_loop(server_initiated))

    # ── Named Group（命名群）高层 API ────────────────────────────

    async def create_named_group(self, group_name: str, **kwargs) -> dict:
        """创建命名群：本地生成 P-256 keypair，调用 group.create 传入 public_key，
        服务端签发群 AID 证书，返回后将证书和私钥存入 keystore。
        """
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import serialization as _ser

        # 生成 P-256 keypair
        private_key = _ec.generate_private_key(_ec.SECP256R1())
        public_key_der = private_key.public_key().public_bytes(
            _ser.Encoding.X962, _ser.PublicFormat.UncompressedPoint
        )
        import base64
        public_key_b64 = base64.b64encode(public_key_der).decode("ascii")
        private_key_pem = private_key.private_bytes(
            _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()
        ).decode("utf-8")

        params = dict(kwargs)
        params["group_name"] = group_name
        params["public_key"] = public_key_b64
        params["curve"] = "P-256"

        result = await self.call("group.create", params)

        # 存储群 AID 的私钥和证书到 keystore
        aid_cert = result.get("aid_cert") if isinstance(result, dict) else None
        group_info = result.get("group", {}) if isinstance(result, dict) else {}
        group_aid = group_info.get("group_aid", "")
        if aid_cert and group_aid:
            self._keystore.save_identity(group_aid, {
                "private_key_pem": private_key_pem,
                "public_key": public_key_b64,
                "curve": "P-256",
                "type": "group_identity",
            })
            cert_pem = aid_cert.get("cert", "")
            if cert_pem:
                self._keystore.save_cert(group_aid, cert_pem)

        return result

    async def bind_group_aid(self, group_id: str, group_name: str) -> dict:
        """为已有普通群绑定命名 AID：本地生成 keypair，调用 group.bind_aid，
        存储证书和私钥到 keystore。
        """
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import serialization as _ser

        private_key = _ec.generate_private_key(_ec.SECP256R1())
        public_key_der = private_key.public_key().public_bytes(
            _ser.Encoding.X962, _ser.PublicFormat.UncompressedPoint
        )
        import base64
        public_key_b64 = base64.b64encode(public_key_der).decode("ascii")
        private_key_pem = private_key.private_bytes(
            _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()
        ).decode("utf-8")

        result = await self.call("group.bind_aid", {
            "group_id": group_id,
            "group_name": group_name,
            "public_key": public_key_b64,
            "curve": "P-256",
        })

        aid_cert = result.get("aid_cert") if isinstance(result, dict) else None
        group_info = result.get("group", {}) if isinstance(result, dict) else {}
        group_aid = group_info.get("group_aid", "")
        if aid_cert and group_aid:
            self._keystore.save_identity(group_aid, {
                "private_key_pem": private_key_pem,
                "public_key": public_key_b64,
                "curve": "P-256",
                "type": "group_identity",
            })
            cert_pem = aid_cert.get("cert", "")
            if cert_pem:
                self._keystore.save_cert(group_aid, cert_pem)

        return result

    async def _reconnect_loop(self, server_initiated: bool = False) -> None:
        retry = dict(self._session_options["retry"])
        max_base_delay = _clamp_reconnect_delay(
            retry.get("max_delay", _RECONNECT_MAX_BASE_DELAY),
            _RECONNECT_MAX_BASE_DELAY,
        )
        # max_attempts=0 表示无限重试（与 Go/TS/JS 对齐）
        max_attempts_raw = int(retry.get("max_attempts", 0))
        max_attempts = max_attempts_raw if max_attempts_raw > 0 else 0
        # 服务端主动关闭时从 16s 起跳，避免重连风暴；网络断开从 initial_delay 起跳
        base_delay = _clamp_reconnect_delay(
            16.0 if server_initiated else retry.get("initial_delay", 1.0),
            16.0 if server_initiated else 1.0,
            max_base_delay,
        )
        delay = base_delay
        attempt = 0
        self._log.debug("client", "reconnect loop started: server_initiated=%s max_attempts=%s base_delay=%.1fs", server_initiated, max_attempts, base_delay)

        while not self._closing:
            attempt += 1
            # R1 fix: max_attempts 检查在循环顶部，覆盖所有路径（含 health-fail）
            if max_attempts > 0 and attempt > max_attempts:
                self._state = "terminal_failed"
                self._reconnect_task = None
                self._log.warn("client", "reconnect max attempts reached, terminating: attempts=%d", attempt - 1)
                await self._dispatcher.publish("connection.state", {
                    "state": self._state,
                    "attempt": attempt - 1,
                    "reason": "max_attempts_exhausted",
                })
                return

            self._state = "reconnecting"
            await self._dispatcher.publish("connection.state", {
                "state": self._state,
                "attempt": attempt,
            })
            try:
                # 固定上限抖动：base=[1s, max_base]，delay=base+rand(0..max_base)。
                await self._reconnect_sleep(_reconnect_sleep_delay(delay, max_base_delay))
                # 重连前先 GET /health 探测，不健康则跳过本轮
                if self._gateway_url:
                    healthy = await self._discovery.check_health(self._gateway_url)
                    if not healthy:
                        self._log.debug("client", "reconnect health check failed, skipping this round: attempt=%d gateway=%s", attempt, self._gateway_url)
                        delay = min(delay * 2, max_base_delay)
                        continue
                await self._transport.close()
                self._log.debug("client", "reconnect attempting _connect_once: attempt=%d", attempt)
                await self._invoke_reconnect_connect_once()
                self._log.debug("client", "reconnect success: attempt=%d", attempt)
                self._reconnect_task = None
                return
            except asyncio.CancelledError:
                self._reconnect_task = None
                raise
            except Exception as exc:
                self._log.warn("client", "reconnect failed: attempt=%d error=%s retryable=%s", attempt, exc, self._should_retry_reconnect(exc))
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
                delay = min(delay * 2, max_base_delay)

    async def _reconnect_sleep(self, delay: float) -> None:
        await asyncio.sleep(delay)

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

        # 长短连接选项：默认 long，向后兼容
        kind_raw = request.get("connection_kind")
        if kind_raw is None:
            connection_kind = "long"
        else:
            connection_kind = str(kind_raw).strip().lower()
        if connection_kind not in ("long", "short"):
            raise ValidationError("connection_kind must be 'long' or 'short'")
        request["connection_kind"] = connection_kind
        try:
            request["short_ttl_ms"] = max(0, int(request.get("short_ttl_ms") or 0))
        except (TypeError, ValueError):
            raise ValidationError("short_ttl_ms must be a non-negative integer")
        if connection_kind != "short":
            request["short_ttl_ms"] = 0
        return request

    def _build_session_options(self, params: dict[str, Any]) -> dict[str, Any]:
        connection_kind = str(params.get("connection_kind") or "long")
        options: dict[str, Any] = {
            "auto_reconnect": _DEFAULT_SESSION_OPTIONS["auto_reconnect"],
            "heartbeat_interval": _DEFAULT_SESSION_OPTIONS["heartbeat_interval"],
            "token_refresh_before": _DEFAULT_SESSION_OPTIONS["token_refresh_before"],
            "retry": dict(_DEFAULT_SESSION_OPTIONS["retry"]),
            "timeouts": dict(_DEFAULT_SESSION_OPTIONS["timeouts"]),
            "connection_kind": connection_kind,
            "short_ttl_ms": int(params.get("short_ttl_ms") or 0),
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
                self._log.debug(
                    "client",
                    "_invoke_reconnect_connect_once refreshed access_token from cached identity aid=%s",
                    self._aid,
                )
                self._session_params["access_token"] = fresh_token
            else:
                self._log.debug(
                    "client",
                    "_invoke_reconnect_connect_once cached identity has no valid access_token aid=%s",
                    self._aid,
                )
        else:
            self._log.debug(
                "client",
                "_invoke_reconnect_connect_once no cached identity for aid=%s, using existing session params",
                self._aid,
            )
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

    # ── V2 E2EE ──────────────────────────────────────────────

    _V2_BOOTSTRAP_TTL = 3600  # 发送端 bootstrap 缓存 1 小时

    _V2_SIG_CACHE_TTL = 600  # 验签结果缓存 10 分钟
    _V2_SIG_CACHE_MAX = 16384

    async def _init_v2_session(self) -> None:
        """connect 成功后初始化 V2 session 并注册设备 SPK。IK = AID 长期密钥（无需独立注册）。"""
        if not self._aid:
            return
        identity = self._identity
        if not identity or not identity.get("private_key_pem"):
            self._log.warn("client", "V2 session init skipped: no AID private key")
            return

        # 把 AID PEM 私钥转为 raw scalar (32 bytes) + DER 公钥
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import serialization as _ser
        pk = _ser.load_pem_private_key(identity["private_key_pem"].encode("utf-8"), password=None)
        if not isinstance(pk, _ec.EllipticCurvePrivateKey):
            raise RuntimeError("AID private key must be EC P-256")
        priv_int = pk.private_numbers().private_value
        aid_priv_der = priv_int.to_bytes(32, "big")  # raw scalar
        aid_pub_der = pk.public_key().public_bytes(
            encoding=_ser.Encoding.DER,
            format=_ser.PublicFormat.SubjectPublicKeyInfo,
        )

        db = self._keystore._get_db(self._aid)
        self._v2_session = V2Session(
            db, self._device_id, self._aid,
            aid_priv_der=aid_priv_der, aid_pub_der=aid_pub_der,
        )
        self._v2_session.ensure_keys()
        self._v2_bootstrap_cache: dict[str, tuple[list[dict], float]] = {}
        await self._v2_session.ensure_registered(self.call)
        self._log.debug("client", "V2 session initialized (IK=AID identity): aid=%s device=%s", self._aid, self._device_id)

    async def _send_encrypted_v2(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。

        内部方法，由 call("message.send") 拦截路由调用。
        params 中需要 to（目标 AID）和 payload（业务 payload）。
        """
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        to = str(params.get("to") or "").strip()
        payload = params.get("payload") or {}
        if not to:
            raise ValidationError("message.send requires 'to'")
        if not isinstance(payload, dict):
            raise ValidationError("message.send payload must be a dict for V2 encryption")

        async def _attempt(use_cache: bool) -> dict[str, Any]:
            if use_cache:
                cached = self._v2_bootstrap_cache.get(to)
                if cached and (time.time() - cached[1]) < self._V2_BOOTSTRAP_TTL:
                    peer_devices = cached[0]
                else:
                    peer_devices = None
            else:
                peer_devices = None

            if peer_devices is None:
                bootstrap = await self.call("message.v2.bootstrap", {"peer_aid": to})
                peer_devices = bootstrap.get("peer_devices", [])
                audit_recipients_raw = bootstrap.get("audit_recipients", [])
                self._log.info("client", "DEBUG _send_encrypted_v2 bootstrap: to=%s peer_devices=%d spk_pks=%s",
                               to, len(peer_devices),
                               [d.get("spk_pk", "")[:20] or "<empty>" for d in peer_devices[:3]])
                if peer_devices:
                    self._v2_bootstrap_cache[to] = (peer_devices, time.time(), audit_recipients_raw)
            else:
                audit_recipients_raw = cached[2] if len(cached) > 2 and isinstance(cached[2], list) else []

            if not peer_devices:
                raise E2EEError(f"V2 bootstrap: no devices found for {to}")

            targets = []
            for dev in peer_devices:
                ik_pk_der = base64.b64decode(dev["ik_pk"])
                spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
                self._v2_session.cache_peer_ik(to, dev.get("device_id", ""), ik_pk_der)
                targets.append({
                    "aid": to,
                    "device_id": dev.get("device_id", ""),
                    "role": "peer",
                    "key_source": dev.get("key_source", "peer_device_prekey"),
                    "ik_pk_der": ik_pk_der,
                    "spk_pk_der": spk_pk_der,
                    "spk_id": dev.get("spk_id", ""),
                })

            # 构造 audit_recipients
            audit_targets = []
            for dev in audit_recipients_raw:
                ik_pk_der = base64.b64decode(dev["ik_pk"]) if dev.get("ik_pk") else None
                if not ik_pk_der:
                    continue
                spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
                audit_targets.append({
                    "aid": dev.get("aid", ""),
                    "device_id": dev.get("device_id", ""),
                    "role": "audit",
                    "key_source": dev.get("key_source", "peer_device_prekey"),
                    "ik_pk_der": ik_pk_der,
                    "spk_pk_der": spk_pk_der,
                    "spk_id": dev.get("spk_id", ""),
                })

            target_set = {"targets": targets, "audit_recipients": audit_targets}
            sender = self._v2_session.get_sender_identity()

            # Self-sync
            if self._aid and self._aid != to:
                try:
                    self_cached = self._v2_bootstrap_cache.get(self._aid)
                    if self_cached and (time.time() - self_cached[1]) < self._V2_BOOTSTRAP_TTL:
                        self_devices = self_cached[0]
                    else:
                        self_bs = await self.call("message.v2.bootstrap", {"peer_aid": self._aid})
                        self_devices = self_bs.get("peer_devices", [])
                        if self_devices:
                            self._v2_bootstrap_cache[self._aid] = (self_devices, time.time())
                    for dev in self_devices:
                        dev_id = dev.get("owner_device_id") or dev.get("device_id", "")
                        if dev_id == self._device_id:
                            continue
                        ik_pk_der = base64.b64decode(dev["ik_pk"])
                        spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
                        targets.append({
                            "aid": self._aid,
                            "device_id": dev_id,
                            "role": "self_sync",
                            "key_source": dev.get("key_source", "peer_device_prekey"),
                            "ik_pk_der": ik_pk_der,
                            "spk_pk_der": spk_pk_der,
                            "spk_id": dev.get("spk_id", ""),
                        })
                except Exception as exc:
                    self._log.debug("client", "V2 self-sync bootstrap failed (non-fatal): %s", exc)

            envelope = encrypt_p2p_message(
                sender=sender,
                target_set=target_set,
                payload=payload,
                message_id=params.get("message_id"),
                timestamp=params.get("timestamp"),
                protected_headers=params.get("protected_headers") if isinstance(params.get("protected_headers"), dict) else None,
                context=params.get("context") if isinstance(params.get("context"), dict) else None,
            )

            return await self.call("message.send", {
                "to": to,
                "payload": envelope,
                "encrypt": False,
            })

        try:
            return await _attempt(use_cache=True)
        except Exception as exc:
            exc_code = getattr(exc, "code", None)
            if exc_code in (-33011, -33012, -33050, -33052, -33054):
                self._log.debug("client", "V2 P2P speculative send rejected (code=%s), refreshing bootstrap: %s", exc_code, exc)
                self._v2_bootstrap_cache.pop(to, None)
                return await _attempt(use_cache=False)
            raise

    async def _pull_v2_internal(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """V2 P2P 拉取并解密消息。内部方法，由 call("message.pull") 路由调用。"""
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")
        after_seq = int(params.get("after_seq", 0) or 0)
        limit = int(params.get("limit", 50) or 50)

        ns = f"p2p:{self._aid}" if self._aid else ""
        effective_after_seq = after_seq or self._seq_tracker.get_contiguous_seq(ns)

        result = await self.call("message.v2.pull", {
            "after_seq": effective_after_seq,
            "limit": limit,
        })
        messages = result.get("messages", [])
        seqs = [
            int(m.get("seq") or 0)
            for m in messages
            if isinstance(m, dict) and int(m.get("seq") or 0) > 0
        ]
        contig_before = self._seq_tracker.get_contiguous_seq(ns) if ns else 0
        if ns and seqs and seqs[0] > contig_before:
            self._seq_tracker.force_contiguous_seq(ns, seqs[0])

        decrypted = []
        for msg in messages:
            seq = msg.get("seq", 0)
            if seq <= 0:
                continue

            # V1 行（服务端 v2.pull 合并的 V1 历史）：V2-only 客户端跳过 V1 envelope，
            # 仅明文消息照常 publish；e2ee.encrypted / e2ee.group_encrypted / 未知类型一律
            # 推进 seq tracker 并丢弃。
            if str(msg.get("version", "") or "") == "v1":
                legacy = msg.get("legacy_v1") or {}
                v1_payload = legacy.get("payload")
                v1_payload_type = ""
                if isinstance(v1_payload, dict):
                    v1_payload_type = str(v1_payload.get("type") or "").strip()
                # 仅放行明文（非 V1 E2EE 包装类型）
                if v1_payload_type not in ("e2ee.encrypted", "e2ee.group_encrypted") and v1_payload is not None:
                    v1_msg = {
                        "message_id": msg.get("message_id", ""),
                        "from": msg.get("from_aid", ""),
                        "to": legacy.get("to", self._aid),
                        "seq": seq,
                        "type": msg.get("type", ""),
                        "timestamp": msg.get("t_server", 0),
                        "payload": v1_payload,
                        "encrypted": False,
                    }
                    if ns:
                        await self._publish_pulled_message("message.received", ns, seq, v1_msg)
                    else:
                        await self._publish_app_event("message.received", v1_msg)
                    decrypted.append(v1_msg)
                else:
                    self._log.debug("client", "v2.pull skipping V1 envelope seq=%d payload_type=%s (V1 E2EE removed)",
                                    seq, v1_payload_type or "<none>")
                continue

            # 跟踪每个旧 SPK 引用的最大 seq（用于消费后销毁）
            try:
                msg_spk_id = str(msg.get("spk_id", "") or "")
                if msg_spk_id and self._v2_session and not self._v2_session.is_current_spk(msg_spk_id):
                    self._v2_session.track_old_spk_max_seq(msg_spk_id, seq)
            except Exception:
                pass
            # 解密
            plaintext = await self._decrypt_v2_message(msg)
            if plaintext is None:
                continue
            # pull 批发布只做去重，不受批内部永久空洞阻塞
            if ns:
                await self._publish_pulled_message("message.received", ns, seq, plaintext)
            else:
                await self._publish_app_event("message.received", plaintext)
            decrypted.append(plaintext)

        if ns and seqs:
            max_seq = max(seqs)
            current_contig = self._seq_tracker.get_contiguous_seq(ns)
            if max_seq > current_contig:
                self._seq_tracker.force_contiguous_seq(ns, max_seq)
                await self._drain_ordered_messages(ns)

        if ns:
            contig = self._seq_tracker.get_contiguous_seq(ns)
            if contig != contig_before:
                self._persist_seq(ns)
            if contig > 0 and contig != contig_before:
                self._fire_ack("message.v2.ack", {
                    "up_to_seq": contig,
                }, "V2 P2P auto-ack")
        return {"messages": decrypted}

    async def _ack_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 确认消费 + 自检销毁旧 SPK。内部方法，由 call("message.ack") 路由调用。"""
        ns = f"p2p:{self._aid}" if self._aid else ""
        up_to_seq = int(params.get("seq", 0) or params.get("up_to_seq", 0) or 0)
        seq = up_to_seq or (self._seq_tracker.get_contiguous_seq(ns) if ns else 0)
        if seq <= 0:
            return {"acked": 0}
        result = await self.call("message.v2.ack", {"up_to_seq": seq})
        # 补充兼容字段
        if isinstance(result, dict):
            result["ack_seq"] = seq
            result["success"] = True
            # V1+V2 共享 seq 空间：即使 V2 inbox 没 wrap 行（明文消息在 V1 表），
            # V1 cursor 也被推进了，视为 ack 成功
            if result.get("acked", 0) == 0 and seq > 0:
                result["acked"] = seq
        # 自检：所有旧 SPK 引用的消息都已 ack → 销毁旧 SPK 私钥（PFS）
        if self._v2_session:
            try:
                destroyed = self._v2_session.maybe_destroy_old_spks(seq)
                if destroyed:
                    self._log.info("client", "V2 destroyed old SPKs after ack: %s (PFS)", destroyed[:3])
            except Exception as exc:
                self._log.debug("client", "V2 SPK destroy failed (non-fatal): %s", exc)
        return result

    # ── V2 Group E2EE API ─────────────────────────────────────────

    _V2_GROUP_BOOTSTRAP_TTL = 3600

    async def _send_group_encrypted_v2(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 加密发送。内部方法，由 call("group.send") 路由调用。"""
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        from .v2.e2ee.encrypt_group import encrypt_group_message

        group_id = str(params.get("group_id") or "").strip()
        payload = params.get("payload") or {}
        if not group_id:
            raise ValidationError("group.send requires 'group_id'")
        if not isinstance(payload, dict):
            raise ValidationError("group.send payload must be a dict for V2 encryption")

        async def _attempt(use_cache: bool) -> dict[str, Any]:
            cache_key = f"group:{group_id}"
            epoch = 0
            if use_cache:
                cached = self._v2_bootstrap_cache.get(cache_key)
                if cached and (time.time() - cached[1]) < self._V2_GROUP_BOOTSTRAP_TTL:
                    all_devices = cached[0]
                    epoch = cached[2] if len(cached) > 2 else 0
                else:
                    all_devices = None
            else:
                all_devices = None

            if all_devices is None:
                bootstrap = await self.call("group.v2.bootstrap", {"group_id": group_id})
                all_devices = bootstrap.get("devices", [])
                epoch = int(bootstrap.get("epoch", 0))
                pending_adds = set(bootstrap.get("pending_adds", []))
                committed_aids = set(bootstrap.get("committed_member_aids", []))
                # 分叉检测：比对 state_chain
                server_chain = str(bootstrap.get("state_chain", "") or "")
                await self._v2_check_fork(group_id, server_chain)
                # 验证 owner/admin 对 state 的签名（防服务端篡改字段）
                await self._v2_verify_state_signature(group_id, bootstrap)
                # 抽取 state_commitment 用于绑定到 envelope AAD
                state_commitment = {
                    "state_version": int(bootstrap.get("state_version", 0) or 0),
                    "state_hash": str(bootstrap.get("state_hash_signed") or bootstrap.get("state_hash") or ""),
                    "state_chain": server_chain,
                }
                audit_recipients_raw = bootstrap.get("audit_recipients", []) or []
                # 安全等级变化通知（open/invite_code 群降级为 transport）
                level = str(bootstrap.get("e2ee_security_level", "") or "").strip() or "end_to_end"
                prev_level = self._v2_group_security_levels.get(group_id)
                if prev_level != level:
                    self._v2_group_security_levels[group_id] = level
                    try:
                        await self._dispatcher.publish("group.v2.security_level", {
                            "group_id": group_id,
                            "level": level,
                            "warning": str(bootstrap.get("e2ee_security_warning", "") or ""),
                            "previous_level": prev_level,
                        })
                    except Exception as exc:
                        self._log.debug("client", "publish group.v2.security_level failed (non-fatal): %s", exc)
                if all_devices:
                    self._v2_bootstrap_cache[cache_key] = (
                        all_devices, time.time(), epoch, pending_adds, committed_aids,
                        state_commitment, audit_recipients_raw,
                    )
                # lazy sync 触发：发现 pending members 且自己是 owner/admin 时异步发起提案
                if pending_adds and self._v2_session:
                    self._v2_maybe_trigger_auto_propose(group_id)
            else:
                pending_adds = cached[3] if len(cached) > 3 else set()
                committed_aids = cached[4] if len(cached) > 4 else set()
                state_commitment = cached[5] if len(cached) > 5 else {"state_version": 0, "state_hash": "", "state_chain": ""}
                audit_recipients_raw = cached[6] if len(cached) > 6 else []

            if not all_devices:
                raise E2EEError(f"V2 group bootstrap: no devices found for group {group_id}")

            targets = []
            for dev in all_devices:
                dev_aid = dev.get("aid", "")
                dev_id = dev.get("device_id", "")
                if dev_aid == self._aid and dev_id == self._device_id:
                    continue
                # pending 成员默认可收发（可用性优先），安全敏感群可通过配置严格过滤
                ik_pk_der = base64.b64decode(dev["ik_pk"])
                spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
                role = "self_sync" if dev_aid == self._aid else "member"
                targets.append({
                    "aid": dev_aid,
                    "device_id": dev_id,
                    "role": role,
                    "key_source": dev.get("key_source", "peer_device_prekey"),
                    "ik_pk_der": ik_pk_der,
                    "spk_pk_der": spk_pk_der,
                    "spk_id": dev.get("spk_id", ""),
                })

            if not targets:
                raise E2EEError(f"V2 group: no target devices for group {group_id}")

            # 监管 AID：把 audit_recipients 一并加入 targets（role="audit"）
            for dev in audit_recipients_raw:
                ik_b64 = dev.get("ik_pk")
                if not ik_b64:
                    continue
                ik_pk_der = base64.b64decode(ik_b64)
                spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
                targets.append({
                    "aid": dev.get("aid", ""),
                    "device_id": dev.get("device_id", ""),
                    "role": "audit",
                    "key_source": dev.get("key_source", "peer_device_prekey"),
                    "ik_pk_der": ik_pk_der,
                    "spk_pk_der": spk_pk_der,
                    "spk_id": dev.get("spk_id", ""),
                })

            sender = self._v2_session.get_sender_identity()
            envelope = encrypt_group_message(
                sender=sender,
                group_id=group_id,
                epoch=epoch,
                targets=targets,
                payload=payload,
                state_commitment=state_commitment,
                message_id=params.get("message_id"),
                timestamp=params.get("timestamp"),
                protected_headers=params.get("protected_headers") if isinstance(params.get("protected_headers"), dict) else None,
                context=params.get("context") if isinstance(params.get("context"), dict) else None,
            )

            return await self.call("group.v2.send", {
                "group_id": group_id,
                "envelope": envelope,
            })

        try:
            result = await _attempt(use_cache=True)
        except Exception as exc:
            exc_code = getattr(exc, "code", None)
            if exc_code in (-33011, -33012, -33050, -33052, -33054):
                self._log.debug("client", "group V2 speculative send rejected (code=%s), refreshing bootstrap: %s", exc_code, exc)
                self._v2_bootstrap_cache.pop(f"group:{group_id}", None)
                result = await _attempt(use_cache=False)
            else:
                raise

        # 发送成功后记录自己发的消息 seq，保证 SeqTracker 连续
        if isinstance(result, dict) and result.get("seq"):
            ns = f"group:{group_id}"
            seq = int(result["seq"])
            self._seq_tracker.on_message_seq(ns, seq)
            self._mark_published_seq(ns, seq)
            self._persist_seq(ns)
        return result

    # ── V2 thought（per-device wrap，服务端不持久化）─────────────

    async def _build_v2_p2p_envelope(
        self,
        *,
        to: str,
        payload: dict[str, Any],
        message_id: str | None,
        timestamp: int | None,
        use_cache: bool = True,
        protected_headers: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """V2 P2P 多设备 wrap envelope 构造（不发送）。

        thought.put 复用此函数构造与 message.send 相同的 V2 envelope。
        """
        from .v2.e2ee.encrypt_p2p import encrypt_p2p_message

        cached = self._v2_bootstrap_cache.get(to) if use_cache else None
        if cached and (time.time() - cached[1]) < self._V2_BOOTSTRAP_TTL:
            peer_devices = cached[0]
            audit_recipients_raw = cached[2] if len(cached) > 2 and isinstance(cached[2], list) else []
        else:
            bootstrap = await self.call("message.v2.bootstrap", {"peer_aid": to})
            peer_devices = bootstrap.get("peer_devices", [])
            audit_recipients_raw = bootstrap.get("audit_recipients", []) or []
            if peer_devices:
                self._v2_bootstrap_cache[to] = (peer_devices, time.time(), audit_recipients_raw)

        if not peer_devices:
            raise E2EEError(f"V2 bootstrap: no devices found for {to}")

        targets: list[dict[str, Any]] = []
        for dev in peer_devices:
            ik_pk_der = base64.b64decode(dev["ik_pk"])
            spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
            self._v2_session.cache_peer_ik(to, dev.get("device_id", ""), ik_pk_der)
            targets.append({
                "aid": to,
                "device_id": dev.get("device_id", ""),
                "role": "peer",
                "key_source": dev.get("key_source", "peer_device_prekey"),
                "ik_pk_der": ik_pk_der,
                "spk_pk_der": spk_pk_der,
                "spk_id": dev.get("spk_id", ""),
            })

        for dev in audit_recipients_raw:
            ik_b64 = dev.get("ik_pk")
            if not ik_b64:
                continue
            ik_pk_der = base64.b64decode(ik_b64)
            spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
            targets.append({
                "aid": dev.get("aid", ""),
                "device_id": dev.get("device_id", ""),
                "role": "audit",
                "key_source": dev.get("key_source", "peer_device_prekey"),
                "ik_pk_der": ik_pk_der,
                "spk_pk_der": spk_pk_der,
                "spk_id": dev.get("spk_id", ""),
            })

        # Self-sync：自己其它设备
        if self._aid and self._aid != to:
            try:
                self_cached = self._v2_bootstrap_cache.get(self._aid)
                if self_cached and (time.time() - self_cached[1]) < self._V2_BOOTSTRAP_TTL:
                    self_devices = self_cached[0]
                else:
                    self_bs = await self.call("message.v2.bootstrap", {"peer_aid": self._aid})
                    self_devices = self_bs.get("peer_devices", [])
                    if self_devices:
                        self._v2_bootstrap_cache[self._aid] = (self_devices, time.time())
                for dev in self_devices:
                    dev_id = dev.get("owner_device_id") or dev.get("device_id", "")
                    if dev_id == self._device_id:
                        continue
                    ik_pk_der = base64.b64decode(dev["ik_pk"])
                    spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
                    targets.append({
                        "aid": self._aid,
                        "device_id": dev_id,
                        "role": "self_sync",
                        "key_source": dev.get("key_source", "peer_device_prekey"),
                        "ik_pk_der": ik_pk_der,
                        "spk_pk_der": spk_pk_der,
                        "spk_id": dev.get("spk_id", ""),
                    })
            except Exception as exc:
                self._log.debug("client", "V2 thought self-sync bootstrap failed (non-fatal): %s", exc)

        sender = self._v2_session.get_sender_identity()
        target_set = {"targets": targets, "audit_recipients": []}
        envelope = encrypt_p2p_message(
            sender=sender,
            target_set=target_set,
            payload=payload,
            message_id=message_id,
            timestamp=timestamp,
            protected_headers=protected_headers,
            context=context,
        )
        return envelope

    async def _put_message_thought_encrypted_v2(self, params: dict[str, Any]) -> Any:
        """V2 P2P thought.put：使用 V2 多设备 wrap envelope。

        服务端仍走 message.thought.put（内存 KV），envelope 透传，由接收端单设备解密。
        """
        to_aid = str(params.get("to") or "").strip()
        self._validate_message_recipient(to_aid)
        payload = params.get("payload")
        if not to_aid:
            raise ValidationError("message.thought.put requires to")
        if not isinstance(payload, dict):
            raise ValidationError("message.thought.put payload must be an object when encrypt=true")

        thought_id = str(params.get("thought_id") or f"mt-{uuid.uuid4()}").strip()
        timestamp = int(params.get("timestamp") or time.time() * 1000)

        async def _attempt(use_cache: bool) -> Any:
            envelope = await self._build_v2_p2p_envelope(
                to=to_aid,
                payload=payload,
                message_id=thought_id,
                timestamp=timestamp,
                use_cache=use_cache,
                context=params.get("context") if isinstance(params.get("context"), dict) else None,
            )
            send_params: dict[str, Any] = {
                "to": to_aid,
                "payload": envelope,
                "encrypted": True,
                "thought_id": thought_id,
                "timestamp": timestamp,
            }
            if "context" in params:
                send_params["context"] = params["context"]
            self._sign_client_operation("message.thought.put", send_params)
            return await self._transport.call("message.thought.put", send_params)

        try:
            return await _attempt(use_cache=True)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "device" in err_msg or "prekey" in err_msg or "recipient" in err_msg or "stale" in err_msg:
                self._log.debug("client", "V2 P2P thought put speculative rejected, refreshing bootstrap: %s", exc)
                self._v2_bootstrap_cache.pop(to_aid, None)
                return await _attempt(use_cache=False)
            raise

    async def _build_v2_group_envelope(
        self,
        *,
        group_id: str,
        payload: dict[str, Any],
        message_id: str | None,
        timestamp: int | None,
        use_cache: bool = True,
        protected_headers: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """V2 Group 多设备 wrap envelope 构造（不发送）。"""
        from .v2.e2ee.encrypt_group import encrypt_group_message

        cache_key = f"group:{group_id}"
        cached = self._v2_bootstrap_cache.get(cache_key) if use_cache else None
        if cached and (time.time() - cached[1]) < self._V2_GROUP_BOOTSTRAP_TTL:
            all_devices = cached[0]
            epoch = cached[2] if len(cached) > 2 else 0
            state_commitment = cached[5] if len(cached) > 5 else {"state_version": 0, "state_hash": "", "state_chain": ""}
            audit_recipients_raw = cached[6] if len(cached) > 6 else []
        else:
            bootstrap = await self.call("group.v2.bootstrap", {"group_id": group_id})
            all_devices = bootstrap.get("devices", [])
            epoch = int(bootstrap.get("epoch", 0))
            server_chain = str(bootstrap.get("state_chain", "") or "")
            await self._v2_check_fork(group_id, server_chain)
            await self._v2_verify_state_signature(group_id, bootstrap)
            state_commitment = {
                "state_version": int(bootstrap.get("state_version", 0) or 0),
                "state_hash": str(bootstrap.get("state_hash_signed") or bootstrap.get("state_hash") or ""),
                "state_chain": server_chain,
            }
            audit_recipients_raw = bootstrap.get("audit_recipients", []) or []
            pending_adds = set(bootstrap.get("pending_adds", []))
            committed_aids = set(bootstrap.get("committed_member_aids", []))
            if all_devices:
                self._v2_bootstrap_cache[cache_key] = (
                    all_devices, time.time(), epoch, pending_adds, committed_aids,
                    state_commitment, audit_recipients_raw,
                )
            # lazy sync 触发：发现 pending members 且自己是 owner/admin 时异步发起提案
            if pending_adds and self._v2_session:
                self._v2_maybe_trigger_auto_propose(group_id)

        if not all_devices:
            raise E2EEError(f"V2 group bootstrap: no devices for {group_id}")

        targets: list[dict[str, Any]] = []
        for dev in all_devices:
            dev_aid = dev.get("aid", "")
            dev_id = dev.get("device_id", "")
            if dev_aid == self._aid and dev_id == self._device_id:
                continue
            ik_pk_der = base64.b64decode(dev["ik_pk"])
            spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
            role = "self_sync" if dev_aid == self._aid else "member"
            targets.append({
                "aid": dev_aid,
                "device_id": dev_id,
                "role": role,
                "key_source": dev.get("key_source", "peer_device_prekey"),
                "ik_pk_der": ik_pk_der,
                "spk_pk_der": spk_pk_der,
                "spk_id": dev.get("spk_id", ""),
            })

        for dev in audit_recipients_raw:
            ik_b64 = dev.get("ik_pk")
            if not ik_b64:
                continue
            ik_pk_der = base64.b64decode(ik_b64)
            spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
            targets.append({
                "aid": dev.get("aid", ""),
                "device_id": dev.get("device_id", ""),
                "role": "audit",
                "key_source": dev.get("key_source", "peer_device_prekey"),
                "ik_pk_der": ik_pk_der,
                "spk_pk_der": spk_pk_der,
                "spk_id": dev.get("spk_id", ""),
            })

        if not targets:
            raise E2EEError(f"V2 group: no target devices for {group_id}")

        sender = self._v2_session.get_sender_identity()
        envelope = encrypt_group_message(
            sender=sender,
            group_id=group_id,
            epoch=epoch,
            targets=targets,
            payload=payload,
            state_commitment=state_commitment,
            message_id=message_id,
            timestamp=timestamp,
            protected_headers=protected_headers,
            context=context,
        )
        return envelope

    async def _put_group_thought_encrypted_v2(self, params: dict[str, Any]) -> Any:
        """V2 Group thought.put：多设备 wrap envelope。"""
        group_id = str(params.get("group_id") or "").strip()
        payload = params.get("payload")
        if not group_id:
            raise ValidationError("group.thought.put requires 'group_id'")
        if not isinstance(payload, dict):
            raise ValidationError("group.thought.put payload must be an object when encrypt=true")

        thought_id = str(params.get("thought_id") or f"gt-{uuid.uuid4()}").strip()
        timestamp = int(params.get("timestamp") or time.time() * 1000)

        async def _attempt(use_cache: bool) -> Any:
            envelope = await self._build_v2_group_envelope(
                group_id=group_id,
                payload=payload,
                message_id=thought_id,
                timestamp=timestamp,
                use_cache=use_cache,
                context=params.get("context") if isinstance(params.get("context"), dict) else None,
            )
            send_params: dict[str, Any] = {
                "group_id": group_id,
                "payload": envelope,
                "encrypted": True,
                "thought_id": thought_id,
                "timestamp": timestamp,
            }
            if "context" in params:
                send_params["context"] = params["context"]
            self._sign_client_operation("group.thought.put", send_params)
            return await self._transport.call("group.thought.put", send_params)

        try:
            return await _attempt(use_cache=True)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "member" in err_msg or "device" in err_msg or "recipient" in err_msg or "stale" in err_msg or "epoch" in err_msg:
                self._log.debug("client", "V2 group thought put speculative rejected, refreshing bootstrap: %s", exc)
                self._v2_bootstrap_cache.pop(f"group:{group_id}", None)
                return await _attempt(use_cache=False)
            raise

    async def _decrypt_v2_envelope_for_thought(
        self,
        *,
        envelope: dict[str, Any],
        from_aid: str,
    ) -> dict[str, Any] | None:
        """解密一个 V2 thought envelope（P2P 或 Group），返回 payload dict。

        与 _decrypt_v2_message 不同：
        - 不依赖 msg.envelope_json 包装
        - 失败返回 None，不发布 message.undecryptable 事件
        """
        from .v2.e2ee.decrypt import decrypt_message as v2_decrypt_message

        if not self._v2_session or not isinstance(envelope, dict):
            return None

        # 确定接收方 SPK：根据 envelope.recipients 中本设备所引用的 spk_id
        spk_id = ""
        recipients = envelope.get("recipients")
        if isinstance(recipients, list):
            for row in recipients:
                if isinstance(row, list) and len(row) >= 6:
                    if row[0] == self._aid and row[1] == self._device_id:
                        spk_id = str(row[5] or "")
                        break
        ik_priv, spk_priv = self._v2_session.get_decrypt_keys(spk_id)

        sender_device_id = (envelope.get("aad") or {}).get("from_device", "")
        sender_pub_der = self._v2_session.get_peer_ik(from_aid, sender_device_id)
        if not sender_pub_der:
            try:
                bs = await self.call("message.v2.bootstrap", {"peer_aid": from_aid})
                for dev in bs.get("peer_devices", []):
                    dev_id = dev.get("device_id") or dev.get("owner_device_id", "")
                    ik_der = base64.b64decode(dev["ik_pk"])
                    self._v2_session.cache_peer_ik(from_aid, dev_id, ik_der)
                sender_pub_der = self._v2_session.get_peer_ik(from_aid, sender_device_id)
            except Exception as exc:
                self._log.warn("client", "V2 thought decrypt: bootstrap sender %s failed: %s", from_aid, exc)
        # CA fallback：bootstrap 拿不到时从 CA 拉证书提取 IK 公钥
        if not sender_pub_der and from_aid:
            try:
                cert_pem = await self._fetch_peer_cert(from_aid)
                if cert_pem:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization as _ser
                    cert = x509.load_pem_x509_certificate(cert_pem)
                    sender_pub_der = cert.public_key().public_bytes(
                        encoding=_ser.Encoding.DER,
                        format=_ser.PublicFormat.SubjectPublicKeyInfo,
                    )
                    if sender_device_id:
                        self._v2_session.cache_peer_ik(from_aid, sender_device_id, sender_pub_der)
                    self._log.debug("client", "V2 thought decrypt: sender IK fallback from CA cert for %s", from_aid)
            except Exception as exc:
                self._log.warn("client", "V2 thought decrypt: CA fallback for %s failed: %s", from_aid, exc)
        if not sender_pub_der:
            self._log.warn("client", "V2 thought decrypt: no sender IK for %s device=%s", from_aid, sender_device_id)
            return None

        try:
            return v2_decrypt_message(
                envelope=envelope,
                self_aid=self._aid,
                self_device_id=self._device_id,
                self_ik_priv=ik_priv,
                self_spk_priv=spk_priv,
                sender_pub_der=sender_pub_der,
            )
        except Exception as exc:
            self._log.warn("client", "V2 thought decrypt failed from=%s: %s", from_aid, exc)
            return None

    async def _pull_group_v2_internal(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """V2 Group 拉取并解密消息。内部方法，由 call("group.pull") 路由调用。

        注：明文消息（encrypt=False）由服务端 group.v2.pull 自动从 group_messages
        合并到返回结果（version=v1，明文 payload 直接 publish），密文走 V2 解密。
        """
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        group_id = str(params.get("group_id") or "").strip()
        after_seq = int(params.get("after_seq", 0) or 0)
        limit = int(params.get("limit", 50) or 50)

        ns = f"group:{group_id}"
        effective_after_seq = after_seq or self._seq_tracker.get_contiguous_seq(ns)

        result = await self.call("group.v2.pull", {
            "group_id": group_id,
            "after_seq": effective_after_seq,
            "limit": limit,
        })
        messages = result.get("messages", [])
        seqs = [
            int(m.get("seq") or 0)
            for m in messages
            if isinstance(m, dict) and int(m.get("seq") or 0) > 0
        ]
        contig_before = self._seq_tracker.get_contiguous_seq(ns)
        if seqs and seqs[0] > contig_before:
            self._seq_tracker.force_contiguous_seq(ns, seqs[0])

        decrypted = []
        for msg in messages:
            seq = msg.get("seq", 0)
            if seq <= 0:
                continue

            # 服务端合并的 V1 明文行：version=v1 + payload 已是明文
            if str(msg.get("version", "") or "") == "v1":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") in ("e2ee.encrypted", "e2ee.group_encrypted"):
                    # 兜底：V1 加密 envelope 在 V2-only 客户端跳过
                    continue
                v1_msg = {
                    "message_id": msg.get("message_id", ""),
                    "from": msg.get("from_aid", ""),
                    "group_id": group_id,
                    "seq": seq,
                    "type": msg.get("type", ""),
                    "timestamp": msg.get("t_server", 0),
                    "payload": payload,
                    "encrypted": False,
                }
                await self._publish_pulled_message("group.message_created", ns, seq, v1_msg)
                decrypted.append(v1_msg)
                continue

            # V2 加密消息：解密
            plaintext = await self._decrypt_v2_message(msg)
            if plaintext is None:
                # V2 解密失败：跳过并推进 seq tracker（避免卡 contiguous_seq）
                continue
            plaintext["group_id"] = group_id
            await self._publish_pulled_message("group.message_created", ns, seq, plaintext)
            decrypted.append(plaintext)

        if seqs:
            max_seq = max(seqs)
            current_contig = self._seq_tracker.get_contiguous_seq(ns)
            if max_seq > current_contig:
                self._seq_tracker.force_contiguous_seq(ns, max_seq)
                await self._drain_ordered_messages(ns)

        contig = self._seq_tracker.get_contiguous_seq(ns)
        if contig != contig_before:
            self._persist_seq(ns)
        if contig > 0 and contig != contig_before:
            self._fire_ack("group.v2.ack", {
                "group_id": group_id, "up_to_seq": contig,
            }, f"V2 群消息 auto-ack group={group_id}")
        return {"messages": decrypted}

    async def _ack_group_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 确认消费。内部方法，由 call("group.ack_messages") 路由调用。"""
        group_id = str(params.get("group_id") or "").strip()
        up_to_seq = int(params.get("msg_seq", 0) or params.get("up_to_seq", 0) or 0)
        ns = f"group:{group_id}"
        seq = up_to_seq or (self._seq_tracker.get_contiguous_seq(ns) if ns else 0)
        if seq <= 0:
            return {"acked": 0}
        return await self.call("group.v2.ack", {"group_id": group_id, "up_to_seq": seq})

    async def _v2_verify_state_signature(self, group_id: str, bootstrap: dict) -> None:
        """验证 owner/admin 对 state 的 ECDSA 签名（防服务端篡改 bootstrap 字段）。

        - 无签名（state_version=0 或新建群）→ 跳过
        - 签名验证失败 → 抛 E2EEError 拒绝信任 bootstrap
        - 验证通过 → 校验 bootstrap 返回的 member_aids 是否在签名快照中
        """
        if not isinstance(bootstrap, dict):
            return
        state_signature = str(bootstrap.get("state_signature", "") or "")
        actor_aid = str(bootstrap.get("state_actor_aid", "") or "")
        state_hash_signed = str(bootstrap.get("state_hash_signed", "") or "")
        membership_snapshot = str(bootstrap.get("state_membership_snapshot", "") or "")
        state_version = int(bootstrap.get("state_version", 0) or 0)
        if state_version == 0 or not state_signature or not actor_aid:
            return  # 群刚创建或没有签名 state（C+D 模式下允许）

        try:
            # 重构签名 payload（与服务端 propose_state 中的格式一致）
            sign_payload = json.dumps({
                "group_id": group_id,
                "state_version": state_version,
                "state_hash": state_hash_signed,
                "membership_snapshot": membership_snapshot,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            sig_bytes = base64.b64decode(state_signature)

            # 先查验签缓存（命中即跳过 cert 拉取 + ECDSA 验证）
            import hashlib as _hl
            sig_cache_key = _hl.sha256(
                actor_aid.encode("utf-8") + b"\x00"
                + sign_payload + b"\x00"
                + sig_bytes
            ).digest()
            now_ts = time.time()
            cached_exp = self._v2_sig_cache.get(sig_cache_key)
            if cached_exp is not None and cached_exp > now_ts:
                self._log.debug("client", "V2 state signature cache hit: group=%s sv=%d", group_id, state_version)
            else:
                # 获取 actor 证书（通过 HTTP PKI 端点，不走 ca.get_cert RPC）
                cert_pem_bytes = await self._fetch_peer_cert(actor_aid)
                cert_pem = cert_pem_bytes.decode("utf-8") if isinstance(cert_pem_bytes, bytes) else str(cert_pem_bytes or "")
                if not cert_pem:
                    self._log.warn("client", "V2 state verify: no cert for actor=%s, group=%s", actor_aid, group_id)
                    raise E2EEError(f"V2 state verify: cannot fetch actor cert for {actor_aid}")

                from cryptography.x509 import load_pem_x509_certificate
                from cryptography.hazmat.primitives.asymmetric import ec as _ec
                from cryptography.hazmat.primitives import hashes as _hashes
                cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
                pub_key = cert.public_key()
                pub_key.verify(sig_bytes, sign_payload, _ec.ECDSA(_hashes.SHA256()))
                self._v2_sig_cache[sig_cache_key] = now_ts + self._V2_SIG_CACHE_TTL
                if len(self._v2_sig_cache) > self._V2_SIG_CACHE_MAX:
                    stale = [k for k, exp in self._v2_sig_cache.items() if exp <= now_ts]
                    for k in stale:
                        self._v2_sig_cache.pop(k, None)
                    if len(self._v2_sig_cache) > self._V2_SIG_CACHE_MAX:
                        oldest = sorted(self._v2_sig_cache.items(), key=lambda x: x[1])[: self._V2_SIG_CACHE_MAX // 4]
                        for k, _ in oldest:
                            self._v2_sig_cache.pop(k, None)
                self._log.debug("client", "V2 state signature verified: group=%s sv=%d actor=%s", group_id, state_version, actor_aid)

            # 验证服务端返回的 member_aids 是否在签名快照中
            try:
                signed_snapshot = json.loads(membership_snapshot) if membership_snapshot.startswith("[") else None
                if signed_snapshot:
                    server_members = set(bootstrap.get("member_aids", []))
                    signed_members = set(signed_snapshot)
                    extra = server_members - signed_members
                    if extra:
                        # 检查是否是 open/invite_code 群（允许 pending）
                        try:
                            req_resp = await self.call("group.get_join_requirements", {"group_id": group_id})
                            mode = str(req_resp.get("mode", "") or "").strip() if isinstance(req_resp, dict) else ""
                        except Exception:
                            mode = ""
                        if mode not in ("open", "invite_code", "invite_only"):
                            self._log.warn("client",
                                "V2 state tamper detected: group=%s pending_extra=%s mode=%s",
                                group_id, sorted(extra), mode)
                            await self._dispatcher.publish("group.v2.state_tampered", {
                                "group_id": group_id,
                                "pending_extra": sorted(extra),
                                "mode": mode,
                            })
            except Exception:
                pass
        except E2EEError:
            raise
        except Exception as exc:
            self._log.warn("client", "V2 state signature verification failed: group=%s err=%s", group_id, exc)
            raise E2EEError(f"V2 state signature verification failed: {exc}")

    async def _v2_check_fork(self, group_id: str, server_chain: str) -> None:
        """分叉检测：比对服务端 state_chain 与本地存储。
        - 本地无记录 → 接受并存储
        - server_chain 为空 → 跳过（state 未初始化）
        - 服务端 chain 与本地一致 → 正常
        - 服务端 chain 不一致 → 发布 group.v2.fork_detected 事件
        """
        if not server_chain:
            return
        try:
            local = self._v2_state_chains.get(group_id)
            if local is None:
                self._v2_state_chains[group_id] = (0, server_chain)
                return
            local_chain = local[1]
            if local_chain == server_chain:
                return
            # 不一致：可能是新 commit 推进了 chain，也可能是分叉
            # 简化策略：尝试通过 get_state 拿当前 state_version 判断
            try:
                state_resp = await self.call("group.get_state", {"group_id": group_id})
                if isinstance(state_resp, dict):
                    server_sv = int(state_resp.get("state_version", 0))
                    local_sv = local[0]
                    if server_sv > local_sv:
                        # 正常推进
                        self._v2_state_chains[group_id] = (server_sv, server_chain)
                        return
                    if server_sv < local_sv:
                        self._log.warn("client", "V2 state chain rollback detected: group=%s server_sv=%d local_sv=%d", group_id, server_sv, local_sv)
            except Exception:
                pass
            # 告警
            self._log.warn("client", "V2 state chain fork detected: group=%s local_chain=%s... server_chain=%s...",
                           group_id, local_chain[:16], server_chain[:16])
            await self._dispatcher.publish("group.v2.fork_detected", {
                "group_id": group_id,
                "local_chain": local_chain,
                "server_chain": server_chain,
            })
        except Exception as exc:
            self._log.debug("client", "V2 fork check failed (non-fatal): %s", exc)

    def _v2_maybe_trigger_auto_propose(self, group_id: str) -> None:
        """lazy sync 路径：发现 pending members 时异步触发 auto propose（fire-and-forget，去重）。"""
        now = time.time()
        last = self._v2_lazy_propose_triggered.get(group_id, 0.0)
        if now - last < 10.0:
            return
        self._v2_lazy_propose_triggered[group_id] = now
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._v2_auto_propose_state(group_id, leader_delay=True))

    async def _v2_auto_propose_state(self, group_id: str, *, leader_delay: bool = False) -> None:
        normalized_group_id = _normalize_group_id(str(group_id or "").strip()) if group_id else ""
        if not normalized_group_id:
            return
        if leader_delay:
            should_continue = await self._v2_auto_propose_leader_delay(normalized_group_id)
            if not should_continue:
                return
        async with self._v2_auto_propose_locks_guard:
            lock = self._v2_auto_propose_locks.get(normalized_group_id)
            if lock is None:
                lock = asyncio.Lock()
                self._v2_auto_propose_locks[normalized_group_id] = lock
        async with lock:
            await self._do_v2_auto_propose_state(normalized_group_id)

    async def _v2_auto_propose_leader_delay(self, group_id: str) -> bool:
        """事件触发路径的 leader 选举：仅在线 owner/admin 参与，leader 立即提案，非 leader jitter 后兜底。"""
        try:
            members_resp = await self.call("group.get_online_members", {"group_id": group_id})
            members = members_resp.get("members") or members_resp.get("items") or members_resp.get("online_members") or []
            my_aid = self._aid or ""
            my_role = ""
            online_admin_aids: list[str] = []
            for m in members:
                if not isinstance(m, dict):
                    continue
                aid = str(m.get("aid") or "").strip()
                role = str(m.get("role") or "").strip()
                if not aid:
                    continue
                if "online" in m and not m.get("online"):
                    continue
                if role in ("owner", "admin"):
                    online_admin_aids.append(aid)
                if aid == my_aid:
                    my_role = role
            online_admin_aids = sorted(set(online_admin_aids))
            if my_role not in ("owner", "admin"):
                return False

            bootstrap_resp = await self.call("group.v2.bootstrap", {"group_id": group_id})
            devices = bootstrap_resp.get("devices", []) if isinstance(bootstrap_resp, dict) else []
            online_admin_set = set(online_admin_aids)
            candidates: list[str] = []
            for dev in devices:
                if not isinstance(dev, dict):
                    continue
                aid = str(dev.get("aid") or "").strip()
                device_id = str(dev.get("device_id") or "").strip()
                if aid in online_admin_set and device_id:
                    candidates.append(f"{aid}\x1f{device_id}")
            if not candidates:
                candidates = [f"{aid}\x1f" for aid in online_admin_aids]
            my_key = f"{my_aid}\x1f{self._device_id or ''}"
            if my_key not in candidates:
                candidates.append(my_key)
            leader = sorted(set(candidates))[0]
            if leader == my_key:
                self._log.debug("client", "V2 auto propose leader elected: group=%s leader=%s", group_id, leader)
                return True

            seed = f"{group_id}\0{my_key}".encode("utf-8")
            delay_ms = 2000 + (int.from_bytes(hashlib.sha256(seed).digest()[:4], "big") % 4000)
            self._log.debug(
                "client",
                "V2 auto propose non-leader delay: group=%s leader=%s self=%s delay_ms=%d",
                group_id, leader, my_key, delay_ms,
            )
            await asyncio.sleep(delay_ms / 1000)
            return True
        except Exception as exc:
            self._log.debug("client", "V2 auto propose leader check failed, fallback immediate: group=%s err=%s", group_id, exc)
            return True

    def _v2_verify_committed_state_base(self, group_id: str, state_resp: dict[str, Any]) -> bool:
        current_sv = int(state_resp.get("state_version") or 0)
        if current_sv <= 0:
            return True
        current_sh = str(state_resp.get("state_hash") or "").strip()
        membership_snapshot = str(state_resp.get("membership_snapshot") or "").strip()
        if not current_sh or not membership_snapshot:
            self._log.warn("client", "V2 committed state base incomplete: group=%s sv=%d", group_id, current_sv)
            return False
        try:
            parsed = json.loads(membership_snapshot)
            if not isinstance(parsed, dict):
                self._log.warn("client", "V2 committed state base snapshot is not object: group=%s sv=%d", group_id, current_sv)
                return False
            from .v2.state.commitment import compute_state_commitment
            computed = compute_state_commitment(group_id, current_sv, parsed)
            if computed != current_sh:
                self._log.warn("client", "V2 committed state base hash mismatch: group=%s sv=%d", group_id, current_sv)
                return False
            return True
        except Exception as exc:
            self._log.warn("client", "V2 committed state base verification failed: group=%s sv=%d err=%s", group_id, current_sv, exc)
            return False

    async def _do_v2_auto_propose_state(self, group_id: str) -> None:
        """成员变更后自动 propose state（仅 owner/admin 执行）。

        使用完整 state commitment（覆盖 members+devices, audit_aids, admin_set,
        wrap_protocol 等），防止服务端篡改单个字段。
        """
        try:
            # 获取当前成员列表 + 角色
            members_resp = await self.call("group.get_members", {"group_id": group_id})
            members = members_resp.get("members") or members_resp.get("items") or []
            my_aid = self._aid or ""
            my_role = ""
            member_aids = []
            admin_aids = []
            for m in members:
                if not isinstance(m, dict):
                    continue
                aid = str(m.get("aid") or "").strip()
                role = str(m.get("role") or "").strip()
                if aid:
                    member_aids.append(aid)
                    if role in ("owner", "admin"):
                        admin_aids.append(aid)
                if aid == my_aid:
                    my_role = role

            if my_role not in ("owner", "admin"):
                return

            # 前置检查：如果已有 pending proposal，先尝试 confirm 而非重复 propose
            proposal_resp = await self.call("group.v2.get_proposal", {"group_id": group_id})
            if isinstance(proposal_resp, dict):
                pending_proposal = proposal_resp.get("proposal")
                if isinstance(pending_proposal, dict) and pending_proposal.get("proposal_id"):
                    confirmed = await self._v2_confirm_pending_proposal(group_id)
                    if confirmed:
                        return
                    auto_confirm_at = int(pending_proposal.get("auto_confirm_at") or 0)
                    now_ms = int(time.time() * 1000)
                    if auto_confirm_at > now_ms:
                        wait_s = min((auto_confirm_at - now_ms) / 1000 + 0.5, 35.0)
                        self._log.debug("client", "V2 auto propose: pending proposal exists, waiting %.1fs group=%s", wait_s, group_id)
                        await asyncio.sleep(wait_s)

            # 获取群所有成员的设备列表（V2 bootstrap）
            bootstrap_resp = await self.call("group.v2.bootstrap", {"group_id": group_id})
            all_devices = bootstrap_resp.get("devices", []) if isinstance(bootstrap_resp, dict) else []
            audit_recipients = bootstrap_resp.get("audit_recipients", []) if isinstance(bootstrap_resp, dict) else []
            audit_aids_list = sorted(set(
                str(r.get("aid") or "").strip() for r in audit_recipients if str(r.get("aid") or "").strip()
            ))

            # 按 aid 分组设备
            members_with_devices = {}
            for aid in member_aids:
                members_with_devices[aid] = []
            for dev in all_devices:
                dev_aid = str(dev.get("aid") or "").strip()
                if dev_aid in members_with_devices:
                    members_with_devices[dev_aid].append({
                        "device_id": str(dev.get("device_id") or ""),
                        "ik_fp": str(dev.get("ik_fp") or ""),
                    })

            members_payload = [
                {"aid": aid, "devices": devices}
                for aid, devices in members_with_devices.items()
            ]

            state_payload = {
                "members": members_payload,
                "audit_aids": audit_aids_list,
                "admin_set": {"admin_aids": sorted(admin_aids), "threshold": 1},
                "join_policy_hash": None,
                "recovery_quorum": None,
                "history_policy": "recent_7_days",
                "wrap_protocol": "3DH",
            }

            # 获取当前 state
            state_resp = await self.call("group.get_state", {"group_id": group_id})
            if not isinstance(state_resp, dict):
                return
            if not self._v2_verify_committed_state_base(group_id, state_resp):
                return
            current_sv = int(state_resp.get("state_version", 0))
            current_sh = str(state_resp.get("state_hash", ""))
            key_epoch = int(state_resp.get("key_epoch", 0))

            # 用完整 commitment 算 state_hash
            from .v2.state.commitment import compute_state_commitment
            state_hash = compute_state_commitment(group_id, current_sv + 1, state_payload)

            # 签名 state proposal（绑定完整 state_payload）
            membership_snapshot = json.dumps(state_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if self._v2_auto_propose_last_snapshot.get(group_id) == membership_snapshot:
                return
            current_membership_snapshot = str(state_resp.get("membership_snapshot") or "")
            if current_membership_snapshot and current_membership_snapshot == membership_snapshot:
                self._v2_auto_propose_last_snapshot[group_id] = membership_snapshot
                return
            signature = ""
            identity = self._identity
            if identity and identity.get("private_key_pem"):
                try:
                    from cryptography.hazmat.primitives.asymmetric import ec as _ec
                    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
                    sign_payload = json.dumps({
                        "group_id": group_id,
                        "state_version": current_sv + 1,
                        "state_hash": state_hash,
                        "membership_snapshot": membership_snapshot,
                    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                    pk = _ser.load_pem_private_key(identity["private_key_pem"].encode("utf-8"), password=None)
                    sig = pk.sign(sign_payload, _ec.ECDSA(_hashes.SHA256()))
                    signature = base64.b64encode(sig).decode("ascii")
                except Exception as _sig_exc:
                    self._log.debug("client", "propose_state signature failed: %s", _sig_exc)

            propose_result = await self.call("group.v2.propose_state", {
                "group_id": group_id,
                "state_version": current_sv + 1,
                "key_epoch": key_epoch,
                "state_hash": state_hash,
                "prev_state_hash": current_sh,
                "membership_snapshot": membership_snapshot,
                "signature": signature,
                "reason": "membership_changed",
                "auto_confirm_seconds": 30,
            })
            self._log.debug("client", "V2 auto propose_state: group=%s sv=%d", group_id, current_sv + 1)
            # 单 owner/admin 签即可生效：propose 成功后立即 confirm
            proposal_id = ""
            if isinstance(propose_result, dict):
                proposal_id = str(propose_result.get("proposal_id") or "").strip()
            if proposal_id:
                try:
                    await self.call("group.v2.confirm_state", {"proposal_id": proposal_id})
                    self._v2_auto_propose_last_snapshot[group_id] = membership_snapshot
                    self._log.debug("client", "V2 auto confirm_state: group=%s proposal=%s", group_id, proposal_id)
                except Exception as confirm_exc:
                    self._log.debug("client", "V2 auto confirm_state failed (non-fatal): group=%s err=%s", group_id, confirm_exc)
        except Exception as exc:
            self._log.debug("client", "V2 auto propose_state failed (non-fatal): group=%s err=%s", group_id, exc)

    def _v2_verify_pending_proposal_against_base(
        self,
        group_id: str,
        proposal: dict[str, Any],
        state_resp: dict[str, Any],
    ) -> bool:
        if not self._v2_verify_committed_state_base(group_id, state_resp):
            return False
        current_sv = int(state_resp.get("state_version") or 0)
        current_sh = str(state_resp.get("state_hash") or "").strip()
        proposal_sv = int(proposal.get("state_version") or 0)
        proposal_hash = str(proposal.get("state_hash") or "").strip()
        proposal_prev = str(proposal.get("prev_state_hash") or "").strip()
        membership_snapshot = str(proposal.get("membership_snapshot") or "").strip()
        if proposal_sv != current_sv + 1 or proposal_prev != current_sh or not proposal_hash or not membership_snapshot:
            self._log.warn(
                "client",
                "V2 pending proposal base mismatch: group=%s current_sv=%d proposal_sv=%d",
                group_id, current_sv, proposal_sv,
            )
            return False
        try:
            parsed = json.loads(membership_snapshot)
            if not isinstance(parsed, dict):
                return False
            from .v2.state.commitment import compute_state_commitment
            computed = compute_state_commitment(group_id, proposal_sv, parsed)
            if computed != proposal_hash:
                self._log.warn("client", "V2 pending proposal hash mismatch: group=%s proposal_sv=%d", group_id, proposal_sv)
                return False
            return True
        except Exception as exc:
            self._log.warn("client", "V2 pending proposal verification failed: group=%s err=%s", group_id, exc)
            return False

    async def _v2_confirm_pending_proposal(self, group_id: str) -> bool:
        proposal_resp = await self.call("group.v2.get_proposal", {"group_id": group_id})
        proposal = proposal_resp.get("proposal") if isinstance(proposal_resp, dict) else None
        if not isinstance(proposal, dict):
            return False
        proposal_id = str(proposal.get("proposal_id") or "").strip()
        if not proposal_id:
            return False

        state_resp = await self.call("group.get_state", {"group_id": group_id})
        if not isinstance(state_resp, dict):
            return False
        current_sv = int(state_resp.get("state_version") or 0)
        proposal_sv = int(proposal.get("state_version") or 0)
        if proposal_sv <= current_sv:
            self._log.debug(
                "client",
                "V2 pending proposal already settled: group=%s current_sv=%d proposal_sv=%d",
                group_id, current_sv, proposal_sv,
            )
            return False
        if not self._v2_verify_pending_proposal_against_base(group_id, proposal, state_resp):
            return False

        await self.call("group.v2.confirm_state", {"proposal_id": proposal_id})
        self._log.info("client", "V2 confirmed pending proposal: group=%s proposal=%s", group_id, proposal_id)
        return True

    async def _v2_auto_confirm_pending_proposals(self) -> None:
        """Owner/admin 上线时自动检查：confirm pending proposals 或发起新 propose。"""
        try:
            my_aid = self._aid or ""
            if not my_aid:
                return
            groups_resp = await self.call("group.list_my", {})
            groups = groups_resp.get("groups") or groups_resp.get("items") or []
            for g in groups:
                if not isinstance(g, dict):
                    continue
                group_id = str(g.get("group_id") or "").strip()
                my_role = str(g.get("role") or g.get("my_role") or "").strip()
                if not group_id or my_role not in ("owner", "admin"):
                    continue
                try:
                    confirmed = await self._v2_confirm_pending_proposal(group_id)
                    if not confirmed:
                        # 没有 pending proposal，检查是否有 pending members 需要发起新 propose
                        await self._v2_auto_propose_state(group_id)
                except Exception as exc:
                    self._log.debug("client", "V2 auto confirm/propose failed (non-fatal): group=%s err=%s", group_id, exc)
        except Exception as exc:
            self._log.debug("client", "V2 auto confirm pending proposals failed (non-fatal): %s", exc)

    async def _on_v2_state_proposed(self, data: Any) -> None:
        if not isinstance(data, dict) or not self._v2_session:
            return
        group_id = str(data.get("group_id") or "").strip()
        if not group_id:
            return
        await self._dispatcher.publish("group.v2.state_proposed", data)
        try:
            await self._v2_confirm_pending_proposal(group_id)
        except Exception as exc:
            self._log.debug("client", "V2 state_proposed handling failed (non-fatal): group=%s err=%s", group_id, exc)

    async def _on_v2_state_retry_needed(self, data: Any) -> None:
        if not isinstance(data, dict) or not self._v2_session:
            return
        group_id = str(data.get("group_id") or "").strip()
        if not group_id:
            return
        await self._dispatcher.publish("group.v2.state_retry_needed", data)
        try:
            await self._v2_auto_propose_state(group_id, leader_delay=True)
        except Exception as exc:
            self._log.debug("client", "V2 state_retry_needed handling failed (non-fatal): group=%s err=%s", group_id, exc)

    async def _on_v2_state_confirmed(self, data: Any) -> None:
        if not isinstance(data, dict):
            return
        group_id = str(data.get("group_id") or "").strip()
        if group_id:
            self._v2_bootstrap_cache.pop(f"group:{group_id}", None)
            self._v2_auto_propose_last_snapshot.pop(group_id, None)
        await self._dispatcher.publish("group.v2.state_confirmed", data)

    async def _on_v2_push_notification(self, data: Any) -> None:
        """处理 V2 push 通知：自动 pull + decrypt + emit。
        only one in flight：用 dedup_key 保证同一时间只有一个 pull 在执行。
        """
        if not self._v2_session:
            self._log.debug("client", "_on_v2_push_notification skipped: no v2_session")
            return
        ns = f"p2p:{self._aid}" if self._aid else ""
        after_seq = self._seq_tracker.get_contiguous_seq(ns) if ns else 0
        dedup_key = f"p2p_pull:{ns}"
        if dedup_key in self._gap_fill_done:
            self._log.debug("client", "_on_v2_push_notification skipped: dedup_key=%s already in flight", dedup_key)
            return
        self._gap_fill_done[dedup_key] = time.time()
        self._log.debug("client", "_on_v2_push_notification executing: dedup_key=%s after_seq=%d", dedup_key, after_seq)
        try:
            await self._pull_v2_internal({})
            self._log.debug("client", "_on_v2_push_notification pull done, new contiguous=%d", self._seq_tracker.get_contiguous_seq(ns) if ns else -1)
        except Exception as exc:
            self._log.warn("client", "V2 push auto-pull failed: %s", exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)

    async def _decrypt_v2_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """解密单条 V2 消息。

        Args:
            msg: pull 返回的消息行（含 envelope_json, from_aid, seq 等）

        Returns:
            解密后的应用层消息 dict，或 None（解密失败）
        """
        envelope_json = msg.get("envelope_json", "")
        if not envelope_json:
            return None
        try:
            envelope = json.loads(envelope_json)
        except (json.JSONDecodeError, TypeError):
            self._log.warn("client", "V2 decrypt: invalid envelope_json for msg seq=%s", msg.get("seq"))
            return None

        # 确定 spk_id
        if "recipient" in envelope:
            spk_id = envelope["recipient"].get("spk_id", "")
        elif "recipients" in envelope:
            spk_id = msg.get("spk_id", "")
        else:
            spk_id = ""

        self._log.info("client", "DEBUG _decrypt_v2_message: seq=%s spk_id=%s from=%s has_recipient=%s has_recipients=%s",
                       msg.get("seq"), spk_id or "<empty>", msg.get("from_aid", ""),
                       "recipient" in envelope, "recipients" in envelope)

        ik_priv, spk_priv = self._v2_session.get_decrypt_keys(spk_id)
        self._log.info("client", "DEBUG _decrypt_v2_message: ik_priv=%d bytes spk_priv=%s",
                       len(ik_priv) if ik_priv else 0, f"{len(spk_priv)} bytes" if spk_priv else "None")

        # 获取 sender IK 公钥（按 sender device_id 精确匹配）
        from_aid = msg.get("from_aid", "")
        sender_device_id = envelope.get("aad", {}).get("from_device", "")
        sender_pub_der = self._v2_session.get_peer_ik(from_aid, sender_device_id)
        if not sender_pub_der:
            # 尝试 bootstrap 获取（V2 设备列表）
            try:
                bs = await self.call("message.v2.bootstrap", {"peer_aid": from_aid})
                for dev in bs.get("peer_devices", []):
                    dev_id = dev.get("device_id") or dev.get("owner_device_id", "")
                    ik_der = base64.b64decode(dev["ik_pk"])
                    self._v2_session.cache_peer_ik(from_aid, dev_id, ik_der)
                # 重新查找精确匹配的 sender device IK
                sender_pub_der = self._v2_session.get_peer_ik(from_aid, sender_device_id)
            except Exception as exc:
                self._log.warn("client", "V2 decrypt: bootstrap for sender %s failed: %s", from_aid, exc)

        # CA fallback：bootstrap 拿不到对端 SPK 时（对端从未 V2 上线 / 不同 device），
        # 从 CA 拉对端 AID 证书 → 公钥即 IK 公钥（V2 设计：IK = AID 长期密钥）
        if not sender_pub_der and from_aid:
            try:
                cert_pem = await self._fetch_peer_cert(from_aid)
                if cert_pem:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization as _ser
                    cert = x509.load_pem_x509_certificate(cert_pem)
                    sender_pub_der = cert.public_key().public_bytes(
                        encoding=_ser.Encoding.DER,
                        format=_ser.PublicFormat.SubjectPublicKeyInfo,
                    )
                    # 缓存到 V2 session（同一 AID 的所有 device 共享 IK）
                    if sender_device_id:
                        self._v2_session.cache_peer_ik(from_aid, sender_device_id, sender_pub_der)
                    self._log.debug("client", "V2 decrypt: sender IK fallback from CA cert for %s", from_aid)
            except Exception as exc:
                self._log.warn("client", "V2 decrypt: CA fallback for %s failed: %s", from_aid, exc)

        if not sender_pub_der:
            self._log.warn("client", "V2 decrypt: no sender IK for %s, cannot verify signature", from_aid)
            await self._dispatcher.publish("message.undecryptable", {
                "message_id": msg.get("message_id", ""),
                "from": from_aid,
                "seq": msg.get("seq"),
                "_decrypt_error": "sender_ik_not_found",
            })
            return None

        try:
            plaintext = v2_decrypt_message(
                envelope=envelope,
                self_aid=self._aid,
                self_device_id=self._device_id,
                self_ik_priv=ik_priv,
                self_spk_priv=spk_priv,
                sender_pub_der=sender_pub_der,
            )
        except Exception as exc:
            self._log.warn("client", "V2 decrypt failed for msg seq=%s: %s", msg.get("seq"), exc)
            await self._dispatcher.publish("message.undecryptable", {
                "message_id": msg.get("message_id", ""),
                "from": from_aid,
                "seq": msg.get("seq"),
                "_decrypt_error": str(exc),
            })
            return None

        if plaintext is None:
            return None

        # SPK 轮换：当前活跃 SPK 被消费后立即轮换（后台执行，不阻塞消息处理）
        self._log.info("client", "DEBUG SPK rotation check: spk_id=%s current=%s is_current=%s",
                       spk_id, self._v2_session._spk_id, self._v2_session.is_current_spk(spk_id))
        if self._v2_session.is_current_spk(spk_id):
            async def _do_rotate():
                try:
                    await self._v2_session.rotate_spk(self.call)
                    self._log.debug("client", "V2 SPK rotated after consumption: aid=%s", self._aid)
                except Exception as exc:
                    self._log.warn("client", "V2 SPK rotation failed (non-fatal): %s", exc)
            loop = self._loop or asyncio.get_running_loop()
            loop.create_task(_do_rotate())

        return {
            "message_id": msg.get("message_id", ""),
            "from": from_aid,
            "to": self._aid,
            "seq": msg.get("seq"),
            "t_server": msg.get("t_server"),
            "payload": plaintext,
            "encrypted": True,
            "e2ee": {
                "version": "v2",
                "suite": envelope.get("suite", ""),
                "encryption_mode": "v2_" + envelope.get("suite", "unknown"),
                "forward_secrecy": True,
            },
        }
