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
from .e2ee import E2EEManager, GroupE2EEManager, ProtectedHeaders
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
        # 由 set_local_agent_md_path() 设置；用于跟服务端 RPC 注入的 _meta.agent_md_etag 比对，
        # 触发"本地未发布到服务端"或"服务端版本更新"的 UI 提示。
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
        self._e2ee = E2EEManager(
            identity_fn=lambda: self._identity or {},
            device_id_fn=lambda: self._device_id,
            keystore=keystore,
            replay_window_seconds=self._config_model.replay_window_seconds,
            logger=self._log,
        )
        self._group_e2ee = GroupE2EEManager(
            identity_fn=lambda: self._identity or {},
            keystore=keystore,
            sender_cert_resolver=lambda aid: self._get_verified_peer_cert(aid),
            initiator_cert_resolver=lambda aid: self._get_verified_peer_cert(aid),
            logger=self._log,
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
        # 已发布到应用层的 seq 集合（按命名空间），补洞/pull 路径 publish 前检查以避免重复分发。
        # 字段名保留 _pushed_seqs 以兼容既有测试和内部引用。
        self._pushed_seqs: dict[str, set[int]] = {}
        # 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq）
        self._pending_ordered_msgs: dict[str, dict[int, tuple[str, Any]]] = {}
        # 群惰性同步标志：只有收到推送或主动 pull 后才标记为已同步
        # 发送消息前如果未同步，先做一次 pull
        self._group_synced: set[str] = set()
        # PY-001: 解密失败的群消息待重试队列（按 namespace 分组）
        self._pending_decrypt_msgs: dict[str, list[dict[str, Any]]] = {}
        # recovery 兜底定时去重：每个 group 在 30s 内最多调度一次"超时强制推进"任务
        self._recovery_timeout_scheduled: dict[str, float] = {}
        self._group_epoch_rotation_inflight: set[str] = set()
        self._group_epoch_rotation_retry_tasks: dict[str, asyncio.Task] = {}
        self._group_epoch_recovery_inflight: dict[str, asyncio.Future[bool]] = {}
        self._group_membership_rotation_done: set[str] = set()
        self._group_member_key_backfill_done: set[str] = set()

        self.auth = AuthNamespace(self)
        self.custody = CustodyNamespace(self)
        self.meta = MetaNamespace(self)
        # V2 E2EE session（延迟初始化，connect 后才有 aid）
        self._v2_session: V2Session | None = None
        # V2 state chain 本地存储（分叉检测）：group_id -> (state_version, state_chain)
        self._v2_state_chains: dict[str, tuple[int, str]] = {}
        # 内部订阅：推送消息自动解密后 re-publish 给用户
        self._dispatcher.subscribe("_raw.message.received", self._on_raw_message_received)
        # V2 P2P 推送通知
        self._dispatcher.subscribe("_raw.peer.v2.message_received", self._on_v2_push_notification)
        # 群组消息推送：自动解密后 re-publish
        self._dispatcher.subscribe("_raw.group.message_created", self._on_raw_group_message_created)
        # 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
        self._dispatcher.subscribe("_raw.group.changed", self._on_raw_group_changed)
        # V2 epoch 轮换事件：清除 bootstrap 缓存 + 触发 SPK rotation
        self._dispatcher.subscribe("_raw.group.v2.epoch_rotated", self._on_v2_epoch_rotated)
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

    def set_local_agent_md_path(self, path: str | None) -> str:
        """记录本地 agent.md 文件路径并一次性计算 etag（quoted sha256，与服务端一致）。

        - path 为空字符串 / None：清除本地 path 与 etag。
        - 文件不存在 / 读取失败：清除 etag 并返回空串，不抛异常（应用可读 get_local_agent_md_etag()
          为空判断）。
        - 文件变更后需要重新调用 set_local_agent_md_path() 触发重算（按设计：设置时一次性计算）。

        返回当前 etag（quoted hex 或空串）。
        """
        raw_path = str(path or "").strip()
        if not raw_path:
            self._local_agent_md_path = ""
            self._local_agent_md_etag = ""
            return ""
        self._local_agent_md_path = raw_path
        try:
            with open(raw_path, "rb") as f:
                data = f.read()
            digest = hashlib.sha256(data).hexdigest()
            self._local_agent_md_etag = f'"{digest}"'
        except OSError as exc:
            self._log.warn("client", "set_local_agent_md_path 读取失败 path=%s err=%s", raw_path, exc)
            self._local_agent_md_etag = ""
        return self._local_agent_md_etag

    def get_local_agent_md_etag(self) -> str:
        """返回 set_local_agent_md_path 计算的 etag；未设置或读取失败时返回空串。"""
        return self._local_agent_md_etag

    def get_remote_agent_md_etag(self) -> str:
        """返回 gateway 在最近一次 RPC envelope._meta 注入的服务端 agent.md etag。

        未收到过则为空串；不阻塞调用，纯内存读。
        """
        return getattr(self, "_remote_agent_md_etag", "") or ""

    def _observe_rpc_meta(self, meta: dict) -> None:
        """transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。"""
        if not isinstance(meta, dict):
            return
        etag = str(meta.get("agent_md_etag") or "").strip()
        if etag:
            self._remote_agent_md_etag = etag

    def _local_issuer_domain(self) -> str:
        """从本地 AID 提取 issuer 域名（{name}.{issuer}）。"""
        aid = self._aid or ""
        if not aid or "." not in aid:
            return ""
        return aid.split(".", 1)[1].strip(".").lower()

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

    async def call(self, method: str, params: dict | None = None) -> Any:
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

        # 自动加密：message.send 默认加密（encrypt 默认 True）
        if method == "message.send":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                self._log.debug("client", "call encrypt branch: method=message.send to=%s", params.get("to", "-"))
                try:
                    result = await self._send_encrypted(params)
                    self._log.debug("client", "call exit (encrypted): elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
                    return result
                except Exception as exc:
                    self._log.debug("client", "call exit (encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                    raise
            # encrypt=false：明文走通用 RPC 路径；protected_headers/headers 是信封元数据，加密与否都保留
            self._maybe_append_echo_trace_send(params)

        # 自动加密：group.send 默认加密（encrypt 默认 True）
        if method == "group.send":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                self._log.debug("client", "call encrypt branch: method=group.send group_id=%s", params.get("group_id", "-"))
                try:
                    result = await self._send_group_encrypted(params)
                    self._log.debug("client", "call exit (group-encrypted): elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
                    return result
                except Exception as exc:
                    self._log.debug("client", "call exit (group-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                    raise
            # encrypt=false：明文走通用 RPC 路径，不受 group epoch 轮换/恢复约束
            self._maybe_append_echo_trace_send(params)
        if method == "group.thought.put":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                try:
                    result = await self._put_group_thought_encrypted(params)
                    self._log.debug("client", "call exit (thought-encrypted): elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
                    return result
                except Exception as exc:
                    self._log.debug("client", "call exit (thought-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                    raise
            # encrypt=false：明文走通用 RPC 路径
        if method == "message.thought.put":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                try:
                    result = await self._put_message_thought_encrypted(params)
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
        try:
            result = await self._transport.call(method, params, **call_kwargs)
        except TypeError as exc:
            if call_kwargs and "unexpected keyword argument 'timeout'" in str(exc):
                result = await self._transport.call(method, params)
            else:
                self._log.debug("client", "call exit (error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                raise
        except Exception as exc:
            self._log.debug("client", "call exit (error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
            raise

        # 自动解密：message.pull 返回的消息
        if method == "message.pull" and isinstance(result, dict):
            messages = result.get("messages")
            ns = f"p2p:{self._aid}" if self._aid else ""
            if isinstance(messages, list) and messages:
                pull_source = "gap_fill" if getattr(self, "_gap_fill_active", False) else "pull"
                result["messages"] = await self._decrypt_messages(messages, source=pull_source)
                if self._aid and getattr(self, "_seq_tracker", None) is not None:
                    self._seq_tracker.on_pull_result(ns, messages)
            if self._aid and getattr(self, "_seq_tracker", None) is not None:
                # P2P retention floor 即使本次没有消息也必须生效，否则空拉时的历史 gap 会一直悬挂。
                server_ack = int(result.get("server_ack_seq") or 0)
                if server_ack > 0:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig < server_ack:
                        self._log.info("client", 
                            "message.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d",
                            ns, contig, server_ack,
                        )
                        self._seq_tracker.force_contiguous_seq(ns, server_ack)
                self._persist_seq(ns)
                # auto-ack：ack contiguous_seq
                contig = self._seq_tracker.get_contiguous_seq(ns)
                should_ack = bool(isinstance(messages, list) and messages) or server_ack > 0
                if contig > 0 and should_ack:
                    try:
                        await self._transport.call("message.ack", {
                            "seq": contig, "device_id": self._device_id, "slot_id": self._slot_id,
                        })
                    except Exception as _ack_exc:
                        self._log.debug("client", "message.pull auto-ack failed: %s", _ack_exc)

        # 自动解密：group.pull 返回的群消息
        if method == "group.pull" and isinstance(result, dict):
            messages = result.get("messages")
            gid = (params or {}).get("group_id", "")
            ns = f"group:{gid}" if gid else ""
            decrypted_messages: list = []
            failed_count = 0
            if isinstance(messages, list) and messages:
                result["messages"] = await self._decrypt_group_messages(messages)
                # 区分解密成功 / 失败：失败的 payload 仍是 e2ee.group_encrypted；
                # 成功后 ApplyGroupDecryptedPayload 会改成明文 type。
                for m in (result["messages"] or []):
                    if not isinstance(m, dict):
                        continue
                    payload = m.get("payload") or {}
                    ptype = payload.get("type") if isinstance(payload, dict) else None
                    if ptype == "e2ee.group_encrypted":
                        failed_count += 1
                        # 失败的入 pending queue，等密钥恢复后 retry
                        if gid:
                            self._enqueue_pending_decrypt(gid, m)
                    else:
                        decrypted_messages.append(m)
                if gid and getattr(self, "_seq_tracker", None) is not None:
                    # 仅用解密成功的消息推进 contig；失败的等 retry 解密成功才推进。
                    self._seq_tracker.on_pull_result(ns, decrypted_messages)
            if gid and getattr(self, "_seq_tracker", None) is not None:
                # group retention floor 由 cursor.current_seq 表达，也需要在空拉时推进。
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
                self._persist_seq(ns)
                # auto-ack：仅在没有解密失败时 auto-ack；
                # 有失败时让服务端 cursor 留在原位等 retry。
                contig = self._seq_tracker.get_contiguous_seq(ns)
                should_ack = failed_count == 0 and (
                    bool(decrypted_messages) or (
                        isinstance(cursor, dict) and int(cursor.get("current_seq") or 0) > 0
                    )
                )
                if contig > 0 and should_ack:
                    try:
                        await self._transport.call("group.ack_messages", {
                            "group_id": gid, "msg_seq": contig,
                            "device_id": self._device_id,
                            "slot_id": self._slot_id,
                        })
                    except Exception as _ack_exc:
                        self._log.debug("client", "group.pull auto-ack failed: group=%s %s", gid, _ack_exc)
                # 有解密失败时调度 recovery 兜底定时
                if failed_count > 0 and gid:
                    self._schedule_recovery_timeout(gid)

        if method == "group.thought.get" and isinstance(result, dict):
            result = await self._decrypt_group_thoughts(result)
        if method == "message.thought.get" and isinstance(result, dict):
            result = await self._decrypt_message_thoughts(result)

        # ── Group E2EE 自动编排 ────────────────────────────
        # 群组 E2EE 是必备能力，始终启用自动编排

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

        # 成员集变更必须触发 epoch 轮换并重新签名发布 member list。
        # 事件路径仍是主路径；RPC 成功返回路径做幂等兜底，避免 group.changed 推送/补洞丢失或延迟时不轮换。
        if method in {
            "group.add_member", "group.kick", "group.remove_member", "group.leave",
            "group.review_join_request", "group.batch_review_join_request",
            "group.use_invite_code", "group.request_join",
        } and isinstance(result, dict):
            gid = self._extract_group_id_from_result(result) or str(params.get("group_id") or "")
            expected_epoch = self._membership_rotation_expected_epoch(result)
            if gid and self._membership_rotation_changed(method, result):
                # 自加入方法（request_join/use_invite_code）需要 allow_member=True，
                # 因为新成员角色是 member，必须允许 member 参与 leader 选举。
                am = method in ("group.request_join", "group.use_invite_code")
                await self._maybe_lead_rotate_group_epoch(
                    gid,
                    reason="membership_changed",
                    trigger_id=self._membership_rotation_trigger_id(gid, result),
                    expected_epoch=expected_epoch,
                    allow_member=am,
                )

        self._log.debug("client", "call exit: elapsed=%.3fs method=%s", time.time() - _t_call_start, method)
        return result



    @staticmethod
    def _membership_rotation_trigger_id(group_id: str, payload: dict[str, Any]) -> str:
        action = str(payload.get("action") or "").strip()
        if not action:
            if payload.get("removed_aid"):
                action = "member_removed"
            elif payload.get("left_aid"):
                action = "member_left"
            elif isinstance(payload.get("member"), dict):
                action = "member_added"
            else:
                action = str(payload.get("status") or payload.get("reason") or "membership_changed")
        event_seq = payload.get("event_seq") or payload.get("seq") or ""
        group = payload.get("group")
        if isinstance(group, dict):
            event_seq = event_seq or group.get("event_seq") or ""
        changed_aids: set[str] = set()
        changed_aid = (
            payload.get("aid") or payload.get("removed_aid") or payload.get("left_aid")
            or payload.get("member_aid") or payload.get("target_aid") or ""
        )
        if changed_aid:
            changed_aids.add(str(changed_aid))
        member = payload.get("member")
        if isinstance(member, dict):
            changed_aid = changed_aid or member.get("aid") or ""
            if member.get("aid"):
                changed_aids.add(str(member.get("aid")))
        request = payload.get("request")
        if isinstance(request, dict):
            changed_aid = changed_aid or request.get("aid") or ""
            if request.get("aid"):
                changed_aids.add(str(request.get("aid")))
        invite_code = payload.get("invite_code")
        if isinstance(invite_code, dict):
            changed_aid = changed_aid or invite_code.get("used_by") or invite_code.get("aid") or ""
            for key in ("used_by", "aid"):
                if invite_code.get(key):
                    changed_aids.add(str(invite_code.get(key)))
        results = payload.get("results")
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                item_status = str(item.get("status") or "").strip().lower()
                if item_status != "approved" and not bool(item.get("approved")):
                    continue
                for key in ("aid", "member_aid", "target_aid"):
                    if item.get(key):
                        changed_aids.add(str(item.get(key)))
                for key in ("member", "request"):
                    nested = item.get(key)
                    if isinstance(nested, dict) and nested.get("aid"):
                        changed_aids.add(str(nested.get("aid")))
        changed_aid_key = ",".join(sorted(aid for aid in changed_aids if aid))
        expected_epoch = AUNClient._membership_rotation_expected_epoch(payload)
        if changed_aid_key and expected_epoch is not None:
            return f"{group_id}:{action}:aid:{changed_aid_key}:epoch:{expected_epoch}"
        if event_seq:
            return f"{group_id}:{action}:event:{event_seq}"
        return f"{group_id}:{action}:aid:{changed_aid_key or changed_aid or '-'}"

    @staticmethod
    def _membership_rotation_changed(method: str, payload: dict[str, Any]) -> bool:
        """判断 RPC 成功返回是否真的意味着成员集合变更。"""
        if method in {"group.add_member", "group.kick", "group.remove_member", "group.leave"}:
            return True
        status = str(payload.get("status") or "").strip().lower()
        if method in {"group.use_invite_code", "group.request_join"}:
            return status in {"joined", "approved"} or isinstance(payload.get("member"), dict)
        if method == "group.review_join_request":
            return status == "approved" or bool(payload.get("approved")) or isinstance(payload.get("member"), dict)
        if method == "group.batch_review_join_request":
            results = payload.get("results")
            if not isinstance(results, list):
                return False
            for item in results:
                if not isinstance(item, dict):
                    continue
                item_status = str(item.get("status") or "").strip().lower()
                if item_status == "approved" or bool(item.get("approved")):
                    return True
            return False
        return False

    @staticmethod
    def _membership_rotation_expected_epoch(payload: dict[str, Any]) -> int | None:
        for key in ("old_epoch", "current_epoch", "e2ee_epoch"):
            value = payload.get(key)
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    pass
        group = payload.get("group")
        if isinstance(group, dict):
            value = group.get("old_epoch", group.get("current_epoch", group.get("e2ee_epoch")))
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    pass
        return None

    @staticmethod
    def _extract_group_id_from_result(result: dict[str, Any]) -> str:
        group = result.get("group")
        if isinstance(group, dict):
            gid = str(group.get("group_id") or "").strip()
            if gid:
                return gid
        for key in ("group_id",):
            gid = str(result.get(key) or "").strip()
            if gid:
                return gid
        member = result.get("member")
        if isinstance(member, dict):
            gid = str(member.get("group_id") or "").strip()
            if gid:
                return gid
        return ""

    async def _get_group_member_aids(self, group_id: str) -> list[str]:
        members_result = await self.call("group.get_members", {"group_id": group_id})
        raw_list = members_result.get("members") or members_result.get("items") if isinstance(members_result, dict) else []
        if not isinstance(raw_list, list):
            return []
        member_aids: list[str] = []
        for item in raw_list:
            if isinstance(item, dict):
                aid = str(item.get("aid") or "").strip()
                if aid:
                    member_aids.append(aid)
        return sorted(set(member_aids))

    def _local_group_members_match(self, group_id: str, member_aids: list[str]) -> bool:
        secret_data = self._group_e2ee.load_secret(group_id)
        if not secret_data:
            return False
        local_members = sorted(set(str(aid) for aid in secret_data.get("member_aids", []) if aid))
        return local_members == sorted(set(member_aids))

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
            self._log.warn("client", "failed to publish e2ee orchestration event: %s", _pub_exc)

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

    async def _send_encrypted(self, params: dict[str, Any]) -> Any:
        """自动加密并发送消息。首次失败时若为对端材料错误则刷新缓存重试一次。"""
        import time as _time
        import uuid as _uuid

        _t_start = _time.time()
        to_aid = params.get("to")
        self._validate_message_recipient(to_aid)
        payload = params.get("payload")
        message_id = params.get("message_id") or str(_uuid.uuid4())
        timestamp = params.get("timestamp") or int(_time.time() * 1000)
        self._log.debug("client", "_send_encrypted enter: to=%s message_id=%s", to_aid, message_id)

        # 惰性 P2P 同步：connect 完成后由 _start_background_tasks 异步触发一次，
        # 与 C++ FillP2PGap 行为对齐。这里不再 await 阻塞用户发送，保持 send 路径轻量。
        # 后续 push gap 检测与 reconnect 钩子负责其余补齐场景。

        persist_required = bool(params.get("persist_required") or params.get("durable"))
        protected_headers = self._protected_headers_from_params(params)

        async def _attempt(refresh: bool = False) -> Any:
            recipient_prekeys = (
                await self._refresh_peer_prekeys(to_aid)
                if refresh
                else await self._fetch_peer_prekeys(to_aid)
            )
            self_sync_copies = await self._build_self_sync_copies(
                logical_to_aid=to_aid,
                payload=payload,
                message_id=message_id,
                timestamp=timestamp,
                protected_headers=protected_headers,
            )

            # 统一 multi-device 路径：必须有 recipient prekey
            if not recipient_prekeys:
                raise RuntimeError(f"no registered device prekeys for {to_aid}, cannot send encrypted message")

            recipient_copies = await self._build_recipient_device_copies(
                to_aid=to_aid,
                payload=payload,
                message_id=message_id,
                timestamp=timestamp,
                prekeys=recipient_prekeys,
                protected_headers=protected_headers,
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
            if persist_required:
                send_params["persist_required"] = True
            return await self._transport.call("message.send", send_params)

        try:
            result = await _attempt(False)
            self._log.debug("client", "_send_encrypted exit: elapsed=%.3fs to=%s message_id=%s", _time.time() - _t_start, to_aid, message_id)
            return result
        except Exception as exc:
            if not _is_retryable_peer_material_error(exc):
                self._log.debug("client", "_send_encrypted exit (error): elapsed=%.3fs to=%s message_id=%s err=%s", _time.time() - _t_start, to_aid, message_id, exc)
                raise
            self._log.warn("client",
                "peer cert/prekey mismatch for %s, refreshing and retrying once", to_aid,
            )
        try:
            result = await _attempt(True)
            self._log.debug("client", "_send_encrypted exit (retry): elapsed=%.3fs to=%s message_id=%s", _time.time() - _t_start, to_aid, message_id)
            return result
        except Exception as exc:
            self._log.debug("client", "_send_encrypted exit (retry-error): elapsed=%.3fs to=%s message_id=%s err=%s", _time.time() - _t_start, to_aid, message_id, exc)
            raise

    async def _build_recipient_device_copies(
        self,
        *,
        to_aid: str,
        payload: dict[str, Any],
        message_id: str,
        timestamp: int,
        prekeys: list[dict[str, Any]],
        protected_headers: dict[str, Any] | ProtectedHeaders | None = None,
    ) -> list[dict[str, Any]]:
        prekeys = self._normalize_peer_prekeys(prekeys)
        recipient_copies: list[dict[str, Any]] = []
        cert_cache: dict[str, bytes] = {}
        for prekey in prekeys:
            device_id = str(prekey.get("device_id") or "").strip()
            if not device_id:
                continue
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
                protected_headers=protected_headers,
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
            self._log.debug("client", "failed to extract cert fingerprint: %s", _fp_exc)
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
            self._log.debug("client", "failed to load local cert: %s", _lc_exc)
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
        protected_headers: dict[str, Any] | ProtectedHeaders | None = None,
    ) -> list[dict[str, Any]]:
        my_aid = self._aid
        if not my_aid:
            return []
        prekeys = self._normalize_peer_prekeys(await self._fetch_peer_prekeys(my_aid))
        if not prekeys:
            return []
        copies: list[dict[str, Any]] = []
        for prekey in prekeys:
            device_id = str(prekey.get("device_id") or "").strip()
            if not device_id:
                continue
            if device_id == self._device_id:
                continue
            try:
                peer_cert_pem = await self._resolve_self_copy_peer_cert(
                    str(prekey.get("cert_fingerprint", "") or "").strip().lower() or None,
                )
            except (ValidationError, Exception) as exc:
                # 旧设备的 prekey 可能携带已轮换的证书指纹，跳过该设备的自同步副本
                self._log.warn("client", 
                    "self-sync 跳过设备 %s: 证书解析失败 (%s)，可能是旧 prekey",
                    device_id, exc,
                )
                continue
            envelope, encrypt_result = self._encrypt_copy_payload(
                logical_to_aid=logical_to_aid,
                payload=payload,
                peer_cert_pem=peer_cert_pem,
                prekey=prekey,
                message_id=message_id,
                timestamp=timestamp,
                protected_headers=protected_headers,
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
        protected_headers: dict[str, Any] | ProtectedHeaders | None = None,
        context: dict[str, Any] | None = None,
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
                    protected_headers=protected_headers,
                    context=context,
                )
                return envelope, {
                    "encrypted": True,
                    "forward_secrecy": True,
                    "mode": "prekey_ecdh_v2",
                    "degraded": False,
                }
            except Exception as exc:
                self._log.warn("client", "prekey encryption failed, degrading to long_term_key: %s", exc)

        envelope, _ = self._e2ee._encrypt_with_long_term_key(
            logical_to_aid,
            payload,
            peer_cert_pem,
            message_id=message_id,
            timestamp=timestamp,
            protected_headers=protected_headers,
            context=context,
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
                    self._log.warn("client", "e2ee.degraded event not published: event loop not running")
            except Exception as exc:
                self._log.warn("client", "failed to publish e2ee.degraded event: %s", exc)

    async def _send_group_encrypted(self, params: dict[str, Any]) -> Any:
        """自动加密并发送群组消息。发送前预检本地 epoch 是否与服务端一致。"""
        _t_start = time.time()
        gid = str(params.get("group_id") or "")
        self._log.debug("client", "_send_group_encrypted enter: group_id=%s", gid)
        try:
            result = await self._call_group_encrypted_rpc(
                "group.send",
                params,
                id_field="message_id",
                id_prefix="gm",
            )
            self._log.debug("client", "_send_group_encrypted exit: elapsed=%.3fs group_id=%s", time.time() - _t_start, gid)
            return result
        except Exception as exc:
            self._log.debug("client", "_send_group_encrypted exit (error): elapsed=%.3fs group_id=%s err=%s", time.time() - _t_start, gid, exc)
            raise

    async def _put_group_thought_encrypted(self, params: dict[str, Any]) -> Any:
        return await self._call_group_encrypted_rpc(
            "group.thought.put",
            params,
            id_field="thought_id",
            id_prefix="gt",
            extra_fields=("context",),
        )

    async def _put_message_thought_encrypted(self, params: dict[str, Any]) -> Any:
        to_aid = str(params.get("to") or "").strip()
        self._validate_message_recipient(to_aid)
        payload = params.get("payload")
        if not to_aid:
            raise ValidationError("message.thought.put requires to")
        if not isinstance(payload, dict):
            raise ValidationError("message.thought.put payload must be an object when encrypt=true")

        thought_id = str(params.get("thought_id") or f"mt-{uuid.uuid4()}").strip()
        timestamp = int(params.get("timestamp") or time.time() * 1000)
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
            message_id=thought_id,
            timestamp=timestamp,
            protected_headers=self._protected_headers_from_params(params),
            context=params.get("context") if isinstance(params.get("context"), dict) else None,
        )
        self._ensure_encrypt_result(to_aid, encrypt_result)
        send_params: dict[str, Any] = {
            "to": to_aid,
            "payload": envelope,
            "type": "e2ee.encrypted",
            "encrypted": True,
            "thought_id": thought_id,
            "timestamp": timestamp,
        }
        if "context" in params:
            send_params["context"] = params["context"]
        self._sign_client_operation("message.thought.put", send_params)
        return await self._transport.call("message.thought.put", send_params)

    async def _call_group_encrypted_rpc(
        self,
        method: str,
        params: dict[str, Any],
        *,
        id_field: str,
        id_prefix: str,
        extra_fields: tuple[str, ...] = (),
    ) -> Any:
        self._log.debug(
            "client",
            "_call_group_encrypted_rpc entry method=%s group_id=%s id_field=%s",
            method, str(params.get("group_id") or ""), id_field,
        )
        send_params, group_id = await self._prepare_group_encrypted_rpc_params(
            method,
            params,
            id_field=id_field,
            id_prefix=id_prefix,
            extra_fields=extra_fields,
        )
        for attempt in range(2):
            try:
                result = await self._transport.call(method, send_params)
                self._log.debug(
                    "client",
                    "_call_group_encrypted_rpc completed method=%s group_id=%s attempt=%d",
                    method, group_id, attempt,
                )
                return result
            except AUNError as exc:
                if attempt == 0 and self._is_recoverable_group_epoch_error(exc):
                    self._log.warn("client", "group %s calling %s epoch unavailable, retrying after recovery: %s", group_id, method, exc)
                    send_params, _ = await self._prepare_group_encrypted_rpc_params(
                        method,
                        params,
                        id_field=id_field,
                        id_prefix=id_prefix,
                        extra_fields=extra_fields,
                        strict_epoch_ready=True,
                    )
                    continue
                raise

        raise StateError(f"{method} failed after epoch recovery retry: group={group_id}")

    async def _prepare_group_encrypted_rpc_params(
        self,
        method: str,
        params: dict[str, Any],
        *,
        id_field: str,
        id_prefix: str,
        extra_fields: tuple[str, ...] = (),
        strict_epoch_ready: bool = False,
    ) -> tuple[dict[str, Any], str]:
        group_id = str(params.get("group_id") or "").strip()
        payload = params.get("payload")
        if not group_id:
            raise ValidationError(f"{method} requires group_id")

        self._log.debug(
            "client",
            "_prepare_group_encrypted_rpc_params entry method=%s group_id=%s synced=%s strict_epoch_ready=%s",
            method, group_id, group_id in self._group_synced, strict_epoch_ready,
        )

        if group_id not in self._group_synced:
            await self._lazy_sync_group(group_id)

        await self._ensure_group_epoch_ready(group_id, strict=strict_epoch_ready)
        await self._wait_for_group_membership_epoch_floor(group_id, timeout_s=5.0, strict=True)

        operation_id = str(params.get(id_field) or f"{id_prefix}-{uuid.uuid4()}").strip()
        timestamp = int(params.get("timestamp") or time.time() * 1000)
        epoch_result = await self._committed_group_epoch_state(group_id)
        committed_epoch = int(epoch_result.get("committed_epoch", epoch_result.get("epoch", 0)) or 0)
        protected_headers = self._protected_headers_from_params(params)
        context = params.get("context") if method == "group.thought.put" and isinstance(params.get("context"), dict) else None
        if committed_epoch > 0:
            ready_epoch = await self._ensure_committed_group_secret_for_send(group_id, committed_epoch, epoch_result)
            envelope = self._group_e2ee.encrypt_with_epoch(
                group_id, ready_epoch, payload,
                message_id=operation_id, timestamp=timestamp,
                protected_headers=protected_headers,
                context=context,
            )
        else:
            envelope = self._group_e2ee.encrypt(
                group_id, payload,
                message_id=operation_id, timestamp=timestamp,
                protected_headers=protected_headers,
                context=context,
            )
        send_params: dict[str, Any] = {
            "group_id": group_id,
            "payload": envelope,
            "type": "e2ee.group_encrypted",
            "encrypted": True,
            id_field: operation_id,
            "timestamp": timestamp,
        }
        for field in extra_fields:
            if field in params:
                send_params[field] = params[field]
        self._sign_client_operation(method, send_params)
        return send_params, group_id

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


    @staticmethod
    def _is_group_epoch_too_old_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            "e2ee epoch too old" in text
            or "epoch below sender membership floor" in text
        )

    @staticmethod
    def _is_group_epoch_rotation_pending_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return "e2ee epoch rotation pending" in text or "e2ee epoch not committed" in text

    @staticmethod
    def _is_group_epoch_changed_during_send_error(exc: Exception) -> bool:
        return "e2ee epoch changed during send" in str(exc).lower()

    @classmethod
    def _is_recoverable_group_epoch_error(cls, exc: Exception) -> bool:
        return (
            cls._is_group_epoch_too_old_error(exc)
            or cls._is_group_epoch_rotation_pending_error(exc)
            or cls._is_group_epoch_changed_during_send_error(exc)
        )

    @staticmethod
    def _is_expected_group_rotation_skip_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            "is not a member" in text
            or "client is not connected" in text
            or "not connected" in text
        )

    @staticmethod
    def _extract_group_join_mode(payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        for key in ("join_mode", "mode"):
            value = str(payload.get(key) or "").strip().lower()
            if value:
                return value
        for key in ("join_requirements", "join"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                value = str(nested.get("mode") or nested.get("join_mode") or "").strip().lower()
                if value:
                    return value
        group = payload.get("group")
        if isinstance(group, dict):
            value = AUNClient._extract_group_join_mode(group)
            if value:
                return value
        settings = payload.get("settings")
        if isinstance(settings, dict):
            for key in ("join.mode", "join_mode", "mode"):
                value = str(settings.get(key) or "").strip().lower()
                if value:
                    return value
        if isinstance(settings, list):
            for item in settings:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("key") or item.get("name") or "").strip().lower()
                if key in {"join.mode", "join_mode", "mode"}:
                    value = str(item.get("value") or "").strip().lower()
                    if value:
                        return value
        return ""

    @staticmethod
    def _join_mode_allows_member_epoch_rotation(mode: str) -> bool:
        return str(mode or "").strip().lower() in {"open", "invite_only", "invite_code"}

    async def _group_allows_member_epoch_rotation(self, group_id: str) -> bool:
        """仅 open / invite code 群允许普通成员参与轮换及服务端 epoch key 存取。"""
        try:
            resp = await self.call("group.get_join_requirements", {"group_id": group_id})
            mode = self._extract_group_join_mode(resp)
            if mode:
                return self._join_mode_allows_member_epoch_rotation(mode)
        except Exception as exc:
            self._log.debug("client", "failed to read group join mode: group=%s method=get_join_requirements err=%s", group_id, exc)
        try:
            resp = await self.call("group.get_settings", {
                "group_id": group_id,
                "keys": ["join.mode"],
            })
            mode = self._extract_group_join_mode(resp)
            if mode:
                return self._join_mode_allows_member_epoch_rotation(mode)
        except Exception as exc:
            self._log.debug("client", "failed to read group settings: group=%s method=get_settings err=%s", group_id, exc)
        try:
            resp = await self.call("group.get", {"group_id": group_id})
            mode = self._extract_group_join_mode(resp)
            if mode:
                return self._join_mode_allows_member_epoch_rotation(mode)
        except Exception as exc:
            self._log.debug("client", "failed to read group info: group=%s method=get err=%s", group_id, exc)
        return False

    def _group_key_recovery_candidates(self, group_id: str, epoch_result: dict[str, Any]) -> list[str]:
        candidates: list[str] = []

        def add(value: Any) -> None:
            if isinstance(value, str):
                aid = value.strip()
                if aid and aid != self._aid and aid not in candidates:
                    candidates.append(aid)

        for key in ("rotated_by", "owner_aid"):
            add(epoch_result.get(key))
        for key in ("recovery_candidates", "admins", "members"):
            values = epoch_result.get(key)
            if isinstance(values, list):
                for value in values:
                    add(value)
                    if isinstance(value, dict):
                        add(value.get("aid"))
        for aid in self._group_e2ee.get_member_aids(group_id):
            add(aid)
        return candidates

    async def _request_group_key_from_candidates(
        self, group_id: str, server_epoch: int, epoch_result: dict[str, Any]
    ) -> None:
        candidates = self._group_key_recovery_candidates(group_id, epoch_result)
        for target_aid in candidates:
            await self._request_group_key_from(group_id, target_aid, epoch=server_epoch)

    async def _recover_initial_group_epoch_if_needed(
        self,
        group_id: str,
        local_epoch: int,
        epoch_result: dict[str, Any],
    ) -> dict[str, Any]:
        """恢复建群后本地 epoch 1 已创建、服务端 epoch 仍为 0 的崩溃窗口。"""
        server_epoch = int(epoch_result.get("epoch", 0) if isinstance(epoch_result, dict) else 0)
        if server_epoch != 0 or local_epoch != 1:
            return epoch_result
        secret_data = self._group_e2ee.load_secret(group_id, 1)
        if not isinstance(secret_data, dict) or secret_data.get("pending_rotation_id"):
            return epoch_result
        self._log.warn("client",
            "group %s detected local epoch 1 exists but server epoch still 0, attempting initial epoch sync",
            group_id,
        )
        await self._sync_epoch_to_server(group_id)
        try:
            refreshed = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
            if isinstance(refreshed, dict):
                return refreshed
        except Exception as exc:
            self._log.warn("client", "group %s initial epoch sync refresh failed: %s", group_id, exc)
        return epoch_result

    async def _recover_group_epoch_key(
        self,
        group_id: str,
        epoch: int,
        *,
        sender_aid: str = "",
        timeout_s: float = 5.0,
    ) -> bool:
        _t_start = time.time()
        self._log.debug("client", "_recover_group_epoch_key enter: group=%s epoch=%s sender=%s timeout=%.1fs", group_id, epoch, sender_aid or "-", timeout_s)
        existing = self._group_e2ee.load_secret(group_id, epoch)
        _debug_group_e2ee(
            "recover_enter",
            aid=self._aid or "",
            group=group_id,
            epoch=epoch,
            sender=sender_aid or "-",
            has_local=bool(existing),
            local_pending=str(existing.get("pending_rotation_id") or "-") if isinstance(existing, dict) else "-",
        )
        if await self._group_epoch_secret_ready_for_recovery(group_id, epoch, existing):
            self._log.debug("client",
                "group epoch key recovery skipped: group=%s epoch=%s key already local", group_id, epoch,
            )
            _debug_group_e2ee(
                "recover_skip_ready",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
            )
            self._schedule_retry_pending_decrypt_msgs(group_id)
            self._log.debug("client", "_recover_group_epoch_key exit (already-ready): elapsed=%.3fs group=%s epoch=%s", time.time() - _t_start, group_id, epoch)
            return True

        # inflight 去重：同 group_id:epoch 的并发恢复共享同一个 Future
        key = f"{group_id}:{epoch}"
        inflight = self._group_epoch_recovery_inflight.get(key)
        if inflight is not None:
            self._log.info("client",
                "group epoch key recovery reusing inflight request: group=%s epoch=%s", group_id, epoch,
            )
            _debug_group_e2ee(
                "recover_inflight_join",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
            )
            joined = await asyncio.shield(inflight)
            self._log.debug("client", "_recover_group_epoch_key exit (inflight-joined): elapsed=%.3fs group=%s epoch=%s result=%s", time.time() - _t_start, group_id, epoch, joined)
            return joined

        self._log.info("client",
            "group epoch key recovery initiated: group=%s epoch=%s sender=%s", group_id, epoch, sender_aid,
        )

        future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()
        self._group_epoch_recovery_inflight[key] = future
        try:
            result = await self._do_recover_group_epoch_key(
                group_id, epoch, sender_aid=sender_aid, timeout_s=timeout_s,
            )
            _debug_group_e2ee(
                "recover_done",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                result=result,
            )
            future.set_result(result)
            self._log.debug("client", "_recover_group_epoch_key exit: elapsed=%.3fs group=%s epoch=%s result=%s", time.time() - _t_start, group_id, epoch, result)
            return result
        except Exception as exc:
            _debug_group_e2ee(
                "recover_exception",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                error=type(exc).__name__,
                detail=str(exc),
            )
            future.set_exception(exc)
            self._log.debug("client", "_recover_group_epoch_key exit (error): elapsed=%.3fs group=%s epoch=%s err=%s", time.time() - _t_start, group_id, epoch, exc)
            raise
        finally:
            self._group_epoch_recovery_inflight.pop(key, None)

    async def _try_recover_epoch_key_from_server(self, group_id: str, epoch: int) -> bool:
        """尝试从 Group 服务端拉取 ECIES 加密的 epoch key 并解密存入 keystore。"""
        try:
            params: dict[str, Any] = {"group_id": group_id}
            if epoch > 0:
                params["epoch"] = epoch
            _debug_group_e2ee(
                "server_recover_request",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
            )
            result = await self.call("group.e2ee.get_epoch_key", params)
            _debug_group_e2ee(
                "server_recover_response",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                result_type=type(result).__name__,
                has_encrypted=isinstance(result, dict) and bool(result.get("encrypted_key")),
                server_epoch=result.get("epoch") if isinstance(result, dict) else "-",
            )
            if not isinstance(result, dict):
                return False
            encrypted_b64 = result.get("encrypted_key")
            server_epoch = int(result.get("epoch", epoch))
            if not encrypted_b64:
                _debug_group_e2ee(
                    "server_recover_no_key",
                    aid=self._aid or "",
                    group=group_id,
                    epoch=server_epoch,
                )
                return False
            encrypted_bytes = base64.b64decode(encrypted_b64)
            # 用自己的 AID 私钥 ECIES 解密
            from .e2ee import ecies_decrypt
            from cryptography.hazmat.primitives import serialization as _ser
            my_aid = self._aid or ""
            key_pair = self._auth._keystore.load_key_pair(my_aid)
            if not key_pair or not key_pair.get("private_key_pem"):
                self._log.warn("client", "cannot load AID private key for ECIES decryption: aid=%s", my_aid)
                _debug_group_e2ee(
                    "server_recover_no_private_key",
                    aid=my_aid,
                    group=group_id,
                    epoch=server_epoch,
                )
                return False
            privkey = _ser.load_pem_private_key(key_pair["private_key_pem"].encode("utf-8"), password=None)
            group_secret = ecies_decrypt(privkey, encrypted_bytes)
            if not group_secret or len(group_secret) != 32:
                self._log.warn("client", "server epoch key ECIES decrypt result length abnormal: group=%s epoch=%s len=%s", group_id, server_epoch, len(group_secret) if group_secret else 0)
                _debug_group_e2ee(
                    "server_recover_decrypt_bad_length",
                    aid=my_aid,
                    group=group_id,
                    epoch=server_epoch,
                    secret_len=len(group_secret) if group_secret else 0,
                )
                return False
            member_aids: list[str] = []
            committed_rotation: dict[str, Any] | None = None
            epoch_chain: str | None = None
            try:
                epoch_info = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
                if isinstance(epoch_info, dict):
                    committed_dbg = epoch_info.get("committed_rotation")
                    _debug_group_e2ee(
                        "server_recover_epoch_info",
                        aid=my_aid,
                        group=group_id,
                        requested_epoch=server_epoch,
                        committed_epoch=epoch_info.get("committed_epoch", epoch_info.get("epoch", "-")),
                        has_committed=isinstance(committed_dbg, dict),
                    )
                    raw_members = epoch_info.get("members")
                    if isinstance(raw_members, list):
                        for item in raw_members:
                            if isinstance(item, dict):
                                aid = str(item.get("aid") or "").strip()
                            else:
                                aid = str(item or "").strip()
                            if aid:
                                member_aids.append(aid)
                    committed = epoch_info.get("committed_rotation")
                    if isinstance(committed, dict):
                        committed_rotation = committed
                        raw_chain = str(committed.get("epoch_chain") or "").strip()
                        if raw_chain:
                            epoch_chain = raw_chain
                        expected_members = committed.get("expected_members")
                        if isinstance(expected_members, list):
                            member_aids = []
                            for item in expected_members:
                                aid = str(item or "").strip()
                                if aid:
                                    member_aids.append(aid)
            except Exception as exc:
                _debug_group_e2ee(
                    "server_recover_epoch_info_error",
                    aid=my_aid,
                    group=group_id,
                    epoch=server_epoch,
                    error=type(exc).__name__,
                    detail=str(exc),
                )
            if not member_aids:
                self._log.warn("client", "server epoch key recovery missing member snapshot: group=%s epoch=%s", group_id, server_epoch)
                _debug_group_e2ee(
                    "server_recover_no_members",
                    aid=my_aid,
                    group=group_id,
                    epoch=server_epoch,
                )
                return False
            from .e2ee import compute_membership_commitment, verify_epoch_chain
            commitment = compute_membership_commitment(member_aids, server_epoch, group_id, group_secret)
            epoch_chain_unverified: bool | None = None
            epoch_chain_unverified_reason: str | None = None
            if isinstance(committed_rotation, dict):
                committed_epoch = int(committed_rotation.get("target_epoch") or server_epoch)
                committed_commitment = str(committed_rotation.get("key_commitment") or "").strip()
                rotator_aid = str(
                    committed_rotation.get("rotated_by")
                    or committed_rotation.get("lease_owner")
                    or committed_rotation.get("committed_by")
                    or ""
                ).strip()
                _debug_group_e2ee(
                    "server_recover_commitment_check",
                    aid=my_aid,
                    group=group_id,
                    epoch=server_epoch,
                    members=len(member_aids),
                    committed_epoch=committed_epoch,
                    computed=commitment[:16],
                    committed=committed_commitment[:16] if committed_commitment else "-",
                    rotation=str(committed_rotation.get("rotation_id") or "-"),
                )
                if committed_epoch == server_epoch and committed_commitment and committed_commitment != commitment:
                    self._log.warn("client", 
                        "服务端 epoch key 恢复 commitment 不匹配: group=%s epoch=%s",
                        group_id, server_epoch,
                    )
                    _debug_group_e2ee(
                        "server_recover_commitment_mismatch",
                        aid=my_aid,
                        group=group_id,
                        epoch=server_epoch,
                    )
                    return False
                if epoch_chain and committed_epoch == server_epoch:
                    prev_secret = self._group_e2ee.load_secret(group_id, server_epoch - 1)
                    prev_chain = str(prev_secret.get("epoch_chain") or "").strip() if isinstance(prev_secret, dict) else ""
                    if prev_chain and rotator_aid:
                        if not verify_epoch_chain(epoch_chain, prev_chain, server_epoch, commitment, rotator_aid):
                            self._log.warn("client", 
                                "服务端 epoch key 恢复 epoch_chain 验证失败: group=%s epoch=%s rotator=%s",
                                group_id, server_epoch, rotator_aid,
                            )
                            _debug_group_e2ee(
                                "server_recover_chain_mismatch",
                                aid=my_aid,
                                group=group_id,
                                epoch=server_epoch,
                                rotator=rotator_aid,
                            )
                            return False
                        epoch_chain_unverified = False
                    else:
                        epoch_chain_unverified = True
                        epoch_chain_unverified_reason = "missing_prev_chain" if not prev_chain else "missing_rotator_aid"
                        _debug_group_e2ee(
                            "server_recover_chain_unverified",
                            aid=my_aid,
                            group=group_id,
                            epoch=server_epoch,
                            reason=epoch_chain_unverified_reason,
                        )
            self._group_e2ee.store_secret(
                group_id, server_epoch, group_secret, commitment, member_aids,
                epoch_chain=epoch_chain,
                epoch_chain_unverified=epoch_chain_unverified,
                epoch_chain_unverified_reason=epoch_chain_unverified_reason,
            )
            self._log.info("client", "epoch key recovered from server: group=%s epoch=%s", group_id, server_epoch)
            _debug_group_e2ee(
                "server_recover_store_ok",
                aid=my_aid,
                group=group_id,
                epoch=server_epoch,
                members=len(member_aids),
                commitment=commitment[:16],
            )
            return True
        except Exception as exc:
            self._log.debug("client", "epoch key recovery from server failed: group=%s epoch=%s err=%s", group_id, epoch, exc)
            _debug_group_e2ee(
                "server_recover_exception",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                error=type(exc).__name__,
                detail=str(exc),
            )
            return False

    async def _do_recover_group_epoch_key(
        self,
        group_id: str,
        epoch: int,
        *,
        sender_aid: str = "",
        timeout_s: float = 5.0,
    ) -> bool:
        epoch_result: dict[str, Any] = {"epoch": epoch}
        try:
            raw = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
            if isinstance(raw, dict):
                epoch_result.update(raw)
        except Exception as exc:
            self._log.debug("client", "group %s epoch recovery candidate query failed: %s", group_id, exc)
            _debug_group_e2ee(
                "recover_epoch_info_error",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                error=type(exc).__name__,
                detail=str(exc),
            )

        _debug_group_e2ee(
            "recover_epoch_info",
            aid=self._aid or "",
            group=group_id,
            requested_epoch=epoch,
            server_epoch=epoch_result.get("committed_epoch", epoch_result.get("epoch", "-")),
            has_pending=isinstance(epoch_result.get("pending_rotation"), dict),
            has_committed=isinstance(epoch_result.get("committed_rotation"), dict),
            candidates=len(self._group_key_recovery_candidates(group_id, epoch_result)),
        )

        server_key_allowed = await self._group_allows_member_epoch_rotation(group_id)
        _debug_group_e2ee(
            "recover_route",
            aid=self._aid or "",
            group=group_id,
            epoch=epoch,
            server_key_allowed=server_key_allowed,
        )
        if server_key_allowed:
            # 仅 open / invite code 群允许从服务端拉取 ECIES 加密的 epoch key。
            if await self._try_recover_epoch_key_from_server(group_id, epoch):
                self._schedule_retry_pending_decrypt_msgs(group_id)
                _debug_group_e2ee(
                    "recover_server_success",
                    aid=self._aid or "",
                    group=group_id,
                    epoch=epoch,
                )
                return True
            _debug_group_e2ee(
                "recover_server_miss_fallback_p2p",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
            )

        if sender_aid:
            epoch_result.setdefault("recovery_candidates", [])
            if isinstance(epoch_result["recovery_candidates"], list):
                epoch_result["recovery_candidates"].insert(0, sender_aid)

        # 在线优先恢复：先查在线成员列表，只向在线成员发送密钥请求
        online_aids: list[str] | None = None
        try:
            online_resp = await self.call("group.get_online_members", {"group_id": group_id})
            if isinstance(online_resp, dict):
                raw_members = online_resp.get("members") or online_resp.get("items") or []
                if isinstance(raw_members, list):
                    online_aids = [
                        str(m.get("aid", ""))
                        for m in raw_members
                        if isinstance(m, dict) and m.get("online") is True and str(m.get("aid", "")) != self._aid
                    ]
        except Exception as exc:
            self._log.debug("client", "group %s online member query failed, falling back to full candidate recovery: %s", group_id, exc)
            _debug_group_e2ee(
                "recover_online_error",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                error=type(exc).__name__,
                detail=str(exc),
            )

        if online_aids is not None:
            _debug_group_e2ee(
                "recover_online_members",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                online_count=len(online_aids),
                online=",".join(online_aids) if online_aids else "-",
            )
            if not online_aids:
                # 无在线成员，恢复失败
                self._log.info("client", "group epoch key recovery no online candidates: group=%s epoch=%s", group_id, epoch)
                _debug_group_e2ee(
                    "recover_no_online_candidates",
                    aid=self._aid or "",
                    group=group_id,
                    epoch=epoch,
                )
                return False
            # 用在线成员过滤候选列表
            await self._request_group_key_from_online(group_id, epoch, online_aids, epoch_result)
        else:
            # 回退：get_online_members 不可用时走原有全量候选逻辑
            await self._request_group_key_from_candidates(group_id, epoch, epoch_result)

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            await asyncio.sleep(_KEY_WAIT_POLL_INTERVAL_S)
            secret = self._group_e2ee.load_secret(group_id, epoch)
            if await self._group_epoch_secret_ready_for_recovery(group_id, epoch, secret):
                self._schedule_retry_pending_decrypt_msgs(group_id)
                self._log.info("client", "group epoch key recovery complete: group=%s epoch=%s", group_id, epoch)
                return True
        secret = self._group_e2ee.load_secret(group_id, epoch)
        ready = await self._group_epoch_secret_ready_for_recovery(group_id, epoch, secret)
        if ready:
            self._schedule_retry_pending_decrypt_msgs(group_id)
        if not ready:
            self._log.warn("client", "group epoch key recovery timeout: group=%s epoch=%s", group_id, epoch)
            _debug_group_e2ee(
                "recover_timeout",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                has_secret=bool(secret),
                pending=str(secret.get("pending_rotation_id") or "-") if isinstance(secret, dict) else "-",
            )
        return ready

    async def _request_group_key_from_online(
        self, group_id: str, server_epoch: int, online_aids: list[str], epoch_result: dict[str, Any]
    ) -> None:
        """只向在线成员发送密钥恢复请求，优先级：候选列表中的在线成员 > 其他在线成员。"""
        candidates = self._group_key_recovery_candidates(group_id, epoch_result)
        # 优先发送给候选列表中在线的成员
        ordered: list[str] = []
        for aid in candidates:
            if aid in online_aids and aid not in ordered:
                ordered.append(aid)
        # 补充其他在线成员
        for aid in online_aids:
            if aid not in ordered:
                ordered.append(aid)
        _debug_group_e2ee(
            "recover_p2p_ordered_targets",
            aid=self._aid or "",
            group=group_id,
            epoch=server_epoch,
            targets=",".join(ordered) if ordered else "-",
            candidates=",".join(candidates) if candidates else "-",
        )
        for target_aid in ordered:
            await self._request_group_key_from(group_id, target_aid, epoch=server_epoch)

    async def _group_epoch_secret_ready_for_recovery(
        self,
        group_id: str,
        epoch: int,
        secret_data: Any,
    ) -> bool:
        if not isinstance(secret_data, dict):
            return False
        pending_rotation_id = str(secret_data.get("pending_rotation_id") or "").strip()
        if not pending_rotation_id:
            return True
        return await self._pending_group_secret_still_current(group_id, epoch, pending_rotation_id)

    async def _pending_group_secret_still_current(
        self,
        group_id: str,
        epoch: int,
        pending_rotation_id: str,
    ) -> bool:
        try:
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
        except Exception:
            return False
        if not isinstance(epoch_result, dict):
            return False
        pending = epoch_result.get("pending_rotation")
        if (
            isinstance(pending, dict)
            and not pending.get("expired")
            and str(pending.get("rotation_id") or "").strip() == pending_rotation_id
        ):
            return True
        committed_rotation = epoch_result.get("committed_rotation")
        if isinstance(committed_rotation, dict):
            try:
                committed_epoch = int(committed_rotation.get("target_epoch") or 0)
            except (TypeError, ValueError):
                committed_epoch = 0
            if committed_epoch == epoch and str(committed_rotation.get("rotation_id") or "").strip() == pending_rotation_id:
                return True
        return False

    async def _ensure_group_epoch_ready(self, group_id: str, *, strict: bool) -> None:
        local_epoch = self._group_e2ee.current_epoch(group_id)
        if local_epoch is None:
            local_epoch = 0
        try:
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
        except Exception as exc:
            if strict:
                raise StateError(f"group {group_id} failed to query server epoch before retry: {exc}") from exc
            self._log.warn("client", "group %s epoch pre-check failed: %s", group_id, exc)
            return

        advertised_epoch = int(epoch_result.get("epoch", 0) if isinstance(epoch_result, dict) else 0)
        server_epoch = int(
            epoch_result.get("committed_epoch", advertised_epoch)
            if isinstance(epoch_result, dict) else advertised_epoch
        )
        pending = epoch_result.get("pending_rotation") if isinstance(epoch_result, dict) else None
        if isinstance(pending, dict):
            try:
                pending_base_epoch = int(pending.get("base_epoch") or server_epoch)
            except (TypeError, ValueError):
                pending_base_epoch = server_epoch
            self._schedule_group_rotation_retry(
                group_id,
                reason="pending_recovery",
                trigger_id=str(pending.get("rotation_id") or ""),
                expected_epoch=pending_base_epoch,
                pending=pending,
            )
        if server_epoch == 0 and local_epoch == 1:
            epoch_result = await self._recover_initial_group_epoch_if_needed(group_id, local_epoch, epoch_result)
            advertised_epoch = int(epoch_result.get("epoch", 0) if isinstance(epoch_result, dict) else 0)
            server_epoch = int(
                epoch_result.get("committed_epoch", advertised_epoch)
                if isinstance(epoch_result, dict) else advertised_epoch
            )
            if server_epoch == 0:
                raise StateError(
                    f"group {group_id} initial epoch sync has not completed; "
                    "refuse to send with local epoch 1 while server epoch is 0"
                )
        if server_epoch <= local_epoch:
            if not strict or server_epoch <= 0:
                return
            deadline = time.monotonic() + _KEY_WAIT_TIMEOUT_S
            while time.monotonic() < deadline:
                await asyncio.sleep(_KEY_WAIT_POLL_INTERVAL_S)
                refreshed = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
                refreshed_advertised = int(refreshed.get("epoch", 0) if isinstance(refreshed, dict) else 0)
                refreshed_epoch = int(
                    refreshed.get("committed_epoch", refreshed_advertised)
                    if isinstance(refreshed, dict) else refreshed_advertised
                )
                current_local = self._group_e2ee.current_epoch(group_id) or 0
                if refreshed_epoch > server_epoch:
                    epoch_result = refreshed
                    server_epoch = refreshed_epoch
                    local_epoch = current_local
                    break
                if current_local > local_epoch:
                    return
            else:
                raise StateError(f"group {group_id} epoch rotation has not completed")

        self._log.warn("client", "group %s local epoch=%d < server epoch=%d, triggering key recovery", group_id, local_epoch, server_epoch)
        await self._recover_group_epoch_key(group_id, server_epoch, timeout_s=_KEY_WAIT_TIMEOUT_S)

        deadline = time.monotonic() + _KEY_WAIT_TIMEOUT_S
        while time.monotonic() < deadline:
            await asyncio.sleep(_KEY_WAIT_POLL_INTERVAL_S)
            refreshed_epoch = self._group_e2ee.current_epoch(group_id)
            if refreshed_epoch is not None and refreshed_epoch >= server_epoch:
                return

        refreshed_epoch = self._group_e2ee.current_epoch(group_id)
        raise StateError(
            f"group {group_id} local epoch {refreshed_epoch} is behind server epoch {server_epoch}; "
            "key recovery has not completed"
        )

    async def _wait_for_group_membership_epoch_floor(
        self,
        group_id: str,
        *,
        timeout_s: float,
        strict: bool = False,
    ) -> None:
        """发送 epoch 以服务端 committed epoch 为准，成员 floor 只作为异常诊断。"""
        _ = timeout_s
        _ = strict
        while True:
            try:
                epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
                committed_epoch = int(
                    epoch_result.get("committed_epoch", epoch_result.get("epoch", 0))
                    if isinstance(epoch_result, dict) else 0
                )
                members_result = await self.call("group.get_members", {"group_id": group_id})
            except Exception as exc:
                self._log.debug("client", "group %s member epoch floor pre-check skipped: %s", group_id, exc)
                return

            members = members_result.get("members") if isinstance(members_result, dict) else None
            max_min_read_epoch = 0
            if isinstance(members, list):
                for member in members:
                    if not isinstance(member, dict):
                        continue
                    try:
                        max_min_read_epoch = max(max_min_read_epoch, int(member.get("min_read_epoch") or 0))
                    except (TypeError, ValueError):
                        continue

            if max_min_read_epoch <= committed_epoch:
                return

            self._log.warn("client",
                "group %s member min_read_epoch above committed epoch, sending with committed epoch: committed=%s floor=%s",
                group_id, committed_epoch, max_min_read_epoch,
            )
            return

    async def _committed_group_epoch(self, group_id: str) -> int:
        try:
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
        except Exception as exc:
            self._log.warn("client", "group %s committed epoch query failed, falling back to local epoch: %s", group_id, exc)
            return self._group_e2ee.current_epoch(group_id) or 0
        if not isinstance(epoch_result, dict):
            return self._group_e2ee.current_epoch(group_id) or 0
        return int(epoch_result.get("committed_epoch", epoch_result.get("epoch", 0)) or 0)

    @staticmethod
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

    async def _committed_group_epoch_state(self, group_id: str) -> dict[str, Any]:
        try:
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
            if isinstance(epoch_result, dict):
                return epoch_result
        except Exception as exc:
            self._log.warn("client", "group %s committed epoch state query failed, falling back to local epoch: %s", group_id, exc)
        return {
            "epoch": self._group_e2ee.current_epoch(group_id) or 0,
            "committed_epoch": self._group_e2ee.current_epoch(group_id) or 0,
        }

    async def _ensure_committed_group_secret_for_send(
        self,
        group_id: str,
        committed_epoch: int,
        epoch_result: dict[str, Any],
    ) -> int:
        if committed_epoch <= 0:
            return committed_epoch
        secret_data = self._group_e2ee.load_secret(group_id, committed_epoch)
        committed_rotation = epoch_result.get("committed_rotation") if isinstance(epoch_result, dict) else None
        if await self._committed_rotation_membership_gap(group_id, committed_epoch, committed_rotation):
            allow_member = await self._group_allows_member_epoch_rotation(group_id)
            self._log.warn("client", 
                "群 %s committed epoch %s 的成员快照与当前成员不一致，触发成员变更轮换修复",
                group_id, committed_epoch,
            )
            await self._maybe_lead_rotate_group_epoch(
                group_id,
                reason="membership_changed",
                trigger_id=f"{group_id}:committed_membership_gap:aid:{self._aid}:epoch:{committed_epoch}",
                expected_epoch=committed_epoch,
                allow_member=allow_member,
            )
            refreshed = await self._committed_group_epoch_state(group_id)
            refreshed_committed_epoch = int(
                (
                    refreshed.get("committed_epoch", refreshed.get("epoch", committed_epoch))
                    if isinstance(refreshed, dict) else committed_epoch
                ) or committed_epoch
            )
            if refreshed_committed_epoch > committed_epoch:
                committed_epoch = refreshed_committed_epoch
                committed_rotation = refreshed.get("committed_rotation") if isinstance(refreshed, dict) else None
                secret_data = self._group_e2ee.load_secret(group_id, committed_epoch)
            if await self._committed_rotation_membership_gap(group_id, committed_epoch, committed_rotation):
                raise StateError(
                    f"group {group_id} committed membership is stale at epoch {committed_epoch}; "
                    "key rotation repair has not completed"
                )
        if self._group_secret_matches_committed_rotation(secret_data, committed_rotation, local_aid=self._aid or ""):
            return committed_epoch
        pending_rotation_id = str(secret_data.get("pending_rotation_id") or "") if isinstance(secret_data, dict) else ""
        self._log.warn("client", 
            "群 %s epoch %s 本地 pending key 未匹配服务端 committed rotation，先恢复密钥: local_rotation=%s",
            group_id, committed_epoch, pending_rotation_id or "-",
        )
        await self._recover_group_epoch_key(group_id, committed_epoch, timeout_s=5.0)
        refreshed = await self._committed_group_epoch_state(group_id)
        refreshed_committed_epoch = int(
            (
                refreshed.get("committed_epoch", refreshed.get("epoch", committed_epoch))
                if isinstance(refreshed, dict) else committed_epoch
            ) or committed_epoch
        )
        if refreshed_committed_epoch > committed_epoch:
            committed_epoch = refreshed_committed_epoch
            await self._recover_group_epoch_key(group_id, committed_epoch, timeout_s=5.0)
            refreshed = await self._committed_group_epoch_state(group_id)
        refreshed_rotation = refreshed.get("committed_rotation") if isinstance(refreshed, dict) else None
        refreshed_secret = self._group_e2ee.load_secret(group_id, committed_epoch)
        if not self._group_secret_matches_committed_rotation(refreshed_secret, refreshed_rotation, local_aid=self._aid or ""):
            raise StateError(
                f"group {group_id} epoch {committed_epoch} local key is pending or mismatched; "
                "refuse to send with uncommitted group key"
            )
        return committed_epoch

    async def _committed_rotation_membership_gap(
        self,
        group_id: str,
        committed_epoch: int,
        committed_rotation: dict[str, Any] | None,
    ) -> bool:
        if not self._aid or committed_epoch <= 0 or not isinstance(committed_rotation, dict):
            return False
        expected_members = committed_rotation.get("expected_members")
        if not isinstance(expected_members, list):
            return False
        expected_set = {str(item).strip() for item in expected_members if str(item or "").strip()}
        if not expected_set:
            return False
        try:
            members_result = await self.call("group.get_members", {"group_id": group_id})
        except Exception as exc:
            self._log.debug("client", "query current members failed, cannot determine committed membership gap: group=%s err=%s", group_id, exc)
            return False
        raw_members = members_result.get("members") or members_result.get("items") if isinstance(members_result, dict) else []
        if not isinstance(raw_members, list):
            return False
        active_set: set[str] = set()
        for item in raw_members:
            if not isinstance(item, dict):
                continue
            aid = str(item.get("aid") or "").strip()
            status = str(item.get("status") or "active").strip().lower()
            if aid and status in {"", "active"}:
                active_set.add(aid)
        if self._aid not in active_set:
            return False
        if not active_set:
            return False
        if active_set != expected_set:
            missing = sorted(active_set - expected_set)
            extra = sorted(expected_set - active_set)
            self._log.info("client",
                "group %s committed membership gap: epoch=%s missing=%s extra=%s",
                group_id, committed_epoch, missing, extra,
            )
            return True
        return False

    # ── 便利方法 ──────────────────────────────────────────

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
            self._log.debug(
                "client",
                "DIAG _process_and_publish_message enter: message_id=%s seq=%s from=%s device_id=%s slot_id=%s",
                msg.get("message_id"), msg.get("seq"), msg.get("from"),
                msg.get("device_id"), msg.get("slot_id"),
            )
            if not self._message_targets_current_instance(msg):
                self._log.debug(
                    "client",
                    "DIAG _process_and_publish_message filtered (instance mismatch): "
                    "msg_device=%s self_device=%s msg_slot=%s self_slot=%s",
                    msg.get("device_id"), self._device_id,
                    msg.get("slot_id"), self._slot_id,
                )
                return

            # 拦截 P2P 传输的群组密钥分发/请求/响应消息
            if await self._try_handle_group_key_message(msg):
                self._log.debug(
                    "client",
                    "DIAG group_key intercepted: message_id=%s seq=%s elapsed=%.3fs",
                    msg.get("message_id"), msg.get("seq"), time.time() - _t_start,
                )
                # group_key 控制消息也要推进 seq tracker + auto-ack，
                # 否则 fillP2pGap 会因为 contig 卡在此 seq 之前而重复拉取同样的历史消息。
                seq = msg.get("seq")
                if seq is not None and self._aid:
                    ns = f"p2p:{self._aid}"
                    self._seq_tracker.on_message_seq(ns, int(seq))
                    self._persist_seq(ns)
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        self._fire_ack("message.ack", {
                            "seq": contig, "device_id": self._device_id, "slot_id": self._slot_id,
                        }, "P2P auto-ack（group_key control）")
                # 让出事件循环，避免连续处理大量 group_key 消息时阻塞 ws 握手等 IO
                await asyncio.sleep(0)
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

            decrypted = await self._decrypt_single_message(msg, source="push")
            if decrypted is None:
                # 解密返回 None（replay guard 判定重复或解密失败），不投递消息，
                # 但 SeqTracker 已推进 contiguous，仍需 auto-ack 避免服务端重推。
                if seq is not None and self._aid:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    await self._drain_ordered_messages(ns)
                    if contig > 0:
                        self._fire_ack("message.ack", {
                            "seq": contig, "device_id": self._device_id, "slot_id": self._slot_id,
                        }, "P2P auto-ack（解密None）")
                return
            if seq is not None and self._aid:
                self._log.debug(
                    "client",
                    "DIAG publish ordered: ns=%s seq=%s message_id=%s",
                    ns, seq, decrypted.get("message_id") if isinstance(decrypted, dict) else "?",
                )
                await self._publish_ordered_message("message.received", ns, seq, decrypted)
            else:
                self._log.debug(
                    "client",
                    "DIAG publish app event (no seq): message_id=%s",
                    decrypted.get("message_id") if isinstance(decrypted, dict) else "?",
                )
                await self._publish_app_event("message.received", decrypted)

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
        """处理群组消息推送：自动解密后 re-publish。"""
        _t_start = time.time()
        if isinstance(data, dict):
            self._log.debug(
                "client",
                "_on_raw_group_message_created enter: message_id=%s seq=%s group_id=%s from=%s",
                data.get("message_id", "-"), data.get("seq", "-"),
                data.get("group_id", "-"), data.get("from", "-"),
            )
        else:
            self._log.debug("client", "_on_raw_group_message_created enter (non-dict): type=%s", type(data).__name__)
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._process_and_publish_group_message(data))
        self._log.debug("client", "_on_raw_group_message_created exit: elapsed=%.3fs", time.time() - _t_start)

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
                loop.create_task(self._v2_auto_propose_state(group_id))

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

            # 成员退出或被踢 → 剩余 admin/owner 自动补位轮换
            if data.get("action") in ("member_left", "member_removed") and group_id:
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                expected_epoch = self._membership_rotation_expected_epoch(data)
                if expected_epoch is None:
                    self._log.debug("client", "membership event without old_epoch skipped for epoch rotation: aid=%s group=%s action=%s event_seq=%s", self._aid, group_id, data.get("action"), data.get("event_seq"))
                else:
                    loop.create_task(self._maybe_lead_rotate_group_epoch(
                        group_id,
                        reason="membership_changed",
                        trigger_id=self._membership_rotation_trigger_id(group_id, data),
                        expected_epoch=expected_epoch,
                    ))

            # 成员加入同样改变成员集：按 action 区分策略
            # - member_added / join_approved（私密群/审批群）：admin 必然在线，立即轮换
            # - joined / invite_code_used（开放群/邀请码群）：新成员先恢复 committed_epoch，延迟轮换
            if data.get("action") in ("member_added", "joined", "join_approved", "invite_code_used") and group_id:
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                action = data.get("action")
                expected_epoch = self._membership_rotation_expected_epoch(data)

                # 新成员自身入群（open/invite_code）：走延迟轮换 + backfill
                joined_aids = self._joined_member_aids_from_payload(data)
                is_self_joining = self._aid in joined_aids and action in ("joined", "invite_code_used")
                if is_self_joining or action in ("joined", "invite_code_used"):
                    # open/invite_code 群：所有在线成员都参与延迟轮换
                    # 新成员自己延迟更长，优先让其他在线成员先轮换
                    trigger_id = self._membership_rotation_trigger_id(group_id, data)
                    if not is_self_joining:
                        loop.create_task(self._maybe_backfill_key_to_joined_member(group_id, data, trigger_id))
                    if expected_epoch is not None:
                        delay = self._SELF_JOIN_ROTATION_DELAY_S if is_self_joining else None
                        loop.create_task(self._delayed_rotate_after_join(
                            group_id,
                            reason="membership_changed",
                            trigger_id=trigger_id,
                            expected_epoch=expected_epoch,
                            allow_member=True,
                            delay_s=delay,
                        ))
                else:
                    # member_added / join_approved：立即轮换
                    if expected_epoch is None:
                        trigger_id = self._membership_rotation_trigger_id(group_id, data)
                        loop.create_task(self._maybe_backfill_key_to_joined_member(group_id, data, trigger_id))
                    else:
                        loop.create_task(self._maybe_lead_rotate_group_epoch(
                            group_id,
                            reason="membership_changed",
                            trigger_id=self._membership_rotation_trigger_id(group_id, data),
                            expected_epoch=expected_epoch,
                        ))

            # PY-003: 群组解散 → 清理本地 epoch key、seq_tracker 等状态
            if data.get("action") == "dissolved" and group_id:
                self._cleanup_group_state(group_id)
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

    async def _process_and_publish_group_message(self, data: Any) -> None:
        """处理群组推送消息的异步任务。

        带 payload 的事件（消息推送）：解密后 re-publish。
        不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。

        解密失败的消息仍按已收到推进并 auto-ack，避免缺 key 期间游标长期卡住；
        同时加入待重试队列，后续拿到密钥后再补发明文事件。
        """
        try:
            if not isinstance(data, dict):
                await self._publish_app_event("group.message_created", data)
                return
            msg = dict(data)
            group_id = msg.get("group_id", "")
            seq = msg.get("seq")
            payload = msg.get("payload")

            payload_present = payload is not None and (not isinstance(payload, dict) or bool(payload))
            if group_id:
                self._group_synced.add(group_id)

            if not payload_present:
                # 不带 payload 的通知不能先推进 seq，否则 auto-pull 会用推进后的 cursor 跳过该消息。
                await self._auto_pull_group_messages(msg)
                return
            if group_id and seq is not None:
                ns_key = f"group:{group_id}"
                seq_i = int(seq)
                if self._is_published_seq(ns_key, seq_i) or self._is_pending_ordered_seq(ns_key, seq_i):
                    # republish guard：已投递或已解密待投递的 seq 不再进入解密/recover/pending 流程。
                    return
            decrypted = await self._decrypt_group_message(msg)

            # PY-001: 检查解密是否成功（成功时有 e2ee 字段）
            is_encrypted_payload = isinstance(payload, dict) and payload.get("type") == "e2ee.group_encrypted"
            decrypt_success = not is_encrypted_payload or (isinstance(decrypted, dict) and decrypted.get("e2ee"))

            if group_id and seq is not None:
                ns = f"group:{group_id}"
                if decrypt_success:
                    need_pull = self._seq_tracker.on_message_seq(ns, int(seq))
                    self._persist_seq(ns)
                    if need_pull:
                        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                        loop.create_task(self._fill_group_gap(group_id))

            if decrypt_success:
                # 解密成功：按 contiguous_seq 有序放行 + auto-ack
                if group_id and seq is not None:
                    ns_key = f"group:{group_id}"
                    await self._publish_ordered_message("group.message_created", ns_key, seq, decrypted)
                else:
                    await self._publish_app_event("group.message_created", decrypted)

                # auto-ack：ack contiguous_seq（避免空洞时跳跃推进）
                if group_id and seq is not None:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        self._fire_ack("group.ack_messages", {
                            "group_id": group_id, "msg_seq": contig,
                            "device_id": self._device_id,
                            "slot_id": self._slot_id,
                        }, f"群消息 auto-ack group={group_id}")
            else:
                # 解密失败 → 入 pending queue，**不推进 seq tracker 也不 auto-ack**：
                # 让服务端 cursor 留在原位，等密钥恢复后 retry 解密成功才推进 + ack。
                # 兜底：恢复彻底失败时由 _retry_pending_decrypt_msgs(force_advance_on_fail=True)
                # 强制推进，避免一条永远解不开的消息无限卡住整个群的 cursor。
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
                await self._publish_app_event("group.message_undecryptable", safe_event)
                # 触发兜底定时（30s 后如果仍未解开，强制推进 + ack）
                self._schedule_recovery_timeout(group_id)
        except Exception as _exc:
            self._log.warn("client", "group message push processing failed: %s", _exc)
            # H26: 解密失败改发 group.message_undecryptable 事件，不投递原始密文 payload
            if isinstance(data, dict):
                _payload = data.get("payload")
                _payload_present = _payload is not None and (not isinstance(_payload, dict) or bool(_payload))
                safe_event = {
                    "message_id": data.get("message_id"),
                    "group_id": data.get("group_id"),
                    "from": data.get("from"),
                    "seq": data.get("seq"),
                    "timestamp": data.get("timestamp"),
                    "_decrypt_error": str(_exc),
                }
                await self._publish_app_event("group.message_undecryptable", safe_event)
                # 异常路径同样按已收到推进/ack，并加入待重试队列。
                _exc_group_id = data.get("group_id", "")
                if _payload_present and _exc_group_id:
                    self._enqueue_pending_decrypt(_exc_group_id, dict(data))
                    _exc_seq = data.get("seq")
                    if _exc_seq is not None:
                        _exc_ns = f"group:{_exc_group_id}"
                        need_pull = self._seq_tracker.on_message_seq(_exc_ns, int(_exc_seq))
                        self._persist_seq(_exc_ns)
                        if need_pull:
                            loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                            loop.create_task(self._fill_group_gap(_exc_group_id))
                        _exc_contig = self._seq_tracker.get_contiguous_seq(_exc_ns)
                        await self._drain_ordered_messages(_exc_ns)
                        if _exc_contig > 0:
                            self._fire_ack("group.ack_messages", {
                                "group_id": _exc_group_id, "msg_seq": _exc_contig,
                                "device_id": self._device_id,
                                "slot_id": self._slot_id,
                            }, f"群消息 auto-ack（异常路径）group={_exc_group_id}")

    async def _auto_pull_group_messages(self, notification: dict[str, Any]) -> None:
        """收到不带 payload 的 group.message_created 通知后，自动 pull 最新消息。"""
        group_id = notification.get("group_id", "")
        if not group_id:
            await self._publish_app_event("group.message_created", notification)
            return
        notification_seq = notification.get("seq")
        local_after_seq = self._seq_tracker.get_contiguous_seq(f"group:{group_id}")
        if notification_seq is not None:
            try:
                # 已有本地游标时从本地 contiguous 位置继续拉取，避免通知 seq 跳过中间空洞。
                # 冷启动没有本地游标时，只拉通知对应的新消息，避免一次性拉取全部历史。
                after_seq = local_after_seq if local_after_seq > 0 else max(0, int(notification_seq) - 1)
            except Exception:
                after_seq = local_after_seq
        else:
            after_seq = local_after_seq
        try:
            result = await self.call("group.pull", {
                "group_id": group_id,
                "after_message_seq": after_seq,
                "device_id": self._device_id,
                "slot_id": self._slot_id,
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
                                continue  # 已发布到应用层，跳过重复投递
                            if s is not None:
                                await self._publish_ordered_message("group.message_created", ns_key, s, msg)
                            else:
                                await self._publish_app_event("group.message_created", msg)
                    self._prune_pushed_seqs(ns_key)
                    return
        except Exception as _exc:
            self._log.warn("client", "auto pull group messages failed: %s", _exc)
        # pull 失败时仍透传原始通知
        await self._publish_app_event("group.message_created", notification)

    async def _fill_group_gap(self, group_id: str) -> None:
        """后台补齐群消息空洞。"""
        if self._state != "connected" or self._closing:
            return
        after_seq = self._seq_tracker.get_contiguous_seq(f"group:{group_id}")
        dedup_key = f"group_msg:{group_id}:{after_seq}"
        if dedup_key in self._gap_fill_done:
            return
        self._gap_fill_done[dedup_key] = time.time()
        # S1: dedup 键必须在所有出口（成功/异常/空返）清理，避免"成功但返回 0 条"永久占位。
        # 真实空洞下次 push 还会触发；同窗口内并发由 add 前的 in 检查保证幂等。
        try:
            self._log.info("client", "group message gap fill start: group=%s after_seq=%d", group_id, after_seq)
            result = await self.call("group.pull", {
                "group_id": group_id,
                "after_message_seq": after_seq,
                "device_id": self._device_id,
                "limit": 50,
            })
            if isinstance(result, dict):
                messages = result.get("messages", [])
                if isinstance(messages, list):
                    self._log.info("client", "group message gap fill done: group=%s after_seq=%d pulled=%d", group_id, after_seq, len(messages))
                    ns_key = f"group:{group_id}"
                    pushed = self._pushed_seqs.get(ns_key)
                    # seq_tracker 在 call() 中自动处理；ack 由 push 路径负责
                    for msg in messages:
                        if isinstance(msg, dict):
                            s = msg.get("seq")
                            if pushed and s is not None and int(s) in pushed:
                                continue  # 已发布到应用层，跳过重复投递
                            if s is not None:
                                await self._publish_ordered_message("group.message_created", ns_key, s, msg)
                            else:
                                await self._publish_app_event("group.message_created", msg)
                    # 维护 republish guard 上限
                    self._prune_pushed_seqs(ns_key)
        except Exception as exc:
            self._log.warn("client", "group message gap fill failed: group=%s after_seq=%d error=%s", group_id, after_seq, exc)
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
                    self._seq_tracker.on_pull_result(ns, events)
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
                    self._persist_seq(ns)
                    # auto-ack contiguous_seq
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
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
            self._log.warn("client", "group event gap fill failed: group=%s after_seq=%d error=%s", group_id, after_seq, exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)

    async def _request_group_key_from(self, group_id: str, target_aid: str, *, epoch: int = 0) -> None:
        """主动向指定成员请求群组密钥（用于重连时无 epoch key 的群）。"""
        try:
            from .e2ee import build_key_request
            req_payload = build_key_request(group_id, epoch, self._aid or "")
            self._group_e2ee.remember_key_request(req_payload, expected_responder_aid=target_aid)
            _debug_group_e2ee(
                "p2p_key_request_send",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                target=target_aid,
                request_id=str(req_payload.get("request_id") or "-"),
            )
            await self.call("message.send", {
                "to": target_aid,
                "payload": req_payload,
                "encrypt": True,
                "persist_required": True,
            })
            self._log.info("client", "group key recovery request sent: group=%s target=%s epoch=%s", group_id, target_aid, epoch)
            _debug_group_e2ee(
                "p2p_key_request_sent",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                target=target_aid,
                request_id=str(req_payload.get("request_id") or "-"),
            )
        except Exception as exc:
            self._log.warn("client", "group key recovery request send failed: group=%s target=%s epoch=%s err=%s", group_id, target_aid, epoch, exc)
            _debug_group_e2ee(
                "p2p_key_request_failed",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                target=target_aid,
                error=type(exc).__name__,
                detail=str(exc),
            )

    async def _ack_group_rotation_key(
        self,
        *,
        rotation_id: str,
        key_commitment: str,
        device_id: str | None = None,
    ) -> bool:
        if not rotation_id:
            return False
        self._log.debug(
            "client",
            "_ack_group_rotation_key entry rotation_id=%s device_id=%s",
            rotation_id, device_id if device_id is not None else self._device_id,
        )
        try:
            result = await self.call("group.e2ee.ack_rotation_key", {
                "rotation_id": rotation_id,
                "key_commitment": key_commitment,
                "device_id": device_id if device_id is not None else self._device_id,
            })
            success = bool(isinstance(result, dict) and result.get("success"))
            self._log.debug(
                "client",
                "_ack_group_rotation_key completed rotation_id=%s success=%s",
                rotation_id, success,
            )
            return success
        except Exception as exc:
            self._log.warn("client", "epoch key ack submission failed: rotation=%s err=%s", rotation_id, exc)
            return False

    async def _verify_active_group_rotation_distribution(self, payload: dict[str, Any]) -> bool:
        """只接受服务端 pending 或已 committed 的 rotation 分发。

        对于不在当前 session 活跃群列表中的群（历史消息激活的），
        跳过 RPC 验证直接返回 True（让 handle_incoming 本地处理），
        避免 fillP2pGap 拉到大量历史群密钥消息时触发 epoch 编排风暴。
        """
        rotation_id = str(payload.get("rotation_id") or "").strip()
        group_id = str(payload.get("group_id") or "").strip()
        if not group_id:
            return False
        # 历史群（不在当前 session 活跃列表）：跳过 RPC 验证，只做本地 handle_incoming
        if group_id not in self._group_synced:
            self._log.debug("client",
                "skip RPC verify for inactive group: group=%s rotation=%s (not in group_synced)",
                group_id, rotation_id,
            )
            return True
        try:
            epoch = int(payload.get("epoch") or 0)
        except (TypeError, ValueError):
            return False
        commitment = str(payload.get("commitment") or "").strip()
        try:
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
        except Exception as exc:
            self._log.warn("client",
                "rejecting epoch key distribution: cannot verify active rotation: group=%s rotation=%s err=%s",
                group_id, rotation_id, exc,
            )
            return False
        committed_epoch = int(
            epoch_result.get("committed_epoch", epoch_result.get("epoch", 0))
            if isinstance(epoch_result, dict) else 0
        )
        committed_rotation = epoch_result.get("committed_rotation") if isinstance(epoch_result, dict) else None
        if not rotation_id:
            if epoch > 0 and epoch <= committed_epoch:
                if isinstance(committed_rotation, dict) and int(committed_rotation.get("target_epoch") or committed_epoch) == epoch:
                    committed_commitment = str(committed_rotation.get("key_commitment") or "").strip()
                    if committed_commitment and commitment and committed_commitment != commitment:
                        expected_members = committed_rotation.get("expected_members") or []
                        if self._aid and self._aid not in expected_members:
                            pass  # 新成员 backfill 场景，放行
                        else:
                            return False
                return True
            self._log.info("client", 
                "拒绝缺少 rotation_id 的未来 epoch key 分发: group=%s epoch=%s committed=%s",
                group_id, epoch, committed_epoch,
            )
            return False
        pending = epoch_result.get("pending_rotation") if isinstance(epoch_result, dict) else None
        if isinstance(pending, dict) and not pending.get("expired"):
            pending_commitment = str(pending.get("key_commitment") or "").strip()
            if (
                str(pending.get("rotation_id") or "") == rotation_id
                and int(pending.get("target_epoch") or 0) == epoch
                and (not pending_commitment or commitment == pending_commitment)
            ):
                return True

        if isinstance(committed_rotation, dict) and committed_epoch >= epoch:
            committed_commitment = str(committed_rotation.get("key_commitment") or "").strip()
            if (
                str(committed_rotation.get("rotation_id") or "") == rotation_id
                and (not committed_commitment or commitment == committed_commitment)
            ):
                return True

        self._log.info("client", 
            "拒绝非 pending/committed 状态的 epoch key 分发: group=%s rotation=%s epoch=%s",
            group_id, rotation_id, epoch,
        )
        return False

    async def _discard_group_distribution_if_stale(self, payload: dict[str, Any]) -> None:
        """处理后再校验一次，关闭 verify/store 之间的状态变化窗口。"""
        rotation_id = str(payload.get("rotation_id") or "").strip()
        if not rotation_id:
            return
        group_id = str(payload.get("group_id") or "").strip()
        try:
            epoch = int(payload.get("epoch") or 0)
        except (TypeError, ValueError):
            return
        if not group_id or epoch <= 0:
            return
        if await self._verify_active_group_rotation_distribution(payload):
            return
        try:
            if self._group_e2ee.discard_pending_secret(group_id, epoch, rotation_id):
                self._log.info("client", 
                    "丢弃 verify 后变为 stale 的 group epoch key: group=%s epoch=%s rotation=%s",
                    group_id, epoch, rotation_id,
                )
        except Exception as exc:
            self._log.debug("client", 
                "清理 stale group epoch key 失败: group=%s epoch=%s rotation=%s err=%s",
                group_id, epoch, rotation_id, exc,
            )

    async def _verify_group_key_response_epoch(self, payload: dict[str, Any]) -> bool:
        group_id = str(payload.get("group_id") or "").strip()
        if not group_id:
            return False
        try:
            epoch = int(payload.get("epoch") or 0)
        except (TypeError, ValueError):
            return False
        if epoch <= 0:
            return False
        commitment = str(payload.get("commitment") or "").strip()
        try:
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
        except Exception as exc:
            self._log.warn("client", 
                "拒绝无法校验 committed epoch 的 group key response: group=%s epoch=%s err=%s",
                group_id, epoch, exc,
            )
            return False
        if not isinstance(epoch_result, dict):
            return False
        committed_epoch = int(epoch_result.get("committed_epoch", epoch_result.get("epoch", 0)) or 0)
        committed_rotation = epoch_result.get("committed_rotation")
        _debug_group_e2ee(
            "p2p_response_epoch_check",
            aid=self._aid or "",
            group=group_id,
            epoch=epoch,
            committed_epoch=committed_epoch,
            has_committed=isinstance(committed_rotation, dict),
            response_commitment=commitment[:16] if commitment else "-",
            rotation=str(committed_rotation.get("rotation_id") or "-") if isinstance(committed_rotation, dict) else "-",
        )
        if epoch > committed_epoch:
            self._log.info("client", 
                "拒绝未提交 epoch 的 group key response: group=%s epoch=%s committed=%s",
                group_id, epoch, committed_epoch,
            )
            _debug_group_e2ee(
                "p2p_response_reject_future_epoch",
                aid=self._aid or "",
                group=group_id,
                epoch=epoch,
                committed_epoch=committed_epoch,
            )
            return False
        if isinstance(committed_rotation, dict) and int(committed_rotation.get("target_epoch") or committed_epoch) == epoch:
            committed_commitment = str(committed_rotation.get("key_commitment") or "").strip()
            if committed_commitment and commitment and committed_commitment != commitment:
                # open/invite_code 新成员恢复：自己不在原始 expected_members 中，放行
                expected_members = committed_rotation.get("expected_members") or []
                if self._aid and self._aid not in expected_members:
                    _debug_group_e2ee(
                        "p2p_response_allow_new_member_commitment_mismatch",
                        aid=self._aid or "",
                        group=group_id,
                        epoch=epoch,
                        expected_members=len(expected_members),
                        committed=committed_commitment[:16],
                        response=commitment[:16],
                    )
                    self._log.debug("client", 
                        "放行 group key response：新成员恢复 commitment 不匹配属正常 group=%s epoch=%s",
                        group_id, epoch,
                    )
                else:
                    self._log.warn("client", 
                        "拒绝 group key response：commitment 与 committed rotation 不匹配 group=%s epoch=%s committed_commitment=%s response_commitment=%s",
                        group_id, epoch, committed_commitment[:16], commitment[:16],
                    )
                    _debug_group_e2ee(
                        "p2p_response_reject_commitment_mismatch",
                        aid=self._aid or "",
                        group=group_id,
                        epoch=epoch,
                        expected_members=len(expected_members) if isinstance(expected_members, list) else "-",
                        committed=committed_commitment[:16],
                        response=commitment[:16],
                    )
                    return False
        return True

    async def _fill_p2p_gap(self) -> None:
        """后台补齐 P2P 消息空洞。"""
        if self._state != "connected" or self._closing:
            return
        if not self._aid:
            return
        ns = f"p2p:{self._aid}"
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        dedup_key = f"p2p:{after_seq}"
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
                                await self._publish_ordered_message("message.received", ns_key, s, msg)
                            else:
                                await self._publish_app_event("message.received", msg)
                            # 每条消息处理后让出事件循环，避免大量历史消息解密阻塞 ws 握手等 IO
                            await asyncio.sleep(0)
                    # 维护 republish guard 上限
                    self._prune_pushed_seqs(ns_key)
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

    def _enqueue_pending_decrypt(self, group_id: str, msg: dict[str, Any]) -> None:
        """PY-001: 将解密失败的消息加入待重试队列（有大小上限）。"""
        ns = f"group:{group_id}"
        queue = self._pending_decrypt_msgs.setdefault(ns, [])
        queue.append(msg)
        # 超过上限时丢弃最旧的
        if len(queue) > _PENDING_DECRYPT_LIMIT:
            self._pending_decrypt_msgs[ns] = queue[-_PENDING_DECRYPT_LIMIT:]

    def _schedule_retry_pending_decrypt_msgs(self, group_id: str) -> None:
        ns = f"group:{group_id}"
        if not group_id or not self._pending_decrypt_msgs.get(ns):
            return
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._retry_pending_decrypt_msgs(group_id))

    async def _retry_pending_decrypt_msgs(self, group_id: str, *, force_advance_on_fail: bool = False) -> None:
        """PY-002: 密钥恢复后重试待解密队列中的消息。

        成功解密的消息发布到 group.message_created 并推进 seq tracker + auto-ack。
        force_advance_on_fail=True 时（recovery 兜底超时调用），仍解密失败的消息也强制
        推进 seq tracker + 发 undecryptable + ack，避免永久卡住游标；False 时保留在队列里。
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
                decrypted = await self._decrypt_group_message(msg, skip_replay=False)
                is_encrypted = isinstance(msg.get("payload"), dict) and msg["payload"].get("type") == "e2ee.group_encrypted"
                if is_encrypted and (not isinstance(decrypted, dict) or not decrypted.get("e2ee")):
                    # 仍然解密失败
                    if force_advance_on_fail:
                        self._log.info(
                            "client",
                            "group recovery give up: group=%s seq=%s → force advance + publish undecryptable",
                            group_id, msg.get("seq"),
                        )
                        seq = msg.get("seq")
                        if seq is not None:
                            self._seq_tracker.on_message_seq(ns, int(seq))
                            self._persist_seq(ns)
                        safe_event = {
                            "message_id": msg.get("message_id"),
                            "group_id": group_id,
                            "from": msg.get("from"),
                            "seq": seq,
                            "timestamp": msg.get("timestamp"),
                            "_decrypt_error": "epoch recovery failed",
                        }
                        await self._publish_app_event("group.message_undecryptable", safe_event)
                        contig = self._seq_tracker.get_contiguous_seq(ns)
                        if contig > 0:
                            self._fire_ack("group.ack_messages", {
                                "group_id": group_id, "msg_seq": contig,
                                "device_id": self._device_id,
                                "slot_id": self._slot_id,
                            }, f"recovery 超时 force advance group={group_id}")
                    else:
                        still_pending.append(msg)
                    continue
                # 解密成功
                seq = msg.get("seq")
                if group_id and seq is not None:
                    # 推进 seq tracker（之前 push 失败时没推进）
                    self._seq_tracker.on_message_seq(ns, int(seq))
                    self._persist_seq(ns)
                    ns_key = f"group:{group_id}"
                    await self._publish_ordered_message("group.message_created", ns_key, seq, decrypted)
                else:
                    await self._dispatcher.publish("group.message_created", decrypted)
                # auto-ack
                if group_id and seq is not None:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig > 0:
                        self._fire_ack("group.ack_messages", {
                            "group_id": group_id, "msg_seq": contig,
                            "device_id": self._device_id,
                            "slot_id": self._slot_id,
                        }, f"重试 auto-ack group={group_id}")
            except Exception as _exc:
                self._log.debug("client", "retry decrypt failed: group=%s seq=%s: %s", group_id, msg.get("seq"), _exc)
                still_pending.append(msg)

        queued_during_retry = list(self._pending_decrypt_msgs.get(ns) or [])
        merged_pending = still_pending + queued_during_retry
        if merged_pending:
            self._pending_decrypt_msgs[ns] = merged_pending[-_PENDING_DECRYPT_LIMIT:]
        else:
            self._pending_decrypt_msgs.pop(ns, None)

    def _schedule_recovery_timeout(self, group_id: str, *, timeout_seconds: int = 30) -> None:
        """recovery 兜底定时：N 秒后如果 pending queue 仍有未解密消息，强制推进 cursor。"""
        if not group_id:
            return
        # 去重：同一 group 短时间内只调度一次
        now = time.time()
        last = self._recovery_timeout_scheduled.get(group_id, 0.0)
        if last and (last + timeout_seconds) > now:
            return
        self._recovery_timeout_scheduled[group_id] = now
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()

        async def _run():
            try:
                await asyncio.sleep(timeout_seconds)
                if self._closing:
                    return
                ns = f"group:{group_id}"
                if not self._pending_decrypt_msgs.get(ns):
                    return
                self._log.info("client", "group recovery timeout: group=%s → force advance", group_id)
                await self._retry_pending_decrypt_msgs(group_id, force_advance_on_fail=True)
            except Exception as _exc:
                self._log.debug("client", "_schedule_recovery_timeout failed: group=%s err=%s", group_id, _exc)

        loop.create_task(_run())

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
                self._log.debug("client", "cleanup group %s epoch key failed: %s", group_id, _exc)

        # 清理 seq_tracker
        self._seq_tracker.remove_namespace(ns_msg)
        self._seq_tracker.remove_namespace(ns_evt)

        # 清理 pushed_seqs
        self._pushed_seqs.pop(ns_msg, None)

        # 清理有序放行待发布队列
        self._pending_ordered().pop(ns_msg, None)

        # 清理待重试解密队列
        self._pending_decrypt_msgs.pop(ns_msg, None)

        # 清理补洞去重状态
        for k in list(self._gap_fill_done):
            if group_id in k:
                self._gap_fill_done.pop(k, None)

        self._log.info("client", "cleaned up group %s local state (epoch key + seq + pushed_seqs)", group_id)

    async def _decrypt_group_message(self, message: dict[str, Any], *, skip_replay: bool = False) -> dict[str, Any]:
        """解密单条群组消息。"""
        _t_start = time.time()
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "e2ee.group_encrypted":
            return self._attach_group_dispatch_mode_to_payload(message)

        group_id = message.get("group_id", "")
        msg_epoch = payload.get("epoch")
        msg_seq = message.get("seq")
        self._log.debug("client", "_decrypt_group_message enter: group=%s epoch=%s seq=%s", group_id, msg_epoch, msg_seq)

        # 确保发送方证书已缓存（签名验证需要）— 失败时拒绝解密
        sender_aid = message.get("from", message.get("sender_aid", ""))
        if sender_aid:
            cert_ok = await self._ensure_sender_cert_cached(sender_aid)
            if not cert_ok:
                self._log.warn("client",
                    "群消息解密跳过：发送方 %s 证书不可用 (group=%s epoch=%s seq=%s)",
                    sender_aid, group_id, msg_epoch, msg_seq,
                )
                self._log.debug("client", "_decrypt_group_message exit (cert-missing): elapsed=%.3fs group=%s seq=%s", time.time() - _t_start, group_id, msg_seq)
                return message

        # 先尝试直接解密
        result = self._group_e2ee.decrypt(message, skip_replay=skip_replay)
        if result is not None and result.get("e2ee"):
            self._log.debug("client", "_decrypt_group_message exit (ok): elapsed=%.3fs group=%s seq=%s", time.time() - _t_start, group_id, msg_seq)
            return self._attach_group_dispatch_mode_to_payload(result)

        # replay guard 命中：decrypt 返回了原消息（非 None）但无 e2ee 字段
        # 这不是解密失败，不应触发 recover
        if result is not None:
            self._log.debug("client",
                "群消息 replay guard 命中，跳过 recover: group=%s seq=%s sender=%s",
                group_id, msg_seq, sender_aid,
            )
            self._log.debug("client", "_decrypt_group_message exit (replay): elapsed=%.3fs group=%s seq=%s", time.time() - _t_start, group_id, msg_seq)
            return result

        # 真正的解密失败（result is None），记录原因
        _has_cert = self._get_verified_peer_cert(sender_aid) is not None if sender_aid else False
        _local_secrets = self._group_e2ee.load_all_secrets(group_id)
        self._log.info("client",
            "群消息解密返回 None：group=%s epoch=%s seq=%s sender=%s "
            "has_cert=%s local_epochs=%s skip_replay=%s",
            group_id, msg_epoch, msg_seq, sender_aid,
            _has_cert, sorted(_local_secrets.keys()) if _local_secrets else [],
            skip_replay,
        )

        # 解密失败时，先同步请求目标 epoch key；5 秒内拿到则立即重解。
        sender = message.get("from", message.get("sender_aid", ""))
        epoch = msg_epoch
        if epoch is not None and group_id:
            self._log.info("client",
                "触发群组 epoch 密钥恢复：group=%s epoch=%s sender=%s",
                group_id, epoch, sender,
            )
            try:
                recovered = await self._recover_group_epoch_key(
                    group_id,
                    int(epoch),
                    sender_aid=str(sender or ""),
                    timeout_s=5.0,
                )
                if recovered:
                    retry = self._group_e2ee.decrypt(message, skip_replay=skip_replay)
                    if retry is not None and retry.get("e2ee"):
                        self._log.debug("client", "_decrypt_group_message exit (recovered): elapsed=%.3fs group=%s seq=%s", time.time() - _t_start, group_id, msg_seq)
                        return self._attach_group_dispatch_mode_to_payload(retry)
                    self._log.warn("client",
                        "群消息密钥恢复后仍解密失败：group=%s seq=%s message_id=%s epoch=%s",
                        group_id, msg_seq, message.get("message_id"), epoch,
                    )
            except Exception as exc:
                self._log.warn("client",
                    "group message key recovery error: group=%s seq=%s message_id=%s epoch=%s error=%s",
                    group_id, msg_seq, message.get("message_id"), epoch, exc,
                )
                self._log.debug("client", "group %s epoch %s sync recovery failed: %s", group_id, epoch, exc)

        self._log.warn("client",
            "group message decrypt failed after key recovery attempt: group=%s seq=%s message_id=%s epoch=%s",
            group_id, msg_seq, message.get("message_id"), msg_epoch,
        )
        self._log.debug("client", "_decrypt_group_message exit (failed): elapsed=%.3fs group=%s seq=%s", time.time() - _t_start, group_id, msg_seq)
        return message

    @staticmethod
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

    async def _decrypt_group_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """批量解密群组消息（用于 group.pull/补洞）。"""
        result = []
        for msg in messages:
            # pull/补洞可能重新拿到已由 push 解密但尚未按序投递的消息；
            # 这里跳过本地 replay guard，避免 burst/乱序场景把待补齐消息误判为重复。
            decrypted = await self._decrypt_group_message(msg, skip_replay=True)
            payload = msg.get("payload") if isinstance(msg, dict) else None
            group_id = msg.get("group_id", "") if isinstance(msg, dict) else ""
            is_encrypted = isinstance(payload, dict) and payload.get("type") == "e2ee.group_encrypted"
            if is_encrypted and isinstance(msg, dict) and group_id and not decrypted.get("e2ee"):
                self._enqueue_pending_decrypt(group_id, msg)
                continue  # R3: 解密失败不入 result，不 publish 密文给应用层
            result.append(decrypted)
        return result

    async def _decrypt_group_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        """解密 group.thought.get 的 RPC 查询结果。

        thought 不是群消息推送/拉取结果，不分配 seq、不发布应用层事件、不 ack。
        因此它必须跳过 group replay guard，也不能进入 republish guard 或有序发布队列。
        """
        if not isinstance(result, dict):
            return result
        items = result.get("thoughts")
        if not result.get("found"):
            result = dict(result)
            result["thoughts"] = []
            return result
        if not isinstance(items, list):
            result = dict(result)
            result["thoughts"] = []
            return result

        group_id = str(result.get("group_id") or "").strip()
        sender_aid = str(result.get("sender_aid") or "").strip()
        thoughts: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            payload = item.get("payload")
            thought_id = str(item.get("thought_id") or item.get("message_id") or "").strip()
            message = {
                "group_id": group_id,
                "sender_aid": sender_aid,
                "from": sender_aid,
                "message_id": thought_id,
                "payload": payload,
                "created_at": item.get("created_at"),
            }
            if isinstance(item.get("context"), dict):
                message["context"] = item["context"]
            decrypted = await self._decrypt_group_message(message, skip_replay=True)
            decrypt_failed = (
                isinstance(payload, dict)
                and payload.get("type") == "e2ee.group_encrypted"
                and not decrypted.get("e2ee")
            )
            thought = {
                "thought_id": thought_id,
                "message_id": thought_id,
                "payload": decrypted.get("payload"),
                "created_at": item.get("created_at"),
                "e2ee": decrypted.get("e2ee"),
            }
            if decrypt_failed:
                thought["decrypt_failed"] = True
            if item.get("context") is not None:
                thought["context"] = item.get("context")
            thoughts.append(thought)

        result_view = dict(result)
        result_view["thoughts"] = thoughts
        return result_view

    async def _decrypt_message_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(result, dict):
            return result
        items = result.get("thoughts")
        if not result.get("found"):
            result = dict(result)
            result["thoughts"] = []
            return result
        if not isinstance(items, list):
            result = dict(result)
            result["thoughts"] = []
            return result

        sender_aid = str(result.get("sender_aid") or "").strip()
        peer_aid = str(result.get("peer_aid") or "").strip()
        thoughts: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            payload = item.get("payload")
            thought_id = str(item.get("thought_id") or item.get("message_id") or "").strip()
            from_aid = str(item.get("from") or sender_aid).strip()
            to_aid = str(item.get("to") or peer_aid).strip()
            message = {
                "from": from_aid,
                "to": to_aid,
                "message_id": thought_id,
                "payload": payload,
                "encrypted": item.get("encrypted", True),
                "timestamp": item.get("created_at"),
            }
            if isinstance(item.get("context"), dict):
                message["context"] = item["context"]
            decrypted = message
            decrypt_failed = False
            if isinstance(payload, dict) and payload.get("type") == "e2ee.encrypted":
                if not self._e2ee._should_decrypt_for_current_aid(message, payload):
                    decrypt_failed = True
                else:
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
                            self._log.warn("client", 
                                "p2p.thought.decrypt failed: 无法获取发送方证书 thought_id=%s from=%s",
                                thought_id, from_aid,
                            )
                            decrypt_failed = True
                    if not decrypt_failed:
                        decrypted = self._e2ee._decrypt_message(message, source="message.thought.get")
                        if decrypted is None:
                            self._log.warn("client", "p2p.thought.decrypt failed thought_id=%s", thought_id)
                            decrypt_failed = True
                            decrypted = message
            thought = {
                "thought_id": thought_id,
                "message_id": thought_id,
                "from": from_aid,
                "to": to_aid,
                "payload": decrypted.get("payload") if isinstance(decrypted, dict) else None,
                "created_at": item.get("created_at"),
                "e2ee": decrypted.get("e2ee") if isinstance(decrypted, dict) else None,
            }
            if decrypt_failed:
                thought["decrypt_failed"] = True
            if item.get("context") is not None:
                thought["context"] = item.get("context")
            thoughts.append(thought)

        result_view = dict(result)
        result_view["thoughts"] = thoughts
        return result_view

    async def _try_handle_group_key_message(self, message: dict[str, Any]) -> bool:
        """尝试处理 P2P 传输的群组密钥消息。返回 True 表示已处理（不再传播）。

        只有明文 type 或 P2P 加密信封解密后的内层 type 明确命中
        e2ee.group_key_* 时才拦截。外层 E2EE 解密失败交给普通链路处理，
        普通链路不会投递原始密文。
        """
        _t_start = time.time()
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
                self._log.warn("client", 
                    "群组密钥控制消息 P2P 解密失败：from=%s message_id=%s",
                    message.get("from"), message.get("message_id"),
                )
                return False
            self._schedule_prekey_replenish_if_consumed(decrypted)
            actual_payload = decrypted.get("payload", {})
            if not isinstance(actual_payload, dict):
                return False
            inner_type = actual_payload.get("type")
            if inner_type in _GROUP_KEY_TYPES:
                is_control_plane = True

        if is_control_plane:
            _debug_group_e2ee(
                "control_message",
                aid=self._aid or "",
                outer_type=outer_type or "-",
                inner_type=str(actual_payload.get("type") or "-") if isinstance(actual_payload, dict) else "-",
                from_aid=str(message.get("from") or "-"),
                group=str(actual_payload.get("group_id") or "-") if isinstance(actual_payload, dict) else "-",
                epoch=actual_payload.get("epoch", "-") if isinstance(actual_payload, dict) else "-",
                rotation=str(actual_payload.get("rotation_id") or "-") if isinstance(actual_payload, dict) else "-",
                request_id=str(actual_payload.get("request_id") or "-") if isinstance(actual_payload, dict) else "-",
            )

        if not is_control_plane:
            # 不是控制面消息，交给原 handle_incoming 兜底（其只对 group_key_* 返回非 None）
            result = self._group_e2ee.handle_incoming(actual_payload)
            if result is None:
                return False
        else:
            if actual_payload.get("type") == "e2ee.group_key_distribution":
                # 快速跳过已过期的历史 epoch 分发：本地已有更高 committed epoch 时，
                # 不发任何 RPC（verify/ack/sync），避免 fillP2pGap 拉到大量历史群密钥
                # 消息时触发 epoch 编排风暴（几十个群 × 多次轮换 = 上百条 RPC）。
                dist_group_id = str(actual_payload.get("group_id") or "").strip()
                dist_epoch = int(actual_payload.get("epoch") or 0)
                if dist_group_id and dist_epoch > 0:
                    local_epoch = self._group_e2ee.current_epoch(dist_group_id) or 0
                    if local_epoch >= dist_epoch:
                        self._log.debug("client",
                            "skip stale group_key_distribution: group=%s msg_epoch=%d local_epoch=%d",
                            dist_group_id, dist_epoch, local_epoch,
                        )
                        return True
                if not await self._verify_active_group_rotation_distribution(actual_payload):
                    self._log.warn("client",
                        "拒绝 group key distribution：group=%s epoch=%s rotation=%s",
                        actual_payload.get("group_id"), actual_payload.get("epoch"),
                        actual_payload.get("rotation_id"),
                    )
                    return True
            elif actual_payload.get("type") == "e2ee.group_key_response":
                # 同样跳过已过期的 key_response
                resp_group_id = str(actual_payload.get("group_id") or "").strip()
                resp_epoch = int(actual_payload.get("epoch") or 0)
                if resp_group_id and resp_epoch > 0:
                    local_epoch = self._group_e2ee.current_epoch(resp_group_id) or 0
                    if local_epoch >= resp_epoch:
                        self._log.debug("client",
                            "skip stale group_key_response: group=%s msg_epoch=%d local_epoch=%d",
                            resp_group_id, resp_epoch, local_epoch,
                        )
                        return True
                if not await self._verify_group_key_response_epoch(actual_payload):
                    self._log.warn("client",
                        "拒绝 group key response：group=%s epoch=%s commitment=%s",
                        actual_payload.get("group_id"), actual_payload.get("epoch"),
                        str(actual_payload.get("commitment") or "")[:16],
                    )
                    return True
            result = self._group_e2ee.handle_incoming(actual_payload)
            if result == "distribution":
                await self._discard_group_distribution_if_stale(actual_payload)
                # 收到 epoch key 说明该群有活动，触发惰性同步建立 seq 基线
                dist_group_id = actual_payload.get("group_id", "")
                if dist_group_id and dist_group_id not in self._group_synced:
                    asyncio.ensure_future(self._lazy_sync_group(dist_group_id))

        if result == "request":
            # 处理密钥请求并回复
            group_id = actual_payload.get("group_id", "")
            requester = actual_payload.get("requester_aid", "")
            members = self._group_e2ee.get_member_aids(group_id)
            # 请求者不在本地成员列表时，回源查询服务端最新成员列表
            # （覆盖 use_invite_code 等不经过 owner 客户端的入群路径）
            # 注意：仅用于传递 current_members 做当前成员校验，
            # 不改写历史 epoch 的 member_aids，防止破坏历史隔离。
            if requester and requester not in members:
                try:
                    members_result = await self.call("group.get_members", {"group_id": group_id})
                    members = [m["aid"] for m in members_result.get("members", [])]
                except Exception as exc:
                    self._log.warn("client", "group %s member list origin fetch failed: %s", group_id, exc)

            response = self._group_e2ee.handle_key_request_msg(actual_payload, members)
            _debug_group_e2ee(
                "p2p_key_request_handle",
                aid=self._aid or "",
                group=group_id,
                epoch=actual_payload.get("epoch", "-"),
                requester=requester or "-",
                members=len(members) if isinstance(members, list) else "-",
                has_response=bool(response),
            )
            if response:
                if requester:
                    try:
                        _debug_group_e2ee(
                            "p2p_key_response_send",
                            aid=self._aid or "",
                            group=group_id,
                            epoch=response.get("epoch", "-"),
                            requester=requester,
                            request_id=str(response.get("request_id") or "-"),
                            responder=str(response.get("responder_aid") or "-"),
                            has_sig=bool(response.get("response_signature")),
                        )
                        await self.call("message.send", {
                            "to": requester,
                            "payload": response,
                            "encrypt": True,
                            "persist_required": True,
                        })
                        _debug_group_e2ee(
                            "p2p_key_response_sent",
                            aid=self._aid or "",
                            group=group_id,
                            epoch=response.get("epoch", "-"),
                            requester=requester,
                            request_id=str(response.get("request_id") or "-"),
                        )
                    except Exception as exc:
                        self._log.warn("client", "failed to reply group key to %s: %s", requester, exc)
                        _debug_group_e2ee(
                            "p2p_key_response_failed",
                            aid=self._aid or "",
                            group=group_id,
                            epoch=response.get("epoch", "-"),
                            requester=requester,
                            error=type(exc).__name__,
                            detail=str(exc),
                        )

        # PY-002: 密钥分发/响应成功后，触发待解密消息重试
        if result in ("distribution", "response"):
            group_id_for_retry = actual_payload.get("group_id", "")
            rotation_id = str(actual_payload.get("rotation_id") or "")
            key_commitment = str(actual_payload.get("commitment") or "")
            if rotation_id and key_commitment:
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._ack_group_rotation_key(
                    rotation_id=rotation_id,
                    key_commitment=key_commitment,
                ))
            self._schedule_retry_pending_decrypt_msgs(group_id_for_retry)

        if is_control_plane:
            _debug_group_e2ee(
                "control_message_result",
                aid=self._aid or "",
                group=str(actual_payload.get("group_id") or "-") if isinstance(actual_payload, dict) else "-",
                epoch=actual_payload.get("epoch", "-") if isinstance(actual_payload, dict) else "-",
                type=str(actual_payload.get("type") or "-") if isinstance(actual_payload, dict) else "-",
                result=result or "-",
            )

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

    def _invalidate_peer_prekey_cache(self, peer_aid: str) -> None:
        """清除指定对端的 prekey 缓存。"""
        self._peer_prekeys_cache.pop(peer_aid, None)
        self._e2ee.invalidate_prekey_cache(peer_aid)

    def _clear_peer_cert_cache(self, peer_aid: str) -> None:
        """清除指定对端的证书缓存。"""
        keys_to_remove = [k for k in self._cert_cache if k == peer_aid or k.startswith(f"{peer_aid}#")]
        for k in keys_to_remove:
            del self._cert_cache[k]

    async def _refresh_peer_prekeys(self, peer_aid: str) -> list[dict[str, Any]]:
        """清除对端缓存后重新获取 prekeys。"""
        self._invalidate_peer_prekey_cache(peer_aid)
        self._clear_peer_cert_cache(peer_aid)
        return await self._fetch_peer_prekeys(peer_aid)

    async def _fetch_peer_prekeys(self, peer_aid: str) -> list[dict[str, Any]]:
        """获取对方所有设备的 prekey 列表。"""
        _t_start = time.time()
        self._log.debug("client", "_fetch_peer_prekeys enter: peer=%s", peer_aid)
        cached_list = self._peer_prekeys_cache.get(peer_aid)
        if cached_list is not None:
            items, expire_at = cached_list
            if time.time() < expire_at:
                normalized = self._normalize_peer_prekeys(items)
                if normalized:
                    self._log.debug("client", "_fetch_peer_prekeys exit (cache-hit): elapsed=%.3fs peer=%s count=%d", time.time() - _t_start, peer_aid, len(normalized))
                    return normalized
            self._peer_prekeys_cache.pop(peer_aid, None)
        cached = self._e2ee.get_cached_prekey(peer_aid)
        if cached is not None:
            normalized = self._normalize_peer_prekeys([cached])
            if normalized:
                self._log.debug("client", "_fetch_peer_prekeys exit (e2ee-cache): elapsed=%.3fs peer=%s count=%d", time.time() - _t_start, peer_aid, len(normalized))
                return normalized
        try:
            result = await self._transport.call("message.e2ee.get_prekey", {"aid": peer_aid})
        except Exception as exc:
            self._log.debug("client", "_fetch_peer_prekeys exit (rpc-error): elapsed=%.3fs peer=%s err=%s", time.time() - _t_start, peer_aid, exc)
            raise ValidationError(f"failed to fetch peer prekey for {peer_aid}: {exc}") from exc
        if not isinstance(result, dict):
            raise ValidationError(f"invalid prekey response for {peer_aid}")
        if result.get("found") is False:
            self._log.debug("client", "_fetch_peer_prekeys exit (not-found): elapsed=%.3fs peer=%s", time.time() - _t_start, peer_aid)
            return []

        device_prekeys = result.get("device_prekeys")
        if isinstance(device_prekeys, list):
            normalized = self._normalize_peer_prekeys(device_prekeys)
            if normalized:
                self._peer_prekeys_cache[peer_aid] = (
                    [dict(item) for item in normalized],
                    time.time() + _PEER_PREKEYS_CACHE_TTL,
                )
                self._e2ee.cache_prekey(peer_aid, normalized[0])
                self._log.debug("client", "_fetch_peer_prekeys exit: elapsed=%.3fs peer=%s count=%d", time.time() - _t_start, peer_aid, len(normalized))
                return normalized

        prekey = result.get("prekey")
        if isinstance(prekey, dict):
            normalized = self._normalize_peer_prekeys([prekey])
            if normalized:
                self._peer_prekeys_cache[peer_aid] = (
                    [dict(item) for item in normalized],
                    time.time() + _PEER_PREKEYS_CACHE_TTL,
                )
                self._e2ee.cache_prekey(peer_aid, normalized[0])
                self._log.debug("client", "_fetch_peer_prekeys exit (single): elapsed=%.3fs peer=%s count=%d", time.time() - _t_start, peer_aid, len(normalized))
                return normalized
        if result.get("found"):
            raise ValidationError(f"invalid prekey response for {peer_aid}")
        self._log.debug("client", "_fetch_peer_prekeys exit (empty): elapsed=%.3fs peer=%s", time.time() - _t_start, peer_aid)
        return []

    async def _fetch_peer_prekey(self, peer_aid: str) -> dict[str, Any] | None:
        """获取对方的单个 prekey（兼容接口，优先返回第一条 device prekey）。"""
        cached_list = self._peer_prekeys_cache.get(peer_aid)
        if cached_list is not None:
            items, expire_at = cached_list
            if time.time() < expire_at and items:
                normalized = self._normalize_peer_prekeys(items)
                if normalized:
                    return dict(normalized[0])
            self._peer_prekeys_cache.pop(peer_aid, None)
        cached = self._e2ee.get_cached_prekey(peer_aid)
        if cached is not None:
            normalized = self._normalize_peer_prekeys([cached])
            if normalized:
                return dict(normalized[0])
        prekeys = await self._fetch_peer_prekeys(peer_aid)
        return dict(prekeys[0]) if prekeys else None

    def _normalize_peer_prekeys(self, prekeys: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for item in prekeys:
            if not isinstance(item, dict):
                continue
            prekey_id = str(item.get("prekey_id") or "").strip()
            public_key = str(item.get("public_key") or "").strip()
            signature = str(item.get("signature") or "").strip()
            if not prekey_id or not public_key or not signature:
                continue
            candidate = dict(item)
            candidate["prekey_id"] = prekey_id
            candidate["public_key"] = public_key
            candidate["signature"] = signature
            candidate["device_id"] = str(candidate.get("device_id") or "").strip()
            cert_fingerprint = str(candidate.get("cert_fingerprint") or "").strip().lower()
            if cert_fingerprint:
                candidate["cert_fingerprint"] = cert_fingerprint
            elif "cert_fingerprint" in candidate:
                candidate.pop("cert_fingerprint", None)
            normalized.append(candidate)
        if not normalized:
            return []
        if len(normalized) == 1:
            if not normalized[0]["device_id"]:
                normalized[0]["device_id"] = _PREKEY_FALLBACK_DEVICE_ID
            return normalized
        filtered: list[dict[str, Any]] = []
        seen_device_ids: set[str] = set()
        for item in normalized:
            device_id = str(item.get("device_id") or "").strip()
            if not device_id or device_id == _PREKEY_FALLBACK_DEVICE_ID:
                continue
            if device_id in seen_device_ids:
                continue
            seen_device_ids.add(device_id)
            filtered.append(item)
        return filtered

    async def _upload_prekey(self) -> dict[str, Any]:
        """生成 prekey 并上传到服务端"""
        prekey_material = self._e2ee.generate_prekey()
        prekey_id = prekey_material.get("prekey_id", "?")
        self._log.info("client", "prekey uploading: prekey_id=%s", prekey_id)
        result = await self._transport.call("message.e2ee.put_prekey", prekey_material)
        self._log.info("client", "prekey upload done: prekey_id=%s result=%s", prekey_id, result)
        # 上传成功后记录为活跃 prekey：只有活跃 prekey 被消费时才触发 replenish
        self._active_prekey_id = str(prekey_id)
        return result if isinstance(result, dict) else {"ok": True}

    async def _decrypt_messages(self, messages: list[dict[str, Any]], *, source: str = "pull") -> list[dict[str, Any]]:
        """批量解密消息（用于 message.pull）。

        直接解密，不经过 E2EEManager 的 seen set（避免与推送冲突）。
        同一批次内按 message_id 去重。
        群组密钥控制面消息只更新本地群密钥状态，不暴露给业务消息流。
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
            if isinstance(payload, dict) and payload.get("type") != "e2ee.encrypted" and msg.get("encrypted") is True:
                self._log.debug("client", "pull skipping encrypted message: payload.type=%r mid=%s keys=%s",
                                  payload.get("type"), mid, list(payload.keys())[:10])
            if (isinstance(payload, dict)
                and payload.get("type") == "e2ee.encrypted"
                and (msg.get("encrypted") is True or "encrypted" not in msg)):
                if await self._try_handle_group_key_message(msg):
                    continue
                if not self._e2ee._should_decrypt_for_current_aid(msg, payload):
                    self._log.debug("client", "[%s] P2P decrypt skipped: message not targeting current AID message_id=%s", source, mid)
                    continue
                # prekey 预检查：prekey_ecdh_v2 模式下，local missing prekey 私钥则跳过解密
                enc_mode = payload.get("encryption_mode", "")
                prekey_id = payload.get("prekey_id") or (payload.get("aad") or {}).get("prekey_id") or ""
                if enc_mode == "prekey_ecdh_v2" and prekey_id:
                    if prekey_id in self._e2ee._missing_prekey_ids:
                        self._log.debug("client", "[%s] P2P decrypt skipped: missing local prekey private key message_id=%s prekey_id=%s",
                                          source, mid, prekey_id)
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
                        self._log.warn("client", "cannot get sender %s cert, skipping decrypt", from_aid)
                        continue
                decrypted = self._e2ee._decrypt_message(msg, source=source)
                mid = msg.get("message_id", "")
                seq_val = msg.get("seq", "?")
                if decrypted is not None:
                    self._log.debug("client", "[%s] P2P decrypt success: message_id=%s seq=%s from=%s", source, mid, seq_val, from_aid)
                else:
                    self._log.debug("client", "[%s] P2P decrypt failed: message_id=%s seq=%s from=%s", source, mid, seq_val, from_aid)
                # pull 路径不触发 prekey 补充（历史消息，prekey 早在推送时消耗过）
                if decrypted is not None:
                    result.append(decrypted)
            else:
                result.append(msg)
        return result

    async def _decrypt_single_message(self, message: dict[str, Any], *, source: str = "push") -> dict[str, Any] | None:
        """解密单条消息：本地实例级防重放 + 密码学解密。"""
        payload = message.get("payload")
        if not isinstance(payload, dict):
            self._log.debug("client", "_decrypt_single skipped: payload is not dict, mid=%s", message.get("message_id"))
            return message
        ptype = payload.get("type")
        if ptype != "e2ee.encrypted":
            self._log.debug("client", "_decrypt_single skipped: payload.type=%r != 'e2ee.encrypted', mid=%s encrypted=%r keys=%s",
                              ptype, message.get("message_id"), message.get("encrypted"), list(payload.keys())[:10])
            return message
        if message.get("encrypted") is not True and "encrypted" in message:
            self._log.debug("client", "_decrypt_single skipped: encrypted=%r, mid=%s", message.get("encrypted"), message.get("message_id"))
            return message
        if not self._e2ee._should_decrypt_for_current_aid(message, payload):
            self._log.debug("client", "[%s] P2P decrypt skipped: message not targeting current AID message_id=%s", source, message.get("message_id"))
            return None

        # 接收侧不再调用服务端 replay guard；服务端入口已做 AID 级防重放。
        # 这里依赖当前 SDK 实例本地 seen set，避免多设备/多 slot fanout 被全局去重误杀。
        message_id = message.get("message_id", "")
        from_aid = message.get("from", "")
        encryption_mode = payload.get("encryption_mode", "")
        sender_cert_fingerprint = str(
            payload.get("sender_cert_fingerprint")
            or (payload.get("aad") or {}).get("sender_cert_fingerprint")
            or ""
        ).strip().lower()

        # 确保发送方证书已缓存到 keystore（三路 ECDH + 签名验证需要）
        if from_aid:
            cert_ready = await self._ensure_sender_cert_cached(
                from_aid, sender_cert_fingerprint or None,
            )
            if not cert_ready:
                self._log.warn("client", "cannot get sender %s cert, skipping decrypt", from_aid)
                return None

        # 密码学解密（E2EEManager.decrypt_message 内含本地防重放）
        decrypted = self._e2ee.decrypt_message(message, source=source)
        if decrypted is None:
            self._log.warn("client", "[%s] message decrypt returned None: message_id=%s seq=%s from=%s encryption_mode=%s",
                                source, message_id, message.get("seq"), from_aid, encryption_mode)
        else:
            e2ee_info = decrypted.get("e2ee", {}) if isinstance(decrypted, dict) else {}
            self._log.debug("client", "[%s] P2P decrypt success: message_id=%s seq=%s from=%s mode=%s prekey=%s",
                              source, message_id, message.get("seq"), from_aid,
                              e2ee_info.get("encryption_mode", "?"), e2ee_info.get("prekey_id", "?"))
        self._schedule_prekey_replenish_if_consumed(decrypted)
        return decrypted

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

            # 上线后自动上传 prekey（最多重试 3 次，指数退避）
            for _prekey_attempt in range(3):
                try:
                    await self._upload_prekey()
                    break
                except Exception as exc:
                    self._log.warn("client", "prekey upload failed (attempt %d/3): %s", _prekey_attempt + 1, exc)
                    if _prekey_attempt < 2:
                        await asyncio.sleep(0.5 * (2 ** _prekey_attempt))

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
        self._start_group_epoch_tasks()

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
        for key, task in list(self._group_epoch_rotation_retry_tasks.items()):
            task.cancel()
            if task is current_task:
                continue
            try:
                await task
            except asyncio.CancelledError:
                pass
            self._group_epoch_rotation_retry_tasks.pop(key, None)

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

    def _start_prekey_refresh_task(self) -> None:
        if self._prekey_refresh_task is not None and not self._prekey_refresh_task.done():
            return
        interval = 3600.0  # 每小时检查一次 prekey 是否需要补充
        self._prekey_refresh_task = asyncio.get_event_loop().create_task(
            self._prekey_refresh_loop(interval)
        )

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
                    self._log.warn("client", "prekey periodic refresh failed: %s", exc)
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

    def _maybe_append_echo_trace_send(self, params: dict[str, Any]) -> None:
        """明文 echo 消息发送时追加 SDK.send trace"""
        payload = params.get("payload")
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
        trace = f"{ts} [AUN-SDK.send] aid={self._aid or '-'} conn_uptime={uptime}s"
        params["payload"] = {**payload, "text": text + "\n" + trace}

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

    def _schedule_prekey_replenish_if_consumed(self, message: dict[str, Any] | None) -> None:
        """活跃 prekey 被消费时上传新 prekey。

        只有当前活跃 prekey（connect 后最近一次上传的）被消费才触发上传。
        历史 prekey 被消费（如 fillP2pGap 拉到的旧消息）不触发，避免上传风暴。
        活跃 prekey 只有一个且只能被消费一次，天然串行，无需 inflight 限流。
        """
        prekey_id = self._extract_consumed_prekey_id(message)
        if not prekey_id or self._state != "connected":
            return
        if not self._active_prekey_id or prekey_id != self._active_prekey_id:
            return
        # 清空活跃标记，防止重复触发（新上传完成后会设新的 active）
        self._active_prekey_id = ""

        async def _replenish() -> None:
            try:
                await self._upload_prekey()
            except Exception as exc:
                self._log.warn("client", "prekey replenish after consumption failed: %s", exc)

        loop = getattr(self, "_loop", None)
        if loop and loop.is_running():
            loop.create_task(_replenish())
        else:
            try:
                asyncio.get_running_loop().create_task(_replenish())
            except RuntimeError:
                pass

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
        if hasattr(self, "_pending_decrypt_msgs"):
            self._pending_decrypt_msgs.clear()
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
        if hasattr(self, "_pending_decrypt_msgs"):
            self._pending_decrypt_msgs.clear()
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

    def _build_rotation_signature(
        self,
        group_id: str,
        current_epoch: int,
        new_epoch: int = 0,
        params: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """构建 epoch 轮换签名参数。"""
        identity = self._identity
        if not identity or not identity.get("private_key_pem"):
            return {}
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
            aid = identity.get("aid", "")
            ts = str(int(time.time()))
            target_epoch = int(new_epoch or current_epoch + 1)
            source = params or {}
            sign_payload = {
                "version": "v2",
                "group_id": group_id,
                "base_epoch": int(current_epoch),
                "target_epoch": target_epoch,
                "aid": aid,
                "rotation_timestamp": ts,
                "rotation_id": str(source.get("rotation_id") or source.get("new_rotation_id") or ""),
                "reason": str(source.get("reason") or ""),
                "key_commitment": str(source.get("key_commitment") or ""),
                "manifest_hash": str(source.get("manifest_hash") or ""),
                "epoch_chain": str(source.get("epoch_chain") or ""),
                "expected_members": sorted(str(item) for item in source.get("expected_members", []) if str(item or "").strip())
                if isinstance(source.get("expected_members"), list) else [],
                "required_acks": sorted(str(item) for item in source.get("required_acks", []) if str(item or "").strip())
                if isinstance(source.get("required_acks"), list) else [],
            }
            sign_data = json.dumps(
                sign_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            pk = _ser.load_pem_private_key(
                identity["private_key_pem"].encode("utf-8"), password=None,
            )
            sig = pk.sign(sign_data, _ec.ECDSA(_hashes.SHA256()))
            return {
                "rotation_sig_version": "v2",
                "rotation_signature": base64.b64encode(sig).decode("ascii"),
                "rotation_timestamp": ts,
            }
        except Exception as _sig_exc:
            self._log.warn("client", "failed to build rotation signature: %s", _sig_exc)
            return {}

    @staticmethod
    def _attach_rotation_id(info: dict[str, Any], rotation_id: str) -> None:
        if not rotation_id:
            return
        for dist in info.get("distributions", []):
            if not isinstance(dist, dict):
                continue
            payload = dist.get("payload")
            if isinstance(payload, dict):
                payload["rotation_id"] = rotation_id

    async def _build_epoch_encrypted_keys(
        self,
        info: dict[str, Any],
        member_aids: list[str],
        target_epoch: int,
        group_id: str,
    ) -> dict[str, str]:
        """为每个成员用其 AID 证书公钥 ECIES 加密 group_secret，返回 {aid: base64_ciphertext}。"""
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from .e2ee import ecies_encrypt
        # 从 distribution payload 中提取 group_secret
        distributions = info.get("distributions", [])
        group_secret_b64 = ""
        for dist in distributions:
            if isinstance(dist, dict) and isinstance(dist.get("payload"), dict):
                group_secret_b64 = dist["payload"].get("group_secret", "")
                if group_secret_b64:
                    break
        if not group_secret_b64:
            # fallback: 从本地 keystore 加载
            loaded = self._group_e2ee.load_secret(group_id, target_epoch)
            if loaded and loaded.get("secret"):
                group_secret_bytes = loaded["secret"]
            else:
                self._log.warn("client", "cannot get group_secret for ECIES encryption: group=%s epoch=%s", group_id, target_epoch)
                return {}
        else:
            group_secret_bytes = base64.b64decode(group_secret_b64)

        encrypted_keys: dict[str, str] = {}
        for aid in member_aids:
            try:
                if aid == self._aid and isinstance(self._identity, dict) and self._identity.get("cert"):
                    raw_cert = self._identity.get("cert")
                    cert_bytes = raw_cert.encode("utf-8") if isinstance(raw_cert, str) else bytes(raw_cert)
                else:
                    cert_bytes = await self._fetch_peer_cert(aid)
                cert_obj = _x509.load_pem_x509_certificate(cert_bytes)
                pubkey = cert_obj.public_key()
                if not isinstance(pubkey, _ec.EllipticCurvePublicKey):
                    self._log.debug("client", "member %s cert public key is not EC type, skipping ECIES encryption", aid)
                    continue
                pubkey_bytes = pubkey.public_bytes(
                    _ser.Encoding.X962,
                    _ser.PublicFormat.UncompressedPoint,
                )
                ciphertext = ecies_encrypt(pubkey_bytes, group_secret_bytes)
                encrypted_keys[aid] = base64.b64encode(ciphertext).decode("ascii")
            except Exception as exc:
                self._log.warn("client", "failed to build ECIES epoch key for member %s: %s", aid, exc)
                continue
        return encrypted_keys

    async def _distribute_group_epoch_key(
        self,
        info: dict[str, Any],
        *,
        rotation_id: str = "",
    ) -> dict[str, list[str]]:
        sent: list[str] = []
        failed: list[str] = []
        last_heartbeat = time.monotonic()
        for dist in info.get("distributions", []):
            if not isinstance(dist, dict):
                continue
            target = dist.get("to")
            payload = dist.get("payload")
            if not target or not isinstance(payload, dict):
                continue
            if rotation_id and time.monotonic() - last_heartbeat >= 20.0:
                if await self._heartbeat_group_rotation(rotation_id):
                    last_heartbeat = time.monotonic()
            for attempt in range(3):
                try:
                    await self.call("message.send", {
                        "to": target,
                        "payload": payload,
                        "encrypt": True,
                        "persist_required": True,
                    })
                    sent.append(str(target))
                    break
                except Exception as exc:
                    if attempt < 2:
                        await asyncio.sleep(1.0 * (attempt + 1))
                    else:
                        failed.append(str(target))
                        self._log.warn("client", "epoch key distribution failed (to=%s): %s", target, exc)
        return {"sent": sent, "failed": failed}

    async def _heartbeat_group_rotation(self, rotation_id: str) -> bool:
        if not rotation_id:
            return False
        try:
            result = await self.call("group.e2ee.heartbeat_rotation", {
                "rotation_id": rotation_id,
                "lease_ms": _GROUP_ROTATION_LEASE_MS,
            })
            return bool(isinstance(result, dict) and result.get("success"))
        except Exception as exc:
            self._log.warn("client", "refresh epoch rotation lease failed: rotation=%s err=%s", rotation_id, exc)
            return False

    async def _abort_group_rotation(self, rotation_id: str, *, reason: str = "") -> bool:
        if not rotation_id:
            return False
        try:
            result = await self.call("group.e2ee.abort_rotation", {
                "rotation_id": rotation_id,
                "reason": reason or "client_abort",
            })
            return bool(isinstance(result, dict) and result.get("success"))
        except Exception as exc:
            self._log.warn("client", "abort epoch rotation failed: rotation=%s err=%s", rotation_id, exc)
            return False

    @staticmethod
    def _rotation_expected_members_stale(rotation: dict[str, Any], member_aids: list[str]) -> bool:
        expected = rotation.get("expected_members")
        if not isinstance(expected, list) or not expected:
            return False
        expected_members = sorted({str(item) for item in expected if str(item or "").strip()})
        current_members = sorted({str(item) for item in member_aids if str(item or "").strip()})
        return bool(expected_members and current_members and expected_members != current_members)

    @staticmethod
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

    def _schedule_group_rotation_retry(
        self,
        group_id: str,
        *,
        reason: str,
        trigger_id: str,
        expected_epoch: int | None,
        pending: dict[str, Any] | None,
    ) -> None:
        if self._closing or self._state != "connected":
            return
        retry_key = f"{group_id}:{trigger_id or reason}:{expected_epoch if expected_epoch is not None else '-'}"
        existing = self._group_epoch_rotation_retry_tasks.get(retry_key)
        if existing is not None and not existing.done():
            return
        delay = self._rotation_retry_delay_s(pending)

        async def _retry_later() -> None:
            try:
                await asyncio.sleep(delay)
                if self._closing or self._state != "connected":
                    return
                await self._maybe_lead_rotate_group_epoch(
                    group_id,
                    reason=reason,
                    trigger_id=trigger_id,
                    expected_epoch=expected_epoch,
                )
            except asyncio.CancelledError:
                raise
            finally:
                self._group_epoch_rotation_retry_tasks.pop(retry_key, None)

        self._group_epoch_rotation_retry_tasks[retry_key] = asyncio.create_task(_retry_later())

    async def _sync_epoch_to_server(self, group_id: str) -> None:
        """建群后将本地 epoch 1 同步到服务端（服务端初始为 0），最多重试 3 次。"""
        wait_started = time.monotonic()
        while group_id in self._group_epoch_rotation_inflight:
            if self._closing or self._state != "connected":
                return
            if time.monotonic() - wait_started > 20.0:
                self._log.warn("client", "group epoch create sync still in-flight; skip duplicate sync (group=%s)", group_id)
                return
            await asyncio.sleep(0.2)
        self._group_epoch_rotation_inflight.add(group_id)
        try:
            max_retries = 3
            for attempt in range(1, max_retries + 1):
                try:
                    secret_data = self._group_e2ee.load_secret(group_id, 1)
                    if not secret_data:
                        raise StateError(f"group {group_id} epoch 1 secret missing")
                    rotation_id = f"rot-{uuid.uuid4().hex}"
                    rotate_params = {
                        "group_id": group_id,
                        "base_epoch": 0,
                        "target_epoch": 1,
                        "rotation_id": rotation_id,
                        "reason": "create_group",
                        "key_commitment": secret_data.get("commitment", ""),
                        "expected_members": secret_data.get("member_aids", [self._aid] if self._aid else []),
                        "required_acks": [self._aid] if self._aid else [],
                        "lease_ms": _GROUP_ROTATION_LEASE_MS,
                    }
                    rotate_params.update(self._build_rotation_signature(group_id, 0, 1, rotate_params))
                    begin_result = await self.call("group.e2ee.begin_rotation", rotate_params)
                    rotation = begin_result.get("rotation") if isinstance(begin_result, dict) else None
                    if not begin_result.get("success") or not isinstance(rotation, dict):
                        self._log.warn("client", 
                            "group epoch begin failed; stop key distribution (group=%s, returned=%s)",
                            group_id, begin_result,
                        )
                        return
                    if not await self._ack_group_rotation_key(
                        rotation_id=rotation.get("rotation_id", rotation_id),
                        key_commitment=secret_data.get("commitment", ""),
                    ):
                        self._log.warn("client", "group epoch self ack failed (group=%s, rotation=%s)", group_id, rotation_id)
                        await self._abort_group_rotation(rotation.get("rotation_id", rotation_id), reason="self_ack_failed")
                        return
                    commit_result = await self.call("group.e2ee.commit_rotation", {
                        "rotation_id": rotation.get("rotation_id", rotation_id),
                    })
                    if commit_result.get("success"):
                        self._group_e2ee.store_secret(
                            group_id,
                            1,
                            secret_data["secret"],
                            secret_data.get("commitment", ""),
                            secret_data.get("member_aids", [self._aid] if self._aid else []),
                            epoch_chain=secret_data.get("epoch_chain"),
                        )
                        return
                    self._log.warn("client", 
                        "group epoch commit failed (group=%s, returned=%s)",
                        group_id, commit_result,
                    )
                    return
                except Exception as exc:
                    if attempt < max_retries:
                        delay = 0.5 * (2 ** (attempt - 1))
                        self._log.warn("client", 
                            "同步 epoch 到服务端失败 (group=%s, 第%d/%d次): %s, %.1fs后重试",
                            group_id, attempt, max_retries, exc, delay,
                        )
                        await asyncio.sleep(delay)
                    else:
                        self._log.error("client", 
                            "同步 epoch 到服务端最终失败 (group=%s, 已重试%d次): %s",
                            group_id, max_retries, exc,
                        )
        finally:
            self._group_epoch_rotation_inflight.discard(group_id)

    async def _maybe_lead_rotate_group_epoch(self, group_id: str, *, reason: str = "membership_changed", trigger_id: str = "", expected_epoch: int | None = None, allow_member: bool = False) -> None:
        """基于"排序最小 admin = leader"选举，其他 admin 走 jitter 兜底重试。

        allow_member=True 时（open/invite_code 群），普通 member 也参与选举，
        优先级：owner/admin 排序在前 > member 排序在后。
        V2 群强制 owner/admin-only（无论 allow_member 参数）。
        """
        # V2 群：强制 owner/admin-only rotation
        cache_key = f"group:{group_id}"
        cached = self._v2_bootstrap_cache.get(cache_key)
        if cached and len(cached) > 2 and cached[2] is not None:
            allow_member = False
        _t_start = time.time()
        my_aid = self._aid
        if not my_aid or self._closing or self._state != "connected":
            return
        self._log.debug("client", "_maybe_lead_rotate_group_epoch enter: group=%s reason=%s trigger=%s expected_epoch=%s allow_member=%s", group_id, reason, trigger_id or "-", expected_epoch, allow_member)
        wait_started = time.monotonic()
        while group_id in self._group_epoch_rotation_inflight:
            if reason == "membership_changed" and trigger_id and trigger_id in self._group_membership_rotation_done:
                self._log.debug("client", "_maybe_lead_rotate_group_epoch exit (already-done): elapsed=%.3fs group=%s trigger=%s", time.time() - _t_start, group_id, trigger_id)
                return
            if self._closing or self._state != "connected":
                self._log.debug("client", "_maybe_lead_rotate_group_epoch exit (closing): elapsed=%.3fs group=%s", time.time() - _t_start, group_id)
                return
            if time.monotonic() - wait_started > 20.0:
                self._log.warn("client",
                    "group epoch rotation still in-flight; skip pending trigger (group=%s trigger=%s)",
                    group_id, trigger_id or "-",
                )
                self._log.debug("client", "_maybe_lead_rotate_group_epoch exit (timeout): elapsed=%.3fs group=%s", time.time() - _t_start, group_id)
                return
            await asyncio.sleep(0.2)
        self._group_epoch_rotation_inflight.add(group_id)
        try:
            if self._closing or self._state != "connected":
                self._log.debug("client", "_maybe_lead_rotate_group_epoch exit (closing-2): elapsed=%.3fs group=%s", time.time() - _t_start, group_id)
                return
            # 1. 获取候选成员。open/invite_code 场景优先使用在线成员列表。
            members_resp = await self.call("group.get_members", {"group_id": group_id})
            if not isinstance(members_resp, dict):
                members_resp = {}
            candidates = await self._ranked_group_rotation_candidates(
                group_id,
                allow_member=allow_member,
                members_resp=members_resp,
            )
            if not candidates:
                self._log.debug("client", "epoch rotation no candidates, skipping: group=%s", group_id)
                return

            # 没有当前 epoch key 的成员不参与 leader 选举：
            # 缺少 prev epoch chain 的成员无法正确计算 epoch_chain。
            # 但如果排除后候选列表为空且是 open/invite_code 群，新成员保留自己兜底
            # （从服务端 committed_rotation.epoch_chain 获取 prev chain 发起轮换）。
            if expected_epoch is not None and expected_epoch > 0:
                local_secret = self._group_e2ee.load_secret(group_id, expected_epoch)
                if local_secret is None:
                    filtered = [c for c in candidates if c != my_aid]
                    if filtered:
                        candidates = filtered
                    elif not allow_member:
                        return
                    # else: open/invite_code 群只剩自己时保留兜底

            if my_aid not in candidates:
                self._log.debug("client", "epoch rotation this node not in candidate list, skipping: group=%s my_aid=%s candidates=%s", group_id, my_aid, candidates[:3])
                return

            my_rank = candidates.index(my_aid)
            self._log.debug("client", "epoch rotation leader election: group=%s my_rank=%d/%d is_leader=%s", group_id, my_rank, len(candidates), my_rank == 0)
            if allow_member:
                delay_s = my_rank * _GROUP_JOIN_ROTATION_STAGGER_S + random.random() * _GROUP_JOIN_ROTATION_STAGGER_S
                if delay_s > 0:
                    await asyncio.sleep(delay_s)
                if self._closing or self._state != "connected":
                    return
                try:
                    after_resp = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
                    after_epoch = after_resp.get("epoch", 0) if isinstance(after_resp, dict) else 0
                except Exception:
                    after_resp = {}
                    after_epoch = self._group_e2ee.current_epoch(group_id) or 0
                if expected_epoch is not None and after_epoch != expected_epoch:
                    return
                pending = after_resp.get("pending_rotation") if isinstance(after_resp, dict) else None
                if isinstance(pending, dict) and not pending.get("expired"):
                    self._schedule_group_rotation_retry(
                        group_id,
                        reason=reason,
                        trigger_id=trigger_id,
                        expected_epoch=expected_epoch,
                        pending=pending,
                    )
                    return
                await self._rotate_group_epoch(
                    group_id, reason=reason, trigger_id=trigger_id, expected_epoch=expected_epoch,
                )
                return

            if my_rank == 0:
                await self._rotate_group_epoch(
                    group_id, reason=reason, trigger_id=trigger_id, expected_epoch=expected_epoch,
                )
                return

            # 非 leader：随机 jitter（2~6s）后查询服务端 epoch 是否已被 leader 推进
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
                after_resp = {}
                after_epoch = self._group_e2ee.current_epoch(group_id) or 0

            if self._closing or self._state != "connected":
                return
            if after_epoch > before_epoch:
                return  # leader 已完成
            pending = after_resp.get("pending_rotation") if isinstance(after_resp, dict) else None
            if isinstance(pending, dict) and not pending.get("expired"):
                self._schedule_group_rotation_retry(
                    group_id,
                    reason=reason,
                    trigger_id=trigger_id,
                    expected_epoch=expected_epoch,
                    pending=pending,
                )
                return

            self._log.info("client",
                "[H21] leader 未完成 epoch 轮换，非 leader 兜底: group=%s myAid=%s",
                group_id, my_aid
            )
            await self._rotate_group_epoch(group_id, reason=reason, trigger_id=trigger_id, expected_epoch=expected_epoch)
        except Exception as exc:
            if self._is_expected_group_rotation_skip_error(exc):
                self._log.debug("client",
                    "跳过 group epoch 轮换兜底: group=%s aid=%s reason=%s err=%s",
                    group_id, my_aid, reason, exc,
                )
                self._log.debug("client", "_maybe_lead_rotate_group_epoch exit (skip): elapsed=%.3fs group=%s", time.time() - _t_start, group_id)
                return
            self._log.warn("client", "_maybe_lead_rotate_group_epoch failed: %s", exc)
        finally:
            self._group_epoch_rotation_inflight.discard(group_id)
            self._log.debug("client", "_maybe_lead_rotate_group_epoch exit: elapsed=%.3fs group=%s", time.time() - _t_start, group_id)

    async def _ranked_group_rotation_candidates(
        self,
        group_id: str,
        *,
        allow_member: bool,
        members_resp: dict[str, Any] | None = None,
    ) -> list[str]:
        """返回当前可发起群密钥轮换的候选 AID，按 owner > admin > member 排序。"""
        my_aid = self._aid or ""
        raw_list: list[Any] = []
        online_seen = False
        try:
            online_resp = await self.call("group.get_online_members", {"group_id": group_id})
            if isinstance(online_resp, dict):
                raw_online = online_resp.get("members") or online_resp.get("items") or online_resp.get("online_members")
                if isinstance(raw_online, list):
                    raw_list = raw_online
                    online_seen = True
        except Exception as exc:
            self._log.debug("client", "failed to get online members, falling back to member list election: group=%s err=%s", group_id, exc)

        if not raw_list:
            if members_resp is None:
                members_resp = await self.call("group.get_members", {"group_id": group_id})
            raw_members = members_resp.get("members") or members_resp.get("items") if isinstance(members_resp, dict) else []
            raw_list = raw_members if isinstance(raw_members, list) else []

        buckets: dict[str, set[str]] = {"owner": set(), "admin": set(), "member": set()}
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            aid = str(item.get("aid") or "").strip()
            if not aid:
                continue
            if online_seen and item.get("online") is not True and aid != my_aid:
                continue
            role = str(item.get("role") or "").strip().lower()
            if role == "owner":
                buckets["owner"].add(aid)
            elif role == "admin":
                buckets["admin"].add(aid)
            elif allow_member and role == "member":
                buckets["member"].add(aid)

        candidates = sorted(buckets["owner"]) + sorted(buckets["admin"])
        if allow_member:
            candidates += sorted(buckets["member"])
        return candidates

    async def _rotate_group_epoch(self, group_id: str, *, reason: str = "manual", trigger_id: str = "", expected_epoch: int | None = None) -> None:
        """为指定群组轮换 epoch 并分发新密钥。

        使用服务端 CAS 保证只有一方成功。
        服务端同时校验 owner/admin 角色。
        """
        _t_rotate_start = time.time()
        self._log.debug("client", "_rotate_group_epoch enter: group=%s reason=%s trigger=%s expected_epoch=%s", group_id, reason, trigger_id or "-", expected_epoch)
        try:
            # 1. 先获取最新成员列表。若本地当前 epoch 的签名成员集已经一致，
            #    说明事件路径/RPC 兜底重复触发，必须在 CAS 前幂等跳过，避免无谓推进服务端 epoch。
            member_aids = await self._get_group_member_aids(group_id)
            if reason == "membership_changed" and trigger_id:
                if trigger_id in self._group_membership_rotation_done:
                    return

            # 2. 读取服务端当前 epoch。成员变更触发的轮换必须绑定到变更发生时的 old_epoch，
            #    只允许 old_epoch -> old_epoch + 1；若 epoch 已推进，说明同一变更已被其它路径处理。
            epoch_result = await self.call("group.e2ee.get_epoch", {"group_id": group_id})
            server_epoch = int(epoch_result.get("epoch", 0))
            pending_rotation = epoch_result.get("pending_rotation") if isinstance(epoch_result, dict) else None
            if isinstance(pending_rotation, dict) and not pending_rotation.get("expired"):
                stale_pending = (
                    reason == "membership_changed"
                    and expected_epoch is not None
                    and server_epoch == expected_epoch
                    and self._rotation_expected_members_stale(pending_rotation, member_aids)
                )
                if stale_pending and await self._abort_group_rotation(
                    str(pending_rotation.get("rotation_id") or ""),
                    reason="membership_changed_during_rotation",
                ):
                    self._log.info("client", 
                        "aborted stale pending group epoch rotation: group=%s rotation=%s",
                        group_id, pending_rotation.get("rotation_id") or "-",
                    )
                else:
                    self._schedule_group_rotation_retry(
                        group_id,
                        reason=reason,
                        trigger_id=trigger_id,
                        expected_epoch=expected_epoch,
                        pending=pending_rotation,
                    )
                    return
            if reason == "membership_changed" and expected_epoch is not None and server_epoch != expected_epoch:
                if trigger_id:
                    self._group_membership_rotation_done.add(trigger_id)
                self._log.info("client", 
                    "skip membership epoch rotation: group=%s expected_epoch=%s server_epoch=%s trigger=%s",
                    group_id, expected_epoch, server_epoch, trigger_id or "-",
                )
                return
            current_epoch = expected_epoch if expected_epoch is not None else server_epoch

            target_epoch = current_epoch + 1
            # 3. 本地生成目标 epoch 密钥；服务端 begin 只创建 pending，不推进 committed epoch。
            # 新成员可能没有 prev epoch key，或有 key 但缺少 epoch_chain（通过 backfill 接收）。
            # 从 committed_rotation.epoch_chain 获取 prev chain hint。
            prev_chain_hint: str | None = None
            local_prev = self._group_e2ee.load_secret(group_id, current_epoch)
            local_prev_chain = str(local_prev.get("epoch_chain") or "").strip() if local_prev else ""
            if not local_prev_chain:
                committed_rotation = epoch_result.get("committed_rotation") if isinstance(epoch_result, dict) else None
                if isinstance(committed_rotation, dict):
                    raw_chain = str(committed_rotation.get("epoch_chain") or "").strip()
                    if raw_chain:
                        prev_chain_hint = raw_chain
                        self._log.info("client", 
                            "轮换补充 prev epoch chain from server: group=%s epoch=%s",
                            group_id, current_epoch,
                        )
            rotation_id = f"rot-{uuid.uuid4().hex}"
            self._log.debug("client", "epoch rotation begin phase: group=%s base_epoch=%s target_epoch=%s rotation_id=%s members=%d", group_id, current_epoch, target_epoch, rotation_id, len(member_aids))
            info = self._group_e2ee.rotate_epoch_to(
                group_id, target_epoch, member_aids, rotation_id=rotation_id,
                prev_chain_hint=prev_chain_hint,
            )
            self._attach_rotation_id(info, rotation_id)
            def discard_generated_pending() -> None:
                try:
                    self._group_e2ee.discard_pending_secret(group_id, target_epoch, rotation_id)
                except Exception as cleanup_exc:
                    self._log.debug("client", 
                        "清理本地 pending group key 失败: group=%s epoch=%s rotation=%s err=%s",
                        group_id, target_epoch, rotation_id, cleanup_exc,
                    )

            rotate_params = {
                "group_id": group_id,
                "base_epoch": current_epoch,
                "target_epoch": target_epoch,
                "rotation_id": rotation_id,
                "reason": reason,
                "key_commitment": info.get("commitment", ""),
                "expected_members": member_aids,
                "required_acks": [self._aid] if self._aid else [],
                "lease_ms": _GROUP_ROTATION_LEASE_MS,
            }
            rotate_params.update(self._build_rotation_signature(group_id, current_epoch, target_epoch, rotate_params))
            try:
                begin_result = await self.call("group.e2ee.begin_rotation", rotate_params)
            except Exception:
                discard_generated_pending()
                raise
            rotation = begin_result.get("rotation") if isinstance(begin_result, dict) else None
            if not isinstance(begin_result, dict) or not begin_result.get("success") or not isinstance(rotation, dict):
                if isinstance(rotation, dict) and not rotation.get("expired"):
                    if (
                        reason == "membership_changed"
                        and self._rotation_expected_members_stale(rotation, member_aids)
                        and await self._abort_group_rotation(
                            str(rotation.get("rotation_id") or ""),
                            reason="membership_changed_during_rotation",
                        )
                    ):
                        self._schedule_group_rotation_retry(
                            group_id,
                            reason=reason,
                            trigger_id=trigger_id,
                            expected_epoch=expected_epoch,
                            pending=None,
                        )
                    else:
                        self._schedule_group_rotation_retry(
                            group_id,
                            reason=reason,
                            trigger_id=trigger_id,
                            expected_epoch=expected_epoch,
                            pending=rotation,
                        )
                elif isinstance(begin_result, dict) and begin_result.get("reason") == "expected_members_mismatch":
                    self._schedule_group_rotation_retry(
                        group_id,
                        reason=reason,
                        trigger_id=trigger_id,
                        expected_epoch=expected_epoch,
                        pending=None,
                    )
                self._log.warn("client", 
                    "group epoch begin failed; stop key distribution (group=%s, current_epoch=%s, returned=%s)",
                    group_id, current_epoch, begin_result,
                )
                discard_generated_pending()
                return
            active_rotation_id = str(rotation.get("rotation_id") or rotation_id)
            self._log.debug("client", "epoch rotation distribute phase: group=%s rotation=%s target_epoch=%s", group_id, active_rotation_id, target_epoch)
            distribute_result = await self._distribute_group_epoch_key(info, rotation_id=active_rotation_id)
            failed = distribute_result.get("failed", [])
            if failed:
                self._log.warn("client", 
                    "group epoch key distribution incomplete; abort rotation before retry "
                    "(group=%s rotation=%s failed=%s)",
                    group_id, active_rotation_id, failed,
                )
                await self._abort_group_rotation(active_rotation_id, reason="distribution_failed")
                self._schedule_group_rotation_retry(
                    group_id,
                    reason=reason,
                    trigger_id=trigger_id,
                    expected_epoch=expected_epoch,
                    pending=None,
                )
                discard_generated_pending()
                return
            await self._heartbeat_group_rotation(rotation.get("rotation_id", rotation_id))
            if not await self._ack_group_rotation_key(
                rotation_id=active_rotation_id,
                key_commitment=info.get("commitment", ""),
            ):
                self._log.warn("client", 
                    "group epoch self ack failed; abort rotation before retry "
                    "(group=%s rotation=%s)",
                    group_id, active_rotation_id,
                )
                await self._abort_group_rotation(active_rotation_id, reason="self_ack_failed")
                self._schedule_group_rotation_retry(
                    group_id,
                    reason=reason,
                    trigger_id=trigger_id,
                    expected_epoch=expected_epoch,
                    pending=None,
                )
                discard_generated_pending()
                return
            commit_params: dict[str, Any] = {
                "rotation_id": active_rotation_id,
            }
            if await self._group_allows_member_epoch_rotation(group_id):
                # 只有 open / invite code 群把 per-member ECIES epoch key 交给服务端托管。
                encrypted_keys = await self._build_epoch_encrypted_keys(
                    info, member_aids, target_epoch, group_id
                )
                if encrypted_keys:
                    commit_params["encrypted_keys"] = encrypted_keys
            self._log.debug("client", "epoch rotation commit phase: group=%s rotation=%s target_epoch=%s", group_id, active_rotation_id, target_epoch)
            commit_result = await self.call("group.e2ee.commit_rotation", commit_params)
            if not commit_result.get("success"):
                self._log.warn("client", 
                    "group epoch commit failed (group=%s, rotation=%s, returned=%s)",
                    group_id, active_rotation_id, commit_result,
                )
                self._schedule_group_rotation_retry(
                    group_id,
                    reason=reason,
                    trigger_id=trigger_id,
                    expected_epoch=expected_epoch,
                    pending=commit_result.get("rotation") if isinstance(commit_result, dict) else rotation,
                )
                returned_rotation = commit_result.get("rotation") if isinstance(commit_result, dict) else None
                if not (
                    isinstance(returned_rotation, dict)
                    and str(returned_rotation.get("rotation_id") or "") == active_rotation_id
                    and str(returned_rotation.get("status") or "") == "distributing"
                ):
                    discard_generated_pending()
                return
            committed_secret = self._group_e2ee.load_secret(group_id, target_epoch)
            committed_rotation = (
                commit_result.get("rotation")
                if isinstance(commit_result, dict) and isinstance(commit_result.get("rotation"), dict)
                else {
                    "rotation_id": active_rotation_id,
                    "key_commitment": info.get("commitment", ""),
                }
            )
            if committed_secret and self._group_secret_matches_committed_rotation(committed_secret, committed_rotation, local_aid=self._aid or ""):
                self._group_e2ee.store_secret(
                    group_id,
                    target_epoch,
                    committed_secret["secret"],
                    committed_secret.get("commitment", ""),
                    committed_secret.get("member_aids", member_aids),
                    epoch_chain=committed_secret.get("epoch_chain"),
                )
                self._log.debug("client", "epoch rotation complete: group=%s epoch=%s->%s rotation=%s reason=%s", group_id, current_epoch, target_epoch, active_rotation_id, reason)
            else:
                self._log.warn("client", 
                    "group epoch commit succeeded but local target key does not match committed rotation; keep pending blocked "
                    "(group=%s rotation=%s epoch=%s)",
                    group_id, active_rotation_id, target_epoch,
                )
            if reason == "membership_changed" and trigger_id:
                self._group_membership_rotation_done.add(trigger_id)
                if len(self._group_membership_rotation_done) > 2000:
                    self._group_membership_rotation_done = set(list(self._group_membership_rotation_done)[-1000:])
        except Exception as exc:
            self._log_e2ee_error("rotate_epoch", group_id, "", exc)
            self._log.debug("client", "_rotate_group_epoch exit (error): elapsed=%.3fs group=%s err=%s", time.time() - _t_rotate_start, group_id, exc)
            return
        self._log.debug("client", "_rotate_group_epoch exit: elapsed=%.3fs group=%s", time.time() - _t_rotate_start, group_id)
    def _joined_member_aids_from_payload(self, payload: dict[str, Any]) -> list[str]:
        """从成员加入事件 payload 中提取新加入的成员 AID 列表。"""
        aids: set[str] = set()

        def add_aid(value: Any) -> None:
            aid = str(value or '').strip()
            if aid:
                aids.add(aid)

        add_aid(payload.get('aid') or payload.get('applicant_aid') or payload.get('applicantAid'))
        add_aid(payload.get('actor_aid'))
        for key in ('member_aid', 'target_aid', 'new_member_aid', 'used_by'):
            add_aid(payload.get(key))
        for key in ('member', 'request', 'invite_code'):
            nested = payload.get(key)
            if not isinstance(nested, dict):
                continue
            add_aid(nested.get('aid') or nested.get('applicant_aid') or nested.get('applicantAid'))
            for nk in ('member_aid', 'target_aid', 'used_by'):
                add_aid(nested.get(nk))
        results = payload.get('results')
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                status = str(item.get('status') or '').strip().lower()
                if status != 'approved' and item.get('approved') is not True:
                    continue
                add_aid(item.get('aid') or item.get('applicant_aid') or item.get('applicantAid'))
                for key in ('member_aid', 'target_aid'):
                    add_aid(item.get(key))
                for key in ('member', 'request'):
                    nested = item.get(key)
                    if not isinstance(nested, dict):
                        continue
                    add_aid(nested.get('aid') or nested.get('applicant_aid'))
                    for nk in ('member_aid', 'target_aid'):
                        add_aid(nested.get(nk))
        return list(aids)

    # ── 入群密钥恢复策略 ──────────────────────────────────────

    # 延迟轮换等待时间（秒）：给新成员恢复 committed_epoch 的窗口
    _JOIN_ROTATION_DELAY_S = 3.0
    # 新成员自身延迟轮换时间（秒）：优先让其他在线成员先轮换
    _SELF_JOIN_ROTATION_DELAY_S = 6.0

    async def _delayed_rotate_after_join(
        self,
        group_id: str,
        reason: str = "membership_changed",
        trigger_id: str = "",
        expected_epoch: int = 0,
        allow_member: bool = False,
        delay_s: float | None = None,
    ) -> None:
        """open/invite_code 入群后延迟轮换。"""
        await asyncio.sleep(delay_s if delay_s is not None else self._JOIN_ROTATION_DELAY_S)
        await self._maybe_lead_rotate_group_epoch(
            group_id,
            reason=reason,
            trigger_id=trigger_id,
            expected_epoch=expected_epoch,
            allow_member=allow_member,
        )

    async def _maybe_backfill_key_to_joined_member(
        self, group_id: str, payload: dict[str, Any], trigger_id: str = ''
    ) -> None:
        """当新成员加入但缺少 old_epoch 时，将当前 epoch 密钥分发给新成员。"""
        member_aids = [
            aid for aid in self._joined_member_aids_from_payload(payload)
            if aid and aid != self._aid
        ]
        if not group_id or not self._aid or not member_aids:
            return
        self._log.debug("client", "backfill key evaluation: group=%s new_members=%s trigger=%s", group_id, member_aids, trigger_id or "-")
        secret_data = self._group_e2ee.load_secret(group_id)
        if secret_data is None:
            self._log.debug("client", "backfill skipped: no local epoch key: group=%s", group_id)
            return
        for member_aid in member_aids:
            dedupe_key = (
                f"{trigger_id or self._membership_rotation_trigger_id(group_id, payload)}"
                f":backfill:{member_aid}"
            )
            if dedupe_key in self._group_member_key_backfill_done:
                continue
            self._group_member_key_backfill_done.add(dedupe_key)
            if len(self._group_member_key_backfill_done) > 2000:
                self._group_member_key_backfill_done = set(
                    list(self._group_member_key_backfill_done)[-1000:]
                )
            self._log.debug("client", "backfill distributing key to new member: group=%s member=%s epoch=%s", group_id, member_aid, secret_data.get("epoch", "-"))
            await self._distribute_key_to_new_member(group_id, member_aid)

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

            # 用最新成员列表计算 commitment（仅用于 distribution payload，不覆写本地存储）
            from .e2ee import (
                compute_membership_commitment,
                build_key_distribution, build_membership_manifest, sign_membership_manifest,
            )
            epoch = secret_data["epoch"]
            commitment = compute_membership_commitment(member_aids, epoch, group_id, secret_data["secret"])

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
                epoch_chain=secret_data.get("epoch_chain"),
            )
            for _attempt in range(3):
                try:
                    await self.call("message.send", {
                        "to": new_member_aid,
                        "payload": dist_payload,
                        "encrypt": True,
                        "persist_required": True,
                    })
                    self._log.debug("client", "backfill key distribution success: group=%s member=%s epoch=%s", group_id, new_member_aid, epoch)
                    break
                except Exception as _send_exc:
                    if _attempt < 2:
                        await asyncio.sleep(1.0 * (_attempt + 1))
                    else:
                        self._log.warn("client", "backfill key distribution failed (retries exhausted): group=%s member=%s epoch=%s error=%s", group_id, new_member_aid, epoch, _send_exc)
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
            self._log.debug("client", "leader election query failed: group=%s: %s", group_id, _exc)
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
                    group_ids = self._keystore.list_group_secret_ids(my_aid)
                    for gid in list(group_ids):
                        await self._maybe_lead_rotate_group_epoch(gid, reason="scheduled")
                except Exception as _exc:
                    self._log.warn("client", "epoch rotation failed: %s", _exc)
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
                    group_ids = self._keystore.list_group_secret_ids(my_aid)
                    retention = self._config_model.old_epoch_retention_seconds
                    for gid in list(group_ids):
                        self._group_e2ee.cleanup(gid, retention)
                except Exception as _exc:
                    self._log.warn("client", "epoch rotation failed: %s", _exc)
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

    async def send_v2(self, to: str, payload: dict[str, Any], **kwargs) -> dict[str, Any]:
        """V2 P2P 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。

        Args:
            to: 目标 AID
            payload: 业务 payload（将被加密）

        Returns:
            服务端响应 dict
        """
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

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
                **kwargs,
            )

            return await self.call("message.send", {
                "to": to,
                "payload": envelope,
                "encrypt": False,
            })

        try:
            return await _attempt(use_cache=True)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "device" in err_msg or "prekey" in err_msg or "recipient" in err_msg or "stale" in err_msg:
                self._log.debug("client", "V2 P2P speculative send rejected, refreshing bootstrap: %s", exc)
                self._v2_bootstrap_cache.pop(to, None)
                return await _attempt(use_cache=False)
            raise

    async def pull_v2(self, after_seq: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        """拉取并解密 V2 P2P 消息。

        Args:
            after_seq: 从此 seq 之后开始拉取（0 表示从头）
            limit: 最多拉取条数

        Returns:
            解密后的消息列表
        """
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        ns = f"p2p:{self._aid}" if self._aid else ""
        effective_after_seq = after_seq or self._seq_tracker.get_contiguous_seq(ns)

        result = await self.call("message.v2.pull", {
            "after_seq": effective_after_seq,
            "limit": limit,
        })
        messages = result.get("messages", [])
        decrypted = []
        max_seq = effective_after_seq
        for msg in messages:
            seq = msg.get("seq", 0)
            if seq > max_seq:
                max_seq = seq
            plaintext = await self._decrypt_v2_message(msg)
            if plaintext is not None:
                decrypted.append(plaintext)
            # 跟踪每个旧 SPK 引用的最大 seq（用于消费后销毁）
            try:
                msg_spk_id = str(msg.get("spk_id", "") or "")
                if msg_spk_id and self._v2_session and not self._v2_session.is_current_spk(msg_spk_id):
                    self._v2_session.track_old_spk_max_seq(msg_spk_id, seq)
            except Exception:
                pass
        # 推进 SeqTracker：V2 消息 seq 可能远高于当前 contiguous（共享 seq 空间），
        # 直接 restore 到 max_seq 避免 gap 检测误判
        if ns and max_seq > self._seq_tracker.get_contiguous_seq(ns):
            self._seq_tracker.restore_state({ns: max_seq})
            self._persist_seq(ns)
        return decrypted

    async def ack_v2(self, up_to_seq: int | None = None) -> dict[str, Any]:
        """确认 V2 消息已消费 + 自检销毁旧 SPK。"""
        ns = f"p2p:{self._aid}" if self._aid else ""
        seq = up_to_seq or (self._seq_tracker.get_contiguous_seq(ns) if ns else 0)
        if seq <= 0:
            return {"acked": 0}
        result = await self.call("message.v2.ack", {"up_to_seq": seq})
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

    async def send_group_v2(self, group_id: str, payload: dict[str, Any], **kwargs) -> dict[str, Any]:
        """V2 Group 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。"""
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        from .v2.e2ee.encrypt_group import encrypt_group_message

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
                **kwargs,
            )

            return await self.call("group.v2.send", {
                "group_id": group_id,
                "envelope": envelope,
            })

        try:
            return await _attempt(use_cache=True)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "member" in err_msg or "device" in err_msg or "recipient" in err_msg or "stale" in err_msg or "epoch" in err_msg:
                self._log.debug("client", "group V2 speculative send rejected, refreshing bootstrap: %s", exc)
                self._v2_bootstrap_cache.pop(f"group:{group_id}", None)
                return await _attempt(use_cache=False)
            raise

    async def pull_group_v2(self, group_id: str, after_seq: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        """拉取并解密 V2 Group 消息。"""
        if not self._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        ns = f"group:{group_id}"
        effective_after_seq = after_seq or self._seq_tracker.get_contiguous_seq(ns)

        result = await self.call("group.v2.pull", {
            "group_id": group_id,
            "after_seq": effective_after_seq,
            "limit": limit,
        })
        messages = result.get("messages", [])
        decrypted = []
        max_seq = effective_after_seq
        for msg in messages:
            seq = msg.get("seq", 0)
            if seq > max_seq:
                max_seq = seq
            plaintext = await self._decrypt_v2_message(msg)
            if plaintext is not None:
                plaintext["group_id"] = group_id
                decrypted.append(plaintext)
        if ns and max_seq > self._seq_tracker.get_contiguous_seq(ns):
            self._seq_tracker.restore_state({ns: max_seq})
            self._persist_seq(ns)
        return decrypted

    async def ack_group_v2(self, group_id: str, up_to_seq: int | None = None) -> dict[str, Any]:
        """确认 V2 群消息已消费。"""
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
                # 获取 actor 证书
                cert_result = await self.call("ca.get_cert", {"aid": actor_aid})
                cert_pem = ""
                if isinstance(cert_result, dict):
                    cert_pem = str(cert_result.get("cert_pem") or cert_result.get("cert") or "")
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

    async def _v2_auto_propose_state(self, group_id: str) -> None:
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
            current_sv = int(state_resp.get("state_version", 0))
            current_sh = str(state_resp.get("state_hash", ""))
            key_epoch = int(state_resp.get("key_epoch", 0))

            # 用完整 commitment 算 state_hash
            from .v2.state.commitment import compute_state_commitment
            state_hash = compute_state_commitment(group_id, current_sv + 1, state_payload)

            # 签名 state proposal（绑定完整 state_payload）
            membership_snapshot = json.dumps(state_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
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

            await self.call("group.v2.propose_state", {
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
        except Exception as exc:
            self._log.debug("client", "V2 auto propose_state failed (non-fatal): group=%s err=%s", group_id, exc)

    async def _v2_auto_confirm_pending_proposals(self) -> None:
        """Owner 上线时自动检查并签名确认 pending state proposals。"""
        try:
            my_aid = self._aid or ""
            if not my_aid:
                return
            # 获取我参与的群列表
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
                    proposal_resp = await self.call("group.v2.get_proposal", {"group_id": group_id})
                    proposal = proposal_resp.get("proposal")
                    if not proposal:
                        continue
                    proposal_id = proposal.get("proposal_id", "")
                    if not proposal_id:
                        continue
                    # 签名确认
                    await self.call("group.v2.confirm_state", {"proposal_id": proposal_id})
                    self._log.info("client", "V2 auto confirmed pending proposal: group=%s proposal=%s", group_id, proposal_id)
                except Exception as exc:
                    self._log.debug("client", "V2 auto confirm proposal failed (non-fatal): group=%s err=%s", group_id, exc)
        except Exception as exc:
            self._log.debug("client", "V2 auto confirm pending proposals failed (non-fatal): %s", exc)

    async def _on_v2_push_notification(self, data: Any) -> None:
        """处理 V2 push 通知：自动 pull + decrypt + emit。"""
        if not self._v2_session:
            return
        try:
            messages = await self.pull_v2()
            for msg in messages:
                await self._dispatcher.publish("message.received", msg)
        except Exception as exc:
            self._log.warn("client", "V2 push auto-pull failed: %s", exc)

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

        ik_priv, spk_priv = self._v2_session.get_decrypt_keys(spk_id)

        # 获取 sender IK 公钥（按 sender device_id 精确匹配）
        from_aid = msg.get("from_aid", "")
        sender_device_id = envelope.get("aad", {}).get("from_device", "")
        sender_pub_der = self._v2_session.get_peer_ik(from_aid, sender_device_id)
        if not sender_pub_der:
            # 尝试 bootstrap 获取
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
            },
        }
