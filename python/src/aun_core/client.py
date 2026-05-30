from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import random
import re
import secrets
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse, urlunparse

import aiohttp
import websockets

from .aid import AID
from .aid_store import AIDStore
from .auth import AuthFlow
from .config import AUNConfig, get_device_id, normalize_instance_id, normalize_slot_id
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
    NotFoundError,
    PermissionError as AUNPermissionError,
    StateError,
    ValidationError,
)
from .events import EventDispatcher, Subscription
from .group_id import normalize_group_id as _normalize_group_id
from .keystore.file import FileKeyStore
from .transport import RPCTransport
from .seq_tracker import SeqTracker
from .types import ConnectionOptions, ConnectionState
from .v2.session import V2Session
from .v2.e2ee.encrypt_p2p import encrypt_p2p_message
from .v2.e2ee.decrypt import decrypt_message as v2_decrypt_message
from .v2.crypto.ecdsa import ecdsa_verify_raw

_INTERNAL_ONLY_METHODS = {
    "auth.login1",
    "auth.aid_login1",
    "auth.login2",
    "auth.aid_login2",
    "auth.connect",
    "auth.refresh_token",
    "initialize",
}

_PROTECTED_HEADERS_METHODS = frozenset({
    "message.send",
    "group.send",
    "message.thought.put",
    "group.thought.put",
})


_STATE_TO_PUBLIC = {
    "idle": "no_identity",
    "authenticating": "connecting",
    "connected": "ready",
    "disconnected": "standby",
    "terminal_failed": "connection_failed",
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
_ONLINE_UNREAD_HINT_INITIAL_DELAY = 0.75
_ONLINE_UNREAD_HINT_INTERVAL = 0.05


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


def _v2_normalize_wrap_policy(raw: Any) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        return None
    protocol = str(raw.get("protocol") or "").strip().upper()
    scope = str(raw.get("scope") or "").strip().lower()
    if scope not in ("aid", "device"):
        if raw.get("per_aid_wrap") is True:
            scope = "aid"
        elif raw.get("per_device_wrap") is True:
            scope = "device"
        else:
            scope = ""
    if protocol not in ("1DH", "3DH"):
        protocol = ""
    if scope == "aid":
        protocol = "1DH"
    if not protocol and not scope:
        return None
    return {"protocol": protocol, "scope": scope}


def _v2_wrap_capabilities() -> dict[str, Any]:
    return {
        "version": "v2.1",
        "protocols": ["1DH", "3DH"],
        "scopes": ["aid", "device"],
        "per_aid_wrap": True,
        "per_device_wrap": True,
    }


def _v2_apply_wrap_policy_to_targets(
    targets: list[dict[str, Any]],
    policy: dict[str, str] | None,
) -> list[dict[str, Any]]:
    if not policy:
        return targets
    normalized: list[dict[str, Any]] = []
    for target in targets:
        row = dict(target)
        if policy.get("protocol") == "1DH":
            row["key_source"] = "aid_master"
            row["spk_pk_der"] = None
            row["spk_id"] = ""
        normalized.append(row)
    if policy.get("scope") != "aid":
        return normalized
    collapsed: dict[tuple[str, str], dict[str, Any]] = {}
    preserved: list[dict[str, Any]] = []
    for target in normalized:
        if str(target.get("role") or "") == "self_sync":
            preserved.append(dict(target))
            continue
        key = (str(target.get("aid") or ""), str(target.get("role") or ""))
        if key not in collapsed:
            row = dict(target)
            row["device_id"] = ""
            collapsed[key] = row
    return list(collapsed.values()) + preserved


def _length_prefixed_bytes_key(*parts: bytes) -> bytes:
    chunks: list[bytes] = []
    for part in parts:
        chunks.append(str(len(part)).encode("ascii"))
        chunks.append(b":")
        chunks.append(part)
        chunks.append(b";")
    return b"".join(chunks)


def _length_prefixed_text_key(*parts: str) -> str:
    chunks: list[str] = []
    for part in parts:
        encoded = part.encode("utf-8")
        chunks.append(f"{len(encoded)}:{part};")
    return "".join(chunks)
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
    "background_sync": True,
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


def _v2_device_id_from_device(dev: dict[str, Any]) -> tuple[bool, str]:
    if "device_id" in dev:
        return True, str(dev.get("device_id") or "").strip()
    if "owner_device_id" in dev:
        return True, str(dev.get("owner_device_id") or "").strip()
    return False, ""


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


def _make_connection_factory(verify_ssl: bool = True, logger: AUNLogger | NullLogger | None = None, net=None):
    """根据 verify_ssl 配置创建 WebSocket 连接工厂（支持 DNS 容灾）"""
    from .net import _is_dns_error, _parse_host_port, _replace_host_with_ip
    _log = logger or NullLogger()

    async def _factory(url: str) -> Any:
        global _ssl_warning_emitted
        kw: dict[str, Any] = {"open_timeout": 5, "close_timeout": 5, "ping_interval": None}
        if url.startswith("wss://"):
            if verify_ssl:
                pass
            else:
                kw["ssl"] = _get_no_verify_ssl()
                if not _ssl_warning_emitted:
                    _log.warn(
                        "client",
                        "TLS 证书验证已禁用（verify_ssl=False）。"
                        "生产环境应设为 True 以防止中间人攻击。"
                    )
                    _ssl_warning_emitted = True
        try:
            return await websockets.connect(url, **kw)
        except Exception as exc:
            if not net or not _is_dns_error(exc):
                raise

        hostname, port = _parse_host_port(url)
        _log.debug("client", "WS DNS failed for %s, trying cached IP", hostname)
        cached = net._load_dns_cache(hostname)
        if not cached:
            raise ConnectionError(f"DNS failed and no cached IP for {hostname}")

        ip, cached_port = cached
        ip_url = _replace_host_with_ip(url, ip)
        ws_kw = dict(kw)
        if url.startswith("wss://"):
            if verify_ssl:
                import ssl as _ssl_mod
                ssl_ctx = _ssl_mod.create_default_context()
                ssl_ctx.check_hostname = True
                ssl_ctx.verify_mode = _ssl_mod.CERT_REQUIRED
                ws_kw["ssl"] = ssl_ctx
            ws_kw["additional_headers"] = {"Host": hostname if port in (80, 443) else f"{hostname}:{port}"}
            ws_kw["server_hostname"] = hostname
        return await websockets.connect(ip_url, **ws_kw)
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

    def __init__(
        self,
        aid: AID | None = None,
    ) -> None:
        if aid is not None and not isinstance(aid, AID):
            raise TypeError("AUNClient expects an AID instance or None")
        initial_aid_obj = aid if aid is not None and aid.is_private_key_valid() else None
        if aid is not None and initial_aid_obj is None:
            raise StateError("AUNClient received an AID without a valid private key; load a complete identity first")
        debug = initial_aid_obj.debug if initial_aid_obj is not None else False
        raw_config = {"aun_path": initial_aid_obj.aun_path} if initial_aid_obj else {}
        self._config_model = AUNConfig.from_dict(raw_config)
        init_aid = initial_aid_obj.aid if initial_aid_obj else (str(raw_config.get("aid") or "").strip() or None)
        self._device_id = (initial_aid_obj.device_id if initial_aid_obj else None) or get_device_id(self._config_model.aun_path)
        # AUNLogger 自身已处理 debug=False：INFO/WARN/ERROR 输出 stderr，DEBUG 不输出，无文件日志
        # 不再用 NullLogger 整个静默掉，否则用户排查问题时看不到任何 SDK 异常
        self._log: AUNLogger | NullLogger = AUNLogger(
            debug=debug, aun_path=str(self._config_model.aun_path)
        )
        self._log.bind_device_id(self._device_id)
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
        self._current_aid: AID | None = initial_aid_obj
        self._identity: dict[str, Any] | None = None
        self._state = "standby" if initial_aid_obj is not None else "no_identity"
        self._peer_cache: dict[str, AID] = {}
        self._next_retry_at: float | None = None
        self._retry_attempt = 0
        self._retry_max_attempts = 0
        self._last_error: BaseException | None = None
        self._last_error_code: str | None = None
        self._instance_protected_headers: dict[str, Any] | None = None
        self._gateway_url: str | None = None
        self._peer_gateway_cache: dict[str, str] = {}
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
        from .net import DnsResilientNet
        self._net = DnsResilientNet(
            aun_path=self._config_model.aun_path,
            verify_ssl=self._config_model.verify_ssl,
            logger=self._log,
        )
        self._discovery = GatewayDiscovery(verify_ssl=self._config_model.verify_ssl, logger=self._log, net=self._net)

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
        self._v2_sender_ik_pending: dict[str, dict[str, Any]] = {}
        self._v2_sender_ik_fetching: set[str] = set()
        self._peer_prekeys_cache: dict[str, tuple[list[dict[str, Any]], float]] = {}
        self._prekey_replenish_inflight: bool = False
        self._prekey_pending_replenish: int = 0
        # agent.md 存储路径：{aun_path}/AIDs/{aid}/agentmd.json（元数据）+ agent.md（正文）
        self._agent_md_path: str = str(Path(self._config_model.aun_path) / "AIDs")
        self._local_agent_md_etag: str = ""
        # gateway 在 RPC envelope._meta.agent_md_etag 注入的服务端 etag；纯观察，无下游依赖。
        self._remote_agent_md_etag: str = ""
        self._agent_md_cache: dict[str, dict[str, Any]] = {}
        # 当前活跃 prekey：只有这个 prekey 被消费时才触发 replenish 上传。
        # connect 成功后上传的 prekey 记录为活跃；历史 prekey 被消费不触发上传。
        self._active_prekey_id: str = ""

        connection_factory = _make_connection_factory(self._config_model.verify_ssl, self._log, net=self._net)
        keystore = FileKeyStore(
            self._config_model.aun_path,
            encryption_seed=self._config_model.seed_password,
            logger=self._log,
        )
        self._keystore = keystore
        self._slot_id = normalize_slot_id(initial_aid_obj.slot_id if initial_aid_obj else None)
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
            net=self._net,
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
        # P2P pull 进行中到达的纯通知 push 上界。当前 pull 结束后需要再补拉一次。
        self._pending_p2p_pull_upper: dict[str, int] = {}
        # 群惰性同步标志：只有收到推送或主动 pull 后才标记为已同步
        # 发送消息前如果未同步，先做一次 pull
        self._group_synced: set[str] = set()
        self._online_unread_hint_queue: dict[str, dict[str, Any]] = {}
        self._online_unread_hint_task: asyncio.Task | None = None
        self._online_unread_hint_initial_delay = _ONLINE_UNREAD_HINT_INITIAL_DELAY
        self._online_unread_hint_interval = _ONLINE_UNREAD_HINT_INTERVAL

        # V2 E2EE session（延迟初始化，connect 后才有 aid）
        self._v2_session: V2Session | None = None
        # Pull Gate：per-key 序列化，防止同一 namespace/group 并发 pull
        self._pull_gates: dict[str, dict] = {}
        self._PULL_GATE_STALE_MS = 30000
        # Per-namespace 消息处理锁：同一 namespace 的 push/pull 串行执行，
        # 防止并发 task 导致乱序投递或 seq_tracker 状态不一致。
        # 不同 namespace 之间互不阻塞。锁只在最外层入口获取，内部方法不再获取，避免死锁。
        self._ns_locks: dict[str, asyncio.Lock] = {}
        # V2 state chain 本地存储（分叉检测）：group_id -> (state_version, state_chain)
        self._v2_state_chains: dict[str, tuple[int, str]] = {}
        # 同一 group 的 V2 自动提案必须串行，避免 group.create 与后续成员变更抢同一 state_version。
        self._v2_auto_propose_locks: dict[str, asyncio.Lock] = {}
        self._v2_auto_propose_locks_guard = asyncio.Lock()
        self._v2_auto_propose_last_snapshot: dict[str, str] = {}
        self._v2_auto_state_management_enabled = True
        self._v2_lazy_propose_triggered: dict[str, float] = {}
        self._group_spk_registration_inflight: set[str] = set()
        self._group_spk_rotation_inflight: set[str] = set()
        self._group_spk_peer_fallback_registered: set[str] = set()
        # 内部订阅：推送消息自动解密后 re-publish 给用户
        self._dispatcher.subscribe("_raw.message.received", self._on_raw_message_received)
        # V2 P2P 推送通知
        self._dispatcher.subscribe("_raw.peer.v2.message_received", self._on_v2_push_notification)
        # 群组明文消息推送：直接透传给应用层
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

    @property
    def current_aid(self) -> AID | None:
        return self._current_aid if self.has_identity else None

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def slot_id(self) -> str:
        return self._slot_id

    @property
    def gateway_url(self) -> str | None:
        gateway_url = getattr(self, "_gateway_url", None)
        if gateway_url:
            return gateway_url
        session_params = getattr(self, "_session_params", None)
        if isinstance(session_params, dict):
            gateway = str(session_params.get("gateway") or "").strip()
            return gateway or None
        return None

    @property
    def session_options(self) -> dict[str, Any]:
        snapshot: dict[str, Any] = {}
        for key, value in self._session_options.items():
            snapshot[key] = dict(value) if isinstance(value, dict) else value
        return snapshot

    async def verify_event_signature(self, event: dict[str, Any], client_signature: dict[str, Any]) -> str | bool:
        return await self._verify_event_signature(event, client_signature)

    @property
    def has_identity(self) -> bool:
        return self._current_aid is not None and self._state not in {"no_identity", "closed"}

    @property
    def can_sign(self) -> bool:
        return bool(self.current_aid and self.current_aid.is_private_key_valid())

    @property
    def can_connect(self) -> bool:
        return bool(self.has_identity and self._public_state != ConnectionState.CLOSED)

    @property
    def can_send(self) -> bool:
        return self._public_state == ConnectionState.READY

    @property
    def is_ready(self) -> bool:
        return self.can_send

    @property
    def is_online(self) -> bool:
        return self._public_state in {
            ConnectionState.READY,
            ConnectionState.RETRY_BACKOFF,
            ConnectionState.RECONNECTING,
        }

    @property
    def is_closed(self) -> bool:
        return self._public_state == ConnectionState.CLOSED

    @property
    def is_closing(self) -> bool:
        return bool(self._closing)

    @property
    def next_retry_at(self) -> float | None:
        return self._next_retry_at if self._public_state == ConnectionState.RETRY_BACKOFF else None

    @property
    def next_retry_in_seconds(self) -> float | None:
        if self.next_retry_at is None:
            return None
        return max(0.0, self.next_retry_at - time.time())

    @property
    def retry_attempt(self) -> int:
        return int(getattr(self, "_retry_attempt", 0) or 0)

    @property
    def retry_max_attempts(self) -> int:
        return int(getattr(self, "_retry_max_attempts", 0) or 0)

    @property
    def last_error(self) -> BaseException | None:
        return getattr(self, "_last_error", None)

    @property
    def last_error_code(self) -> str | None:
        return getattr(self, "_last_error_code", None)

    @property
    def access_token(self) -> str | None:
        identity = getattr(self, "_identity", None)
        if isinstance(identity, dict):
            token = str(identity.get("access_token") or "").strip()
            if token:
                return token
        session_params = getattr(self, "_session_params", None)
        if isinstance(session_params, dict):
            token = str(session_params.get("access_token") or "").strip()
            return token or None
        return None

    @property
    def access_token_expires_at(self) -> float | None:
        identity = getattr(self, "_identity", None)
        if not isinstance(identity, dict):
            return None
        raw = identity.get("access_token_expires_at")
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    @property
    def aun_path(self) -> str | None:
        return self.current_aid.aun_path if self.current_aid else None

    @property
    def _public_state(self) -> ConnectionState:
        raw_state = self._state.value if isinstance(self._state, ConnectionState) else str(self._state)
        return ConnectionState(_STATE_TO_PUBLIC.get(raw_state, raw_state))

    def load_identity(self, aid: AID) -> None:
        if self._state not in {"no_identity", "closed"}:
            raise StateError(f"load_identity not allowed in state {self._public_state.value}")
        if not isinstance(aid, AID) or not aid.is_private_key_valid():
            raise StateError("load_identity requires an AID with a valid private key")
        self._rebuild_runtime_for_identity(aid)
        self._current_aid = aid
        self._aid = aid.aid
        self._auth._aid = aid.aid
        self._state = "standby"
        self._closing = False
        self._identity = None
        self._last_error = None
        self._last_error_code = None
        self._next_retry_at = None
        self._retry_attempt = 0

    def _require_peer_management_state(self) -> None:
        if not self.has_identity:
            raise StateError("peer management requires a loaded identity")

    def cache_peer(self, aid: AID) -> AID:
        self._require_peer_management_state()
        if not isinstance(aid, AID) or not aid.is_cert_valid():
            raise ValidationError("cache_peer requires an AID with a valid certificate")
        self._peer_cache[aid.aid] = aid
        return aid

    def get_peer(self, aid: str) -> AID | None:
        self._require_peer_management_state()
        target = str(aid or "").strip()
        if not target:
            raise ValidationError("get_peer requires non-empty aid")
        return self._peer_cache.get(target)

    async def lookup_peer(self, aid: str) -> AID:
        self._require_peer_management_state()
        target = str(aid or "").strip()
        if not target:
            raise ValidationError("lookup_peer requires non-empty aid")
        cached = self._peer_cache.get(target)
        if cached is not None:
            return cached
        store = self._make_aid_store()
        try:
            resolved = await store.resolve(target, {"skip_agent_md": True})
        finally:
            store.close()
        if not resolved.ok or resolved.data is None:
            message = resolved.error.message if resolved.error else f"resolve peer failed: {target}"
            raise AUNError(message)
        peer = resolved.data.get("aid")
        if not isinstance(peer, AID) or not peer.is_cert_valid():
            raise AUNError(f"resolved peer certificate is invalid: {target}")
        self._peer_cache[peer.aid] = peer
        return peer

    def peers(self) -> list[AID]:
        self._require_peer_management_state()
        return [self._peer_cache[key] for key in sorted(self._peer_cache)]

    def _rebuild_runtime_for_identity(self, aid: AID) -> None:
        """让无身份客户端加载 AID 后切到该身份所属的 aun_path。"""
        raw_config = {"aun_path": aid.aun_path}
        next_config = AUNConfig.from_dict(raw_config)
        current_path = str(getattr(self._config_model, "aun_path", ""))
        next_path = str(next_config.aun_path)
        if current_path == next_path and self._auth._aid == aid.aid:
            return

        debug_enabled = bool(getattr(self._log, "_debug", False))
        try:
            self._keystore.close()
        except Exception:
            pass
        try:
            self._net.close()
        except Exception:
            pass

        self._config_model = next_config
        self._device_id = (aid.device_id or None) or get_device_id(self._config_model.aun_path)
        self._log = AUNLogger(debug=debug_enabled, aun_path=str(self._config_model.aun_path))
        self._log.bind_device_id(self._device_id)
        self.config = {
            "aun_path": str(self._config_model.aun_path),
            "root_ca_path": self._config_model.root_ca_path,
            "seed_password": self._config_model.seed_password,
        }
        self._dispatcher._log = self._log

        from .net import DnsResilientNet

        self._net = DnsResilientNet(
            aun_path=self._config_model.aun_path,
            verify_ssl=self._config_model.verify_ssl,
            logger=self._log,
        )
        self._discovery = GatewayDiscovery(
            verify_ssl=self._config_model.verify_ssl,
            logger=self._log,
            net=self._net,
        )
        connection_factory = _make_connection_factory(self._config_model.verify_ssl, self._log, net=self._net)
        self._keystore = FileKeyStore(
            self._config_model.aun_path,
            encryption_seed=self._config_model.seed_password,
            logger=self._log,
        )
        self._auth = AuthFlow(
            keystore=self._keystore,
            crypto=CryptoProvider(),
            aid=aid.aid,
            device_id=self._device_id,
            slot_id=self._slot_id,
            connection_factory=connection_factory,
            root_ca_path=self._config_model.root_ca_path,
            verify_ssl=self._config_model.verify_ssl,
            logger=self._log,
            net=self._net,
        )
        self._transport = RPCTransport(
            event_dispatcher=self._dispatcher,
            connection_factory=connection_factory,
            timeout=self._session_options.get("timeouts", {}).get("call", _DEFAULT_SESSION_OPTIONS["timeouts"]["call"]),
            on_disconnect=self._handle_transport_disconnect,
            logger=self._log,
        )
        self._transport.set_meta_observer(self._observe_rpc_meta)
        self._agent_md_path = str(Path(self._config_model.aun_path) / "AIDs")
        self._agent_md_cache.clear()
        self._peer_gateway_cache.clear()

    def set_protected_headers(self, headers: dict[str, Any] | None) -> None:
        if not headers:
            self._instance_protected_headers = None
            return
        # 字段规范：key 限 [a-z0-9_-]，_auth 为保留键不可设置。
        # 非法 key 静默跳过（不报错），值强转 str。
        cleaned: dict[str, str] = {}
        for key, value in headers.items():
            key_str = str(key)
            if key_str == "_auth":
                continue
            if not re.fullmatch(r"[a-z0-9_-]+", key_str):
                continue
            cleaned[key_str] = "" if value is None else str(value)
        self._instance_protected_headers = cleaned if cleaned else None

    def get_protected_headers(self) -> dict[str, Any] | None:
        return dict(self._instance_protected_headers) if self._instance_protected_headers else None

    @staticmethod
    def _agent_md_content_etag(content: str) -> str:
        digest = hashlib.sha256(str(content or "").encode("utf-8")).hexdigest()
        return f'"{digest}"'

    def _agent_md_owner_aid(self) -> str:
        return str(self._aid or "").strip()

    def _agent_md_root(self) -> Path:
        root = Path(getattr(self, "_agent_md_path", "") or (Path(self._config_model.aun_path) / "AIDs"))
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _make_aid_store(self) -> AIDStore:
        return AIDStore(
            aun_path=self._config_model.aun_path,
            encryption_seed=str(self._config_model.seed_password or ""),
            device_id=self._device_id,
            slot_id=self._slot_id or "default",
            verify_ssl=self._config_model.verify_ssl,
            root_ca_path=self._config_model.root_ca_path,
            logger=self._log,
        )

    async def _discover_gateway_for_aid(self, aid: str) -> str:
        target = str(aid or "").strip()
        if not target:
            raise StateError("gateway discovery requires aid")
        if self._gateway_url:
            return self._gateway_url
        store = self._make_aid_store()
        try:
            gateway_url = await store._resolved_gateway(target)
            self._gateway_url = gateway_url
            return gateway_url
        finally:
            store.close()

    @staticmethod
    def _issuer_domain_for_aid(aid: str) -> str:
        target = str(aid or "").strip().lower()
        if not target:
            return ""
        if "." not in target:
            return target
        return target.split(".", 1)[1].strip(".")

    async def _discover_gateway_for_peer_aid(self, peer_aid: str) -> str:
        target = str(peer_aid or "").strip()
        if not target:
            raise ValidationError("peer aid is required for gateway discovery")

        peer_issuer = self._issuer_domain_for_aid(target)
        local_issuer = self._local_issuer_domain()
        current_gateway = self.gateway_url
        cache_key = peer_issuer or target.lower()

        if peer_issuer and local_issuer and peer_issuer == local_issuer and current_gateway:
            return current_gateway

        cached_gateway = self._peer_gateway_cache.get(cache_key)
        if cached_gateway:
            return cached_gateway

        discovery_aid = target
        if peer_issuer and local_issuer and peer_issuer == local_issuer and self._aid:
            discovery_aid = self._aid

        store = self._make_aid_store()
        try:
            gateway_url = await store._resolved_gateway(discovery_aid)
        finally:
            store.close()
        if gateway_url:
            self._peer_gateway_cache[cache_key] = gateway_url
        return gateway_url

    def _agent_md_url(self, aid: str, gateway_url: str = "") -> str:
        raw_gateway = str(gateway_url or "").strip().lower()
        scheme = "http" if raw_gateway.startswith("ws://") else "https"
        host = self._agent_md_safe_aid(aid)
        if self._config_model.discovery_port and ":" not in host:
            host = f"{host}:{int(self._config_model.discovery_port)}"
        return f"{scheme}://{host}/agent.md"

    @staticmethod
    def _agent_md_safe_aid(aid: str) -> str:
        target = str(aid or "").strip()
        if not target or any(ch in target for ch in ("/", "\\", "\x00")):
            raise ValidationError("agent.md aid is empty or contains path separators")
        return target

    def _agent_md_file_path(self, aid: str) -> Path:
        return self._agent_md_root() / self._agent_md_safe_aid(aid) / "agent.md"

    def _agent_md_meta_path(self, aid: str) -> Path:
        return self._agent_md_root() / self._agent_md_safe_aid(aid) / "agentmd.json"

    @contextmanager
    def _agent_md_record_lock(self, aid: str):
        meta_path = self._agent_md_meta_path(aid)
        lock_path = meta_path.parent / "agentmd.json.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a+b") as fp:
            try:
                if os.name == "nt":
                    import msvcrt
                    fp.seek(0)
                    msvcrt.locking(fp.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
                yield
            finally:
                try:
                    if os.name == "nt":
                        import msvcrt
                        fp.seek(0)
                        msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass

    @staticmethod
    def _atomic_write_text(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as fp:
                fp.write(content)
                fp.flush()
                os.fsync(fp.fileno())
            os.replace(tmp, path)
            if os.name != "nt":
                try:
                    dir_fd = os.open(str(path.parent), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except Exception:
                    pass
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass

    def _write_agent_md_record_unlocked(self, aid: str, record: dict[str, Any]) -> None:
        payload = {k: v for k, v in record.items() if k != "content" and v is not None}
        payload["aid"] = self._agent_md_safe_aid(aid)
        self._atomic_write_text(
            self._agent_md_meta_path(aid),
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )

    def _normalize_agent_md_record(self, aid: str, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            return {}
        record: dict[str, Any] = {k: v for k, v in data.items() if k != "content"}
        record["aid"] = self._agent_md_safe_aid(str(record.get("aid") or aid))
        for key in ("fetched_at", "observed_at", "checked_at", "updated_at"):
            try:
                record[key] = int(record.get(key) or 0)
            except Exception:
                record[key] = 0
        return record

    def _read_agent_md_record_unlocked(self, aid: str) -> dict[str, Any]:
        path = self._agent_md_meta_path(aid)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return self._normalize_agent_md_record(aid, data)
        except Exception as exc:
            self._log.warn("client", "agent.md metadata damaged, ignoring: aid=%s err=%s", aid, exc)
            return {}

    def _read_agent_md_content(self, aid: str) -> str:
        return self._agent_md_file_path(aid).read_text(encoding="utf-8")

    def _write_agent_md_content(self, aid: str, content: str) -> str:
        path = self._agent_md_file_path(aid)
        self._atomic_write_text(path, str(content or ""))
        return str(path)

    def _load_agent_md_record(self, aid: str) -> dict[str, Any] | None:
        target = str(aid or "").strip()
        if not target:
            return None
        try:
            with self._agent_md_record_lock(target):
                record = self._read_agent_md_record_unlocked(target)
            loaded: dict[str, Any]
            if record:
                loaded = dict(record)
                loaded["aid"] = target
            else:
                loaded = {"aid": target}
            try:
                content = self._read_agent_md_content(target)
                loaded["content"] = content
                loaded["local_etag"] = self._agent_md_content_etag(content)
            except Exception as exc:
                if self._agent_md_meta_path(target).exists():
                    self._log.warn("client", "agent.md content read failed: aid=%s err=%s", target, exc)
            if len(loaded) <= 1:
                return None
            if record == {} and "content" in loaded:
                with self._agent_md_record_lock(target):
                    self._write_agent_md_record_unlocked(target, {
                        "aid": target,
                        "local_etag": loaded.get("local_etag"),
                        "updated_at": int(time.time() * 1000),
                    })
            self._agent_md_cache[target] = dict(loaded)
            return dict(loaded)
        except Exception as exc:
            self._log.debug("client", "agent.md cache load skipped: aid=%s err=%s", target, exc)
        return None

    def _save_agent_md_record(self, aid: str, **fields: Any) -> dict[str, Any]:
        target = str(aid or "").strip()
        if not target:
            return {}
        try:
            content_marker = object()
            content = fields.pop("content", content_marker)
            saved_to = ""
            if content is not content_marker and content is not None:
                saved_to = self._write_agent_md_content(target, str(content))
                fields.setdefault("local_etag", self._agent_md_content_etag(str(content)))
                fields.setdefault("fetched_at", int(time.time() * 1000))
            with self._agent_md_record_lock(target):
                record = dict(self._read_agent_md_record_unlocked(target) or {})
                record["aid"] = target
                for key, value in fields.items():
                    if value is not None:
                        record[key] = value
                record["updated_at"] = int(time.time() * 1000)
                self._write_agent_md_record_unlocked(target, record)
            loaded = dict(record)
            if content is not content_marker and content is not None:
                loaded["content"] = str(content)
                if saved_to:
                    loaded["saved_to"] = saved_to
            else:
                cached = self._agent_md_cache.get(target)
                if isinstance(cached, dict) and "content" in cached:
                    loaded["content"] = cached["content"]
            self._agent_md_cache[target] = dict(loaded)
            owner = self._agent_md_owner_aid()
            if target == owner:
                local_etag = str(loaded.get("local_etag") or "").strip()
                remote_etag = str(loaded.get("remote_etag") or "").strip()
                if local_etag:
                    self._local_agent_md_etag = local_etag
                if remote_etag:
                    self._remote_agent_md_etag = remote_etag
            return dict(loaded)
        except Exception as exc:
            self._log.debug("client", "agent.md cache save skipped: aid=%s err=%s", target, exc)
        return {}

    def _agent_md_has_local_content(self, aid: str, record: dict[str, Any] | None = None) -> bool:
        if isinstance(record, dict) and record.get("content"):
            return True
        try:
            return self._agent_md_file_path(aid).is_file()
        except Exception:
            return False

    @staticmethod
    def _agent_md_checked_at_fresh(checked_at_ms: int, max_unsynced_days: float) -> bool:
        """判断上次 HEAD 时间距今是否在允许窗口内。

        - max_unsynced_days <= 0：每次都强制 HEAD（返回 False）
        - checked_at_ms 无效：视为从未 HEAD（返回 False）
        """
        try:
            days = float(max_unsynced_days or 0)
        except (TypeError, ValueError):
            return False
        if days <= 0 or checked_at_ms <= 0:
            return False
        return (time.time() * 1000 - float(checked_at_ms)) <= days * 86400_000

    def _schedule_agent_md_fetch_if_missing(self, aid: str, record: dict[str, Any] | None, *, source: str = "") -> None:
        target = str(aid or "").strip()
        if not target or self._agent_md_has_local_content(target, record):
            return
        inflight = getattr(self, "_agent_md_fetch_inflight", set())
        self._agent_md_fetch_inflight = inflight
        if target in inflight:
            return

        async def _fetch_missing() -> None:
            try:
                await self._fetch_agent_md(target)
            except Exception as exc:
                self._save_agent_md_record(target, last_error=str(exc), remote_status="found")
                self._log.debug("client", "agent.md auto fetch failed: aid=%s source=%s err=%s", target, source or "-", exc)
            finally:
                inflight.discard(target)

        inflight.add(target)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_fetch_missing())
        except RuntimeError:
            asyncio.run(_fetch_missing())

    def _observe_agent_md_meta(self, aid: str, etag: str = "", last_modified: str = "", *, source: str = "") -> None:
        target = str(aid or "").strip()
        remote_etag = str(etag or "").strip()
        remote_last_modified = str(last_modified or "").strip()
        if not target or not (remote_etag or remote_last_modified):
            return
        before = self._agent_md_cache.get(target)
        if not isinstance(before, dict):
            before = self._load_agent_md_record(target) or {}
        same = (
            (not remote_etag or str(before.get("remote_etag") or "").strip() == remote_etag)
            and (not remote_last_modified or str(before.get("last_modified") or "").strip() == remote_last_modified)
        )
        record = dict(before)
        if not same or not before:
            fields: dict[str, Any] = {
                "observed_at": int(time.time() * 1000),
                "remote_status": "found",
            }
            if remote_etag:
                fields["remote_etag"] = remote_etag
            if remote_last_modified:
                fields["last_modified"] = remote_last_modified
            record = self._save_agent_md_record(target, **fields) or record
        if target == self._agent_md_owner_aid() and remote_etag:
            self._remote_agent_md_etag = remote_etag
        self._schedule_agent_md_fetch_if_missing(target, record, source=source)
        self._log.debug(
            "client",
            "agent.md meta observed: aid=%s etag=%s last_modified=%s source=%s",
            target,
            remote_etag or "-",
            remote_last_modified or "-",
            source or "-",
        )

    def _observe_agent_md_etag(self, aid: str, etag: str, *, source: str = "") -> None:
        self._observe_agent_md_meta(aid, etag, "", source=source)

    def _observe_agent_md_from_envelope(self, envelope: Any) -> None:
        if not isinstance(envelope, dict):
            return
        agent_md = envelope.get("agent_md")
        if not isinstance(agent_md, dict):
            return
        sender = agent_md.get("sender")
        if not isinstance(sender, dict):
            return
        sender_aid = str(sender.get("aid") or "").strip()
        if not sender_aid:
            aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
            sender_aid = str(aad.get("from") or envelope.get("from") or "").strip()
        self._observe_agent_md_meta(
            sender_aid,
            str(sender.get("etag") or ""),
            str(sender.get("last_modified") or sender.get("lastModified") or ""),
            source="envelope",
        )

    async def _check_agent_md(self, aid: str | None = None, max_unsynced_days: float = 0) -> dict[str, Any]:
        target = str(aid or self._aid or "").strip()
        if not target:
            raise ValidationError("check_agent_md requires aid (or local AID)")
        before = self._load_agent_md_record(target) or {}
        local_etag = str(before.get("local_etag") or "").strip()
        local_found = bool(before and (before.get("content") or local_etag))
        remote_etag_cached = str(before.get("remote_etag") or "").strip()
        last_modified_cached = str(before.get("last_modified") or "").strip()
        checked_at_cached = int(before.get("checked_at") or before.get("fetched_at") or 0)
        cached_in_sync = bool(local_found and local_etag and remote_etag_cached and local_etag == remote_etag_cached)
        # max_unsynced_days > 0 时，距上次 HEAD 在窗口内则跳过 HEAD（直接返回缓存）；
        # max_unsynced_days <= 0 时，每次都强制 HEAD 确认远端状态。
        if cached_in_sync and self._agent_md_checked_at_fresh(checked_at_cached, max_unsynced_days):
            return {
                "aid": target,
                "local_found": True,
                "remote_found": True,
                "local_etag": local_etag,
                "remote_etag": remote_etag_cached,
                "in_sync": True,
                "last_modified": last_modified_cached,
                "status": 200,
                "cached": True,
                "verify_status": str(before.get("verify_status") or ""),
                "verify_error": str(before.get("verify_error") or ""),
            }
        # 远端确认不存在 + 本地也没有 + 在时间窗口内 → 跳过 HEAD
        remote_found_cached = bool(remote_etag_cached or str(before.get("remote_status") or "") == "found")
        if (not local_found and not remote_found_cached
                and str(before.get("remote_status") or "") == "missing"
                and self._agent_md_checked_at_fresh(checked_at_cached, max_unsynced_days)):
            return {
                "aid": target,
                "local_found": False,
                "remote_found": False,
                "local_etag": "",
                "remote_etag": "",
                "in_sync": False,
                "last_modified": "",
                "status": 404,
                "cached": True,
                "verify_status": "",
                "verify_error": "",
            }

        now_ms = int(time.time() * 1000)
        store = self._make_aid_store()
        try:
            remote_result = await store.head_agent_md(target)
            if not remote_result.ok or remote_result.data is None:
                message = remote_result.error.message if remote_result.error else "head agent.md failed"
                raise AUNError(message)
            remote = remote_result.data
        except Exception as exc:
            self._save_agent_md_record(target, checked_at=now_ms, remote_status="error", last_error=str(exc))
            raise
        finally:
            store.close()

        remote_found = bool(remote.get("found"))
        remote_etag = str(remote.get("etag") or "").strip()
        last_modified = str(remote.get("last_modified") or remote.get("lastModified") or "").strip()
        remote_status = "found" if remote_found else "missing"
        saved = self._save_agent_md_record(
            target,
            remote_etag=remote_etag if remote_found else "",
            last_modified=last_modified,
            checked_at=now_ms,
            remote_status=remote_status,
            last_error="",
        )
        if target == self._agent_md_owner_aid() and remote_etag:
            self._remote_agent_md_etag = remote_etag
        in_sync = bool(local_found and remote_found and local_etag and remote_etag and local_etag == remote_etag)
        # 远端有但本地没有 → 自动触发下载，保证本地一定有 agent.md（前提是服务端有）
        if remote_found and not local_found:
            self._schedule_agent_md_fetch_if_missing(target, saved or before, source="check_agent_md")
        return {
            "aid": target,
            "local_found": local_found,
            "remote_found": remote_found,
            "local_etag": local_etag,
            "remote_etag": remote_etag,
            "in_sync": in_sync,
            "last_modified": last_modified,
            "status": int(remote.get("status") or (200 if remote_found else 404)),
            "cached": False,
            "verify_status": str(saved.get("verify_status") or before.get("verify_status") or ""),
            "verify_error": str(saved.get("verify_error") or before.get("verify_error") or ""),
        }

    async def publish_agent_md(self, content: str | None = None) -> dict[str, Any]:
        """签名并上传 agent.md；content 未传时读取 {agent_md_path}/{self_aid}/agent.md。"""
        target = self._agent_md_owner_aid()
        if not target:
            raise ValidationError("publish_agent_md requires local AID")
        if self._current_aid is None or not self._current_aid.is_private_key_valid():
            raise StateError("publish_agent_md requires loaded AID with a valid private key")
        raw_content = self._read_agent_md_content(target) if content is None else str(content)
        signed_result = self._current_aid.sign_agent_md(raw_content)
        if not signed_result.ok or signed_result.data is None:
            message = signed_result.error.message if signed_result.error else "agent.md signing failed"
            raise ClientSignatureError(message)
        signed = signed_result.data["signed"]
        result = await self.upload_agent_md(signed)
        local_etag = self._agent_md_content_etag(signed)
        self._local_agent_md_etag = local_etag
        remote_etag = str(result.get("etag") or "").strip() if isinstance(result, dict) else ""
        if remote_etag:
            self._remote_agent_md_etag = remote_etag
        self._save_agent_md_record(
            target,
            content=signed,
            local_etag=local_etag,
            remote_etag=remote_etag,
            last_modified=str(result.get("last_modified") or "").strip() if isinstance(result, dict) else "",
            fetched_at=int(time.time() * 1000),
            remote_status="found" if remote_etag else "unknown",
            last_error="",
        )
        return result

    async def upload_agent_md(self, content: str) -> dict[str, Any]:
        """上传已签名 agent.md。"""
        if not str(content or "").strip():
            raise ValidationError("upload_agent_md requires non-empty content")
        target = self._agent_md_owner_aid()
        if not target:
            raise ValidationError("upload_agent_md requires local AID")
        _t_start = time.time()
        self._log.debug("client", "upload_agent_md enter: aid=%s content_len=%d", target, len(content or ""))
        gateway_url = await self._discover_gateway_for_aid(target)
        token = ""
        identity = self._identity if isinstance(self._identity, dict) else {}
        token = str(identity.get("access_token") or "").strip()
        if not token and isinstance(self._session_params, dict):
            token = str(self._session_params.get("access_token") or "").strip()
        if not token:
            auth_result = await self.authenticate()
            token = str(auth_result.get("access_token") or "").strip()
        if not token:
            raise StateError("authenticate did not return access_token")

        agent_md_url = self._agent_md_url(target, gateway_url)
        trace_mode = getattr(self._transport, "_trace_mode", "off")
        trace_id = secrets.token_hex(16) if trace_mode != "off" else ""
        if trace_id:
            self._log.info("client", "[trace=%s] http_out PUT agent.md aid=%s", trace_id, target)
        timeout = aiohttp.ClientTimeout(total=30)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "text/markdown; charset=utf-8",
        }
        if trace_id:
            headers["X-AUN-Trace"] = trace_id
        ssl_param = None if self._config_model.verify_ssl else False
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.put(
                    agent_md_url,
                    data=str(content or "").encode("utf-8"),
                    headers=headers,
                    ssl=ssl_param,
                ) as response:
                    duration_ms = int((time.time() - _t_start) * 1000)
                    if trace_id:
                        self._log.info(
                            "client",
                            "[trace=%s] http_in status=%d duration_ms=%d",
                            trace_id,
                            response.status,
                            duration_ms,
                        )
                        observer = getattr(self._transport, "_trace_observer", None)
                        if observer:
                            try:
                                observer({
                                    "type": "http",
                                    "trace_id": trace_id,
                                    "method": "PUT",
                                    "url": agent_md_url,
                                    "status": response.status,
                                    "duration_ms": duration_ms,
                                })
                            except Exception:
                                pass
                    if response.status == 404:
                        raise NotFoundError(f"agent.md endpoint not found for aid: {target}")
                    if response.status < 200 or response.status >= 300:
                        message = (await response.text()).strip()
                        raise AUNError(
                            f"upload agent.md failed: HTTP {response.status}"
                            + (f" - {message}" if message else "")
                        )
                    result = await response.json()
                    self._log.debug(
                        "client",
                        "upload_agent_md exit: elapsed=%.3fs aid=%s status=%d",
                        time.time() - _t_start,
                        target,
                        response.status,
                    )
                    return result
        except Exception as exc:
            self._log.debug(
                "client",
                "upload_agent_md exit (error): elapsed=%.3fs aid=%s err=%s",
                time.time() - _t_start,
                target,
                exc,
            )
            raise

    async def _fetch_agent_md(self, aid: str | None = None) -> dict[str, Any]:
        """下载 agent.md 并自动验签；内容固定保存到 {agent_md_path}/{aid}/agent.md。"""
        target = (aid or self._aid or "").strip()
        if not target:
            raise ValidationError("fetch_agent_md requires aid (or local AID)")
        store = self._make_aid_store()
        try:
            fetched = await store.fetch_agent_md(target)
            if not fetched.ok or fetched.data is None:
                message = fetched.error.message if fetched.error else "fetch agent.md failed"
                if fetched.error and fetched.error.code == "AGENTMD_NOT_FOUND":
                    raise NotFoundError(message)
                raise AUNError(message)
            data = fetched.data
        finally:
            store.close()

        content = str(data.get("content") or "")
        signature = dict(data.get("signature") or {})

        is_self = target == (self._aid or "")
        local_etag = self._agent_md_content_etag(content)
        remote_etag = str(data.get("etag") or "").strip()
        last_modified = str(data.get("last_modified") or data.get("lastModified") or "").strip()
        if is_self:
            self._local_agent_md_etag = local_etag
            if remote_etag:
                self._remote_agent_md_etag = remote_etag
        saved = self._save_agent_md_record(
            target,
            content=content,
            local_etag=local_etag,
            remote_etag=remote_etag if remote_etag else None,
            last_modified=last_modified if last_modified else None,
            fetched_at=int(time.time() * 1000),
            remote_status="found",
            verify_status=str(signature.get("status") or "") if isinstance(signature, dict) else "",
            verify_error=str(signature.get("reason") or "") if isinstance(signature, dict) else "",
            last_error="",
        )
        in_sync: bool | None = None
        if is_self:
            remote = remote_etag or self._remote_agent_md_etag or ""
            in_sync = (local_etag == remote) if (local_etag and remote) else False

        return {
            "aid": target,
            "content": content,
            "signature": signature,
            "in_sync": in_sync,
            "saved_to": saved.get("saved_to") or str(self._agent_md_file_path(target)),
            "save_error": None,
        }
    def _observe_rpc_meta(self, meta: dict) -> None:
        """transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。"""
        if not isinstance(meta, dict):
            return
        etag = str(meta.get("agent_md_etag") or "").strip()
        if etag:
            self._remote_agent_md_etag = etag
            self._observe_agent_md_meta(self._aid or "", etag, "", source="rpc.self")
        etags = meta.get("agent_md_etags")
        if isinstance(etags, dict):
            # role key 优先级：requester / peer 是新规范，其余是兼容旧 SDK 的别名。
            # 同一 AID 在多个 role 下出现时，set_default 自动去重（首次写入即生效）。
            for key in ("requester", "peer", "receiver", "target", "to", "sender", "from"):
                item = etags.get(key)
                if not isinstance(item, dict):
                    continue
                self._observe_agent_md_meta(
                    str(item.get("aid") or ""),
                    str(item.get("etag") or ""),
                    str(item.get("last_modified") or item.get("lastModified") or ""),
                    source=f"rpc.{key}",
                )
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
        return self._public_state

    # ── 生命周期 ──────────────────────────────────────────

    @property
    def gateway_health(self) -> bool | None:
        """最近一次 health check 结果，None 表示尚未检查。"""
        return self._discovery.last_healthy

    async def authenticate(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """获取访问 token，但不建立长连接。"""
        _t_start = time.time()
        if self._public_state != ConnectionState.STANDBY:
            raise StateError(f"authenticate not allowed in state {self._public_state.value}")
        if not self._aid:
            raise StateError("authenticate requires loaded identity")
        request = dict(options or {})
        if "gateway" in request or "gateways" in request:
            raise ValidationError("gateway must be resolved by discovery and cannot be supplied externally")
        gateway_url = str(self._gateway_url or "").strip()
        try:
            if not gateway_url:
                gateway_url = await self._discover_gateway_for_aid(self._aid)
            self._gateway_url = gateway_url
            self._log.debug("client", "authenticate enter: aid=%s gateway=%s", self._aid, gateway_url)
            result = await self._auth.authenticate(gateway_url, aid=self._aid)
            self._aid = str(result.get("aid") or self._aid)
            self._auth._aid = self._aid
            identity = self._auth.load_identity_or_none(self._aid) or {"aid": self._aid}
            access_token = result.get("access_token")
            if access_token:
                identity["access_token"] = access_token
            self._identity = identity
            self._state = ConnectionState.AUTHENTICATED.value
            self._last_error = None
            self._last_error_code = None
            self._log.debug("client", "authenticate exit: elapsed=%.3fs aid=%s", time.time() - _t_start, self._aid)
            return result
        except Exception as exc:
            self._last_error = exc
            self._last_error_code = "authenticate_failed"
            self._log.debug("client", "authenticate exit (error): elapsed=%.3fs aid=%s err=%s", time.time() - _t_start, self._aid, exc)
            raise

    async def connect(self, opts: ConnectionOptions | None = None) -> None:
        _t_start = time.time()
        if self._public_state not in {
            ConnectionState.NO_IDENTITY,
            ConnectionState.STANDBY,
            ConnectionState.AUTHENTICATED,
            ConnectionState.RETRY_BACKOFF,
            ConnectionState.CONNECTION_FAILED,
        }:
            raise StateError(f"connect not allowed in state {self._public_state.value}")
        if opts and "gateway" in opts:
            raise ValidationError("gateway must be resolved by discovery and cannot be supplied externally")
        params: dict[str, Any] = {}
        if opts:
            if "auto_reconnect" in opts:
                params["auto_reconnect"] = opts["auto_reconnect"]
            if "connect_timeout" in opts:
                params.setdefault("timeouts", {})["connect"] = opts["connect_timeout"]
            if any(k in opts for k in ("retry_initial_delay", "retry_max_delay", "retry_max_attempts")):
                params["retry"] = {
                    "initial_delay": opts.get("retry_initial_delay", 1),
                    "max_delay": opts.get("retry_max_delay", 64),
                    "max_attempts": opts.get("retry_max_attempts", 0),
                }
            if "heartbeat_interval" in opts:
                params["heartbeat_interval"] = opts["heartbeat_interval"]
            if "call_timeout" in opts:
                params.setdefault("timeouts", {})["call"] = opts["call_timeout"]
        # slot_id 来自 AID，不从 opts 传入
        slot_id = getattr(self._current_aid, "slot_id", None) or self._slot_id or ""
        if slot_id:
            params["slot_id"] = slot_id
        if self._public_state == ConnectionState.NO_IDENTITY:
            raise StateError("connect requires a loaded identity")

        if self._public_state == ConnectionState.STANDBY:
            auth_result = await self.authenticate()
            params["access_token"] = auth_result.get("access_token")
            params["gateway"] = auth_result.get("gateway") or self._gateway_url
        elif self._public_state in {
            ConnectionState.AUTHENTICATED,
            ConnectionState.RETRY_BACKOFF,
            ConnectionState.CONNECTION_FAILED,
        }:
            identity = self._identity if isinstance(self._identity, dict) else {}
            token = identity.get("access_token")
            if not token and self._session_params:
                token = self._session_params.get("access_token")
            if token:
                params["access_token"] = token
            if self._gateway_url:
                params["gateway"] = self._gateway_url

        if self._public_state == ConnectionState.RETRY_BACKOFF and self._reconnect_task is not None:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None

        if self._public_state == ConnectionState.CONNECTION_FAILED:
            self._retry_attempt = 0
            self._last_error = None
            self._last_error_code = None
        self._next_retry_at = None

        normalized = self._normalize_connect_params(params)
        self._state = ConnectionState.CONNECTING.value
        self._session_params = normalized
        self._session_options = self._build_session_options(normalized)
        self._transport.set_timeout(self._session_options["timeouts"]["call"])
        self._closing = False

        gateways = self._resolve_gateways(normalized)
        self._log.debug("client", "connect enter: gateways=%s", gateways)
        last_error: BaseException | None = None
        for gw in gateways:
            try:
                gw_params = dict(normalized)
                gw_params["gateway"] = gw
                await self._connect_once(gw_params, allow_reauth=False)
                if self._public_state != ConnectionState.READY:
                    self._state = ConnectionState.READY.value
                self._last_error = None
                self._last_error_code = None
                self._next_retry_at = None
                self._log.debug("client", "connect exit: elapsed=%.3fs gateway=%s aid=%s", time.time() - _t_start, self._gateway_url, self._aid or "-")
                return
            except BaseException as exc:
                last_error = exc
                if len(gateways) > 1:
                    self._log.warn("client", "connect: gateway %s failed, trying next: %s", gw, exc)
                if self._public_state == ConnectionState.CONNECTING:
                    self._state = ConnectionState.CONNECTING.value

        if self._public_state == ConnectionState.CONNECTING:
            self._state = ConnectionState.STANDBY.value if self.has_identity else ConnectionState.NO_IDENTITY.value
        if last_error is not None:
            self._last_error = last_error
            self._last_error_code = "connect_failed"
        self._log.warn("client", "connect exit (error): elapsed=%.3fs gateways=%s err=%s", time.time() - _t_start, gateways, last_error)
        raise last_error  # type: ignore[misc]

    async def disconnect(self) -> None:
        """断开连接但不关闭客户端（可重新 connect，对齐 C++ Disconnect）"""
        _t_start = time.time()
        self._log.debug("client", "disconnect enter: state=%s closing=%s", self._state, self._closing)
        # 若 close() 已在执行中，跳过 disconnect 避免竞态
        if self._closing:
            self._log.debug("client", "disconnect exit (close-in-progress): elapsed=%.3fs", time.time() - _t_start)
            return
        if self._public_state not in {
            ConnectionState.AUTHENTICATED,
            ConnectionState.CONNECTING,
            ConnectionState.READY,
            ConnectionState.RETRY_BACKOFF,
            ConnectionState.RECONNECTING,
            ConnectionState.CONNECTION_FAILED,
        }:
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
        self._identity = None
        self._next_retry_at = None
        self._retry_attempt = 0
        self._last_error = None
        self._last_error_code = None
        self._state = ConnectionState.STANDBY.value if self._current_aid is not None or self._aid else ConnectionState.NO_IDENTITY.value
        await self._dispatcher.publish("state_change", {"state": self._state})
        self._log.debug("client", "disconnect exit: elapsed=%.3fs state=%s", time.time() - _t_start, self._state)

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
                self._current_aid = None
                self._aid = None
                self._identity = None
                self._gateway_url = None
                self._peer_gateway_cache.clear()
                self._session_params = None
                self._next_retry_at = None
                self._retry_attempt = 0
                self._last_error = None
                self._last_error_code = None
                self._reset_seq_tracking_state()
                self._log.debug("client", "close exit (was idle/closed): elapsed=%.3fs state=%s", time.time() - _t_start, self._state)
                return
            await self._transport.close()
            self._state = "closed"
            self._current_aid = None
            self._aid = None
            self._identity = None
            self._gateway_url = None
            self._peer_gateway_cache.clear()
            self._session_params = None
            self._next_retry_at = None
            self._retry_attempt = 0
            self._last_error = None
            self._last_error_code = None
            await self._dispatcher.publish("state_change", {"state": self._state})
            self._reset_seq_tracking_state()
            self._log.debug("client", "close exit: elapsed=%.3fs state=%s", time.time() - _t_start, self._state)
        finally:
            close_keystore = getattr(self._keystore, "close", None)
            if callable(close_keystore):
                close_keystore()

    # ── RPC ───────────────────────────────────────────────

    # 需要客户端签名的关键方法（渐进式部署：服务端有签名则验，无签名则放行）
    _SIGNED_METHODS = frozenset({
        "message.send",
        "message.v2.put_peer_pk", "message.v2.bootstrap",
        "message.v2.group_bootstrap", "message.v2.pull",
        "message.v2.ack",
        "group.send",
        "group.v2.put_group_pk", "group.v2.bootstrap",
        "group.v2.send", "group.v2.pull", "group.v2.ack",
        "group.v2.propose_state", "group.v2.confirm_state",
        "group.v2.get_proposal",
        "group.kick", "group.add_member",
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

    # ── Pull Gate ─────────────────────────────────────────────────

    def _pull_gate_key_for_call(self, method: str, params: dict) -> str:
        if method in ("message.pull", "message.v2.pull"):
            return f"p2p:{self._aid}" if self._aid else ""
        if method in ("group.pull", "group.v2.pull"):
            gid = str(params.get("group_id") or "").strip()
            return f"group:{gid}" if gid else ""
        if method == "group.pull_events":
            gid = str(params.get("group_id") or "").strip()
            return f"group_event:{gid}" if gid else ""
        return ""

    def _try_acquire_pull_gate(self, key: str) -> int | None:
        if not key:
            return 0
        if not hasattr(self, "_pull_gates"):
            self._pull_gates = {}
        now = int(time.time() * 1000)
        gate = self._pull_gates.get(key, {"inflight": False, "started_at": 0, "token": 0})
        if gate["inflight"] and now - gate["started_at"] <= self._PULL_GATE_STALE_MS:
            return None
        if gate["inflight"]:
            self._log.warn("client", "pull in-flight stale reset: key=%s age=%dms", key, now - gate["started_at"])
        gate["token"] += 1
        gate["inflight"] = True
        gate["started_at"] = now
        self._pull_gates[key] = gate
        return gate["token"]

    def _release_pull_gate(self, key: str, token: int | None) -> None:
        if not key or token is None:
            return
        gate = self._pull_gates.get(key)
        if not gate or gate["token"] != token:
            return
        gate["inflight"] = False
        gate["started_at"] = 0

    async def _run_pull_serialized(self, key: str, operation):
        """acquire gate → execute → release。gate 被占时短等待后重试。"""
        token = self._try_acquire_pull_gate(key)
        if token is None:
            deadline = time.time() + (self._PULL_GATE_STALE_MS + 100) / 1000.0
            while token is None and time.time() <= deadline:
                await asyncio.sleep(0.025)
                token = self._try_acquire_pull_gate(key)
            if token is None:
                raise StateError(f"pull already in-flight for {key}")
        try:
            return await operation()
        finally:
            self._release_pull_gate(key, token)

    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None) -> Any:
        _t_call_start = time.time()
        if not isinstance(method, str) or not method.strip():
            raise ValidationError("call() requires a non-empty method string")
        if self._public_state != ConnectionState.READY:
            raise ConnectionError("client is not connected")
        if self._is_internal_only_method(method):
            raise AUNPermissionError(f"method is internal_only: {method}")

        params = dict(params) if params else {}
        params = self._merge_instance_protected_headers(method, params)
        self._log.debug("client", "call enter: method=%s", method)
        if method in {"message.send", "group.send"}:
            self._normalize_outbound_message_payload(params, method=method)
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
        if method.startswith("group.") and "device_id" not in params:
            params["device_id"] = self._device_id
        if method.startswith("group.") and "slot_id" not in params:
            params["slot_id"] = self._slot_id

        # 自动加密：message.send 默认加密（encrypt 默认 True）— V2-only 客户端必须走 V2 路径
        if method == "message.send":
            encrypt = params.pop("encrypt", True)
            self._log_message_debug(
                "send-input",
                "message.send",
                "message.send",
                params,
                payload_override=params.get("payload", params.get("content")),
                extra={"encrypt": encrypt},
            )
            self._log.debug("client", "call message.send: to=%s encrypt=%s payload_keys=%s",
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
            self._log_message_debug(
                "send-input",
                "group.send",
                "group.send",
                params,
                payload_override=params.get("payload", params.get("content")),
                extra={"encrypt": encrypt},
            )
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

        # message.pull：V2 就绪时走 V2 pull（V2-only：跳过旧加密 envelope）
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
            if self._should_skip_client_signature(method, params):
                params.pop("client_signature", None)
            else:
                self._sign_client_operation(method, params)

        # P1-23: 非幂等方法使用更长超时
        call_kwargs: dict[str, Any] = {}
        if method in _NON_IDEMPOTENT_METHODS:
            call_kwargs["timeout"] = _NON_IDEMPOTENT_TIMEOUT
        if trace:
            call_kwargs["trace"] = trace

        # Pull Gate：序列化同一 key 的 pull 操作
        pull_gate_key = self._pull_gate_key_for_call(method, params)
        if pull_gate_key:
            async def _gated_call():
                if method in ("group.thought.get", "message.thought.get"):
                    self._log.debug("client", "thought.get transport call start: method=%s params=%s", method, params)
                try:
                    return await self._transport.call(method, params, **call_kwargs)
                except TypeError as exc:
                    if call_kwargs and "unexpected keyword argument" in str(exc):
                        call_kwargs.pop("timeout", None)
                        call_kwargs.pop("trace", None)
                        return await self._transport.call(method, params, **call_kwargs) if call_kwargs else await self._transport.call(method, params)
                    raise
            try:
                result = await self._run_pull_serialized(pull_gate_key, _gated_call)
            except Exception as exc:
                self._log.debug("client", "call exit (error): elapsed=%.3fs method=%s err=%s", time.time() - _t_call_start, method, exc)
                raise
        else:
            if method in ("group.thought.get", "message.thought.get"):
                self._log.debug("client", "thought.get transport call start: method=%s params=%s", method, params)
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

        if method == "group.thought.get" and isinstance(result, dict):
            self._log.debug(
                "client",
                "group.thought.get transport result: found=%s raw_count=%d",
                result.get("found"),
                len(result.get("thoughts", [])) if isinstance(result.get("thoughts"), list) else 0,
            )
            result = await self._decrypt_group_thoughts(result)
        if method == "message.thought.get" and isinstance(result, dict):
            self._log.debug(
                "client",
                "message.thought.get transport result: found=%s raw_count=%d",
                result.get("found"),
                len(result.get("thoughts", [])) if isinstance(result.get("thoughts"), list) else 0,
            )
            result = await self._decrypt_message_thoughts(result)
        if method in {"message.v2.bootstrap", "group.v2.bootstrap"} and isinstance(result, dict):
            try:
                await self._v2_observe_bootstrap_material(method, params, result)
            except Exception as exc:
                self._log.debug("client", "V2 bootstrap material observe skipped: method=%s err=%s", method, exc)
        # 自动解密：message.pull 返回的消息（V2 路径已在 call() 开头路由，此处为 plaintext pull 的 seq 跟踪）
        if method == "message.pull" and isinstance(result, dict):
            ns = f"p2p:{self._aid}" if self._aid else ""
            messages = result.get("messages")
            if isinstance(messages, list):
                for msg in messages:
                    self._log_message_debug("pull-raw", "message.pull", "message.received", msg)
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
            if isinstance(messages, list):
                for msg in messages:
                    self._log_message_debug("pull-raw", "group.pull", "group.message_created", msg)
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
                if method in {"group.create", "group.use_invite_code"}:
                    self._schedule_group_spk_registration(gid, reason=method)
                # group SPK 轮换只由 group.changed 成员关系事件或解密消费当前 group SPK 触发。
                # 这里不在本地 RPC 返回后直接轮换，避免 lazy/propose 路径和事件路径重复触发。

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

    def _merge_instance_protected_headers(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        instance_headers = getattr(self, "_instance_protected_headers", None)
        if method not in _PROTECTED_HEADERS_METHODS or not instance_headers:
            return params
        existing = self._protected_headers_from_params(params)
        merged = dict(instance_headers)
        if existing:
            to_dict = getattr(existing, "to_dict", None)
            existing_dict = to_dict() if callable(to_dict) else dict(existing)
            if isinstance(existing_dict, dict):
                merged.update(existing_dict)
        params["protected_headers"] = merged
        return params

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

    # ── 事件 ──────────────────────────────────────────────

    def on(self, event: str, handler: Callable[[Any], Any]) -> Subscription:
        if not isinstance(event, str) or not event.strip():
            raise ValidationError("on() requires a non-empty event name")
        if not callable(handler):
            raise ValidationError("on() requires a callable handler")
        return self._dispatcher.subscribe(event, handler)

    def off(self, event: str, handler: Callable[[Any], Any]) -> None:
        """注销事件处理器（对齐 C++ RemoveEventHandler / JS off）。"""
        if not isinstance(event, str) or not event.strip():
            raise ValidationError("off() requires a non-empty event name")
        if not callable(handler):
            raise ValidationError("off() requires a callable handler")
        self._dispatcher.unsubscribe(event, handler)

    # ── per-namespace 消息处理锁 ──────────────────────────────
    def _get_ns_lock(self, ns: str) -> asyncio.Lock:
        """获取指定 namespace 的消息处理锁（懒创建）。

        同一 namespace 的 push/pull 必须串行，防止乱序投递。
        不同 namespace 之间互不阻塞。asyncio 单线程中 dict 操作是原子的，无需额外 guard。
        """
        locks = getattr(self, "_ns_locks", None)
        if locks is None:
            locks = {}
            self._ns_locks = locks
        lock = locks.get(ns)
        if lock is None:
            lock = asyncio.Lock()
            locks[ns] = lock
        return lock

    # ── P1-17: auto-ack fire-and-forget 辅助 ──────────────────
    def _fire_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        """将 ack RPC 以 fire-and-forget 方式发送，不阻塞消息事件分发。

        防御：ack 调用前 clamp，永远不发送超过本地已知上界（max_seen_seq）的 seq，
        避免把本地脏数据/异常状态回传服务端污染数据库。
        """
        params = self._clamp_ack_params(method, params) if isinstance(params, dict) else params
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._safe_ack(method, params, label))

    def _clamp_ack_params(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """ack 参数边界保护：clamp 到 [0, max_seen_seq]。

        覆盖以下方法：
        - message.v2.ack: up_to_seq
        - message.ack: seq
        - group.v2.ack: up_to_seq（per-group ns）
        - group.ack_messages: msg_seq（per-group ns）
        - group.ack_events: event_seq（per-group ns，事件 ns 与消息 ns 共享 max_seen）
        """
        def _clamp_field(p: dict, field: str, ns: str) -> dict:
            value = p.get(field)
            if not isinstance(value, (int, float)):
                return p
            ivalue = int(value)
            new_value = ivalue
            if ivalue < 0:
                new_value = 0
            if ns:
                max_seen = self._seq_tracker.get_max_seen_seq(ns)
                if max_seen > 0 and new_value > max_seen:
                    self._log.warn(
                        "client",
                        "ack clamp: method=%s %s=%d > max_seen=%d, clamp",
                        method, field, ivalue, max_seen,
                    )
                    new_value = max_seen
            if new_value != ivalue:
                return {**p, field: new_value}
            return p

        if method == "message.v2.ack":
            ns = f"p2p:{self._aid}" if self._aid else ""
            return _clamp_field(params, "up_to_seq", ns)
        if method == "message.ack":
            ns = f"p2p:{self._aid}" if self._aid else ""
            return _clamp_field(params, "seq", ns)
        # Group ack: ns 来自 group_id
        if method in ("group.v2.ack", "group.ack_messages", "group.ack_events"):
            group_id = str(params.get("group_id") or "").strip()
            ns = f"group:{group_id}" if group_id else ""
            if method == "group.v2.ack":
                return _clamp_field(params, "up_to_seq", ns)
            if method == "group.ack_messages":
                return _clamp_field(params, "msg_seq", ns)
            if method == "group.ack_events":
                return _clamp_field(params, "event_seq", ns)
        return params

    async def _safe_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        """安全执行 ack RPC，失败仅记录日志。"""
        try:
            params = dict(params)
            if method in self._SIGNED_METHODS:
                self._sign_client_operation(method, params)
            self._log.debug("client", "%s auto-ack send: method=%s params=%s", label or method, method, params)
            result = await self._transport.call(method, params)
            self._log.debug("client", "%s auto-ack ok: method=%s result=%s", label or method, method, result)
        except Exception as exc:
            self._log.debug("client", "%s auto-ack failed: %s", label or method, exc)

    async def _on_raw_message_received(self, data: Any) -> None:
        """处理 transport 层推送的原始消息：解密后 re-publish 给用户。"""
        _t_start = time.time()
        if isinstance(data, dict):
            self._log_message_debug("server-push", "_raw.message.received", "message.received", data)
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
        # P2P namespace 锁：同一 namespace 的 push/pull 串行执行
        ns_key = ""
        if isinstance(data, dict) and data.get("seq") is not None and self._aid:
            ns_key = f"p2p:{self._aid}"
        if ns_key:
            async with self._get_ns_lock(ns_key):
                await self._process_and_publish_message_inner(data)
        else:
            await self._process_and_publish_message_inner(data)

    async def _process_and_publish_message_inner(self, data: Any) -> None:
        """P2P push 处理内部实现（在 ns lock 保护下调用）。"""
        _t_start = time.time()
        try:
            if not isinstance(data, dict):
                await self._publish_app_event("message.received", data)
                return
            msg = dict(data)
            self._log.debug(
                "client",
                "_process_and_publish_message enter: message_id=%s seq=%s from=%s device_id=%s slot_id=%s",
                msg.get("message_id"), msg.get("seq"), msg.get("from"),
                msg.get("device_id"), msg.get("slot_id"),
            )
            if not self._message_targets_current_instance(msg):
                self._log.debug(
                    "client",
                    "_process_and_publish_message filtered (instance mismatch): "
                    "msg_device=%s self_device=%s msg_slot=%s self_slot=%s",
                    msg.get("device_id"), self._device_id,
                    msg.get("slot_id"), self._slot_id,
                )
                return

            # P2P 空洞检测
            seq = msg.get("seq")
            encrypted_push = self._is_encrypted_push_message(msg)
            if seq is not None and self._aid:
                ns = f"p2p:{self._aid}"
                # Push 修上界：先更新 max_seen_seq，让上界反映服务端状态（即使后续被去重/旁路）
                seq_int = int(seq) if isinstance(seq, (int, float)) else 0
                if seq_int > 0:
                    self._seq_tracker.update_max_seen(ns, seq_int)
                old_contig = self._seq_tracker.get_contiguous_seq(ns)
                need_pull = self._seq_tracker.on_message_seq(ns, seq_int)
                new_contig = self._seq_tracker.get_contiguous_seq(ns)
                self._log.debug("client", "P2P push seq tracking: seq=%d contig=%d->%d need_pull=%s",
                                  seq_int, old_contig, new_contig, need_pull)
                self._persist_seq(ns)
                if need_pull:
                    loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(self._fill_p2p_gap())

            # 明文消息直接透传（V2 加密消息走 _on_v2_push_notification）
            if seq is not None and self._aid:
                self._log.debug(
                    "client",
                    "publish ordered: ns=%s seq=%s message_id=%s",
                    ns, seq, msg.get("message_id", "?"),
                )
                if encrypted_push:
                    await self._publish_encrypted_push_message(
                        "message.received", "message.undecryptable", ns, seq, msg, group=False,
                    )
                else:
                    await self._publish_ordered_message("message.received", ns, seq, msg)
            else:
                if encrypted_push:
                    await self._publish_encrypted_push_message(
                        "message.received", "message.undecryptable", "", seq, msg, group=False,
                    )
                    return
                self._log.debug(
                    "client",
                    "publish app event (no seq): message_id=%s",
                    msg.get("message_id", "?"),
                )
                await self._publish_app_event("message.received", msg, source="push")

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
                self._attach_v2_envelope_metadata_from_source(safe_event, data)
                await self._publish_app_event("message.undecryptable", safe_event)

    async def _on_raw_group_message_created(self, data: Any) -> None:
        """处理 group.message_created 推送。
        V2-only 模式：推送不带 payload，触发 group.v2.pull 获取完整消息。
        明文推送：payload 已在推送中时直接透传。
        """
        if not isinstance(data, dict):
            await self._publish_app_event("group.message_created", data, source="group-push")
            return
        group_id = str(data.get("group_id") or "").strip()
        # 群消息 namespace 锁：同一 group 的 push/pull 串行
        if group_id:
            ns_key = f"group:{group_id}"
            async with self._get_ns_lock(ns_key):
                await self._on_raw_group_message_created_inner(data)
        else:
            await self._on_raw_group_message_created_inner(data)

    async def _on_raw_group_message_created_inner(self, data: Any) -> None:
        """群消息 push 内部实现（在 ns lock 保护下调用）。"""
        self._log_message_debug("server-push", "_raw.group.message_created", "group.message_created", data)
        group_id = data.get("group_id", "")
        seq = data.get("seq")
        if group_id:
            self._group_synced.add(group_id)
        payload = data.get("payload")
        has_payload = payload is not None and not (isinstance(payload, dict) and not payload)
        encrypted_push = self._is_encrypted_push_message(data) if has_payload else False

        if encrypted_push:
            if group_id and seq is not None:
                ns = f"group:{group_id}"
                seq_i = int(seq)
                if seq_i > 0:
                    self._seq_tracker.update_max_seen(ns, seq_i)
                    if self._seq_tracker.get_contiguous_seq(ns) == seq_i:
                        self._log.debug(
                            "client",
                            "_raw.group.message_created encrypted push already covered: group=%s seq=%d",
                            group_id, seq_i,
                        )
                        return
                    self._repair_push_contiguous_bound(
                        ns, seq_i, has_payload=True, label="_raw.group.message_created.encrypted",
                    )
                if self._is_published_seq(ns, seq_i) or self._is_pending_ordered_seq(ns, seq_i):
                    return
                self._seq_tracker.on_message_seq(ns, seq_i)
                self._persist_seq(ns)
                await self._publish_encrypted_push_message(
                    "group.message_created", "group.message_undecryptable", ns, seq, data, group=True,
                )
                contig = self._seq_tracker.get_contiguous_seq(ns)
                if contig > 0:
                    self._fire_ack("group.ack_messages", {
                        "group_id": group_id, "msg_seq": contig,
                        "device_id": self._device_id,
                        "slot_id": self._slot_id,
                    }, f"群消息 auto-ack group={group_id}")
            else:
                await self._publish_encrypted_push_message(
                    "group.message_created", "group.message_undecryptable", "", seq, data, group=True,
                )
            return

        # V2-only 模式：明文历史推送不带 payload 时，也通过 group.v2.pull 获取完整消息
        if getattr(self, "_v2_session", None) and group_id and seq is not None:
            ns = f"group:{group_id}"
            seq_i = int(seq)
            # Push 修上界：先更新 max_seen_seq
            if seq_i > 0:
                self._seq_tracker.update_max_seen(ns, seq_i)
                if self._seq_tracker.get_contiguous_seq(ns) == seq_i:
                    self._log.debug(
                        "client",
                        "_raw.group.message_created duplicate push already covered: group=%s seq=%d",
                        group_id, seq_i,
                    )
                    return
                self._repair_push_contiguous_bound(
                    ns, seq_i, has_payload=False, label="_raw.group.message_created",
                )
            if self._is_published_seq(ns, seq_i) or self._is_pending_ordered_seq(ns, seq_i):
                return
            # 复用 V2 push 的 pull 逻辑
            async def _pull_and_publish() -> None:
                # 群消息 namespace 锁：create_task 出去的独立 task 需自行持锁
                async with self._get_ns_lock(ns):
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
            loop.create_task(_pull_and_publish())
            return

        # 明文 payload 推送路径
        if group_id and seq is not None:
            ns = f"group:{group_id}"
            seq_i = int(seq)
            # Push 修上界：先更新 max_seen_seq
            if seq_i > 0:
                self._seq_tracker.update_max_seen(ns, seq_i)
                if self._seq_tracker.get_contiguous_seq(ns) == seq_i:
                    self._log.debug(
                        "client",
                        "_raw.group.message_created payload push already covered: group=%s seq=%d",
                        group_id, seq_i,
                    )
                    return
                self._repair_push_contiguous_bound(
                    ns, seq_i, has_payload=True, label="_raw.group.message_created",
                )
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
            await self._publish_app_event("group.message_created", data, source="group-push")

    async def _on_raw_group_v2_message_created(self, data: Any) -> None:
        """处理 V2 群消息推送：服务端 push 仅携带 seq + message_id + sender_aid + group_id，
        SDK 收到后主动 group.v2.pull 拉取 envelope 并自动解密，转发为 group.message_created
        事件给应用层。
        """
        _t_start = time.time()
        if not isinstance(data, dict):
            self._log.debug("client", "_on_raw_group_v2_message_created skipped (non-dict): type=%s", type(data).__name__)
            return
        self._log_message_debug("server-push", "_raw.group.v2.message_created", "group.message_created", data)
        group_id = str(data.get("group_id") or "").strip()
        seq = int(data.get("seq", 0) or 0)
        message_id = str(data.get("message_id") or "").strip()
        sender_aid = str(data.get("sender_aid") or "").strip()
        event_kind = str(data.get("kind") or "").strip()
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
        if event_kind == "group.online_unread_hint" and not data.get("_online_hint_drained"):
            if not self._session_options.get("background_sync", True):
                self._log.debug(
                    "client",
                    "_on_raw_group_v2_message_created skipped online unread hint: group=%s background_sync=false",
                    group_id,
                )
                return
            self._enqueue_online_unread_hint(data)
            return

        # Push 修上界：先更新 max_seen_seq
        ns_for_max = f"group:{group_id}"
        self._seq_tracker.update_max_seen(ns_for_max, seq)
        if self._seq_tracker.get_contiguous_seq(ns_for_max) == seq:
            self._log.debug(
                "client",
                "_on_raw_group_v2_message_created duplicate push already covered: group=%s seq=%d",
                group_id, seq,
            )
            return
        self._repair_push_contiguous_bound(
            ns_for_max, seq, has_payload=False, label="_raw.group.v2.message_created",
        )

        async def _pull_and_publish() -> None:
            # 群消息 namespace 锁：与群 push 串行
            ns = f"group:{group_id}"
            async with self._get_ns_lock(ns):
                try:
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

        if data.get("_online_hint_drained"):
            await _pull_and_publish()
        else:
            loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
            loop.create_task(_pull_and_publish())
        self._log.debug("client", "_on_raw_group_v2_message_created exit: elapsed=%.3fs", time.time() - _t_start)

    def _enqueue_online_unread_hint(self, data: dict[str, Any]) -> None:
        group_id = str(data.get("group_id") or "").strip()
        if not group_id:
            return
        self._online_unread_hint_queue[group_id] = dict(data)
        task = self._online_unread_hint_task
        if task is not None and not task.done():
            return
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        self._online_unread_hint_task = loop.create_task(self._drain_online_unread_hints())

    async def _drain_online_unread_hints(self) -> None:
        try:
            delay = max(0.0, float(getattr(self, "_online_unread_hint_initial_delay", _ONLINE_UNREAD_HINT_INITIAL_DELAY) or 0.0))
            if delay:
                await asyncio.sleep(delay)
            while self._online_unread_hint_queue:
                if self._public_state != ConnectionState.READY:
                    return
                if not self._session_options.get("background_sync", True):
                    return
                group_id = next(iter(self._online_unread_hint_queue))
                payload = self._online_unread_hint_queue.pop(group_id)
                payload["_online_hint_drained"] = True
                await self._on_raw_group_v2_message_created(payload)
                interval = max(0.0, float(getattr(self, "_online_unread_hint_interval", _ONLINE_UNREAD_HINT_INTERVAL) or 0.0))
                if interval:
                    await asyncio.sleep(interval)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._log.debug("client", "online unread hint drain failed: %s", exc)
        finally:
            self._online_unread_hint_task = None

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
                if self._should_skip_event_signature(data):
                    data.pop("client_signature", None)
                else:
                    data["_verified"] = await self._verify_event_signature(data, cs)
            # 发布给用户（publish 流程保持不变）
            await self._dispatcher.publish("group.changed", data)

            group_id = data.get("group_id", "")

            # V2 bootstrap 缓存失效：成员变更可能导致 epoch 递增或设备列表变化
            if group_id:
                bootstrap_cache = getattr(self, "_v2_bootstrap_cache", None)
                if bootstrap_cache is not None:
                    bootstrap_cache.pop(f"group:{group_id}", None)
                membership_actions = {
                    "member_added", "member_left", "member_removed", "role_changed",
                    "owner_transferred", "joined", "join_approved", "invite_code_used",
                }
                if action in membership_actions and getattr(self, "_v2_session", None):
                    joined_aid = str(
                        data.get("joined_aid")
                        or data.get("member_aid")
                        or data.get("aid")
                        or ""
                    ).strip()
                    actor_aid = str(data.get("actor_aid") or "").strip()
                    self_aid = str(getattr(self, "_aid", "") or "").strip()
                    join_actions = {"member_added", "joined", "join_approved", "invite_code_used"}
                    is_self_join = (
                        action in join_actions
                        and self_aid
                        and (
                            joined_aid == self_aid
                            or (
                                not joined_aid
                                and action in {"joined", "invite_code_used"}
                                and actor_aid == self_aid
                            )
                        )
                    )
                    if is_self_join:
                        self._schedule_group_spk_registration(group_id, reason=f"group.changed:{action}")
                    else:
                        self._schedule_group_spk_rotation(group_id, reason=f"group.changed:{action}")

            # V2 自动 propose_state：owner/admin 在成员变更后自动提交 state proposal
            if group_id and action in ("upsert", "member_added", "member_left", "member_removed", "role_changed", "owner_transferred", "joined", "join_approved", "invite_code_used") and getattr(self, "_v2_session", None):
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
            if self._should_skip_event_signature(data):
                data.pop("client_signature", None)
            else:
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
        # 群事件 namespace 锁：与群事件 push 串行
        async with self._get_ns_lock(ns):
            await self._fill_group_event_gap_inner(group_id, ns)

    async def _fill_group_event_gap_inner(self, group_id: str, ns: str) -> None:
        """群事件 gap fill 内部实现（在 ns lock 保护下调用）。"""
        if self._state != "connected" or self._closing:
            return
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        dedup_key = f"group_event_pull:{ns}"
        if dedup_key in self._gap_fill_done:
            return
        self._gap_fill_done[dedup_key] = time.time()
        # S1: try/finally 保证 dedup 键在所有出口清理
        try:
            next_after_seq = after_seq
            max_pages = 100
            page_count = 0
            while page_count < max_pages:
                page_count += 1
                self._log.info("client", "group event gap fill start: group=%s after_seq=%d", group_id, next_after_seq)
                result = await self.call("group.pull_events", {
                    "group_id": group_id,
                    "after_event_seq": next_after_seq,
                    "device_id": self._device_id,
                    "limit": 50,
                })
                if not isinstance(result, dict):
                    return
                events = result.get("events", [])
                if not isinstance(events, list):
                    return

                self._log.info("client", "group event gap fill page done: group=%s after_seq=%d pulled=%d",
                               group_id, next_after_seq, len(events))
                page_contig_before = self._seq_tracker.get_contiguous_seq(ns)
                if events:
                    self._seq_tracker.on_pull_result(ns, events, after_seq=next_after_seq)

                cursor = result.get("cursor")
                server_ack = int(cursor.get("current_seq") or 0) if isinstance(cursor, dict) else 0
                if server_ack > 0:
                    contig_before_floor = self._seq_tracker.get_contiguous_seq(ns)
                    if contig_before_floor < server_ack:
                        self._log.info(
                            "client",
                            "group.pull_events retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                            ns, contig_before_floor, server_ack,
                        )
                        self._seq_tracker.force_contiguous_seq(ns, server_ack)

                event_seqs: list[int] = []
                for evt in events:
                    if isinstance(evt, dict):
                        try:
                            es = int(evt.get("event_seq") or 0)
                        except (TypeError, ValueError):
                            es = 0
                        if es > 0:
                            event_seqs.append(es)
                        evt["_from_gap_fill"] = True
                        et = evt.get("event_type", "")
                        # 消息事件由群消息 pull 负责，事件补洞不重复投递
                        if et == "group.message_created":
                            continue
                        # 验签：有 client_signature 就验（与实时事件路径对齐）
                        cs = evt.get("client_signature")
                        if cs and isinstance(cs, dict):
                            if self._should_skip_event_signature(evt):
                                evt.pop("client_signature", None)
                            else:
                                evt["_verified"] = await self._verify_event_signature(evt, cs)
                        # group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
                        await self._dispatcher.publish("group.changed", evt)

                contig = self._seq_tracker.get_contiguous_seq(ns)
                if contig != page_contig_before:
                    self._persist_seq(ns)
                if events and contig > 0 and contig != page_contig_before:
                    max_seen_ack = self._seq_tracker.get_max_seen_seq(ns)
                    ack_seq = min(contig, max_seen_ack) if max_seen_ack > 0 else contig
                    try:
                        await self._transport.call("group.ack_events", {
                            "group_id": group_id, "event_seq": ack_seq,
                            "device_id": self._device_id,
                            "slot_id": self._slot_id,
                        })
                    except Exception as _ack_exc:
                        self._log.debug("client", "group event auto-ack failed: group=%s %s", group_id, _ack_exc)

                next_after = max(max(event_seqs) if event_seqs else next_after_seq, next_after_seq)
                if not events or next_after <= next_after_seq or result.get("has_more") is False:
                    break
                next_after_seq = next_after
            if page_count >= max_pages:
                self._log.warn("client", "group event gap fill reached max_pages=%d group=%s after_seq=%d",
                               max_pages, group_id, next_after_seq)
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
        # P2P namespace 锁：与 push 串行
        async with self._get_ns_lock(ns):
            await self._fill_p2p_gap_inner(ns)

    async def _fill_p2p_gap_inner(self, ns: str) -> None:
        """P2P gap fill 内部实现（在 ns lock 保护下调用）。"""
        if self._state != "connected" or self._closing:
            return
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
                                await self._publish_app_event("message.received", msg, source="pull")
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
            self._schedule_pending_p2p_pull_if_needed(ns, reason="gap-fill-complete")

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

    def _record_pending_p2p_pull(self, ns: str, seq: int) -> None:
        if not ns or seq <= 0:
            return
        pending = getattr(self, "_pending_p2p_pull_upper", None)
        if pending is None:
            pending = {}
            self._pending_p2p_pull_upper = pending
        previous = int(pending.get(ns, 0) or 0)
        if seq > previous:
            pending[ns] = seq
        self._log.debug(
            "client",
            "P2P pending pull upper recorded: ns=%s seq=%d previous=%d contiguous=%d",
            ns, seq, previous, self._seq_tracker.get_contiguous_seq(ns),
        )

    def _schedule_pending_p2p_pull_if_needed(self, ns: str, *, reason: str) -> bool:
        if not ns:
            return False
        pending = getattr(self, "_pending_p2p_pull_upper", None)
        if not pending:
            return False
        upper_seq = int(pending.get(ns, 0) or 0)
        if upper_seq <= 0:
            pending.pop(ns, None)
            return False
        contig = self._seq_tracker.get_contiguous_seq(ns)
        if upper_seq <= contig:
            pending.pop(ns, None)
            self._log.debug(
                "client",
                "P2P pending pull upper already covered: ns=%s upper_seq=%d contiguous=%d reason=%s",
                ns, upper_seq, contig, reason,
            )
            return False
        if self._state != "connected" or self._closing:
            self._log.debug(
                "client",
                "P2P pending pull postponed: ns=%s upper_seq=%d contiguous=%d state=%s closing=%s reason=%s",
                ns, upper_seq, contig, self._state, self._closing, reason,
            )
            return False
        dedup_key = f"p2p_pull:{ns}"
        if dedup_key in self._gap_fill_done:
            return False
        pending.pop(ns, None)
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        self._log.info(
            "client",
            "P2P pending push follow-up pull scheduled: ns=%s upper_seq=%d contiguous=%d reason=%s",
            ns, upper_seq, contig, reason,
        )
        loop.create_task(self._fill_p2p_gap())
        return True

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
        if "device_id" not in result:
            result["device_id"] = self._device_id
        if self._slot_id and not str(result.get("slot_id") or "").strip():
            result["slot_id"] = self._slot_id
        return result

    def _normalize_published_message_payload(self, event: str, payload: Any) -> Any:
        if not self._is_instance_scoped_message_event(event):
            return payload
        return self._attach_current_instance_context(payload)

    @staticmethod
    def _debug_json_default(value: Any) -> Any:
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            return {
                "_type": "bytes",
                "len": len(raw),
                "base64": base64.b64encode(raw).decode("ascii"),
            }
        return str(value)

    @classmethod
    def _debug_json(cls, value: Any) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=cls._debug_json_default)
        except Exception:
            return str(value)

    @staticmethod
    def _message_payload_for_debug(message: Any) -> Any:
        if not isinstance(message, dict):
            return message
        if "payload" in message:
            return message.get("payload")
        if "content" in message:
            return message.get("content")
        if "envelope_json" in message:
            raw = message.get("envelope_json")
            if isinstance(raw, str):
                try:
                    return json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    return raw
            return raw
        legacy = message.get("legacy_v1")
        if isinstance(legacy, dict):
            if "payload" in legacy:
                return legacy.get("payload")
            if "content" in legacy:
                return legacy.get("content")
        return None

    @staticmethod
    def _message_envelope_fields_for_debug(message: Any) -> Any:
        if not isinstance(message, dict):
            return {"value_type": type(message).__name__}
        keys = (
            "message_id", "id", "from", "from_aid", "sender_aid", "to", "to_aid",
            "group_id", "seq", "msg_seq", "type", "version", "timestamp", "t_server",
            "device_id", "slot_id", "encrypted", "dispatch_mode", "dispatch",
            "e2ee", "headers", "protected_headers", "context", "status",
        )
        return {key: message[key] for key in keys if key in message}

    def _log_message_debug(
        self,
        stage: str,
        source: str,
        event: str,
        message: Any,
        *,
        payload_override: Any = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "stage": stage,
            "source": source,
            "event": event,
            "envelope": self._message_envelope_fields_for_debug(message),
            "payload": payload_override if payload_override is not None else self._message_payload_for_debug(message),
        }
        if extra:
            record["extra"] = extra
        self._log.debug("client", "message.debug %s", self._debug_json(record))

    def _log_app_message_publish(self, event: str, payload: Any, source: str) -> None:
        if event not in ("message.received", "group.message_created"):
            return
        self._log_message_debug("publish", source, event, payload)

    async def _publish_app_event(self, event: str, payload: Any, *, source: str = "direct") -> None:
        if event in ("message.received", "group.message_created") and isinstance(payload, dict):
            self._maybe_append_echo_trace_receive(payload)
            self._log_app_message_publish(event, payload, source)
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
        if "device_id" in message:
            target_device_id = str(message.get("device_id") or "").strip()
            if target_device_id != self._device_id:
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
                self._log.debug("client", "publish ordered drain skipped duplicate: ns=%s seq=%d event=%s", ns, seq, event)
                continue
            await self._publish_app_event(event, payload, source="ordered-drain")
            self._mark_published_seq(ns, seq)
            self._log.debug("client", "publish ordered drain delivered: ns=%s seq=%d event=%s", ns, seq, event)
        if not pending:
            self._pending_ordered().pop(ns, None)

    async def _publish_ordered_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        """按 contiguous_seq 对应用层事件做有序放行。

        返回 True 表示本次调用实际发布了 payload；False 表示已挂起或已去重。
        """
        try:
            seq_i = int(seq)
        except (TypeError, ValueError):
            self._log.debug("client", "publish ordered direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq)
            await self._publish_app_event(event, payload, source="ordered")
            return True
        if seq_i <= 0:
            self._log.debug("client", "publish ordered direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq_i)
            await self._publish_app_event(event, payload, source="ordered")
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
        await self._publish_app_event(event, payload, source="ordered")
        self._mark_published_seq(ns, seq_i)
        self._log.debug("client", "publish ordered delivered: event=%s ns=%s seq=%d", event, ns, seq_i)
        await self._drain_ordered_messages(ns)
        return True

    async def _publish_pulled_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        """发布 pull 批中的消息，只按 namespace+seq 去重，不受批内部空洞阻塞。"""
        try:
            seq_i = int(seq)
        except (TypeError, ValueError):
            self._log.debug("client", "publish pulled direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq)
            await self._publish_app_event(event, payload, source="pull")
            return True
        if seq_i <= 0 or not ns:
            self._log.debug("client", "publish pulled direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq_i)
            await self._publish_app_event(event, payload, source="pull")
            return True
        if self._is_published_seq(ns, seq_i):
            self._log.debug("client", "publish pulled skipped duplicate: event=%s ns=%s seq=%d", event, ns, seq_i)
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
        await self._publish_app_event(event, payload, source="pull")
        self._mark_published_seq(ns, seq_i)
        self._log.debug("client", "publish pulled delivered: event=%s ns=%s seq=%d", event, ns, seq_i)
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

    def _v2_pending_sender_ik_message_key(self, msg: dict[str, Any], group_id: str) -> str:
        message_id = str(msg.get("message_id") or "").strip()
        seq = str(msg.get("seq") or "").strip()
        prefix = f"group:{group_id}" if group_id else f"p2p:{self._aid or ''}"
        return f"{prefix}:{message_id or seq or id(msg)}"

    def _v2_pending_sender_ik_fetch_key(self, from_aid: str, sender_device_id: str, group_id: str) -> str:
        return f"{from_aid}#{sender_device_id}#{group_id or ''}"

    async def _v2_sender_pub_der_from_cache_or_cert(self, from_aid: str, sender_device_id: str) -> bytes | None:
        """只查本地 IK 缓存和独立 PKI HTTP 证书，不在解密栈里调用 bootstrap RPC。"""
        if not self._v2_session or not from_aid:
            return None
        sender_pub_der = self._v2_session.get_peer_ik(from_aid, sender_device_id)
        if sender_pub_der:
            return sender_pub_der
        try:
            cert_pem = await asyncio.wait_for(self._fetch_peer_cert(from_aid), timeout=3.0)
            if not cert_pem:
                return None
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization as _ser
            cert = x509.load_pem_x509_certificate(cert_pem)
            sender_pub_der = cert.public_key().public_bytes(
                encoding=_ser.Encoding.DER,
                format=_ser.PublicFormat.SubjectPublicKeyInfo,
            )
            # AID 证书公钥是 IK；同一 AID 多设备共享该 IK，按当前 device 精确缓存。
            self._v2_session.cache_peer_ik(from_aid, sender_device_id, sender_pub_der)
            self._log.debug("client", "V2 decrypt: sender IK fallback from PKI cert for %s", from_aid)
            return sender_pub_der
        except Exception as exc:
            self._log.warn("client", "V2 decrypt: PKI cert sender IK fallback failed for %s: %s", from_aid, exc)
            return None

    def _v2_cache_peer_ik_from_device(self, dev: Any, fallback_aid: str = "") -> None:
        if not self._v2_session or not isinstance(dev, dict):
            return
        has_dev_id, dev_id = _v2_device_id_from_device(dev)
        ik_b64 = str(dev.get("ik_pk") or "").strip()
        aid = str(dev.get("aid") or fallback_aid or "").strip()
        if not has_dev_id or not ik_b64 or not aid:
            return
        try:
            ik_der = base64.b64decode(ik_b64)
            self._v2_session.cache_peer_ik(aid, dev_id, ik_der)
        except Exception as exc:
            self._log.debug("client", "V2 sender IK cache from bootstrap skipped aid=%s dev=%s: %s", aid, dev_id, exc)

    async def _v2_cache_peer_ik_from_device_or_cert(self, dev: Any, fallback_aid: str = "") -> None:
        if not self._v2_session or not isinstance(dev, dict):
            return
        has_dev_id, dev_id = _v2_device_id_from_device(dev)
        aid = str(dev.get("aid") or fallback_aid or "").strip()
        if not has_dev_id or not aid:
            return
        ik_b64 = str(dev.get("ik_pk") or "").strip()
        try:
            if ik_b64:
                ik_der = base64.b64decode(ik_b64)
                source = "bootstrap"
            else:
                ik_der = await self._v2_trusted_ik_pub_der(aid)
                source = "cert"
            self._v2_session.cache_peer_ik(aid, dev_id, ik_der)
            self._log.debug("client", "V2 peer IK cached from %s: aid=%s device=%s", source, aid, dev_id or "<aid>")
        except Exception as exc:
            self._log.debug("client", "V2 peer IK cache skipped aid=%s dev=%s: %s", aid, dev_id, exc)

    async def _v2_observe_bootstrap_material(self, method: str, params: dict[str, Any], result: dict[str, Any]) -> None:
        if method == "message.v2.bootstrap":
            peer_aid = str(params.get("peer_aid") or "").strip()
            if peer_aid:
                await self._prime_bootstrap_peer_certs(result, peer_aid)
            for dev in result.get("peer_devices", []) or []:
                await self._v2_cache_peer_ik_from_device_or_cert(dev, peer_aid)
            for dev in result.get("self_devices", []) or []:
                await self._v2_cache_peer_ik_from_device_or_cert(dev, self._aid or "")
            for dev in result.get("audit_recipients", []) or []:
                await self._v2_cache_peer_ik_from_device_or_cert(dev)
            return

        if method == "group.v2.bootstrap":
            for dev in result.get("devices", []) or []:
                await self._v2_cache_peer_ik_from_device_or_cert(dev)
            for dev in result.get("audit_recipients", []) or []:
                await self._v2_cache_peer_ik_from_device_or_cert(dev)

    def _schedule_v2_sender_ik_pending(
        self,
        *,
        msg: dict[str, Any],
        envelope: dict[str, Any],
        from_aid: str,
        sender_device_id: str,
        group_id: str,
    ) -> None:
        if not from_aid:
            return
        message_key = self._v2_pending_sender_ik_message_key(msg, group_id)
        self._v2_sender_ik_pending[message_key] = {
            "msg": dict(msg),
            "from_aid": from_aid,
            "sender_device_id": sender_device_id,
            "group_id": group_id,
            "created_at": time.time(),
        }
        self._log.debug(
            "client",
            "V2 decrypt pending sender IK: key=%s from=%s device=%s group=%s pending=%d",
            message_key, from_aid, sender_device_id or "-", group_id or "<p2p>", len(self._v2_sender_ik_pending),
        )
        fetch_key = self._v2_pending_sender_ik_fetch_key(from_aid, sender_device_id, group_id)
        if fetch_key in self._v2_sender_ik_fetching:
            return
        self._v2_sender_ik_fetching.add(fetch_key)
        loop = self._loop or asyncio.get_running_loop()
        loop.create_task(self._resolve_v2_sender_ik_pending(from_aid, sender_device_id, group_id, fetch_key))

    def _schedule_v2_sender_ik_fetch(self, from_aid: str, sender_device_id: str, group_id: str) -> None:
        if not from_aid:
            return
        fetch_key = self._v2_pending_sender_ik_fetch_key(from_aid, sender_device_id, group_id)
        if fetch_key in self._v2_sender_ik_fetching:
            return
        self._v2_sender_ik_fetching.add(fetch_key)
        loop = self._loop or asyncio.get_running_loop()
        loop.create_task(self._resolve_v2_sender_ik_pending(from_aid, sender_device_id, group_id, fetch_key))

    async def _resolve_v2_sender_ik_pending(
        self,
        from_aid: str,
        sender_device_id: str,
        group_id: str,
        fetch_key: str,
    ) -> None:
        try:
            if self._v2_session and from_aid:
                try:
                    bs = await self.call("message.v2.bootstrap", {
                        "peer_aid": from_aid,
                        "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                    })
                    if isinstance(bs, dict):
                        for dev in bs.get("peer_devices", []) or []:
                            await self._v2_cache_peer_ik_from_device_or_cert(dev, from_aid)
                except Exception as exc:
                    self._log.warn("client", "V2 sender IK pending bootstrap failed peer=%s: %s", from_aid, exc)
                if group_id:
                    try:
                        gbs = await self.call("group.v2.bootstrap", {
                            "group_id": group_id,
                            "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                        })
                        if isinstance(gbs, dict):
                            for dev in gbs.get("devices", []) or []:
                                await self._v2_cache_peer_ik_from_device_or_cert(dev)
                            for dev in gbs.get("audit_recipients", []) or []:
                                await self._v2_cache_peer_ik_from_device_or_cert(dev)
                    except Exception as exc:
                        self._log.warn("client", "V2 sender IK pending group bootstrap failed group=%s: %s", group_id, exc)
                if not self._v2_session.get_peer_ik(from_aid, sender_device_id):
                    await self._v2_sender_pub_der_from_cache_or_cert(from_aid, sender_device_id)

            pending_items = [
                (key, entry)
                for key, entry in list(self._v2_sender_ik_pending.items())
                if entry.get("from_aid") == from_aid
                and entry.get("sender_device_id") == sender_device_id
                and entry.get("group_id", "") == group_id
            ]
            for key, entry in pending_items:
                msg = entry.get("msg")
                if not isinstance(msg, dict):
                    self._v2_sender_ik_pending.pop(key, None)
                    continue
                try:
                    plaintext = await self._decrypt_v2_message(msg, allow_pending=False)
                except Exception as exc:
                    self._log.warn("client", "V2 sender IK pending retry raised: key=%s err=%s", key, exc)
                    self._v2_sender_ik_pending.pop(key, None)
                    continue
                if plaintext is None:
                    self._log.debug("client", "V2 sender IK pending retry failed: key=%s", key)
                    self._v2_sender_ik_pending.pop(key, None)
                    continue
                self._v2_sender_ik_pending.pop(key, None)
                seq = int(msg.get("seq") or 0)
                if group_id:
                    plaintext["group_id"] = group_id
                    await self._publish_pulled_message("group.message_created", f"group:{group_id}", seq, plaintext)
                else:
                    await self._publish_pulled_message("message.received", f"p2p:{self._aid}", seq, plaintext)
                self._log.debug("client", "V2 sender IK pending retry delivered: key=%s", key)
        finally:
            self._v2_sender_ik_fetching.discard(fetch_key)

    @staticmethod
    def _cert_cache_key(aid: str, cert_fingerprint: str | None = None) -> str:
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        return aid if not normalized_fp else f"{aid}#{normalized_fp}"

    @staticmethod
    def _normalize_bootstrap_ca_chain(material: Any) -> list[str]:
        if not isinstance(material, dict):
            return []
        raw_chain = (
            material.get("ca_chain")
            or material.get("ca_chain_pems")
            or material.get("cert_chain")
            or material.get("chain")
            or []
        )
        if not isinstance(raw_chain, list):
            return []
        result: list[str] = []
        for item in raw_chain:
            cert_type = ""
            if isinstance(item, dict):
                pem = str(item.get("cert_pem") or item.get("cert") or "").strip()
                cert_type = str(item.get("cert_type") or "").strip().lower()
                if cert_type == "agent":
                    continue
            else:
                pem = str(item or "").strip()
            if not pem:
                continue
            if not cert_type:
                try:
                    from cryptography import x509 as _x509
                    cert_obj = _x509.load_pem_x509_certificate(pem.encode("utf-8"))
                    try:
                        basic_constraints = cert_obj.extensions.get_extension_for_class(
                            _x509.BasicConstraints
                        ).value
                        if not basic_constraints.ca:
                            continue
                    except _x509.ExtensionNotFound:
                        continue
                except Exception:
                    continue
            result.append(pem)
        return result

    async def _validate_and_cache_peer_cert(
        self,
        aid: str,
        cert_pem: str | bytes,
        cert_fingerprint: str | None = None,
        *,
        ca_chain_pems: list[str] | None = None,
        source: str = "fetch",
    ) -> bytes:
        cert_text = cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else str(cert_pem or "")
        if not cert_text.strip():
            raise ValidationError(f"empty peer cert material for {aid}")
        cert_bytes = cert_text.encode("utf-8")

        peer_gateway_url = await self._discover_gateway_for_peer_aid(aid)
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _hashes
        cert_obj = _x509.load_pem_x509_certificate(cert_bytes)

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

        if ca_chain_pems:
            try:
                self._auth.cache_gateway_ca_chain(peer_gateway_url, ca_chain_pems, chain_aid=aid)
            except Exception as exc:
                self._log.debug(
                    "client",
                    "bootstrap CA chain cache skipped: peer=%s source=%s err=%s",
                    aid,
                    source,
                    exc,
                )

        try:
            await self._auth.verify_peer_certificate(peer_gateway_url, cert_obj, aid)
        except Exception as exc:
            if ca_chain_pems:
                discard_chain = getattr(self._auth, "discard_gateway_ca_chain", None)
                if callable(discard_chain):
                    discard_chain(peer_gateway_url, chain_aid=aid)
            _debug_group_e2ee(
                "peer_cert_verify_failed",
                aid=self._aid or "-",
                peer=aid,
                fp=expected_fp or "-",
                source=source,
                error=type(exc).__name__,
            )
            raise ValidationError(f"peer cert verification failed for {aid}: {exc}")

        now = time.time()
        cached = _CachedPeerCert(
            cert_bytes=cert_bytes,
            validated_at=now,
            refresh_after=now + _PEER_CERT_CACHE_TTL,
        )
        bare_key = self._cert_cache_key(aid, None)
        self._cert_cache[bare_key] = cached
        if expected_fp:
            self._cert_cache[self._cert_cache_key(aid, expected_fp)] = cached
        _debug_group_e2ee(
            "peer_cert_cached",
            aid=self._aid or "-",
            peer=aid,
            fp=expected_fp or "-",
            source=source,
            cache_key=bare_key,
        )
        try:
            self._keystore.save_cert(
                aid,
                cert_text,
                cert_fingerprint=cert_fingerprint,
                make_active=False,
            )
        except TypeError:
            pass
        except Exception as exc:
            _debug_group_e2ee(
                "peer_cert_save_failed",
                aid=self._aid or "-",
                peer=aid,
                fp=expected_fp or "-",
                source=source,
                error=type(exc).__name__,
            )
            self._log.error("client", "failed to write peer cert to keystore (aid=%s, fp=%s): %s", aid, cert_fingerprint or "", exc)
        return cert_bytes

    async def _prime_bootstrap_peer_certs(self, bootstrap: dict[str, Any], peer_aid: str) -> None:
        materials = bootstrap.get("certs") if isinstance(bootstrap, dict) else None
        if not isinstance(materials, dict):
            return
        expected_aids: set[str] = set()
        peer_aid = str(peer_aid or "").strip()
        if peer_aid:
            expected_aids.add(peer_aid)
        for dev in bootstrap.get("audit_recipients", []) or []:
            if isinstance(dev, dict):
                aid = str(dev.get("aid") or "").strip()
                if aid:
                    expected_aids.add(aid)

        for aid in sorted(expected_aids):
            if self._aid and aid == self._aid:
                continue
            material = materials.get(aid)
            if not isinstance(material, dict):
                continue
            cert_pem = material.get("cert_pem") or material.get("cert")
            if not cert_pem:
                continue
            cert_fingerprint = (
                material.get("cert_fingerprint")
                or material.get("fingerprint")
                or material.get("fp")
            )
            ca_chain_pems = self._normalize_bootstrap_ca_chain(material)
            try:
                await self._validate_and_cache_peer_cert(
                    aid,
                    cert_pem,
                    str(cert_fingerprint or "").strip() or None,
                    ca_chain_pems=ca_chain_pems,
                    source="bootstrap",
                )
            except Exception as exc:
                self._log.debug(
                    "client",
                    "bootstrap peer cert material ignored: peer=%s err=%s",
                    aid,
                    exc,
                )

    async def _fetch_peer_cert(self, aid: str, cert_fingerprint: str | None = None) -> bytes:
        """获取对方证书（带缓存 + 完整 PKI 验证：链 + CRL + OCSP + AID 绑定）

        跨域时按 peer AID 的 issuer 做 Gateway discovery；本域复用当前已发现 Gateway。
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
        peer_gateway_url = await self._discover_gateway_for_peer_aid(aid)
        cert_url = self._build_cert_url(peer_gateway_url, aid, cert_fingerprint)
        _debug_group_e2ee(
            "peer_cert_fetch_http",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            url=cert_url,
        )
        # PY-017: 显式设置 HTTP 超时，避免 aiohttp 默认 300s 阻塞
        try:
            cert_pem = await self._net.http_get_text(cert_url, timeout=10.0)
        except Exception as exc:
            raise ConnectionError(f"failed to fetch cert from {cert_url}: {exc}", retryable=True) from exc
        _debug_group_e2ee(
            "peer_cert_fetch_http_result",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            bytes=len(cert_pem),
        )
        cert_bytes = await self._validate_and_cache_peer_cert(
            aid,
            cert_pem,
            cert_fingerprint,
            source="fetch",
        )
        self._log.debug("client", "_fetch_peer_cert exit: elapsed=%.3fs peer=%s fp=%s", time.time() - _t_start, aid, normalized_fp or "-")
        return cert_bytes

    async def _v2_trusted_ik_pub_der(self, aid: str) -> bytes:
        """返回经信任锚确认的 IK 公钥 DER；本 AID 用本地身份，其它 AID 用已 PKI 校验证书。"""
        normalized_aid = str(aid or "").strip()
        if not normalized_aid:
            raise E2EEError("spk_aid_missing")
        if self._aid and normalized_aid == self._aid:
            if not self._v2_session:
                raise E2EEError("V2 session not initialized")
            return self._v2_session.ik_pub_der

        cert_pem = await self._fetch_peer_cert(normalized_aid)
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import serialization as _ser

        cert_obj = _x509.load_pem_x509_certificate(
            cert_pem if isinstance(cert_pem, bytes) else str(cert_pem).encode("utf-8")
        )
        return cert_obj.public_key().public_bytes(
            encoding=_ser.Encoding.DER,
            format=_ser.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def _v2_spk_timestamp_text(value: Any, *, aid: str, device_id: str, spk_id: str) -> str:
        if value is None or value == "":
            raise E2EEError(f"spk_timestamp_missing: aid={aid} device_id={device_id} spk_id={spk_id}")
        if isinstance(value, bool):
            raise E2EEError(f"spk_timestamp_invalid: aid={aid} device_id={device_id} spk_id={spk_id}")
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            if not value.is_integer():
                raise E2EEError(f"spk_timestamp_invalid: aid={aid} device_id={device_id} spk_id={spk_id}")
            return str(int(value))
        text = str(value).strip()
        if not text or not text.isdigit():
            raise E2EEError(f"spk_timestamp_invalid: aid={aid} device_id={device_id} spk_id={spk_id}")
        return str(int(text))

    async def _v2_verify_spk_device(
        self,
        dev: dict[str, Any],
        *,
        aid: str,
        device_id: str,
        ik_pk_der: bytes,
        spk_pk_der: bytes | None,
        key_source: str,
    ) -> None:
        """发送端校验 bootstrap 中的 SPK 确实由 AID 证书 IK 背书。"""
        if not self._v2_session:
            raise E2EEError("V2 session not initialized")
        spk_id = str(dev.get("spk_id") or "").strip()
        if not spk_id:
            return
        if key_source not in {"peer_device_prekey", "group_device_prekey"}:
            raise E2EEError(f"spk_key_source_invalid: aid={aid} device_id={device_id} spk_id={spk_id} key_source={key_source}")
        if not spk_pk_der:
            raise E2EEError(f"spk_public_key_missing: aid={aid} device_id={device_id} spk_id={spk_id}")

        expected_spk_id = "sha256:" + hashlib.sha256(spk_pk_der).hexdigest()[:16]
        if spk_id != expected_spk_id:
            raise E2EEError(f"spk_id_mismatch: aid={aid} device_id={device_id} spk_id={spk_id} expected={expected_spk_id}")

        trusted_ik = await self._v2_trusted_ik_pub_der(aid)
        if trusted_ik != ik_pk_der:
            raise E2EEError(f"spk_ik_mismatch: aid={aid} device_id={device_id} spk_id={spk_id}")
        if spk_pk_der == trusted_ik:
            self._v2_session.mark_peer_spk_verified(aid, device_id, spk_id)
            return

        sig_b64 = str(dev.get("spk_signature") or "").strip()
        if not sig_b64:
            raise E2EEError(f"spk_signature_missing: aid={aid} device_id={device_id} spk_id={spk_id}")
        try:
            signature = base64.b64decode(sig_b64, validate=True)
        except Exception as exc:
            raise E2EEError(f"spk_signature_invalid_base64: aid={aid} device_id={device_id} spk_id={spk_id}") from exc
        ts_text = self._v2_spk_timestamp_text(dev.get("spk_timestamp"), aid=aid, device_id=device_id, spk_id=spk_id)
        sign_data = spk_pk_der + spk_id.encode("utf-8") + ts_text.encode("utf-8")
        if not ecdsa_verify_raw(trusted_ik, signature, sign_data):
            raise E2EEError(f"spk_signature_invalid: aid={aid} device_id={device_id} spk_id={spk_id}")
        self._v2_session.mark_peer_spk_verified(aid, device_id, spk_id)

    async def _v2_build_target_from_device(
        self,
        dev: dict[str, Any],
        *,
        aid: str,
        device_id: str,
        role: str,
        default_key_source: str,
    ) -> dict[str, Any] | None:
        aid = str(aid or "").strip()
        has_device_id, normalized_device_id = _v2_device_id_from_device(dev)
        device_id = normalized_device_id if has_device_id else str(device_id or "").strip()
        ik_b64 = str(dev.get("ik_pk") or "").strip()
        if not aid or not has_device_id:
            return None
        if ik_b64:
            ik_pk_der = base64.b64decode(ik_b64)
        else:
            ik_pk_der = await self._v2_trusted_ik_pub_der(aid)
            self._log.debug("client", "V2 target IK loaded from cert: aid=%s device=%s role=%s", aid, device_id or "<aid>", role)
        spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
        key_source = str(dev.get("key_source") or default_key_source).strip() or default_key_source
        await self._v2_verify_spk_device(
            dev,
            aid=aid,
            device_id=device_id,
            ik_pk_der=ik_pk_der,
            spk_pk_der=spk_pk_der,
            key_source=key_source,
        )
        if self._v2_session:
            self._v2_session.cache_peer_ik(aid, device_id, ik_pk_der)
        return {
            "aid": aid,
            "device_id": device_id,
            "role": role,
            "key_source": key_source,
            "ik_pk_der": ik_pk_der,
            "spk_pk_der": spk_pk_der,
            "spk_id": str(dev.get("spk_id") or "").strip(),
        }

    @staticmethod
    def _list_contains_token(value: Any, token: str) -> bool:
        if not isinstance(value, list):
            return False
        return token in value

    def _client_uses_v2_p2p(self) -> bool:
        """Python SDK 是 V2-only 客户端，P2P 不做 V1 降级。"""
        return True

    def _client_uses_v2_group(self) -> bool:
        """Python SDK 是 V2-only 客户端，Group 不做 V1 降级。"""
        return True

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

    # ── 内部：连接 ────────────────────────────────────────

    async def _connect_once(self, params: dict[str, Any], *, allow_reauth: bool) -> None:
        _t_start = time.time()
        gateway_url = self._resolve_gateway(params)
        self._gateway_url = gateway_url
        self._loop = asyncio.get_running_loop()
        self._slot_id = normalize_slot_id(params.get("slot_id"))
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
            # 连接成功：刷新 DNS 缓存
            net = getattr(self, "_net", None)
            if net is not None:
                try:
                    net._refresh_dns_cache_after_success(gateway_url)
                except Exception as exc:
                    self._log.debug("client", "DNS cache refresh skipped: %s", exc)
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
            self._state = ConnectionState.READY.value
            self._connected_at = time.time()
            self._last_error = None
            self._last_error_code = None
            self._next_retry_at = None
            self._log.debug("client", "auth complete, state changed to ready: gateway=%s aid=%s", gateway_url, self._aid or "-")
            await self._dispatcher.publish("state_change", {"state": self._state, "gateway": gateway_url})

            # auth 阶段 aid 可能被 identity 覆盖（上方 self._aid = identity.get(...)）；
            # 若 context 发生变化，重新 refresh + restore，保持 tracker 与真实身份一致
            if self._seq_tracker_context != self._current_seq_tracker_context():
                self._refresh_seq_tracking_context()
                self._restore_seq_tracker_state()

            self._start_background_tasks()

            session_options = getattr(self, "_session_options", {}) or {}
            background_sync = bool(params.get("background_sync", session_options.get("background_sync", True)))

            # connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压。
            # CLI 这类一次性短命令可通过 background_sync=False 跳过，避免无关 RPC 增加延迟。
            if background_sync:
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
            if background_sync and getattr(self, "_v2_session", None):
                loop = self._loop or asyncio.get_running_loop()
                loop.create_task(self._v2_auto_confirm_pending_proposals())
            self._log.debug("client", "_connect_once exit: elapsed=%.3fs gateway=%s aid=%s", time.time() - _t_start, gateway_url, self._aid or "-")
        except Exception as exc:
            self._log.debug("client", "_connect_once exit (error): elapsed=%.3fs gateway=%s err=%s", time.time() - _t_start, gateway_url, exc)
            raise

    def _resolve_gateway(self, params: dict[str, Any]) -> str:
        gateways = self._resolve_gateways(params)
        return gateways[0]

    def _resolve_gateways(self, params: dict[str, Any]) -> list[str]:
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
        gateway = params.get("gateway") or params.get("gateways")
        if isinstance(gateway, list):
            urls = [str(g) for g in gateway if g]
            if urls:
                return urls
        if isinstance(gateway, str) and gateway:
            return [gateway]
        raise StateError("missing gateway in connect params")

    @staticmethod
    def _is_internal_only_method(method: str) -> bool:
        return method in _INTERNAL_ONLY_METHODS

    # ── 内部：后台任务 ────────────────────────────────────

    def _start_background_tasks(self) -> None:
        # 短连接生命周期短，禁用心跳与 token 刷新（不接收推送、不需要长期会话维护）
        if not self._session_options.get("background_sync", True):
            return
        if self._session_options.get("connection_kind") != "short":
            self._start_heartbeat_task()
            self._start_token_refresh_task()

    async def _stop_background_tasks(self) -> None:
        current_task = asyncio.current_task()
        for attr in ("_heartbeat_task", "_token_refresh_task",
                      "_cache_cleanup_task", "_online_unread_hint_task"):
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
        if hasattr(self, "_online_unread_hint_queue"):
            self._online_unread_hint_queue.clear()

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
                gateway_url = self.gateway_url
                if self._public_state != ConnectionState.READY or not gateway_url:
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
                    identity = await self._auth.refresh_cached_tokens(gateway_url, identity)
                    # 防竞态：刷新期间可能已断线/重连，状态不再是 READY 说明 transport 已变，丢弃结果
                    if self._public_state != ConnectionState.READY:
                        self._log.debug("client", "token refresh succeeded but state changed, discarding result")
                        return
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
                        # 不直接调用 _handle_transport_disconnect（会 cancel 自身导致递归），
                        # 而是关闭 transport 让 on_disconnect 回调自然触发重连。
                        if self._transport and not getattr(self._transport, "_closed", True):
                            await self._transport.close()
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
        if not str(to_aid or "").strip():
            raise ValidationError("message.send requires a non-empty 'to' (recipient AID)")
        if _is_group_service_aid(to_aid):
            raise ValidationError("message.send receiver cannot be group.{issuer}; use group.send instead")

    def _normalize_outbound_message_payload(self, params: dict[str, Any], *, method: str = "") -> None:
        if "payload" not in params and "content" in params:
            params["payload"] = params.pop("content")
        payload = params.get("payload")
        if isinstance(payload, dict) and "type" not in payload and isinstance(payload.get("text"), str):
            params["payload"] = {"type": "text", **payload}

    def _is_echo_message_params(self, params: dict[str, Any]) -> bool:
        if params.get("encrypted") or params.get("encrypt"):
            return False
        payload = params.get("payload")
        if not isinstance(payload, dict):
            return False
        text = payload.get("text")
        if not isinstance(text, str) or len(text) > 4096:
            return False
        return "echo" in text.split("\n", 1)[0].lower()

    def _should_skip_client_signature(self, method: str, params: dict[str, Any]) -> bool:
        # echo 是链路测试消息，中间节点会追加 trace 行，不能参与客户端操作签名。
        return method in {"message.send", "group.send"} and self._is_echo_message_params(params)

    def _should_skip_event_signature(self, event: dict[str, Any]) -> bool:
        # echo 是链路测试消息，服务端/SDK 会追加 trace 行；误带签名时也不验签。
        return self._is_echo_message_params(event)

    def _maybe_append_echo_trace_send(self, params: dict[str, Any]) -> None:
        """明文 echo 消息发送时追加 SDK.send trace"""
        payload = params.get("payload")
        if not isinstance(payload, dict):
            self._log.debug("client", "echo_trace_send skip: payload not dict, type=%s", type(payload).__name__)
            return
        text = payload.get("text")
        if not isinstance(text, str) or len(text) > 4096:
            self._log.debug("client", "echo_trace_send skip: text invalid, type=%s len=%s", type(text).__name__, len(text) if isinstance(text, str) else "?")
            return
        first_line = text.split("\n", 1)[0].lower()
        if "echo" not in first_line:
            self._log.debug("client", "echo_trace_send skip: no 'echo' in first line=%r", first_line[:80])
            return
        import datetime
        now = datetime.datetime.now()
        ts = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"
        uptime = int(time.time() - getattr(self, "_connected_at", time.time()))
        trace = f"{ts} [AUN-SDK.send] aid={self._aid or '-'} conn_uptime={uptime}s"
        params["payload"] = {**payload, "text": text + "\n" + trace}
        self._log.debug("client", "echo_trace_send appended: %s", trace)

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
        slot_id = normalize_slot_id(params.get("slot_id", self._slot_id))
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
        if hasattr(self, "_pending_p2p_pull_upper"):
            self._pending_p2p_pull_upper.clear()
        if hasattr(self, "_v2_sender_ik_pending"):
            self._v2_sender_ik_pending.clear()
        if hasattr(self, "_v2_sender_ik_fetching"):
            self._v2_sender_ik_fetching.clear()
        if hasattr(self, "_group_synced"):
            self._group_synced.clear()
        if hasattr(self, "_online_unread_hint_queue"):
            self._online_unread_hint_queue.clear()

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
        if hasattr(self, "_pending_p2p_pull_upper"):
            self._pending_p2p_pull_upper.clear()
        if hasattr(self, "_v2_sender_ik_pending"):
            self._v2_sender_ik_pending.clear()
        if hasattr(self, "_v2_sender_ik_fetching"):
            self._v2_sender_ik_fetching.clear()
        if hasattr(self, "_group_synced"):
            self._group_synced.clear()
        if hasattr(self, "_online_unread_hint_queue"):
            self._online_unread_hint_queue.clear()
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

    def _persist_repaired_seq(self, ns: str) -> None:
        """持久化倒退修复后的 seq；修复到 0 时删除旧落盘游标。"""
        if not self._aid:
            return
        seq = self._seq_tracker.get_contiguous_seq(ns)
        if seq > 0:
            self._persist_seq(ns)
            return
        deleter = getattr(self._keystore, "delete_seq", None)
        if callable(deleter):
            try:
                deleter(self._aid, self._device_id, self._slot_id, ns)
            except Exception as exc:
                self._log.debug("client", "delete repaired seq failed: ns=%s err=%s", ns, exc)

    def _repair_push_contiguous_bound(self, ns: str, push_seq: int, *, has_payload: bool, label: str) -> int:
        """按 push 类型修复异常过高的 contiguous_seq，并返回修复后的值。"""
        if not ns or push_seq <= 0:
            return self._seq_tracker.get_contiguous_seq(ns) if ns else 0
        contig = self._seq_tracker.get_contiguous_seq(ns)
        should_repair = contig > push_seq
        if not should_repair:
            return contig
        repaired_to = max(0, push_seq - 1)
        self._seq_tracker.repair_contiguous_seq(ns, repaired_to)
        repaired = self._seq_tracker.get_contiguous_seq(ns)
        self._persist_repaired_seq(ns)
        self._log.warn(
            "client",
            "%s push repaired contiguous_seq: ns=%s payload=%s push_seq=%d contiguous=%d->%d",
            label, ns, has_payload, push_seq, contig, repaired,
        )
        return repaired

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
        # 断线时保存 SeqTracker 状态，防止进程崩溃后 seq 回退
        try:
            self._save_seq_tracker_state()
        except Exception as exc:
            self._log.debug("client", "failed to save SeqTracker on disconnect: %s", exc)
        if not bool(self._session_options["auto_reconnect"]):
            self._state = ConnectionState.STANDBY.value if self.has_identity else ConnectionState.NO_IDENTITY.value
            self._identity = None
            self._next_retry_at = None
            self._retry_attempt = 0
            self._last_error = error
            self._last_error_code = "transport_disconnected" if error else None
            await self._dispatcher.publish("state_change", {"state": self._state, "error": error})
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        # 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
        if self._server_kicked or (close_code is not None and close_code in self._NO_RECONNECT_CODES):
            self._state = ConnectionState.CONNECTION_FAILED.value
            self._last_error = error
            self._last_error_code = "server_kicked" if self._server_kicked else "no_reconnect_close_code"
            self._next_retry_at = None
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
            await self._dispatcher.publish("state_change", event_payload)
            return
        await self._stop_background_tasks()
        # 1006 = 网络异常断开（无 close frame），1000 = 正常关闭（客户端主动）
        # 其他 code = 服务端主动关闭
        server_initiated = close_code is not None and close_code not in (1000, 1006)
        self._reconnect_task = asyncio.create_task(self._reconnect_loop(server_initiated))

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
        self._retry_attempt = 0
        self._retry_max_attempts = max_attempts
        self._log.debug("client", "reconnect loop started: server_initiated=%s max_attempts=%s base_delay=%.1fs", server_initiated, max_attempts, base_delay)

        while not self._closing:
            attempt += 1
            self._retry_attempt = attempt
            sleep_delay = _reconnect_sleep_delay(delay, max_base_delay)
            self._next_retry_at = time.time() + sleep_delay
            self._state = ConnectionState.RETRY_BACKOFF.value
            await self._dispatcher.publish("state_change", {
                "state": self._state,
                "attempt": attempt,
                "next_retry_at": self._next_retry_at,
            })
            try:
                # 固定上限抖动：base=[1s, max_base]，delay=base+rand(0..max_base)。
                await self._reconnect_sleep(sleep_delay)
                if self._closing:
                    self._next_retry_at = None
                    self._reconnect_task = None
                    return
                self._next_retry_at = None
                self._state = ConnectionState.RECONNECTING.value
                await self._dispatcher.publish("state_change", {
                    "state": self._state,
                    "attempt": attempt,
                })
                if self._closing:
                    self._reconnect_task = None
                    return
                # 重连前先 GET /health 探测，不健康则跳过本轮
                gateway_url = self.gateway_url
                if gateway_url:
                    healthy = await self._discovery.check_health(gateway_url)
                    if self._closing:
                        self._reconnect_task = None
                        return
                    if not healthy:
                        self._log.debug("client", "reconnect health check failed, skipping this round: attempt=%d gateway=%s", attempt, gateway_url)
                        self._last_error = RuntimeError("gateway health check failed")
                        self._last_error_code = "gateway_unhealthy"
                        if max_attempts > 0 and attempt >= max_attempts:
                            self._state = ConnectionState.CONNECTION_FAILED.value
                            self._reconnect_task = None
                            await self._dispatcher.publish("state_change", {
                                "state": self._state,
                                "attempt": attempt,
                                "reason": "max_attempts_exhausted",
                            })
                            return
                        delay = min(delay * 2, max_base_delay)
                        continue
                await self._transport.close()
                if self._closing:
                    self._reconnect_task = None
                    return
                self._log.debug("client", "reconnect attempting _connect_once: attempt=%d", attempt)
                await self._invoke_reconnect_connect_once()
                if self._closing:
                    self._reconnect_task = None
                    return
                self._log.debug("client", "reconnect success: attempt=%d", attempt)
                if self._public_state != ConnectionState.READY:
                    self._state = ConnectionState.READY.value
                self._last_error = None
                self._last_error_code = None
                self._next_retry_at = None
                self._reconnect_task = None
                return
            except asyncio.CancelledError:
                self._next_retry_at = None
                self._reconnect_task = None
                raise
            except Exception as exc:
                retryable = self._should_retry_reconnect(exc)
                self._last_error = exc
                self._last_error_code = "reconnect_failed"
                self._log.warn("client", "reconnect failed: attempt=%d error=%s retryable=%s", attempt, exc, retryable)
                await self._dispatcher.publish("connection.error", {
                    "error": exc,
                    "attempt": attempt,
                })
                if not retryable or (max_attempts > 0 and attempt >= max_attempts):
                    self._state = ConnectionState.CONNECTION_FAILED.value
                    self._next_retry_at = None
                    self._reconnect_task = None
                    await self._dispatcher.publish("state_change", {
                        "state": self._state,
                        "error": exc,
                        "attempt": attempt,
                        "reason": "not_retryable" if not retryable else "max_attempts_exhausted",
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
        gateway = str(request.get("gateway") or self.gateway_url or "")
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
        request["slot_id"] = normalize_slot_id(request.get("slot_id", self._slot_id))
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
            "background_sync": bool(params.get("background_sync", _DEFAULT_SESSION_OPTIONS["background_sync"])),
        }
        if "auto_reconnect" in params:
            options["auto_reconnect"] = bool(params["auto_reconnect"])
        if "background_sync" in params:
            options["background_sync"] = bool(params["background_sync"])
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

    _V2_SIG_CACHE_TTL = 3600  # 验签结果缓存 1 小时
    _V2_SIG_CACHE_MAX = 16384

    async def _init_v2_session(self) -> None:
        """connect 成功后初始化 V2 session 并注册设备 SPK。IK = AID 长期密钥（无需独立注册）。"""
        if not self._aid:
            return
        identity = self._identity
        if not identity or not identity.get("private_key_pem"):
            # fallback：缓存的 identity 可能被 instance_state 污染，重新从 keystore 加载
            try:
                reloaded = self._keystore.load_identity(self._aid)
            except Exception:
                reloaded = None
            if reloaded and reloaded.get("private_key_pem"):
                self._identity = reloaded
                identity = reloaded
                self._log.warn("client", "V2 session init: identity cache was stale, reloaded from keystore")
                # 自愈：重新持久化 identity，清理 instance_state 中的脏数据
                try:
                    self._auth._persist_identity(reloaded)
                except Exception:
                    pass
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
        self._v2_bootstrap_cache: dict[str, tuple] = {}
        await self._v2_session.ensure_registered(self.call)
        self._log.debug("client", "V2 session initialized (IK=AID identity): aid=%s device=%s", self._aid, self._device_id)

    def _schedule_group_spk_registration(self, group_id: str, *, reason: str) -> None:
        group_id = str(group_id or "").strip()
        if not group_id or not self._v2_session:
            return
        inflight = getattr(self, "_group_spk_registration_inflight", None)
        if inflight is None:
            inflight = set()
            self._group_spk_registration_inflight = inflight
        if group_id in inflight:
            return
        inflight.add(group_id)
        async def _run() -> None:
            try:
                if self._state != "connected" or not self._v2_session:
                    return
                await self._v2_session.ensure_group_registered(group_id, self.call)
                self._log.debug("client", "group SPK registered: group=%s reason=%s", group_id, reason)
            except Exception as exc:
                self._log.debug("client", "group SPK registration failed (non-fatal): group=%s reason=%s err=%s", group_id, reason, exc)
            finally:
                inflight.discard(group_id)
        loop = self._loop or asyncio.get_running_loop()
        loop.create_task(_run())

    def _schedule_group_spk_rotation(self, group_id: str, *, reason: str) -> None:
        group_id = str(group_id or "").strip()
        if not group_id or not self._v2_session:
            return
        inflight = getattr(self, "_group_spk_rotation_inflight", None)
        if inflight is None:
            inflight = set()
            self._group_spk_rotation_inflight = inflight
        if group_id in inflight:
            return
        inflight.add(group_id)
        async def _run() -> None:
            try:
                if self._state != "connected" or not self._v2_session:
                    return
                await self._v2_session.rotate_group_spk(group_id, self.call)
                self._log.debug("client", "group SPK rotated: group=%s reason=%s", group_id, reason)
            except Exception as exc:
                self._log.debug("client", "group SPK rotation failed (non-fatal): group=%s reason=%s err=%s", group_id, reason, exc)
            finally:
                inflight.discard(group_id)
        loop = self._loop or asyncio.get_running_loop()
        loop.create_task(_run())

    def _schedule_group_spk_registration_after_peer_fallback(self, group_id: str) -> None:
        group_id = str(group_id or "").strip()
        registered = getattr(self, "_group_spk_peer_fallback_registered", None)
        if registered is None:
            registered = set()
            self._group_spk_peer_fallback_registered = registered
        if not group_id or group_id in registered:
            return
        registered.add(group_id)
        self._schedule_group_spk_registration(group_id, reason="peer_device_prekey_fallback")

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
        self._log_message_debug(
            "send-plaintext",
            "message.send.v2",
            "message.send",
            params,
            payload_override=payload,
            extra={"to": to},
        )

        async def _attempt(use_cache: bool) -> dict[str, Any]:
            self._log.debug("client", "message.v2.send attempt: to=%s use_cache=%s", to, use_cache)
            if use_cache:
                cached = self._v2_bootstrap_cache.get(to)
                if cached and (time.time() - cached[1]) < self._V2_BOOTSTRAP_TTL:
                    peer_devices = cached[0]
                    self_devices_from_bootstrap = cached[3] if len(cached) > 3 and isinstance(cached[3], list) else None
                    wrap_policy = cached[4] if len(cached) > 4 else None
                else:
                    peer_devices = None
                    self_devices_from_bootstrap = None
                    wrap_policy = None
            else:
                peer_devices = None
                self_devices_from_bootstrap = None
                wrap_policy = None

            if peer_devices is None:
                bootstrap = await self.call("message.v2.bootstrap", {
                    "peer_aid": to,
                    "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                })
                if isinstance(bootstrap, dict):
                    await self._prime_bootstrap_peer_certs(bootstrap, to)
                peer_devices = bootstrap.get("peer_devices", [])
                audit_recipients_raw = bootstrap.get("audit_recipients", [])
                wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
                raw_self_devices = bootstrap.get("self_devices")
                self_devices_from_bootstrap = raw_self_devices if isinstance(raw_self_devices, list) else None
                self._log.debug("client", "_send_encrypted_v2 bootstrap: to=%s peer_devices=%d spk_pks=%s",
                                to, len(peer_devices),
                                [d.get("spk_pk", "")[:20] or "<empty>" for d in peer_devices[:3]])
                if peer_devices:
                    self._v2_bootstrap_cache[to] = (
                        peer_devices,
                        time.time(),
                        audit_recipients_raw,
                        self_devices_from_bootstrap,
                        wrap_policy,
                    )
                if self._aid and self_devices_from_bootstrap:
                    self._v2_bootstrap_cache[self._aid] = (self_devices_from_bootstrap, time.time())
            else:
                audit_recipients_raw = cached[2] if len(cached) > 2 and isinstance(cached[2], list) else []

            if not peer_devices:
                raise E2EEError(f"V2 bootstrap: no devices found for {to}")

            targets = []
            for dev in peer_devices:
                target = await self._v2_build_target_from_device(
                    dev,
                    aid=to,
                    device_id=dev.get("device_id", ""),
                    role="peer",
                    default_key_source="peer_device_prekey",
                )
                if target:
                    targets.append(target)

            # 构造 audit_recipients
            audit_targets = []
            for dev in audit_recipients_raw:
                target = await self._v2_build_target_from_device(
                    dev,
                    aid=dev.get("aid", ""),
                    device_id=dev.get("device_id", ""),
                    role="audit",
                    default_key_source="peer_device_prekey",
                )
                if target:
                    audit_targets.append(target)

            target_set = {"targets": targets, "audit_recipients": audit_targets}
            sender = self._v2_session.get_sender_identity()

            # Self-sync
            if self._aid and self._aid != to:
                try:
                    self_devices = self_devices_from_bootstrap if self_devices_from_bootstrap else None
                    if self_devices is None:
                        self_cached = self._v2_bootstrap_cache.get(self._aid)
                        if self_cached and (time.time() - self_cached[1]) < self._V2_BOOTSTRAP_TTL:
                            self_devices = self_cached[0]
                        else:
                            self_bs = await self.call("message.v2.bootstrap", {
                                "peer_aid": self._aid,
                                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                            })
                            self_devices = self_bs.get("peer_devices", [])
                            if self_devices:
                                self._v2_bootstrap_cache[self._aid] = (self_devices, time.time())
                    for dev in self_devices:
                        has_dev_id, dev_id = _v2_device_id_from_device(dev)
                        if not has_dev_id or dev_id == self._device_id:
                            continue
                        target = await self._v2_build_target_from_device(
                            dev,
                            aid=self._aid,
                            device_id=dev_id,
                            role="self_sync",
                            default_key_source="peer_device_prekey",
                        )
                        if target:
                            targets.append(target)
                except Exception as exc:
                    self._log.debug("client", "V2 self-sync bootstrap failed (non-fatal): %s", exc)

            target_set["targets"] = _v2_apply_wrap_policy_to_targets(target_set["targets"], wrap_policy)
            target_set["audit_recipients"] = _v2_apply_wrap_policy_to_targets(target_set["audit_recipients"], wrap_policy)
            envelope = encrypt_p2p_message(
                sender=sender,
                target_set=target_set,
                payload=payload,
                message_id=params.get("message_id"),
                timestamp=params.get("timestamp"),
                protected_headers=params.get("protected_headers") if isinstance(params.get("protected_headers"), dict) else None,
                context=params.get("context") if isinstance(params.get("context"), dict) else None,
            )

            self._log_message_debug(
                "send-envelope",
                "message.send.v2",
                "message.send",
                {
                    "to": to,
                    "message_id": envelope.get("message_id"),
                    "type": envelope.get("type"),
                    "version": envelope.get("version"),
                    "headers": envelope.get("protected_headers"),
                    "context": envelope.get("context"),
                },
                payload_override=envelope,
                extra={"plaintext_payload": payload},
            )

            result = await self.call("message.send", {
                "to": to,
                "payload": envelope,
                "encrypt": False,
            })
            self._log.debug("client", "message.v2.send ok: to=%s use_cache=%s seq=%s", to, use_cache, result.get("seq") if isinstance(result, dict) else "")
            return result

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
        force = params.get("force") is True

        ns = f"p2p:{self._aid}" if self._aid else ""
        next_after_seq = after_seq if force else (after_seq or self._seq_tracker.get_contiguous_seq(ns))
        first_contig_before = self._seq_tracker.get_contiguous_seq(ns) if ns else 0
        response: dict[str, Any] = {}
        decrypted: list[dict[str, Any]] = []
        total_raw_count = 0
        latest_seq = 0
        server_ack_seq = 0
        page_count = 0
        max_pages = int(params.get("max_pages", 100) or 100)

        while page_count < max_pages:
            page_count += 1
            self._log.debug(
                "client",
                "message.v2.pull page request: page=%d after_seq=%d limit=%d ns=%s",
                page_count, next_after_seq, limit, ns or "<none>",
            )
            pull_params = {
                "after_seq": next_after_seq,
                "limit": limit,
            }
            if force:
                pull_params["force"] = True
            result = await self.call("message.v2.pull", pull_params)
            if isinstance(result, dict):
                response.update(result)
            else:
                result = {}

            messages = result.get("messages", [])
            raw_messages = messages if isinstance(messages, list) else []
            total_raw_count += len(raw_messages)
            self._log.debug(
                "client",
                "message.v2.pull page response: page=%d raw_count=%d has_more=%s server_ack_seq=%s",
                page_count, len(raw_messages), result.get("has_more"), result.get("server_ack_seq"),
            )
            for msg in raw_messages:
                self._log_message_debug("pull-raw", "message.v2.pull", "message.received", msg)
            seqs = [
                int(m.get("seq") or 0)
                for m in raw_messages
                if isinstance(m, dict) and int(m.get("seq") or 0) > 0
            ]
            page_contig_before = self._seq_tracker.get_contiguous_seq(ns) if ns else 0

            if seqs:
                page_max_seq = max(seqs)
                latest_seq = max(latest_seq, page_max_seq)
                if ns:
                    self._seq_tracker.force_contiguous_seq(ns, page_max_seq)
                    self._log.debug(
                        "client",
                        "message.v2.pull force contiguous: ns=%s page_max_seq=%d previous=%d",
                        ns, page_max_seq, page_contig_before,
                    )
            else:
                page_max_seq = next_after_seq

            for msg in raw_messages:
                if not isinstance(msg, dict):
                    continue
                seq = int(msg.get("seq", 0) or 0)
                if seq <= 0:
                    continue

                # 服务端 v2.pull 合并的明文历史行：V2-only 客户端跳过旧加密 envelope，
                # 仅明文消息照常 publish；e2ee.encrypted / e2ee.group_encrypted / 未知类型一律
                # 推进 seq tracker 并丢弃。
                if str(msg.get("version", "") or "") == "v1":
                    legacy = msg.get("legacy_v1") or {}
                    v1_payload = legacy.get("payload")
                    v1_payload_type = ""
                    if isinstance(v1_payload, dict):
                        v1_payload_type = str(v1_payload.get("type") or "").strip()
                    # 仅放行明文（非旧 E2EE 包装类型）
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
                            await self._publish_app_event("message.received", v1_msg, source="pull")
                        decrypted.append(v1_msg)
                        self._log.debug("client", "message.v2.pull plaintext legacy row delivered: ns=%s seq=%d", ns or "<none>", seq)
                    else:
                        self._log.debug("client", "v2.pull skipping legacy envelope seq=%d payload_type=%s (old E2EE removed)",
                                        seq, v1_payload_type or "<none>")
                    continue

                # 跟踪每个旧 SPK 引用的最大 seq（用于消费后销毁）
                try:
                    msg_spk_id = str(msg.get("spk_id", "") or "")
                    if msg_spk_id and self._v2_session and msg_spk_id != self._v2_session._spk_id:
                        self._v2_session.track_old_spk_max_seq(msg_spk_id, seq)
                except Exception:
                    pass
                # 解密失败不阻断本页 seq 下界推进和 ack。
                plaintext = await self._decrypt_v2_message(msg)
                if plaintext is None:
                    self._log.debug("client", "message.v2.pull decrypt returned None: ns=%s seq=%d", ns or "<none>", seq)
                    continue
                if ns:
                    await self._publish_pulled_message("message.received", ns, seq, plaintext)
                else:
                    await self._publish_app_event("message.received", plaintext, source="pull")
                decrypted.append(plaintext)
                self._log_message_debug("decrypt-ok", "message.v2.pull", "message.received", plaintext)

            if ns:
                page_server_ack = int(result.get("server_ack_seq") or 0)
                server_ack_seq = max(server_ack_seq, page_server_ack)
                if page_server_ack > 0:
                    contig = self._seq_tracker.get_contiguous_seq(ns)
                    if contig < page_server_ack:
                        self._log.info(
                            "client",
                            "message.v2.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d",
                            ns, contig, page_server_ack,
                        )
                        self._seq_tracker.force_contiguous_seq(ns, page_server_ack)

                if not raw_messages and not decrypted and self._seq_tracker.has_pending_gaps(ns):
                    self._log.info(
                        "client",
                        "message.v2.pull 返回空但有 pending gaps: ns=%s contiguous=%d, 可能原因：多设备竞态/临时消息过期/Push-Pull 时序差",
                        ns, self._seq_tracker.get_contiguous_seq(ns),
                    )

                contig = self._seq_tracker.get_contiguous_seq(ns)
                contig_advanced = contig != page_contig_before
                if contig_advanced:
                    await self._drain_ordered_messages(ns)
                    self._persist_seq(ns)
                if raw_messages and contig_advanced and contig > 0:
                    self._log.debug("client", "message.v2.pull scheduling auto-ack: ns=%s ack_seq=%d raw_count=%d", ns, contig, len(raw_messages))
                    self._fire_ack("message.v2.ack", {"up_to_seq": contig}, "V2 P2P page auto-ack")

            next_after = max(page_max_seq, next_after_seq)
            if not raw_messages or next_after <= next_after_seq or result.get("has_more") is False:
                break
            next_after_seq = next_after

        if page_count >= max_pages:
            self._log.warn("client", "message.v2.pull reached max_pages=%d after_seq=%d", max_pages, next_after_seq)

        response["messages"] = decrypted
        response["_contig_before"] = first_contig_before
        response["raw_count"] = total_raw_count
        if latest_seq:
            response["latest_seq"] = max(int(response.get("latest_seq") or 0), latest_seq)
        if server_ack_seq:
            response["server_ack_seq"] = max(int(response.get("server_ack_seq") or 0), server_ack_seq)
        self._log.debug(
            "client",
            "message.v2.pull done: requested_after_seq=%d pages=%d raw_count=%d decrypted=%d ns=%s",
            after_seq, page_count, total_raw_count, len(decrypted), ns or "<none>",
        )
        return response

    async def _ack_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 确认消费 + 自检销毁旧 SPK。内部方法，由 call("message.ack") 路由调用。"""
        ns = f"p2p:{self._aid}" if self._aid else ""
        up_to_seq = int(params.get("seq", 0) or params.get("up_to_seq", 0) or 0)
        seq = up_to_seq or (self._seq_tracker.get_contiguous_seq(ns) if ns else 0)
        if seq <= 0:
            self._log.debug("client", "message.v2.ack skipped: ns=%s up_to_seq=%s", ns or "<none>", up_to_seq)
            return {"acked": 0}
        # ack clamp：永远不发送超过 max_seen_seq 的 up_to_seq
        if ns:
            max_seen = self._seq_tracker.get_max_seen_seq(ns)
            if max_seen > 0 and seq > max_seen:
                self._log.warn(
                    "client",
                    "_ack_v2_internal clamp: up_to_seq=%d > max_seen=%d, clamp",
                    seq, max_seen,
                )
                seq = max_seen
        self._log.debug("client", "message.v2.ack send: ns=%s up_to_seq=%d", ns or "<none>", seq)
        result = await self.call("message.v2.ack", {"up_to_seq": seq})
        actual_ack_seq = seq
        # 补充兼容字段
        if isinstance(result, dict):
            try:
                if "effective_ack_seq" in result:
                    actual_ack_seq = int(result.get("effective_ack_seq") or 0)
                elif "ack_seq" in result:
                    actual_ack_seq = int(result.get("ack_seq") or 0)
                elif "cursor" in result:
                    actual_ack_seq = int(result.get("cursor") or 0)
            except Exception:
                actual_ack_seq = seq
            result["ack_seq"] = actual_ack_seq
            result["success"] = True
            # 共享 seq 空间：即使 V2 inbox 没 wrap 行（明文历史在普通消息表），
            # 服务端 cursor 也被推进了，视为 ack 成功
            if result.get("acked", 0) == 0 and actual_ack_seq > 0:
                result["acked"] = actual_ack_seq
        # 自检：所有旧 SPK 引用的消息都已 ack → 销毁旧 SPK 私钥（PFS）
        if self._v2_session:
            try:
                destroyed = self._v2_session.maybe_destroy_old_spks(actual_ack_seq)
                if destroyed:
                    self._log.info("client", "V2 destroyed old SPKs after ack: %s (PFS)", destroyed[:3])
            except Exception as exc:
                self._log.debug("client", "V2 SPK destroy failed (non-fatal): %s", exc)
        self._log.debug("client", "message.v2.ack ok: ns=%s requested=%d effective=%d result=%s", ns or "<none>", seq, actual_ack_seq, result)
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
        self._log_message_debug(
            "send-plaintext",
            "group.send.v2",
            "group.send",
            params,
            payload_override=payload,
            extra={"group_id": group_id},
        )

        async def _attempt(use_cache: bool) -> dict[str, Any]:
            self._log.debug("client", "group.v2.send attempt: group=%s use_cache=%s", group_id, use_cache)
            cache_key = f"group:{group_id}"
            epoch = 0
            if use_cache:
                cached = self._v2_bootstrap_cache.get(cache_key)
                if cached and (time.time() - cached[1]) < self._V2_GROUP_BOOTSTRAP_TTL:
                    all_devices = cached[0]
                    epoch = cached[2] if len(cached) > 2 else 0
                    wrap_policy = cached[7] if len(cached) > 7 else None
                else:
                    all_devices = None
                    wrap_policy = None
            else:
                all_devices = None
                wrap_policy = None

            if all_devices is None:
                bootstrap = await self.call("group.v2.bootstrap", {
                    "group_id": group_id,
                    "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                })
                all_devices = bootstrap.get("devices", [])
                epoch = int(bootstrap.get("epoch", 0))
                wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
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
                        state_commitment, audit_recipients_raw, wrap_policy,
                    )
                # lazy sync 触发：发现 pending members 且自己是 owner/admin 时异步发起提案
                if pending_adds and self._v2_session:
                    self._v2_maybe_trigger_auto_propose(group_id)
            else:
                pending_adds = cached[3] if len(cached) > 3 else set()
                committed_aids = cached[4] if len(cached) > 4 else set()
                state_commitment = cached[5] if len(cached) > 5 else {"state_version": 0, "state_hash": "", "state_chain": ""}
                audit_recipients_raw = cached[6] if len(cached) > 6 else []
                wrap_policy = cached[7] if len(cached) > 7 else None

            if not all_devices:
                raise E2EEError(f"V2 group bootstrap: no devices found for group {group_id}")

            targets = []
            for dev in all_devices:
                dev_aid = dev.get("aid", "")
                has_dev_id, dev_id = _v2_device_id_from_device(dev)
                if dev_aid == self._aid and has_dev_id and dev_id == self._device_id:
                    continue
                # pending 成员默认可收发（可用性优先），安全敏感群可通过配置严格过滤
                role = "self_sync" if dev_aid == self._aid else "member"
                target = await self._v2_build_target_from_device(
                    dev,
                    aid=dev_aid,
                    device_id=dev_id,
                    role=role,
                    default_key_source="peer_device_prekey",
                )
                if target:
                    targets.append(target)

            if not targets:
                raise E2EEError(f"V2 group: no target devices for group {group_id}")

            # 监管 AID：把 audit_recipients 一并加入 targets（role="audit"）
            for dev in audit_recipients_raw:
                target = await self._v2_build_target_from_device(
                    dev,
                    aid=dev.get("aid", ""),
                    device_id=dev.get("device_id", ""),
                    role="audit",
                    default_key_source="peer_device_prekey",
                )
                if target:
                    targets.append(target)

            sender = self._v2_session.get_sender_identity()
            targets = _v2_apply_wrap_policy_to_targets(targets, wrap_policy)
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

            self._log_message_debug(
                "send-envelope",
                "group.send.v2",
                "group.send",
                {
                    "group_id": group_id,
                    "message_id": envelope.get("message_id"),
                    "type": envelope.get("type"),
                    "version": envelope.get("version"),
                    "headers": envelope.get("protected_headers"),
                    "context": envelope.get("context"),
                },
                payload_override=envelope,
                extra={"plaintext_payload": payload, "epoch": epoch},
            )

            result = await self.call("group.v2.send", {
                "group_id": group_id,
                "envelope": envelope,
            })
            self._log.debug("client", "group.v2.send ok: group=%s use_cache=%s seq=%s", group_id, use_cache, result.get("seq") if isinstance(result, dict) else "")
            return result

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
            self._log.debug("client", "group.v2.send marked own seq: group=%s ns=%s seq=%d", group_id, ns, seq)
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
            self_devices_from_bootstrap = cached[3] if len(cached) > 3 and isinstance(cached[3], list) else None
            wrap_policy = cached[4] if len(cached) > 4 else None
        else:
            bootstrap = await self.call("message.v2.bootstrap", {
                "peer_aid": to,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
            if isinstance(bootstrap, dict):
                await self._prime_bootstrap_peer_certs(bootstrap, to)
            peer_devices = bootstrap.get("peer_devices", [])
            audit_recipients_raw = bootstrap.get("audit_recipients", []) or []
            wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
            raw_self_devices = bootstrap.get("self_devices")
            self_devices_from_bootstrap = raw_self_devices if isinstance(raw_self_devices, list) else None
            if peer_devices:
                self._v2_bootstrap_cache[to] = (
                    peer_devices,
                    time.time(),
                    audit_recipients_raw,
                    self_devices_from_bootstrap,
                    wrap_policy,
                )
            if self._aid and self_devices_from_bootstrap:
                self._v2_bootstrap_cache[self._aid] = (self_devices_from_bootstrap, time.time())

        if not peer_devices:
            raise E2EEError(f"V2 bootstrap: no devices found for {to}")

        targets: list[dict[str, Any]] = []
        for dev in peer_devices:
            target = await self._v2_build_target_from_device(
                dev,
                aid=to,
                device_id=dev.get("device_id", ""),
                role="peer",
                default_key_source="peer_device_prekey",
            )
            if target:
                targets.append(target)

        for dev in audit_recipients_raw:
            target = await self._v2_build_target_from_device(
                dev,
                aid=dev.get("aid", ""),
                device_id=dev.get("device_id", ""),
                role="audit",
                default_key_source="peer_device_prekey",
            )
            if target:
                targets.append(target)

        # Self-sync：自己其它设备
        if self._aid and self._aid != to:
            try:
                self_devices = self_devices_from_bootstrap if self_devices_from_bootstrap else None
                if self_devices is None:
                    self_cached = self._v2_bootstrap_cache.get(self._aid)
                    if self_cached and (time.time() - self_cached[1]) < self._V2_BOOTSTRAP_TTL:
                        self_devices = self_cached[0]
                    else:
                        self_bs = await self.call("message.v2.bootstrap", {
                            "peer_aid": self._aid,
                            "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                        })
                        self_devices = self_bs.get("peer_devices", [])
                        if self_devices:
                            self._v2_bootstrap_cache[self._aid] = (self_devices, time.time())
                for dev in self_devices:
                    has_dev_id, dev_id = _v2_device_id_from_device(dev)
                    if not has_dev_id or dev_id == self._device_id:
                        continue
                    target = await self._v2_build_target_from_device(
                        dev,
                        aid=self._aid,
                        device_id=dev_id,
                        role="self_sync",
                        default_key_source="peer_device_prekey",
                    )
                    if target:
                        targets.append(target)
            except Exception as exc:
                self._log.debug("client", "V2 thought self-sync bootstrap failed (non-fatal): %s", exc)

        sender = self._v2_session.get_sender_identity()
        targets = _v2_apply_wrap_policy_to_targets(targets, wrap_policy)
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
        self._log_message_debug(
            "thought-send-plaintext",
            "message.thought.put.v2",
            "message.thought.put",
            {"to": to_aid, "thought_id": thought_id, "timestamp": timestamp, "payload": payload},
            payload_override=payload,
        )

        async def _attempt(use_cache: bool) -> Any:
            self._log.debug("client", "message.thought.put attempt: to=%s thought_id=%s use_cache=%s", to_aid, thought_id, use_cache)
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
            self._log_message_debug(
                "thought-send-envelope",
                "message.thought.put.v2",
                "message.thought.put",
                send_params,
                payload_override=envelope,
                extra={"to": to_aid, "thought_id": thought_id, "use_cache": use_cache},
            )
            result = await self._transport.call("message.thought.put", send_params)
            self._log.debug("client", "message.thought.put ok: to=%s thought_id=%s use_cache=%s", to_aid, thought_id, use_cache)
            return result

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
            wrap_policy = cached[7] if len(cached) > 7 else None
            self._log.debug(
                "client",
                "group.v2.bootstrap cache hit: group=%s devices=%d audit=%d epoch=%s state_version=%s",
                group_id, len(all_devices), len(audit_recipients_raw), epoch, state_commitment.get("state_version"),
            )
        else:
            bootstrap = await self.call("group.v2.bootstrap", {
                "group_id": group_id,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
            all_devices = bootstrap.get("devices", [])
            epoch = int(bootstrap.get("epoch", 0))
            wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
            self._log.debug(
                "client",
                "group.v2.bootstrap fetched: group=%s devices=%d audit=%d epoch=%s members=%d",
                group_id,
                len(all_devices) if isinstance(all_devices, list) else 0,
                len(bootstrap.get("audit_recipients", []) or []),
                epoch,
                len(bootstrap.get("member_aids", []) or []),
            )
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
                    state_commitment, audit_recipients_raw, wrap_policy,
                )
            # lazy sync 触发：发现 pending members 且自己是 owner/admin 时异步发起提案
            if pending_adds and self._v2_session:
                self._v2_maybe_trigger_auto_propose(group_id)

        if not all_devices:
            raise E2EEError(f"V2 group bootstrap: no devices for {group_id}")

        targets: list[dict[str, Any]] = []
        for dev in all_devices:
            dev_aid = dev.get("aid", "")
            has_dev_id, dev_id = _v2_device_id_from_device(dev)
            if dev_aid == self._aid and has_dev_id and dev_id == self._device_id:
                continue
            role = "self_sync" if dev_aid == self._aid else "member"
            target = await self._v2_build_target_from_device(
                dev,
                aid=dev_aid,
                device_id=dev_id,
                role=role,
                default_key_source="peer_device_prekey",
            )
            if target:
                targets.append(target)

        for dev in audit_recipients_raw:
            target = await self._v2_build_target_from_device(
                dev,
                aid=dev.get("aid", ""),
                device_id=dev.get("device_id", ""),
                role="audit",
                default_key_source="peer_device_prekey",
            )
            if target:
                targets.append(target)

        if not targets:
            raise E2EEError(f"V2 group: no target devices for {group_id}")

        sender = self._v2_session.get_sender_identity()
        targets = _v2_apply_wrap_policy_to_targets(targets, wrap_policy)
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
        self._log_message_debug(
            "send-envelope",
            "group.send.v2",
            "group.send",
            {
                "group_id": group_id,
                "message_id": envelope.get("message_id"),
                "type": envelope.get("type"),
                "version": envelope.get("version"),
                "headers": envelope.get("protected_headers"),
                "context": envelope.get("context"),
            },
            payload_override=envelope,
            extra={
                "plaintext_payload": payload,
                "epoch": epoch,
                "target_count": len(targets),
                "audit_count": len(audit_recipients_raw),
                "state_version": state_commitment.get("state_version"),
                "use_cache": use_cache,
            },
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
        self._log_message_debug(
            "thought-send-plaintext",
            "group.thought.put.v2",
            "group.thought.put",
            {"group_id": group_id, "thought_id": thought_id, "timestamp": timestamp, "payload": payload},
            payload_override=payload,
        )

        async def _attempt(use_cache: bool) -> Any:
            self._log.debug("client", "group.thought.put attempt: group=%s thought_id=%s use_cache=%s", group_id, thought_id, use_cache)
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
            self._log_message_debug(
                "thought-send-envelope",
                "group.thought.put.v2",
                "group.thought.put",
                send_params,
                payload_override=envelope,
                extra={"group_id": group_id, "thought_id": thought_id, "use_cache": use_cache},
            )
            result = await self._transport.call("group.thought.put", send_params)
            self._log.debug("client", "group.thought.put ok: group=%s thought_id=%s use_cache=%s", group_id, thought_id, use_cache)
            return result

        try:
            return await _attempt(use_cache=True)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "member" in err_msg or "device" in err_msg or "recipient" in err_msg or "stale" in err_msg or "epoch" in err_msg:
                self._log.debug("client", "V2 group thought put speculative rejected, refreshing bootstrap: %s", exc)
                self._v2_bootstrap_cache.pop(f"group:{group_id}", None)
                return await _attempt(use_cache=False)
            raise

    async def _decrypt_group_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        return await self._decrypt_thought_get_result(result, group=True)

    async def _decrypt_message_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        return await self._decrypt_thought_get_result(result, group=False)

    async def _decrypt_thought_get_result(self, result: dict[str, Any], *, group: bool) -> dict[str, Any]:
        """解密 thought.get 返回中的 V2 envelope，并保留服务端返回的元数据字段。"""
        label = "group" if group else "message"
        self._log.debug(
            "client",
            "%s.thought.get decrypt enter: found=%s sender=%s group=%s peer=%s",
            label,
            result.get("found"),
            result.get("sender_aid"),
            result.get("group_id"),
            result.get("peer_aid"),
        )
        if not result.get("found"):
            self._log.debug("client", "%s.thought.get decrypt exit: not found", label)
            return {**result, "thoughts": []}
        raw_items = result.get("thoughts")
        if not isinstance(raw_items, list):
            self._log.debug("client", "%s.thought.get decrypt exit: invalid thoughts", label)
            return {**result, "thoughts": []}

        sender_aid = str(result.get("sender_aid") or "").strip()
        peer_aid = str(result.get("peer_aid") or "").strip()
        thoughts: list[dict[str, Any]] = []
        decrypted_count = 0
        failed_count = 0
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            item = dict(raw)
            payload = item.get("payload") if isinstance(item.get("payload"), dict) else None
            from_aid = str(item.get("from") or item.get("sender_aid") or sender_aid).strip()
            thought_id = str(item.get("thought_id") or item.get("message_id") or "").strip()
            self._log_message_debug(
                "thought-get-raw",
                f"{label}.thought.get",
                f"{label}.thought.get",
                item,
                extra={"thought_id": thought_id, "from": from_aid},
            )
            if group:
                if from_aid and "sender_aid" not in item:
                    item["sender_aid"] = from_aid
            else:
                to_aid = str(item.get("to") or item.get("peer_aid") or peer_aid or self._aid or "").strip()
                if from_aid and "from" not in item:
                    item["from"] = from_aid
                if to_aid and "to" not in item:
                    item["to"] = to_aid

            if payload and self._is_v2_thought_envelope(payload, group=group):
                meta = self._v2_thought_e2ee_metadata(payload)
                plaintext = await self._decrypt_v2_envelope_for_thought(envelope=payload, from_aid=from_aid)
                item["e2ee"] = meta
                self._attach_v2_envelope_metadata(item, meta)
                if plaintext is None:
                    item["decrypt_failed"] = True
                    failed_count += 1
                    self._log.debug("client", "%s.thought.get decrypt returned None: thought_id=%s from=%s", label, thought_id, from_aid)
                else:
                    item["payload"] = plaintext
                    item["encrypted"] = True
                    item.pop("decrypt_failed", None)
                    decrypted_count += 1
                    self._log_message_debug(
                        "thought-decrypt-ok",
                        f"{label}.thought.get",
                        f"{label}.thought.get",
                        item,
                        payload_override=plaintext,
                        extra={"thought_id": thought_id, "from": from_aid},
                    )
            elif payload and self._is_encrypted_thought_payload(payload):
                item["decrypt_failed"] = True
                failed_count += 1
                self._log.debug(
                    "client",
                    "%s.thought.get unsupported encrypted payload: thought_id=%s type=%s version=%s",
                    label, thought_id, payload.get("type"), payload.get("version"),
                )
            self._log_message_debug(
                "thought-result",
                f"{label}.thought.get",
                f"{label}.thought.get",
                item,
                extra={"thought_id": thought_id, "decrypt_failed": bool(item.get("decrypt_failed"))},
            )
            thoughts.append(item)

        self._log.debug(
            "client",
            "%s.thought.get post-decrypt: total=%d decrypted=%d failed=%d",
            label,
            len(thoughts),
            decrypted_count,
            failed_count,
        )
        return {**result, "thoughts": thoughts}

    @staticmethod
    def _is_v2_thought_envelope(payload: dict[str, Any], *, group: bool) -> bool:
        expected_type = "e2ee.group_encrypted" if group else "e2ee.p2p_encrypted"
        if str(payload.get("type") or "") != expected_type:
            return False
        return str(payload.get("version") or "") == "v2" or isinstance(payload.get("recipients"), list)

    @staticmethod
    def _is_encrypted_thought_payload(payload: dict[str, Any]) -> bool:
        return str(payload.get("type") or "") in {
            "e2ee.encrypted",
            "e2ee.p2p_encrypted",
            "e2ee.group_encrypted",
        }

    @staticmethod
    def _metadata_without_auth(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {k: v for k, v in value.items() if k != "_auth"}

    @staticmethod
    def _v2_envelope_payload_type(envelope: dict[str, Any], protected_headers: dict[str, Any] | None = None) -> str:
        value = envelope.get("payload_type")
        if value is None and isinstance(protected_headers, dict):
            value = protected_headers.get("payload_type")
        return str(value or "").strip()

    def _v2_thought_e2ee_metadata(self, envelope: dict[str, Any]) -> dict[str, Any]:
        suite = str(envelope.get("suite") or "")
        meta: dict[str, Any] = {
            "version": "v2",
            "suite": suite,
            "encryption_mode": "v2_" + (suite or "unknown"),
            "forward_secrecy": True,
        }
        protected_headers = self._metadata_without_auth(envelope.get("protected_headers"))
        if protected_headers:
            meta["protected_headers"] = protected_headers
        payload_type = self._v2_envelope_payload_type(envelope, protected_headers)
        if payload_type:
            meta["payload_type"] = payload_type
        context = self._metadata_without_auth(envelope.get("context"))
        if context:
            meta["context"] = context
        agent_md = self._metadata_without_auth(envelope.get("agent_md"))
        if agent_md:
            meta["agent_md"] = agent_md
        return meta

    @staticmethod
    def _attach_v2_envelope_metadata(message: dict[str, Any], meta: dict[str, Any]) -> None:
        payload_type = str(meta.get("payload_type") or "").strip()
        if payload_type:
            message["payload_type"] = payload_type
        protected_headers = meta.get("protected_headers")
        if isinstance(protected_headers, dict) and protected_headers:
            message["protected_headers"] = dict(protected_headers)
        agent_md = meta.get("agent_md")
        if isinstance(agent_md, dict) and agent_md:
            message["agent_md"] = dict(agent_md)

    def _attach_v2_envelope_metadata_from_source(self, message: dict[str, Any], source: Any) -> None:
        envelope: dict[str, Any] | None = None
        if isinstance(source, dict):
            payload = source.get("payload")
            if isinstance(payload, dict):
                envelope = payload
            if envelope is None:
                envelope_json = source.get("envelope_json")
                if isinstance(envelope_json, str) and envelope_json:
                    try:
                        parsed = json.loads(envelope_json)
                    except (json.JSONDecodeError, TypeError):
                        parsed = None
                    if isinstance(parsed, dict):
                        envelope = parsed
        if envelope is not None:
            self._observe_agent_md_from_envelope(envelope)
            self._attach_v2_envelope_metadata(message, self._v2_thought_e2ee_metadata(envelope))

    @staticmethod
    def _truthy_bool(value: Any) -> bool:
        if value is True or value == 1:
            return True
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "on"}
        return False

    @staticmethod
    def _is_encrypted_envelope_payload(payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        payload_type = str(payload.get("type") or "").strip()
        if payload_type.startswith("e2ee."):
            return True
        if not str(payload.get("ciphertext") or "").strip():
            return False
        return any(
            key in payload
            for key in ("nonce", "tag", "recipient", "recipients", "wrapped_key", "recipients_digest")
        )

    def _encrypted_push_envelope(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        payload = msg.get("payload")
        if self._is_encrypted_envelope_payload(payload):
            return payload
        envelope_json = msg.get("envelope_json")
        if isinstance(envelope_json, str) and envelope_json.strip():
            try:
                parsed = json.loads(envelope_json)
            except (json.JSONDecodeError, TypeError):
                return None
            if self._is_encrypted_envelope_payload(parsed):
                return parsed
        return None

    def _is_encrypted_push_message(self, msg: dict[str, Any]) -> bool:
        if self._truthy_bool(msg.get("encrypted")):
            return True
        return self._encrypted_push_envelope(msg) is not None

    @staticmethod
    def _is_v2_encrypted_envelope_payload(envelope: dict[str, Any] | None) -> bool:
        if not isinstance(envelope, dict):
            return False
        payload_type = str(envelope.get("type") or "").strip()
        if payload_type in {"e2ee.p2p_encrypted", "e2ee.group_encrypted"}:
            return True
        return str(envelope.get("version") or "").strip().lower() == "v2" and payload_type.startswith("e2ee.")

    def _safe_undecryptable_push_event(self, msg: dict[str, Any], *, group: bool) -> dict[str, Any]:
        event: dict[str, Any] = {
            "message_id": msg.get("message_id"),
            "from": msg.get("from"),
            "seq": msg.get("seq"),
            "timestamp": msg.get("timestamp") if msg.get("timestamp") is not None else msg.get("t_server"),
            "device_id": msg.get("device_id"),
            "slot_id": msg.get("slot_id"),
            "_decrypt_error": "encrypted push payload is not decryptable on raw push path",
            "_decrypt_stage": "push_envelope",
        }
        if group:
            event["group_id"] = msg.get("group_id")
        else:
            event["to"] = msg.get("to")
        envelope = self._encrypted_push_envelope(msg)
        if envelope is not None:
            event["_envelope_type"] = str(envelope.get("type") or "")
            event["_suite"] = str(envelope.get("suite") or "")
            if self._is_v2_encrypted_envelope_payload(envelope):
                self._attach_v2_envelope_metadata(event, self._v2_thought_e2ee_metadata(envelope))
        return event

    async def _decrypt_encrypted_push_payload(self, msg: dict[str, Any], *, group: bool) -> dict[str, Any] | None:
        envelope = self._encrypted_push_envelope(msg)
        if not self._is_v2_encrypted_envelope_payload(envelope):
            return None
        assert envelope is not None
        aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
        from_aid = str(msg.get("from_aid") or msg.get("from") or msg.get("sender_aid") or aad.get("from") or "").strip()
        plaintext = await self._decrypt_v2_envelope_for_thought(envelope=envelope, from_aid=from_aid)
        if plaintext is None:
            return None
        e2ee_meta = self._v2_thought_e2ee_metadata(envelope)
        result: dict[str, Any] = {
            "message_id": str(msg.get("message_id") or ""),
            "from": from_aid,
            "seq": msg.get("seq"),
            "timestamp": msg.get("t_server") if msg.get("t_server") is not None else msg.get("timestamp"),
            "payload": plaintext,
            "encrypted": True,
            "e2ee": e2ee_meta,
        }
        result["direction"] = "outbound_sync" if from_aid and from_aid == self._aid else "inbound"
        if msg.get("t_server") is not None:
            result["t_server"] = msg.get("t_server")
        if "device_id" in msg:
            result["device_id"] = msg.get("device_id")
        if "slot_id" in msg:
            result["slot_id"] = msg.get("slot_id")
        if group:
            result["group_id"] = msg.get("group_id") or aad.get("group_id") or envelope.get("group_id")
        else:
            result["to"] = msg.get("to") or self._aid or ""
        self._attach_v2_envelope_metadata(result, e2ee_meta)
        self._log_message_debug("decrypt-ok", "push.encrypted", "group.message_created" if group else "message.received", result)
        return result

    async def _publish_encrypted_push_as_undecryptable(
        self,
        event: str,
        ns: str,
        seq: Any,
        msg: dict[str, Any],
        *,
        group: bool,
    ) -> bool:
        safe_event = self._safe_undecryptable_push_event(msg, group=group)
        self._log_message_debug("decrypt-fail", "push.encrypted", event, safe_event)
        if ns:
            return await self._publish_ordered_message(event, ns, seq, safe_event)
        await self._publish_app_event(event, safe_event, source="push")
        return True

    async def _publish_encrypted_push_message(
        self,
        normal_event: str,
        undecryptable_event: str,
        ns: str,
        seq: Any,
        msg: dict[str, Any],
        *,
        group: bool,
    ) -> bool:
        decrypted = await self._decrypt_encrypted_push_payload(msg, group=group)
        if decrypted is not None:
            if ns:
                return await self._publish_ordered_message(normal_event, ns, seq, decrypted)
            await self._publish_app_event(normal_event, decrypted, source="push")
            return True
        return await self._publish_encrypted_push_as_undecryptable(
            undecryptable_event, ns, seq, msg, group=group,
        )

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
        self._observe_agent_md_from_envelope(envelope)

        # 确定接收方 SPK：根据 envelope.recipients 中本设备所引用的 spk_id
        spk_id = ""
        recipient_key_source = ""
        recipients = envelope.get("recipients")
        if isinstance(recipients, list):
            for row in recipients:
                if isinstance(row, list) and len(row) >= 6:
                    if row[0] == self._aid and (row[1] == self._device_id or row[1] == ""):
                        spk_id = str(row[5] or "")
                        recipient_key_source = str(row[3] or "") if len(row) > 3 else ""
                        break
        aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
        group_id_for_keys = str(aad.get("group_id") or envelope.get("group_id") or "").strip()
        self._log.debug(
            "client",
            "V2 thought decrypt start: from=%s sender_device=%s group=%s spk_id=%s key_source=%s type=%s",
            from_aid,
            aad.get("from_device", ""),
            group_id_for_keys or "<p2p>",
            spk_id or "<empty>",
            recipient_key_source or "<empty>",
            envelope.get("type", ""),
        )
        try:
            if group_id_for_keys:
                ik_priv, spk_priv = self._v2_session.get_group_decrypt_keys(group_id_for_keys, spk_id)
            else:
                ik_priv, spk_priv = self._v2_session.get_decrypt_keys(spk_id)
        except Exception as exc:
            self._log.warn(
                "client",
                "V2 thought decrypt: key lookup failed from=%s group=%s spk_id=%s: %s",
                from_aid, group_id_for_keys or "<p2p>", spk_id, exc,
            )
            return None

        sender_device_id = str(aad.get("from_device") or "")
        sender_pub_der = await self._v2_sender_pub_der_from_cache_or_cert(from_aid, sender_device_id)
        if not sender_pub_der:
            self._log.warn("client", "V2 thought decrypt pending: no sender IK for %s device=%s", from_aid, sender_device_id)
            self._schedule_v2_sender_ik_fetch(from_aid, sender_device_id, group_id_for_keys)
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
            self._log.debug(
                "client",
                "V2 thought decrypt ok: from=%s sender_device=%s group=%s",
                from_aid, sender_device_id, group_id_for_keys or "<p2p>",
            )
            if (
                plaintext is not None
                and group_id_for_keys
                and recipient_key_source == "group_device_prekey"
                and self._v2_session.is_last_uploaded_group_spk(group_id_for_keys, spk_id)
            ):
                self._schedule_group_spk_rotation(group_id_for_keys, reason="group_spk_consumed")
            elif plaintext is not None and group_id_for_keys and recipient_key_source == "peer_device_prekey":
                self._schedule_group_spk_registration_after_peer_fallback(group_id_for_keys)
            return plaintext
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
        next_after_seq = after_seq or self._seq_tracker.get_contiguous_seq(ns)
        first_contig_before = self._seq_tracker.get_contiguous_seq(ns)
        response: dict[str, Any] = {}
        decrypted: list[dict[str, Any]] = []
        total_raw_count = 0
        latest_seq = 0
        page_count = 0
        max_pages = int(params.get("max_pages", 100) or 100)

        while page_count < max_pages:
            page_count += 1
            self._log.debug(
                "client",
                "group.v2.pull page request: group=%s page=%d after_seq=%d limit=%d ns=%s",
                group_id, page_count, next_after_seq, limit, ns,
            )
            result = await self.call("group.v2.pull", {
                "group_id": group_id,
                "after_seq": next_after_seq,
                "limit": limit,
            })
            if isinstance(result, dict):
                response.update(result)
            else:
                result = {}

            messages = result.get("messages", [])
            raw_messages = messages if isinstance(messages, list) else []
            total_raw_count += len(raw_messages)
            cursor = result.get("cursor") if isinstance(result.get("cursor"), dict) else {}
            self._log.debug(
                "client",
                "group.v2.pull page response: group=%s page=%d raw_count=%d has_more=%s cursor_current=%s",
                group_id, page_count, len(raw_messages), result.get("has_more"), cursor.get("current_seq"),
            )
            for msg in raw_messages:
                self._log_message_debug("pull-raw", "group.v2.pull", "group.message_created", msg)
            seqs = [
                int(m.get("seq") or 0)
                for m in raw_messages
                if isinstance(m, dict) and int(m.get("seq") or 0) > 0
            ]
            page_contig_before = self._seq_tracker.get_contiguous_seq(ns)

            if seqs:
                page_max_seq = max(seqs)
                latest_seq = max(latest_seq, page_max_seq)
                self._seq_tracker.force_contiguous_seq(ns, page_max_seq)
                self._log.debug(
                    "client",
                    "group.v2.pull force contiguous: group=%s ns=%s page_max_seq=%d previous=%d",
                    group_id, ns, page_max_seq, page_contig_before,
                )
            else:
                page_max_seq = next_after_seq

            for msg in raw_messages:
                if not isinstance(msg, dict):
                    continue
                seq = int(msg.get("seq", 0) or 0)
                if seq <= 0:
                    continue

                # 服务端合并的明文历史行：payload 已是明文
                if str(msg.get("version", "") or "") == "v1":
                    payload = msg.get("payload")
                    if isinstance(payload, dict) and payload.get("type") in ("e2ee.encrypted", "e2ee.group_encrypted"):
                        # 兜底：旧加密 envelope 在 V2-only 客户端跳过
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
                    self._log.debug("client", "group.v2.pull plaintext legacy row delivered: group=%s seq=%d", group_id, seq)
                    continue

                # 解密失败不阻断本页 seq 下界推进和 ack。
                plaintext = await self._decrypt_v2_message(msg)
                if plaintext is None:
                    self._log.debug("client", "group.v2.pull decrypt returned None: group=%s seq=%d", group_id, seq)
                    continue
                plaintext["group_id"] = group_id
                await self._publish_pulled_message("group.message_created", ns, seq, plaintext)
                decrypted.append(plaintext)
                self._log_message_debug("decrypt-ok", "group.v2.pull", "group.message_created", plaintext)

            cursor = result.get("cursor")
            if isinstance(cursor, dict):
                server_ack = int(cursor.get("current_seq") or 0)
                if server_ack > 0:
                    contig_before_ack = self._seq_tracker.get_contiguous_seq(ns)
                    if contig_before_ack < server_ack:
                        self._log.info(
                            "client",
                            "group.v2.pull retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                            ns, contig_before_ack, server_ack,
                        )
                        self._seq_tracker.force_contiguous_seq(ns, server_ack)

            contig = self._seq_tracker.get_contiguous_seq(ns)
            contig_advanced = contig != page_contig_before
            if contig_advanced:
                await self._drain_ordered_messages(ns)
                self._persist_seq(ns)
            if raw_messages and contig_advanced and contig > 0:
                self._log.debug("client", "group.v2.pull scheduling auto-ack: group=%s ns=%s ack_seq=%d raw_count=%d", group_id, ns, contig, len(raw_messages))
                self._fire_ack("group.v2.ack", {
                    "group_id": group_id, "up_to_seq": contig,
                }, f"V2 群消息 page auto-ack group={group_id}")

            next_after = max(page_max_seq, next_after_seq)
            if not raw_messages or next_after <= next_after_seq or result.get("has_more") is False:
                break
            next_after_seq = next_after

        if page_count >= max_pages:
            self._log.warn("client", "group.v2.pull reached max_pages=%d group=%s after_seq=%d", max_pages, group_id, next_after_seq)

        response["messages"] = decrypted
        response["_contig_before"] = first_contig_before
        response["raw_count"] = total_raw_count
        if latest_seq:
            response["latest_seq"] = max(int(response.get("latest_seq") or 0), latest_seq)
        self._log.debug(
            "client",
            "group.v2.pull done: group=%s requested_after_seq=%d pages=%d raw_count=%d decrypted=%d ns=%s",
            group_id, after_seq, page_count, total_raw_count, len(decrypted), ns,
        )
        return response

    async def _ack_group_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 确认消费。内部方法，由 call("group.ack_messages") 路由调用。"""
        group_id = str(params.get("group_id") or "").strip()
        up_to_seq = int(params.get("msg_seq", 0) or params.get("up_to_seq", 0) or 0)
        ns = f"group:{group_id}"
        seq = up_to_seq or (self._seq_tracker.get_contiguous_seq(ns) if ns else 0)
        if seq <= 0:
            self._log.debug("client", "group.v2.ack skipped: group=%s ns=%s up_to_seq=%s", group_id, ns, up_to_seq)
            return {"acked": 0}
        # ack clamp：永远不发送超过 max_seen_seq 的 up_to_seq
        max_seen = self._seq_tracker.get_max_seen_seq(ns) if ns else 0
        if max_seen > 0 and seq > max_seen:
            self._log.warn(
                "client",
                "_ack_group_v2_internal clamp: group=%s up_to_seq=%d > max_seen=%d, clamp",
                group_id, seq, max_seen,
            )
            seq = max_seen
        self._log.debug("client", "group.v2.ack send: group=%s ns=%s up_to_seq=%d", group_id, ns, seq)
        result = await self.call("group.v2.ack", {"group_id": group_id, "up_to_seq": seq})
        self._log.debug("client", "group.v2.ack ok: group=%s ns=%s requested=%d result=%s", group_id, ns, seq, result)
        return result

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
                _length_prefixed_bytes_key(actor_aid.encode("utf-8"), sign_payload)
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
        if not self._v2_auto_state_management_enabled:
            return
        now = time.time()
        last = self._v2_lazy_propose_triggered.get(group_id, 0.0)
        if now - last < 10.0:
            return
        self._v2_lazy_propose_triggered[group_id] = now
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._v2_auto_propose_state(group_id, leader_delay=True))

    async def _v2_auto_propose_state(self, group_id: str, *, leader_delay: bool = False) -> None:
        if not self._v2_auto_state_management_enabled:
            return
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

            bootstrap_resp = await self.call("group.v2.bootstrap", {
                "group_id": group_id,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
            devices = bootstrap_resp.get("devices", []) if isinstance(bootstrap_resp, dict) else []
            online_admin_set = set(online_admin_aids)
            candidates: list[str] = []
            for dev in devices:
                if not isinstance(dev, dict):
                    continue
                aid = str(dev.get("aid") or "").strip()
                has_device_id, device_id = _v2_device_id_from_device(dev)
                if aid in online_admin_set and has_device_id:
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

            seed = _length_prefixed_text_key(group_id, my_key).encode("utf-8")
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
            if isinstance(parsed, list):
                self._log.debug(
                    "client",
                    "V2 committed state base uses legacy snapshot array, accepting as hash anchor: group=%s sv=%d",
                    group_id,
                    current_sv,
                )
                return True
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
            bootstrap_resp = await self.call("group.v2.bootstrap", {
                "group_id": group_id,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
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
        if not self._v2_auto_state_management_enabled:
            return
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
        if not self._v2_auto_state_management_enabled:
            return
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

        Push-Pull 双重修复机制：
        - Push 带 payload 且解密成功：contiguous_seq 上界 = push_seq（消息已拿到）
        - Push 不带 payload（纯通知）：contiguous_seq 上界 = push_seq - 1（消息还需 pull）
        - Pull 确定下界：server_ack_seq 以下的消息已被消费
        """
        self._log_message_debug("server-push", "_raw.peer.v2.message_received", "message.received", data)
        if not self._v2_session:
            self._log.debug("client", "_on_v2_push_notification skipped: no v2_session")
            return

        # 提取 push 通知中的元数据
        push_seq = data.get("seq") if isinstance(data, dict) else None
        push_from = data.get("from_aid") if isinstance(data, dict) else None
        push_msg_id = data.get("message_id") if isinstance(data, dict) else None
        envelope_json = data.get("envelope_json") if isinstance(data, dict) else None

        ns = f"p2p:{self._aid}" if self._aid else ""
        contig_before = self._seq_tracker.get_contiguous_seq(ns) if ns else 0
        dedup_key = f"p2p_pull:{ns}"
        pull_in_flight = dedup_key in self._gap_fill_done

        self._log.debug(
            "client",
            "_on_v2_push_notification: push_seq=%s push_from=%s push_msg_id=%s has_payload=%s contiguous_seq=%d pull_in_flight=%s",
            push_seq, push_from, push_msg_id, bool(envelope_json), contig_before, pull_in_flight,
        )

        push_seq_int = int(push_seq) if push_seq and isinstance(push_seq, (int, float)) and push_seq > 0 else 0

        # ── Push 修上界：只更新 max_seen_seq，不动 contiguous_seq ──
        # 即使 push_seq 是脏数据（如服务端 bug 导致的 99999），也只影响"已知上界"，
        # 不会污染下界 contiguous_seq，更不会导致 SDK 把脏数据 ack 回服务端。
        if push_seq_int > 0 and ns:
            self._seq_tracker.update_max_seen(ns, push_seq_int)
            if contig_before == push_seq_int:
                self._log.debug(
                    "client",
                    "_on_v2_push_notification: push seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
                    push_seq_int, contig_before,
                )
                return
            contig_before = self._repair_push_contiguous_bound(
                ns, push_seq_int, has_payload=bool(envelope_json), label="_raw.peer.v2.message_received",
            )

        # ── 带 payload 的 push：尝试就地解密 ──
        if envelope_json and push_seq_int > 0 and ns:
            try:
                decrypted = await self._decrypt_v2_message(data)
                if decrypted is not None:
                    # 解密成功：把 push_seq 加入 received_seqs，让 _try_advance 自然推进
                    # （如果 push_seq == contiguous_seq + 1 会自动推进到 push_seq）
                    need_pull = self._seq_tracker.on_message_seq(ns, push_seq_int)
                    published = await self._publish_ordered_message("message.received", ns, push_seq_int, decrypted)
                    new_contig = self._seq_tracker.get_contiguous_seq(ns)
                    if new_contig != contig_before:
                        self._persist_seq(ns)
                    if new_contig > 0 and new_contig != contig_before:
                        # ack clamp：永远不发送超过 max_seen_seq 的 up_to_seq
                        max_seen = self._seq_tracker.get_max_seen_seq(ns)
                        ack_seq = min(new_contig, max_seen) if max_seen > 0 else new_contig
                        self._fire_ack("message.v2.ack", {"up_to_seq": ack_seq}, "V2 P2P push-ack")
                    self._log.debug(
                        "client",
                        "_on_v2_push_notification: push 带 payload 解密成功, contiguous_seq=%d->%d push_seq=%d",
                        contig_before, new_contig, push_seq_int,
                    )
                    if not need_pull and (published or new_contig >= push_seq_int or push_seq_int <= contig_before):
                        return
                    self._log.debug(
                        "client",
                        "_on_v2_push_notification: payload push seq=%d 因空洞挂起，继续 pull 补齐 after_seq=%d",
                        push_seq_int, new_contig,
                    )
                    if pull_in_flight:
                        self._record_pending_p2p_pull(ns, push_seq_int)
                        self._log.debug(
                            "client",
                            "_on_v2_push_notification: payload push seq=%d 已挂起，复用进行中的 pull",
                            push_seq_int,
                        )
                        return
            except Exception as exc:
                self._log.debug("client", "_on_v2_push_notification: push payload 解密失败, fallback to pull: %s", exc)

        # ── 不带 payload 或解密失败：触发 pull ──
        # 关键：push 通知只表示"服务端有 seq=push_seq 的新消息"，
        # 此时消息内容尚未到达本地，绝不能调用 on_message_seq() 推进 contiguous_seq
        # （那会让随后的 pull 用 after_seq=push_seq，跳过这条消息本身导致拉空）。
        # 正确做法：保持 contiguous_seq 不变，用它作为 pull 的 after_seq；
        # pull 成功 + 解密成功后再由 pull 路径推进 contiguous_seq。
        if push_seq_int > 0 and ns:
            # 纯通知：不更新 contiguous_seq，由 pull 结果驱动推进
            self._log.debug(
                "client",
                "_on_v2_push_notification: 纯通知 push_seq=%d > contiguous_seq=%d, 触发 pull(after_seq=%d)",
                push_seq_int, contig_before, contig_before,
            )
            if pull_in_flight:
                self._record_pending_p2p_pull(ns, push_seq_int)
                self._log.debug(
                    "client",
                    "_on_v2_push_notification: pull 已在进行中，仅记录上界 push_seq=%d",
                    push_seq_int,
                )
                return

        self._gap_fill_done[dedup_key] = time.time()

        try:
            await self._pull_v2_internal({})
            new_contig = self._seq_tracker.get_contiguous_seq(ns) if ns else -1
            self._log.debug(
                "client",
                "_on_v2_push_notification pull done: contiguous_seq=%d->%d (push_seq=%s)",
                contig_before, new_contig, push_seq,
            )
        except Exception as exc:
            self._log.warn("client", "V2 push auto-pull failed: %s", exc)
        finally:
            self._gap_fill_done.pop(dedup_key, None)
            self._schedule_pending_p2p_pull_if_needed(ns, reason="push-auto-pull-complete")

    async def _decrypt_v2_message(self, msg: dict[str, Any], *, allow_pending: bool = True) -> dict[str, Any] | None:
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
        self._observe_agent_md_from_envelope(envelope)

        # 确定 spk_id
        recipient_key_source = ""
        if "recipient" in envelope:
            recipient = envelope["recipient"]
            spk_id = recipient.get("spk_id", "")
            recipient_key_source = str(recipient.get("key_source") or "")
        elif "recipients" in envelope:
            spk_id = msg.get("spk_id", "")
            selected_row = None
            if not spk_id:
                recipients = envelope.get("recipients")
                if isinstance(recipients, list):
                    for row in recipients:
                        if (
                            isinstance(row, list)
                            and len(row) >= 6
                            and row[0] == self._aid
                            and (row[1] == self._device_id or row[1] == "")
                        ):
                            selected_row = row
                            spk_id = str(row[5] or "")
                            break
            if selected_row is None:
                recipients = envelope.get("recipients")
                if isinstance(recipients, list):
                    for row in recipients:
                        if (
                            isinstance(row, list)
                            and len(row) >= 6
                            and row[0] == self._aid
                            and (row[1] == self._device_id or row[1] == "")
                        ):
                            selected_row = row
                            break
            if isinstance(selected_row, list) and len(selected_row) >= 4:
                recipient_key_source = str(selected_row[3] or "")
        else:
            spk_id = ""

        aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
        group_id_for_keys = str(msg.get("group_id") or aad.get("group_id") or envelope.get("group_id") or "").strip()
        e2ee_meta = self._v2_thought_e2ee_metadata(envelope)
        undecryptable_event = "group.message_undecryptable" if group_id_for_keys else "message.undecryptable"

        self._log.debug("client", "_decrypt_v2_message: seq=%s spk_id=%s group_id=%s from=%s has_recipient=%s has_recipients=%s",
                        msg.get("seq"), spk_id or "<empty>", group_id_for_keys or "<p2p>",
                        msg.get("from_aid", ""), "recipient" in envelope, "recipients" in envelope)

        try:
            if group_id_for_keys:
                ik_priv, spk_priv = self._v2_session.get_group_decrypt_keys(group_id_for_keys, spk_id)
            else:
                ik_priv, spk_priv = self._v2_session.get_decrypt_keys(spk_id)
        except Exception as exc:
            self._log.warn("client", "V2 decrypt: SPK lookup failed seq=%s spk_id=%s: %s", msg.get("seq"), spk_id, exc)
            event = {
                "message_id":     msg.get("message_id", ""),
                "from":           msg.get("from_aid", ""),
                "to":             msg.get("to", ""),
                "seq":            msg.get("seq"),
                "timestamp":      msg.get("t_server") or msg.get("timestamp"),
                "device_id":      msg.get("device_id", ""),
                "slot_id":        msg.get("slot_id", ""),
                "_decrypt_error": str(exc),
                "_decrypt_stage": "spk_lookup",
                "_envelope_type": envelope.get("type", ""),
                "_suite":         envelope.get("suite", ""),
                "_spk_id":        spk_id,
            }
            self._attach_v2_envelope_metadata(event, e2ee_meta)
            await self._dispatcher.publish(undecryptable_event, event)
            return None
        self._log.debug("client", "_decrypt_v2_message: ik_priv=%d bytes spk_priv=%s",
                        len(ik_priv) if ik_priv else 0, f"{len(spk_priv)} bytes" if spk_priv else "None")

        # 获取 sender IK 公钥（按 sender device_id 精确匹配）
        from_aid = msg.get("from_aid", "")
        sender_device_id = envelope.get("aad", {}).get("from_device", "")
        sender_pub_der = await self._v2_sender_pub_der_from_cache_or_cert(from_aid, sender_device_id)

        if not sender_pub_der:
            self._log.warn("client", "V2 decrypt: no sender IK for %s device=%s", from_aid, sender_device_id)
            if allow_pending:
                self._schedule_v2_sender_ik_pending(
                    msg=msg,
                    envelope=envelope,
                    from_aid=str(from_aid or ""),
                    sender_device_id=str(sender_device_id or ""),
                    group_id=group_id_for_keys,
                )
                return None
            event = {
                "message_id":        msg.get("message_id", ""),
                "from":              from_aid,
                "to":                msg.get("to", ""),
                "seq":               msg.get("seq"),
                "timestamp":         msg.get("t_server") or msg.get("timestamp"),
                "device_id":         msg.get("device_id", ""),
                "slot_id":           msg.get("slot_id", ""),
                "_decrypt_error":    "sender_ik_not_found",
                "_decrypt_stage":    "sender_ik",
                "_envelope_type":    envelope.get("type", ""),
                "_suite":            envelope.get("suite", ""),
                "_sender_device_id": aad.get("from_device", ""),
            }
            self._attach_v2_envelope_metadata(event, e2ee_meta)
            await self._dispatcher.publish(undecryptable_event, event)
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
            event = {
                "message_id":        msg.get("message_id", ""),
                "from":              from_aid,
                "to":                msg.get("to", ""),
                "seq":               msg.get("seq"),
                "timestamp":         msg.get("t_server") or msg.get("timestamp"),
                "device_id":         msg.get("device_id", ""),
                "slot_id":           msg.get("slot_id", ""),
                "_decrypt_error":    str(exc),
                "_decrypt_stage":    "decrypt",
                "_envelope_type":    envelope.get("type", ""),
                "_suite":            envelope.get("suite", ""),
                "_sender_device_id": aad.get("from_device", ""),
            }
            self._attach_v2_envelope_metadata(event, e2ee_meta)
            await self._dispatcher.publish(undecryptable_event, event)
            return None

        if plaintext is None:
            return None

        # SPK 处理：P2P 与 Group 分开。群消息 fallback 到 peer_device_prekey 时，
        # 补注册一次 group SPK；只有真正消费 group_device_prekey 时才轮换该群的 group SPK。
        group_spk_consumed = (
            group_id_for_keys
            and recipient_key_source == "group_device_prekey"
            and self._v2_session.is_last_uploaded_group_spk(group_id_for_keys, spk_id)
        )
        if group_spk_consumed:
            self._schedule_group_spk_rotation(group_id_for_keys, reason="group_spk_consumed")
        elif group_id_for_keys and recipient_key_source == "peer_device_prekey":
            self._schedule_group_spk_registration_after_peer_fallback(group_id_for_keys)
        elif not group_id_for_keys and self._v2_session.is_last_uploaded_spk(spk_id):
            self._log.debug("client", "SPK rotation check: spk_id=%s last_uploaded=%s matched=%s",
                            spk_id, self._v2_session._last_uploaded_spk_id, True)
            async def _do_rotate():
                try:
                    await self._v2_session.rotate_spk(self.call)
                    self._log.debug("client", "V2 SPK rotated after consumption: aid=%s", self._aid)
                except Exception as exc:
                    self._log.warn("client", "V2 SPK rotation failed (non-fatal): %s", exc)
            loop = self._loop or asyncio.get_running_loop()
            loop.create_task(_do_rotate())

        meta = self._v2_thought_e2ee_metadata(envelope)
        result = {
            "message_id": msg.get("message_id", ""),
            "from": from_aid,
            "to": self._aid,
            "seq": msg.get("seq"),
            "t_server": msg.get("t_server"),
            "payload": plaintext,
            "encrypted": True,
            "e2ee": meta,
        }
        direction = str(msg.get("direction") or "").strip()
        if not direction:
            direction = "outbound_sync" if from_aid and from_aid == self._aid else "inbound"
        if direction:
            result["direction"] = direction
        if "device_id" in msg:
            result["device_id"] = msg.get("device_id")
        if "slot_id" in msg:
            result["slot_id"] = msg.get("slot_id")
        self._attach_v2_envelope_metadata(result, meta)
        return result

