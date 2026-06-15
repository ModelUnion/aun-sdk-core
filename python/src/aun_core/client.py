from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import random
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse, urlunparse

import websockets
from cryptography import x509

from ._client import (
    ClientRuntime,
    GroupStateCoordinator,
    IdentityRuntimeManager,
    LifecycleController,
    MessageDeliveryEngine,
    PeerDirectory,
    RpcPipeline,
    V2E2EECoordinator,
)
from .aid import AID
from .agent_md import AgentMdManager
from ._cert_utils import cert_matches_fingerprint, normalize_fingerprint_hex
from .auth import AuthFlow
from .config import AUNConfig, get_device_id, normalize_instance_id, normalize_slot_id, slot_isolation_key
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
from .keystore.local_token_store import LocalTokenStore
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
_MAX_NOTIFY_PAYLOAD_SIZE = 64 * 1024


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

# P1-23: 非幂等方法使用更长超时（35s），避免 SDK 10s 超时 < gateway 30s 处理时间
_NON_IDEMPOTENT_TIMEOUT = 35.0
_NON_IDEMPOTENT_METHODS = frozenset({
    "message.send", "group.send", "group.create", "group.invite",
    "group.kick", "group.remove_member", "group.leave", "group.dissolve",
    "group.update_name", "group.update_avatar", "group.update_announcement",
    "group.update_settings", "group.rotate_epoch",
    "storage.put_object", "storage.delete_object", "storage.get_by_share",
    "storage.create_share_link", "storage.revoke_share_link",
    "storage.create_upload_session", "storage.complete_upload",
    "storage.create_folder", "storage.rename_folder", "storage.move_folder",
    "storage.delete_folder", "storage.move_object", "storage.copy_object",
    "storage.batch_delete", "storage.set_object_meta", "storage.append_object",
    "storage.set_acl", "storage.remove_acl", "storage.set_visibility",
    "storage.issue_token", "storage.revoke_token",
    "storage.create_symlink", "storage.atomic_repoint",
    "storage.rename_symlink", "storage.delete_symlink",
    "storage.fs.mkdir", "storage.fs.remove", "storage.fs.rename", "storage.fs.copy",
    "storage.fs.mount", "storage.fs.approve", "storage.fs.reject", "storage.fs.unmount",
    "storage.fs.invalidate_membership",
    "storage.volume.create", "storage.volume.renew", "storage.volume.expire_due",
    "auth.create_aid", "auth.renew_cert", "auth.rekey",
    "message.thought.put", "group.thought.put",
    "group.add_member", "group.bind_group_aid", "group.complete_transfer",
    "group.resources.put", "group.resources.create_folder",
    "group.resources.rename", "group.resources.move",
    "group.resources.mount_object", "group.resources.update",
    "group.resources.delete",
    "group.resources.namespace_ready", "group.resources.confirm",
    "group.resources.confirm_mount", "group.resources.get_df",
    "group.resources.unmount",
    "group.resources.get_access",
    "group.resources.resolve_access_ticket",
    "collab.create", "collab.submit", "collab.export", "collab.adopt",
    "collab.prune", "collab.unregister",
    "collab.snapshot.create", "collab.snapshot.restore",
    "collab.snapshot.rm", "collab.snapshot.prune",
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

_PUBLIC_CONNECTION_OPTION_KEYS = frozenset({
    "auto_reconnect",
    "connect_timeout",
    "retry_initial_delay",
    "retry_max_delay",
    "retry_max_attempts",
    "heartbeat_interval",
    "call_timeout",
    "connection_kind",
    "short_ttl_ms",
    "extra_info",
    "delivery_mode",
    "background_sync",
})


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


def _build_client_runtime_manager(client: Any) -> AgentMdManager:
    def access_token() -> str:
        identity = client._identity if isinstance(client._identity, dict) else {}
        token = str(identity.get("access_token") or "").strip()
        if token:
            return token
        if isinstance(client._session_params, dict):
            return str(client._session_params.get("access_token") or "").strip()
        return ""

    def trace_context() -> dict[str, Any]:
        return {
            "mode": getattr(client._transport, "_trace_mode", "off"),
            "observer": getattr(client._transport, "_trace_observer", None),
        }

    async def resolve_peer(aid: str, cert_fingerprint: str | None = None) -> AID:
        target = str(aid or "").strip()
        return await client._resolve_peer_aid(target, cert_fingerprint=cert_fingerprint)

    return AgentMdManager(
        client._config_model.aun_path,
        verify_ssl=client._config_model.verify_ssl,
        logger=client._log,
        owner_aid_getter=lambda: client._aid,
        current_aid_getter=lambda: client._current_aid,
        gateway_resolver=lambda aid: client._discover_gateway_for_aid(aid),
        peer_resolver=resolve_peer,
        token_provider=access_token,
        authenticator=client.authenticate,
        trace_context_provider=trace_context,
        discovery_port=client._config_model.discovery_port,
    )


_PEER_CERT_CACHE_TTL = 3600  # 1 小时


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
        raw_config = {}
        if initial_aid_obj:
            raw_config = {
                "aun_path": initial_aid_obj.aun_path,
                "verify_ssl": initial_aid_obj.verify_ssl,
                "debug": initial_aid_obj.debug,
            }
            if initial_aid_obj.root_ca_path:
                raw_config["root_ca_path"] = initial_aid_obj.root_ca_path
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
        self._prekey_replenish_inflight: bool = False
        self._prekey_pending_replenish: int = 0
        # agent.md 存储路径由 AgentMdManager 固定管理为 {aun_path}/AIDs/{aid}/。
        self._agent_md_manager = _build_client_runtime_manager(self)
        # 当前活跃 prekey：只有这个 prekey 被消费时才触发 replenish 上传。
        # connect 成功后上传的 prekey 记录为活跃；历史 prekey 被消费不触发上传。
        self._active_prekey_id: str = ""

        connection_factory = _make_connection_factory(self._config_model.verify_ssl, self._log, net=self._net)
        token_store = LocalTokenStore(
            self._config_model.aun_path,
            logger=self._log,
        )
        self._token_store = token_store
        self._slot_id = normalize_slot_id(initial_aid_obj.slot_id if initial_aid_obj else None)
        self._connect_delivery_mode = _normalize_delivery_mode_config({"mode": "fanout"})
        self._default_connect_delivery_mode = dict(self._connect_delivery_mode)
        self._auth = AuthFlow(
            token_store=token_store,
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
        if initial_aid_obj is not None:
            self._identity = {
                "aid": initial_aid_obj.aid,
                "private_key_pem": initial_aid_obj.private_key_pem,
                "public_key_der_b64": initial_aid_obj.public_key,
                "cert": initial_aid_obj.cert_pem,
            }
            self._auth.set_identity(self._identity)
        self._transport = RPCTransport(
            event_dispatcher=self._dispatcher,
            connection_factory=connection_factory,
            timeout=_DEFAULT_SESSION_OPTIONS["timeouts"]["call"],
            on_disconnect=self._handle_transport_disconnect,
            logger=self._log,
        )
        self._transport.set_meta_observer(self._observe_rpc_meta)
        self._token_refresh_failures = 0  # token 刷新连续失败计数
        # 消息序列号跟踪器（群消息 + P2P 共用，按命名空间隔离）
        self._seq_tracker = SeqTracker()
        self._seq_tracker_context: tuple[str, str, str] | None = None
        self._gap_fill_done: dict[str, float] = {}  # 补洞去重：进行中的 key -> 开始时间戳
        self._gap_fill_active: bool = False  # 当前是否在补洞中（用于标记 pull 来源）
        self._background_rpc_depth: int = 0  # SDK 内部后台任务 depth，不进入业务 RPC 参数
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
        self._background_ack_tasks: set[asyncio.Task] = set()
        self._background_ack_drain_timeout = 1.0

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
        self._v2_auto_state_tasks: set[asyncio.Task] = set()
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
        # 群组消息撤回推送：在线 push 通道，与 pull 双 tombstone 兜底互补（SDK 去重只回调一次）
        self._dispatcher.subscribe("_raw.group.message_recalled", self._on_raw_group_message_recalled)
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
        self._client_runtime = ClientRuntime(self)
        self._identity_runtime = IdentityRuntimeManager(self._client_runtime)
        self._peer_directory = PeerDirectory(self._client_runtime)
        self._lifecycle_controller = LifecycleController(self._client_runtime)
        self._rpc_pipeline = RpcPipeline(self._client_runtime)
        self._message_delivery = MessageDeliveryEngine(self._client_runtime)
        self._v2_e2ee = V2E2EECoordinator(self._client_runtime)
        self._group_state_coordinator = GroupStateCoordinator(self._client_runtime)
        self._storage_vfs = None
        self._message_facade = None
        self._group_facade = None
        self._stream_facade = None
        self._collab_facade = None

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
    def storage(self):
        from .storage import StorageVFS

        if self._storage_vfs is None:
            self._storage_vfs = StorageVFS(self)
        return self._storage_vfs

    @property
    def collab(self):
        from .collab import CollabClient

        if self._collab_facade is None:
            self._collab_facade = CollabClient(self)
        return self._collab_facade

    @property
    def message(self):
        from .facades import MessageFacade

        if self._message_facade is None:
            self._message_facade = MessageFacade(self)
        return self._message_facade

    @property
    def group(self):
        from .facades import GroupFacade

        if self._group_facade is None:
            self._group_facade = GroupFacade(self)
        return self._group_facade

    @property
    def stream(self):
        from .facades import StreamFacade

        if self._stream_facade is None:
            self._stream_facade = StreamFacade(self)
        return self._stream_facade

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
        self._identity_runtime.load_identity(aid)

    def cache_peer(self, aid: AID) -> AID:
        return self._peer_directory.cache_peer(aid)

    def get_peer(self, aid: str) -> AID | None:
        return self._peer_directory.get_peer(aid)

    async def lookup_peer(self, aid: str) -> AID:
        return await self._peer_directory.lookup_peer(aid)

    def peers(self) -> list[AID]:
        return self._peer_directory.peers()

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

    async def _discover_gateway_for_aid(self, aid: str) -> str:
        return await self._peer_directory.discover_gateway_for_aid(aid)

    async def _discover_gateway_for_peer_aid(self, peer_aid: str) -> str:
        return await self._peer_directory.discover_gateway_for_peer_aid(peer_aid)

    async def _resolve_peer_aid(self, aid: str, cert_fingerprint: str | None = None) -> AID:
        return await self._peer_directory.resolve_peer_aid(aid, cert_fingerprint=cert_fingerprint)

    def _observe_rpc_meta(self, meta: dict) -> None:
        """transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。"""
        self._agent_md_manager.observe_rpc_meta(meta, owner_aid=self._aid or "")

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

    def _runtime(self) -> ClientRuntime:
        runtime = ClientRuntime.coerce(self)
        self._client_runtime = runtime
        return runtime

    def _lifecycle(self) -> LifecycleController:
        controller = getattr(self, "_lifecycle_controller", None)
        if controller is None:
            controller = LifecycleController(self._runtime())
            self._lifecycle_controller = controller
        return controller

    def _rpc(self) -> RpcPipeline:
        pipeline = getattr(self, "_rpc_pipeline", None)
        if pipeline is None:
            pipeline = RpcPipeline(self._runtime())
            self._rpc_pipeline = pipeline
        return pipeline

    def _delivery(self) -> MessageDeliveryEngine:
        engine = getattr(self, "_message_delivery", None)
        if engine is None:
            engine = MessageDeliveryEngine(self._runtime())
            self._message_delivery = engine
        return engine

    def _v2_e2ee_coordinator(self) -> V2E2EECoordinator:
        coordinator = getattr(self, "_v2_e2ee", None)
        if coordinator is None:
            coordinator = V2E2EECoordinator(self._runtime())
            self._v2_e2ee = coordinator
        return coordinator

    def _group_state(self) -> GroupStateCoordinator:
        coordinator = getattr(self, "_group_state_coordinator", None)
        if coordinator is None:
            coordinator = GroupStateCoordinator(self._runtime())
            self._group_state_coordinator = coordinator
        return coordinator

    async def authenticate(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._lifecycle().authenticate(options)

    async def connect(self, opts: ConnectionOptions | None = None) -> None:
        return await self._lifecycle().connect(opts)

    async def disconnect(self) -> None:
        return await self._lifecycle().disconnect()

    async def close(self) -> None:
        return await self._lifecycle().close()

    # ── RPC ───────────────────────────────────────────────

    # 需要客户端签名的关键方法（渐进式部署：服务端有签名则验，无签名则放行）
    _SIGNED_METHODS = frozenset({
        "message.send",
        "message.v2.put_peer_pk", "message.v2.bootstrap",
        "message.v2.group_bootstrap", "message.v2.pull",
        "message.v2.ack",
        "group.send",
        "group.recall",
        "group.v2.put_group_pk", "group.v2.bootstrap",
        "group.v2.send", "group.v2.pull", "group.v2.ack",
        "group.v2.propose_state", "group.v2.confirm_state",
        "group.v2.get_proposal",
        "group.kick", "group.add_member",
        "group.leave", "group.remove_member", "group.update_rules",
        "group.update", "group.update_announcement",
        "group.update_join_requirements", "group.set_role",
        "group.transfer_owner", "group.bind_group_aid", "group.complete_transfer",
        "group.review_join_request",
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
        "storage.put_object", "storage.delete_object", "storage.get_by_share",
        "storage.create_share_link", "storage.revoke_share_link",
        "storage.create_upload_session", "storage.complete_upload",
        "storage.create_folder", "storage.rename_folder", "storage.move_folder",
        "storage.delete_folder", "storage.move_object", "storage.copy_object",
        "storage.batch_delete", "storage.set_object_meta", "storage.append_object",
        "storage.set_acl", "storage.remove_acl", "storage.set_visibility",
        "storage.check_access",
        "storage.issue_token", "storage.revoke_token",
        "storage.create_symlink", "storage.atomic_repoint",
        "storage.rename_symlink", "storage.delete_symlink",
        "storage.fs.mkdir", "storage.fs.remove", "storage.fs.rename", "storage.fs.copy",
        "storage.fs.mount", "storage.fs.approve", "storage.fs.reject", "storage.fs.unmount",
        "storage.fs.invalidate_membership",
        "storage.volume.create", "storage.volume.renew", "storage.volume.expire_due",
        "group.resources.put", "group.resources.create_folder",
        "group.resources.rename", "group.resources.move",
        "group.resources.mount_object", "group.resources.update",
        "group.resources.delete",
        "group.resources.namespace_ready", "group.resources.confirm",
        "group.resources.confirm_mount", "group.resources.get_df",
        "group.resources.unmount",
        "group.resources.get_access",
        "group.resources.resolve_access_ticket",
    "collab.create", "collab.submit", "collab.export", "collab.adopt",
    "collab.prune", "collab.unregister",
    "collab.snapshot.create", "collab.snapshot.restore",
    "collab.snapshot.rm", "collab.snapshot.prune",
})

    def _sign_client_operation(self, method: str, params: dict[str, Any]) -> None:
        self._rpc().sign_client_operation(method, params)

    # ── Pull Gate ─────────────────────────────────────────────────

    def _try_acquire_pull_gate(self, key: str) -> int | None:
        return self._rpc().try_acquire_pull_gate(key)

    def _release_pull_gate(self, key: str, token: int | None) -> None:
        self._rpc().release_pull_gate(key, token)

    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None) -> Any:
        return await self._rpc().call(method, params, trace=trace)

    async def create_group(
        self,
        params: dict[str, Any] | None = None,
        *,
        aid_store: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """创建群组；命名群自动生成并落盘 group_aid 身份。

        命名群必须传入 `aid_store=`，因为 AUNClient 不持有 keystore seed。
        匿名群不生成 group_aid 密钥，保持原有 `group.create` 转发语义。
        """
        merged: dict[str, Any] = {}
        if params is not None:
            if not isinstance(params, dict):
                raise TypeError("params must be a dict")
            merged.update(params)
        merged.update({key: value for key, value in kwargs.items() if value is not None})
        group_name = str(merged.get("group_name") or "").strip()
        if not group_name:
            return await self.call("group.create", merged)

        store = aid_store or getattr(self, "_aid_store", None)
        if store is None or not hasattr(store, "_register_flow") or not hasattr(store, "import_group_identity"):
            raise ValueError("create_group named flow requires aid_store with import_group_identity")

        identity = store._register_flow.generate_identity()
        public_key = str(identity.get("public_key_der_b64") or "").strip()
        private_key = str(identity.get("private_key_pem") or "").strip()
        curve = str(identity.get("curve") or "P-256").strip() or "P-256"
        if not public_key or not private_key:
            raise ValueError("create_group generated incomplete group identity")
        merged["public_key"] = public_key
        merged["curve"] = curve

        result = await self.call("group.create", merged)
        group = result.get("group") if isinstance(result, dict) else None
        aid_cert = result.get("aid_cert") if isinstance(result, dict) else None
        group_aid = str((group or {}).get("group_aid") or "").strip()
        cert_pem = str((aid_cert or {}).get("cert") or (aid_cert or {}).get("cert_pem") or "").strip()
        if not group_aid or not cert_pem:
            raise ValueError("create_group response missing group.group_aid or aid_cert.cert")

        imported = store.import_group_identity(
            group_aid,
            private_key_pem=private_key,
            public_key_der_b64=public_key,
            curve=curve,
            cert_pem=cert_pem,
        )
        if not imported.ok:
            message = imported.error.message if imported.error else "unknown error"
            raise ValueError(f"create_group failed to persist group identity: {message}")
        return result

    async def bind_group_aid(
        self,
        params: dict[str, Any] | None = None,
        *,
        aid_store: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """为匿名群补齐 group_aid 身份材料并落盘本地 AIDs。"""
        merged: dict[str, Any] = {}
        if params is not None:
            if not isinstance(params, dict):
                raise TypeError("params must be a dict")
            merged.update(params)
        merged.update({key: value for key, value in kwargs.items() if value is not None})

        store = aid_store or getattr(self, "_aid_store", None)
        if store is None or not hasattr(store, "_register_flow") or not hasattr(store, "import_group_identity"):
            raise ValueError("bind_group_aid requires aid_store with import_group_identity")

        identity = store._register_flow.generate_identity()
        public_key = str(identity.get("public_key_der_b64") or "").strip()
        private_key = str(identity.get("private_key_pem") or "").strip()
        curve = str(identity.get("curve") or "P-256").strip() or "P-256"
        if not public_key or not private_key:
            raise ValueError("bind_group_aid generated incomplete group identity")
        merged["public_key"] = public_key
        merged["curve"] = curve

        result = await self.call("group.bind_group_aid", merged)
        group = result.get("group") if isinstance(result, dict) else None
        aid_cert = result.get("aid_cert") if isinstance(result, dict) else None
        group_aid = str((group or {}).get("group_aid") or "").strip()
        cert_pem = str((aid_cert or {}).get("cert") or (aid_cert or {}).get("cert_pem") or "").strip()
        if not group_aid or not cert_pem:
            raise ValueError("bind_group_aid response missing group.group_aid or aid_cert.cert")

        imported = store.import_group_identity(
            group_aid,
            private_key_pem=private_key,
            public_key_der_b64=public_key,
            curve=curve,
            cert_pem=cert_pem,
        )
        if not imported.ok:
            message = imported.error.message if imported.error else "unknown error"
            raise ValueError(f"bind_group_aid failed to persist group identity: {message}")
        return result

    async def start_group_transfer(
        self,
        params: dict[str, Any] | None = None,
        *,
        aid_store: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """发起 group-storage 群主转让：旧群主用旧 group_aid 私钥签名授权，传入 transfer_auth。

        aid_store 必须包含当前 group_aid 私钥（建命名群时落盘）。
        返回服务端的 pending_rekey 响应。
        """
        merged: dict[str, Any] = {}
        if params is not None:
            if not isinstance(params, dict):
                raise TypeError("params must be a dict")
            merged.update(params)
        merged.update({key: value for key, value in kwargs.items() if value is not None})

        group_id = str(merged.get("group_id") or "").strip()
        new_owner = str(merged.get("new_owner") or "").strip()
        if not group_id or not new_owner:
            raise ValueError("start_group_transfer requires group_id and new_owner")
        store = aid_store or getattr(self, "_aid_store", None)
        if store is None or not hasattr(store, "load"):
            raise ValueError("start_group_transfer requires aid_store with group_aid private key")

        group_aid = str(merged.get("group_aid") or "").strip()
        if not group_aid:
            info = await self.call("group.get", {"group_id": group_id})
            group_aid = str((info.get("group") or info or {}).get("group_aid") or "").strip()
        if not group_aid:
            raise ValueError("start_group_transfer: unable to determine group_aid")

        loaded = store.load(group_aid)
        if not getattr(loaded, "ok", False) or not getattr(loaded, "data", None):
            raise ValueError(f"start_group_transfer: group_aid identity not found: {group_aid}")
        aid_obj = loaded.data.get("aid") if isinstance(loaded.data, dict) else None
        if aid_obj is None or not getattr(aid_obj, "private_key_pem", None):
            raise ValueError(f"start_group_transfer: group_aid has no private key: {group_aid}")

        nonce = uuid.uuid4().hex
        issued_ms = int(time.time() * 1000)
        canonical = "|".join([
            "aun-group-owner-transfer-v1",
            group_id.strip().lower(),
            group_aid.strip().lower(),
            new_owner.strip().lower(),
            nonce,
            str(issued_ms),
        ])
        signed = aid_obj.sign(canonical)
        if not signed.ok:
            raise ValueError(f"start_group_transfer: sign failed: {signed.error}")
        # AID.sign 返回标准 base64，服务端验签用 urlsafe base64；两者仅 +/- _ 差异，后端已 urlsafe_b64decode 且 pad_base64 处理，直接传
        sig_b64 = signed.data["signature"]

        merged["group_aid"] = group_aid
        merged["transfer_auth"] = {"nonce": nonce, "issued_ms": issued_ms, "signature": sig_b64}
        return await self.call("group.transfer_owner", merged)

    async def complete_group_transfer(
        self,
        params: dict[str, Any] | None = None,
        *,
        aid_store: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """完成 group-storage 群主转让 rekey，并落盘新的 group_aid 身份。"""
        merged: dict[str, Any] = {}
        if params is not None:
            if not isinstance(params, dict):
                raise TypeError("params must be a dict")
            merged.update(params)
        merged.update({key: value for key, value in kwargs.items() if value is not None})

        store = aid_store or getattr(self, "_aid_store", None)
        if store is None or not hasattr(store, "_register_flow") or not hasattr(store, "import_group_identity"):
            raise ValueError("complete_group_transfer requires aid_store with import_group_identity")

        identity = store._register_flow.generate_identity()
        public_key = str(identity.get("public_key_der_b64") or "").strip()
        private_key = str(identity.get("private_key_pem") or "").strip()
        curve = str(identity.get("curve") or "P-256").strip() or "P-256"
        if not public_key or not private_key:
            raise ValueError("complete_group_transfer generated incomplete group identity")
        group_id = str(merged.get("group_id") or "").strip()
        if not group_id:
            raise ValueError("complete_group_transfer requires group_id")
        group_aid = str(merged.get("group_aid") or "").strip()
        if not group_aid:
            info = await self.call("group.get", {"group_id": group_id})
            group_info = info.get("group") if isinstance(info, dict) else {}
            group_aid = str(group_info.get("group_aid") or "").strip() if isinstance(group_info, dict) else ""
        if not group_aid:
            raise ValueError("complete_group_transfer: unable to determine group_aid")
        current = self.current_aid
        new_owner = str(getattr(current, "aid", "") or "").strip()
        if current is None or not new_owner or not current.is_private_key_valid():
            raise ValueError("complete_group_transfer requires current new-owner AID with private key")
        nonce = uuid.uuid4().hex
        issued_ms = int(time.time() * 1000)
        public_key_hash = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
        canonical = "|".join([
            "aun-group-owner-transfer-accept-v1",
            group_id.strip().lower(),
            group_aid.strip().lower(),
            new_owner.strip().lower(),
            public_key_hash,
            nonce,
            str(issued_ms),
        ])
        signed = current.sign(canonical)
        if not signed.ok:
            raise ValueError(f"complete_group_transfer: accept sign failed: {signed.error}")
        merged["group_aid"] = group_aid
        merged["public_key"] = public_key
        merged["curve"] = curve
        merged["transfer_accept"] = {
            "nonce": nonce,
            "issued_ms": issued_ms,
            "signature": signed.data["signature"],
        }

        result = await self.call("group.complete_transfer", merged)
        result_map = result if isinstance(result, dict) else {}
        group = result_map.get("group") if isinstance(result_map.get("group"), dict) else {}
        aid_cert = result_map.get("aid_cert") if isinstance(result_map.get("aid_cert"), dict) else {}
        group_aid = str(group.get("group_aid") or result_map.get("group_aid") or "").strip()
        cert_pem = str(
            aid_cert.get("cert")
            or aid_cert.get("cert_pem")
            or result_map.get("cert")
            or result_map.get("cert_pem")
            or ""
        ).strip()
        if not group_aid or not cert_pem:
            raise ValueError("complete_group_transfer response missing group.group_aid or aid_cert.cert")

        imported = store.import_group_identity(
            group_aid,
            private_key_pem=private_key,
            public_key_der_b64=public_key,
            curve=curve,
            cert_pem=cert_pem,
        )
        if not imported.ok:
            message = imported.error.message if imported.error else "unknown error"
            raise ValueError(f"complete_group_transfer failed to persist group identity: {message}")
        return result

    @staticmethod
    def _notify_params_size_ok(params: dict[str, Any]) -> bool:
        try:
            return len(json.dumps(params, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= _MAX_NOTIFY_PAYLOAD_SIZE
        except Exception:
            return False

    @staticmethod
    def _validate_notify_event_method(method: str) -> str:
        method = str(method or "").strip()
        if not method.startswith("event/app.") or len(method) <= len("event/app."):
            raise ValidationError("routed notify method must be event/app.*")
        return method

    @staticmethod
    def _normalize_notify_ttl(ttl_ms: int | None) -> int | None:
        if ttl_ms is None:
            return None
        try:
            ttl = int(ttl_ms)
        except (TypeError, ValueError) as exc:
            raise ValidationError("ttl_ms must be an integer") from exc
        if ttl < 0 or ttl > 60000:
            raise ValidationError("ttl_ms must be between 0 and 60000")
        return ttl

    async def notify(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        to: str | None = None,
        group_id: str | None = None,
        device_id: str | None = None,
        slot_id: str | None = None,
        ttl_ms: int | None = None,
    ) -> None:
        if params is not None and not isinstance(params, dict):
            raise ValidationError("notify params must be a dict")
        payload = dict(params or {})
        if not self._notify_params_size_ok(payload):
            raise ValidationError("notify payload is too large")
        target_aid = str(to or "").strip()
        target_group_id = str(group_id or "").strip()
        target_device_id = str(device_id or "").strip()
        target_slot_id = str(slot_id or "").strip()
        ttl = self._normalize_notify_ttl(ttl_ms)

        if target_aid and target_group_id:
            raise ValidationError("notify() cannot set both to and group_id")
        if target_slot_id and not target_device_id:
            raise ValidationError("slot_id requires device_id for notify target")

        if target_aid:
            event_method = self._validate_notify_event_method(method)
            target: dict[str, Any] = {"type": "aid", "aid": target_aid}
            if target_device_id:
                target["device_id"] = target_device_id
            if target_slot_id:
                target["slot_id"] = target_slot_id
            route_params: dict[str, Any] = {
                "target": target,
                "deliver": {"method": event_method, "params": payload},
            }
            if ttl is not None:
                route_params["ttl_ms"] = ttl
            await self._transport.notify("notification/route", route_params)
            return

        if target_group_id:
            event_method = self._validate_notify_event_method(method)
            normalized_group_id = _normalize_group_id(target_group_id)
            if not normalized_group_id:
                raise ValidationError("group_id is required for group notify")
            route_params = {
                "group_id": normalized_group_id,
                "deliver": {"method": event_method, "params": payload},
            }
            if ttl is not None:
                route_params["ttl_ms"] = ttl
            await self._transport.notify("notification/group.route", route_params)
            return

        if target_device_id or target_slot_id:
            raise ValidationError("device_id and slot_id require to")
        direct_method = str(method or "").strip()
        if not direct_method.startswith("notification/"):
            raise ValidationError("direct notify method must start with notification/")
        await self._transport.notify(direct_method, payload)

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
        return self._rpc().merge_instance_protected_headers(method, params)

    def _cert_sha256_fingerprint(self, cert_pem: bytes | str | None) -> str:
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
        return self._delivery().fire_ack(method, params, label)

    async def _await_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        return await self._delivery().await_ack(method, params, label)

    def _clamp_ack_params(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return self._delivery().clamp_ack_params(method, params)

    async def _safe_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        return await self._delivery().safe_ack(method, params, label)

    async def _on_raw_message_received(self, data: Any) -> None:
        return await self._delivery().on_raw_message_received(data)

    async def _process_and_publish_message(self, data: Any) -> None:
        return await self._delivery().process_and_publish_message(data)

    async def _process_and_publish_message_inner(self, data: Any) -> None:
        return await self._delivery().process_and_publish_message_inner(data)

    async def _on_raw_group_message_created(self, data: Any) -> None:
        return await self._delivery().on_raw_group_message_created(data)

    async def _on_raw_group_message_created_inner(self, data: Any) -> None:
        return await self._delivery().on_raw_group_message_created_inner(data)

    async def _on_raw_group_v2_message_created(self, data: Any) -> None:
        return await self._delivery().on_raw_group_v2_message_created(data)

    async def _on_raw_group_message_recalled(self, data: Any) -> None:
        return await self._delivery().on_raw_group_message_recalled(data)

    def _enqueue_online_unread_hint(self, data: dict[str, Any]) -> None:
        return self._delivery().enqueue_online_unread_hint(data)

    async def _drain_online_unread_hints(self) -> None:
        return await self._delivery().drain_online_unread_hints()

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
            await self._delivery().handle_group_changed_event(data, group_id)

            self._log.debug("client", "_on_raw_group_changed exit: elapsed=%.3fs group=%s action=%s", time.time() - _t_start, group_id, action)
        else:
            await self._delivery().publish_ordered_group_changed(data, source="legacy")
            self._log.debug("client", "_on_raw_group_changed exit (non-dict): elapsed=%.3fs", time.time() - _t_start)

    def _cleanup_dissolved_group(self, group_id: str) -> None:
        """群组解散后清理本地 V2 缓存、seq_tracker 和有序队列运行态。"""
        group_id = str(group_id or "").strip()
        if not group_id:
            return
        self._v2_bootstrap_cache.pop(f"group:{group_id}", None)
        self._v2_group_security_levels.pop(group_id, None)
        self._seq_tracker.remove_namespace(f"group:{group_id}")
        self._seq_tracker.remove_namespace(f"group_event:{group_id}")
        self._delivery().save_seq_tracker_state()

        for key in list(self._gap_fill_done):
            if group_id in key:
                self._gap_fill_done.pop(key, None)

        self._pushed_seqs.pop(f"group:{group_id}", None)
        self._pushed_seqs.pop(f"group_event:{group_id}", None)
        self._pending_ordered().pop(f"group:{group_id}", None)
        self._pending_ordered().pop(f"group_event:{group_id}", None)
        self._log.info("client", "cleaned up dissolved group local state: group=%s", group_id)

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
        return await self._group_state().on_group_state_committed(data)

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
            if expected_fp:
                if not cert_matches_fingerprint(cert_obj, expected_fp):
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
        return await self._delivery().fill_group_event_gap(group_id)

    async def _fill_group_event_gap_inner(self, group_id: str, ns: str) -> None:
        return await self._delivery().fill_group_event_gap_inner(group_id, ns)

    async def _fill_p2p_gap(self) -> None:
        return await self._delivery().fill_p2p_gap()

    async def _fill_p2p_gap_inner(self, ns: str) -> None:
        return await self._delivery().fill_p2p_gap_inner(ns)

    def _mark_published_seq(self, ns: str, seq: int) -> None:
        return self._delivery().mark_published_seq(ns, seq)

    def _is_published_seq(self, ns: str, seq: int) -> bool:
        return self._delivery().is_published_seq(ns, seq)

    def _is_pending_ordered_seq(self, ns: str, seq: int) -> bool:
        return self._delivery().is_pending_ordered_seq(ns, seq)

    def _pending_ordered(self) -> dict[str, dict[int, tuple[str, Any]]]:
        return self._delivery().pending_ordered()

    def _record_pending_p2p_pull(self, ns: str, seq: int) -> None:
        return self._delivery().record_pending_p2p_pull(ns, seq)

    def _schedule_pending_p2p_pull_if_needed(self, ns: str, *, reason: str) -> bool:
        return self._delivery().schedule_pending_p2p_pull_if_needed(ns, reason=reason)

    def _enqueue_ordered_message(self, ns: str, event: str, seq: int, payload: Any) -> None:
        return self._delivery().enqueue_ordered_message(ns, event, seq, payload)

    @staticmethod
    def _is_instance_scoped_message_event(event: str) -> bool:
        return MessageDeliveryEngine.is_instance_scoped_message_event(event)

    def _attach_current_instance_context(self, payload: Any) -> Any:
        return self._delivery().attach_current_instance_context(payload)

    def _normalize_published_message_payload(self, event: str, payload: Any) -> Any:
        return self._delivery().normalize_published_message_payload(event, payload)

    @classmethod
    def _debug_json(cls, value: Any) -> str:
        return MessageDeliveryEngine.debug_json(value)

    @staticmethod
    def _message_payload_for_debug(message: Any) -> Any:
        return MessageDeliveryEngine.message_payload_for_debug(message)

    @staticmethod
    def _message_envelope_fields_for_debug(message: Any) -> Any:
        return MessageDeliveryEngine.message_envelope_fields_for_debug(message)

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
        return self._delivery().log_message_debug(
            stage,
            source,
            event,
            message,
            payload_override=payload_override,
            extra=extra,
        )

    def _log_app_message_publish(self, event: str, payload: Any, source: str) -> None:
        return self._delivery().log_app_message_publish(event, payload, source)

    async def _publish_app_event(self, event: str, payload: Any, *, source: str = "direct") -> None:
        return await self._delivery().publish_app_event(event, payload, source=source)

    def _message_targets_current_instance(self, message: Any) -> bool:
        return self._delivery().message_targets_current_instance(message)

    async def _drain_ordered_messages(self, ns: str, *, before_seq: int | None = None) -> None:
        return await self._delivery().drain_ordered_messages(ns, before_seq=before_seq)

    async def _publish_ordered_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        return await self._delivery().publish_ordered_message(event, ns, seq, payload)

    async def _publish_pulled_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        return await self._delivery().publish_pulled_message(event, ns, seq, payload)

    def _prune_pushed_seqs(self, ns: str) -> None:
        return self._delivery().prune_pushed_seqs(ns)

    def _enforce_pushed_seqs_limit(self, ns: str) -> None:
        return self._delivery().enforce_pushed_seqs_limit(ns)

    def _v2_pending_sender_ik_message_key(self, msg: dict[str, Any], group_id: str) -> str:
        return self._v2_e2ee_coordinator().pending_sender_ik_message_key(msg, group_id)

    def _v2_pending_sender_ik_fetch_key(self, from_aid: str, sender_device_id: str, group_id: str) -> str:
        return self._v2_e2ee_coordinator().pending_sender_ik_fetch_key(from_aid, sender_device_id, group_id)

    @staticmethod
    def _v2_pub_der_matches_fingerprint(pub_der: bytes, cert_fingerprint: str | None) -> bool:
        expected = str(cert_fingerprint or "").strip().lower()
        if not expected:
            return True
        if not expected.startswith("sha256:"):
            return False
        expected_hex = expected.split(":", 1)[1]
        if len(expected_hex) not in (16, 64) or any(ch not in "0123456789abcdef" for ch in expected_hex):
            return False
        spki_hex = hashlib.sha256(pub_der).hexdigest()
        if len(expected_hex) == 16:
            return spki_hex[:16] == expected_hex
        return spki_hex == expected_hex

    async def _v2_sender_pub_der_from_cache_or_cert(
        self,
        from_aid: str,
        sender_device_id: str,
        cert_fingerprint: str | None = None,
    ) -> bytes | None:
        """只查本地 IK 缓存和独立 PKI HTTP 证书，不在解密栈里调用 bootstrap RPC。"""
        if not self._v2_session or not from_aid:
            return None
        sender_pub_der = self._v2_session.get_peer_ik(from_aid, sender_device_id)
        if sender_pub_der and self._v2_pub_der_matches_fingerprint(sender_pub_der, cert_fingerprint):
            return sender_pub_der
        try:
            cert_pem = await asyncio.wait_for(self._fetch_peer_cert(from_aid, cert_fingerprint), timeout=3.0)
            if not cert_pem:
                return None
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization as _ser
            cert = x509.load_pem_x509_certificate(cert_pem)
            sender_pub_der = cert.public_key().public_bytes(
                encoding=_ser.Encoding.DER,
                format=_ser.PublicFormat.SubjectPublicKeyInfo,
            )
            if not self._v2_pub_der_matches_fingerprint(sender_pub_der, cert_fingerprint):
                return None
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
        return self._v2_e2ee_coordinator().schedule_sender_ik_pending(
            msg=msg,
            envelope=envelope,
            from_aid=from_aid,
            sender_device_id=sender_device_id,
            group_id=group_id,
        )

    def _schedule_v2_sender_ik_fetch(self, from_aid: str, sender_device_id: str, group_id: str) -> None:
        return self._v2_e2ee_coordinator().schedule_sender_ik_fetch(from_aid, sender_device_id, group_id)

    async def _resolve_v2_sender_ik_pending(
        self,
        from_aid: str,
        sender_device_id: str,
        group_id: str,
        fetch_key: str,
    ) -> None:
        return await self._v2_e2ee_coordinator().resolve_sender_ik_pending(
            from_aid,
            sender_device_id,
            group_id,
            fetch_key,
        )

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
        cert_obj = _x509.load_pem_x509_certificate(cert_bytes)

        expected_fp = str(cert_fingerprint or "").strip().lower()
        if expected_fp:
            if not normalize_fingerprint_hex(expected_fp):
                raise ValidationError(f"unsupported cert_fingerprint format for {aid}: {expected_fp[:24]}")
            if not cert_matches_fingerprint(cert_obj, expected_fp):
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
        if expected_fp:
            self._cert_cache[self._cert_cache_key(aid, expected_fp)] = cached
        else:
            bare_key = self._cert_cache_key(aid, None)
            self._cert_cache[bare_key] = cached
        _debug_group_e2ee(
            "peer_cert_cached",
            aid=self._aid or "-",
            peer=aid,
            fp=expected_fp or "-",
            source=source,
            cache_key=self._cert_cache_key(aid, expected_fp or None),
        )
        try:
            self._token_store.save_cert(
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
        return await self._v2_e2ee_coordinator().build_target_from_device(
            dev,
            aid=aid,
            device_id=device_id,
            role=role,
            default_key_source=default_key_source,
        )

    def _get_verified_peer_cert(self, aid: str, cert_fingerprint: str | None = None) -> str | None:
        """获取经过 PKI 验证的 peer 证书（仅信任内存缓存中已验证的证书）。

        零信任要求：只返回经 _fetch_peer_cert 完整 PKI 验证后缓存的证书，
        不直接信任 keystore 中可能由恶意服务端注入的证书。
        """
        now = time.time()
        normalized_fp = str(cert_fingerprint or "").strip().lower()
        cache_key = self._cert_cache_key(aid, cert_fingerprint)
        def _cert_text(entry: _CachedPeerCert) -> str:
            return entry.cert_bytes.decode("utf-8") if isinstance(entry.cert_bytes, bytes) else str(entry.cert_bytes)

        def _cached_matches(entry: _CachedPeerCert) -> bool:
            if not normalized_fp:
                return True
            try:
                cert_obj = x509.load_pem_x509_certificate(_cert_text(entry).encode("utf-8"))
                return cert_matches_fingerprint(cert_obj, normalized_fp)
            except Exception:
                return False

        _debug_group_e2ee(
            "verified_peer_cert_enter",
            aid=self._aid or "-",
            peer=aid,
            fp=normalized_fp or "-",
            cache_key=cache_key,
            cache_size=len(self._cert_cache),
        )
        cached = self._cert_cache.get(cache_key)
        if cached and now < cached.validated_at + _PEER_CERT_CACHE_TTL * 2 and _cached_matches(cached):
            _debug_group_e2ee(
                "verified_peer_cert_hit_exact",
                aid=self._aid or "-",
                peer=aid,
                fp=normalized_fp or "-",
                cache_key=cache_key,
            )
            return _cert_text(cached)
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
            if bare_cached and now < bare_cached.validated_at + _PEER_CERT_CACHE_TTL * 2 and _cached_matches(bare_cached):
                _debug_group_e2ee(
                    "verified_peer_cert_hit_bare",
                    aid=self._aid or "-",
                    peer=aid,
                    fp=normalized_fp or "-",
                    cache_key=bare_key,
                )
                return _cert_text(bare_cached)
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
            if now < entry.validated_at + _PEER_CERT_CACHE_TTL * 2 and _cached_matches(entry):
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
            return _cert_text(entry)
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
        return await self._lifecycle().connect_once(params, allow_reauth=allow_reauth)

    def _resolve_gateway(self, params: dict[str, Any]) -> str:
        return self._lifecycle().resolve_gateway(params)

    def _resolve_gateways(self, params: dict[str, Any]) -> list[str]:
        return self._lifecycle().resolve_gateways(params)

    @staticmethod
    def _is_internal_only_method(method: str) -> bool:
        return method in _INTERNAL_ONLY_METHODS

    # ── 内部：后台任务 ────────────────────────────────────

    def _start_background_tasks(self) -> None:
        self._lifecycle().start_background_tasks()

    async def _stop_background_tasks(self) -> None:
        return await self._lifecycle().stop_background_tasks()

    def _start_heartbeat_task(self) -> None:
        self._lifecycle().start_heartbeat_task()

    def _start_token_refresh_task(self) -> None:
        self._lifecycle().start_token_refresh_task()

    async def _heartbeat_loop(self) -> None:
        return await self._lifecycle().heartbeat_loop()

    def _apply_server_heartbeat_interval(self, raw: Any, *, source: str) -> None:
        self._lifecycle().apply_server_heartbeat_interval(raw, source=source)

    async def _token_refresh_loop(self) -> None:
        return await self._lifecycle().token_refresh_loop()

    def _validate_message_recipient(self, to_aid: Any) -> None:
        if not str(to_aid or "").strip():
            raise ValidationError("message.send requires a non-empty 'to' (recipient AID)")
        if _is_group_service_aid(to_aid):
            raise ValidationError("message.send receiver cannot be group.{issuer}; use group.send instead")

    def _normalize_outbound_message_payload(self, params: dict[str, Any], *, method: str = "") -> None:
        self._rpc().normalize_outbound_message_payload(params, method=method)

    def _should_skip_client_signature(self, method: str, params: dict[str, Any]) -> bool:
        return self._rpc().should_skip_client_signature(method, params)

    def _should_skip_event_signature(self, event: dict[str, Any]) -> bool:
        return self._rpc().should_skip_event_signature(event)

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
        self._rpc().validate_outbound_call(method, params)

    def _inject_message_cursor_context(self, method: str, params: dict[str, Any]) -> None:
        self._rpc().inject_message_cursor_context(method, params)

    def _group_cursor_targets_current_instance(self, params: dict[str, Any]) -> bool:
        return self._rpc().group_cursor_targets_current_instance(params)

    def _restore_seq_tracker_state(self) -> None:
        return self._delivery().restore_seq_tracker_state()

    def _migrate_seq_state_group_ids(self, state: dict[str, int]) -> dict[str, int]:
        return self._delivery().migrate_seq_state_group_ids(state)

    def _current_seq_tracker_context(self) -> tuple[str, str, str] | None:
        return self._delivery().current_seq_tracker_context()

    def _reset_seq_tracking_state(self) -> None:
        return self._delivery().reset_seq_tracking_state()

    def _refresh_seq_tracking_context(self) -> None:
        return self._delivery().refresh_seq_tracking_context()

    def _persist_seq(self, ns: str, *, force_seq: int | None = None) -> None:
        return self._delivery().persist_seq(ns, force_seq=force_seq)

    def _persist_repaired_seq(self, ns: str) -> None:
        return self._delivery().persist_repaired_seq(ns)

    def _repair_push_contiguous_bound(self, ns: str, push_seq: int, *, has_payload: bool, label: str) -> int:
        return self._delivery().repair_push_contiguous_bound(ns, push_seq, has_payload=has_payload, label=label)

    def _save_seq_tracker_state(self) -> None:
        return self._delivery().save_seq_tracker_state()

    # ── 内部：断线重连 ────────────────────────────────────

    # 不重连 close code 集合：客户端/认证/权限错误，重连无意义
    # 4014: 短连接 idle TTL 兜底（不重连）
    # 4015: 长连接配额超限被踢（aid_device_slot / aid_devices）
    _NO_RECONNECT_CODES = frozenset({4001, 4003, 4008, 4009, 4010, 4011, 4012, 4013, 4014, 4015})

    async def _on_gateway_disconnect(self, data: Any) -> None:
        return await self._lifecycle().on_gateway_disconnect(data)

    async def _handle_transport_disconnect(self, error: Exception | None, close_code: int | None = None) -> None:
        return await self._lifecycle().handle_transport_disconnect(error, close_code=close_code)

    async def _reconnect_loop(self, server_initiated: bool = False) -> None:
        return await self._lifecycle().reconnect_loop(server_initiated)

    async def _reconnect_sleep(self, delay: float) -> None:
        return await self._lifecycle().reconnect_sleep(delay)

    # ── 内部：参数处理 ────────────────────────────────────

    def _normalize_connect_params(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._lifecycle().normalize_connect_params(params)

    def _build_session_options(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._lifecycle().build_session_options(params)

    def _sync_identity_after_connect(self, access_token: str) -> None:
        aid = ""
        identity = self._identity if isinstance(self._identity, dict) else None
        if identity is not None:
            aid = str(identity.get("aid") or self._aid or "")
            identity["access_token"] = access_token
            identity["aid"] = aid
            self._identity = identity
        else:
            aid = str(self._aid or "")
        if not aid:
            return
        self._aid = aid
        updater = getattr(self._token_store, "update_instance_state", None)
        if not callable(updater):
            return

        def _merge(current: dict[str, Any]) -> dict[str, Any]:
            current["access_token"] = access_token
            return current

        updater(aid, self._device_id, self._slot_id, _merge)

    async def _invoke_reconnect_connect_once(self) -> None:
        return await self._lifecycle().invoke_reconnect_connect_once()

    @staticmethod
    def _should_retry_reconnect(error: Exception) -> bool:
        return LifecycleController.should_retry_reconnect_error(error)

    # ── V2 E2EE ──────────────────────────────────────────────

    _V2_BOOTSTRAP_TTL = 3600  # 发送端 bootstrap 缓存 1 小时

    _V2_SIG_CACHE_TTL = 3600  # 验签结果缓存 1 小时
    _V2_SIG_CACHE_MAX = 16384

    async def _init_v2_session(self) -> None:
        return await self._v2_e2ee_coordinator().init_v2_session()

    def _schedule_group_spk_registration(self, group_id: str, *, reason: str) -> None:
        return self._v2_e2ee_coordinator().schedule_group_spk_registration(group_id, reason=reason)

    def _schedule_group_spk_rotation(self, group_id: str, *, reason: str) -> None:
        return self._v2_e2ee_coordinator().schedule_group_spk_rotation(group_id, reason=reason)

    def _schedule_group_spk_registration_after_peer_fallback(self, group_id: str) -> None:
        return self._v2_e2ee_coordinator().schedule_group_spk_registration_after_peer_fallback(group_id)

    async def _send_encrypted_v2(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。

        内部方法，由 call("message.send") 拦截路由调用。
        params 中需要 to（目标 AID）和 payload（业务 payload）。
        """
        return await self._v2_e2ee_coordinator().send_encrypted_v2(params)

    async def _pull_v2_internal(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """V2 P2P 拉取并解密消息。内部方法，由 call("message.pull") 路由调用。"""
        return await self._v2_e2ee_coordinator().pull_v2_internal(params)

    async def _ack_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 确认消费 + 自检销毁旧 SPK。内部方法，由 call("message.ack") 路由调用。"""
        return await self._v2_e2ee_coordinator().ack_v2_internal(params)

    # ── V2 Group E2EE API ─────────────────────────────────────────

    _V2_GROUP_BOOTSTRAP_TTL = 3600

    async def _send_group_encrypted_v2(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 加密发送。内部方法，由 call("group.send") 路由调用。"""
        return await self._v2_e2ee_coordinator().send_group_encrypted_v2(params)

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
        return await self._v2_e2ee_coordinator().build_v2_p2p_envelope(
            to=to,
            payload=payload,
            message_id=message_id,
            timestamp=timestamp,
            use_cache=use_cache,
            protected_headers=protected_headers,
            context=context,
        )

    async def _put_message_thought_encrypted_v2(self, params: dict[str, Any]) -> Any:
        """V2 P2P thought.put：使用 V2 多设备 wrap envelope。

        服务端仍走 message.thought.put（内存 KV），envelope 透传，由接收端单设备解密。
        """
        return await self._v2_e2ee_coordinator().put_message_thought_encrypted_v2(params)

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
        return await self._v2_e2ee_coordinator().build_v2_group_envelope(
            group_id=group_id,
            payload=payload,
            message_id=message_id,
            timestamp=timestamp,
            use_cache=use_cache,
            protected_headers=protected_headers,
            context=context,
        )

    async def _put_group_thought_encrypted_v2(self, params: dict[str, Any]) -> Any:
        """V2 Group thought.put：多设备 wrap envelope。"""
        return await self._v2_e2ee_coordinator().put_group_thought_encrypted_v2(params)

    async def _decrypt_group_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        return await self._v2_e2ee_coordinator().decrypt_group_thoughts(result)

    async def _decrypt_message_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        return await self._v2_e2ee_coordinator().decrypt_message_thoughts(result)

    @staticmethod
    def _is_v2_thought_envelope(payload: dict[str, Any], *, group: bool) -> bool:
        return V2E2EECoordinator.is_v2_thought_envelope(payload, group=group)

    @staticmethod
    def _is_encrypted_thought_payload(payload: dict[str, Any]) -> bool:
        return V2E2EECoordinator.is_encrypted_thought_payload(payload)

    def _v2_thought_e2ee_metadata(self, envelope: dict[str, Any]) -> dict[str, Any]:
        return self._v2_e2ee_coordinator().v2_thought_e2ee_metadata(envelope)

    @staticmethod
    def _attach_v2_envelope_metadata(message: dict[str, Any], meta: dict[str, Any]) -> None:
        return V2E2EECoordinator.attach_v2_envelope_metadata(message, meta)

    @staticmethod
    def _attach_gateway_proximity(message: dict[str, Any], source: Any) -> None:
        return V2E2EECoordinator.attach_gateway_proximity(message, source)

    def _attach_v2_envelope_metadata_from_source(self, message: dict[str, Any], source: Any) -> None:
        return self._v2_e2ee_coordinator().attach_v2_envelope_metadata_from_source(message, source)

    @staticmethod
    def _truthy_bool(value: Any) -> bool:
        return V2E2EECoordinator.truthy_bool(value)

    @staticmethod
    def _is_encrypted_envelope_payload(payload: Any) -> bool:
        return V2E2EECoordinator.is_encrypted_envelope_payload(payload)

    def _encrypted_push_envelope(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        return self._v2_e2ee_coordinator().encrypted_push_envelope(msg)

    def _is_encrypted_push_message(self, msg: dict[str, Any]) -> bool:
        return self._v2_e2ee_coordinator().is_encrypted_push_message(msg)

    @staticmethod
    def _is_v2_encrypted_envelope_payload(envelope: dict[str, Any] | None) -> bool:
        return V2E2EECoordinator.is_v2_encrypted_envelope_payload(envelope)

    def _safe_undecryptable_push_event(self, msg: dict[str, Any], *, group: bool) -> dict[str, Any]:
        return self._v2_e2ee_coordinator().safe_undecryptable_push_event(msg, group=group)

    async def _decrypt_encrypted_push_payload(self, msg: dict[str, Any], *, group: bool) -> dict[str, Any] | None:
        return await self._v2_e2ee_coordinator().decrypt_encrypted_push_payload(msg, group=group)

    async def _publish_encrypted_push_as_undecryptable(
        self,
        event: str,
        ns: str,
        seq: Any,
        msg: dict[str, Any],
        *,
        group: bool,
    ) -> bool:
        return await self._v2_e2ee_coordinator().publish_encrypted_push_as_undecryptable(
            event, ns, seq, msg, group=group,
        )

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
        return await self._v2_e2ee_coordinator().publish_encrypted_push_message(
            normal_event, undecryptable_event, ns, seq, msg, group=group,
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
        return await self._v2_e2ee_coordinator().decrypt_v2_envelope_for_thought(
            envelope=envelope,
            from_aid=from_aid,
        )

    async def _pull_group_v2_internal(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """V2 Group 拉取并解密消息。内部方法，由 call("group.pull") 路由调用。

        注：明文消息（encrypt=False）由服务端 group.v2.pull 自动从 group_messages
        合并到返回结果（version=v1，明文 payload 直接 publish），密文走 V2 解密。
        """
        return await self._v2_e2ee_coordinator().pull_group_v2_internal(params)

    async def _ack_group_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 确认消费。内部方法，由 call("group.ack_messages") 路由调用。"""
        return await self._v2_e2ee_coordinator().ack_group_v2_internal(params)

    async def _v2_verify_state_signature(self, group_id: str, bootstrap: dict) -> None:
        """验证 owner/admin 对 state 的 ECDSA 签名（防服务端篡改 bootstrap 字段）。

        - 无签名（state_version=0 或新建群）→ 跳过
        - 签名验证失败 → 抛 E2EEError 拒绝信任 bootstrap
        - 验证通过 → 校验 bootstrap 返回的 member_aids 是否在签名快照中
        """
        return await self._group_state().verify_state_signature(group_id, bootstrap)

    async def _v2_check_fork(self, group_id: str, server_chain: str) -> None:
        """分叉检测：比对服务端 state_chain 与本地存储。
        - 本地无记录 → 接受并存储
        - server_chain 为空 → 跳过（state 未初始化）
        - 服务端 chain 与本地一致 → 正常
        - 服务端 chain 不一致 → 发布 group.v2.fork_detected 事件
        """
        return await self._group_state().check_fork(group_id, server_chain)

    def _v2_maybe_trigger_auto_propose(self, group_id: str) -> None:
        """lazy sync 路径：发现 pending members 时异步触发 auto propose（fire-and-forget，去重）。"""
        return self._group_state().maybe_trigger_auto_propose(group_id)

    async def _v2_auto_propose_state(self, group_id: str, *, leader_delay: bool = False) -> None:
        return await self._group_state().auto_propose_state(group_id, leader_delay=leader_delay)

    async def _v2_auto_propose_leader_delay(self, group_id: str) -> bool:
        """事件触发路径的 leader 选举：仅在线 owner/admin 参与，leader 立即提案，非 leader jitter 后兜底。"""
        return await self._group_state().auto_propose_leader_delay(group_id)

    def _v2_verify_committed_state_base(self, group_id: str, state_resp: dict[str, Any]) -> bool:
        return self._group_state().verify_committed_state_base(group_id, state_resp)

    async def _do_v2_auto_propose_state(self, group_id: str) -> None:
        """成员变更后自动 propose state（仅 owner/admin 执行）。

        使用完整 state commitment（覆盖 members+devices, audit_aids, admin_set,
        wrap_protocol 等），防止服务端篡改单个字段。
        """
        return await self._group_state().do_auto_propose_state(group_id)

    def _v2_verify_pending_proposal_against_base(
        self,
        group_id: str,
        proposal: dict[str, Any],
        state_resp: dict[str, Any],
    ) -> bool:
        return self._group_state().verify_pending_proposal_against_base(group_id, proposal, state_resp)

    async def _v2_confirm_pending_proposal(self, group_id: str) -> bool:
        return await self._group_state().confirm_pending_proposal(group_id)

    async def _v2_auto_confirm_pending_proposals(self) -> None:
        """Owner/admin 上线时自动检查：confirm pending proposals 或发起新 propose。"""
        return await self._group_state().auto_confirm_pending_proposals()

    async def _on_v2_state_proposed(self, data: Any) -> None:
        return await self._group_state().on_v2_state_proposed(data)

    async def _on_v2_state_retry_needed(self, data: Any) -> None:
        return await self._group_state().on_v2_state_retry_needed(data)

    async def _on_v2_state_confirmed(self, data: Any) -> None:
        return await self._group_state().on_v2_state_confirmed(data)

    async def _on_v2_push_notification(self, data: Any) -> None:
        return await self._delivery().on_v2_push_notification(data)

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
        self._agent_md_manager.observe_envelope(envelope)

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
        sender_cert_fingerprint = str(envelope.get("sender_cert_fingerprint") or "").strip().lower()
        sender_pub_der = await self._v2_sender_pub_der_from_cache_or_cert(from_aid, sender_device_id, sender_cert_fingerprint)

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
        self._attach_gateway_proximity(result, msg)
        self._attach_v2_envelope_metadata(result, meta)
        return result


