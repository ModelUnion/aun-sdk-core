from __future__ import annotations

import asyncio
import base64
import hashlib
import json
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
from .crypto import CryptoProvider
from .discovery import GatewayDiscovery
from .e2ee import E2EEManager, GroupE2EEManager
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
from .namespaces.custody_namespace import CustodyNamespace
from .transport import RPCTransport
from .seq_tracker import SeqTracker

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
        "initial_delay": 0.5,
        "max_delay": 30.0,
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

_NO_VERIFY_SSL = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
_NO_VERIFY_SSL.check_hostname = False
_NO_VERIFY_SSL.verify_mode = _ssl.CERT_NONE


def _make_connection_factory(verify_ssl: bool = True):
    """根据 verify_ssl 配置创建 WebSocket 连接工厂"""
    async def _factory(url: str) -> Any:
        global _ssl_warning_emitted
        kw: dict[str, Any] = {"open_timeout": 5, "close_timeout": 5, "ping_interval": None}
        if url.startswith("wss://"):
            if verify_ssl:
                pass  # 使用默认 SSL 上下文（验证证书）
            else:
                kw["ssl"] = _NO_VERIFY_SSL
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
        kw["ssl"] = _NO_VERIFY_SSL
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

    def __init__(self, config: dict | None = None) -> None:
        raw_config = dict(config or {})
        self._config_model = AUNConfig.from_dict(raw_config)
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
        self._prekey_replenish_inflight: set[str] = set()
        self._prekey_replenished: set[str] = set()

        connection_factory = _make_connection_factory(self._config_model.verify_ssl)
        from .keystore.sqlite_backup import SQLiteBackup
        backup_dir = self._config_model.aun_path / ".aun_backup"
        sqlite_backup = SQLiteBackup(backup_dir / "aun_backup.db")
        keystore = FileKeyStore(
            self._config_model.aun_path,
            encryption_seed=self._config_model.seed_password,
            sqlite_backup=sqlite_backup,
        )
        self._keystore = keystore
        # 获取并缓存 device_id
        from .config import get_device_id
        self._device_id = get_device_id(self._config_model.aun_path, sqlite_backup)
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
        self._group_epoch_rotate_task: asyncio.Task | None = None
        self._group_epoch_cleanup_task: asyncio.Task | None = None
        # 消息序列号跟踪器（群消息 + P2P 共用，按命名空间隔离）
        self._seq_tracker = SeqTracker()

        self.auth = AuthNamespace(self)
        self.custody = CustodyNamespace(self)

        # 内部订阅：推送消息自动解密后 re-publish 给用户
        self._dispatcher.subscribe("_raw.message.received", self._on_raw_message_received)
        # 群组消息推送：自动解密后 re-publish
        self._dispatcher.subscribe("_raw.group.message_created", self._on_raw_group_message_created)
        # 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
        self._dispatcher.subscribe("_raw.group.changed", self._on_raw_group_changed)
        # 其他事件直接透传
        for evt in ("message.recalled", "message.ack"):
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

    @property
    def group_e2ee(self) -> GroupE2EEManager:
        return self._group_e2ee

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
            sqlite_backup = getattr(self._keystore, "_sqlite_backup", None)
            if sqlite_backup and hasattr(sqlite_backup, "close"):
                sqlite_backup.close()
            self._state = "closed"
            return
        await self._transport.close()
        sqlite_backup = getattr(self._keystore, "_sqlite_backup", None)
        if sqlite_backup and hasattr(sqlite_backup, "close"):
            sqlite_backup.close()
        self._state = "closed"
        await self._dispatcher.publish("connection.state", {"state": self._state})

    # ── RPC ───────────────────────────────────────────────

    # 需要客户端签名的关键方法（渐进式部署：服务端有签名则验，无签名则放行）
    _SIGNED_METHODS = frozenset({
        "group.send", "group.kick", "group.add_member",
        "group.leave", "group.remove_member", "group.update_rules",
        "group.update", "group.update_announcement",
        "group.update_join_requirements", "group.set_role",
        "group.transfer_owner", "group.review_join_request",
        "group.batch_review_join_request",
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
            _client_log.warning("客户端签名失败，继续发送无签名请求: %s", exc)

    async def call(self, method: str, params: dict | None = None) -> Any:
        if self._state != "connected":
            raise ConnectionError("client is not connected")
        if self._is_internal_only_method(method):
            raise AUNPermissionError(f"method is internal_only: {method}")

        params = dict(params) if params else {}
        self._validate_outbound_call(method, params)
        self._inject_message_cursor_context(method, params)

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
                result["messages"] = await self._decrypt_messages(messages)
                if self._aid:
                    self._seq_tracker.on_pull_result(f"p2p:{self._aid}", messages)

        # 自动解密：group.pull 返回的群消息
        if method == "group.pull" and isinstance(result, dict):
            messages = result.get("messages")
            if isinstance(messages, list) and messages:
                result["messages"] = await self._decrypt_group_messages(messages)
                gid = (params or {}).get("group_id", "")
                if gid:
                    self._seq_tracker.on_pull_result(f"group:{gid}", messages)

        # ── Group E2EE 自动编排 ────────────────────────────
        if self._config_model.group_e2ee:
            loop = getattr(self, "_loop", None) or asyncio.get_running_loop()

            # 建群后自动创建 epoch（幂等：已有 secret 时跳过）
            # 同步到服务端确保 epoch 一致
            if method == "group.create" and isinstance(result, dict):
                group = result.get("group", {})
                gid = group.get("group_id", "")
                if gid and self._aid and not self._group_e2ee.has_secret(gid):
                    try:
                        self._group_e2ee.create_epoch(gid, [self._aid])
                        # 同步到服务端：将服务端 epoch 从 0 推到 1
                        loop.create_task(self._sync_epoch_to_server(gid))
                    except Exception as exc:
                        self._log_e2ee_error("create_epoch", gid, "", exc)

            # 加人后自动分发密钥给新成员（如 rotate_on_join 则先轮换）
            if method == "group.add_member":
                group_id = params.get("group_id", "")
                new_aid = params.get("aid", "")
                if group_id and new_aid:
                    if self._config_model.rotate_on_join:
                        loop.create_task(self._rotate_group_epoch(group_id))
                    else:
                        loop.create_task(self._distribute_key_to_new_member(group_id, new_aid))

            # 踢人后自动轮换 epoch
            if method == "group.kick":
                group_id = params.get("group_id", "")
                if group_id:
                    loop.create_task(self._rotate_group_epoch(group_id))

            # group.leave：按协议，离开者自身不执行轮换。
            # 剩余在线 admin/owner 收到 group.changed(action=member_left) 后自动补位轮换。

            # 审批通过后自动分发密钥给新成员
            if method == "group.review_join_request" and isinstance(result, dict):
                if result.get("approved") or result.get("status") == "approved":
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
        except Exception:
            pass  # 日志本身不应阻断主流程

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
        if not recipient_prekeys or (len(recipient_prekeys) <= 1 and not self_sync_copies):
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
        except Exception:
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
        except Exception:
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
        """自动加密并发送群组消息。"""
        group_id = params.get("group_id")
        payload = params.get("payload")
        if not group_id:
            raise ValidationError("group.send requires group_id")

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
                need_pull = self._seq_tracker.on_message_seq(f"p2p:{self._aid}", int(seq))
                if need_pull:
                    loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(self._fill_p2p_gap())

            decrypted = await self._decrypt_single_message(msg)
            await self._dispatcher.publish("message.received", decrypted)
        except Exception as _exc:
            import logging as _logging
            _logging.getLogger("aun_core").debug("解密失败: %s", _exc)

    async def _on_raw_group_message_created(self, data: Any) -> None:
        """处理群组消息推送：自动解密后 re-publish。"""
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._process_and_publish_group_message(data))

    async def _on_raw_group_changed(self, data: Any) -> None:
        """处理群组变更事件：验签 → 透传给用户 → 自动补齐 → epoch 轮换。

        验签策略：有 client_signature 就验，没有默认安全（兼容旧版）。
        """
        if isinstance(data, dict):
            # 验签：有签名就验证操作者身份
            cs = data.get("client_signature")
            if cs and isinstance(cs, dict):
                data["_verified"] = await self._verify_event_signature(data, cs)
            # 发布给用户
            await self._dispatcher.publish("group.changed", data)

            group_id = data.get("group_id", "")
            # 收到事件推送时自动 pull 补齐
            if group_id:
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._fill_group_event_gap(group_id))

            # 成员退出或被踢 → 剩余 admin/owner 自动补位轮换
            if data.get("action") in ("member_left", "member_removed") and group_id:
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._rotate_group_epoch(group_id))
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
        """
        try:
            if not isinstance(data, dict):
                await self._dispatcher.publish("group.message_created", data)
                return
            msg = dict(data)
            group_id = msg.get("group_id", "")
            seq = msg.get("seq")
            payload = msg.get("payload")

            # 空洞检测（无论带不带 payload 都检查）
            if group_id and seq is not None:
                need_pull = self._seq_tracker.on_message_seq(f"group:{group_id}", int(seq))
                if need_pull:
                    loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(self._fill_group_gap(group_id))

            if payload is None or (isinstance(payload, dict) and not payload):
                # 不带 payload 的通知：自动 pull 最新消息
                await self._auto_pull_group_messages(msg)
                return
            decrypted = await self._decrypt_group_message(msg)
            await self._dispatcher.publish("group.message_created", decrypted)
        except Exception as _exc:
            import logging as _logging
            _logging.getLogger("aun_core").debug("解密失败: %s", _exc)

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
                    self._seq_tracker.on_pull_result(f"group:{group_id}", messages)
                    for msg in messages:
                        if isinstance(msg, dict):
                            await self._dispatcher.publish("group.message_created", msg)
                    return
        except Exception as _exc:
            import logging as _logging
            _logging.getLogger("aun_core").debug("自动 pull 群消息失败: %s", _exc)
        # pull 失败时仍透传原始通知
        await self._dispatcher.publish("group.message_created", notification)

    async def _fill_group_gap(self, group_id: str) -> None:
        """后台补齐群消息空洞。"""
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
                    self._seq_tracker.on_pull_result(f"group:{group_id}", messages)
                    for msg in messages:
                        if isinstance(msg, dict):
                            await self._dispatcher.publish("group.message_created", msg)
        except Exception:
            pass  # 静默失败，下次空洞检测时重试

    async def _fill_group_event_gap(self, group_id: str) -> None:
        """后台补齐群事件空洞。"""
        ns = f"group_event:{group_id}"
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        try:
            result = await self.call("group.pull_events", {
                "group_id": group_id,
                "after_event_seq": after_seq,
                "device_id": self._device_id,
                "limit": 50,
            })
            if isinstance(result, dict):
                events = result.get("events", [])
                if isinstance(events, list):
                    self._seq_tracker.on_pull_result(ns, events)
                    for evt in events:
                        if isinstance(evt, dict):
                            await self._dispatcher.publish("group.changed", evt)
        except Exception:
            pass  # 静默失败，下次空洞检测时重试

    async def _pull_all_group_events_once(self) -> None:
        """上线/重连后一次性补齐所有已加入群的事件。"""
        try:
            result = await self.call("group.list", {})
            groups = result.get("items", []) if isinstance(result, dict) else []
            for g in groups:
                gid = g.get("group_id", "") if isinstance(g, dict) else ""
                if gid:
                    await self._fill_group_event_gap(gid)
        except Exception:
            pass  # 静默失败

    async def _fill_p2p_gap(self) -> None:
        """后台补齐 P2P 消息空洞。"""
        if not self._aid:
            return
        ns = f"p2p:{self._aid}"
        after_seq = self._seq_tracker.get_contiguous_seq(ns)
        try:
            result = await self.call("message.pull", {
                "after_seq": after_seq,
                "limit": 50,
            })
            if isinstance(result, dict):
                messages = result.get("messages", [])
                if isinstance(messages, list):
                    self._seq_tracker.on_pull_result(ns, messages)
                    for msg in messages:
                        if isinstance(msg, dict):
                            await self._dispatcher.publish("message.received", msg)
        except Exception:
            pass

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
                try:
                    await self.call("message.send", {
                        "to": recovery["to"],
                        "payload": recovery["payload"],
                        "encrypt": True,
                    })
                except Exception as _exc:
                    import logging as _logging
                    _logging.getLogger("aun_core").debug("操作失败: %s", _exc)

        return message

    async def _decrypt_group_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """批量解密群组消息（用于 group.pull）。跳过防重放检查。"""
        result = []
        for msg in messages:
            decrypted = await self._decrypt_group_message(msg, skip_replay=True)
            result.append(decrypted)
        return result

    async def _try_handle_group_key_message(self, message: dict[str, Any]) -> bool:
        """尝试处理 P2P 传输的群组密钥消息。返回 True 表示已处理（不再传播）。"""
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return False

        # 先解密 P2P E2EE（如果是加密的）
        # 注意：用 _decrypt_message 而非 decrypt_message，避免消耗 seen set
        actual_payload = payload
        if payload.get("type") == "e2ee.encrypted":
            # 确保发送方证书已缓存（签名验证需要）
            from_aid = message.get("from", "")
            if from_aid:
                await self._ensure_sender_cert_cached(from_aid)
            decrypted = self._e2ee._decrypt_message(message)
            if decrypted is None:
                return False
            self._schedule_prekey_replenish_if_consumed(decrypted)
            actual_payload = decrypted.get("payload", {})
            if not isinstance(actual_payload, dict):
                return False

        result = self._group_e2ee.handle_incoming(actual_payload)
        if result is None:
            return False

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
        async with aiohttp.ClientSession() as session:
            async with session.get(cert_url, ssl=ssl_param) as response:
                response.raise_for_status()
                cert_pem = await response.text()
        cert_bytes = cert_pem.encode("utf-8")

        # 完整 PKI 验证：链 + CRL + OCSP + AID 绑定
        # 验证时也用 peer 的 Gateway URL（链/OCSP/CRL 都从 peer 域获取）
        from cryptography import x509 as _x509
        cert_obj = _x509.load_pem_x509_certificate(cert_bytes)
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
        try:
            self._keystore.save_cert(
                aid,
                cert_pem,
                cert_fingerprint=cert_fingerprint,
                make_active=not bool(cert_fingerprint),
            )
        except TypeError:
            # 兼容旧 keystore 实现：仅 active_signing 路径覆盖主证书
            if not cert_fingerprint:
                try:
                    self._keystore.save_cert(aid, cert_pem)
                except Exception as exc:
                    _client_log.error("写入证书到 keystore 失败 (aid=%s): %s", aid, exc)
        except Exception as exc:
            _client_log.error("写入证书到 keystore 失败 (aid=%s, fp=%s): %s", aid, cert_fingerprint or "", exc)
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
                    time.time() + 3600.0,
                )
                self._e2ee.cache_prekey(peer_aid, normalized[0])
                return normalized

        prekey = result.get("prekey")
        if isinstance(prekey, dict):
            self._peer_prekeys_cache[peer_aid] = ([dict(prekey)], time.time() + 3600.0)
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
        result = await self._transport.call("message.e2ee.put_prekey", prekey_material)
        return result if isinstance(result, dict) else {"ok": True}

    async def _check_replay_guard(
        self, message_id: str, sender_aid: str, encryption_mode: str, message: dict[str, Any],
    ) -> bool:
        """服务端防重放检查（可通过 config.server_replay_guard=False 关闭）。

        本地防重放由 E2EEManager._seen_messages 处理，无需此方法。
        此方法提供跨进程/跨重启的持久化防重放增强。
        """
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
        except Exception as _exc:
            import logging as _logging
            _logging.getLogger("aun_core").debug("操作失败: %s", _exc)
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
                if not self._e2ee._should_decrypt_for_current_aid(msg, payload):
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
                decrypted = self._e2ee._decrypt_message(msg)
                # pull 路径不触发 prekey 补充（历史消息，prekey 早在推送时消耗过）
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
        sender_cert_fingerprint = str(
            payload.get("sender_cert_fingerprint")
            or (payload.get("aad") or {}).get("sender_cert_fingerprint")
            or ""
        ).strip().lower()
        if not await self._check_replay_guard(message_id, from_aid, encryption_mode, message):
            return message

        # 确保发送方证书已缓存到 keystore（三路 ECDH + 签名验证需要）
        if from_aid:
            cert_ready = await self._ensure_sender_cert_cached(
                from_aid, sender_cert_fingerprint or None,
            )
            if not cert_ready:
                _client_log.warning("无法获取发送方 %s 的证书，跳过解密", from_aid)
                return message

        # 密码学解密（E2EEManager.decrypt_message 内含本地防重放）
        decrypted = self._e2ee.decrypt_message(message)
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
        except Exception:
            local_cert = None
        if local_cert:
            now = time.time()
            cert_bytes = local_cert.encode("utf-8") if isinstance(local_cert, str) else local_cert
            self._cert_cache[cache_key] = _CachedPeerCert(
                cert_bytes=cert_bytes,
                validated_at=now,
                refresh_after=now + _PEER_CERT_CACHE_TTL,
            )
            return True
        try:
            # _fetch_peer_cert 内部：下载 → 完整 PKI 验证 → 更新内存缓存
            cert_bytes = await self._fetch_peer_cert(aid, cert_fingerprint)
            cert_pem = cert_bytes.decode("utf-8") if isinstance(cert_bytes, bytes) else cert_bytes
            self._keystore.save_cert(
                aid,
                cert_pem,
                cert_fingerprint=cert_fingerprint,
                make_active=not bool(cert_fingerprint),
            )
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

        # 从 keystore 恢复 SeqTracker 状态
        self._restore_seq_tracker_state()

        self._start_background_tasks()

        # 上线后自动上传 prekey（失败时记录日志）
        try:
            await self._upload_prekey()
        except Exception as exc:
            _client_log.warning("prekey 上传失败: %s", exc)

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
        # 上线/重连后一次性补齐群事件
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(self._pull_all_group_events_once())

    async def _stop_background_tasks(self) -> None:
        for attr in ("_heartbeat_task", "_token_refresh_task", "_prekey_refresh_task",
                      "_group_epoch_rotate_task", "_group_epoch_cleanup_task"):
            task = getattr(self, attr, None)
            if task is None:
                continue
            task.cancel()
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
        return

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
                except AuthError as exc:
                    _client_log.debug("token 刷新失败，下次重试: %s", exc)
                    continue
                except Exception as exc:
                    await self._dispatcher.publish("connection.error", {"error": exc})
        except asyncio.CancelledError:
            raise

    async def _prekey_refresh_loop(self, interval: float) -> None:
        return

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
        if prekey_id in self._prekey_replenished:
            return
        # 全局只允许一个 put_prekey 请求 inflight，避免淹没 RPC 通道
        if self._prekey_replenish_inflight:
            return
        self._prekey_replenish_inflight.add(prekey_id)

        async def _replenish() -> None:
            try:
                await self._upload_prekey()
            except Exception as exc:
                _client_log.warning("消费 prekey %s 后补充 current prekey 失败: %s", prekey_id, exc)
            else:
                self._prekey_replenished.add(prekey_id)
            finally:
                self._prekey_replenish_inflight.discard(prekey_id)

        loop = getattr(self, "_loop", None)
        if loop and loop.is_running():
            loop.create_task(_replenish())
            return
        try:
            asyncio.get_running_loop().create_task(_replenish())
        except RuntimeError:
            self._prekey_replenish_inflight.discard(prekey_id)

    def _restore_seq_tracker_state(self) -> None:
        """从 keystore metadata 恢复 SeqTracker 状态。"""
        if not self._aid:
            return
        try:
            state = None
            loader = getattr(self._keystore, "load_instance_state", None)
            if callable(loader):
                instance_state = loader(self._aid, self._device_id, self._slot_id)
                if isinstance(instance_state, dict):
                    state = instance_state.get("seq_tracker_state")
            if not isinstance(state, dict):
                metadata = self._keystore.load_metadata(self._aid)
                if isinstance(metadata, dict):
                    state = metadata.get("seq_tracker_state")
            if isinstance(state, dict):
                self._seq_tracker.restore_state(state)
        except Exception as exc:
            _client_log.debug("恢复 SeqTracker 状态失败: %s", exc)

    def _save_seq_tracker_state(self) -> None:
        """将 SeqTracker 状态保存到 keystore metadata。"""
        if not self._aid:
            return
        state = self._seq_tracker.export_state()
        if not state:
            return
        try:
            updater = getattr(self._keystore, "update_instance_state", None)
            if callable(updater):
                def _merge_instance(m: dict[str, Any]) -> dict[str, Any]:
                    m["seq_tracker_state"] = state
                    return m

                updater(self._aid, self._device_id, self._slot_id, _merge_instance)
                return

            def _merge(m: dict) -> dict[str, Any]:
                m["seq_tracker_state"] = state
                return m
            self._keystore.update_metadata(self._aid, _merge)
        except Exception as exc:
            _client_log.debug("保存 SeqTracker 状态失败: %s", exc)

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
        except Exception:
            return {}

    async def _sync_epoch_to_server(self, group_id: str) -> None:
        """建群后将本地 epoch 1 同步到服务端（服务端初始为 0）。"""
        try:
            rotate_params = {
                "group_id": group_id,
                "current_epoch": 0,
            }
            rotate_params.update(self._build_rotation_signature(group_id, 0, 1))
            await self.call("group.e2ee.rotate_epoch", rotate_params)
        except Exception as exc:
            _client_log.debug("同步 epoch 到服务端失败 (group=%s，可能已同步): %s", group_id, exc)

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
                try:
                    await self.call("message.send", {
                        "to": dist["to"],
                        "payload": dist["payload"],
                        "encrypt": True,
                    })
                except Exception as _exc:
                    import logging as _logging
                    _logging.getLogger("aun_core").debug("操作失败: %s", _exc)
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
            await self.call("message.send", {
                "to": new_member_aid,
                "payload": dist_payload,
                "encrypt": True,
            })
        except Exception as exc:
            self._log_e2ee_error("distribute_key", group_id, new_member_aid, exc)

    def _start_group_epoch_tasks(self) -> None:
        """启动群组 epoch 相关后台任务"""
        if not self._config_model.group_e2ee:
            return
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

    async def _group_epoch_rotate_loop(self, interval: float) -> None:
        """定时轮换所有已知群组的 epoch"""
        try:
            while not self._closing:
                await asyncio.sleep(interval)
                if self._state != "connected":
                    continue
                my_aid = self._aid
                if not my_aid:
                    continue
                try:
                    metadata = self._keystore.load_metadata(my_aid) or {}
                    group_secrets = metadata.get("group_secrets", {})
                    for gid in list(group_secrets.keys()):
                        await self._rotate_group_epoch(gid)
                except Exception as _exc:
                    import logging as _logging
                    _logging.getLogger("aun_core").debug("epoch 轮换失败: %s", _exc)
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
                    metadata = self._keystore.load_metadata(my_aid) or {}
                    group_secrets = metadata.get("group_secrets", {})
                    retention = self._config_model.old_epoch_retention_seconds
                    for gid in list(group_secrets.keys()):
                        self._group_e2ee.cleanup(gid, retention)
                except Exception as _exc:
                    import logging as _logging
                    _logging.getLogger("aun_core").debug("epoch 轮换失败: %s", _exc)
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
        initial_delay = float(retry.get("initial_delay", 0.5))
        max_delay = float(retry.get("max_delay", 30.0))
        delay = initial_delay
        attempt = 0

        while not self._closing:
            attempt += 1
            self._state = "reconnecting"
            await self._dispatcher.publish("connection.state", {
                "state": self._state,
                "attempt": attempt,
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
        persist_identity = getattr(self._auth, "_persist_identity", None)
        if callable(persist_identity):
            persist_identity(identity)
        else:
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
