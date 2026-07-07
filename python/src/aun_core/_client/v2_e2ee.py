from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from ..group_id import normalize_group_id as _normalize_group_id
from ..types import ConnectionState
from ..v2.session import V2Session
from .runtime import ClientRuntime


_V2_PULL_DEFAULT_PAGE_LIMIT = 50
_V2_PULL_MAX_PAGE_LIMIT = 50
_V2_PULL_TAIL_DELAY_MIN_S = 0.005
_V2_PULL_TAIL_DELAY_MAX_S = 0.500


def _group_identifier_pair(params: dict[str, Any]) -> tuple[str, str]:
    wire_group_id = str(params.get("group_id") or params.get("groupId") or "").strip()
    group_aid = str(params.get("group_aid") or params.get("groupAid") or "").strip()
    if group_aid:
        group_aid = _normalize_group_id(group_aid) or group_aid
    elif wire_group_id:
        group_aid = _normalize_group_id(wire_group_id) or wire_group_id
    if not wire_group_id:
        wire_group_id = group_aid
    return wire_group_id, group_aid


def _v2_effective_page_limit(value: Any) -> int:
    try:
        requested = int(value or _V2_PULL_DEFAULT_PAGE_LIMIT)
    except (TypeError, ValueError):
        requested = _V2_PULL_DEFAULT_PAGE_LIMIT
    return max(1, min(requested, _V2_PULL_MAX_PAGE_LIMIT))


def _v2_pull_tail_delay_seconds(msg_count: int, page_limit: int) -> float:
    try:
        count = int(msg_count or 0)
    except (TypeError, ValueError):
        count = 0
    try:
        limit = int(page_limit or 0)
    except (TypeError, ValueError):
        limit = 0
    if count <= 0 or (limit > 0 and count >= limit):
        return 0.0
    return min(_V2_PULL_TAIL_DELAY_MAX_S, max(_V2_PULL_TAIL_DELAY_MIN_S, 1.0 / float(count + 1)))


@dataclass(slots=True)
class _DecryptJob:
    seq: int
    msg: dict[str, Any]
    envelope: dict[str, Any]
    spk_id: str
    recipient_key_source: str
    group_id: str
    from_aid: str
    sender_device_id: str
    ik_priv: bytes
    spk_priv: bytes | None
    sender_pub_der: bytes


@dataclass(slots=True)
class _DecryptResult:
    seq: int
    msg: dict[str, Any]
    envelope: dict[str, Any]
    spk_id: str = ""
    recipient_key_source: str = ""
    group_id: str = ""
    from_aid: str = ""
    sender_device_id: str = ""
    plaintext: dict[str, Any] | None = None
    error: Exception | None = None


def _decrypt_job_sync(job: _DecryptJob, *, aid: str, device_id: str) -> _DecryptResult:
    from ..v2.e2ee.decrypt import decrypt_message as v2_decrypt_message

    try:
        plaintext = v2_decrypt_message(
            envelope=job.envelope,
            self_aid=aid,
            self_device_id=device_id,
            self_ik_priv=job.ik_priv,
            self_spk_priv=job.spk_priv,
            sender_pub_der=job.sender_pub_der,
        )
        return _DecryptResult(
            seq=job.seq,
            msg=job.msg,
            envelope=job.envelope,
            spk_id=job.spk_id,
            recipient_key_source=job.recipient_key_source,
            group_id=job.group_id,
            from_aid=job.from_aid,
            sender_device_id=job.sender_device_id,
            plaintext=plaintext,
        )
    except Exception as exc:
        return _DecryptResult(
            seq=job.seq,
            msg=job.msg,
            envelope=job.envelope,
            spk_id=job.spk_id,
            recipient_key_source=job.recipient_key_source,
            group_id=job.group_id,
            from_aid=job.from_aid,
            sender_device_id=job.sender_device_id,
            error=exc,
        )


class V2E2EECoordinator:
    """V2 E2EE 会话、bootstrap、加密与解密协调器。"""

    def __init__(self, runtime: Any) -> None:
        self.runtime = ClientRuntime.coerce(runtime)
        self.client = self.runtime.client

    def _target_cache(self) -> dict[str, tuple[float, Any]]:
        cache = getattr(self.client, "_v2_target_set_cache", None)
        if cache is None:
            cache = {}
            self.client._v2_target_set_cache = cache
        return cache

    def _target_cache_get(self, key: str, ttl: float) -> Any | None:
        cached = self._target_cache().get(key)
        if not cached:
            return None
        created_at = float(cached[0] or 0)
        if time.time() - created_at >= ttl:
            self._target_cache().pop(key, None)
            return None
        return cached[1]

    def _target_cache_put(self, key: str, value: Any) -> Any:
        self._target_cache()[key] = (time.time(), value)
        return value

    def clear_bootstrap_cache(self, key: str) -> None:
        self.client._v2_bootstrap_cache.pop(key, None)
        self._target_cache().pop(key, None)

    def clear_group_bootstrap_cache(self, group_id: str) -> None:
        self.clear_bootstrap_cache(f"group:{group_id}")

    @staticmethod
    def _protected_headers_dict(value: Any) -> dict[str, Any] | None:
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
        if isinstance(value, dict):
            return dict(value)
        return None

    async def on_connected(self, *, background_sync: bool) -> None:
        """连接成功后的 V2 E2EE 初始化与后台协调。"""
        client = self.client
        try:
            await client._init_v2_session()
        except Exception as exc:
            client._log.warn("client", "V2 session init failed (non-fatal): %s", exc)
        if background_sync and getattr(client, "_v2_session", None):
            client._group_state().schedule_auto_confirm_pending_proposals()

    async def init_v2_session(self) -> None:
        """connect 成功后初始化 V2 session 并注册设备 SPK。IK = AID 长期密钥。"""
        client = self.client
        if not client._aid:
            return
        current_aid = client._current_aid
        if not current_aid or not current_aid.private_key_pem:
            client._log.warn("client", "V2 session init skipped: no AID private key")
            return

        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import ec as _ec

        pk = _ser.load_pem_private_key(current_aid.private_key_pem.encode("utf-8"), password=None)
        if not isinstance(pk, _ec.EllipticCurvePrivateKey):
            raise RuntimeError("AID private key must be EC P-256")
        priv_int = pk.private_numbers().private_value
        aid_priv_der = priv_int.to_bytes(32, "big")
        aid_pub_der = pk.public_key().public_bytes(
            encoding=_ser.Encoding.DER,
            format=_ser.PublicFormat.SubjectPublicKeyInfo,
        )

        db = client._token_store._get_db(client._aid)
        self.runtime.v2.session = V2Session(
            db,
            client._device_id,
            client._aid,
            aid_priv_der=aid_priv_der,
            aid_pub_der=aid_pub_der,
        )
        client._v2_session.ensure_keys()
        self.runtime.v2.bootstrap_cache.clear()
        self._target_cache().clear()
        await client._v2_session.ensure_registered(client.call)
        client._log.debug(
            "client",
            "V2 session initialized (IK=AID identity): aid=%s device=%s",
            client._aid,
            client._device_id,
        )

    def schedule_group_spk_registration(self, group_id: str, *, reason: str) -> None:
        client = self.client
        group_id = str(group_id or "").strip()
        if not group_id or not client._v2_session:
            return
        inflight = self.runtime.v2.group_spk_registration_inflight
        if group_id in inflight:
            return
        inflight.add(group_id)

        async def _run() -> None:
            try:
                if client._public_state != ConnectionState.READY or not client._v2_session:
                    return
                await client._delivery().run_background_rpc(
                    lambda: client._v2_session.ensure_group_registered(group_id, client.call)
                )
                client._log.debug("client", "group SPK registered: group=%s reason=%s", group_id, reason)
            except Exception as exc:
                client._log.debug(
                    "client",
                    "group SPK registration failed (non-fatal): group=%s reason=%s err=%s",
                    group_id,
                    reason,
                    exc,
                )
            finally:
                inflight.discard(group_id)

        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        client._group_state().track_auto_state_task(loop.create_task(_run()))

    def schedule_group_spk_rotation(self, group_id: str, *, reason: str) -> None:
        client = self.client
        group_id = str(group_id or "").strip()
        if not group_id or not client._v2_session:
            return
        inflight = self.runtime.v2.group_spk_rotation_inflight
        if group_id in inflight:
            return
        inflight.add(group_id)

        async def _run() -> None:
            try:
                if client._public_state != ConnectionState.READY or not client._v2_session:
                    return
                session = client._v2_session
                # 尝试记录轮换前的 group SPK，用于上传失败时回滚
                old_spk = None
                normalized_gid = None
                try:
                    normalized_gid = session._group_key(group_id)
                    old_spk = session._store.load_current_group_spk(session._device_id, normalized_gid)
                except Exception:
                    pass  # session 不支持这些方法时跳过回滚准备
                try:
                    await client._delivery().run_background_rpc(
                        lambda: session.rotate_group_spk(group_id, client.call)
                    )
                    client._log.debug("client", "group SPK rotated: group=%s reason=%s", group_id, reason)
                except Exception as exc:
                    # 上传失败：回滚本地新 SPK，避免本地/服务端 spk_id 不一致
                    if normalized_gid is not None:
                        try:
                            new_spk = session._store.load_current_group_spk(session._device_id, normalized_gid)
                            if new_spk and (not old_spk or new_spk[0] != old_spk[0]):
                                session._store.delete_group_spk(session._device_id, normalized_gid, new_spk[0])
                                try:
                                    session._group_spk_cache.pop((normalized_gid, new_spk[0]), None)
                                except Exception:
                                    pass
                                client._log.warn(
                                    "client",
                                    "group SPK rotation upload failed, rolled back local spk_id=%s: group=%s reason=%s err=%s",
                                    new_spk[0], group_id, reason, exc,
                                )
                                return
                        except Exception:
                            pass  # 回滚不可用时走 non-fatal 路径
                    client._log.debug(
                        "client",
                        "group SPK rotation failed (non-fatal): group=%s reason=%s err=%s",
                        group_id, reason, exc,
                    )
            except Exception as exc:
                client._log.debug(
                    "client",
                    "group SPK rotation schedule error (non-fatal): group=%s reason=%s err=%s",
                    group_id,
                    reason,
                    exc,
                )
            finally:
                inflight.discard(group_id)

        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        client._group_state().track_auto_state_task(loop.create_task(_run()))

    def schedule_group_spk_registration_after_peer_fallback(self, group_id: str) -> None:
        client = self.client
        group_id = str(group_id or "").strip()
        registered = self.runtime.v2.group_spk_peer_fallback_registered
        if not group_id or group_id in registered:
            return
        registered.add(group_id)
        client._schedule_group_spk_registration(group_id, reason="peer_device_prekey_fallback")

    def pending_sender_ik_message_key(self, msg: dict[str, Any], group_id: str) -> str:
        client = self.client
        message_id = str(msg.get("message_id") or "").strip()
        seq = str(msg.get("seq") or "").strip()
        prefix = f"group:{group_id}" if group_id else f"p2p:{client._aid or ''}"
        return f"{prefix}:{message_id or seq or id(msg)}"

    @staticmethod
    def pending_sender_ik_fetch_key(from_aid: str, sender_device_id: str, group_id: str) -> str:
        return f"{from_aid}#{sender_device_id}#{group_id or ''}"

    def schedule_sender_ik_pending(
        self,
        *,
        msg: dict[str, Any],
        envelope: dict[str, Any],
        from_aid: str,
        sender_device_id: str,
        group_id: str,
    ) -> None:
        client = self.client
        if not from_aid:
            return
        if getattr(client, "_closing", False):
            return
        message_key = client._v2_pending_sender_ik_message_key(msg, group_id)
        # 队列上限保护：超限时丢弃最旧的条目
        _V2_SENDER_IK_PENDING_MAX = 1000
        if len(client._v2_sender_ik_pending) >= _V2_SENDER_IK_PENDING_MAX and message_key not in client._v2_sender_ik_pending:
            oldest_key = min(client._v2_sender_ik_pending, key=lambda k: client._v2_sender_ik_pending[k].get("created_at", 0))
            client._v2_sender_ik_pending.pop(oldest_key, None)
            client._log.warn(
                "client",
                "V2 sender IK pending queue full (%d), evicted oldest: key=%s",
                _V2_SENDER_IK_PENDING_MAX,
                oldest_key,
            )
        client._v2_sender_ik_pending[message_key] = {
            "msg": dict(msg),
            "from_aid": from_aid,
            "sender_device_id": sender_device_id,
            "group_id": group_id,
            "created_at": time.time(),
        }
        client._log.debug(
            "client",
            "V2 decrypt pending sender IK: key=%s from=%s device=%s group=%s pending=%d",
            message_key,
            from_aid,
            sender_device_id or "-",
            group_id or "<p2p>",
            len(client._v2_sender_ik_pending),
        )
        fetch_key = client._v2_pending_sender_ik_fetch_key(from_aid, sender_device_id, group_id)
        if fetch_key in client._v2_sender_ik_fetching:
            return
        client._v2_sender_ik_fetching.add(fetch_key)
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        async def _run() -> None:
            await client._delivery().run_background_rpc(
                lambda: client._resolve_v2_sender_ik_pending(from_aid, sender_device_id, group_id, fetch_key)
            )

        client._group_state().track_auto_state_task(loop.create_task(_run()))

    def schedule_sender_ik_fetch(self, from_aid: str, sender_device_id: str, group_id: str) -> None:
        client = self.client
        if not from_aid:
            return
        if getattr(client, "_closing", False):
            return
        fetch_key = client._v2_pending_sender_ik_fetch_key(from_aid, sender_device_id, group_id)
        if fetch_key in client._v2_sender_ik_fetching:
            return
        client._v2_sender_ik_fetching.add(fetch_key)
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        async def _run() -> None:
            await client._delivery().run_background_rpc(
                lambda: client._resolve_v2_sender_ik_pending(from_aid, sender_device_id, group_id, fetch_key)
            )

        client._group_state().track_auto_state_task(loop.create_task(_run()))

    async def resolve_sender_ik_pending(
        self,
        from_aid: str,
        sender_device_id: str,
        group_id: str,
        fetch_key: str,
    ) -> None:
        from ..client import _v2_wrap_capabilities

        client = self.client
        try:
            if client._v2_session and from_aid:
                try:
                    bs = await client.call("message.v2.bootstrap", {
                        "peer_aid": from_aid,
                        "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                    })
                    if isinstance(bs, dict):
                        for dev in bs.get("peer_devices", []) or []:
                            await client._v2_cache_peer_ik_from_device_or_cert(dev, from_aid)
                except Exception as exc:
                    client._log.warn("client", "V2 sender IK pending bootstrap failed peer=%s: %s", from_aid, exc)
                if group_id:
                    try:
                        gbs = await client.call("group.v2.bootstrap", {
                            "group_id": group_id,
                            "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                        })
                        if isinstance(gbs, dict):
                            for dev in gbs.get("devices", []) or []:
                                await client._v2_cache_peer_ik_from_device_or_cert(dev)
                            for dev in gbs.get("audit_recipients", []) or []:
                                await client._v2_cache_peer_ik_from_device_or_cert(dev)
                    except Exception as exc:
                        client._log.warn("client", "V2 sender IK pending group bootstrap failed group=%s: %s", group_id, exc)
                if not client._v2_session.get_peer_ik(from_aid, sender_device_id):
                    await client._v2_sender_pub_der_from_cache_or_cert(from_aid, sender_device_id)

            pending_items = [
                (key, entry)
                for key, entry in list(client._v2_sender_ik_pending.items())
                if entry.get("from_aid") == from_aid
                and entry.get("sender_device_id") == sender_device_id
                and entry.get("group_id", "") == group_id
            ]
            for key, entry in pending_items:
                msg = entry.get("msg")
                if not isinstance(msg, dict):
                    client._v2_sender_ik_pending.pop(key, None)
                    continue
                try:
                    plaintext = await client._decrypt_v2_message(msg, allow_pending=False)
                except Exception as exc:
                    client._log.warn("client", "V2 sender IK pending retry raised: key=%s err=%s", key, exc)
                    client._v2_sender_ik_pending.pop(key, None)
                    continue
                if plaintext is None:
                    client._log.warn("client", "V2 sender IK pending retry still undecryptable: key=%s", key)
                    # 不 pop —— 保留在队列中，等待后续重试机会
                    # 发射 undecryptable 事件通知上层
                    seq = int(msg.get("seq") or 0)
                    is_group = bool(group_id)
                    event_name = "group.message_undecryptable" if is_group else "message.undecryptable"
                    safe_event = client._safe_undecryptable_push_event(msg, group=is_group)
                    safe_event["_decrypt_error"] = "sender IK pending retry failed"
                    safe_event["_decrypt_stage"] = "sender_ik_pending_retry"
                    await client._publish_app_event(event_name, safe_event, source="pending_retry")
                    continue
                client._v2_sender_ik_pending.pop(key, None)
                seq = int(msg.get("seq") or 0)
                if group_id:
                    plaintext["group_id"] = group_id
                    await client._publish_pulled_message("group.message_created", f"group:{group_id}", seq, plaintext)
                else:
                    await client._publish_pulled_message("message.received", f"p2p:{client._aid}", seq, plaintext)
                client._log.debug("client", "V2 sender IK pending retry delivered: key=%s", key)
        finally:
            client._v2_sender_ik_fetching.discard(fetch_key)

    async def build_target_from_device(
        self,
        dev: dict[str, Any],
        *,
        aid: str,
        device_id: str,
        role: str,
        default_key_source: str,
    ) -> dict[str, Any] | None:
        from ..client import _v2_device_id_from_device

        client = self.client
        aid = str(aid or "").strip()
        has_device_id, normalized_device_id = _v2_device_id_from_device(dev)
        device_id = normalized_device_id if has_device_id else str(device_id or "").strip()
        ik_b64 = str(dev.get("ik_pk") or "").strip()
        if not aid or not has_device_id:
            return None
        if ik_b64:
            ik_pk_der = base64.b64decode(ik_b64)
        else:
            ik_pk_der = await client._v2_trusted_ik_pub_der(aid)
            client._log.debug("client", "V2 target IK loaded from cert: aid=%s device=%s role=%s", aid, device_id or "<aid>", role)
        spk_pk_der = base64.b64decode(dev["spk_pk"]) if dev.get("spk_pk") else None
        key_source = str(dev.get("key_source") or default_key_source).strip() or default_key_source
        await client._v2_verify_spk_device(
            dev,
            aid=aid,
            device_id=device_id,
            ik_pk_der=ik_pk_der,
            spk_pk_der=spk_pk_der,
            key_source=key_source,
        )
        if client._v2_session:
            client._v2_session.cache_peer_ik(aid, device_id, ik_pk_der)
        return {
            "aid": aid,
            "device_id": device_id,
            "role": role,
            "key_source": key_source,
            "ik_pk_der": ik_pk_der,
            "spk_pk_der": spk_pk_der,
            "spk_id": str(dev.get("spk_id") or "").strip(),
        }

    async def send_encrypted_v2(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。"""
        from ..client import (
            _v2_apply_wrap_policy_to_targets,
            _v2_device_id_from_device,
            _v2_normalize_wrap_policy,
            _v2_wrap_capabilities,
        )
        from ..errors import E2EEError, StateError, ValidationError
        from ..v2.e2ee.encrypt_p2p import encrypt_p2p_message

        client = self.client
        background_rpc = bool(params.pop("_rpc_background", False) or getattr(client, "_background_rpc_depth", 0) > 0)
        if not client._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        to = str(params.get("to") or "").strip()
        payload = params.get("payload") or {}
        if not to:
            raise ValidationError("message.send requires 'to'")
        if not isinstance(payload, dict):
            raise ValidationError("message.send payload must be a dict for V2 encryption")
        protected_headers = self._protected_headers_dict(client._protected_headers_from_params(params))
        client._log_message_debug(
            "send-plaintext",
            "message.send.v2",
            "message.send",
            params,
            payload_override=payload,
            extra={"to": to},
        )

        async def _attempt(use_cache: bool) -> dict[str, Any]:
            client._log.debug("client", "message.v2.send attempt: to=%s use_cache=%s", to, use_cache)
            if use_cache:
                cached = client._v2_bootstrap_cache.get(to)
                if cached and (time.time() - cached[1]) < client._V2_BOOTSTRAP_TTL:
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
                self._target_cache().pop(to, None)
                bootstrap = await client.call("message.v2.bootstrap", {
                    "peer_aid": to,
                    "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                })
                if isinstance(bootstrap, dict):
                    await client._prime_bootstrap_peer_certs(bootstrap, to)
                peer_devices = bootstrap.get("peer_devices", [])
                audit_recipients_raw = bootstrap.get("audit_recipients", [])
                wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
                raw_self_devices = bootstrap.get("self_devices")
                self_devices_from_bootstrap = raw_self_devices if isinstance(raw_self_devices, list) else None
                client._log.debug("client", "_send_encrypted_v2 bootstrap: to=%s peer_devices=%d spk_pks=%s",
                                  to, len(peer_devices),
                                  [d.get("spk_pk", "")[:20] or "<empty>" for d in peer_devices[:3]])
                if peer_devices:
                    client._v2_bootstrap_cache[to] = (
                        peer_devices,
                        time.time(),
                        audit_recipients_raw,
                        self_devices_from_bootstrap,
                        wrap_policy,
                    )
                if client._aid and self_devices_from_bootstrap:
                    client._v2_bootstrap_cache[client._aid] = (self_devices_from_bootstrap, time.time())
            else:
                audit_recipients_raw = cached[2] if len(cached) > 2 and isinstance(cached[2], list) else []

            if not peer_devices:
                raise E2EEError(f"V2 bootstrap: no devices found for {to}")

            target_cache_key = to
            target_set = self._target_cache_get(target_cache_key, client._V2_BOOTSTRAP_TTL) if use_cache else None
            if target_set is None:
                targets = []
                for dev in peer_devices:
                    target = await client._v2_build_target_from_device(
                        dev,
                        aid=to,
                        device_id=dev.get("device_id", ""),
                        role="peer",
                        default_key_source="peer_device_prekey",
                    )
                    if target:
                        targets.append(target)

                audit_targets = []
                for dev in audit_recipients_raw:
                    target = await client._v2_build_target_from_device(
                        dev,
                        aid=dev.get("aid", ""),
                        device_id=dev.get("device_id", ""),
                        role="audit",
                        default_key_source="peer_device_prekey",
                    )
                    if target:
                        audit_targets.append(target)

                if client._aid and client._aid != to:
                    try:
                        self_devices = self_devices_from_bootstrap if self_devices_from_bootstrap else None
                        if self_devices is None:
                            self_cached = client._v2_bootstrap_cache.get(client._aid)
                            if self_cached and (time.time() - self_cached[1]) < client._V2_BOOTSTRAP_TTL:
                                self_devices = self_cached[0]
                            else:
                                self_bs = await client.call("message.v2.bootstrap", {
                                    "peer_aid": client._aid,
                                    "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                                })
                                self_devices = self_bs.get("peer_devices", [])
                                if self_devices:
                                    client._v2_bootstrap_cache[client._aid] = (self_devices, time.time())
                        for dev in self_devices:
                            has_dev_id, dev_id = _v2_device_id_from_device(dev)
                            if not has_dev_id or dev_id == client._device_id:
                                continue
                            target = await client._v2_build_target_from_device(
                                dev,
                                aid=client._aid,
                                device_id=dev_id,
                                role="self_sync",
                                default_key_source="peer_device_prekey",
                            )
                            if target:
                                targets.append(target)
                    except Exception as exc:
                        client._log.debug("client", "V2 self-sync bootstrap failed (non-fatal): %s", exc)

                target_set = {
                    "targets": _v2_apply_wrap_policy_to_targets(targets, wrap_policy),
                    "audit_recipients": _v2_apply_wrap_policy_to_targets(audit_targets, wrap_policy),
                }
                self._target_cache_put(target_cache_key, target_set)
            else:
                target_set = {
                    "targets": [dict(t) for t in target_set.get("targets", []) if isinstance(t, dict)],
                    "audit_recipients": [dict(t) for t in target_set.get("audit_recipients", []) if isinstance(t, dict)],
                }
            sender = client._v2_session.get_sender_identity()
            envelope = encrypt_p2p_message(
                sender=sender,
                target_set=target_set,
                payload=payload,
                message_id=params.get("message_id"),
                timestamp=params.get("timestamp"),
                protected_headers=protected_headers,
                context=params.get("context") if isinstance(params.get("context"), dict) else None,
            )

            client._log_message_debug(
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

            result = await client.call("message.send", {
                "to": to,
                "payload": envelope,
                "encrypt": False,
                "_skip_send_result_envelope": True,
            })
            client._log.debug("client", "message.v2.send ok: to=%s use_cache=%s seq=%s", to, use_cache, result.get("seq") if isinstance(result, dict) else "")
            return result

        try:
            result = await _attempt(use_cache=True)
        except Exception as exc:
            exc_code = getattr(exc, "code", None)
            if exc_code in (-33011, -33012, -33050, -33052, -33054):
                client._log.debug("client", "V2 P2P speculative send rejected (code=%s), refreshing bootstrap: %s", exc_code, exc)
                self.clear_bootstrap_cache(to)
                result = await _attempt(use_cache=False)
            else:
                raise
        return client._delivery().attach_send_result_envelope("message.send", params, result, encrypted=True)

    async def pull_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 拉取并解密消息。内部方法，由 call("message.pull") 路由调用。"""
        from ..errors import StateError

        client = self.client
        background_rpc = bool(params.pop("_rpc_background", False) or getattr(client, "_background_rpc_depth", 0) > 0)
        if not client._v2_session:
            raise StateError("V2 session not initialized (not connected?)")
        after_seq = int(params.get("after_seq", 0) or 0)
        limit = _v2_effective_page_limit(params.get("limit"))
        force = params.get("force") is True

        ns = f"p2p:{client._aid}" if client._aid else ""
        next_after_seq = after_seq if force else (after_seq or client._seq_tracker.get_contiguous_seq(ns))
        first_contig_before = client._seq_tracker.get_contiguous_seq(ns) if ns else 0
        response: dict[str, Any] = {}
        decrypted: list[dict[str, Any]] = []
        total_raw_count = 0
        latest_seq = 0
        server_ack_seq = 0
        page_count = 0
        last_auto_ack_seq = 0
        pending_ack_seq = 0
        max_pages = int(params.get("max_pages", 100) or 100)

        while page_count < max_pages:
            page_count += 1
            ack_up_to_seq = pending_ack_seq
            client._log.debug(
                "client",
                "message.v2.pull page request: page=%d after_seq=%d limit=%d ack_up_to_seq=%d ns=%s",
                page_count, next_after_seq, limit, ack_up_to_seq, ns or "<none>",
            )
            pull_params = {"after_seq": next_after_seq, "limit": limit}
            if force:
                pull_params["force"] = True
            if ack_up_to_seq > 0:
                pull_params["ack_up_to_seq"] = ack_up_to_seq
            result = await client._rpc().raw_call("message.v2.pull", pull_params, background=background_rpc)
            if ack_up_to_seq > 0:
                pending_ack_seq = 0
                last_auto_ack_seq = max(last_auto_ack_seq, ack_up_to_seq)
            if isinstance(result, dict):
                response.update(result)
            else:
                result = {}

            messages = result.get("messages", [])
            raw_page_messages = messages if isinstance(messages, list) else []
            raw_messages = [
                msg for msg in raw_page_messages
                if isinstance(msg, dict) and int(msg.get("seq") or 0) > next_after_seq
            ]
            raw_messages.sort(key=lambda msg: int(msg.get("seq") or 0))
            total_raw_count += len(raw_messages)
            client._log.debug(
                "client",
                "message.v2.pull page response: page=%d raw_count=%d stale_count=%d has_more=%s server_ack_seq=%s",
                page_count, len(raw_messages), max(0, len(raw_page_messages) - len(raw_messages)), result.get("has_more"), result.get("server_ack_seq"),
            )
            for msg in raw_messages:
                client._log_message_debug("pull-raw", "message.v2.pull", "message.received", msg)
            seqs = [
                int(m.get("seq") or 0)
                for m in raw_messages
                if isinstance(m, dict) and int(m.get("seq") or 0) > 0
            ]
            page_contig_before = client._seq_tracker.get_contiguous_seq(ns) if ns else 0

            if seqs:
                page_max_seq = max(seqs)
                latest_seq = max(latest_seq, page_max_seq)
                if ns:
                    client._seq_tracker.force_contiguous_seq(ns, page_max_seq)
                    client._log.debug(
                        "client",
                        "message.v2.pull force contiguous: ns=%s page_max_seq=%d previous=%d",
                        ns, page_max_seq, page_contig_before,
                    )
            else:
                page_max_seq = next_after_seq

            next_after = max(page_max_seq, next_after_seq)
            raw_count = len(raw_messages)
            can_continue_page = raw_count > 0 and next_after > next_after_seq
            full_page = can_continue_page and limit > 0 and raw_count >= limit
            delivered_seqs: list[int] = []
            has_page_server_ack = "server_ack_seq" in result
            page_server_ack = int(result.get("server_ack_seq") or 0)
            server_ack_seq = max(server_ack_seq, page_server_ack)
            if ns and page_server_ack > 0:
                contig = client._seq_tracker.get_contiguous_seq(ns)
                if contig < page_server_ack:
                    client._log.info(
                        "client",
                        "message.v2.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d",
                        ns, contig, page_server_ack,
                    )
                    client._seq_tracker.force_contiguous_seq(ns, page_server_ack)

            if ns and self._can_parallel_decrypt_v2_page(raw_messages, expected_group_id=""):
                page_decrypted = await self._decrypt_p2p_page_parallel(raw_messages)
                for item in page_decrypted:
                    plaintext = await self._apply_p2p_decrypt_result(item, ns)
                    if plaintext is not None:
                        decrypted.append(plaintext)
                        delivered_seqs.append(item.seq)
                    else:
                        client._log.debug("client", "message.v2.pull decrypt returned None: ns=%s seq=%d", ns or "<none>", item.seq)
            else:
                for msg in raw_messages:
                    if not isinstance(msg, dict):
                        continue
                    seq = int(msg.get("seq", 0) or 0)
                    if seq <= 0:
                        continue

                    if str(msg.get("version", "") or "") == "v1":
                        legacy = msg.get("legacy_v1") or {}
                        v1_payload = legacy.get("payload")
                        v1_payload_type = ""
                        if isinstance(v1_payload, dict):
                            v1_payload_type = str(v1_payload.get("type") or "").strip()
                        if v1_payload_type not in ("e2ee.encrypted", "e2ee.group_encrypted") and v1_payload is not None:
                            v1_msg = {
                                "message_id": msg.get("message_id", ""),
                                "from": msg.get("from_aid", ""),
                                "to": legacy.get("to", client._aid),
                                "seq": seq,
                                "type": msg.get("type", ""),
                                "timestamp": msg.get("t_server", 0),
                                "payload": v1_payload,
                                "encrypted": False,
                            }
                            self.attach_gateway_proximity(v1_msg, msg)
                            event_name, event_payload = client._delivery().p2p_app_event_for_message(v1_msg)
                            if ns:
                                await client._publish_pulled_message(event_name, ns, seq, event_payload)
                            else:
                                await client._publish_app_event(event_name, event_payload, source="pull")
                            decrypted.append(v1_msg)
                            delivered_seqs.append(seq)
                            client._log.debug("client", "message.v2.pull plaintext legacy row delivered: ns=%s seq=%d", ns or "<none>", seq)
                        else:
                            client._log.debug("client", "v2.pull skipping legacy envelope seq=%d payload_type=%s (old E2EE removed)",
                                              seq, v1_payload_type or "<none>")
                        continue

                    try:
                        msg_spk_id = str(msg.get("spk_id", "") or "")
                        if msg_spk_id and client._v2_session and msg_spk_id != client._v2_session._spk_id:
                            client._v2_session.track_old_spk_max_seq(msg_spk_id, seq)
                    except Exception:
                        pass
                    plaintext = await client._decrypt_v2_message(msg)
                    if plaintext is None:
                        client._log.debug("client", "message.v2.pull decrypt returned None: ns=%s seq=%d", ns or "<none>", seq)
                        continue
                    if ns:
                        await client._publish_pulled_message("message.received", ns, seq, plaintext)
                    else:
                        await client._publish_app_event("message.received", plaintext, source="pull")
                    decrypted.append(plaintext)
                    delivered_seqs.append(seq)
                    client._log_message_debug("decrypt-ok", "message.v2.pull", "message.received", plaintext)

            if ns:
                for delivered_seq in sorted(set(delivered_seqs)):
                    client._seq_tracker.on_message_seq(ns, delivered_seq)

                if not raw_messages and not decrypted and client._seq_tracker.has_pending_gaps(ns):
                    client._log.info(
                        "client",
                        "message.v2.pull 返回空但有 pending gaps: ns=%s contiguous=%d, 可能原因：多设备竞态/临时消息过期/Push-Pull 时序差",
                        ns, client._seq_tracker.get_contiguous_seq(ns),
                    )

                contig = client._seq_tracker.get_contiguous_seq(ns)
                contig_advanced = contig != page_contig_before
                if contig_advanced:
                    await client._drain_ordered_messages(ns)
                    client._persist_seq(ns)
                ack_needed = (
                    bool(raw_page_messages)
                    and contig > 0
                    and contig > last_auto_ack_seq
                    and (
                        contig_advanced
                        or (has_page_server_ack and contig > page_server_ack)
                    )
                )
                if ack_needed:
                    if can_continue_page:
                        pending_ack_seq = max(pending_ack_seq, contig)
                        last_auto_ack_seq = max(last_auto_ack_seq, contig)
                        client._log.debug(
                            "client",
                            "message.v2.pull queued piggyback auto-ack: ns=%s ack_seq=%d raw_count=%d full_page=%s",
                            ns, pending_ack_seq, raw_count, full_page,
                        )
                    else:
                        client._log.debug(
                            "client",
                            "message.v2.pull sending terminal auto-ack: ns=%s ack_seq=%d raw_count=%d",
                            ns, contig, raw_count,
                        )
                        await client._await_ack("message.v2.ack", {"up_to_seq": contig}, "V2 P2P terminal auto-ack")
                        last_auto_ack_seq = max(last_auto_ack_seq, contig)

            should_continue = can_continue_page and (full_page or pending_ack_seq > 0)
            if not should_continue:
                break
            tail_delay = _v2_pull_tail_delay_seconds(raw_count, limit)
            if tail_delay > 0:
                await asyncio.sleep(tail_delay)
            next_after_seq = next_after

        if page_count >= max_pages:
            client._log.warn("client", "message.v2.pull reached max_pages=%d after_seq=%d", max_pages, next_after_seq)
            if pending_ack_seq > 0:
                client._log.debug("client", "message.v2.pull flushing pending auto-ack after max_pages: ns=%s ack_seq=%d", ns, pending_ack_seq)
                await client._await_ack("message.v2.ack", {"up_to_seq": pending_ack_seq}, "V2 P2P max_pages auto-ack")
                pending_ack_seq = 0

        response["messages"] = decrypted
        response["_contig_before"] = first_contig_before
        response["raw_count"] = total_raw_count
        if latest_seq:
            response["latest_seq"] = max(int(response.get("latest_seq") or 0), latest_seq)
        if server_ack_seq:
            response["server_ack_seq"] = max(int(response.get("server_ack_seq") or 0), server_ack_seq)
        client._log.debug(
            "client",
            "message.v2.pull done: requested_after_seq=%d pages=%d raw_count=%d decrypted=%d ns=%s",
            after_seq, page_count, total_raw_count, len(decrypted), ns or "<none>",
        )
        return response

    def _can_parallel_decrypt_v2_page(self, raw_messages: list[Any], *, expected_group_id: str = "") -> bool:
        if len(raw_messages) <= 1:
            return False
        for msg in raw_messages:
            if not isinstance(msg, dict):
                return False
            try:
                seq = int(msg.get("seq", 0) or 0)
            except (TypeError, ValueError):
                return False
            if seq <= 0:
                return False
            if str(msg.get("version", "") or "") == "v1":
                return False
            envelope_json = msg.get("envelope_json")
            if not envelope_json:
                return False
            try:
                envelope = json.loads(envelope_json)
            except (json.JSONDecodeError, TypeError):
                return False
            aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
            group_id_for_keys = str(msg.get("group_id") or aad.get("group_id") or envelope.get("group_id") or "").strip()
            if expected_group_id:
                if group_id_for_keys != expected_group_id:
                    return False
            elif group_id_for_keys:
                return False
        return True

    def _can_parallel_decrypt_p2p_page(self, raw_messages: list[Any]) -> bool:
        return self._can_parallel_decrypt_v2_page(raw_messages, expected_group_id="")

    async def _prepare_decrypt_job(self, msg: dict[str, Any], seq: int, *, expected_group_id: str = "") -> _DecryptJob | None:
        client = self.client
        envelope_json = msg.get("envelope_json", "")
        try:
            envelope = json.loads(envelope_json)
        except (json.JSONDecodeError, TypeError):
            client._log.warn("client", "V2 decrypt: invalid envelope_json for msg seq=%s", msg.get("seq"))
            return None
        client._agent_md_manager.observe_envelope(envelope)

        spk_id = ""
        recipient_key_source = ""
        if "recipient" in envelope:
            recipient = envelope["recipient"]
            spk_id = str(recipient.get("spk_id", "") or "")
            recipient_key_source = str(recipient.get("key_source") or "")
        elif "recipients" in envelope:
            spk_id = str(msg.get("spk_id", "") or "")
            selected_row = None
            recipients = envelope.get("recipients")
            if isinstance(recipients, list):
                for row in recipients:
                    if (
                        isinstance(row, list)
                        and len(row) >= 6
                        and row[0] == client._aid
                        and (row[1] == client._device_id or row[1] == "")
                    ):
                        selected_row = row
                        if not spk_id:
                            spk_id = str(row[5] or "")
                        break
            if isinstance(selected_row, list) and len(selected_row) >= 4:
                recipient_key_source = str(selected_row[3] or "")

        aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
        group_id_for_keys = str(msg.get("group_id") or aad.get("group_id") or envelope.get("group_id") or "").strip()
        if expected_group_id and group_id_for_keys != expected_group_id:
            return None
        if not expected_group_id and group_id_for_keys:
            return None
        try:
            if group_id_for_keys:
                ik_priv, spk_priv = client._v2_session.get_group_decrypt_keys(group_id_for_keys, spk_id)
            else:
                ik_priv, spk_priv = client._v2_session.get_decrypt_keys(spk_id)
        except Exception as exc:
            client._log.warn("client", "V2 decrypt: SPK lookup failed seq=%s spk_id=%s: %s", msg.get("seq"), spk_id, exc)
            event_name = "group.message_undecryptable" if group_id_for_keys else "message.undecryptable"
            event = {
                "message_id": msg.get("message_id", ""),
                "from": msg.get("from_aid", ""),
                "to": msg.get("to", ""),
                "seq": msg.get("seq"),
                "timestamp": msg.get("t_server") or msg.get("timestamp"),
                "device_id": msg.get("device_id", ""),
                "slot_id": msg.get("slot_id", ""),
                "_decrypt_error": str(exc),
                "_decrypt_stage": "spk_lookup",
                "_envelope_type": envelope.get("type", ""),
                "_suite": envelope.get("suite", ""),
                "_spk_id": spk_id,
            }
            client._attach_v2_envelope_metadata(event, client._v2_thought_e2ee_metadata(envelope))
            await client._dispatcher.publish(event_name, event)
            return None

        from_aid = str(msg.get("from_aid") or "")
        sender_device_id = str(aad.get("from_device") or "")
        sender_cert_fingerprint = str(envelope.get("sender_cert_fingerprint") or "").strip().lower()
        sender_pub_der = await client._v2_sender_pub_der_from_cache_or_cert(from_aid, sender_device_id, sender_cert_fingerprint)
        if not sender_pub_der:
            client._log.warn("client", "V2 decrypt: no sender IK for %s device=%s", from_aid, sender_device_id)
            client._schedule_v2_sender_ik_pending(
                msg=msg,
                envelope=envelope,
                from_aid=from_aid,
                sender_device_id=sender_device_id,
                group_id=group_id_for_keys,
            )
            return None
        return _DecryptJob(
            seq=seq,
            msg=msg,
            envelope=envelope,
            spk_id=spk_id,
            recipient_key_source=recipient_key_source,
            group_id=group_id_for_keys,
            from_aid=from_aid,
            sender_device_id=sender_device_id,
            ik_priv=ik_priv,
            spk_priv=spk_priv,
            sender_pub_der=sender_pub_der,
        )

    async def _prepare_p2p_decrypt_job(self, msg: dict[str, Any], seq: int) -> _DecryptJob | None:
        return await self._prepare_decrypt_job(msg, seq)

    async def _decrypt_page_parallel(self, raw_messages: list[Any], *, expected_group_id: str = "") -> list[_DecryptResult]:
        client = self.client
        jobs: list[_DecryptJob] = []
        for msg in raw_messages:
            seq = int(msg.get("seq", 0) or 0)
            if not expected_group_id:
                try:
                    msg_spk_id = str(msg.get("spk_id", "") or "")
                    if msg_spk_id and client._v2_session and msg_spk_id != client._v2_session._spk_id:
                        client._v2_session.track_old_spk_max_seq(msg_spk_id, seq)
                except Exception:
                    pass
            job = await self._prepare_decrypt_job(msg, seq, expected_group_id=expected_group_id)
            if job is None:
                continue
            jobs.append(job)
        if not jobs:
            return []
        tasks = [
            asyncio.to_thread(_decrypt_job_sync, job, aid=client._aid, device_id=client._device_id)
            for job in jobs
        ]
        results = await asyncio.gather(*tasks)
        results.sort(key=lambda item: item.seq)
        return results

    async def _decrypt_p2p_page_parallel(self, raw_messages: list[Any]) -> list[_DecryptResult]:
        return await self._decrypt_page_parallel(raw_messages)

    async def _apply_p2p_decrypt_result(self, item: _DecryptResult, ns: str) -> dict[str, Any] | None:
        client = self.client
        msg = item.msg
        if item.error is not None:
            client._log.warn("client", "V2 decrypt failed for msg seq=%s: %s", msg.get("seq"), item.error)
            event = {
                "message_id": msg.get("message_id", ""),
                "from": item.from_aid,
                "to": msg.get("to", ""),
                "seq": msg.get("seq"),
                "timestamp": msg.get("t_server") or msg.get("timestamp"),
                "device_id": msg.get("device_id", ""),
                "slot_id": msg.get("slot_id", ""),
                "_decrypt_error": str(item.error),
                "_decrypt_stage": "decrypt",
                "_envelope_type": item.envelope.get("type", ""),
                "_suite": item.envelope.get("suite", ""),
            }
            client._attach_v2_envelope_metadata(event, client._v2_thought_e2ee_metadata(item.envelope))
            await client._dispatcher.publish("message.undecryptable", event)
            return None
        if item.plaintext is None:
            return None

        if not item.from_aid and isinstance(msg.get("from_aid"), str):
            item.from_aid = str(msg.get("from_aid") or "")
        is_last_uploaded_spk = getattr(client._v2_session, "is_last_uploaded_spk", None) if client._v2_session else None
        if item.spk_id and callable(is_last_uploaded_spk) and is_last_uploaded_spk(item.spk_id):
            client._log.debug(
                "client",
                "SPK rotation check: spk_id=%s last_uploaded=%s matched=%s",
                item.spk_id,
                client._v2_session._last_uploaded_spk_id,
                True,
            )

            async def _do_rotate():
                try:
                    await client._v2_session.rotate_spk(client.call)
                    client._log.debug("client", "V2 SPK rotated after consumption: aid=%s", client._aid)
                except Exception as exc:
                    client._log.warn("client", "V2 SPK rotation failed (non-fatal): %s", exc)

            loop = client._loop or asyncio.get_running_loop()
            loop.create_task(_do_rotate())

        meta = client._v2_thought_e2ee_metadata(item.envelope)
        result = {
            "message_id": msg.get("message_id", ""),
            "from": item.from_aid,
            "to": client._aid,
            "seq": msg.get("seq"),
            "t_server": msg.get("t_server"),
            "payload": item.plaintext,
            "encrypted": True,
            "e2ee": meta,
        }
        direction = str(msg.get("direction") or "").strip()
        if not direction:
            direction = "outbound_sync" if item.from_aid and item.from_aid == client._aid else "inbound"
        if direction:
            result["direction"] = direction
        if "device_id" in msg:
            result["device_id"] = msg.get("device_id")
        if "slot_id" in msg:
            result["slot_id"] = msg.get("slot_id")
        self.attach_gateway_proximity(result, msg)
        client._attach_v2_envelope_metadata(result, meta)
        await client._publish_pulled_message("message.received", ns, item.seq, result)
        client._log_message_debug("decrypt-ok", "message.v2.pull", "message.received", result)
        return result

    async def _apply_group_decrypt_result(self, item: _DecryptResult, group_id: str, ns: str) -> dict[str, Any] | None:
        client = self.client
        msg = item.msg
        if item.error is not None:
            client._log.warn("client", "V2 decrypt failed for msg seq=%s: %s", msg.get("seq"), item.error)
            event = {
                "message_id": msg.get("message_id", ""),
                "from": item.from_aid,
                "to": msg.get("to", ""),
                "seq": msg.get("seq"),
                "timestamp": msg.get("t_server") or msg.get("timestamp"),
                "device_id": msg.get("device_id", ""),
                "slot_id": msg.get("slot_id", ""),
                "_decrypt_error": str(item.error),
                "_decrypt_stage": "decrypt",
                "_envelope_type": item.envelope.get("type", ""),
                "_suite": item.envelope.get("suite", ""),
            }
            client._attach_v2_envelope_metadata(event, client._v2_thought_e2ee_metadata(item.envelope))
            await client._dispatcher.publish("group.message_undecryptable", event)
            return None
        if item.plaintext is None:
            return None

        if (
            item.recipient_key_source == "group_device_prekey"
            and client._v2_session
            and callable(getattr(client._v2_session, "is_last_uploaded_group_spk", None))
            and client._v2_session.is_last_uploaded_group_spk(group_id, item.spk_id)
        ):
            client._schedule_group_spk_rotation(group_id, reason="group_spk_consumed")
        elif item.recipient_key_source == "peer_device_prekey":
            client._schedule_group_spk_registration_after_peer_fallback(group_id)

        meta = client._v2_thought_e2ee_metadata(item.envelope)
        result = {
            "message_id": msg.get("message_id", ""),
            "from": item.from_aid,
            "to": client._aid,
            "seq": msg.get("seq"),
            "t_server": msg.get("t_server"),
            "payload": item.plaintext,
            "encrypted": True,
            "e2ee": meta,
            "group_id": group_id,
        }
        direction = str(msg.get("direction") or "").strip()
        if not direction:
            direction = "outbound_sync" if item.from_aid and item.from_aid == client._aid else "inbound"
        if direction:
            result["direction"] = direction
        if "device_id" in msg:
            result["device_id"] = msg.get("device_id")
        if "slot_id" in msg:
            result["slot_id"] = msg.get("slot_id")
        self.attach_gateway_proximity(result, msg)
        client._attach_v2_envelope_metadata(result, meta)
        await client._publish_pulled_message("group.message_created", ns, item.seq, result)
        client._log_message_debug("decrypt-ok", "group.v2.pull", "group.message_created", result)
        return result

    async def ack_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 P2P 确认消费 + 自检销毁旧 SPK。内部方法，由 call("message.ack") 路由调用。"""
        client = self.client
        background_rpc = bool(params.pop("_rpc_background", False) or getattr(client, "_background_rpc_depth", 0) > 0)
        ns = f"p2p:{client._aid}" if client._aid else ""
        up_to_seq = int(params.get("seq", 0) or params.get("up_to_seq", 0) or 0)
        seq = up_to_seq or (client._seq_tracker.get_contiguous_seq(ns) if ns else 0)
        if seq <= 0:
            client._log.debug("client", "message.v2.ack skipped: ns=%s up_to_seq=%s", ns or "<none>", up_to_seq)
            return {"acked": 0}
        if ns:
            max_seen = client._seq_tracker.get_max_seen_seq(ns)
            if max_seen > 0 and seq > max_seen:
                client._log.warn(
                    "client",
                    "_ack_v2_internal clamp: up_to_seq=%d > max_seen=%d, clamp",
                    seq, max_seen,
                )
                seq = max_seen
        client._log.debug("client", "message.v2.ack send: ns=%s up_to_seq=%d", ns or "<none>", seq)
        ack_params: dict[str, Any] = {"up_to_seq": seq}
        if background_rpc:
            ack_params["_rpc_background"] = True
        result = await client.call("message.v2.ack", ack_params)
        actual_ack_seq = seq
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
            if result.get("acked", 0) == 0 and actual_ack_seq > 0:
                result["acked"] = actual_ack_seq
        if client._v2_session:
            try:
                destroyed = client._v2_session.maybe_destroy_old_spks(actual_ack_seq)
                if destroyed:
                    client._log.info("client", "V2 destroyed old SPKs after ack: %s (PFS)", destroyed[:3])
            except Exception as exc:
                client._log.debug("client", "V2 SPK destroy failed (non-fatal): %s", exc)
        client._log.debug("client", "message.v2.ack ok: ns=%s requested=%d effective=%d result=%s", ns or "<none>", seq, actual_ack_seq, result)
        return result

    async def build_v2_p2p_envelope(
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
        """V2 P2P 多设备 wrap envelope 构造（不发送）。"""
        from ..client import (
            _v2_apply_wrap_policy_to_targets,
            _v2_device_id_from_device,
            _v2_normalize_wrap_policy,
            _v2_wrap_capabilities,
        )
        from ..errors import E2EEError
        from ..v2.e2ee.encrypt_p2p import encrypt_p2p_message

        client = self.client
        cached = client._v2_bootstrap_cache.get(to) if use_cache else None
        if cached and (time.time() - cached[1]) < client._V2_BOOTSTRAP_TTL:
            peer_devices = cached[0]
            audit_recipients_raw = cached[2] if len(cached) > 2 and isinstance(cached[2], list) else []
            self_devices_from_bootstrap = cached[3] if len(cached) > 3 and isinstance(cached[3], list) else None
            wrap_policy = cached[4] if len(cached) > 4 else None
        else:
            self._target_cache().pop(to, None)
            bootstrap = await client.call("message.v2.bootstrap", {
                "peer_aid": to,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
            if isinstance(bootstrap, dict):
                await client._prime_bootstrap_peer_certs(bootstrap, to)
            peer_devices = bootstrap.get("peer_devices", [])
            audit_recipients_raw = bootstrap.get("audit_recipients", []) or []
            wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
            raw_self_devices = bootstrap.get("self_devices")
            self_devices_from_bootstrap = raw_self_devices if isinstance(raw_self_devices, list) else None
            if peer_devices:
                client._v2_bootstrap_cache[to] = (
                    peer_devices,
                    time.time(),
                    audit_recipients_raw,
                    self_devices_from_bootstrap,
                    wrap_policy,
                )
            if client._aid and self_devices_from_bootstrap:
                client._v2_bootstrap_cache[client._aid] = (self_devices_from_bootstrap, time.time())

        if not peer_devices:
            raise E2EEError(f"V2 bootstrap: no devices found for {to}")

        sender = client._v2_session.get_sender_identity()
        target_set = self._target_cache_get(to, client._V2_BOOTSTRAP_TTL) if use_cache else None
        if target_set is None:
            targets: list[dict[str, Any]] = []
            audit_targets: list[dict[str, Any]] = []
            for dev in peer_devices:
                target = await client._v2_build_target_from_device(
                    dev,
                    aid=to,
                    device_id=dev.get("device_id", ""),
                    role="peer",
                    default_key_source="peer_device_prekey",
                )
                if target:
                    targets.append(target)

            for dev in audit_recipients_raw:
                target = await client._v2_build_target_from_device(
                    dev,
                    aid=dev.get("aid", ""),
                    device_id=dev.get("device_id", ""),
                    role="audit",
                    default_key_source="peer_device_prekey",
                )
                if target:
                    audit_targets.append(target)

            if client._aid and client._aid != to:
                try:
                    self_devices = self_devices_from_bootstrap if self_devices_from_bootstrap else None
                    if self_devices is None:
                        self_cached = client._v2_bootstrap_cache.get(client._aid)
                        if self_cached and (time.time() - self_cached[1]) < client._V2_BOOTSTRAP_TTL:
                            self_devices = self_cached[0]
                        else:
                            self_bs = await client.call("message.v2.bootstrap", {
                                "peer_aid": client._aid,
                                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                            })
                            self_devices = self_bs.get("peer_devices", [])
                            if self_devices:
                                client._v2_bootstrap_cache[client._aid] = (self_devices, time.time())
                    for dev in self_devices:
                        has_dev_id, dev_id = _v2_device_id_from_device(dev)
                        if not has_dev_id or dev_id == client._device_id:
                            continue
                        target = await client._v2_build_target_from_device(
                            dev,
                            aid=client._aid,
                            device_id=dev_id,
                            role="self_sync",
                            default_key_source="peer_device_prekey",
                        )
                        if target:
                            targets.append(target)
                except Exception as exc:
                    client._log.debug("client", "V2 thought self-sync bootstrap failed (non-fatal): %s", exc)

            target_set = {
                "targets": _v2_apply_wrap_policy_to_targets(targets, wrap_policy),
                "audit_recipients": _v2_apply_wrap_policy_to_targets(audit_targets, wrap_policy),
            }
            self._target_cache_put(to, target_set)
        else:
            target_set = {
                "targets": [dict(t) for t in target_set.get("targets", []) if isinstance(t, dict)],
                "audit_recipients": [dict(t) for t in target_set.get("audit_recipients", []) if isinstance(t, dict)],
            }
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

    async def send_group_encrypted_v2(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 加密发送。内部方法，由 call("group.send") 路由调用。"""
        from ..client import (
            _v2_apply_wrap_policy_to_targets,
            _v2_device_id_from_device,
            _v2_normalize_wrap_policy,
            _v2_wrap_capabilities,
        )
        from ..errors import E2EEError, StateError, ValidationError
        from ..v2.e2ee.encrypt_group import encrypt_group_message

        client = self.client
        background_rpc = bool(params.pop("_rpc_background", False))
        if not client._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        _wire_group_id, group_id = _group_identifier_pair(params)
        payload = params.get("payload") or {}
        if not group_id:
            raise ValidationError("group.send requires 'group_id'")
        if not isinstance(payload, dict):
            raise ValidationError("group.send payload must be a dict for V2 encryption")
        protected_headers = self._protected_headers_dict(client._protected_headers_from_params(params))
        client._log_message_debug(
            "send-plaintext",
            "group.send.v2",
            "group.send",
            params,
            payload_override=payload,
            extra={"group_id": group_id},
        )

        def _text_set(raw: Any) -> set[str]:
            if not isinstance(raw, (list, tuple, set)):
                return set()
            return {str(item).strip() for item in raw if str(item or "").strip()}

        def _expected_peer_aids(
            *,
            member_aids: set[str],
            committed_aids: set[str],
        ) -> set[str]:
            candidates: set[str] = set()
            candidates.update(member_aids)
            candidates.update(committed_aids)
            return {aid for aid in candidates if aid and aid != client._aid}

        async def _attempt(use_cache: bool) -> dict[str, Any]:
            client._log.debug("client", "group.v2.send attempt: group=%s use_cache=%s", group_id, use_cache)
            cache_key = f"group:{group_id}"
            epoch = 0
            used_cached_bootstrap = False
            if use_cache:
                cached = client._v2_bootstrap_cache.get(cache_key)
                if cached and (time.time() - cached[1]) < client._V2_GROUP_BOOTSTRAP_TTL:
                    all_devices = cached[0]
                    epoch = cached[2] if len(cached) > 2 else 0
                    wrap_policy = cached[7] if len(cached) > 7 else None
                    used_cached_bootstrap = True
                else:
                    all_devices = None
                    wrap_policy = None
            else:
                all_devices = None
                wrap_policy = None

            if all_devices is None:
                self._target_cache().pop(cache_key, None)
                bootstrap = await client.call("group.v2.bootstrap", {
                    "group_id": group_id,
                    "group_aid": group_id,
                    "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
                })
                all_devices = bootstrap.get("devices", [])
                epoch = int(bootstrap.get("epoch", 0))
                wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
                pending_adds = _text_set(bootstrap.get("pending_adds", []))
                committed_aids = _text_set(bootstrap.get("committed_member_aids", []))
                member_aids = _text_set(bootstrap.get("member_aids", []))
                server_chain = str(bootstrap.get("state_chain", "") or "")
                await client._v2_check_fork(group_id, server_chain)
                await client._v2_verify_state_signature(group_id, bootstrap)
                state_commitment = {
                    "state_version": int(bootstrap.get("state_version", 0) or 0),
                    "state_hash": str(bootstrap.get("state_hash_signed") or bootstrap.get("state_hash") or ""),
                    "state_chain": server_chain,
                }
                audit_recipients_raw = bootstrap.get("audit_recipients", []) or []
                level = str(bootstrap.get("e2ee_security_level", "") or "").strip() or "end_to_end"
                prev_level = client._v2_group_security_levels.get(group_id)
                if prev_level != level:
                    client._v2_group_security_levels[group_id] = level
                    try:
                        await client._dispatcher.publish("group.v2.security_level", {
                            "group_id": group_id,
                            "level": level,
                            "warning": str(bootstrap.get("e2ee_security_warning", "") or ""),
                            "previous_level": prev_level,
                        })
                    except Exception as exc:
                        client._log.debug("client", "publish group.v2.security_level failed (non-fatal): %s", exc)
                if all_devices:
                    client._v2_bootstrap_cache[cache_key] = (
                        all_devices, time.time(), epoch, pending_adds, committed_aids,
                        state_commitment, audit_recipients_raw, wrap_policy, member_aids,
                    )
                if pending_adds and client._v2_session:
                    client._v2_maybe_trigger_auto_propose(group_id)
            else:
                pending_adds = cached[3] if len(cached) > 3 else set()
                committed_aids = cached[4] if len(cached) > 4 else set()
                state_commitment = cached[5] if len(cached) > 5 else {"state_version": 0, "state_hash": "", "state_chain": ""}
                audit_recipients_raw = cached[6] if len(cached) > 6 else []
                wrap_policy = cached[7] if len(cached) > 7 else None
                member_aids = cached[8] if len(cached) > 8 else set()

            if not all_devices:
                raise E2EEError(f"V2 group bootstrap: no devices found for group {group_id}")

            targets = self._target_cache_get(cache_key, client._V2_GROUP_BOOTSTRAP_TTL) if use_cache else None
            if targets is None:
                targets = []
                for dev in all_devices:
                    dev_aid = str(dev.get("aid", "") or "").strip()
                    has_dev_id, dev_id = _v2_device_id_from_device(dev)
                    if dev_aid == client._aid and has_dev_id and dev_id == client._device_id:
                        continue
                    role = "self_sync" if dev_aid == client._aid else "member"
                    target = await client._v2_build_target_from_device(
                        dev,
                        aid=dev_aid,
                        device_id=dev_id,
                        role=role,
                        default_key_source="peer_device_prekey",
                    )
                    if target:
                        targets.append(target)

                if not targets:
                    expected_peer_aids = _expected_peer_aids(
                        member_aids=member_aids,
                        committed_aids=committed_aids,
                    )
                    if expected_peer_aids:
                        raise E2EEError(
                            f"V2 group: no target devices for group {group_id}; bootstrap may be stale",
                            code=-33054,
                            data={"expected_peer_aids": sorted(expected_peer_aids)},
                        )
                    if used_cached_bootstrap:
                        raise E2EEError(
                            f"V2 group: no target devices for group {group_id}; bootstrap may be stale",
                            code=-33054,
                            data={"expected_peer_aids": []},
                        )
                    raise E2EEError(f"V2 group: no target devices for group {group_id}")

                for dev in audit_recipients_raw:
                    target = await client._v2_build_target_from_device(
                        dev,
                        aid=dev.get("aid", ""),
                        device_id=dev.get("device_id", ""),
                        role="audit",
                        default_key_source="peer_device_prekey",
                    )
                    if target:
                        targets.append(target)
                targets = _v2_apply_wrap_policy_to_targets(targets, wrap_policy)
                self._target_cache_put(cache_key, targets)
            else:
                targets = [dict(t) for t in targets if isinstance(t, dict)]

            sender = client._v2_session.get_sender_identity()
            envelope = encrypt_group_message(
                sender=sender,
                group_id=group_id,
                epoch=epoch,
                targets=targets,
                payload=payload,
                state_commitment=state_commitment,
                message_id=params.get("message_id"),
                timestamp=params.get("timestamp"),
                protected_headers=protected_headers,
                context=params.get("context") if isinstance(params.get("context"), dict) else None,
            )

            client._log_message_debug(
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

            result = await client.call("group.v2.send", {
                "group_id": group_id,
                "group_aid": group_id,
                "envelope": envelope,
            })
            client._log.debug("client", "group.v2.send ok: group=%s use_cache=%s seq=%s", group_id, use_cache, result.get("seq") if isinstance(result, dict) else "")
            return result

        retries = 0
        use_cache = True
        while True:
            try:
                result = await _attempt(use_cache=use_cache)
                break
            except Exception as exc:
                exc_code = getattr(exc, "code", None)
                if exc_code not in (-33011, -33012, -33050, -33052, -33054):
                    raise
                max_retries = 2 if exc_code == -33054 else 1
                if retries >= max_retries:
                    raise
                retries += 1
                client._log.debug("client", "group V2 speculative send rejected (code=%s), refreshing bootstrap: %s", exc_code, exc)
                self.clear_group_bootstrap_cache(group_id)
                use_cache = False
                if exc_code == -33054 and retries > 1:
                    await asyncio.sleep(0.25 * (retries - 1))

        if isinstance(result, dict) and result.get("seq"):
            ns = f"group:{group_id}"
            seq = int(result["seq"])
            client._seq_tracker.on_message_seq(ns, seq)
            client._mark_published_seq(ns, seq)
            client._persist_seq(ns)
            client._log.debug("client", "group.v2.send marked own seq: group=%s ns=%s seq=%d", group_id, ns, seq)
        return client._delivery().attach_send_result_envelope("group.send", params, result, encrypted=True)

    async def build_v2_group_envelope(
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
        from ..client import (
            _v2_apply_wrap_policy_to_targets,
            _v2_device_id_from_device,
            _v2_normalize_wrap_policy,
            _v2_wrap_capabilities,
        )
        from ..errors import E2EEError
        from ..v2.e2ee.encrypt_group import encrypt_group_message

        client = self.client
        cache_key = f"group:{group_id}"
        cached = client._v2_bootstrap_cache.get(cache_key) if use_cache else None
        if cached and (time.time() - cached[1]) < client._V2_GROUP_BOOTSTRAP_TTL:
            all_devices = cached[0]
            epoch = cached[2] if len(cached) > 2 else 0
            state_commitment = cached[5] if len(cached) > 5 else {"state_version": 0, "state_hash": "", "state_chain": ""}
            audit_recipients_raw = cached[6] if len(cached) > 6 else []
            wrap_policy = cached[7] if len(cached) > 7 else None
            client._log.debug(
                "client",
                "group.v2.bootstrap cache hit: group=%s devices=%d audit=%d epoch=%s state_version=%s",
                group_id, len(all_devices), len(audit_recipients_raw), epoch, state_commitment.get("state_version"),
            )
        else:
            self._target_cache().pop(cache_key, None)
            bootstrap = await client.call("group.v2.bootstrap", {
                "group_id": group_id,
                "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
            })
            all_devices = bootstrap.get("devices", [])
            epoch = int(bootstrap.get("epoch", 0))
            wrap_policy = _v2_normalize_wrap_policy(bootstrap.get("e2ee_wrap_policy"))
            client._log.debug(
                "client",
                "group.v2.bootstrap fetched: group=%s devices=%d audit=%d epoch=%s members=%d",
                group_id,
                len(all_devices) if isinstance(all_devices, list) else 0,
                len(bootstrap.get("audit_recipients", []) or []),
                epoch,
                len(bootstrap.get("member_aids", []) or []),
            )
            server_chain = str(bootstrap.get("state_chain", "") or "")
            await client._v2_check_fork(group_id, server_chain)
            await client._v2_verify_state_signature(group_id, bootstrap)
            state_commitment = {
                "state_version": int(bootstrap.get("state_version", 0) or 0),
                "state_hash": str(bootstrap.get("state_hash_signed") or bootstrap.get("state_hash") or ""),
                "state_chain": server_chain,
            }
            audit_recipients_raw = bootstrap.get("audit_recipients", []) or []
            pending_adds = set(bootstrap.get("pending_adds", []))
            committed_aids = set(bootstrap.get("committed_member_aids", []))
            if all_devices:
                client._v2_bootstrap_cache[cache_key] = (
                    all_devices, time.time(), epoch, pending_adds, committed_aids,
                    state_commitment, audit_recipients_raw, wrap_policy,
                )
            if pending_adds and client._v2_session:
                client._v2_maybe_trigger_auto_propose(group_id)

        if not all_devices:
            raise E2EEError(f"V2 group bootstrap: no devices for {group_id}")

        targets = self._target_cache_get(cache_key, client._V2_GROUP_BOOTSTRAP_TTL) if use_cache else None
        if targets is None:
            targets = []
            for dev in all_devices:
                dev_aid = dev.get("aid", "")
                has_dev_id, dev_id = _v2_device_id_from_device(dev)
                if dev_aid == client._aid and has_dev_id and dev_id == client._device_id:
                    continue
                role = "self_sync" if dev_aid == client._aid else "member"
                target = await client._v2_build_target_from_device(
                    dev,
                    aid=dev_aid,
                    device_id=dev_id,
                    role=role,
                    default_key_source="peer_device_prekey",
                )
                if target:
                    targets.append(target)

            for dev in audit_recipients_raw:
                target = await client._v2_build_target_from_device(
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
            targets = _v2_apply_wrap_policy_to_targets(targets, wrap_policy)
            self._target_cache_put(cache_key, targets)
        else:
            targets = [dict(t) for t in targets if isinstance(t, dict)]

        sender = client._v2_session.get_sender_identity()
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
        client._log_message_debug(
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

    async def put_message_thought_encrypted_v2(self, params: dict[str, Any]) -> Any:
        """V2 P2P thought.put：使用 V2 多设备 wrap envelope。"""
        from ..errors import ValidationError

        client = self.client
        to_aid = str(params.get("to") or "").strip()
        client._validate_message_recipient(to_aid)
        payload = params.get("payload")
        if not to_aid:
            raise ValidationError("message.thought.put requires to")
        if not isinstance(payload, dict):
            raise ValidationError("message.thought.put payload must be an object when encrypt=true")

        thought_id = str(params.get("thought_id") or f"mt-{uuid.uuid4()}").strip()
        timestamp = int(params.get("timestamp") or time.time() * 1000)
        protected_headers = self._protected_headers_dict(client._protected_headers_from_params(params))
        client._log_message_debug(
            "thought-send-plaintext",
            "message.thought.put.v2",
            "message.thought.put",
            {"to": to_aid, "thought_id": thought_id, "timestamp": timestamp, "payload": payload},
            payload_override=payload,
        )

        async def _attempt(use_cache: bool) -> Any:
            client._log.debug("client", "message.thought.put attempt: to=%s thought_id=%s use_cache=%s", to_aid, thought_id, use_cache)
            envelope = await client._build_v2_p2p_envelope(
                to=to_aid,
                payload=payload,
                message_id=thought_id,
                timestamp=timestamp,
                use_cache=use_cache,
                protected_headers=protected_headers,
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
            client._sign_client_operation("message.thought.put", send_params)
            client._log_message_debug(
                "thought-send-envelope",
                "message.thought.put.v2",
                "message.thought.put",
                send_params,
                payload_override=envelope,
                extra={"to": to_aid, "thought_id": thought_id, "use_cache": use_cache},
            )
            result = await client._transport.call("message.thought.put", send_params)
            client._log.debug("client", "message.thought.put ok: to=%s thought_id=%s use_cache=%s", to_aid, thought_id, use_cache)
            return result

        try:
            result = await _attempt(use_cache=True)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "device" in err_msg or "prekey" in err_msg or "recipient" in err_msg or "stale" in err_msg:
                client._log.debug("client", "V2 P2P thought put speculative rejected, refreshing bootstrap: %s", exc)
                self.clear_bootstrap_cache(to_aid)
                result = await _attempt(use_cache=False)
            else:
                raise
        return client._delivery().attach_send_result_envelope("message.thought.put", {
            **params,
            "to": to_aid,
            "payload": payload,
            "thought_id": thought_id,
            "timestamp": timestamp,
            "protected_headers": protected_headers,
        }, result, encrypted=True)

    async def put_group_thought_encrypted_v2(self, params: dict[str, Any]) -> Any:
        """V2 Group thought.put：多设备 wrap envelope。"""
        from ..errors import ValidationError

        client = self.client
        group_id = str(params.get("group_id") or "").strip()
        payload = params.get("payload")
        if not group_id:
            raise ValidationError("group.thought.put requires 'group_id'")
        if not isinstance(payload, dict):
            raise ValidationError("group.thought.put payload must be an object when encrypt=true")
        thought_id = str(params.get("thought_id") or f"gt-{uuid.uuid4()}").strip()
        timestamp = int(params.get("timestamp") or time.time() * 1000)
        protected_headers = self._protected_headers_dict(client._protected_headers_from_params(params))
        client._log_message_debug(
            "thought-send-plaintext",
            "group.thought.put.v2",
            "group.thought.put",
            {"group_id": group_id, "thought_id": thought_id, "timestamp": timestamp, "payload": payload},
            payload_override=payload,
        )

        async def _attempt(use_cache: bool) -> Any:
            client._log.debug("client", "group.thought.put attempt: group=%s thought_id=%s use_cache=%s", group_id, thought_id, use_cache)
            envelope = await client._build_v2_group_envelope(
                group_id=group_id,
                payload=payload,
                message_id=thought_id,
                timestamp=timestamp,
                use_cache=use_cache,
                protected_headers=protected_headers,
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
            client._sign_client_operation("group.thought.put", send_params)
            client._log_message_debug(
                "thought-send-envelope",
                "group.thought.put.v2",
                "group.thought.put",
                send_params,
                payload_override=envelope,
                extra={"group_id": group_id, "thought_id": thought_id, "use_cache": use_cache},
            )
            result = await client._transport.call("group.thought.put", send_params)
            client._log.debug("client", "group.thought.put ok: group=%s thought_id=%s use_cache=%s", group_id, thought_id, use_cache)
            return result

        try:
            result = await _attempt(use_cache=True)
        except Exception as exc:
            err_msg = str(exc).lower()
            if "member" in err_msg or "device" in err_msg or "recipient" in err_msg or "stale" in err_msg or "epoch" in err_msg:
                client._log.debug("client", "V2 group thought put speculative rejected, refreshing bootstrap: %s", exc)
                self.clear_group_bootstrap_cache(group_id)
                result = await _attempt(use_cache=False)
            else:
                raise
        return client._delivery().attach_send_result_envelope("group.thought.put", {
            **params,
            "group_id": group_id,
            "payload": payload,
            "thought_id": thought_id,
            "timestamp": timestamp,
            "protected_headers": protected_headers,
        }, result, encrypted=True)

    async def decrypt_group_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        return await self.decrypt_thought_get_result(result, group=True)

    async def decrypt_message_thoughts(self, result: dict[str, Any]) -> dict[str, Any]:
        return await self.decrypt_thought_get_result(result, group=False)

    async def decrypt_thought_get_result(self, result: dict[str, Any], *, group: bool) -> dict[str, Any]:
        """解密 thought.get 返回中的 V2 envelope，并保留服务端返回的元数据字段。"""
        client = self.client
        label = "group" if group else "message"
        client._log.debug(
            "client",
            "%s.thought.get decrypt enter: found=%s sender=%s group=%s peer=%s",
            label,
            result.get("found"),
            result.get("sender_aid"),
            result.get("group_id"),
            result.get("peer_aid"),
        )
        if not result.get("found"):
            client._log.debug("client", "%s.thought.get decrypt exit: not found", label)
            return {**result, "thoughts": []}
        raw_items = result.get("thoughts")
        if not isinstance(raw_items, list):
            client._log.debug("client", "%s.thought.get decrypt exit: invalid thoughts", label)
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
            client._log_message_debug(
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
                to_aid = str(item.get("to") or item.get("peer_aid") or peer_aid or client._aid or "").strip()
                if from_aid and "from" not in item:
                    item["from"] = from_aid
                if to_aid and "to" not in item:
                    item["to"] = to_aid

            if payload and client._is_v2_thought_envelope(payload, group=group):
                meta = client._v2_thought_e2ee_metadata(payload)
                plaintext = await client._decrypt_v2_envelope_for_thought(envelope=payload, from_aid=from_aid)
                item["e2ee"] = meta
                client._attach_v2_envelope_metadata(item, meta)
                if plaintext is None:
                    item["decrypt_failed"] = True
                    failed_count += 1
                    client._log.debug("client", "%s.thought.get decrypt returned None: thought_id=%s from=%s", label, thought_id, from_aid)
                else:
                    item["payload"] = plaintext
                    item["encrypted"] = True
                    item.pop("decrypt_failed", None)
                    decrypted_count += 1
                    client._log_message_debug(
                        "thought-decrypt-ok",
                        f"{label}.thought.get",
                        f"{label}.thought.get",
                        item,
                        payload_override=plaintext,
                        extra={"thought_id": thought_id, "from": from_aid},
                    )
            elif payload and client._is_encrypted_thought_payload(payload):
                item["decrypt_failed"] = True
                failed_count += 1
                client._log.debug(
                    "client",
                    "%s.thought.get unsupported encrypted payload: thought_id=%s type=%s version=%s",
                    label, thought_id, payload.get("type"), payload.get("version"),
                )
            client._log_message_debug(
                "thought-result",
                f"{label}.thought.get",
                f"{label}.thought.get",
                item,
                extra={"thought_id": thought_id, "decrypt_failed": bool(item.get("decrypt_failed"))},
            )
            thoughts.append(item)

        client._log.debug(
            "client",
            "%s.thought.get post-decrypt: total=%d decrypted=%d failed=%d",
            label,
            len(thoughts),
            decrypted_count,
            failed_count,
        )
        return {**result, "thoughts": thoughts}

    @staticmethod
    def is_v2_thought_envelope(payload: dict[str, Any], *, group: bool) -> bool:
        expected_type = "e2ee.group_encrypted" if group else "e2ee.p2p_encrypted"
        if str(payload.get("type") or "") != expected_type:
            return False
        return str(payload.get("version") or "") == "v2" or isinstance(payload.get("recipients"), list)

    @staticmethod
    def is_encrypted_thought_payload(payload: dict[str, Any]) -> bool:
        return str(payload.get("type") or "") in {
            "e2ee.encrypted",
            "e2ee.p2p_encrypted",
            "e2ee.group_encrypted",
        }

    @staticmethod
    def metadata_without_auth(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {k: v for k, v in value.items() if k != "_auth"}

    @staticmethod
    def v2_envelope_payload_type(envelope: dict[str, Any], protected_headers: dict[str, Any] | None = None) -> str:
        value = envelope.get("payload_type")
        if value is None and isinstance(protected_headers, dict):
            value = protected_headers.get("payload_type")
        return str(value or "").strip()

    def v2_thought_e2ee_metadata(self, envelope: dict[str, Any]) -> dict[str, Any]:
        suite = str(envelope.get("suite") or "")
        meta: dict[str, Any] = {
            "version": "v2",
            "suite": suite,
            "encryption_mode": "v2_" + (suite or "unknown"),
            "forward_secrecy": True,
        }
        protected_headers = self.metadata_without_auth(envelope.get("protected_headers"))
        if protected_headers:
            meta["protected_headers"] = protected_headers
        payload_type = self.v2_envelope_payload_type(envelope, protected_headers)
        if payload_type:
            meta["payload_type"] = payload_type
        context = self.metadata_without_auth(envelope.get("context"))
        if context:
            meta["context"] = context
        agent_md = self.metadata_without_auth(envelope.get("agent_md"))
        if agent_md:
            meta["agent_md"] = agent_md
        return meta

    @staticmethod
    def attach_v2_envelope_metadata(message: dict[str, Any], meta: dict[str, Any]) -> None:
        payload_type = str(meta.get("payload_type") or "").strip()
        if payload_type:
            message["payload_type"] = payload_type
        protected_headers = meta.get("protected_headers")
        if isinstance(protected_headers, dict) and protected_headers:
            message["protected_headers"] = dict(protected_headers)
        agent_md = meta.get("agent_md")
        if isinstance(agent_md, dict) and agent_md:
            message["agent_md"] = dict(agent_md)

    @staticmethod
    def attach_gateway_proximity(message: dict[str, Any], source: Any) -> None:
        if not isinstance(message, dict) or not isinstance(source, dict):
            return
        proximity = source.get("proximity")
        if isinstance(proximity, dict):
            message["proximity"] = dict(proximity)
        for key in ("same_device", "same_network", "same_egress_ip"):
            if key in source:
                message[key] = source.get(key)

    def attach_v2_envelope_metadata_from_source(self, message: dict[str, Any], source: Any) -> None:
        client = self.client
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
            client._agent_md_manager.observe_envelope(envelope)
            client._attach_v2_envelope_metadata(message, client._v2_thought_e2ee_metadata(envelope))

    @staticmethod
    def truthy_bool(value: Any) -> bool:
        if value is True or value == 1:
            return True
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "on"}
        return False

    @staticmethod
    def is_encrypted_envelope_payload(payload: Any) -> bool:
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

    def encrypted_push_envelope(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        client = self.client
        payload = msg.get("payload")
        if client._is_encrypted_envelope_payload(payload):
            return payload
        envelope_json = msg.get("envelope_json")
        if isinstance(envelope_json, str) and envelope_json.strip():
            try:
                parsed = json.loads(envelope_json)
            except (json.JSONDecodeError, TypeError):
                return None
            if client._is_encrypted_envelope_payload(parsed):
                return parsed
        return None

    def is_encrypted_push_message(self, msg: dict[str, Any]) -> bool:
        client = self.client
        if client._truthy_bool(msg.get("encrypted")):
            return True
        return client._encrypted_push_envelope(msg) is not None

    @staticmethod
    def is_v2_encrypted_envelope_payload(envelope: dict[str, Any] | None) -> bool:
        if not isinstance(envelope, dict):
            return False
        payload_type = str(envelope.get("type") or "").strip()
        if payload_type in {"e2ee.p2p_encrypted", "e2ee.group_encrypted"}:
            return True
        return str(envelope.get("version") or "").strip().lower() == "v2" and payload_type.startswith("e2ee.")

    def safe_undecryptable_push_event(self, msg: dict[str, Any], *, group: bool) -> dict[str, Any]:
        client = self.client
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
        envelope = client._encrypted_push_envelope(msg)
        if envelope is not None:
            event["_envelope_type"] = str(envelope.get("type") or "")
            event["_suite"] = str(envelope.get("suite") or "")
            if client._is_v2_encrypted_envelope_payload(envelope):
                client._attach_v2_envelope_metadata(event, client._v2_thought_e2ee_metadata(envelope))
        return event

    async def decrypt_encrypted_push_payload(self, msg: dict[str, Any], *, group: bool) -> dict[str, Any] | None:
        client = self.client
        envelope = client._encrypted_push_envelope(msg)
        if not client._is_v2_encrypted_envelope_payload(envelope):
            return None
        assert envelope is not None
        aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
        from_aid = str(msg.get("from_aid") or msg.get("from") or msg.get("sender_aid") or aad.get("from") or "").strip()
        plaintext = await client._decrypt_v2_envelope_for_thought(envelope=envelope, from_aid=from_aid)
        if plaintext is None:
            return None
        e2ee_meta = client._v2_thought_e2ee_metadata(envelope)
        result: dict[str, Any] = {
            "message_id": str(msg.get("message_id") or ""),
            "from": from_aid,
            "seq": msg.get("seq"),
            "timestamp": msg.get("t_server") if msg.get("t_server") is not None else msg.get("timestamp"),
            "payload": plaintext,
            "encrypted": True,
            "e2ee": e2ee_meta,
        }
        result["direction"] = "outbound_sync" if from_aid and from_aid == client._aid else "inbound"
        if msg.get("t_server") is not None:
            result["t_server"] = msg.get("t_server")
        if "device_id" in msg:
            result["device_id"] = msg.get("device_id")
        if "slot_id" in msg:
            result["slot_id"] = msg.get("slot_id")
        if group:
            result["group_id"] = msg.get("group_id") or aad.get("group_id") or envelope.get("group_id")
        else:
            result["to"] = msg.get("to") or client._aid or ""
        self.attach_gateway_proximity(result, msg)
        client._attach_v2_envelope_metadata(result, e2ee_meta)
        client._log_message_debug("decrypt-ok", "push.encrypted", "group.message_created" if group else "message.received", result)
        return result

    async def publish_encrypted_push_as_undecryptable(
        self,
        event: str,
        ns: str,
        seq: Any,
        msg: dict[str, Any],
        *,
        group: bool,
    ) -> bool:
        client = self.client
        scope = "group" if group else "p2p"
        client._delivery().record_push_processing(scope, "decrypt_fail")
        safe_event = client._safe_undecryptable_push_event(msg, group=group)
        client._log_message_debug("decrypt-fail", "push.encrypted", event, safe_event)
        if ns:
            published = await client._publish_ordered_message(event, ns, seq, safe_event)
            if published:
                client._delivery().record_push_processing(scope, "undecryptable_published")
            return published
        await client._publish_app_event(event, safe_event, source="push")
        client._delivery().record_push_processing(scope, "undecryptable_published")
        return True

    async def publish_encrypted_push_message(
        self,
        normal_event: str,
        undecryptable_event: str,
        ns: str,
        seq: Any,
        msg: dict[str, Any],
        *,
        group: bool,
    ) -> bool:
        client = self.client
        scope = "group" if group else "p2p"
        decrypted = await client._decrypt_encrypted_push_payload(msg, group=group)
        if decrypted is not None:
            client._delivery().record_push_processing(scope, "decrypt_ok")
            if ns:
                published = await client._publish_ordered_message(normal_event, ns, seq, decrypted)
                if published:
                    client._delivery().record_push_processing(scope, "app_published")
                return published
            await client._publish_app_event(normal_event, decrypted, source="push")
            client._delivery().record_push_processing(scope, "app_published")
            return True
        return await client._publish_encrypted_push_as_undecryptable(
            undecryptable_event, ns, seq, msg, group=group,
        )

    async def decrypt_v2_envelope_for_thought(
        self,
        *,
        envelope: dict[str, Any],
        from_aid: str,
    ) -> dict[str, Any] | None:
        """解密一个 V2 thought envelope（P2P 或 Group），返回 payload dict。"""
        from ..v2.e2ee.decrypt import decrypt_message as v2_decrypt_message

        client = self.client
        if not client._v2_session or not isinstance(envelope, dict):
            return None
        client._agent_md_manager.observe_envelope(envelope)

        spk_id = ""
        recipient_key_source = ""
        recipients = envelope.get("recipients")
        if isinstance(recipients, list):
            for row in recipients:
                if isinstance(row, list) and len(row) >= 6:
                    if row[0] == client._aid and (row[1] == client._device_id or row[1] == ""):
                        spk_id = str(row[5] or "")
                        recipient_key_source = str(row[3] or "") if len(row) > 3 else ""
                        break
        aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
        group_id_for_keys = str(aad.get("group_id") or envelope.get("group_id") or "").strip()
        client._log.debug(
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
                ik_priv, spk_priv = client._v2_session.get_group_decrypt_keys(group_id_for_keys, spk_id)
            else:
                ik_priv, spk_priv = client._v2_session.get_decrypt_keys(spk_id)
        except Exception as exc:
            client._log.warn(
                "client",
                "V2 thought decrypt: key lookup failed from=%s group=%s spk_id=%s: %s",
                from_aid, group_id_for_keys or "<p2p>", spk_id, exc,
            )
            return None

        sender_device_id = str(aad.get("from_device") or "")
        sender_cert_fingerprint = str(envelope.get("sender_cert_fingerprint") or "").strip().lower()
        sender_pub_der = await client._v2_sender_pub_der_from_cache_or_cert(
            from_aid,
            sender_device_id,
            sender_cert_fingerprint,
        )
        if not sender_pub_der:
            client._log.warn("client", "V2 thought decrypt pending: no sender IK for %s device=%s", from_aid, sender_device_id)
            client._schedule_v2_sender_ik_fetch(from_aid, sender_device_id, group_id_for_keys)
            return None

        try:
            plaintext = v2_decrypt_message(
                envelope=envelope,
                self_aid=client._aid,
                self_device_id=client._device_id,
                self_ik_priv=ik_priv,
                self_spk_priv=spk_priv,
                sender_pub_der=sender_pub_der,
            )
            client._log.debug(
                "client",
                "V2 thought decrypt ok: from=%s sender_device=%s group=%s",
                from_aid, sender_device_id, group_id_for_keys or "<p2p>",
            )
            if (
                plaintext is not None
                and group_id_for_keys
                and recipient_key_source == "group_device_prekey"
                and client._v2_session.is_last_uploaded_group_spk(group_id_for_keys, spk_id)
            ):
                client._schedule_group_spk_rotation(group_id_for_keys, reason="group_spk_consumed")
            elif plaintext is not None and group_id_for_keys and recipient_key_source == "peer_device_prekey":
                client._schedule_group_spk_registration_after_peer_fallback(group_id_for_keys)
            return plaintext
        except Exception as exc:
            client._log.warn("client", "V2 thought decrypt failed from=%s: %s", from_aid, exc)
            return None

    async def pull_group_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 拉取并解密消息。内部方法，由 call("group.pull") 路由调用。"""
        from ..errors import StateError

        client = self.client
        background_rpc = bool(params.pop("_rpc_background", False) or getattr(client, "_background_rpc_depth", 0) > 0)
        if not client._v2_session:
            raise StateError("V2 session not initialized (not connected?)")

        wire_group_id, group_id = _group_identifier_pair(params)
        if "after_seq" in params:
            after_seq = int(params.get("after_seq") or 0)
            has_explicit_after_seq = True
        elif "after_message_seq" in params:
            after_seq = int(params.get("after_message_seq") or 0)
            has_explicit_after_seq = True
        else:
            after_seq = 0
            has_explicit_after_seq = False
        limit = _v2_effective_page_limit(params.get("limit"))
        cursor_params = {
            key: params[key]
            for key in ("device_id", "slot_id", "device_name", "device_type")
            if key in params and params[key] is not None
        }
        request_device_id = str(cursor_params.get("device_id") or "")
        request_slot_id = str(cursor_params.get("slot_id") or "")
        owns_cursor = (
            (not request_device_id or request_device_id == (client._device_id or ""))
            and (not request_slot_id or request_slot_id == (client._slot_id or ""))
        )

        ns = f"group:{group_id}"
        next_after_seq = after_seq if has_explicit_after_seq else client._seq_tracker.get_contiguous_seq(ns)
        first_contig_before = client._seq_tracker.get_contiguous_seq(ns)
        response: dict[str, Any] = {}
        decrypted: list[dict[str, Any]] = []
        total_raw_count = 0
        latest_seq = 0
        page_count = 0
        last_auto_ack_seq = 0
        pending_ack_seq = 0
        max_pages = int(params.get("max_pages", 100) or 100)

        while page_count < max_pages:
            page_count += 1
            ack_up_to_seq = pending_ack_seq if owns_cursor else 0
            client._log.debug(
                "client",
                "group.v2.pull page request: group=%s page=%d after_seq=%d limit=%d ack_up_to_seq=%d ns=%s",
                group_id, page_count, next_after_seq, limit, ack_up_to_seq, ns,
            )
            pull_params = {
                "group_id": wire_group_id,
                "group_aid": group_id,
                "after_seq": next_after_seq,
                "limit": limit,
                **cursor_params,
            }
            if "device_id" not in pull_params:
                pull_params["device_id"] = client._device_id
            if "slot_id" not in pull_params:
                pull_params["slot_id"] = client._slot_id
            if ack_up_to_seq > 0:
                pull_params["ack_up_to_seq"] = ack_up_to_seq
            result = await client._rpc().raw_call("group.v2.pull", pull_params, background=background_rpc)
            if ack_up_to_seq > 0:
                pending_ack_seq = 0
                last_auto_ack_seq = max(last_auto_ack_seq, ack_up_to_seq)
            if isinstance(result, dict):
                response.update(result)
            else:
                result = {}

            messages = result.get("messages", [])
            raw_page_messages = messages if isinstance(messages, list) else []
            raw_messages = [
                msg for msg in raw_page_messages
                if isinstance(msg, dict) and int(msg.get("seq") or 0) > next_after_seq
            ]
            raw_messages.sort(key=lambda msg: int(msg.get("seq") or 0))
            total_raw_count += len(raw_messages)
            cursor = result.get("cursor") if isinstance(result.get("cursor"), dict) else {}
            client._log.debug(
                "client",
                "group.v2.pull page response: group=%s page=%d raw_count=%d stale_count=%d has_more=%s cursor_current=%s",
                group_id, page_count, len(raw_messages), max(0, len(raw_page_messages) - len(raw_messages)), result.get("has_more"), cursor.get("current_seq"),
            )
            for msg in raw_messages:
                client._log_message_debug("pull-raw", "group.v2.pull", "group.message_created", msg)
            seqs = [
                int(m.get("seq") or 0)
                for m in raw_messages
                if isinstance(m, dict) and int(m.get("seq") or 0) > 0
            ]
            page_contig_before = client._seq_tracker.get_contiguous_seq(ns)

            if seqs:
                page_max_seq = max(seqs)
                latest_seq = max(latest_seq, page_max_seq)
                client._seq_tracker.force_contiguous_seq(ns, page_max_seq)
                client._log.debug(
                    "client",
                    "group.v2.pull force contiguous: group=%s ns=%s page_max_seq=%d previous=%d",
                    group_id, ns, page_max_seq, page_contig_before,
                )
            else:
                page_max_seq = next_after_seq

            next_after = max(page_max_seq, next_after_seq)
            raw_count = len(raw_messages)
            can_continue_page = raw_count > 0 and next_after > next_after_seq and owns_cursor
            full_page = can_continue_page and limit > 0 and raw_count >= limit

            if self._can_parallel_decrypt_v2_page(raw_messages, expected_group_id=group_id):
                page_decrypted = await self._decrypt_page_parallel(raw_messages, expected_group_id=group_id)
                for item in page_decrypted:
                    plaintext = await self._apply_group_decrypt_result(item, group_id, ns)
                    if plaintext is not None:
                        decrypted.append(plaintext)
                    else:
                        client._log.debug("client", "group.v2.pull decrypt returned None: group=%s seq=%d", group_id, item.seq)
            else:
                for msg in raw_messages:
                    if not isinstance(msg, dict):
                        continue
                    seq = int(msg.get("seq", 0) or 0)
                    if seq <= 0:
                        continue

                    if str(msg.get("version", "") or "") == "v1":
                        payload = msg.get("payload")
                        if isinstance(payload, dict) and payload.get("type") in ("e2ee.encrypted", "e2ee.group_encrypted"):
                            continue
                        # 群撤回 tombstone（占位 / 通知）：归一化为 group.message_recalled，
                        # 不当作普通消息投递；仍占 seq，确保 contiguous / ack 正常推进。
                        if client._delivery().recall_event_from_group_message(msg) is not None:
                            await client._delivery().publish_group_recall_tombstone(group_id, seq, msg)
                            client._mark_published_seq(ns, seq)
                            client._log.debug("client", "group.v2.pull recall tombstone delivered: group=%s seq=%d", group_id, seq)
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
                        self.attach_gateway_proximity(v1_msg, msg)
                        await client._publish_pulled_message("group.message_created", ns, seq, v1_msg)
                        decrypted.append(v1_msg)
                        client._log.debug("client", "group.v2.pull plaintext legacy row delivered: group=%s seq=%d", group_id, seq)
                        continue

                    plaintext = await client._decrypt_v2_message(msg)
                    if plaintext is None:
                        client._log.debug("client", "group.v2.pull decrypt returned None: group=%s seq=%d", group_id, seq)
                        continue
                    plaintext["group_id"] = group_id
                    await client._publish_pulled_message("group.message_created", ns, seq, plaintext)
                    decrypted.append(plaintext)
                    client._log_message_debug("decrypt-ok", "group.v2.pull", "group.message_created", plaintext)

            cursor = result.get("cursor")
            has_server_cursor = isinstance(cursor, dict) and "current_seq" in cursor
            server_ack = 0
            if isinstance(cursor, dict):
                server_ack = int(cursor.get("current_seq") or 0)
                if server_ack > 0:
                    contig_before_ack = client._seq_tracker.get_contiguous_seq(ns)
                    if contig_before_ack < server_ack:
                        client._log.info(
                            "client",
                            "group.v2.pull retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                            ns, contig_before_ack, server_ack,
                        )
                        client._seq_tracker.force_contiguous_seq(ns, server_ack)

            contig = client._seq_tracker.get_contiguous_seq(ns)
            contig_advanced = contig != page_contig_before
            if contig_advanced:
                await client._drain_ordered_messages(ns)
                client._persist_seq(ns)
            ack_needed = (
                contig > 0
                and contig > last_auto_ack_seq
                and owns_cursor
                and (
                    (bool(raw_messages) and contig_advanced)
                    or (has_server_cursor and contig > server_ack)
                )
            )
            if ack_needed:
                if can_continue_page:
                    pending_ack_seq = max(pending_ack_seq, contig)
                    last_auto_ack_seq = max(last_auto_ack_seq, contig)
                    client._log.debug(
                        "client",
                        "group.v2.pull queued piggyback auto-ack: group=%s ns=%s ack_seq=%d raw_count=%d full_page=%s",
                        group_id, ns, pending_ack_seq, raw_count, full_page,
                    )
                else:
                    client._log.debug(
                        "client",
                        "group.v2.pull sending terminal auto-ack: group=%s ns=%s ack_seq=%d raw_count=%d",
                        group_id, ns, contig, raw_count,
                    )
                    await client._await_ack("group.v2.ack", {
                        "group_id": group_id, "group_aid": group_id, "up_to_seq": contig,
                    }, f"V2 群消息 terminal auto-ack group={group_id}")
                    last_auto_ack_seq = max(last_auto_ack_seq, contig)
            elif raw_messages and contig_advanced and contig > 0 and not owns_cursor:
                client._log.debug(
                    "client",
                    "group.v2.pull 跳过外部 cursor 自动 ack: group=%s ns=%s device_id=%s slot_id=%s ack_seq=%d",
                    group_id, ns, request_device_id, request_slot_id, contig,
                )

            if not owns_cursor:
                break
            should_continue = can_continue_page and (full_page or pending_ack_seq > 0)
            if not should_continue:
                break
            tail_delay = _v2_pull_tail_delay_seconds(raw_count, limit)
            if tail_delay > 0:
                await asyncio.sleep(tail_delay)
            next_after_seq = next_after

        if page_count >= max_pages:
            client._log.warn("client", "group.v2.pull reached max_pages=%d group=%s after_seq=%d", max_pages, group_id, next_after_seq)
            if pending_ack_seq > 0:
                client._log.debug(
                    "client",
                    "group.v2.pull flushing pending auto-ack after max_pages: group=%s ns=%s ack_seq=%d",
                    group_id, ns, pending_ack_seq,
                )
                await client._await_ack("group.v2.ack", {
                    "group_id": group_id, "group_aid": group_id, "up_to_seq": pending_ack_seq,
                }, f"V2 群消息 max_pages auto-ack group={group_id}")
                pending_ack_seq = 0

        response["messages"] = decrypted
        response["_contig_before"] = first_contig_before
        response["raw_count"] = total_raw_count
        if page_count >= max_pages and total_raw_count >= limit and int(limit or 0) > 0:
            response["has_more"] = True
        latest_available = max(
            int(response.get("latest_seq") or 0),
            int(response.get("latest_message_seq") or 0),
            int((response.get("cursor") or {}).get("latest_seq") or 0) if isinstance(response.get("cursor"), dict) else 0,
        )
        if "has_more" not in response:
            response["has_more"] = bool(total_raw_count and latest_available > latest_seq)
        if latest_seq:
            response["latest_seq"] = max(int(response.get("latest_seq") or 0), latest_seq)
        client._log.debug(
            "client",
            "group.v2.pull done: group=%s requested_after_seq=%d pages=%d raw_count=%d decrypted=%d ns=%s",
            group_id, after_seq, page_count, total_raw_count, len(decrypted), ns,
        )
        return response

    async def ack_group_v2_internal(self, params: dict[str, Any]) -> dict[str, Any]:
        """V2 Group 确认消费。内部方法，由 call("group.ack_messages") 路由调用。"""
        client = self.client
        background_rpc = bool(params.pop("_rpc_background", False))
        _wire_group_id, group_id = _group_identifier_pair(params)
        up_to_seq = int(params.get("msg_seq", 0) or params.get("up_to_seq", 0) or 0)
        ns = f"group:{group_id}"
        seq = up_to_seq or (client._seq_tracker.get_contiguous_seq(ns) if ns else 0)
        if seq <= 0:
            client._log.debug("client", "group.v2.ack skipped: group=%s ns=%s up_to_seq=%s", group_id, ns, up_to_seq)
            return {"acked": 0}
        max_seen = client._seq_tracker.get_max_seen_seq(ns) if ns else 0
        if max_seen > 0 and seq > max_seen:
            client._log.warn(
                "client",
                "_ack_group_v2_internal clamp: group=%s up_to_seq=%d > max_seen=%d, clamp",
                group_id, seq, max_seen,
            )
            seq = max_seen
        client._log.debug("client", "group.v2.ack send: group=%s ns=%s up_to_seq=%d", group_id, ns, seq)
        cursor_params = {
            key: params[key]
            for key in ("device_id", "slot_id")
            if key in params and params[key] is not None
        }
        ack_params = {"group_id": group_id, "group_aid": group_id, "up_to_seq": seq, **cursor_params}
        if background_rpc:
            ack_params["_rpc_background"] = True
        result = await client.call("group.v2.ack", ack_params)
        client._log.debug("client", "group.v2.ack ok: group=%s ns=%s requested=%d result=%s", group_id, ns, seq, result)
        return result

    async def postprocess_result(self, method: str, params: dict[str, Any], result: Any) -> Any:
        client = self.client
        if method == "group.thought.get" and isinstance(result, dict):
            client._log.debug(
                "client",
                "group.thought.get transport result: found=%s raw_count=%d",
                result.get("found"),
                len(result.get("thoughts", [])) if isinstance(result.get("thoughts"), list) else 0,
            )
            result = await client._decrypt_group_thoughts(result)
        if method == "message.thought.get" and isinstance(result, dict):
            client._log.debug(
                "client",
                "message.thought.get transport result: found=%s raw_count=%d",
                result.get("found"),
                len(result.get("thoughts", [])) if isinstance(result.get("thoughts"), list) else 0,
            )
            result = await client._decrypt_message_thoughts(result)
        if method in {"message.v2.bootstrap", "group.v2.bootstrap"} and isinstance(result, dict):
            try:
                await client._v2_observe_bootstrap_material(method, params, result)
            except Exception as exc:
                client._log.debug("client", "V2 bootstrap material observe skipped: method=%s err=%s", method, exc)
        return result
