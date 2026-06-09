from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from typing import Any

from ..config import normalize_slot_id, slot_isolation_key
from ..errors import (
    ClientSignatureError,
    ConnectionError,
    PermissionError as AUNPermissionError,
    StateError,
    ValidationError,
)
from ..group_id import normalize_group_id as _normalize_group_id
from ..types import ConnectionState
from .runtime import ClientRuntime


class RpcPipeline:
    """RPC 调用前置校验、路由与后处理协调器。"""

    def __init__(self, runtime: Any) -> None:
        self.runtime = ClientRuntime.coerce(runtime)
        self.client = self.runtime.client

    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None) -> Any:
        client = self.client
        t_call_start = time.time()
        if not isinstance(method, str) or not method.strip():
            raise ValidationError("call() requires a non-empty method string")
        if client._public_state != ConnectionState.READY:
            raise ConnectionError("client is not connected")
        if client._is_internal_only_method(method):
            raise AUNPermissionError(f"method is internal_only: {method}")

        prepared = dict(params) if params else {}
        prepared = client._merge_instance_protected_headers(method, prepared)
        client._log.debug("client", "call enter: method=%s", method)
        if method in {"message.send", "group.send"}:
            client._normalize_outbound_message_payload(prepared, method=method)
        client._validate_outbound_call(method, prepared)
        client._inject_message_cursor_context(method, prepared)

        # group.* 方法的 group_id 归一化为 canonical 格式（兼容老/污染数据）
        # 不对无域输入补本域——保持与历史行为兼容，交给服务端归一化
        if method.startswith("group.") and "group_id" in prepared:
            raw_gid = prepared.get("group_id")
            if raw_gid:
                normalized_gid = _normalize_group_id(str(raw_gid))
                if normalized_gid != str(raw_gid):
                    client._log.debug("client", "call group_id normalized: %s -> %s method=%s", raw_gid, normalized_gid, method)
                prepared["group_id"] = normalized_gid

        # group.* 方法注入 device_id（服务端用于多设备消息路由）
        if method.startswith("group.") and "device_id" not in prepared:
            prepared["device_id"] = client._device_id
        if method.startswith("group.") and "slot_id" not in prepared:
            prepared["slot_id"] = client._slot_id

        return await self.call_after_pipeline(method, prepared, trace=trace, started_at=t_call_start)

    async def call_after_pipeline(
        self,
        method: str,
        params: dict[str, Any],
        *,
        trace: str | None,
        started_at: float,
    ) -> Any:
        from ..client import _NON_IDEMPOTENT_METHODS, _NON_IDEMPOTENT_TIMEOUT

        client = self.client
        t_call_start = started_at
        pull_gate_locked = bool(params.pop("_pull_gate_locked", False))
        skip_send_result_envelope = bool(params.pop("_skip_send_result_envelope", False))
        pull_gate_key = self.pull_gate_key_for_call(method, params)
        if pull_gate_key and not pull_gate_locked:
            locked_params = dict(params)
            locked_params["_pull_gate_locked"] = True
            if skip_send_result_envelope:
                locked_params["_skip_send_result_envelope"] = True

            async def _gated_call():
                return await self.call_after_pipeline(
                    method,
                    locked_params,
                    trace=trace,
                    started_at=started_at,
                )

            return await self.run_pull_serialized(pull_gate_key, _gated_call)

        if method == "message.send":
            encrypt = params.pop("encrypt", True)
            client._log_message_debug(
                "send-input",
                "message.send",
                "message.send",
                params,
                payload_override=params.get("payload", params.get("content")),
                extra={"encrypt": encrypt},
            )
            client._log.debug(
                "client",
                "call message.send: to=%s encrypt=%s payload_keys=%s",
                params.get("to", "-"),
                encrypt,
                list(params.get("payload", {}).keys()) if isinstance(params.get("payload"), dict) else type(params.get("payload")).__name__,
            )
            if encrypt:
                if not client._v2_session:
                    raise StateError("V2 session not initialized; encrypted message.send requires V2 (V1 E2EE removed)")
                client._log.debug("client", "call encrypt branch: method=message.send to=%s v2=True", params.get("to", "-"))
                try:
                    result = await client._send_encrypted_v2(params)
                    client._log.debug("client", "call exit (encrypted): elapsed=%.3fs method=%s", time.time() - t_call_start, method)
                    return result
                except Exception as exc:
                    client._log.debug("client", "call exit (encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - t_call_start, method, exc)
                    raise
            client._maybe_append_echo_trace_send(params)

        if method == "group.send":
            encrypt = params.pop("encrypt", True)
            client._log_message_debug(
                "send-input",
                "group.send",
                "group.send",
                params,
                payload_override=params.get("payload", params.get("content")),
                extra={"encrypt": encrypt},
            )
            if encrypt:
                if not client._v2_session:
                    raise StateError("V2 session not initialized; encrypted group.send requires V2 (V1 E2EE removed)")
                client._log.debug("client", "call encrypt branch: method=group.send group_id=%s v2=True", params.get("group_id", "-"))
                try:
                    result = await client._send_group_encrypted_v2(params)
                    client._log.debug("client", "call exit (group-encrypted): elapsed=%.3fs method=%s", time.time() - t_call_start, method)
                    return result
                except Exception as exc:
                    client._log.debug("client", "call exit (group-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - t_call_start, method, exc)
                    raise
            client._maybe_append_echo_trace_send(params)

        if method == "message.pull" and getattr(client, "_v2_session", None):
            client._log.debug("client", "call route: message.pull -> V2 pull")
            return await client._pull_v2_internal(params)

        if method == "message.ack" and getattr(client, "_v2_session", None):
            client._log.debug("client", "call route: message.ack -> V2 ack")
            return await client._ack_v2_internal(params)

        if method == "group.pull" and client._v2_session and params.get("group_id"):
            client._log.debug("client", "call route: group.pull -> V2 pull")
            return await client._pull_group_v2_internal(params)

        if method == "group.ack_messages" and client._v2_session and params.get("group_id"):
            if client._group_cursor_targets_current_instance(params):
                client._log.debug("client", "call route: group.ack_messages -> V2 ack")
                return await client._ack_group_v2_internal(params)
            client._log.debug(
                "client",
                "call route: group.ack_messages external cursor -> raw ack device_id=%s slot_id=%s",
                params.get("device_id"),
                params.get("slot_id"),
            )

        if method == "group.thought.put":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                if not client._v2_session or not params.get("group_id"):
                    raise StateError("V2 session not initialized; encrypted group.thought.put requires V2 (V1 E2EE removed)")
                try:
                    client._log.debug("client", "call route: group.thought.put -> V2 encrypted put")
                    result = await client._put_group_thought_encrypted_v2(params)
                    client._log.debug("client", "call exit (thought-encrypted): elapsed=%.3fs method=%s", time.time() - t_call_start, method)
                    return result
                except Exception as exc:
                    client._log.debug("client", "call exit (thought-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - t_call_start, method, exc)
                    raise

        if method == "message.thought.put":
            encrypt = params.pop("encrypt", True)
            if encrypt:
                if not client._v2_session or not params.get("to"):
                    raise StateError("V2 session not initialized; encrypted message.thought.put requires V2 (V1 E2EE removed)")
                try:
                    client._log.debug("client", "call route: message.thought.put -> V2 encrypted put")
                    result = await client._put_message_thought_encrypted_v2(params)
                    client._log.debug("client", "call exit (msg-thought-encrypted): elapsed=%.3fs method=%s", time.time() - t_call_start, method)
                    return result
                except Exception as exc:
                    client._log.debug("client", "call exit (msg-thought-encrypted-error): elapsed=%.3fs method=%s err=%s", time.time() - t_call_start, method, exc)
                    raise

        if method in client._SIGNED_METHODS:
            if self.should_skip_client_signature(method, params):
                params.pop("client_signature", None)
            else:
                self.sign_client_operation(method, params)

        call_kwargs: dict[str, Any] = {}
        if method in _NON_IDEMPOTENT_METHODS:
            call_kwargs["timeout"] = _NON_IDEMPOTENT_TIMEOUT
        if trace:
            call_kwargs["trace"] = trace

        if method in ("group.thought.get", "message.thought.get"):
            client._log.debug("client", "thought.get transport call start: method=%s params=%s", method, params)
        try:
            result = await client._transport.call(method, params, **call_kwargs)
        except TypeError as exc:
            if call_kwargs and "unexpected keyword argument" in str(exc):
                call_kwargs.pop("timeout", None)
                call_kwargs.pop("trace", None)
                result = await client._transport.call(method, params, **call_kwargs) if call_kwargs else await client._transport.call(method, params)
            else:
                client._log.debug("client", "call exit (error): elapsed=%.3fs method=%s err=%s", time.time() - t_call_start, method, exc)
                raise
        except Exception as exc:
            client._log.debug("client", "call exit (error): elapsed=%.3fs method=%s err=%s", time.time() - t_call_start, method, exc)
            raise

        result = await self.postprocess_result(method, params, result)
        if not skip_send_result_envelope:
            result = client._delivery().attach_send_result_envelope(
                method,
                params,
                result,
                encrypted=bool(params.get("encrypted")),
            )
        client._log.debug("client", "call exit: elapsed=%.3fs method=%s", time.time() - t_call_start, method)
        return result

    def merge_instance_protected_headers(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        from ..client import _PROTECTED_HEADERS_METHODS

        client = self.client
        instance_headers = getattr(client, "_instance_protected_headers", None)
        if method not in _PROTECTED_HEADERS_METHODS or not instance_headers:
            return params
        existing = client._protected_headers_from_params(params)
        merged = dict(instance_headers)
        if existing:
            to_dict = getattr(existing, "to_dict", None)
            existing_dict = to_dict() if callable(to_dict) else dict(existing)
            if isinstance(existing_dict, dict):
                merged.update(existing_dict)
        params["protected_headers"] = merged
        return params

    def normalize_outbound_message_payload(self, params: dict[str, Any], *, method: str = "") -> None:
        if "payload" not in params and "content" in params:
            params["payload"] = params.pop("content")
        payload = params.get("payload")
        if isinstance(payload, dict) and "type" not in payload and isinstance(payload.get("text"), str):
            params["payload"] = {"type": "text", **payload}

    def validate_outbound_call(self, method: str, params: dict[str, Any]) -> None:
        client = self.client
        if method == "message.send":
            client._validate_message_recipient(params.get("to"))
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
            client._validate_message_recipient(params.get("to"))
            if not str(params.get("to") or "").strip():
                raise ValidationError("message.thought.put requires to")
        if method == "message.thought.get":
            if not str(params.get("sender_aid") or "").strip():
                raise ValidationError("message.thought.get requires sender_aid")

    def inject_message_cursor_context(self, method: str, params: dict[str, Any]) -> None:
        client = self.client
        if method not in {"message.pull", "message.ack"}:
            return
        if "device_id" in params and str(params.get("device_id") or "").strip() != client._device_id:
            raise ValidationError("message.pull/message.ack device_id must match the current client instance")
        slot_id = normalize_slot_id(params.get("slot_id", client._slot_id))
        if slot_isolation_key(slot_id) != slot_isolation_key(client._slot_id):
            raise ValidationError("message.pull/message.ack slot_id must match the current client instance")
        params["device_id"] = client._device_id
        params["slot_id"] = client._slot_id

    def group_cursor_targets_current_instance(self, params: dict[str, Any]) -> bool:
        client = self.client
        device_id = str(params.get("device_id") or "").strip()
        slot_id = str(params.get("slot_id") or "").strip()
        return (
            (not device_id or device_id == (client._device_id or ""))
            and (not slot_id or slot_id == (client._slot_id or ""))
        )

    def sign_client_operation(self, method: str, params: dict[str, Any]) -> None:
        """为关键操作附加客户端 ECDSA 签名（_client_signature 字段）。"""
        client = self.client
        current_aid = client._current_aid
        if not current_aid or not current_aid.private_key_pem:
            return
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
            aid = current_aid.aid
            ts = str(int(time.time()))
            params_for_hash = {k: v for k, v in params.items()
                               if k != "client_signature" and not k.startswith("_")}
            params_json = json.dumps(params_for_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            params_hash = hashlib.sha256(params_json.encode("utf-8")).hexdigest()
            sign_data = f"{method}|{aid}|{ts}|{params_hash}".encode("utf-8")
            pk = _ser.load_pem_private_key(
                current_aid.private_key_pem.encode("utf-8"), password=None,
            )
            sig = pk.sign(sign_data, _ec.ECDSA(_hashes.SHA256()))
            # 证书指纹：用于锁定签名时使用的证书版本
            cert_fingerprint = ""
            cert_pem = current_aid.cert_pem
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

    def is_echo_message_params(self, params: dict[str, Any]) -> bool:
        if params.get("encrypted") or params.get("encrypt"):
            return False
        payload = params.get("payload")
        if not isinstance(payload, dict):
            return False
        text = payload.get("text")
        if not isinstance(text, str) or len(text) > 4096:
            return False
        return "echo" in text.split("\n", 1)[0].lower()

    def should_skip_client_signature(self, method: str, params: dict[str, Any]) -> bool:
        # echo 是链路测试消息，中间节点会追加 trace 行，不能参与客户端操作签名。
        return method in {"message.send", "group.send"} and self.is_echo_message_params(params)

    def should_skip_event_signature(self, event: dict[str, Any]) -> bool:
        # echo 是链路测试消息，服务端/SDK 会追加 trace 行；误带签名时也不验签。
        return self.is_echo_message_params(event)

    def pull_gate_key_for_call(self, method: str, params: dict) -> str:
        client = self.client
        if method in ("message.pull", "message.v2.pull"):
            return f"p2p:{client._aid}" if client._aid else ""
        if method in ("group.pull", "group.v2.pull"):
            gid = str(params.get("group_id") or "").strip()
            return f"group:{gid}" if gid else ""
        if method == "group.pull_events":
            gid = str(params.get("group_id") or "").strip()
            return f"group_event:{gid}" if gid else ""
        return ""

    def try_acquire_pull_gate(self, key: str) -> int | None:
        client = self.client
        if not key:
            return 0
        gates = self.runtime.rpc.pull_gates
        now = int(time.time() * 1000)
        gate = gates.get(key, {"inflight": False, "started_at": 0, "token": 0})
        if gate["inflight"] and now - gate["started_at"] <= client._PULL_GATE_STALE_MS:
            return None
        if gate["inflight"]:
            client._log.warn("client", "pull in-flight stale reset: key=%s age=%dms", key, now - gate["started_at"])
        gate["token"] += 1
        gate["inflight"] = True
        gate["started_at"] = now
        gates[key] = gate
        return gate["token"]

    def release_pull_gate(self, key: str, token: int | None) -> None:
        client = self.client
        if not key or token is None:
            return
        gate = self.runtime.rpc.pull_gates.get(key)
        if not gate or gate["token"] != token:
            return
        gate["inflight"] = False
        gate["started_at"] = 0

    async def run_pull_serialized(self, key: str, operation):
        """acquire gate → execute → release。gate 被占时短等待后重试。"""
        client = self.client
        token = client._try_acquire_pull_gate(key)
        if token is None:
            deadline = time.time() + (client._PULL_GATE_STALE_MS + 100) / 1000.0
            while token is None and time.time() <= deadline:
                await asyncio.sleep(0.025)
                token = client._try_acquire_pull_gate(key)
            if token is None:
                raise StateError(f"pull already in-flight for {key}")
        try:
            return await operation()
        finally:
            client._release_pull_gate(key, token)

    async def postprocess_result(self, method: str, params: dict[str, Any], result: Any) -> Any:
        """按 RPC method 调度响应后处理；具体业务逻辑继续下沉到专门组件。"""
        client = self.client
        result = await client._v2_e2ee_coordinator().postprocess_result(method, params, result)
        result = await client._delivery().postprocess_result(method, params, result)
        result = await client._group_state().postprocess_result(method, params, result)
        return result

    async def raw_call(
        self,
        method: str,
        params: dict | None = None,
        *,
        timeout: float | None = None,
        trace: str | None = None,
        signed: bool = True,
    ) -> Any:
        """内部裸 RPC 入口；默认仍执行客户端签名策略。"""
        client = self.client
        payload = dict(params) if params else {}
        if signed and method in client._SIGNED_METHODS:
            if client._should_skip_client_signature(method, payload):
                payload.pop("client_signature", None)
            else:
                client._sign_client_operation(method, payload)
        call_kwargs: dict[str, Any] = {}
        if timeout is not None:
            call_kwargs["timeout"] = timeout
        if trace:
            call_kwargs["trace"] = trace
        try:
            return await client._transport.call(method, payload, **call_kwargs)
        except TypeError as exc:
            if call_kwargs and "unexpected keyword argument" in str(exc):
                call_kwargs.pop("timeout", None)
                call_kwargs.pop("trace", None)
                return await client._transport.call(method, payload, **call_kwargs) if call_kwargs else await client._transport.call(method, payload)
            raise
