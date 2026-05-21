from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any, TYPE_CHECKING

import websockets

from .errors import ConnectionError, SerializationError, TimeoutError, ValidationError, map_remote_error
from .events import EventDispatcher

if TYPE_CHECKING:
    from .logger import AUNLogger, NullLogger


MAX_WS_PAYLOAD_SIZE = 1_000_000

ConnectionFactory = Callable[[str], Awaitable[Any]]
DisconnectCallback = Callable[[Exception | None, int | None], Awaitable[None]]

EVENT_NAME_MAP = {
    "message.received": "message.received",
    "message.recalled": "message.recalled",
    "message.ack": "message.ack",
    "group.changed": "group.changed",
    "group.message_created": "group.message_created",
    "storage.object_changed": "storage.object_changed",
}


# 提取诊断字段时使用的字段白名单（按 RPC method 前缀匹配）
# 仅打印元数据/路由字段，绝不打印 payload 明文、token、私钥、密钥材料
_DIAG_PARAM_FIELDS = (
    "to", "to_aid", "from", "from_aid", "group_id", "message_id", "mid",
    "method", "device_id", "slot_id", "epoch", "epoch_id", "rotation_id",
    "after_seq", "after_event_seq", "seq", "event_seq", "limit", "cursor",
    "aid", "session_id", "type", "encrypt", "encryption_mode", "suite",
    "prekey_id", "trust_root_version", "version", "ok", "request_id",
    "owner_aid", "rotated_by", "action",
)
_DIAG_RESULT_FIELDS = _DIAG_PARAM_FIELDS + (
    "members", "messages", "events", "count", "imported", "skipped",
    "next_cursor", "current_seq", "committed_epoch",
)


def _summarize_dict(payload: Any, fields: tuple[str, ...]) -> str:
    """提取 dict 中的关键诊断字段，序列化为简短字符串。

    敏感字段（payload/content/text/cert/private_key/token/secret/ciphertext 等）一律不打印。
    list/dict 类型只打长度或键名。
    """
    if not isinstance(payload, dict):
        if isinstance(payload, list):
            return f"[list len={len(payload)}]"
        return "<empty>" if payload is None else f"<{type(payload).__name__}>"
    parts = []
    for key in fields:
        if key not in payload:
            continue
        value = payload[key]
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple)):
            parts.append(f"{key}=[len={len(value)}]")
        elif isinstance(value, dict):
            parts.append(f"{key}={{keys={len(value)}}}")
        elif isinstance(value, (int, float, bool)):
            parts.append(f"{key}={value}")
        else:
            s = str(value)
            if len(s) > 64:
                s = s[:61] + "..."
            parts.append(f"{key}={s}")
    return " ".join(parts) if parts else "<no diag fields>"


class RPCTransport:
    def __init__(
        self,
        *,
        event_dispatcher: EventDispatcher,
        connection_factory: ConnectionFactory,
        timeout: float = 35.0,
        on_disconnect: DisconnectCallback | None = None,
        logger: "AUNLogger | NullLogger | None" = None,
    ) -> None:
        self._dispatcher = event_dispatcher
        self._connection_factory = connection_factory
        self._timeout = timeout
        self._on_disconnect = on_disconnect
        self._ws: Any | None = None
        self._reader_task: asyncio.Task | None = None
        self._pending: dict[str, asyncio.Future] = {}
        self._closed = True
        self._challenge: dict[str, Any] | None = None
        # Gateway 在 RPC envelope 注入 _meta 字段（与 result 同级），由 client 层 observer 接收。
        # 注入失败 / 字段缺失时 observer 不会被调用，不影响业务路径。
        self._meta_observer: "callable | None" = None
        self._trace_mode: str = "off"
        self._trace_observer: "callable | None" = None
        from .logger import NullLogger as _NL
        self._log = logger or _NL()

    def set_meta_observer(self, observer) -> None:
        """注册 RPC envelope _meta 字段观察者；observer(meta_dict) 在每次成功 RPC 时调用。

        Gateway 注入的 _meta 与业务无关（如 agent_md_etag），observer 抛异常会被吞掉，
        不影响 RPC result 返回。
        """
        self._meta_observer = observer

    def set_trace_mode(self, mode: str) -> None:
        if mode not in ("off", "log", "diag"):
            raise ValueError(f"invalid trace mode: {mode!r}, must be off/log/diag")
        self._trace_mode = mode

    def set_trace_observer(self, observer) -> None:
        """注册 trace observer；observer(trace_info: dict) 在每次 RPC/事件携带 _trace 时调用。"""
        self._trace_observer = observer

    def set_timeout(self, timeout: float) -> None:
        self._timeout = timeout

    @property
    def challenge(self) -> dict[str, Any] | None:
        return self._challenge

    async def connect(self, url: str) -> dict[str, Any] | None:
        _t_start = time.time()
        self._log.debug("transport", "connect enter: url=%s", url)
        try:
            self._ws = await self._connection_factory(url)
            self._closed = False
            challenge = await self._recv_initial_message()
            self._challenge = challenge
            self._reader_task = asyncio.create_task(self._reader_loop())
            self._log.debug("transport", "connect exit: elapsed=%.3fs url=%s has_challenge=%s", time.time() - _t_start, url, challenge is not None)
            return challenge
        except Exception as exc:
            self._log.debug("transport", "connect exit (error): elapsed=%.3fs url=%s err=%s", time.time() - _t_start, url, exc)
            raise

    async def close(self) -> None:
        _t_start = time.time()
        self._log.debug("transport", "close enter")
        self._closed = True
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass  # 任务取消，正常清理
            self._reader_task = None
        if self._ws is not None:
            await self._ws.close()
            self._ws = None
        pending_count = len(self._pending)
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(ConnectionError("transport closed"))
        self._pending.clear()
        self._log.debug("transport", "close exit: elapsed=%.3fs cancelled_pending=%d", time.time() - _t_start, pending_count)

    async def call(self, method: str, params: dict[str, Any] | None = None, *, timeout: float | None = None, trace: str | None = None) -> Any:
        if self._closed or self._ws is None:
            self._log.warn("transport", "RPC call failed (not connected): method=%s", method)
            raise ConnectionError("transport not connected")

        rpc_id = f"rpc-{secrets.token_hex(8)}"
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[rpc_id] = future

        import time as _diag_time
        _t0 = _diag_time.time()

        # 注入 _trace（会话级或调用级 mode 非 off 时）
        effective_trace_mode = trace if trace in ("off", "log", "diag") else self._trace_mode
        trace_id = ""
        if effective_trace_mode != "off":
            trace_id = secrets.token_hex(16)
            params = dict(params) if params else {}
            _trace_payload: dict = {"trace_id": trace_id, "mode": effective_trace_mode}
            if effective_trace_mode == "diag":
                _trace_payload["spans"] = [{"node": "sdk", "ts": int(_t0 * 1000), "action": "send"}]
            params["_trace"] = _trace_payload
            self._log.info("transport", "[trace=%s] rpc_send method=%s rpc_id=%s", trace_id, method, rpc_id)

        self._log.debug(
            "transport",
            "RPC send: method=%s rpc_id=%s %s",
            method, rpc_id, _summarize_dict(params, _DIAG_PARAM_FIELDS),
        )
        try:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "method": method,
                "params": params or {},
            })
            payload_bytes = payload.encode("utf-8")
            if len(payload_bytes) > MAX_WS_PAYLOAD_SIZE:
                raise ValidationError("payload is too large")
            await self._ws.send(payload)
        except Exception as exc:
            self._pending.pop(rpc_id, None)
            self._log.warn("transport", "RPC send failed: method=%s rpc_id=%s err=%s", method, rpc_id, exc)
            raise ConnectionError(f"failed to send rpc {method}: {exc}") from exc

        _t_sent = _diag_time.time()
        try:
            response = await asyncio.wait_for(future, timeout=timeout or self._timeout)
        except asyncio.TimeoutError as exc:
            self._pending.pop(rpc_id, None)
            _elapsed = _diag_time.time() - _t0
            self._log.warn(
                "transport",
                "RPC timeout method=%s rpc_id=%s send_took=%.3fs total=%.3fs pending_count=%d reader_alive=%s",
                method, rpc_id, _t_sent - _t0, _elapsed, len(self._pending),
                self._reader_task is not None and not self._reader_task.done() if self._reader_task else False,
            )
            raise TimeoutError(f"rpc timeout: {method}", retryable=True) from exc

        _elapsed = _diag_time.time() - _t0
        if "error" in response:
            self._log.debug(
                "transport",
                "RPC error response: method=%s rpc_id=%s elapsed=%.3fs error=%s",
                method, rpc_id, _elapsed, response["error"],
            )
            if trace_id:
                self._log.info("transport", "[trace=%s] rpc_recv method=%s rpc_id=%s duration_ms=%d status=error",
                               trace_id, method, rpc_id, int(_elapsed * 1000))
            if self._trace_observer is not None:
                resp_trace = response.get("_trace")
                if isinstance(resp_trace, dict):
                    try:
                        sdk_recv_span = {"node": "sdk", "action": "recv", "ms": int(_elapsed * 1000)}
                        spans = list(resp_trace.get("spans") or []) + [sdk_recv_span]
                        enriched = dict(resp_trace)
                        enriched["spans"] = spans
                        self._trace_observer({"type": "rpc", "method": method, "trace": enriched,
                                              "status": "error", "duration_ms": int(_elapsed * 1000)})
                    except Exception as exc:
                        self._log.debug("transport", "trace_observer raised: %s", exc)
            raise map_remote_error(response["error"])
        self._log.debug(
            "transport",
            "RPC success: method=%s rpc_id=%s elapsed=%.3fs %s",
            method, rpc_id, _elapsed,
            _summarize_dict(response.get("result"), _DIAG_RESULT_FIELDS),
        )
        if trace_id:
            self._log.info("transport", "[trace=%s] rpc_recv method=%s rpc_id=%s duration_ms=%d status=ok",
                           trace_id, method, rpc_id, int(_elapsed * 1000))
        # 透传 envelope._meta 给 observer（与业务无关，注入失败被吞，不影响 result 返回）。
        if self._meta_observer is not None:
            meta = response.get("_meta")
            if isinstance(meta, dict):
                try:
                    self._meta_observer(meta)
                except Exception as exc:
                    self._log.debug("transport", "meta_observer raised: %s", exc)
        # 透传 envelope._trace 给 trace observer（diag 模式回传 spans）
        if self._trace_observer is not None:
            resp_trace = response.get("_trace")
            if isinstance(resp_trace, dict):
                try:
                    # 追加 sdk.recv span，记录 SDK 端总耗时
                    sdk_recv_span = {"node": "sdk", "action": "recv", "ms": int(_elapsed * 1000)}
                    spans = list(resp_trace.get("spans") or []) + [sdk_recv_span]
                    enriched = dict(resp_trace)
                    enriched["spans"] = spans
                    self._trace_observer({"type": "rpc", "method": method, "trace": enriched,
                                          "duration_ms": int(_elapsed * 1000)})
                except Exception as exc:
                    self._log.debug("transport", "trace_observer raised: %s", exc)
        return response.get("result")

    async def _recv_initial_message(self) -> dict[str, Any] | None:
        if self._ws is None:
            return None
        raw = await self._ws.recv()
        message = self._decode_message(raw)
        if message.get("method") == "challenge":
            return message
        await self._route_message(message)
        return None

    async def _reader_loop(self) -> None:
        disconnect_error: Exception | None = None
        unexpected_disconnect = False
        import time as _diag_time
        try:
            while not self._closed and self._ws is not None:
                raw = await self._ws.recv()
                _t_recv = _diag_time.time()
                message = self._decode_message(raw)
                await self._route_message(message)
                _route_elapsed = _diag_time.time() - _t_recv
                if _route_elapsed > 1.0:
                    _msg_method = message.get("method", message.get("id", "?"))
                    self._log.warn(
                        "transport",
                        "_route_message slow: %.3fs method/id=%s pending=%d",
                        _route_elapsed, _msg_method, len(self._pending),
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            disconnect_error = exc
            unexpected_disconnect = not self._closed
            if not self._closed:
                self._log.error("transport", "connection unexpectedly closed: err=%s pending=%d", exc, len(self._pending), err=exc)
                await self._dispatcher.publish("connection.error", {"error": exc})
        finally:
            self._closed = True
            if unexpected_disconnect:
                if self._on_disconnect is not None:
                    # 从 websockets.ConnectionClosed 中提取 close code
                    close_code: int | None = None
                    if isinstance(disconnect_error, websockets.ConnectionClosed):
                        close_code = disconnect_error.code
                    self._log.debug("transport", "triggering on_disconnect callback: close_code=%s", close_code)
                    await self._on_disconnect(disconnect_error, close_code)

    async def _route_message(self, message: dict[str, Any]) -> None:
        if "id" in message:
            rpc_id = str(message["id"])
            future = self._pending.pop(rpc_id, None)
            if future is not None and not future.done():
                future.set_result(message)
            return

        method = str(message.get("method", ""))
        if method == "challenge":
            self._challenge = message
            self._log.debug("transport", "challenge received")
            await self._dispatcher.publish("connection.challenge", message.get("params", {}))
            return

        if method.startswith("event/"):
            protocol_event = method.removeprefix("event/")
            sdk_event = EVENT_NAME_MAP.get(protocol_event, protocol_event)
            params = message.get("params", {})
            self._log.debug(
                "transport",
                "event recv: event=%s %s",
                sdk_event, _summarize_dict(params, _DIAG_RESULT_FIELDS),
            )
            # 提取事件中的 _trace 并回调 observer，然后从 params 中剥离
            if isinstance(params, dict) and "_trace" in params:
                event_trace = params.pop("_trace", None)
                if self._trace_observer is not None and isinstance(event_trace, dict):
                    try:
                        self._trace_observer({"type": "event", "event": sdk_event, "trace": event_trace})
                    except Exception:
                        pass
                if event_trace and isinstance(event_trace, dict):
                    self._log.info("transport", "[trace=%s] event_recv event=%s",
                                   event_trace.get("trace_id", ""), sdk_event)
            if "v2" in sdk_event:
                self._log.info("transport", "DEBUG: V2 event arrived at transport: %s params_keys=%s", sdk_event, list(params.keys()) if isinstance(params, dict) else "?")
            asyncio.create_task(self._dispatcher.publish(f"_raw.{sdk_event}", params))
            return

        self._log.debug("transport", "notification recv: method=%s", method or "<no-method>")
        await self._dispatcher.publish("notification", message)

    @staticmethod
    def _decode_message(raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not isinstance(raw, str):
            raise SerializationError(f"unsupported websocket payload type: {type(raw)!r}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SerializationError("invalid json payload") from exc
