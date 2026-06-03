from __future__ import annotations

import asyncio
import math
import time
from typing import Any

import websockets

from ..config import normalize_slot_id
from ..errors import (
    AUNError,
    AuthError,
    ConnectionError,
    PermissionError as AUNPermissionError,
    StateError,
    ValidationError,
)
from ..types import ConnectionState
from .runtime import ClientRuntime


class LifecycleController:
    """连接生命周期、后台任务与重连协调器。"""

    def __init__(self, runtime: Any) -> None:
        self.runtime = ClientRuntime.coerce(runtime)
        self.client = self.runtime.client

    async def authenticate(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """获取访问 token，但不建立长连接。"""
        client = self.client
        t_start = time.time()
        if client._public_state != ConnectionState.STANDBY:
            raise StateError(f"authenticate not allowed in state {client._public_state.value}")
        if not client._aid:
            raise StateError("authenticate requires loaded identity")
        request = dict(options or {})
        if "gateway" in request or "gateways" in request:
            raise ValidationError("gateway must be resolved by discovery and cannot be supplied externally")
        gateway_url = str(client._gateway_url or "").strip()
        try:
            if not gateway_url:
                gateway_url = await client._discover_gateway_for_aid(client._aid)
            self.runtime.lifecycle.set_gateway_url(gateway_url)
            client._log.debug("client", "authenticate enter: aid=%s gateway=%s", client._aid, gateway_url)
            result = await client._auth.authenticate(gateway_url, aid=client._aid)
            self.runtime.identity.set_aid(str(result.get("aid") or client._aid))
            identity = dict(client._identity) if client._identity else {"aid": client._aid}
            access_token = result.get("access_token")
            if access_token:
                identity["access_token"] = access_token
            refresh_token = result.get("refresh_token")
            if refresh_token:
                identity["refresh_token"] = refresh_token
            expires_at = result.get("access_token_expires_at", result.get("expires_at"))
            if expires_at is not None:
                identity["access_token_expires_at"] = expires_at
            self.runtime.identity.set_identity(identity)
            self.runtime.lifecycle.set_state(ConnectionState.AUTHENTICATED.value)
            self.runtime.lifecycle.clear_error()
            client._log.debug(
                "client",
                "authenticate exit: elapsed=%.3fs aid=%s",
                time.time() - t_start,
                client._aid,
            )
            return result
        except Exception as exc:
            self.runtime.lifecycle.set_error(exc, "authenticate_failed")
            client._log.debug(
                "client",
                "authenticate exit (error): elapsed=%.3fs aid=%s err=%s",
                time.time() - t_start,
                client._aid,
                exc,
            )
            raise

    async def connect(self, opts: dict[str, Any] | None = None) -> None:
        from ..client import _PUBLIC_CONNECTION_OPTION_KEYS

        client = self.client
        _t_start = time.time()
        if client._public_state not in {
            ConnectionState.NO_IDENTITY,
            ConnectionState.STANDBY,
            ConnectionState.AUTHENTICATED,
            ConnectionState.RETRY_BACKOFF,
            ConnectionState.CONNECTION_FAILED,
        }:
            raise StateError(f"connect not allowed in state {client._public_state.value}")
        params: dict[str, Any] = {}
        if opts:
            invalid_keys = set(opts) - _PUBLIC_CONNECTION_OPTION_KEYS
            if invalid_keys:
                invalid = ", ".join(sorted(invalid_keys))
                raise ValidationError(f"connect options contain unsupported field(s): {invalid}")
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
            if "connection_kind" in opts:
                params["connection_kind"] = opts["connection_kind"]
            if "short_ttl_ms" in opts:
                params["short_ttl_ms"] = opts["short_ttl_ms"]
            if "extra_info" in opts:
                params["extra_info"] = opts["extra_info"]
            if "delivery_mode" in opts:
                params["delivery_mode"] = opts["delivery_mode"]
            if "background_sync" in opts:
                params["background_sync"] = opts["background_sync"]
        # slot_id 来自 AID，不从 opts 传入
        slot_id = getattr(client._current_aid, "slot_id", None) or client._slot_id or ""
        if slot_id:
            params["slot_id"] = slot_id
        if client._public_state == ConnectionState.NO_IDENTITY:
            raise StateError("connect requires a loaded identity")

        if client._public_state == ConnectionState.STANDBY:
            auth_result = await client.authenticate()
            params["access_token"] = auth_result.get("access_token")
            params["gateway"] = auth_result.get("gateway") or client._gateway_url
        elif client._public_state in {
            ConnectionState.AUTHENTICATED,
            ConnectionState.RETRY_BACKOFF,
            ConnectionState.CONNECTION_FAILED,
        }:
            identity = client._identity if isinstance(client._identity, dict) else {}
            token = identity.get("access_token")
            if not token and client._session_params:
                token = client._session_params.get("access_token")
            if token:
                params["access_token"] = token
            if client._gateway_url:
                params["gateway"] = client._gateway_url

        if client._public_state == ConnectionState.RETRY_BACKOFF and client._reconnect_task is not None:
            client._reconnect_task.cancel()
            try:
                await client._reconnect_task
            except asyncio.CancelledError:
                pass
            self.runtime.lifecycle.clear_reconnect_task()

        if client._public_state == ConnectionState.CONNECTION_FAILED:
            self.runtime.lifecycle.set_retry_attempt(0)
            self.runtime.lifecycle.clear_error()
        self.runtime.lifecycle.set_next_retry_at(None)

        normalized = client._normalize_connect_params(params)
        self.runtime.lifecycle.set_state(ConnectionState.CONNECTING.value)
        self.runtime.lifecycle.set_session(normalized, client._build_session_options(normalized))
        client._transport.set_timeout(client._session_options["timeouts"]["call"])
        self.runtime.lifecycle.set_closing(False)

        gateways = client._resolve_gateways(normalized)
        client._log.debug("client", "connect enter: gateways=%s", gateways)
        last_error: BaseException | None = None
        for gw in gateways:
            try:
                gw_params = dict(normalized)
                gw_params["gateway"] = gw
                await client._connect_once(gw_params, allow_reauth=False)
                if client._public_state != ConnectionState.READY:
                    self.runtime.lifecycle.set_state(ConnectionState.READY.value)
                self.runtime.lifecycle.clear_error()
                self.runtime.lifecycle.set_next_retry_at(None)
                client._log.debug(
                    "client",
                    "connect exit: elapsed=%.3fs gateway=%s aid=%s",
                    time.time() - _t_start,
                    client._gateway_url,
                    client._aid or "-",
                )
                return
            except BaseException as exc:
                last_error = exc
                if len(gateways) > 1:
                    client._log.warn("client", "connect: gateway %s failed, trying next: %s", gw, exc)
                if client._public_state == ConnectionState.CONNECTING:
                    self.runtime.lifecycle.set_state(ConnectionState.CONNECTING.value)

        if client._public_state == ConnectionState.CONNECTING:
            self.runtime.lifecycle.set_state(ConnectionState.STANDBY.value if client.has_identity else ConnectionState.NO_IDENTITY.value)
        if last_error is not None:
            self.runtime.lifecycle.set_error(last_error, "connect_failed")
        client._log.warn(
            "client",
            "connect exit (error): elapsed=%.3fs gateways=%s err=%s",
            time.time() - _t_start,
            gateways,
            last_error,
        )
        raise last_error  # type: ignore[misc]

    async def disconnect(self) -> None:
        """断开连接但不关闭客户端（可重新 connect，对齐 C++ Disconnect）"""
        client = self.client
        _t_start = time.time()
        client._log.debug("client", "disconnect enter: state=%s closing=%s", client._state, client._closing)
        # 若 close() 已在执行中，跳过 disconnect 避免竞态
        if client._closing:
            client._log.debug("client", "disconnect exit (close-in-progress): elapsed=%.3fs", time.time() - _t_start)
            return
        if client._public_state not in {
            ConnectionState.AUTHENTICATED,
            ConnectionState.CONNECTING,
            ConnectionState.READY,
            ConnectionState.RETRY_BACKOFF,
            ConnectionState.RECONNECTING,
            ConnectionState.CONNECTION_FAILED,
        }:
            client._log.debug(
                "client",
                "disconnect exit (not-connected): elapsed=%.3fs state=%s",
                time.time() - _t_start,
                client._state,
            )
            return
        client._save_seq_tracker_state()
        await client._stop_background_tasks()
        # 取消重连任务，防止 disconnect 后僵尸重连
        if client._reconnect_task is not None:
            client._reconnect_task.cancel()
            try:
                await client._reconnect_task
            except asyncio.CancelledError:
                pass
            self.runtime.lifecycle.clear_reconnect_task()
        await client._transport.close()
        next_state = (
            ConnectionState.STANDBY.value
            if client._current_aid is not None or client._aid
            else ConnectionState.NO_IDENTITY.value
        )
        self.runtime.lifecycle.reset_for_disconnect(next_state)
        await client._dispatcher.publish("state_change", {"state": client._state})
        client._log.debug("client", "disconnect exit: elapsed=%.3fs state=%s", time.time() - _t_start, client._state)

    async def close(self) -> None:
        client = self.client
        _t_start = time.time()
        client._log.debug("client", "close enter: state=%s", client._state)
        self.runtime.lifecycle.set_closing(True)
        try:
            # 关闭前保存 SeqTracker 状态
            client._save_seq_tracker_state()
            await client._stop_background_tasks()
            if client._reconnect_task is not None:
                client._reconnect_task.cancel()
                try:
                    await client._reconnect_task
                except asyncio.CancelledError:
                    pass  # 任务取消，正常清理
                self.runtime.lifecycle.clear_reconnect_task()
            if client._state in {"idle", "closed"}:
                self.runtime.lifecycle.reset_for_close()
                client._reset_seq_tracking_state()
                client._log.debug(
                    "client",
                    "close exit (was idle/closed): elapsed=%.3fs state=%s",
                    time.time() - _t_start,
                    client._state,
                )
                return
            await client._transport.close()
            self.runtime.lifecycle.reset_for_close()
            await client._dispatcher.publish("state_change", {"state": client._state})
            client._reset_seq_tracking_state()
            client._log.debug("client", "close exit: elapsed=%.3fs state=%s", time.time() - _t_start, client._state)
        finally:
            close_token_store = getattr(client._token_store, "close", None)
            if callable(close_token_store):
                close_token_store()

    async def connect_once(self, params: dict[str, Any], *, allow_reauth: bool) -> None:
        client = self.client
        _t_start = time.time()
        gateway_url = client._resolve_gateway(params)
        self.runtime.lifecycle.set_gateway_url(gateway_url)
        self.runtime.lifecycle.set_loop(asyncio.get_running_loop())
        self.runtime.identity.set_instance_context(
            device_id=client._device_id,
            slot_id=normalize_slot_id(params.get("slot_id")),
        )
        self.runtime.lifecycle.set_connect_delivery_mode(dict(params.get("delivery_mode") or client._connect_delivery_mode))
        connection_kind = str(params.get("connection_kind") or "long")
        short_ttl_ms = int(params.get("short_ttl_ms") or 0)
        extra_info = params.get("extra_info") if isinstance(params.get("extra_info"), dict) else None
        self.runtime.lifecycle.set_state("connecting")
        client._log.debug(
            "client",
            "_connect_once enter: gateway=%s allow_reauth=%s kind=%s",
            gateway_url,
            allow_reauth,
            connection_kind,
        )

        try:
            # 前置 restore：在 transport.connect 启动 reader 之前完成，避免启动期竞态。
            client._refresh_seq_tracking_context()
            client._restore_seq_tracker_state()

            client._log.debug("client", "transport.connect start: gateway=%s allow_reauth=%s", gateway_url, allow_reauth)
            challenge = await client._transport.connect(gateway_url)
            # 连接成功：刷新 DNS 缓存
            net = getattr(client, "_net", None)
            if net is not None:
                try:
                    net._refresh_dns_cache_after_success(gateway_url)
                except Exception as exc:
                    client._log.debug("client", "DNS cache refresh skipped: %s", exc)
            self.runtime.lifecycle.set_state("authenticating")
            client._log.debug("client", "auth phase start: mode=%s", "reauth" if allow_reauth else "token")
            if allow_reauth:
                auth_context = await client._auth.connect_session(
                    client._transport,
                    challenge,
                    gateway_url,
                    access_token=params.get("access_token"),
                    device_id=client._device_id,
                    slot_id=client._slot_id,
                    delivery_mode=client._connect_delivery_mode,
                    connection_kind=connection_kind,
                    short_ttl_ms=short_ttl_ms,
                    extra_info=extra_info,
                )
                identity = auth_context.get("identity") if isinstance(auth_context, dict) else None
                if isinstance(identity, dict):
                    self.runtime.identity.set_identity(identity)
                    self.runtime.identity.set_aid(identity.get("aid", client._aid))
                    if client._session_params is not None:
                        client._session_params["access_token"] = auth_context.get("token", params.get("access_token"))
                hello = auth_context.get("hello") if isinstance(auth_context, dict) else None
                if isinstance(hello, dict) and "heartbeat_interval" in hello:
                    client._apply_server_heartbeat_interval(hello.get("heartbeat_interval"), source="auth")
            else:
                hello = await client._auth.initialize_with_token(
                    client._transport,
                    challenge,
                    str(params["access_token"]),
                    device_id=client._device_id,
                    slot_id=client._slot_id,
                    delivery_mode=client._connect_delivery_mode,
                    connection_kind=connection_kind,
                    short_ttl_ms=short_ttl_ms,
                    extra_info=extra_info,
                )
                client._sync_identity_after_connect(str(params["access_token"]))
                if isinstance(hello, dict) and "heartbeat_interval" in hello:
                    client._apply_server_heartbeat_interval(hello.get("heartbeat_interval"), source="auth")
            self.runtime.lifecycle.set_state(ConnectionState.READY.value)
            self.runtime.lifecycle.set_connected_at(time.time())
            self.runtime.lifecycle.clear_error()
            self.runtime.lifecycle.set_next_retry_at(None)
            client._log.debug(
                "client",
                "auth complete, state changed to ready: gateway=%s aid=%s",
                gateway_url,
                client._aid or "-",
            )
            await client._dispatcher.publish("state_change", {"state": client._state, "gateway": gateway_url})

            # auth 阶段 aid 可能被 identity 覆盖；若 context 变化，重新 refresh + restore。
            if client._seq_tracker_context != client._current_seq_tracker_context():
                client._refresh_seq_tracking_context()
                client._restore_seq_tracker_state()

            client._start_background_tasks()

            session_options = getattr(client, "_session_options", {}) or {}
            background_sync = bool(params.get("background_sync", session_options.get("background_sync", True)))

            # connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压。
            if background_sync:
                try:
                    loop = client._loop or asyncio.get_running_loop()
                    loop.create_task(client._fill_p2p_gap())
                except Exception as exc:
                    client._log.warn("client", "schedule post-connect P2P gap fill failed: %s", exc)

            await client._v2_e2ee_coordinator().on_connected(background_sync=background_sync)
            client._log.debug(
                "client",
                "_connect_once exit: elapsed=%.3fs gateway=%s aid=%s",
                time.time() - _t_start,
                gateway_url,
                client._aid or "-",
            )
        except Exception as exc:
            client._log.debug(
                "client",
                "_connect_once exit (error): elapsed=%.3fs gateway=%s err=%s",
                time.time() - _t_start,
                gateway_url,
                exc,
            )
            raise

    def start_background_tasks(self) -> None:
        client = self.client
        # 短连接生命周期短，禁用心跳与 token 刷新（不接收推送、不需要长期会话维护）
        if not client._session_options.get("background_sync", True):
            return
        if client._session_options.get("connection_kind") != "short":
            client._start_heartbeat_task()
            client._start_token_refresh_task()

    async def stop_background_tasks(self) -> None:
        client = self.client
        current_task = asyncio.current_task()
        for attr in (
            "_heartbeat_task",
            "_token_refresh_task",
            "_online_unread_hint_task",
        ):
            task = getattr(client, attr, None)
            if task is None:
                continue
            task.cancel()
            if task is current_task:
                setattr(client, attr, None)
                continue
            try:
                await task
            except asyncio.CancelledError:
                pass
            setattr(client, attr, None)
        if hasattr(client, "_online_unread_hint_queue"):
            client._online_unread_hint_queue.clear()

    def start_heartbeat_task(self) -> None:
        from ..client import _clamp_heartbeat_interval

        client = self.client
        if client._heartbeat_task is not None and not client._heartbeat_task.done():
            return
        # interval=0 时不启动 task（避免空转）；服务端下发非零值时会通过
        # _apply_server_heartbeat_interval 触发启动。
        interval = _clamp_heartbeat_interval(client._session_options.get("heartbeat_interval"))
        if interval <= 0:
            return
        if client._heartbeat_nudge is None:
            self.runtime.lifecycle.set_heartbeat_nudge(asyncio.Event())
        self.runtime.lifecycle.set_heartbeat_task(asyncio.create_task(client._heartbeat_loop()))

    def start_token_refresh_task(self) -> None:
        client = self.client
        if client._token_refresh_task is not None and not client._token_refresh_task.done():
            return
        self.runtime.lifecycle.set_token_refresh_task(asyncio.create_task(client._token_refresh_loop()))

    async def heartbeat_loop(self) -> None:
        from ..client import _clamp_heartbeat_interval

        client = self.client
        consecutive_failures = 0
        max_failures = 3  # 连续失败 3 次触发重连
        try:
            while not client._closing:
                interval = _clamp_heartbeat_interval(client._session_options.get("heartbeat_interval"))
                if interval <= 0:
                    # 心跳被服务端动态关闭：退出循环，task 终止；后续若再下发非零值会重新 start
                    return
                client._heartbeat_nudge.clear()
                try:
                    # 用 nudge.wait 实现"可中断 sleep"：interval 改变可立即生效
                    await asyncio.wait_for(client._heartbeat_nudge.wait(), timeout=interval)
                    # nudge 触发：重读 interval，不发心跳
                    continue
                except asyncio.TimeoutError:
                    pass  # 正常到点，发心跳
                if client._state != "connected":
                    consecutive_failures = 0
                    continue
                try:
                    pong = await client._transport.call("meta.ping", {})
                    consecutive_failures = 0
                    # 服务端可在 pong 中下发新的 heartbeat_interval
                    if isinstance(pong, dict) and "heartbeat_interval" in pong:
                        client._apply_server_heartbeat_interval(pong.get("heartbeat_interval"), source="pong")
                except Exception as exc:
                    consecutive_failures += 1
                    client._log.warn("client", "heartbeat failed (%d/%d): %s", consecutive_failures, max_failures, exc)
                    await client._dispatcher.publish("connection.error", {"error": exc})
                    if consecutive_failures >= max_failures:
                        client._log.warn("client", "%d consecutive heartbeat failures, triggering reconnect", max_failures)
                        await client._handle_transport_disconnect(exc)
                        return
        except asyncio.CancelledError:
            raise

    def apply_server_heartbeat_interval(self, raw: Any, *, source: str) -> None:
        """读取服务端下发的 heartbeat_interval 并写入 session_options，唤醒/启动/停止心跳循环。"""
        from ..client import _clamp_heartbeat_interval

        client = self.client
        new_interval = _clamp_heartbeat_interval(raw)
        old_interval = _clamp_heartbeat_interval(client._session_options.get("heartbeat_interval"))
        if new_interval == old_interval:
            return
        client._session_options["heartbeat_interval"] = new_interval
        client._log.debug("client", "heartbeat_interval updated by %s: %s -> %s", source, old_interval, new_interval)
        # 唤醒已在跑的循环（让它重读 interval；若新值=0 会自然退出）
        if client._heartbeat_nudge is not None:
            client._heartbeat_nudge.set()
        # 之前 interval=0 没起任务，新值为正时需要启动
        if new_interval > 0 and (client._heartbeat_task is None or client._heartbeat_task.done()):
            client._start_heartbeat_task()

    async def token_refresh_loop(self) -> None:
        from ..client import (
            _TOKEN_REFRESH_CHECK_INTERVAL,
            _TOKEN_REFRESH_DEFAULT_LEAD,
            _TOKEN_REFRESH_MAX_FAILURES,
        )

        client = self.client
        lead = float(client._session_options.get("token_refresh_before", _TOKEN_REFRESH_DEFAULT_LEAD))
        if not math.isfinite(lead) or lead <= 0:
            lead = _TOKEN_REFRESH_DEFAULT_LEAD
        try:
            while not client._closing:
                gateway_url = client.gateway_url
                if client._public_state != ConnectionState.READY or not gateway_url:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                identity = client._identity
                if identity is None:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                self.runtime.identity.set_identity(identity)
                expires_at = client._auth.get_access_token_expiry(identity)
                if expires_at is None:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                if expires_at - time.time() > lead:
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                try:
                    identity = await client._auth.refresh_cached_tokens(gateway_url, identity)
                    # 防竞态：刷新期间可能已断线/重连，状态不再是 READY 说明 transport 已变，丢弃结果
                    if client._public_state != ConnectionState.READY:
                        client._log.debug("client", "token refresh succeeded but state changed, discarding result")
                        return
                    self.runtime.identity.set_identity(identity)
                    if client._session_params is not None and identity.get("access_token"):
                        client._session_params["access_token"] = identity["access_token"]
                    await client._dispatcher.publish("token.refreshed", {
                        "aid": identity.get("aid"),
                        "expires_at": identity.get("access_token_expires_at"),
                    })
                    self.runtime.lifecycle.set_token_refresh_failures(0)  # 刷新成功，重置连续失败计数
                except AuthError as exc:
                    failures = self.runtime.lifecycle.increment_token_refresh_failures()
                    if failures >= _TOKEN_REFRESH_MAX_FAILURES:
                        client._log.warn(
                            "client",
                            "token 刷新连续失败 %d 次，停止刷新循环并触发重连",
                            failures,
                        )
                        await client._dispatcher.publish("token.refresh_exhausted", {
                            "aid": client._identity.get("aid") if client._identity else None,
                            "consecutive_failures": failures,
                            "last_error": str(exc),
                        })
                        self.runtime.lifecycle.set_token_refresh_failures(0)
                        # 不直接调用 _handle_transport_disconnect（会 cancel 自身导致递归），
                        # 而是关闭 transport 让 on_disconnect 回调自然触发重连。
                        if client._transport and not getattr(client._transport, "_closed", True):
                            await client._transport.close()
                        return
                    else:
                        client._log.debug(
                            "client",
                            "token 刷新失败 (%d/%d)，下次检查后重试: %s",
                            failures,
                            _TOKEN_REFRESH_MAX_FAILURES,
                            exc,
                        )
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
                    continue
                except Exception as exc:
                    await client._dispatcher.publish("connection.error", {"error": exc})
                    await asyncio.sleep(_TOKEN_REFRESH_CHECK_INTERVAL)
        except asyncio.CancelledError:
            raise

    async def on_gateway_disconnect(self, data: Any) -> None:
        """处理服务端主动断开通知 event/gateway.disconnect。"""
        client = self.client
        if not isinstance(data, dict):
            data = {}
        code = data.get("code")
        reason = data.get("reason", "")
        detail = data.get("detail") if isinstance(data.get("detail"), dict) else {}
        client._log.warn(
            "client",
            "server initiated disconnect: code=%s, reason=%s, detail=%s",
            code,
            reason,
            detail,
        )
        self.runtime.lifecycle.set_server_kicked(True)
        # 缓存最近一次 disconnect 信息，让后续 connection.state(terminal_failed) 也能带 detail
        self.runtime.lifecycle.set_last_disconnect_info({"code": code, "reason": reason, "detail": detail})
        # 透传给应用层订阅者
        try:
            await client._dispatcher.publish("gateway.disconnect", {
                "code": code,
                "reason": reason,
                "detail": detail,
            })
        except Exception as exc:
            client._log.debug("client", "publish gateway.disconnect failed: %s", exc)

    async def handle_transport_disconnect(self, error: Exception | None, close_code: int | None = None) -> None:
        client = self.client
        if client._closing or client._state == "closed":
            return
        # 断线时保存 SeqTracker 状态，防止进程崩溃后 seq 回退
        try:
            client._save_seq_tracker_state()
        except Exception as exc:
            client._log.debug("client", "failed to save SeqTracker on disconnect: %s", exc)
        if not bool(client._session_options["auto_reconnect"]):
            self.runtime.lifecycle.reset_for_disconnect(
                ConnectionState.STANDBY.value if client.has_identity else ConnectionState.NO_IDENTITY.value
            )
            self.runtime.lifecycle.set_error(error, "transport_disconnected" if error else None)
            await client._dispatcher.publish("state_change", {"state": client._state, "error": error})
            return
        if client._reconnect_task is not None and not client._reconnect_task.done():
            return
        # 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
        if client._server_kicked or (close_code is not None and close_code in client._NO_RECONNECT_CODES):
            self.runtime.lifecycle.set_connection_failed(
                error=error,
                code="server_kicked" if client._server_kicked else "no_reconnect_close_code",
            )
            reason = "server kicked" if client._server_kicked else f"close code {close_code}"
            client._log.warn("client", "suppressing auto-reconnect: %s", reason)
            disconnect_info = getattr(client, "_last_disconnect_info", None) or {}
            event_payload = {
                "state": client._state, "error": error, "reason": reason,
            }
            # 把服务端附带的结构化 detail（如配额超限信息）也带给应用层
            if disconnect_info.get("detail"):
                event_payload["detail"] = disconnect_info["detail"]
            if disconnect_info.get("code") is not None:
                event_payload["code"] = disconnect_info["code"]
            await client._dispatcher.publish("state_change", event_payload)
            return
        await client._stop_background_tasks()
        # 1006 = 网络异常断开（无 close frame），1000 = 正常关闭（客户端主动）
        # 其他 code = 服务端主动关闭
        server_initiated = close_code is not None and close_code not in (1000, 1006)
        self.runtime.lifecycle.set_reconnect_task(asyncio.create_task(client._reconnect_loop(server_initiated)))

    async def reconnect_loop(self, server_initiated: bool = False) -> None:
        from ..client import (
            _RECONNECT_MAX_BASE_DELAY,
            _clamp_reconnect_delay,
            _reconnect_sleep_delay,
        )

        client = self.client
        retry = dict(client._session_options["retry"])
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
        self.runtime.lifecycle.set_retry_attempt(0)
        self.runtime.lifecycle.set_retry_max_attempts(max_attempts)
        client._log.debug(
            "client",
            "reconnect loop started: server_initiated=%s max_attempts=%s base_delay=%.1fs",
            server_initiated,
            max_attempts,
            base_delay,
        )

        while not client._closing:
            attempt += 1
            sleep_delay = _reconnect_sleep_delay(delay, max_base_delay)
            self.runtime.lifecycle.set_retry_backoff(
                attempt=attempt,
                next_retry_at=time.time() + sleep_delay,
            )
            await client._dispatcher.publish("state_change", {
                "state": client._state,
                "attempt": attempt,
                "next_retry_at": client._next_retry_at,
            })
            try:
                # 固定上限抖动：base=[1s, max_base]，delay=base+rand(0..max_base)。
                await client._reconnect_sleep(sleep_delay)
                if client._closing:
                    self.runtime.lifecycle.set_next_retry_at(None)
                    self.runtime.lifecycle.clear_reconnect_task()
                    return
                self.runtime.lifecycle.set_next_retry_at(None)
                self.runtime.lifecycle.set_state(ConnectionState.RECONNECTING.value)
                await client._dispatcher.publish("state_change", {
                    "state": client._state,
                    "attempt": attempt,
                })
                if client._closing:
                    self.runtime.lifecycle.clear_reconnect_task()
                    return
                # 重连前先 GET /health 探测，不健康则跳过本轮
                gateway_url = client.gateway_url
                if gateway_url:
                    healthy = await client._discovery.check_health(gateway_url)
                    if client._closing:
                        self.runtime.lifecycle.clear_reconnect_task()
                        return
                    if not healthy:
                        client._log.debug(
                            "client",
                            "reconnect health check failed, skipping this round: attempt=%d gateway=%s",
                            attempt,
                            gateway_url,
                        )
                        self.runtime.lifecycle.set_error(RuntimeError("gateway health check failed"), "gateway_unhealthy")
                        if max_attempts > 0 and attempt >= max_attempts:
                            self.runtime.lifecycle.set_state(ConnectionState.CONNECTION_FAILED.value)
                            self.runtime.lifecycle.clear_reconnect_task()
                            await client._dispatcher.publish("state_change", {
                                "state": client._state,
                                "attempt": attempt,
                                "reason": "max_attempts_exhausted",
                            })
                            return
                        delay = min(delay * 2, max_base_delay)
                        continue
                await client._transport.close()
                if client._closing:
                    self.runtime.lifecycle.clear_reconnect_task()
                    return
                client._log.debug("client", "reconnect attempting _connect_once: attempt=%d", attempt)
                await client._invoke_reconnect_connect_once()
                if client._closing:
                    self.runtime.lifecycle.clear_reconnect_task()
                    return
                client._log.debug("client", "reconnect success: attempt=%d", attempt)
                if client._public_state != ConnectionState.READY:
                    self.runtime.lifecycle.set_state(ConnectionState.READY.value)
                self.runtime.lifecycle.clear_error()
                self.runtime.lifecycle.set_next_retry_at(None)
                self.runtime.lifecycle.clear_reconnect_task()
                return
            except asyncio.CancelledError:
                self.runtime.lifecycle.set_next_retry_at(None)
                self.runtime.lifecycle.clear_reconnect_task()
                raise
            except Exception as exc:
                retryable = client._should_retry_reconnect(exc)
                self.runtime.lifecycle.set_error(exc, "reconnect_failed")
                client._log.warn("client", "reconnect failed: attempt=%d error=%s retryable=%s", attempt, exc, retryable)
                await client._dispatcher.publish("connection.error", {
                    "error": exc,
                    "attempt": attempt,
                })
                if not retryable or (max_attempts > 0 and attempt >= max_attempts):
                    self.runtime.lifecycle.set_state(ConnectionState.CONNECTION_FAILED.value)
                    self.runtime.lifecycle.set_next_retry_at(None)
                    self.runtime.lifecycle.clear_reconnect_task()
                    await client._dispatcher.publish("state_change", {
                        "state": client._state,
                        "error": exc,
                        "attempt": attempt,
                        "reason": "not_retryable" if not retryable else "max_attempts_exhausted",
                    })
                    return
                delay = min(delay * 2, max_base_delay)

    async def reconnect_sleep(self, delay: float) -> None:
        await asyncio.sleep(delay)

    async def invoke_reconnect_connect_once(self) -> None:
        client = self.client
        if client._session_params is None:
            raise StateError("missing connect params for reconnect")
        # 从内存 identity 刷新 token，避免用过期/失败的旧 token 反复重试
        fresh_identity = client._identity
        if fresh_identity:
            fresh_token = client._auth._get_cached_access_token(fresh_identity)
            if fresh_token:
                client._log.debug(
                    "client",
                    "_invoke_reconnect_connect_once refreshed access_token from cached identity aid=%s",
                    client._aid,
                )
                client._session_params["access_token"] = fresh_token
            else:
                client._log.debug(
                    "client",
                    "_invoke_reconnect_connect_once cached identity has no valid access_token aid=%s",
                    client._aid,
                )
        else:
            client._log.debug(
                "client",
                "_invoke_reconnect_connect_once no cached identity for aid=%s, using existing session params",
                client._aid,
            )
        await client._connect_once(client._session_params, allow_reauth=True)

    def should_retry_reconnect(self, error: Exception) -> bool:
        return self.should_retry_reconnect_error(error)

    @staticmethod
    def should_retry_reconnect_error(error: Exception) -> bool:
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

    def resolve_gateway(self, params: dict[str, Any]) -> str:
        gateways = self.resolve_gateways(params)
        return gateways[0]

    def resolve_gateways(self, params: dict[str, Any]) -> list[str]:
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

    def normalize_connect_params(self, params: dict[str, Any]) -> dict[str, Any]:
        from ..client import _normalize_delivery_mode_config

        client = self.client
        request = dict(params)
        access_token = str(request.get("access_token") or "")
        if not access_token:
            raise StateError("connect requires non-empty access_token")
        gateway = str(request.get("gateway") or client.gateway_url or "")
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
        request["device_id"] = client._device_id
        request["slot_id"] = normalize_slot_id(request.get("slot_id", client._slot_id))
        delivery_mode_raw = request.get("delivery_mode")
        if delivery_mode_raw is None:
            delivery_mode_raw = dict(client._default_connect_delivery_mode)
        elif not isinstance(delivery_mode_raw, dict):
            delivery_mode_raw = {"mode": delivery_mode_raw}
        if "queue_routing" in request:
            delivery_mode_raw["routing"] = request["queue_routing"]
        if "affinity_ttl_ms" in request:
            delivery_mode_raw["affinity_ttl_ms"] = request["affinity_ttl_ms"]
        request["delivery_mode"] = _normalize_delivery_mode_config(delivery_mode_raw)

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

    def build_session_options(self, params: dict[str, Any]) -> dict[str, Any]:
        from ..client import _DEFAULT_SESSION_OPTIONS

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
