from __future__ import annotations

from typing import Any


class ClientRuntime:
    """AUNClient 内部运行时入口。

    各分区仍以 AUNClient 现有字段作为兼容 backing store，但所有组件新增写入点
    应通过这些分区方法进入，避免在组件内继续散落 client._xxx 赋值。
    """

    def __init__(self, client: Any) -> None:
        self.client = client
        self.identity = RuntimeIdentityState(self)
        self.lifecycle = RuntimeLifecycleState(self)
        self.rpc = RuntimeRpcState(self)
        self.delivery = RuntimeDeliveryState(self)
        self.v2 = RuntimeV2State(self)
        self.group_state = RuntimeGroupState(self)
        self.services = RuntimeServices(self)

    @classmethod
    def coerce(cls, runtime_or_client: Any) -> "ClientRuntime":
        if isinstance(runtime_or_client, cls):
            return runtime_or_client
        runtime = getattr(runtime_or_client, "_client_runtime", None)
        if isinstance(runtime, cls):
            return runtime
        return cls(runtime_or_client)


class _RuntimeSection:
    def __init__(self, runtime: ClientRuntime) -> None:
        self.runtime = runtime

    @property
    def client(self) -> Any:
        return self.runtime.client


class RuntimeIdentityState(_RuntimeSection):
    @property
    def aid(self) -> str | None:
        return getattr(self.client, "_aid", None)

    @property
    def current_aid(self) -> Any:
        return getattr(self.client, "_current_aid", None)

    @property
    def identity(self) -> dict[str, Any] | None:
        return getattr(self.client, "_identity", None)

    @property
    def device_id(self) -> str:
        return str(getattr(self.client, "_device_id", "") or "")

    @property
    def slot_id(self) -> str:
        return str(getattr(self.client, "_slot_id", "") or "")

    @property
    def config_model(self) -> Any:
        return getattr(self.client, "_config_model", None)

    def set_loaded_identity(self, aid: Any, identity: dict[str, Any]) -> None:
        client = self.client
        client._current_aid = aid
        client._aid = aid.aid
        client._identity = identity
        auth = getattr(client, "_auth", None)
        if auth is not None:
            auth._aid = aid.aid
            auth.set_identity(identity)

    def set_identity(self, identity: dict[str, Any] | None) -> None:
        self.client._identity = identity

    def set_aid(self, aid: str | None) -> None:
        self.client._aid = aid
        auth = getattr(self.client, "_auth", None)
        if auth is not None:
            auth._aid = aid

    def set_instance_context(self, *, device_id: str, slot_id: str) -> None:
        client = self.client
        client._device_id = device_id
        client._slot_id = slot_id
        auth = getattr(client, "_auth", None)
        if auth is not None:
            auth.set_instance_context(device_id=device_id, slot_id=slot_id)

    def clear(self) -> None:
        client = self.client
        client._current_aid = None
        client._aid = None
        client._identity = None

    def apply_runtime_context(
        self,
        *,
        config_model: Any,
        device_id: str,
        slot_id: str,
        log: Any,
        net: Any,
        discovery: Any,
        token_store: Any,
        auth: Any,
        transport: Any,
        agent_md_manager: Any,
    ) -> None:
        client = self.client
        client._config_model = config_model
        client._device_id = device_id
        client._slot_id = slot_id
        client._log = log
        client.config = {
            "aun_path": str(config_model.aun_path),
            "root_ca_path": config_model.root_ca_path,
            "seed_password": config_model.seed_password,
        }
        client._dispatcher._log = log
        client._net = net
        client._discovery = discovery
        client._token_store = token_store
        client._auth = auth
        client._transport = transport
        if agent_md_manager is not None:
            client._agent_md_manager = agent_md_manager
        client._peer_gateway_cache.clear()


class RuntimeLifecycleState(_RuntimeSection):
    @property
    def state(self) -> str:
        return str(getattr(self.client, "_state", ""))

    @property
    def closing(self) -> bool:
        return bool(getattr(self.client, "_closing", False))

    def set_state(self, state: str) -> None:
        self.client._state = state

    def set_closing(self, closing: bool) -> None:
        self.client._closing = closing

    def set_gateway_url(self, gateway_url: str | None) -> None:
        self.client._gateway_url = gateway_url

    def set_loop(self, loop: Any) -> None:
        self.client._loop = loop

    def set_connect_delivery_mode(self, delivery_mode: dict[str, Any]) -> None:
        self.client._connect_delivery_mode = delivery_mode

    def set_session(self, params: dict[str, Any] | None, options: dict[str, Any] | None = None) -> None:
        self.client._session_params = params
        if options is not None:
            self.client._session_options = options

    def clear_retry_state(self) -> None:
        client = self.client
        client._next_retry_at = None
        client._retry_attempt = 0
        client._last_error = None
        client._last_error_code = None

    def set_error(self, error: BaseException | None, code: str | None) -> None:
        self.client._last_error = error
        self.client._last_error_code = code

    def clear_error(self) -> None:
        self.set_error(None, None)

    def set_connected_at(self, connected_at: float | None) -> None:
        self.client._connected_at = connected_at

    def set_next_retry_at(self, next_retry_at: float | None) -> None:
        self.client._next_retry_at = next_retry_at

    def set_retry_attempt(self, attempt: int) -> None:
        self.client._retry_attempt = attempt

    def set_retry_max_attempts(self, max_attempts: int) -> None:
        self.client._retry_max_attempts = max_attempts

    def set_retry_backoff(self, *, attempt: int, next_retry_at: float, max_attempts: int | None = None) -> None:
        client = self.client
        client._retry_attempt = attempt
        client._next_retry_at = next_retry_at
        if max_attempts is not None:
            client._retry_max_attempts = max_attempts
        client._state = "retry_backoff"

    def set_reconnect_task(self, task: Any) -> None:
        self.client._reconnect_task = task

    def clear_reconnect_task(self) -> None:
        self.set_reconnect_task(None)

    def set_heartbeat_nudge(self, nudge: Any) -> None:
        self.client._heartbeat_nudge = nudge

    def set_heartbeat_task(self, task: Any) -> None:
        self.client._heartbeat_task = task

    def set_token_refresh_task(self, task: Any) -> None:
        self.client._token_refresh_task = task

    def set_token_refresh_failures(self, failures: int) -> None:
        self.client._token_refresh_failures = failures

    def increment_token_refresh_failures(self) -> int:
        client = self.client
        client._token_refresh_failures += 1
        return int(client._token_refresh_failures)

    def set_server_kicked(self, server_kicked: bool) -> None:
        self.client._server_kicked = server_kicked

    def set_last_disconnect_info(self, info: dict[str, Any] | None) -> None:
        self.client._last_disconnect_info = info

    def set_connection_failed(self, *, error: BaseException | None, code: str | None) -> None:
        client = self.client
        client._state = "connection_failed"
        client._last_error = error
        client._last_error_code = code
        client._next_retry_at = None

    def reset_for_disconnect(self, next_state: str) -> None:
        client = self.client
        client._identity = None
        client._next_retry_at = None
        client._retry_attempt = 0
        client._last_error = None
        client._last_error_code = None
        client._state = next_state

    def reset_for_close(self) -> None:
        client = self.client
        client._state = "closed"
        client._current_aid = None
        client._aid = None
        client._identity = None
        client._gateway_url = None
        peer_gateway_cache = getattr(client, "_peer_gateway_cache", None)
        if peer_gateway_cache is not None:
            peer_gateway_cache.clear()
        client._session_params = None
        client._next_retry_at = None
        client._retry_attempt = 0
        client._last_error = None
        client._last_error_code = None


class RuntimeRpcState(_RuntimeSection):
    @property
    def protected_headers(self) -> dict[str, Any] | None:
        return getattr(self.client, "_instance_protected_headers", None)

    @protected_headers.setter
    def protected_headers(self, value: dict[str, Any] | None) -> None:
        self.client._instance_protected_headers = value

    @property
    def pull_gates(self) -> dict[str, dict[str, Any]]:
        gates = getattr(self.client, "_pull_gates", None)
        if gates is None:
            gates = {}
            self.client._pull_gates = gates
        return gates

    def set_pull_gates(self, gates: dict[str, dict[str, Any]]) -> None:
        self.client._pull_gates = gates


class RuntimeDeliveryState(_RuntimeSection):
    @property
    def seq_tracker(self) -> Any:
        return getattr(self.client, "_seq_tracker", None)

    @seq_tracker.setter
    def seq_tracker(self, value: Any) -> None:
        self.client._seq_tracker = value

    @property
    def pending_ordered(self) -> dict[str, dict[int, tuple[str, Any]]]:
        pending = getattr(self.client, "_pending_ordered_msgs", None)
        if pending is None:
            pending = {}
            self.client._pending_ordered_msgs = pending
        return pending

    @property
    def pending_p2p_pull_upper(self) -> dict[str, int]:
        pending = getattr(self.client, "_pending_p2p_pull_upper", None)
        if pending is None:
            pending = {}
            self.client._pending_p2p_pull_upper = pending
        return pending

    def set_online_unread_hint_task(self, task: Any) -> None:
        self.client._online_unread_hint_task = task

    def set_gap_fill_active(self, active: bool) -> None:
        self.client._gap_fill_active = active

    def reset_seq_tracking_state(self, *, next_context: Any = None, reset_context: bool = False) -> None:
        from ..seq_tracker import SeqTracker

        client = self.client
        client._seq_tracker = SeqTracker()
        if reset_context:
            client._seq_tracker_context = None
        elif next_context is not None:
            client._seq_tracker_context = next_context
        client._gap_fill_done.clear()
        client._gap_fill_active = False
        client._pushed_seqs.clear()
        self.pending_ordered.clear()
        if hasattr(client, "_pending_p2p_pull_upper"):
            client._pending_p2p_pull_upper.clear()
        if hasattr(client, "_v2_sender_ik_pending"):
            client._v2_sender_ik_pending.clear()
        if hasattr(client, "_v2_sender_ik_fetching"):
            client._v2_sender_ik_fetching.clear()
        if hasattr(client, "_group_synced"):
            client._group_synced.clear()
        if hasattr(client, "_online_unread_hint_queue"):
            client._online_unread_hint_queue.clear()


class RuntimeV2State(_RuntimeSection):
    @property
    def session(self) -> Any:
        return getattr(self.client, "_v2_session", None)

    @session.setter
    def session(self, value: Any) -> None:
        self.client._v2_session = value

    @property
    def bootstrap_cache(self) -> dict[str, Any]:
        cache = getattr(self.client, "_v2_bootstrap_cache", None)
        if cache is None:
            cache = {}
            self.client._v2_bootstrap_cache = cache
        return cache

    def reset_for_identity(self) -> None:
        client = self.client
        client._v2_session = None
        client._v2_bootstrap_cache = {}
        client._v2_sig_cache = {}
        client._v2_sender_ik_pending = {}
        client._v2_sender_ik_fetching = set()

    @property
    def group_spk_registration_inflight(self) -> set[str]:
        inflight = getattr(self.client, "_group_spk_registration_inflight", None)
        if inflight is None:
            inflight = set()
            self.client._group_spk_registration_inflight = inflight
        return inflight

    @property
    def group_spk_rotation_inflight(self) -> set[str]:
        inflight = getattr(self.client, "_group_spk_rotation_inflight", None)
        if inflight is None:
            inflight = set()
            self.client._group_spk_rotation_inflight = inflight
        return inflight

    @property
    def group_spk_peer_fallback_registered(self) -> set[str]:
        registered = getattr(self.client, "_group_spk_peer_fallback_registered", None)
        if registered is None:
            registered = set()
            self.client._group_spk_peer_fallback_registered = registered
        return registered


class RuntimeGroupState(_RuntimeSection):
    @property
    def state_chains(self) -> dict[str, Any]:
        chains = getattr(self.client, "_v2_state_chains", None)
        if chains is None:
            chains = {}
            self.client._v2_state_chains = chains
        return chains

    @property
    def security_levels(self) -> dict[str, str]:
        levels = getattr(self.client, "_v2_group_security_levels", None)
        if levels is None:
            levels = {}
            self.client._v2_group_security_levels = levels
        return levels


class RuntimeServices(_RuntimeSection):
    def __getattr__(self, name: str) -> Any:
        attr = f"_{name}"
        if hasattr(self.client, attr):
            return getattr(self.client, attr)
        raise AttributeError(name)

    def set_agent_md_manager(self, manager: Any) -> None:
        self.client._agent_md_manager = manager
