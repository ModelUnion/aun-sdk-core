from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import typer

from aun_cli.config import get_effective_profile_name, get_profile, load_config, set_tab_profile_name
from aun_cli.output import output_error, is_json_mode, set_json_mode


EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_ARGS = 2
EXIT_AUTH = 3
EXIT_CONNECTION = 4
EXIT_TIMEOUT = 5
EXIT_PERMISSION = 6
EXIT_NOT_FOUND = 7


@dataclass
class RPCCallStat:
    method: str
    duration_ms: int
    status: str
    error: str = ""
    origin: str = "main"


@dataclass
class PhaseStat:
    name: str
    duration_ms: int


@dataclass
class CLIInvocationStats:
    start: float
    json_mode: bool = False
    rpc_calls: list[RPCCallStat] = field(default_factory=list)
    phases: list[PhaseStat] = field(default_factory=list)
    printed: bool = False
    suppress_summary: bool = False


_CURRENT_STATS: CLIInvocationStats | None = None


def start_cli_invocation(*, json_mode: bool = False) -> None:
    global _CURRENT_STATS
    _CURRENT_STATS = CLIInvocationStats(start=time.perf_counter(), json_mode=json_mode)
    set_json_mode(json_mode)


def record_rpc_call(method: str, duration_ms: int, status: str, error: str = "", *, origin: str = "main") -> None:
    stats = _CURRENT_STATS
    if stats is None:
        return
    if len(error) > 160:
        error = error[:157] + "..."
    stats.rpc_calls.append(RPCCallStat(method=method, duration_ms=duration_ms, status=status, error=error, origin=origin))


def record_cli_phase(name: str, duration_ms: int) -> None:
    stats = _CURRENT_STATS
    if stats is None:
        return
    stats.phases.append(PhaseStat(name=name, duration_ms=duration_ms))


def suppress_cli_summary() -> None:
    stats = _CURRENT_STATS
    if stats is None:
        return
    stats.suppress_summary = True


def finish_cli_invocation() -> None:
    global _CURRENT_STATS
    stats = _CURRENT_STATS
    try:
        if stats is None or stats.printed:
            return
        stats.printed = True
        if stats.json_mode or stats.suppress_summary or (not stats.rpc_calls and not stats.phases):
            return
        total_ms = int((time.perf_counter() - stats.start) * 1000)
        print(
            f"[aun-cli] RPC summary: count={len(stats.rpc_calls)} total={total_ms}ms",
            file=sys.stderr,
        )
        for index, call in enumerate(stats.rpc_calls, 1):
            marker = " [bg]" if call.origin == "background" else ""
            print(
                f"  {index}.{marker} {call.method} {call.duration_ms}ms {call.status}",
                file=sys.stderr,
            )
            if call.error:
                print(f"     error: {call.error}", file=sys.stderr)
        if stats.phases:
            phase_text = " ".join(f"{phase.name}={phase.duration_ms}ms" for phase in stats.phases)
            print(f"[aun-cli] phase summary: {phase_text}", file=sys.stderr)
    finally:
        set_json_mode(False)
        _CURRENT_STATS = None


def run_async(coro) -> Any:
    """同步入口调用 SDK 异步方法"""
    return asyncio.run(coro)


def _print_debug(message: str) -> None:
    print(message, file=sys.stderr)


def resolve_profile_config(ctx: typer.Context) -> dict[str, Any]:
    """从 ctx.obj + 环境变量 + cli.toml 解析最终配置"""
    from aun_cli.config import load_config
    cfg = load_config()
    defaults = cfg.get("default", {})

    profile_name, profile_source = get_effective_profile_name(ctx.obj.get("profile"))
    if profile_source == "default":
        set_tab_profile_name(profile_name)

    try:
        profile = get_profile(profile_name)
    except KeyError:
        profile = {}

    # Gateway 只能通过 SDK discovery 发现，CLI 不接受外部覆盖。
    gateway = None
    timeout = ctx.obj.get("timeout") or profile.get("timeout") or defaults.get("timeout", 30)
    debug = ctx.obj.get("debug") or os.environ.get("AUN_DEBUG", "").lower() in ("1", "true") or profile.get("debug", defaults.get("debug", False))
    trace = ctx.obj.get("trace") or profile.get("trace") or defaults.get("trace", "off")
    encryption_seed = (
        os.environ.get("AUN_ENCRYPTION_SEED")
        or os.environ.get("AUN_SEED_PASSWORD")
        or profile.get("encryption_seed")
        or profile.get("seed_password")
        or defaults.get("encryption_seed")
        or defaults.get("seed_password")
        or ""
    )

    aun_path = os.environ.get("AUN_DATA_ROOT") or profile.get("aun_path", "")
    if not aun_path:
        aun_path = str(Path.home() / ".aun" / "profiles" / profile_name)

    return {
        "profile_name": profile_name,
        "aid": profile.get("aid"),
        "gateway": gateway,
        "aun_path": aun_path,
        "debug": debug,
        "timeout": timeout,
        "encryption_seed": str(encryption_seed),
        "trace": trace,
        "active_group": str(profile.get("active_group") or "").strip() or None,
        "profile_source": profile_source,
    }


def make_aid_store(resolved: dict[str, Any]):
    from aun_core import AIDStore

    if not isinstance(resolved, dict):
        resolved = {"aun_path": str(resolved)}

    return AIDStore(
        aun_path=resolved["aun_path"],
        encryption_seed=str(resolved.get("encryption_seed") or ""),
        debug=bool(resolved.get("debug")),
    )


class CLISession:
    """管理 AUNClient 生命周期的异步上下文管理器"""

    def __init__(
        self,
        ctx: typer.Context,
        *,
        need_auth: bool = True,
        aid: str | None = None,
        background_sync: bool = False,
    ):
        self._ctx = ctx
        self._need_auth = need_auth
        self._client = None
        self._store = None
        self._foreground_task: asyncio.Task | None = None
        self._background_sync = background_sync
        self._resolved = resolve_profile_config(ctx)
        if aid:
            self._resolved["aid"] = aid

    @property
    def resolved(self) -> dict[str, Any]:
        return self._resolved

    async def __aenter__(self):
        from aun_core import AUNClient
        from aun_core.errors import StateError
        self._foreground_task = asyncio.current_task()

        phase_started = time.perf_counter()
        if self._need_auth and self._resolved["aid"]:
            self._store = make_aid_store(self._resolved)
            loaded = self._store.load(self._resolved["aid"])
            if not loaded.ok or loaded.data is None:
                message = loaded.error.message if loaded.error else "identity load failed"
                raise StateError(message)
            self._client = AUNClient(loaded.data["aid"])
            self._client._aid_store = self._store
        else:
            self._client = AUNClient()
        record_cli_phase("sdk_init", int((time.perf_counter() - phase_started) * 1000))
        self._install_rpc_stats_hooks(self._client)
        debug = self._resolved["debug"]

        # 启用 trace mode
        trace = self._resolved.get("trace", "off")
        if trace and trace != "off":
            self._client.set_trace_mode(trace)

        if self._need_auth and self._resolved["aid"]:
            if debug:
                _print_debug(f"[DEBUG][cli] authenticate: aid={self._resolved['aid']}")
            phase_started = time.perf_counter()
            auth_result = await self._client.authenticate()
            record_cli_phase("authenticate", int((time.perf_counter() - phase_started) * 1000))
            if debug:
                _print_debug(f"[DEBUG][cli] authenticate done: gateway={auth_result.get('gateway')}")
            connect_options = {
                "auto_reconnect": self._background_sync,
                "background_sync": self._background_sync,
            }
            if not self._background_sync:
                connect_options["heartbeat_interval"] = 0
            phase_started = time.perf_counter()
            await asyncio.wait_for(
                self._client.connect(connect_options),
                timeout=self._resolved["timeout"],
            )
            record_cli_phase("connect", int((time.perf_counter() - phase_started) * 1000))
            if debug:
                _print_debug(f"[DEBUG][cli] connect done: state={self._client.state}")
        return self._client

    def _install_rpc_stats_hooks(self, client: Any) -> None:
        client_call = getattr(client, "call", None)
        if not callable(client_call):
            return None

        async def traced_client_call(method: str, params: dict | None = None, *args: Any, **kwargs: Any) -> Any:
            return await self._record_rpc_timing(method, client_call, method, params, *args, **kwargs)

        client.call = traced_client_call
        return None

    async def _record_rpc_timing(
        self,
        method: str,
        call: Callable[..., Awaitable[Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        current_task = asyncio.current_task()
        origin = "main" if current_task is self._foreground_task else "background"
        started = time.perf_counter()
        try:
            result = await call(*args, **kwargs)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            error = str(exc) or type(exc).__name__
            if not self._is_shutdown_background_noise(origin, error):
                record_rpc_call(method, duration_ms, "error", error, origin=origin)
            raise
        duration_ms = int((time.perf_counter() - started) * 1000)
        record_rpc_call(method, duration_ms, "ok", origin=origin)
        return result

    def _is_shutdown_background_noise(self, origin: str, error: str) -> bool:
        if origin != "background":
            return False
        if "transport closed" not in str(error).lower():
            return False
        return bool(getattr(self._client, "is_closing", False) or getattr(self._client, "is_closed", False))

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            phase_started = time.perf_counter()
            await self._client.close()
            record_cli_phase("close", int((time.perf_counter() - phase_started) * 1000))
        if self._store:
            self._store.close()
        return False


def handle_error(e: Exception) -> None:
    """将异常映射到退出码并输出错误信息"""
    from aun_core.errors import AUNError, StateError

    if isinstance(e, asyncio.TimeoutError):
        output_error("operation timed out", hint="increase --timeout or check network", code=EXIT_TIMEOUT)
        raise typer.Exit(EXIT_TIMEOUT)
    if isinstance(e, (ConnectionError, OSError)) or "websocket" in type(e).__name__.lower():
        output_error(str(e), hint="check gateway URL and network connectivity", code=EXIT_CONNECTION)
        raise typer.Exit(EXIT_CONNECTION)
    if isinstance(e, StateError) and "auth" in str(e).lower():
        output_error(str(e), code=EXIT_AUTH)
        raise typer.Exit(EXIT_AUTH)

    if isinstance(e, AUNError):
        code_attr = getattr(e, "code", None)
        if code_attr == -32004:
            output_error(str(e), code=EXIT_PERMISSION)
            raise typer.Exit(EXIT_PERMISSION)
        if code_attr == -32001:
            output_error(str(e), code=EXIT_NOT_FOUND)
            raise typer.Exit(EXIT_NOT_FOUND)

    output_error(str(e), code=EXIT_GENERAL)
    raise typer.Exit(EXIT_GENERAL)
