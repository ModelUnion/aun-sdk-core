from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import typer

from aun_cli.config import load_config, get_profile
from aun_cli.output import output_error, is_json_mode


EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_ARGS = 2
EXIT_AUTH = 3
EXIT_CONNECTION = 4
EXIT_TIMEOUT = 5
EXIT_PERMISSION = 6
EXIT_NOT_FOUND = 7


def run_async(coro) -> Any:
    """同步入口调用 SDK 异步方法"""
    return asyncio.run(coro)


def resolve_profile_config(ctx: typer.Context) -> dict[str, Any]:
    """从 ctx.obj + 环境变量 + cli.toml 解析最终配置"""
    from aun_cli.config import load_config
    cfg = load_config()
    defaults = cfg.get("default", {})

    profile_name = os.environ.get("AUN_PROFILE") or ctx.obj.get("profile", "default")

    try:
        profile = get_profile(profile_name)
    except KeyError:
        profile = {}

    # 优先级：命令行 > 环境变量 > profile 级配置 > 全局默认
    gateway = ctx.obj.get("gateway") or os.environ.get("AUN_GATEWAY") or profile.get("gateway")
    timeout = ctx.obj.get("timeout") or profile.get("timeout") or defaults.get("timeout", 30)
    debug = ctx.obj.get("debug") or os.environ.get("AUN_DEBUG", "").lower() in ("1", "true") or profile.get("debug", defaults.get("debug", False))
    trace = ctx.obj.get("trace") or profile.get("trace") or defaults.get("trace", "off")

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
        "trace": trace,
    }


def _trace_printer(trace_info: dict) -> None:
    """将 trace spans 格式化输出到 stderr"""
    import sys
    from datetime import datetime
    method = trace_info.get("method", "?")
    status = trace_info.get("status", "ok")
    duration_ms = trace_info.get("duration_ms")
    trace_data = trace_info.get("trace", {})
    trace_id = trace_data.get("trace_id", "")
    spans = trace_data.get("spans", [])

    is_tty = sys.stderr.isatty()
    c_trace = "\033[35m" if is_tty else ""   # 紫色 — trace header
    c_ok    = "\033[36m" if is_tty else ""   # 青色 — ok span
    c_err   = "\033[31m" if is_tty else ""   # 红色 — error
    c_dim   = "\033[90m" if is_tty else ""   # 灰色 — 次要信息
    c_reset = "\033[0m"  if is_tty else ""

    status_color = c_err if status == "error" else c_ok
    total_str = f" total={duration_ms}ms" if duration_ms is not None else ""
    header = f"{c_trace}[TRACE][{method}]{c_reset}{status_color}[{status}]{c_reset}{total_str} {c_dim}trace_id={trace_id}{c_reset}"
    print(header, file=sys.stderr, flush=True)

    for i, span in enumerate(spans):
        node   = span.get("node", "?")
        action = span.get("action", "?")
        ms     = span.get("ms", "")
        ts     = span.get("ts", 0)
        ts_str = datetime.fromtimestamp(ts / 1000).strftime("%H:%M:%S.%f")[:-3] if ts else ""

        ms_str = f"{ms}ms" if ms != "" else "0ms"
        ts_part = f" @{ts_str}" if ts_str else ""
        prefix = "  └─" if i == len(spans) - 1 else "  ├─"
        line = f"{c_dim}{prefix}{c_reset} {c_ok}{node}.{action}{c_reset}  {c_dim}dur={ms_str}{ts_part}{c_reset}"
        print(line, file=sys.stderr, flush=True)


class CLISession:
    """管理 AUNClient 生命周期的异步上下文管理器"""

    def __init__(self, ctx: typer.Context, *, need_auth: bool = True, aid: str | None = None, gateway: str | None = None):
        self._ctx = ctx
        self._need_auth = need_auth
        self._client = None
        self._resolved = resolve_profile_config(ctx)
        if aid:
            self._resolved["aid"] = aid
        if gateway:
            self._resolved["gateway"] = gateway

    @property
    def resolved(self) -> dict[str, Any]:
        return self._resolved

    async def __aenter__(self):
        from aun_core import AUNClient
        config: dict[str, Any] = {
            "aun_path": self._resolved["aun_path"],
        }
        if self._resolved["gateway"]:
            config["gateway"] = self._resolved["gateway"]

        self._client = AUNClient(config=config, debug=self._resolved["debug"])
        debug = self._resolved["debug"]

        # 启用 trace mode
        trace = self._resolved.get("trace", "off")
        if trace and trace != "off":
            self._client.set_trace_mode(trace)
            self._client.set_trace_observer(_trace_printer)

        if self._need_auth and self._resolved["aid"]:
            auth_params: dict[str, Any] = {"aid": self._resolved["aid"]}
            if debug:
                print(f"[DEBUG][cli] authenticate: aid={auth_params['aid']}")
            auth_result = await self._client.auth.authenticate(auth_params)
            if debug:
                print(f"[DEBUG][cli] authenticate done: gateway={auth_result.get('gateway')}")
            await asyncio.wait_for(
                self._client.connect(auth_result),
                timeout=self._resolved["timeout"],
            )
            if debug:
                print(f"[DEBUG][cli] connect done: state={self._client.state}")
        return self._client

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.close()
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
