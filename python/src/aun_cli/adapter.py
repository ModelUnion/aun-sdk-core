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
    profile_name = os.environ.get("AUN_PROFILE") or ctx.obj.get("profile", "default")
    gateway = ctx.obj.get("gateway") or os.environ.get("AUN_GATEWAY")
    debug = ctx.obj.get("debug") or os.environ.get("AUN_DEBUG", "").lower() in ("1", "true")
    timeout = ctx.obj.get("timeout", 30)

    try:
        profile = get_profile(profile_name)
    except KeyError:
        profile = {}

    aun_path = os.environ.get("AUN_DATA_ROOT") or profile.get("aun_path", "")
    if not aun_path:
        aun_path = str(Path.home() / ".aun" / "profiles" / profile_name)

    return {
        "profile_name": profile_name,
        "aid": profile.get("aid"),
        "gateway": gateway or profile.get("gateway"),
        "aun_path": aun_path,
        "debug": debug,
        "timeout": timeout,
    }


class CLISession:
    """管理 AUNClient 生命周期的异步上下文管理器"""

    def __init__(self, ctx: typer.Context, *, need_auth: bool = True):
        self._ctx = ctx
        self._need_auth = need_auth
        self._client = None
        self._resolved = resolve_profile_config(ctx)

    @property
    def resolved(self) -> dict[str, Any]:
        return self._resolved

    async def __aenter__(self):
        from aun_core import AUNClient
        config: dict[str, Any] = {
            "aun_path": self._resolved["aun_path"],
        }

        self._client = AUNClient(config=config, debug=self._resolved["debug"])

        if self._need_auth and self._resolved["aid"]:
            auth_params: dict[str, Any] = {"aid": self._resolved["aid"]}
            if self._resolved["gateway"]:
                auth_params["gateway"] = self._resolved["gateway"]
            await asyncio.wait_for(
                self._client.connect(auth=auth_params),
                timeout=self._resolved["timeout"],
            )
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
