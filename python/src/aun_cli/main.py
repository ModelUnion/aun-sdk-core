from __future__ import annotations

import typer

from aun_cli import __version__

app = typer.Typer(
    name="aun",
    help="AUN Protocol CLI — 身份管理、消息收发、群组操作、诊断",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"aun {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    profile: str = typer.Option("default", "--profile", "-p", help="使用指定 profile"),
    gateway: str | None = typer.Option(None, "--gateway", "-g", help="覆盖网关地址"),
    json_output: bool = typer.Option(False, "--json", help="JSON 格式输出"),
    debug: bool = typer.Option(False, "--debug", help="启用 debug 日志"),
    no_color: bool = typer.Option(False, "--no-color", help="禁用彩色输出"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="操作超时秒数"),
    version: bool = typer.Option(False, "--version", "-V", callback=version_callback, is_eager=True),
) -> None:
    """全局选项"""
    ctx.ensure_object(dict)
    ctx.obj["profile"] = profile
    ctx.obj["gateway"] = gateway
    ctx.obj["json"] = json_output
    ctx.obj["debug"] = debug
    ctx.obj["no_color"] = no_color
    ctx.obj["timeout"] = timeout
