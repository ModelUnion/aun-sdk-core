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

    # 输出 banner（JSON 模式下静默）
    if not json_output:
        from aun_cli.adapter import resolve_profile_config
        resolved = resolve_profile_config(ctx)
        aid = resolved["aid"] or "(none)"
        gw = resolved["gateway"] or "(none)"
        trace = resolved.get("trace", "off")
        print(f"[aun-cli] profile={resolved['profile_name']} aid={aid} gateway={gw} trace={trace}")


from aun_cli.commands.identity import identity_app, register, login, whoami
from aun_cli.commands.message import send, pull, ack
from aun_cli.commands.group import group_app
from aun_cli.commands.listen import listen

app.add_typer(identity_app)
app.command("register")(register)
app.command("login")(login)
app.command("whoami")(whoami)
app.command("send")(send)
app.command("pull")(pull)
app.command("ack")(ack)
app.command("listen")(listen)

app.add_typer(group_app)

from aun_cli.commands.diag import status, ping, doctor, logs

app.command("status")(status)
app.command("ping")(ping)
app.command("doctor")(doctor)
app.command("logs")(logs)

from aun_cli.commands.config import config_app

app.add_typer(config_app)

from aun_cli.commands.storage import storage_app

app.add_typer(storage_app)

from aun_cli.commands.keys import keys_app

app.add_typer(keys_app)


@app.command("help", hidden=True)
def help_cmd(ctx: typer.Context, command: str = typer.Argument(None, help="命令名称")) -> None:
    """显示帮助信息"""
    if not command:
        print(ctx.parent.get_help())
        return

    # 查找顶层命令或子命令组
    parent = ctx.parent
    target = parent.command.get_command(parent, command)
    if target is None:
        from aun_cli.output import output_error
        output_error(f"Unknown command: {command}")
        raise typer.Exit(2)

    import click
    sub_ctx = click.Context(target, info_name=command, parent=parent)
    print(target.get_help(sub_ctx))
