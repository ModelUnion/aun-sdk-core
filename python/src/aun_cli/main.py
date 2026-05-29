from __future__ import annotations

from typing import Optional

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
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="仅本次命令使用指定 profile"),
    json_output: bool = typer.Option(False, "--json", help="JSON 格式输出"),
    debug: bool = typer.Option(False, "--debug", help="启用 debug 日志"),
    no_color: bool = typer.Option(False, "--no-color", help="禁用彩色输出"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="操作超时秒数"),
    version: bool = typer.Option(False, "--version", "-V", callback=version_callback, is_eager=True),
) -> None:
    """全局选项"""
    ctx.ensure_object(dict)
    ctx.obj["profile"] = profile
    ctx.obj["json"] = json_output
    ctx.obj["debug"] = debug
    ctx.obj["no_color"] = no_color
    ctx.obj["timeout"] = timeout
    from aun_cli.adapter import finish_cli_invocation, start_cli_invocation
    start_cli_invocation(json_mode=json_output)
    ctx.call_on_close(finish_cli_invocation)

    # 输出 banner（JSON 模式下静默）
    if not json_output:
        from aun_cli.adapter import resolve_profile_config
        resolved = resolve_profile_config(ctx)
        aid = resolved["aid"] or "(none)"
        trace = resolved.get("trace", "off")
        active_group = resolved.get("active_group") or "(none)"
        print(f"[aun-cli] profile={resolved['profile_name']} aid={aid} active_group={active_group} trace={trace}")


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

from aun_cli.commands.config import config_app, profile_app

app.add_typer(config_app)
app.add_typer(profile_app)

from aun_cli.commands.storage import storage_app

app.add_typer(storage_app)

from aun_cli.commands.agentmd import agentmd_app

app.add_typer(agentmd_app)

from aun_cli.commands.keys import keys_app

app.add_typer(keys_app)

from aun_cli.commands.bench import bench_app

app.add_typer(bench_app)


@app.command("help", hidden=True)
def help_cmd(ctx: typer.Context, commands: list[str] = typer.Argument(None, help="命令路径，如 group create")) -> None:
    """显示帮助信息"""
    parent = ctx.parent
    if not commands:
        print(parent.get_help())
        return

    import click

    current_ctx = parent
    current_command = parent.command
    for command_name in commands:
        if not isinstance(current_command, click.Group):
            from aun_cli.output import output_error
            output_error(f"Command '{current_ctx.info_name}' has no subcommands")
            raise typer.Exit(2)
        target = current_command.get_command(current_ctx, command_name)
        if target is None:
            from aun_cli.output import output_error
            output_error(f"Unknown command: {' '.join(commands)}")
            raise typer.Exit(2)
        current_ctx = click.Context(target, info_name=command_name, parent=current_ctx)
        current_command = target

    print(current_command.get_help(current_ctx))
