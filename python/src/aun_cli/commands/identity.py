from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error, resolve_profile_config
from aun_cli.config import set_profile
from aun_cli.output import output_dict, output_success, output_json, output_table, is_json_mode, set_json_mode

identity_app = typer.Typer(name="identity", help="身份管理", no_args_is_help=True)


@identity_app.command("list")
def identity_list(ctx: typer.Context) -> None:
    """列出本地所有身份"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx, need_auth=False) as client:
            return client.list_identities()

    try:
        identities = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(identities)
    else:
        if not identities:
            print("  (no identities found)")
            return
        headers = ["AID"]
        rows = [[i["aid"]] for i in identities]
        output_table(headers, rows)


def register(
    ctx: typer.Context,
    aid: str = typer.Argument(..., help="要注册的 AID (如 alice@aid.com)"),
    gateway: str = typer.Option(..., "--gateway", "-g", help="网关地址"),
) -> None:
    """注册新 AID"""
    set_json_mode(ctx.obj.get("json", False))
    profile_name = ctx.obj.get("profile", "default")

    async def _run():
        from aun_core import AUNClient
        aun_path = str(Path.home() / ".aun" / "profiles" / profile_name)
        client = AUNClient(config={"aun_path": aun_path}, debug=ctx.obj.get("debug", False))
        try:
            result = await client.auth.create_aid({"aid": aid, "gateway": gateway})
            return result
        finally:
            await client.close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    aun_path = str(Path.home() / ".aun" / "profiles" / profile_name)
    set_profile(profile_name, {"aid": aid, "gateway": gateway, "aun_path": aun_path})

    if is_json_mode():
        output_json({"status": "registered", "aid": aid, "profile": profile_name})
    else:
        output_success(f"Registered: {aid} (profile: {profile_name})")


def login(
    ctx: typer.Context,
    aid: Optional[str] = typer.Argument(None, help="要登录的 AID（默认使用 profile 中的 AID）"),
) -> None:
    """登录已有 AID（验证密钥可用，刷新 token）"""
    set_json_mode(ctx.obj.get("json", False))

    if aid:
        ctx.obj["_override_aid"] = aid

    async def _run():
        resolved = resolve_profile_config(ctx)
        login_aid = aid or resolved["aid"]
        if not login_aid:
            raise typer.BadParameter("No AID specified and no default AID in profile")
        async with CLISession(ctx) as client:
            return {"aid": client.aid, "state": client.state}

    try:
        result = run_async(_run())
    except typer.BadParameter as e:
        from aun_cli.output import output_error
        output_error(str(e), code=2)
        raise typer.Exit(2)
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json({"status": "authenticated", "aid": result["aid"]})
    else:
        output_success(f"Authenticated: {result['aid']}")


def whoami(ctx: typer.Context) -> None:
    """显示当前身份信息"""
    set_json_mode(ctx.obj.get("json", False))
    resolved = resolve_profile_config(ctx)

    info = {
        "AID": resolved["aid"] or "(not set)",
        "Profile": resolved["profile_name"],
        "Gateway": resolved["gateway"] or "(not set)",
        "Data Path": resolved["aun_path"],
    }

    if is_json_mode():
        output_json(info)
    else:
        output_dict(info)
