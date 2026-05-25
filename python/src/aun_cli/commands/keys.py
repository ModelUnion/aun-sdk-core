from __future__ import annotations

import typer

from aun_cli.adapter import CLISession, run_async, handle_error, resolve_profile_config
from aun_cli.output import output_json, output_success, output_table, is_json_mode, set_json_mode

keys_app = typer.Typer(name="keys", help="密钥管理", no_args_is_help=True)


@keys_app.command("list")
def keys_list(ctx: typer.Context) -> None:
    """列出本地密钥"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx, need_auth=False) as client:
            resolved = resolve_profile_config(ctx)
            aid = resolved["aid"]
            if not aid:
                raise typer.BadParameter("No AID configured in current profile")
            identity = client._keystore.load_identity(aid)
            keys_info: list[dict] = []
            if identity:
                if identity.get("private_key_pem"):
                    keys_info.append({
                        "type": "IK",
                        "id": aid,
                        "status": "active",
                    })
            prekeys = client._keystore.list_prekeys(aid) if hasattr(client._keystore, "list_prekeys") else []
            for pk in prekeys:
                keys_info.append({
                    "type": "SPK",
                    "id": pk.get("id", "?"),
                    "status": pk.get("status", "active"),
                })
            return keys_info

    try:
        keys_info = run_async(_run())
    except typer.BadParameter as e:
        from aun_cli.output import output_error
        output_error(str(e), code=2)
        raise typer.Exit(2)
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(keys_info)
    else:
        if not keys_info:
            print("  (no keys found)")
            return
        headers = ["TYPE", "ID", "STATUS"]
        rows = [[k["type"], k["id"], k["status"]] for k in keys_info]
        output_table(headers, rows)


@keys_app.command("rotate")
def keys_rotate(
    ctx: typer.Context,
    key_type: str = typer.Option("spk", "--type", help="密钥类型: spk | ik"),
) -> None:
    """轮换密钥"""
    set_json_mode(ctx.obj.get("json", False))

    if key_type not in ("spk", "ik"):
        from aun_cli.output import output_error
        output_error(f"Unknown key type: {key_type}. Use 'spk' or 'ik'.")
        raise typer.Exit(2)

    async def _run():
        async with CLISession(ctx) as client:
            if key_type == "spk":
                return await client.call("auth.rotate_spk", {})
            else:
                return await client.call("auth.rekey", {})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Rotated {key_type.upper()} successfully")
