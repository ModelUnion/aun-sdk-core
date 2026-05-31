from __future__ import annotations

from pathlib import Path

import typer

from aun_cli.adapter import run_async, handle_error, resolve_profile_config, make_aid_store
from aun_cli.output import output_json, output_success, output_table, is_json_mode, set_json_mode

keys_app = typer.Typer(name="keys", help="密钥管理", no_args_is_help=True)


@keys_app.command("list")
def keys_list(ctx: typer.Context) -> None:
    """列出本地密钥"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        resolved = resolve_profile_config(ctx)
        aid = resolved["aid"]
        if not aid:
            raise typer.BadParameter("No AID configured in current profile")
        store = make_aid_store(resolved)
        try:
            loaded = store.load(aid)
            keys_info: list[dict] = []
            if loaded.ok and loaded.data and loaded.data["aid"].is_private_key_valid():
                keys_info.append({
                    "type": "IK",
                    "id": aid,
                    "status": "active",
                })
            return keys_info
        finally:
            store.close()

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


@keys_app.command("change-seed")
def keys_change_seed(
    ctx: typer.Context,
    old_seed: str = typer.Option(".seed", "--old-seed", help="旧 seed_password；'.seed' 表示读取数据目录下的 .seed"),
    new_seed: str = typer.Option(..., "--new-seed", help="新的 seed_password（空字符串有效）"),
    aun_path: str | None = typer.Option(None, "--aun-path", help="AUN 数据目录；默认使用当前 profile"),
) -> None:
    """迁移本地 seed 加密材料"""
    set_json_mode(ctx.obj.get("json", False))
    from aun_cli.output import output_error
    from aun_core.keystore.seed_migration import SeedMigrationError, change_seed

    resolved = resolve_profile_config(ctx)
    root = Path(aun_path or resolved["aun_path"]).expanduser()
    try:
        result = change_seed(root, old_seed, new_seed)
    except SeedMigrationError as exc:
        output_error(str(exc), code=1)
        raise typer.Exit(1)
    except Exception as exc:
        output_error(f"seed migration failed: {exc}", code=1)
        raise typer.Exit(1)

    payload = {
        "aun_path": str(root),
        "migrated": result.migrated,
        "skipped": result.skipped,
        "private_keys_migrated": result.private_keys_migrated,
        "seed_files_renamed": result.seed_files_renamed,
    }
    if is_json_mode():
        output_json(payload)
    else:
        output_success(
            "Seed changed: migrated={migrated} skipped={skipped} private_keys={private_keys_migrated} renamed={seed_files_renamed}".format(
                **payload
            )
        )
