from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error
from aun_cli.output import output_json, output_success, is_json_mode, set_json_mode

storage_app = typer.Typer(name="storage", help="对象存储", no_args_is_help=True)


@storage_app.command("upload")
def storage_upload(
    ctx: typer.Context,
    local_path: str = typer.Argument(..., help="本地文件路径"),
    name: Optional[str] = typer.Option(None, "--name", help="远程文件名（默认使用本地文件名）"),
) -> None:
    """上传文件"""
    set_json_mode(ctx.obj.get("json", False))
    file = Path(local_path)
    if not file.exists():
        from aun_cli.output import output_error
        output_error(f"File not found: {local_path}")
        raise typer.Exit(1)

    remote_name = name or file.name
    data = file.read_bytes()

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("storage.upload", {
                "name": remote_name,
                "data": base64.b64encode(data).decode("ascii"),
                "size": len(data),
            })

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        obj_id = result.get("object_id", result.get("id", ""))
        output_success(f"Uploaded: {remote_name} (id: {obj_id})")


@storage_app.command("download")
def storage_download(
    ctx: typer.Context,
    object_id: str = typer.Argument(..., help="对象 ID"),
    output_path: Optional[str] = typer.Option(None, "--output", "-o", help="保存路径"),
) -> None:
    """下载文件"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("storage.download", {"object_id": object_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
        return

    data_b64 = result.get("data", "")
    file_name = result.get("name", object_id)
    save_path = Path(output_path) if output_path else Path(file_name)
    save_path.write_bytes(base64.b64decode(data_b64))
    output_success(f"Downloaded: {save_path}")


@storage_app.command("delete")
def storage_delete(
    ctx: typer.Context,
    object_id: str = typer.Argument(..., help="对象 ID"),
) -> None:
    """删除文件"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("storage.delete", {"object_id": object_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Deleted: {object_id}")
