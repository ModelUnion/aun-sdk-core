from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error
from aun_cli.output import (
    output_json,
    output_success,
    output_error,
    is_json_mode,
    set_json_mode,
)
from aun_cli import storage_core

storage_app = typer.Typer(name="storage", help="对象存储", no_args_is_help=True)


def _resolve_verify_ssl() -> bool:
    from aun_core.config import resolve_verify_ssl_from_env

    return resolve_verify_ssl_from_env()


@storage_app.command("upload")
def storage_upload(
    ctx: typer.Context,
    local_path: str = typer.Argument(..., help="本地文件路径"),
    name: Optional[str] = typer.Option(None, "--name", help="远程对象 key（默认使用本地文件名）"),
    public: bool = typer.Option(False, "--public", help="公开可读（默认私有）"),
) -> None:
    """上传文件（小文件走 inline，大文件走上传会话 + HTTP PUT）"""
    set_json_mode(ctx.obj.get("json", False))
    file = Path(local_path)
    if not file.exists() or not file.is_file():
        output_error(f"File not found: {local_path}")
        raise typer.Exit(1)

    object_key = name or file.name
    data = file.read_bytes()
    content_type = storage_core.guess_content_type(file.name)

    async def _run():
        async with CLISession(ctx) as client:
            return await storage_core.upload_object(
                client, object_key=object_key, data=data,
                content_type=content_type, is_private=not public,
                verify_ssl=_resolve_verify_ssl(),
            )

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Uploaded: {result.get('object_key', object_key)} ({result.get('size_bytes', len(data))} bytes)")


@storage_app.command("download")
def storage_download(
    ctx: typer.Context,
    object_key: str = typer.Argument(..., help="对象 key"),
    output_path: Optional[str] = typer.Option(None, "--output", "-o", help="保存路径"),
) -> None:
    """下载文件（统一走下载 ticket + HTTP GET，兼容 inline 与历史 folder-path 对象）"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await storage_core.download_object(
                client, object_key=object_key, verify_ssl=_resolve_verify_ssl(),
            )

    try:
        ticket, data = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    file_name = ticket.get("file_name") or object_key.split("/")[-1]
    save_path = Path(output_path) if output_path else Path(file_name)
    save_path.write_bytes(data)

    if is_json_mode():
        output_json({
            "object_key": object_key,
            "saved_to": str(save_path),
            "size_bytes": len(data),
            "content_type": ticket.get("content_type", ""),
        })
    else:
        output_success(f"Downloaded: {save_path} ({len(data)} bytes)")


@storage_app.command("delete")
def storage_delete(
    ctx: typer.Context,
    object_key: str = typer.Argument(..., help="对象 key"),
) -> None:
    """删除文件"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await storage_core.delete_object(client, object_key=object_key)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Deleted: {object_key}")

