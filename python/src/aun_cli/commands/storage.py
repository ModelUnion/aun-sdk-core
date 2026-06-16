from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error
from aun_cli.output import (
    output_json,
    output_success,
    output_error,
    output_dict,
    output_table,
    is_json_mode,
    set_json_mode,
)
from aun_cli import storage_core

storage_app = typer.Typer(name="storage", help="对象存储", no_args_is_help=True)


def _resolve_verify_ssl() -> bool:
    from aun_core.config import resolve_verify_ssl_from_env

    return resolve_verify_ssl_from_env()


def _normalize_object_key(value: str) -> str:
    return str(value or "").strip().replace("\\", "/").lstrip("/")


@storage_app.command("list")
@storage_app.command("ls")
def storage_list(
    ctx: typer.Context,
    prefix: str = typer.Argument("", help="对象 key 前缀"),
    page: int = typer.Option(1, "--page", help="页码"),
    size: int = typer.Option(100, "--size", help="每页数量"),
    marker: Optional[str] = typer.Option(None, "--marker", help="分页游标"),
    include_prefixes: bool = typer.Option(True, "--prefixes/--no-prefixes", help="同时列出直接子前缀"),
) -> None:
    """列出当前身份的对象"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_prefix = _normalize_object_key(prefix)

    async def _run():
        async with CLISession(ctx) as client:
            params = {"prefix": resolved_prefix, "page": page, "size": size}
            if marker is not None:
                params["marker"] = marker
            objects = await client.call("storage.list_objects", params)
            prefixes = {}
            if include_prefixes:
                prefixes = await client.call("storage.list_prefixes", {"prefix": resolved_prefix, "size": size})
            return {"prefix": resolved_prefix, "objects": objects or {}, "prefixes": prefixes or {}}

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
        return

    rows = []
    for item in (result.get("prefixes") or {}).get("prefixes", []) or []:
        rows.append(["prefix", str(item), "-", "-", "-"])
    for item in (result.get("objects") or {}).get("items", []) or []:
        if not isinstance(item, dict):
            continue
        rows.append([
            "object",
            item.get("object_key") or item.get("path") or item.get("name") or "",
            str(item.get("size_bytes") or item.get("size") or 0),
            item.get("content_type", ""),
            str(item.get("updated_at") or item.get("mtime") or ""),
        ])
    output_table(["type", "key", "size", "content_type", "updated_at"], rows)


@storage_app.command("info")
def storage_info(
    ctx: typer.Context,
    object_key: str = typer.Argument(..., help="对象 key"),
) -> None:
    """查看对象元信息"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_key = _normalize_object_key(object_key)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("storage.head_object", {"object_key": resolved_key})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    output_json(result) if is_json_mode() else output_dict(result)


@storage_app.command("upload")
def storage_upload(
    ctx: typer.Context,
    local_path: str = typer.Argument(..., help="本地文件路径"),
    name: Optional[str] = typer.Option(None, "--name", help="远程对象 key（默认使用本地文件名）"),
    public: bool = typer.Option(False, "--public", help="公开可读（默认私有）"),
    force: bool = typer.Option(False, "--force", help="覆盖已存在对象"),
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
                verify_ssl=_resolve_verify_ssl(), overwrite=force,
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
    force: bool = typer.Option(False, "--force", help="覆盖已存在本地文件"),
) -> None:
    """下载文件（统一走下载 ticket + HTTP GET，兼容 inline 与历史 folder-path 对象）"""
    set_json_mode(ctx.obj.get("json", False))
    if output_path and Path(output_path).exists() and not force:
        output_error(f"本地文件已存在: {output_path}，使用 --force 覆盖")
        raise typer.Exit(1)

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
    if save_path.exists() and not force:
        output_error(f"本地文件已存在: {save_path}，使用 --force 覆盖")
        raise typer.Exit(1)
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
