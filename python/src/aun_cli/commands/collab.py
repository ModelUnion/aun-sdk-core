from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any, Optional

import typer

from aun_cli.adapter import CLISession, handle_error, run_async
from aun_cli.output import is_json_mode, output_dict, output_error, output_json, output_success, output_table, set_json_mode
from aun_core.collab import CollabConflictError
from aun_core.errors import AUNError, NotFoundError as AUNNotFoundError, PermissionError as AUNPermissionError, ValidationError


collab_app = typer.Typer(name="collab", help="collab 协作层", no_args_is_help=True)
snapshot_app = typer.Typer(name="snapshot", help="collab 快照操作", no_args_is_help=True)
collab_app.add_typer(snapshot_app)

_REMOTE_RE = re.compile(r"^[^:/\\][^:]*:/")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _set_json(ctx: typer.Context) -> None:
    set_json_mode(bool(ctx.obj.get("json", False)))


def _is_aid_path(value: str) -> bool:
    text = str(value or "").strip()
    if _WINDOWS_DRIVE_RE.match(text):
        return False
    return bool(_REMOTE_RE.match(text))


def _source_value(source: str) -> str:
    if _is_aid_path(source):
        return source
    path = Path(source)
    if path.exists() and path.is_file():
        return base64.b64encode(path.read_bytes()).decode("ascii")
    try:
        base64.b64decode(source, validate=True)
        return source
    except Exception:
        return base64.b64encode(source.encode("utf-8")).decode("ascii")


def _decode_content(result: dict[str, Any]) -> bytes:
    return base64.b64decode(str(result.get("content") or ""))


def _print_result(result: Any) -> None:
    if is_json_mode():
        output_json(result)
    elif isinstance(result, list):
        if not result:
            output_table(["result"], [])
        else:
            keys = sorted({key for item in result if isinstance(item, dict) for key in item.keys()})
            output_table(keys, [[str(item.get(key, "")) for key in keys] for item in result])
    elif isinstance(result, dict):
        output_dict(result)
    else:
        output_success(str(result))


def _run_collab(ctx: typer.Context, coro):
    try:
        return run_async(coro)
    except CollabConflictError as exc:
        output_error(str(exc), hint=exc.hint, code=2)
        raise typer.Exit(2)
    except Exception as exc:
        if _is_collab_user_error(exc):
            output_error(str(exc), code=3)
            raise typer.Exit(3)
        handle_error(exc)
        return None


def _is_collab_user_error(exc: Exception) -> bool:
    if isinstance(exc, (AUNPermissionError, AUNNotFoundError, ValidationError)):
        return True
    if isinstance(exc, AUNError):
        return exc.code in {-32600, -32601, -32602, -32001, -32004, -32008, -32009, -32010, 4000, 403, 4030, 404, 4040}
    return False


@collab_app.command("ls")
def collab_ls(ctx: typer.Context, collab_root: str = typer.Argument(...)) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.ls(collab_root)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("create")
def collab_create(ctx: typer.Context, collab_root: str, doc: str, source: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.create(collab_root, doc, _source_value(source))

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("read")
def collab_read(ctx: typer.Context, collab_root: str, doc: str, output: Optional[str] = typer.Option(None, "--output", "-o")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.read(collab_root, doc)

    result = _run_collab(ctx, _run())
    if output:
        Path(output).write_bytes(_decode_content(result))
        output_success(f"Wrote: {output}")
    else:
        _print_result(result)


@collab_app.command("submit")
def collab_submit(
    ctx: typer.Context,
    collab_root: str,
    doc: str,
    source: str,
    base_version: int = typer.Option(..., "--base-version"),
    message: str = typer.Option("", "--message"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.submit(collab_root, doc, _source_value(source), base_version, message=message)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("merge")
def collab_merge(
    ctx: typer.Context,
    collab_root: str,
    doc: str,
    source: str,
    base_version: int = typer.Option(..., "--base-version"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.merge(collab_root, doc, _source_value(source), base_version)

    result = _run_collab(ctx, _run())
    if result is None:
        return
    if output:
        Path(output).write_bytes(_decode_content(result))
        output_success(f"Wrote: {output}")
    else:
        _print_result(result)
    if result.get("conflicts"):
        raise typer.Exit(1)


@collab_app.command("history")
def collab_history(ctx: typer.Context, collab_root: str, doc: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.history(collab_root, doc)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("get")
def collab_get(ctx: typer.Context, collab_root: str, doc: str, version: int = typer.Option(..., "--version"), output: Optional[str] = typer.Option(None, "--output", "-o")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.get(collab_root, doc, version)

    result = _run_collab(ctx, _run())
    if output:
        Path(output).write_bytes(_decode_content(result))
        output_success(f"Wrote: {output}")
    else:
        _print_result(result)


@collab_app.command("diff")
def collab_diff(ctx: typer.Context, collab_root: str, doc: str, v_from: int = typer.Option(..., "--from"), v_to: int = typer.Option(..., "--to")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.diff(collab_root, doc, v_from, v_to)

    result = _run_collab(ctx, _run())
    print(result.get("diff", "")) if not is_json_mode() else output_json(result)


@collab_app.command("export")
def collab_export(ctx: typer.Context, collab_root: str, dest: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.export(collab_root, dest)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("adopt")
def collab_adopt(ctx: typer.Context, src: str, new_root: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.adopt(src, new_root)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("prune")
def collab_prune(ctx: typer.Context, collab_root: str, doc: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.prune(collab_root, doc)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("reset")
def collab_reset(
    ctx: typer.Context,
    collab_root: str,
    doc: str,
    version: int = typer.Option(..., "--version"),
    message: str = typer.Option("", "--message"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.reset(collab_root, doc, version, message=message)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("gc")
def collab_gc(
    ctx: typer.Context,
    collab_root: str,
    dry_run: bool = typer.Option(True, "--dry-run/--apply", help="默认只预览；--apply 才实际清理"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.gc(collab_root, dry_run=dry_run)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("reflog")
def collab_reflog(
    ctx: typer.Context,
    collab_root: str,
    doc: Optional[str] = typer.Argument(None),
    limit: int = typer.Option(100, "--limit"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.reflog(collab_root, doc, limit=limit)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("discover")
def collab_discover(ctx: typer.Context, group_aid: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.discover(group_aid)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("unregister")
def collab_unregister(ctx: typer.Context, group_aid: str, collab_root: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.unregister(group_aid, collab_root)

    _print_result(_run_collab(ctx, _run()))


@snapshot_app.command("create")
def snapshot_create(ctx: typer.Context, collab_root: str, message: str = typer.Option("", "--message"), major: bool = typer.Option(False, "--major")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.snapshot.create(collab_root, message=message, major=major)

    _print_result(_run_collab(ctx, _run()))


@snapshot_app.command("list")
def snapshot_list(ctx: typer.Context, collab_root: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.snapshot.list(collab_root)

    _print_result(_run_collab(ctx, _run()))


@snapshot_app.command("show")
def snapshot_show(ctx: typer.Context, collab_root: str, version: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.snapshot.show(collab_root, version)

    _print_result(_run_collab(ctx, _run()))


@snapshot_app.command("diff")
def snapshot_diff(ctx: typer.Context, collab_root: str, version_a: str, version_b: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.snapshot.diff(collab_root, version_a, version_b)

    _print_result(_run_collab(ctx, _run()))


@snapshot_app.command("restore")
def snapshot_restore(ctx: typer.Context, collab_root: str, version: str, message: str = typer.Option("", "--message")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.snapshot.restore(collab_root, version, message=message)

    _print_result(_run_collab(ctx, _run()))


@snapshot_app.command("rm")
def snapshot_rm(ctx: typer.Context, collab_root: str, version: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.snapshot.rm(collab_root, version)

    _print_result(_run_collab(ctx, _run()))


@snapshot_app.command("prune")
def snapshot_prune(ctx: typer.Context, collab_root: str, before: Optional[str] = typer.Option(None, "--before"), keep_last: Optional[int] = typer.Option(None, "--keep-last")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.snapshot.prune(collab_root, before=before, keep_last=keep_last)

    _print_result(_run_collab(ctx, _run()))
