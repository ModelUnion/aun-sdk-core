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


collab_app = typer.Typer(name="collab", help="collab 协作层（Git 命令子集）", no_args_is_help=True)
tag_app = typer.Typer(name="tag", help="collab 目录级标签（带内容快照）", no_args_is_help=True)
collab_app.add_typer(tag_app)

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

# APPEND_MARKER


@collab_app.command("ls-files")
def collab_ls_files(ctx: typer.Context, collab_root: str = typer.Argument(...)) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.ls_files(collab_root)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("create")
def collab_create(ctx: typer.Context, collab_root: str, doc: str, source: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.create(collab_root, doc, _source_value(source))

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("show")
def collab_show(
    ctx: typer.Context,
    collab_root: str,
    doc: str,
    rev: Optional[int] = typer.Option(None, "--rev", help="指定历史版本号；省略则读当前版本"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.show(collab_root, doc, rev)

    result = _run_collab(ctx, _run())
    if output:
        Path(output).write_bytes(_decode_content(result))
        output_success(f"Wrote: {output}")
    else:
        _print_result(result)


@collab_app.command("commit")
def collab_commit(
    ctx: typer.Context,
    collab_root: str,
    doc: str,
    source: str,
    onto: int = typer.Option(..., "--onto", help="基线版本号（来自 show 响应的 version 字段）"),
    message: str = typer.Option("", "--message"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.commit(collab_root, doc, _source_value(source), onto, message=message)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("merge")
def collab_merge(
    ctx: typer.Context,
    collab_root: str,
    doc: str,
    source: str,
    onto: int = typer.Option(..., "--onto", help="基线版本号（来自 commit 失败响应的 currentVersion）"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.merge(collab_root, doc, _source_value(source), onto)

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


@collab_app.command("log")
def collab_log(ctx: typer.Context, collab_root: str, doc: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.log(collab_root, doc)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("diff")
def collab_diff(ctx: typer.Context, collab_root: str, doc: str, v_from: int = typer.Option(..., "--from"), v_to: int = typer.Option(..., "--to")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.diff(collab_root, doc, v_from, v_to)

    result = _run_collab(ctx, _run())
    print(result.get("diff", "")) if not is_json_mode() else output_json(result)


@collab_app.command("clone")
def collab_clone(
    ctx: typer.Context,
    src: str,
    dest: str,
    reroot: bool = typer.Option(False, "--reroot", help="换 host 重建并转移授权方（原 adopt）；默认纯子树拷贝"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.clone(src, dest, reroot=reroot)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("prune")
def collab_prune(ctx: typer.Context, collab_root: str, doc: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.prune(collab_root, doc)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("revert")
def collab_revert(
    ctx: typer.Context,
    collab_root: str,
    doc: str,
    rev: int = typer.Option(..., "--rev", help="要回退到的版本号"),
    message: str = typer.Option("", "--message"),
) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.revert(collab_root, doc, rev, message=message)

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


@collab_app.command("ls-remote")
def collab_ls_remote(ctx: typer.Context, group_aid: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.ls_remote(group_aid)

    _print_result(_run_collab(ctx, _run()))


@collab_app.command("unregister")
def collab_unregister(ctx: typer.Context, group_aid: str, collab_root: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.unregister(group_aid, collab_root)

    _print_result(_run_collab(ctx, _run()))


@tag_app.command("create")
def tag_create(ctx: typer.Context, collab_root: str, message: str = typer.Option("", "--message"), major: bool = typer.Option(False, "--major")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.tag.create(collab_root, message=message, major=major)

    _print_result(_run_collab(ctx, _run()))


@tag_app.command("list")
def tag_list(ctx: typer.Context, collab_root: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.tag.list(collab_root)

    _print_result(_run_collab(ctx, _run()))


@tag_app.command("show")
def tag_show(ctx: typer.Context, collab_root: str, version: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.tag.show(collab_root, version)

    _print_result(_run_collab(ctx, _run()))


@tag_app.command("diff")
def tag_diff(ctx: typer.Context, collab_root: str, version_a: str, version_b: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.tag.diff(collab_root, version_a, version_b)

    _print_result(_run_collab(ctx, _run()))


@tag_app.command("restore")
def tag_restore(ctx: typer.Context, collab_root: str, version: str, message: str = typer.Option("", "--message")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.tag.restore(collab_root, version, message=message)

    _print_result(_run_collab(ctx, _run()))


@tag_app.command("rm")
def tag_rm(ctx: typer.Context, collab_root: str, version: str) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.tag.rm(collab_root, version)

    _print_result(_run_collab(ctx, _run()))


@tag_app.command("prune")
def tag_prune(ctx: typer.Context, collab_root: str, before: Optional[str] = typer.Option(None, "--before"), keep_last: Optional[int] = typer.Option(None, "--keep-last")) -> None:
    _set_json(ctx)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.collab.tag.prune(collab_root, before=before, keep_last=keep_last)

    _print_result(_run_collab(ctx, _run()))
