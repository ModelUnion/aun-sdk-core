from __future__ import annotations

import typer

from aun_cli.adapter import CLISession, handle_error, resolve_profile_config, run_async, make_aid_store
from aun_cli.output import output_dict, output_json, output_success, is_json_mode, set_json_mode

agentmd_app = typer.Typer(name="agentmd", help="agent.md 管理", no_args_is_help=True)
DEFAULT_CHECK_MAX_UNSYNCED_DAYS = 1.0


def _print_result(result: dict) -> None:
    if is_json_mode():
        output_json(result)
    else:
        output_dict({str(k): v for k, v in result.items() if k != "content"})


def _unwrap_result(result, action: str) -> dict:
    if result.ok and result.data is not None:
        return result.data
    message = result.error.message if result.error else f"{action} failed"
    raise RuntimeError(message)


@agentmd_app.command("upload")
@agentmd_app.command("upload_agent_md")
def agentmd_upload(ctx: typer.Context) -> None:
    """签名并上传当前 AID 的 agent.md"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx, need_auth=True) as client:
            return await client.upload_agent_md()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        aid = result.get("aid", "")
        etag = result.get("etag", "")
        url = result.get("agent_md_url", "")
        output_success(f"Uploaded agent.md: aid={aid} etag={etag} url={url}")


@agentmd_app.command("download")
@agentmd_app.command("download_agent_md")
def agentmd_download(
    ctx: typer.Context,
    aid: str | None = typer.Argument(None, help="要下载的 AID；省略时使用当前 profile AID"),
) -> None:
    """下载、验签并保存 agent.md"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        resolved = resolve_profile_config(ctx)
        target = aid or resolved.get("aid")
        if not target:
            raise RuntimeError("download agent.md requires aid or profile aid")
        store = make_aid_store(resolved)
        try:
            return _unwrap_result(await store.download_agent_md(target), "download agent.md")
        finally:
            store.close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    _print_result(result)


@agentmd_app.command("check")
@agentmd_app.command("check_agent_md")
def agentmd_check(
    ctx: typer.Context,
    aid: str | None = typer.Argument(None, help="要检查的 AID；省略时使用当前 profile AID"),
    max_unsynced_days: float = typer.Option(
        DEFAULT_CHECK_MAX_UNSYNCED_DAYS,
        "--max-unsynced-days",
        help="缓存窗口天数；0 表示强制 HEAD",
    ),
) -> None:
    """检查本地 agent.md 与远端版本是否一致"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        resolved = resolve_profile_config(ctx)
        target = aid or resolved.get("aid")
        if not target:
            raise RuntimeError("check agent.md requires aid or profile aid")
        store = make_aid_store(resolved)
        try:
            ttl_days = max(0, int(max_unsynced_days))
            return _unwrap_result(await store.check_agent_md(target, ttl_days=ttl_days), "check agent.md")
        finally:
            store.close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    _print_result(result)
