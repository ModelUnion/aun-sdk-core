from __future__ import annotations

import base64
import fnmatch
import time
from datetime import datetime, time as datetime_time, timezone
from pathlib import Path
from typing import Any, Optional

import typer

from aun_cli.adapter import CLISession, handle_error, run_async
from aun_cli.fs_utils import format_remote, is_remote, normalize_path, parse_remote
from aun_cli.output import is_json_mode, output_dict, output_error, output_json, output_success, output_table, set_json_mode
from aun_core.storage.types import to_plain


fs_app = typer.Typer(name="fs", help="类 POSIX 文件系统操作", no_args_is_help=True)
token_app = typer.Typer(name="token", help="访问令牌管理", no_args_is_help=True)


def _json_ready(value: Any) -> Any:
    return to_plain(value)


def _set_json(ctx: typer.Context) -> None:
    set_json_mode(bool(ctx.obj.get("json", False)))


def _remote_or_exit(value: str) -> tuple[str, str]:
    try:
        return parse_remote(value)
    except ValueError as exc:
        output_error(str(exc))
        raise typer.Exit(2)


def _is_text(content_type: str, data: bytes) -> bool:
    lowered = (content_type or "").lower()
    if lowered.startswith("text/") or lowered in {"application/json", "application/xml"}:
        return True
    return b"\0" not in data[:256]


def _content_type_is_text(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return lowered.startswith("text/") or lowered in {"application/json", "application/xml"}


def _link_target_value(target: str, *, link_owner: str) -> str:
    if is_remote(target):
        target_owner, target_path = parse_remote(target)
        if target_owner == link_owner:
            return target_path
        return format_remote(target_owner, target_path)
    if str(target or "").startswith(("/", "\\")):
        return normalize_path(target)
    return str(target or "").strip().replace("\\", "/")


def _parse_expires(value: Optional[str]) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    raw = str(value).strip()
    if raw.isdigit():
        return int(raw)
    try:
        if "T" in raw:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            dt = datetime.combine(datetime.fromisoformat(raw).date(), datetime_time.min, tzinfo=timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception as exc:
        raise ValueError(f"expires 格式不合法: {value}") from exc


def _parse_acl_spec(value: str, *, require_perms: bool) -> tuple[str, Optional[str]]:
    parts = str(value or "").split(":")
    if len(parts) < 2 or parts[0] != "aid" or not parts[1]:
        raise ValueError("ACL 条目格式应为 aid:<AID>:<perms> 或 aid:<AID>")
    if require_perms:
        if len(parts) != 3 or not parts[2]:
            raise ValueError("setfacl -m 格式应为 aid:<AID>:<perms>")
        return parts[1], parts[2]
    if len(parts) != 2:
        raise ValueError("setfacl -x 格式应为 aid:<AID>")
    return parts[1], None


def _match_type(node: dict[str, Any], expected: Optional[str]) -> bool:
    if not expected:
        return True
    mapping = {"f": "file", "d": "dir", "l": "symlink"}
    return str(node.get("type") or "") == mapping.get(expected, expected)


def _match_size(node: dict[str, Any], expr: Optional[str]) -> bool:
    if not expr:
        return True
    raw = str(expr).strip()
    op = raw[0] if raw[:1] in {"+", "-"} else ""
    number = raw[1:] if op else raw
    try:
        threshold = int(number)
    except ValueError as exc:
        raise ValueError("--size 格式应为 N、+N 或 -N") from exc
    size = int(node.get("size") or 0)
    if op == "+":
        return size > threshold
    if op == "-":
        return size < threshold
    return size == threshold


def _match_mtime(node: dict[str, Any], expr: Optional[str]) -> bool:
    if not expr:
        return True
    raw = str(expr).strip()
    op = raw[0] if raw[:1] in {"+", "-"} else ""
    number = raw[1:] if op else raw
    try:
        days = int(number)
    except ValueError as exc:
        raise ValueError("--mtime 格式应为 N、+N 或 -N，单位为天") from exc
    mtime = int(node.get("mtime") or 0)
    age_days = int(max(0, time.time() - mtime) // 86400)
    if op == "+":
        return age_days > days
    if op == "-":
        return age_days < days
    return age_days == days


def _filter_find_nodes(nodes: list[Any], *, name: Optional[str], node_type: Optional[str], size: Optional[str], mtime: Optional[str]) -> list[dict[str, Any]]:
    result = []
    for item in nodes:
        node = _json_ready(item)
        node_name = str(node.get("name") or "")
        if name and not fnmatch.fnmatchcase(node_name, name):
            continue
        if not _match_type(node, node_type):
            continue
        if not _match_size(node, size):
            continue
        if not _match_mtime(node, mtime):
            continue
        result.append(node)
    return result


def _print_node_table(nodes: list[Any], *, long: bool = False) -> None:
    rows = []
    for item in nodes:
        node = _json_ready(item)
        name = node.get("name", "")
        if node.get("type") == "symlink" and node.get("target"):
            name = f"{name} -> {node.get('target')}"
        if long:
            rows.append([
                node.get("type", ""),
                node.get("mode", "") or "-",
                node.get("owner", ""),
                str(node.get("size", 0) if node.get("type") == "file" else "-"),
                str(node.get("mtime", 0) or "-"),
                name,
            ])
        else:
            rows.append([node.get("type", ""), name])
    output_table(
        ["type", "mode", "owner", "size", "mtime", "name"] if long else ["type", "name"],
        rows,
    )


@fs_app.command("ls")
def fs_ls(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径，形如 aid:/path"),
    long: bool = typer.Option(False, "--long", "-l", help="显示长格式"),
    page: int = typer.Option(1, "--page", help="页码"),
    size: int = typer.Option(100, "--size", help="每页数量"),
    marker: Optional[str] = typer.Option(None, "--marker", help="分页游标"),
    token: Optional[str] = typer.Option(None, "--token", help="访问令牌"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            kwargs = {"owner": owner, "page": page, "size": size, "marker": marker, "long": long}
            if token is not None:
                kwargs["token"] = token
            return await client.storage.list(remote_path, **kwargs)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    if is_json_mode():
        output_json(_json_ready(result))
    else:
        _print_node_table(result, long=long)


@fs_app.command("stat")
def fs_stat(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径"),
    follow: bool = typer.Option(False, "-L", "--follow", help="跟随链接"),
    token: Optional[str] = typer.Option(None, "--token", help="访问令牌"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            if follow:
                return await client.storage.stat(remote_path, owner=owner, token=token)
            return await client.storage.lstat(remote_path, owner=owner, token=token)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    data = _json_ready(result)
    output_json(data) if is_json_mode() else output_dict(data)


@fs_app.command("cat")
def fs_cat(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程文件路径"),
    head_bytes: int = typer.Option(256, "--head-bytes", help="二进制输出头部字节数"),
    token: Optional[str] = typer.Option(None, "--token", help="访问令牌"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            node = await client.storage.stat(remote_path, owner=owner, token=token)
            node_dict = _json_ready(node)
            content_type = str(node_dict.get("content_type") or "")
            if _content_type_is_text(content_type):
                data = await client.storage.read_bytes(remote_path, owner=owner, token=token)
                return node, data, False
            head = await client.storage.read_bytes(
                remote_path,
                owner=owner,
                token=token,
                offset=0,
                limit=max(0, head_bytes),
            )
            if _is_text(content_type, head):
                data = await client.storage.read_bytes(remote_path, owner=owner, token=token)
                return node, data, False
            return node, head, True

    try:
        node, data, binary_head_only = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    node_dict = _json_ready(node)
    content_type = str(node_dict.get("content_type") or "")
    if not binary_head_only and _is_text(content_type, data):
        text = data.decode("utf-8", errors="replace")
        if is_json_mode():
            output_json({"path": format_remote(owner, remote_path), "content_type": content_type, "content": text})
        else:
            typer.echo(text)
        return
    head = data[: max(0, head_bytes)]
    size = int(node_dict.get("size") or node_dict.get("size_bytes") or len(data))
    payload = {
        "path": format_remote(owner, remote_path),
        "size": size,
        "content_type": content_type,
        "binary": True,
        "head": {"encoding": "base64", "bytes": len(head), "data": base64.b64encode(head).decode("ascii")},
    }
    output_json(payload) if is_json_mode() else output_dict(payload)


@fs_app.command("cp")
def fs_cp(
    ctx: typer.Context,
    src: str = typer.Argument(..., help="源路径，本地或远程"),
    dst: str = typer.Argument(..., help="目标路径，本地或远程"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="递归复制目录"),
    public: bool = typer.Option(False, "--public", help="上传后公开可读"),
    content_type: Optional[str] = typer.Option(None, "--content-type", help="上传内容类型"),
    force: bool = typer.Option(False, "--force", help="覆盖目标"),
    token: Optional[str] = typer.Option(None, "--token", help="访问令牌"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    src_remote = is_remote(src)
    dst_remote = is_remote(dst)
    if not src_remote and not dst_remote:
        output_error("本地到本地复制请使用系统 cp/copy")
        raise typer.Exit(2)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            if not src_remote and dst_remote:
                owner, remote_path = parse_remote(dst)
                return await client.storage.upload_file(
                    src,
                    remote_path,
                    owner=owner,
                    content_type=content_type,
                    public=public,
                    overwrite=force,
                )
            if src_remote and not dst_remote:
                owner, remote_path = parse_remote(src)
                return await client.storage.download_file(remote_path, dst, owner=owner, token=token)
            src_owner, src_path = parse_remote(src)
            dst_owner, dst_path = parse_remote(dst)
            return await client.storage.copy(
                src_path,
                dst_path,
                owner=src_owner,
                dst_owner=dst_owner if dst_owner != src_owner else None,
                overwrite=force,
                recursive=recursive,
            )

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    if is_json_mode():
        output_json(_json_ready(result))
    else:
        output_success("cp 完成")


@fs_app.command("mv")
def fs_mv(
    ctx: typer.Context,
    src: str = typer.Argument(..., help="源远程路径"),
    dst: str = typer.Argument(..., help="目标远程路径"),
    force: bool = typer.Option(False, "--force", help="覆盖目标"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    src_owner, src_path = _remote_or_exit(src)
    dst_owner, dst_path = _remote_or_exit(dst)
    if src_owner != dst_owner:
        output_error("跨 AID mv 不具备原子性，请使用 cp 后 rm")
        raise typer.Exit(2)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.rename(src_path, dst_path, owner=src_owner, overwrite=force)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("mv 完成")


@fs_app.command("rm")
def fs_rm(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="递归删除"),
    force: bool = typer.Option(False, "--force", help="忽略交互确认"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)
    _ = force

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.remove(remote_path, owner=owner, recursive=recursive)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("rm 完成")


@fs_app.command("ln")
def fs_ln(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="软链目标"),
    link_path: str = typer.Argument(..., help="软链路径"),
    symbolic: bool = typer.Option(False, "--symbolic", "-s", help="创建符号链接"),
    force: bool = typer.Option(False, "--force", "-f", help="原子重指已有软链"),
    expected_version: Optional[int] = typer.Option(None, "--expected-version", help="CAS 期望版本"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    if not symbolic:
        output_error("当前仅支持 ln -s")
        raise typer.Exit(2)
    owner, remote_link = _remote_or_exit(link_path)
    link_target = _link_target_value(target, link_owner=owner)
    if not link_target:
        output_error("软链目标不能为空")
        raise typer.Exit(2)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            if force:
                return await client.storage.repoint(
                    remote_link,
                    link_target,
                    owner=owner,
                    expected_version=expected_version,
                )
            return await client.storage.symlink(link_target, remote_link, owner=owner, overwrite=False)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("ln 完成")


@fs_app.command("mkdir")
def fs_mkdir(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程目录路径"),
    parents: bool = typer.Option(False, "--parents", "-p", help="逐级创建父目录"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.mkdir(remote_path, owner=owner, parents=parents)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("mkdir 完成")


@fs_app.command("df")
def fs_df(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="远程主体，形如 aid:"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, _ = _remote_or_exit(target)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.df(owner=owner)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    data = _json_ready(result)
    output_json(data) if is_json_mode() else output_dict(data)


@fs_app.command("mount")
def fs_mount(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="远程挂载点，形如 aid:/mount/path"),
    source: Optional[str] = typer.Option(None, "--source", help="源路径，形如 aid:/source/path"),
    volume: Optional[str] = typer.Option(None, "--volume", help="卷 ID"),
    readonly: bool = typer.Option(True, "--readonly/--readwrite", help="只读或读写挂载"),
    require_approval: bool = typer.Option(False, "--require-approval", help="创建 pending 挂载，等待源 owner 审批"),
    expires: Optional[str] = typer.Option(None, "--expires", help="过期时间，Unix 秒或 ISO 日期"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(target)
    if bool(source) == bool(volume):
        output_error("mount 必须且只能指定 --source 或 --volume")
        raise typer.Exit(2)
    source_ref = ""
    if source:
        source_owner, source_path = _remote_or_exit(source or "")
        source_ref = format_remote(source_owner, source_path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            if volume:
                return await client.storage.mount_volume(
                    volume,
                    remote_path,
                    owner=owner,
                    readonly=readonly,
                    require_approval=require_approval,
                    expires_at=_parse_expires(expires),
                )
            return await client.storage.mount(
                source_ref,
                remote_path,
                owner=owner,
                readonly=readonly,
                require_approval=require_approval,
                expires_at=_parse_expires(expires),
            )

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("mount 完成")


@fs_app.command("approve")
def fs_approve(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="远程挂载点，形如 aid:/mount/path"),
    request_id: Optional[str] = typer.Option(None, "--request-id", help="待审批挂载请求 ID"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(target)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            kwargs: dict[str, Any] = {"owner": owner}
            if request_id is not None:
                kwargs["request_id"] = request_id
            return await client.storage.approve_mount(remote_path, **kwargs)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("approve 完成")


@fs_app.command("reject")
def fs_reject(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="远程挂载点，形如 aid:/mount/path"),
    request_id: Optional[str] = typer.Option(None, "--request-id", help="待审批挂载请求 ID"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(target)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            kwargs: dict[str, Any] = {"owner": owner}
            if request_id is not None:
                kwargs["request_id"] = request_id
            return await client.storage.reject_mount(remote_path, **kwargs)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("reject 完成")


@fs_app.command("umount")
def fs_umount(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="远程挂载点，形如 aid:/mount/path"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(target)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.unmount(remote_path, owner=owner)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("umount 完成")


@fs_app.command("find")
def fs_find(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程目录路径"),
    name: Optional[str] = typer.Option(None, "--name", help="按文件名 glob 过滤"),
    node_type: Optional[str] = typer.Option(None, "--type", help="类型：f、d、l"),
    size_expr: Optional[str] = typer.Option(None, "--size", help="大小过滤：N、+N、-N"),
    mtime_expr: Optional[str] = typer.Option(None, "--mtime", help="mtime 天数过滤：N、+N、-N"),
    page_size: int = typer.Option(1000, "--page-size", help="递归 list 每页大小"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)
    if node_type and node_type not in {"f", "d", "l", "file", "dir", "symlink"}:
        output_error("--type 仅支持 f、d、l")
        raise typer.Exit(2)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            nodes = await client.storage.find(
                remote_path,
                owner=owner,
                name=name,
                node_type=node_type,
                size=size_expr,
                mtime=mtime_expr,
                page_size=page_size,
            )
            return [_json_ready(item) for item in nodes]

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    if is_json_mode():
        output_json(result)
    else:
        for item in result:
            typer.echo(format_remote(owner, str(item.get("path") or "")))


@fs_app.command("chmod")
def fs_chmod(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径或 chmod 模式"),
    maybe_path: Optional[str] = typer.Argument(None, help="使用 +r/o-r 时的远程路径"),
    visibility: Optional[str] = typer.Option(None, "--visibility", help="public 或 private"),
    allow_roles: list[str] = typer.Option([], "--allow-roles", help="允许读取的群角色，可重复或逗号分隔"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    mode = None
    if maybe_path is not None:
        mode = path
        path = maybe_path
    if mode in {"+r", "a+r"}:
        visibility = "public"
    elif mode in {"o-r", "-r", "a-r"}:
        visibility = "private"
    elif mode is not None:
        output_error("chmod 当前支持 +r、o-r 或 --visibility public|private")
        raise typer.Exit(2)
    owner, remote_path = _remote_or_exit(path)
    if visibility not in {"public", "private"}:
        output_error("chmod 当前支持 +r、o-r 或 --visibility public|private")
        raise typer.Exit(2)
    roles = []
    for item in allow_roles:
        for role in str(item or "").split(","):
            role = role.strip()
            if role:
                roles.append(role)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            kwargs = {"owner": owner, "visibility": visibility}
            if roles:
                kwargs["allow_roles"] = roles
            return await client.storage.set_visibility(remote_path, **kwargs)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("chmod 完成")


@fs_app.command("setfacl")
def fs_setfacl(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径"),
    modify: Optional[str] = typer.Option(None, "-m", help="新增/更新 ACL，如 aid:bob.aid:r"),
    remove: Optional[str] = typer.Option(None, "-x", help="移除 ACL，如 aid:bob.aid"),
    expires: Optional[str] = typer.Option(None, "--expires", help="过期时间，Unix 秒或 ISO 日期"),
    max_uses: Optional[int] = typer.Option(None, "--max-uses", help="最大使用次数"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)
    if bool(modify) == bool(remove):
        output_error("setfacl 必须且只能指定 -m 或 -x")
        raise typer.Exit(2)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            if modify:
                grantee, perms = _parse_acl_spec(modify, require_perms=True)
                return await client.storage.set_acl(
                    remote_path,
                    owner=owner,
                    grantee_aid=grantee,
                    perms=perms or "",
                    expires_at=_parse_expires(expires),
                    max_uses=max_uses,
                )
            grantee, _ = _parse_acl_spec(remove or "", require_perms=False)
            return await client.storage.remove_acl(remote_path, owner=owner, grantee_aid=grantee)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("setfacl 完成")


@fs_app.command("getfacl")
def fs_getfacl(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.list_acl(remote_path, owner=owner)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


@token_app.command("issue")
def fs_token_issue(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径"),
    expires: Optional[str] = typer.Option(None, "--expires", help="过期时间，Unix 秒或 ISO 日期"),
    max_reads: Optional[int] = typer.Option(None, "--max-reads", help="最大读取次数"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.issue_token(
                remote_path,
                owner=owner,
                expires_at=_parse_expires(expires),
                max_reads=max_reads,
            )

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


@token_app.command("revoke")
def fs_token_revoke(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径"),
    token: str = typer.Option(..., "--token", help="要吊销的 token"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.revoke_token(remote_path, owner=owner, token=token)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("token revoke 完成")


@token_app.command("ls")
def fs_token_ls(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="远程路径"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    _set_json(ctx)
    owner, remote_path = _remote_or_exit(path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.storage.list_tokens(remote_path, owner=owner)

    try:
        result = run_async(_run())
    except Exception as exc:
        handle_error(exc)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


fs_app.add_typer(token_app, name="token")
