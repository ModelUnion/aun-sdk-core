from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import posixpath
import re
from pathlib import Path
from typing import Any
from typing import Optional
import uuid

import typer

from aun_cli.adapter import CLISession, run_async, handle_error, resolve_profile_config, make_aid_store
from aun_cli.config import get_profile, set_profile
from aun_cli.output import output_json, output_success, output_table, output_dict, output_error, is_json_mode, set_json_mode
from aun_core.group_fs import is_group_remote_path

group_app = typer.Typer(name="group", help="群组管理", no_args_is_help=True)
fs_app = typer.Typer(name="fs", help="群 POSIX 文件系统", no_args_is_help=True)

_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _current_profile_name(ctx: typer.Context) -> str:
    return resolve_profile_config(ctx)["profile_name"]


def _set_active_group(ctx: typer.Context, group_id: str) -> None:
    profile_name = _current_profile_name(ctx)
    try:
        prof = get_profile(profile_name)
    except KeyError:
        prof = {}
    prof["active_group"] = group_id
    set_profile(profile_name, prof)


def _extract_group_id(result: object) -> str:
    if isinstance(result, dict):
        group = result.get("group")
        if isinstance(group, dict):
            gid = str(group.get("group_id") or "").strip()
            if gid:
                return gid
        return str(result.get("group_id") or "").strip()
    return ""


def _extract_groups(result: object) -> list:
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        groups = result.get("items")
        if isinstance(groups, list):
            return groups
        groups = result.get("groups")
        if isinstance(groups, list):
            return groups
    return []


def _nested_dict(data: dict, key: str) -> dict:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _first_value(data: dict, *keys: str, default: object = "") -> object:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    group = _nested_dict(data, "group")
    for key in keys:
        value = group.get(key)
        if value not in (None, ""):
            return value
    return default


def _group_info_display(result: dict) -> dict[str, object]:
    e2ee = _nested_dict(result, "e2ee")
    info: dict[str, object] = {
        "Name": _first_value(result, "name"),
        "ID": _first_value(result, "group_id"),
        "Group AID": _first_value(result, "group_aid"),
        "Owner AID": _first_value(result, "owner_aid", "owner"),
        "Visibility": _first_value(result, "visibility"),
        "Status": _first_value(result, "status"),
        "Description": _first_value(result, "description"),
        "Members": _first_value(result, "member_count", default="?"),
        "Message Seq": _first_value(result, "message_seq", default=0),
        "Event Seq": _first_value(result, "event_seq", default=0),
        "State Version": _first_value(result, "state_version", default=e2ee.get("state_version", "")),
        "Key Epoch": _first_value(result, "key_epoch", "e2ee_epoch", "epoch", default=e2ee.get("key_epoch", e2ee.get("epoch", ""))),
        "State Hash": _first_value(result, "state_hash"),
        "Created At": _first_value(result, "created_at"),
        "Updated At": _first_value(result, "updated_at"),
    }
    return {key: value for key, value in info.items() if value not in (None, "")}


def _is_canonical_group_id(value: str) -> bool:
    text = str(value or "").strip().lower()
    if text.startswith("group.") or text.startswith("g-") or text.startswith("grp-"):
        return True
    try:
        uuid.UUID(text)
        return True
    except ValueError:
        return False


def _resolve_group_id(ctx: typer.Context, group_id: str | None) -> str:
    gid = str(group_id or "").strip()
    if gid:
        return gid
    active_group = str(resolve_profile_config(ctx).get("active_group") or "").strip()
    if active_group:
        return active_group
    raise typer.BadParameter("No group_id specified and no active group set. Run 'aun group use <group_id>' first.")


def _normalize_group_fs_bare_path(value: str | None) -> str:
    raw = str(value or "/").strip().replace("\\", "/")
    if not raw:
        raw = "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    normalized = posixpath.normpath(re.sub(r"/+", "/", raw))
    return "/" if normalized == "." else normalized


def _is_local_group_fs_path(value: str) -> bool:
    text = str(value or "").strip()
    return text.startswith("local:") or bool(_WINDOWS_DRIVE_RE.match(text))


def _strip_local_group_fs_prefix(value: str) -> str:
    text = str(value or "").strip()
    return text[6:] if text.startswith("local:") else text


def _resolve_group_fs_single_path(ctx: typer.Context, path: str | None) -> tuple[str, dict[str, Any]]:
    text = str(path or "/").strip()
    if is_group_remote_path(text):
        return text, {}
    if _is_local_group_fs_path(text):
        raise typer.BadParameter("group fs path must be a group path, not a local path")
    return _normalize_group_fs_bare_path(text), {"group_id": _resolve_group_id(ctx, None)}


def _classify_group_fs_cp_path(value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if _is_local_group_fs_path(text):
        return "local", _strip_local_group_fs_prefix(text)
    if is_group_remote_path(text):
        return "remote", text
    return "bare", text


def _group_fs_node_items(result: Any) -> list[Any]:
    data = _json_ready(result)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "nodes", "children", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _output_group_fs_nodes(result: Any, *, long: bool = False) -> None:
    rows = []
    for item in _group_fs_node_items(result):
        node = item if isinstance(item, dict) else _json_ready(item)
        storage = node.get("storage") if isinstance(node.get("storage"), dict) else {}
        owner = node.get("owner") or node.get("member_aid") or storage.get("owner_aid") or ""
        name = node.get("name") or str(node.get("path") or "").rstrip("/").rsplit("/", 1)[-1]
        if node.get("type") == "symlink" and node.get("target"):
            name = f"{name} -> {node.get('target')}"
        if long:
            rows.append([
                node.get("type", ""),
                node.get("mode", "") or "-",
                owner,
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


def _normalize_resource_path(value: str) -> str:
    path = str(value or "").strip().replace("\\", "/").strip("/")
    if not path:
        raise typer.BadParameter("resource path cannot be empty")
    return path


def _split_resource_parent_name(path: str) -> tuple[str, str]:
    normalized = _normalize_resource_path(path)
    if "/" in normalized:
        parent, name = normalized.rsplit("/", 1)
    else:
        parent, name = "", normalized
    if not name:
        raise typer.BadParameter("destination name cannot be empty")
    return parent, name


def _is_pending_ops_result(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("pending_ops"), list)


def _json_ready(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def _parse_json_object(value: str | None, *, option_name: str) -> dict[str, Any] | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"{option_name} must be a valid JSON object") from exc
    if not isinstance(parsed, dict):
        raise typer.BadParameter(f"{option_name} must be a JSON object")
    return parsed


def _split_option_values(values: list[str]) -> list[str]:
    result: list[str] = []
    for item in values:
        for part in str(item or "").split(","):
            part = part.strip()
            if part:
                result.append(part)
    return result


def _with_group_identity_store(ctx: typer.Context):
    resolved = resolve_profile_config(ctx)
    return make_aid_store(resolved)


def _resolve_group_and_resource_path(
    ctx: typer.Context,
    group_id_or_path: str | None,
    resource_path: str | None,
) -> tuple[str, str]:
    if resource_path is not None:
        return _resolve_group_id(ctx, group_id_or_path), _normalize_resource_path(resource_path)
    value = str(group_id_or_path or "").strip()
    if not value:
        return _resolve_group_id(ctx, None), ""
    if _is_canonical_group_id(value):
        return _resolve_group_id(ctx, value), ""
    return _resolve_group_id(ctx, None), _normalize_resource_path(value)


def _extract_group_aid(result: object) -> str:
    if isinstance(result, dict):
        group = result.get("group")
        if isinstance(group, dict):
            value = str(group.get("group_aid") or "").strip()
            if value:
                return value
        return str(result.get("group_aid") or "").strip()
    return ""


def _is_named_group_aid(group_aid: str) -> bool:
    value = str(group_aid or "").strip().lower()
    if not value or "." not in value:
        return False
    prefix = value.split(".", 1)[0]
    return not prefix.isdigit()


@fs_app.command("ls")
def group_fs_ls(
    ctx: typer.Context,
    path: str = typer.Argument("/", help="群 FS 路径"),
    long: bool = typer.Option(False, "--long", "-l", help="显示长格式"),
    page: int = typer.Option(1, "--page", help="页码"),
    size: int = typer.Option(100, "--size", help="每页数量"),
    marker: Optional[str] = typer.Option(None, "--marker", help="分页游标"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)
    options.update({"page": page, "size": size, "long": long})
    if marker is not None:
        options["marker"] = marker

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.group.fs.ls(resolved_path, **options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else _output_group_fs_nodes(result, long=long)


@fs_app.command("find")
def group_fs_find(
    ctx: typer.Context,
    path: str = typer.Argument("/", help="群 FS 路径"),
    name: Optional[str] = typer.Option(None, "--name", help="按文件名 glob 过滤"),
    node_type: Optional[str] = typer.Option(None, "--type", help="类型：f、d、file、dir、symlink"),
    size_expr: Optional[str] = typer.Option(None, "--size", help="大小过滤表达式"),
    mtime_expr: Optional[str] = typer.Option(None, "--mtime", help="mtime 过滤表达式"),
    page: int = typer.Option(1, "--page", help="页码"),
    page_size: int = typer.Option(1000, "--page-size", help="每页数量"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)
    options.update({
        "name": name,
        "node_type": node_type,
        "size": size_expr,
        "mtime": mtime_expr,
        "page": page,
        "page_size": page_size,
    })

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.group.fs.find(resolved_path, **{k: v for k, v in options.items() if v is not None})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else _output_group_fs_nodes(result, long=True)


@fs_app.command("stat")
def group_fs_stat(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="群 FS 路径"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.group.fs.stat(resolved_path, **options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


@fs_app.command("lstat")
def group_fs_lstat(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="群 FS 路径"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.group.fs.lstat(resolved_path, **options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


@fs_app.command("mkdir")
def group_fs_mkdir(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="群 FS 目录路径"),
    parents: bool = typer.Option(False, "--parents", "-p", help="逐级创建父目录"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="签名 AID（群自有区写入传 group_aid）"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)

    async def _run():
        async with CLISession(ctx) as client:
            call_options = dict(options)
            if as_aid:
                call_options["sign_as"] = as_aid
            return await client.group.fs.mkdir(resolved_path, parents=parents, **call_options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("group fs mkdir 完成")


@fs_app.command("rm")
def group_fs_rm(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="群 FS 路径"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="递归删除"),
    force: bool = typer.Option(False, "--force", help="强制删除"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="签名 AID（群自有区写入传 group_aid）"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)

    async def _run():
        async with CLISession(ctx) as client:
            call_options = dict(options)
            if as_aid:
                call_options["sign_as"] = as_aid
            return await client.group.fs.rm(resolved_path, recursive=recursive, force=force, **call_options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("group fs rm 完成")


@fs_app.command("cp")
def group_fs_cp(
    ctx: typer.Context,
    src: str = typer.Argument(..., help="源路径，本地或群 FS"),
    dst: str = typer.Argument(..., help="目标路径，本地或群 FS"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="递归复制目录"),
    force: bool = typer.Option(False, "--force", help="覆盖目标"),
    parents: bool = typer.Option(True, "--parents/--no-parents", help="上传时自动创建父目录"),
    content_type: Optional[str] = typer.Option(None, "--content-type", help="上传内容类型"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="签名 AID（群自有区写入传 group_aid）"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    src_kind, src_value = _classify_group_fs_cp_path(src)
    dst_kind, dst_value = _classify_group_fs_cp_path(dst)
    options: dict[str, Any] = {
        "force": force,
        "recursive": recursive,
        "parents": parents,
        "content_type": content_type,
    }
    active_group = _resolve_group_id(ctx, None)

    if src_kind == "bare" and dst_kind == "bare":
        if Path(src_value).exists():
            resolved_src = src_value
            resolved_dst = _normalize_group_fs_bare_path(dst_value)
            options["dst_group_id"] = active_group
        else:
            resolved_src = _normalize_group_fs_bare_path(src_value)
            resolved_dst = _normalize_group_fs_bare_path(dst_value)
            options["src_group_id"] = active_group
            options["dst_group_id"] = active_group
    elif src_kind == "local" and dst_kind == "bare":
        resolved_src = src_value
        resolved_dst = _normalize_group_fs_bare_path(dst_value)
        options["dst_group_id"] = active_group
    elif src_kind == "bare" and dst_kind == "local":
        resolved_src = _normalize_group_fs_bare_path(src_value)
        resolved_dst = dst_value
        options["src_group_id"] = active_group
    elif src_kind == "remote" and dst_kind == "bare":
        resolved_src = src_value
        resolved_dst = dst_value
    elif src_kind == "bare" and dst_kind == "remote":
        resolved_src = src_value
        resolved_dst = dst_value
    elif src_kind == "local" and dst_kind == "remote":
        resolved_src = src_value
        resolved_dst = dst_value
    elif src_kind == "remote" and dst_kind == "local":
        resolved_src = src_value
        resolved_dst = dst_value
    elif src_kind == "remote" and dst_kind == "remote":
        resolved_src = src_value
        resolved_dst = dst_value
    else:
        output_error("group fs cp 不处理本地到本地复制")
        raise typer.Exit(2)

    async def _run():
        async with CLISession(ctx) as client:
            call_options = dict(options)
            if as_aid:
                call_options["sign_as"] = as_aid
            return await client.group.fs.cp(resolved_src, resolved_dst, **call_options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("group fs cp 完成")


@fs_app.command("mv")
def group_fs_mv(
    ctx: typer.Context,
    src: str = typer.Argument(..., help="源群 FS 路径"),
    dst: str = typer.Argument(..., help="目标群 FS 路径"),
    force: bool = typer.Option(False, "--force", help="覆盖目标"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="签名 AID（群自有区写入传 group_aid）"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    src_kind, src_value = _classify_group_fs_cp_path(src)
    dst_kind, dst_value = _classify_group_fs_cp_path(dst)
    if src_kind == "local" or dst_kind == "local":
        output_error("group fs mv 只支持群 FS 路径")
        raise typer.Exit(2)
    options: dict[str, Any] = {"force": force}
    if src_kind == "bare" and dst_kind == "bare":
        resolved_src = _normalize_group_fs_bare_path(src_value)
        resolved_dst = _normalize_group_fs_bare_path(dst_value)
        options["group_id"] = _resolve_group_id(ctx, None)
    elif src_kind == "bare":
        resolved_src = _normalize_group_fs_bare_path(src_value)
        resolved_dst = dst_value
        options["src_group_id"] = _resolve_group_id(ctx, None)
    elif dst_kind == "bare":
        resolved_src = src_value
        resolved_dst = _normalize_group_fs_bare_path(dst_value)
        options["dst_group_id"] = _resolve_group_id(ctx, None)
    else:
        resolved_src = src_value
        resolved_dst = dst_value

    async def _run():
        async with CLISession(ctx) as client:
            call_options = dict(options)
            if as_aid:
                call_options["sign_as"] = as_aid
            return await client.group.fs.mv(resolved_src, resolved_dst, **call_options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("group fs mv 完成")


@fs_app.command("df")
def group_fs_df(
    ctx: typer.Context,
    path: str = typer.Argument("/", help="群 FS 路径"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.group.fs.df(resolved_path, **options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


@fs_app.command("mount")
def group_fs_mount(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="memberdata 槽位路径"),
    readonly: bool = typer.Option(True, "--readonly/--readwrite", help="只读或读写挂载"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)
    options["readonly"] = readonly

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.group.fs.mount(resolved_path, **options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("group fs mount 完成")


@fs_app.command("umount")
def group_fs_umount(
    ctx: typer.Context,
    path: str = typer.Argument(..., help="memberdata 槽位路径"),
    as_aid: Optional[str] = typer.Option(None, "--as", help="操作者 AID"),
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    resolved_path, options = _resolve_group_fs_single_path(ctx, path)

    async def _run():
        async with CLISession(ctx, aid=as_aid) as client:
            return await client.group.fs.umount(resolved_path, **options)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return
    output_json(_json_ready(result)) if is_json_mode() else output_success("group fs umount 完成")


@group_app.command("create")
def group_create(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="群组名称"),
    members: Optional[str] = typer.Option(None, "--members", help="初始成员 AID（逗号分隔）"),
    group_name: Optional[str] = typer.Option(None, "--group-name", help="命名群短名；设置后创建 group_aid 身份"),
) -> None:
    """创建群组"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            params: dict = {"name": name}
            if members:
                params["members"] = [m.strip() for m in members.split(",")]
            if group_name:
                params["group_name"] = group_name
                store = _with_group_identity_store(ctx)
                try:
                    return await client.create_group(params, aid_store=store)
                finally:
                    close = getattr(store, "close", None)
                    if callable(close):
                        close()
            return await client.call("group.create", params)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    gid = _extract_group_id(result)
    if gid:
        _set_active_group(ctx, gid)

    if is_json_mode():
        output_json(result)
    else:
        gid = _extract_group_id(result)
        output_success(f"Created group: {name} (id: {gid})")


@group_app.command("bind")
@group_app.command("bind-aid")
def group_bind(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
    group_name: Optional[str] = typer.Option(None, "--group-name", help="匿名群升级时指定命名 group_aid 短名"),
) -> None:
    """为匿名群补齐可签名 group_aid 身份"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            info = await client.call("group.info", {"group_id": resolved_group_id})
            group = info.get("group") if isinstance(info, dict) else None
            if not isinstance(group, dict):
                raise ValueError(f"group not found or unavailable: {resolved_group_id}")
            existing_group_aid = str(group.get("group_aid") or "").strip()
            if _is_named_group_aid(existing_group_aid):
                raise ValueError(f"group already has group_aid: {existing_group_aid}")
            params: dict[str, Any] = {"group_id": resolved_group_id}
            if group_name:
                params["group_name"] = group_name
            store = _with_group_identity_store(ctx)
            try:
                return await client.bind_group_aid(params, aid_store=store)
            finally:
                close = getattr(store, "close", None)
                if callable(close):
                    close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        group_aid = _first_value(result, "group_aid")
        output_success(f"Bound group AID for {resolved_group_id}: {group_aid}")


@group_app.command("transfer")
def group_transfer(
    ctx: typer.Context,
    group_id_or_new_owner: str = typer.Argument(..., help="群组 ID 或新群主 AID"),
    new_owner: str | None = typer.Argument(None, help="新群主 AID；省略群组 ID 时使用当前 active group"),
) -> None:
    """转移群主"""
    set_json_mode(ctx.obj.get("json", False))
    if new_owner is None:
        resolved_group_id = _resolve_group_id(ctx, None)
        target = group_id_or_new_owner
    else:
        resolved_group_id = _resolve_group_id(ctx, group_id_or_new_owner)
        target = new_owner

    async def _run():
        async with CLISession(ctx) as client:
            # group.fs 转让需旧群主用 group_aid 私钥签名授权。
            store = _with_group_identity_store(ctx)
            try:
                return await client.start_group_transfer(
                    {"group_id": resolved_group_id, "new_owner": target},
                    aid_store=store,
                )
            finally:
                close = getattr(store, "close", None)
                if callable(close):
                    close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        status = result.get("status", "transferred") if isinstance(result, dict) else "transferred"
        output_success(f"Transfer {resolved_group_id} to {target}: {status}")


@group_app.command("complete-transfer")
@group_app.command("transfer-complete", hidden=True)
def group_transfer_complete(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
) -> None:
    """完成 group.fs 群主转让 rekey"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            store = _with_group_identity_store(ctx)
            try:
                return await client.complete_group_transfer({"group_id": resolved_group_id}, aid_store=store)
            finally:
                close = getattr(store, "close", None)
                if callable(close):
                    close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Completed group.fs transfer for {resolved_group_id}")



group_app.add_typer(fs_app)


@group_app.command("use")
def group_use(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="要设为当前 active group 的群组 ID"),
) -> None:
    """设置当前 active group"""
    set_json_mode(ctx.obj.get("json", False))
    profile_name = _current_profile_name(ctx)
    _set_active_group(ctx, group_id)

    if is_json_mode():
        output_json({"status": "ok", "profile": profile_name, "active_group": group_id})
    else:
        output_success(f"Active group set to {group_id} (profile: {profile_name})")


@group_app.command("current")
def group_current(ctx: typer.Context) -> None:
    """查看当前 active group"""
    set_json_mode(ctx.obj.get("json", False))
    resolved = resolve_profile_config(ctx)
    info = {
        "Profile": resolved["profile_name"],
        "Active Group": resolved.get("active_group") or "(not set)",
        "AID": resolved.get("aid") or "(not set)",
    }

    if is_json_mode():
        output_json(info)
    else:
        output_dict(info)


@group_app.command("send")
def group_send(
    ctx: typer.Context,
    group_id_or_message: str = typer.Argument(..., help="群组 ID 或消息内容"),
    message: str | None = typer.Argument(None, help="消息内容；省略群组 ID 时使用当前 active group"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
) -> None:
    """发送群组消息"""
    set_json_mode(ctx.obj.get("json", False))
    if message is None:
        resolved_group_id = _resolve_group_id(ctx, None)
        content = group_id_or_message
    else:
        resolved_group_id = _resolve_group_id(ctx, group_id_or_message)
        content = message

    async def _run():
        async with CLISession(ctx) as client:
            params = {
                "group_id": resolved_group_id,
                "payload": {"text": content},
                "encrypt": not no_encrypt,
            }
            return await client.call("group.send", params)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Sent to group {resolved_group_id}")


@group_app.command("list")
def group_list(ctx: typer.Context) -> None:
    """列出已加入的群组"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.list_my", {})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    groups = _extract_groups(result)

    if is_json_mode():
        output_json(groups)
    else:
        if not groups:
            print("  (no groups)")
            return
        headers = ["GROUP ID", "NAME", "MEMBERS", "ROLE"]
        rows = [
            [g.get("group_id", ""), g.get("name", ""),
             str(g.get("member_count", g.get("members", "?"))), g.get("role", "")]
            for g in groups
        ]
        output_table(headers, rows)


@group_app.command("members")
def group_members(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
) -> None:
    """查看群组成员"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.get_members", {"group_id": resolved_group_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    members = result if isinstance(result, list) else result.get("members", [])

    if is_json_mode():
        output_json(members)
    else:
        if not members:
            print("  (no members)")
            return
        headers = ["AID", "ROLE"]
        rows = [[m.get("aid", ""), m.get("role", "")] for m in members]
        output_table(headers, rows)


@group_app.command("invite")
def group_invite(
    ctx: typer.Context,
    args: list[str] = typer.Argument(..., help="群组 ID 和 AID；省略群组 ID 时使用当前 active group"),
) -> None:
    """邀请成员加入群组"""
    set_json_mode(ctx.obj.get("json", False))
    if len(args) >= 2 and _is_canonical_group_id(args[0]):
        resolved_group_id = _resolve_group_id(ctx, args[0])
        aids = args[1:]
    else:
        resolved_group_id = _resolve_group_id(ctx, None)
        aids = args

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.invite", {"group_id": resolved_group_id, "members": aids})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Invited {', '.join(aids)} to {resolved_group_id}")


@group_app.command("add-member")
@group_app.command("add_member")
def group_add_member(
    ctx: typer.Context,
    group_id_or_aid: str = typer.Argument(..., help="群组 ID 或要添加的 AID"),
    aid: str | None = typer.Argument(None, help="要添加的 AID；省略群组 ID 时使用当前 active group"),
    role: str = typer.Option("member", "--role", help="成员角色：member / admin"),
    member_type: str = typer.Option("human", "--member-type", help="成员类型：human / ai"),
) -> None:
    """直接添加成员（需要 admin/owner 权限）"""
    set_json_mode(ctx.obj.get("json", False))
    if aid is None:
        resolved_group_id = _resolve_group_id(ctx, None)
        member_aid = group_id_or_aid
    else:
        resolved_group_id = _resolve_group_id(ctx, group_id_or_aid)
        member_aid = aid

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.add_member", {
                "group_id": resolved_group_id,
                "aid": member_aid,
                "role": role,
                "member_type": member_type,
            })

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Added {member_aid} to {resolved_group_id}")


@group_app.command("kick")
def group_kick(
    ctx: typer.Context,
    group_id_or_aid: str = typer.Argument(..., help="群组 ID 或要移除的 AID"),
    aid: str | None = typer.Argument(None, help="要移除的 AID；省略群组 ID 时使用当前 active group"),
) -> None:
    """移除群组成员"""
    set_json_mode(ctx.obj.get("json", False))
    if aid is None:
        resolved_group_id = _resolve_group_id(ctx, None)
        member_aid = group_id_or_aid
    else:
        resolved_group_id = _resolve_group_id(ctx, group_id_or_aid)
        member_aid = aid

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.kick", {"group_id": resolved_group_id, "aid": member_aid})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Kicked {member_aid} from {resolved_group_id}")


@group_app.command("leave")
def group_leave(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
) -> None:
    """退出群组"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.leave", {"group_id": resolved_group_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Left group {resolved_group_id}")


@group_app.command("dissolve")
def group_dissolve(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
) -> None:
    """解散群组"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.dissolve", {"group_id": resolved_group_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Dissolved group {resolved_group_id}")


@group_app.command("info")
def group_info(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
) -> None:
    """查看群组详情"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.info", {"group_id": resolved_group_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_dict(_group_info_display(result))
