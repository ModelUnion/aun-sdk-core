from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any
from typing import Optional
import uuid

import typer

from aun_cli.adapter import CLISession, run_async, handle_error, resolve_profile_config, make_aid_store
from aun_cli.config import get_profile, set_profile
from aun_cli.output import output_json, output_success, output_table, output_dict, output_error, is_json_mode, set_json_mode

group_app = typer.Typer(name="group", help="群组管理", no_args_is_help=True)
resources_app = typer.Typer(name="resources", help="群存储资源", no_args_is_help=True)


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
            # group-storage 转让需旧群主用 group_aid 私钥签名授权。
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
    """完成 group-storage 群主转让 rekey"""
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
        output_success(f"Completed group-storage transfer for {resolved_group_id}")


@resources_app.command("init")
def group_resources_init(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
    group_aid: Optional[str] = typer.Option(None, "--group-aid", help="群 group_aid；省略时先读取 group.info"),
) -> None:
    """初始化群 storage 命名空间"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            resolved_group_aid = str(group_aid or "").strip()
            if not resolved_group_aid:
                info = await client.call("group.info", {"group_id": resolved_group_id})
                resolved_group_aid = _extract_group_aid(info)
            if not resolved_group_aid:
                raise ValueError("group_aid is required; pass --group-aid or ensure group.info returns it")
            store = _with_group_identity_store(ctx)
            try:
                return await client.group.resources.initialize_namespace(
                    group_id=resolved_group_id,
                    group_aid=resolved_group_aid,
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

    output_json(result) if is_json_mode() else output_success(f"Initialized group resources for {resolved_group_id}")


@resources_app.command("ls")
def group_resources_ls(
    ctx: typer.Context,
    group_id_or_prefix: str = typer.Argument(None, help="群组 ID 或资源前缀"),
    prefix: str | None = typer.Argument(None, help="资源前缀；省略群组 ID 时使用 active group"),
    page: int = typer.Option(1, "--page", help="页码"),
    size: int = typer.Option(100, "--size", help="每页数量"),
    include_status: bool = typer.Option(False, "--include-status", help="附带 storage 状态抽查"),
) -> None:
    """列出群存储镜像资源"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_prefix = _resolve_group_and_resource_path(ctx, group_id_or_prefix, prefix)

    async def _run():
        async with CLISession(ctx) as client:
            params: dict[str, Any] = {
                "group_id": resolved_group_id,
                "prefix": resolved_prefix,
                "page": page,
                "size": size,
                "include_status": include_status,
            }
            return await client.group.resources.list(**params)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(_json_ready(result))
    else:
        data = result if isinstance(result, dict) else {"items": result}
        items = data.get("items") or data.get("resources") or []
        rows = [
            [
                item.get("resource_type", item.get("type", "")),
                item.get("resource_path", item.get("path", "")),
                item.get("status", ""),
            ]
            for item in items
            if isinstance(item, dict)
        ]
        output_table(["type", "path", "status"], rows)


@resources_app.command("children")
def group_resources_children(
    ctx: typer.Context,
    group_id_or_path: str = typer.Argument(None, help="群组 ID 或目录路径；省略时列 active group 根目录"),
    resource_path: str | None = typer.Argument(None, help="目录路径；省略群组 ID 时使用 active group"),
    node_type: Optional[str] = typer.Option(None, "--type", help="资源类型：folder / file / link"),
    page: int = typer.Option(1, "--page", help="页码"),
    size: int = typer.Option(100, "--size", help="每页数量"),
    include_status: bool = typer.Option(False, "--include-status", help="附带 storage 状态抽查"),
    sort_by: Optional[str] = typer.Option(None, "--sort-by", help="排序字段"),
    order: Optional[str] = typer.Option(None, "--order", help="asc 或 desc"),
) -> None:
    """列出群资源目录的直接子节点"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_path = _resolve_group_and_resource_path(ctx, group_id_or_path, resource_path)

    async def _run():
        async with CLISession(ctx) as client:
            params: dict[str, Any] = {
                "group_id": resolved_group_id,
                "resource_path": resolved_path,
                "page": page,
                "size": size,
                "include_status": include_status,
            }
            if node_type:
                params["resource_type"] = node_type
            if sort_by:
                params["sort_by"] = sort_by
            if order:
                params["order"] = order
            return await client.group.resources.list_children(**params)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(_json_ready(result))
    else:
        data = result if isinstance(result, dict) else {"items": result}
        items = data.get("items") or data.get("children") or []
        rows = [
            [
                item.get("resource_type", item.get("type", "")),
                item.get("resource_path", item.get("path", "")),
                item.get("status", ""),
            ]
            for item in items
            if isinstance(item, dict)
        ]
        output_table(["type", "path", "status"], rows)


@resources_app.command("get")
def group_resources_get(
    ctx: typer.Context,
    group_id_or_path: str = typer.Argument(..., help="群组 ID 或资源路径"),
    resource_path: str | None = typer.Argument(None, help="资源路径；省略群组 ID 时使用 active group"),
    include_status: bool = typer.Option(False, "--include-status", help="附带 storage 状态抽查"),
) -> None:
    """查看群存储镜像资源详情"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_path = _resolve_group_and_resource_path(ctx, group_id_or_path, resource_path)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.group.resources.get(
                group_id=resolved_group_id,
                resource_path=resolved_path,
                include_status=include_status,
            )

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


@resources_app.command("update")
def group_resources_update(
    ctx: typer.Context,
    group_id_or_path: str = typer.Argument(..., help="群组 ID 或资源路径"),
    resource_path: str | None = typer.Argument(None, help="资源路径；省略群组 ID 时使用 active group"),
    title: Optional[str] = typer.Option(None, "--title", help="资源标题"),
    visibility: Optional[str] = typer.Option(None, "--visibility", help="可见性：members_only / public"),
    tags: list[str] = typer.Option([], "--tag", help="资源标签，可重复或逗号分隔"),
    metadata_json: Optional[str] = typer.Option(None, "--metadata-json", help="资源 metadata JSON 对象"),
    expected_version: Optional[int] = typer.Option(None, "--expected-version", help="CAS 期望版本"),
) -> None:
    """更新群资源业务元数据"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_path = _resolve_group_and_resource_path(ctx, group_id_or_path, resource_path)
    updates: dict[str, Any] = {"group_id": resolved_group_id, "resource_path": resolved_path}
    if title is not None:
        updates["title"] = title
    if visibility is not None:
        if visibility not in {"members_only", "public"}:
            raise typer.BadParameter("visibility must be members_only or public")
        updates["visibility"] = visibility
    parsed_tags = _split_option_values(tags)
    if parsed_tags:
        updates["tags"] = parsed_tags
    metadata = _parse_json_object(metadata_json, option_name="--metadata-json")
    if metadata is not None:
        updates["metadata"] = metadata
    if expected_version is not None:
        updates["expected_version"] = expected_version
    if set(updates.keys()) <= {"group_id", "resource_path"}:
        output_error("No update fields specified")
        raise typer.Exit(2)

    async def _make(client):
        return await client.group.resources.update(**updates)

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Updated {resolved_path} in {resolved_group_id}")


@resources_app.command("df")
def group_resources_df(
    ctx: typer.Context,
    group_id: str = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
) -> None:
    """查看群存储用量视图"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)

    async def _run():
        async with CLISession(ctx) as client:
            return await client.group.resources.get_df(group_id=resolved_group_id)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_dict(_json_ready(result))


@resources_app.command("put")
def group_resources_put(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    local_path: str = typer.Argument(..., help="本地文件路径"),
    resource_path: str = typer.Argument(..., help="群自有区资源路径，如 announce/a.txt"),
    content_type: Optional[str] = typer.Option(None, "--content-type", help="内容类型"),
    title: Optional[str] = typer.Option(None, "--title", help="资源标题"),
    expected_version: Optional[int] = typer.Option(None, "--expected-version", help="CAS 期望版本"),
) -> None:
    """写入群自有区文件并确认 group.resources 镜像"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    resolved_path = _normalize_resource_path(resource_path)
    file_path = Path(local_path)
    upload_data = file_path.read_bytes()
    guessed_type = content_type or mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    max_inline_bytes = 65536

    async def _make(client):
        params: dict[str, Any] = {
            "group_id": resolved_group_id,
            "resource_path": resolved_path,
            "content_type": guessed_type,
            "size_bytes": len(upload_data),
            "sha256": hashlib.sha256(upload_data).hexdigest(),
        }
        if len(upload_data) <= max_inline_bytes:
            params["content"] = base64.b64encode(upload_data).decode("ascii")
            params["content_encoding"] = "base64"
        if title:
            params["title"] = title
        if expected_version is not None:
            params["expected_version"] = expected_version
        return await client.group.resources.put(**params)

    pending_upload_data = upload_data if len(upload_data) > max_inline_bytes else None
    try:
        result = run_async(_run_pending(ctx, _make, default_sign_as_from_pending=True, upload_data=pending_upload_data))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Put {resolved_path} into {resolved_group_id}")


async def _run_pending(
    ctx: typer.Context,
    make_pending,
    *,
    default_sign_as_from_pending: bool = False,
    upload_data: bytes | None = None,
) -> Any:
    """通用 group-storage 写编排：facade 取 pending_ops，再以对应身份 execute_pending_ops。

    群自有区写（put/delete/mkdir/rename/move）以 group_aid 签名，成员挂载（mount）以成员
    自己 AID 签名——签名身份由服务端 pending_ops 的 sign_as 决定，这里只负责加载本地身份。
    """
    async with CLISession(ctx) as client:
        pending = await make_pending(client)
        if not _is_pending_ops_result(pending):
            return pending
        store = _with_group_identity_store(ctx)
        try:
            kwargs: dict[str, Any] = {"aid_store": store}
            if default_sign_as_from_pending:
                group_aid = str(pending.get("group_aid") or pending.get("groupAid") or "").strip()
                if group_aid:
                    kwargs["sign_as"] = group_aid
            if upload_data is not None:
                kwargs["upload_data"] = upload_data
            return await client.group.resources.execute_pending_ops(pending, **kwargs)
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()


@resources_app.command("rm")
@resources_app.command("delete")
def group_resources_rm(
    ctx: typer.Context,
    group_id_or_path: str = typer.Argument(..., help="群组 ID 或资源路径"),
    resource_path: str | None = typer.Argument(None, help="资源路径；省略群组 ID 时使用 active group"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="递归删除目录"),
) -> None:
    """删除群自有区资源（群主以 group_aid 身份执行）"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_path = _resolve_group_and_resource_path(ctx, group_id_or_path, resource_path)

    async def _make(client):
        return await client.group.resources.delete(
            group_id=resolved_group_id, resource_path=resolved_path,
            recursive=recursive,
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Removed {resolved_path} from {resolved_group_id}")


@resources_app.command("mkdir")
def group_resources_mkdir(
    ctx: typer.Context,
    group_id_or_path: str = typer.Argument(..., help="群组 ID 或目录路径"),
    resource_path: str | None = typer.Argument(None, help="目录路径；省略群组 ID 时使用 active group"),
) -> None:
    """在群自有区创建目录（群主以 group_aid 身份执行）"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_path = _resolve_group_and_resource_path(ctx, group_id_or_path, resource_path)

    async def _make(client):
        return await client.group.resources.create_folder(
            group_id=resolved_group_id, resource_path=resolved_path,
            resource_type="folder",
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Created dir {resolved_path} in {resolved_group_id}")


@resources_app.command("mv")
@resources_app.command("move")
def group_resources_mv(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    resource_path: str = typer.Argument(..., help="源资源路径"),
    dst_path: str = typer.Argument(..., help="目标资源路径"),
) -> None:
    """移动群自有区资源（群主以 group_aid 身份执行）"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    resolved_src = _normalize_resource_path(resource_path)
    resolved_dst = _normalize_resource_path(dst_path)
    dst_parent_path, new_name = _split_resource_parent_name(resolved_dst)

    async def _make(client):
        return await client.group.resources.move(
            group_id=resolved_group_id, resource_path=resolved_src,
            dst_parent_path=dst_parent_path, new_name=new_name,
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Moved {resolved_src} → {resolved_dst} in {resolved_group_id}")


@resources_app.command("ren")
@resources_app.command("rename")
def group_resources_rename(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    resource_path: str = typer.Argument(..., help="资源路径"),
    new_name: str = typer.Argument(..., help="新名称"),
) -> None:
    """重命名群自有区资源（群主以 group_aid 身份执行）"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    resolved_path = _normalize_resource_path(resource_path)
    resolved_name = str(new_name or "").strip()
    if not resolved_name or "/" in resolved_name or "\\" in resolved_name:
        raise typer.BadParameter("new_name must be a non-empty file or folder name")

    async def _make(client):
        return await client.group.resources.rename(
            group_id=resolved_group_id,
            resource_path=resolved_path,
            new_name=resolved_name,
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Renamed {resolved_path} to {resolved_name} in {resolved_group_id}")


@resources_app.command("mount-object")
def group_resources_mount_object(
    ctx: typer.Context,
    group_id_or_path: str = typer.Argument(..., help="群组 ID 或资源路径"),
    resource_path: str | None = typer.Argument(None, help="资源路径；省略群组 ID 时使用 active group"),
    owner_aid: str = typer.Option(..., "--owner-aid", help="被挂载对象的 owner AID"),
    object_key: str = typer.Option(..., "--object-key", help="被挂载对象 key"),
    bucket: str = typer.Option("default", "--bucket", help="storage bucket"),
    title: Optional[str] = typer.Option(None, "--title", help="资源标题"),
    visibility: Optional[str] = typer.Option(None, "--visibility", help="可见性：members_only / public"),
    tags: list[str] = typer.Option([], "--tag", help="资源标签，可重复或逗号分隔"),
    metadata_json: Optional[str] = typer.Option(None, "--metadata-json", help="资源 metadata JSON 对象"),
    conflict_policy: str = typer.Option("reject", "--conflict-policy", help="冲突策略：reject / replace / keep_both"),
    mkdirs: bool = typer.Option(True, "--mkdirs/--no-mkdirs", help="自动创建父目录"),
) -> None:
    """把已有 storage 对象挂载为群资源"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_path = _resolve_group_and_resource_path(ctx, group_id_or_path, resource_path)
    policy = str(conflict_policy or "").strip()
    if policy not in {"reject", "replace", "keep_both"}:
        raise typer.BadParameter("conflict_policy must be reject, replace, or keep_both")
    storage_ref = {
        "owner_aid": str(owner_aid or "").strip(),
        "bucket": bucket,
        "object_key": str(object_key or "").strip().replace("\\", "/").lstrip("/"),
    }
    if not storage_ref["owner_aid"]:
        raise typer.BadParameter("owner_aid cannot be empty")
    if not storage_ref["object_key"]:
        raise typer.BadParameter("object_key cannot be empty")
    params: dict[str, Any] = {
        "group_id": resolved_group_id,
        "resource_path": resolved_path,
        "storage_ref": storage_ref,
        "mkdirs": mkdirs,
        "conflict_policy": policy,
    }
    if title is not None:
        params["title"] = title
    if visibility is not None:
        if visibility not in {"members_only", "public"}:
            raise typer.BadParameter("visibility must be members_only or public")
        params["visibility"] = visibility
    parsed_tags = _split_option_values(tags)
    if parsed_tags:
        params["tags"] = parsed_tags
    metadata = _parse_json_object(metadata_json, option_name="--metadata-json")
    if metadata is not None:
        params["metadata"] = metadata

    async def _make(client):
        return await client.group.resources.mount_object(**params)

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Mounted object {storage_ref['object_key']} as {resolved_path}")


@resources_app.command("download")
@resources_app.command("dl")
def group_resources_download(
    ctx: typer.Context,
    group_id_or_path: str = typer.Argument(..., help="群组 ID 或资源路径"),
    resource_path: str | None = typer.Argument(None, help="资源路径；省略群组 ID 时使用 active group"),
    output_path: Optional[str] = typer.Option(None, "--output", "-o", help="保存路径"),
) -> None:
    """下载群资源（经 group.resources.get_access 校验群成员身份后下载）"""
    from aun_cli import storage_core
    from aun_core.config import resolve_verify_ssl_from_env

    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id, resolved_path = _resolve_group_and_resource_path(ctx, group_id_or_path, resource_path)

    async def _run():
        async with CLISession(ctx) as client:
            return await storage_core.download_group_resource(
                client, group_id=resolved_group_id, resource_path=resolved_path,
                verify_ssl=resolve_verify_ssl_from_env(),
            )

    try:
        download, data = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    file_name = download.get("file_name") or resolved_path.rsplit("/", 1)[-1]
    save_path = Path(output_path) if output_path else Path(file_name)
    save_path.write_bytes(data)

    if is_json_mode():
        output_json({
            "group_id": resolved_group_id,
            "resource_path": resolved_path,
            "saved_to": str(save_path),
            "size_bytes": len(data),
            "content_type": download.get("content_type", ""),
        })
    else:
        output_success(f"Downloaded: {save_path} ({len(data)} bytes)")


@resources_app.command("mount")
def group_resources_mount(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    source_path: str = typer.Option(
        "", "--source-path",
        help="群目录 {aid}/{group_aid} 下的子路径（可留空挂整个群目录）；协议固定源根，不能挂群目录外的路径",
    ),
    member_aid: Optional[str] = typer.Option(None, "--member-aid", help="成员 AID；省略时使用当前 profile 身份"),
    readonly: bool = typer.Option(False, "--readonly", help="只读挂载"),
) -> None:
    """成员自助挂载自己的卷到 memberdata/{aid}（成员以自己 AID 身份执行）"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    resolved_member = str(member_aid or "").strip() or resolve_profile_config(ctx).get("aid", "")
    if not resolved_member:
        output_error("member_aid is required; pass --member-aid or set profile aid")
        raise typer.Exit(1)
    mount_path = f"memberdata/{resolved_member}"

    async def _make(client):
        source = str(source_path or "").strip()
        return await client.group.resources.mount_object(
            group_id=resolved_group_id, mount_path=mount_path,
            source_aid=resolved_member,
            source_path=_normalize_resource_path(source) if source else "",
            readonly=readonly,
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Mounted {mount_path} in {resolved_group_id}")


@resources_app.command("umount")
@resources_app.command("unmount")
def group_resources_umount(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    member_aid: Optional[str] = typer.Option(None, "--member-aid", help="成员 AID；省略时使用当前 profile 身份"),
) -> None:
    """卸载成员挂载区 memberdata/{aid}"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    resolved_member = str(member_aid or "").strip() or resolve_profile_config(ctx).get("aid", "")
    if not resolved_member:
        output_error("member_aid is required; pass --member-aid or set profile aid")
        raise typer.Exit(1)
    mount_path = f"memberdata/{resolved_member}"

    async def _run():
        async with CLISession(ctx) as client:
            return await client.group.resources.unmount(
                group_id=resolved_group_id, resource_path=mount_path,
            )

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Unmounted {mount_path} from {resolved_group_id}")


@resources_app.command("setfacl")
def group_resources_setfacl(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    member_aid: str = typer.Argument(..., help="要授权的成员 AID"),
    perms: str = typer.Option("rwx", "--perms", help="群自有区 storage ACL 权限"),
) -> None:
    """把成员提升为 admin，并同步群自有区 storage ACL"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    target_aid = str(member_aid or "").strip()

    async def _make(client):
        return await client.group.set_role(
            group_id=resolved_group_id,
            aid=target_aid,
            role="admin",
            perms=perms,
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Granted group storage ACL to {target_aid} in {resolved_group_id}")


@resources_app.command("remove_acl")
@resources_app.command("remove-acl")
def group_resources_remove_acl(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    member_aid: str = typer.Argument(..., help="要移除授权的成员 AID"),
) -> None:
    """把成员降为 member，并移除群自有区 storage ACL"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    target_aid = str(member_aid or "").strip()

    async def _make(client):
        return await client.group.set_role(
            group_id=resolved_group_id,
            aid=target_aid,
            role="member",
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Removed group storage ACL from {target_aid} in {resolved_group_id}")


@resources_app.command("adopt")
def group_resources_adopt(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    member_aid: str = typer.Argument(..., help="要接管为群自有区管理员的成员 AID"),
    perms: str = typer.Option("rwx", "--perms", help="群自有区 storage ACL 权限"),
) -> None:
    """接纳成员为群自有区 admin，并同步 storage ACL"""
    set_json_mode(ctx.obj.get("json", False))
    resolved_group_id = _resolve_group_id(ctx, group_id)
    target_aid = str(member_aid or "").strip()

    async def _make(client):
        return await client.group.set_role(
            group_id=resolved_group_id,
            aid=target_aid,
            role="admin",
            perms=perms,
        )

    try:
        result = run_async(_run_pending(ctx, _make))
    except Exception as e:
        handle_error(e)
        return

    output_json(_json_ready(result)) if is_json_mode() else output_success(f"Adopted {target_aid} for group storage in {resolved_group_id}")


group_app.add_typer(resources_app)


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
