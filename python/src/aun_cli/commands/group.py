from __future__ import annotations

from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error, resolve_profile_config
from aun_cli.config import get_profile, set_profile
from aun_cli.output import output_json, output_success, output_table, output_dict, is_json_mode, set_json_mode

group_app = typer.Typer(name="group", help="群组管理", no_args_is_help=True)


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
    return text.startswith("group.") or text.startswith("g-") or text.startswith("grp-")


def _resolve_group_id(ctx: typer.Context, group_id: str | None) -> str:
    gid = str(group_id or "").strip()
    if gid:
        return gid
    active_group = str(resolve_profile_config(ctx).get("active_group") or "").strip()
    if active_group:
        return active_group
    raise typer.BadParameter("No group_id specified and no active group set. Run 'aun group use <group_id>' first.")


@group_app.command("create")
def group_create(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="群组名称"),
    members: Optional[str] = typer.Option(None, "--members", help="初始成员 AID（逗号分隔）"),
) -> None:
    """创建群组"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            params: dict = {"name": name}
            if members:
                params["members"] = [m.strip() for m in members.split(",")]
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
