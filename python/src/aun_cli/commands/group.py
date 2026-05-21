from __future__ import annotations

from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error
from aun_cli.output import output_json, output_success, output_table, output_dict, is_json_mode, set_json_mode

group_app = typer.Typer(name="group", help="群组管理", no_args_is_help=True)


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

    if is_json_mode():
        output_json(result)
    else:
        gid = result.get("group_id", "")
        output_success(f"Created group: {name} (id: {gid})")


@group_app.command("send")
def group_send(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    message: str = typer.Argument(..., help="消息内容"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
) -> None:
    """发送群组消息"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            params = {
                "group_id": group_id,
                "content": {"text": message},
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
        output_success(f"Sent to group {group_id}")


@group_app.command("list")
def group_list(ctx: typer.Context) -> None:
    """列出已加入的群组"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.list", {})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    groups = result if isinstance(result, list) else result.get("groups", [])

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
    group_id: str = typer.Argument(..., help="群组 ID"),
) -> None:
    """查看群组成员"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.members", {"group_id": group_id})

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
    group_id: str = typer.Argument(..., help="群组 ID"),
    aids: list[str] = typer.Argument(..., help="要邀请的 AID"),
) -> None:
    """邀请成员加入群组"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.invite", {"group_id": group_id, "members": aids})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Invited {', '.join(aids)} to {group_id}")


@group_app.command("kick")
def group_kick(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
    aid: str = typer.Argument(..., help="要移除的 AID"),
) -> None:
    """移除群组成员"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.kick", {"group_id": group_id, "aid": aid})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Kicked {aid} from {group_id}")


@group_app.command("leave")
def group_leave(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
) -> None:
    """退出群组"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.leave", {"group_id": group_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Left group {group_id}")


@group_app.command("dissolve")
def group_dissolve(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
) -> None:
    """解散群组"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.dissolve", {"group_id": group_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Dissolved group {group_id}")


@group_app.command("info")
def group_info(
    ctx: typer.Context,
    group_id: str = typer.Argument(..., help="群组 ID"),
) -> None:
    """查看群组详情"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("group.info", {"group_id": group_id})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_dict({
            "Name": result.get("name", ""),
            "ID": result.get("group_id", ""),
            "Owner": result.get("owner", ""),
            "Members": str(result.get("member_count", "?")),
            "Epoch": str(result.get("epoch", "")),
        })
