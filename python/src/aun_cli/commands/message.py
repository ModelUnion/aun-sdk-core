from __future__ import annotations

import sys
from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error
from aun_cli.output import output_json, output_success, output_error, is_json_mode, set_json_mode


def send(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="目标 AID"),
    message: str = typer.Argument(..., help="消息内容（- 表示从 stdin 读取）"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
) -> None:
    """发送 P2P 消息"""
    set_json_mode(ctx.obj.get("json", False))

    content = sys.stdin.read().strip() if message == "-" else message

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("message.send", {
                "to": target,
                "content": {"text": content},
                "encrypt": not no_encrypt,
            })

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        msg_id = result.get("message_id", result.get("id", ""))
        output_success(f"Sent to {target} (id: {msg_id})")


def pull(
    ctx: typer.Context,
    from_aid: Optional[str] = typer.Option(None, "--from", help="只拉取某人的消息"),
    limit: int = typer.Option(20, "--limit", help="最多拉取条数"),
    after_seq: Optional[int] = typer.Option(None, "--after-seq", help="从指定 seq 之后拉取"),
) -> None:
    """拉取离线消息"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            params: dict = {"limit": limit}
            if from_aid:
                params["from"] = from_aid
            if after_seq is not None:
                params["after_seq"] = after_seq
            return await client.call("message.pull", params)

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    messages = result if isinstance(result, list) else result.get("messages", [])

    if is_json_mode():
        output_json(messages)
    else:
        if not messages:
            print("  (no messages)")
            return
        for msg in messages:
            sender = msg.get("from", "?")
            content = msg.get("content", {})
            text = content.get("text", "") if isinstance(content, dict) else str(content)
            seq = msg.get("seq", "")
            print(f"  [{seq}] {sender}: {text}")


def ack(
    ctx: typer.Context,
    sender: str = typer.Argument(..., help="发送方 AID"),
    seq: int = typer.Option(..., "--seq", help="确认到的 seq"),
) -> None:
    """确认消息（推进 ack_seq）"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            return await client.call("message.ack", {"seq": seq})

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_success(f"Acked seq {seq} from {sender}")
