from __future__ import annotations

import asyncio
import signal
import sys
from datetime import datetime
from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error
from aun_cli.output import output_json, is_json_mode, set_json_mode


def listen(
    ctx: typer.Context,
    from_aid: Optional[str] = typer.Option(None, "--from", help="只监听某人的消息"),
    group: Optional[str] = typer.Option(None, "--group", help="只监听指定群组"),
) -> None:
    """实时监听消息（P2P + 群组，长连接，Ctrl+C 退出）"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx, background_sync=True) as client:
            stop = asyncio.Event()

            def _on_signal():
                stop.set()

            loop = asyncio.get_running_loop()
            if sys.platform != "win32":
                loop.add_signal_handler(signal.SIGINT, _on_signal)
                loop.add_signal_handler(signal.SIGTERM, _on_signal)

            def _handle_message(data):
                if not isinstance(data, dict):
                    return
                sender = data.get("from", "?")
                if from_aid and sender != from_aid:
                    return
                ts = datetime.now().strftime("%H:%M:%S")
                content = data.get("content", data.get("payload", {}))
                text = content.get("text", "") if isinstance(content, dict) else str(content)
                if is_json_mode():
                    output_json(data)
                else:
                    print(f"  [{ts}] {sender}: {text}", flush=True)

            def _handle_group_message(data):
                if not isinstance(data, dict):
                    return
                gid = data.get("group_id", "?")
                if group and gid != group:
                    return
                sender = data.get("from", "?")
                if from_aid and sender != from_aid:
                    return
                ts = datetime.now().strftime("%H:%M:%S")
                content = data.get("content", data.get("payload", {}))
                text = content.get("text", "") if isinstance(content, dict) else str(content)
                if is_json_mode():
                    output_json(data)
                else:
                    print(f"  [{ts}] group:{gid} {sender}: {text}", flush=True)

            client.on("message.received", _handle_message)
            client.on("group.message_created", _handle_group_message)

            if not is_json_mode():
                hint = ""
                if from_aid:
                    hint += f" from={from_aid}"
                if group:
                    hint += f" group={group}"
                print(f"Listening{hint}... (Ctrl+C to stop)", flush=True)

            try:
                if sys.platform == "win32":
                    while not stop.is_set():
                        try:
                            await asyncio.wait_for(stop.wait(), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass
                else:
                    await stop.wait()
            except KeyboardInterrupt:
                pass

    try:
        run_async(_run())
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        handle_error(e)
