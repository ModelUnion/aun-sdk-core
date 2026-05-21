from __future__ import annotations

import time

import typer

from aun_cli.adapter import CLISession, run_async, handle_error
from aun_cli.output import output_json, output_dict, is_json_mode, set_json_mode


def status(ctx: typer.Context) -> None:
    """显示连接状态"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            result = await client.status()
            return {
                "aid": client.aid,
                "gateway": client._gateway_url,
                "state": client.state,
                "status": result,
            }

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
    else:
        output_dict({
            "AID": result.get("aid", ""),
            "Gateway": result.get("gateway", ""),
            "State": result.get("state", ""),
        })


def ping(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="目标 AID"),
    count: int = typer.Option(1, "--count", "-c", help="ping 次数"),
) -> None:
    """验证目标 AID 可达性"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            results = []
            for _ in range(count):
                t0 = time.time()
                resp = await client.ping({"target": target})
                latency_ms = int((time.time() - t0) * 1000)
                results.append({"response": resp, "latency_ms": latency_ms})
            return results

    try:
        results = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json({"target": target, "results": results})
    else:
        for r in results:
            print(f"  {target} reachable (latency: {r['latency_ms']}ms)")
