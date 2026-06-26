from __future__ import annotations

import asyncio
import time
from collections import Counter
from contextlib import contextmanager
from typing import Any, Callable

import typer

from aun_cli.adapter import CLISession, handle_error, resolve_profile_config, run_async, suppress_cli_summary
from aun_cli.output import output_dict, output_json, is_json_mode, set_json_mode


bench_app = typer.Typer(name="bench", help="压测工具", no_args_is_help=True)
bench_group_app = typer.Typer(name="group", help="群组压测", no_args_is_help=True)


def _validate_limits(count: int, concurrency: int, size: int) -> None:
    if count < 1:
        raise typer.BadParameter("--count 必须 >= 1")
    if concurrency < 1:
        raise typer.BadParameter("--concurrency 必须 >= 1")
    if size < 0:
        raise typer.BadParameter("--size 必须 >= 0")


def _payload_text(prefix: str, index: int, size: int) -> str:
    base = f"{prefix}-{index}-"
    if size <= len(base):
        return base[:size]
    return base + ("x" * (size - len(base)))


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, int((percentile / 100) * len(ordered) + 0.999999))
    return ordered[min(rank - 1, len(ordered) - 1)]


def _round_ms(value: float) -> float:
    return round(value, 2)


def _summarize_results(
    *,
    command: str,
    method: str,
    target_label: str,
    target_value: str,
    count: int,
    concurrency: int,
    size: int,
    encrypt: bool,
    started_at: float,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    total_seconds = max(time.perf_counter() - started_at, 0.000001)
    total_ms = int(total_seconds * 1000)
    ok_results = [r for r in results if r["ok"]]
    failed_results = [r for r in results if not r["ok"]]
    latencies = [float(r["ms"]) for r in ok_results]
    error_counts = Counter(str(r.get("error") or "unknown error") for r in failed_results)

    summary = {
        "command": command,
        "method": method,
        target_label: target_value,
        "count": count,
        "concurrency": concurrency,
        "payload_size": size,
        "encrypt": encrypt,
        "ok": len(ok_results),
        "failed": len(failed_results),
        "total_ms": total_ms,
        "rps": round(len(results) / total_seconds, 2),
        "latency_ms": {
            "min": _round_ms(min(latencies)) if latencies else 0.0,
            "avg": _round_ms(sum(latencies) / len(latencies)) if latencies else 0.0,
            "p50": _round_ms(_percentile(latencies, 50)),
            "p95": _round_ms(_percentile(latencies, 95)),
            "p99": _round_ms(_percentile(latencies, 99)),
            "max": _round_ms(max(latencies)) if latencies else 0.0,
        },
        "errors": [
            {"message": message, "count": error_counts[message]}
            for message in sorted(error_counts, key=lambda item: (-error_counts[item], item))[:5]
        ],
    }
    return summary


def _print_summary(summary: dict[str, Any]) -> None:
    if is_json_mode():
        output_json(summary)
        return

    latency = summary["latency_ms"]
    output_dict({
        "Benchmark": summary["command"],
        "Method": summary["method"],
        "Target": summary.get("target") or summary.get("group_id") or "",
        "Count": summary["count"],
        "Concurrency": summary["concurrency"],
        "Payload Size": summary["payload_size"],
        "Encrypt": summary["encrypt"],
        "OK": summary["ok"],
        "Failed": summary["failed"],
        "Total": f"{summary['total_ms']}ms",
        "RPS": summary["rps"],
        "Latency": (
            f"min={latency['min']}ms avg={latency['avg']}ms "
            f"p50={latency['p50']}ms p95={latency['p95']}ms "
            f"p99={latency['p99']}ms max={latency['max']}ms"
        ),
    })
    if summary["errors"]:
        print("  Errors")
        for item in summary["errors"]:
            print(f"    {item['count']}x {item['message']}")


@contextmanager
def _bench_trace_off(ctx: typer.Context):
    ctx.ensure_object(dict)
    had_trace = "trace" in ctx.obj
    previous = ctx.obj.get("trace")
    ctx.obj["trace"] = "off"
    try:
        yield
    finally:
        if had_trace:
            ctx.obj["trace"] = previous
        else:
            ctx.obj.pop("trace", None)


async def _run_benchmark(
    *,
    ctx: typer.Context,
    count: int,
    concurrency: int,
    method: str,
    build_params: Callable[[int], dict[str, Any]],
) -> list[dict[str, Any]]:
    with _bench_trace_off(ctx):
        session = CLISession(ctx)
    async with session as client:
        async def _run_one(index: int) -> dict[str, Any]:
            started = time.perf_counter()
            try:
                await client.call(method, build_params(index))
                return {
                    "ok": True,
                    "ms": (time.perf_counter() - started) * 1000,
                }
            except Exception as exc:
                return {
                    "ok": False,
                    "ms": (time.perf_counter() - started) * 1000,
                    "error": str(exc) or type(exc).__name__,
                }

        results: list[dict[str, Any] | None] = [None] * count
        next_index = 0
        index_lock = asyncio.Lock()

        async def _worker() -> None:
            nonlocal next_index
            while True:
                async with index_lock:
                    if next_index >= count:
                        return
                    index = next_index
                    next_index += 1
                results[index] = await _run_one(index)

        await asyncio.gather(*(_worker() for _ in range(min(count, concurrency))))
        return [result for result in results if result is not None]


@bench_app.command("send")
def bench_send(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="目标 AID"),
    count: int = typer.Option(100, "--count", "-n", help="总发送条数"),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="单 WebSocket 最大 in-flight RPC 数"),
    size: int = typer.Option(64, "--size", help="payload.text 目标字符数"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    no_persist: bool = typer.Option(False, "--no-persist", help="不持久化（临时消息，不写数据库）"),
    prefix: str = typer.Option("bench", "--prefix", help="消息内容前缀"),
) -> None:
    """压测 P2P message.send"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    _validate_limits(count, concurrency, size)
    encrypt = not no_encrypt

    def _params(index: int) -> dict[str, Any]:
        params = {
            "to": target,
            "payload": {"text": _payload_text(prefix, index, size)},
            "encrypt": encrypt,
        }
        if no_persist:
            params["persist_required"] = False
        return params

    started_at = time.perf_counter()
    try:
        results = run_async(_run_benchmark(
            ctx=ctx,
            count=count,
            concurrency=concurrency,
            method="message.send",
            build_params=_params,
        ))
    except Exception as exc:
        handle_error(exc)
        return

    _print_summary(_summarize_results(
        command="bench.send",
        method="message.send",
        target_label="target",
        target_value=target,
        count=count,
        concurrency=concurrency,
        size=size,
        encrypt=encrypt,
        started_at=started_at,
        results=results,
    ))


def _resolve_group_id(ctx: typer.Context, group_id: str | None) -> str:
    resolved_group_id = str(group_id or "").strip()
    if resolved_group_id:
        return resolved_group_id
    active_group = str(resolve_profile_config(ctx).get("active_group") or "").strip()
    if active_group:
        return active_group
    raise typer.BadParameter("未指定 group_id，也没有 active group；请先运行 'aun group use <group_id>'")


@bench_app.command("group-send")
@bench_app.command("group_send")
@bench_group_app.command("send")
def bench_group_send(
    ctx: typer.Context,
    group_id: str | None = typer.Argument(None, help="群组 ID，省略时使用当前 active group"),
    count: int = typer.Option(100, "--count", "-n", help="总发送条数"),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="单 WebSocket 最大 in-flight RPC 数"),
    size: int = typer.Option(64, "--size", help="payload.text 目标字符数"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    prefix: str = typer.Option("bench", "--prefix", help="消息内容前缀"),
) -> None:
    """压测 group.send"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    _validate_limits(count, concurrency, size)
    resolved_group_id = _resolve_group_id(ctx, group_id)
    encrypt = not no_encrypt

    def _params(index: int) -> dict[str, Any]:
        return {
            "group_id": resolved_group_id,
            "payload": {"text": _payload_text(prefix, index, size)},
            "encrypt": encrypt,
        }

    started_at = time.perf_counter()
    try:
        results = run_async(_run_benchmark(
            ctx=ctx,
            count=count,
            concurrency=concurrency,
            method="group.send",
            build_params=_params,
        ))
    except Exception as exc:
        handle_error(exc)
        return

    _print_summary(_summarize_results(
        command="bench.group.send",
        method="group.send",
        target_label="group_id",
        target_value=resolved_group_id,
        count=count,
        concurrency=concurrency,
        size=size,
        encrypt=encrypt,
        started_at=started_at,
        results=results,
    ))


bench_app.add_typer(bench_group_app)

from aun_cli.commands.bench_e2e import autoscale_app, e2e_app

bench_app.add_typer(e2e_app)
bench_app.add_typer(autoscale_app)
