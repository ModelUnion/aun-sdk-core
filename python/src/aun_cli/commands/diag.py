from __future__ import annotations

import time
from pathlib import Path
import typer

from aun_cli.adapter import CLISession, run_async, handle_error, resolve_profile_config, make_aid_store
from aun_cli.output import output_json, output_dict, output_error, is_json_mode, set_json_mode


def _check_private_key(resolved: dict, aid: str) -> tuple[bool, str]:
    """通过 AIDStore 检查当前身份私钥。"""
    store = make_aid_store(resolved)
    try:
        loaded = store.load(aid)
        if not loaded.ok or loaded.data is None:
            return False, loaded.error.message if loaded.error else "not found"
        identity = loaded.data["aid"]
        return (True, "P-256") if identity.is_private_key_valid() else (False, "not found")
    except Exception as exc:
        return False, str(exc) or type(exc).__name__
    finally:
        store.close()


def status(ctx: typer.Context) -> None:
    """显示连接状态"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        async with CLISession(ctx) as client:
            result = await client.call("meta.status", {})
            return {
                "aid": client.aid,
                "gateway": client.gateway_url,
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
                resp = await client.call("meta.ping", {"target": target})
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


def doctor(ctx: typer.Context) -> None:
    """一键健康检查"""
    set_json_mode(ctx.obj.get("json", False))
    resolved = resolve_profile_config(ctx)
    checks: list[dict] = []

    profile_ok = bool(resolved["profile_name"])
    checks.append({"name": "Profile exists", "ok": profile_ok,
                   "detail": resolved["profile_name"]})

    aid = resolved["aid"]
    checks.append({"name": "AID configured", "ok": bool(aid),
                   "detail": aid or "(not set)"})

    aun_path = Path(resolved["aun_path"])
    path_ok = aun_path.exists()
    checks.append({"name": "Data directory exists", "ok": path_ok,
                   "detail": str(aun_path)})

    key_ok = False
    key_detail = "not checked"
    if aid and path_ok:
        key_ok, key_detail = _check_private_key(resolved, aid)
    checks.append({"name": "Private key intact", "ok": key_ok,
                   "detail": key_detail})

    gateway_ok = False
    auth_ok = False
    gateway_url = ""

    if aid:
        async def _check():
            nonlocal gateway_ok, auth_ok
            nonlocal gateway_url
            async with CLISession(ctx, aid=aid) as client:
                gateway_url = client.gateway_url or ""
                gateway_ok = bool(client.is_ready)
                auth_ok = client.state.value == "ready"

        try:
            run_async(_check())
        except Exception:
            pass

    checks.append({"name": "Gateway reachable", "ok": gateway_ok,
                   "detail": gateway_url or "(auto discovery pending)"})
    checks.append({"name": "Authentication", "ok": auth_ok,
                   "detail": "success" if auth_ok else "failed"})

    passed = sum(1 for c in checks if c["ok"])
    total = len(checks)

    if is_json_mode():
        output_json({"checks": checks, "passed": passed, "total": total})
    else:
        for c in checks:
            mark = "+" if c["ok"] else "x"
            print(f"  [{mark}] {c['name']}: {c['detail']}")
        print(f"\n  {passed}/{total} checks passed")


def logs(
    ctx: typer.Context,
    tail: int = typer.Option(50, "--tail", "-n", help="显示最后 N 行"),
    follow: bool = typer.Option(False, "--follow", "-f", help="实时跟踪"),
) -> None:
    """查看本地 SDK 日志"""
    set_json_mode(ctx.obj.get("json", False))
    resolved = resolve_profile_config(ctx)
    aun_path = Path(resolved["aun_path"])
    log_dir = aun_path / "logs"

    if not log_dir.exists():
        log_dir = Path.home() / ".aun" / "logs"

    if not log_dir.exists():
        output_error("No log directory found", hint="Enable debug mode to generate logs")
        raise typer.Exit(1)

    log_files = sorted(log_dir.glob("python-sdk-*.log"), key=lambda f: f.name, reverse=True)
    if not log_files:
        output_error("No log files found", hint="Enable debug mode to generate logs")
        raise typer.Exit(1)

    latest = log_files[0]

    if not follow:
        lines = latest.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-tail:]:
            print(line)
        return

    import time as _time
    try:
        with open(latest, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            for line in all_lines[-tail:]:
                print(line.rstrip())
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    print(line.rstrip(), flush=True)
                else:
                    _time.sleep(0.3)
    except KeyboardInterrupt:
        pass
