from __future__ import annotations

from typing import Optional

import typer

from aun_cli.adapter import CLISession, run_async, handle_error, resolve_profile_config, make_aid_store
from aun_cli.config import get_profile, set_profile
from aun_cli.output import output_dict, output_success, output_json, output_table, is_json_mode, set_json_mode

identity_app = typer.Typer(name="identity", help="身份管理", no_args_is_help=True)


def _unwrap_result(result, action: str):
    if result.ok and result.data is not None:
        return result.data
    message = result.error.message if result.error else f"{action} failed"
    raise RuntimeError(message)


def _diagnose_payload(data: dict) -> dict:
    local_raw = data.get("local", {}) if isinstance(data, dict) else {}
    remote_raw = data.get("remote", {}) if isinstance(data, dict) else {}
    local_cert = bool(local_raw.get("cert") or data.get("local_valid") or data.get("localValid"))
    local_key = bool(local_raw.get("private_key") or data.get("local_valid") or data.get("localValid"))
    remote_exists = data.get("remote_registered", data.get("remoteRegistered", remote_raw.get("exists")))
    status = str(data.get("status") or "")
    suggestions = data.get("suggestions") if isinstance(data.get("suggestions"), list) else []
    return {
        "aid": data.get("aid"),
        "status": status,
        "can_register": status == "available",
        "localValid": bool(data.get("local_valid", data.get("localValid", False))),
        "remoteRegistered": bool(data.get("remote_registered", data.get("remoteRegistered", False))),
        "certMatch": bool(data.get("cert_match", data.get("certMatch", False))),
        "suggestions": suggestions,
        "local": {
            "exists": local_cert or local_key,
            "complete": local_cert and local_key,
            "private_key": local_key,
            "public_key": local_cert,
            "certificate": {
                "present": local_cert,
                "valid": local_cert,
                "expired": False,
                "not_after": "",
                "fingerprint": "",
            },
            "issues": [local_raw["error"]["message"]] if isinstance(local_raw.get("error"), dict) else [],
        },
        "remote": {
            "checked": bool(remote_raw.get("checked")),
            "exists": remote_exists,
            "status": "registered" if remote_exists is True else "available" if remote_exists is False else "unknown",
            "source": "pki",
            "error": remote_raw.get("error"),
        },
    }


@identity_app.command("list")
def identity_list(ctx: typer.Context) -> None:
    """列出本地所有身份"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        resolved = resolve_profile_config(ctx)
        store = make_aid_store(resolved)
        try:
            return _unwrap_result(store.list(), "list identities")["identities"]
        finally:
            store.close()

    try:
        identities = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(identities)
    else:
        if not identities:
            print("  (no identities found)")
            return
        headers = ["AID"]
        rows = [[i["aid"]] for i in identities]
        output_table(headers, rows)


@identity_app.command("check")
def identity_check(
    ctx: typer.Context,
    aid: str = typer.Argument(..., help="要检查的 AID"),
) -> None:
    """检查 AID 本地身份材料和远端注册可用性"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        resolved = resolve_profile_config(ctx)
        store = make_aid_store(resolved)
        try:
            return _diagnose_payload(_unwrap_result(await store.diagnose(aid), "diagnose identity"))
        finally:
            store.close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    if is_json_mode():
        output_json(result)
        return

    local = result.get("local", {})
    cert = local.get("certificate", {}) if isinstance(local, dict) else {}
    remote = result.get("remote", {})
    rows = [
        ["AID", result.get("aid", aid)],
        ["Status", result.get("status", "")],
        ["Can Register", str(result.get("can_register"))],
        ["Local Exists", str(local.get("exists", False))],
        ["Local Complete", str(local.get("complete", False))],
        ["Private Key", str(local.get("private_key", False))],
        ["Public Key", str(local.get("public_key", False))],
        ["Certificate", str(cert.get("present", False))],
        ["Certificate Valid", str(cert.get("valid", False))],
        ["Certificate Expired", str(cert.get("expired", False))],
        ["Certificate Not After", str(cert.get("not_after", ""))],
        ["Certificate Fingerprint", str(cert.get("fingerprint", ""))],
        ["Remote Status", str(remote.get("status", ""))],
        ["Remote Source", str(remote.get("source", ""))],
        ["Cert Match", str(result.get("certMatch", False))],
        ["Suggestions", "; ".join(str(item) for item in result.get("suggestions", []))],
    ]
    if remote.get("error"):
        rows.append(["Remote Error", str(remote.get("error"))])
    issues = local.get("issues", []) if isinstance(local, dict) else []
    if issues:
        rows.append(["Local Issues", "; ".join(str(item) for item in issues)])
    output_table(["FIELD", "VALUE"], rows)


def register(
    ctx: typer.Context,
    aid: str = typer.Argument(..., help="要注册的 AID (如 alice@aid.com)"),
) -> None:
    """注册新 AID"""
    set_json_mode(ctx.obj.get("json", False))
    resolved = resolve_profile_config(ctx)
    profile_name = resolved["profile_name"]
    aun_path = resolved["aun_path"]

    async def _run():
        resolved = resolve_profile_config(ctx)
        store = make_aid_store(resolved)
        try:
            return _unwrap_result(await store.register(aid), "register identity")
        finally:
            store.close()

    try:
        result = run_async(_run())
    except Exception as e:
        handle_error(e)
        return

    try:
        profile_data: dict = get_profile(profile_name)
    except KeyError:
        profile_data = {}
    profile_data["aid"] = aid
    profile_data["aun_path"] = aun_path
    set_profile(profile_name, profile_data)

    if is_json_mode():
        output_json({"status": "registered", "aid": aid, "profile": profile_name})
    else:
        output_success(f"Registered: {aid} (profile: {profile_name})")


def login(
    ctx: typer.Context,
    aid: Optional[str] = typer.Argument(None, help="要登录的 AID（默认使用 profile 中的 AID）"),
) -> None:
    """登录已有 AID（验证密钥可用，刷新 token）"""
    set_json_mode(ctx.obj.get("json", False))

    async def _run():
        resolved = resolve_profile_config(ctx)
        login_aid = aid or resolved["aid"]
        if not login_aid:
            raise typer.BadParameter("No AID specified and no default AID in profile")
        async with CLISession(ctx, aid=login_aid) as client:
            return {"aid": client.aid, "state": client.state}

    try:
        result = run_async(_run())
    except typer.BadParameter as e:
        from aun_cli.output import output_error
        output_error(str(e), code=2)
        raise typer.Exit(2)
    except Exception as e:
        handle_error(e)
        return

    # 登录成功后更新 profile 中的 aid，后续命令自动使用
    resolved = resolve_profile_config(ctx)
    profile_name = resolved["profile_name"]
    from aun_cli.config import get_profile, set_profile as _set_profile
    try:
        prof = get_profile(profile_name)
    except KeyError:
        prof = {}
    prof["aid"] = result["aid"]
    if resolved["aun_path"]:
        prof["aun_path"] = resolved["aun_path"]
    _set_profile(profile_name, prof)

    if is_json_mode():
        output_json({"status": "authenticated", "aid": result["aid"]})
    else:
        output_success(f"Authenticated: {result['aid']}")


def whoami(ctx: typer.Context) -> None:
    """显示当前身份信息"""
    set_json_mode(ctx.obj.get("json", False))
    resolved = resolve_profile_config(ctx)

    info = {
        "AID": resolved["aid"] or "(not set)",
        "Profile": resolved["profile_name"],
        "Data Path": resolved["aun_path"],
    }

    if is_json_mode():
        output_json(info)
    else:
        output_dict(info)
