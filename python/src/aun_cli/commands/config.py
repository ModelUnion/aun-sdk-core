from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import typer

from aun_cli.config import (
    get_default_profile_name,
    get_effective_profile_name,
    get_terminal_session_id,
    load_config,
    save_config,
    set_tab_profile_name,
)
from aun_cli.output import output_json, output_dict, output_success, output_table, output_error, is_json_mode, set_json_mode

config_app = typer.Typer(name="config", help="配置管理", no_args_is_help=True)
profile_app = typer.Typer(name="profile", help="Profile 管理", no_args_is_help=True)
config_app.add_typer(profile_app)

_BOOL_TRUE = {"true", "1", "yes", "on"}
_BOOL_FALSE = {"false", "0", "no", "off"}
_PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _parse_value(value: str):
    """将字符串值转为合适的 Python 类型"""
    low = value.lower()
    if low in _BOOL_TRUE:
        return True
    if low in _BOOL_FALSE:
        return False
    try:
        return int(value)
    except ValueError:
        return value


def _validate_profile_name(name: str) -> None:
    if not _PROFILE_NAME_PATTERN.fullmatch(name):
        output_error("Invalid profile name", hint="Use 1-128 chars: letters, digits, dot, underscore or dash", code=2)
        raise typer.Exit(2)


def _default_profile_path(name: str) -> str:
    return str(Path.home() / ".aun" / "profiles" / name)


def _new_profile_data(name: str, aid: Optional[str], aun_path: Optional[str]) -> dict:
    data = {"aun_path": aun_path or _default_profile_path(name)}
    if aid:
        data["aid"] = aid
    return data


@config_app.command("set")
def config_set(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="配置项名称 (如 debug, timeout, output)"),
    value: str = typer.Argument(..., help="配置值"),
) -> None:
    """设置配置项"""
    set_json_mode(ctx.obj.get("json", False))
    cfg = load_config()
    parsed = _parse_value(value)
    cfg["default"][key] = parsed
    save_config(cfg)

    if is_json_mode():
        output_json({"key": key, "value": parsed})
    else:
        output_success(f"{key} = {parsed}")


@config_app.command("get")
def config_get(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="配置项名称"),
) -> None:
    """读取配置项"""
    set_json_mode(ctx.obj.get("json", False))
    cfg = load_config()
    value = cfg.get("default", {}).get(key)

    if value is None:
        from aun_cli.output import output_error
        output_error(f"config key '{key}' not found")
        raise typer.Exit(1)

    if is_json_mode():
        output_json({"key": key, "value": value})
    else:
        print(f"{key} = {value}")


@config_app.command("list")
def config_list(ctx: typer.Context) -> None:
    """显示所有配置"""
    set_json_mode(ctx.obj.get("json", False))
    cfg = load_config()
    defaults = cfg.get("default", {})

    if is_json_mode():
        output_json(defaults)
    else:
        if not defaults:
            print("  (no config)")
            return
        for k, v in defaults.items():
            print(f"  {k} = {v}")


@profile_app.command("list")
def profile_list(ctx: typer.Context) -> None:
    """列出所有 profile"""
    set_json_mode(ctx.obj.get("json", False))
    cfg = load_config()
    profiles = cfg.get("profiles", {})
    current, source = get_effective_profile_name(ctx.obj.get("profile"))
    if source == "default":
        set_tab_profile_name(current)
    default_profile = get_default_profile_name()

    if is_json_mode():
        output_json({
            "current": current,
            "source": source,
            "default_for_new_tabs": default_profile,
            "profiles": profiles,
        })
    else:
        if not profiles:
            print("  (no profiles)")
            return
        headers = ["PROFILE", "AID", "ACTIVE_GROUP", "CURRENT", "NEW_TAB_DEFAULT"]
        rows = []
        for name, prof in profiles.items():
            current_mark = "*" if name == current else ""
            default_mark = "*" if name == default_profile else ""
            rows.append([
                name,
                prof.get("aid", ""),
                prof.get("active_group", ""),
                current_mark,
                default_mark,
            ])
        output_table(headers, rows)


@profile_app.command("current")
def profile_current(ctx: typer.Context) -> None:
    """显示当前终端标签页 profile"""
    set_json_mode(ctx.obj.get("json", False))
    cfg = load_config()
    profiles = cfg.get("profiles", {})
    current, source = get_effective_profile_name(ctx.obj.get("profile"))
    if source == "default":
        set_tab_profile_name(current)
    prof = profiles.get(current, {})
    default_profile = get_default_profile_name()

    data = {
        "Profile": current,
        "Source": source,
        "Default for new tabs": default_profile,
        "AID": prof.get("aid", ""),
        "Active Group": prof.get("active_group", ""),
        "Session": get_terminal_session_id(),
    }
    if is_json_mode():
        output_json({
            "profile": current,
            "source": source,
            "default_for_new_tabs": default_profile,
            "aid": prof.get("aid", ""),
            "active_group": prof.get("active_group", ""),
            "session_id": get_terminal_session_id(),
        })
    else:
        output_dict(data)


@profile_app.command("create")
def profile_create(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="要创建的 profile 名称"),
    aid: Optional[str] = typer.Option(None, "--aid", help="绑定的默认 AID"),
    aun_path: Optional[str] = typer.Option(None, "--aun-path", help="profile 数据目录"),
    switch: bool = typer.Option(True, "--switch/--no-switch", help="创建后切换当前终端标签页到该 profile"),
) -> None:
    """创建 profile"""
    set_json_mode(ctx.obj.get("json", False))
    _validate_profile_name(name)
    cfg = load_config()
    profiles = cfg.setdefault("profiles", {})

    if name in profiles:
        output_error(f"Profile '{name}' already exists")
        raise typer.Exit(1)

    profiles[name] = _new_profile_data(name, aid, aun_path)
    if switch:
        cfg.setdefault("default", {})
        cfg["default"]["profile"] = name
        set_tab_profile_name(name)
    save_config(cfg)

    if is_json_mode():
        output_json({
            "created": name,
            "profile": profiles[name],
            "switched": switch,
            "default_for_new_tabs": cfg.get("default", {}).get("profile", "default"),
        })
    else:
        suffix = " and switched current tab" if switch else ""
        output_success(f"Created profile: {name}{suffix}")


@profile_app.command("switch")
def profile_switch(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="要切换到的 profile 名称"),
    create: bool = typer.Option(False, "--create", help="profile 不存在时创建"),
    aid: Optional[str] = typer.Option(None, "--aid", help="创建时绑定的默认 AID"),
    aun_path: Optional[str] = typer.Option(None, "--aun-path", help="创建时使用的 profile 数据目录"),
) -> None:
    """切换当前终端标签页 profile"""
    set_json_mode(ctx.obj.get("json", False))
    _validate_profile_name(name)
    cfg = load_config()
    profiles = cfg.setdefault("profiles", {})

    if name not in profiles:
        if not create:
            output_error(f"Profile '{name}' not found", hint=f"Create it first: aun profile create {name}")
            raise typer.Exit(1)
        profiles[name] = _new_profile_data(name, aid, aun_path)

    cfg.setdefault("default", {})
    cfg["default"]["profile"] = name
    save_config(cfg)
    set_tab_profile_name(name)

    if is_json_mode():
        output_json({
            "switched_to": name,
            "aid": profiles[name].get("aid", ""),
            "created": create,
            "scope": "current_tab",
            "default_for_new_tabs": name,
        })
    else:
        aid = profiles[name].get("aid", "(no aid)")
        created = "Created and switched" if create else "Switched current tab profile"
        output_success(f"{created}: {name} ({aid}); new tabs default to: {name}")
