from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_PATH_ENV = "AUN_CLI_CONFIG"
PROFILE_ENV = "AUN_PROFILE"
SESSION_ID_ENV = "AUN_CLI_SESSION_ID"
STATE_DIR_ENV = "AUN_CLI_STATE_DIR"

_TERMINAL_SESSION_ENV_KEYS = (
    "WT_SESSION",
    "WEZTERM_PANE",
    "TMUX_PANE",
    "TERM_SESSION_ID",
    "KITTY_WINDOW_ID",
    "VSCODE_IPC_HOOK_CLI",
    "SSH_TTY",
)

_DEFAULT_CONFIG: dict[str, Any] = {
    "default": {
        "profile": "default",
        "output": "table",
        "color": True,
        "timeout": 30,
    },
    "profiles": {},
}


def _default_config_copy() -> dict[str, Any]:
    return {
        "default": dict(_DEFAULT_CONFIG["default"]),
        "profiles": {},
    }


def _config_path() -> Path:
    env = os.environ.get(CONFIG_PATH_ENV)
    if env:
        return Path(env)
    return Path.home() / ".aun" / "cli.toml"


def load_config() -> dict[str, Any]:
    path = _config_path()
    if not path.exists():
        return _default_config_copy()
    with open(path, "rb") as f:
        data = tomllib.load(f)
    merged = _default_config_copy()
    if "default" in data:
        merged["default"] = dict(_DEFAULT_CONFIG["default"])
        merged["default"].update(data["default"])
    if "profiles" in data:
        merged["profiles"] = data["profiles"]
    return merged


def save_config(config: dict[str, Any]) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if "default" in config:
        lines.append("[default]")
        for k, v in config["default"].items():
            lines.append(f"{k} = {_toml_value(v)}")
        lines.append("")
    for name, prof in config.get("profiles", {}).items():
        lines.append(f"[profiles.{name}]")
        for k, v in prof.items():
            lines.append(f"{k} = {_toml_value(v)}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def get_profile(name: str) -> dict[str, Any]:
    cfg = load_config()
    profiles = cfg.get("profiles", {})
    if name not in profiles:
        raise KeyError(f"profile '{name}' not found")
    return profiles[name]


def set_profile(name: str, data: dict[str, Any]) -> None:
    cfg = load_config()
    if "profiles" not in cfg:
        cfg["profiles"] = {}
    cfg["profiles"][name] = data
    save_config(cfg)


def get_default_profile_name() -> str:
    cfg = load_config()
    return cfg.get("default", {}).get("profile", "default")


def _state_dir() -> Path:
    env = os.environ.get(STATE_DIR_ENV)
    if env:
        return Path(env)
    return _config_path().parent / "cli-sessions"


def _raw_terminal_session_id() -> tuple[str, str]:
    explicit = os.environ.get(SESSION_ID_ENV)
    if explicit:
        return SESSION_ID_ENV, explicit
    for key in _TERMINAL_SESSION_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            return key, value
    return "PPID", str(os.getppid())


def get_terminal_session_id() -> str:
    """返回当前终端标签页/窗格的稳定状态 ID。"""
    source, value = _raw_terminal_session_id()
    raw = f"{source}:{value}"
    digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    prefix = "".join(ch.lower() if ch.isalnum() else "-" for ch in source).strip("-")
    return f"{prefix}-{digest}"


def _tab_state_path() -> Path:
    return _state_dir() / f"{get_terminal_session_id()}.json"


def get_tab_profile_name() -> str | None:
    path = _tab_state_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    profile = data.get("profile")
    if isinstance(profile, str) and profile:
        return profile
    return None


def set_tab_profile_name(name: str) -> None:
    path = _tab_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "profile": name,
        "session_id": get_terminal_session_id(),
    }
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def get_effective_profile_name(explicit_profile: str | None = None) -> tuple[str, str]:
    if explicit_profile:
        return explicit_profile, "command"
    env_profile = os.environ.get(PROFILE_ENV)
    if env_profile:
        return env_profile, "env"
    tab_profile = get_tab_profile_name()
    if tab_profile:
        return tab_profile, "tab"
    return get_default_profile_name(), "default"


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return f"'{v}'"
    return f"'{v}'"
