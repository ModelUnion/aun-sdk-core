from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_PATH_ENV = "AUN_CLI_CONFIG"

_DEFAULT_CONFIG: dict[str, Any] = {
    "default": {
        "profile": "default",
        "output": "table",
        "color": True,
        "timeout": 30,
    },
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
        return dict(_DEFAULT_CONFIG)
    with open(path, "rb") as f:
        data = tomllib.load(f)
    merged = dict(_DEFAULT_CONFIG)
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


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return f"'{v}'"
    return f"'{v}'"
