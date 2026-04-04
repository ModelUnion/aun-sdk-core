from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _resolve_default_aun_path() -> Path:
    home_root = Path.home() / ".aun"
    cwd = Path.cwd().resolve()
    app_dir = cwd.name or "aun-app"
    return _bind_app_instance(home_root, app_dir, cwd)


def _bind_app_instance(home_root: Path, app_dir: str, app_path: Path) -> Path:
    home_root.mkdir(parents=True, exist_ok=True)
    candidate = home_root / app_dir
    suffix = 0
    while True:
        current = candidate if suffix == 0 else home_root / f"{app_dir}~{suffix}"
        bound = _read_bound_cwd(current)
        if not current.exists():
            current.mkdir(parents=True, exist_ok=True)
            _write_bound_cwd(current, app_path)
            return current
        if bound is None:
            _write_bound_cwd(current, app_path)
            return current
        if bound == app_path:
            return current
        suffix += 1


def _bound_cwd_path(root: Path) -> Path:
    return root / ".cwd"


def _read_bound_cwd(root: Path) -> Path | None:
    marker = _bound_cwd_path(root)
    if not marker.exists():
        return None
    try:
        raw = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None
    try:
        return Path(raw).resolve()
    except OSError:
        return Path(raw)


def _write_bound_cwd(root: Path, app_path: Path) -> None:
    try:
        _bound_cwd_path(root).write_text(str(app_path), encoding="utf-8")
    except OSError:
        return


def _default_aun_path() -> Path:
    return _resolve_default_aun_path()


@dataclass(slots=True)
class AUNConfig:
    aun_path: Path = field(default_factory=_default_aun_path)
    root_ca_path: str | None = None
    encryption_seed: str | None = None
    discovery_port: int | None = None
    # 群组 E2EE 配置（group_e2ee 是必选能力，始终为 True）
    group_e2ee: bool = True
    rotate_on_join: bool = False
    epoch_auto_rotate_interval: int = 0  # 秒，0=禁用
    old_epoch_retention_seconds: int = 604800  # 7 天
    verify_ssl: bool = True  # TLS 证书验证（开发环境可设为 False）
    require_forward_secrecy: bool = True  # 严格模式：拒绝无前向保密的 E2EE 降级
    replay_window_seconds: int = 300  # 防重放时间窗口（秒）

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "AUNConfig":
        data = dict(raw or {})
        aun_path = data.get("aun_path")
        if aun_path is None:
            aun_path = _default_aun_path()
        dp = data.get("discovery_port")
        return cls(
            aun_path=Path(aun_path).expanduser(),
            root_ca_path=data.get("root_ca_path"),
            encryption_seed=data.get("encryption_seed"),
            discovery_port=int(dp) if dp is not None else None,
            # group_e2ee 是必选能力，忽略用户传入值
            rotate_on_join=bool(data.get("rotate_on_join", False)),
            epoch_auto_rotate_interval=int(data.get("epoch_auto_rotate_interval", 0)),
            old_epoch_retention_seconds=int(data.get("old_epoch_retention_seconds", 604800)),
            verify_ssl=bool(data.get("verify_ssl", True)),
            require_forward_secrecy=bool(data.get("require_forward_secrecy", True)),
            replay_window_seconds=int(data.get("replay_window_seconds", 300)),
        )
