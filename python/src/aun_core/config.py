from __future__ import annotations

import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_INSTANCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DEV_ENV_VALUES = {"development", "dev", "local"}


def _coalesce(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _read_optional_int(value: Any, fallback: int | None) -> int | None:
    if isinstance(value, bool):
        return fallback
    if isinstance(value, (int, float)):
        return int(value)
    return fallback


def _read_bool(value: Any, fallback: bool) -> bool:
    return value if isinstance(value, bool) else fallback


def normalize_instance_id(value: Any, field: str, *, allow_empty: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        if allow_empty:
            return ""
        raise ValueError(f"{field} must be a non-empty string")
    if not _INSTANCE_ID_PATTERN.fullmatch(text):
        raise ValueError(f"{field} contains unsupported characters")
    return text


def get_device_id(aun_root: Path | str | None = None) -> str:
    """获取本设备的稳定 ID。

    存储在 ~/.aun/.device_id（或 aun_root/.device_id）。
    首次调用时自动生成并持久化，后续调用返回同一值。
    """
    root = Path(aun_root) if aun_root else Path.home() / ".aun"
    root.mkdir(parents=True, exist_ok=True)
    device_id_path = root / ".device_id"

    if device_id_path.exists():
        try:
            stored = device_id_path.read_text(encoding="utf-8").strip()
            if stored:
                return normalize_instance_id(stored, "device_id")
        except (OSError, ValueError):
            pass

    device_id = normalize_instance_id(str(uuid.uuid4()), "device_id")
    try:
        device_id_path.write_text(device_id, encoding="utf-8")
        if sys.platform != "win32":
            os.chmod(device_id_path, 0o600)
    except OSError:
        pass
    return device_id


def resolve_verify_ssl_from_env() -> bool:
    """根据运行环境决定是否校验 TLS 证书。

    优先读取 AUN_ENV，其次读取 KITE_ENV。
    development/dev/local 视为开发环境，返回 False；
    其余值或未配置都按生产环境处理，返回 True。
    """
    for key in ("AUN_ENV", "KITE_ENV"):
        raw = os.environ.get(key)
        if raw is None:
            continue
        value = str(raw).strip().lower()
        if not value:
            continue
        return value not in _DEV_ENV_VALUES
    return True


@dataclass(slots=True)
class AUNConfig:
    aun_path: Path = field(default_factory=lambda: Path.home() / ".aun")
    root_ca_path: str | None = None
    seed_password: str | None = None
    discovery_port: int | None = None
    group_e2ee: bool = True
    rotate_on_join: bool = False
    epoch_auto_rotate_interval: int = 0
    old_epoch_retention_seconds: int = 604800
    verify_ssl: bool = field(default_factory=resolve_verify_ssl_from_env)
    require_forward_secrecy: bool = True
    replay_window_seconds: int = 300

    @property
    def device_id(self) -> str:
        """当前设备的稳定 ID（首次自动生成，后续复用）。"""
        return get_device_id(self.aun_path)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "AUNConfig":
        data = dict(raw or {})
        default_verify_ssl = resolve_verify_ssl_from_env()
        aun_path = _coalesce(data, "aun_path", "aunPath") or Path.home() / ".aun"
        seed_password = _coalesce(
            data,
            "seed_password",
            "seedPassword",
            "encryption_seed",
            "encryptionSeed",
        )
        return cls(
            aun_path=Path(aun_path).expanduser(),
            root_ca_path=_coalesce(data, "root_ca_path", "rootCaPath"),
            seed_password=seed_password,
            discovery_port=_read_optional_int(_coalesce(data, "discovery_port", "discoveryPort"), None),
            group_e2ee=True,  # 必备能力，不可配置
            rotate_on_join=_read_bool(_coalesce(data, "rotate_on_join", "rotateOnJoin"), False),
            epoch_auto_rotate_interval=_read_optional_int(
                _coalesce(data, "epoch_auto_rotate_interval", "epochAutoRotateInterval"),
                0,
            ) or 0,
            old_epoch_retention_seconds=_read_optional_int(
                _coalesce(data, "old_epoch_retention_seconds", "oldEpochRetentionSeconds"),
                604800,
            ) or 604800,
            verify_ssl=_read_bool(_coalesce(data, "verify_ssl", "verifySSL", "verifySsl"), default_verify_ssl),
            require_forward_secrecy=_read_bool(
                _coalesce(data, "require_forward_secrecy", "requireForwardSecrecy"),
                True,
            ),
            replay_window_seconds=_read_optional_int(
                _coalesce(data, "replay_window_seconds", "replayWindowSeconds"),
                300,
            ) or 300,
        )
