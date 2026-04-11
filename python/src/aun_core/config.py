from __future__ import annotations

import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def get_device_id(aun_root: Path | str | None = None, sqlite_backup: Any = None) -> str:
    """获取本设备的稳定 ID。

    存储在 ~/.aun/.device_id（或 aun_root/.device_id）。
    首次调用时自动生成并持久化，后续调用返回同一值。
    同一台机器上所有 SDK 实例共享同一个 device_id。
    支持 SQLite 备份：文件丢失时从 SQLite 恢复。
    """
    root = Path(aun_root) if aun_root else Path.home() / ".aun"
    root.mkdir(parents=True, exist_ok=True)
    device_id_path = root / ".device_id"
    device_id: str | None = None
    source = ""

    # 1. 先读文件
    if device_id_path.exists():
        try:
            stored = device_id_path.read_text(encoding="utf-8").strip()
            if stored:
                device_id = stored
                source = "file"
        except OSError:
            pass

    # 2. 文件没有 → 读 SQLite
    if device_id is None and sqlite_backup:
        restored = sqlite_backup.restore_device_id()
        if restored:
            device_id = restored
            source = "sqlite"
            try:
                device_id_path.write_text(device_id, encoding="utf-8")
                if sys.platform != "win32":
                    os.chmod(device_id_path, 0o600)
            except OSError:
                pass

    # 3. 都没有 → 生成新 ID
    if device_id is None:
        device_id = str(uuid.uuid4())
        source = "new"
        try:
            device_id_path.write_text(device_id, encoding="utf-8")
            if sys.platform != "win32":
                os.chmod(device_id_path, 0o600)
        except OSError:
            pass

    # 双写：确保 SQLite 中也有
    if sqlite_backup and source != "sqlite":
        try:
            sqlite_backup.backup_device_id(device_id)
        except Exception:
            pass

    return device_id


@dataclass(slots=True)
class AUNConfig:
    aun_path: Path = field(default_factory=lambda: Path.home() / ".aun")
    root_ca_path: str | None = None
    encryption_seed: str | None = None
    discovery_port: int | None = None
    group_e2ee: bool = True
    rotate_on_join: bool = False
    epoch_auto_rotate_interval: int = 0
    old_epoch_retention_seconds: int = 604800
    verify_ssl: bool = True
    require_forward_secrecy: bool = True
    replay_window_seconds: int = 300

    @property
    def device_id(self) -> str:
        """当前设备的稳定 ID（首次自动生成，后续复用）。"""
        return get_device_id(self.aun_path)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "AUNConfig":
        data = dict(raw or {})
        aun_path = data.get("aun_path") or Path.home() / ".aun"
        dp = data.get("discovery_port")
        return cls(
            aun_path=Path(aun_path).expanduser(),
            root_ca_path=data.get("root_ca_path"),
            encryption_seed=data.get("encryption_seed"),
            discovery_port=int(dp) if dp is not None else None,
            rotate_on_join=bool(data.get("rotate_on_join", False)),
            epoch_auto_rotate_interval=int(data.get("epoch_auto_rotate_interval", 0)),
            old_epoch_retention_seconds=int(data.get("old_epoch_retention_seconds", 604800)),
            verify_ssl=bool(data.get("verify_ssl", True)),
            require_forward_secrecy=bool(data.get("require_forward_secrecy", True)),
            replay_window_seconds=int(data.get("replay_window_seconds", 300)),
        )
