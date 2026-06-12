from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def normalize_display_path(path: Any) -> str:
    raw = _text(path).replace("\\", "/").strip()
    if not raw:
        return "/"
    return raw if raw.startswith("/") else f"/{raw}"


def name_from_path(path: str) -> str:
    cleaned = normalize_display_path(path).rstrip("/")
    if not cleaned or cleaned == "/":
        return "/"
    return cleaned.rsplit("/", 1)[-1]


@dataclass(slots=True)
class NodeView:
    type: str
    path: str
    name: str
    owner: str
    bucket: str = "default"
    size: int = 0
    mtime: int = 0
    content_type: str = ""
    version: int = 0
    mode: str = ""
    is_public: bool = False
    object_id: str = ""
    folder_id: str = ""
    target: str = ""
    mount_source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_object(cls, raw: dict[str, Any]) -> "NodeView":
        path = normalize_display_path(raw.get("path") or raw.get("object_key"))
        return cls(
            type="file",
            path=path,
            name=_text(raw.get("name")) or name_from_path(path),
            owner=_text(raw.get("owner") or raw.get("owner_aid")),
            bucket=_text(raw.get("bucket"), "default") or "default",
            size=_int(raw.get("size") if "size" in raw else raw.get("size_bytes")),
            mtime=_int(raw.get("mtime") if "mtime" in raw else raw.get("updated_at")),
            content_type=_text(raw.get("content_type")),
            version=_int(raw.get("version")),
            mode=_text(raw.get("mode")),
            is_public=not _bool(raw.get("is_private"), True),
            object_id=_text(raw.get("object_id")),
            metadata=dict(raw.get("metadata") or {}),
        )

    @classmethod
    def from_folder(cls, raw: dict[str, Any]) -> "NodeView":
        path = normalize_display_path(raw.get("path"))
        return cls(
            type="dir",
            path=path,
            name=_text(raw.get("name")) or name_from_path(path),
            owner=_text(raw.get("owner") or raw.get("owner_aid")),
            bucket=_text(raw.get("bucket"), "default") or "default",
            mtime=_int(raw.get("mtime") if "mtime" in raw else raw.get("updated_at")),
            version=_int(raw.get("version")),
            mode=_text(raw.get("mode")),
            folder_id=_text(raw.get("folder_id")),
            metadata=dict(raw.get("metadata") or {}),
        )

    @classmethod
    def from_any(cls, raw: dict[str, Any]) -> "NodeView":
        node_type = _text(raw.get("type") or raw.get("node_type")).lower()
        if node_type in {"folder", "dir", "directory"}:
            return cls.from_folder(raw)
        if node_type in {"symlink", "link"}:
            path = normalize_display_path(raw.get("path"))
            node = cls.from_folder(raw)
            node.type = "symlink"
            node.path = path
            node.name = _text(raw.get("name")) or name_from_path(path)
            node.target = _text(raw.get("target"))
            if "dangling" in raw:
                node.metadata = {**node.metadata, "dangling": _bool(raw.get("dangling"))}
            return node
        if node_type == "mount":
            path = normalize_display_path(raw.get("path"))
            node = cls.from_folder(raw)
            node.type = "mount"
            node.path = path
            node.name = _text(raw.get("name")) or name_from_path(path)
            node.mount_source = _text(raw.get("mount_source"))
            return node
        return cls.from_object(raw)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ObjectView(NodeView):
    sha256: str = ""
    etag: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ObjectView":
        base = NodeView.from_object(raw)
        return cls(
            **base.to_dict(),
            sha256=_text(raw.get("sha256")),
            etag=_text(raw.get("etag")),
        )


@dataclass(slots=True)
class DownloadResult:
    path: str
    local_path: str
    size: int
    sha256: str = ""
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RemoveResult:
    path: str
    removed_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class UsageView:
    owner: str
    quota_bytes: int
    used_bytes: int
    avail_bytes: int
    object_count: int

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "UsageView":
        quota = _int(raw.get("quota_bytes") if "quota_bytes" in raw else raw.get("quota_total_bytes"))
        used = _int(raw.get("used_bytes") if "used_bytes" in raw else raw.get("quota_used_bytes"))
        return cls(
            owner=_text(raw.get("owner") or raw.get("owner_aid")),
            quota_bytes=quota,
            used_bytes=used,
            avail_bytes=max(0, quota - used) if quota else 0,
            object_count=_int(raw.get("object_count")),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def to_plain(value: Any) -> Any:
    if isinstance(value, list):
        return [to_plain(item) for item in value]
    if isinstance(value, tuple):
        return [to_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: to_plain(item) for key, item in value.items()}
    if is_dataclass(value):
        return asdict(value)
    return value
