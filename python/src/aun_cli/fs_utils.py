from __future__ import annotations

import posixpath
import re


_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def is_remote(value: str) -> bool:
    text = str(value or "")
    if _WINDOWS_DRIVE_RE.match(text):
        return False
    if text.startswith(("http://", "https://")):
        return False
    idx = text.find(":")
    return idx > 0


def normalize_path(path: str) -> str:
    raw = str(path or "/").replace("\\", "/").strip()
    if not raw.startswith("/"):
        raw = f"/{raw}"
    raw = re.sub(r"/+", "/", raw)
    normalized = posixpath.normpath(raw)
    return "/" if normalized == "." else normalized


def parse_remote(value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if not is_remote(text):
        raise ValueError(f"不是远程路径: {value}")
    owner, path = text.split(":", 1)
    owner = owner.strip()
    if not owner:
        raise ValueError(f"远程路径缺少 AID: {value}")
    return owner, normalize_path(path or "/")


def format_remote(owner: str, path: str) -> str:
    return f"{owner}:{normalize_path(path)}"
