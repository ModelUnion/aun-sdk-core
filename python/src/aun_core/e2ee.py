from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_METADATA_AUTH_FIELD = "_auth"


class ProtectedHeaders:
    """端到端保护的信封元数据，语义接近 HTTP headers。"""

    def __init__(self, values: dict[str, Any] | None = None):
        self._items: dict[str, str] = {}
        if values:
            for key, value in values.items():
                self.set(key, value)

    @staticmethod
    def _normalize_key(key: object) -> str:
        value = str(key or "").strip().lower()
        if not value or not re.fullmatch(r"[a-z0-9_-]+", value):
            raise ValueError("protected header key must match [a-z0-9_-]+")
        if value == _METADATA_AUTH_FIELD:
            raise ValueError("protected header key is reserved")
        return value

    def set(self, key: str, value: object) -> "ProtectedHeaders":
        self._items[self._normalize_key(key)] = "" if value is None else str(value)
        return self

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._items.get(self._normalize_key(key), default)

    def remove(self, key: str) -> "ProtectedHeaders":
        self._items.pop(self._normalize_key(key), None)
        return self

    def to_dict(self) -> dict[str, str]:
        return dict(self._items)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> "ProtectedHeaders":
        return cls(values or {})


def compute_state_hash(
    *,
    group_id: str,
    state_version: int,
    key_epoch: int,
    members: list[dict],
    policy: dict,
    prev_state_hash: str,
) -> str:
    """计算群组状态哈希。"""

    sorted_members = sorted(members, key=lambda m: m["aid"])
    membership_block = "|".join(f"{m['aid']}:{m['role']}" for m in sorted_members)
    policy_block = json.dumps(policy, sort_keys=True, separators=(",", ":")) if policy else ""
    prev_bytes = bytes.fromhex(prev_state_hash) if prev_state_hash else b"\x00" * 32

    data = (
        group_id.encode("utf-8")
        + b"\x00"
        + int(state_version).to_bytes(8, "big")
        + b"\x00"
        + int(key_epoch).to_bytes(8, "big")
        + b"\x00"
        + membership_block.encode("utf-8")
        + b"\x00"
        + policy_block.encode("utf-8")
        + b"\x00"
        + prev_bytes
    )
    return hashlib.sha256(data).hexdigest()
