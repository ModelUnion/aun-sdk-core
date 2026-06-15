#!/usr/bin/env python3
"""同步仓库根 SDK 文档到 Python 包内 skill 文档目录。"""
from __future__ import annotations

import shutil
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
KITE_ROOT = REPO_ROOT.parent
SDK_DOCS = REPO_ROOT / "docs" / "sdk"
PROTOCOL_SOURCE = KITE_ROOT / "docs" / "AUN文档" / "AUN协议"
PROTOCOL_TARGET = REPO_ROOT / "docs" / "protocol"
PACKED_PROTOCOL_TARGET = REPO_ROOT / "python" / "src" / "aun_core" / "_packed_docs" / "protocol"
SKILL_ROOT = REPO_ROOT / "python" / "src" / "aun_core" / "docs" / "skill"
SKILL_SDK_CORE = SKILL_ROOT / "sdk-core"

RPC_ALIASES = {
    "09-message-rpc-manual.md": SKILL_ROOT / "rpc-manual" / "message" / "04-RPC-Manual.md",
    "09-group-rpc-manual.md": SKILL_ROOT / "rpc-manual" / "group" / "04-RPC-Manual.md",
    "09-storage-rpc-manual.md": SKILL_ROOT / "rpc-manual" / "storage" / "04-RPC-Manual.md",
    "09-collab-rpc-manual.md": SKILL_ROOT / "rpc-manual" / "collab" / "04-RPC-Manual.md",
    "09-stream-rpc-manual.md": SKILL_ROOT / "rpc-manual" / "stream" / "04-RPC-Manual.md",
    "09-meta-rpc-manual.md": SKILL_ROOT / "rpc-manual" / "meta" / "01-RPC-Manual.md",
    "09-proxy-rpc-manual.md": SKILL_ROOT / "rpc-manual" / "proxy" / "04-RPC-Manual.md",
}

PROTOCOL_FILES = [
    "06-服务协议.md",
]

COMPAT_ALIASES = {
    "09-payload-reference.md": SKILL_SDK_CORE / "消息Payload参考约定.md",
    **RPC_ALIASES,
}


def copy_file(src: Path, dst: Path) -> None:
    if not src.is_file():
        raise FileNotFoundError(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def main() -> int:
    if not SDK_DOCS.is_dir():
        raise FileNotFoundError(SDK_DOCS)

    copied = 0
    for src in sorted(SDK_DOCS.glob("*.md")):
        copy_file(src, SKILL_SDK_CORE / src.name)
        copied += 1
        alias = COMPAT_ALIASES.get(src.name)
        if alias is not None:
            copy_file(src, alias)
            copied += 1

    for name in PROTOCOL_FILES:
        copy_file(PROTOCOL_SOURCE / name, PROTOCOL_TARGET / name)
        copy_file(PROTOCOL_SOURCE / name, PACKED_PROTOCOL_TARGET / name)
        copied += 1
        copied += 1

    print(f"[sync_docs] copied {copied} SDK doc files/aliases to {SKILL_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
