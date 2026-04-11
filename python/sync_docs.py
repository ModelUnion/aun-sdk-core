#!/usr/bin/env python3
"""
sync_docs.py — 同步文档到多个目标。

同步规则：
  1. skill 文档（aun-skill/…/aun-sdk/）→ python/src/aun_core/docs/skill/
  2. AUN 协议文档                       → docs/protocol/
  3. docs/sdk（排除 *-rpc-manual.md）   → aun-skill/…/sdk-core/
  4. rpc-manual 各服务手册              → python/src/aun_core/docs/skill/rpc-manual/
                                         + docs/sdk/{service}-rpc-manual.md

用法：
  python sync_docs.py              # 正常同步
  python sync_docs.py --dry-run    # 仅预览，不实际操作
  python sync_docs.py --clean      # 同步前先清空脚本负责的目标目录
"""
import argparse
import shutil
from pathlib import Path

# ── 路径配置 ──────────────────────────────────────────────

SKILL_SRC = Path(r"D:/modelunion/aun-skill/.claude/skills/aun-sdk")
PROTOCOL_SRC = Path(r"D:/modelunion/kite/docs/AUN文档/AUN协议")

PYTHON_DIR = Path(__file__).resolve().parent
REPO_ROOT = PYTHON_DIR.parent

SKILL_DST = PYTHON_DIR / "src" / "aun_core" / "docs" / "skill"
PROTOCOL_DST = REPO_ROOT / "docs" / "protocol"

# docs/sdk → skill/sdk-core（排除 rpc-manual）
SDK_DOCS_SRC = REPO_ROOT / "docs" / "sdk"
SDK_CORE_DST = SKILL_SRC / "sdk-core"

# rpc-manual 源 → 两个目标
RPC_MANUAL_SRC = SKILL_SRC / "rpc-manual"
RPC_MANUAL_SDK_DST = REPO_ROOT / "docs" / "sdk"  # 重命名为 {service}-rpc-manual.md

# skill 目录下要同步的子目录/文件（排除 SKILL.md 本身）
SKILL_ITEMS = [
    "methods",
    "sdk-core",
    "rpc-manual",
    "examples",
    "docs",
    "checklists",
    "references",
    "总体架构.md",
]


# ── 同步逻辑 ──────────────────────────────────────────────

def sync_item(src: Path, dst: Path, *, dry_run: bool = False) -> int:
    """复制单个文件或目录，返回复制的文件数。"""
    count = 0
    if src.is_file():
        if dry_run:
            print(f"  COPY {src} -> {dst}")
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        count = 1
    elif src.is_dir():
        for item in sorted(src.rglob("*")):
            if item.is_file():
                rel = item.relative_to(src)
                target = dst / rel
                if dry_run:
                    print(f"  COPY {item} -> {target}")
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, target)
                count += 1
    else:
        print(f"  SKIP {src} (not found)")
    return count


def sync_sdk_docs_to_skill(*, dry_run: bool = False) -> int:
    """docs/sdk 下除 *-rpc-manual.md 外的文件同步到 skill/sdk-core。"""
    if not SDK_DOCS_SRC.exists():
        print(f"  SKIP {SDK_DOCS_SRC} (not found)")
        return 0

    count = 0
    for item in sorted(SDK_DOCS_SRC.iterdir()):
        if not item.is_file():
            continue
        # 排除 rpc 手册
        if item.name.endswith("-rpc-manual.md"):
            continue
        target = SDK_CORE_DST / item.name
        if dry_run:
            print(f"  COPY {item} -> {target}")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
        count += 1
    return count


def sync_rpc_manual_to_sdk_docs(*, dry_run: bool = False) -> int:
    """rpc-manual/{service}/04-RPC-Manual.md → docs/sdk/{service}-rpc-manual.md"""
    if not RPC_MANUAL_SRC.exists():
        print(f"  SKIP {RPC_MANUAL_SRC} (not found)")
        return 0

    count = 0
    for service_dir in sorted(RPC_MANUAL_SRC.iterdir()):
        if not service_dir.is_dir():
            continue
        service_name = service_dir.name  # group, message, meta, storage, stream
        # 找到该服务目录下的 RPC 手册文件（通常是 *-RPC-Manual.md）
        for md_file in sorted(service_dir.glob("*RPC-Manual.md")):
            target_name = f"{service_name}-rpc-manual.md"
            target = RPC_MANUAL_SDK_DST / target_name
            if dry_run:
                print(f"  COPY {md_file} -> {target}")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(md_file, target)
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="同步 skill 文档与 AUN 协议文档")
    parser.add_argument("--dry-run", action="store_true", help="仅预览，不实际复制")
    parser.add_argument("--clean", action="store_true", help="同步前先清空脚本负责的目标目录")
    args = parser.parse_args()

    # 前置检查
    for label, path in [("Skill", SKILL_SRC), ("Protocol", PROTOCOL_SRC)]:
        if not path.exists():
            print(f"ERROR: {label} 源目录不存在: {path}")
            return 1

    # 清理
    if args.clean:
        for target in [SKILL_DST, PROTOCOL_DST]:
            if not target.exists():
                continue
            if args.dry_run:
                print(f"[dry-run] CLEAN {target}")
            else:
                shutil.rmtree(target)
                print(f"CLEANED {target}")

    total = 0

    # 1) docs/sdk（排除 *-rpc-manual.md）→ skill/sdk-core
    #    必须先于步骤3执行，确保 skill/sdk-core 拿到最新内容后再被同步到 python 包内
    print(f"\n=== SDK 文档 → Skill/sdk-core ===")
    print(f"  FROM: {SDK_DOCS_SRC}")
    print(f"  TO:   {SDK_CORE_DST}\n")
    total += sync_sdk_docs_to_skill(dry_run=args.dry_run)

    # 2) rpc-manual 各服务手册 → docs/sdk/{service}-rpc-manual.md
    print(f"\n=== RPC 手册 → docs/sdk ===")
    print(f"  FROM: {RPC_MANUAL_SRC}")
    print(f"  TO:   {RPC_MANUAL_SDK_DST}\n")
    total += sync_rpc_manual_to_sdk_docs(dry_run=args.dry_run)

    # 3) 同步 skill 文档 → python/src/aun_core/docs/skill/
    #    此时 skill/sdk-core 已包含步骤1写入的最新文件
    print(f"\n=== Skill 文档 ===")
    print(f"  FROM: {SKILL_SRC}")
    print(f"  TO:   {SKILL_DST}\n")
    for name in SKILL_ITEMS:
        src = SKILL_SRC / name
        dst = SKILL_DST / name
        n = sync_item(src, dst, dry_run=args.dry_run)
        total += n

    # 4) 同步 AUN 协议文档
    print(f"\n=== AUN 协议文档 ===")
    print(f"  FROM: {PROTOCOL_SRC}")
    print(f"  TO:   {PROTOCOL_DST}\n")
    total += sync_item(PROTOCOL_SRC, PROTOCOL_DST, dry_run=args.dry_run)

    prefix = "[dry-run] " if args.dry_run else ""
    print(f"\n{prefix}Done. {total} files synced.")
    print(f"  Skill     -> {SKILL_DST}")
    print(f"  Protocol  -> {PROTOCOL_DST}")
    print(f"  SDK→Skill -> {SDK_CORE_DST}")
    print(f"  RPC→SDK   -> {RPC_MANUAL_SDK_DST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
