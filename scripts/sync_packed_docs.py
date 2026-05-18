#!/usr/bin/env python3
"""sync_packed_docs.py — 把仓库根 docs/ 中被 git 跟踪的文件同步到指定 SDK 的 _packed_docs/

设计要点：
  - 用 `git ls-files docs/` 取清单 → 自动排除 .gitignore 中的项目（`AUN测试运行指南.md`、
    `superpowers/`、`AUN C++ SDK与四语言SDK Gap分析.md` 等不会进包）。
  - 每次运行先清空目标目录，避免老 SDK 留下已删除的过期文档。
  - 仅复制 docs/，不污染 SDK 源码目录；目标目录加进各 SDK 的 .gitignore，仓库结构不变。

用法：
    python scripts/sync_packed_docs.py python   # 同步到 python/_packed_docs/
    python scripts/sync_packed_docs.py ts       # 同步到 ts/_packed_docs/
    python scripts/sync_packed_docs.py js       # 同步到 js/_packed_docs/

退出码：0=成功，非 0=失败。
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path


def run_git_ls_files(repo_root: Path, target: str) -> list[str]:
    """git ls-files 列出受跟踪文件；自动遵从 .gitignore。

    用 -z 让 git 输出 NUL 分隔的原始字节路径，避免 core.quotepath=true 时
    中文路径被转义成 \\xxx 形式。
    """
    result = subprocess.run(
        ["git", "ls-files", "-z", target],
        cwd=repo_root,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git ls-files failed (exit {result.returncode}): {result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    raw = result.stdout
    # NUL 分隔的字节流；末尾可能有空段
    parts = [p for p in raw.split(b"\x00") if p]
    return [p.decode("utf-8") for p in parts]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <sdk: python|ts|js>", file=sys.stderr)
        return 2
    sdk = sys.argv[1].strip().lower()
    if sdk not in {"python", "ts", "js"}:
        print(f"error: unknown sdk '{sdk}', must be one of python/ts/js", file=sys.stderr)
        return 2

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent  # aun-sdk-core/
    docs_dir = repo_root / "docs"
    if not docs_dir.is_dir():
        print(f"error: {docs_dir} not found", file=sys.stderr)
        return 1

    target_dir_map = {
        # Python: 复制到 package 内部，setuptools 才能 include 进 wheel
        "python": repo_root / "python" / "src" / "aun_core" / "_packed_docs",
        # TS / JS: package.json 的 "files" 字段会包含项目根的目录
        "ts": repo_root / "ts" / "_packed_docs",
        "js": repo_root / "js" / "_packed_docs",
    }
    target_dir = target_dir_map[sdk]
    # 清空旧的，避免遗留过期文档；Windows 下 read-only 副本会让 rmtree 失败，
    # 用 onexc 强制改写权限再重试。
    def _force_rm(func, path, _exc):
        try:
            os.chmod(path, stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            func(path)
        except Exception:
            pass
    if target_dir.exists():
        # Python 3.12+ 用 onexc，旧版用 onerror；都传可向后兼容
        try:
            shutil.rmtree(target_dir, onexc=_force_rm)
        except TypeError:
            shutil.rmtree(target_dir, onerror=_force_rm)
        if target_dir.exists():
            print(
                f"[sync_packed_docs] WARNING: 部分旧文件未清理 {target_dir}（可能被 IDE/git 占用）",
                file=sys.stderr,
            )
    target_dir.mkdir(parents=True, exist_ok=True)

    files = run_git_ls_files(repo_root, "docs")
    if not files:
        print("[sync_packed_docs] WARNING: git ls-files docs/ returned empty list")
        return 0

    copied = 0
    for rel_path in files:
        src = repo_root / rel_path
        if not src.is_file():
            # git index 里可能有 stale entry（文件已重命名/删除但 git 没刷新）
            continue
        # rel_path 形如 "docs/protocol/01-xxx.md"，去掉前缀 "docs/"
        rel_under_docs = Path(rel_path).relative_to("docs")
        dst = target_dir / rel_under_docs
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        # Windows 下源文件 read-only 时 copy2 会保留只读属性，导致下次清空失败
        try:
            os.chmod(dst, stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass
        copied += 1

    print(f"[sync_packed_docs] {sdk}: copied {copied} files to {target_dir}")

    # 顺便把当前 SDK 自己的 CHANGELOG.md 也放进去（如果存在）
    sdk_dir_map = {
        "python": repo_root / "python",
        "ts": repo_root / "ts",
        "js": repo_root / "js",
    }
    sdk_changelog = sdk_dir_map[sdk] / "CHANGELOG.md"
    if sdk_changelog.is_file():
        shutil.copy2(sdk_changelog, target_dir / "CHANGELOG.md")
        print(f"[sync_packed_docs] {sdk}: also bundled CHANGELOG.md")

    return 0


if __name__ == "__main__":
    sys.exit(main())
