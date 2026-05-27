#!/usr/bin/env python3
"""AUN SDK seed 迁移工具（复用 SDK 严格 ChangeSeed 实现）。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    repo_python = Path(__file__).resolve().parent
    sys.path.insert(0, str(repo_python / "src"))

    from aun_core.keystore.seed_migration import SeedMigrationError, change_seed

    parser = argparse.ArgumentParser(
        description="AUN SDK seed 迁移工具：把旧 .seed/seed_password 加密材料迁移到新的 seed_password。"
    )
    parser.add_argument("--aun-path", required=True, help="AUN 数据目录路径")
    parser.add_argument("--old-seed", default=".seed", help="旧 seed_password；'.seed' 表示读取 {aun_path}/.seed")
    parser.add_argument("--seed-password", required=True, help="新的 seed_password（空字符串有效）")
    args = parser.parse_args()

    try:
        result = change_seed(args.aun_path, args.old_seed, args.seed_password, emit=lambda msg: print(f"[INFO] {msg}"))
    except SeedMigrationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ERROR] seed migration failed: {exc}", file=sys.stderr)
        return 1

    print(
        "[OK] migrated={migrated} skipped={skipped} private_keys={private_keys} renamed={renamed}".format(
            migrated=result.migrated,
            skipped=result.skipped,
            private_keys=result.private_keys_migrated,
            renamed=result.seed_files_renamed,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
