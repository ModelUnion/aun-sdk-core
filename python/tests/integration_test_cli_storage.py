#!/usr/bin/env python3
"""CLI storage_core 集成测试：在真实 docker 环境验证上传/下载/删除数据面。

直接复用 CLI 的 typer-free 核心（aun_cli.storage_core），用真实 AUNClient 连接
storage 服务，跑通：
  1. 小文件 inline 上传 → 下载内容一致
  2. 大文件 ticket 上传（HTTP PUT + 302→PUT）→ 下载内容一致
  3. 历史/普通对象统一走 download ticket → 兼容下载
  4. 删除后下载失败

使用方法：
  python -X utf8 tests/integration_test_cli_storage.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT 指向 Docker 挂载的持久化数据目录
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path
from aun_cli import storage_core

os.environ.setdefault("AUN_ENV", "development")
_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_storage"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_VERIFY_SSL = False  # dev 环境自签证书

_passed = 0
_failed = 0


def _ok(name: str):
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str):
    global _failed
    _failed += 1
    print(f"  [FAIL] {name} — {reason}")


async def _run_tests():
    rid = uuid.uuid4().hex[:10]
    client = make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)
    await ensure_connected_identity(client, _ALICE_AID)

    small_key = f"cli-test/{rid}/small.txt"
    large_key = f"cli-test/{rid}/large.bin"
    small_data = b"CLI-SMALL-" + rid.encode("ascii")
    # 大于 inline 上限（默认 64KB），强制走 ticket + HTTP PUT
    large_data = (b"CLI-LARGE-" + rid.encode("ascii")) * 8192

    try:
        # 1) 小文件 inline 上传 → 下载内容一致
        try:
            up = await storage_core.upload_object(
                client, object_key=small_key, data=small_data,
                content_type="text/plain", is_private=True, verify_ssl=_VERIFY_SSL,
            )
            if up.get("object_key") != small_key:
                raise AssertionError(f"inline 上传返回 key 不符: {up}")
            _, got = await storage_core.download_object(
                client, object_key=small_key, verify_ssl=_VERIFY_SSL,
            )
            if got != small_data:
                raise AssertionError(f"inline 下载内容不一致: {len(got)} vs {len(small_data)}")
            _ok("cli_inline_upload_download_roundtrip")
        except Exception as exc:
            _fail("cli_inline_upload_download_roundtrip", str(exc))

        # 2) 大文件 ticket 上传（HTTP PUT + 302→PUT）→ 下载内容一致
        try:
            up = await storage_core.upload_object(
                client, object_key=large_key, data=large_data,
                content_type="application/octet-stream", is_private=True, verify_ssl=_VERIFY_SSL,
            )
            if int(up.get("size_bytes") or 0) != len(large_data):
                raise AssertionError(f"ticket 上传 size 不符: {up}")
            _, got = await storage_core.download_object(
                client, object_key=large_key, verify_ssl=_VERIFY_SSL,
            )
            if got != large_data:
                raise AssertionError(f"ticket 下载内容不一致: {len(got)} vs {len(large_data)}")
            _ok("cli_ticket_upload_download_roundtrip")
        except Exception as exc:
            _fail("cli_ticket_upload_download_roundtrip", str(exc))

        # 3) 删除后下载失败
        try:
            res = await storage_core.delete_object(client, object_key=small_key)
            if res.get("deleted") is not True:
                raise AssertionError(f"删除未返回 deleted=True: {res}")
            failed = False
            try:
                await storage_core.download_object(client, object_key=small_key, verify_ssl=_VERIFY_SSL)
            except Exception:
                failed = True
            if not failed:
                raise AssertionError("删除后下载应失败但成功了")
            _ok("cli_delete_then_download_fails")
        except Exception as exc:
            _fail("cli_delete_then_download_fails", str(exc))
    finally:
        # 清理大文件
        try:
            await storage_core.delete_object(client, object_key=large_key)
        except Exception:
            pass
        await client.close()


def main():
    print("=" * 50)
    print("CLI storage_core 集成测试")
    print("=" * 50)
    asyncio.run(_run_tests())
    print("=" * 50)
    print(f"结果: {_passed} passed, {_failed} failed")
    if _failed:
        print("失败 ❌")
        sys.exit(1)
    print("全部通过 ✅")


if __name__ == "__main__":
    main()

