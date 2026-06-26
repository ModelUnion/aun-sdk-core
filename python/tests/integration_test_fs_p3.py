#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.storage import NotFoundError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path


os.environ.setdefault("AUN_ENV", "development")
_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_fs_p3"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p3-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
pytestmark = pytest.mark.asyncio

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} - {reason}")
    if os.environ.get("PYTEST_CURRENT_TEST"):
        raise AssertionError(reason)


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


@pytest.fixture
def root() -> str:
    return f"fs-p3-{uuid.uuid4().hex[:10]}"


@pytest_asyncio.fixture
async def client(root: str) -> AUNClient:
    client = _make_client()
    try:
        await ensure_connected_identity(client, _ALICE_AID)
        yield client
    finally:
        try:
            await client.storage.remove(f"/{root}", owner=_ALICE_AID, recursive=True)
        except Exception:
            pass
        await client.close()


async def _expect_missing(client: AUNClient, path: str) -> None:
    try:
        await client.storage.stat(path, owner=_ALICE_AID)
    except NotFoundError:
        return
    except Exception:
        return
    raise AssertionError(f"{path} 应不存在")


async def test_authoritative_nodes(client: AUNClient, root: str) -> None:
    name = "fs_p3_authoritative_nodes"
    try:
        await client.storage.mkdir(f"/{root}/docs/sub", owner=_ALICE_AID, parents=True)
        await client.storage.write_bytes(f"/{root}/docs/a.txt", b"P3-A", owner=_ALICE_AID, content_type="text/plain")
        await client.storage.symlink(f"/{root}/docs/a.txt", f"/{root}/docs/current.txt", owner=_ALICE_AID)
        nodes = await client.storage.list(f"/{root}/docs", owner=_ALICE_AID, long=True)
        rows = {(n.type, n.name, n.mode) for n in nodes}
        expected = {("file", "a.txt", "0644"), ("dir", "sub", "0755"), ("symlink", "current.txt", "0777")}
        if rows != expected:
            raise AssertionError(f"list 权威节点异常: {rows}")
        stat = await client.storage.stat(f"/{root}/docs/current.txt", owner=_ALICE_AID)
        lstat = await client.storage.lstat(f"/{root}/docs/current.txt", owner=_ALICE_AID)
        if stat.type != "file" or lstat.type != "symlink":
            raise AssertionError(f"stat/lstat 异常: stat={stat} lstat={lstat}")
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def test_mutations(client: AUNClient, root: str) -> None:
    name = "fs_p3_mutations"
    try:
        await client.storage.write_bytes(f"/{root}/work/src.txt", b"P3-COPY", owner=_ALICE_AID, content_type="text/plain")
        touched = await client.storage.touch(f"/{root}/work/empty.txt", owner=_ALICE_AID, parents=True, mtime=1_700_000_000)
        if touched.type != "file" or touched.path != f"/{root}/work/empty.txt" or int(touched.size or 0) != 0:
            raise AssertionError(f"touch 创建空文件异常: {touched}")
        du = await client.storage.du(f"/{root}/work", owner=_ALICE_AID, max_depth=2)
        if int(du.get("file_count") or 0) < 2 or int(du.get("size_bytes") or 0) < len(b"P3-COPY"):
            raise AssertionError(f"du 聚合异常: {du}")
        copied = await client.storage.copy(f"/{root}/work/src.txt", f"/{root}/work/copy.txt", owner=_ALICE_AID)
        if copied.type != "file" or copied.path != f"/{root}/work/copy.txt":
            raise AssertionError(f"copy 异常: {copied}")
        renamed = await client.storage.rename(f"/{root}/work/copy.txt", f"/{root}/work/renamed.txt", owner=_ALICE_AID)
        if renamed.type != "file" or renamed.path != f"/{root}/work/renamed.txt":
            raise AssertionError(f"rename 异常: {renamed}")
        removed = await client.storage.remove(f"/{root}/work/renamed.txt", owner=_ALICE_AID)
        if removed.removed_count != 1:
            raise AssertionError(f"remove 异常: {removed}")
        await _expect_missing(client, f"/{root}/work/renamed.txt")
        if await client.storage.read_bytes(f"/{root}/work/src.txt", owner=_ALICE_AID) != b"P3-COPY":
            raise AssertionError("copy/remove 后源文件内容异常")
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def main() -> None:
    print("=== AUN fs P3 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    root = f"fs-p3-{uuid.uuid4().hex[:10]}"
    client = _make_client()
    try:
        await ensure_connected_identity(client, _ALICE_AID)
        await test_authoritative_nodes(client, root)
        await test_mutations(client, root)
    finally:
        try:
            await client.storage.remove(f"/{root}", owner=_ALICE_AID, recursive=True)
        except Exception:
            pass
        await client.close()
    print("=" * 50)
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        for item in _errors:
            print(f"  - {item}")
    if _failed:
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
