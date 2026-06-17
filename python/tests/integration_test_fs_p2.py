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
from aun_core.storage import ConflictError, DanglingSymlinkError, LoopError, NotFoundError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path


os.environ.setdefault("AUN_ENV", "development")
_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_fs_p2"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p2-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
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
    return f"fs-p2-{uuid.uuid4().hex[:10]}"


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


async def test_symlink_basic(client: AUNClient, root: str) -> None:
    name = "symlink_basic"
    try:
        await client.storage.write_bytes(f"/{root}/private/v1.txt", b"v1", owner=_ALICE_AID, content_type="text/plain")
        link = await client.storage.symlink(f"/{root}/private/v1.txt", f"/{root}/public/current.txt", owner=_ALICE_AID)
        if link.type != "symlink" or link.target != f"/{root}/private/v1.txt":
            raise AssertionError(f"symlink 返回异常: {link}")
        lstat = await client.storage.lstat(f"/{root}/public/current.txt", owner=_ALICE_AID)
        stat = await client.storage.stat(f"/{root}/public/current.txt", owner=_ALICE_AID)
        data = await client.storage.read_bytes(f"/{root}/public/current.txt", owner=_ALICE_AID)
        if lstat.type != "symlink" or stat.type != "file" or data != b"v1":
            raise AssertionError(f"软链跟随异常: lstat={lstat} stat={stat} data={data!r}")
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def test_repoint_and_remove(client: AUNClient, root: str) -> None:
    name = "repoint_and_remove"
    link_path = f"/{root}/public/repoint-current.txt"
    try:
        await client.storage.write_bytes(f"/{root}/private/v1.txt", b"v1", owner=_ALICE_AID, content_type="text/plain")
        await client.storage.symlink(f"/{root}/private/v1.txt", link_path, owner=_ALICE_AID)
        await client.storage.write_bytes(f"/{root}/private/v2.txt", b"v2", owner=_ALICE_AID, content_type="text/plain")
        with expect_raises(ConflictError):
            await client.storage.repoint(
                link_path,
                f"/{root}/private/v2.txt",
                owner=_ALICE_AID,
                expected_version=99,
            )
        updated = await client.storage.repoint(
            link_path,
            f"/{root}/private/v2.txt",
            owner=_ALICE_AID,
            expected_version=1,
        )
        if updated.version != 2:
            raise AssertionError(f"version 未递增: {updated}")
        if await client.storage.read_bytes(link_path, owner=_ALICE_AID) != b"v2":
            raise AssertionError("重指后读取内容不对")
        removed = await client.storage.remove(link_path, owner=_ALICE_AID)
        if removed.removed_count != 1:
            raise AssertionError(f"删除软链结果异常: {removed}")
        await client.storage.stat(f"/{root}/private/v2.txt", owner=_ALICE_AID)
        with expect_raises(NotFoundError):
            await client.storage.lstat(link_path, owner=_ALICE_AID)
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def test_dangling_and_loop(client: AUNClient, root: str) -> None:
    name = "dangling_and_loop"
    try:
        await client.storage.symlink(f"/{root}/private/missing.txt", f"/{root}/public/missing.txt", owner=_ALICE_AID)
        dangling = await client.storage.readlink(f"/{root}/public/missing.txt", owner=_ALICE_AID)
        if not dangling.metadata.get("dangling"):
            raise AssertionError(f"readlink 未标记 dangling: {dangling}")
        with expect_raises(DanglingSymlinkError):
            await client.storage.stat(f"/{root}/public/missing.txt", owner=_ALICE_AID)
        await client.storage.symlink(f"/{root}/loop/self.txt", f"/{root}/loop/self.txt", owner=_ALICE_AID)
        with expect_raises(LoopError):
            await client.storage.stat(f"/{root}/loop/self.txt", owner=_ALICE_AID)
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


class expect_raises:
    def __init__(self, exc_type):
        self.exc_type = exc_type

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            raise AssertionError(f"未抛出 {self.exc_type.__name__}")
        return issubclass(exc_type, self.exc_type)


async def main() -> None:
    print("=== AUN fs P2 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    root = f"fs-p2-{uuid.uuid4().hex[:10]}"
    client = _make_client()
    try:
        await ensure_connected_identity(client, _ALICE_AID)
        await test_symlink_basic(client, f"{root}/basic")
        await test_repoint_and_remove(client, f"{root}/repoint")
        await test_dangling_and_loop(client, f"{root}/dangling")
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
