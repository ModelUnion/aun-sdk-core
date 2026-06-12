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
    return "./.aun_test_fs_p6"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p6-alice-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
_GROUP_AID = os.environ.get("AUN_TEST_GROUP_AID", f"fs-p6-group-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
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
    return f"fs-p6-{uuid.uuid4().hex[:10]}"


@pytest_asyncio.fixture
async def alice(root: str) -> AUNClient:
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


@pytest_asyncio.fixture
async def group(root: str) -> AUNClient:
    client = _make_client()
    try:
        await ensure_connected_identity(client, _GROUP_AID)
        yield client
    finally:
        try:
            await client.storage.remove(f"/{root}", owner=_GROUP_AID, recursive=True)
        except Exception:
            pass
        await client.close()


async def _expect_missing(coro) -> None:
    try:
        await coro
    except NotFoundError:
        return
    except Exception:
        return
    raise AssertionError("expected missing/denied path")


async def test_mount_read_write_and_unmount(alice: AUNClient, group: AUNClient, root: str) -> None:
    name = "fs_p6_mount_read_write_unmount"
    try:
        source_dir = f"/{root}/source"
        mount_dir = f"/{root}/memberdata/alice"
        await alice.storage.write_bytes(f"{source_dir}/a.txt", b"P6-SOURCE", owner=_ALICE_AID, content_type="text/plain")
        await alice.storage.set_acl(source_dir, owner=_ALICE_AID, grantee_aid=_GROUP_AID, perms="rwd")

        mounted = await group.storage.mount(
            f"{_ALICE_AID}:{source_dir}",
            mount_dir,
            owner=_GROUP_AID,
            readonly=False,
        )
        if mounted.type != "mount" or mounted.mount_source != f"{_ALICE_AID}:{source_dir.lstrip('/')}":
            raise AssertionError(f"mount 返回异常: {mounted}")

        lstat = await group.storage.lstat(mount_dir, owner=_GROUP_AID)
        stat = await group.storage.stat(mount_dir, owner=_GROUP_AID)
        nodes = await group.storage.list(mount_dir, owner=_GROUP_AID, long=True)
        if lstat.type != "mount" or stat.type != "dir" or [node.name for node in nodes] != ["a.txt"]:
            raise AssertionError(f"stat/list 未解析挂载: lstat={lstat} stat={stat} nodes={nodes}")
        if await group.storage.read_bytes(f"{mount_dir}/a.txt", owner=_GROUP_AID) != b"P6-SOURCE":
            raise AssertionError("挂载点读取源数据失败")

        await group.storage.write_bytes(f"{mount_dir}/b.txt", b"P6-WRITE", owner=_GROUP_AID, content_type="text/plain")
        if await alice.storage.read_bytes(f"{source_dir}/b.txt", owner=_ALICE_AID) != b"P6-WRITE":
            raise AssertionError("挂载点写入未落到 source")

        copied = await group.storage.copy(f"{mount_dir}/b.txt", f"{mount_dir}/copied.txt", owner=_GROUP_AID)
        renamed = await group.storage.rename(f"{mount_dir}/copied.txt", f"{mount_dir}/renamed.txt", owner=_GROUP_AID)
        removed = await group.storage.remove(f"{mount_dir}/renamed.txt", owner=_GROUP_AID)
        if copied.owner != _ALICE_AID or renamed.path != f"{source_dir}/renamed.txt" or removed.removed_count != 1:
            raise AssertionError(f"fs mutation 返回异常: copied={copied} renamed={renamed} removed={removed}")
        await _expect_missing(alice.storage.stat(f"{source_dir}/renamed.txt", owner=_ALICE_AID))

        unmounted = await group.storage.unmount(mount_dir, owner=_GROUP_AID)
        if unmounted.removed_count != 1:
            raise AssertionError(f"unmount 返回异常: {unmounted}")
        await _expect_missing(group.storage.stat(mount_dir, owner=_GROUP_AID))
        if await alice.storage.read_bytes(f"{source_dir}/a.txt", owner=_ALICE_AID) != b"P6-SOURCE":
            raise AssertionError("unmount 后 source 数据丢失")
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def main() -> None:
    print("=== AUN fs P6 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"GROUP    = {_GROUP_AID}")
    root = f"fs-p6-{uuid.uuid4().hex[:10]}"
    alice = _make_client()
    group = _make_client()
    try:
        await ensure_connected_identity(alice, _ALICE_AID)
        await ensure_connected_identity(group, _GROUP_AID)
        await test_mount_read_write_and_unmount(alice, group, root)
    finally:
        try:
            await alice.storage.remove(f"/{root}", owner=_ALICE_AID, recursive=True)
        except Exception:
            pass
        try:
            await group.storage.remove(f"/{root}", owner=_GROUP_AID, recursive=True)
        except Exception:
            pass
        await alice.close()
        await group.close()
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
