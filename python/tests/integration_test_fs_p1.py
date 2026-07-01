#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import tempfile
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
    return "./.aun_test_fs_p1"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p1-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
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
    return f"fs-p1-{uuid.uuid4().hex[:10]}"


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


async def test_roundtrip_small_and_large(client: AUNClient, root: str) -> None:
    name = "fs_p1_roundtrip_small_and_large"
    tmp = Path(os.environ.get("AUN_TEST_TMP_DIR", tempfile.gettempdir())) / ".tmp_fs_p1" / uuid.uuid4().hex
    tmp.mkdir(parents=True, exist_ok=True)
    small = tmp / "small.txt"
    large = tmp / "large.bin"
    got_small = tmp / "got-small.txt"
    got_large = tmp / "got-large.bin"
    small.write_bytes(b"FS-P1-SMALL-" + root.encode("ascii"))
    large.write_bytes((b"FS-P1-LARGE-" + root.encode("ascii")) * 8192)
    try:
        await client.storage.upload_file(str(small), f"/{root}/small.txt", owner=_ALICE_AID, content_type="text/plain")
        await client.storage.upload_file(str(large), f"/{root}/large.bin", owner=_ALICE_AID, content_type="application/octet-stream")
        await client.storage.download_file(f"/{root}/small.txt", str(got_small), owner=_ALICE_AID)
        await client.storage.download_file(f"/{root}/large.bin", str(got_large), owner=_ALICE_AID)
        if hashlib.sha256(small.read_bytes()).hexdigest() != hashlib.sha256(got_small.read_bytes()).hexdigest():
            raise AssertionError("small sha256 mismatch")
        if hashlib.sha256(large.read_bytes()).hexdigest() != hashlib.sha256(got_large.read_bytes()).hexdigest():
            raise AssertionError("large sha256 mismatch")
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def test_list_stat_rm_df(client: AUNClient, root: str) -> None:
    name = "fs_p1_list_stat_rm_df"
    try:
        await client.storage.mkdir(f"/{root}/dir", owner=_ALICE_AID, parents=True)
        await client.storage.write_bytes(f"/{root}/dir/a.txt", b"abc", owner=_ALICE_AID, content_type="text/plain")
        nodes = await client.storage.list(f"/{root}", owner=_ALICE_AID)
        if ("dir", f"/{root}/dir") not in {(n.type, n.path) for n in nodes}:
            raise AssertionError(f"list 未返回目录: {nodes}")
        stat = await client.storage.stat(f"/{root}/dir/a.txt", owner=_ALICE_AID)
        if stat.type != "file" or stat.size != 3:
            raise AssertionError(f"stat 异常: {stat}")
        usage = await client.storage.get_usage(owner=_ALICE_AID)
        if usage.owner != _ALICE_AID:
            raise AssertionError(f"df owner 异常: {usage}")
        removed = await client.storage.remove(f"/{root}", owner=_ALICE_AID, recursive=True)
        if removed.removed_count <= 0:
            raise AssertionError(f"rm -r 未删除任何节点: {removed}")
        await _expect_missing(client, f"/{root}/dir/a.txt")
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def main() -> None:
    print("=== AUN fs P1 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    root = f"fs-p1-{uuid.uuid4().hex[:10]}"
    client = _make_client()
    try:
        await ensure_connected_identity(client, _ALICE_AID)
        await test_roundtrip_small_and_large(client, root)
        await test_list_stat_rm_df(client, root)
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
