#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
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
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path


os.environ.setdefault("AUN_ENV", "development")
_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_fs_p4"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p4-alice-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"fs-p4-bob-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
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
    return f"fs-p4-{uuid.uuid4().hex[:10]}"


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
async def bob() -> AUNClient:
    client = _make_client()
    try:
        await ensure_connected_identity(client, _BOB_AID)
        yield client
    finally:
        await client.close()


async def _expect_denied(coro):
    try:
        await coro
    except Exception:
        return
    raise AssertionError("expected access denied")


async def test_acl_and_visibility(alice: AUNClient, bob: AUNClient, root: str) -> None:
    name = "fs_p4_acl_and_visibility"
    try:
        await alice.storage.write_bytes(f"/{root}/docs/a.txt", b"P4-ACL", owner=_ALICE_AID, content_type="text/plain")
        await _expect_denied(bob.storage.read_bytes(f"/{root}/docs/a.txt", owner=_ALICE_AID))
        await alice.storage.set_acl(f"/{root}/docs", owner=_ALICE_AID, grantee_aid=_BOB_AID, perms="w")
        await _expect_denied(bob.storage.read_bytes(f"/{root}/docs/a.txt", owner=_ALICE_AID))
        await bob.storage.write_bytes(f"/{root}/docs/b.txt", b"P4-ACL-WRITE", owner=_ALICE_AID, content_type="text/plain")
        share = await alice.call("storage.create_share_link", {
            "owner_aid": _ALICE_AID,
            "object_key": f"{root}/docs/a.txt",
            "allowed_aids": [_BOB_AID],
            "expire_in_seconds": 300,
        })
        shared = await bob.call("storage.get_by_share", {"share_id": share["share_id"]})
        if base64.b64decode(str(shared.get("content") or "")) != b"P4-ACL":
            raise AssertionError("bob share-link read mismatch")
        await alice.call("storage.revoke_share_link", {"share_id": share["share_id"]})
        await _expect_denied(bob.call("storage.get_by_share", {"share_id": share["share_id"]}))
        await alice.storage.remove_acl(f"/{root}/docs", owner=_ALICE_AID, grantee_aid=_BOB_AID)
        await _expect_denied(bob.storage.write_bytes(f"/{root}/docs/c.txt", b"no", owner=_ALICE_AID))
        await alice.storage.set_visibility(f"/{root}/docs/a.txt", owner=_ALICE_AID, visibility="public")
        if await bob.storage.read_bytes(f"/{root}/docs/a.txt", owner=_ALICE_AID) != b"P4-ACL":
            raise AssertionError("public read mismatch")
        await alice.storage.set_visibility(f"/{root}/docs/a.txt", owner=_ALICE_AID, visibility="private")
        await _expect_denied(bob.storage.read_bytes(f"/{root}/docs/a.txt", owner=_ALICE_AID))
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def test_token_reads(alice: AUNClient, bob: AUNClient, root: str) -> None:
    name = "fs_p4_token_reads"
    try:
        await alice.storage.write_bytes(f"/{root}/share/a.txt", b"P4-TOKEN", owner=_ALICE_AID, content_type="text/plain")
        issued = await alice.storage.issue_token(f"/{root}/share/a.txt", owner=_ALICE_AID, max_reads=1)
        token = issued["token"]
        if await bob.storage.read_bytes(f"/{root}/share/a.txt", owner=_ALICE_AID, token=token) != b"P4-TOKEN":
            raise AssertionError("token read mismatch")
        await _expect_denied(bob.storage.read_bytes(f"/{root}/share/a.txt", owner=_ALICE_AID, token=token))
        issued2 = await alice.storage.issue_token(f"/{root}/share/a.txt", owner=_ALICE_AID)
        await alice.storage.revoke_token(f"/{root}/share/a.txt", owner=_ALICE_AID, token=issued2["token"])
        await _expect_denied(bob.storage.read_bytes(f"/{root}/share/a.txt", owner=_ALICE_AID, token=issued2["token"]))
        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))


async def main() -> None:
    print("=== AUN fs P4 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOB_AID}")
    root = f"fs-p4-{uuid.uuid4().hex[:10]}"
    alice = _make_client()
    bob = _make_client()
    try:
        await ensure_connected_identity(alice, _ALICE_AID)
        await ensure_connected_identity(bob, _BOB_AID)
        await test_acl_and_visibility(alice, bob, root)
        await test_token_reads(alice, bob, root)
    finally:
        try:
            await alice.storage.remove(f"/{root}", owner=_ALICE_AID, recursive=True)
        except Exception:
            pass
        await alice.close()
        await bob.close()
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
