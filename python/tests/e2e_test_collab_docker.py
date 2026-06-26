#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AIDStore, AUNClient
from aun_core.collab import CollabConflictError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get(
    "AUN_TEST_AUN_PATH",
    f"{_AUN_DATA_ROOT}/single-domain/persistent" if _AUN_DATA_ROOT else "./.aun_test_collab_e2e",
).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"collab-alice-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"collab-bob-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
_SEED = os.environ.get("AUN_TEST_ENCRYPTION_SEED", "")

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


def _make_store() -> AIDStore:
    return AIDStore(_TEST_AUN_PATH, encryption_seed=_SEED, verify_ssl=False)


def _b64(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return base64.b64encode(data).decode("ascii")


def _text(result: dict[str, Any]) -> str:
    return base64.b64decode(str(result.get("content") or "")).decode("utf-8")


async def _rpc(client: AUNClient, method: str, params: dict[str, Any]) -> Any:
    return await client.call(method, params)


async def _cleanup_root(client: AUNClient, owner: str, root: str) -> None:
    try:
        _, root_path = root.split(":", 1)
        await client.storage.remove(root_path, owner=owner, recursive=True)
    except Exception:
        pass


async def test_collab_create_show_commit_log_get_diff() -> None:
    name = "collab_create_show_commit_log_get_diff"
    rid = uuid.uuid4().hex[:10]
    root = f"{_ALICE_AID}:/collab-e2e/{rid}/proj"
    doc = "spec.md"
    alice = _make_client()
    try:
        await ensure_connected_identity(alice, _ALICE_AID)
        created = await alice.collab.create(root, doc, _b64("a\n"))
        if created.get("version") != 1 or not str(created.get("current_target") or "").startswith(f"{_ALICE_AID}:/"):
            raise AssertionError(f"create 返回异常: {created}")

        read = await alice.collab.show(root, doc)
        if read.get("version") != 1 or _text(read) != "a\n":
            raise AssertionError(f"show 返回异常: {read}")

        submitted = await alice.collab.commit(root, doc, _b64("a\nb\n"), onto=1)
        if submitted.get("version") != 2:
            raise AssertionError(f"commit 返回异常: {submitted}")

        history = await alice.collab.log(root, doc)
        if [item.get("version") for item in history] != [1, 2]:
            raise AssertionError(f"log 返回异常: {history}")
        if not all(str(item.get("target") or "").startswith(f"{_ALICE_AID}:/") for item in history):
            raise AssertionError(f"log target 不是完整 AID path: {history}")

        first = await alice.collab.show(root, doc, rev=1)
        if _text(first) != "a\n":
            raise AssertionError(f"show rev=1 返回异常: {first}")

        diff = await alice.collab.diff(root, doc, 1, 2)
        if "+b" not in str(diff.get("diff") or ""):
            raise AssertionError(f"diff 未返回新增行: {diff}")

        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))
    finally:
        await _cleanup_root(alice, _ALICE_AID, root)
        await alice.close()


async def test_collab_submit_conflict_hint_and_merge_modes() -> None:
    name = "collab_submit_conflict_hint_and_merge_modes"
    rid = uuid.uuid4().hex[:10]
    root = f"{_ALICE_AID}:/collab-e2e/{rid}/merge"
    doc = "merge.md"
    alice = _make_client()
    try:
        await ensure_connected_identity(alice, _ALICE_AID)
        await alice.collab.create(root, doc, _b64("line1\nline2\nline3\n"))
        await alice.collab.commit(root, doc, _b64("line1\nLINE2\nline3\n"), onto=1)

        no_conflict = await alice.collab.merge(root, doc, _b64("line1\nline2\nLINE3\n"), onto=1)
        if no_conflict.get("conflicts") is not False or _text(no_conflict) != "line1\nLINE2\nLINE3\n":
            raise AssertionError(f"merge no-conflict 返回异常: {no_conflict}")

        try:
            await alice.collab.commit(root, doc, _b64("stale\n"), onto=1)
        except CollabConflictError as exc:
            if exc.current_version != 2 or "merge" not in exc.hint.lower() or not exc.current_target:
                raise AssertionError(f"冲突字段异常: {exc.current_version}, {exc.current_target}, {exc.hint}")
        else:
            raise AssertionError("commit stale base 应触发 CAS 冲突")

        conflict_root = f"{_ALICE_AID}:/collab-e2e/{rid}/conflict"
        await alice.collab.create(conflict_root, doc, _b64("X\n"))
        await alice.collab.commit(conflict_root, doc, _b64("THEIRS\n"), onto=1)
        conflict = await alice.collab.merge(conflict_root, doc, _b64("OURS\n"), onto=1)
        if conflict.get("conflicts") is not True or "<<<<<<< ours" not in _text(conflict):
            raise AssertionError(f"merge conflict 返回异常: {conflict}")

        pruned = await alice.collab.prune(root, doc)
        # CAS 冲突时自动清理孤儿草稿，prune 返回 0 表示已无残留（符合预期）
        if not isinstance(pruned.get("pruned"), int):
            raise AssertionError(f"prune 返回格式异常: {pruned}")

        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))
    finally:
        await _cleanup_root(alice, _ALICE_AID, root)
        await _cleanup_root(alice, _ALICE_AID, f"{_ALICE_AID}:/collab-e2e/{rid}/conflict")
        await alice.close()


async def test_collab_snapshot_export_adopt_roundtrip() -> None:
    name = "collab_snapshot_export_adopt_roundtrip"
    rid = uuid.uuid4().hex[:10]
    root = f"{_ALICE_AID}:/collab-e2e/{rid}/snap"
    exported_root = f"{_ALICE_AID}:/collab-e2e/{rid}/exported"
    adopted_root = f"{_ALICE_AID}:/collab-e2e/{rid}/adopted"
    alice = _make_client()
    try:
        await ensure_connected_identity(alice, _ALICE_AID)
        await alice.storage.write_bytes(f"/collab-e2e/{rid}/snap/.collab", f"root: {root}\nauthority: {_ALICE_AID}\n".encode(), owner=_ALICE_AID)
        await alice.collab.create(root, "a.md", _b64("v1\n"))

        snap1 = await alice.collab.tag.create(root, message="init")
        if snap1.get("version") != "1.0.0" or "a.md" not in snap1.get("changed", []):
            raise AssertionError(f"tag create 返回异常: {snap1}")
        await alice.collab.commit(root, "a.md", _b64("v2\n"), onto=1)
        snap2 = await alice.collab.tag.create(root, message="patch")
        if snap2.get("version") != "1.0.1":
            raise AssertionError(f"tag patch 版本异常: {snap2}")

        listed = await alice.collab.tag.list(root)
        if [item.get("version") for item in listed] != ["1.0.0", "1.0.1"]:
            raise AssertionError(f"tag list 返回异常: {listed}")
        shown = await alice.collab.tag.show(root, "1.0.0")
        if not any(entry.get("doc") == "a.md" for entry in shown.get("entries", [])):
            raise AssertionError(f"tag show 返回异常: {shown}")
        if not all(str(entry.get("current_target") or "").startswith(f"{_ALICE_AID}:/") for entry in shown.get("entries", [])):
            raise AssertionError(f"tag show current_target 应为完整 AID path: {shown}")
        snap_diff = await alice.collab.tag.diff(root, "1.0.0", "1.0.1")
        if snap_diff.get("changed") != ["a.md"]:
            raise AssertionError(f"tag diff 返回异常: {snap_diff}")

        restored = await alice.collab.tag.restore(root, "1.0.0", message="restore")
        if restored.get("restored_from") != "1.0.0":
            raise AssertionError(f"tag restore 返回异常: {restored}")
        if _text(await alice.collab.show(root, "a.md")) != "v1\n":
            raise AssertionError("restore 后 current 内容不匹配")

        exported = await alice.collab.clone(root, exported_root, reroot=False)
        if exported.get("ok") is not True or exported.get("dest") != exported_root:
            raise AssertionError(f"clone reroot=False 返回异常: {exported}")
        exported_history = await alice.collab.log(exported_root, "a.md")
        if [item.get("version") for item in exported_history] != [1, 2, 3]:
            raise AssertionError(f"clone ledger 复制异常: {exported_history}")

        adopted = await alice.collab.clone(root, adopted_root, reroot=True)
        if adopted.get("new_root") != adopted_root or adopted.get("new_authority_aid") != _ALICE_AID:
            raise AssertionError(f"clone reroot=True 返回异常: {adopted}")
        anchor = await alice.storage.read_bytes(f"/collab-e2e/{rid}/adopted/.collab", owner=_ALICE_AID)
        if f"root: {adopted_root}" not in anchor.decode("utf-8"):
            raise AssertionError(f"adopt 未重写 .collab root: {anchor!r}")

        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))
    finally:
        await _cleanup_root(alice, _ALICE_AID, root)
        await _cleanup_root(alice, _ALICE_AID, exported_root)
        await _cleanup_root(alice, _ALICE_AID, adopted_root)
        await alice.close()


async def test_collab_group_discover_unregister_and_wrong_namespace() -> None:
    name = "collab_group_discover_unregister_and_wrong_namespace"
    rid = uuid.uuid4().hex[:10]
    owner = _make_client()
    member = _make_client()
    group_identity = _make_client()
    owner_store = _make_store()
    group_id = ""
    group_aid = ""
    try:
        owner_aid = f"collab-owner-{rid}.{_ISSUER}"
        member_aid = f"collab-member-{rid}.{_ISSUER}"
        await ensure_connected_identity(owner, owner_aid)
        await ensure_connected_identity(member, member_aid)

        created = await owner.create_group(
            {
                "name": f"collab-{rid}",
                "group_name": f"gst{rid}",
                "visibility": "private",
            },
            aid_store=owner_store,
        )
        group = created.get("group") or {}
        group_id = str(group.get("group_id") or "")
        group_aid = str(group.get("group_aid") or "")
        if not group_id or not group_aid:
            raise AssertionError(f"create_group 未返回 group_id/group_aid: {created}")
        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": member_aid, "role": "member"})
        namespace = await _rpc(owner, "group.fs.namespace_ready", {"group_id": group_id})
        if namespace.get("namespace_ready") is not True or "public" not in namespace.get("baseline_paths", []):
            raise AssertionError(f"group.fs namespace 初始化异常: {namespace}")
        role_updated = await _rpc(
            owner,
            "group.set_role",
            {"group_id": group_id, "aid": member_aid, "role": "admin", "perms": "rwd"},
        )
        if role_updated.get("new_role") != "admin":
            raise AssertionError(f"group.set_role 未返回 admin: {role_updated}")

        collab_root = f"{group_aid}:/public/collab-e2e/{rid}/group-proj"
        await ensure_connected_identity(group_identity, group_aid)
        await group_identity.collab.create(collab_root, "g.md", _b64("group\n"))
        if _text(await member.collab.show(collab_root, "g.md")) != "group\n":
            raise AssertionError("成员未能读取 group_aid 创建的群协作文档")
        roots = await member.collab.ls_remote(group_aid)
        if {"collab_root": collab_root, "authority_aid": group_aid} not in roots:
            raise AssertionError(f"ls_remote 未返回群协作根: {roots}")

        removed = await group_identity.collab.unregister(group_aid, collab_root)
        if removed.get("removed") != 1 or await member.collab.ls_remote(group_aid) != []:
            raise AssertionError(f"unregister/ls_remote 返回异常: {removed}")

        try:
            await member.call("storage.collab.show", {"collab_root": collab_root, "doc": "g.md"})
        except Exception as exc:
            error_text = str(exc)
            if "Method not found" not in error_text and "Permission denied" not in error_text:
                raise AssertionError(f"storage.collab.* 应被 Gateway/服务端拒绝，实际: {exc}") from exc
        else:
            raise AssertionError("storage.collab.* 不应可用")

        _ok(name)
    except Exception as exc:
        _fail(name, str(exc))
    finally:
        if group_aid:
            await _cleanup_root(group_identity, group_aid, f"{group_aid}:/public/collab-e2e/{rid}/group-proj")
        if group_id:
            try:
                await _rpc(owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        owner_store.close()
        await group_identity.close()
        await member.close()
        await owner.close()


async def main() -> None:
    print("=== AUN collab 单域 Docker E2E ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOB_AID}")
    tests = [
        test_collab_create_show_commit_log_get_diff,
        test_collab_submit_conflict_hint_and_merge_modes,
        test_collab_snapshot_export_adopt_roundtrip,
        test_collab_group_discover_unregister_and_wrong_namespace,
    ]
    for fn in tests:
        print(f"--- {fn.__name__} ---")
        try:
            await fn()
        except Exception as exc:
            _fail(fn.__name__, str(exc))
        print()
    print("=" * 50)
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        print("错误摘要:")
        for item in _errors:
            print(f"  - {item}")
    if _failed:
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
