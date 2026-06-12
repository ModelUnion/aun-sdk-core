#!/usr/bin/env python3
"""未签名 storage/group.resources RPC 集成测试。

普通 SDK call 会给关键方法自动附加 client_signature；本测试在 AID 已认证连接后，
直接使用底层 transport 发送裸 JSON-RPC，验证服务端可选验签阶段能放行缺签名请求。
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys
import traceback
import uuid
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_refactor_helpers import _store_for_client, ensure_connected_identity, make_client_for_path

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_unsigned_storage_group_resources"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_RUN_ID = os.environ.get("AUN_TEST_RUN_ID", uuid.uuid4().hex[:8]).strip() or uuid.uuid4().hex[:8]
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"unsigned-alice-{_RUN_ID}.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"unsigned-bobb-{_RUN_ID}.{_ISSUER}").strip()

_passed = 0
_failed = 0


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    return await ensure_connected_identity(client, aid)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


async def _unsigned_call(client: AUNClient, method: str, params: dict[str, Any]) -> Any:
    signed_methods = getattr(client, "_SIGNED_METHODS", frozenset())
    if method not in signed_methods:
        raise AssertionError(f"{method} 不在 SDK 自动签名集合中，不能证明绕过签名 pipeline")
    payload = dict(params)
    if "client_signature" in payload:
        raise AssertionError(f"{method} 测试参数不应携带 client_signature")
    transport = getattr(client, "_transport", None)
    if transport is None:
        raise AssertionError("client 未初始化 transport")
    result = await transport.call(method, payload)
    if "client_signature" in payload:
        raise AssertionError(f"{method} 底层调用不应注入 client_signature")
    return result


def _resource_id(result: dict[str, Any], label: str) -> str:
    resource_id = str((result.get("resource") or {}).get("resource_id") or "").strip()
    if not resource_id:
        raise AssertionError(f"{label} 未返回 resource_id: {result}")
    return resource_id


async def test_unsigned_storage_write_and_tree_methods() -> None:
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bucket = f"unsigned-storage-{rid}"
    folder_path = f"docs/{rid}"
    object_id = ""
    folder_id = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)

        folder = await _unsigned_call(alice, "storage.create_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "path": folder_path,
            "mkdirs": True,
        })
        folder_id = str((folder.get("folder") or folder).get("folder_id") or "").strip()
        if not folder_id:
            raise AssertionError(f"storage.create_folder 未返回 folder_id: {folder}")

        put = await _unsigned_call(alice, "storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": f"{folder_path}/note.txt",
            "content": _b64(f"unsigned-storage-{rid}".encode("utf-8")),
            "content_type": "text/plain",
            "is_private": True,
        })
        object_id = str(put.get("object_id") or "").strip()
        if not object_id:
            raise AssertionError(f"storage.put_object 未返回 object_id: {put}")

        meta = await _unsigned_call(alice, "storage.set_object_meta", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
            "metadata": {"unsigned_probe": rid},
        })
        if str(meta.get("object_id") or "") != object_id:
            raise AssertionError(f"storage.set_object_meta 返回异常: {meta}")

        moved = await _unsigned_call(alice, "storage.move_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
            "dst_parent_path": folder_path,
            "new_name": "note-renamed.txt",
        })
        if moved.get("path") != f"{folder_path}/note-renamed.txt":
            raise AssertionError(f"storage.move_object path 异常: {moved}")

        deleted = await _unsigned_call(alice, "storage.delete_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
        })
        if deleted.get("deleted") is not True:
            raise AssertionError(f"storage.delete_object 返回异常: {deleted}")
        object_id = ""

        await _unsigned_call(alice, "storage.delete_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "folder_id": folder_id,
            "recursive": True,
        })
        folder_id = ""
    finally:
        if object_id:
            try:
                await alice.call("storage.delete_object", {
                    "owner_aid": _ALICE_AID,
                    "bucket": bucket,
                    "object_id": object_id,
                })
            except Exception:
                pass
        if folder_id:
            try:
                await alice.call("storage.delete_folder", {
                    "owner_aid": _ALICE_AID,
                    "bucket": bucket,
                    "folder_id": folder_id,
                    "recursive": True,
                })
            except Exception:
                pass
        await alice.close()


async def test_unsigned_group_resources_tree_methods() -> None:
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    alice_store = _store_for_client(alice)
    group_id = ""
    resource_id = ""
    folder_path = f"announce/unsigned/{rid}"

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        created = await alice.create_group(
            {"name": f"unsigned-res-{rid}", "group_name": f"unsigned{rid}"},
            aid_store=alice_store,
        )
        group_id = str((created.get("group") or {}).get("group_id") or "").strip()
        group_aid = str((created.get("group") or {}).get("group_aid") or "").strip()
        if not group_id or not group_aid:
            raise AssertionError(f"group.create 未返回 group_id/group_aid: {created}")
        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})

        pending = await _unsigned_call(alice, "group.resources.create_folder", {
            "group_id": group_id,
            "path": folder_path,
            "mkdirs": True,
        })
        if pending.get("mode") != "pending_ops" or pending.get("operation") != "create_folder":
            raise AssertionError(f"group.resources.create_folder 未返回 group-storage pending_ops: {pending}")
        ops = pending.get("pending_ops") or []
        if not ops or ops[0].get("rpc") != "storage.fs.mkdir":
            raise AssertionError(f"group.resources.create_folder pending op 异常: {pending}")
        if (ops[0].get("params") or {}).get("path") != folder_path:
            raise AssertionError(f"group.resources.create_folder pending path 异常: {pending}")

        confirm_params = dict(pending.get("confirm_params") or {})
        confirm_params["storage_results"] = {
            "mkdir": {"status": "active", "path": folder_path},
        }
        confirm_params["storage_result"] = {"status": "active", "path": folder_path}
        confirm_params.setdefault("confirm_key", "mkdir")
        try:
            await _unsigned_call(alice, "group.resources.confirm", confirm_params)
        except Exception as exc:
            if "group_identity" not in str(exc) and "signature" not in str(exc).lower():
                raise AssertionError(f"裸 group.resources.confirm 应因 group_identity 签名被拒绝，实际错误: {exc}") from exc
        else:
            raise AssertionError("裸 group.resources.confirm 不应在强制 group_identity 签名策略下成功")

        confirmed_plan = await alice.group.resources.execute_pending_ops(pending, aid_store=alice_store)
        confirmed = confirmed_plan.get("confirmed") if isinstance(confirmed_plan, dict) else None
        if not isinstance(confirmed, dict) or confirmed.get("confirmed") is not True:
            raise AssertionError(f"group.resources.execute_pending_ops confirm 返回异常: {confirmed_plan}")
        resource_id = _resource_id(confirmed, "group.resources.confirm")
        if (confirmed.get("resource") or {}).get("resource_path") != folder_path:
            raise AssertionError(f"group.resources.confirm resource_path 异常: {confirmed}")

        listed = await bob.call("group.resources.list", {
            "group_id": group_id,
            "prefix": "announce/unsigned/",
        })
        items = listed.get("items") if isinstance(listed, dict) else []
        if not any(item.get("resource_id") == resource_id for item in items or []):
            raise AssertionError(f"成员未看到无签名 confirm 后的 group-storage 目录: {listed}")

        delete_pending = await _unsigned_call(alice, "group.resources.delete", {
            "group_id": group_id,
            "resource_id": resource_id,
            "recursive": True,
        })
        if delete_pending.get("mode") != "pending_ops" or delete_pending.get("operation") != "delete":
            raise AssertionError(f"group.resources.delete 未返回 pending_ops: {delete_pending}")
        deleted_plan = await alice.group.resources.execute_pending_ops(delete_pending, aid_store=alice_store)
        deleted = deleted_plan.get("confirmed") if isinstance(deleted_plan, dict) else None
        if not isinstance(deleted, dict) or deleted.get("deleted") is not True:
            raise AssertionError(f"group.resources.execute_pending_ops delete 返回异常: {deleted_plan}")
        resource_id = ""
    finally:
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        alice_store.close()
        await bob.close()
        await alice.close()


async def main() -> None:
    global _passed, _failed

    print("=== 未签名 storage/group.resources 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOBB     = {_BOBB_AID}")
    print()

    tests = [
        test_unsigned_storage_write_and_tree_methods,
        test_unsigned_group_resources_tree_methods,
    ]

    for fn in tests:
        print(f"--- {fn.__name__} ---")
        try:
            await fn()
            _passed += 1
            print("  [PASS]")
        except Exception as exc:
            _failed += 1
            print(f"  [FAIL] {exc}")
            traceback.print_exc()
        print()

    print("=" * 50)
    print(f"结果: {_passed} passed, {_failed} failed")
    if _failed:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
