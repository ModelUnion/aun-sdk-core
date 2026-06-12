#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import os
import ssl
import sys
import tempfile
import urllib.request
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
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get(
    "AUN_TEST_AUN_PATH",
    f"{_AUN_DATA_ROOT}/single-domain/persistent" if _AUN_DATA_ROOT else "./.aun_test_group_storage_e2e",
).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
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


def _make_store_for_path(path: str) -> AIDStore:
    return AIDStore(path, encryption_seed=_SEED, verify_ssl=False)


async def _rpc(client: AUNClient, method: str, params: dict[str, Any]) -> dict[str, Any]:
    result = await client.call(method, params)
    if not isinstance(result, dict):
        raise AssertionError(f"{method} 返回非对象: {result!r}")
    if isinstance(result.get("error"), dict):
        raise RuntimeError(f"{method} 失败: {result['error']}")
    return result


async def _http_get_bytes(url: str) -> bytes:
    def _download() -> bytes:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(url, timeout=20, context=ctx) as resp:
            return resp.read()

    return await asyncio.to_thread(_download)


def _resource_items(result: dict[str, Any]) -> list[dict[str, Any]]:
    items = result.get("items")
    return items if isinstance(items, list) else []


def _is_denied(exc: Exception) -> bool:
    msg = str(exc).lower()
    needles = (
        "permission denied",
        "denied",
        "forbidden",
        "owner required",
        "admin required",
        "unauthorized",
        "not a member",
        "not_member",
        "不是群成员",
        "权限",
        "无权",
        "signature",
        "certificate",
        "cert fingerprint",
        "cert mismatch",
        "rekey",
    )
    return any(item in msg for item in needles)


async def test_named_group_storage_full_flow() -> None:
    rid = uuid.uuid4().hex[:8]
    owner_aid = f"gst-owner-{rid}.{_ISSUER}"
    new_owner_aid = f"gst-new-owner-{rid}.{_ISSUER}"
    member_aid = f"gst-member-{rid}.{_ISSUER}"
    group_name = f"gst{rid}"
    resource_path = f"announce/e2e-{rid}.txt"
    body = f"GROUP_STORAGE_E2E_{rid}".encode("utf-8")

    owner = _make_client()
    new_owner = _make_client()
    member = _make_client()
    owner_store = _make_store()
    new_owner_store = _make_store()
    member_store = _make_store()
    stale_group_store: AIDStore | None = None
    stale_group_tmp: tempfile.TemporaryDirectory[str] | None = None
    group_id = ""

    try:
        await ensure_connected_identity(owner, owner_aid)
        await ensure_connected_identity(new_owner, new_owner_aid)
        await ensure_connected_identity(member, member_aid)

        created = await owner.create_group(
            {
                "name": f"group-storage-{rid}",
                "group_name": group_name,
                "visibility": "private",
            },
            aid_store=owner_store,
        )
        group = created.get("group") or {}
        group_id = str(group.get("group_id") or "").strip()
        group_aid = str(group.get("group_aid") or "").strip()
        if not group_id or not group_aid:
            raise AssertionError(f"create_group 未返回 group_id/group_aid: {created}")
        loaded_group = owner_store.load(group_aid)
        if not loaded_group.ok or loaded_group.data is None or not loaded_group.data["aid"].is_private_key_valid():
            raise AssertionError(f"group_aid 未落盘或私钥无效: {group_aid}")
        old_group_identity = loaded_group.data["aid"]
        stale_group_tmp = tempfile.TemporaryDirectory(prefix="aun-gst-stale-")
        stale_group_store = _make_store_for_path(stale_group_tmp.name)
        imported_old = stale_group_store.import_group_identity(
            group_aid,
            private_key_pem=old_group_identity.private_key_pem,
            public_key_der_b64=old_group_identity.public_key,
            curve="P-256",
            cert_pem=old_group_identity.cert_pem,
        )
        if not imported_old.ok:
            message = imported_old.error.message if imported_old.error else "unknown error"
            raise AssertionError(f"旧 group_aid 快照落盘失败: {message}")

        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": new_owner_aid, "role": "member"})
        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": member_aid, "role": "member"})

        namespace = await owner.group.resources.initialize_namespace(
            group_id=group_id,
            group_aid=group_aid,
            aid_store=owner_store,
        )
        if not namespace.get("namespace_ready"):
            raise AssertionError(f"namespace_ready 返回异常: {namespace}")

        pending = await owner.group.resources.put(
            {
                "group_id": group_id,
                "resource_path": resource_path,
                "resource_type": "file",
                "title": f"e2e-{rid}.txt",
                "content": base64.b64encode(body).decode("ascii"),
                "content_type": "text/plain",
                "visibility": "members_only",
            }
        )
        if pending.get("mode") != "pending_ops" or not pending.get("pending_ops"):
            raise AssertionError(f"group-storage put 未返回 pending_ops: {pending}")
        confirmed = await owner.group.resources.execute_pending_ops(pending, aid_store=owner_store)
        if not (confirmed.get("confirmed") or {}).get("confirmed"):
            raise AssertionError(f"execute_pending_ops confirm 异常: {confirmed}")

        listed = await member.group.resources.list({"group_id": group_id, "prefix": "announce/"})
        if not any(item.get("resource_path") == resource_path for item in _resource_items(listed)):
            raise AssertionError(f"成员未看到 group-storage 资源: {listed}")

        access = await member.group.resources.get_access({"group_id": group_id, "resource_path": resource_path})
        download_url = str((access.get("download") or {}).get("download_url") or "").strip()
        if not download_url:
            raise AssertionError(f"get_access 未返回 download_url: {access}")
        got = await _http_get_bytes(download_url)
        if got != body:
            raise AssertionError(f"下载内容不匹配: got={got!r} want={body!r}")

        df = await member.group.resources.get_df({"group_id": group_id})
        if df.get("group_aid") != group_aid or not isinstance((df.get("own") or {}).get("paths"), list):
            raise AssertionError(f"get_df 返回异常: {df}")

        # F20：成员自助挂载 memberdata，其他成员可经 group mirror 读取。
        member_child = f"share-{rid}"
        member_source_dir = f"{member_aid}/{group_aid}/{member_child}"
        member_body = f"MEMBERDATA_E2E_{rid}".encode("utf-8")
        await _rpc(member, "storage.fs.mkdir", {
            "owner_aid": member_aid,
            "path": member_source_dir,
            "parents": True,
        })
        await _rpc(member, "storage.put_object", {
            "owner_aid": member_aid,
            "object_key": f"{member_source_dir}/note.txt",
            "content": base64.b64encode(member_body).decode("ascii"),
            "content_type": "text/plain",
            "is_private": True,
            "overwrite": True,
        })
        mount_pending = await member.group.resources.mount_object({
            "group_id": group_id,
            "mount_path": f"memberdata/{member_aid}",
            "source_aid": member_aid,
            "source_path": "",
            "readonly": True,
        })
        mount_done = await member.group.resources.execute_pending_ops(mount_pending, aid_store=member_store)
        if not (mount_done.get("confirmed") or {}).get("confirmed"):
            raise AssertionError(f"memberdata mount confirm 异常: {mount_done}")
        mounted_access = await owner.group.resources.get_access({
            "group_id": group_id,
            "resource_path": f"memberdata/{member_aid}/{member_child}/note.txt",
        })
        mounted_url = str((mounted_access.get("download") or {}).get("download_url") or "").strip()
        if await _http_get_bytes(mounted_url) != member_body:
            raise AssertionError("memberdata 自助挂载读取内容不匹配")

        # F20：ACL 变更真实走 pending_ops，提升为 admin 后成员可写群自有区。
        acl_pending = await owner.group.set_role({
            "group_id": group_id,
            "aid": member_aid,
            "role": "admin",
            "perms": "rwx",
        })
        acl_done = await owner.group.resources.execute_pending_ops(acl_pending, aid_store=owner_store)
        if not (acl_done.get("confirmed") or {}).get("confirmed"):
            raise AssertionError(f"ACL pending confirm 异常: {acl_done}")
        admin_path = f"archive/member-admin-{rid}.txt"
        admin_pending = await member.group.resources.put({
            "group_id": group_id,
            "resource_path": admin_path,
            "resource_type": "file",
            "content": base64.b64encode(f"ADMIN_WRITE_{rid}".encode("utf-8")).decode("ascii"),
            "content_type": "text/plain",
            "visibility": "members_only",
        })
        admin_done = await member.group.resources.execute_pending_ops(admin_pending, aid_store=owner_store)
        if not (admin_done.get("confirmed") or {}).get("confirmed"):
            raise AssertionError(f"admin 写群自有区 confirm 异常: {admin_done}")

        remove_acl_pending = await owner.group.set_role({
            "group_id": group_id,
            "aid": member_aid,
            "role": "member",
        })
        remove_acl_done = await owner.group.resources.execute_pending_ops(remove_acl_pending, aid_store=owner_store)
        if not (remove_acl_done.get("confirmed") or {}).get("confirmed"):
            raise AssertionError(f"remove_acl pending confirm 异常: {remove_acl_done}")
        try:
            demoted_pending = await member.group.resources.put({
                "group_id": group_id,
                "resource_path": f"archive/member-demoted-{rid}.txt",
                "resource_type": "file",
                "content": base64.b64encode(b"DEMOTED").decode("ascii"),
                "content_type": "text/plain",
            })
            await member.group.resources.execute_pending_ops(demoted_pending, aid_store=owner_store)
        except Exception as exc:  # noqa: BLE001
            if not _is_denied(exc):
                raise AssertionError(f"成员降级后写失败但错误非权限类: {exc!r}") from exc
        else:
            raise AssertionError("成员降级为 member 后仍可写群自有区")

        transfer = await owner.start_group_transfer(
            {
                "group_id": group_id,
                "new_owner": new_owner_aid,
            },
            aid_store=owner_store,
        )
        if transfer.get("status") != "pending_rekey" or not transfer.get("requires_ca_rekey"):
            raise AssertionError(f"group-storage transfer 未进入 pending_rekey: {transfer}")

        completed = await new_owner.complete_group_transfer(
            {"group_id": group_id},
            aid_store=new_owner_store,
        )
        done_group = completed.get("group") or {}
        if completed.get("status") != "transferred" or done_group.get("owner_aid") != new_owner_aid:
            raise AssertionError(f"complete_group_transfer 返回异常: {completed}")
        loaded_after = new_owner_store.load(group_aid)
        if not loaded_after.ok or loaded_after.data is None or not loaded_after.data["aid"].is_private_key_valid():
            raise AssertionError("新群主未落盘 rekey 后 group_aid 私钥")

        # F19：rekey 后旧群主本地旧 group_aid 私钥不能再完成群自有区写，新群主新私钥可以写。
        stale_path = f"archive/old-owner-stale-{rid}.txt"
        try:
            stale_pending = await owner.group.resources.put({
                "group_id": group_id,
                "resource_path": stale_path,
                "resource_type": "file",
                "content": base64.b64encode(b"STALE").decode("ascii"),
                "content_type": "text/plain",
            })
            await owner.group.resources.execute_pending_ops(stale_pending, aid_store=stale_group_store)
        except Exception as exc:  # noqa: BLE001
            if not _is_denied(exc):
                raise AssertionError(f"旧群主旧私钥写失败但错误非权限/签名类: {exc!r}") from exc
        else:
            raise AssertionError("旧群主旧 group_aid 私钥在 rekey 后仍可写群自有区")

        new_owner_path = f"archive/new-owner-{rid}.txt"
        new_pending = await new_owner.group.resources.put({
            "group_id": group_id,
            "resource_path": new_owner_path,
            "resource_type": "file",
            "content": base64.b64encode(b"NEW_OWNER").decode("ascii"),
            "content_type": "text/plain",
        })
        new_done = await new_owner.group.resources.execute_pending_ops(new_pending, aid_store=new_owner_store)
        if not (new_done.get("confirmed") or {}).get("confirmed"):
            raise AssertionError(f"新群主 rekey 后写入失败: {new_done}")

        # F20：退群后 memberdata mount 失效。
        await _rpc(member, "group.leave", {"group_id": group_id})
        try:
            await owner.group.resources.get_access({
                "group_id": group_id,
                "resource_path": f"memberdata/{member_aid}/{member_child}/note.txt",
            })
        except Exception as exc:  # noqa: BLE001
            if not _is_denied(exc):
                raise AssertionError(f"退群后 memberdata 读取失败但错误非权限类: {exc!r}") from exc
        else:
            raise AssertionError("成员退群后 memberdata 挂载仍可读取")

        _ok("named_group_storage_full_flow")
    finally:
        if group_id:
            try:
                await _rpc(new_owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                try:
                    await _rpc(owner, "group.dissolve", {"group_id": group_id})
                except Exception:
                    pass
        owner_store.close()
        new_owner_store.close()
        member_store.close()
        if stale_group_store is not None:
            stale_group_store.close()
        if stale_group_tmp is not None:
            stale_group_tmp.cleanup()
        await member.close()
        await new_owner.close()
        await owner.close()


async def main() -> None:
    print("=== AUN group-storage 单域 E2E ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    try:
        await test_named_group_storage_full_flow()
    except Exception as exc:
        _fail("named_group_storage_full_flow", str(exc))

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
