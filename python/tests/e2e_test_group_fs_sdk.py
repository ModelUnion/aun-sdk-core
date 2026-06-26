#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

import pytest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from aun_core import AIDStore, AUNClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get(
    "AUN_TEST_AUN_PATH",
    f"{_AUN_DATA_ROOT}/single-domain/persistent" if _AUN_DATA_ROOT else "./.aun_test_group_fs_sdk_e2e",
).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_SEED = os.environ.get("AUN_TEST_ENCRYPTION_SEED", "")

pytestmark = pytest.mark.asyncio


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


def _make_store() -> AIDStore:
    return AIDStore(_TEST_AUN_PATH, encryption_seed=_SEED, verify_ssl=False)


async def _create_named_group(owner: AUNClient, owner_aid: str, group_name: str) -> tuple[str, str, AIDStore]:
    store = _make_store()
    await ensure_connected_identity(owner, owner_aid)
    created = await owner.create_group(
        {
            "name": f"group-fs-sdk-{group_name}",
            "group_name": group_name,
            "visibility": "private",
        },
        aid_store=store,
    )
    group = created.get("group") if isinstance(created, dict) else {}
    group_id = str((group or {}).get("group_id") or "").strip()
    group_aid = str((group or {}).get("group_aid") or "").strip()
    if not group_id or not group_aid:
        store.close()
        raise AssertionError(f"create_group 未返回 group_id/group_aid: {created}")
    return group_id, group_aid, store


async def test_group_fs_sdk_facade_roundtrip(tmp_path: Path) -> None:
    rid = uuid.uuid4().hex[:8]
    owner_aid = f"gfs-sdk-owner-{rid}.{_ISSUER}"
    group_name = f"gfssdk{rid}"
    owner = _make_client()
    group_id = ""
    store: AIDStore | None = None
    try:
        group_id, group_aid, store = await _create_named_group(owner, owner_aid, group_name)
        try:
            await owner.call("group.fs.namespace_ready", {"group_id": group_id})
        except Exception:
            pass

        base_dir = f"{group_aid}:/public/sdk-e2e-{rid}"
        source = tmp_path / "source.txt"
        downloaded = tmp_path / "download.txt"
        body = f"GROUP-FS-SDK-E2E-{rid}"
        source.write_text(body, encoding="utf-8")
        write_opts = {"sign_as": group_aid, "aid_store": store}

        await owner.group.fs.mkdir(base_dir, parents=True, **write_opts)
        uploaded = await owner.group.fs.cp(str(source), f"{base_dir}/note.txt", force=True, **write_opts)
        if str(uploaded.get("type") or "") != "file":
            raise AssertionError(f"cp 上传返回异常: {uploaded}")

        listed = await owner.group.fs.ls(base_dir, long=True)
        items = listed.get("items") if isinstance(listed, dict) else []
        if not any(isinstance(item, dict) and item.get("name") == "note.txt" for item in items):
            raise AssertionError(f"ls 未返回上传文件: {listed}")

        stat = await owner.group.fs.stat(f"{base_dir}/note.txt")
        if stat.get("type") != "file" or stat.get("name") != "note.txt":
            raise AssertionError(f"stat 返回异常: {stat}")

        usage = await owner.group.fs.df(base_dir)
        if not isinstance(usage, dict) or not str(usage.get("group_aid") or group_aid):
            raise AssertionError(f"df 返回异常: {usage}")

        copied = await owner.group.fs.cp(f"{base_dir}/note.txt", f"{base_dir}/copy.txt", force=True, **write_opts)
        if str(copied.get("type") or "") != "file":
            raise AssertionError(f"群内 cp 返回异常: {copied}")

        moved = await owner.group.fs.mv(f"{base_dir}/copy.txt", f"{base_dir}/renamed.txt", force=True, **write_opts)
        if moved.get("name") != "renamed.txt":
            raise AssertionError(f"mv 返回异常: {moved}")

        found = await owner.group.fs.find(base_dir, name="renamed.txt")
        found_items = found.get("items") if isinstance(found, dict) else []
        if not any(isinstance(item, dict) and item.get("name") == "renamed.txt" for item in found_items):
            raise AssertionError(f"find 未返回 renamed.txt: {found}")

        result = await owner.group.fs.cp(f"{base_dir}/note.txt", f"local:{downloaded}", force=True)
        if not getattr(result, "verified", False) or int(getattr(result, "size", 0) or 0) != len(body.encode("utf-8")):
            raise AssertionError(f"下载结果内容异常: {result}")
        if downloaded.read_text(encoding="utf-8") != body:
            raise AssertionError("下载本地文件内容不一致")

        removed = await owner.group.fs.rm(base_dir, recursive=True, force=True, **write_opts)
        if int(removed.get("removed_count") or 0) < 1:
            raise AssertionError(f"rm 返回异常: {removed}")
    finally:
        if group_id:
            try:
                await owner.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        if store is not None:
            store.close()
        await owner.close()


async def test_group_fs_admin_role_acl_grant_and_revoke(tmp_path: Path) -> None:
    rid = uuid.uuid4().hex[:8]
    owner_aid = f"gfs-acl-owner-{rid}.{_ISSUER}"
    admin_aid = f"gfs-acl-admin-{rid}.{_ISSUER}"
    group_name = f"gfsacl{rid}"
    owner = _make_client()
    admin = _make_client()
    group_id = ""
    store: AIDStore | None = None
    try:
        await ensure_connected_identity(admin, admin_aid)
        group_id, group_aid, store = await _create_named_group(owner, owner_aid, group_name)
        await owner.call("group.add_member", {"group_id": group_id, "aid": admin_aid, "role": "member"})
        role_result = await owner.call("group.set_role", {"group_id": group_id, "aid": admin_aid, "role": "admin"})
        if role_result.get("new_role") != "admin":
            raise AssertionError(f"group.set_role 未返回 admin: {role_result}")
        try:
            await owner.call("group.fs.namespace_ready", {"group_id": group_id})
        except Exception:
            pass

        base_dir = f"{group_aid}:/archive/python-acl-{rid}"
        before = tmp_path / "before.txt"
        granted = tmp_path / "granted.txt"
        after = tmp_path / "after.txt"
        before.write_text(f"before grant {rid}", encoding="utf-8")
        granted_body = f"admin write after grant {rid}"
        granted.write_text(granted_body, encoding="utf-8")
        after.write_text(f"after revoke {rid}", encoding="utf-8")

        with pytest.raises(Exception):
            await admin.group.fs.cp(str(before), f"{base_dir}/before.txt", force=True, parents=True)

        grant = await owner.group.fs.set_acl(base_dir, grantee_aid="role:admin", perms="rwx")
        if grant.get("acl_action") != "set_acl":
            raise AssertionError(f"group.fs.set_acl 返回异常: {grant}")

        uploaded = await admin.group.fs.cp(str(granted), f"{base_dir}/granted.txt", force=True, parents=True)
        if str(uploaded.get("type") or "") != "file":
            raise AssertionError(f"admin 授权后写入异常: {uploaded}")

        downloaded = tmp_path / "downloaded.txt"
        result = await owner.group.fs.cp(f"{base_dir}/granted.txt", f"local:{downloaded}", force=True)
        if not getattr(result, "verified", False) or downloaded.read_text(encoding="utf-8") != granted_body:
            raise AssertionError(f"owner 读取 admin 写入内容异常: {result}")

        revoked = await owner.group.fs.remove_acl(base_dir, grantee_aid="role:admin")
        if revoked.get("acl_action") != "remove_acl":
            raise AssertionError(f"group.fs.remove_acl 返回异常: {revoked}")

        with pytest.raises(Exception):
            await admin.group.fs.cp(str(after), f"{base_dir}/after.txt", force=True, parents=True)
    finally:
        if group_id:
            try:
                await owner.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        if store is not None:
            store.close()
        await admin.close()
        await owner.close()
