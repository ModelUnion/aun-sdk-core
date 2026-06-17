"""群协作根的 storage ACL 读权限集成测试。"""
from __future__ import annotations

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
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get(
    "AUN_TEST_AUN_PATH",
    f"{_AUN_DATA_ROOT}/single-domain/persistent" if _AUN_DATA_ROOT else "./.aun_test_collab_acl",
).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_SEED = os.environ.get("AUN_TEST_ENCRYPTION_SEED", "")


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


def _make_store() -> AIDStore:
    return AIDStore(_TEST_AUN_PATH, encryption_seed=_SEED, verify_ssl=False)


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


async def _rpc(client: AUNClient, method: str, params: dict[str, Any]) -> Any:
    return await client.call(method, params)


async def _cleanup_root(client: AUNClient, owner: str, collab_root: str) -> None:
    try:
        _, root_path = collab_root.split(":", 1)
        await client.storage.remove(root_path, owner=owner, recursive=True)
    except Exception as exc:
        print(f"[collab-acl] cleanup root skipped: {exc}")


async def _grant_root_acl(client: AUNClient, owner: str, collab_root: str, grantee_aid: str, perms: str) -> None:
    _, root_path = collab_root.split(":", 1)
    await client.storage.set_acl(root_path, owner=owner, grantee_aid=grantee_aid, perms=perms)
    print(f"[collab-acl] acl owner={owner} root={root_path} grantee={grantee_aid} perms={perms}")


def _is_permission_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(token in text for token in ("permission", "forbidden", "denied", "无权", "权限", "不存在"))


async def _setup_group_case(*, grant_charlie: bool) -> tuple[AUNClient, AUNClient, AUNClient, AIDStore, str, str, str]:
    rid = uuid.uuid4().hex[:10]
    owner_aid = f"collab-acl-owner-{rid}.{_ISSUER}"
    member_aid = f"collab-acl-member-{rid}.{_ISSUER}"
    charlie_aid = f"collab-acl-charlie-{rid}.{_ISSUER}"
    owner = _make_client()
    member = _make_client()
    charlie = _make_client()
    store = _make_store()

    await ensure_connected_identity(owner, owner_aid)
    await ensure_connected_identity(member, member_aid)
    await ensure_connected_identity(charlie, charlie_aid)

    created = await owner.create_group(
        {
            "name": f"collab-acl-{rid}",
            "group_name": f"gacl{rid}",
            "visibility": "private",
        },
        aid_store=store,
    )
    group = created.get("group") or {}
    group_id = str(group.get("group_id") or "")
    group_aid = str(group.get("group_aid") or "")
    if not group_id or not group_aid:
        raise AssertionError(f"create_group 未返回 group_id/group_aid: {created}")
    await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": member_aid, "role": "member"})

    collab_root = f"{group_aid}:/collab-acl/{rid}/proj"
    await _grant_root_acl(owner, group_aid, collab_root, owner_aid, "rwd")
    await _grant_root_acl(owner, group_aid, collab_root, member_aid, "r")
    if grant_charlie:
        await _grant_root_acl(owner, group_aid, collab_root, charlie_aid, "r")

    await owner.collab.create(collab_root, "doc1.md", _b64("group acl\n"))
    return owner, member, charlie, store, group_id, group_aid, collab_root


async def _close_case(
    owner: AUNClient,
    member: AUNClient,
    charlie: AUNClient,
    store: AIDStore,
    group_id: str,
    group_aid: str,
    collab_root: str,
) -> None:
    await _cleanup_root(owner, group_aid, collab_root)
    try:
        await _rpc(owner, "group.dissolve", {"group_id": group_id})
    except Exception as exc:
        print(f"[collab-acl] dissolve skipped: {exc}")
    store.close()
    await charlie.close()
    await member.close()
    await owner.close()


@pytest.mark.asyncio
async def test_collab_read_non_member_with_acl() -> None:
    owner, member, charlie, store, group_id, group_aid, collab_root = await _setup_group_case(grant_charlie=True)
    try:
        result = await charlie.collab.show(collab_root, "doc1.md")
        content = base64.b64decode(str(result.get("content") or "")).decode("utf-8")
        assert content == "group acl\n", f"Charlie 读取内容异常: {result}"
        print(f"[collab-acl] non-member read with ACL ok root={collab_root}")
    finally:
        await _close_case(owner, member, charlie, store, group_id, group_aid, collab_root)


@pytest.mark.asyncio
async def test_collab_read_non_member_without_acl() -> None:
    owner, member, charlie, store, group_id, group_aid, collab_root = await _setup_group_case(grant_charlie=False)
    try:
        with pytest.raises(Exception) as exc_info:
            await charlie.collab.show(collab_root, "doc1.md")
        assert _is_permission_error(exc_info.value), f"无 ACL 读取应被权限拒绝，实际: {exc_info.value}"
        print(f"[collab-acl] non-member read without ACL denied: {exc_info.value}")
    finally:
        await _close_case(owner, member, charlie, store, group_id, group_aid, collab_root)
