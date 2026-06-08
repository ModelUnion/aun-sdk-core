#!/usr/bin/env python3
"""group.resources 集成测试。

覆盖：
  1. owner direct_add + 成员 list/get/get_access/resolve_access_ticket
  2. prefix/tags/visibility/owner/sort/offset 组合过滤
  3. 成员 request_add，owner approve/reject，pending 列表
  4. 非 owner direct_add/list_pending/approve/reject 被拒绝
  5. 非成员访问群资源被拒绝
  6. update/delete 权限与参数冲突
"""
from __future__ import annotations

import asyncio
import base64
import os
import ssl
import sys
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


from aun_core import AUNClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_resources"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
_CHARLIE_AID = os.environ.get("AUN_TEST_CHARLIE_AID", f"charlie.{_ISSUER}").strip()

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str):
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str):
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} - {reason}")


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    return await ensure_connected_identity(client, aid)


async def _expect_failure(factory, label: str, *, contains: str | None = None):
    try:
        await factory()
    except Exception as exc:
        text = str(exc)
        if contains and contains not in text:
            raise AssertionError(f"{label}: 失败信息不匹配: {text}") from exc
        print(f"  [OK] {label}: {exc}")
        return
    raise AssertionError(f"{label}: 期望失败但实际成功")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _assert_non_loopback_url(url: str, label: str):
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise AssertionError(f"{label} host 为空: {url}")
    if host in {"127.0.0.1", "localhost", "0.0.0.0", "::1", "::"}:
        raise AssertionError(f"{label} 不应返回 loopback URL: {url}")


async def _http_get_bytes(url: str) -> bytes:
    def _download() -> bytes:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(url, timeout=20, context=ctx) as resp:
            return resp.read()

    return await asyncio.to_thread(_download)


async def _put_storage(client: AUNClient, owner_aid: str, bucket: str, object_key: str, body: bytes, *, is_private: bool = True) -> dict:
    return await client.call("storage.put_object", {
        "owner_aid": owner_aid,
        "bucket": bucket,
        "object_key": object_key,
        "content": _b64(body),
        "content_type": "text/plain",
        "is_private": is_private,
    })


async def _create_group_with_members(alice: AUNClient, group_name: str, *member_aids: str) -> str:
    created = await alice.call("group.create", {
        "name": group_name,
        "visibility": "private",
    })
    group_id = (created.get("group") or {}).get("group_id", "")
    if not group_id:
        raise AssertionError(f"group.create 未返回 group_id: {created}")
    for aid in member_aids:
        await alice.call("group.add_member", {"group_id": group_id, "aid": aid})
    return group_id


async def test_group_resources_direct_access_filters_and_update_delete():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    charlie = _make_client()
    group_id = ""
    bucket = f"group-res-{rid}"
    owner_body = f"owner-resource-{rid}".encode("utf-8")

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)
        group_id = await _create_group_with_members(alice, f"res-direct-{rid}", _BOBB_AID)

        object_key = f"owner/{rid}/guide.txt"
        put = await _put_storage(alice, _ALICE_AID, bucket, object_key, owner_body)
        storage_ref = {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "filename": "guide.txt",
        }

        await _expect_failure(
            lambda: bob.call("group.resources.direct_add", {
                "group_id": group_id,
                "resource_path": f"files/{rid}/not-owner.txt",
                "resource_type": "file",
                "title": "not owner",
                "storage_ref": storage_ref,
            }),
            "非 owner direct_add 被拒绝",
        )
        await _expect_failure(
            lambda: alice.call("group.resources.direct_add", {
                "group_id": group_id,
                "resource_path": "../escape.txt",
                "resource_type": "file",
                "title": "bad",
                "storage_ref": storage_ref,
            }),
            "resource_path 路径穿越被拒绝",
        )
        await _expect_failure(
            lambda: alice.call("group.resources.direct_add", {
                "group_id": group_id,
                "resource_path": f"files/{rid}/bad.txt",
                "resource_type": "bad-type",
                "title": "bad",
                "storage_ref": storage_ref,
            }),
            "非法 resource_type 被拒绝",
        )

        direct = await alice.call("group.resources.direct_add", {
            "group_id": group_id,
            "resource_path": f"files/{rid}/guide.txt",
            "resource_type": "file",
            "title": "Guide",
            "storage_ref": storage_ref,
            "visibility": "members_only",
            "tags": ["docs", "release"],
            "metadata": {"kind": "guide"},
        })
        resource = direct.get("resource") or {}
        if resource.get("resource_path") != f"files/{rid}/guide.txt":
            raise AssertionError(f"direct_add 返回异常: {direct}")
        if resource.get("owner_aid") != _ALICE_AID:
            raise AssertionError(f"resource owner_aid 异常: {resource}")

        await _expect_failure(
            lambda: charlie.call("group.resources.list", {"group_id": group_id}),
            "非成员 list_resources 被拒绝",
        )

        listed = await bob.call("group.resources.list", {
            "group_id": group_id,
            "prefix": f"files/{rid}/",
            "tags": ["docs"],
            "visibility": "members_only",
            "owner_aid": _ALICE_AID,
            "sort_by": "updated_at",
            "order": "desc",
            "size": 10,
        })
        paths = [str(item.get("resource_path") or "") for item in listed.get("items", [])]
        if paths != [f"files/{rid}/guide.txt"]:
            raise AssertionError(f"资源过滤列表异常: {listed}")

        await _expect_failure(
            lambda: bob.call("group.resources.list", {
                "group_id": group_id,
                "size": 5,
                "limit": 5,
            }),
            "list_resources 同时传 size/limit 被拒绝",
        )
        await _expect_failure(
            lambda: bob.call("group.resources.list", {
                "group_id": group_id,
                "page": 1,
                "offset": 0,
            }),
            "list_resources 同时传 page/offset 被拒绝",
        )

        access = await bob.call("group.resources.get_access", {
            "group_id": group_id,
            "resource_path": f"files/{rid}/guide.txt",
        })
        download_url = str((access.get("download") or {}).get("download_url") or "")
        if not download_url:
            raise AssertionError(f"get_access 未返回 download_url: {access}")
        _assert_non_loopback_url(download_url, "group.resources.get_access.download_url")
        if await _http_get_bytes(download_url) != owner_body:
            raise AssertionError("group resource 下载内容不匹配")

        ticket = (access.get("access_ticket") or {}).get("ticket") or access.get("access_token")
        if not ticket:
            raise AssertionError(f"get_access 未返回 access ticket: {access}")
        resolved = await bob.call("group.resources.resolve_access_ticket", {
            "access_ticket": ticket,
        })
        resolved_url = str((resolved.get("download") or {}).get("download_url") or "")
        if not resolved_url:
            raise AssertionError(f"resolve_access_ticket 未返回 download_url: {resolved}")

        await _expect_failure(
            lambda: bob.call("group.resources.resolve_access_ticket", {
                "access_ticket": ticket,
            }),
            "access_ticket 二次使用被拒绝",
        )

        updated = await alice.call("group.resources.update", {
            "group_id": group_id,
            "resource_path": f"files/{rid}/guide.txt",
            "title": "Guide v2",
            "visibility": "public",
            "tags": ["docs", "v2"],
            "metadata": {"kind": "guide", "version": 2},
        })
        if (updated.get("resource") or {}).get("title") != "Guide v2":
            raise AssertionError(f"resources.update 返回异常: {updated}")

        page = await bob.call("group.resources.list", {
            "group_id": group_id,
            "offset": 0,
            "limit": 1,
            "sort_by": "resource_path",
        })
        if len(page.get("items", [])) > 1:
            raise AssertionError(f"offset/limit 分页异常: {page}")

        deleted = await alice.call("group.resources.delete", {
            "group_id": group_id,
            "resource_path": f"files/{rid}/guide.txt",
        })
        if deleted.get("deleted") is not True:
            raise AssertionError(f"resources.delete 返回异常: {deleted}")
        await _expect_failure(
            lambda: bob.call("group.resources.get", {
                "group_id": group_id,
                "resource_path": f"files/{rid}/guide.txt",
            }),
            "删除后的资源不可读取",
        )

        _ok("group_resources_direct_access_filters_and_update_delete")
    finally:
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        await charlie.close()
        await bob.close()
        await alice.close()


async def test_group_resources_request_approve_reject_flow():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    group_id = ""
    bucket = f"group-req-{rid}"

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        group_id = await _create_group_with_members(alice, f"res-request-{rid}", _BOBB_AID)

        bob_object = f"bob/{rid}/proposal.txt"
        bob_body = f"bob-proposal-{rid}".encode("utf-8")
        await _put_storage(bob, _BOBB_AID, bucket, bob_object, bob_body)
        bob_ref = {
            "owner_aid": _BOBB_AID,
            "bucket": bucket,
            "object_key": bob_object,
            "filename": "proposal.txt",
        }

        await _expect_failure(
            lambda: bob.call("group.resources.request_add", {
                "group_id": group_id,
                "resource_path": f"requests/{rid}/wrong-owner.txt",
                "resource_type": "file",
                "title": "wrong owner",
                "storage_ref": {
                    "owner_aid": _ALICE_AID,
                    "bucket": bucket,
                    "object_key": bob_object,
                },
            }),
            "request_add 不允许引用非本人 storage 对象",
        )

        request = await bob.call("group.resources.request_add", {
            "group_id": group_id,
            "resource_path": f"requests/{rid}/proposal.txt",
            "resource_type": "file",
            "title": "Proposal",
            "storage_ref": bob_ref,
            "visibility": "members_only",
            "tags": ["proposal"],
        })
        req_obj = request.get("request") or {}
        request_id = str(req_obj.get("request_id") or "")
        if not request_id or req_obj.get("status") != "pending":
            raise AssertionError(f"request_add 返回异常: {request}")

        await _expect_failure(
            lambda: bob.call("group.resources.list_pending", {"group_id": group_id}),
            "非 owner list_pending 被拒绝",
        )
        pending = await alice.call("group.resources.list_pending", {
            "group_id": group_id,
            "status": "pending",
        })
        pending_ids = [str(item.get("request_id") or "") for item in pending.get("items", [])]
        if request_id not in pending_ids:
            raise AssertionError(f"pending 列表未包含请求: {pending}")

        await _expect_failure(
            lambda: bob.call("group.resources.approve_request", {
                "request_id": request_id,
            }),
            "非 owner approve_request 被拒绝",
        )
        approved = await alice.call("group.resources.approve_request", {
            "request_id": request_id,
            "note": "ok",
        })
        if (approved.get("request") or {}).get("status") != "approved":
            raise AssertionError(f"approve_request 返回异常: {approved}")
        if (approved.get("resource") or {}).get("created_by") != _BOBB_AID:
            raise AssertionError(f"approved resource created_by 异常: {approved}")

        access = await alice.call("group.resources.get_access", {
            "group_id": group_id,
            "resource_path": f"requests/{rid}/proposal.txt",
        })
        download_url = str((access.get("download") or {}).get("download_url") or "")
        _assert_non_loopback_url(download_url, "approved resource download_url")
        if await _http_get_bytes(download_url) != bob_body:
            raise AssertionError("approved resource 下载内容不匹配")

        reject_object = f"bob/{rid}/reject.txt"
        await _put_storage(bob, _BOBB_AID, bucket, reject_object, b"reject-me")
        reject_req = await bob.call("group.resources.request_add", {
            "group_id": group_id,
            "resource_path": f"requests/{rid}/reject.txt",
            "resource_type": "file",
            "title": "Reject",
            "storage_ref": {
                "owner_aid": _BOBB_AID,
                "bucket": bucket,
                "object_key": reject_object,
                "filename": "reject.txt",
            },
        })
        reject_id = str((reject_req.get("request") or {}).get("request_id") or "")
        rejected = await alice.call("group.resources.reject_request", {
            "request_id": reject_id,
            "note": "no",
        })
        if (rejected.get("request") or {}).get("status") != "rejected":
            raise AssertionError(f"reject_request 返回异常: {rejected}")
        await _expect_failure(
            lambda: alice.call("group.resources.approve_request", {
                "request_id": reject_id,
            }),
            "已拒绝请求不能再 approve",
        )

        _ok("group_resources_request_approve_reject_flow")
    finally:
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        await bob.close()
        await alice.close()


async def test_group_resources_tree_folder_mount_rename_move_delete():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    charlie = _make_client()
    group_id = ""
    object_id = ""
    bucket = f"group-tree-{rid}"
    body = f"group-tree-body-{rid}".encode("utf-8")

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)
        group_id = await _create_group_with_members(alice, f"res-tree-{rid}", _BOBB_AID)

        object_key = f"tree/{rid}/report.txt"
        put = await _put_storage(alice, _ALICE_AID, bucket, object_key, body, is_private=True)
        object_id = str(put.get("object_id") or "")
        if not object_id:
            raise AssertionError(f"storage.put_object 未返回 object_id: {put}")

        await _expect_failure(
            lambda: bob.call("group.resources.mount_object", {
                "group_id": group_id,
                "path": f"资料/{rid}/bob.txt",
                "storage_ref": {
                    "owner_aid": _BOBB_AID,
                    "bucket": bucket,
                    "object_key": object_key,
                },
            }),
            "普通成员不能直接 mount_object",
        )

        root = await alice.call("group.resources.create_folder", {
            "group_id": group_id,
            "path": f"资料/{rid}",
            "mkdirs": True,
        })
        root_id = str((root.get("resource") or {}).get("resource_id") or "")
        if not root_id:
            raise AssertionError(f"create_folder 未返回 resource_id: {root}")

        mounted = await alice.call("group.resources.mount_object", {
            "group_id": group_id,
            "parent_resource_id": root_id,
            "name": "report.txt",
            "storage_ref": {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_id": object_id,
                "object_key": object_key,
                "filename": "report.txt",
            },
        })
        resource = mounted.get("resource") or {}
        resource_id = str(resource.get("resource_id") or "")
        if not resource_id or resource.get("resource_path") != f"资料/{rid}/report.txt":
            raise AssertionError(f"mount_object 返回异常: {mounted}")
        if ((resource.get("storage_ref") or {}).get("object_id") != object_id):
            raise AssertionError(f"mount_object 未保存 object_id: {resource}")

        listed = await bob.call("group.resources.list_children", {
            "group_id": group_id,
            "resource_id": root_id,
            "include_status": True,
        })
        if listed.get("total") != 1 or (listed.get("items") or [{}])[0].get("resource_id") != resource_id:
            raise AssertionError(f"list_children 返回异常: {listed}")
        if (listed.get("items") or [{}])[0].get("storage_status", {}).get("exists") is not True:
            raise AssertionError(f"include_status 未确认 storage 存在: {listed}")

        access = await bob.call("group.resources.get_access", {
            "group_id": group_id,
            "resource_id": resource_id,
        })
        download_url = str((access.get("download") or {}).get("download_url") or "")
        _assert_non_loopback_url(download_url, "tree get_access.download_url")
        if await _http_get_bytes(download_url) != body:
            raise AssertionError("resource_id get_access 下载内容不匹配")

        await _expect_failure(
            lambda: charlie.call("group.resources.get_access", {
                "group_id": group_id,
                "resource_id": resource_id,
            }),
            "非成员不能 get_access",
        )
        await _expect_failure(
            lambda: bob.call("group.resources.get_access", {
                "group_id": group_id,
                "resource_id": root_id,
            }),
            "folder 不能 get_access",
        )

        renamed = await alice.call("group.resources.rename", {
            "group_id": group_id,
            "resource_id": resource_id,
            "new_name": "report-v2.txt",
        })
        if (renamed.get("resource") or {}).get("resource_id") != resource_id:
            raise AssertionError(f"rename 后 resource_id 不稳定: {renamed}")
        await _expect_failure(
            lambda: bob.call("group.resources.resolve_path", {
                "group_id": group_id,
                "path": f"资料/{rid}/report.txt",
                "expected_type": "file",
            }),
            "rename 后旧 resource path 失效",
        )

        archive = await alice.call("group.resources.create_folder", {
            "group_id": group_id,
            "path": f"归档/{rid}",
            "mkdirs": True,
        })
        archive_id = str((archive.get("resource") or {}).get("resource_id") or "")
        moved = await alice.call("group.resources.move", {
            "group_id": group_id,
            "resource_id": resource_id,
            "dst_parent_resource_id": archive_id,
        })
        moved_path = (moved.get("resource") or {}).get("resource_path")
        if moved_path != f"归档/{rid}/report-v2.txt":
            raise AssertionError(f"move 返回异常: {moved}")
        moved_access = await bob.call("group.resources.get_access", {
            "group_id": group_id,
            "resource_id": resource_id,
        })
        if str(moved_access.get("resource_path") or "") != f"归档/{rid}/report-v2.txt":
            raise AssertionError(f"move 后 resource_id 访问路径异常: {moved_access}")

        refs = await alice.call("group.resources.list_refs_by_storage", {
            "group_id": group_id,
            "owner_aid": _ALICE_AID,
            "object_id": object_id,
        })
        if refs.get("total") != 1 or (refs.get("items") or [{}])[0].get("resource_id") != resource_id:
            raise AssertionError(f"list_refs_by_storage 返回异常: {refs}")

        await _expect_failure(
            lambda: alice.call("group.resources.delete", {
                "group_id": group_id,
                "resource_id": archive_id,
            }),
            "非空群资源目录 recursive=false 删除被拒绝",
        )
        deleted = await alice.call("group.resources.delete", {
            "group_id": group_id,
            "resource_id": archive_id,
            "recursive": True,
        })
        paths = {str(item.get("resource_path") or "") for item in deleted.get("deleted_resources", [])}
        if f"归档/{rid}/report-v2.txt" not in paths or f"归档/{rid}" not in paths:
            raise AssertionError(f"recursive delete 返回异常: {deleted}")
        storage_head = await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
        })
        if storage_head.get("object_id") != object_id:
            raise AssertionError(f"删除群资源不应删除 storage object: {storage_head}")

        _ok("group_resources_tree_folder_mount_rename_move_delete")
    finally:
        try:
            await alice.call("storage.delete_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_id": object_id,
            })
        except Exception:
            pass
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        await charlie.close()
        await bob.close()
        await alice.close()


async def test_group_resources_request_mount_cleanup_and_unmount_edges():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    charlie = _make_client()
    group_id = ""
    bucket = f"group-edges-{rid}"
    bob_object_id = ""
    cleanup_object_id = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)
        group_id = await _create_group_with_members(alice, f"res-edges-{rid}", _BOBB_AID)

        bob_object_key = f"bob/{rid}/proposal.txt"
        bob_body = f"proposal-{rid}".encode("utf-8")
        bob_put = await _put_storage(bob, _BOBB_AID, bucket, bob_object_key, bob_body)
        bob_object_id = str(bob_put.get("object_id") or "")
        if not bob_object_id:
            raise AssertionError(f"Bob storage.put_object 未返回 object_id: {bob_put}")

        request = await bob.call("group.resources.request_mount_object", {
            "group_id": group_id,
            "path": f"requests/{rid}/proposal.txt",
            "storage_ref": {
                "owner_aid": _BOBB_AID,
                "bucket": bucket,
                "object_id": bob_object_id,
                "object_key": bob_object_key,
                "filename": "proposal.txt",
            },
            "metadata": {"kind": "proposal"},
        })
        req_obj = request.get("request") or {}
        request_id = str(req_obj.get("request_id") or "")
        if not request_id or (req_obj.get("storage_ref") or {}).get("object_id") != bob_object_id:
            raise AssertionError(f"request_mount_object 未保存 object_id: {request}")
        await _expect_failure(
            lambda: bob.call("group.resources.approve_request", {"request_id": request_id}),
            "普通成员不能 approve request_mount_object",
        )
        approved = await alice.call("group.resources.approve_request", {
            "request_id": request_id,
        })
        resource = approved.get("resource") or {}
        if resource.get("created_by") != _BOBB_AID or (resource.get("storage_ref") or {}).get("object_id") != bob_object_id:
            raise AssertionError(f"approve_request 创建资源异常: {approved}")

        refs_by_key = await bob.call("group.resources.list_refs_by_storage", {
            "group_id": group_id,
            "owner_aid": _BOBB_AID,
            "object_key": bob_object_key,
        })
        if refs_by_key.get("total") != 1 or (refs_by_key.get("items") or [{}])[0].get("resource_id") != resource.get("resource_id"):
            raise AssertionError(f"list_refs_by_storage object_key fallback 异常: {refs_by_key}")
        access = await alice.call("group.resources.get_access", {
            "group_id": group_id,
            "resource_id": resource.get("resource_id"),
        })
        url = str((access.get("download") or {}).get("download_url") or "")
        _assert_non_loopback_url(url, "approved request_mount_object download_url")
        if await _http_get_bytes(url) != bob_body:
            raise AssertionError("request_mount_object approve 后下载内容不匹配")

        cleanup_key = f"cleanup/{rid}/one.txt"
        cleanup_body = f"cleanup-{rid}".encode("utf-8")
        cleanup_put = await _put_storage(alice, _ALICE_AID, bucket, cleanup_key, cleanup_body)
        cleanup_object_id = str(cleanup_put.get("object_id") or "")
        first = await alice.call("group.resources.mount_object", {
            "group_id": group_id,
            "path": f"cleanup/{rid}/one.txt",
            "storage_ref": {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_id": cleanup_object_id,
                "object_key": cleanup_key,
                "filename": "one.txt",
            },
        })
        second = await alice.call("group.resources.mount_object", {
            "group_id": group_id,
            "path": f"cleanup/{rid}/two.txt",
            "storage_ref": {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_id": cleanup_object_id,
                "object_key": cleanup_key,
                "filename": "two.txt",
            },
        })
        await _expect_failure(
            lambda: bob.call("group.resources.cleanup_by_storage_ref", {
                "group_id": group_id,
                "owner_aid": _ALICE_AID,
                "object_id": cleanup_object_id,
            }),
            "非 owner/admin/storage_owner 不能 cleanup",
        )
        cleanup = await alice.call("group.resources.cleanup_by_storage_ref", {
            "group_id": group_id,
            "owner_aid": _ALICE_AID,
            "object_id": cleanup_object_id,
            "mode": "delete",
        })
        if cleanup.get("affected_count") != 2:
            raise AssertionError(f"cleanup_by_storage_ref delete 返回异常: {cleanup}")
        refs_after_delete = await alice.call("group.resources.list_refs_by_storage", {
            "group_id": group_id,
            "owner_aid": _ALICE_AID,
            "object_id": cleanup_object_id,
        })
        if refs_after_delete.get("total") != 0:
            raise AssertionError(f"cleanup delete 后仍有引用: {refs_after_delete}")
        storage_head = await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": cleanup_object_id,
        })
        if storage_head.get("object_id") != cleanup_object_id:
            raise AssertionError(f"cleanup 不应删除 storage object: {storage_head}")

        unmount_key = f"unmount/{rid}/file.txt"
        unmount_put = await _put_storage(alice, _ALICE_AID, bucket, unmount_key, b"unmount")
        unmount_object_id = str(unmount_put.get("object_id") or "")
        mounted = await alice.call("group.resources.mount_object", {
            "group_id": group_id,
            "path": f"unmount/{rid}/file.txt",
            "storage_ref": {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_id": unmount_object_id,
                "object_key": unmount_key,
                "filename": "file.txt",
            },
        })
        unmounted = await alice.call("group.resources.unmount", {
            "group_id": group_id,
            "resource_id": (mounted.get("resource") or {}).get("resource_id"),
        })
        if unmounted.get("deleted") is not True:
            raise AssertionError(f"unmount_resource 返回异常: {unmounted}")
        await _expect_failure(
            lambda: bob.call("group.resources.resolve_path", {
                "group_id": group_id,
                "path": f"unmount/{rid}/file.txt",
            }),
            "unmount 后群资源 path 失效",
        )
        still_storage = await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": unmount_object_id,
        })
        if still_storage.get("object_id") != unmount_object_id:
            raise AssertionError(f"unmount 不应删除 storage object: {still_storage}")

        _ok("group_resources_request_mount_cleanup_and_unmount_edges")
    finally:
        for owner_client, owner_aid, object_id in [
            (bob, _BOBB_AID, bob_object_id),
            (alice, _ALICE_AID, cleanup_object_id),
        ]:
            if object_id:
                try:
                    await owner_client.call("storage.delete_object", {
                        "owner_aid": owner_aid,
                        "bucket": bucket,
                        "object_id": object_id,
                    })
                except Exception:
                    pass
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        await charlie.close()
        await bob.close()
        await alice.close()


async def test_group_resources_storage_delete_marks_resource_missing():
    """storage.delete_object 后 group resource 引用应自动标记为 missing。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    group_id = ""
    bucket = f"del-missing-{rid}"
    object_id = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        group_id = await _create_group_with_members(alice, f"del-missing-{rid}", _BOBB_AID)

        object_key = f"del/{rid}/file.txt"
        put = await _put_storage(alice, _ALICE_AID, bucket, object_key, b"content")
        object_id = str(put.get("object_id") or "")
        if not object_id:
            raise AssertionError(f"put_object 未返回 object_id: {put}")

        mounted = await alice.call("group.resources.mount_object", {
            "group_id": group_id,
            "path": f"del/{rid}/file.txt",
            "storage_ref": {
                "owner_aid": _ALICE_AID, "bucket": bucket,
                "object_id": object_id, "object_key": object_key,
            },
        })
        resource_id = str((mounted.get("resource") or {}).get("resource_id") or "")
        if not resource_id:
            raise AssertionError(f"mount_object 未返回 resource_id: {mounted}")

        # 删除 storage 对象，服务端应异步触发 group resource mark_missing
        await alice.call("storage.delete_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
        })
        object_id = ""  # 已删，finally 不再重删

        # 等待异步 cleanup 完成（最多 3 秒）
        import time as _time
        deadline = _time.monotonic() + 3.0
        resource_status = ""
        while _time.monotonic() < deadline:
            try:
                detail = await alice.call("group.resources.get", {
                    "group_id": group_id, "resource_id": resource_id,
                })
                resource_status = str((detail.get("resource") or detail).get("status") or "")
                if resource_status == "missing":
                    break
            except Exception:
                pass
            await asyncio.sleep(0.3)

        if resource_status != "missing":
            raise AssertionError(
                f"storage 删除后 group resource 状态应为 missing，实际为: {resource_status!r}"
            )

        _ok("group_resources_storage_delete_marks_resource_missing")
    finally:
        if object_id:
            try:
                await alice.call("storage.delete_object", {
                    "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
                })
            except Exception:
                pass
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        await bob.close()
        await alice.close()


async def test_group_resources_mount_object_conflict_policy():
    """mount_object 的 conflict_policy=replace/keep_both 行为验证。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    group_id = ""
    bucket = f"mount-conflict-{rid}"

    try:
        await _ensure_connected(alice, _ALICE_AID)
        group_id = await _create_group_with_members(alice, f"mount-conflict-{rid}")

        path = f"docs/{rid}/report.txt"
        first_put = await _put_storage(alice, _ALICE_AID, bucket, f"first/{rid}.txt", b"first")
        second_put = await _put_storage(alice, _ALICE_AID, bucket, f"second/{rid}.txt", b"second")
        third_put = await _put_storage(alice, _ALICE_AID, bucket, f"third/{rid}.txt", b"third")

        first_id = str(first_put.get("object_id") or "")
        second_id = str(second_put.get("object_id") or "")
        third_id = str(third_put.get("object_id") or "")

        # 首次挂载
        m1 = await alice.call("group.resources.mount_object", {
            "group_id": group_id, "path": path,
            "storage_ref": {"owner_aid": _ALICE_AID, "bucket": bucket, "object_id": first_id},
        })
        r1_id = str((m1.get("resource") or {}).get("resource_id") or "")

        # 同路径重复挂载 conflict_policy=reject → 应报错
        await _expect_failure(
            lambda: alice.call("group.resources.mount_object", {
                "group_id": group_id, "path": path,
                "storage_ref": {"owner_aid": _ALICE_AID, "bucket": bucket, "object_id": second_id},
                "conflict_policy": "reject",
            }),
            "同路径 reject 应报冲突",
        )

        # conflict_policy=replace → 新 resource_id
        m2 = await alice.call("group.resources.mount_object", {
            "group_id": group_id, "path": path,
            "storage_ref": {"owner_aid": _ALICE_AID, "bucket": bucket, "object_id": second_id},
            "conflict_policy": "replace",
        })
        r2_id = str((m2.get("resource") or {}).get("resource_id") or "")
        if r2_id == r1_id:
            raise AssertionError(f"replace 应产生新 resource_id，仍为旧值: {r2_id}")

        # conflict_policy=keep_both → 第三个 resource，名称带后缀
        m3 = await alice.call("group.resources.mount_object", {
            "group_id": group_id, "path": path,
            "storage_ref": {"owner_aid": _ALICE_AID, "bucket": bucket, "object_id": third_id},
            "conflict_policy": "keep_both",
        })
        r3 = m3.get("resource") or {}
        r3_id = str(r3.get("resource_id") or "")
        if r3_id in {r1_id, r2_id}:
            raise AssertionError(f"keep_both 应产生第三个 resource_id，实际: {r3_id}")
        if r3.get("name") == "report.txt":
            raise AssertionError(f"keep_both 应重命名避免冲突，实际 name={r3.get('name')!r}")

        _ok("group_resources_mount_object_conflict_policy")
    finally:
        for oid in [first_put.get("object_id"), second_put.get("object_id"), third_put.get("object_id")]:
            if oid:
                try:
                    await alice.call("storage.delete_object", {
                        "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": oid,
                    })
                except Exception:
                    pass
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        await alice.close()


async def main():
    global _failed

    print("=== group.resources 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOBB     = {_BOBB_AID}")
    print(f"CHARLIE  = {_CHARLIE_AID}")
    print()

    tests = [
        test_group_resources_direct_access_filters_and_update_delete,
        test_group_resources_request_approve_reject_flow,
        test_group_resources_tree_folder_mount_rename_move_delete,
        test_group_resources_request_mount_cleanup_and_unmount_edges,
        test_group_resources_storage_delete_marks_resource_missing,
        test_group_resources_mount_object_conflict_policy,
    ]

    for fn in tests:
        print(f"--- {fn.__name__} ---")
        try:
            await fn()
        except Exception as exc:
            print(f"  [ERROR] {fn.__name__}: {exc}")
            import traceback
            traceback.print_exc()
            _failed += 1
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

