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

from aun_core import AUNClient, AuthError, RateLimitError

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
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            await client.connect(auth)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


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
