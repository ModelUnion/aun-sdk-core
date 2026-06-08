#!/usr/bin/env python3
"""Storage 服务集成测试。

覆盖：
  1. inline put/get/head/list/delete/quota
  2. 私有对象跨 AID 拒绝，公开对象跨 AID 可读
  3. storage.object_changed 事件
  4. create_upload_session / complete_upload / create_download_ticket 数据面回路
  5. list_prefixes / list_objects 分页 / overwrite 与 expected_version 冲突
  6. object_key/content/ttl 参数校验
  7. upload session 与 complete_upload 的 CAS、sha256、size 失败路径

使用方法：
  python -X utf8 tests/integration_test_storage.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT 指向 Docker 挂载的持久化数据目录
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import sys
import time
import urllib.request
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_storage"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

# ---------------------------------------------------------------------------
# 计数
# ---------------------------------------------------------------------------

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
    print(f"  [FAIL] {name} — {reason}")


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

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


async def _http_request(url: str, *, method: str = "GET", payload: bytes | None = None,
                        headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    def _run() -> tuple[int, bytes]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=payload, method=method)
        for key, value in (headers or {}).items():
            req.add_header(key, value)

        class _AllMethodRedirectHandler(urllib.request.HTTPRedirectHandler):
            """跟随所有 HTTP 方法的 302/307 重定向（urllib 默认只跟随 GET/HEAD）。"""
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                m = req.get_method()
                if code in (301, 302, 303, 307, 308) and m in ("PUT", "POST", "DELETE", "PATCH"):
                    newreq = urllib.request.Request(
                        newurl, data=req.data, method=m,
                        headers={k: v for k, v in req.header_items() if k.lower() != "host"},
                    )
                    return newreq
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            _AllMethodRedirectHandler(),
        )
        with opener.open(req, timeout=20) as resp:
            return int(resp.status), resp.read()

    return await asyncio.to_thread(_run)


def _assert_non_loopback_url(url: str, label: str):
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise AssertionError(f"{label} host 为空: {url}")
    if host in {"127.0.0.1", "localhost", "0.0.0.0", "::1", "::"}:
        raise AssertionError(f"{label} 不应返回 loopback URL: {url}")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

async def test_storage_inline_permissions_events_and_quota():
    """覆盖 inline 存取、权限、事件与配额回收。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    bucket = f"storage-inline-{rid}"
    private_key = f"private/docs/{rid}/secret.txt"
    public_key = f"public/docs/{rid}/readme.txt"

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        events: list[dict] = []
        done = asyncio.Event()

        def on_storage_changed(data):
            if not isinstance(data, dict):
                return
            key = str(data.get("object_key") or "")
            if key not in {private_key, public_key}:
                return
            events.append(dict(data))
            if len(events) >= 4:
                done.set()

        sub = alice.on("storage.object_changed", on_storage_changed)
        try:
            quota_before = await alice.call("storage.get_quota", {"owner_aid": _ALICE_AID})
            used_before = int(quota_before.get("used_bytes") or 0)
            count_before = int(quota_before.get("object_count") or 0)

            private_body = f"secret-{rid}".encode("utf-8")
            public_body = f"public-{rid}".encode("utf-8")

            private_put = await alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": private_key,
                "content": _b64(private_body),
                "content_type": "text/plain",
                "is_private": True,
            })
            if private_put.get("object_key") != private_key:
                raise AssertionError(f"private put 返回异常: {private_put}")

            private_head = await alice.call("storage.head_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": private_key,
            })
            if int(private_head.get("size_bytes") or 0) != len(private_body):
                raise AssertionError(f"private head size 异常: {private_head}")
            if private_head.get("is_private") is not True:
                raise AssertionError(f"private head is_private 异常: {private_head}")

            private_get = await alice.call("storage.get_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": private_key,
            })
            if base64.b64decode(str(private_get.get("content") or "")) != private_body:
                raise AssertionError(f"private get 内容不匹配: {private_get}")

            await _expect_failure(
                lambda: bob.call("storage.head_object", {
                    "owner_aid": _ALICE_AID,
                    "bucket": bucket,
                    "object_key": private_key,
                }),
                "Bob 读取私有对象 metadata",
            )
            await _expect_failure(
                lambda: bob.call("storage.get_object", {
                    "owner_aid": _ALICE_AID,
                    "bucket": bucket,
                    "object_key": private_key,
                }),
                "Bob 读取私有对象内容",
            )
            await _expect_failure(
                lambda: bob.call("storage.get_quota", {"owner_aid": _ALICE_AID}),
                "Bob 查询 Alice 配额",
            )

            public_put = await alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": public_key,
                "content": _b64(public_body),
                "content_type": "text/plain",
                "is_private": False,
            })
            if public_put.get("object_key") != public_key:
                raise AssertionError(f"public put 返回异常: {public_put}")

            public_get = await bob.call("storage.get_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": public_key,
            })
            if base64.b64decode(str(public_get.get("content") or "")) != public_body:
                raise AssertionError(f"public get 内容不匹配: {public_get}")

            listed = await alice.call("storage.list_objects", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "prefix": "public/docs/",
                "size": 20,
            })
            keys = [str(item.get("object_key") or "") for item in listed.get("items", [])]
            if public_key not in keys:
                raise AssertionError(f"list_objects 未返回 public 对象: {listed}")

            deleted_private = await alice.call("storage.delete_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": private_key,
            })
            if deleted_private.get("deleted") is not True:
                raise AssertionError(f"delete private 返回异常: {deleted_private}")

            deleted_public = await alice.call("storage.delete_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": public_key,
            })
            if deleted_public.get("deleted") is not True:
                raise AssertionError(f"delete public 返回异常: {deleted_public}")

            await asyncio.wait_for(done.wait(), timeout=5.0)

            got_events = sorted(
                (str(item.get("action") or ""), str(item.get("object_key") or ""))
                for item in events
            )
            expected_events = sorted([
                ("put_object", private_key),
                ("put_object", public_key),
                ("delete", private_key),
                ("delete", public_key),
            ])
            if got_events != expected_events:
                raise AssertionError(f"storage.object_changed 事件集合异常: {events}")

            quota_after = await alice.call("storage.get_quota", {"owner_aid": _ALICE_AID})
            if int(quota_after.get("used_bytes") or 0) != used_before:
                raise AssertionError(
                    f"quota used_bytes 未回收: before={used_before} after={quota_after}"
                )
            if int(quota_after.get("object_count") or 0) != count_before:
                raise AssertionError(
                    f"quota object_count 未回收: before={count_before} after={quota_after}"
                )

            _ok("storage_inline_permissions_events_and_quota")
        finally:
            sub.unsubscribe()
    finally:
        await bob.close()
        await alice.close()


async def test_storage_upload_session_roundtrip_and_download_ticket():
    """覆盖上传 ticket、完成上传和下载 ticket 的数据面回路。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    bucket = f"storage-upload-{rid}"
    object_key = f"archive/{rid}/large.bin"
    payload = (b"AUN-STORAGE-" + rid.encode("ascii")) * 4096  # 大于 inline 上限
    sha256 = hashlib.sha256(payload).hexdigest()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        session = await alice.call("storage.create_upload_session", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "size_bytes": len(payload),
            "content_type": "application/octet-stream",
            "expire_in_seconds": 300,
        })
        upload_url = str(session.get("upload_url") or "")
        if not upload_url:
            raise AssertionError(f"create_upload_session 未返回 upload_url: {session}")
        _assert_non_loopback_url(upload_url, "storage.create_upload_session.upload_url")

        status, _ = await _http_request(
            upload_url,
            method="PUT",
            payload=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        if status < 200 or status >= 300:
            raise AssertionError(f"HTTP PUT 上传失败: status={status}")

        completed = await alice.call("storage.complete_upload", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "content_type": "application/octet-stream",
            "is_private": False,
            "sha256": sha256,
            "size_bytes": len(payload),
            "expire_in_seconds": 300,
        })
        if completed.get("sha256") != sha256:
            raise AssertionError(f"complete_upload sha256 异常: {completed}")
        if int(completed.get("size_bytes") or 0) != len(payload):
            raise AssertionError(f"complete_upload size_bytes 异常: {completed}")

        head = await bob.call("storage.head_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
        })
        if head.get("is_private") is not False:
            raise AssertionError(f"公开大对象 head_object is_private 异常: {head}")
        if int(head.get("size_bytes") or 0) != len(payload):
            raise AssertionError(f"公开大对象 head_object size 异常: {head}")

        await _expect_failure(
            lambda: bob.call("storage.get_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
            }),
            "Bob inline 读取大对象",
            contains="create_download_ticket",
        )

        ticket = await bob.call("storage.create_download_ticket", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "expire_in_seconds": 300,
        })
        download_url = str(ticket.get("download_url") or "")
        if not download_url:
            raise AssertionError(f"create_download_ticket 未返回 download_url: {ticket}")
        if str(ticket.get("file_name") or "") != "large.bin":
            raise AssertionError(f"download ticket file_name 异常: {ticket}")
        _assert_non_loopback_url(download_url, "storage.create_download_ticket.download_url")

        _, body = await _http_request(download_url)
        if body != payload:
            raise AssertionError("下载内容与上传内容不一致")

        _ok("storage_upload_session_roundtrip_and_download_ticket")
    finally:
        await bob.close()
        await alice.close()


async def test_storage_prefix_pagination_and_version_conflict():
    """覆盖 list_prefixes、list_objects 分页和版本冲突。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bucket = f"storage-prefix-{rid}"

    try:
        await _ensure_connected(alice, _ALICE_AID)

        body_a = f"A-{rid}".encode("utf-8")
        body_b = f"B-{rid}".encode("utf-8")
        body_c = f"C-{rid}".encode("utf-8")
        body_notes = f"N-{rid}".encode("utf-8")

        put_a = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": "docs/a.txt",
            "content": _b64(body_a),
            "content_type": "text/plain",
            "is_private": True,
        })
        put_b = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": "docs/b.txt",
            "content": _b64(body_b),
            "content_type": "text/plain",
            "is_private": True,
        })
        put_c = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": "docs/c.txt",
            "content": _b64(body_c),
            "content_type": "text/plain",
            "is_private": True,
        })
        put_notes = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": "notes/c.txt",
            "content": _b64(body_notes),
            "content_type": "text/plain",
            "is_private": True,
        })
        if (
            not put_a.get("version")
            or not put_b.get("version")
            or not put_c.get("version")
            or not put_notes.get("version")
        ):
            raise AssertionError("put_object 未返回版本号")

        prefixes = await alice.call("storage.list_prefixes", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "prefix": "",
            "size": 20,
        })
        got_prefixes = set(str(p) for p in prefixes.get("prefixes", []))
        if got_prefixes != {"docs/", "notes/"}:
            raise AssertionError(f"list_prefixes 异常: {prefixes}")

        page1 = await alice.call("storage.list_objects", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "prefix": "docs/",
            "page": 1,
            "size": 2,
        })
        keys1 = [str(item.get("object_key") or "") for item in page1.get("items", [])]
        if keys1 != ["docs/a.txt", "docs/b.txt"]:
            raise AssertionError(f"list_objects page1 异常: {page1}")
        if str(page1.get("next_marker") or "") != "docs/b.txt":
            raise AssertionError(f"list_objects page1 next_marker 异常: {page1}")

        page2 = await alice.call("storage.list_objects", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "prefix": "docs/",
            "marker": "docs/b.txt",
            "size": 2,
        })
        keys2 = [str(item.get("object_key") or "") for item in page2.get("items", [])]
        if keys2 != ["docs/c.txt"]:
            raise AssertionError(f"list_objects marker 异常: {page2}")
        if str(page2.get("next_marker") or "") != "":
            raise AssertionError(f"list_objects page2 next_marker 异常: {page2}")

        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": "docs/a.txt",
                "content": _b64(body_a),
                "content_type": "text/plain",
                "overwrite": False,
            }),
            "overwrite=false 拒绝已存在对象",
        )

        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": "docs/a.txt",
                "content": _b64(body_a),
                "content_type": "text/plain",
                "expected_version": 999,
            }),
            "expected_version 冲突",
        )

        updated = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": "docs/a.txt",
            "content": _b64(f"updated-{rid}".encode("utf-8")),
            "content_type": "text/plain",
            "expected_version": int(put_a.get("version") or 0),
        })
        if int(updated.get("version") or 0) != int(put_a.get("version") or 0) + 1:
            raise AssertionError(f"更新后版本号未递增: {updated}")

        _ok("storage_prefix_pagination_and_version_conflict")
    finally:
        await alice.close()


async def test_storage_validation_ttl_and_upload_conflicts():
    """覆盖参数校验、ticket CAS 与上传完成失败路径。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    bucket = f"storage-validate-{rid}"
    object_key = f"docs/{rid}/cas.txt"
    large_key = f"docs/{rid}/large.bin"

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": "../escape.txt",
                "content": _b64(b"x"),
            }),
            "object_key 拒绝路径穿越",
        )
        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": "docs/bad space.txt",
                "content": _b64(b"x"),
            }),
            "object_key 拒绝空格",
        )
        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": f"docs/{rid}/empty.txt",
                "content": "",
            }),
            "content 不能为空",
        )
        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": f"docs/{rid}/bad-base64.txt",
                "content": "not base64",
            }),
            "content base64 解码失败",
        )
        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": f"docs/{rid}/too-large-inline.bin",
                "content": _b64(b"x" * (70 * 1024)),
                "content_type": "application/octet-stream",
            }),
            "inline 大对象必须走 upload session",
            contains="create_upload_session",
        )
        await _expect_failure(
            lambda: alice.call("storage.put_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": f"docs/{rid}/negative-ttl.txt",
                "content": _b64(b"x"),
                "expire_in_seconds": -1,
            }),
            "put_object 拒绝负 ttl",
        )

        created = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "content": _b64(b"v1"),
            "content_type": "text/plain",
            "is_private": True,
            "expected_version": 0,
        })
        version = int(created.get("version") or 0)
        if version <= 0:
            raise AssertionError(f"expected_version=0 创建未返回有效版本: {created}")

        await _expect_failure(
            lambda: alice.call("storage.create_upload_session", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
                "size_bytes": 2,
                "expected_version": 0,
            }),
            "create_upload_session expected_version=0 拒绝覆盖现有对象",
        )
        await _expect_failure(
            lambda: alice.call("storage.create_upload_session", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
                "size_bytes": 2,
                "expected_version": version + 1,
            }),
            "create_upload_session 拒绝错误版本",
        )
        await _expect_failure(
            lambda: alice.call("storage.create_upload_session", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": large_key,
                "size_bytes": 2,
                "expire_in_seconds": -1,
            }),
            "create_upload_session 拒绝负 ttl",
        )
        await _expect_failure(
            lambda: alice.call("storage.complete_upload", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": large_key,
                "size_bytes": 2,
            }),
            "complete_upload 拒绝未上传 blob",
        )

        payload = (f"upload-{rid}-".encode("ascii")) * 1024
        sha256 = hashlib.sha256(payload).hexdigest()
        session = await alice.call("storage.create_upload_session", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "size_bytes": len(payload),
            "content_type": "application/octet-stream",
            "expected_version": version,
            "expire_in_seconds": 300,
        })
        upload_url = str(session.get("upload_url") or "")
        if not upload_url:
            raise AssertionError(f"create_upload_session 未返回 upload_url: {session}")
        _assert_non_loopback_url(upload_url, "storage.create_upload_session.cas_upload_url")

        status, _ = await _http_request(
            upload_url,
            method="PUT",
            payload=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        if status < 200 or status >= 300:
            raise AssertionError(f"HTTP PUT 上传失败: status={status}")

        await _expect_failure(
            lambda: alice.call("storage.complete_upload", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
                "content_type": "application/octet-stream",
                "sha256": "0" * 64,
                "size_bytes": len(payload),
                "expected_version": version,
            }),
            "complete_upload 拒绝 sha256 不匹配",
        )
        await _expect_failure(
            lambda: alice.call("storage.complete_upload", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
                "content_type": "application/octet-stream",
                "sha256": sha256,
                "size_bytes": len(payload) + 1,
                "expected_version": version,
            }),
            "complete_upload 拒绝 size 不匹配",
        )
        await _expect_failure(
            lambda: alice.call("storage.complete_upload", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
                "content_type": "application/octet-stream",
                "sha256": sha256,
                "size_bytes": len(payload),
                "expected_version": version + 1,
            }),
            "complete_upload 拒绝错误版本",
        )

        completed = await alice.call("storage.complete_upload", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "content_type": "application/octet-stream",
            "is_private": True,
            "sha256": sha256,
            "size_bytes": len(payload),
            "expected_version": version,
            "expire_in_seconds": 300,
        })
        if int(completed.get("version") or 0) != version + 1:
            raise AssertionError(f"complete_upload 成功后版本号未递增: {completed}")

        await _expect_failure(
            lambda: bob.call("storage.create_download_ticket", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
            }),
            "Bob 无权为 Alice 私有对象创建下载 ticket",
        )
        await _expect_failure(
            lambda: alice.call("storage.create_download_ticket", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
                "expire_in_seconds": -1,
            }),
            "create_download_ticket 拒绝负 ttl",
        )

        _ok("storage_validation_ttl_and_upload_conflicts")
    finally:
        await bob.close()
        await alice.close()


async def test_storage_cas_dedup_and_instant_upload_download():
    """覆盖 CAS 去重与秒传：多个对象共享同一内容时，每个对象都必须能真实下载。

    复现并验证 folder-path/CAS-path 映射 bug 的修复：
    - 对象1 首传同内容
    - 对象2 同内容（不同 owner_aid + object_key），不能跨 owner 秒传，但正常上传后复用 CAS
    - 对象3 同内容（同 owner 不同 object_key），走 check_upload 秒传
    - 两个对象的下载 URL 经签名→302→后端，都必须下到正确内容（非 404）
    """
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    bucket = f"storage-dedup-{rid}"
    key1 = f"dedup/{rid}/file1.bin"
    key2 = f"dedup/{rid}/file2.bin"
    key3 = f"dedup/{rid}/file3.bin"
    payload = (b"AUN-CAS-DEDUP-" + rid.encode("ascii")) * 4096  # 大于 inline 上限
    sha256 = hashlib.sha256(payload).hexdigest()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        # ---- 对象1（alice）：首传，真实 PUT 上传 ----
        s1 = await alice.call("storage.create_upload_session", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": key1,
            "size_bytes": len(payload), "expire_in_seconds": 300,
        })
        status, _ = await _http_request(
            str(s1.get("upload_url") or ""), method="PUT", payload=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        if status < 200 or status >= 300:
            raise AssertionError(f"对象1 HTTP PUT 上传失败: status={status}")
        await alice.call("storage.complete_upload", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": key1,
            "is_private": False, "sha256": sha256, "size_bytes": len(payload),
            "expire_in_seconds": 300,
        })

        # ---- 对象1 下载验证（首传内容必须可下载）----
        t1 = await bob.call("storage.create_download_ticket", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": key1,
            "expire_in_seconds": 300,
        })
        _, body1 = await _http_request(str(t1.get("download_url") or ""))
        if body1 != payload:
            raise AssertionError("对象1 下载内容与上传不一致（首传对象悬空）")

        # ---- 对象2（bob）：跨 owner 不能秒传，避免暴露全局 CAS 存在性 ----
        chk_bob = await bob.call("storage.check_upload", {
            "sha256": sha256, "size_bytes": len(payload),
        })
        if chk_bob.get("exists") is not False or chk_bob.get("skip_upload") is not False:
            raise AssertionError(f"check_upload 不应允许跨 owner 秒传: {chk_bob}")

        await _expect_failure(
            lambda: bob.call("storage.complete_upload", {
                "owner_aid": _BOBB_AID, "bucket": bucket, "object_key": key2,
                "is_private": False, "sha256": sha256, "size_bytes": len(payload),
                "skip_blob": True, "expire_in_seconds": 300,
            }),
            "complete_upload skip_blob 拒绝跨 owner 秒传",
            contains="仅允许复用当前 owner",
        )

        s2 = await bob.call("storage.create_upload_session", {
            "owner_aid": _BOBB_AID, "bucket": bucket, "object_key": key2,
            "size_bytes": len(payload), "expire_in_seconds": 300,
        })
        status_bob, _ = await _http_request(
            str(s2.get("upload_url") or ""), method="PUT", payload=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        if status_bob < 200 or status_bob >= 300:
            raise AssertionError(f"对象2 HTTP PUT 上传失败: status={status_bob}")
        completed2 = await bob.call("storage.complete_upload", {
            "owner_aid": _BOBB_AID, "bucket": bucket, "object_key": key2,
            "is_private": False, "sha256": sha256, "size_bytes": len(payload),
            "expire_in_seconds": 300,
        })
        if completed2.get("sha256") != sha256:
            raise AssertionError(f"对象2 complete_upload sha256 异常: {completed2}")

        # ---- 对象2 下载验证（跨 owner 正常上传后复用 CAS，也必须可下载）----
        t2 = await bob.call("storage.create_download_ticket", {
            "owner_aid": _BOBB_AID, "bucket": bucket, "object_key": key2,
            "expire_in_seconds": 300,
        })
        download_url2 = str(t2.get("download_url") or "")
        _assert_non_loopback_url(download_url2, "对象2 download_url")
        status2, body2 = await _http_request(download_url2)
        if status2 != 200:
            raise AssertionError(f"对象2（跨 owner 同内容上传）下载失败 status={status2}（CAS 路径悬空 404）")
        if body2 != payload:
            raise AssertionError("对象2（跨 owner 同内容上传）下载内容与上传不一致")

        # ---- 对象3（alice）：同 owner 已拥有该内容，check_upload 命中并允许秒传 ----
        chk_alice = await alice.call("storage.check_upload", {
            "sha256": sha256, "size_bytes": len(payload),
        })
        if chk_alice.get("exists") is not True or chk_alice.get("skip_upload") is not True:
            raise AssertionError(f"check_upload 同 owner 未命中去重: {chk_alice}")

        completed3 = await alice.call("storage.complete_upload", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": key3,
            "is_private": False, "sha256": sha256, "size_bytes": len(payload),
            "skip_blob": True, "expire_in_seconds": 300,
        })
        if completed3.get("sha256") != sha256:
            raise AssertionError(f"同 owner 秒传 complete_upload sha256 异常: {completed3}")

        t3 = await bob.call("storage.create_download_ticket", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": key3,
            "expire_in_seconds": 300,
        })
        status3, body3 = await _http_request(str(t3.get("download_url") or ""))
        if status3 != 200:
            raise AssertionError(f"对象3（同 owner 秒传）下载失败 status={status3}")
        if body3 != payload:
            raise AssertionError("对象3（同 owner 秒传）下载内容与上传不一致")

        _ok("storage_cas_dedup_and_instant_upload_download")
    finally:
        await bob.close()
        await alice.close()


async def test_storage_directory_tree_rename_move_delete():
    """覆盖目录树 RPC：权限、同名冲突、递归 path 更新、ID 稳定和非空删除。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    bucket = f"storage-tree-{rid}"
    body = f"tree-report-{rid}".encode("utf-8")
    share_id = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        await _expect_failure(
            lambda: bob.call("storage.create_folder", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "path": "docs",
            }),
            "Bob 不能管理 Alice 的 storage 目录",
        )

        folder = await alice.call("storage.create_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "path": "docs/sub",
            "mkdirs": True,
            "metadata": {"rid": rid},
        })
        folder_id = str(folder.get("folder_id") or "")
        if not folder_id:
            raise AssertionError(f"create_folder 未返回 folder_id: {folder}")

        put = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": "docs/sub/report.txt",
            "content": _b64(body),
            "content_type": "text/plain",
            "is_private": False,
        })
        object_id = str(put.get("object_id") or "")
        if not object_id:
            raise AssertionError(f"put_object 未返回 object_id: {put}")

        listed = await alice.call("storage.list_children", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "path": "docs/sub",
        })
        names = {(item.get("node_type"), item.get("name")) for item in listed.get("items", [])}
        if ("object", "report.txt") not in names:
            raise AssertionError(f"list_children 未返回文件节点: {listed}")

        share = await alice.call("storage.create_share_link", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
            "allowed_aids": ["*"],
            "expire_in_seconds": 300,
        })
        share_id = str(share.get("share_id") or "")
        if not share_id:
            raise AssertionError(f"create_share_link 未返回 share_id: {share}")

        await alice.call("storage.rename_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "folder_id": folder_id,
            "new_name": "renamed",
        })
        by_id = await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
        })
        if by_id.get("path") != "docs/renamed/report.txt":
            raise AssertionError(f"rename_folder 后 object path 异常: {by_id}")
        await _expect_failure(
            lambda: alice.call("storage.resolve_path", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "path": "docs/sub/report.txt",
                "expected_type": "object",
            }),
            "rename_folder 后旧 path 失效",
        )

        shared_after_rename = await bob.call("storage.get_by_share", {"share_id": share_id})
        if shared_after_rename.get("object_id") != object_id:
            raise AssertionError(f"分享链接未通过 target_id 稳定解析: {shared_after_rename}")
        if base64.b64decode(str(shared_after_rename.get("content") or "")) != body:
            raise AssertionError("rename_folder 后分享链接内容不匹配")

        archive = await alice.call("storage.create_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "path": "archive",
        })
        renamed = await alice.call("storage.resolve_path", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "path": "docs/renamed",
            "expected_type": "folder",
        })
        await alice.call("storage.move_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "folder_id": renamed["folder_id"],
            "dst_parent_folder_id": archive["folder_id"],
            "new_name": "moved",
        })
        moved = await alice.call("storage.resolve_path", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "path": "archive/moved/report.txt",
            "expected_type": "object",
        })
        if moved.get("object_id") != object_id:
            raise AssertionError(f"move_folder 后 object_id 不稳定: {moved}")

        url_info = await alice.call("storage.get_object_url", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
        })
        _assert_non_loopback_url(str(url_info.get("object_url") or ""), "storage.get_object_url.object_url")

        await _expect_failure(
            lambda: alice.call("storage.delete_folder", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "folder_id": archive["folder_id"],
            }),
            "非空目录 recursive=false 删除被拒绝",
        )
        dry = await alice.call("storage.delete_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "folder_id": archive["folder_id"],
            "recursive": True,
            "dry_run": True,
        })
        if dry.get("dry_run") is not True or int(dry.get("deleted_objects") or 0) != 1:
            raise AssertionError(f"delete_folder dry_run 返回异常: {dry}")
        still_there = await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_id": object_id,
        })
        if still_there.get("object_id") != object_id:
            raise AssertionError(f"dry_run 误删对象: {still_there}")

        deleted = await alice.call("storage.delete_folder", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "folder_id": archive["folder_id"],
            "recursive": True,
        })
        if int(deleted.get("deleted_objects") or 0) != 1:
            raise AssertionError(f"recursive delete 未删除子对象: {deleted}")
        await _expect_failure(
            lambda: alice.call("storage.head_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_id": object_id,
            }),
            "recursive delete 后 object_id 失效",
        )

        _ok("storage_directory_tree_rename_move_delete")
    finally:
        if share_id:
            try:
                await alice.call("storage.revoke_share_link", {"share_id": share_id})
            except Exception:
                pass
        await bob.close()
        await alice.close()


async def test_storage_share_links_and_short_urls():
    """覆盖分享链接 RPC、短链接 HTTP 下载、授权名单、次数限制和撤销。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    eve = _make_client()
    eve_aid = f"eve-share-{rid}.{_ISSUER}"
    bucket = f"storage-share-{rid}"
    object_key = f"docs/{rid}/share.txt"
    payload = f"share-hello-{rid}".encode("utf-8")
    share_ids: list[str] = []

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        await _ensure_connected(eve, eve_aid)

        await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "content": _b64(payload),
            "content_type": "text/plain",
            "is_private": True,
        })

        public_share = await alice.call("storage.create_share_link", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "allowed_aids": ["*"],
            "expire_in_seconds": 300,
        })
        public_share_id = str(public_share.get("share_id") or "")
        public_share_url = str(public_share.get("share_url") or "")
        share_ids.append(public_share_id)
        if len(public_share_id) != 10:
            raise AssertionError(f"share_id 长度异常: {public_share}")
        if f"/s/{public_share_id}" not in public_share_url:
            raise AssertionError(f"share_url 未包含短链路径: {public_share}")
        _assert_non_loopback_url(public_share_url, "storage.create_share_link.share_url")

        status, body = await _http_request(public_share_url)
        if status < 200 or status >= 300 or body != payload:
            raise AssertionError(f"分享短链接 HTTP 下载异常: status={status} body={body!r}")

        bob_public = await bob.call("storage.get_by_share", {
            "share_id": public_share_id,
        })
        if base64.b64decode(str(bob_public.get("content") or "")) != payload:
            raise AssertionError(f"公开分享 get_by_share 内容异常: {bob_public}")

        restricted_share = await alice.call("storage.create_share_link", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "allowed_aids": [_BOBB_AID],
            "expire_in_seconds": 300,
        })
        restricted_share_id = str(restricted_share.get("share_id") or "")
        share_ids.append(restricted_share_id)

        bob_restricted = await bob.call("storage.get_by_share", {
            "share_id": restricted_share_id,
        })
        if base64.b64decode(str(bob_restricted.get("content") or "")) != payload:
            raise AssertionError(f"授权分享 get_by_share 内容异常: {bob_restricted}")

        await _expect_failure(
            lambda: eve.call("storage.get_by_share", {
                "share_id": restricted_share_id,
            }),
            "未授权 AID 读取指定分享",
        )

        limited_share = await alice.call("storage.create_share_link", {
            "owner_aid": _ALICE_AID,
            "bucket": bucket,
            "object_key": object_key,
            "allowed_aids": ["*"],
            "expire_in_seconds": 300,
            "max_uses": 1,
        })
        limited_share_id = str(limited_share.get("share_id") or "")
        share_ids.append(limited_share_id)
        await bob.call("storage.get_by_share", {"share_id": limited_share_id})
        await _expect_failure(
            lambda: bob.call("storage.get_by_share", {"share_id": limited_share_id}),
            "max_uses=1 的分享第二次读取",
        )

        listed = await alice.call("storage.list_share_links", {
            "bucket": bucket,
            "object_key": object_key,
        })
        listed_ids = {str(item.get("share_id") or "") for item in listed.get("links", [])}
        if public_share_id not in listed_ids or restricted_share_id not in listed_ids:
            raise AssertionError(f"list_share_links 未返回已创建分享: {listed}")

        revoked = await alice.call("storage.revoke_share_link", {
            "share_id": restricted_share_id,
        })
        if revoked.get("revoked") is not True:
            raise AssertionError(f"revoke_share_link 返回异常: {revoked}")
        await _expect_failure(
            lambda: bob.call("storage.get_by_share", {
                "share_id": restricted_share_id,
            }),
            "撤销后的分享不可读取",
        )

        _ok("storage_share_links_and_short_urls")
    finally:
        for share_id in share_ids:
            try:
                await alice.call("storage.revoke_share_link", {"share_id": share_id})
            except Exception:
                pass
        try:
            await alice.call("storage.delete_object", {
                "owner_aid": _ALICE_AID,
                "bucket": bucket,
                "object_key": object_key,
            })
        except Exception:
            pass
        await eve.close()
        await bob.close()
        await alice.close()


async def _http_status(url: str, *, headers: dict | None = None) -> tuple[int, bytes]:
    """GET 并返回 (status, body)，4xx/5xx 不抛异常（用于断言鉴权码）。"""
    import urllib.error

    def _run():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        try:
            with opener.open(req, timeout=20) as resp:
                return int(resp.status), resp.read()
        except urllib.error.HTTPError as e:
            return int(e.code), e.read()

    return await asyncio.to_thread(_run)


async def test_storage_logical_url_public_and_private():
    """逻辑 URL（无签名）：公开文件免鉴权可访问，私有文件需 AID bearer token。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    bucket = "default"  # 逻辑 URL 仅支持 default bucket
    pub_key = f"logical/{rid}/pub.bin"
    priv_key = f"logical/{rid}/priv.bin"
    small_key = f"logical/{rid}/small.txt"
    pub_body = (b"LOGICAL-PUB-" + rid.encode()) * 4096
    priv_body = (b"LOGICAL-PRIV-" + rid.encode()) * 4096

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        # 上传公开 + 私有大文件
        for okey, body, is_priv in [(pub_key, pub_body, False), (priv_key, priv_body, True)]:
            s = await alice.call("storage.create_upload_session", {
                "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": okey,
                "size_bytes": len(body), "expire_in_seconds": 300,
            })
            st, _ = await _http_request(str(s.get("upload_url") or ""), method="PUT",
                                        payload=body, headers={"Content-Type": "application/octet-stream"})
            if st < 200 or st >= 300:
                raise AssertionError(f"上传失败 {okey}: status={st}")
            await alice.call("storage.complete_upload", {
                "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": okey,
                "is_private": is_priv, "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body), "expire_in_seconds": 300,
            })

        # ticket 必须返回干净 logical_url（无 cas、无签名）和 AID 风格 url
        ticket = await alice.call("storage.create_download_ticket", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": pub_key,
        })
        logical_url = str(ticket.get("logical_url") or "")
        if not logical_url:
            raise AssertionError(f"ticket 未返回 logical_url: {ticket}")
        if "cas/" in logical_url or "expire=" in logical_url or "sig=" in logical_url:
            raise AssertionError(f"logical_url 不干净: {logical_url}")
        _assert_non_loopback_url(logical_url, "logical_url")
        if "/alice/" not in logical_url:
            raise AssertionError(f"logical_url 用户段不符: {logical_url}")

        # 验证新增 url 字段（AID 风格，优先/默认）
        aid_url = str(ticket.get("url") or "")
        if not aid_url:
            raise AssertionError(f"ticket 未返回 url 字段: {ticket}")
        if f"{_ALICE_AID}/storage/" not in aid_url:
            raise AssertionError(f"url 不含 AID 路径段: {aid_url}")
        if pub_key not in aid_url:
            raise AssertionError(f"url 不含 object_key: {aid_url}")
        print(f"  url={aid_url}")
        print(f"  logical_url={logical_url}")

        # 验证 put_object 也返回 url 字段
        put_res = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID, "object_key": small_key,
            "content": __import__("base64").b64encode(b"hello").decode(),
            "is_private": False,
        })
        if not str(put_res.get("url") or ""):
            raise AssertionError(f"put_object 未返回 url: {put_res}")
        if f"{_ALICE_AID}/storage/" not in put_res["url"]:
            raise AssertionError(f"put_object url 不含 AID 路径段: {put_res['url']}")
        print(f"  put_object url={put_res['url']}")

        # 公开文件：无 token 直接访问
        st, body = await _http_status(logical_url)
        if st != 200 or body != pub_body:
            raise AssertionError(f"公开 logical_url 访问失败: status={st} len={len(body)}")

        # 私有文件逻辑 URL
        priv_logical = logical_url.replace(pub_key, priv_key)
        # 无 token → 403
        st_no, _ = await _http_status(priv_logical)
        if st_no != 403:
            raise AssertionError(f"私有文件无 token 应 403，实际 {st_no}")
        # 带 owner 的 AID token → 200
        token = alice.access_token
        if not token:
            raise AssertionError("alice.access_token 为空，无法测私有鉴权")
        st_ok, body_ok = await _http_status(priv_logical, headers={"Authorization": f"Bearer {token}"})
        if st_ok != 200 or body_ok != priv_body:
            raise AssertionError(f"私有文件带 token 访问失败: status={st_ok} len={len(body_ok)}")
        # 非 owner（bob）的 token → 403
        bob_token = bob.access_token
        st_bob, _ = await _http_status(priv_logical, headers={"Authorization": f"Bearer {bob_token}"})
        if st_bob != 403:
            raise AssertionError(f"非 owner token 应 403，实际 {st_bob}")

        _ok("storage_logical_url_public_and_private")
    finally:
        for okey in (pub_key, priv_key, small_key):
            try:
                await alice.call("storage.delete_object", {
                    "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": okey})
            except Exception:
                pass
        await bob.close()
        await alice.close()


async def test_storage_object_move_copy_batch_and_meta_edges():
    """覆盖 move/copy/batch/meta 的真实 RPC 边界：冲突策略、ID 稳定、dry_run 不删除。"""
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bob = _make_client()
    bucket = f"storage-ops-{rid}"
    share_id = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        await alice.call("storage.create_folder", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "path": "docs",
        })
        archive = await alice.call("storage.create_folder", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "path": "archive",
        })
        await alice.call("storage.create_folder", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "path": "archive/existing",
        })
        first_body = f"alpha-{rid}".encode("utf-8")
        first = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": "docs/a.txt",
            "content": _b64(first_body), "content_type": "text/plain",
            "metadata": {"stage": "new"},
        })
        second = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": "archive/a.txt",
            "content": _b64(f"beta-{rid}".encode("utf-8")), "content_type": "text/plain",
        })
        object_id = str(first.get("object_id") or "")
        if not object_id:
            raise AssertionError(f"put_object 未返回 object_id: {first}")

        await _expect_failure(
            lambda: alice.call("storage.move_object", {
                "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
                "dst_parent_path": "archive",
            }),
            "move_object 同名文件 reject 冲突",
        )
        await _expect_failure(
            lambda: alice.call("storage.move_object", {
                "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
                "dst_parent_path": "archive", "new_name": "existing",
            }),
            "move_object 目标同名目录冲突",
        )
        await _expect_failure(
            lambda: bob.call("storage.move_object", {
                "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
                "dst_parent_path": "archive", "new_name": "blocked.txt",
            }),
            "Bob 不能 move Alice 对象",
        )

        moved = await alice.call("storage.move_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
            "dst_parent_path": "archive", "new_name": "a.txt",
            "conflict_policy": "keep_both",
        })
        if moved.get("object_id") != object_id or moved.get("path") != "archive/a-1.txt":
            raise AssertionError(f"move_object keep_both 返回异常: {moved}")
        await _expect_failure(
            lambda: alice.call("storage.head_object", {
                "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": "docs/a.txt",
            }),
            "move_object 后旧 path 失效",
        )

        share = await alice.call("storage.create_share_link", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
            "allowed_aids": ["*"], "expire_in_seconds": 300,
        })
        share_id = str(share.get("share_id") or "")
        renamed = await alice.call("storage.move_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
            "dst_parent_path": "docs", "new_name": "final.txt",
        })
        if renamed.get("path") != "docs/final.txt":
            raise AssertionError(f"move_object rename path 异常: {renamed}")
        shared = await bob.call("storage.get_by_share", {"share_id": share_id})
        if shared.get("object_id") != object_id or base64.b64decode(str(shared.get("content") or "")) != first_body:
            raise AssertionError(f"分享链接未按 target_id 稳定解析: {shared}")

        copied_keep = await alice.call("storage.copy_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
            "dst_parent_path": "archive", "new_name": "a.txt", "conflict_policy": "keep_both",
        })
        if copied_keep.get("object_id") == object_id or copied_keep.get("path") != "archive/a-1.txt":
            raise AssertionError(f"copy_object keep_both 返回异常: {copied_keep}")
        copied_replace = await alice.call("storage.copy_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
            "dst_parent_path": "archive", "new_name": "a.txt", "conflict_policy": "replace",
        })
        if copied_replace.get("object_id") in {object_id, second.get("object_id")} or copied_replace.get("path") != "archive/a.txt":
            raise AssertionError(f"copy_object replace 返回异常: {copied_replace}")

        await _expect_failure(
            lambda: bob.call("storage.set_object_meta", {
                "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
                "metadata": {"blocked": True},
            }),
            "Bob 不能 set Alice 对象 meta",
        )
        updated = await alice.call("storage.set_object_meta", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": object_id,
            "metadata": {"stage": "final"}, "content_type": "text/markdown",
        })
        if updated.get("path") != "docs/final.txt" or (updated.get("metadata") or {}).get("stage") != "final":
            raise AssertionError(f"set_object_meta 返回异常: {updated}")

        keep_folder = await alice.call("storage.create_folder", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "path": "batch/folder", "mkdirs": True,
        })
        batch_obj = await alice.call("storage.put_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_key": "batch/folder/item.txt",
            "content": _b64(b"batch"), "content_type": "text/plain",
        })
        dry = await alice.call("storage.batch_delete", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "dry_run": True, "recursive": True,
            "items": [
                {"type": "object", "object_id": copied_keep["object_id"]},
                {"type": "folder", "folder_id": keep_folder["folder_id"]},
            ],
        })
        if (dry.get("summary") or {}).get("errors") != 0:
            raise AssertionError(f"batch_delete dry_run 返回异常: {dry}")
        still_copy = await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": copied_keep["object_id"],
        })
        still_batch = await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": batch_obj["object_id"],
        })
        if not still_copy.get("object_id") or not still_batch.get("object_id"):
            raise AssertionError("batch_delete dry_run 误删对象")
        mixed = await alice.call("storage.batch_delete", {
            "owner_aid": _ALICE_AID, "bucket": bucket,
            "items": [
                {"type": "folder", "folder_id": keep_folder["folder_id"]},
                {"type": "object", "object_id": copied_keep["object_id"]},
            ],
        })
        if (mixed.get("summary") or {}).get("errors") != 1 or (mixed.get("summary") or {}).get("deleted") != 1:
            raise AssertionError(f"batch_delete 混合删除摘要异常: {mixed}")
        await alice.call("storage.head_object", {
            "owner_aid": _ALICE_AID, "bucket": bucket, "object_id": batch_obj["object_id"],
        })

        _ok("storage_object_move_copy_batch_and_meta_edges")
    finally:
        if share_id:
            try:
                await alice.call("storage.revoke_share_link", {"share_id": share_id})
            except Exception:
                pass
        await bob.close()
        await alice.close()


async def main():
    global _failed

    print("=== storage 集成测试 ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOBB     = {_BOBB_AID}")
    print()

    tests = [
        test_storage_inline_permissions_events_and_quota,
        test_storage_upload_session_roundtrip_and_download_ticket,
        test_storage_cas_dedup_and_instant_upload_download,
        test_storage_directory_tree_rename_move_delete,
        test_storage_prefix_pagination_and_version_conflict,
        test_storage_validation_ttl_and_upload_conflicts,
        test_storage_share_links_and_short_urls,
        test_storage_logical_url_public_and_private,
        test_storage_object_move_copy_batch_and_meta_edges,
    ]

    for fn in tests:
        print(f"--- {fn.__name__} ---")
        try:
            await fn()
        except Exception as exc:
            print(f"  💥 {fn.__name__} 异常: {exc}")
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
    print("全部通过 ✅")


if __name__ == "__main__":
    asyncio.run(main())

