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
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.register_aid({"aid": aid})
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
                ("put", private_key),
                ("put", public_key),
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
        test_storage_prefix_pagination_and_version_conflict,
        test_storage_validation_ttl_and_upload_conflicts,
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
