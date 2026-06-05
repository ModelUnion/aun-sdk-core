"""Storage CLI 核心逻辑（不依赖 typer）。

把 HTTP 数据面与上传/下载/删除编排从 typer 命令层剥离，
使其既能被 CLI 命令复用，也能在不安装 typer 的测试容器内直接导入做集成验证。
"""
from __future__ import annotations

import base64
import hashlib
import mimetypes
import ssl
import urllib.request
from typing import Any


def guess_content_type(file_name: str) -> str:
    return mimetypes.guess_type(file_name)[0] or "application/octet-stream"


class _AllMethodRedirectHandler(urllib.request.HTTPRedirectHandler):
    """跟随所有 HTTP 方法的重定向（urllib 默认只跟随 GET/HEAD）。

    storage 的 presigned URL 会 302 跳到后端，PUT/GET 都必须保留原方法与 body。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        method = req.get_method()
        if code in (301, 302, 303, 307, 308) and method in ("PUT", "POST", "DELETE", "PATCH"):
            return urllib.request.Request(
                newurl, data=req.data, method=method,
                headers={k: v for k, v in req.header_items() if k.lower() != "host"},
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener(verify_ssl: bool):
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _AllMethodRedirectHandler(),
    )


def _http_put(url: str, data: bytes, content_type: str, verify_ssl: bool = True) -> int:
    """HTTP PUT 上传到 presigned URL，返回状态码。跟随 302→PUT 重定向。"""
    opener = _build_opener(verify_ssl)
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Content-Type", content_type or "application/octet-stream")
    with opener.open(req, timeout=120) as resp:
        return int(resp.status)


def _http_get(url: str, verify_ssl: bool = True) -> bytes:
    """HTTP GET 从 presigned URL 下载，返回内容字节。跟随 302→GET 重定向。"""
    opener = _build_opener(verify_ssl)
    req = urllib.request.Request(url, method="GET")
    with opener.open(req, timeout=120) as resp:
        return resp.read()


async def upload_object(
    client: Any, *, object_key: str, data: bytes, content_type: str,
    is_private: bool, verify_ssl: bool,
) -> dict:
    """小文件走 inline put_object，大文件走 upload session + HTTP PUT + complete_upload。"""
    limits = await client.call("storage.get_limits", {})
    max_inline = int(limits.get("max_inline_bytes") or 65536)

    if len(data) <= max_inline:
        return await client.call("storage.put_object", {
            "object_key": object_key,
            "content": base64.b64encode(data).decode("ascii"),
            "content_type": content_type,
            "is_private": is_private,
            "overwrite": True,
        })

    session = await client.call("storage.create_upload_session", {
        "object_key": object_key,
        "size_bytes": len(data),
        "content_type": content_type,
    })
    upload_url = str(session.get("upload_url") or "")
    if not upload_url:
        raise RuntimeError(f"create_upload_session 未返回 upload_url: {session}")
    status = _http_put(upload_url, data, content_type, verify_ssl)
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP PUT 上传失败: status={status}")
    return await client.call("storage.complete_upload", {
        "object_key": object_key,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "content_type": content_type,
        "is_private": is_private,
    })


async def download_object(client: Any, *, object_key: str, verify_ssl: bool) -> tuple[dict, bytes]:
    """统一走下载 ticket + HTTP GET，兼容 inline 与历史 folder-path 对象。"""
    ticket = await client.call("storage.create_download_ticket", {"object_key": object_key})
    download_url = str(ticket.get("download_url") or "")
    if not download_url:
        raise RuntimeError(f"create_download_ticket 未返回 download_url: {ticket}")
    data = _http_get(download_url, verify_ssl)
    return ticket, data


async def delete_object(client: Any, *, object_key: str) -> dict:
    return await client.call("storage.delete_object", {"object_key": object_key})

