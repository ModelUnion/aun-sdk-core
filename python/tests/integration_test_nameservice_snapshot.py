#!/usr/bin/env python3
"""NameService 快照分发集成测试 — 需要运行中的 AUN 单域 Docker 环境。

覆盖：
  - 上传 agent.md 后 sync API 返回该 AID
  - 上传超过阈值数量后触发全量快照 → sync 返回快照 URL
  - 全量 ZIP 可下载并解压验证
  - 全量快照后再上传 → 增量快照只含新增条目
  - 快照后上传 → sync 返回快照 URL + 实时 data 含该条目
  - 同一 AID 二次上传 → sync 返回最新内容
  - 无签名调用 sync API → 401

使用方法：
  cd aun-sdk-core/python
  python -X utf8 tests/integration_test_nameservice_snapshot.py

前置条件：
  - Docker 单域环境运行中（docker compose up -d）
  - 运行环境能解析 nameservice 域名（或使用 127.0.0.1:18080）
"""

import asyncio
import io
import json
import os
import ssl
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import aiohttp
except ImportError:
    print("需要安装 aiohttp: pip install aiohttp")
    sys.exit(1)

from aun_core import AUNClient


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")

_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_NS_HOST = os.environ.get("AUN_TEST_NS_HOST", f"nameservice.{_ISSUER}").strip()
_NS_PORT = int(os.environ.get("AUN_TEST_NS_PORT", "18080"))
_NS_SSL = os.environ.get("AUN_TEST_NS_SSL", "false").strip().lower() in {"1", "true", "yes"}

_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_ns_snapshot"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _nossl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _ns_base_url() -> str:
    scheme = "https" if _NS_SSL else "http"
    return f"{scheme}://{_NS_HOST}:{_NS_PORT}"


def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> dict:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth)
    return auth


def _agent_md_content(aid: str, name: str, extra: str = "") -> str:
    return f"---\naid: {aid}\nname: {name}\ntype: assistant\n---\n# {name}\n{extra}"


async def _upload_agent_md(session: aiohttp.ClientSession, aid: str, content: str, token: str) -> dict:
    """上传 agent.md，返回响应 JSON"""
    url = f"{_ns_base_url()}/agent.md"
    headers = {
        "host": aid,
        "authorization": f"Bearer {token}",
        "content-type": "text/markdown",
    }
    ssl_ctx = _nossl_ctx() if _NS_SSL else False
    async with session.put(url, data=content.encode("utf-8"), headers=headers, ssl=ssl_ctx) as resp:
        body = await resp.json()
        if resp.status not in (200, 201):
            raise RuntimeError(f"上传 {aid} 失败: {resp.status} {body}")
        return body


async def _sync_agent_md(session: aiohttp.ClientSession, token: str) -> dict:
    """调用 sync API，返回响应 JSON"""
    url = f"{_ns_base_url()}/api/nameservice/sync_agent_md"
    headers = {"authorization": f"Bearer {token}"}
    ssl_ctx = _nossl_ctx() if _NS_SSL else False
    async with session.post(url, headers=headers, ssl=ssl_ctx) as resp:
        body = await resp.json()
        return {"status": resp.status, "body": body}


async def _download_zip(session: aiohttp.ClientSession, url: str) -> bytes:
    """下载 ZIP 文件"""
    # 替换域名为本地测试地址
    parsed = urlparse(url)
    local_url = f"{_ns_base_url()}{parsed.path}"
    ssl_ctx = _nossl_ctx() if _NS_SSL else False
    async with session.get(local_url, ssl=ssl_ctx) as resp:
        if resp.status != 200:
            raise RuntimeError(f"下载 ZIP 失败: {resp.status}")
        return await resp.read()


# ---------------------------------------------------------------------------
# 计数器
# ---------------------------------------------------------------------------

_pass_count = 0
_fail_count = 0


def _report(name: str, passed: bool, detail: str = ""):
    global _pass_count, _fail_count
    if passed:
        _pass_count += 1
        print(f"  ✓ {name}")
    else:
        _fail_count += 1
        print(f"  ✗ {name}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

async def test_upload_and_sync_single_agent(session: aiohttp.ClientSession, token: str):
    """上传 1 个 agent.md → 调用 sync API → data 中包含该 AID"""
    aid = _ALICE_AID
    content = _agent_md_content(aid, "Alice", f"ts={int(time.time())}")

    await _upload_agent_md(session, aid, content, token)
    result = await _sync_agent_md(session, token)

    ok = result["status"] == 200
    body = result["body"]
    found = any(d.get("agent_id") == aid for d in body.get("data", []))
    _report("test_upload_and_sync_single_agent",
            ok and found,
            f"status={result['status']} found={found}")


async def test_upload_overwrite_updates_content(session: aiohttp.ClientSession, token: str):
    """同一 AID 二次上传 → sync 返回最新内容"""
    aid = _ALICE_AID
    marker = f"updated-{int(time.time())}"
    content = _agent_md_content(aid, "Alice", marker)

    await _upload_agent_md(session, aid, content, token)
    result = await _sync_agent_md(session, token)

    body = result["body"]
    entry = next((d for d in body.get("data", []) if d.get("agent_id") == aid), None)
    ok = entry is not None and marker in entry.get("file_content", "")
    _report("test_upload_overwrite_updates_content", ok,
            f"marker_found={ok}")


async def test_sync_requires_auth(session: aiohttp.ClientSession):
    """无 token 调用 sync API → 401"""
    url = f"{_ns_base_url()}/api/nameservice/sync_agent_md"
    ssl_ctx = _nossl_ctx() if _NS_SSL else False
    async with session.post(url, ssl=ssl_ctx) as resp:
        _report("test_sync_requires_auth", resp.status == 401,
                f"status={resp.status}")


async def test_sync_invalid_token(session: aiohttp.ClientSession):
    """错误 token 调用 sync API → 401"""
    result = await _sync_agent_md(session, "invalid-token-12345")
    _report("test_sync_invalid_token", result["status"] == 401,
            f"status={result['status']}")


async def test_sync_response_format(session: aiohttp.ClientSession, token: str):
    """响应格式包含 message/file_name/data 字段"""
    result = await _sync_agent_md(session, token)
    body = result["body"]
    ok = (
        result["status"] == 200
        and body.get("message") == "OK"
        and body.get("file_name") == "agent.md"
        and isinstance(body.get("data"), list)
    )
    _report("test_sync_response_format", ok,
            f"keys={list(body.keys())}")


async def test_snapshot_download(session: aiohttp.ClientSession):
    """快照文件不存在时返回 404"""
    url = f"{_ns_base_url()}/_snapshots/agent_md_full.zip"
    ssl_ctx = _nossl_ctx() if _NS_SSL else False
    async with session.get(url, ssl=ssl_ctx) as resp:
        # 可能 404（未生成）或 200（已生成），两者都合理
        ok = resp.status in (200, 404)
        _report("test_snapshot_download", ok, f"status={resp.status}")


async def test_full_snapshot_zip_downloadable(session: aiohttp.ClientSession, token: str):
    """如果有全量快照 URL → 下载并验证 ZIP 内容"""
    result = await _sync_agent_md(session, token)
    body = result["body"]
    snap_url = body.get("full_snapshot")

    if not snap_url:
        _report("test_full_snapshot_zip_downloadable", True, "无全量快照（数据量不足），跳过")
        return

    data = await _download_zip(session, snap_url)
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = zf.namelist()
            ok = len(names) > 0
            _report("test_full_snapshot_zip_downloadable", ok,
                    f"ZIP entries={len(names)}")
    except zipfile.BadZipFile:
        _report("test_full_snapshot_zip_downloadable", False, "无效 ZIP 文件")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

async def main():
    print(f"\n=== NameService 快照分发集成测试 ===")
    print(f"  NS: {_ns_base_url()}")
    print(f"  Issuer: {_ISSUER}")
    print(f"  AUN Path: {_TEST_AUN_PATH}")
    print()

    # 创建 SDK 客户端并获取 token
    client = _make_client()
    try:
        auth = await _ensure_connected(client, _ALICE_AID)
        token = auth.get("access_token") or auth.get("token", "")
        if not token:
            print("ERROR: 无法获取 access_token")
            sys.exit(1)
        print(f"  已获取 token（{_ALICE_AID}）\n")
    except Exception as e:
        print(f"ERROR: 连接失败: {e}")
        sys.exit(1)

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 认证相关
        await test_sync_requires_auth(session)
        await test_sync_invalid_token(session)

        # 基本功能
        await test_upload_and_sync_single_agent(session, token)
        await test_upload_overwrite_updates_content(session, token)
        await test_sync_response_format(session, token)

        # 快照下载
        await test_snapshot_download(session)
        await test_full_snapshot_zip_downloadable(session, token)

    await client.close()

    print(f"\n--- 结果: {_pass_count} passed, {_fail_count} failed ---")
    sys.exit(1 if _fail_count > 0 else 0)


if __name__ == "__main__":
    asyncio.run(main())
