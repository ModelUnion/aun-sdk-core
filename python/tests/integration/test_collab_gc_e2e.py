"""collab.gc 单域集成测试。"""
from __future__ import annotations

import base64
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

import pytest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aun_core import AUNClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

os.environ.setdefault("AUN_ENV", "development")

_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"


def _b64(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return base64.b64encode(data).decode("ascii")


async def _make_connected_client(tag: str) -> tuple[AUNClient, str, str]:
    aun_path = tempfile.mkdtemp(prefix=f"aun-collab-gc-{tag}-")
    aid = f"collab-gc-{tag}-{uuid.uuid4().hex[:8]}.{_ISSUER}"
    client = make_client_for_path(aun_path, require_forward_secrecy=False)
    await ensure_connected_identity(client, aid)
    print(f"[collab-gc] connected aid={aid} aun_path={aun_path}")
    return client, aid, aun_path


async def _cleanup(client: AUNClient, aid: str, root_path: str, aun_path: str) -> None:
    try:
        await client.storage.remove(root_path, owner=aid, recursive=True)
    except Exception as exc:
        print(f"[collab-gc] cleanup remote skipped: {exc}")
    await client.close()
    shutil.rmtree(aun_path, ignore_errors=True)


def _assert_gc_shape(result: dict[str, Any]) -> None:
    for key in ("scanned", "reachable", "garbage", "deleted"):
        assert key in result, f"gc 返回缺少字段 {key}: {result}"


@pytest.mark.asyncio
async def test_gc_basic_dry_run() -> None:
    client, aid, aun_path = await _make_connected_client("dry")
    root_path = f"/gc-test-{uuid.uuid4().hex[:10]}"
    collab_root = f"{aid}:{root_path}"
    try:
        await client.collab.create(collab_root, "doc1.md", _b64("test content"))

        result = await client.collab.gc(collab_root, dry_run=True)
        _assert_gc_shape(result)
        assert result["deleted"] == 0
        print(f"[collab-gc] dry_run result={result}")
    finally:
        await _cleanup(client, aid, root_path, aun_path)


@pytest.mark.asyncio
async def test_gc_cleans_orphans() -> None:
    client, aid, aun_path = await _make_connected_client("orphan")
    root_path = f"/gc-orphan-test-{uuid.uuid4().hex[:10]}"
    collab_root = f"{aid}:{root_path}"
    try:
        await client.collab.create(collab_root, "doc1.md", _b64("v1"))

        orphan_path = f"{root_path}/.collab-versions/doc1.md/{aid}/orphan-99.md"
        await client.storage.write_bytes(
            orphan_path,
            b"orphan content",
            owner=aid,
            content_type="text/plain",
        )
        print(f"[collab-gc] orphan created path={orphan_path}")

        result_dry = await client.collab.gc(collab_root, dry_run=True)
        _assert_gc_shape(result_dry)
        assert result_dry["garbage"] >= 1, f"应该发现至少 1 个孤儿对象: {result_dry}"
        assert result_dry["deleted"] == 0
        print(f"[collab-gc] dry orphan result={result_dry}")

        result_clean = await client.collab.gc(collab_root, dry_run=False)
        _assert_gc_shape(result_clean)
        assert result_clean["deleted"] >= 1, f"应该删除至少 1 个孤儿对象: {result_clean}"
        print(f"[collab-gc] clean result={result_clean}")

        result_final = await client.collab.gc(collab_root, dry_run=True)
        _assert_gc_shape(result_final)
        assert result_final["garbage"] == 0, f"清理后不应再有垃圾: {result_final}"
    finally:
        await _cleanup(client, aid, root_path, aun_path)
