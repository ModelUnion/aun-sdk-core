"""client.publish_agent_md / client.fetch_agent_md 主 API 单测。

仅依赖 monkeypatch，把底层 auth.sign/verify/upload/download 替换为 fake，
聚焦验证主 API 自身行为：
- path / content 校验
- 文件不存在
- 上传后 _local_agent_md_etag 与上传字节的 sha256 对齐
- 下载自己 aid 时刷新 _local_agent_md_etag
- 下载别人 aid 时不动 _local_agent_md_etag
- save_path 写盘正向 / 写盘失败兜底
- in_sync 字段语义
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from aun_core import AUNClient
from aun_core.errors import ValidationError


# ── publish_agent_md ─────────────────────────────────────────────────


def test_publish_agent_md_path_missing_raises():
    client = AUNClient()
    with pytest.raises(ValidationError):
        asyncio.run(client.publish_agent_md(""))


def test_publish_agent_md_file_not_found_raises():
    client = AUNClient()
    with pytest.raises(FileNotFoundError):
        asyncio.run(client.publish_agent_md("/path/does/not/exist/agent.md"))


def test_publish_agent_md_signs_and_updates_local_etag(monkeypatch, tmp_path: Path):
    client = AUNClient()
    client._aid = "alice.agentid.pub"

    md_file = tmp_path / "agent.md"
    md_file.write_bytes(b"---\naid: alice.agentid.pub\n---\n# Alice\n")

    captured: dict[str, str] = {}

    async def fake_sign(content, *, aid=None):
        captured["signed_input"] = content
        return (
            content
            + "\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n"
        )

    async def fake_upload(content):
        captured["uploaded"] = content
        return {"aid": "alice.agentid.pub", "etag": '"abc"', "agent_md_url": "https://x"}

    monkeypatch.setattr(client.auth, "sign_agent_md", fake_sign)
    monkeypatch.setattr(client.auth, "upload_agent_md", fake_upload)

    result = asyncio.run(client.publish_agent_md(str(md_file)))

    assert result["aid"] == "alice.agentid.pub"
    assert captured["signed_input"].startswith("---\naid: alice.agentid.pub")
    expected_digest = hashlib.sha256(captured["uploaded"].encode("utf-8")).hexdigest()
    assert client._local_agent_md_etag == f'"{expected_digest}"'


# ── fetch_agent_md ───────────────────────────────────────────────────


def test_fetch_agent_md_uses_self_aid_and_updates_local_etag(monkeypatch):
    client = AUNClient()
    client._aid = "alice.agentid.pub"

    download_calls: list[str] = []

    async def fake_download(aid):
        download_calls.append(aid)
        return "---\naid: alice.agentid.pub\n---\n# Alice\n"

    async def fake_verify(content, *, aid=None, cert_pem=None):
        return {"status": "unsigned", "verified": False, "payload": content}

    monkeypatch.setattr(client.auth, "download_agent_md", fake_download)
    monkeypatch.setattr(client.auth, "verify_agent_md", fake_verify)

    info = asyncio.run(client.fetch_agent_md())

    assert download_calls == ["alice.agentid.pub"]
    assert info["aid"] == "alice.agentid.pub"
    assert info["content"].startswith("---\naid: alice.agentid.pub")
    assert info["signature"]["status"] == "unsigned"
    assert info["in_sync"] in (True, False)
    expected = hashlib.sha256(info["content"].encode("utf-8")).hexdigest()
    assert client._local_agent_md_etag == f'"{expected}"'


def test_fetch_agent_md_other_aid_does_not_update_local_etag(monkeypatch):
    client = AUNClient()
    client._aid = "alice.agentid.pub"
    client._local_agent_md_etag = '"unchanged"'

    async def fake_download(aid):
        return "---\naid: bob.agentid.pub\n---\n# Bob\n"

    async def fake_verify(content, *, aid=None, cert_pem=None):
        return {"status": "unsigned", "verified": False, "payload": content}

    monkeypatch.setattr(client.auth, "download_agent_md", fake_download)
    monkeypatch.setattr(client.auth, "verify_agent_md", fake_verify)

    info = asyncio.run(client.fetch_agent_md("bob.agentid.pub"))

    assert info["aid"] == "bob.agentid.pub"
    assert info["in_sync"] is None
    assert client._local_agent_md_etag == '"unchanged"'


def test_fetch_agent_md_saves_to_path(monkeypatch, tmp_path: Path):
    client = AUNClient()
    client._aid = "alice.agentid.pub"

    async def fake_download(aid):
        return "---\naid: alice.agentid.pub\n---\n# Alice\n"

    async def fake_verify(content, *, aid=None, cert_pem=None):
        return {"status": "unsigned", "verified": False, "payload": content}

    monkeypatch.setattr(client.auth, "download_agent_md", fake_download)
    monkeypatch.setattr(client.auth, "verify_agent_md", fake_verify)

    target = tmp_path / "agent.md"
    info = asyncio.run(client.fetch_agent_md(save_path=str(target)))

    assert target.exists()
    assert target.read_text(encoding="utf-8").startswith("---\naid: alice.agentid.pub")
    assert info["saved_to"] == str(target)
    assert info["save_error"] is None


def test_fetch_agent_md_no_aid_no_self_raises():
    client = AUNClient()
    client._aid = None
    with pytest.raises(ValidationError):
        asyncio.run(client.fetch_agent_md())


def test_fetch_agent_md_in_sync_true_when_etags_match(monkeypatch):
    client = AUNClient()
    client._aid = "alice.agentid.pub"

    body = "---\naid: alice.agentid.pub\n---\n# Alice\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    client._remote_agent_md_etag = f'"{digest}"'  # gateway 注入的远端 etag

    async def fake_download(aid):
        return body

    async def fake_verify(content, *, aid=None, cert_pem=None):
        return {"status": "unsigned", "verified": False, "payload": content}

    monkeypatch.setattr(client.auth, "download_agent_md", fake_download)
    monkeypatch.setattr(client.auth, "verify_agent_md", fake_verify)

    info = asyncio.run(client.fetch_agent_md())
    assert info["in_sync"] is True
