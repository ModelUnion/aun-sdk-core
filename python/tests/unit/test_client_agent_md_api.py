"""client agent.md 文件型本地存储单测。

覆盖：
- 默认 {aun_path}/AgentMDs
- publish_agent_md(content?) 可直接接收内容；不传时读取 {root}/{aid}/agent.md
- fetch_agent_md() 固定保存到 {root}/{aid}/agent.md
- {aid}/agentmd.json 只保存元数据，不保存正文
- {aid}/agentmd.json 损坏时从同目录 agent.md 重建
"""

from __future__ import annotations

import asyncio
from email.utils import formatdate
import hashlib
import json
import time
from pathlib import Path

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AIDStore, AUNClient, result_ok
from aun_core.errors import ValidationError
from aun_core.events import EventDispatcher
from aun_core.transport import RPCTransport


def _etag(content: str) -> str:
    return f'"{hashlib.sha256(content.encode("utf-8")).hexdigest()}"'


def _make_identity(aid: str) -> dict[str, str]:
    from datetime import datetime, timedelta, timezone
    import base64

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return {
        "aid": aid,
        "private_key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
        "public_key_der_b64": base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii"),
        "curve": "P-256",
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
    }


def _make_client(tmp_path: Path, aid: str = "alice.agentid.pub") -> AUNClient:
    store = AIDStore(tmp_path / "aun", encryption_seed="", verify_ssl=False)
    try:
        store._keystore.save_identity(aid, _make_identity(aid))
        loaded = store.load(aid)
        assert loaded.ok, loaded.error
        assert loaded.data is not None
        return AUNClient(loaded.data["aid"])
    finally:
        store.close()


def _write_local_agent_md(client: AUNClient, aid: str, content: str) -> Path:
    path = Path(client._agent_md_path) / aid / "agent.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _read_record(client: AUNClient, aid: str) -> dict:
    return json.loads((Path(client._agent_md_path) / aid / "agentmd.json").read_text(encoding="utf-8"))


# ── path ─────────────────────────────────────────────────────────────


def test_agent_md_path_defaults_to_agentmds(tmp_path: Path):
    client = _make_client(tmp_path)
    assert Path(client._agent_md_path) == tmp_path / "aun" / "AgentMDs"
    client._keystore.close()


# ── publish_agent_md ─────────────────────────────────────────────────


def test_publish_agent_md_without_aid_raises(tmp_path: Path):
    client = AUNClient()
    with pytest.raises(ValidationError):
        asyncio.run(client.publish_agent_md())
    client._keystore.close()


def test_publish_agent_md_missing_default_file_raises(tmp_path: Path):
    client = _make_client(tmp_path)
    with pytest.raises(FileNotFoundError):
        asyncio.run(client.publish_agent_md())
    client._keystore.close()


def test_publish_agent_md_reads_default_file_uploads_and_persists(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    unsigned = "---\naid: alice.agentid.pub\n---\n# Alice\n"
    _write_local_agent_md(client, "alice.agentid.pub", unsigned)

    captured: dict[str, str] = {}

    async def fake_upload(content):
        captured["uploaded"] = content
        return {"aid": "alice.agentid.pub", "etag": '"alice-cloud"', "last_modified": "Sun, 24 May 2026 00:00:00 GMT"}

    monkeypatch.setattr(client, "upload_agent_md", fake_upload)

    result = asyncio.run(client.publish_agent_md())

    assert result["etag"] == '"alice-cloud"'
    assert captured["uploaded"].startswith(unsigned)
    assert "<!-- AUN-SIGNATURE" in captured["uploaded"]
    signed_path = Path(client._agent_md_path) / "alice.agentid.pub" / "agent.md"
    assert signed_path.read_text(encoding="utf-8") == captured["uploaded"]
    rec = _read_record(client, "alice.agentid.pub")
    assert "content" not in rec
    assert rec["local_etag"] == _etag(captured["uploaded"])
    assert rec["remote_etag"] == '"alice-cloud"'
    assert rec["last_modified"] == "Sun, 24 May 2026 00:00:00 GMT"
    assert client._local_agent_md_etag == _etag(captured["uploaded"])
    client._keystore.close()


def test_publish_agent_md_accepts_content_uploads_and_persists(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    unsigned = "---\naid: alice.agentid.pub\n---\n# Alice From Memory\n"

    captured: dict[str, str] = {}

    async def fake_upload(content):
        captured["uploaded"] = content
        return {"aid": "alice.agentid.pub", "etag": '"alice-memory"', "last_modified": "Sun, 24 May 2026 00:00:00 GMT"}

    monkeypatch.setattr(client, "upload_agent_md", fake_upload)

    result = asyncio.run(client.publish_agent_md(unsigned))

    assert result["etag"] == '"alice-memory"'
    assert captured["uploaded"].startswith(unsigned)
    assert "<!-- AUN-SIGNATURE" in captured["uploaded"]
    signed_path = Path(client._agent_md_path) / "alice.agentid.pub" / "agent.md"
    assert signed_path.read_text(encoding="utf-8") == captured["uploaded"]
    rec = _read_record(client, "alice.agentid.pub")
    assert rec["local_etag"] == _etag(captured["uploaded"])
    assert rec["remote_etag"] == '"alice-memory"'
    client._keystore.close()


# ── fetch_agent_md ───────────────────────────────────────────────────


def test_fetch_agent_md_uses_self_aid_updates_cache_and_saves_file(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    body = "---\naid: alice.agentid.pub\n---\n# Alice\n"
    class FakeStore:
        async def fetch_agent_md(self, aid):
            return result_ok({
                "aid": aid,
                "content": body,
                "signature": {"status": "unsigned", "payload": body},
                "etag": _etag(body),
                "last_modified": "Sun, 24 May 2026 00:00:00 GMT",
                "status": 200,
            })

        def close(self):
            pass

    monkeypatch.setattr(client, "_make_aid_store", lambda: FakeStore())

    info = asyncio.run(client._fetch_agent_md())

    assert info["aid"] == "alice.agentid.pub"
    assert info["in_sync"] is True
    saved = Path(info["saved_to"])
    assert saved == Path(client._agent_md_path) / "alice.agentid.pub" / "agent.md"
    assert saved.read_text(encoding="utf-8") == body
    assert client._local_agent_md_etag == _etag(body)
    rec = _read_record(client, "alice.agentid.pub")
    assert rec["local_etag"] == _etag(body)
    assert rec["remote_etag"] == _etag(body)
    client._keystore.close()


def test_fetch_agent_md_other_aid_saves_without_touching_self_etag(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    client._local_agent_md_etag = '"unchanged"'
    body = "---\naid: bob.agentid.pub\n---\n# Bob\n"
    class FakeStore:
        async def fetch_agent_md(self, aid):
            return result_ok({
                "aid": aid,
                "content": body,
                "signature": {"status": "unsigned", "payload": body},
                "etag": '"bob-cloud"',
                "last_modified": "",
                "status": 200,
            })

        def close(self):
            pass

    monkeypatch.setattr(client, "_make_aid_store", lambda: FakeStore())

    info = asyncio.run(client._fetch_agent_md("bob.agentid.pub"))

    assert info["in_sync"] is None
    assert client._local_agent_md_etag == '"unchanged"'
    assert Path(info["saved_to"]).read_text(encoding="utf-8") == body
    rec = _read_record(client, "bob.agentid.pub")
    assert rec["local_etag"] == _etag(body)
    assert rec["remote_etag"] == '"bob-cloud"'
    client._keystore.close()


def test_fetch_agent_md_no_aid_no_self_raises(tmp_path: Path):
    client = AUNClient()
    with pytest.raises(ValidationError):
        asyncio.run(client._fetch_agent_md())
    client._keystore.close()


# ── metadata / recovery ──────────────────────────────────────────────


def test_observe_rpc_meta_persists_structured_meta_and_fetches_missing_local(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    fetched: list[str] = []

    async def fake_fetch(aid):
        fetched.append(aid)
        content = f"# {aid}\n"
        client._save_agent_md_record(aid, content=content, local_etag=_etag(content), remote_status="found")
        return {"aid": aid, "content": content, "signature": {"status": "unsigned"}, "in_sync": False}

    monkeypatch.setattr(client, "_fetch_agent_md", fake_fetch)

    client._observe_rpc_meta({
        "agent_md_etag": '"alice-cloud"',
        "agent_md_etags": {
            "requester": {
                "aid": "alice.agentid.pub",
                "etag": '"alice-cloud-2"',
                "last_modified": "Sun, 24 May 2026 00:00:00 GMT",
            },
            "receiver": {
                "aid": "bob.agentid.pub",
                "etag": '"bob-cloud"',
                "last_modified": "Sun, 24 May 2026 00:00:01 GMT",
            },
            "sender": {"aid": "dave.agentid.pub", "etag": '"dave-cloud"'},
        },
    })

    records = {
        aid: _read_record(client, aid)
        for aid in ("alice.agentid.pub", "bob.agentid.pub", "dave.agentid.pub")
    }
    assert records["alice.agentid.pub"]["remote_etag"] == '"alice-cloud-2"'
    assert records["alice.agentid.pub"]["last_modified"] == "Sun, 24 May 2026 00:00:00 GMT"
    assert records["bob.agentid.pub"]["remote_etag"] == '"bob-cloud"'
    assert records["bob.agentid.pub"]["last_modified"] == "Sun, 24 May 2026 00:00:01 GMT"
    assert records["dave.agentid.pub"]["remote_etag"] == '"dave-cloud"'
    assert all("content" not in rec for rec in records.values())
    assert fetched == ["alice.agentid.pub", "bob.agentid.pub", "dave.agentid.pub"]
    assert (Path(client._agent_md_path) / "bob.agentid.pub" / "agent.md").read_text(encoding="utf-8") == "# bob.agentid.pub\n"
    client._keystore.close()


def test_observe_envelope_agent_md_persists_sender_etag(tmp_path: Path):
    client = _make_client(tmp_path, aid="bob.agentid.pub")

    client._observe_agent_md_from_envelope({"agent_md": {"sender": {"aid": "alice.agentid.pub", "etag": '"alice-cloud"'}}})

    rec = _read_record(client, "alice.agentid.pub")
    assert rec["remote_etag"] == '"alice-cloud"'
    client._keystore.close()


def test_check_agent_md_head_compares_file_local_etag(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    body = "# Bob\n"
    client._save_agent_md_record("bob.agentid.pub", content=body, local_etag=_etag(body), remote_etag='"old"')

    class FakeStore:
        async def head_agent_md(self, aid):
            return result_ok({"aid": aid, "found": True, "etag": _etag(body), "last_modified": "Sun, 24 May 2026 00:00:00 GMT", "status": 200})

        def close(self):
            pass

    monkeypatch.setattr(client, "_make_aid_store", lambda: FakeStore())

    result = asyncio.run(client._check_agent_md("bob.agentid.pub"))

    assert result["local_found"] is True
    assert result["remote_found"] is True
    assert result["in_sync"] is True
    assert result["local_etag"] == _etag(body)
    assert result["remote_etag"] == _etag(body)
    assert _read_record(client, "bob.agentid.pub")["remote_etag"] == _etag(body)
    client._keystore.close()


def test_check_agent_md_uses_fresh_cached_match_without_head(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    body = "# Bob\n"
    fresh_last_modified = formatdate(time.time(), usegmt=True)
    client._save_agent_md_record(
        "bob.agentid.pub",
        content=body,
        local_etag=_etag(body),
        remote_etag=_etag(body),
        last_modified=fresh_last_modified,
        verify_status="valid",
        verify_error="",
    )

    class FakeStore:
        async def head_agent_md(self, aid):
            raise AssertionError("fresh cached check_agent_md should not HEAD")

        def close(self):
            pass

    monkeypatch.setattr(client, "_make_aid_store", lambda: FakeStore())

    result = asyncio.run(client._check_agent_md("bob.agentid.pub", max_unsynced_days=7))

    assert result["local_found"] is True
    assert result["remote_found"] is True
    assert result["in_sync"] is True
    assert result["cached"] is True
    assert result["verify_status"] == "valid"
    client._keystore.close()
def test_check_agent_md_without_local_record_still_heads(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)

    class FakeStore:
        async def head_agent_md(self, aid):
            return result_ok({"aid": aid, "found": True, "etag": '"remote"', "last_modified": "", "status": 200})

        def close(self):
            pass

    monkeypatch.setattr(client, "_make_aid_store", lambda: FakeStore())

    result = asyncio.run(client._check_agent_md("carol.agentid.pub"))

    assert result["local_found"] is False
    assert result["remote_found"] is True
    assert result["in_sync"] is False
    assert result["remote_etag"] == '"remote"'
    client._keystore.close()


def test_damaged_agentmd_json_rebuilds_from_agent_md_file(tmp_path: Path):
    client = _make_client(tmp_path)
    body = "# Alice\n"
    _write_local_agent_md(client, "alice.agentid.pub", body)
    client._agent_md_cache["alice.agentid.pub"] = {"aid": "alice.agentid.pub", "remote_etag": '"cloud"'}
    client._agent_md_cache["bob.agentid.pub"] = {"aid": "bob.agentid.pub", "remote_etag": '"stale"'}
    meta_path = Path(client._agent_md_path) / "alice.agentid.pub" / "agentmd.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text("{bad json", encoding="utf-8")

    record = client._load_agent_md_record("alice.agentid.pub")

    assert record is not None
    assert record["content"] == body
    assert record["local_etag"] == _etag(body)
    assert "remote_etag" not in record
    rebuilt = _read_record(client, "alice.agentid.pub")
    assert rebuilt["local_etag"] == _etag(body)
    assert "remote_etag" not in rebuilt
    assert "bob.agentid.pub" in client._agent_md_cache
    client._keystore.close()


def test_transport_event_and_notification_meta_observer_receives_agent_md_etags():
    async def _run():
        observed = []

        async def _factory(_url):
            return None

        transport = RPCTransport(event_dispatcher=EventDispatcher(), connection_factory=_factory)
        transport.set_meta_observer(lambda meta: observed.append(meta))

        await transport._route_message({
            "method": "event/custom.notice",
            "params": {},
            "_meta": {"agent_md_etags": {"target": {"aid": "alice.agentid.pub", "etag": '"alice-cloud"'}}},
        })
        await transport._route_message({
            "method": "custom.notice",
            "params": {},
            "_meta": {"agent_md_etags": {"sender": {"aid": "bob.agentid.pub", "etag": '"bob-cloud"'}}},
        })
        await asyncio.sleep(0)

        assert observed == [
            {"agent_md_etags": {"target": {"aid": "alice.agentid.pub", "etag": '"alice-cloud"'}}},
            {"agent_md_etags": {"sender": {"aid": "bob.agentid.pub", "etag": '"bob-cloud"'}}},
        ]

    asyncio.run(_run())
