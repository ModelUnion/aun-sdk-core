"""agent.md 文件型本地存储单测。

覆盖：
- 默认 {aun_path}/AIDs
- AIDStore.upload_agent_md(aid, content?) 负责签名、上传并持久化
- RPC/envelope 观察到的远端 etag 落盘到 agentmd.json
- {aid}/agentmd.json 只保存元数据，不保存正文
- {aid}/agentmd.json 损坏时从同目录 agent.md 重建
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AIDStore, AUNClient
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
        client = AUNClient(loaded.data["aid"])
        client._identity = {"aid": aid, "access_token": "token"}
        client._agent_md_manager._gateway_resolver = lambda _aid: "ws://gateway.agentid.pub/aun"
        return client
    finally:
        store.close()


def _make_store(tmp_path: Path, aid: str = "alice.agentid.pub") -> AIDStore:
    store = AIDStore(tmp_path / "aun", encryption_seed="", verify_ssl=False)
    store._keystore.save_identity(aid, _make_identity(aid))
    store._token_store.save_instance_state(
        aid,
        store.device_id,
        store.slot_id,
        {
            "access_token": "token",
            "refresh_token": "refresh",
            "access_token_expires_at": time.time() + 3600,
        },
    )
    store._resolve_gateway = lambda _aid: "ws://gateway.agentid.pub/aun"
    loaded = store.load(aid)
    assert loaded.ok, loaded.error
    return store


def _write_local_agent_md(holder, aid: str, content: str) -> Path:
    path = holder._agent_md_manager.file_path(aid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _read_record(holder, aid: str) -> dict:
    return json.loads(holder._agent_md_manager.meta_path(aid).read_text(encoding="utf-8"))


class _FakePutResponse:
    status = 200

    def __init__(self, etag: str):
        self._etag = etag

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self):
        return {"aid": "alice.agentid.pub", "etag": self._etag, "last_modified": "Sun, 24 May 2026 00:00:00 GMT"}

    async def text(self):
        return ""


class _FakePutSession:
    def __init__(self, captured: dict[str, object], etag: str):
        self._captured = captured
        self._etag = etag

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def put(self, url, *, data=None, headers=None, ssl=None):
        self._captured["url"] = url
        self._captured["data"] = data
        self._captured["headers"] = headers
        return _FakePutResponse(self._etag)


def _patch_put(monkeypatch, captured: dict[str, object], etag: str = '"cloud"') -> None:
    import aun_core.agent_md as mod

    monkeypatch.setattr(mod.aiohttp, "ClientSession", lambda *args, **kwargs: _FakePutSession(captured, etag))


def test_agent_md_path_defaults_to_aids(tmp_path: Path):
    client = _make_client(tmp_path)
    assert client._agent_md_manager.root == tmp_path / "aun" / "AIDs"
    assert not hasattr(client, "upload_agent_md")
    client._token_store.close()


def test_upload_agent_md_without_aid_returns_error(tmp_path: Path):
    store = AIDStore(tmp_path / "aun", encryption_seed="", verify_ssl=False)
    try:
        result = asyncio.run(store.upload_agent_md(""))
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "INVALID_AID_FORMAT"
    finally:
        store.close()


def test_upload_agent_md_missing_default_file_returns_error(tmp_path: Path):
    store = _make_store(tmp_path)
    try:
        result = asyncio.run(store.upload_agent_md("alice.agentid.pub"))
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "NETWORK_ERROR"
    finally:
        store.close()


def test_upload_agent_md_reads_default_file_uploads_and_persists(monkeypatch, tmp_path: Path):
    store = _make_store(tmp_path)
    unsigned = "---\naid: alice.agentid.pub\n---\n# Alice\n"
    _write_local_agent_md(store, "alice.agentid.pub", unsigned)
    captured: dict[str, object] = {}
    _patch_put(monkeypatch, captured, '"alice-cloud"')

    result = asyncio.run(store.upload_agent_md("alice.agentid.pub"))
    assert result.ok, result.error

    uploaded = bytes(captured["data"]).decode("utf-8")
    assert result.data["etag"] == '"alice-cloud"'
    assert captured["url"] == "http://alice.agentid.pub/agent.md"
    assert captured["headers"]["Authorization"] == "Bearer token"
    assert uploaded.startswith(unsigned)
    assert "<!-- AUN-SIGNATURE" in uploaded
    signed_path = store._agent_md_manager.file_path("alice.agentid.pub")
    assert signed_path.read_text(encoding="utf-8") == uploaded
    rec = _read_record(store, "alice.agentid.pub")
    assert "content" not in rec
    assert rec["local_etag"] == _etag(uploaded)
    assert rec["remote_etag"] == '"alice-cloud"'
    store.close()


def test_upload_agent_md_accepts_content_uploads_and_persists(monkeypatch, tmp_path: Path):
    store = _make_store(tmp_path)
    unsigned = "---\naid: alice.agentid.pub\n---\n# Alice From Memory\n"
    captured: dict[str, object] = {}
    _patch_put(monkeypatch, captured, '"alice-memory"')

    result = asyncio.run(store.upload_agent_md("alice.agentid.pub", unsigned))
    assert result.ok, result.error

    uploaded = bytes(captured["data"]).decode("utf-8")
    assert result.data["etag"] == '"alice-memory"'
    assert uploaded.startswith(unsigned)
    assert "<!-- AUN-SIGNATURE" in uploaded
    rec = _read_record(store, "alice.agentid.pub")
    assert rec["local_etag"] == _etag(uploaded)
    assert rec["remote_etag"] == '"alice-memory"'
    store.close()


def test_observe_rpc_meta_persists_structured_meta_and_downloads_missing_local(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path)
    downloaded: list[str] = []

    async def fake_download(aid):
        downloaded.append(aid)
        content = f"# {aid}\n"
        client._agent_md_manager.save_record(aid, content=content, local_etag=_etag(content), remote_status="found")
        return {"aid": aid, "content": content, "signature": {"status": "unsigned"}, "in_sync": False}

    monkeypatch.setattr(client._agent_md_manager, "download", fake_download)

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
            "group": {
                "aid": "team.group.agentid.pub",
                "etag": '"group-cloud"',
                "last_modified": "Sun, 24 May 2026 00:00:02 GMT",
            },
            "sender": {"aid": "dave.agentid.pub", "etag": '"dave-cloud"'},
        },
    })

    records = {
        aid: _read_record(client, aid)
        for aid in ("alice.agentid.pub", "bob.agentid.pub", "team.group.agentid.pub", "dave.agentid.pub")
    }
    assert records["alice.agentid.pub"]["remote_etag"] == '"alice-cloud-2"'
    assert records["bob.agentid.pub"]["remote_etag"] == '"bob-cloud"'
    assert records["team.group.agentid.pub"]["remote_etag"] == '"group-cloud"'
    assert records["team.group.agentid.pub"]["last_modified"] == "Sun, 24 May 2026 00:00:02 GMT"
    assert records["dave.agentid.pub"]["remote_etag"] == '"dave-cloud"'
    assert downloaded == ["alice.agentid.pub", "team.group.agentid.pub", "bob.agentid.pub", "dave.agentid.pub"]
    assert client._agent_md_manager.file_path("bob.agentid.pub").read_text(encoding="utf-8") == "# bob.agentid.pub\n"
    client._token_store.close()


def test_observe_envelope_agent_md_persists_sender_etag(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path, aid="bob.agentid.pub")

    async def fake_download(aid):
        return {"aid": aid}

    monkeypatch.setattr(client._agent_md_manager, "download", fake_download)
    client._agent_md_manager.observe_envelope({"agent_md": {"sender": {"aid": "alice.agentid.pub", "etag": '"alice-cloud"'}}})

    rec = _read_record(client, "alice.agentid.pub")
    assert rec["remote_etag"] == '"alice-cloud"'
    client._token_store.close()


def test_observe_envelope_agent_md_persists_group_etag(monkeypatch, tmp_path: Path):
    client = _make_client(tmp_path, aid="bob.agentid.pub")

    async def fake_download(aid):
        return {"aid": aid}

    monkeypatch.setattr(client._agent_md_manager, "download", fake_download)
    client._agent_md_manager.observe_envelope({
        "group_aid": "team.group.agentid.pub",
        "agent_md": {
            "sender": {"aid": "alice.agentid.pub", "etag": '"alice-cloud"'},
            "group": {
                "etag": '"group-cloud"',
                "last_modified": "Sun, 24 May 2026 00:00:02 GMT",
            },
        },
    })

    sender = _read_record(client, "alice.agentid.pub")
    group = _read_record(client, "team.group.agentid.pub")
    assert sender["remote_etag"] == '"alice-cloud"'
    assert group["remote_etag"] == '"group-cloud"'
    assert group["last_modified"] == "Sun, 24 May 2026 00:00:02 GMT"
    client._token_store.close()


def test_damaged_agentmd_json_rebuilds_from_agent_md_file(tmp_path: Path):
    client = _make_client(tmp_path)
    body = "# Alice\n"
    _write_local_agent_md(client, "alice.agentid.pub", body)
    client._agent_md_manager.cache["bob.agentid.pub"] = {"aid": "bob.agentid.pub", "remote_etag": '"stale"'}
    meta_path = client._agent_md_manager.meta_path("alice.agentid.pub")
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text("{bad json", encoding="utf-8")

    record = client._agent_md_manager.load_record("alice.agentid.pub")

    assert record is not None
    assert record["content"] == body
    assert record["local_etag"] == _etag(body)
    assert "remote_etag" not in record
    rebuilt = _read_record(client, "alice.agentid.pub")
    assert rebuilt["local_etag"] == _etag(body)
    assert "remote_etag" not in rebuilt
    assert "bob.agentid.pub" in client._agent_md_manager.cache
    client._token_store.close()


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

