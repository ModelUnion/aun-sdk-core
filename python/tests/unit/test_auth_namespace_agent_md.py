import asyncio
import base64
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AIDStore, result_ok
from aun_core._cert_utils import parse_agent_md_tail_signature


def _make_identity(aid: str) -> dict[str, str]:
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


def _sample_agent_md(aid: str = "alice.agentid.pub") -> str:
    return (
        "---\n"
        f"aid: \"{aid}\"\n"
        "name: \"Alice\"\n"
        "type: \"assistant\"\n"
        "version: \"1.0.0\"\n"
        "description: \"Alice\"\n"
        "---\n"
        "\n"
        "# Alice\n"
    )


def _store_with_identity(tmp_path, aid: str = "alice.agentid.pub") -> tuple[AIDStore, dict[str, str]]:
    store = AIDStore(tmp_path, encryption_seed="", verify_ssl=False)
    identity = _make_identity(aid)
    store._keystore.save_identity(aid, identity)
    return store, identity


def _load_aid(store: AIDStore, aid: str):
    loaded = store.load(aid)
    assert loaded.ok, loaded.error
    assert loaded.data is not None
    return loaded.data["aid"]


def test_aid_sign_agent_md_appends_tail_signature(tmp_path):
    store, identity = _store_with_identity(tmp_path, "alice.agentid.pub")
    aid = _load_aid(store, identity["aid"])

    signed = aid.sign_agent_md(_sample_agent_md())

    assert signed.ok, signed.error
    assert signed.data is not None
    text = signed.data["signed"]
    assert text.startswith("---\n")
    assert text.count("<!-- AUN-SIGNATURE") == 1
    assert text.rstrip().endswith("-->")
    _, fields, _ = parse_agent_md_tail_signature(text)
    assert fields is not None
    cert = x509.load_pem_x509_certificate(identity["cert"].encode("utf-8"))
    cert_fp = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_fp = "sha256:" + hashlib.sha256(spki).hexdigest()
    assert fields["cert_fingerprint"] == cert_fp
    assert fields["public_key_fingerprint"] == public_key_fp
    store.close()


def test_aid_verify_agent_md_unsigned_returns_unsigned(tmp_path):
    store, identity = _store_with_identity(tmp_path, "alice.agentid.pub")
    aid = _load_aid(store, identity["aid"])

    result = aid.verify_agent_md(_sample_agent_md())

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["status"] == "unsigned"
    store.close()


def test_aid_verify_agent_md_roundtrip(tmp_path):
    store, identity = _store_with_identity(tmp_path, "alice.agentid.pub")
    aid = _load_aid(store, identity["aid"])

    signed = aid.sign_agent_md(_sample_agent_md())
    assert signed.ok and signed.data is not None
    result = aid.verify_agent_md(signed.data["signed"])

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["status"] == "verified"
    assert result.data["aid"] == identity["aid"]
    assert result.data["payload"] == _sample_agent_md()
    store.close()


def test_aid_store_diagnose_reports_local_ready(tmp_path, monkeypatch):
    aid = "alice.agentid.pub"
    store, identity = _store_with_identity(tmp_path, aid)

    async def fake_exists(_aid: str):
        return result_ok({"exists": True})

    async def fake_fetch_peer_cert(_gateway_url: str, _aid: str):
        return identity["cert"]

    monkeypatch.setattr(store, "exists", fake_exists)
    monkeypatch.setattr(store, "_resolve_gateway", lambda _aid: "wss://gateway.agentid.pub")
    monkeypatch.setattr(store._register_flow, "fetch_peer_cert", fake_fetch_peer_cert)
    result = asyncio.run(store.diagnose(aid))

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["status"] == "ready"
    assert result.data["local_valid"] is True
    assert result.data["remote_registered"] is True
    assert result.data["suggestions"] == []
    store.close()


def test_aid_store_diagnose_available_when_remote_missing(tmp_path, monkeypatch):
    aid = "free.agentid.pub"
    store = AIDStore(tmp_path, encryption_seed="", verify_ssl=False)

    async def fake_exists(_aid: str):
        return result_ok({"exists": False})

    monkeypatch.setattr(store, "exists", fake_exists)
    result = asyncio.run(store.diagnose(aid))

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["status"] == "available"
    assert result.data["local_valid"] is False
    assert result.data["remote_registered"] is False
    assert result.data["suggestions"]
    store.close()


def test_aid_store_diagnose_registered_when_remote_exists(tmp_path, monkeypatch):
    aid = "taken.agentid.pub"
    store = AIDStore(tmp_path, encryption_seed="", verify_ssl=False)

    async def fake_exists(_aid: str):
        return result_ok({"exists": True})

    monkeypatch.setattr(store, "exists", fake_exists)
    result = asyncio.run(store.diagnose(aid))

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["status"] == "registered_remote"
    assert result.data["local_valid"] is False
    assert result.data["remote_registered"] is True
    assert result.data["suggestions"]
    store.close()


def test_aid_verify_agent_md_rejects_tamper(tmp_path):
    store, identity = _store_with_identity(tmp_path, "alice.agentid.pub")
    aid = _load_aid(store, identity["aid"])
    signed = aid.sign_agent_md(_sample_agent_md())
    assert signed.ok and signed.data is not None

    tampered = signed.data["signed"].replace("Alice", "Mallory", 1)
    result = aid.verify_agent_md(tampered)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["status"] == "invalid"
    store.close()


def test_aid_sign_agent_md_replaces_existing_signature(tmp_path):
    store, identity = _store_with_identity(tmp_path, "alice.agentid.pub")
    aid = _load_aid(store, identity["aid"])
    signed_once = aid.sign_agent_md(_sample_agent_md())
    assert signed_once.ok and signed_once.data is not None

    signed_twice = aid.sign_agent_md(signed_once.data["signed"])

    assert signed_twice.ok, signed_twice.error
    assert signed_twice.data is not None
    assert signed_twice.data["signed"].count("<!-- AUN-SIGNATURE") == 1
    store.close()


class _FakeResponse:
    def __init__(self, status: int, text: str = "", headers: dict[str, str] | None = None):
        self.status = status
        self._text = text
        self.headers = headers or {}

    async def text(self) -> str:
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def get(self, url, *, ssl=None, headers=None, allow_redirects=True):
        self.calls.append(dict(headers or {}))
        return self._responses.pop(0)


def _patch_session(monkeypatch, session):
    import aun_core.aid_store as mod

    monkeypatch.setattr(mod.aiohttp, "ClientSession", lambda *a, **kw: session)


def test_download_agent_md_always_uses_unconditional_get(monkeypatch, tmp_path):
    aid_name = "alice.agentid.pub"
    store, _identity = _store_with_identity(tmp_path, aid_name)
    aid = _load_aid(store, aid_name)
    signed = aid.sign_agent_md(_sample_agent_md(aid_name))
    assert signed.ok and signed.data is not None

    async def fake_gateway(_aid: str):
        return "https://gateway.agentid.pub/aun"

    monkeypatch.setattr(store, "_resolved_gateway", fake_gateway)
    headers = {
        "ETag": "\"abc123\"",
        "Last-Modified": "Sun, 18 May 2026 00:00:00 GMT",
    }
    session = _FakeSession([
        _FakeResponse(200, signed.data["signed"], headers),
        _FakeResponse(304, "", headers),
    ])
    _patch_session(monkeypatch, session)

    first = asyncio.run(store.download_agent_md(aid_name))
    assert first.ok, first.error
    assert first.data is not None
    assert first.data["content"] == signed.data["signed"]
    assert "If-None-Match" not in session.calls[0]
    assert "If-Modified-Since" not in session.calls[0]

    second = asyncio.run(store.download_agent_md(aid_name))
    assert second.ok, second.error
    assert second.data is not None
    assert second.data["content"] == signed.data["signed"]
    assert "If-None-Match" not in session.calls[1]
    assert "If-Modified-Since" not in session.calls[1]
    store.close()


def test_download_agent_md_retries_unconditional_get_when_304_without_content(monkeypatch, tmp_path):
    aid_name = "alice.agentid.pub"
    store, _identity = _store_with_identity(tmp_path, aid_name)
    aid = _load_aid(store, aid_name)
    signed = aid.sign_agent_md(_sample_agent_md(aid_name))
    assert signed.ok and signed.data is not None

    async def fake_gateway(_aid: str):
        return "https://gateway.agentid.pub/aun"

    monkeypatch.setattr(store, "_resolved_gateway", fake_gateway)
    manager = store._agent_md_manager
    manager.save_record(aid_name, remote_etag="\"head-only\"", remote_status="found")
    session = _FakeSession([
        _FakeResponse(304, "", {"ETag": "\"head-only\""}),
        _FakeResponse(200, signed.data["signed"], {"ETag": "\"head-only\""}),
    ])
    _patch_session(monkeypatch, session)

    result = asyncio.run(store.download_agent_md(aid_name))
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["content"] == signed.data["signed"]
    assert len(session.calls) == 2
    assert "If-None-Match" not in session.calls[0]
    assert "If-Modified-Since" not in session.calls[0]
    assert "If-None-Match" not in session.calls[1]
    assert "If-Modified-Since" not in session.calls[1]
    store.close()


def test_download_agent_md_updates_cache_on_change(monkeypatch, tmp_path):
    aid_name = "alice.agentid.pub"
    store, _identity = _store_with_identity(tmp_path, aid_name)
    aid = _load_aid(store, aid_name)
    signed_v1 = aid.sign_agent_md(_sample_agent_md(aid_name))
    signed_v2 = aid.sign_agent_md(_sample_agent_md(aid_name) + "# v2\n")
    assert signed_v1.ok and signed_v1.data is not None
    assert signed_v2.ok and signed_v2.data is not None

    async def fake_gateway(_aid: str):
        return "https://gateway.agentid.pub/aun"

    monkeypatch.setattr(store, "_resolved_gateway", fake_gateway)
    session = _FakeSession([
        _FakeResponse(200, signed_v1.data["signed"], {"ETag": "\"v1\"", "Last-Modified": "Sun, 18 May 2026 00:00:00 GMT"}),
        _FakeResponse(200, signed_v2.data["signed"], {"ETag": "\"v2\"", "Last-Modified": "Sun, 18 May 2026 01:00:00 GMT"}),
        _FakeResponse(200, signed_v2.data["signed"], {"ETag": "\"v2\"", "Last-Modified": "Sun, 18 May 2026 01:00:00 GMT"}),
    ])
    _patch_session(monkeypatch, session)

    assert asyncio.run(store.download_agent_md(aid_name)).data["content"] == signed_v1.data["signed"]
    assert asyncio.run(store.download_agent_md(aid_name)).data["content"] == signed_v2.data["signed"]
    assert asyncio.run(store.download_agent_md(aid_name)).data["content"] == signed_v2.data["signed"]
    assert "If-None-Match" not in session.calls[1]
    assert "If-Modified-Since" not in session.calls[1]
    assert "If-None-Match" not in session.calls[2]
    assert "If-Modified-Since" not in session.calls[2]
    store.close()


class _FakeHeadSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def head(self, url, *, ssl=None, headers=None, allow_redirects=True):
        self.calls.append(dict(headers or {}))
        return self._responses.pop(0)


def test_check_agent_md_uses_head_etag_without_body(monkeypatch, tmp_path):
    store = AIDStore(tmp_path, encryption_seed="", verify_ssl=False)

    async def fake_gateway(_aid: str):
        return "https://gateway.agentid.pub/aun"

    monkeypatch.setattr(store, "_resolved_gateway", fake_gateway)
    session = _FakeHeadSession([
        _FakeResponse(200, "should-not-read", {"ETag": '"abc123"', "Last-Modified": "Sun, 24 May 2026 00:00:00 GMT"}),
    ])
    _patch_session(monkeypatch, session)

    result = asyncio.run(store.check_agent_md("alice.agentid.pub", ttl_days=0))

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["aid"] == "alice.agentid.pub"
    assert result.data["local_found"] is False
    assert result.data["remote_found"] is True
    assert result.data["remote_etag"] == '"abc123"'
    assert result.data["last_modified"] == "Sun, 24 May 2026 00:00:00 GMT"
    assert result.data["needs_update"] is True
    assert session.calls[0].get("Accept") is None
    store.close()


def test_check_agent_md_404_returns_missing_state(monkeypatch, tmp_path):
    store = AIDStore(tmp_path, encryption_seed="", verify_ssl=False)

    async def fake_gateway(_aid: str):
        return "https://gateway.agentid.pub/aun"

    monkeypatch.setattr(store, "_resolved_gateway", fake_gateway)
    session = _FakeHeadSession([_FakeResponse(404)])
    _patch_session(monkeypatch, session)

    result = asyncio.run(store.check_agent_md("missing.agentid.pub", ttl_days=0))

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["remote_found"] is False
    assert result.data["status"] == 404
    assert result.data["needs_update"] is False
    store.close()

