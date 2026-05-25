import asyncio
import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AUNClient
from aun_core.errors import NotFoundError


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


def test_sign_agent_md_appends_tail_signature(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))

    assert signed.startswith("---\n")
    assert signed.count("<!-- AUN-SIGNATURE") == 1
    assert signed.rstrip().endswith("-->")


def test_verify_agent_md_unsigned_returns_unsigned():
    client = AUNClient()
    result = asyncio.run(client.auth.verify_agent_md(_sample_agent_md()))

    assert result["status"] == "unsigned"
    assert result["verified"] is False


def test_verify_agent_md_roundtrip(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))
    result = asyncio.run(
        client.auth.verify_agent_md(
            signed,
            aid=identity["aid"],
            cert_pem=identity["cert"],
        )
    )

    assert result["status"] == "verified"
    assert result["verified"] is True
    assert result["aid"] == identity["aid"]
    assert result["payload"] == _sample_agent_md()


def test_check_aid_reports_local_complete(tmp_path, monkeypatch):
    aid = "alice.agentid.pub"
    client = AUNClient({"aun_path": str(tmp_path / "check_local")})
    identity = _make_identity(aid)
    client._keystore.save_identity(aid, identity)

    async def fail_download(_aid: str):
        raise AssertionError("local complete check should not download agent.md")

    monkeypatch.setattr(client.auth, "download_agent_md", fail_download)

    result = asyncio.run(client.auth.check_aid({"aid": aid}))

    assert result["status"] == "local_ready"
    assert result["can_register"] is False
    assert result["local"]["exists"] is True
    assert result["local"]["complete"] is True
    assert result["local"]["private_key"] is True
    assert result["local"]["certificate"]["valid"] is True
    assert result["local"]["certificate"]["expired"] is False
    assert result["local"]["certificate"]["not_after"]
    assert result["remote"]["status"] == "not_checked"
    client._keystore.close()


def test_check_aid_available_when_agent_md_not_found(monkeypatch):
    aid = "free.agentid.pub"
    client = AUNClient()
    called: list[str] = []

    async def fake_download(target_aid: str):
        called.append(target_aid)
        raise NotFoundError(f"agent.md not found for aid: {target_aid}")

    monkeypatch.setattr(client.auth, "download_agent_md", fake_download)

    result = asyncio.run(client.auth.check_aid({"aid": aid}))

    assert called == [aid]
    assert result["status"] == "available"
    assert result["can_register"] is True
    assert result["local"]["exists"] is False
    assert result["remote"]["status"] == "available"
    assert result["remote"]["source"] == "agent.md"


def test_check_aid_registered_when_agent_md_exists(monkeypatch):
    aid = "taken.agentid.pub"
    client = AUNClient()

    async def fake_download(target_aid: str):
        return _sample_agent_md(target_aid)

    monkeypatch.setattr(client.auth, "download_agent_md", fake_download)

    result = asyncio.run(client.auth.check_aid({"aid": aid}))

    assert result["status"] == "registered_remote"
    assert result["can_register"] is False
    assert result["remote"]["status"] == "registered"
    assert result["remote"]["agent_md_aid"] == aid


def test_verify_agent_md_rejects_tamper(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))
    tampered = signed.replace("Alice", "Mallory", 1)
    result = asyncio.run(
        client.auth.verify_agent_md(
            tampered,
            aid=identity["aid"],
            cert_pem=identity["cert"],
        )
    )

    assert result["status"] == "invalid"
    assert result["verified"] is False


def test_sign_agent_md_replaces_existing_signature(monkeypatch):
    client = AUNClient()
    identity = _make_identity("alice.agentid.pub")
    client._aid = identity["aid"]
    monkeypatch.setattr(client._auth, "load_identity_or_none", lambda aid=None: identity)

    signed_once = asyncio.run(client.auth.sign_agent_md(_sample_agent_md()))
    signed_twice = asyncio.run(client.auth.sign_agent_md(signed_once))

    assert signed_twice.count("<!-- AUN-SIGNATURE") == 1


# ── download_agent_md 条件请求缓存 ────────────────────────────────────


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

    def get(self, url, headers=None):
        self.calls.append(dict(headers or {}))
        return self._responses.pop(0)


def _patch_session(monkeypatch, session: _FakeSession):
    import aun_core.namespaces.auth_namespace as mod

    monkeypatch.setattr(mod.aiohttp, "ClientSession", lambda *a, **kw: session)


def test_download_agent_md_caches_etag_and_last_modified(monkeypatch):
    client = AUNClient()
    namespace = client.auth

    async def _fake_resolve(_self, _aid):
        return "https://alice.agentid.pub/agent.md"

    monkeypatch.setattr(type(namespace), "_resolve_agent_md_url", _fake_resolve)

    payload = _sample_agent_md()
    headers = {
        "ETag": "\"abc123\"",
        "Last-Modified": "Sun, 18 May 2026 00:00:00 GMT",
    }
    session = _FakeSession([
        _FakeResponse(200, payload, headers),
        _FakeResponse(304, "", headers),
    ])
    _patch_session(monkeypatch, session)

    first = asyncio.run(namespace.download_agent_md("alice.agentid.pub"))
    assert first == payload
    # 第一次没有条件头
    assert "If-None-Match" not in session.calls[0]
    assert "If-Modified-Since" not in session.calls[0]

    # 第二次应当自动带上条件头，遇到 304 时返回上次缓存
    second = asyncio.run(namespace.download_agent_md("alice.agentid.pub"))
    assert second == payload
    assert session.calls[1].get("If-None-Match") == "\"abc123\""
    assert session.calls[1].get("If-Modified-Since") == "Sun, 18 May 2026 00:00:00 GMT"


def test_download_agent_md_updates_cache_on_change(monkeypatch):
    client = AUNClient()
    namespace = client.auth

    async def _fake_resolve(_self, _aid):
        return "https://alice.agentid.pub/agent.md"

    monkeypatch.setattr(type(namespace), "_resolve_agent_md_url", _fake_resolve)

    payload_v1 = _sample_agent_md()
    payload_v2 = _sample_agent_md() + "# v2\n"
    session = _FakeSession([
        _FakeResponse(200, payload_v1, {"ETag": "\"v1\"", "Last-Modified": "Sun, 18 May 2026 00:00:00 GMT"}),
        _FakeResponse(200, payload_v2, {"ETag": "\"v2\"", "Last-Modified": "Sun, 18 May 2026 01:00:00 GMT"}),
        _FakeResponse(304, "", {"ETag": "\"v2\"", "Last-Modified": "Sun, 18 May 2026 01:00:00 GMT"}),
    ])
    _patch_session(monkeypatch, session)

    assert asyncio.run(namespace.download_agent_md("alice.agentid.pub")) == payload_v1
    assert asyncio.run(namespace.download_agent_md("alice.agentid.pub")) == payload_v2
    # 第三次 304 应返回 v2
    assert asyncio.run(namespace.download_agent_md("alice.agentid.pub")) == payload_v2
    assert session.calls[1].get("If-None-Match") == "\"v1\""
    assert session.calls[2].get("If-None-Match") == "\"v2\""


class _FakeHeadSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def head(self, url, headers=None):
        self.calls.append(dict(headers or {}))
        return self._responses.pop(0)


def test_head_agent_md_returns_etag_without_body(monkeypatch):
    client = AUNClient()
    namespace = client.auth

    async def _fake_resolve(_self, _aid):
        return "https://alice.agentid.pub/agent.md"

    monkeypatch.setattr(type(namespace), "_resolve_agent_md_url", _fake_resolve)
    session = _FakeHeadSession([
        _FakeResponse(200, "should-not-read", {"ETag": '"abc123"', "Last-Modified": "Sun, 24 May 2026 00:00:00 GMT"}),
    ])
    _patch_session(monkeypatch, session)

    result = asyncio.run(namespace.head_agent_md("alice.agentid.pub"))

    assert result["aid"] == "alice.agentid.pub"
    assert result["found"] is True
    assert result["etag"] == '"abc123"'
    assert result["last_modified"] == "Sun, 24 May 2026 00:00:00 GMT"
    assert result["status"] == 200
    assert session.calls[0].get("Accept") == "text/markdown"


def test_head_agent_md_404_returns_not_found(monkeypatch):
    client = AUNClient()
    namespace = client.auth

    async def _fake_resolve(_self, _aid):
        return "https://missing.agentid.pub/agent.md"

    monkeypatch.setattr(type(namespace), "_resolve_agent_md_url", _fake_resolve)
    session = _FakeHeadSession([_FakeResponse(404)])
    _patch_session(monkeypatch, session)

    result = asyncio.run(namespace.head_agent_md("missing.agentid.pub"))

    assert result["found"] is False
    assert result["etag"] == ""
    assert result["status"] == 404
