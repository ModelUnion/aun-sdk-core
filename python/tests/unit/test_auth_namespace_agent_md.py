import asyncio
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AUNClient


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
