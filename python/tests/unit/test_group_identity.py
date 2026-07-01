from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aun_core import AIDStore, AUNClient


def _cert_for_public_key(aid: str, public_key_der_b64: str) -> str:
    public_key = serialization.load_der_public_key(base64.b64decode(public_key_der_b64))
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, aid)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca.agentid.pub")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_import_group_identity_persists_and_loads(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    material = store._register_flow.generate_identity()
    group_aid = "g-demo.agentid.pub"
    cert_pem = _cert_for_public_key(group_aid, material["public_key_der_b64"])

    result = store.import_group_identity(
        group_aid,
        private_key_pem=material["private_key_pem"],
        public_key_der_b64=material["public_key_der_b64"],
        curve=material["curve"],
        cert_pem=cert_pem,
    )

    assert result.ok, result.error
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    aid_obj = loaded.data["aid"]
    assert aid_obj.is_private_key_valid()
    assert aid_obj.sign("hello").ok
    store.close()


def test_import_group_identity_rejects_cn_mismatch(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    material = store._register_flow.generate_identity()
    cert_pem = _cert_for_public_key("other.agentid.pub", material["public_key_der_b64"])

    result = store.import_group_identity(
        "g-demo.agentid.pub",
        private_key_pem=material["private_key_pem"],
        public_key_der_b64=material["public_key_der_b64"],
        curve=material["curve"],
        cert_pem=cert_pem,
    )

    assert not result.ok
    store.close()


def test_import_group_identity_rejects_public_key_mismatch(tmp_path):
    """F06：服务端用不同密钥签发证书（cert 公钥 ≠ 本地私钥对应公钥），落盘前应被拒。

    否则会落盘一个私钥/证书不配套的身份，该 group_aid 永远无法签名。
    """
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    material = store._register_flow.generate_identity()
    group_aid = "g-demo.agentid.pub"
    # 用另一份密钥的公钥签发证书（CN 仍是 group_aid，自洽但公钥不对）
    other = store._register_flow.generate_identity()
    cert_pem = _cert_for_public_key(group_aid, other["public_key_der_b64"])

    result = store.import_group_identity(
        group_aid,
        private_key_pem=material["private_key_pem"],
        public_key_der_b64=material["public_key_der_b64"],
        curve=material["curve"],
        cert_pem=cert_pem,
    )

    assert not result.ok
    assert "public key" in str(result.error.message).lower() or "mismatch" in str(result.error.message).lower()
    store.close()


class _CreateGroupClient(AUNClient):
    def __init__(self, group_aid: str, aid=None) -> None:
        super().__init__(aid)
        self.group_aid = group_aid
        self.calls: list[tuple[str, dict]] = []

    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None):
        payload = dict(params or {})
        self.calls.append((method, payload))
        if method == "group.bind_group_aid":
            cert_pem = _cert_for_public_key(self.group_aid, payload["public_key"])
            return {
                "group": {"group_id": payload.get("group_id", "123456"), "group_aid": self.group_aid},
                "aid_cert": {"cert": cert_pem, "curve": payload["curve"]},
            }
        if method == "group.complete_transfer":
            cert_pem = _cert_for_public_key(self.group_aid, payload["public_key"])
            return {
                "status": "transferred",
                "group": {"group_id": payload.get("group_id", "123456"), "group_aid": self.group_aid},
                "aid_cert": {"cert": cert_pem, "curve": payload["curve"], "key_purpose": "group_identity"},
            }
        if method == "group.transfer_owner":
            return {
                "status": "pending_rekey",
                "group_id": payload.get("group_id", "123456"),
                "group_aid": payload.get("group_aid", self.group_aid),
                "old_owner": "old-owner.agentid.pub",
                "new_owner": payload.get("new_owner"),
                "pending_owner_transfer": {
                    "status": "pending_rekey",
                    "transfer_auth": payload.get("transfer_auth") or {},
                },
            }
        if method == "group.get_info":
            group_id = payload.get("group_id", "123456")
            return {"group_id": group_id, "group_aid": self.group_aid}
        if "group_name" not in payload:
            return {"group": {"group_id": "123456", "group_aid": "123456.agentid.pub"}}
        cert_pem = _cert_for_public_key(self.group_aid, payload["public_key"])
        return {
            "group": {"group_id": f"group.agentid.pub/{payload['group_name']}", "group_aid": self.group_aid},
            "aid_cert": {"cert": cert_pem, "curve": payload["curve"]},
        }


class _CertPemGroupClient(_CreateGroupClient):
    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None):
        payload = dict(params or {})
        self.calls.append((method, payload))
        cert_pem = _cert_for_public_key(self.group_aid, payload.get("public_key", ""))
        if method == "group.bind_group_aid":
            return {
                "group": {"group_id": payload.get("group_id", "123456"), "group_aid": self.group_aid},
                "aid_cert": {"cert_pem": cert_pem, "curve": payload["curve"]},
            }
        if "group_name" not in payload:
            return {"group": {"group_id": "123456", "group_aid": "123456.agentid.pub"}}
        return {
            "group": {"group_id": f"group.agentid.pub/{payload['group_name']}", "group_aid": self.group_aid},
            "aid_cert": {"cert_pem": cert_pem, "curve": payload["curve"]},
        }


@pytest.mark.asyncio
async def test_create_named_group_generates_key_and_persists(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    group_aid = "g-demo.agentid.pub"
    client = _CreateGroupClient(group_aid)

    result = await client.create_group(
        {"name": "demo group", "group_name": "g-demo"},
        aid_store=store,
    )

    assert result["group"]["group_aid"] == group_aid
    assert client.calls[0][0] == "group.create"
    assert client.calls[0][1]["public_key"]
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    assert loaded.data["aid"].is_private_key_valid()
    store.close()


@pytest.mark.asyncio
async def test_create_named_group_accepts_aid_cert_cert_pem(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    group_aid = "g-cert-pem.agentid.pub"
    client = _CertPemGroupClient(group_aid)

    result = await client.create_group(
        {"name": "demo group", "group_name": "g-cert-pem"},
        aid_store=store,
    )

    assert result["group"]["group_aid"] == group_aid
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    assert loaded.data["aid"].is_private_key_valid()
    store.close()


@pytest.mark.asyncio
async def test_create_anonymous_group_skips_group_identity_keygen(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    client = _CreateGroupClient("unused.agentid.pub")

    result = await client.create_group({"name": "anonymous"}, aid_store=store)

    assert result["group"]["group_id"] == "123456"
    assert client.calls == [("group.create", {"name": "anonymous"})]
    assert store.list().data["identities"] == []
    store.close()


@pytest.mark.asyncio
async def test_bind_group_aid_generates_key_and_persists_without_group_name(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    group_aid = "123456.agentid.pub"
    client = _CreateGroupClient(group_aid)

    result = await client.bind_group_aid({"group_id": "group.agentid.pub/123456"}, aid_store=store)

    assert result["group"]["group_aid"] == group_aid
    assert client.calls[0][0] == "group.bind_group_aid"
    assert client.calls[0][1]["public_key"]
    assert client.calls[0][1]["curve"] == "P-256"
    assert "group_name" not in client.calls[0][1]
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    assert loaded.data["aid"].is_private_key_valid()
    store.close()


@pytest.mark.asyncio
async def test_bind_group_aid_accepts_aid_cert_cert_pem(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    group_aid = "123456.agentid.pub"
    client = _CertPemGroupClient(group_aid)

    result = await client.bind_group_aid({"group_id": "group.agentid.pub/123456"}, aid_store=store)

    assert result["group"]["group_aid"] == group_aid
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    assert loaded.data["aid"].is_private_key_valid()
    store.close()


@pytest.mark.asyncio
async def test_bind_group_aid_requires_aid_store():
    client = _CreateGroupClient("123456.agentid.pub")

    with pytest.raises(ValueError, match="aid_store"):
        await client.bind_group_aid({"group_id": "group.agentid.pub/123456"})


@pytest.mark.asyncio
async def test_start_group_transfer_signs_with_group_aid_identity(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    material = store._register_flow.generate_identity()
    group_aid = "g-transfer.agentid.pub"
    cert_pem = _cert_for_public_key(group_aid, material["public_key_der_b64"])
    imported = store.import_group_identity(
        group_aid,
        private_key_pem=material["private_key_pem"],
        public_key_der_b64=material["public_key_der_b64"],
        curve=material["curve"],
        cert_pem=cert_pem,
    )
    assert imported.ok, imported.error
    client = _CreateGroupClient(group_aid)

    result = await client.start_group_transfer(
        {
            "group_id": "group.agentid.pub/transfer-demo",
            "new_owner": "new-owner.agentid.pub",
            "group_aid": group_aid,
        },
        aid_store=store,
    )

    assert result["status"] == "pending_rekey"
    assert [item[0] for item in client.calls] == ["group.transfer_owner"]
    payload = client.calls[0][1]
    assert payload["group_aid"] == group_aid
    auth = payload["transfer_auth"]
    assert auth["nonce"]
    assert isinstance(auth["issued_ms"], int)
    assert auth["signature"]
    canonical = "|".join([
        "aun-group-owner-transfer-v1",
        "group.agentid.pub/transfer-demo",
        group_aid,
        "new-owner.agentid.pub",
        auth["nonce"],
        str(auth["issued_ms"]),
    ])
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    verified = loaded.data["aid"].verify(canonical, auth["signature"])
    assert verified.ok, verified.error
    assert verified.data["valid"] is True
    store.close()


@pytest.mark.asyncio
async def test_start_group_transfer_requires_group_identity(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    client = _CreateGroupClient("missing.agentid.pub")

    with pytest.raises(ValueError, match="group_aid identity not found"):
        await client.start_group_transfer(
            {
                "group_id": "group.agentid.pub/missing",
                "new_owner": "new-owner.agentid.pub",
                "group_aid": "missing.agentid.pub",
            },
            aid_store=store,
        )
    store.close()


@pytest.mark.asyncio
async def test_complete_group_transfer_generates_key_and_persists(tmp_path):
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    new_owner_material = store._register_flow.generate_identity()
    new_owner_aid = "new-owner.agentid.pub"
    new_owner_cert = _cert_for_public_key(new_owner_aid, new_owner_material["public_key_der_b64"])
    imported_owner = store.import_group_identity(
        new_owner_aid,
        private_key_pem=new_owner_material["private_key_pem"],
        public_key_der_b64=new_owner_material["public_key_der_b64"],
        curve=new_owner_material["curve"],
        cert_pem=new_owner_cert,
    )
    assert imported_owner.ok, imported_owner.error
    loaded_owner = store.load(new_owner_aid)
    assert loaded_owner.ok, loaded_owner.error
    group_aid = "123456.agentid.pub"
    client = _CreateGroupClient(group_aid, loaded_owner.data["aid"])

    result = await client.complete_group_transfer({"group_id": "group.agentid.pub/123456"}, aid_store=store)

    assert result["group"]["group_aid"] == group_aid
    assert [item[0] for item in client.calls] == ["group.get_info", "group.complete_transfer"]
    complete_payload = client.calls[1][1]
    assert complete_payload["public_key"]
    assert complete_payload["curve"] == "P-256"
    assert complete_payload["group_aid"] == group_aid
    assert complete_payload["transfer_accept"]["signature"]
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    assert loaded.data["aid"].is_private_key_valid()
    store.close()


@pytest.mark.asyncio
async def test_complete_group_transfer_requires_aid_store():
    client = _CreateGroupClient("123456.agentid.pub")

    with pytest.raises(ValueError, match="aid_store"):
        await client.complete_group_transfer({"group_id": "group.agentid.pub/123456"})
