"""bind_group_aid 幂等（崩溃恢复复用密钥）+ renew_group_aid 显式轮换的 Python SDK 单元测试。

设计要点：
- bind 首次生成密钥后立即以 group_id 暂存到 AIDStore pending 槽位，import 成功后清除。
  若 import 前崩溃，重试时复用同一密钥（断言两次 public_key 相同），服务端幂等返回同证书。
- renew 用本地旧 group_aid 私钥对 canonical payload 签名，新密钥落盘覆盖。
"""
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


class _BindClient(AUNClient):
    """bind 幂等场景：记录每次 RPC 收到的 public_key。"""

    def __init__(self, group_aid: str) -> None:
        super().__init__(None)
        self.group_aid = group_aid
        self.bind_pubkeys: list[str] = []
        self.calls: list[tuple[str, dict]] = []

    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None):
        payload = dict(params or {})
        self.calls.append((method, payload))
        if method == "group.bind_group_aid":
            self.bind_pubkeys.append(payload["public_key"])
            cert_pem = _cert_for_public_key(self.group_aid, payload["public_key"])
            return {
                "group": {"group_id": payload.get("group_id", "123456"), "group_aid": self.group_aid},
                "aid_cert": {"cert": cert_pem, "curve": payload["curve"]},
            }
        raise AssertionError(f"unexpected method {method}")


@pytest.mark.asyncio
async def test_bind_idempotent_reuses_key_after_import_crash(tmp_path):
    """import 前崩溃 → 重试复用 pending 槽位同一密钥（两次 RPC public_key 相同）。"""
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    group_aid = "123456.agentid.pub"
    group_id = "group.agentid.pub/123456"
    client = _BindClient(group_aid)

    # 第一次：让 import_group_identity 抛错模拟崩溃（落盘前失败）
    real_import = store.import_group_identity
    calls = {"n": 0}

    def _flaky_import(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated crash before import persists")
        return real_import(*args, **kwargs)

    store.import_group_identity = _flaky_import

    with pytest.raises(RuntimeError, match="simulated crash"):
        await client.bind_group_aid({"group_id": group_id}, aid_store=store)

    # 第二次：重试应复用 pending 槽位的同一密钥
    result = await client.bind_group_aid({"group_id": group_id}, aid_store=store)

    assert result["group"]["group_aid"] == group_aid
    assert len(client.bind_pubkeys) == 2
    assert client.bind_pubkeys[0] == client.bind_pubkeys[1], "重试必须复用同一公钥（幂等）"
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    assert loaded.data["aid"].is_private_key_valid()
    # 成功后 pending 槽位应被清除
    assert store._keystore.load_pending_group_bind(group_id) is None
    store.close()


@pytest.mark.asyncio
async def test_bind_clears_pending_slot_on_success(tmp_path):
    """正常 bind 成功后 pending 槽位被清除。"""
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    group_aid = "123456.agentid.pub"
    group_id = "group.agentid.pub/123456"
    client = _BindClient(group_aid)

    await client.bind_group_aid({"group_id": group_id}, aid_store=store)

    assert store._keystore.load_pending_group_bind(group_id) is None
    assert len(client.bind_pubkeys) == 1
    store.close()


# ── renew_group_aid ──────────────────────────────────────────

class _RenewClient(AUNClient):
    def __init__(self, group_aid: str, new_cert_pubkey_b64: str | None = None) -> None:
        super().__init__(None)
        self.group_aid = group_aid
        self.calls: list[tuple[str, dict]] = []

    async def call(self, method: str, params: dict | None = None, *, trace: str | None = None):
        payload = dict(params or {})
        self.calls.append((method, payload))
        if method == "group.renew_group_aid":
            # 服务端用新公钥签发新证书
            cert_pem = _cert_for_public_key(self.group_aid, payload["new_public_key"])
            return {
                "group": {"group_id": payload.get("group_id"), "group_aid": self.group_aid},
                "aid_cert": {"cert": cert_pem, "curve": payload["curve"], "key_purpose": "group_identity"},
                "revoked_serial": "sn-old",
            }
        raise AssertionError(f"unexpected method {method}")


@pytest.mark.asyncio
async def test_renew_signs_with_old_key_and_persists_new(tmp_path):
    """renew 用旧私钥签名 renew_proof，新密钥落盘覆盖。"""
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    group_aid = "g-renew.agentid.pub"
    group_id = "group.agentid.pub/renew"
    # 先导入旧群身份
    old = store._register_flow.generate_identity()
    old_cert = _cert_for_public_key(group_aid, old["public_key_der_b64"])
    imported = store.import_group_identity(
        group_aid,
        private_key_pem=old["private_key_pem"],
        public_key_der_b64=old["public_key_der_b64"],
        curve=old["curve"],
        cert_pem=old_cert,
    )
    assert imported.ok, imported.error
    old_pub_b64 = old["public_key_der_b64"]

    client = _RenewClient(group_aid)
    result = await client.renew_group_aid(
        {"group_id": group_id, "group_aid": group_aid}, aid_store=store
    )

    assert result["revoked_serial"] == "sn-old"
    assert client.calls[0][0] == "group.renew_group_aid"
    payload = client.calls[0][1]
    # old_public_key 必须是旧公钥；new_public_key 必须是新生成的、与旧不同
    assert payload["old_public_key"] == old_pub_b64
    assert payload["new_public_key"] and payload["new_public_key"] != old_pub_b64
    proof = payload["renew_proof"]
    assert proof["nonce"] and proof["signature"] and isinstance(proof["issued_ms"], int)

    # 验证签名用旧公钥可验过（canonical payload 与服务端一致）
    import hashlib
    old_hash = hashlib.sha256(payload["old_public_key"].encode()).hexdigest()
    new_hash = hashlib.sha256(payload["new_public_key"].encode()).hexdigest()
    canonical = "|".join([
        "aun-group-aid-renew-v1",
        group_id.strip().lower(),
        group_aid.strip().lower(),
        old_hash,
        new_hash,
        proof["nonce"],
        str(proof["issued_ms"]),
    ])
    old_pub = serialization.load_der_public_key(base64.b64decode(old_pub_b64))
    sig = base64.urlsafe_b64decode(proof["signature"] + "=" * (-len(proof["signature"]) % 4))
    old_pub.verify(sig, canonical.encode(), ec.ECDSA(hashes.SHA256()))  # 不抛即通过

    # 新身份已落盘覆盖（新公钥）
    loaded = store.load(group_aid)
    assert loaded.ok, loaded.error
    assert loaded.data["aid"].is_private_key_valid()
    store.close()


@pytest.mark.asyncio
async def test_renew_requires_existing_local_identity(tmp_path):
    """本地无旧 group 身份时 renew 报错。"""
    store = AIDStore(tmp_path / "aun", encryption_seed="test-seed")
    client = _RenewClient("missing.agentid.pub")

    with pytest.raises(ValueError, match="not found|no private key|identity"):
        await client.renew_group_aid(
            {"group_id": "group.agentid.pub/missing", "group_aid": "missing.agentid.pub"},
            aid_store=store,
        )
    store.close()


@pytest.mark.asyncio
async def test_renew_requires_aid_store():
    client = _RenewClient("123456.agentid.pub")
    with pytest.raises(ValueError, match="aid_store"):
        await client.renew_group_aid({"group_id": "group.agentid.pub/123456", "group_aid": "123456.agentid.pub"})
