"""E2EE 单元测试 — 覆盖两级降级（prekey_ecdh / long_term_key）、AAD、防重放。

测试策略：用真实密码学原语（cryptography 库），E2EEManager 为纯工具类，无 RPC mock。
"""

import asyncio
import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aun_core.e2ee import (
    AAD_FIELDS_OFFLINE,
    AAD_MATCH_FIELDS_OFFLINE,
    MODE_LONG_TERM_KEY,
    MODE_PREKEY_ECDH,
    SUITE,
    E2EEManager,
)
from aun_core.errors import E2EEDecryptFailedError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_ec_keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    pub_der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, pub_der, base64.b64encode(pub_der).decode("ascii")


def _make_self_signed_cert(private_key):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class FakeKeystore:
    def __init__(self):
        self._metadata = {}
        self._key_pairs = {}

    def load_metadata(self, aid):
        return self._metadata.get(aid, {})

    def save_metadata(self, aid, meta):
        self._metadata[aid] = meta

    def load_key_pair(self, aid):
        return self._key_pairs.get(aid)


def _build_identity(aid, private_key):
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    pub_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "aid": aid,
        "private_key_pem": priv_pem,
        "public_key_der_b64": base64.b64encode(pub_der).decode("ascii"),
    }


def _make_e2ee_pair():
    """创建一对 sender/receiver 的 E2EEManager + 证书。"""
    sender_key, _, _ = _generate_ec_keypair()
    receiver_key, _, _ = _generate_ec_keypair()

    sender_identity = _build_identity("sender.test", sender_key)
    receiver_identity = _build_identity("receiver.test", receiver_key)

    sender_ks = FakeKeystore()
    receiver_ks = FakeKeystore()

    sender_ks._key_pairs["sender.test"] = {
        "private_key_pem": sender_identity["private_key_pem"],
        "public_key_der_b64": sender_identity["public_key_der_b64"],
    }
    receiver_ks._key_pairs["receiver.test"] = {
        "private_key_pem": receiver_identity["private_key_pem"],
        "public_key_der_b64": receiver_identity["public_key_der_b64"],
    }

    sender_mgr = E2EEManager(
        identity_fn=lambda: sender_identity,
        keystore=sender_ks,
    )
    receiver_mgr = E2EEManager(
        identity_fn=lambda: receiver_identity,
        keystore=receiver_ks,
    )

    sender_cert = _make_self_signed_cert(sender_key)
    receiver_cert = _make_self_signed_cert(receiver_key)

    return (sender_mgr, receiver_mgr, sender_key, receiver_key,
            sender_cert, receiver_cert, sender_ks, receiver_ks)


def _make_prekey(receiver_key):
    """生成 prekey 并用 receiver 身份私钥签名。"""
    prekey_private = ec.generate_private_key(ec.SECP256R1())
    prekey_pub_der = prekey_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    prekey_id = str(uuid.uuid4())
    public_key_b64 = base64.b64encode(prekey_pub_der).decode("ascii")

    sign_data = f"{prekey_id}|{public_key_b64}".encode("utf-8")
    signature = receiver_key.sign(sign_data, ec.ECDSA(hashes.SHA256()))

    prekey = {
        "prekey_id": prekey_id,
        "public_key": public_key_b64,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return prekey, prekey_private


# ---------------------------------------------------------------------------
# AAD 测试
# ---------------------------------------------------------------------------

class TestAADMethods:
    def test_aad_bytes_offline_field_count(self):
        assert len(AAD_FIELDS_OFFLINE) == 8
        assert "encryption_mode" in AAD_FIELDS_OFFLINE
        assert "recipient_cert_fingerprint" in AAD_FIELDS_OFFLINE

    def test_aad_bytes_offline_deterministic(self):
        aad = {
            "from": "a", "to": "b", "message_id": "m1", "timestamp": 123,
            "encryption_mode": MODE_PREKEY_ECDH, "suite": SUITE,
            "ephemeral_public_key": "pk_b64",
            "recipient_cert_fingerprint": "sha256:abc",
        }
        b1 = E2EEManager._aad_bytes_offline(aad)
        b2 = E2EEManager._aad_bytes_offline(aad)
        assert b1 == b2
        keys = list(json.loads(b1).keys())
        assert keys == sorted(keys)

    def test_aad_matches_offline(self):
        a = {"from": "a", "to": "b", "message_id": "m", "timestamp": 100,
             "encryption_mode": MODE_PREKEY_ECDH, "suite": SUITE,
             "ephemeral_public_key": "pk", "recipient_cert_fingerprint": "fp"}
        b = {**a, "timestamp": 999}
        assert E2EEManager._aad_matches_offline(a, b)

    def test_aad_matches_offline_mode_mismatch(self):
        a = {"from": "a", "to": "b", "message_id": "m",
             "encryption_mode": MODE_PREKEY_ECDH, "suite": SUITE,
             "ephemeral_public_key": "pk", "recipient_cert_fingerprint": "fp"}
        b = {**a, "encryption_mode": MODE_LONG_TERM_KEY}
        assert not E2EEManager._aad_matches_offline(a, b)


# ---------------------------------------------------------------------------
# prekey_ecdh 加解密
# ---------------------------------------------------------------------------

class TestPrekeyEncrypt:
    def test_prekey_encrypt_envelope_fields(self):
        sender_mgr, _, _, receiver_key, _, receiver_cert, _, _ = _make_e2ee_pair()
        prekey, _ = _make_prekey(receiver_key)

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr._encrypt_with_prekey(
            "receiver.test", {"text": "hello"}, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok
        assert envelope["encryption_mode"] == MODE_PREKEY_ECDH
        assert envelope["prekey_id"] == prekey["prekey_id"]
        assert "ephemeral_public_key" in envelope
        aad = envelope["aad"]
        assert aad["encryption_mode"] == MODE_PREKEY_ECDH

    def test_prekey_encrypt_decrypt_roundtrip(self):
        sender_mgr, receiver_mgr, _, receiver_key, _, receiver_cert, _, receiver_ks = _make_e2ee_pair()
        prekey, prekey_private = _make_prekey(receiver_key)

        # 将 prekey 私钥存入 receiver keystore
        priv_pem = prekey_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks._metadata["receiver.test"] = {
            "e2ee_prekeys": {
                prekey["prekey_id"]: {"private_key_pem": priv_pem, "created_at": int(time.time() * 1000)},
            },
        }

        payload = {"text": "prekey roundtrip"}
        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)

        envelope, ok = sender_mgr._encrypt_with_prekey(
            "receiver.test", payload, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok

        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }

        result = receiver_mgr._decrypt_message_prekey(message)
        assert result is not None
        assert result["payload"] == payload
        assert result["e2ee"]["encryption_mode"] == MODE_PREKEY_ECDH


# ---------------------------------------------------------------------------
# long_term_key 加解密
# ---------------------------------------------------------------------------

class TestLongTermKey:
    def test_long_term_key_envelope_has_8_field_aad(self):
        sender_mgr, _, _, _, _, receiver_cert, _, _ = _make_e2ee_pair()

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr._encrypt_with_long_term_key(
            "receiver.test", {"text": "hello"}, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok
        assert envelope["encryption_mode"] == MODE_LONG_TERM_KEY
        aad = envelope["aad"]
        for field in AAD_FIELDS_OFFLINE:
            assert field in aad

    def test_long_term_key_roundtrip(self):
        sender_mgr, receiver_mgr, _, _, _, receiver_cert, _, _ = _make_e2ee_pair()

        payload = {"text": "mode3 roundtrip"}
        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)

        envelope, ok = sender_mgr._encrypt_with_long_term_key(
            "receiver.test", payload, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok

        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }

        result = receiver_mgr._decrypt_message_long_term(message)
        assert result is not None
        assert result["payload"] == payload
        assert result["e2ee"]["encryption_mode"] == MODE_LONG_TERM_KEY


# ---------------------------------------------------------------------------
# 两级降级
# ---------------------------------------------------------------------------

class TestEncryptOutboundDegradation:
    def test_prekey_available_uses_prekey(self):
        """有 prekey → 使用 prekey_ecdh"""
        sender_mgr, _, _, receiver_key, _, receiver_cert, _, _ = _make_e2ee_pair()
        prekey, _ = _make_prekey(receiver_key)

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr.encrypt_outbound(
            "receiver.test", {"text": "test"},
            peer_cert_pem=receiver_cert,
            prekey=prekey,
            message_id=mid, timestamp=ts,
        )
        assert ok
        assert envelope["encryption_mode"] == MODE_PREKEY_ECDH

    def test_no_prekey_falls_to_long_term(self):
        """无 prekey → 降级到 long_term_key"""
        sender_mgr, _, _, _, _, receiver_cert, _, _ = _make_e2ee_pair()

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr.encrypt_outbound(
            "receiver.test", {"text": "test"},
            peer_cert_pem=receiver_cert,
            prekey=None,
            message_id=mid, timestamp=ts,
        )
        assert ok
        assert envelope["encryption_mode"] == MODE_LONG_TERM_KEY


# ---------------------------------------------------------------------------
# 本地防重放
# ---------------------------------------------------------------------------

class TestReplayGuard:
    def test_local_seen_set_blocks_duplicate(self):
        _, receiver_mgr, _, receiver_key, _, receiver_cert, _, receiver_ks = _make_e2ee_pair()
        sender_mgr = _make_e2ee_pair()[0]

        prekey, prekey_private = _make_prekey(receiver_key)
        priv_pem = prekey_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks._metadata["receiver.test"] = {
            "e2ee_prekeys": {
                prekey["prekey_id"]: {"private_key_pem": priv_pem, "created_at": int(time.time() * 1000)},
            },
        }

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, _ = sender_mgr._encrypt_with_prekey(
            "receiver.test", {"text": "test"}, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }

        # 第一次解密成功
        result1 = receiver_mgr.decrypt_message(message)
        assert result1 is not None
        assert result1["payload"]["text"] == "test"

        # 第二次重放被拦截
        result2 = receiver_mgr.decrypt_message(message)
        assert result2 is None

    def test_seen_set_trim(self):
        _, receiver_mgr, _, _, _, _, _, _ = _make_e2ee_pair()
        receiver_mgr._seen_max_size = 100
        for i in range(120):
            receiver_mgr._seen_messages[f"sender:msg_{i}"] = True
        receiver_mgr._trim_seen_set()
        assert len(receiver_mgr._seen_messages) == 80
        assert "sender:msg_119" in receiver_mgr._seen_messages
        assert "sender:msg_0" not in receiver_mgr._seen_messages


# ---------------------------------------------------------------------------
# prekey 生成
# ---------------------------------------------------------------------------

class TestPrekeyGenerate:
    def test_generate_prekey_stores_private_key(self):
        """generate_prekey 后私钥存入本地 keystore"""
        _, receiver_mgr, _, _, _, _, _, receiver_ks = _make_e2ee_pair()

        result = receiver_mgr.generate_prekey()
        assert "prekey_id" in result
        assert "public_key" in result
        assert "signature" in result

        meta = receiver_ks.load_metadata("receiver.test")
        prekeys = meta.get("e2ee_prekeys", {})
        assert len(prekeys) == 1
        pid = list(prekeys.keys())[0]
        assert "private_key_pem" in prekeys[pid]
        assert "created_at" in prekeys[pid]


# ---------------------------------------------------------------------------
# decrypt_message 便利方法
# ---------------------------------------------------------------------------

class TestDecryptMessage:
    def test_plaintext_passthrough(self):
        """明文消息直接透传"""
        _, receiver_mgr, _, _, _, _, _, _ = _make_e2ee_pair()
        message = {"seq": 1, "payload": {"text": "hello"}}
        result = receiver_mgr.decrypt_message(message)
        assert result is not None
        assert result["payload"]["text"] == "hello"

    def test_encrypted_decrypted(self):
        """加密消息被自动解密"""
        sender_mgr, receiver_mgr, _, _, _, receiver_cert, _, _ = _make_e2ee_pair()

        payload = {"text": "secret"}
        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, _ = sender_mgr._encrypt_with_long_term_key(
            "receiver.test", payload, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }

        result = receiver_mgr.decrypt_message(message)
        assert result is not None
        assert result["payload"] == payload


# ---------------------------------------------------------------------------
# FileKeyStore 存储保护
# ---------------------------------------------------------------------------

class TestFileKeyStoreProtection:
    def test_identity_private_key_not_plaintext(self, tmp_path):
        import json
        from aun_core.keystore.file import FileKeyStore

        ks = FileKeyStore(root=tmp_path)
        identity = {
            "private_key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            "public_key_der_b64": "MFkw...",
            "curve": "P-256",
        }
        ks.save_identity("test.aid", identity)

        key_file = tmp_path / "AIDs" / "test.aid" / "private" / "key.json"
        assert key_file.exists()
        content = json.loads(key_file.read_text(encoding="utf-8"))
        assert "private_key_pem" not in content
        assert "private_key_protection" in content

        loaded = ks.load_identity("test.aid")
        assert loaded is not None
        assert loaded["private_key_pem"] == identity["private_key_pem"]

    def test_prekey_private_key_not_plaintext(self, tmp_path):
        import json
        from aun_core.keystore.file import FileKeyStore

        ks = FileKeyStore(root=tmp_path)
        metadata = {
            "e2ee_prekeys": {
                "prekey-123": {
                    "private_key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
                    "public_key": "MFkw...",
                }
            }
        }
        ks.save_metadata("test.aid", metadata)

        meta_file = tmp_path / "AIDs" / "test.aid" / "tokens" / "meta.json"
        assert meta_file.exists()
        content = json.loads(meta_file.read_text(encoding="utf-8"))
        prekey_data = content["e2ee_prekeys"]["prekey-123"]
        assert "private_key_pem" not in prekey_data
        assert "private_key_protection" in prekey_data

        loaded = ks.load_metadata("test.aid")
        assert loaded["e2ee_prekeys"]["prekey-123"]["private_key_pem"] == metadata["e2ee_prekeys"]["prekey-123"]["private_key_pem"]
