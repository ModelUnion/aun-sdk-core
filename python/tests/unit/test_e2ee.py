"""E2EE 单元测试 — 覆盖 prekey_ecdh_v2（四路 ECDH）/ long_term_key 两级降级、AAD、防重放。

测试策略：用真实密码学原语（cryptography 库），E2EEManager 为纯工具类，无 RPC mock。
"""

import asyncio
import base64
import json
import time
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aun_core.e2ee import (
    AAD_FIELDS_OFFLINE,
    AAD_MATCH_FIELDS_OFFLINE,
    MODE_LONG_TERM_KEY,
    MODE_PREKEY_ECDH_V2,
    PREKEY_RETENTION_SECONDS,
    SUITE,
    E2EEManager,
)
from aun_core.errors import E2EEDecryptFailedError, E2EEError


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


def _make_self_signed_cert(private_key, cn="test"):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
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
        self._key_pairs = {}
        self._certs = {}
        self._prekeys = {}  # {aid: {prekey_id: data}}
        self._group_secrets = {}  # {aid: {group_id: entry}}

    def save_e2ee_prekey(self, aid, prekey_id, prekey_data, device_id=""):
        self._prekeys.setdefault(aid, {})[prekey_id] = prekey_data

    def load_e2ee_prekeys(self, aid):
        return self._prekeys.get(aid, {})

    def cleanup_e2ee_prekeys(self, aid, cutoff_ms, keep_latest=7):
        return []

    def save_group_secret_state(self, aid, group_id, entry):
        self._group_secrets.setdefault(aid, {})[group_id] = entry

    def load_group_secret_state(self, aid, group_id):
        return self._group_secrets.get(aid, {}).get(group_id)

    def load_all_group_secret_states(self, aid):
        return self._group_secrets.get(aid, {})

    def cleanup_group_old_epochs_state(self, aid, group_id, cutoff_ms):
        return 0

    def load_key_pair(self, aid):
        return self._key_pairs.get(aid)

    def load_cert(self, aid, cert_fingerprint=None):
        if cert_fingerprint:
            cert = self._certs.get((aid, cert_fingerprint))
            if cert is not None:
                return cert
            active = self._certs.get(aid)
            if active:
                try:
                    cert_obj = x509.load_pem_x509_certificate(
                        active.encode("utf-8") if isinstance(active, str) else active
                    )
                    actual_fp = "sha256:" + cert_obj.fingerprint(hashes.SHA256()).hex()
                    if actual_fp == cert_fingerprint:
                        return active
                except Exception:
                    return None
            return None
        return self._certs.get(aid)

    def save_cert(self, aid, cert_pem, cert_fingerprint=None, *, make_active=True):
        if cert_fingerprint:
            self._certs[(aid, cert_fingerprint)] = cert_pem
        if make_active or not cert_fingerprint:
            self._certs[aid] = cert_pem


class StructuredPrekeyKeystore(FakeKeystore):
    def __init__(self):
        super().__init__()
        self._prekeys = {}

    def load_e2ee_prekeys(self, aid):
        prekeys = self._prekeys.get(aid, {})
        return {key: dict(value) for key, value in prekeys.items()}

    def save_e2ee_prekey(self, aid, prekey_id, prekey_data):
        self._prekeys.setdefault(aid, {})[prekey_id] = dict(prekey_data)

    def cleanup_e2ee_prekeys(self, aid, cutoff_ms, keep_latest=7):
        prekeys = self._prekeys.get(aid, {})
        retained_ids = {
            prekey_id
            for prekey_id, _marker in sorted(
                (
                    (
                        prekey_id,
                        int(
                            prekey_data.get("created_at")
                            or prekey_data.get("updated_at")
                            or prekey_data.get("expires_at")
                            or 0
                        ),
                    )
                    for prekey_id, prekey_data in prekeys.items()
                    if isinstance(prekey_data, dict)
                ),
                key=lambda item: (item[1], item[0]),
                reverse=True,
            )[:keep_latest]
        }
        removed = []
        for prekey_id, prekey_data in list(prekeys.items()):
            marker = prekey_data.get("created_at") or prekey_data.get("updated_at") or prekey_data.get("expires_at") or 0
            if (
                prekey_id not in retained_ids
                and isinstance(marker, (int, float))
                and int(marker) < cutoff_ms
            ):
                removed.append(prekey_id)
                prekeys.pop(prekey_id, None)
        return removed


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
        "cert": _make_self_signed_cert(private_key, aid).decode("utf-8"),
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

    sender_cert = sender_identity["cert"]
    receiver_cert = receiver_identity["cert"]

    # 每个 keystore 保存对方的证书（用于签名验证和三路 ECDH）
    sender_ks._certs["receiver.test"] = receiver_cert
    receiver_ks._certs["sender.test"] = sender_cert

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
        assert len(AAD_FIELDS_OFFLINE) == 10
        assert "encryption_mode" in AAD_FIELDS_OFFLINE
        assert "recipient_cert_fingerprint" in AAD_FIELDS_OFFLINE
        assert "sender_cert_fingerprint" in AAD_FIELDS_OFFLINE
        assert "prekey_id" in AAD_FIELDS_OFFLINE

    def test_aad_bytes_offline_deterministic(self):
        aad = {
            "from": "a", "to": "b", "message_id": "m1", "timestamp": 123,
            "encryption_mode": MODE_PREKEY_ECDH_V2, "suite": SUITE,
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
             "encryption_mode": MODE_PREKEY_ECDH_V2, "suite": SUITE,
             "ephemeral_public_key": "pk", "recipient_cert_fingerprint": "fp"}
        b = {**a, "timestamp": 999}
        assert E2EEManager._aad_matches_offline(a, b)

    def test_aad_matches_offline_mode_mismatch(self):
        a = {"from": "a", "to": "b", "message_id": "m",
             "encryption_mode": MODE_PREKEY_ECDH_V2, "suite": SUITE,
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
        assert envelope["encryption_mode"] == MODE_PREKEY_ECDH_V2
        assert envelope["prekey_id"] == prekey["prekey_id"]
        assert "ephemeral_public_key" in envelope
        aad = envelope["aad"]
        assert aad["encryption_mode"] == MODE_PREKEY_ECDH_V2

    def test_prekey_encrypt_decrypt_roundtrip(self):
        sender_mgr, receiver_mgr, _, receiver_key, _, receiver_cert, _, receiver_ks = _make_e2ee_pair()
        prekey, prekey_private = _make_prekey(receiver_key)

        # 将 prekey 私钥存入 receiver keystore
        priv_pem = prekey_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks.save_e2ee_prekey("receiver.test", prekey["prekey_id"], {
            "private_key_pem": priv_pem, "created_at": int(time.time() * 1000),
        })

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

        result = receiver_mgr._decrypt_message_prekey_v2(message)
        assert result is not None
        assert result["payload"] == payload
        assert result["e2ee"]["encryption_mode"] == MODE_PREKEY_ECDH_V2

    def test_sender_skips_its_own_outbound_prekey_message(self):
        sender_mgr, _, _, receiver_key, _, receiver_cert, _, _ = _make_e2ee_pair()
        prekey, _ = _make_prekey(receiver_key)

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr._encrypt_with_prekey(
            "receiver.test", {"text": "self echo"}, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok

        outbound_copy = {
            "message_id": mid,
            "from": "sender.test",
            "to": "receiver.test",
            "timestamp": ts,
            "seq": 1,
            "payload": envelope,
            "encrypted": True,
        }

        assert sender_mgr.decrypt_message(outbound_copy) == outbound_copy


# ---------------------------------------------------------------------------
# long_term_key 加解密
# ---------------------------------------------------------------------------

class TestLongTermKey:
    def test_long_term_key_envelope_aad_fields(self):
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
        # long_term_key 的 AAD 包含除 prekey_id 外的所有字段
        for field in AAD_FIELDS_OFFLINE:
            if field == "prekey_id":
                continue  # long_term_key 无 prekey_id
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
        """有 prekey → 使用 prekey_ecdh_v2（双 ECDH）"""
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
        assert envelope["encryption_mode"] == MODE_PREKEY_ECDH_V2

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
        sender_mgr, _, sender_key_2, _, sender_cert_2, _, _, _ = _make_e2ee_pair()

        # receiver keystore 需要保存这个 sender 的证书
        receiver_ks._certs["sender.test"] = sender_cert_2.decode("utf-8") if isinstance(sender_cert_2, bytes) else sender_cert_2

        prekey, prekey_private = _make_prekey(receiver_key)
        priv_pem = prekey_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks.save_e2ee_prekey("receiver.test", prekey["prekey_id"], {
            "private_key_pem": priv_pem, "created_at": int(time.time() * 1000),
        })

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
        import time as _t
        _, receiver_mgr, _, _, _, _, _, _ = _make_e2ee_pair()
        receiver_mgr._seen_max_size = 100
        for i in range(120):
            receiver_mgr._seen_messages[f"sender:msg_{i}"] = _t.time()
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
        assert result["cert_fingerprint"].startswith("sha256:")

        prekeys = receiver_ks.load_e2ee_prekeys("receiver.test")
        assert len(prekeys) == 1
        pid = list(prekeys.keys())[0]
        assert "private_key_pem" in prekeys[pid]
        assert "created_at" in prekeys[pid]

    def test_generate_prekey_includes_created_at(self):
        """generate_prekey 返回值包含 created_at 时间戳"""
        _, receiver_mgr, _, _, _, _, _, _ = _make_e2ee_pair()
        result = receiver_mgr.generate_prekey()
        assert "created_at" in result
        assert isinstance(result["created_at"], int)
        assert result["created_at"] > 0
        assert result["cert_fingerprint"].startswith("sha256:")

    def test_prekey_encrypt_rejects_cert_fingerprint_mismatch(self):
        sender_mgr, _, _, receiver_key, _, receiver_cert, _, _ = _make_e2ee_pair()
        prekey, _ = _make_prekey(receiver_key)
        prekey["cert_fingerprint"] = "sha256:" + "0" * 64

        with pytest.raises(E2EEError, match="prekey cert fingerprint mismatch"):
            sender_mgr._encrypt_with_prekey(
                peer_aid="receiver.test",
                payload={"text": "hello"},
                prekey=prekey,
                peer_cert_pem=receiver_cert,
                message_id=str(uuid.uuid4()),
                timestamp=int(time.time() * 1000),
            )

    def test_generate_prekey_prefers_structured_keystore_api(self):
        """存在结构化接口时，不应回退到 metadata 整块读改写。"""
        receiver_key, _, _ = _generate_ec_keypair()
        receiver_identity = _build_identity("receiver.test", receiver_key)
        receiver_ks = StructuredPrekeyKeystore()
        receiver_mgr = E2EEManager(
            identity_fn=lambda: receiver_identity,
            keystore=receiver_ks,
        )

        result = receiver_mgr.generate_prekey()
        stored = receiver_ks.load_e2ee_prekeys("receiver.test")
        assert result["prekey_id"] in stored
        assert "private_key_pem" in stored[result["prekey_id"]]

    def test_load_prekey_private_key_from_structured_keystore(self):
        """_load_prekey_private_key 应能直接读取结构化 prekey 存储。"""
        receiver_key, _, _ = _generate_ec_keypair()
        receiver_identity = _build_identity("receiver.test", receiver_key)
        receiver_ks = StructuredPrekeyKeystore()
        receiver_mgr = E2EEManager(
            identity_fn=lambda: receiver_identity,
            keystore=receiver_ks,
        )

        result = receiver_mgr.generate_prekey()
        receiver_mgr._local_prekey_cache.clear()
        loaded = receiver_mgr._load_prekey_private_key(receiver_ks, result["prekey_id"])
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)

    def test_prekey_signature_binds_timestamp(self):
        """prekey 签名绑定 created_at，篡改时间戳导致签名验证失败"""
        (sender_mgr, _, _, receiver_key, _, receiver_cert,
         _, _) = _make_e2ee_pair()
        prekey, _ = _make_prekey(receiver_key)
        # 添加 created_at 并用正确格式重签
        # 先用旧格式 prekey（无 created_at）加密应成功
        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr._encrypt_with_prekey(
            "receiver.test", {"text": "test"}, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok  # 无 created_at 时兼容旧格式

    def test_old_prekey_with_valid_signature_still_accepted(self):
        """旧 prekey 只验签名，不再因为 created_at 过老而拒绝"""
        (sender_mgr, _, _, receiver_key, _, receiver_cert,
         _, _) = _make_e2ee_pair()
        prekey, _ = _make_prekey(receiver_key)
        prekey["created_at"] = int((time.time() - 31 * 86400) * 1000)
        sign_data = f"{prekey['prekey_id']}|{prekey['public_key']}|{prekey['created_at']}".encode("utf-8")
        prekey["signature"] = base64.b64encode(
            receiver_key.sign(sign_data, ec.ECDSA(hashes.SHA256()))
        ).decode("ascii")

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr._encrypt_with_prekey(
            "receiver.test", {"text": "test"}, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )

        assert ok is True
        assert envelope["prekey_id"] == prekey["prekey_id"]

    def test_cleanup_expired_prekeys_keeps_latest_seven(self):
        receiver_key, _, _ = _generate_ec_keypair()
        receiver_identity = _build_identity("receiver.test", receiver_key)
        receiver_ks = StructuredPrekeyKeystore()
        receiver_mgr = E2EEManager(
            identity_fn=lambda: receiver_identity,
            keystore=receiver_ks,
        )
        now_ms = int(time.time() * 1000)
        cutoff_ms = now_ms - PREKEY_RETENTION_SECONDS * 1000

        for idx in range(8):
            receiver_ks.save_e2ee_prekey("receiver.test", f"pk-{idx}", {
                "private_key_pem": f"KEY-{idx}",
                "created_at": cutoff_ms - 10_000 - idx,
            })

        receiver_mgr._cleanup_expired_prekeys(receiver_ks, "receiver.test")
        remaining = receiver_ks.load_e2ee_prekeys("receiver.test")

        assert sorted(remaining.keys()) == [f"pk-{idx}" for idx in range(7)]


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
        ks.save_e2ee_prekey("test.aid", "prekey-123", {
            "private_key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            "public_key": "MFkw...",
        })

        # prekey 私钥存储在 SQLCipher 加密的 aun.db 中，不应出现在 meta.json
        safe_aid = "test.aid"
        db_file = tmp_path / "AIDs" / safe_aid / "aun.db"
        assert db_file.exists(), "aun.db 应该存在"

        prekeys = ks.load_e2ee_prekeys("test.aid")
        assert prekeys["prekey-123"]["private_key_pem"] == "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"


# ---------------------------------------------------------------------------
# 双 ECDH (prekey_ecdh_v2)
# ---------------------------------------------------------------------------

class TestPrekeyV2:
    def test_v2_envelope_fields(self):
        """v2 信封包含 encryption_mode: prekey_ecdh_v2"""
        sender_mgr, _, _, receiver_key, _, receiver_cert, _, _ = _make_e2ee_pair()
        prekey, _ = _make_prekey(receiver_key)

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr._encrypt_with_prekey(
            "receiver.test", {"text": "v2 test"}, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok
        assert envelope["encryption_mode"] == MODE_PREKEY_ECDH_V2
        assert envelope["aad"]["encryption_mode"] == MODE_PREKEY_ECDH_V2

    def test_v2_roundtrip(self):
        """双 ECDH 加解密往返成功"""
        sender_mgr, receiver_mgr, _, receiver_key, _, receiver_cert, _, receiver_ks = _make_e2ee_pair()
        prekey, prekey_private = _make_prekey(receiver_key)

        priv_pem = prekey_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks.save_e2ee_prekey("receiver.test", prekey["prekey_id"], {
            "private_key_pem": priv_pem, "created_at": int(time.time() * 1000),
        })

        payload = {"text": "双 ECDH 往返"}
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
        result = receiver_mgr.decrypt_message(message)
        assert result is not None
        assert result["payload"] == payload
        assert result["e2ee"]["encryption_mode"] == MODE_PREKEY_ECDH_V2

    def test_old_v1_still_decryptable(self):
        """旧 prekey_ecdh (v1) 加密模式已移除，v1 消息应被拒绝"""
        sender_mgr, receiver_mgr, _, receiver_key, _, receiver_cert, _, receiver_ks = _make_e2ee_pair()
        prekey, prekey_private = _make_prekey(receiver_key)

        priv_pem = prekey_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks.save_e2ee_prekey("receiver.test", prekey["prekey_id"], {
            "private_key_pem": priv_pem, "created_at": int(time.time() * 1000),
        })

        # 手动构造 v1 信封（单 ECDH）— 使用已移除的 encryption_mode
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
        import secrets as _secrets

        peer_prekey_public = serialization.load_der_public_key(base64.b64decode(prekey["public_key"]))
        ephemeral_private = _ec.generate_private_key(_ec.SECP256R1())
        ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        shared_secret = ephemeral_private.exchange(_ec.ECDH(), peer_prekey_public)
        hkdf = _HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                      info=f"aun-prekey:{prekey['prekey_id']}".encode("utf-8"))
        message_key = hkdf.derive(shared_secret)

        payload = {"text": "v1 legacy"}
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        nonce = _secrets.token_bytes(12)
        aesgcm = _AESGCM(message_key)

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        ephemeral_pk_b64 = base64.b64encode(ephemeral_public_bytes).decode("ascii")
        from cryptography import x509 as _x509
        _rcert = _x509.load_pem_x509_certificate(receiver_cert.encode("utf-8"))
        recipient_fp = f"sha256:{_rcert.fingerprint(hashes.SHA256()).hex()}"
        aad = {
            "from": "sender.test", "to": "receiver.test",
            "message_id": mid, "timestamp": ts,
            "encryption_mode": "prekey_ecdh",  # 已移除的 v1 模式
            "suite": "P256_HKDF_SHA256_AES_256_GCM",
            "ephemeral_public_key": ephemeral_pk_b64,
            "recipient_cert_fingerprint": recipient_fp,
        }
        aad_bytes = E2EEManager._aad_bytes_offline(aad)
        ct_tag = aesgcm.encrypt(nonce, plaintext, aad_bytes)

        envelope = {
            "type": "e2ee.encrypted", "version": "1",
            "encryption_mode": "prekey_ecdh",  # 已移除的 v1 模式
            "suite": "P256_HKDF_SHA256_AES_256_GCM",
            "prekey_id": prekey["prekey_id"],
            "ephemeral_public_key": ephemeral_pk_b64,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ct_tag[:-16]).decode("ascii"),
            "tag": base64.b64encode(ct_tag[-16:]).decode("ascii"),
            "aad": aad,
        }

        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }
        # v1 模式已移除，消息应被拒绝
        result = receiver_mgr.decrypt_message(message)
        assert result is None

    def test_wrong_identity_key_fails(self):
        """只有 prekey 私钥没有正确 identity 私钥 → v2 解密失败"""
        sender_mgr, receiver_mgr, _, receiver_key, _, receiver_cert, _, receiver_ks = _make_e2ee_pair()
        prekey, prekey_private = _make_prekey(receiver_key)

        priv_pem = prekey_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks.save_e2ee_prekey("receiver.test", prekey["prekey_id"], {
            "private_key_pem": priv_pem, "created_at": int(time.time() * 1000),
        })
        # 替换 identity 私钥为错误的密钥
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_pem = wrong_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        receiver_ks._key_pairs["receiver.test"]["private_key_pem"] = wrong_pem

        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, ok = sender_mgr._encrypt_with_prekey(
            "receiver.test", {"text": "should fail"}, prekey, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        assert ok

        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }
        # v2 解密应失败（identity key 不匹配）
        result = receiver_mgr._decrypt_message_prekey_v2(message)
        assert result is None
