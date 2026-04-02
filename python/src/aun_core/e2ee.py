from __future__ import annotations

import base64
import json
import secrets
import time as _time_mod
import uuid
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import (
    E2EEDecryptFailedError,
    E2EEError,
)


SUITE = "P256_HKDF_SHA256_AES_256_GCM"

# 加密模式
MODE_PREKEY_ECDH = "prekey_ecdh"        # 优先：prekey ECDH
MODE_LONG_TERM_KEY = "long_term_key"    # 降级：长期公钥加密

# AAD 字段
AAD_FIELDS_OFFLINE = (
    "from", "to", "message_id", "timestamp",
    "encryption_mode", "suite", "ephemeral_public_key",
    "recipient_cert_fingerprint",
)
AAD_MATCH_FIELDS_OFFLINE = (
    "from", "to", "message_id",
    "encryption_mode", "suite", "ephemeral_public_key",
    "recipient_cert_fingerprint",
)

# prekey 私钥本地保留时间（秒）
PREKEY_RETENTION_SECONDS = 7 * 24 * 3600  # 7 天


class E2EEManager:
    """端到端加密工具类 — 纯密码学操作，无 I/O 依赖。

    加密策略：prekey_ecdh → long_term_key 两层降级。
    I/O（获取 prekey、证书）由调用方（AUNClient）负责。
    内置本地防重放（seen set），裸 WebSocket 开发者无需额外实现。
    """

    def __init__(
        self,
        *,
        identity_fn: Any,
        keystore: Any,
        prekey_cache_ttl: float = 3600.0,
    ) -> None:
        self._identity_fn = identity_fn
        self._keystore_ref = keystore
        # 本地防重放 seen set
        self._seen_messages: dict[str, bool] = {}
        self._seen_max_size = 5000
        # prekey 内存缓存（TTL 默认 1 小时）
        self._prekey_cache: dict[str, tuple[dict[str, Any], float]] = {}
        self._prekey_cache_ttl = prekey_cache_ttl

    # ── 便利方法 ──────────────────────────────────────────────

    def encrypt_message(
        self,
        to_aid: str,
        payload: dict[str, Any],
        *,
        peer_cert_pem: bytes,
        prekey: dict[str, Any] | None = None,
        message_id: str | None = None,
        timestamp: int | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """加密消息（便利方法）。

        调用方负责提前获取 peer_cert_pem 和 prekey（可选）。
        有 prekey 时用 prekey_ecdh，无 prekey 时降级为 long_term_key。
        """
        message_id = message_id or str(uuid.uuid4())
        timestamp = timestamp or int(_time_mod.time() * 1000)
        return self.encrypt_outbound(
            peer_aid=to_aid,
            payload=payload,
            peer_cert_pem=peer_cert_pem,
            prekey=prekey,
            message_id=message_id,
            timestamp=timestamp,
        )

    def decrypt_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """解密单条消息（便利方法，内置本地防重放）。"""
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return message
        payload_type = payload.get("type")
        if payload_type != "e2ee.encrypted":
            return message
        if message.get("encrypted") is not True and "encrypted" in message:
            return message

        # 本地防重放
        message_id = message.get("message_id", "")
        from_aid = message.get("from", "")
        if message_id and from_aid:
            seen_key = f"{from_aid}:{message_id}"
            if seen_key in self._seen_messages:
                return None  # 重放消息
            self._seen_messages[seen_key] = True
            self._trim_seen_set()

        return self._decrypt_message(message)

    def _trim_seen_set(self) -> None:
        if len(self._seen_messages) > self._seen_max_size:
            trim_count = len(self._seen_messages) - int(self._seen_max_size * 0.8)
            keys = list(self._seen_messages.keys())[:trim_count]
            for k in keys:
                del self._seen_messages[k]

    # ── Prekey 缓存 ────────────────────────────────────────────

    def cache_prekey(self, peer_aid: str, prekey: dict[str, Any]) -> None:
        """缓存对方的 prekey（调用方获取后存入，后续 encrypt 自动复用）"""
        self._prekey_cache[peer_aid] = (prekey, _time_mod.time() + self._prekey_cache_ttl)

    def get_cached_prekey(self, peer_aid: str) -> dict[str, Any] | None:
        """获取缓存的 prekey（过期返回 None）"""
        cached = self._prekey_cache.get(peer_aid)
        if cached is None:
            return None
        prekey, expire_at = cached
        if _time_mod.time() >= expire_at:
            del self._prekey_cache[peer_aid]
            return None
        return prekey

    def invalidate_prekey_cache(self, peer_aid: str) -> None:
        """使指定 peer 的 prekey 缓存失效"""
        self._prekey_cache.pop(peer_aid, None)

    # ── 加密 ─────────────────────────────────────────────────

    def encrypt_outbound(
        self,
        peer_aid: str,
        payload: dict[str, Any],
        *,
        peer_cert_pem: bytes,
        prekey: dict[str, Any] | None = None,
        message_id: str,
        timestamp: int,
    ) -> tuple[dict[str, Any], bool]:
        """加密出站消息：有 prekey → prekey_ecdh，无 prekey → long_term_key。

        prekey 传入时自动缓存；传入 None 时自动查缓存。
        """
        # 传入 prekey → 缓存；传入 None → 查缓存
        if prekey is not None:
            self.cache_prekey(peer_aid, prekey)
        else:
            prekey = self.get_cached_prekey(peer_aid)

        if prekey:
            try:
                return self._encrypt_with_prekey(
                    peer_aid, payload, prekey, peer_cert_pem,
                    message_id=message_id, timestamp=timestamp,
                )
            except Exception:
                pass

        return self._encrypt_with_long_term_key(
            peer_aid, payload, peer_cert_pem,
            message_id=message_id, timestamp=timestamp,
        )

    def _encrypt_with_prekey(
        self,
        peer_aid: str,
        payload: dict[str, Any],
        prekey: dict[str, Any],
        peer_cert_pem: bytes,
        *,
        message_id: str,
        timestamp: int,
    ) -> tuple[dict[str, Any], bool]:
        """使用对方 prekey 加密（prekey_ecdh 模式）"""
        # 验证 prekey 签名
        cert = x509.load_pem_x509_certificate(
            peer_cert_pem if isinstance(peer_cert_pem, bytes) else peer_cert_pem.encode("utf-8")
        )
        peer_identity_public = cert.public_key()

        sign_data = f"{prekey['prekey_id']}|{prekey['public_key']}".encode("utf-8")
        signature_bytes = base64.b64decode(prekey["signature"])
        try:
            peer_identity_public.verify(signature_bytes, sign_data, ec.ECDSA(hashes.SHA256()))
        except Exception as exc:
            raise E2EEError(f"prekey signature verification failed: {exc}")

        # 导入对方 prekey 公钥
        peer_prekey_public = serialization.load_der_public_key(
            base64.b64decode(prekey["public_key"])
        )

        # 生成临时 ECDH 密钥对
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # ECDH + HKDF
        shared_secret = ephemeral_private.exchange(ec.ECDH(), peer_prekey_public)
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=f"aun-prekey:{prekey['prekey_id']}".encode("utf-8"),
        )
        message_key = hkdf.derive(shared_secret)

        # AES-GCM 加密
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(message_key)

        recipient_fingerprint = self._fingerprint_cert_pem(peer_cert_pem)
        ephemeral_pk_b64 = base64.b64encode(ephemeral_public_bytes).decode("ascii")
        aad = {
            "from": self._current_aid(),
            "to": peer_aid,
            "message_id": message_id,
            "timestamp": timestamp,
            "encryption_mode": MODE_PREKEY_ECDH,
            "suite": SUITE,
            "ephemeral_public_key": ephemeral_pk_b64,
            "recipient_cert_fingerprint": recipient_fingerprint,
        }
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, self._aad_bytes_offline(aad))
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        envelope = {
            "type": "e2ee.encrypted",
            "version": "1",
            "encryption_mode": MODE_PREKEY_ECDH,
            "suite": SUITE,
            "prekey_id": prekey["prekey_id"],
            "ephemeral_public_key": ephemeral_pk_b64,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "aad": aad,
        }
        return envelope, True

    def _encrypt_with_long_term_key(
        self,
        peer_aid: str,
        payload: dict[str, Any],
        peer_cert_pem: bytes,
        *,
        message_id: str,
        timestamp: int,
    ) -> tuple[dict[str, Any], bool]:
        """使用接收方长期公钥加密（long_term_key 模式）"""
        cert = x509.load_pem_x509_certificate(
            peer_cert_pem if isinstance(peer_cert_pem, bytes) else peer_cert_pem.encode("utf-8")
        )
        peer_public_key = cert.public_key()

        if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            raise E2EEError("Peer certificate does not contain EC public key")

        session_key = secrets.token_bytes(32)
        ephemeral_public_bytes, encrypted_session_key = self._encrypt_session_key_with_public_key(
            session_key, peer_public_key
        )

        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(session_key)

        recipient_fingerprint = self._fingerprint_cert_pem(peer_cert_pem)
        ephemeral_pk_b64 = base64.b64encode(ephemeral_public_bytes).decode("ascii")
        aad = {
            "from": self._current_aid(),
            "to": peer_aid,
            "message_id": message_id,
            "timestamp": timestamp,
            "encryption_mode": MODE_LONG_TERM_KEY,
            "suite": SUITE,
            "ephemeral_public_key": ephemeral_pk_b64,
            "recipient_cert_fingerprint": recipient_fingerprint,
        }
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, self._aad_bytes_offline(aad))
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        envelope = {
            "type": "e2ee.encrypted",
            "version": "1",
            "encryption_mode": MODE_LONG_TERM_KEY,
            "suite": SUITE,
            "ephemeral_public_key": ephemeral_pk_b64,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "aad": aad,
        }
        return envelope, True

    # ── 解密 ─────────────────────────────────────────────────

    def _decrypt_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        payload = message["payload"]
        encryption_mode = payload.get("encryption_mode", MODE_PREKEY_ECDH)

        if encryption_mode == MODE_PREKEY_ECDH:
            return self._decrypt_message_prekey(message)
        elif encryption_mode == MODE_LONG_TERM_KEY:
            return self._decrypt_message_long_term(message)
        else:
            return None

    def _decrypt_message_prekey(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """解密 prekey_ecdh 模式的消息"""
        payload = message["payload"]
        try:
            ephemeral_public_bytes = base64.b64decode(payload["ephemeral_public_key"])
            prekey_id = payload.get("prekey_id", "")
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            tag = base64.b64decode(payload["tag"])

            keystore = self._keystore()
            if not keystore:
                raise E2EEError("Keystore unavailable")
            prekey_private_key = self._load_prekey_private_key(keystore, prekey_id)
            if prekey_private_key is None:
                raise E2EEError(f"prekey not found: {prekey_id}")

            # ECDH + HKDF
            ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), ephemeral_public_bytes
            )
            shared_secret = prekey_private_key.exchange(ec.ECDH(), ephemeral_public)
            hkdf = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=f"aun-prekey:{prekey_id}".encode("utf-8"),
            )
            message_key = hkdf.derive(shared_secret)

            # 验证 AAD 并解密
            aesgcm = AESGCM(message_key)
            aad = payload.get("aad")
            if isinstance(aad, dict):
                expected_aad = self._build_inbound_aad_offline(message, payload)
                if not self._aad_matches_offline(expected_aad, aad):
                    raise E2EEDecryptFailedError("aad mismatch")
                aad_bytes = self._aad_bytes_offline(aad)
            else:
                aad_bytes = b""
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad_bytes)

            decoded = json.loads(plaintext.decode("utf-8"))
            transformed = dict(message)
            transformed["payload"] = decoded
            transformed["encrypted"] = True
            transformed["e2ee"] = {
                "encryption_mode": MODE_PREKEY_ECDH,
                "suite": payload.get("suite", SUITE),
                "prekey_id": prekey_id,
            }
            return transformed
        except E2EEError:
            return None
        except Exception:
            return None

    def _decrypt_message_long_term(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """解密 long_term_key 模式的消息"""
        payload = message["payload"]
        try:
            encrypted_session_key = base64.b64decode(payload["encrypted_session_key"])
            ephemeral_public_bytes = base64.b64decode(payload["ephemeral_public_key"])
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            tag = base64.b64decode(payload["tag"])

            keystore = self._keystore()
            if not keystore:
                raise E2EEError("Keystore unavailable")
            my_aid = self._current_aid()
            key_pair = keystore.load_key_pair(my_aid)
            if not key_pair or "private_key_pem" not in key_pair:
                raise E2EEError("Private key not found")
            private_key = serialization.load_pem_private_key(
                key_pair["private_key_pem"].encode("utf-8"), password=None
            )
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise E2EEError("Private key is not EC key")

            session_key = self._decrypt_session_key_with_private_key(
                encrypted_session_key, ephemeral_public_bytes, private_key
            )

            aesgcm = AESGCM(session_key)
            aad = payload.get("aad")
            if isinstance(aad, dict):
                expected_aad = self._build_inbound_aad_offline(message, payload)
                if not self._aad_matches_offline(expected_aad, aad):
                    raise E2EEDecryptFailedError("aad mismatch")
                aad_bytes = self._aad_bytes_offline(aad)
            else:
                aad_bytes = b""
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad_bytes)

            decoded = json.loads(plaintext.decode("utf-8"))
            transformed = dict(message)
            transformed["payload"] = decoded
            transformed["encrypted"] = True
            transformed["e2ee"] = {
                "encryption_mode": MODE_LONG_TERM_KEY,
                "suite": payload["suite"],
            }
            return transformed
        except E2EEError:
            return None
        except Exception:
            return None

    # ── ECIES 会话密钥加解密（long_term_key 模式用）──────────

    @staticmethod
    def _encrypt_session_key_with_public_key(
        session_key: bytes, recipient_public_key: ec.EllipticCurvePublicKey
    ) -> tuple[bytes, bytes]:
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session_key_encryption")
        encryption_key = kdf.derive(shared_secret)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(encryption_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, session_key, None)
        ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return ephemeral_public_bytes, nonce + ciphertext_with_tag

    @staticmethod
    def _decrypt_session_key_with_private_key(
        encrypted_data: bytes, ephemeral_public_bytes: bytes,
        recipient_private_key: ec.EllipticCurvePrivateKey,
    ) -> bytes:
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_public_bytes
        )
        shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session_key_encryption")
        decryption_key = kdf.derive(shared_secret)
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]
        aesgcm = AESGCM(decryption_key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

    # ── AAD 工具 ─────────────────────────────────────────────

    @staticmethod
    def _aad_bytes_offline(aad: dict[str, Any]) -> bytes:
        return json.dumps(
            {field: aad.get(field) for field in AAD_FIELDS_OFFLINE},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _aad_matches_offline(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
        return all(expected.get(field) == actual.get(field) for field in AAD_MATCH_FIELDS_OFFLINE)

    def _build_inbound_aad_offline(self, message: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "from": message.get("from"),
            "to": message.get("to"),
            "message_id": message.get("message_id"),
            "timestamp": message.get("timestamp"),
            "encryption_mode": payload.get("encryption_mode"),
            "suite": payload.get("suite", SUITE),
            "ephemeral_public_key": payload.get("ephemeral_public_key"),
            "recipient_cert_fingerprint": self._local_cert_fingerprint(),
        }

    # ── Prekey 生成 ──────────────────────────────────────────

    def generate_prekey(self) -> dict[str, Any]:
        """生成 prekey 材料并保存私钥到本地 keystore。

        返回 dict 包含 prekey_id、public_key、signature，可直接用于 RPC 上传。
        调用方负责调 transport.call("message.e2ee.put_prekey", result) 上传。
        """
        keystore = self._keystore()
        if keystore is None:
            raise E2EEError("Keystore unavailable for prekey generation")
        aid = self._current_aid()
        if not aid:
            raise E2EEError("AID unavailable for prekey generation")

        # 生成新 prekey
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        prekey_id = str(uuid.uuid4())
        public_key_b64 = base64.b64encode(public_der).decode("ascii")
        now_ms = int(_time_mod.time() * 1000)

        # 签名：prekey_id|public_key
        sign_data = f"{prekey_id}|{public_key_b64}".encode("utf-8")
        signature = self._sign_bytes(sign_data)

        # 保存私钥到本地 keystore
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        metadata = keystore.load_metadata(aid) or {}
        local_prekeys = metadata.get("e2ee_prekeys", {})
        local_prekeys[prekey_id] = {
            "private_key_pem": private_key_pem,
            "created_at": now_ms,
        }
        metadata["e2ee_prekeys"] = local_prekeys
        keystore.save_metadata(aid, metadata)

        # 清理过期的旧 prekey 私钥
        self._cleanup_expired_prekeys(keystore, aid)

        return {
            "prekey_id": prekey_id,
            "public_key": public_key_b64,
            "signature": signature,
        }

    def _cleanup_expired_prekeys(self, keystore: Any, aid: str) -> None:
        """清理本地过期的 prekey 私钥"""
        metadata = keystore.load_metadata(aid) or {}
        local_prekeys = metadata.get("e2ee_prekeys", {})
        if not local_prekeys:
            return

        now_ms = int(_time_mod.time() * 1000)
        cutoff_ms = now_ms - PREKEY_RETENTION_SECONDS * 1000
        expired = [pid for pid, data in local_prekeys.items()
                   if data.get("created_at", 0) < cutoff_ms]
        if expired:
            for pid in expired:
                del local_prekeys[pid]
            metadata["e2ee_prekeys"] = local_prekeys
            keystore.save_metadata(aid, metadata)

    def _load_prekey_private_key(self, keystore: Any, prekey_id: str) -> ec.EllipticCurvePrivateKey | None:
        """从 keystore 加载 prekey 私钥"""
        aid = self._current_aid()
        if not aid:
            return None
        metadata = keystore.load_metadata(aid) or {}
        prekeys = metadata.get("e2ee_prekeys", {})
        prekey_data = prekeys.get(prekey_id)
        if not prekey_data:
            return None
        private_key_pem = prekey_data.get("private_key_pem")
        if not private_key_pem:
            return None

        # 尝试加密存储（向后兼容）
        key_pair = keystore.load_key_pair(aid)
        if key_pair and "private_key_pem" in key_pair:
            identity_key_hash = hashes.Hash(hashes.SHA256())
            identity_key_hash.update(key_pair["private_key_pem"].encode("utf-8"))
            encryption_password = identity_key_hash.finalize()[:32]
            try:
                pk = serialization.load_pem_private_key(
                    private_key_pem.encode("utf-8"), password=encryption_password
                )
                if isinstance(pk, ec.EllipticCurvePrivateKey):
                    return pk
            except Exception:
                pass

        try:
            pk = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            if isinstance(pk, ec.EllipticCurvePrivateKey):
                return pk
        except Exception:
            pass
        return None

    # ── 证书指纹工具 ────────────────────────────────────────

    @classmethod
    def _fingerprint_cert_pem(cls, cert_pem: bytes) -> str:
        """从 PEM 证书计算公钥指纹"""
        cert_bytes = cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode("utf-8")
        cert = x509.load_pem_x509_certificate(cert_bytes)
        return cls._fingerprint_public_key(cert.public_key())

    def _local_cert_fingerprint(self) -> str:
        return self._local_identity_fingerprint()

    def _sign_bytes(self, data: bytes) -> str:
        identity = self._identity_fn()
        private_key_pem = identity.get("private_key_pem")
        if not private_key_pem:
            raise E2EEError("identity private key unavailable")
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode("ascii")

    def _local_identity_fingerprint(self) -> str:
        identity = self._identity_fn()
        public_key_der_b64 = identity.get("public_key_der_b64")
        if isinstance(public_key_der_b64, str) and public_key_der_b64:
            return self._fingerprint_der_public_key(base64.b64decode(public_key_der_b64))
        cert_pem = identity.get("cert")
        if isinstance(cert_pem, str) and cert_pem:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            return self._fingerprint_public_key(cert.public_key())
        private_key_pem = identity.get("private_key_pem")
        if isinstance(private_key_pem, str) and private_key_pem:
            private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            return self._fingerprint_public_key(private_key.public_key())
        raise E2EEError("identity fingerprint unavailable")

    @classmethod
    def _fingerprint_public_key(cls, public_key: Any) -> str:
        der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cls._fingerprint_der_public_key(der)

    @staticmethod
    def _fingerprint_der_public_key(der: bytes) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(der)
        return f"sha256:{digest.finalize().hex()}"

    # ── 内部工具 ─────────────────────────────────────────────

    def _current_aid(self) -> str | None:
        identity = self._identity_fn()
        aid = identity.get("aid")
        return str(aid) if aid else None

    def _keystore(self) -> Any | None:
        return self._keystore_ref
