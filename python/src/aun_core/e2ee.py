from __future__ import annotations

import base64
import json
import secrets
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import (
    E2EEBadCounterError,
    E2EEBadSignatureError,
    E2EEDecryptFailedError,
    E2EEDowngradeBlockedError,
    E2EEError,
    E2EENegotiationRejectedError,
    E2EESessionExpiredError,
    E2EESessionNotFoundError,
    E2EEUnsupportedSuiteError,
    ValidationError,
)


SUITE = "P256_HKDF_SHA256_AES_256_GCM"
AAD_FIELDS = ("from", "to", "message_id", "timestamp", "session_id", "counter")
AAD_MATCH_FIELDS = ("from", "to", "message_id", "session_id", "counter")


@dataclass
class PendingSession:
    session_id: str
    peer_aid: str
    private_key: ec.EllipticCurvePrivateKey
    public_key_b64: str
    created_at: float


@dataclass
class ActiveSession:
    session_id: str
    peer_aid: str
    key: bytes
    established_at: float
    expires_at: float
    writable: bool = True
    state: str = "active"
    send_counter: int = 0
    recv_counter: int = 0


class E2EEManager:
    def __init__(self, client: Any) -> None:
        self._client = client
        self._sessions_by_peer: dict[str, ActiveSession] = {}
        self._sessions_by_id: dict[str, ActiveSession] = {}
        self._pending: dict[str, PendingSession] = {}
        self._pending_by_peer: dict[str, str] = {}
        self._accept_waiters: dict[str, Any] = {}
        self._pull_cursor = 0
        self._cert_cache: dict[str, bytes] = {}
        self._deferred_messages: list[dict[str, Any]] = []
        self._loaded_sessions_aid: str | None = None
        self._last_error: E2EEError | None = None

    @property
    def last_error(self) -> E2EEError | None:
        return self._last_error

    async def encrypt_outbound(
        self,
        peer_aid: str,
        payload: dict[str, Any],
        *,
        message_id: str,
        timestamp: int,
    ) -> tuple[dict[str, Any], bool]:
        self._restore_sessions_if_needed()
        session = await self._ensure_session(peer_aid)
        if self._should_rekey(session):
            session = await self._rekey_session(session)
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(session.key)
        counter = session.send_counter + 1
        aad = self._build_outbound_aad(peer_aid, message_id, timestamp, session, counter)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, self._aad_bytes(aad))
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        session.send_counter = counter
        self._persist_sessions()
        envelope = {
            "type": "e2ee.encrypted",
            "version": "1",
            "suite": SUITE,
            "session_id": session.session_id,
            "counter": counter,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "aad": aad,
        }
        return envelope, True

    async def process_incoming_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self._restore_sessions_if_needed()
        business: list[dict[str, Any]] = []
        for message in messages:
            seq = int(message.get("seq") or 0)
            if seq > self._pull_cursor:
                self._pull_cursor = seq

            payload = message.get("payload")
            if not isinstance(payload, dict):
                business.append(message)
                continue

            payload_type = payload.get("type")
            if payload_type == "e2ee.negotiate":
                await self._handle_negotiate(message)
                continue
            if payload_type == "e2ee.accept":
                await self._handle_accept(message)
                continue
            if payload_type == "e2ee.reject":
                self._handle_reject(message)
                continue
            if payload_type == "e2ee.close":
                self._handle_close(message)
                continue
            if payload_type == "e2ee.encrypted" and (
                message.get("encrypted") is True or "encrypted" not in message
            ):
                decrypted = self._decrypt_message(message)
                if decrypted is not None:
                    business.append(decrypted)
                continue
            business.append(message)
        return business

    async def _ensure_session(self, peer_aid: str) -> ActiveSession:
        existing = self._sessions_by_peer.get(peer_aid)
        if existing:
            if self._is_session_expired(existing):
                self._record_error(E2EESessionExpiredError())
                await self._send_close(existing, reason="session_expired")
                self.invalidate_session(session_id=existing.session_id)
            else:
                return existing

        pending_session_id = self._pending_by_peer.get(peer_aid)
        if pending_session_id:
            waiter = self._accept_waiters.get(pending_session_id)
            if waiter is not None:
                await self._wait_for_accept(peer_aid, pending_session_id, waiter)
                session = self._sessions_by_peer.get(peer_aid)
                if session and not self._is_session_expired(session):
                    return session
            self._pending_by_peer.pop(peer_aid, None)

        now = self._loop_time()

        session_id = str(uuid.uuid4())
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        public_der = ephemeral.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_b64 = base64.b64encode(public_der).decode("ascii")
        nonce = secrets.token_bytes(16)

        pending = PendingSession(
            session_id=session_id,
            peer_aid=peer_aid,
            private_key=ephemeral,
            public_key_b64=public_key_b64,
            created_at=now,
        )
        self._pending[session_id] = pending
        self._pending_by_peer[peer_aid] = session_id

        canonical = self._canonical_handshake({
            "type": "e2ee.negotiate",
            "version": "1",
            "session_id": session_id,
            "supported_suites": [SUITE],
            "ephemeral_public_key": public_key_b64,
            "identity_key_fingerprint": self._local_identity_fingerprint(),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        })
        signature = self._sign_bytes(canonical)
        waiter = self._client._loop.create_future()
        self._accept_waiters[session_id] = waiter

        await self._client.call("message.send", {
            "to": peer_aid,
            "persist": True,
            "payload": {
                "type": "e2ee.negotiate",
                "version": "1",
                "session_id": session_id,
                "supported_suites": [SUITE],
                "ephemeral_public_key": public_key_b64,
                "identity_key_fingerprint": self._local_identity_fingerprint(),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "signature": signature,
            },
        })

        await self._wait_for_accept(peer_aid, session_id, waiter)
        session = self._sessions_by_peer.get(peer_aid)
        if not session:
            raise E2EEError(f"failed to establish e2ee session with {peer_aid}")
        return session

    async def _wait_for_accept(self, peer_aid: str, session_id: str, waiter: Any) -> None:
        deadline = self._client._loop.time() + 10.0
        try:
            while not waiter.done():
                if self._client._loop.time() >= deadline:
                    raise E2EEError(f"timeout waiting e2ee.accept from {peer_aid}")
                result = await self._client.call("message.pull", {"after_seq": self._pull_cursor, "limit": 20})
                raw_messages = result.get("messages", []) if isinstance(result, dict) else []
                business = await self.process_incoming_messages(raw_messages)
                if business:
                    self._queue_deferred_messages(business)
                if waiter.done():
                    break
            await waiter
        except Exception:
            self._discard_pending(session_id)
            raise

    async def _handle_negotiate(self, message: dict[str, Any]) -> None:
        self._restore_sessions_if_needed()
        payload = message["payload"]
        from_aid = message["from"]
        session_id = str(payload["session_id"])
        if session_id in self._sessions_by_id:
            return
        previous = self._sessions_by_peer.get(from_aid)
        if previous is not None and previous.state == "rekeying":
            await self._send_reject(from_aid, session_id, "busy_rekeying")
            return
        supported = payload.get("supported_suites") or []
        if SUITE not in supported:
            await self._send_reject(from_aid, session_id, "no_common_suite", supported_suites=[SUITE])
            return

        await self.ensure_peer_cert(from_aid)
        self._verify_peer_signature(
            from_aid,
            {
                "type": "e2ee.negotiate",
                "version": payload["version"],
                "session_id": session_id,
                "supported_suites": supported,
                "ephemeral_public_key": payload["ephemeral_public_key"],
                "identity_key_fingerprint": payload["identity_key_fingerprint"],
                "nonce": payload["nonce"],
            },
            payload["signature"],
        )

        peer_public = serialization.load_der_public_key(base64.b64decode(payload["ephemeral_public_key"]))
        our_private = ec.generate_private_key(ec.SECP256R1())
        our_public_der = our_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        shared = our_private.exchange(ec.ECDH(), peer_public)
        key = self._derive_key(shared, session_id)
        now = self._loop_time()
        previous = self._sessions_by_peer.get(from_aid)
        if previous is not None:
            previous.writable = False
            previous.state = "rekeying"
        active = ActiveSession(
            session_id=session_id,
            peer_aid=from_aid,
            key=key,
            established_at=now,
            expires_at=now + self._session_ttl_seconds(),
        )
        self._sessions_by_peer[from_aid] = active
        self._sessions_by_id[session_id] = active
        self._persist_sessions()

        nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        accept_doc = {
            "type": "e2ee.accept",
            "version": "1",
            "session_id": session_id,
            "selected_suite": SUITE,
            "ephemeral_public_key": base64.b64encode(our_public_der).decode("ascii"),
            "identity_key_fingerprint": self._local_identity_fingerprint(),
            "nonce": nonce,
        }
        signature = self._sign_bytes(self._canonical_handshake(accept_doc))

        await self._client.call("message.send", {
            "to": from_aid,
            "persist": True,
            "payload": {
                **accept_doc,
                "signature": signature,
            },
        })

    async def _handle_accept(self, message: dict[str, Any]) -> None:
        self._restore_sessions_if_needed()
        payload = message["payload"]
        from_aid = message["from"]
        session_id = str(payload["session_id"])
        if session_id in self._sessions_by_id and session_id not in self._pending:
            return
        pending = self._pending.pop(session_id, None)
        if pending is None:
            return
        self._pending_by_peer.pop(pending.peer_aid, None)

        await self.ensure_peer_cert(from_aid)
        self._verify_peer_signature(
            from_aid,
            {
                "type": "e2ee.accept",
                "version": payload["version"],
                "session_id": session_id,
                "selected_suite": payload["selected_suite"],
                "ephemeral_public_key": payload["ephemeral_public_key"],
                "identity_key_fingerprint": payload["identity_key_fingerprint"],
                "nonce": payload["nonce"],
            },
            payload["signature"],
        )

        peer_public = serialization.load_der_public_key(base64.b64decode(payload["ephemeral_public_key"]))
        shared = pending.private_key.exchange(ec.ECDH(), peer_public)
        key = self._derive_key(shared, session_id)
        now = self._loop_time()
        previous = self._sessions_by_peer.get(from_aid)
        if previous is not None:
            previous.writable = False
            previous.state = "rekeying"
        active = ActiveSession(
            session_id=session_id,
            peer_aid=from_aid,
            key=key,
            established_at=now,
            expires_at=now + self._session_ttl_seconds(),
            writable=True,
            state="active",
        )
        self._sessions_by_peer[from_aid] = active
        self._sessions_by_id[session_id] = active
        self._persist_sessions()
        waiter = self._accept_waiters.pop(session_id, None)
        if waiter is not None and not waiter.done():
            waiter.set_result(True)

    def _handle_reject(self, message: dict[str, Any]) -> None:
        payload = message["payload"]
        session_id = str(payload.get("session_id") or "")
        if not session_id:
            return
        reason = str(payload.get("reason") or "rejected")
        error = E2EENegotiationRejectedError(
            f"e2ee negotiation rejected: {reason}",
            reject_reason=reason,
        )
        self._record_error(error)
        pending = self._pending.pop(session_id, None)
        if pending is not None:
            self._pending_by_peer.pop(pending.peer_aid, None)
        waiter = self._accept_waiters.pop(session_id, None)
        if waiter is not None and not waiter.done():
            waiter.set_exception(error)

    def _handle_close(self, message: dict[str, Any]) -> None:
        payload = message["payload"]
        session_id = str(payload.get("session_id") or "")
        if not session_id:
            return
        reason = str(payload.get("reason") or "normal")
        session = self._sessions_by_id.get(session_id)
        if reason == "rekey" and session is not None:
            session.writable = False
            session.state = "closed"
            current = self._sessions_by_peer.get(session.peer_aid)
            if current is not None and current.session_id == session_id:
                self._sessions_by_peer.pop(session.peer_aid, None)
            self._persist_sessions()
            return
        self.invalidate_session(session_id=session_id)

    def _decrypt_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        payload = message["payload"]
        session_id = str(payload["session_id"])
        session = self._sessions_by_id.get(session_id)
        if not session:
            self._record_error(E2EESessionNotFoundError())
            return None

        try:
            if self._is_session_expired(session):
                error = E2EESessionExpiredError()
                self._record_error(error)
                self._close_session_now(session, error.close_reason or "session_expired")
                return None
            counter = int(payload["counter"])
            if counter <= session.recv_counter:
                raise E2EEBadCounterError()
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            tag = base64.b64decode(payload["tag"])
            aesgcm = AESGCM(session.key)
            aad = payload.get("aad")
            if isinstance(aad, dict):
                expected_aad = self._build_inbound_aad(message, session_id, counter)
                if not self._aad_matches(expected_aad, aad):
                    raise E2EEDecryptFailedError("aad mismatch")
                aad_bytes = self._aad_bytes(aad)
            else:
                if not self._allow_legacy_envelope():
                    raise E2EEDowngradeBlockedError()
                aad_bytes = self._legacy_aad(session, counter)
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad_bytes)
            session.recv_counter = counter
            self._persist_sessions()

            decoded = json.loads(plaintext.decode("utf-8"))
            transformed = dict(message)
            transformed["payload"] = decoded
            transformed["encrypted"] = True
            transformed["e2ee"] = {
                "session_id": session_id,
                "suite": payload["suite"],
                "counter": counter,
            }
            return transformed
        except E2EEError as exc:
            self._record_error(exc)
            self._close_session_now(session, exc.close_reason or "normal")
            return None
        except Exception as exc:
            error = E2EEDecryptFailedError(str(exc))
            self._record_error(error)
            self._close_session_now(session, error.close_reason or "decrypt_failed")
            return None

    async def _rekey_session(self, session: ActiveSession) -> ActiveSession:
        session.writable = False
        session.state = "rekeying"
        current = self._sessions_by_peer.get(session.peer_aid)
        if current is not None and current.session_id == session.session_id:
            self._sessions_by_peer.pop(session.peer_aid, None)
        self._persist_sessions()
        new_session = await self._ensure_session(session.peer_aid)
        await self._send_close(session, reason="rekey")
        session.state = "closed"
        self._persist_sessions()
        return new_session

    def _build_outbound_aad(
        self,
        peer_aid: str,
        message_id: str,
        timestamp: int,
        session: ActiveSession,
        counter: int,
    ) -> dict[str, Any]:
        sender_aid = self._current_aid()
        if not sender_aid:
            raise E2EEError("local aid unavailable for e2ee aad")
        return {
            "from": sender_aid,
            "to": peer_aid,
            "message_id": message_id,
            "timestamp": timestamp,
            "session_id": session.session_id,
            "counter": counter,
        }

    def _build_inbound_aad(self, message: dict[str, Any], session_id: str, counter: int) -> dict[str, Any]:
        return {
            "from": message.get("from"),
            "to": message.get("to"),
            "message_id": message.get("message_id"),
            "timestamp": message.get("timestamp"),
            "session_id": session_id,
            "counter": counter,
        }

    @staticmethod
    def _aad_matches(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
        # The current gateway persists its own top-level timestamp for delivered
        # messages, so strict outer-envelope timestamp equality would break
        # decryption on real message.pull/history responses. Keep authenticating
        # the sender-provided timestamp inside AEAD AAD, but only require the
        # stable routing/identity fields to match the outer envelope.
        return all(expected.get(field) == actual.get(field) for field in AAD_MATCH_FIELDS)

    @staticmethod
    def _aad_bytes(aad: dict[str, Any]) -> bytes:
        return json.dumps(
            {field: aad[field] for field in AAD_FIELDS},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _legacy_aad(session: ActiveSession, counter: int) -> bytes:
        return f"{session.session_id}:{counter}".encode("utf-8")

    def _sign_bytes(self, data: bytes) -> str:
        identity = self._client._identity or {}
        private_key_pem = identity.get("private_key_pem")
        if not private_key_pem:
            raise E2EEError("identity private key unavailable")
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode("ascii")

    def _verify_peer_signature(self, aid: str, document: dict[str, Any], signature_b64: str) -> None:
        cert_pem = self._cert_cache.get(aid)
        if cert_pem is None:
            raise E2EEError(f"peer certificate not cached for {aid}")
        cert = x509.load_pem_x509_certificate(cert_pem)
        expected_fingerprint = document.get("identity_key_fingerprint")
        actual_fingerprint = self._fingerprint_public_key(cert.public_key())
        if expected_fingerprint != actual_fingerprint:
            raise E2EEBadSignatureError("identity fingerprint mismatch")
        public_key = cert.public_key()
        try:
            public_key.verify(
                base64.b64decode(signature_b64),
                self._canonical_handshake(document),
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception as exc:
            raise E2EEBadSignatureError(str(exc)) from exc

    async def ensure_peer_cert(self, aid: str) -> None:
        if aid in self._cert_cache:
            return
        gateway_url = self._client._gateway_url
        if not gateway_url:
            raise ValidationError("gateway url unavailable for e2ee cert fetch")
        cert_url = self._build_cert_url(gateway_url, aid)
        async with aiohttp.ClientSession() as session:
            async with session.get(cert_url) as response:
                response.raise_for_status()
                cert_pem = await response.text()
        self._cert_cache[aid] = cert_pem.encode("utf-8")

    async def preload_peer(self, aid: str) -> None:
        await self.ensure_peer_cert(aid)

    def drain_deferred_messages(self) -> list[dict[str, Any]]:
        messages = list(self._deferred_messages)
        self._deferred_messages.clear()
        return messages

    def _queue_deferred_messages(self, messages: list[dict[str, Any]]) -> None:
        self._deferred_messages.extend(messages)
        self._deferred_messages.sort(key=lambda item: int(item.get("seq") or 0))

    def invalidate_session(self, *, peer_aid: str | None = None, session_id: str | None = None) -> None:
        self._restore_sessions_if_needed()
        active = None
        if session_id:
            active = self._sessions_by_id.pop(session_id, None)
            if active is not None:
                current = self._sessions_by_peer.get(active.peer_aid)
                if current is not None and current.session_id == session_id:
                    self._sessions_by_peer.pop(active.peer_aid, None)
            self._discard_pending(session_id)
        if peer_aid:
            active = self._sessions_by_peer.pop(peer_aid, None)
            if active is not None:
                self._sessions_by_id.pop(active.session_id, None)
                self._remove_read_only_sessions(active.peer_aid)
            pending_session_id = self._pending_by_peer.pop(peer_aid, None)
            if pending_session_id is not None:
                self._discard_pending(pending_session_id)
        self._persist_sessions()

    def _discard_pending(self, session_id: str) -> None:
        pending = self._pending.pop(session_id, None)
        if pending is not None:
            pending_peer_aid = getattr(pending, "peer_aid", None)
            if pending_peer_aid:
                mapped = self._pending_by_peer.get(pending_peer_aid)
                if mapped == session_id:
                    self._pending_by_peer.pop(pending_peer_aid, None)
        waiter = self._accept_waiters.pop(session_id, None)
        if waiter is not None and not waiter.done():
            waiter.cancel()

    def _is_session_expired(self, session: ActiveSession) -> bool:
        return self._loop_time() >= session.expires_at

    def _should_rekey(self, session: ActiveSession) -> bool:
        if not session.writable:
            return False
        return session.expires_at - self._loop_time() <= self._session_rekey_before_seconds()

    def _session_ttl_seconds(self) -> float:
        config_model = getattr(self._client, "_config_model", None)
        extra = getattr(config_model, "extra", {}) if config_model is not None else {}
        raw_config = getattr(self._client, "config", {}) or {}
        ttl = extra.get("e2ee_session_ttl", raw_config.get("e2ee_session_ttl", 86400.0))
        return max(float(ttl), 1.0)

    def _session_rekey_before_seconds(self) -> float:
        config_model = getattr(self._client, "_config_model", None)
        extra = getattr(config_model, "extra", {}) if config_model is not None else {}
        raw_config = getattr(self._client, "config", {}) or {}
        lead = extra.get("e2ee_rekey_before", raw_config.get("e2ee_rekey_before", 300.0))
        ttl = self._session_ttl_seconds()
        return max(min(float(lead), max(ttl - 1.0, 0.0)), 0.0)

    def _allow_legacy_envelope(self) -> bool:
        config_model = getattr(self._client, "_config_model", None)
        extra = getattr(config_model, "extra", {}) if config_model is not None else {}
        raw_config = getattr(self._client, "config", {}) or {}
        return bool(extra.get("e2ee_allow_legacy_envelope", raw_config.get("e2ee_allow_legacy_envelope", False)))

    def _loop_time(self) -> float:
        loop = getattr(self._client, "_loop", None)
        if loop is None:
            raise E2EEError("event loop unavailable for e2ee manager")
        return float(loop.time())

    def _restore_sessions_if_needed(self) -> None:
        aid = self._current_aid()
        if not aid:
            return
        if self._loaded_sessions_aid == aid:
            return
        self._loaded_sessions_aid = aid
        keystore = self._keystore()
        if keystore is None:
            return
        metadata = keystore.load_metadata(aid) or {}
        stored_sessions = metadata.get("e2ee_sessions")
        if not isinstance(stored_sessions, list):
            return

        cleanup_required = False
        for raw in stored_sessions:
            if not isinstance(raw, dict):
                cleanup_required = True
                continue
            try:
                session_id = str(raw["session_id"])
                peer_aid = str(raw["peer_aid"])
                key = base64.b64decode(raw["key"])
                established_at = float(raw["established_at"])
                expires_at = float(raw["expires_at"])
                send_counter = int(raw.get("send_counter", 0))
                recv_counter = int(raw.get("recv_counter", 0))
            except Exception:
                if "key" in raw and isinstance(raw.get("key"), str):
                    cleanup_required = True
                continue
            session = ActiveSession(
                session_id=session_id,
                peer_aid=peer_aid,
                key=key,
                established_at=established_at,
                expires_at=expires_at,
                writable=bool(raw.get("writable", True)),
                state=str(raw.get("state") or "active"),
                send_counter=send_counter,
                recv_counter=recv_counter,
            )
            if self._is_session_expired(session):
                cleanup_required = True
                continue
            self._sessions_by_id[session_id] = session
            if session.writable:
                self._sessions_by_peer[peer_aid] = session
        if cleanup_required:
            self._persist_sessions()

    def _persist_sessions(self) -> None:
        aid = self._current_aid()
        if not aid:
            return
        keystore = self._keystore()
        if keystore is None:
            return
        metadata = keystore.load_metadata(aid) or {}
        serialized_sessions = []
        expired_session_ids: list[str] = []
        for session in list(self._sessions_by_id.values()):
            if self._is_session_expired(session):
                expired_session_ids.append(session.session_id)
                continue
            serialized_sessions.append({
                "session_id": session.session_id,
                "peer_aid": session.peer_aid,
                "key": base64.b64encode(session.key).decode("ascii"),
                "established_at": session.established_at,
                "expires_at": session.expires_at,
                "writable": session.writable,
                "state": session.state,
                "send_counter": session.send_counter,
                "recv_counter": session.recv_counter,
            })
        for expired_session_id in expired_session_ids:
            self._remove_active_session(expired_session_id)
        if serialized_sessions:
            metadata["e2ee_sessions"] = serialized_sessions
        else:
            metadata.pop("e2ee_sessions", None)
        keystore.save_metadata(aid, metadata)

    def _remove_active_session(self, session_id: str) -> None:
        active = self._sessions_by_id.pop(session_id, None)
        if active is None:
            return
        current = self._sessions_by_peer.get(active.peer_aid)
        if current is not None and current.session_id == session_id:
            self._sessions_by_peer.pop(active.peer_aid, None)

    def _remove_read_only_sessions(self, peer_aid: str) -> None:
        stale_ids = [
            session_id
            for session_id, session in self._sessions_by_id.items()
            if session.peer_aid == peer_aid and not session.writable
        ]
        for stale_id in stale_ids:
            self._remove_active_session(stale_id)

    def _current_aid(self) -> str | None:
        identity = getattr(self._client, "_identity", None) or {}
        aid = identity.get("aid") or getattr(self._client, "_aid", None)
        return str(aid) if aid else None

    def _keystore(self) -> Any | None:
        auth = getattr(self._client, "_auth", None)
        return getattr(auth, "_keystore", None)

    async def _send_close(self, session: ActiveSession, *, reason: str) -> None:
        try:
            await self._client.call("message.send", {
                "to": session.peer_aid,
                "persist": True,
                "payload": {
                    "type": "e2ee.close",
                    "version": "1",
                    "session_id": session.session_id,
                    "reason": reason,
                },
            })
        except Exception:
            return

    async def _send_reject(
        self,
        peer_aid: str,
        session_id: str,
        reason: str,
        *,
        supported_suites: list[str] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "type": "e2ee.reject",
            "version": "1",
            "session_id": session_id,
            "reason": reason,
        }
        if supported_suites is not None:
            payload["supported_suites"] = supported_suites
        try:
            await self._client.call("message.send", {
                "to": peer_aid,
                "persist": True,
                "payload": payload,
            })
        except Exception:
            return

    def _close_session_now(self, session: ActiveSession, reason: str) -> None:
        loop = getattr(self._client, "_loop", None)
        is_running = getattr(loop, "is_running", lambda: False)
        if loop is not None and is_running():
            loop.create_task(self._send_close(session, reason=reason))
        self.invalidate_session(session_id=session.session_id)

    def _record_error(self, error: E2EEError) -> None:
        self._last_error = error

    def _local_identity_fingerprint(self) -> str:
        identity = getattr(self._client, "_identity", None) or {}
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

    @staticmethod
    def _derive_key(shared_secret: bytes, session_id: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"aun-e2ee:{session_id}".encode("utf-8"),
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def _canonical_handshake(document: dict[str, Any]) -> bytes:
        return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _build_cert_url(gateway_url: str, aid: str) -> str:
        parsed = urlparse(gateway_url)
        scheme = "https" if parsed.scheme == "wss" else "http"
        netloc = parsed.netloc
        path = f"/pki/cert/{quote(aid, safe='')}"
        return urlunparse((scheme, netloc, path, "", "", ""))
