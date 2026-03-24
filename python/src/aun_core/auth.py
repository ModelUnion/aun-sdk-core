from __future__ import annotations

import json
import secrets
import time
from typing import Any

import websockets

from .crypto import CryptoProvider
from .errors import AuthError, StateError, ValidationError, map_remote_error
from .keystore.file import FileKeyStore


class AuthFlow:
    def __init__(
        self,
        *,
        keystore: FileKeyStore,
        crypto: CryptoProvider,
        aid: str | None = None,
        connection_factory=None,
    ) -> None:
        self._keystore = keystore
        self._crypto = crypto
        self._aid = aid
        self._connection_factory = connection_factory or self._default_connection_factory

    def load_identity(self, aid: str | None = None) -> dict[str, Any]:
        identity = self._load_identity_or_raise(aid)
        cert = self._keystore.load_cert(identity["aid"])
        if cert:
            identity["cert"] = cert
        metadata = self._keystore.load_metadata(identity["aid"]) or {}
        identity.update(metadata)
        return identity

    def load_identity_or_none(self, aid: str | None = None) -> dict[str, Any] | None:
        try:
            return self.load_identity(aid)
        except StateError:
            return None

    def get_access_token_expiry(self, identity: dict[str, Any]) -> float | None:
        expires_at = identity.get("access_token_expires_at")
        if isinstance(expires_at, (int, float)):
            return float(expires_at)
        return None

    async def create_aid(self, gateway_url: str, aid: str) -> dict[str, Any]:
        identity = self._ensure_local_identity(aid)
        if identity.get("cert"):
            return {"aid": identity["aid"], "cert": identity["cert"]}
        created = await self._create_aid(gateway_url, identity)
        identity.update(created)
        self._keystore.save_identity(identity["aid"], identity)
        self._aid = identity["aid"]
        return {"aid": identity["aid"], "cert": identity["cert"]}

    async def authenticate(self, gateway_url: str, *, aid: str | None = None) -> dict[str, Any]:
        identity = self._load_identity_or_raise(aid)
        if not identity.get("cert"):
            raise StateError("missing local certificate, call auth.create_aid() first")
        login = await self._login(gateway_url, identity)
        self._remember_tokens(identity, login)
        self._keystore.save_identity(identity["aid"], identity)
        self._aid = identity["aid"]
        return {
            "aid": identity["aid"],
            "access_token": identity.get("access_token"),
            "refresh_token": identity.get("refresh_token"),
            "expires_at": identity.get("access_token_expires_at"),
            "gateway": gateway_url,
        }

    async def ensure_authenticated(self, gateway_url: str) -> dict[str, Any]:
        identity = self._ensure_identity()
        if not identity.get("cert"):
            created = await self._create_aid(gateway_url, identity)
            identity.update(created)
            self._keystore.save_identity(identity["aid"], identity)

        login = await self._login(gateway_url, identity)
        self._remember_tokens(identity, login)
        self._keystore.save_identity(identity["aid"], identity)

        token = identity.get("access_token") or identity.get("token") or identity.get("kite_token")
        if not token:
            raise AuthError("login2 did not return access token")
        return {"token": token, "identity": identity}

    async def refresh_cached_tokens(self, gateway_url: str, identity: dict[str, Any]) -> dict[str, Any]:
        refresh_token = str(identity.get("refresh_token") or "")
        if not refresh_token:
            raise AuthError("missing refresh_token")
        refreshed = await self._refresh_access_token(gateway_url, refresh_token)
        self._remember_tokens(identity, refreshed)
        self._keystore.save_identity(identity["aid"], identity)
        return identity

    async def initialize_with_token(
        self,
        transport,
        challenge: dict[str, Any] | None,
        access_token: str,
    ) -> None:
        nonce = challenge.get("params", {}).get("nonce", "")
        if not nonce:
            raise AuthError("gateway challenge missing nonce")
        await self._initialize_session(transport, nonce, access_token)

    async def connect_session(
        self,
        transport,
        challenge: dict[str, Any] | None,
        gateway_url: str,
        *,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        nonce = challenge.get("params", {}).get("nonce", "")
        if not nonce:
            raise AuthError("gateway challenge missing nonce")

        try:
            identity = self.load_identity()
        except StateError:
            identity = None

        explicit_token = str(access_token or "")
        if explicit_token and identity is not None:
            try:
                await self._initialize_session(transport, nonce, explicit_token)
                identity["access_token"] = explicit_token
                self._keystore.save_identity(identity["aid"], identity)
                return {"token": explicit_token, "identity": identity}
            except AuthError:
                pass

        if identity is None:
            auth_context = await self.ensure_authenticated(gateway_url)
            token = auth_context["token"]
            await self._initialize_session(transport, nonce, token)
            return auth_context

        cached_token = self._get_cached_access_token(identity)
        if cached_token:
            try:
                await self._initialize_session(transport, nonce, cached_token)
                return {"token": cached_token, "identity": identity}
            except AuthError:
                pass

        refresh_token = str(identity.get("refresh_token") or "")
        if refresh_token:
            try:
                identity = await self.refresh_cached_tokens(gateway_url, identity)
                cached_token = self._get_cached_access_token(identity)
                if cached_token:
                    await self._initialize_session(transport, nonce, cached_token)
                    return {"token": cached_token, "identity": identity}
            except AuthError:
                pass

        login = await self.authenticate(gateway_url, aid=identity.get("aid"))
        token = str(login.get("access_token") or "")
        if not token:
            raise AuthError("authenticate did not return access_token")
        await self._initialize_session(transport, nonce, token)
        identity = self.load_identity(identity.get("aid"))
        return {"token": token, "identity": identity}

    async def _initialize_session(self, transport, nonce: str, token: str) -> None:
        # The SDK lifecycle concept is "initialize(token)"; the gateway currently
        # serves it through its internal auth.connect entrypoint.
        result = await transport.call("auth.connect", {
            "nonce": nonce,
            "auth": {"method": "kite_token", "token": token},
            "protocol": {"min": "1.0", "max": "1.0"},
        })
        status = (result or {}).get("status")
        if status != "ok":
            raise AuthError(f"initialize failed: {result}")

    async def _create_aid(self, gateway_url: str, identity: dict[str, Any]) -> dict[str, Any]:
        response = await self._short_rpc(gateway_url, "auth.create_aid", {
            "aid": identity["aid"],
            "public_key": identity["public_key_der_b64"],
            "curve": identity.get("curve", "P-256"),
        })
        return {"cert": response["cert"]}

    async def _login(self, gateway_url: str, identity: dict[str, Any]) -> dict[str, Any]:
        phase1 = await self._short_rpc(gateway_url, "auth.aid_login1", {
            "aid": identity["aid"],
            "cert": identity["cert"],
            "client_nonce": self._crypto.new_client_nonce(),
        })
        signature, client_time = self._crypto.sign_login_nonce(identity["private_key_pem"], phase1["nonce"])
        phase2 = await self._short_rpc(gateway_url, "auth.aid_login2", {
            "aid": identity["aid"],
            "request_id": phase1["request_id"],
            "nonce": phase1["nonce"],
            "client_time": client_time,
            "signature": signature,
        })
        return phase2

    async def _refresh_access_token(self, gateway_url: str, refresh_token: str) -> dict[str, Any]:
        result = await self._short_rpc(gateway_url, "auth.refresh_token", {
            "refresh_token": refresh_token,
        })
        if not result.get("success"):
            raise AuthError(str(result.get("error", "refresh failed")))
        return result

    async def _short_rpc(self, gateway_url: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        ws = await self._connection_factory(gateway_url)
        try:
            await ws.recv()
            await ws.send(json.dumps({
                "jsonrpc": "2.0",
                "id": f"pre-{method}",
                "method": method,
                "params": params,
            }))
            raw = await ws.recv()
            message = raw if isinstance(raw, dict) else json.loads(raw)
        finally:
            await ws.close()

        if "error" in message:
            raise map_remote_error(message["error"])
        result = message.get("result")
        if not isinstance(result, dict):
            raise ValidationError(f"invalid pre-auth response for {method}")
        if result.get("success") is False:
            raise AuthError(str(result.get("error", f"{method} failed")))
        return result

    @staticmethod
    def _remember_tokens(identity: dict[str, Any], auth_result: dict[str, Any]) -> None:
        access_token = auth_result.get("access_token") or auth_result.get("token") or auth_result.get("kite_token")
        refresh_token = auth_result.get("refresh_token")
        expires_in = auth_result.get("expires_in")

        if access_token:
            identity["access_token"] = access_token
        if refresh_token:
            identity["refresh_token"] = refresh_token
        if auth_result.get("token"):
            identity["kite_token"] = auth_result["token"]
        if isinstance(expires_in, (int, float)):
            identity["access_token_expires_at"] = int(time.time() + float(expires_in))

    @staticmethod
    def _get_cached_access_token(identity: dict[str, Any]) -> str:
        access_token = str(identity.get("access_token") or "")
        if not access_token:
            return ""
        expires_at = identity.get("access_token_expires_at")
        if isinstance(expires_at, (int, float)) and float(expires_at) <= time.time() + 30:
            return ""
        return access_token

    def _ensure_local_identity(self, aid: str) -> dict[str, Any]:
        existing = self._keystore.load_identity(aid)
        if existing:
            self._aid = aid
            return existing
        identity = self._crypto.generate_identity()
        identity["aid"] = aid
        self._keystore.save_identity(aid, identity)  # 立即持久化 keypair，避免服务端拒绝后丢失
        self._aid = aid
        return identity

    def _load_identity_or_raise(self, aid: str | None = None) -> dict[str, Any]:
        requested_aid = aid or self._aid
        if requested_aid:
            existing = self._keystore.load_identity(requested_aid)
            if existing is None:
                raise StateError(f"identity not found for aid: {requested_aid}")
            self._aid = requested_aid
            return existing

        load_any_identity = getattr(self._keystore, "load_any_identity", None)
        if callable(load_any_identity):
            existing = load_any_identity()
            if existing is not None:
                loaded_aid = existing.get("aid")
                if isinstance(loaded_aid, str) and loaded_aid:
                    self._aid = loaded_aid
                return existing

        raise StateError("no local identity found, call auth.create_aid() first")

    def _ensure_identity(self) -> dict[str, Any]:
        try:
            return self._load_identity_or_raise()
        except StateError:
            if not self._aid:
                raise StateError("no local identity found, call auth.create_aid() first")
            identity = self._crypto.generate_identity()
            identity["aid"] = self._aid
            return identity

    async def _default_connection_factory(self, url: str):
        return await websockets.connect(url, open_timeout=5, close_timeout=5, ping_interval=None)
