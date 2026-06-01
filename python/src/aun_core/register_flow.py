from __future__ import annotations

import asyncio
import base64
import json
import re
import ssl
import time
from typing import Any
from urllib.parse import urlparse, urlunparse

import aiohttp
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .cert_verifier import GatewayCertificateVerifier
from .crypto import CryptoProvider
from .errors import AuthError, ConnectionError, IdentityConflictError, ValidationError, map_remote_error
from .keystore.base import KeyStore


_AID_NAME_RE = re.compile(r'^[a-z0-9_][a-z0-9_-]{3,63}$')


class RegisterFlow:
    def __init__(
        self,
        keystore: KeyStore,
        crypto: CryptoProvider,
        *,
        verify_ssl: bool = False,
        root_ca_path: str | None = None,
        logger=None,
        net=None,
    ) -> None:
        self._keystore = keystore
        self._crypto = crypto
        self._verify_ssl = verify_ssl
        self._log = logger
        self._net = net
        self._certs = GatewayCertificateVerifier(
            root_ca_path=root_ca_path,
            store=keystore,
            verify_ssl=verify_ssl,
            logger=logger,
            net=net,
            module="register_flow",
        )

    def validate_aid_name(self, aid: str) -> None:
        self._validate_aid_name(aid)

    async def fetch_peer_cert(self, gateway_url: str, aid: str) -> str | None:
        return await self._download_registered_cert(gateway_url, aid)

    async def short_rpc(self, gateway_url: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._short_rpc(gateway_url, method, params)

    def generate_identity(self) -> dict[str, Any]:
        return self._crypto.generate_identity()

    def new_client_nonce(self) -> str:
        return self._crypto.new_client_nonce()

    async def verify_phase1_response(self, gateway_url: str, result: dict[str, Any], client_nonce: str) -> None:
        await self._certs.verify_phase1_response(gateway_url, result, client_nonce)

    def reload_trusted_roots(self) -> int:
        return self._certs.reload_trusted_roots()

    async def register_aid(self, gateway_url: str, aid: str) -> dict[str, Any]:
        """注册新 AID，返回含私钥字段的完整 dict，私钥由调用方（AIDStore）写入。"""
        _t_start = time.time()
        self._validate_aid_name(aid)
        self._debug("register_flow", "register_aid enter: aid=%s gateway=%s", aid, gateway_url)
        try:
            # Step 1: 本地已有 keypair → 查服务端做幂等/恢复
            existing = self._keystore.load_identity(aid)
            if existing and existing.get("private_key_pem") and existing.get("public_key_der_b64"):
                local_pub_der = base64.b64decode(existing["public_key_der_b64"])
                server_cert_pem = await self._download_registered_cert(gateway_url, aid)
                if server_cert_pem:
                    cert = x509.load_pem_x509_certificate(server_cert_pem.encode("utf-8"))
                    cert_pub_der = cert.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    if cert_pub_der != local_pub_der:
                        raise IdentityConflictError(
                            f"AID '{aid}' is registered by another party on server (public key mismatch). "
                            f"Choose a different name."
                        )
                    if not existing.get("cert"):
                        existing["cert"] = server_cert_pem
                        self._persist_identity(existing)
                    self._debug("register_flow", "register_aid exit (idempotent): elapsed=%.3fs aid=%s", time.time() - _t_start, aid)
                    return {"aid": aid, "cert": server_cert_pem, "private_key_pem": existing.get("private_key_pem", ""), "public_key_der_b64": existing.get("public_key_der_b64", ""), "curve": existing.get("curve", "P-256")}
                else:
                    created = await self._create_aid(gateway_url, existing)
                    cert_pem = created.get("cert", "")
                    if not cert_pem:
                        raise AuthError(f"register_aid: server response missing cert for {aid}")
                    existing["cert"] = cert_pem
                    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
                    cert_pub_der = cert.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    if cert_pub_der != local_pub_der:
                        raise AuthError(f"register_aid: server returned certificate with mismatched public key for {aid}")
                    self._persist_identity(existing)
                    self._debug("register_flow", "register_aid exit (recovered): elapsed=%.3fs aid=%s", time.time() - _t_start, aid)
                    return {"aid": aid, "cert": cert_pem, "private_key_pem": existing.get("private_key_pem", ""), "public_key_der_b64": existing.get("public_key_der_b64", ""), "curve": existing.get("curve", "P-256")}

            # Step 2: 检查 _pending/ 残留临时目录（崩溃恢复）
            recovered = await self._try_recover_pending_registration(gateway_url, aid)
            if recovered is not None:
                self._debug("register_flow", "register_aid recovered from pending: aid=%s", aid)
                return recovered

            # Step 3: 先查服务端确认未注册
            server_cert_pem = await self._download_registered_cert(gateway_url, aid)
            if server_cert_pem:
                raise IdentityConflictError(
                    f"AID '{aid}' is already registered on server. "
                    f"Choose a different name, or if you own the keypair use a recovery flow."
                )

            # Step 4: 创建 pending 目录 + 生成 keypair + 写入受保护私钥
            identity = self._crypto.generate_identity()
            identity["aid"] = aid
            pending_dir = self._keystore.pending_identity_dir(aid)
            self._keystore.save_pending_key_pair(pending_dir, aid, identity)

            # Step 5: RPC 注册
            try:
                created = await self._create_aid(gateway_url, identity)
            except Exception:
                self._debug("register_flow", "register_aid RPC failed; pending kept for recovery: aid=%s pending=%s", aid, pending_dir)
                raise
            cert_pem = created.get("cert", "")
            if not cert_pem:
                raise AuthError(f"register_aid: server response missing cert for {aid}")
            identity["cert"] = cert_pem

            # Step 6: 校验 cert 公钥 == 本地公钥
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            cert_pub_der = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            local_pub_der = base64.b64decode(identity["public_key_der_b64"])
            if cert_pub_der != local_pub_der:
                raise AuthError(f"register_aid: server returned certificate with mismatched public key for {aid}")

            # Step 7: 写 cert 到 pending，Step 8: 原子 promote 到正式目录
            self._keystore.save_pending_cert(pending_dir, cert_pem)
            try:
                self._keystore.promote_pending_identity(pending_dir, aid)
            except FileExistsError as exc:
                raise IdentityConflictError(
                    f"AID '{aid}' was created by another process during registration; pending dir kept for cleanup."
                ) from exc

            # Step 9: 持久化（不含私钥，私钥已随 pending promote 到正式目录）
            self._persist_identity(identity)
            self._debug("register_flow", "register_aid exit: elapsed=%.3fs aid=%s", time.time() - _t_start, aid)
            return {"aid": aid, "cert": cert_pem, "private_key_pem": identity.get("private_key_pem", ""), "public_key_der_b64": identity.get("public_key_der_b64", ""), "curve": identity.get("curve", "P-256")}
        except Exception as exc:
            self._debug("register_flow", "register_aid exit (error): elapsed=%.3fs aid=%s err=%s", time.time() - _t_start, aid, exc)
            raise

    def _persist_identity(self, identity: dict[str, Any]) -> None:
        """持久化证书；私钥由 pending promote 或 AIDStore.save_key_pair 管理。"""
        aid = str(identity.get("aid") or "")
        if not aid:
            return
        cert_pem = str(identity.get("cert") or "")
        if cert_pem:
            self._keystore.save_cert(aid, cert_pem)

    async def _try_recover_pending_registration(self, gateway_url: str, aid: str) -> dict[str, Any] | None:
        for pending_dir in self._keystore.list_pending_identity_dirs(aid):
            private_data = self._keystore.load_pending_key_pair(pending_dir, aid)
            if private_data is None:
                self._keystore.discard_pending_identity(pending_dir)
                continue

            private_key_pem = str(private_data.get("private_key_pem") or "")
            public_key_der_b64 = str(private_data.get("public_key_der_b64") or "")
            if not private_key_pem or not public_key_der_b64:
                self._keystore.discard_pending_identity(pending_dir)
                continue

            server_cert_pem = await self._download_registered_cert(gateway_url, aid)
            if not server_cert_pem:
                self._debug("register_flow", "pending dir found but server has no registration; cleaning: %s", pending_dir)
                self._keystore.discard_pending_identity(pending_dir)
                return None

            cert = x509.load_pem_x509_certificate(server_cert_pem.encode("utf-8"))
            cert_pub_der = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            local_pub_der = base64.b64decode(public_key_der_b64)
            if cert_pub_der != local_pub_der:
                self._keystore.discard_pending_identity(pending_dir)
                raise IdentityConflictError(
                    f"AID '{aid}' has been registered by another party while local pending registration was incomplete; "
                    f"local pending key discarded."
                )

            identity = {
                "aid": aid,
                "cert": server_cert_pem,
                "private_key_pem": private_key_pem,
                "public_key_der_b64": public_key_der_b64,
                "curve": private_data.get("curve", "P-256"),
            }
            self._keystore.save_pending_key_pair(pending_dir, aid, identity)
            self._keystore.save_pending_cert(pending_dir, server_cert_pem)
            try:
                self._keystore.promote_pending_identity(pending_dir, aid)
            except FileExistsError as exc:
                raise IdentityConflictError(
                    f"AID '{aid}' was created by another process during recovery; pending dir kept for cleanup."
                ) from exc
            self._persist_identity(identity)
            return identity
        return None

    async def _download_registered_cert(self, gateway_url: str, aid: str) -> str | None:
        cert_url = self._gateway_http_url(gateway_url, f"/pki/cert/{aid}")
        try:
            if self._net:
                cert_pem = await self._net.http_get_text(cert_url, timeout=5.0)
            else:
                timeout = aiohttp.ClientTimeout(total=5.0)
                ssl_param = None if self._verify_ssl else False
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(cert_url, ssl=ssl_param) as response:
                        if response.status == 404:
                            return None
                        response.raise_for_status()
                        cert_pem = await response.text()
        except Exception as exc:
            if "404" in str(exc) or "Not Found" in str(exc):
                return None
            raise AuthError(f"failed to fetch {cert_url}") from exc
        if "BEGIN CERTIFICATE" not in cert_pem:
            raise AuthError(f"invalid certificate payload from {cert_url}")
        return cert_pem

    async def _create_aid(self, gateway_url: str, identity: dict[str, Any]) -> dict[str, Any]:
        response = await self._short_rpc(gateway_url, "auth.create_aid", {
            "aid": identity["aid"],
            "public_key": identity["public_key_der_b64"],
            "curve": identity.get("curve", "P-256"),
        })
        return {"cert": response["cert"]}

    async def _short_rpc(self, gateway_url: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        _SHORT_RPC_TIMEOUT = 15.0
        _CONNECT_TIMEOUT = 10.0
        try:
            ws = await asyncio.wait_for(self._connect(gateway_url), timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            raise ConnectionError(f"gateway {gateway_url} WebSocket connect timeout ({_CONNECT_TIMEOUT}s)")
        try:
            try:
                await asyncio.wait_for(ws.recv(), timeout=_SHORT_RPC_TIMEOUT)
            except asyncio.TimeoutError:
                raise ConnectionError(f"gateway {gateway_url} handshake recv timeout ({_SHORT_RPC_TIMEOUT}s)")
            envelope = {"jsonrpc": "2.0", "id": f"pre-{method}", "method": method, "params": params}
            await ws.send(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")))
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=_SHORT_RPC_TIMEOUT)
            except asyncio.TimeoutError:
                raise ConnectionError(f"gateway {gateway_url} RPC recv timeout for {method} ({_SHORT_RPC_TIMEOUT}s)")
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

    async def _connect(self, url: str):
        kwargs: dict[str, Any] = {"open_timeout": 5, "close_timeout": 5, "ping_interval": None}
        if not self._verify_ssl and str(url).lower().startswith("wss://"):
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            kwargs["ssl"] = ssl_ctx
        return await websockets.connect(url, **kwargs)

    @staticmethod
    def _gateway_http_url(gateway_url: str, path: str) -> str:
        parsed = urlparse(gateway_url)
        scheme = "https" if parsed.scheme == "wss" else "http"
        return urlunparse((scheme, parsed.netloc, path, "", "", ""))

    @staticmethod
    def _validate_aid_name(aid: str) -> None:
        name = aid.split(".")[0] if "." in aid else aid
        if not _AID_NAME_RE.match(name):
            raise ValidationError(
                f"Invalid AID name '{name}': must be 4-64 characters, "
                f"only [a-z0-9_-], cannot start with '-'"
            )
        if name.startswith("guest"):
            raise ValidationError("AID name must not start with 'guest'")

    def _debug(self, module: str, msg: str, *args: Any) -> None:
        if self._log is not None:
            self._log.debug(module, msg, *args)
