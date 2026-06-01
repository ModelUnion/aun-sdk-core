from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import aiohttp
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization

from ._cert_utils import cert_common_name, verify_signature
from .errors import AuthError


class GatewayCertificateVerifier:
    def __init__(
        self,
        *,
        root_ca_path: str | None = None,
        store: Any = None,
        verify_ssl: bool = False,
        logger: Any = None,
        net: Any = None,
        module: str = "auth",
        chain_cache_ttl: int = 86400,
    ) -> None:
        self._root_ca_path = root_ca_path
        self._store = store
        self._verify_ssl = verify_ssl
        self._log = logger
        self._net = net
        self._module = module
        self._chain_cache_ttl = chain_cache_ttl
        self._root_certs = self._load_root_certs()
        self._gateway_chain_cache: dict[str, list[str]] = {}
        self._gateway_crl_cache: dict[str, dict[str, Any]] = {}
        self._gateway_ocsp_cache: dict[str, dict[str, dict[str, Any]]] = {}
        self._chain_verified_cache: dict[str, float] = {}
        self._gateway_ca_verified: dict[str, bool] = {}

    @property
    def root_certs(self) -> list[x509.Certificate]:
        return self._root_certs

    def reload_trusted_roots(self) -> int:
        self._root_certs = self._load_root_certs()
        self._gateway_ca_verified.clear()
        self._chain_verified_cache.clear()
        return len(self._root_certs)

    def clean_expired_caches(self) -> None:
        now = time.time()
        for key in list(self._gateway_crl_cache):
            entry = self._gateway_crl_cache[key]
            if float(entry.get("next_refresh_at") or 0.0) <= now:
                del self._gateway_crl_cache[key]
        for key in list(self._gateway_ocsp_cache):
            inner = self._gateway_ocsp_cache[key]
            for serial in list(inner):
                if float(inner[serial].get("next_refresh_at") or 0.0) <= now:
                    del inner[serial]
            if not inner:
                del self._gateway_ocsp_cache[key]
        for key in list(self._chain_verified_cache):
            if now - self._chain_verified_cache[key] >= self._chain_cache_ttl:
                del self._chain_verified_cache[key]

    def cache_gateway_ca_chain(self, gateway_url: str, chain_pems: list[str], *, chain_aid: str = "") -> None:
        self._gateway_chain_cache[self._cache_key(gateway_url, chain_aid)] = list(chain_pems)

    def discard_gateway_ca_chain(self, gateway_url: str, *, chain_aid: str = "") -> None:
        key = self._cache_key(gateway_url, chain_aid)
        self._gateway_chain_cache.pop(key, None)
        self._gateway_ca_verified.pop(key, None)

    async def verify_phase1_response(self, gateway_url: str, result: dict[str, Any], client_nonce: str) -> None:
        auth_cert_pem = str(result.get("auth_cert") or "")
        signature_b64 = str(result.get("client_nonce_signature") or "")
        if not auth_cert_pem:
            raise AuthError("aid_login1 missing auth_cert")
        if not signature_b64:
            raise AuthError("aid_login1 missing client_nonce_signature")
        try:
            auth_cert = x509.load_pem_x509_certificate(auth_cert_pem.encode("utf-8"))
        except Exception as exc:
            raise AuthError("aid_login1 returned invalid auth_cert") from exc

        await self.verify_certificate(gateway_url, auth_cert, label="auth certificate")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            verify_signature(auth_cert.public_key(), signature, client_nonce.encode("utf-8"))
        except Exception as exc:
            raise AuthError("aid_login1 server auth signature verification failed") from exc

    async def verify_certificate(
        self,
        gateway_url: str,
        cert: x509.Certificate,
        *,
        expected_aid: str = "",
        label: str = "certificate",
    ) -> None:
        self._ensure_cert_time_valid(cert, label, time.time())
        await self._verify_cert_chain(gateway_url, cert, chain_aid=expected_aid)
        try:
            await self._verify_cert_revocation(gateway_url, cert, chain_aid=expected_aid)
        except AuthError as exc:
            if "revoked" in str(exc).lower():
                raise
            self._warn("%s CRL check unavailable, degrading gracefully: %s", label, exc)
        except Exception as exc:
            self._warn("%s CRL check unavailable, degrading gracefully: %s", label, exc)
        try:
            await self._verify_cert_ocsp(gateway_url, cert, chain_aid=expected_aid)
        except AuthError as exc:
            if "revoked" in str(exc).lower():
                raise
            self._warn("%s OCSP check unavailable, degrading gracefully: %s", label, exc)
        except Exception as exc:
            self._warn("%s OCSP check unavailable, degrading gracefully: %s", label, exc)
        if expected_aid:
            cert_cn = cert_common_name(cert)
            if cert_cn != expected_aid:
                raise AuthError(f"{label} CN mismatch: expected {expected_aid}, got {cert_cn or 'none'}")

    async def _verify_cert_chain(self, gateway_url: str, cert: x509.Certificate, *, chain_aid: str = "") -> None:
        cert_serial = format(cert.serial_number, "x")
        cached_at = self._chain_verified_cache.get(cert_serial)
        if cached_at and time.time() - cached_at < self._chain_cache_ttl:
            return

        now = time.time()
        self._ensure_cert_time_valid(cert, "auth certificate", now)
        chain = await self._load_gateway_ca_chain(gateway_url, chain_aid)
        if not chain:
            raise AuthError("unable to verify auth certificate chain: missing CA chain")

        cache_key = self._cache_key(gateway_url, chain_aid)
        if self._gateway_ca_verified.get(cache_key):
            issuer = chain[0]
            self._ensure_cert_time_valid(issuer, "Issuer CA", now)
            self._ensure_ca_certificate(issuer, "Issuer CA")
            if cert.issuer != issuer.subject:
                raise AuthError("auth certificate issuer mismatch")
            try:
                verify_signature(issuer.public_key(), cert.signature, cert.tbs_certificate_bytes)
            except Exception as exc:
                raise AuthError("auth certificate signature verification failed") from exc
            self._chain_verified_cache[cert_serial] = time.time()
            return

        current = cert
        for index, ca_cert in enumerate(chain):
            self._ensure_cert_time_valid(ca_cert, f"CA certificate[{index}]", now)
            if current.issuer != ca_cert.subject:
                raise AuthError(f"auth certificate issuer mismatch at chain level {index}")
            self._ensure_ca_certificate(ca_cert, f"CA certificate[{index}]")
            try:
                verify_signature(ca_cert.public_key(), current.signature, current.tbs_certificate_bytes)
            except Exception as exc:
                raise AuthError(f"auth certificate signature verification failed at chain level {index}") from exc
            current = ca_cert

        root = chain[-1]
        if root.issuer != root.subject:
            raise AuthError("auth certificate chain root is not self-signed")
        try:
            verify_signature(root.public_key(), root.signature, root.tbs_certificate_bytes)
        except Exception as exc:
            raise AuthError("auth certificate chain root self-signature verification failed") from exc

        root_der = root.public_bytes(serialization.Encoding.DER)
        if not any(trusted.public_bytes(serialization.Encoding.DER) == root_der for trusted in self._load_trusted_roots()):
            raise AuthError("auth certificate chain is not anchored by a trusted root")

        self._chain_verified_cache[cert_serial] = time.time()
        self._gateway_ca_verified[cache_key] = True

    async def _load_gateway_ca_chain(self, gateway_url: str, chain_aid: str = "") -> list[x509.Certificate]:
        key = self._cache_key(gateway_url, chain_aid)
        cached = self._gateway_chain_cache.get(key)
        if cached is None:
            cached = await self._fetch_gateway_ca_chain(gateway_url, chain_aid)
            self._gateway_chain_cache[key] = cached
        return self._load_cert_bundle(cached)

    async def _verify_cert_revocation(self, gateway_url: str, cert: x509.Certificate, *, chain_aid: str = "") -> None:
        chain = await self._load_gateway_ca_chain(gateway_url, chain_aid)
        if not chain:
            raise AuthError("unable to verify auth certificate revocation: missing issuer certificate")
        crl_gateway_url = self._crl_gateway_url(gateway_url, chain_aid)
        revoked_serials = await self._load_gateway_revoked_serials(crl_gateway_url, chain[0])
        if format(cert.serial_number, "x").lower() in revoked_serials:
            raise AuthError("auth certificate has been revoked")

    async def _verify_cert_ocsp(self, gateway_url: str, cert: x509.Certificate, *, chain_aid: str = "") -> None:
        chain = await self._load_gateway_ca_chain(gateway_url, chain_aid)
        if not chain:
            raise AuthError("unable to verify auth certificate OCSP status: missing issuer certificate")
        status = await self._load_gateway_ocsp_status(gateway_url, cert, chain[0])
        if status == "revoked":
            raise AuthError("auth certificate OCSP status is revoked")
        if status != "good":
            raise AuthError(f"auth certificate OCSP status is {status}")

    async def _load_gateway_revoked_serials(self, gateway_url: str, issuer_cert: x509.Certificate) -> set[str]:
        cached = self._gateway_crl_cache.get(gateway_url)
        now = time.time()
        if cached is None or float(cached.get("next_refresh_at") or 0.0) <= now:
            cached = await self._fetch_gateway_crl(gateway_url, issuer_cert)
            self._gateway_crl_cache[gateway_url] = cached
        return set(cached.get("revoked_serials") or [])

    async def _load_gateway_ocsp_status(
        self,
        gateway_url: str,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
    ) -> str:
        serial_hex = format(cert.serial_number, "x").lower()
        gateway_cache = self._gateway_ocsp_cache.setdefault(gateway_url, {})
        cached = gateway_cache.get(serial_hex)
        now = time.time()
        if cached is None or float(cached.get("next_refresh_at") or 0.0) <= now:
            cached = await self._fetch_gateway_ocsp_status(gateway_url, cert, issuer_cert)
            gateway_cache[serial_hex] = cached
        return str(cached.get("status") or "unknown")

    def _load_trusted_roots(self) -> list[x509.Certificate]:
        if not self._root_certs:
            self._root_certs = self._load_root_certs()
            if not self._root_certs:
                raise AuthError("no trusted roots available for auth certificate verification")
        return self._root_certs

    async def _fetch_gateway_ca_chain(self, gateway_url: str, chain_aid: str = "") -> list[str]:
        _ = chain_aid
        text = await self._fetch_text(self._gateway_http_url(gateway_url, "/pki/chain"))
        return self._split_pem_bundle(text)

    async def _fetch_gateway_crl(self, gateway_url: str, issuer_cert: x509.Certificate) -> dict[str, Any]:
        payload = await self._fetch_json(self._gateway_http_url(gateway_url, "/pki/crl.json"))
        crl_pem = str(payload.get("crl_pem") or "")
        if not crl_pem:
            raise AuthError("gateway CRL endpoint returned no signed CRL")
        try:
            crl = x509.load_pem_x509_crl(crl_pem.encode("utf-8"))
        except Exception as exc:
            raise AuthError("gateway CRL endpoint returned invalid CRL") from exc
        try:
            verify_signature(issuer_cert.public_key(), crl.signature, crl.tbs_certlist_bytes)
        except Exception as exc:
            raise AuthError("gateway CRL signature verification failed") from exc
        if crl.next_update_utc and time.time() > crl.next_update_utc.timestamp():
            raise AuthError("gateway CRL has expired")
        next_refresh_at = crl.next_update_utc.timestamp() if crl.next_update_utc else time.time() + 300
        return {
            "revoked_serials": {format(revoked.serial_number, "x").lower() for revoked in crl},
            "next_refresh_at": min(next_refresh_at, time.time() + 3600),
        }

    async def _fetch_gateway_ocsp_status(
        self,
        gateway_url: str,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
    ) -> dict[str, Any]:
        serial_hex = format(cert.serial_number, "x").lower()
        payload = await self._fetch_json(self._gateway_http_url(gateway_url, f"/pki/ocsp/{serial_hex}"))
        status = str(payload.get("status") or "")
        ocsp_b64 = str(payload.get("ocsp_response") or "")
        if not ocsp_b64:
            raise AuthError("gateway OCSP endpoint returned no ocsp_response")

        effective_status: str | None = None
        response = None
        try:
            response = ocsp.load_der_ocsp_response(base64.b64decode(ocsp_b64))
            if response.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL:
                if response.serial_number != cert.serial_number:
                    raise AuthError("gateway OCSP response serial mismatch")
                expected_name_hash = hashlib.sha256(issuer_cert.subject.public_bytes()).digest()
                expected_key_hash = hashlib.sha256(
                    issuer_cert.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ).digest()
                if response.issuer_name_hash != expected_name_hash:
                    raise AuthError("gateway OCSP issuer name hash mismatch")
                if response.issuer_key_hash != expected_key_hash:
                    raise AuthError("gateway OCSP issuer key hash mismatch")
                try:
                    verify_signature(issuer_cert.public_key(), response.signature, response.tbs_response_bytes)
                except Exception as exc:
                    raise AuthError("gateway OCSP signature verification failed") from exc
                now = time.time()
                if response.this_update_utc and now < response.this_update_utc.timestamp() - 300:
                    raise AuthError("gateway OCSP response is not yet valid")
                if response.next_update_utc and now > response.next_update_utc.timestamp():
                    raise AuthError("gateway OCSP response has expired")
                if response.certificate_status == ocsp.OCSPCertStatus.GOOD:
                    effective_status = "good"
                elif response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                    effective_status = "revoked"
                else:
                    effective_status = "unknown"
                if status and status != effective_status:
                    raise AuthError("gateway OCSP status mismatch")
        except AuthError:
            raise
        except Exception as exc:
            self._debug("OCSP DER parse failed, degrading to JSON status: %s", exc)

        if effective_status is None:
            if not status:
                raise AuthError("gateway OCSP endpoint returned invalid response and no status field")
            effective_status = status

        next_refresh_at = time.time() + 300
        if response is not None:
            try:
                if response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL and response.next_update_utc:
                    next_refresh_at = response.next_update_utc.timestamp()
            except Exception as exc:
                self._warn("OCSP next_update timestamp parse failed, default TTL=300s: %s", exc)
        return {"status": effective_status, "next_refresh_at": min(next_refresh_at, time.time() + 86400)}

    async def _fetch_text(self, url: str) -> str:
        if self._net:
            try:
                return await self._net.http_get_text(url, timeout=5.0)
            except Exception as exc:
                raise AuthError(f"failed to fetch {url}") from exc
        try:
            timeout = aiohttp.ClientTimeout(total=5.0)
            ssl_param = None if self._verify_ssl else False
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=ssl_param) as response:
                    response.raise_for_status()
                    return await response.text()
        except Exception as exc:
            raise AuthError(f"failed to fetch {url}") from exc

    async def _fetch_json(self, url: str) -> dict[str, Any]:
        if self._net:
            try:
                payload = await self._net.http_get_json(url, timeout=5.0)
            except Exception as exc:
                raise AuthError(f"failed to fetch {url}") from exc
            if not isinstance(payload, dict):
                raise AuthError(f"unexpected response type from {url}: {type(payload)}")
            return payload
        try:
            timeout = aiohttp.ClientTimeout(total=5.0)
            ssl_param = None if self._verify_ssl else False
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=ssl_param) as response:
                    response.raise_for_status()
                    payload = await response.json()
        except Exception as exc:
            raise AuthError(f"failed to fetch {url}") from exc
        if not isinstance(payload, dict):
            raise AuthError(f"invalid JSON payload from {url}")
        return payload

    def _load_root_certs(self) -> list[x509.Certificate]:
        candidate_paths: list[Path] = []
        if self._root_ca_path:
            candidate_paths.append(Path(self._root_ca_path))
        bundle_path = self._store_path("trust_root_bundle_path")
        if bundle_path and bundle_path.exists():
            candidate_paths.append(bundle_path)
        bundled_dir = Path(__file__).resolve().parent / "certs"
        if bundled_dir.exists():
            candidate_paths.extend(sorted(bundled_dir.glob("*.crt")))

        certs: list[x509.Certificate] = []
        seen_der: set[bytes] = set()
        for path in candidate_paths:
            paths = sorted(path.glob("*.crt")) if path.is_dir() else [path]
            for item in paths:
                try:
                    text = item.read_text(encoding="utf-8")
                except OSError as exc:
                    raise AuthError(f"failed to read root certificate bundle: {item}") from exc
                for cert in self._load_cert_bundle(self._split_pem_bundle(text)):
                    der = cert.public_bytes(serialization.Encoding.DER)
                    if der in seen_der:
                        continue
                    seen_der.add(der)
                    certs.append(cert)
        return certs

    def _store_path(self, method_name: str) -> Path | None:
        method = getattr(self._store, method_name, None)
        if not callable(method):
            return None
        try:
            return Path(method())
        except Exception as exc:
            self._warn("%s resolve failed: %s", method_name, exc)
            return None

    @staticmethod
    def _gateway_http_url(gateway_url: str, path: str) -> str:
        parsed = urlparse(gateway_url)
        scheme = "https" if parsed.scheme == "wss" else "http"
        return urlunparse((scheme, parsed.netloc, path, "", "", ""))

    @staticmethod
    def _split_pem_bundle(bundle_text: str) -> list[str]:
        marker = "-----END CERTIFICATE-----"
        certs: list[str] = []
        for part in bundle_text.split(marker):
            part = part.strip()
            if part:
                certs.append(f"{part}\n{marker}\n")
        return certs

    @staticmethod
    def _load_cert_bundle(pems: list[str]) -> list[x509.Certificate]:
        return [x509.load_pem_x509_certificate(pem.encode("utf-8")) for pem in pems]

    @staticmethod
    def _ensure_cert_time_valid(cert: x509.Certificate, label: str, now: float) -> None:
        if now < cert.not_valid_before_utc.timestamp():
            raise AuthError(f"{label} is not yet valid")
        if now > cert.not_valid_after_utc.timestamp():
            raise AuthError(f"{label} has expired")

    @staticmethod
    def _ensure_ca_certificate(cert: x509.Certificate, label: str) -> None:
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise AuthError(f"{label} missing BasicConstraints") from exc
        if not constraints.ca:
            raise AuthError(f"{label} is not marked as CA")

    @staticmethod
    def _cache_key(gateway_url: str, chain_aid: str = "") -> str:
        return f"{gateway_url}:{chain_aid}" if chain_aid else gateway_url

    @staticmethod
    def _crl_gateway_url(gateway_url: str, chain_aid: str = "") -> str:
        if chain_aid and "." in chain_aid:
            _, peer_issuer = chain_aid.split(".", 1)
            import re as _re
            match = _re.search(r"gateway\.([^:/]+)", gateway_url)
            local_issuer = match.group(1) if match else ""
            if local_issuer and peer_issuer != local_issuer:
                return gateway_url.replace(f"gateway.{local_issuer}", f"gateway.{peer_issuer}")
        return gateway_url

    def _debug(self, msg: str, *args: Any) -> None:
        if self._log is not None:
            self._log.debug(self._module, msg, *args)

    def _warn(self, msg: str, *args: Any) -> None:
        if self._log is not None:
            self._log.warn(self._module, msg, *args)
