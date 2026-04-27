"""Meta namespace — 心跳、状态和信任根管理。"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import aiohttp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization

from ..auth import _verify_signature
from ..errors import ValidationError


_AUTHORITY_ENDPOINT = "https://trust.aun.network/.well-known/aun/trust-roots.json"
_MAX_CLOCK_SKEW = 300


class MetaNamespace:
    def __init__(self, client) -> None:
        self._client = client

    async def ping(self, params: dict[str, Any] | None = None) -> Any:
        return await self._client.call("meta.ping", params or {})

    async def status(self, params: dict[str, Any] | None = None) -> Any:
        return await self._client.call("meta.status", params or {})

    async def trust_roots(self, params: dict[str, Any] | None = None) -> Any:
        """通过已连接的 Gateway RPC 查询信任根列表。"""
        return await self._client.call("meta.trust_roots", params or {})

    async def download_trust_roots(
        self,
        url: str | None = None,
        *,
        issuer: str | None = None,
        gateway_url: str | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """从管理局权威端点或 Gateway 镜像端点下载 trust-roots.json。"""
        target = self._resolve_trust_roots_url(url, issuer=issuer, gateway_url=gateway_url)
        if not target.lower().startswith(("https://", "http://")):
            raise ValidationError("trust roots url must be http(s)")

        ssl_param = None if self._client._config_model.verify_ssl else False
        http_timeout = aiohttp.ClientTimeout(total=float(timeout))
        async with aiohttp.ClientSession(timeout=http_timeout) as session:
            async with session.get(target, ssl=ssl_param, headers={"Accept": "application/json"}) as response:
                response.raise_for_status()
                payload = await response.json()
        if not isinstance(payload, dict):
            raise ValidationError("trust roots endpoint returned non-object JSON")
        return payload

    async def download_issuer_root_cert(
        self,
        issuer: str,
        url: str | None = None,
        *,
        timeout: float = 10.0,
    ) -> str:
        """从 pki.{issuer}/root.crt 下载指定 issuer 当前发布的 Root CA 证书。"""
        target = str(url or "").strip() or self._issuer_root_cert_url(issuer)
        if not target.lower().startswith(("https://", "http://")):
            raise ValidationError("issuer root certificate url must be http(s)")
        ssl_param = None if self._client._config_model.verify_ssl else False
        http_timeout = aiohttp.ClientTimeout(total=float(timeout))
        async with aiohttp.ClientSession(timeout=http_timeout) as session:
            async with session.get(
                target,
                ssl=ssl_param,
                headers={"Accept": "application/x-pem-file,text/plain"},
            ) as response:
                response.raise_for_status()
                cert_pem = await response.text()
        self._load_root_certificate(cert_pem.strip(), issuer)
        return cert_pem.strip() + "\n"

    def verify_trust_roots(
        self,
        trust_list: dict[str, Any],
        *,
        authority_cert_pem: str | None = None,
        authority_public_key_pem: str | None = None,
        allow_unsigned: bool = False,
    ) -> dict[str, Any]:
        """验证受信根列表签名和根证书结构，返回可导入摘要。"""
        if not isinstance(trust_list, dict):
            raise ValidationError("trust roots list must be a JSON object")
        signature = str(trust_list.get("authority_signature") or "").strip()
        if not signature and not allow_unsigned:
            raise ValidationError("trust roots list missing authority_signature")
        self._validate_list_metadata(trust_list)
        if signature:
            public_key = self._load_authority_public_key(
                authority_cert_pem=authority_cert_pem,
                authority_public_key_pem=authority_public_key_pem,
                trust_list=trust_list,
            )
            signed_payload = self._canonical_signed_payload(trust_list)
            try:
                _verify_signature(public_key, self._decode_signature(signature), signed_payload)
            except InvalidSignature as exc:
                raise ValidationError("trust roots authority_signature verification failed") from exc
            except Exception as exc:
                raise ValidationError("trust roots authority_signature verification failed") from exc

        roots = self._extract_root_entries(trust_list)
        imported: list[dict[str, str]] = []
        skipped: list[dict[str, str]] = []
        now = time.time()
        for item in roots:
            status = str(item.get("status") or "active").strip().lower()
            cert_pem = str(item.get("certificate") or item.get("cert_pem") or "").strip()
            root_id = str(item.get("id") or item.get("agentid") or "").strip()
            if status != "active":
                skipped.append({"id": root_id, "reason": f"status={status}"})
                continue
            cert = self._load_root_certificate(cert_pem, root_id or "root")
            self._validate_root_ca_certificate(cert, root_id or cert.subject.rfc4514_string())
            if cert.not_valid_before_utc.timestamp() > now or cert.not_valid_after_utc.timestamp() < now:
                raise ValidationError(f"root certificate is not currently valid: {root_id or cert.subject.rfc4514_string()}")
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            expected_fp = self._normalize_fingerprint(item.get("fingerprint_sha256"))
            if len(expected_fp) != 64:
                raise ValidationError(f"root certificate missing or invalid fingerprint_sha256: {root_id or fingerprint}")
            if expected_fp != fingerprint:
                raise ValidationError(f"root certificate fingerprint mismatch: {root_id or fingerprint}")
            imported.append({
                "id": root_id or fingerprint,
                "cert_pem": cert_pem,
                "fingerprint_sha256": fingerprint,
            })
        if not imported:
            raise ValidationError("trust roots list contains no active root certificates")
        return {"imported": imported, "skipped": skipped, "count": len(imported)}

    def import_trust_roots(
        self,
        trust_list: dict[str, Any],
        *,
        authority_cert_pem: str | None = None,
        authority_public_key_pem: str | None = None,
        allow_unsigned: bool = False,
    ) -> dict[str, Any]:
        """验证并导入信任根列表，随后刷新当前客户端的根证书缓存。"""
        verified = self.verify_trust_roots(
            trust_list,
            authority_cert_pem=authority_cert_pem,
            authority_public_key_pem=authority_public_key_pem,
            allow_unsigned=allow_unsigned,
        )
        self._enforce_monotonic_version(trust_list)
        bundle_path = self._client._keystore.save_trust_roots(trust_list, verified["imported"])
        reloaded = self._client._auth.reload_trusted_roots()
        return {
            "imported": verified["count"],
            "skipped": verified["skipped"],
            "bundle_path": str(bundle_path),
            "reloaded_roots": reloaded,
            "fingerprints": [item["fingerprint_sha256"] for item in verified["imported"]],
        }

    async def refresh_trust_roots(
        self,
        url: str | None = None,
        *,
        issuer: str | None = None,
        gateway_url: str | None = None,
        authority_cert_pem: str | None = None,
        authority_public_key_pem: str | None = None,
        allow_unsigned: bool = False,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """下载、验签并导入受信根列表。"""
        source_url = self._resolve_trust_roots_url(url, issuer=issuer, gateway_url=gateway_url)
        trust_list = await self.download_trust_roots(source_url, timeout=timeout)
        result = self.import_trust_roots(
            trust_list,
            authority_cert_pem=authority_cert_pem,
            authority_public_key_pem=authority_public_key_pem,
            allow_unsigned=allow_unsigned,
        )
        result["source_url"] = source_url
        return result

    async def update_issuer_root_cert(
        self,
        issuer: str,
        *,
        cert_pem: str | None = None,
        url: str | None = None,
        trust_list: dict[str, Any] | None = None,
        authority_cert_pem: str | None = None,
        authority_public_key_pem: str | None = None,
        allow_unsigned: bool = False,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """下载或接收 issuer root.crt，确认其属于受信根列表后更新本地根证书 bundle。"""
        normalized_issuer = self._validate_issuer(issuer)
        source_url = str(url or "").strip() or self._issuer_root_cert_url(normalized_issuer)
        root_pem = cert_pem.strip() + "\n" if isinstance(cert_pem, str) and cert_pem.strip() else ""
        if not root_pem:
            root_pem = await self.download_issuer_root_cert(normalized_issuer, source_url, timeout=timeout)
        cert = self._load_root_certificate(root_pem, normalized_issuer)
        self._validate_root_ca_certificate(cert, normalized_issuer)
        self._verify_self_signed_root(cert, normalized_issuer)
        now = time.time()
        if cert.not_valid_before_utc.timestamp() > now or cert.not_valid_after_utc.timestamp() < now:
            raise ValidationError(f"issuer root certificate is not currently valid: {normalized_issuer}")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        effective_trust_list = trust_list or self._load_local_trust_list()
        trust_source = "local"
        if effective_trust_list is None:
            effective_trust_list = await self.download_trust_roots(
                issuer=normalized_issuer,
                timeout=timeout,
            )
            trust_source = self._issuer_trust_root_url(normalized_issuer)
        verified = self.verify_trust_roots(
            effective_trust_list,
            authority_cert_pem=authority_cert_pem,
            authority_public_key_pem=authority_public_key_pem,
            allow_unsigned=allow_unsigned,
        )
        self._enforce_monotonic_version(effective_trust_list)
        trusted_fingerprints = {item["fingerprint_sha256"] for item in verified["imported"]}
        if fingerprint not in trusted_fingerprints:
            raise ValidationError("issuer root certificate is not in trusted root list")

        cert_path, bundle_path = self._client._keystore.save_issuer_root_cert(
            normalized_issuer,
            root_pem,
            fingerprint,
        )
        reloaded = self._client._auth.reload_trusted_roots()
        return {
            "issuer": normalized_issuer,
            "fingerprint_sha256": fingerprint,
            "cert_path": str(cert_path),
            "bundle_path": str(bundle_path),
            "reloaded_roots": reloaded,
            "source_url": source_url,
            "trust_source": trust_source,
        }

    def _resolve_trust_roots_url(
        self,
        url: str | None,
        *,
        issuer: str | None = None,
        gateway_url: str | None = None,
    ) -> str:
        target = str(url or "").strip()
        if target:
            return target
        if issuer:
            return self._issuer_trust_root_url(issuer)
        gw = str(gateway_url or getattr(self._client, "_gateway_url", "") or "").strip()
        return self._gateway_trust_roots_url(gw) if gw else _AUTHORITY_ENDPOINT

    def _issuer_trust_root_url(self, issuer: str) -> str:
        authority = self._pki_authority(issuer)
        return f"https://{authority}/trust-root.json"

    def _issuer_root_cert_url(self, issuer: str) -> str:
        authority = self._pki_authority(issuer)
        return f"https://{authority}/root.crt"

    def _pki_authority(self, issuer: str) -> str:
        normalized = self._validate_issuer(issuer)
        port = getattr(self._client._config_model, "discovery_port", None)
        port_suffix = f":{int(port)}" if port and ":" not in normalized else ""
        return f"pki.{normalized}{port_suffix}"

    @staticmethod
    def _validate_issuer(issuer: str) -> str:
        value = str(issuer or "").strip().lower()
        if not value or "://" in value or "/" in value or "\\" in value or value.startswith("."):
            raise ValidationError("issuer must be a domain name")
        return value

    @staticmethod
    def _gateway_trust_roots_url(gateway_url: str) -> str:
        parsed = urlparse(gateway_url)
        if not parsed.netloc:
            raise ValidationError("gateway_url must include scheme and host")
        scheme = "https" if parsed.scheme in {"wss", "https"} else "http"
        return urlunparse((scheme, parsed.netloc, "/pki/trust-roots.json", "", "", ""))

    @staticmethod
    def _canonical_signed_payload(trust_list: dict[str, Any]) -> bytes:
        payload = dict(trust_list)
        payload.pop("authority_signature", None)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _decode_signature(signature: str) -> bytes:
        value = signature.strip()
        if value.startswith("base64:"):
            value = value.split(":", 1)[1]
        padding = "=" * (-len(value) % 4)
        try:
            normalized = (value + padding).replace("-", "+").replace("_", "/")
            return base64.b64decode(normalized.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValidationError("invalid authority_signature encoding") from exc

    def _load_authority_public_key(
        self,
        *,
        authority_cert_pem: str | None,
        authority_public_key_pem: str | None,
        trust_list: dict[str, Any],
    ):
        if authority_public_key_pem:
            try:
                return serialization.load_pem_public_key(authority_public_key_pem.encode("utf-8"))
            except Exception as exc:
                raise ValidationError("invalid authority public key PEM") from exc
        candidate_cert = (
            authority_cert_pem
            or str(trust_list.get("authority_cert_pem") or "")
            or self._load_local_authority_cert()
        )
        if not candidate_cert:
            raise ValidationError("authority certificate/public key is required to verify trust roots")
        try:
            cert = x509.load_pem_x509_certificate(candidate_cert.encode("utf-8"))
        except Exception as exc:
            raise ValidationError("invalid authority certificate PEM") from exc
        return cert.public_key()

    @staticmethod
    def _extract_root_entries(trust_list: dict[str, Any]) -> list[dict[str, Any]]:
        roots = trust_list.get("root_cas")
        if isinstance(roots, list):
            return [item for item in roots if isinstance(item, dict)]
        legacy = trust_list.get("roots")
        if isinstance(legacy, list):
            converted: list[dict[str, Any]] = []
            for item in legacy:
                if not isinstance(item, dict):
                    continue
                converted.append({
                    "id": item.get("agentid") or item.get("id") or item.get("cert_sn"),
                    "certificate": item.get("cert_pem") or item.get("certificate"),
                    "fingerprint_sha256": item.get("fingerprint_sha256"),
                    "status": item.get("status") or "active",
                })
            return converted
        raise ValidationError("trust roots list missing root_cas")

    @staticmethod
    def _validate_list_metadata(trust_list: dict[str, Any]) -> None:
        version = trust_list.get("version")
        if not isinstance(version, int) or version < 0:
            raise ValidationError("trust roots list version must be a non-negative integer")
        issued_at = MetaNamespace._parse_timestamp(trust_list.get("issued_at"), "issued_at")
        next_update = MetaNamespace._parse_timestamp(trust_list.get("next_update"), "next_update")
        if next_update < issued_at:
            raise ValidationError("trust roots list next_update must not be earlier than issued_at")
        if issued_at > datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=_MAX_CLOCK_SKEW):
            raise ValidationError("trust roots list issued_at is too far in the future")

    @staticmethod
    def _parse_timestamp(value: Any, field: str) -> datetime:
        text = str(value or "").strip()
        if not text:
            raise ValidationError(f"trust roots list missing {field}")
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError(f"trust roots list {field} must be ISO-8601") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _normalize_fingerprint(value: Any) -> str:
        text = str(value or "").strip().lower()
        if text.startswith("sha256:"):
            text = text.split(":", 1)[1]
        return "".join(ch for ch in text if ch in "0123456789abcdef")

    @staticmethod
    def _validate_root_ca_certificate(cert: x509.Certificate, root_id: str) -> None:
        try:
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise ValidationError(f"root certificate missing BasicConstraints: {root_id}") from exc
        if not basic.ca:
            raise ValidationError(f"root certificate is not a CA certificate: {root_id}")

    @staticmethod
    def _verify_self_signed_root(cert: x509.Certificate, root_id: str) -> None:
        if cert.subject != cert.issuer:
            raise ValidationError(f"root certificate is not self-issued: {root_id}")
        try:
            _verify_signature(cert.public_key(), cert.signature, cert.tbs_certificate_bytes)
        except Exception as exc:
            raise ValidationError(f"root certificate self-signature verification failed: {root_id}") from exc

    def _enforce_monotonic_version(self, trust_list: dict[str, Any]) -> None:
        version = trust_list.get("version")
        if not isinstance(version, int):
            return
        current_path = self._client._keystore.trust_root_dir() / "trust-roots.json"
        if not current_path.exists():
            return
        try:
            current = json.loads(current_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        current_version = current.get("version") if isinstance(current, dict) else None
        if isinstance(current_version, int) and version < current_version:
            raise ValidationError("trust roots list version rollback is not allowed")

    def _load_local_trust_list(self) -> dict[str, Any] | None:
        path = self._client._keystore.trust_root_dir() / "trust-roots.json"
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError("local trust roots list is invalid") from exc
        if not isinstance(payload, dict):
            raise ValidationError("local trust roots list must be a JSON object")
        return payload

    @staticmethod
    def _load_root_certificate(cert_pem: str, root_id: str) -> x509.Certificate:
        if "BEGIN CERTIFICATE" not in cert_pem:
            raise ValidationError(f"root certificate missing PEM data: {root_id}")
        try:
            return x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except Exception as exc:
            raise ValidationError(f"invalid root certificate PEM: {root_id}") from exc

    def _load_local_authority_cert(self) -> str:
        candidates = [
            self._client._keystore.trust_root_dir().parent / "authority" / "authority.crt",
            Path(__file__).resolve().parent.parent / "certs" / "authority.crt",
        ]
        for path in candidates:
            try:
                if path.exists():
                    return path.read_text(encoding="utf-8")
            except OSError:
                continue
        return ""
