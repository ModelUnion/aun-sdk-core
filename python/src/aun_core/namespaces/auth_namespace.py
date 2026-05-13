from __future__ import annotations

import logging
import base64
import re
import time
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..auth import _verify_signature
from ..errors import AUNError, NotFoundError, StateError, ValidationError

_auth_ns_log = logging.getLogger("aun_core")
_AGENT_MD_SIGNATURE_MARKER = "<!-- AUN-SIGNATURE"
_AGENT_MD_SIGNATURE_RE = re.compile(
    r"<!-- AUN-SIGNATURE\r?\n(?P<body>.*?)\r?\n-->\s*\Z",
    re.DOTALL,
)
_AGENT_MD_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")


def _agent_md_http_scheme(gateway_url: str) -> str:
    raw = str(gateway_url or "").strip().lower()
    return "http" if raw.startswith("ws://") else "https"


def _agent_md_authority(aid: str, discovery_port: int | None) -> str:
    host = str(aid or "").strip()
    if not host:
        return ""
    if discovery_port and ":" not in host:
        return f"{host}:{int(discovery_port)}"
    return host


def _parse_agent_md_tail_signature(content: str) -> tuple[str, dict[str, str] | None, str | None]:
    marker_index = content.rfind(_AGENT_MD_SIGNATURE_MARKER)
    if marker_index < 0:
        return content, None, None
    if marker_index > 0 and content[marker_index - 1] not in "\r\n":
        return content, None, None

    tail = content[marker_index:]
    match = _AGENT_MD_SIGNATURE_RE.fullmatch(tail)
    if not match:
        return content[:marker_index], None, "malformed signature block"

    fields: dict[str, str] = {}
    for line in match.group("body").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ":" not in stripped:
            return content[:marker_index], None, f"malformed signature field: {stripped}"
        key, value = stripped.split(":", 1)
        fields[key.strip().lower()] = value.strip()

    for required in ("cert_fingerprint", "timestamp", "signature"):
        if not fields.get(required):
            return content[:marker_index], None, f"signature block missing {required}"
    if not _AGENT_MD_FINGERPRINT_RE.fullmatch(fields["cert_fingerprint"]):
        return content[:marker_index], None, "invalid cert_fingerprint"
    try:
        int(fields["timestamp"])
    except ValueError:
        return content[:marker_index], None, "invalid timestamp"

    return content[:marker_index], fields, None


def _extract_agent_md_aid(payload: str) -> str:
    lines = payload.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if stripped.startswith("aid:"):
            value = stripped.split(":", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            return value.strip()
    return ""


def _agent_md_result(
    status: str,
    payload: str,
    *,
    reason: str = "",
    aid: str = "",
    cert_fingerprint: str = "",
    timestamp: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "verified": status == "verified",
        "payload": payload,
    }
    if reason:
        result["reason"] = reason
    if aid:
        result["aid"] = aid
    if cert_fingerprint:
        result["cert_fingerprint"] = cert_fingerprint
    if timestamp is not None:
        result["timestamp"] = timestamp
    return result


class AuthNamespace:
    def __init__(self, client: Any) -> None:
        self._client = client

    async def _resolve_gateway(self, aid: str | None = None) -> str:
        """解析 gateway URL。优先使用已预置的 _gateway_url，否则基于 AID 自动发现。

        发现流程：
        1. 若 _gateway_url 已预置，直接返回
        2. 开发环境：先 gateway.{issuer}，再 fallback {aid}（泛域名在开发环境可能不可用）
        3. 生产环境：先 {aid}（泛域名 nameservice），再 fallback gateway.{issuer}
        """
        if self._client._gateway_url:
            return str(self._client._gateway_url)
        resolved_aid = aid or self._client._aid
        if resolved_aid:
            parts = resolved_aid.split(".", 1)
            issuer_domain = parts[1] if len(parts) > 1 else resolved_aid

            port = self._client._config_model.discovery_port
            port_suffix = f":{port}" if port else ""

            aid_url = f"https://{resolved_aid}{port_suffix}/.well-known/aun-gateway"
            gateway_url = f"https://gateway.{issuer_domain}{port_suffix}/.well-known/aun-gateway"

            # 开发环境：先 gateway.{issuer}（固定域名），再 fallback {aid}（泛域名）
            # 生产环境：先 {aid}（泛域名），再 fallback gateway.{issuer}
            if self._client._config_model.verify_ssl:
                primary_url, fallback_url = aid_url, gateway_url
            else:
                primary_url, fallback_url = gateway_url, aid_url

            try:
                return await self._client._discovery.discover(primary_url)
            except Exception as _exc:
                import logging as _logging
                _logging.getLogger("aun_core").debug("gateway 发现失败: %s", _exc)

            return await self._client._discovery.discover(fallback_url)
        raise ValidationError(
            "unable to resolve gateway: set client._gateway_url or provide 'aid' for auto-discovery"
        )

    async def create_aid(self, params: dict[str, Any]) -> dict[str, Any]:
        aid = str((params or {}).get("aid") or "")
        if not aid:
            raise ValueError("auth.create_aid requires 'aid'")
        gateway_url = await self._resolve_gateway(aid)
        self._client._gateway_url = gateway_url
        result = await self._client._auth.create_aid(gateway_url, aid)
        self._client._aid = result["aid"]
        self._client._identity = self._client._auth.load_identity_or_none(result["aid"])
        return {
            "aid": result["aid"],
            "cert_pem": result["cert"],
            "gateway": gateway_url,
        }

    async def authenticate(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request = dict(params or {})
        aid = request.get("aid")
        gateway_url = await self._resolve_gateway(aid)
        self._client._gateway_url = gateway_url
        result = await self._client._auth.authenticate(gateway_url, aid=aid)
        self._client._aid = result["aid"]
        self._client._identity = self._client._auth.load_identity_or_none(result["aid"])
        return result  # 已包含 gateway 字段

    async def _resolve_agent_md_url(self, aid: str) -> str:
        resolved_aid = str(aid or "").strip()
        if not resolved_aid:
            raise ValidationError("agent.md requires non-empty aid")
        gateway_url = str(self._client._gateway_url or "")
        if not gateway_url:
            try:
                gateway_url = await self._resolve_gateway(resolved_aid)
            except Exception:
                gateway_url = ""
        discovery_port = getattr(self._client._config_model, "discovery_port", None)
        authority = _agent_md_authority(resolved_aid, discovery_port)
        return f"{_agent_md_http_scheme(gateway_url)}://{authority}/agent.md"

    def _get_cached_access_token(self, identity: dict[str, Any]) -> str:
        token = str(identity.get("access_token") or "")
        if not token:
            return ""
        expires_at = self._client._auth.get_access_token_expiry(identity)
        if expires_at is not None and expires_at <= time.time() + 30:
            return ""
        return token

    async def _ensure_agent_md_upload_token(self, aid: str, gateway_url: str) -> str:
        identity = self._client._auth.load_identity_or_none(aid)
        if identity is None:
            raise StateError("no local identity found, call auth.create_aid() first")

        token = self._get_cached_access_token(identity)
        if token:
            return token

        refresh_token = str(identity.get("refresh_token") or "")
        if refresh_token:
            try:
                identity = await self._client._auth.refresh_cached_tokens(gateway_url, identity)
                token = self._get_cached_access_token(identity)
                if token:
                    self._client._identity = self._client._auth.load_identity_or_none(aid)
                    return token
            except Exception as exc:
                _auth_ns_log.debug(
                    "agent.md upload refresh_token 失败，回退到完整 authenticate: %s",
                    exc,
                )

        auth_result = await self.authenticate({"aid": aid})
        token = str(auth_result.get("access_token") or "")
        if not token:
            raise StateError("authenticate did not return access_token")
        return token

    async def upload_agent_md(self, content: str) -> dict[str, Any]:
        identity = self._client._auth.load_identity_or_none(self._client._aid)
        if identity is None:
            raise StateError("no local identity found, call auth.create_aid() first")
        aid = str(identity.get("aid") or self._client._aid or "").strip()
        if not aid:
            raise StateError("no local identity found, call auth.create_aid() first")

        gateway_url = await self._resolve_gateway(aid)
        self._client._gateway_url = gateway_url
        token = await self._ensure_agent_md_upload_token(aid, gateway_url)
        agent_md_url = await self._resolve_agent_md_url(aid)

        timeout = aiohttp.ClientTimeout(total=30)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "text/markdown; charset=utf-8",
        }
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.put(agent_md_url, data=content.encode("utf-8"), headers=headers) as response:
                if response.status == 404:
                    raise NotFoundError(f"agent.md endpoint not found for aid: {aid}")
                if response.status < 200 or response.status >= 300:
                    message = (await response.text()).strip()
                    raise AUNError(
                        f"upload agent.md failed: HTTP {response.status}"
                        + (f" - {message}" if message else "")
                    )
                return await response.json()

    async def download_agent_md(self, aid: str) -> str:
        target_aid = str(aid or "").strip()
        if not target_aid:
            raise ValidationError("download_agent_md requires non-empty aid")
        agent_md_url = await self._resolve_agent_md_url(target_aid)

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(agent_md_url, headers={"Accept": "text/markdown"}) as response:
                if response.status == 404:
                    raise NotFoundError(f"agent.md not found for aid: {target_aid}")
                if response.status < 200 or response.status >= 300:
                    message = (await response.text()).strip()
                    raise AUNError(
                        f"download agent.md failed: HTTP {response.status}"
                        + (f" - {message}" if message else "")
                    )
                return await response.text()

    async def sign_agent_md(self, content: str, *, aid: str | None = None) -> str:
        target_aid = str(aid or self._client._aid or "").strip()
        identity = self._client._auth.load_identity_or_none(target_aid or None)
        if identity is None:
            raise StateError("no local identity found, call auth.create_aid() first")

        private_key_pem = str(identity.get("private_key_pem") or "").strip()
        cert_pem = str(identity.get("cert") or "").strip()
        if not private_key_pem or not cert_pem:
            raise StateError("local identity missing private key or certificate")

        payload, _, _ = _parse_agent_md_tail_signature(str(content or ""))
        if payload and not payload.endswith(("\n", "\r")):
            payload += "\n"

        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise StateError("agent.md signing requires an EC private key")

        signature = private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        fingerprint = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
        signed_block = "\n".join([
            "<!-- AUN-SIGNATURE",
            f"cert_fingerprint: {fingerprint}",
            f"timestamp: {int(time.time())}",
            f"signature: {base64.b64encode(signature).decode('ascii')}",
            "-->",
        ])
        return payload + signed_block

    async def verify_agent_md(
        self,
        content: str,
        *,
        aid: str | None = None,
        cert_pem: str | None = None,
    ) -> dict[str, Any]:
        payload, fields, parse_error = _parse_agent_md_tail_signature(str(content or ""))
        if fields is None:
            if parse_error is None:
                return _agent_md_result("unsigned", payload)
            return _agent_md_result("invalid", payload, reason=parse_error)

        expected_aid = str(aid or "").strip()
        payload_aid = _extract_agent_md_aid(payload)
        if expected_aid and payload_aid and payload_aid != expected_aid:
            return _agent_md_result("invalid", payload, reason="aid mismatch", aid=payload_aid)
        if not expected_aid:
            expected_aid = payload_aid

        cert_text = str(cert_pem or "").strip()
        if not cert_text:
            if not expected_aid:
                return _agent_md_result("invalid", payload, reason="aid required to verify agent.md")
            try:
                fetched = await self._client._fetch_peer_cert(expected_aid, fields["cert_fingerprint"])
                cert_text = fetched.decode("utf-8") if isinstance(fetched, bytes) else str(fetched)
            except Exception as exc:
                return _agent_md_result("invalid", payload, reason=str(exc), aid=expected_aid)

        try:
            cert = x509.load_pem_x509_certificate(cert_text.encode("utf-8"))
        except Exception as exc:
            return _agent_md_result("invalid", payload, reason=f"invalid certificate: {exc}", aid=expected_aid)

        actual_fp = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
        if actual_fp.lower() != fields["cert_fingerprint"].lower():
            return _agent_md_result("invalid", payload, reason="certificate fingerprint mismatch", aid=expected_aid)

        if expected_aid:
            try:
                cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            except Exception:
                cn = ""
            if cn and cn != expected_aid:
                return _agent_md_result("invalid", payload, reason="certificate aid mismatch", aid=expected_aid)

        try:
            public_key = cert.public_key()
            signature = base64.b64decode(fields["signature"], validate=True)
            _verify_signature(public_key, signature, payload.encode("utf-8"))
        except Exception as exc:
            return _agent_md_result("invalid", payload, reason=f"signature verification failed: {exc}", aid=expected_aid, cert_fingerprint=fields["cert_fingerprint"], timestamp=int(fields["timestamp"]))

        return _agent_md_result(
            "verified",
            payload,
            aid=expected_aid or payload_aid,
            cert_fingerprint=fields["cert_fingerprint"],
            timestamp=int(fields["timestamp"]),
        )

    async def download_cert(self, params: dict[str, Any] | None = None) -> Any:
        return await self._client.call("auth.download_cert", params or {})

    async def request_cert(self, params: dict[str, Any]) -> Any:
        return await self._client.call("auth.request_cert", params)

    async def renew_cert(self, params: dict[str, Any] | None = None) -> Any:
        return await self._client.call("auth.renew_cert", params or {})

    async def rekey(self, params: dict[str, Any] | None = None) -> Any:
        return await self._client.call("auth.rekey", params or {})

    async def trust_roots(self, params: dict[str, Any] | None = None) -> Any:
        return await self._client.call("meta.trust_roots", params or {})
