from __future__ import annotations

import logging
import time
from typing import Any

import aiohttp

from ..errors import AUNError, NotFoundError, StateError, ValidationError

_auth_ns_log = logging.getLogger("aun_core")


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


class AuthNamespace:
    def __init__(self, client: Any) -> None:
        self._client = client

    async def _resolve_gateway(self, aid: str | None = None) -> str:
        """解析 gateway URL。优先使用已预置的 _gateway_url，否则基于 AID 自动发现。

        发现流程：
        1. 若 _gateway_url 已预置，直接返回
        2. https://{aid}/.well-known/aun-gateway（泛域名 nameservice）
        3. https://gateway.{issuer}/.well-known/aun-gateway（Gateway 直连）
        """
        if self._client._gateway_url:
            return str(self._client._gateway_url)
        resolved_aid = aid or self._client._aid
        if resolved_aid:
            parts = resolved_aid.split(".", 1)
            issuer_domain = parts[1] if len(parts) > 1 else resolved_aid

            port = self._client._config_model.discovery_port
            port_suffix = f":{port}" if port else ""

            primary_url = f"https://{resolved_aid}{port_suffix}/.well-known/aun-gateway"
            try:
                return await self._client._discovery.discover(primary_url)
            except Exception as _exc:
                import logging as _logging
                _logging.getLogger("aun_core").debug("gateway 发现失败: %s", _exc)

            fallback_url = f"https://gateway.{issuer_domain}{port_suffix}/.well-known/aun-gateway"
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
