from __future__ import annotations

from typing import Any

from ..errors import ValidationError


class AuthNamespace:
    def __init__(self, client: Any) -> None:
        self._client = client

    async def _resolve_gateway(self, params: dict[str, Any]) -> str:
        """从 params 获取 gateway，或通过 well_known_url 发现。"""
        gateway = params.get("gateway")
        if gateway:
            return str(gateway)
        well_known_url = params.get("well_known_url")
        if well_known_url:
            return await self._client._discovery.discover(str(well_known_url))
        # 尝试从 AID 推导 well-known URL
        # AID 格式: name.issuer（如 alice.aid.com）
        # Well-Known URL: https://{aid}/.well-known/aun-gateway
        aid = params.get("aid") or self._client._aid
        if aid:
            url = f"https://{aid}/.well-known/aun-gateway"
            return await self._client._discovery.discover(url)
        raise ValidationError(
            "authenticate/create_aid requires 'gateway' or 'well_known_url' in params"
        )

    async def create_aid(self, params: dict[str, Any]) -> dict[str, Any]:
        aid = str((params or {}).get("aid") or "")
        if not aid:
            raise ValueError("auth.create_aid requires 'aid'")
        gateway_url = await self._resolve_gateway(params)
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
        gateway_url = await self._resolve_gateway(request)
        result = await self._client._auth.authenticate(gateway_url, aid=aid)
        self._client._aid = result["aid"]
        self._client._identity = self._client._auth.load_identity_or_none(result["aid"])
        return result  # 已包含 gateway 字段

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
