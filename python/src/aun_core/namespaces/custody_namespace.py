"""AID Custody namespace — 手机号绑定、备份与恢复。"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import aiohttp

from ..errors import AUNError, ConnectionError, ValidationError

_log = logging.getLogger("aun_core")


def _issuer_domain_from_aid(aid: str) -> str:
    parts = str(aid or "").strip().split(".", 1)
    return parts[1] if len(parts) > 1 else parts[0]


def _extract_custody_url(payload: dict[str, Any]) -> str:
    for key in ("custody_url", "custodyUrl", "url"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    custody = payload.get("custody")
    if isinstance(custody, dict):
        value = str(custody.get("url") or "").strip()
        if value:
            return value
    for key in ("custody_services", "custodyServices", "services"):
        items = payload.get(key)
        if isinstance(items, list) and items:
            candidates = [item for item in items if isinstance(item, dict)]
            candidates.sort(key=lambda item: int(item.get("priority") or 999))
            for item in candidates:
                value = str(item.get("url") or "").strip()
                if value:
                    return value
    raise ValidationError("custody well-known missing custody url")


def _normalize_custody_url(url: str) -> str:
    value = str(url or "").strip().rstrip("/")
    if not value:
        return ""
    try:
        parsed = urlparse(value)
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return value


class CustodyNamespace:
    """AUNClient.custody — AID 托管服务 HTTP API 封装。"""

    def __init__(self, client: Any) -> None:
        self._client = client
        self._custody_url: str = ""

    def set_url(self, url: str) -> None:
        """手动设置 custody 服务地址。"""
        self._custody_url = str(url or "").strip().rstrip("/")

    def configure_url(self, url: str) -> None:
        """set_url 的语义化别名。"""
        self.set_url(url)

    def _well_known_urls(self, aid: str) -> list[str]:
        config = getattr(self._client, "_config_model", None)
        port = getattr(config, "discovery_port", None) if config else None
        port_suffix = f":{int(port)}" if port else ""
        resolved_aid = str(aid or "").strip()
        issuer_domain = _issuer_domain_from_aid(resolved_aid)
        aid_url = f"https://{resolved_aid}{port_suffix}/.well-known/aun-custody"
        fallback_url = f"https://aid_custody.{issuer_domain}{port_suffix}/.well-known/aun-custody"
        verify_ssl = bool(getattr(config, "verify_ssl", True)) if config else True
        urls = [aid_url, fallback_url] if verify_ssl else [fallback_url, aid_url]
        deduped: list[str] = []
        for url in urls:
            if url not in deduped:
                deduped.append(url)
        return deduped

    async def discover_url(self, *, aid: str | None = None, timeout: float = 5.0) -> str:
        """通过 AID 域名 well-known 发现官方 custody 服务地址，并缓存到当前 namespace。"""
        resolved_aid = str(aid or getattr(self._client, "_aid", "") or "").strip()
        if not resolved_aid:
            raise ValidationError("custody.discover_url requires aid or authenticated client")
        config = getattr(self._client, "_config_model", None)
        ssl_param = None if bool(getattr(config, "verify_ssl", True)) else False
        last_exc: Exception | None = None
        for well_known_url in self._well_known_urls(resolved_aid):
            try:
                client_timeout = aiohttp.ClientTimeout(total=timeout)
                async with aiohttp.ClientSession(timeout=client_timeout) as session:
                    async with session.get(well_known_url, ssl=ssl_param) as resp:
                        resp.raise_for_status()
                        payload = await resp.json()
                if not isinstance(payload, dict):
                    raise ValidationError("custody well-known returned invalid payload")
                custody_url = _normalize_custody_url(_extract_custody_url(payload))
                if not custody_url:
                    raise ValidationError("custody well-known returned invalid custody url")
                self._custody_url = custody_url
                return custody_url
            except Exception as exc:
                last_exc = exc
                _log.debug("custody 发现失败 (%s): %s", well_known_url, exc)
        raise ConnectionError(
            f"custody discovery failed for {resolved_aid}: {last_exc}",
            retryable=True,
        )

    async def _resolve_custody_url(self, aid: str | None = None) -> str:
        custody_url = _normalize_custody_url(self._custody_url)
        if custody_url:
            if custody_url != self._custody_url:
                self._custody_url = custody_url
            return custody_url
        return await self.discover_url(aid=aid)

    def _get_access_token(self) -> str:
        identity = getattr(self._client, "_identity", None)
        if isinstance(identity, dict):
            token = str(identity.get("access_token") or "").strip()
            if token:
                return token
        raise ValidationError("no access_token available: call auth.authenticate() first")

    async def send_code(self, *, phone: str, aid: str | None = None) -> dict[str, Any]:
        """发送手机验证码。

        不传 aid 时为绑定/上传场景，需要当前 AID 的 access_token；
        传 aid 时为恢复/下载场景，不需要 AID 登录。
        """
        phone_value = str(phone or "").strip()
        if not phone_value:
            raise ValidationError("custody.send_code requires non-empty phone")
        aid_value = str(aid or "").strip()
        body: dict[str, Any] = {"phone": phone_value}
        token: str | None = None
        if aid_value:
            body["aid"] = aid_value
        else:
            token = self._get_access_token()
        return await self._post("/custody/accounts/send-code", body, token=token, aid=aid_value or None)

    async def bind_phone(
        self,
        *,
        phone: str,
        code: str,
        cert: str,
        key: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """绑定手机号，并上传 AID 证书和客户端加密后的私钥密文。"""
        body = {
            "phone": str(phone or "").strip(),
            "code": str(code or "").strip(),
            "cert": str(cert or "").strip(),
            "key": str(key or "").strip(),
        }
        if not all(body.values()):
            raise ValidationError("custody.bind_phone requires phone, code, cert and key")
        if metadata:
            body["metadata"] = metadata
        return await self._post(
            "/custody/accounts/bind-phone",
            body,
            token=self._get_access_token(),
            aid=getattr(self._client, "_aid", None),
        )

    async def restore_phone(self, *, phone: str, code: str, aid: str) -> dict[str, Any]:
        """通过手机号、验证码和 AID 下载证书及加密私钥密文。"""
        body = {
            "phone": str(phone or "").strip(),
            "code": str(code or "").strip(),
            "aid": str(aid or "").strip(),
        }
        if not all(body.values()):
            raise ValidationError("custody.restore_phone requires phone, code and aid")
        return await self._post("/custody/accounts/restore-phone", body, token=None, aid=body["aid"])

    async def create_device_copy(self, *, aid: str | None = None) -> dict[str, Any]:
        """旧设备基于 AID token 发起一次性跨设备复制会话。"""
        aid_value = str(aid or getattr(self._client, "_aid", "") or "").strip()
        if not aid_value:
            raise ValidationError("custody.create_device_copy requires aid or authenticated client")
        return await self._post(
            "/custody/transfers",
            {"aid": aid_value},
            token=self._get_access_token(),
            aid=aid_value,
        )

    async def upload_device_copy_materials(
        self,
        *,
        transfer_code: str,
        cert: str,
        key: str,
        aid: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """旧设备上传 OTP 加密后的私钥密文。OTP 不应传给 custody。"""
        code_value = str(transfer_code or "").strip()
        aid_value = str(aid or getattr(self._client, "_aid", "") or "").strip()
        body = {
            "aid": aid_value,
            "cert": str(cert or "").strip(),
            "key": str(key or "").strip(),
        }
        if not code_value or not all(body.values()):
            raise ValidationError(
                "custody.upload_device_copy_materials requires transfer_code, aid, cert and key"
            )
        if metadata:
            body["metadata"] = metadata
        return await self._post(
            f"/custody/transfers/{code_value}/materials",
            body,
            token=self._get_access_token(),
            aid=aid_value,
        )

    async def claim_device_copy(self, *, aid: str, transfer_code: str) -> dict[str, Any]:
        """新设备凭 AID 和复制码领取 OTP 加密材料。不要传 OTP。"""
        body = {
            "aid": str(aid or "").strip(),
            "transfer_code": str(transfer_code or "").strip(),
        }
        if not all(body.values()):
            raise ValidationError("custody.claim_device_copy requires aid and transfer_code")
        return await self._post("/custody/transfers/claim", body, token=None, aid=body["aid"])

    async def _post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        token: str | None = None,
        aid: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        timeout = aiohttp.ClientTimeout(total=30)
        config = getattr(self._client, "_config_model", None)
        ssl_param = None if bool(getattr(config, "verify_ssl", True)) else False
        url = f"{await self._resolve_custody_url(aid)}{path}"
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=body, headers=headers, ssl=ssl_param) as resp:
                try:
                    data = await resp.json()
                except Exception as exc:
                    raise AUNError(f"custody returned non-JSON response: HTTP {resp.status}") from exc
                if resp.status >= 400:
                    error = data.get("error", {}) if isinstance(data, dict) else {}
                    code = error.get("code", "unknown") if isinstance(error, dict) else "unknown"
                    message = error.get("message", "") if isinstance(error, dict) else str(data)
                    raise AUNError(
                        f"custody {code}: {message}" if message else f"custody HTTP {resp.status}"
                    )
                if not isinstance(data, dict):
                    raise AUNError("custody returned invalid JSON payload")
                return data
