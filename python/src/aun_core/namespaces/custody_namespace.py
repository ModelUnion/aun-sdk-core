"""AID Custody namespace — 手机号绑定、备份与恢复。"""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from ..errors import AUNError, ValidationError

_log = logging.getLogger("aun_core")


class CustodyNamespace:
    """AUNClient.custody — AID 托管服务的 HTTP API 封装。

    提供三个核心方法：
    - send_code: 发送手机验证码
    - bind_phone: 绑定手机号 + 备份证书密钥
    - restore_phone: 手机号 + 验证码恢复
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self._custody_url: str = ""

    def _get_custody_url(self) -> str:
        """获取 custody 服务 URL。"""
        if self._custody_url:
            return self._custody_url
        # 从 client 配置推导
        config = getattr(self._client, "_config_model", None)
        custody_url = getattr(config, "custody_url", "") if config else ""
        if custody_url:
            self._custody_url = str(custody_url).rstrip("/")
            return self._custody_url
        raise ValidationError(
            "custody_url not configured: set client config 'custody_url' "
            "or call client.custody.set_url()"
        )

    def set_url(self, url: str) -> None:
        """手动设置 custody 服务地址。"""
        self._custody_url = str(url or "").rstrip("/")

    def _get_access_token(self) -> str:
        """获取当前 AID 的 aun_token。"""
        identity = getattr(self._client, "_identity", None)
        if identity and isinstance(identity, dict):
            token = identity.get("access_token", "")
            if token:
                return str(token)
        raise ValidationError(
            "no access_token available: call auth.authenticate() first"
        )

    async def send_code(self, *, phone: str) -> dict[str, Any]:
        """发送手机验证码（绑定场景）。需要先 AID 登录。

        Args:
            phone: E.164 格式手机号（如 "+8613800138000"）

        Returns:
            包含 request_id, phone, expires_in_seconds, debug_code 的字典
        """
        url = f"{self._get_custody_url()}/custody/accounts/send-code"
        token = self._get_access_token()
        return await self._post(url, {"phone": phone}, token=token)

    async def bind_phone(
        self,
        *,
        phone: str,
        code: str,
        cert: str,
        key: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """绑定手机号 + 备份证书和加密私钥。需要先 AID 登录。

        Args:
            phone: E.164 格式手机号
            code: 6 位数字验证码
            cert: AID 证书 PEM
            key: 客户端加密后的私钥密文
            metadata: 加密参数和备注（custody 不解读，原样存储）

        Returns:
            包含 binding 和 backup_result 的字典
        """
        url = f"{self._get_custody_url()}/custody/accounts/bind-phone"
        token = self._get_access_token()
        body: dict[str, Any] = {
            "phone": phone,
            "code": code,
            "cert": cert,
            "key": key,
        }
        if metadata:
            body["metadata"] = metadata
        return await self._post(url, body, token=token)

    async def restore_phone(
        self,
        *,
        phone: str,
        code: str,
        aid: str,
    ) -> dict[str, Any]:
        """凭手机号 + 验证码 + AID 恢复备份的证书和加密私钥。不需要登录。

        Args:
            phone: E.164 格式手机号
            code: 6 位数字验证码
            aid: 要恢复的 AID

        Returns:
            包含 aid, cert_pem, key_pem, key_encrypted, metadata 的字典
        """
        url = f"{self._get_custody_url()}/custody/accounts/restore-phone"
        body = {"phone": phone, "code": code, "aid": aid}
        return await self._post(url, body, token=None)

    async def _post(
        self, url: str, body: dict, *, token: str | None = None
    ) -> dict[str, Any]:
        """通用 HTTP POST 请求。"""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=body, headers=headers) as resp:
                data = await resp.json()
                if resp.status >= 400:
                    error = data.get("error", {}) if isinstance(data, dict) else {}
                    code = error.get("code", "unknown") if isinstance(error, dict) else "unknown"
                    message = error.get("message", "") if isinstance(error, dict) else str(data)
                    raise AUNError(
                        f"custody {code}: {message}" if message else f"custody HTTP {resp.status}"
                    )
                return data
