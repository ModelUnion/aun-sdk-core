"""
AUN E2EE V2: 推测性发送引擎

规范引用: §13.3
- 用本地缓存直接加密发送
- 服务端拒绝时用响应 delta 自动重 wrap 一次
- 最多重试一次
- 对应用层透明

纯逻辑层，依赖 transport 抽象（由集成层注入）。
"""
from __future__ import annotations

import base64
from typing import Any, Callable, Awaitable

from .encrypt_p2p import encrypt_p2p_message


class SpeculativeSendResult:
    """推测性发送结果"""
    def __init__(self, success: bool, message_id: str = "", response: dict | None = None, error: dict | None = None):
        self.success = success
        self.message_id = message_id
        self.response = response
        self.error = error


class SpeculativeSender:
    """推测性发送引擎。

    职责：
    1. 用本地缓存构造 envelope
    2. 发送到服务端
    3. 成功 → 应用 piggyback delta → 返回
    4. 拒绝 → 用 error.data 更新缓存 → 重 wrap → 再发一次
    5. 仍失败 → 上报应用层
    """

    def __init__(
        self,
        *,
        cache_provider: Callable[[str], dict | None],
        cache_updater: Callable[[str, dict], None],
        transport_send: Callable[[str, dict], Awaitable[dict]],
    ):
        """
        Args:
            cache_provider: (peer_aid) → target_set dict（从缓存读取对端设备表）
            cache_updater: (peer_aid, delta) → None（用 delta 更新缓存）
            transport_send: (method, params) → response dict（发送 RPC）
        """
        self._cache_provider = cache_provider
        self._cache_updater = cache_updater
        self._transport_send = transport_send

    async def send_p2p(
        self,
        sender: dict[str, Any],
        peer_aid: str,
        payload: dict[str, Any],
    ) -> SpeculativeSendResult:
        """推测性发送 P2P 加密消息。

        Args:
            sender: 发送方身份（aid / device_id / ik_priv / ik_pub_der）
            peer_aid: 接收方 AID
            payload: 业务 payload

        Returns:
            SpeculativeSendResult
        """
        # 1. 从缓存读取 target_set
        target_set = self._cache_provider(peer_aid)
        if target_set is None:
            return SpeculativeSendResult(
                success=False,
                error={"kind": "transient", "message": "peer device cache miss, need bootstrap"},
            )

        # 2. 加密
        envelope = encrypt_p2p_message(sender=sender, target_set=target_set, payload=payload)
        message_id = envelope["aad"]["message_id"]

        # 3. 推测性发送
        response = await self._transport_send("message.send", {
            "to": peer_aid,
            "payload": envelope,
        })

        # 4. 成功路径
        if response.get("status") == "accepted" or response.get("message_id"):
            # 应用 piggyback delta
            delta = response.get("peer_devices_delta")
            if delta:
                self._cache_updater(peer_aid, delta)
            return SpeculativeSendResult(
                success=True,
                message_id=message_id,
                response=response,
            )

        # 5. 拒绝路径 → 用 error.data 重 wrap 一次
        error = response.get("error", {})
        error_code = error.get("code", 0)
        error_data = error.get("data", {})

        # 可重试的错误码
        retryable_codes = {-33011, -33012, -33050, -33052, -33054}
        if error_code not in retryable_codes:
            return SpeculativeSendResult(
                success=False,
                message_id=message_id,
                error={"kind": "rejected", "message": error.get("message", "send rejected"), "code": error_code},
            )

        # 6. 用 error.data 更新缓存
        if error_data:
            self._cache_updater(peer_aid, error_data)

        # 7. 重新读取缓存 + 重 wrap
        target_set_updated = self._cache_provider(peer_aid)
        if target_set_updated is None:
            return SpeculativeSendResult(
                success=False,
                message_id=message_id,
                error={"kind": "transient", "message": "cache still empty after delta update"},
            )

        # 重新加密（补发：msg_type=supplement，复用 message_id）
        envelope_retry = encrypt_p2p_message(
            sender=sender,
            target_set=target_set_updated,
            payload=payload,
            message_id=message_id,
        )
        envelope_retry["msg_type"] = "supplement"
        envelope_retry["t_supplement"] = envelope_retry["t_send"]

        # 8. 重发
        response2 = await self._transport_send("message.send", {
            "to": peer_aid,
            "payload": envelope_retry,
        })

        if response2.get("status") == "accepted" or response2.get("message_id"):
            delta2 = response2.get("peer_devices_delta")
            if delta2:
                self._cache_updater(peer_aid, delta2)
            return SpeculativeSendResult(
                success=True,
                message_id=message_id,
                response=response2,
            )

        # 9. 仍失败 → 上报
        error2 = response2.get("error", {})
        return SpeculativeSendResult(
            success=False,
            message_id=message_id,
            error={"kind": "transient", "message": error2.get("message", "retry also failed"), "code": error2.get("code", 0)},
        )
