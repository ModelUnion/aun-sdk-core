"""
P0 通用缺口测试 — 网关健康检查 / AID 参数校验 / 断线 RPC 拒绝

纯单元测试，无需真实服务端。
"""
import asyncio

import pytest

from aun_core import AIDStore, AUNClient, ConnectionState
from aun_core import error_codes as codes
from aun_core.errors import (
    AUNError,
    ConnectionError,
    PermissionError as AUNPermissionError,
    StateError,
    ValidationError,
)


# ── P0-01: 网关健康检查 ──────────────────────────────────────


class TestP0_01_GatewayHealthCheck:
    """网关健康检查基础场景。"""

    def test_gateway_health_initial_none(self):
        """gateway_health 初始值应为 None"""
        client = AUNClient()
        assert client.gateway_health is None

    @pytest.mark.asyncio
    async def test_health_check_unreachable_returns_false(self):
        """不可达地址应在 timeout 内返回 False"""
        client = AUNClient()
        # 192.0.2.0/24 是 RFC 5737 文档专用地址段，不可达
        ok = await client._discovery.check_health(
            "https://192.0.2.1:9999", timeout=2.0
        )
        assert ok is False

    @pytest.mark.asyncio
    async def test_health_check_refused_returns_false(self):
        """连接拒绝（无服务端口）应返回 False"""
        client = AUNClient()
        ok = await client._discovery.check_health(
            "https://127.0.0.1:1", timeout=3.0
        )
        assert ok is False

    @pytest.mark.asyncio
    async def test_gateway_health_updated_after_check(self):
        """健康检查后 gateway_health 应被更新为 False（无服务）"""
        client = AUNClient()
        await client._discovery.check_health("https://127.0.0.1:1", timeout=2.0)
        assert client.gateway_health is False


# ── P0-14: 断线中 RPC 拒绝 ──────────────────────────────────


class TestP0_14_DisconnectedRPCReject:
    """客户端未连接时 RPC 调用应被拒绝。"""

    @pytest.mark.asyncio
    async def test_call_when_idle_raises_connection_error(self):
        """未连接（idle 状态）时调用 call 应抛出 ConnectionError"""
        client = AUNClient()
        with pytest.raises(ConnectionError):
            await client.call("meta.ping")

    @pytest.mark.asyncio
    async def test_call_error_message_contains_not_connected(self):
        """未连接时 call 的错误消息应包含 'not connected'"""
        client = AUNClient()
        with pytest.raises(ConnectionError, match="not connected"):
            await client.call("meta.ping")

    @pytest.mark.asyncio
    async def test_call_after_disconnect_raises_error(self):
        """断线后调用 call 应抛出 ConnectionError"""
        client = AUNClient()
        # 模拟无可用连接的状态
        client._state = ConnectionState.NO_IDENTITY.value
        with pytest.raises(ConnectionError):
            await client.call(
                "message.send",
                {"to": "test.aid.com", "content": {"text": "hi"}},
            )

    @pytest.mark.asyncio
    async def test_internal_only_method_rejected_when_connected(self):
        """internal_only 方法即使已连接也应被拒绝"""
        client = AUNClient()
        client._state = "connected"
        with pytest.raises(AUNPermissionError):
            await client.call("auth.login1")
        with pytest.raises(AUNPermissionError):
            await client.call("auth.login2")
        with pytest.raises(AUNPermissionError):
            await client.call("auth.connect")

    @pytest.mark.asyncio
    async def test_internal_only_message_contains_keyword(self):
        """internal_only 拒绝消息应包含 'internal_only'"""
        client = AUNClient()
        client._state = "connected"
        with pytest.raises(AUNPermissionError, match="internal_only"):
            await client.call("auth.login1")


# ── P0-02: AID 创建参数校验 ─────────────────────────────────


class TestP0_02_AIDCreationValidation:
    """AID 创建时参数校验基础场景。"""

    @pytest.mark.asyncio
    async def test_empty_aid_raises_error(self, tmp_path):
        """空 AID 应返回 INVALID_AID_FORMAT"""
        store = AIDStore(tmp_path / "aun-test", encryption_seed="", verify_ssl=False)
        result = await store.register("")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == codes.INVALID_AID_FORMAT

    @pytest.mark.asyncio
    async def test_empty_aid_error_message(self, tmp_path):
        """空 AID 错误消息应包含 'aid'"""
        store = AIDStore(tmp_path / "aun-test", encryption_seed="", verify_ssl=False)
        result = await store.register("")
        assert not result.ok
        assert result.error is not None
        assert "aid" in result.error.message.lower()

    @pytest.mark.asyncio
    async def test_missing_aid_field_raises_error(self, tmp_path):
        """不传 aid 字段应返回 INVALID_AID_FORMAT"""
        store = AIDStore(tmp_path / "aun-test", encryption_seed="", verify_ssl=False)
        result = await store.register("")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == codes.INVALID_AID_FORMAT

    @pytest.mark.asyncio
    async def test_aid_too_short_rejected(self, tmp_path):
        """AID 名称过短（< 4 字符）应被拒绝"""
        store = AIDStore(tmp_path / "aun-test", encryption_seed="", verify_ssl=False)
        result = await store.register("ab")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == codes.INVALID_AID_FORMAT

    @pytest.mark.asyncio
    async def test_aid_uppercase_rejected(self, tmp_path):
        """AID 名称含大写应被拒绝"""
        store = AIDStore(tmp_path / "aun-test", encryption_seed="", verify_ssl=False)
        result = await store.register("Alice.aid.com")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == codes.INVALID_AID_FORMAT

    @pytest.mark.asyncio
    async def test_aid_starts_with_dash_rejected(self, tmp_path):
        """AID 名称以 - 开头应被拒绝"""
        store = AIDStore(tmp_path / "aun-test", encryption_seed="", verify_ssl=False)
        result = await store.register("-bad.aid.com")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == codes.INVALID_AID_FORMAT

    @pytest.mark.asyncio
    async def test_aid_guest_prefix_rejected(self, tmp_path):
        """AID 名称以 guest 开头应被拒绝"""
        store = AIDStore(tmp_path / "aun-test", encryption_seed="", verify_ssl=False)
        result = await store.register("guestuser.aid.com")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == codes.INVALID_AID_FORMAT
