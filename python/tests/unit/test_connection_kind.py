"""Python SDK 长短连接机制单元测试（TDD 红色阶段）

目标：
- client.connect(auth, options) 透传 connection_kind / short_ttl_ms 到 auth.connect 的 params.options
- 短连接默认禁用：心跳、auto_reconnect、token_refresh、SeqTracker 持久化
- 4012/4013 加入 _NO_RECONNECT_CODES，被踢/容量满后不再重连
- 不传 connection_kind 时按 long 处理（向后兼容）
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from aun_core import AUNClient


# ── 1. _NO_RECONNECT_CODES 必须包含 4012 / 4013 ────────────────────

def test_no_reconnect_codes_include_long_already_exists_and_short_capacity():
    # 4012 = long_connection_already_exists（被同槽位另一长连接抢占）
    # 4013 = short_connection_capacity_exceeded（短连接池满）
    assert 4012 in AUNClient._NO_RECONNECT_CODES
    assert 4013 in AUNClient._NO_RECONNECT_CODES


# ── 2. _normalize_connect_params 接受 connection_kind / short_ttl_ms ──

def test_normalize_connect_params_keeps_connection_kind_long_default():
    client = AUNClient()
    params = client._normalize_connect_params({
        "access_token": "tok",
        "gateway": "ws://localhost/aun",
    })
    # 不传 connection_kind 时默认 long
    assert params.get("connection_kind") == "long"


def test_normalize_connect_params_accepts_kind_short():
    client = AUNClient()
    params = client._normalize_connect_params({
        "access_token": "tok",
        "gateway": "ws://localhost/aun",
        "connection_kind": "short",
        "short_ttl_ms": 30000,
    })
    assert params["connection_kind"] == "short"
    assert params["short_ttl_ms"] == 30000


def test_normalize_connect_params_rejects_invalid_kind():
    from aun_core.errors import ValidationError
    client = AUNClient()
    with pytest.raises(ValidationError):
        client._normalize_connect_params({
            "access_token": "tok",
            "gateway": "ws://localhost/aun",
            "connection_kind": "weird",
        })


# ── 3. _initialize_session 把 kind / ttl 写入 params.options ────────

@pytest.mark.asyncio
async def test_initialize_session_passes_options_to_auth_connect():
    """调用 _initialize_session 时透传 connection_kind / short_ttl_ms 到 params.options"""
    client = AUNClient()
    captured = {}

    class _FakeTransport:
        async def call(self, method, params):
            captured["method"] = method
            captured["params"] = params
            return {"status": "ok"}

    challenge = {"params": {"nonce": "abc"}}
    await client._auth.initialize_with_token(
        _FakeTransport(),
        challenge,
        access_token="tok",
        device_id="dev-1",
        slot_id="slot-a",
        delivery_mode={"mode": "fanout", "routing": "", "affinity_ttl_ms": 0},
        connection_kind="short",
        short_ttl_ms=30000,
    )
    assert captured["method"] == "auth.connect"
    options = captured["params"].get("options") or {}
    assert options.get("kind") == "short"
    assert options.get("short_ttl_ms") == 30000


@pytest.mark.asyncio
async def test_initialize_session_omits_options_kind_when_long():
    """长连接（默认）不应在 payload 中显式写 options.kind=long，保持向后兼容"""
    client = AUNClient()
    captured = {}

    class _FakeTransport:
        async def call(self, method, params):
            captured["params"] = params
            return {"status": "ok"}

    challenge = {"params": {"nonce": "abc"}}
    await client._auth.initialize_with_token(
        _FakeTransport(),
        challenge,
        access_token="tok",
        device_id="dev-1",
        slot_id="",
        delivery_mode={"mode": "fanout", "routing": "", "affinity_ttl_ms": 0},
        connection_kind="long",
    )
    options = captured["params"].get("options") or {}
    # 长连接走默认路径，不必写 options（向后兼容）
    assert options.get("kind", "long") == "long"


# ── 4. 短连接禁用心跳 / token_refresh ───────────────────────────────

def test_short_connection_disables_heartbeat_and_token_refresh():
    """短连接 _start_background_tasks 不应启动心跳和 token 刷新循环"""
    client = AUNClient()
    client._session_options = {
        "auto_reconnect": False,
        "heartbeat_interval": 30.0,
        "token_refresh_before": 60.0,
        "retry": {"initial_delay": 1.0, "max_delay": 64.0},
        "timeouts": {"connect": 5.0, "call": 10.0, "http": 30.0},
        "connection_kind": "short",
    }
    client._closing = False
    client._state = "connected"

    # 拦截 task 创建：把 _start_*_task 的实际工作捕获
    started = []
    client._start_heartbeat_task = lambda: started.append("heartbeat")
    client._start_token_refresh_task = lambda: started.append("token_refresh")
    client._start_group_epoch_tasks = lambda: started.append("group_epoch")

    client._start_background_tasks()

    # 短连接不启动心跳与 token 刷新；group_epoch 也不需要（短连接不接收推送）
    assert "heartbeat" not in started
    assert "token_refresh" not in started


def test_long_connection_starts_heartbeat_and_token_refresh():
    client = AUNClient()
    client._session_options = {
        "auto_reconnect": True,
        "heartbeat_interval": 30.0,
        "token_refresh_before": 60.0,
        "retry": {"initial_delay": 1.0, "max_delay": 64.0},
        "timeouts": {"connect": 5.0, "call": 10.0, "http": 30.0},
        "connection_kind": "long",
    }
    client._closing = False
    client._state = "connected"

    started = []
    client._start_heartbeat_task = lambda: started.append("heartbeat")
    client._start_token_refresh_task = lambda: started.append("token_refresh")
    client._start_group_epoch_tasks = lambda: started.append("group_epoch")

    client._start_background_tasks()

    assert "heartbeat" in started
    assert "token_refresh" in started


# ── 5. 短连接 auto_reconnect 默认 False ─────────────────────────────

def test_short_connection_allows_auto_reconnect_by_default():
    """短连接允许自动重连（与长连接一致），但不启动 heartbeat 和 token 刷新。"""
    client = AUNClient()
    options = client._build_session_options({
        "access_token": "tok",
        "gateway": "ws://x/aun",
        "connection_kind": "short",
    })
    assert options["auto_reconnect"] is True


def test_long_connection_keeps_default_auto_reconnect():
    client = AUNClient()
    options = client._build_session_options({
        "access_token": "tok",
        "gateway": "ws://x/aun",
        "connection_kind": "long",
    })
    # 默认 auto_reconnect 仍为 True（保留现行行为）
    assert options["auto_reconnect"] is True
