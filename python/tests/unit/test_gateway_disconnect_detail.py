"""验证 gateway.disconnect 事件 detail 字段透传到应用层。"""
from __future__ import annotations

import asyncio

import pytest

from aun_core import AUNClient, ConnectionState


@pytest.mark.asyncio
async def test_gateway_disconnect_event_includes_detail():
    """服务端 event/gateway.disconnect 带 detail 时，应用层订阅者应能拿到。"""
    client = AUNClient()
    received = []
    client.on("gateway.disconnect", lambda data: received.append(data))

    # 模拟 transport 收到带 detail 的 event/gateway.disconnect
    payload = {
        "code": 4015,
        "reason": "long connection quota exceeded: aid_device_slot_quota_exceeded",
        "detail": {
            "aid": "alice.example.com",
            "device_id": "dev-1",
            "slot_id": "slot-old",
            "limit": 10,
            "quota_kind": "aid_device_slot_quota_exceeded",
            "evicted_by": {
                "aid": "alice.example.com",
                "device_id": "dev-1",
                "slot_id": "slot-NEW",
            },
        },
    }
    await client._on_gateway_disconnect(payload)
    # 让事件在 dispatcher 里跑完
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(received) == 1
    evt = received[0]
    assert evt["code"] == 4015
    assert evt["detail"]["aid"] == "alice.example.com"
    assert evt["detail"]["quota_kind"] == "aid_device_slot_quota_exceeded"
    assert evt["detail"]["evicted_by"]["slot_id"] == "slot-NEW"


@pytest.mark.asyncio
async def test_gateway_disconnect_no_detail_payload():
    """服务端不带 detail 时，detail 字段应为空字典而不是缺失。"""
    client = AUNClient()
    received = []
    client.on("gateway.disconnect", lambda data: received.append(data))

    await client._on_gateway_disconnect({"code": 4001, "reason": "Auth failed"})
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(received) == 1
    assert received[0]["code"] == 4001
    assert received[0]["detail"] == {}


@pytest.mark.asyncio
async def test_connection_failed_state_includes_detail_after_kick():
    """连接进入 connection_failed 时 connection.state 也应带服务端 detail。"""
    client = AUNClient()
    states = []
    client.on("state_change", lambda data: states.append(data))

    # 1. 模拟收到 gateway.disconnect 带 detail
    await client._on_gateway_disconnect({
        "code": 4015,
        "reason": "quota exceeded",
        "detail": {
            "aid": "alice.example.com",
            "device_id": "dev-1",
            "slot_id": "slot-x",
            "quota_kind": "aid_device_slot_quota_exceeded",
        },
    })

    # 2. 触发 transport disconnect → 走 connection_failed 路径
    client._state = "connected"
    client._closing = False
    client._session_options = {
        "auto_reconnect": True,
        "heartbeat_interval": 30.0,
        "token_refresh_before": 60.0,
        "retry": {"initial_delay": 1.0, "max_delay": 64.0},
        "timeouts": {"connect": 5.0, "call": 10.0, "http": 30.0},
        "connection_kind": "long",
    }
    await client._handle_transport_disconnect(None, close_code=4015)
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    terminal = [s for s in states if s.get("state") == ConnectionState.CONNECTION_FAILED.value]
    assert len(terminal) == 1
    assert terminal[0]["detail"]["quota_kind"] == "aid_device_slot_quota_exceeded"
    assert terminal[0]["code"] == 4015
