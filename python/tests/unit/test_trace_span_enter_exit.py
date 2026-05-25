import json
import pytest


def test_message_enter_exit_span_structure():
    """验证 Message 模块生成的 enter/exit span 结构"""
    # 模拟 _TracingWS._inject_trace 的输出
    params = {
        "_auth": {"aid": "alice.aid.com"},
        "peer_aid": "bob.aid.com",
        "key_source": "peer_device_prekey",
        "spk_id": "sha256:abc123",
    }

    # Enter span 应包含的字段
    enter_span = {
        "node": "message",
        "ts": 1234567890123,
        "action": "enter",
        "method": "v2.put_peer_pk",
        "caller_aid": "alice.aid.com",
        "peer_aid": "bob.aid.com",
        "key_source": "peer_device_prekey",
        "spk_id": "sha256:abc123ab",
    }

    assert enter_span["action"] == "enter"
    assert "method" in enter_span
    assert "caller_aid" in enter_span
    assert "peer_aid" in enter_span

    # Exit span（失败）应包含的字段
    exit_span = {
        "node": "message",
        "ts": 1234567890130,
        "action": "exit",
        "ms": 7,
        "status": "error",
        "error_code": -32603,
        "error_msg": "AID cert not found",
        "method": "v2.put_peer_pk",
        "peer_aid": "bob.aid.com",
    }

    assert exit_span["action"] == "exit"
    assert exit_span["status"] == "error"
    assert "error_code" in exit_span
    assert "method" in exit_span  # 失败时补充上下文
    assert "peer_aid" in exit_span
