import pytest
from aun_core.transport import _format_trace_tree


def test_enter_exit_pairing():
    spans = [
        {"node": "sdk", "ts": 1000, "action": "send"},
        {"node": "gateway", "ts": 1010, "action": "enter", "route": "service_plane", "method": "v2.put_peer_pk"},
        {"node": "message", "ts": 1012, "action": "enter", "method": "v2.put_peer_pk", "peer_aid": "test.aid.com"},
        {"node": "ca", "ts": 1014, "action": "enter", "method": "get_cert", "aid": "test.aid.com"},
        {"node": "ca", "ts": 1016, "action": "exit", "ms": 2, "status": "error", "found": False},
        {"node": "message", "ts": 1019, "action": "exit", "ms": 7, "status": "error", "error_code": -32603},
        {"node": "gateway", "ts": 1022, "action": "exit", "ms": 12, "status": "error"},
        {"node": "sdk", "ts": 1054, "action": "recv", "ms": 54},
    ]

    result = _format_trace_tree(spans)

    assert "gateway.enter" in result
    assert "message.enter" in result
    assert "  ├─ ca.enter" in result  # 缩进表示嵌套
    assert "  └─ ca.exit" in result
    assert "message.exit" in result
    assert "status=error" in result
    assert "dur=2ms" in result


def test_backward_compatibility_process_action():
    spans = [
        {"node": "sdk", "ts": 1000, "action": "send"},
        {"node": "gateway", "ts": 1010, "action": "process", "ms": 5},
        {"node": "message", "ts": 1012, "action": "process", "ms": 7},
        {"node": "sdk", "ts": 1054, "action": "recv", "ms": 54},
    ]

    result = _format_trace_tree(spans)

    assert "gateway.process dur=5ms" in result
    assert "message.process dur=7ms" in result
