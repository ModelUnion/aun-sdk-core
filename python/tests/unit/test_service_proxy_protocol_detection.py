import base64

from aun_core.service_proxy import ServiceRecord
from aun_core.service_proxy.protocol_detection import (
    detect_request_protocol,
    is_stream_response_headers,
    stream_type_from_response,
)


def _record(service_name="fileshare", service_type="http", metadata=None):
    return ServiceRecord(
        service_name=service_name,
        endpoint="http://127.0.0.1:8080/root",
        service_type=service_type,
        visibility="public",
        metadata=dict(metadata or {}),
    )


def _message(**kwargs):
    result = {
        "type": "service_proxy_request",
        "request_id": "req-1",
        "service_name": "fileshare",
        "method": "GET",
        "path": "/",
        "query_string": "",
        "headers": {},
        "body_base64": "",
    }
    result.update(kwargs)
    return result


def test_sdk_protocol_detection_server_hint_takes_priority():
    result = detect_request_protocol(
        _message(service_type="mcp", headers={"accept": "text/event-stream"}),
        _record(),
    )

    assert result.service_type == "mcp"
    assert result.is_stream is True
    assert result.source == "server-hint"


def test_sdk_protocol_detection_x_service_type_has_priority_over_accept_and_path():
    result = detect_request_protocol(
        _message(path="/sse/events", headers={"x-service-type": "api", "accept": "text/event-stream"}),
        _record(),
    )

    assert result.service_type == "api"
    assert result.is_stream is False
    assert result.source == "x-service-type"


def test_sdk_protocol_detection_detects_sse_mcp_grpc_and_paths():
    jsonrpc_body = base64.b64encode(b'{"jsonrpc":"2.0","method":"tools/list","id":1}').decode("ascii")

    cases = [
        (_message(headers={"accept": "application/json, text/event-stream"}), "sse", True),
        (_message(headers={"mcp-session-id": "session-1"}), "mcp", True),
        (_message(method="POST", body_base64=jsonrpc_body), "mcp", True),
        (_message(method="POST", headers={"content-type": "application/grpc+proto"}), "ws", True),
        (_message(path="/v1/chat/completions"), "api", False),
        (_message(path="/mcp/sse"), "mcp", True),
        (_message(path="/events/stream"), "sse", True),
        (_message(path="/download/report.bin"), "file", True),
    ]

    for message, expected_type, expected_stream in cases:
        result = detect_request_protocol(message, _record())
        assert result.service_type == expected_type
        assert result.is_stream is expected_stream


def test_sdk_protocol_detection_jsonrpc_get_body_is_not_mcp():
    jsonrpc_body = base64.b64encode(b'{"jsonrpc":"2.0","method":"tools/list","id":1}').decode("ascii")

    result = detect_request_protocol(_message(method="GET", body_base64=jsonrpc_body), _record())

    assert result.service_type == "http"
    assert result.is_stream is False


def test_sdk_protocol_detection_no_stream_forces_non_stream_http():
    result = detect_request_protocol(
        _message(service_type="sse", stream_mode="no_stream", headers={"accept": "text/event-stream"}),
        _record(service_name="events", service_type="sse", metadata={"stream_mode": "stream"}),
    )

    assert result.service_type == "http"
    assert result.stream_mode == "no_stream"
    assert result.is_stream is False
    assert result.source == "stream_mode"


def test_sdk_protocol_detection_uses_stream_compatibility_field():
    result = detect_request_protocol(_message(stream=True), _record())

    assert result.service_type == "http"
    assert result.is_stream is True


def test_sdk_protocol_detection_referer_fallback_uses_registered_service_type():
    result = detect_request_protocol(
        _message(headers={"referer": "https://proxy.agentid.pub/alice/events/page"}),
        _record(service_name="events", service_type="sse"),
    )

    assert result.service_type == "sse"
    assert result.is_stream is True
    assert result.source == "referer"


def test_sdk_response_header_stream_detection_covers_sse_and_files():
    assert is_stream_response_headers({"content-type": "text/event-stream; charset=utf-8"}) is True
    assert is_stream_response_headers({"content-type": "application/octet-stream"}) is True
    assert is_stream_response_headers({"content-disposition": "attachment; filename=report.bin"}) is True
    assert is_stream_response_headers({"content-type": "application/json"}) is False


def test_sdk_stream_type_from_response_prefers_sse_and_file_headers():
    assert stream_type_from_response({"content-type": "text/event-stream"}, fallback="mcp") == "sse"
    assert stream_type_from_response({"content-type": "application/pdf"}, fallback="http") == "file"
    assert stream_type_from_response({"content-type": "application/json"}, fallback="mcp") == "mcp"
