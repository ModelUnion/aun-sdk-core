import base64
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from aun_core.service_proxy import ServiceProxyClient


class _AccessLogger:
    def __init__(self):
        self.events = []

    def info(self, _module, message, *args):
        text = message % args if args else message
        if text.startswith("ACCESS "):
            self.events.append(json.loads(text[len("ACCESS "):]))

    def warn(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


def test_service_proxy_client_response_headers_strip_auto_headers():
    headers = ServiceProxyClient._response_headers(
        {
            "Date": "Thu, 04 Jun 2026 00:00:00 GMT",
            "Server": "backend",
            "Content-Length": "2",
            "X-Backend": "ok",
        }
    )

    assert headers == {"x-backend": "ok"}


async def _start_backend(handler):
    app = web.Application()
    app.router.add_route("*", "/root/{tail:.*}", handler)
    server = TestServer(app)
    await server.start_server()
    return server


@pytest.mark.asyncio
async def test_service_proxy_client_calls_backend_get_with_query_and_headers():
    captured = {}

    async def handler(request):
        captured["method"] = request.method
        captured["path_qs"] = request.path_qs
        captured["x_trace"] = request.headers.get("x-trace-id")
        return web.Response(status=202, headers={"x-backend": "ok"}, body=b'{"ok":true}')

    backend = await _start_backend(handler)
    try:
        logger = _AccessLogger()
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", logger=logger)
        client.register_service("fileshare", str(backend.make_url("/root")), visibility="public")

        response = await client.handle_request_message(
            {
                "type": "service_proxy_request",
                "request_id": "req-1",
                "service_name": "fileshare",
                "method": "GET",
                "path": "/health",
                "query_string": "token=QUERYSECRET",
                "headers": {"x-trace-id": "trace-1"},
                "body_base64": "",
            }
        )
    finally:
        await backend.close()

    assert captured == {"method": "GET", "path_qs": "/root/health?token=QUERYSECRET", "x_trace": "trace-1"}
    assert response["type"] == "service_proxy_response"
    assert response["request_id"] == "req-1"
    assert response["status"] == 202
    assert response["headers"]["x-backend"] == "ok"
    assert base64.b64decode(response["body_base64"]) == b'{"ok":true}'

    assert [event["event"] for event in logger.events] == ["backend_request_start", "backend_response"]
    start = logger.events[0]
    assert start["request_id"] == "req-1"
    assert start["provider_aid"] == "alice.agentid.pub"
    assert start["service_name"] == "fileshare"
    assert start["method"] == "GET"
    assert start["path"] == "/health"
    assert start["has_query"] is True
    assert start["query_length"] == len("token=QUERYSECRET")
    result = logger.events[1]
    assert result["request_id"] == "req-1"
    assert result["status"] == 202
    assert result["stream"] is False
    serialized = json.dumps(logger.events, ensure_ascii=False)
    assert "QUERYSECRET" not in serialized
    assert "trace-1" not in serialized


@pytest.mark.asyncio
async def test_service_proxy_client_calls_backend_post_with_body():
    captured = {}

    async def handler(request):
        captured["body"] = await request.read()
        return web.Response(status=201, body=b"created")

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub")
        client.register_service("fileshare", str(backend.make_url("/root")))

        response = await client.handle_request_message(
            {
                "type": "service_proxy_request",
                "request_id": "req-2",
                "service_name": "fileshare",
                "method": "POST",
                "path": "/items",
                "query_string": "",
                "headers": {"content-type": "application/json"},
                "body_base64": base64.b64encode(b'{"name":"demo"}').decode("ascii"),
            }
        )
    finally:
        await backend.close()

    assert captured["body"] == b'{"name":"demo"}'
    assert response["status"] == 201
    assert base64.b64decode(response["body_base64"]) == b"created"


@pytest.mark.asyncio
async def test_service_proxy_client_iter_streams_request_body_to_backend():
    captured = {}

    async def handler(request):
        captured["body"] = await request.read()
        return web.Response(status=200, content_type="text/plain", body=b"received")

    async def body_iter():
        yield b"ab"
        yield b"cd"

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub")
        client.register_service("fileshare", str(backend.make_url("/root")))

        messages = [
            item
            async for item in client.iter_request_messages(
                {
                    "type": "service_proxy_request",
                    "request_id": "req-stream-body",
                    "service_name": "fileshare",
                    "method": "POST",
                    "path": "/upload",
                    "query_string": "",
                    "headers": {"content-type": "application/octet-stream"},
                    "body_stream": True,
                },
                body_iter=body_iter(),
            )
        ]
    finally:
        await backend.close()

    assert captured["body"] == b"abcd"
    assert len(messages) == 1
    assert messages[0]["type"] == "service_proxy_response"
    assert messages[0]["status"] == 200
    assert base64.b64decode(messages[0]["body_base64"]) == b"received"


@pytest.mark.asyncio
async def test_service_proxy_client_backend_caller_rejects_unknown_service():
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")

    response = await client.handle_request_message(
        {
            "type": "service_proxy_request",
            "request_id": "req-404",
            "service_name": "missing",
            "method": "GET",
            "path": "/health",
        }
    )

    assert response["type"] == "service_proxy_error"
    assert response["request_id"] == "req-404"
    assert response["error"]["code"] == "service_not_registered"


@pytest.mark.asyncio
async def test_service_proxy_client_backend_caller_maps_backend_failure(monkeypatch):
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")
    client.register_service("fileshare", "http://127.0.0.1:8080")

    class _BrokenSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def request(self, *args, **kwargs):
            raise OSError("backend down")

    monkeypatch.setattr("aun_core.service_proxy.client.aiohttp.ClientSession", lambda *a, **kw: _BrokenSession())

    response = await client.handle_request_message(
        {
            "type": "service_proxy_request",
            "request_id": "req-502",
            "service_name": "fileshare",
            "method": "GET",
            "path": "/health",
        }
    )

    assert response["type"] == "service_proxy_error"
    assert response["request_id"] == "req-502"
    assert response["error"]["code"] == "backend_unreachable"
    assert response["error"]["message"] == "backend request failed"
    assert "127.0.0.1" not in response["error"]["message"]


@pytest.mark.asyncio
async def test_service_proxy_client_iter_backend_failure_does_not_leak_endpoint(monkeypatch):
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")
    client.register_service("fileshare", "http://127.0.0.1:8080")

    class _BrokenSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def request(self, *args, **kwargs):
            raise OSError("Cannot connect to host 127.0.0.1:8080")

    monkeypatch.setattr("aun_core.service_proxy.client.aiohttp.ClientSession", lambda *a, **kw: _BrokenSession())

    messages = [
        item
        async for item in client.iter_request_messages(
            {
                "type": "service_proxy_request",
                "request_id": "req-502",
                "service_name": "fileshare",
                "method": "GET",
                "path": "/health",
            }
        )
    ]

    assert len(messages) == 1
    assert messages[0]["type"] == "service_proxy_error"
    assert messages[0]["error"]["code"] == "backend_unreachable"
    assert messages[0]["error"]["message"] == "backend request failed"
    assert "127.0.0.1" not in messages[0]["error"]["message"]


@pytest.mark.asyncio
async def test_service_proxy_client_non_stream_response_body_limit():
    async def handler(request):
        return web.Response(status=200, body=b"12345")

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", max_response_body_bytes=4)
        client.register_service("fileshare", str(backend.make_url("/root")))

        response = await client.handle_request_message(
            {
                "type": "service_proxy_request",
                "request_id": "req-large",
                "service_name": "fileshare",
                "method": "GET",
                "path": "/large",
            }
        )
    finally:
        await backend.close()

    assert response["type"] == "service_proxy_error"
    assert response["request_id"] == "req-large"
    assert response["error"]["code"] == "response_body_too_large"


@pytest.mark.asyncio
async def test_service_proxy_client_streams_backend_chunks():
    async def handler(request):
        response = web.StreamResponse(status=200, headers={"content-type": "text/event-stream", "x-stream": "1"})
        await response.prepare(request)
        await response.write(b"data: one\n\n")
        await response.write(b"data: two\n\n")
        await response.write_eof()
        return response

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub")
        client.register_service("events", str(backend.make_url("/root")), service_type="sse")

        chunks = [
            item
            async for item in client.stream_request_message(
                {
                    "type": "service_proxy_request",
                    "request_id": "stream-1",
                    "service_name": "events",
                    "method": "GET",
                    "path": "/live",
                    "query_string": "",
                    "headers": {},
                    "body_base64": "",
                },
                chunk_size=8,
            )
        ]
    finally:
        await backend.close()

    assert chunks[0]["type"] == "service_proxy_stream"
    assert chunks[0]["request_id"] == "stream-1"
    assert chunks[0]["status"] == 200
    assert chunks[0]["headers"]["x-stream"] == "1"
    assert chunks[-1]["done"] is True
    body = b"".join(base64.b64decode(item["data_base64"]) for item in chunks)
    assert body == b"data: one\n\ndata: two\n\n"


@pytest.mark.asyncio
async def test_service_proxy_client_stream_single_done_chunk_keeps_data():
    async def handler(request):
        return web.Response(status=200, headers={"content-type": "text/event-stream"}, body=b"data: only\n\n")

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub")
        client.register_service("events", str(backend.make_url("/root")), service_type="sse")

        chunks = [
            item
            async for item in client.stream_request_message(
                {
                    "type": "service_proxy_request",
                    "request_id": "stream-2",
                    "service_name": "events",
                    "method": "GET",
                    "path": "/live",
                },
                chunk_size=65536,
            )
        ]
    finally:
        await backend.close()

    assert len(chunks) == 1
    assert chunks[0]["done"] is True
    assert base64.b64decode(chunks[0]["data_base64"]) == b"data: only\n\n"


@pytest.mark.asyncio
async def test_service_proxy_client_iter_auto_streams_file_response_headers():
    async def handler(request):
        return web.Response(
            status=200,
            headers={
                "content-type": "application/octet-stream",
                "content-disposition": "attachment; filename=report.bin",
            },
            body=b"report-bytes",
        )

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub")
        client.register_service("fileshare", str(backend.make_url("/root")), service_type="http")

        chunks = [
            item
            async for item in client.iter_request_messages(
                {
                    "type": "service_proxy_request",
                    "request_id": "file-1",
                    "service_name": "fileshare",
                    "method": "GET",
                    "path": "/download/report.bin",
                    "headers": {},
                },
                chunk_size=4,
            )
        ]
    finally:
        await backend.close()

    assert all(item["type"] == "service_proxy_stream" for item in chunks)
    assert chunks[0]["headers"]["x-stream-type"] == "file"
    assert chunks[0]["headers"]["content-disposition"] == "attachment; filename=report.bin"
    assert chunks[-1]["done"] is True
    assert b"".join(base64.b64decode(item["data_base64"]) for item in chunks) == b"report-bytes"


@pytest.mark.asyncio
async def test_service_proxy_client_iter_streams_mcp_jsonrpc_request_hint():
    async def handler(request):
        body = await request.read()
        assert b'"jsonrpc"' in body
        return web.Response(
            status=200,
            headers={"content-type": "application/json"},
            body=b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}',
        )

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub")
        client.register_service("mcp", str(backend.make_url("/root")), service_type="http")

        body = base64.b64encode(b'{"jsonrpc":"2.0","method":"tools/list","id":1}').decode("ascii")
        chunks = [
            item
            async for item in client.iter_request_messages(
                {
                    "type": "service_proxy_request",
                    "request_id": "mcp-1",
                    "service_name": "mcp",
                    "method": "POST",
                    "path": "/rpc",
                    "headers": {"content-type": "application/json"},
                    "body_base64": body,
                },
                chunk_size=16,
            )
        ]
    finally:
        await backend.close()

    assert all(item["type"] == "service_proxy_stream" for item in chunks)
    assert chunks[0]["headers"]["x-stream-type"] == "mcp"
    assert chunks[-1]["done"] is True
    assert b"".join(base64.b64decode(item["data_base64"]) for item in chunks) == (
        b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
    )


@pytest.mark.asyncio
async def test_service_proxy_client_iter_no_stream_prevents_response_header_streaming():
    async def handler(request):
        return web.Response(
            status=200,
            headers={"content-type": "text/event-stream"},
            body=b"data: no-stream\n\n",
        )

    backend = await _start_backend(handler)
    try:
        client = ServiceProxyClient(provider_aid="alice.agentid.pub")
        client.register_service(
            "events",
            str(backend.make_url("/root")),
            service_type="sse",
            metadata={"stream_mode": "no_stream"},
        )

        messages = [
            item
            async for item in client.iter_request_messages(
                {
                    "type": "service_proxy_request",
                    "request_id": "nostream-1",
                    "service_name": "events",
                    "method": "GET",
                    "path": "/live",
                    "stream_mode": "no_stream",
                    "headers": {"accept": "text/event-stream"},
                },
                chunk_size=4,
            )
        ]
    finally:
        await backend.close()

    assert len(messages) == 1
    assert messages[0]["type"] == "service_proxy_response"
    assert messages[0]["request_id"] == "nostream-1"
    assert messages[0]["headers"]["content-type"].startswith("text/event-stream")
    assert base64.b64decode(messages[0]["body_base64"]) == b"data: no-stream\n\n"
