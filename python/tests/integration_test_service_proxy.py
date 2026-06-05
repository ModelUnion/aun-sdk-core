import asyncio
import builtins
import importlib.util
import socket
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import pytest
import uvicorn
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestServer

from aun_core.service_proxy import ServiceProxyClient


REPO_ROOT = Path(__file__).resolve().parents[2]
KITE_ROOT = REPO_ROOT.parent
SERVICE_PROXY_ENTRY = KITE_ROOT / "extensions" / "services" / "service_proxy" / "entry.py"
NAMESERVICE_ENTRY = KITE_ROOT / "extensions" / "services" / "nameservice" / "server.py"


class _FakeSubscription:
    def __init__(self, owner, event: str, handler):
        self.owner = owner
        self.event = event
        self.handler = handler

    def unsubscribe(self):
        handlers = self.owner.handlers.get(self.event, [])
        self.owner.handlers[self.event] = [item for item in handlers if item is not self.handler]


class _FakeAUNClient:
    def __init__(self, *, access_token: str = "gateway-token"):
        self.access_token = access_token
        self.handlers = {}

    def on(self, event: str, handler):
        self.handlers.setdefault(event, []).append(handler)
        return _FakeSubscription(self, event, handler)

    async def publish(self, event: str, payload):
        for handler in list(self.handlers.get(event, [])):
            result = handler(payload)
            if hasattr(result, "__await__"):
                await result


def _patch_proxy_discovery(client: ServiceProxyClient, proxy_port: int) -> None:
    async def _discover_proxy_ws_url(*, force_refresh: bool = False, timeout: float = 5.0) -> str:
        return f"ws://127.0.0.1:{proxy_port}/ws/client"

    client.discover_proxy_ws_url = _discover_proxy_ws_url


def _load_service_entry(path: Path, *, prefix: str):
    unique_name = f"{prefix}_e2e_{uuid.uuid4().hex}"
    old_print = builtins.print
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    old_sys_path = list(sys.path)
    old_sys_modules = set(sys.modules.keys())

    service_dir = str(path.parent)
    if service_dir not in sys.path:
        sys.path.insert(0, service_dir)

    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载服务模块: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        builtins.print = old_print
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        sys.path[:] = old_sys_path
        norm_service_dir = str(path.parent).lower()
        for key in set(sys.modules.keys()) - old_sys_modules:
            item = sys.modules.get(key)
            item_file = str(getattr(item, "__file__", "") or "").lower()
            if item_file.startswith(norm_service_dir):
                sys.modules.pop(key, None)


def _load_service_proxy_module():
    return _load_service_entry(SERVICE_PROXY_ENTRY, prefix="service_proxy")


def _load_nameservice_module():
    return _load_service_entry(NAMESERVICE_ENTRY, prefix="nameservice")


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _start_fastapi_app(app, *, port: int):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None
    task = asyncio.create_task(server.serve())
    async with aiohttp.ClientSession() as session:
        deadline = asyncio.get_running_loop().time() + 3.0
        while asyncio.get_running_loop().time() < deadline:
            try:
                async with session.get(f"http://127.0.0.1:{port}/health") as response:
                    if response.status == 200:
                        return server, task
            except aiohttp.ClientError:
                await asyncio.sleep(0.02)
        server.should_exit = True
        raise AssertionError("service_proxy server did not become ready")


async def _stop_fastapi_server(server, task) -> None:
    server.should_exit = True
    try:
        await asyncio.wait_for(task, timeout=3.0)
    except asyncio.TimeoutError:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


async def _start_service_proxy(*, issuer_domain: str, authenticated_aid: str, **server_kwargs):
    module = _load_service_proxy_module()
    port = _unused_port()
    proxy = module.ServiceProxyServer(
        token="",
        kernel_port=0,
        host="127.0.0.1",
        port=port,
        issuer_domain=issuer_domain,
        request_timeout_seconds=2.0,
        authenticated_aid_resolver=lambda _ws: authenticated_aid,
        **server_kwargs,
    )
    uvicorn_server, task = await _start_fastapi_app(proxy.app, port=port)
    return proxy, port, uvicorn_server, task


async def _start_nameservice(*, issuer_domain: str):
    module = _load_nameservice_module()
    port = _unused_port()
    nameservice = module.NameServiceServer(
        token="",
        kernel_port=0,
        issuer_domain=issuer_domain,
        gateway_url=f"wss://gateway.{issuer_domain}/aun",
    )
    uvicorn_server, task = await _start_fastapi_app(nameservice.app, port=port)
    return nameservice, port, uvicorn_server, task


async def _wait_registered_service(port: int, *, expected_services: int = 1) -> dict:
    async with aiohttp.ClientSession() as session:
        deadline = asyncio.get_running_loop().time() + 3.0
        while asyncio.get_running_loop().time() < deadline:
            async with session.get(f"http://127.0.0.1:{port}/health") as response:
                body = await response.json()
            if body["connections"]["services"] >= expected_services:
                return body
            await asyncio.sleep(0.02)
    raise AssertionError("service_proxy client did not register services")


async def _wait_wakeup_subscription(aun_client: _FakeAUNClient) -> None:
    deadline = asyncio.get_running_loop().time() + 3.0
    while asyncio.get_running_loop().time() < deadline:
        if aun_client.handlers.get("app.service_proxy.wakeup"):
            return
        await asyncio.sleep(0.01)
    raise AssertionError("service_proxy client did not subscribe wakeup event")


async def _start_http_backend(handler):
    app = web.Application()
    app.router.add_route("*", "/root/{tail:.*}", handler)
    server = TestServer(app)
    await server.start_server()
    return server


async def _start_ws_backend(handler):
    app = web.Application()
    app.router.add_get("/root/{tail:.*}", handler)
    server = TestServer(app)
    await server.start_server()
    return server


def _ws_url(server, path="/root") -> str:
    return str(server.make_url(path)).replace("http://", "ws://", 1).replace("https://", "wss://", 1)


def _proxy_local_url(location: str, *, proxy_port: int) -> tuple[str, str]:
    parsed = urlparse(location)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return f"http://127.0.0.1:{proxy_port}{path}", parsed.netloc


@pytest.mark.asyncio
async def test_service_proxy_single_domain_http_e2e_round_trip_and_metrics():
    captured = {}

    async def handler(request):
        captured["method"] = request.method
        captured["path_qs"] = request.path_qs
        captured["body"] = await request.read()
        captured["x_trace"] = request.headers.get("x-trace-id")
        captured["x_aun_provider"] = request.headers.get("x-aun-provider-aid")
        captured["x_aun_service"] = request.headers.get("x-aun-service-name")
        captured["x_forwarded_prefix"] = request.headers.get("x-forwarded-prefix")
        return web.Response(status=202, headers={"x-backend": "ok"}, body=b'{"ok":true}')

    backend = await _start_http_backend(handler)
    proxy_server = None
    proxy_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="alice.agentid.pub",
        )
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("fileshare", str(backend.make_url("/root")), visibility="public")
        serve_task = asyncio.create_task(client.serve_once(max_requests=1))
        await _wait_registered_service(proxy_port)

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{proxy_port}/alice/fileshare/health?x=1",
                headers={"Host": "proxy.agentid.pub", "x-trace-id": "trace-1"},
                data=b'{"name":"demo"}',
            ) as response:
                assert response.status == 202
                assert response.headers["x-backend"] == "ok"
                assert await response.read() == b'{"ok":true}'

            async with session.get(f"http://127.0.0.1:{proxy_port}/health") as response:
                health = await response.json()

        result = await asyncio.wait_for(serve_task, timeout=3.0)
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()

    assert result == {"registered": 1, "handled_requests": 1}
    assert captured == {
        "method": "POST",
        "path_qs": "/root/health?x=1",
        "body": b'{"name":"demo"}',
        "x_trace": "trace-1",
        "x_aun_provider": "alice.agentid.pub",
        "x_aun_service": "fileshare",
        "x_forwarded_prefix": "/alice/fileshare",
    }
    assert health["metrics"]["http_requests_total"] == 1
    assert health["metrics"]["http_errors_total"] == 0
    assert health["metrics"]["http_last_status"] == 202


@pytest.mark.asyncio
async def test_service_proxy_on_demand_wakeup_e2e_offline_provider_registers_and_forwards():
    captured = {}
    wakeups = []
    tokens = []
    fake_aun = _FakeAUNClient(access_token="gateway-token")
    proxy_port = 0

    async def handler(request):
        captured["method"] = request.method
        captured["path_qs"] = request.path_qs
        captured["x_aun_provider"] = request.headers.get("x-aun-provider-aid")
        captured["x_aun_service"] = request.headers.get("x-aun-service-name")
        return web.Response(status=200, headers={"x-backend": "awake"}, body=b"awake")

    async def send_wakeup(provider_aid, payload):
        wakeups.append((provider_aid, dict(payload)))
        local_payload = dict(payload)
        local_payload["proxy_url"] = f"ws://127.0.0.1:{proxy_port}/ws/client"
        await fake_aun.publish("app.service_proxy.wakeup", local_payload)

    def resolve_token(token, _ws):
        tokens.append(token)
        return "alice.agentid.pub" if token == "gateway-token" else ""

    backend = await _start_http_backend(handler)
    proxy_server = None
    proxy_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="",
            access_token_aid_resolver=resolve_token,
            wakeup_sender=send_wakeup,
            wakeup_timeout_seconds=2.0,
            wakeup_cooldown_seconds=0.0,
        )
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=fake_aun)
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("fileshare", str(backend.make_url("/root")), visibility="public")
        serve_task = asyncio.create_task(
            client.serve_forever(
                connection_mode="on_demand",
                idle_timeout_seconds=0.05,
                reconnect_delay_seconds=0.01,
            )
        )
        await _wait_wakeup_subscription(fake_aun)

        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{proxy_port}/health") as response:
                before = await response.json()
            assert before["connections"]["services"] == 0

            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/fileshare/health?x=1",
                headers={"Host": "proxy.agentid.pub"},
            ) as response:
                assert response.status == 200
                assert response.headers["x-backend"] == "awake"
                assert await response.read() == b"awake"

            async with session.get(f"http://127.0.0.1:{proxy_port}/health") as response:
                after = await response.json()

        client.stop()
        result = await asyncio.wait_for(serve_task, timeout=3.0)
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()

    assert len(wakeups) == 1
    provider_aid, payload = wakeups[0]
    assert provider_aid == "alice.agentid.pub"
    assert payload["type"] == "aun.service_proxy.wakeup"
    assert payload["request_kind"] == "http"
    assert payload["service_name"] == "fileshare"
    assert payload["proxy_url"] == "wss://proxy.agentid.pub/ws/client"
    assert tokens == ["gateway-token"]
    assert result["connection_mode"] == "on_demand"
    assert result["wakeup_count"] == 1
    assert result["connections"] == 1
    assert result["registered"] == 1
    assert result["handled_requests"] == 1
    assert after["metrics"]["wakeup_requests_total"] == 1
    assert after["metrics"]["wakeup_errors_total"] == 0
    assert captured == {
        "method": "GET",
        "path_qs": "/root/health?x=1",
        "x_aun_provider": "alice.agentid.pub",
        "x_aun_service": "fileshare",
    }


@pytest.mark.asyncio
async def test_service_proxy_nameservice_redirect_visitor_http_e2e_get_and_post(monkeypatch):
    captured = []

    async def handler(request):
        captured.append({
            "method": request.method,
            "path_qs": request.path_qs,
            "body": await request.read(),
            "x_aun_provider": request.headers.get("x-aun-provider-aid"),
            "x_aun_service": request.headers.get("x-aun-service-name"),
        })
        return web.Response(status=200, headers={"x-backend": "fileshare"}, body=f"{request.method}:{request.path_qs}".encode())

    backend = await _start_http_backend(handler)
    proxy_server = None
    proxy_task = None
    ns_server = None
    ns_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="alice.agentid.pub",
        )
        monkeypatch.setenv("AUN_SERVICE_PROXY_PORT", str(proxy_port))
        _ns, ns_port, ns_server, ns_task = await _start_nameservice(issuer_domain="agentid.pub")

        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("fileshare", str(backend.make_url("/root")), visibility="public")
        serve_task = asyncio.create_task(client.serve_once(max_requests=3))
        await _wait_registered_service(proxy_port)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{ns_port}/proxy/fileshare/health?x=1",
                headers={"Host": "alice.agentid.pub"},
                allow_redirects=False,
            ) as redirect:
                assert redirect.status == 302
                assert redirect.headers["location"] == "https://proxy.agentid.pub/alice/fileshare/health?x=1"
                proxy_url, proxy_host = _proxy_local_url(redirect.headers["location"], proxy_port=proxy_port)

            async with session.get(proxy_url, headers={"Host": proxy_host}) as response:
                assert response.status == 200
                assert await response.read() == b"GET:/root/health?x=1"

            async with session.post(
                f"http://127.0.0.1:{ns_port}/proxy/fileshare/upload?token=abc",
                headers={"Host": "alice.agentid.pub"},
                data=b"payload",
                allow_redirects=False,
            ) as redirect:
                assert redirect.status == 307
                assert redirect.headers["location"] == "https://proxy.agentid.pub/alice/fileshare/upload?token=abc"
                proxy_url, proxy_host = _proxy_local_url(redirect.headers["location"], proxy_port=proxy_port)

            async with session.post(proxy_url, headers={"Host": proxy_host}, data=b"payload") as response:
                assert response.status == 200
                assert await response.read() == b"POST:/root/upload?token=abc"

            async with session.get(
                f"http://127.0.0.1:{ns_port}/alice/fileshare/direct?z=9",
                headers={"Host": "proxy.agentid.pub"},
                allow_redirects=False,
            ) as redirect:
                assert redirect.status == 302
                assert redirect.headers["location"] == f"https://proxy.agentid.pub:{proxy_port}/alice/fileshare/direct?z=9"
                proxy_url, proxy_host = _proxy_local_url(redirect.headers["location"], proxy_port=proxy_port)

            async with session.get(proxy_url, headers={"Host": proxy_host}) as response:
                assert response.status == 200
                assert await response.read() == b"GET:/root/direct?z=9"

        assert await asyncio.wait_for(serve_task, timeout=3.0) == {"registered": 1, "handled_requests": 3}
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if ns_server is not None and ns_task is not None:
            await _stop_fastapi_server(ns_server, ns_task)
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()

    assert captured == [
        {
            "method": "GET",
            "path_qs": "/root/health?x=1",
            "body": b"",
            "x_aun_provider": "alice.agentid.pub",
            "x_aun_service": "fileshare",
        },
        {
            "method": "POST",
            "path_qs": "/root/upload?token=abc",
            "body": b"payload",
            "x_aun_provider": "alice.agentid.pub",
            "x_aun_service": "fileshare",
        },
        {
            "method": "GET",
            "path_qs": "/root/direct?z=9",
            "body": b"",
            "x_aun_provider": "alice.agentid.pub",
            "x_aun_service": "fileshare",
        },
    ]


@pytest.mark.asyncio
async def test_service_proxy_sse_e2e_streams_by_service_type_accept_header_and_backend_content_type():
    async def handler(request):
        response = web.StreamResponse(status=200, headers={"content-type": "text/event-stream", "x-stream": request.match_info["tail"]})
        await response.prepare(request)
        await response.write(f"data: {request.match_info['tail']}-one\n\n".encode())
        await response.write(f"data: {request.match_info['tail']}-two\n\n".encode())
        await response.write_eof()
        return response

    backend = await _start_http_backend(handler)
    proxy_server = None
    proxy_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="alice.agentid.pub",
        )
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("events", str(backend.make_url("/root")), service_type="sse", visibility="public")
        client.register_service("autoevents", str(backend.make_url("/root")), service_type="http", visibility="public")
        client.register_service("contentevents", str(backend.make_url("/root")), service_type="http", visibility="public")
        serve_task = asyncio.create_task(client.serve_once(max_requests=3))
        await _wait_registered_service(proxy_port, expected_services=3)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/events/live",
                headers={"Host": "proxy.agentid.pub"},
            ) as response:
                assert response.status == 200
                assert response.headers["x-stream"] == "live"
                assert response.headers["x-stream-type"] == "sse"
                assert await response.read() == b"data: live-one\n\ndata: live-two\n\n"

            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/autoevents/auto",
                headers={"Host": "proxy.agentid.pub", "Accept": "text/event-stream"},
            ) as response:
                assert response.status == 200
                assert response.headers["x-stream"] == "auto"
                assert response.headers["x-stream-type"] == "sse"
                assert await response.read() == b"data: auto-one\n\ndata: auto-two\n\n"

            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/contentevents/ctype",
                headers={"Host": "proxy.agentid.pub"},
            ) as response:
                assert response.status == 200
                assert response.headers["x-stream"] == "ctype"
                assert response.headers["x-stream-type"] == "sse"
                assert await response.read() == b"data: ctype-one\n\ndata: ctype-two\n\n"

        assert await asyncio.wait_for(serve_task, timeout=3.0) == {"registered": 3, "handled_requests": 3}
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()


@pytest.mark.asyncio
async def test_service_proxy_protocol_detection_e2e_rest_mcp_file_and_no_stream():
    captured = []

    async def handler(request):
        body = await request.read()
        captured.append({
            "method": request.method,
            "path_qs": request.path_qs,
            "body": body,
            "accept": request.headers.get("accept"),
            "x_aun_service": request.headers.get("x-aun-service-name"),
        })
        tail = request.match_info["tail"]
        if tail == "status":
            return web.json_response({"ok": True, "path": request.path_qs})
        if tail == "rpc":
            assert b'"jsonrpc"' in body
            return web.Response(
                status=200,
                headers={"content-type": "application/json"},
                body=b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}',
            )
        if tail == "download/report.bin":
            return web.Response(
                status=200,
                headers={
                    "content-type": "application/octet-stream",
                    "content-disposition": "attachment; filename=report.bin",
                },
                body=b"report-bytes",
            )
        if tail == "live":
            return web.Response(
                status=200,
                headers={"content-type": "text/event-stream"},
                body=b"data: no-stream\n\n",
            )
        return web.Response(status=404, body=b"not found")

    backend = await _start_http_backend(handler)
    proxy_server = None
    proxy_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="alice.agentid.pub",
        )
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("restapi", str(backend.make_url("/root")), service_type="http", visibility="public")
        client.register_service("mcp", str(backend.make_url("/root")), service_type="http", visibility="public")
        client.register_service("files", str(backend.make_url("/root")), service_type="http", visibility="public")
        client.register_service(
            "nostream",
            str(backend.make_url("/root")),
            service_type="sse",
            visibility="public",
            metadata={"stream_mode": "no_stream"},
        )
        serve_task = asyncio.create_task(client.serve_once(max_requests=4))
        await _wait_registered_service(proxy_port, expected_services=4)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/restapi/status",
                headers={"Host": "proxy.agentid.pub"},
            ) as response:
                assert response.status == 200
                assert (await response.json())["path"] == "/root/status"
                assert "x-stream-type" not in response.headers

            async with session.post(
                f"http://127.0.0.1:{proxy_port}/alice/mcp/rpc",
                headers={"Host": "proxy.agentid.pub", "content-type": "application/json"},
                data=b'{"jsonrpc":"2.0","method":"tools/list","id":1}',
            ) as response:
                assert response.status == 200
                assert response.headers["x-stream-type"] == "mcp"
                assert await response.read() == b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'

            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/files/download/report.bin",
                headers={"Host": "proxy.agentid.pub"},
            ) as response:
                assert response.status == 200
                assert response.headers["x-stream-type"] == "file"
                assert response.headers["content-disposition"] == "attachment; filename=report.bin"
                assert await response.read() == b"report-bytes"

            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/nostream/live",
                headers={"Host": "proxy.agentid.pub", "accept": "text/event-stream"},
            ) as response:
                assert response.status == 200
                assert response.headers["content-type"].startswith("text/event-stream")
                assert "x-stream-type" not in response.headers
                assert await response.read() == b"data: no-stream\n\n"

        assert await asyncio.wait_for(serve_task, timeout=3.0) == {"registered": 4, "handled_requests": 4}
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()

    assert [item["x_aun_service"] for item in captured] == ["restapi", "mcp", "files", "nostream"]
    assert captured[1]["body"] == b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
    assert captured[2]["path_qs"] == "/root/download/report.bin"
    assert captured[3]["accept"] == "text/event-stream"


@pytest.mark.asyncio
async def test_service_proxy_web_e2e_host_root_and_path_prefix_modes():
    captured = []

    async def handler(request):
        captured.append({
            "path_qs": request.path_qs,
            "x_forwarded_prefix": request.headers.get("x-forwarded-prefix"),
            "x_forwarded_host": request.headers.get("x-forwarded-host"),
        })
        return web.json_response(captured[-1])

    backend = await _start_http_backend(handler)
    proxy_server = None
    proxy_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="alice.agentid.pub",
        )
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("web", str(backend.make_url("/root")), service_type="web", visibility="public")
        serve_task = asyncio.create_task(client.serve_once(max_requests=2))
        await _wait_registered_service(proxy_port)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/assets/app.js?v=1",
                headers={"Host": "web-alice.agentid.pub"},
            ) as response:
                assert response.status == 200
                body = await response.json()
                assert body["path_qs"] == "/root/assets/app.js?v=1"
                assert body["x_forwarded_prefix"] is None
                assert body["x_forwarded_host"] == "web-alice.agentid.pub"

            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/web/dashboard?tab=home",
                headers={"Host": "proxy.agentid.pub"},
            ) as response:
                assert response.status == 200
                body = await response.json()
                assert body["path_qs"] == "/root/dashboard?tab=home"
                assert body["x_forwarded_prefix"] == "/alice/web"
                assert body["x_forwarded_host"] == "proxy.agentid.pub"

        assert await asyncio.wait_for(serve_task, timeout=3.0) == {"registered": 1, "handled_requests": 2}
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()


@pytest.mark.asyncio
async def test_service_proxy_aun_auth_visibility_e2e_requires_requester_and_forwards_aid():
    captured = {}

    async def handler(request):
        captured["requester"] = request.headers.get("x-aun-requester-aid")
        return web.Response(status=200, body=b"auth-ok")

    backend = await _start_http_backend(handler)
    proxy_server = None
    proxy_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="alice.agentid.pub",
            requester_aid_resolver=lambda request: request.headers.get("x-visitor-aid", ""),
        )
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("secure", str(backend.make_url("/root")), service_type="http", visibility="aun-auth")
        serve_task = asyncio.create_task(client.serve_once(max_requests=1))
        await _wait_registered_service(proxy_port)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/secure/data",
                headers={"Host": "proxy.agentid.pub"},
            ) as response:
                assert response.status == 401
                assert (await response.json())["error"] == "requester_auth_required"

            async with session.get(
                f"http://127.0.0.1:{proxy_port}/alice/secure/data",
                headers={"Host": "proxy.agentid.pub", "x-visitor-aid": "visitor.agentid.pub"},
            ) as response:
                assert response.status == 200
                assert await response.read() == b"auth-ok"

        assert await asyncio.wait_for(serve_task, timeout=3.0) == {"registered": 1, "handled_requests": 1}
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()

    assert captured == {"requester": "visitor.agentid.pub"}


@pytest.mark.asyncio
async def test_service_proxy_single_domain_websocket_e2e_round_trip():
    captured = {}

    async def handler(request):
        captured["path_qs"] = request.path_qs
        captured["x_aun_provider"] = request.headers.get("x-aun-provider-aid")
        captured["x_aun_service"] = request.headers.get("x-aun-service-name")
        ws = web.WebSocketResponse(protocols=("chat.v1",))
        await ws.prepare(request)
        captured["subprotocol"] = ws.ws_protocol
        async for message in ws:
            if message.type == WSMsgType.TEXT:
                await ws.send_str(f"echo:{message.data}")
            elif message.type == WSMsgType.BINARY:
                await ws.send_bytes(b"echo:" + message.data)
        captured["closed"] = True
        return ws

    backend = await _start_ws_backend(handler)
    proxy_server = None
    proxy_task = None
    serve_task = None
    try:
        _proxy, proxy_port, proxy_server, proxy_task = await _start_service_proxy(
            issuer_domain="agentid.pub",
            authenticated_aid="alice.agentid.pub",
        )
        client = ServiceProxyClient(provider_aid="alice.agentid.pub", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, proxy_port)
        client.register_service("chat", _ws_url(backend), service_type="websocket", visibility="public")
        serve_task = asyncio.create_task(client.serve_once(max_requests=1))
        await _wait_registered_service(proxy_port)

        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(
                f"ws://127.0.0.1:{proxy_port}/alice/chat/socket?room=1",
                headers={"Host": "proxy.agentid.pub"},
                protocols=("chat.v1",),
            ) as ws:
                assert ws.protocol == "chat.v1"
                await ws.send_str("hello")
                text_message = await ws.receive(timeout=2.0)
                assert text_message.type == WSMsgType.TEXT
                assert text_message.data == "echo:hello"

                await ws.send_bytes(b"\x01\x02")
                binary_message = await ws.receive(timeout=2.0)
                assert binary_message.type == WSMsgType.BINARY
                assert binary_message.data == b"echo:\x01\x02"

        result = await asyncio.wait_for(serve_task, timeout=3.0)
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if proxy_server is not None and proxy_task is not None:
            await _stop_fastapi_server(proxy_server, proxy_task)
        await backend.close()

    assert result == {"registered": 1, "handled_requests": 1}
    assert captured == {
        "path_qs": "/root/socket?room=1",
        "x_aun_provider": "alice.agentid.pub",
        "x_aun_service": "chat",
        "subprotocol": "chat.v1",
        "closed": True,
    }


@pytest.mark.asyncio
async def test_service_proxy_dual_domain_does_not_route_provider_across_issuer_boundary():
    async def handler(_request):
        return web.Response(status=200, body=b"net-ok")

    backend = await _start_http_backend(handler)
    aid_net_server = None
    aid_net_task = None
    aid_com_server = None
    aid_com_task = None
    serve_task = None
    try:
        _net_proxy, aid_net_port, aid_net_server, aid_net_task = await _start_service_proxy(
            issuer_domain="aid.net",
            authenticated_aid="bob.aid.net",
        )
        _com_proxy, aid_com_port, aid_com_server, aid_com_task = await _start_service_proxy(
            issuer_domain="aid.com",
            authenticated_aid="bob.aid.com",
        )

        client = ServiceProxyClient(provider_aid="bob.aid.net", aun_client=_FakeAUNClient(access_token="gateway-token"))
        _patch_proxy_discovery(client, aid_net_port)
        client.register_service("fileshare", str(backend.make_url("/root")), visibility="public")
        serve_task = asyncio.create_task(client.serve_once(max_requests=1))
        await _wait_registered_service(aid_net_port)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{aid_net_port}/bob/fileshare/ok",
                headers={"Host": "proxy.aid.net"},
            ) as response:
                assert response.status == 200
                assert await response.read() == b"net-ok"

            async with session.get(
                f"http://127.0.0.1:{aid_com_port}/bob/fileshare/ok",
                headers={"Host": "proxy.aid.com"},
            ) as response:
                assert response.status == 503
                assert (await response.json())["error"] == "provider_offline"

        await asyncio.wait_for(serve_task, timeout=3.0)
    finally:
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
        if aid_net_server is not None and aid_net_task is not None:
            await _stop_fastapi_server(aid_net_server, aid_net_task)
        if aid_com_server is not None and aid_com_task is not None:
            await _stop_fastapi_server(aid_com_server, aid_com_task)
        await backend.close()
