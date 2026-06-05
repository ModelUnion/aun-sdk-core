#!/usr/bin/env python3
"""Service Proxy 单域 Docker E2E。

运行环境：
  docker exec kite-sdk-tester python /tests/e2e_test_service_proxy_docker.py

前置条件：
  - Docker 镜像包含并启用了 service_proxy 模块。
  - kite 容器在 Docker 网络内可通过 proxy.{issuer}:19890 访问 service_proxy。
  - service_proxy 的 /ws/client 已接入真实 AUN 身份认证，允许 SDK provider 建立隧道。
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
from aiohttp import WSMsgType, web

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.errors import AuthError
from aun_core.service_proxy import ServiceProxyClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

os.environ.setdefault("AUN_ENV", "development")

ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
PROVIDER_USER = (
    os.environ.get("AUN_SERVICE_PROXY_PROVIDER_USER", "").strip().lower()
    or f"sp{os.getpid()}{time.time_ns() % 1_000_000_000}"
)
PROVIDER_AID = f"{PROVIDER_USER}.{ISSUER}"
PROXY_HOST = os.environ.get("AUN_SERVICE_PROXY_HOST", f"proxy.{ISSUER}").strip() or f"proxy.{ISSUER}"
PROXY_PORT = int(os.environ.get("AUN_SERVICE_PROXY_PORT", "19890") or "19890")
PROXY_HTTP = f"https://{PROXY_HOST}:{PROXY_PORT}"
PROXY_WS_EXTERNAL = f"wss://{PROXY_HOST}:{PROXY_PORT}"
CONNECTION_MODE = os.environ.get("AUN_SERVICE_PROXY_CONNECTION_MODE", "persistent").strip().lower() or "persistent"
ON_DEMAND_IDLE_TIMEOUT_SECONDS = float(os.environ.get("AUN_SERVICE_PROXY_IDLE_TIMEOUT_SECONDS", "0.5") or "0.5")
_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_PROVIDER_AUN_PATH = os.environ.get(
    "AUN_SERVICE_PROXY_PROVIDER_AUN_PATH",
    f"{_AUN_DATA_ROOT}/single-domain/service-proxy-provider" if _AUN_DATA_ROOT else "./.aun_service_proxy_provider",
).strip()
_REQUIRED_FEATURES = ("http_proxy", "tunnel", "websocket_bridge")
_EXPECTED_SERVICES = 9
_EXPECTED_REQUESTS = 18
_LARGE_FILE_BYTES = (b"0123456789abcdef" * 10240) + b"end"

if CONNECTION_MODE not in {"persistent", "on_demand"}:
    raise RuntimeError("AUN_SERVICE_PROXY_CONNECTION_MODE must be persistent or on_demand")


async def _preflight(session: aiohttp.ClientSession) -> None:
    try:
        async with session.get(f"{PROXY_HTTP}/health", timeout=aiohttp.ClientTimeout(total=3)) as resp:
            body = await resp.json()
    except Exception as exc:
        raise RuntimeError(
            f"service_proxy 不可达: {PROXY_HTTP}/health; "
            "请确认 service_proxy 模块已启用、镜像已重建、compose 已包含 proxy.{issuer} alias"
        ) from exc
    if body.get("module") != "service_proxy":
        raise RuntimeError(f"service_proxy health 响应异常: {body!r}")
    features = body.get("features") if isinstance(body.get("features"), dict) else {}
    required = list(_REQUIRED_FEATURES)
    if CONNECTION_MODE == "on_demand":
        required.extend(["access_token_auth", "on_demand_wakeup"])
    missing = [name for name in required if not features.get(name)]
    if missing:
        raise RuntimeError(f"service_proxy health 缺少必要能力 {missing}: {body!r}")


def _raise_if_serve_task_done(serve_task: asyncio.Task) -> None:
    if not serve_task.done():
        return
    try:
        result = serve_task.result()
    except AuthError as exc:
        raise RuntimeError(
            "service_proxy /ws/client 认证失败；请先接入真实 AUN provider 身份认证 resolver，"
            "确保 SDK provider 的 AID 能绑定到隧道认证身份"
        ) from exc
    except asyncio.CancelledError as exc:
        raise RuntimeError("service-proxy-client 隧道任务被提前取消") from exc
    except Exception as exc:
        raise RuntimeError(f"service-proxy-client 隧道任务提前失败: {type(exc).__name__}: {exc}") from exc
    raise RuntimeError(f"service-proxy-client 隧道任务提前结束，服务尚未注册: {result!r}")


async def _start_backends():
    async def http_handler(request: web.Request) -> web.Response:
        body = await request.read()
        tail = request.match_info["tail"]
        if tail == "headers":
            return web.Response(
                status=200,
                headers={"content-type": "text/plain", "x-header-check": "ok"},
                body=(
                    f"trace={request.headers.get('x-trace-id', '')};"
                    f"spoof={request.headers.get('x-aun-spoof', '')};"
                    f"provider={request.headers.get('x-aun-provider-aid', '')};"
                    f"service={request.headers.get('x-aun-service-name', '')};"
                    f"prefix={request.headers.get('x-forwarded-prefix', '')};"
                    f"host={request.headers.get('x-forwarded-host', '')}"
                ).encode(),
            )
        if tail == "rpc":
            if b'"jsonrpc"' not in body:
                return web.Response(status=400, body=b"missing jsonrpc")
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
        if tail == "download/large.bin":
            return web.Response(
                status=200,
                headers={"content-type": "application/octet-stream"},
                body=_LARGE_FILE_BYTES,
            )
        if tail == "download/range.bin":
            payload = b"abcdefghijklmnopqrstuvwxyz"
            if request.headers.get("range") == "bytes=4-9":
                return web.Response(
                    status=206,
                    headers={
                        "content-type": "application/octet-stream",
                        "content-range": "bytes 4-9/26",
                    },
                    body=payload[4:10],
                )
            return web.Response(status=200, headers={"content-type": "application/octet-stream"}, body=payload)
        if tail == "status/404":
            return web.Response(status=404, headers={"x-backend-status": "missing"}, body=b"missing")
        return web.Response(
            status=200,
            headers={"x-provider": "http"},
            body=f"{request.method}:{request.path_qs}:{body.decode()}".encode(),
        )

    async def no_stream_handler(request: web.Request) -> web.Response:
        return web.Response(
            status=200,
            headers={"content-type": "text/event-stream"},
            body=b"data: no-stream\n\n",
        )

    async def sse_handler(request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(status=200, headers={"content-type": "text/event-stream"})
        await response.prepare(request)
        await response.write(b"data: one\n\n")
        await response.write(b"data: two\n\n")
        await response.write_eof()
        return response

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(protocols=("chat.v1",))
        await ws.prepare(request)
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                await ws.send_str(f"echo:{msg.data}")
            elif msg.type == WSMsgType.BINARY:
                await ws.send_bytes(b"echo:" + msg.data)
        return ws

    app = web.Application()
    app.router.add_route("*", "/http/{tail:.*}", http_handler)
    app.router.add_get("/nostream/{tail:.*}", no_stream_handler)
    app.router.add_get("/sse/{tail:.*}", sse_handler)
    app.router.add_get("/ws/{tail:.*}", ws_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    sockets = getattr(site, "_server").sockets
    port = int(sockets[0].getsockname()[1])
    return runner, port


async def _wait_registered(session: aiohttp.ClientSession, expected: int, serve_task: asyncio.Task) -> None:
    deadline = asyncio.get_running_loop().time() + 5
    last_health = None
    while asyncio.get_running_loop().time() < deadline:
        _raise_if_serve_task_done(serve_task)
        async with session.get(f"{PROXY_HTTP}/health") as resp:
            body = await resp.json()
        last_health = body
        if body.get("connections", {}).get("services", 0) >= expected:
            return
        await asyncio.sleep(0.1)
    _raise_if_serve_task_done(serve_task)
    raise RuntimeError(f"service-proxy-client 未在 service_proxy 注册服务，最后 health={last_health!r}")


async def _connect_provider_aun_client() -> AUNClient:
    client = make_client_for_path(_PROVIDER_AUN_PATH, debug=False, require_forward_secrecy=False)
    await ensure_connected_identity(client, PROVIDER_AID, connect_options={"auto_reconnect": False})
    await asyncio.sleep(0.3)
    return client


def _register_test_services(client: ServiceProxyClient, backend_port: int) -> None:
    client.register_service("fileshare", f"http://127.0.0.1:{backend_port}/http", visibility="public")
    client.register_service("mcp", f"http://127.0.0.1:{backend_port}/http", service_type="http", visibility="public")
    client.register_service("files", f"http://127.0.0.1:{backend_port}/http", service_type="http", visibility="public")
    client.register_service("broken", "http://127.0.0.1:1/unreachable", service_type="http", visibility="public")
    client.register_service("secret", f"http://127.0.0.1:{backend_port}/http", service_type="http", visibility="private")
    client.register_service("authonly", f"http://127.0.0.1:{backend_port}/http", service_type="http", visibility="aun-auth")
    client.register_service(
        "nostream",
        f"http://127.0.0.1:{backend_port}/nostream",
        service_type="sse",
        visibility="public",
        metadata={"stream_mode": "no_stream"},
    )
    client.register_service("events", f"http://127.0.0.1:{backend_port}/sse", service_type="sse", visibility="public")
    client.register_service("chat", f"ws://127.0.0.1:{backend_port}/ws", service_type="websocket", visibility="public")


def _proxy_url_from_location(location: str) -> str:
    parsed = urlparse(location)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return f"{PROXY_HTTP}{path}"


async def _run_visitor_checks(session: aiohttp.ClientSession) -> None:
    async with session.get(
        f"https://{PROVIDER_AID}/proxy/fileshare/health?x=1",
        ssl=False,
        allow_redirects=False,
    ) as redirect:
        if redirect.status != 302:
            raise AssertionError(f"NameService GET proxy redirect status={redirect.status}")
        proxy_url = _proxy_url_from_location(redirect.headers["location"])

    async with session.get(proxy_url, headers={"Host": PROXY_HOST}) as resp:
        body = await resp.read()
        if resp.status != 200 or body != b"GET:/http/health?x=1:":
            raise AssertionError(f"HTTP proxy failed status={resp.status} body={body!r}")

    async with session.post(
        f"https://{PROVIDER_AID}/proxy/fileshare/upload?token=abc",
        ssl=False,
        allow_redirects=False,
        data=b"payload",
    ) as redirect:
        if redirect.status != 307:
            raise AssertionError(f"NameService POST proxy redirect status={redirect.status}")
        proxy_url = _proxy_url_from_location(redirect.headers["location"])

    async with session.post(proxy_url, headers={"Host": PROXY_HOST}, data=b"payload") as resp:
        body = await resp.read()
        if resp.status != 200 or body != b"POST:/http/upload?token=abc:payload":
            raise AssertionError(f"POST proxy failed status={resp.status} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/root?view=home",
        headers={"Host": f"fileshare-{PROVIDER_USER}.{ISSUER}"},
    ) as resp:
        body = await resp.read()
        if resp.status != 200 or body != b"GET:/http/root?view=home:":
            raise AssertionError(f"host-root proxy failed status={resp.status} body={body!r}")

    async with session.put(
        f"{PROXY_HTTP}/{PROVIDER_USER}/fileshare/items/42?mode=replace",
        headers={"Host": PROXY_HOST, "content-type": "text/plain"},
        data=b"updated",
    ) as resp:
        body = await resp.read()
        if resp.status != 200 or body != b"PUT:/http/items/42?mode=replace:updated":
            raise AssertionError(f"PUT proxy failed status={resp.status} body={body!r}")

    async with session.delete(
        f"{PROXY_HTTP}/{PROVIDER_USER}/fileshare/items/42?force=1",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.read()
        if resp.status != 200 or body != b"DELETE:/http/items/42?force=1:":
            raise AssertionError(f"DELETE proxy failed status={resp.status} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/fileshare/headers",
        headers={
            "Host": PROXY_HOST,
            "x-trace-id": "trace-e2e",
            "x-aun-spoof": "must-not-forward",
        },
    ) as resp:
        body = await resp.read()
        if (
            resp.status != 200
            or resp.headers.get("x-header-check") != "ok"
            or b"trace=trace-e2e" not in body
            or b"spoof=" not in body
            or b"spoof=must-not-forward" in body
            or f"provider={PROVIDER_AID}".encode() not in body
            or b"service=fileshare" not in body
            or f"prefix=/{PROVIDER_USER}/fileshare".encode() not in body
        ):
            raise AssertionError(f"header proxy failed status={resp.status} headers={dict(resp.headers)!r} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/secret/health",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.json()
        if resp.status != 403 or body.get("error") != "service_private":
            raise AssertionError(f"private service should be rejected status={resp.status} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/authonly/health",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.json()
        if resp.status != 401 or body.get("error") != "requester_auth_required":
            raise AssertionError(f"aun-auth service should require requester status={resp.status} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/api/invalid",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.json()
        if resp.status != 404 or body.get("error") != "not_service_proxy_route":
            raise AssertionError(f"reserved service route should be rejected status={resp.status} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/fileshare/status/404",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.read()
        if resp.status != 404 or body != b"missing" or resp.headers.get("x-backend-status") != "missing":
            raise AssertionError(f"backend 404 should pass through status={resp.status} headers={dict(resp.headers)!r} body={body!r}")

    async with session.get(f"{PROXY_HTTP}/{PROVIDER_USER}/events/live", headers={"Host": PROXY_HOST}) as resp:
        body = await resp.read()
        if (
            resp.status != 200
            or body != b"data: one\n\ndata: two\n\n"
            or resp.headers.get("x-stream-type") != "sse"
        ):
            raise AssertionError(f"SSE proxy failed status={resp.status} headers={dict(resp.headers)!r} body={body!r}")

    async with session.post(
        f"{PROXY_HTTP}/{PROVIDER_USER}/mcp/rpc",
        headers={"Host": PROXY_HOST, "content-type": "application/json"},
        data=b'{"jsonrpc":"2.0","method":"tools/list","id":1}',
    ) as resp:
        body = await resp.read()
        if (
            resp.status != 200
            or body != b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
            or resp.headers.get("x-stream-type") != "mcp"
        ):
            raise AssertionError(f"MCP proxy failed status={resp.status} headers={dict(resp.headers)!r} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/files/download/report.bin",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.read()
        if (
            resp.status != 200
            or body != b"report-bytes"
            or resp.headers.get("x-stream-type") != "file"
            or resp.headers.get("content-disposition") != "attachment; filename=report.bin"
        ):
            raise AssertionError(f"file proxy failed status={resp.status} headers={dict(resp.headers)!r} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/files/download/large.bin",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.read()
        if resp.status != 200 or body != _LARGE_FILE_BYTES or resp.headers.get("x-stream-type") != "file":
            raise AssertionError(f"large file proxy failed status={resp.status} headers={dict(resp.headers)!r} len={len(body)}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/files/download/range.bin",
        headers={"Host": PROXY_HOST, "range": "bytes=4-9"},
    ) as resp:
        body = await resp.read()
        if (
            resp.status != 206
            or body != b"efghij"
            or resp.headers.get("content-range") != "bytes 4-9/26"
            or resp.headers.get("x-stream-type") != "file"
        ):
            raise AssertionError(f"range file proxy failed status={resp.status} headers={dict(resp.headers)!r} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/nostream/live",
        headers={"Host": PROXY_HOST, "accept": "text/event-stream"},
    ) as resp:
        body = await resp.read()
        if resp.status != 200 or body != b"data: no-stream\n\n" or "x-stream-type" in resp.headers:
            raise AssertionError(f"no_stream proxy failed status={resp.status} headers={dict(resp.headers)!r} body={body!r}")

    async with session.get(
        f"{PROXY_HTTP}/{PROVIDER_USER}/broken/probe",
        headers={"Host": PROXY_HOST},
    ) as resp:
        body = await resp.json()
        if resp.status != 502 or body.get("error") != "backend_unreachable":
            raise AssertionError(f"broken backend should map to 502 status={resp.status} body={body!r}")

    async with session.ws_connect(
        f"{PROXY_WS_EXTERNAL}/{PROVIDER_USER}/chat/socket",
        protocols=("chat.v1",),
    ) as ws:
        if ws.protocol != "chat.v1":
            raise AssertionError(f"WS subprotocol mismatch: {ws.protocol!r}")
        await ws.send_str("hello")
        msg = await ws.receive(timeout=3)
        if msg.type != WSMsgType.TEXT or msg.data != "echo:hello":
            raise AssertionError(f"WS echo failed: {msg!r}")
        await ws.send_bytes(b"bin")
        bin_msg = await ws.receive(timeout=3)
        if bin_msg.type != WSMsgType.BINARY or bin_msg.data != b"echo:bin":
            raise AssertionError(f"WS binary echo failed: {bin_msg!r}")

    async def _concurrent_get(index: int) -> bytes:
        async with session.get(
            f"{PROXY_HTTP}/{PROVIDER_USER}/fileshare/concurrent/{index}",
            headers={"Host": PROXY_HOST},
        ) as resp:
            body = await resp.read()
            expected = f"GET:/http/concurrent/{index}:".encode()
            if resp.status != 200 or body != expected:
                raise AssertionError(f"concurrent GET {index} failed status={resp.status} body={body!r}")
            return body

    await asyncio.gather(*(_concurrent_get(index) for index in range(3)))


async def main_async() -> int:
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        await _preflight(session)
        runner, backend_port = await _start_backends()
        provider_aun_client = None
        client = None
        serve_task = None
        try:
            provider_aun_client = await _connect_provider_aun_client()
            if CONNECTION_MODE == "on_demand":
                client = ServiceProxyClient(provider_aid=PROVIDER_AID, aun_client=provider_aun_client)
                _register_test_services(client, backend_port)
                serve_task = asyncio.create_task(
                    client.serve_forever(
                        connection_mode="on_demand",
                        idle_timeout_seconds=ON_DEMAND_IDLE_TIMEOUT_SECONDS,
                        reconnect_delay_seconds=0.1,
                    )
                )
                await asyncio.sleep(0.3)
            else:
                client = ServiceProxyClient(provider_aid=PROVIDER_AID, aun_client=provider_aun_client)
                _register_test_services(client, backend_port)
                serve_task = asyncio.create_task(client.serve_once(max_requests=_EXPECTED_REQUESTS))
                await _wait_registered(session, expected=_EXPECTED_SERVICES, serve_task=serve_task)

            await _run_visitor_checks(session)
            try:
                if CONNECTION_MODE == "on_demand" and client is not None:
                    client.stop()
                result = await asyncio.wait_for(serve_task, timeout=5)
            except AuthError as exc:
                raise RuntimeError(
                    "service_proxy /ws/client 认证失败；请先接入真实 AUN provider 身份认证 resolver"
                ) from exc
            if result.get("handled_requests") != _EXPECTED_REQUESTS:
                raise AssertionError(f"handled_requests 不符合预期: {result}")
            if CONNECTION_MODE == "on_demand" and result.get("wakeup_count", 0) < 1:
                raise AssertionError(f"on-demand 模式未观察到 wakeup: {result}")
        finally:
            if client is not None:
                client.stop()
            if serve_task is not None and not serve_task.done():
                serve_task.cancel()
                with suppress(asyncio.CancelledError):
                    await serve_task
            if provider_aun_client is not None:
                await provider_aun_client.close()
            await runner.cleanup()
    print(f"PASS: Service Proxy 单域 Docker E2E mode={CONNECTION_MODE}")
    return 0


def main() -> None:
    try:
        code = asyncio.run(main_async())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
