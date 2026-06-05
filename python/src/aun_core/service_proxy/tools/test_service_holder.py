from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
from contextlib import suppress
from typing import Any

from aiohttp import WSMsgType, web

from .. import ServiceProxyClient
from .common import (
    default_aun_path,
    default_proxy_base,
    env_bool,
    env_first,
    exit_with_error,
    load_env_file,
    load_or_register_aun_client,
    log,
    split_provider_aid,
)


_LARGE_FILE_BYTES = (b"0123456789abcdef" * 10240) + b"end"


class TestServiceSuite:
    def __init__(self, *, provider_aid: str) -> None:
        self.provider_aid = provider_aid

    def create_app(self) -> web.Application:
        app = web.Application(middlewares=[self._logging_middleware])
        app.router.add_get("/health", self.health)
        app.router.add_route("*", "/http/{tail:.*}", self.http)
        app.router.add_route("*", "/mcp/{tail:.*}", self.mcp)
        app.router.add_get("/sse/{tail:.*}", self.sse)
        app.router.add_route("*", "/files/{tail:.*}", self.files)
        app.router.add_get("/web/{tail:.*}", self.web)
        app.router.add_get("/ws/{tail:.*}", self.ws)
        return app

    @web.middleware
    async def _logging_middleware(self, request: web.Request, handler):
        try:
            response = await handler(request)
            log(
                "backend request",
                method=request.method,
                path=request.path,
                has_query=bool(request.query_string),
                query_length=len(request.query_string),
                status=getattr(response, "status", ""),
                service=request.path.strip("/").split("/", 1)[0] or "root",
                x_aun_request_id=request.headers.get("x-aun-request-id", ""),
                x_aun_ws_connection_id=request.headers.get("x-aun-ws-connection-id", ""),
                x_aun_provider_aid=request.headers.get("x-aun-provider-aid", ""),
                x_aun_service_name=request.headers.get("x-aun-service-name", ""),
                x_aun_requester_aid=request.headers.get("x-aun-requester-aid", ""),
                x_forwarded_prefix=request.headers.get("x-forwarded-prefix", ""),
                x_forwarded_host=request.headers.get("x-forwarded-host", ""),
                x_forwarded_for=request.headers.get("x-forwarded-for", ""),
            )
            return response
        except Exception as exc:
            log(
                "backend request failed",
                method=request.method,
                path=request.path,
                has_query=bool(request.query_string),
                query_length=len(request.query_string),
                error=type(exc).__name__,
                x_aun_request_id=request.headers.get("x-aun-request-id", ""),
                x_aun_ws_connection_id=request.headers.get("x-aun-ws-connection-id", ""),
                x_aun_provider_aid=request.headers.get("x-aun-provider-aid", ""),
                x_aun_service_name=request.headers.get("x-aun-service-name", ""),
                x_aun_requester_aid=request.headers.get("x-aun-requester-aid", ""),
                x_forwarded_prefix=request.headers.get("x-forwarded-prefix", ""),
                x_forwarded_host=request.headers.get("x-forwarded-host", ""),
                x_forwarded_for=request.headers.get("x-forwarded-for", ""),
            )
            raise

    async def health(self, _request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "provider_aid": self.provider_aid})

    async def http(self, request: web.Request) -> web.Response:
        body = await request.read()
        tail = request.match_info["tail"]
        if tail == "headers":
            return web.json_response({
                "provider_aid": self.provider_aid,
                "method": request.method,
                "path_qs": request.path_qs,
                "x_trace_id": request.headers.get("x-trace-id", ""),
                "x_aun_spoof": request.headers.get("x-aun-spoof", ""),
                "x_aun_provider_aid": request.headers.get("x-aun-provider-aid", ""),
                "x_aun_service_name": request.headers.get("x-aun-service-name", ""),
                "x_forwarded_prefix": request.headers.get("x-forwarded-prefix", ""),
                "x_forwarded_host": request.headers.get("x-forwarded-host", ""),
            })
        if tail.startswith("status/"):
            try:
                status = max(100, min(599, int(tail.rsplit("/", 1)[-1])))
            except ValueError:
                status = 400
            return web.Response(status=status, headers={"x-backend-status": str(status)}, body=f"status {status}".encode())
        if tail == "json":
            return web.json_response({
                "provider_aid": self.provider_aid,
                "method": request.method,
                "query": dict(request.query),
                "body_base64": base64.b64encode(body).decode("ascii"),
            })
        return web.Response(
            status=200,
            headers={"content-type": "text/plain", "x-provider-aid": self.provider_aid},
            body=f"{self.provider_aid}:{request.method}:{request.path_qs}:{body.decode(errors='replace')}".encode(),
        )

    async def mcp(self, request: web.Request) -> web.Response:
        tail = request.match_info["tail"]
        if request.method == "GET" and tail in {"sse", "events"}:
            response = web.StreamResponse(status=200, headers={"content-type": "text/event-stream"})
            await response.prepare(request)
            await response.write(b"event: endpoint\ndata: /mcp/rpc\n\n")
            await response.write_eof()
            return response
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            return web.json_response({"error": "missing jsonrpc"}, status=400)
        method = str(payload.get("method") or "")
        if method == "tools/list":
            result: dict[str, Any] = {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo text for Service Proxy debugging",
                        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                    }
                ]
            }
        elif method == "tools/call":
            params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
            args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            result = {"content": [{"type": "text", "text": str(args.get("text") or "")}]}
        else:
            result = {"provider_aid": self.provider_aid, "method": method}
        return web.json_response({"jsonrpc": "2.0", "id": payload.get("id"), "result": result})

    async def sse(self, request: web.Request) -> web.StreamResponse:
        count = _int_query(request, "count", 3)
        interval = max(0.0, min(5.0, _float_query(request, "interval", 0.2)))
        response = web.StreamResponse(status=200, headers={"content-type": "text/event-stream"})
        await response.prepare(request)
        for index in range(max(1, min(100, count))):
            await response.write(f"event: tick\ndata: {self.provider_aid}:{index}\n\n".encode())
            await asyncio.sleep(interval)
        await response.write_eof()
        return response

    async def files(self, request: web.Request) -> web.Response:
        tail = request.match_info["tail"].strip("/")
        if not tail:
            return web.json_response({
                "files": [
                    "download/report.txt",
                    "download/large.bin",
                    "download/range.bin",
                ]
            })
        if tail == "download/report.txt":
            return web.Response(
                status=200,
                headers={
                    "content-type": "text/plain",
                    "content-disposition": "attachment; filename=report.txt",
                },
                body=f"Service Proxy report from {self.provider_aid}\n".encode(),
            )
        if tail == "download/large.bin":
            return web.Response(status=200, headers={"content-type": "application/octet-stream"}, body=_LARGE_FILE_BYTES)
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
        return web.json_response({"error": "file_not_found", "path": tail}, status=404)

    async def web(self, request: web.Request) -> web.Response:
        tail = request.match_info["tail"].strip("/")
        if tail in {"", "index.html"}:
            return web.Response(
                status=200,
                headers={"content-type": "text/html; charset=utf-8"},
                text=_web_index_html(self.provider_aid),
            )
        if tail == "assets/app.js":
            return web.Response(
                status=200,
                headers={"content-type": "application/javascript; charset=utf-8"},
                text=_web_app_js(),
            )
        if tail == "api/info":
            return web.json_response({
                "provider_aid": self.provider_aid,
                "service": "web",
                "message": "browser visitor ok",
            })
        return web.Response(status=404, text="not found")

    async def ws(self, request: web.Request) -> web.WebSocketResponse:
        websocket = web.WebSocketResponse(protocols=("chat.v1",))
        await websocket.prepare(request)
        async for message in websocket:
            if message.type == WSMsgType.TEXT:
                await websocket.send_str(f"{self.provider_aid}:echo:{message.data}")
            elif message.type == WSMsgType.BINARY:
                await websocket.send_bytes(f"{self.provider_aid}:".encode() + bytes(message.data))
        return websocket


def _int_query(request: web.Request, name: str, default: int) -> int:
    try:
        return int(request.query.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _float_query(request: web.Request, name: str, default: float) -> float:
    try:
        return float(request.query.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _web_index_html(provider_aid: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AUN Service Proxy Test</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 24px; max-width: 920px; line-height: 1.5; }}
    code, pre {{ background: #f4f4f4; padding: 2px 4px; border-radius: 4px; }}
    button {{ margin: 4px 8px 4px 0; }}
    pre {{ padding: 12px; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>AUN Service Proxy Test</h1>
  <p>provider: <code>{provider_aid}</code></p>
  <button id="info">Web API</button>
  <button id="rest">REST</button>
  <button id="file">File</button>
  <button id="sse">SSE</button>
  <pre id="out">ready</pre>
  <script src="./assets/app.js"></script>
</body>
</html>"""


def _web_app_js() -> str:
    return """const out = document.getElementById('out');
const show = (name, value) => { out.textContent = `${name}:\\n${value}`; };
document.getElementById('info').onclick = async () => {
  const res = await fetch('./api/info');
  show('web api', JSON.stringify(await res.json(), null, 2));
};
document.getElementById('rest').onclick = async () => {
  const res = await fetch('../rest/json?from=browser', {method: 'POST', body: 'hello'});
  show('rest', await res.text());
};
document.getElementById('file').onclick = async () => {
  const res = await fetch('../files/download/report.txt');
  show('file', await res.text());
};
document.getElementById('sse').onclick = () => {
  const source = new EventSource('../events/live?count=3&interval=0.1');
  out.textContent = 'sse:\\n';
  source.onmessage = event => { out.textContent += event.data + '\\n'; };
  source.addEventListener('tick', event => { out.textContent += event.data + '\\n'; });
  source.onerror = () => source.close();
};"""


async def _start_backend(host: str, port: int, provider_aid: str) -> tuple[web.AppRunner, int]:
    suite = TestServiceSuite(provider_aid=provider_aid)
    runner = web.AppRunner(suite.create_app())
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    sockets = getattr(site, "_server").sockets
    actual_port = int(sockets[0].getsockname()[1])
    log("测试后端已启动", host=host, port=actual_port)
    return runner, actual_port


def _register_services(client: ServiceProxyClient, base_http: str, base_ws: str, selected: set[str]) -> None:
    definitions = {
        "web": (f"{base_http}/web", "http", "public", {}),
        "rest": (f"{base_http}/http", "http", "public", {}),
        "mcp": (f"{base_http}/mcp", "mcp", "public", {}),
        "events": (f"{base_http}/sse", "sse", "public", {}),
        "files": (f"{base_http}/files", "file", "public", {}),
        "chat": (f"{base_ws}/ws", "websocket", "public", {}),
        "secret": (f"{base_http}/http", "http", "private", {}),
        "authonly": (f"{base_http}/http", "http", "aun-auth", {}),
    }
    wanted = set(definitions) if "all" in selected else selected
    for name in sorted(wanted):
        if name not in definitions:
            raise ValueError(f"未知 service: {name}")
        endpoint, service_type, visibility, metadata = definitions[name]
        record = client.register_service(
            name,
            endpoint,
            service_type=service_type,
            visibility=visibility,
            metadata=metadata,
        )
        log("已注册测试服务", service=record.service_name, type=record.service_type, visibility=record.visibility, endpoint=endpoint)


def _print_urls(provider_aid: str, public_proxy_base: str, services: set[str]) -> None:
    user, issuer = split_provider_aid(provider_aid)
    wanted = {"web", "rest", "mcp", "events", "files", "chat", "secret", "authonly"} if "all" in services else services
    log("Visitor URL 示例", canonical_base=public_proxy_base, provider_aid=provider_aid)
    for service in sorted(wanted):
        if service == "chat":
            path = "socket"
        elif service == "events":
            path = "live"
        elif service == "files":
            path = "download/report.txt"
        elif service == "mcp":
            path = "rpc"
        else:
            path = ""
        suffix = f"/{path}" if path else "/"
        print(f"  canonical  {service:8s} {public_proxy_base.rstrip('/')}/{user}/{service}{suffix}", flush=True)
        print(f"  namesvc    {service:8s} https://{provider_aid}/proxy/{service}{suffix}", flush=True)
        print(f"  host-root  {service:8s} https://{service}-{user}.{issuer}{suffix}", flush=True)
    print("", flush=True)
    print("浏览器优先打开 web 服务 canonical URL；页面内按钮会继续访问 REST/File/SSE。", flush=True)


def _parse_args() -> argparse.Namespace:
    boot = argparse.ArgumentParser(add_help=False)
    boot.add_argument("--env-file", default=os.environ.get("AUN_PROXY_ENV_FILE", ".env"))
    known, _remaining = boot.parse_known_args()
    load_env_file(known.env_file)

    provider_default = env_first("AUN_PROXY_PROVIDER_AID", "AUN_SERVICE_PROXY_PROVIDER_AID", "PROVIDER_AID")
    parser = argparse.ArgumentParser(
        parents=[boot],
        description="启动 AUN Service Proxy 测试服务 holder，并通过 Python SDK proxy-client 对外提供服务。",
    )
    parser.add_argument("--provider-aid", default=provider_default, help="服务提供者 AID，形如 alice.agentid.pub")
    parser.add_argument("--public-proxy-base", default=env_first("AUN_SERVICE_PROXY_PUBLIC_BASE", "AUN_PROXY_PUBLIC_BASE"))
    parser.add_argument("--connection-mode", choices=["persistent", "on_demand"], default=env_first("AUN_SERVICE_PROXY_CONNECTION_MODE", default="persistent"))
    parser.add_argument("--idle-timeout", type=float, default=float(env_first("AUN_SERVICE_PROXY_IDLE_TIMEOUT_SECONDS", default="60")))
    parser.add_argument("--backend-host", default=env_first("AUN_PROXY_BACKEND_HOST", default="127.0.0.1"))
    parser.add_argument("--backend-port", type=int, default=int(env_first("AUN_PROXY_BACKEND_PORT", default="0")))
    parser.add_argument("--services", default=env_first("AUN_PROXY_SERVICES", default="all"), help="逗号分隔：all,web,rest,mcp,events,files,chat,secret,authonly")
    parser.add_argument("--aun-path", default=env_first("AUN_PROXY_PROVIDER_AUN_PATH", "AUN_SERVICE_PROXY_PROVIDER_AUN_PATH"))
    parser.add_argument("--seed", default=env_first("AUN_SEED_PASSWORD", "AUN_PROXY_SEED"))
    parser.add_argument("--slot-id", default=env_first("AUN_SLOT_ID", "AUN_PROXY_SLOT_ID", default="default"))
    parser.add_argument("--root-ca-path", default=env_first("AUN_ROOT_CA_PATH", "AUN_PROXY_ROOT_CA_PATH"))
    parser.add_argument("--verify-ssl", action="store_true", default=env_bool("AUN_VERIFY_SSL", False))
    parser.add_argument("--debug", action="store_true", default=env_bool("AUN_DEBUG", False))
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> int:
    if not args.provider_aid:
        exit_with_error("必须通过 --provider-aid 或 .env 指定 AUN_PROXY_PROVIDER_AID")
    provider_aid = str(args.provider_aid).strip().lower()
    _user, issuer = split_provider_aid(provider_aid)
    public_proxy_base = str(args.public_proxy_base or "").strip() or default_proxy_base(provider_aid)
    aun_path = str(args.aun_path or "").strip() or default_aun_path(provider_aid, "holder")
    selected = {item.strip() for item in str(args.services or "all").split(",") if item.strip()}
    if not selected:
        selected = {"all"}

    runner, backend_port = await _start_backend(args.backend_host, args.backend_port, provider_aid)
    aun_client = None
    proxy_client = None
    serve_task = None
    try:
        aun_client = await load_or_register_aun_client(
            provider_aid,
            aun_path=aun_path,
            seed=args.seed,
            slot_id=args.slot_id,
            verify_ssl=bool(args.verify_ssl),
            root_ca_path=args.root_ca_path or None,
            debug=bool(args.debug),
        )
        proxy_client = ServiceProxyClient(
            provider_aid=provider_aid,
            aun_client=aun_client,
            logger=getattr(aun_client, "_log", None),
        )
        base_http = f"http://127.0.0.1:{backend_port}"
        base_ws = f"ws://127.0.0.1:{backend_port}"
        _register_services(proxy_client, base_http, base_ws, selected)
        service_summaries = proxy_client.list_service_summaries()
        log(
            "Service Proxy 服务摘要将用于 Gateway 控制面和 proxy-server 数据面注册",
            count=len(service_summaries),
            services=json.dumps(service_summaries, ensure_ascii=False, separators=(",", ":")),
        )
        _print_urls(provider_aid, public_proxy_base, selected)
        log(
            "Service Proxy holder 启动",
            issuer=issuer,
            connection_mode=args.connection_mode,
            aun_path=aun_path,
        )
        serve_task = asyncio.create_task(
            proxy_client.serve_forever(
                connection_mode=args.connection_mode,
                idle_timeout_seconds=float(args.idle_timeout),
                reconnect_delay_seconds=1.0,
            )
        )
        await serve_task
        return 0
    finally:
        if proxy_client is not None:
            proxy_client.stop()
        if serve_task is not None and not serve_task.done():
            serve_task.cancel()
            with suppress(asyncio.CancelledError):
                await serve_task
        if aun_client is not None:
            await aun_client.close()
        await runner.cleanup()


def main() -> None:
    args = _parse_args()
    try:
        raise SystemExit(asyncio.run(main_async(args)))
    except KeyboardInterrupt:
        log("收到中断，正在退出")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
