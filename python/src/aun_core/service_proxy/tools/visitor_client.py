from __future__ import annotations

import argparse
import asyncio
import json
import os
from contextlib import suppress
from typing import Any
from urllib.parse import quote, urlparse

import aiohttp
from aiohttp import WSMsgType

from .common import (
    default_aun_path,
    default_proxy_base,
    env_bool,
    env_first,
    exit_with_error,
    join_url,
    load_env_file,
    load_or_register_aun_client,
    log,
    split_provider_aid,
    websocket_url_from_http,
)


class VisitorRoutes:
    def __init__(
        self,
        *,
        provider_aid: str,
        proxy_base: str,
        mode: str,
        proxy_host_header: str = "",
        nameservice_scheme: str = "https",
        nameservice_port: str = "",
    ) -> None:
        self.provider_aid = provider_aid
        self.user, self.issuer = split_provider_aid(provider_aid)
        self.proxy_base = proxy_base.rstrip("/")
        self.mode = mode
        self.proxy_host_header = proxy_host_header
        self.nameservice_scheme = nameservice_scheme
        self.nameservice_port = nameservice_port

    def http_url(self, service: str, path: str = "/", *, query: str = "") -> tuple[str, dict[str, str]]:
        service = quote(str(service).strip(), safe="")
        path = "/" + str(path or "/").lstrip("/")
        headers: dict[str, str] = {}
        if self.mode == "canonical":
            url = join_url(self.proxy_base, f"/{quote(self.user, safe='')}/{service}{path}")
            if self.proxy_host_header:
                headers["Host"] = self.proxy_host_header
        elif self.mode == "nameservice":
            port_part = f":{self.nameservice_port}" if self.nameservice_port else ""
            url = f"{self.nameservice_scheme}://{self.provider_aid}{port_part}/proxy/{service}{path}"
        elif self.mode == "host-root":
            parsed = urlparse(self.proxy_base)
            host = f"{service}-{self.user}.{self.issuer}"
            port_part = f":{parsed.port}" if parsed.port else ""
            url = f"{parsed.scheme}://{host}{port_part}{path}"
            if self.proxy_host_header:
                proxy_parsed = parsed._replace(path="", params="", query="", fragment="")
                url = proxy_parsed.geturl().rstrip("/") + path
                headers["Host"] = host
        else:
            raise ValueError(f"未知 route mode: {self.mode}")
        if query:
            url += ("&" if "?" in url else "?") + query.lstrip("?")
        return url, headers

    def ws_url(self, service: str, path: str = "/") -> tuple[str, dict[str, str]]:
        http_url, headers = self.http_url(service, path)
        return websocket_url_from_http(http_url), headers


def _merge_headers(*items: dict[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for item in items:
        merged.update({str(k): str(v) for k, v in item.items() if v is not None})
    return merged


async def _read_response(resp: aiohttp.ClientResponse) -> str:
    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return json.dumps(await resp.json(), ensure_ascii=False)
        except Exception:
            pass
    data = await resp.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(data)} bytes>"


async def check_rest(session: aiohttp.ClientSession, routes: VisitorRoutes, auth: dict[str, str]) -> None:
    url, route_headers = routes.http_url("rest", "/json", query="from=visitor")
    async with session.post(url, headers=_merge_headers(route_headers, auth, {"content-type": "text/plain"}), data=b"hello") as resp:
        body = await _read_response(resp)
        log("REST POST", status=resp.status, url=url, body=body[:200])
        if resp.status != 200:
            raise AssertionError(f"REST POST failed: {resp.status} {body}")

    url, route_headers = routes.http_url("rest", "/headers")
    async with session.get(url, headers=_merge_headers(route_headers, auth, {"x-trace-id": "visitor-client"})) as resp:
        body = await _read_response(resp)
        log("REST headers", status=resp.status, url=url, body=body[:240])
        if resp.status != 200 or "visitor-client" not in body:
            raise AssertionError(f"REST headers failed: {resp.status} {body}")


async def check_mcp(session: aiohttp.ClientSession, routes: VisitorRoutes, auth: dict[str, str]) -> None:
    url, route_headers = routes.http_url("mcp", "/rpc")
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    async with session.post(url, headers=_merge_headers(route_headers, auth, {"content-type": "application/json"}), json=payload) as resp:
        body = await _read_response(resp)
        log("MCP tools/list", status=resp.status, url=url, body=body[:240], stream_type=resp.headers.get("x-stream-type", ""))
        if resp.status != 200 or '"jsonrpc"' not in body:
            raise AssertionError(f"MCP failed: {resp.status} {body}")


async def check_sse(session: aiohttp.ClientSession, routes: VisitorRoutes, auth: dict[str, str]) -> None:
    url, route_headers = routes.http_url("events", "/live", query="count=2&interval=0.05")
    async with session.get(url, headers=_merge_headers(route_headers, auth, {"accept": "text/event-stream"})) as resp:
        body = await _read_response(resp)
        log("SSE", status=resp.status, url=url, body=body[:240], stream_type=resp.headers.get("x-stream-type", ""))
        if resp.status != 200 or "event: tick" not in body:
            raise AssertionError(f"SSE failed: {resp.status} {body}")


async def check_files(session: aiohttp.ClientSession, routes: VisitorRoutes, auth: dict[str, str]) -> None:
    url, route_headers = routes.http_url("files", "/download/report.txt")
    async with session.get(url, headers=_merge_headers(route_headers, auth)) as resp:
        body = await _read_response(resp)
        log("File report", status=resp.status, url=url, body=body[:160], stream_type=resp.headers.get("x-stream-type", ""))
        if resp.status != 200 or "Service Proxy report" not in body:
            raise AssertionError(f"file report failed: {resp.status} {body}")

    url, route_headers = routes.http_url("files", "/download/range.bin")
    async with session.get(url, headers=_merge_headers(route_headers, auth, {"range": "bytes=4-9"})) as resp:
        data = await resp.read()
        log("File range", status=resp.status, url=url, body=data.decode("ascii", errors="replace"), content_range=resp.headers.get("content-range", ""))
        if resp.status != 206 or data != b"efghij":
            raise AssertionError(f"file range failed: {resp.status} {data!r}")


async def check_web(session: aiohttp.ClientSession, routes: VisitorRoutes, auth: dict[str, str]) -> None:
    url, route_headers = routes.http_url("web", "/")
    async with session.get(url, headers=_merge_headers(route_headers, auth)) as resp:
        body = await _read_response(resp)
        log("Web index", status=resp.status, url=url, body=body[:160])
        if resp.status != 200 or "AUN Service Proxy Test" not in body:
            raise AssertionError(f"web index failed: {resp.status} {body[:200]}")

    url, route_headers = routes.http_url("web", "/api/info")
    async with session.get(url, headers=_merge_headers(route_headers, auth)) as resp:
        body = await _read_response(resp)
        log("Web API", status=resp.status, url=url, body=body[:200])
        if resp.status != 200 or "browser visitor ok" not in body:
            raise AssertionError(f"web api failed: {resp.status} {body}")


async def check_ws(session: aiohttp.ClientSession, routes: VisitorRoutes, auth: dict[str, str]) -> None:
    url, route_headers = routes.ws_url("chat", "/socket")
    async with session.ws_connect(url, headers=_merge_headers(route_headers, auth), protocols=("chat.v1",)) as ws:
        await ws.send_str("hello")
        message = await ws.receive(timeout=5)
        log("WebSocket text", type=message.type, data=getattr(message, "data", ""))
        if message.type != WSMsgType.TEXT or "echo:hello" not in str(message.data):
            raise AssertionError(f"ws text failed: {message!r}")
        await ws.send_bytes(b"bin")
        binary = await ws.receive(timeout=5)
        log("WebSocket binary", type=binary.type, bytes=len(binary.data or b"") if binary.type == WSMsgType.BINARY else 0)
        if binary.type != WSMsgType.BINARY or not bytes(binary.data).endswith(b":bin"):
            raise AssertionError(f"ws binary failed: {binary!r}")


async def check_access_control(session: aiohttp.ClientSession, routes: VisitorRoutes, auth: dict[str, str]) -> None:
    url, route_headers = routes.http_url("secret", "/headers")
    async with session.get(url, headers=_merge_headers(route_headers, auth)) as resp:
        body = await _read_response(resp)
        log("Private service", status=resp.status, url=url, body=body[:160])
        if resp.status not in {200, 403}:
            raise AssertionError(f"private service unexpected: {resp.status} {body}")

    url, route_headers = routes.http_url("authonly", "/headers")
    async with session.get(url, headers=_merge_headers(route_headers, auth)) as resp:
        body = await _read_response(resp)
        log("AUN-auth service", status=resp.status, url=url, body=body[:160])
        if resp.status not in {200, 401}:
            raise AssertionError(f"aun-auth service unexpected: {resp.status} {body}")


_CHECKS = {
    "rest": check_rest,
    "mcp": check_mcp,
    "sse": check_sse,
    "files": check_files,
    "web": check_web,
    "ws": check_ws,
    "access": check_access_control,
}


def _parse_args() -> argparse.Namespace:
    boot = argparse.ArgumentParser(add_help=False)
    boot.add_argument("--env-file", default=os.environ.get("AUN_PROXY_ENV_FILE", ".env"))
    known, _remaining = boot.parse_known_args()
    load_env_file(known.env_file)

    provider_default = env_first("AUN_PROXY_PROVIDER_AID", "AUN_SERVICE_PROXY_PROVIDER_AID", "PROVIDER_AID")
    parser = argparse.ArgumentParser(
        parents=[boot],
        description="访问 AUN Service Proxy 测试服务的 visitor client。",
    )
    parser.add_argument("--provider-aid", default=provider_default, help="服务提供者 AID，形如 alice.agentid.pub")
    parser.add_argument("--proxy-base", default=env_first("AUN_PROXY_BASE", "AUN_SERVICE_PROXY_PUBLIC_BASE"))
    parser.add_argument("--route", choices=["canonical", "nameservice", "host-root"], default=env_first("AUN_PROXY_VISITOR_ROUTE", default="canonical"))
    parser.add_argument("--proxy-host-header", default=env_first("AUN_PROXY_HOST_HEADER"))
    parser.add_argument("--nameservice-scheme", default=env_first("AUN_NAMESERVICE_SCHEME", default="https"))
    parser.add_argument("--nameservice-port", default=env_first("AUN_NAMESERVICE_PORT"))
    parser.add_argument("--checks", default=env_first("AUN_PROXY_VISITOR_CHECKS", default="all"), help="逗号分隔：all,rest,mcp,sse,files,web,ws,access")
    parser.add_argument("--insecure", action="store_true", default=env_bool("AUN_PROXY_VISITOR_INSECURE", False), help="禁用 HTTPS 证书校验")
    parser.add_argument("--timeout", type=float, default=float(env_first("AUN_PROXY_VISITOR_TIMEOUT", default="30")))
    parser.add_argument("--visitor-aid", default=env_first("AUN_PROXY_VISITOR_AID", "VISITOR_AID"), help="可选：连接 AUN SDK 后携带 Bearer token")
    parser.add_argument("--visitor-aun-path", default=env_first("AUN_PROXY_VISITOR_AUN_PATH"))
    parser.add_argument("--seed", default=env_first("AUN_SEED_PASSWORD", "AUN_PROXY_SEED"))
    parser.add_argument("--slot-id", default=env_first("AUN_SLOT_ID", "AUN_PROXY_SLOT_ID", default="default"))
    parser.add_argument("--root-ca-path", default=env_first("AUN_ROOT_CA_PATH", "AUN_PROXY_ROOT_CA_PATH"))
    parser.add_argument("--verify-ssl", action="store_true", default=env_bool("AUN_VERIFY_SSL", False))
    parser.add_argument("--debug", action="store_true", default=env_bool("AUN_DEBUG", False))
    return parser.parse_args()


async def _auth_headers(args: argparse.Namespace) -> tuple[dict[str, str], Any]:
    if not args.visitor_aid:
        return {}, None
    aun_path = str(args.visitor_aun_path or "").strip() or default_aun_path(args.visitor_aid, "visitor")
    client = await load_or_register_aun_client(
        args.visitor_aid,
        aun_path=aun_path,
        seed=args.seed,
        slot_id=args.slot_id,
        verify_ssl=bool(args.verify_ssl),
        root_ca_path=args.root_ca_path or None,
        debug=bool(args.debug),
    )
    token = str(client.access_token or "").strip()
    if not token:
        await client.close()
        raise RuntimeError("visitor AUNClient 未获得 access_token")
    return {"authorization": f"Bearer {token}"}, client


async def main_async(args: argparse.Namespace) -> int:
    if not args.provider_aid:
        exit_with_error("必须通过 --provider-aid 或 .env 指定 AUN_PROXY_PROVIDER_AID")
    provider_aid = str(args.provider_aid).strip().lower()
    proxy_base = str(args.proxy_base or "").strip() or default_proxy_base(provider_aid)
    routes = VisitorRoutes(
        provider_aid=provider_aid,
        proxy_base=proxy_base,
        mode=args.route,
        proxy_host_header=args.proxy_host_header,
        nameservice_scheme=args.nameservice_scheme,
        nameservice_port=args.nameservice_port,
    )
    selected = {item.strip() for item in str(args.checks or "all").split(",") if item.strip()}
    if not selected or "all" in selected:
        selected = set(_CHECKS)
    unknown = selected - set(_CHECKS)
    if unknown:
        exit_with_error(f"未知 checks: {', '.join(sorted(unknown))}")

    auth, aun_client = await _auth_headers(args)
    timeout = aiohttp.ClientTimeout(total=max(1.0, float(args.timeout)))
    connector = aiohttp.TCPConnector(ssl=False if args.insecure else None)
    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            log("Visitor 开始访问", provider_aid=provider_aid, proxy_base=proxy_base, route=args.route, checks=",".join(sorted(selected)))
            for name in ["web", "rest", "mcp", "sse", "files", "ws", "access"]:
                if name not in selected:
                    continue
                await _CHECKS[name](session, routes, auth)
        log("Visitor 检查完成", result="PASS")
        return 0
    finally:
        if aun_client is not None:
            with suppress(Exception):
                await aun_client.close()


def main() -> None:
    args = _parse_args()
    try:
        raise SystemExit(asyncio.run(main_async(args)))
    except KeyboardInterrupt:
        log("收到中断，正在退出")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
