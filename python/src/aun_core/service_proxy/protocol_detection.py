from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


STREAMING_SERVICE_TYPES = {"mcp", "mcp-sse", "mcp-streamable-http", "sse", "stream", "file", "ws", "websocket"}
_VALID_STREAM_MODES = {"auto", "stream", "always", "no_stream"}
_FILE_CONTENT_TYPES = {
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-tar",
}


@dataclass(frozen=True)
class ProtocolDetection:
    service_type: str
    stream_mode: str
    is_stream: bool
    source: str
    reasons: tuple[str, ...]

    def summary(self) -> dict[str, Any]:
        return {
            "service_type": self.service_type,
            "stream_mode": self.stream_mode,
            "is_stream": self.is_stream,
            "source": self.source,
            "reasons": list(self.reasons),
        }


def headers_map(headers: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not headers:
        return result
    items = headers.items() if hasattr(headers, "items") else []
    for key, value in items:
        result[str(key).lower()] = str(value)
    return result


def _record_type(record: Any) -> str:
    return str(getattr(record, "service_type", "") or "http").strip().lower() or "http"


def _record_name(record: Any) -> str:
    return str(getattr(record, "service_name", "") or "").strip().lower()


def _record_metadata(record: Any) -> dict:
    metadata = getattr(record, "metadata", None)
    return metadata if isinstance(metadata, dict) else {}


def _stream_mode_from(headers: dict[str, str], record: Any, message: dict[str, Any] | None = None) -> str:
    msg = message or {}
    value = str(msg.get("stream_mode") or "").strip().lower()
    if not value:
        value = str(headers.get("x-stream-mode") or "").strip().lower()
    if not value:
        value = str(_record_metadata(record).get("stream_mode") or "").strip().lower()
    if value == "always":
        return "stream"
    return value if value in _VALID_STREAM_MODES else "auto"


def _body_bytes(message: dict[str, Any]) -> bytes:
    raw = str((message or {}).get("body_base64") or "")
    if not raw:
        return b""
    try:
        return base64.b64decode(raw, validate=True)
    except Exception:
        return b""


def _body_has_jsonrpc(body: bytes) -> bool:
    if not body:
        return False
    if b'"jsonrpc"' in body or b"'jsonrpc'" in body:
        return True
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        return False
    if isinstance(parsed, dict):
        return str(parsed.get("jsonrpc") or "") == "2.0"
    if isinstance(parsed, list):
        return any(isinstance(item, dict) and str(item.get("jsonrpc") or "") == "2.0" for item in parsed)
    return False


def _path_contains(path: str, *needles: str) -> bool:
    value = str(path or "").lower()
    return any(needle in value for needle in needles)


def _referer_service_type(referer: str, record: Any) -> str:
    service_name = _record_name(record)
    service_type = _record_type(record)
    if not referer or not service_name or service_type == "http":
        return ""
    try:
        path = urlparse(str(referer)).path
    except Exception:
        path = ""
    parts = [item.lower() for item in path.split("/") if item]
    if not parts:
        return ""
    if parts[0] == service_name:
        return service_type
    if len(parts) >= 2 and parts[1] == service_name:
        return service_type
    return ""


def detect_request_protocol(message: dict[str, Any], record: Any) -> ProtocolDetection:
    headers = headers_map(message.get("headers") if isinstance(message.get("headers"), dict) else {})
    stream_mode = _stream_mode_from(headers, record, message)
    reasons: list[str] = []
    source = "default"
    hinted_type = str(message.get("service_type") or "").strip().lower()
    service_type = hinted_type or _record_type(record)

    if stream_mode == "no_stream":
        service_type = "http"
        source = "stream_mode"
        reasons.append("stream_mode:no_stream")
    elif hinted_type:
        source = "server-hint"
        reasons.append("server-hint")
    else:
        explicit_type = str(headers.get("x-service-type") or "").strip().lower()
        if explicit_type:
            service_type = explicit_type
            source = "x-service-type"
            reasons.append("x-service-type")
        elif stream_mode != "no_stream":
            accept = headers.get("accept", "").lower()
            content_type = headers.get("content-type", "").lower()
            method = str(message.get("method") or "").upper()
            path = str(message.get("path") or "")
            body = _body_bytes(message)
            referer = headers.get("referer", "")

            if "text/event-stream" in accept:
                service_type = "sse"
                source = "accept"
                reasons.append("accept:text/event-stream")
            elif "mcp-session-id" in headers:
                service_type = "mcp"
                source = "mcp-session-id"
                reasons.append("mcp-session-id")
            elif method == "POST" and _body_has_jsonrpc(body):
                service_type = "mcp"
                source = "jsonrpc-body"
                reasons.append("jsonrpc-body")
            elif content_type.startswith("application/grpc"):
                service_type = "ws"
                source = "content-type"
                reasons.append("content-type:application/grpc")
            elif _path_contains(path, "/v1/chat/completions", "/v1/completions", "/chat"):
                service_type = "api"
                source = "path"
                reasons.append("path:api")
            elif _path_contains(path, "/mcp"):
                service_type = "mcp"
                source = "path"
                reasons.append("path:mcp")
            elif _path_contains(path, "/sse", "/events"):
                service_type = "sse"
                source = "path"
                reasons.append("path:sse")
            elif _path_contains(path, "/download", "/files/"):
                service_type = "file"
                source = "path"
                reasons.append("path:file")
            else:
                referer_type = _referer_service_type(referer, record)
                if referer_type:
                    service_type = referer_type
                    source = "referer"
                    reasons.append("referer")

    if not reasons and service_type != "http":
        source = "registry"
        reasons.append("registry")

    if stream_mode in {"stream", "always"}:
        is_stream = True
    elif stream_mode == "no_stream":
        is_stream = False
    elif "is_stream" in message:
        is_stream = bool(message.get("is_stream"))
    elif "stream" in message:
        is_stream = bool(message.get("stream"))
    else:
        is_stream = service_type in STREAMING_SERVICE_TYPES

    return ProtocolDetection(
        service_type=service_type or "http",
        stream_mode=stream_mode,
        is_stream=is_stream,
        source=source,
        reasons=tuple(reasons or ("default",)),
    )


def is_stream_response_headers(headers: dict[str, Any]) -> bool:
    mapped = headers_map(headers)
    content_type = mapped.get("content-type", "").split(";", 1)[0].strip().lower()
    content_disposition = mapped.get("content-disposition", "").lower()
    if "text/event-stream" in mapped.get("content-type", "").lower():
        return True
    if content_type in _FILE_CONTENT_TYPES:
        return True
    if content_type.startswith("image/") or content_type.startswith("video/"):
        return True
    return "attachment" in content_disposition


def stream_type_from_response(headers: dict[str, Any], fallback: str = "") -> str:
    mapped = headers_map(headers)
    content_type = mapped.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        return "sse"
    if is_stream_response_headers(headers):
        return "file"
    return str(fallback or "").strip().lower() or "stream"
