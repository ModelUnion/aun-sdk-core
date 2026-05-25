#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sys
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from aiohttp import web

from aun_core import AUNClient


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(k): _json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_json_safe(v) for v in value]
        return str(value)


def _sha256_json(value: Any) -> str:
    data = json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _cert_fingerprint(cert_pem: Any) -> str:
    text = str(cert_pem or "").strip()
    if not text:
        return ""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_pem_x509_certificate(text.encode("utf-8"))
        return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        return ""


class CrossSdkPythonAgent:
    def __init__(self) -> None:
        self.language = "python"
        self.sdk_version = self._sdk_version()
        self.aid = os.environ.get("AUN_TEST_AID", "cross-py.agentid.pub").strip()
        self.issuer = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
        self.gateway_aid = os.environ.get("AUN_GATEWAY_AID", f"gateway.{self.issuer}").strip()
        self.gateway_url = os.environ.get("AUN_GATEWAY_URL", "").strip()
        self.slot_id = os.environ.get("AUN_TEST_SLOT_ID", f"cross-sdk-python-{uuid.uuid4().hex[:8]}").strip()
        self.aun_path = os.environ.get("AUN_TEST_AUN_PATH") or os.environ.get("AUN_DATA_ROOT") or "/data/aun"
        self.debug = _env_bool("AUN_TEST_DEBUG", False)
        self.client = AUNClient(
            {
                "aun_path": self.aun_path,
                "require_forward_secrecy": False,
            },
            debug=self.debug,
        )
        self.client._config_model.require_forward_secrecy = False
        self.client._test_slot_id = self.slot_id
        if self.gateway_url:
            self.client._gateway_url = self.gateway_url
        self.ready = False
        self.startup_error = ""
        self.inbox: list[dict[str, Any]] = []
        self.group_inbox: list[dict[str, Any]] = []
        self.traces: dict[str, list[dict[str, Any]]] = {}
        self.send_results: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _sdk_version() -> str:
        try:
            from aun_core import __version__

            return str(__version__)
        except Exception:
            return "unknown"

    async def start(self) -> None:
        self.client.on("message.received", self._on_message_received)
        self.client.on("message.undecryptable", self._on_message_undecryptable)
        self.client.on("group.message_created", self._on_group_message_created)
        self.client.on("group.message_undecryptable", self._on_group_message_undecryptable)
        await self._ensure_connected()
        self.ready = True

    async def close(self) -> None:
        try:
            await self.client.close()
        except Exception:
            pass

    async def _ensure_connected(self) -> None:
        if self.gateway_url:
            self.client._gateway_url = self.gateway_url
        else:
            self.client._gateway_url = await self.client.auth._resolve_gateway(self.gateway_aid)
        try:
            await self.client.auth.create_aid({"aid": self.aid})
        except Exception as exc:
            local_identity = self.client._auth.load_identity_or_none(self.aid)
            if not local_identity:
                raise RuntimeError(f"create_aid failed and no local identity exists: {exc}") from exc
        auth = await self.client.auth.authenticate({"aid": self.aid})
        params = dict(auth)
        params["slot_id"] = self.slot_id
        params["auto_reconnect"] = _env_bool("AUN_TEST_AUTO_RECONNECT", False)
        params["background_sync"] = True
        await self.client.connect(params)

    def _record_trace(self, trace_id: str, item: dict[str, Any]) -> None:
        if not trace_id:
            return
        self.traces.setdefault(trace_id, []).append(
            {
                "ts": int(time.time() * 1000),
                "language": self.language,
                "aid": self.aid,
                **item,
            }
        )

    async def _store_inbox_item(self, item: dict[str, Any]) -> None:
        async with self._lock:
            self.inbox.append(item)
            if len(self.inbox) > 1000:
                self.inbox = self.inbox[-1000:]
            self._record_trace(str(item.get("trace_id") or ""), {"stage": "receive", "message": item})

    @staticmethod
    def _extract_envelope_metadata(data: dict[str, Any]) -> dict[str, Any]:
        e2ee = data.get("e2ee") if isinstance(data.get("e2ee"), dict) else {}
        protected_headers = data.get("protected_headers") if isinstance(data.get("protected_headers"), dict) else None
        if protected_headers is None and isinstance(e2ee, dict) and isinstance(e2ee.get("protected_headers"), dict):
            protected_headers = e2ee.get("protected_headers")
        payload_type = str(data.get("payload_type") or "").strip()
        if not payload_type and isinstance(protected_headers, dict):
            payload_type = str(protected_headers.get("payload_type") or "").strip()
        if not payload_type and isinstance(e2ee, dict):
            payload_type = str(e2ee.get("payload_type") or "").strip()
        out: dict[str, Any] = {}
        if payload_type:
            out["payload_type"] = payload_type
        if isinstance(protected_headers, dict):
            out["protected_headers"] = _json_safe(protected_headers)
        return out

    def _normalize_message(self, msg: Any, *, decrypted: bool, error_code: str = "") -> dict[str, Any]:
        data = msg if isinstance(msg, dict) else {"raw": msg}
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        trace_id = str(payload.get("trace_id") or data.get("trace_id") or "")
        text = str(payload.get("text") or data.get("text") or "")
        metadata = self._extract_envelope_metadata(data)
        return {
            "trace_id": trace_id,
            "message_id": str(data.get("message_id") or data.get("id") or ""),
            "from": str(data.get("from") or data.get("from_aid") or ""),
            "to": str(data.get("to") or data.get("to_aid") or self.aid),
            "text": text,
            "decrypted": bool(decrypted),
            "encrypted": bool(data.get("e2ee") or data.get("encrypted")),
            "seq": int(data.get("seq") or data.get("message_seq") or 0),
            "ack_seq": int(data.get("ack_seq") or 0),
            "error_code": error_code,
            "raw_sha256": _sha256_json(data),
            **metadata,
        }

    def _normalize_group_message(self, msg: Any, *, decrypted: bool, error_code: str = "") -> dict[str, Any]:
        data = msg if isinstance(msg, dict) else {"raw": msg}
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        trace_id = str(payload.get("trace_id") or data.get("trace_id") or "")
        text = str(payload.get("text") or data.get("text") or "")
        metadata = self._extract_envelope_metadata(data)
        return {
            "trace_id": trace_id,
            "group_id": str(data.get("group_id") or ""),
            "message_id": str(data.get("message_id") or data.get("id") or ""),
            "from": str(data.get("from") or data.get("from_aid") or data.get("sender_aid") or ""),
            "text": text,
            "decrypted": bool(decrypted),
            "encrypted": bool(data.get("e2ee") or data.get("encrypted")),
            "seq": int(data.get("seq") or data.get("message_seq") or data.get("msg_seq") or 0),
            "error_code": error_code,
            "raw_sha256": _sha256_json(data),
            **metadata,
        }

    def _on_message_received(self, msg: Any) -> None:
        item = self._normalize_message(msg, decrypted=True)
        asyncio.create_task(self._store_inbox_item(item))

    def _on_message_undecryptable(self, msg: Any) -> None:
        item = self._normalize_message(msg, decrypted=False, error_code="undecryptable")
        asyncio.create_task(self._store_inbox_item(item))

    async def _store_group_inbox_item(self, item: dict[str, Any]) -> None:
        async with self._lock:
            self.group_inbox.append(item)
            if len(self.group_inbox) > 1000:
                self.group_inbox = self.group_inbox[-1000:]
            self._record_trace(str(item.get("trace_id") or ""), {"stage": "group_receive", "message": item})

    def _on_group_message_created(self, msg: Any) -> None:
        item = self._normalize_group_message(msg, decrypted=True)
        asyncio.create_task(self._store_group_inbox_item(item))

    def _on_group_message_undecryptable(self, msg: Any) -> None:
        item = self._normalize_group_message(msg, decrypted=False, error_code="undecryptable")
        asyncio.create_task(self._store_group_inbox_item(item))

    def identity(self) -> dict[str, Any]:
        identity = self.client._identity or self.client._auth.load_identity_or_none(self.aid) or {}
        return {
            "aid": self.aid,
            "device_id": getattr(self.client, "_device_id", ""),
            "slot_id": getattr(self.client, "_slot_id", "") or self.slot_id,
            "issuer": self.issuer,
            "public_key_fingerprint": _cert_fingerprint(identity.get("cert") or identity.get("cert_pem")),
        }

    async def reset(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        trace_id = str(body.get("trace_id") or "")
        async with self._lock:
            if trace_id:
                self.inbox = [item for item in self.inbox if item.get("trace_id") != trace_id]
                self.group_inbox = [item for item in self.group_inbox if item.get("trace_id") != trace_id]
                self.traces.pop(trace_id, None)
                self.send_results.pop(trace_id, None)
            else:
                self.inbox.clear()
                self.group_inbox.clear()
                self.traces.clear()
                self.send_results.clear()
        return self._json({"ok": True})

    async def send(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        trace_id = str(body.get("trace_id") or uuid.uuid4().hex)
        message_id = str(body.get("message_id") or f"{trace_id}-{uuid.uuid4().hex[:8]}")
        target = str(body.get("to") or "").strip()
        text = str(body.get("text") or "")
        e2ee = bool(body.get("e2ee", True))
        if not target:
            return self._json({"ok": False, "error_code": "bad_request", "error_message": "to is required"}, status=400)
        payload = {
            "type": "text",
            "text": text,
            "trace_id": trace_id,
            "case_id": str(body.get("case_id") or trace_id),
        }
        params: dict[str, Any] = {
            "to": target,
            "payload": payload,
            "encrypt": e2ee,
            "message_id": message_id,
        }
        try:
            result = await self.client.call("message.send", params)
            response = {
                "ok": True,
                "trace_id": trace_id,
                "message_id": message_id,
                "seq": int(result.get("seq") or result.get("message_seq") or 0) if isinstance(result, dict) else 0,
                "encrypted": e2ee,
                "result": _json_safe(result),
            }
            self.send_results[trace_id] = response
            self._record_trace(trace_id, {"stage": "send", "target": target, "message_id": message_id, "result": response})
            return self._json(response)
        except Exception as exc:
            error = {
                "ok": False,
                "trace_id": trace_id,
                "message_id": message_id,
                "encrypted": e2ee,
                "error_code": exc.__class__.__name__,
                "error_message": str(exc),
            }
            self.send_results[trace_id] = error
            self._record_trace(trace_id, {"stage": "send_error", "target": target, "message_id": message_id, "error": error})
            return self._json(error, status=500)

    async def ack(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        seq = int(body.get("seq") or body.get("up_to_seq") or 0)
        params: dict[str, Any] = {}
        if seq > 0:
            params["seq"] = seq
        try:
            result = await self.client.call("message.ack", params)
            return self._json({"ok": True, "seq": seq, "result": _json_safe(result)})
        except Exception as exc:
            return self._json(
                {"ok": False, "seq": seq, "error_code": exc.__class__.__name__, "error_message": str(exc)},
                status=500,
            )

    async def pull(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        after_seq = int(body.get("after_seq") or 0)
        limit = int(body.get("limit") or 50)
        try:
            result = await self.client.call("message.pull", {"after_seq": after_seq, "limit": limit})
            messages = result.get("messages") if isinstance(result, dict) and isinstance(result.get("messages"), list) else []
            for msg in messages:
                await self._store_inbox_item(self._normalize_message(msg, decrypted=True))
            return self._json({"ok": True, "result": _json_safe(result)})
        except Exception as exc:
            return self._json(
                {"ok": False, "error_code": exc.__class__.__name__, "error_message": str(exc)},
                status=500,
            )

    async def group_create(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        trace_id = str(body.get("trace_id") or uuid.uuid4().hex)
        name = str(body.get("name") or f"cross-sdk-{trace_id[:8]}")
        members = body.get("members") if isinstance(body.get("members"), list) else []
        params: dict[str, Any] = {
            "name": name,
            "visibility": str(body.get("visibility") or "private"),
        }
        join_mode = str(body.get("join_mode") or "").strip()
        if join_mode:
            params["join_mode"] = join_mode
        try:
            create_result = await self.client.call("group.create", params)
            group_id = self._extract_group_id(create_result)
            if not group_id:
                raise RuntimeError(f"group.create did not return group_id: {create_result}")
            add_results = []
            for member in members:
                aid = str(member).strip()
                if not aid or aid == self.aid:
                    continue
                add_result = await self.client.call("group.add_member", {"group_id": group_id, "aid": aid, "role": "member"})
                add_results.append(_json_safe(add_result))
            response = {
                "ok": True,
                "trace_id": trace_id,
                "group_id": group_id,
                "create_result": _json_safe(create_result),
                "add_results": add_results,
            }
            self._record_trace(trace_id, {"stage": "group_create", "group_id": group_id, "result": response})
            return self._json(response)
        except Exception as exc:
            error = {"ok": False, "trace_id": trace_id, "error_code": exc.__class__.__name__, "error_message": str(exc)}
            self._record_trace(trace_id, {"stage": "group_create_error", "error": error})
            return self._json(error, status=500)

    async def group_ready(self, request: web.Request) -> web.Response:
        group_id = str(request.query.get("group_id") or "").strip()
        expected = [x.strip() for x in str(request.query.get("members") or self.aid).split(",") if x.strip()]
        require_devices = _env_bool("CROSS_SDK_GROUP_READY_REQUIRE_DEVICES", True)
        if not group_id:
            return self._json({"ok": False, "ready": False, "error_code": "bad_request", "error_message": "group_id is required"}, status=400)
        try:
            bootstrap = await self.client.call("group.v2.bootstrap", {"group_id": group_id})
            committed = set(bootstrap.get("committed_member_aids") or bootstrap.get("member_aids") or [])
            devices = bootstrap.get("devices") if isinstance(bootstrap.get("devices"), list) else []
            device_aids = {str(item.get("aid") or "") for item in devices if isinstance(item, dict)}
            membership_ok = all(aid in committed for aid in expected)
            devices_ok = (not require_devices) or all(aid in device_aids for aid in expected)
            ready = membership_ok and devices_ok
            return self._json(
                {
                    "ok": True,
                    "ready": ready,
                    "group_id": group_id,
                    "expected": expected,
                    "committed_member_aids": sorted(str(x) for x in committed),
                    "device_aids": sorted(device_aids),
                    "pending_adds": bootstrap.get("pending_adds") or [],
                    "bootstrap": _json_safe(bootstrap),
                }
            )
        except Exception as exc:
            return self._json({"ok": False, "ready": False, "error_code": exc.__class__.__name__, "error_message": str(exc)}, status=500)

    async def group_send(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        trace_id = str(body.get("trace_id") or uuid.uuid4().hex)
        message_id = str(body.get("message_id") or f"{trace_id}-{uuid.uuid4().hex[:8]}")
        group_id = str(body.get("group_id") or "").strip()
        text = str(body.get("text") or "")
        e2ee = bool(body.get("e2ee", True))
        if not group_id:
            return self._json({"ok": False, "error_code": "bad_request", "error_message": "group_id is required"}, status=400)
        payload = {
            "type": "text",
            "text": text,
            "trace_id": trace_id,
            "case_id": str(body.get("case_id") or trace_id),
        }
        try:
            result = await self.client.call(
                "group.send",
                {
                    "group_id": group_id,
                    "payload": payload,
                    "encrypt": e2ee,
                    "message_id": message_id,
                },
            )
            response = {
                "ok": True,
                "trace_id": trace_id,
                "group_id": group_id,
                "message_id": message_id,
                "seq": int(result.get("seq") or result.get("message_seq") or 0) if isinstance(result, dict) else 0,
                "encrypted": e2ee,
                "result": _json_safe(result),
            }
            self._record_trace(trace_id, {"stage": "group_send", "group_id": group_id, "message_id": message_id, "result": response})
            return self._json(response)
        except Exception as exc:
            error = {
                "ok": False,
                "trace_id": trace_id,
                "group_id": group_id,
                "message_id": message_id,
                "encrypted": e2ee,
                "error_code": exc.__class__.__name__,
                "error_message": str(exc),
            }
            self._record_trace(trace_id, {"stage": "group_send_error", "group_id": group_id, "message_id": message_id, "error": error})
            return self._json(error, status=500)

    async def group_pull(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        group_id = str(body.get("group_id") or "").strip()
        after_seq = int(body.get("after_seq") or 0)
        limit = int(body.get("limit") or 50)
        if not group_id:
            return self._json({"ok": False, "error_code": "bad_request", "error_message": "group_id is required"}, status=400)
        result = await self.client.call("group.pull", {"group_id": group_id, "after_seq": after_seq, "limit": limit})
        messages = result.get("messages") if isinstance(result, dict) and isinstance(result.get("messages"), list) else []
        for msg in messages:
            await self._store_group_inbox_item(self._normalize_group_message(msg, decrypted=True))
        return self._json({"ok": True, "group_id": group_id, "result": _json_safe(result)})

    async def group_ack(self, request: web.Request) -> web.Response:
        body = await self._read_json(request)
        group_id = str(body.get("group_id") or "").strip()
        seq = int(body.get("seq") or body.get("msg_seq") or body.get("up_to_seq") or 0)
        if not group_id:
            return self._json({"ok": False, "error_code": "bad_request", "error_message": "group_id is required"}, status=400)
        params: dict[str, Any] = {"group_id": group_id}
        if seq > 0:
            params["msg_seq"] = seq
            params["up_to_seq"] = seq
        try:
            result = await self.client.call("group.ack_messages", params)
            return self._json({"ok": True, "group_id": group_id, "seq": seq, "result": _json_safe(result)})
        except Exception as exc:
            return self._json(
                {
                    "ok": False,
                    "group_id": group_id,
                    "seq": seq,
                    "error_code": exc.__class__.__name__,
                    "error_message": str(exc),
                },
                status=500,
            )

    async def group_inbox_view(self, request: web.Request) -> web.Response:
        trace_id = str(request.query.get("trace_id") or "")
        group_id = str(request.query.get("group_id") or "")
        from_aid = str(request.query.get("from") or "")
        limit = int(request.query.get("limit") or 20)
        async with self._lock:
            items = list(self.group_inbox)
        if trace_id:
            items = [item for item in items if item.get("trace_id") == trace_id]
        if group_id:
            items = [item for item in items if item.get("group_id") == group_id]
        if from_aid:
            items = [item for item in items if item.get("from") == from_aid]
        items = items[-limit:]
        return self._json({"received": bool(items), "items": items})

    async def inbox_view(self, request: web.Request) -> web.Response:
        trace_id = str(request.query.get("trace_id") or "")
        from_aid = str(request.query.get("from") or "")
        limit = int(request.query.get("limit") or 20)
        async with self._lock:
            items = list(self.inbox)
        if trace_id:
            items = [item for item in items if item.get("trace_id") == trace_id]
        if from_aid:
            items = [item for item in items if item.get("from") == from_aid]
        items = items[-limit:]
        return self._json({"received": bool(items), "items": items})

    async def trace_view(self, request: web.Request) -> web.Response:
        trace_id = str(request.match_info.get("trace_id") or "")
        return self._json({"trace_id": trace_id, "items": self.traces.get(trace_id, [])})

    async def logs_view(self, request: web.Request) -> web.Response:
        log_dir = Path(os.environ.get("AUN_LOG_DIR", "/root/.aun/logs"))
        files = []
        if log_dir.exists():
            files = [str(p) for p in sorted(log_dir.rglob("*")) if p.is_file()][-20:]
        return self._json({"log_files": files, "tail": []})

    async def health(self, _request: web.Request) -> web.Response:
        return self._json(
            {
                "ok": not self.startup_error,
                "agent_ready": self.ready and getattr(self.client, "_state", "") == "connected",
                "state": getattr(self.client, "_state", ""),
                "aid": self.aid,
                "language": self.language,
                "sdk_version": self.sdk_version,
                "gateway_url": getattr(self.client, "_gateway_url", "") or "",
                "startup_error": self.startup_error,
            },
            status=200 if not self.startup_error else 503,
        )

    async def identity_view(self, _request: web.Request) -> web.Response:
        return self._json(self.identity())

    @staticmethod
    def _extract_group_id(result: Any) -> str:
        if not isinstance(result, dict):
            return ""
        if result.get("group_id"):
            return str(result.get("group_id") or "")
        group = result.get("group")
        if isinstance(group, dict) and group.get("group_id"):
            return str(group.get("group_id") or "")
        member = result.get("member")
        if isinstance(member, dict) and member.get("group_id"):
            return str(member.get("group_id") or "")
        return ""

    @staticmethod
    async def _read_json(request: web.Request) -> dict[str, Any]:
        if request.can_read_body:
            try:
                data = await request.json()
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        return {}

    @staticmethod
    def _json(data: dict[str, Any], status: int = 200) -> web.Response:
        return web.json_response(_json_safe(data), status=status)


async def _startup(agent: CrossSdkPythonAgent) -> None:
    try:
        await agent.start()
    except Exception as exc:
        agent.startup_error = f"{exc.__class__.__name__}: {exc}"
        traceback.print_exc()


async def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    agent = CrossSdkPythonAgent()
    app = web.Application()
    app.router.add_get("/health", agent.health)
    app.router.add_post("/reset", agent.reset)
    app.router.add_get("/identity", agent.identity_view)
    app.router.add_post("/send", agent.send)
    app.router.add_post("/ack", agent.ack)
    app.router.add_post("/pull", agent.pull)
    app.router.add_get("/inbox", agent.inbox_view)
    app.router.add_post("/group/create", agent.group_create)
    app.router.add_get("/group/ready", agent.group_ready)
    app.router.add_post("/group/send", agent.group_send)
    app.router.add_post("/group/pull", agent.group_pull)
    app.router.add_post("/group/ack", agent.group_ack)
    app.router.add_get("/group/inbox", agent.group_inbox_view)
    app.router.add_get("/traces/{trace_id}", agent.trace_view)
    app.router.add_get("/logs", agent.logs_view)
    app.on_startup.append(lambda _app: asyncio.create_task(_startup(agent)))
    app.on_cleanup.append(lambda _app: agent.close())

    host = os.environ.get("AUN_CONTROL_HOST", "0.0.0.0")
    port = int(os.environ.get("AUN_CONTROL_PORT", "9001"))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()
    print(f"cross-sdk python agent listening on {host}:{port}", flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
