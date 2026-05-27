from __future__ import annotations

import base64
from datetime import datetime, timezone
import re
import time
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..auth import _verify_signature
from ..errors import AUNError, NotFoundError, StateError, ValidationError

_AGENT_MD_SIGNATURE_MARKER = "<!-- AUN-SIGNATURE"
_AGENT_MD_SIGNATURE_RE = re.compile(
    r"<!-- AUN-SIGNATURE\r?\n(?P<body>.*?)\r?\n-->\s*\Z",
    re.DOTALL,
)
_AGENT_MD_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")


def _agent_md_http_scheme(gateway_url: str) -> str:
    raw = str(gateway_url or "").strip().lower()
    return "http" if raw.startswith("ws://") else "https"


def _agent_md_authority(aid: str, discovery_port: int | None) -> str:
    host = str(aid or "").strip()
    if not host:
        return ""
    if discovery_port and ":" not in host:
        return f"{host}:{int(discovery_port)}"
    return host


def _parse_agent_md_tail_signature(content: str) -> tuple[str, dict[str, str] | None, str | None]:
    marker_index = content.rfind(_AGENT_MD_SIGNATURE_MARKER)
    if marker_index < 0:
        return content, None, None
    if marker_index > 0 and content[marker_index - 1] not in "\r\n":
        return content, None, None

    tail = content[marker_index:]
    match = _AGENT_MD_SIGNATURE_RE.fullmatch(tail)
    if not match:
        return content[:marker_index], None, "malformed signature block"

    fields: dict[str, str] = {}
    for line in match.group("body").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ":" not in stripped:
            return content[:marker_index], None, f"malformed signature field: {stripped}"
        key, value = stripped.split(":", 1)
        fields[key.strip().lower()] = value.strip()

    for required in ("cert_fingerprint", "timestamp", "signature"):
        if not fields.get(required):
            return content[:marker_index], None, f"signature block missing {required}"
    if not _AGENT_MD_FINGERPRINT_RE.fullmatch(fields["cert_fingerprint"]):
        return content[:marker_index], None, "invalid cert_fingerprint"
    try:
        int(fields["timestamp"])
    except ValueError:
        return content[:marker_index], None, "invalid timestamp"

    return content[:marker_index], fields, None


def _extract_agent_md_aid(payload: str) -> str:
    lines = payload.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if stripped.startswith("aid:"):
            value = stripped.split(":", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            return value.strip()
    return ""


def _agent_md_result(
    status: str,
    payload: str,
    *,
    reason: str = "",
    aid: str = "",
    cert_fingerprint: str = "",
    timestamp: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "verified": status == "verified",
        "payload": payload,
    }
    if reason:
        result["reason"] = reason
    if aid:
        result["aid"] = aid
    if cert_fingerprint:
        result["cert_fingerprint"] = cert_fingerprint
    if timestamp is not None:
        result["timestamp"] = timestamp
    return result


class AuthNamespace:
    def __init__(self, client: Any) -> None:
        self._client = client

    async def _resolve_gateway(self, aid: str | None = None) -> str:
        """解析 gateway URL。优先使用已预置的 _gateway_url，否则基于 AID 自动发现。

        发现流程：
        1. 若 _gateway_url 已预置（内存），直接返回
        2. 从 keystore metadata 读 cached gateway_url（跨进程复用）
        3. 开发环境：先 gateway.{issuer}，再 fallback {aid}（泛域名在开发环境可能不可用）
        4. 生产环境：先 {aid}（泛域名 nameservice），再 fallback gateway.{issuer}
        """
        self._client._log.debug("auth", "_resolve_gateway entry aid=%s preset_gateway=%s", aid or "-", bool(self._client._gateway_url))
        if self._client._gateway_url:
            self._client._log.debug("auth", "_resolve_gateway using preset gateway=%s", self._client._gateway_url)
            return str(self._client._gateway_url)
        resolved_aid = aid or self._client._aid
        if resolved_aid:
            # 从 keystore metadata 读持久化的 gateway_url（避免每次进程启动都做 well-known discovery）
            try:
                cached_gateway = self._load_cached_gateway_url(resolved_aid)
                if cached_gateway:
                    self._client._log.debug("auth", "_resolve_gateway from keystore cache aid=%s gateway=%s", resolved_aid, cached_gateway)
                    self._client._gateway_url = cached_gateway
                    return cached_gateway
            except Exception as _exc:
                self._client._log.debug("auth", "load cached gateway_url failed: %s", _exc)

            parts = resolved_aid.split(".", 1)
            issuer_domain = parts[1] if len(parts) > 1 else resolved_aid

            port = self._client._config_model.discovery_port
            port_suffix = f":{port}" if port else ""

            aid_url = f"https://{resolved_aid}{port_suffix}/.well-known/aun-gateway"
            gateway_url = f"https://gateway.{issuer_domain}{port_suffix}/.well-known/aun-gateway"

            # 开发环境：先 gateway.{issuer}（固定域名），再 fallback {aid}（泛域名）
            # 生产环境：先 {aid}（泛域名），再 fallback gateway.{issuer}
            if self._client._config_model.verify_ssl:
                primary_url, fallback_url = aid_url, gateway_url
            else:
                primary_url, fallback_url = gateway_url, aid_url

            try:
                discovered = await self._client._discovery.discover(primary_url)
                self._client._log.debug("auth", "_resolve_gateway primary discovery succeeded aid=%s gateway=%s", resolved_aid, discovered)
                self._persist_gateway_url(resolved_aid, discovered)
                return discovered
            except Exception as _exc:
                self._client._log.debug("auth", "gateway discovery failed: %s", _exc)

            discovered = await self._client._discovery.discover(fallback_url)
            self._client._log.debug("auth", "_resolve_gateway fallback discovery succeeded aid=%s gateway=%s", resolved_aid, discovered)
            self._persist_gateway_url(resolved_aid, discovered)
            return discovered
        raise ValidationError(
            "unable to resolve gateway: set client._gateway_url or provide 'aid' for auto-discovery"
        )

    def _load_cached_gateway_url(self, aid: str) -> str:
        """从 keystore metadata 读取 cached gateway_url（用于跨进程复用，避免重做 discovery）"""
        import json as _json
        keystore = self._client._keystore
        try:
            db = keystore._get_db(aid)
            raw = db.get_metadata("gateway_url")
            if not raw:
                return ""
            # save_identity 走 json.dumps；这里 json.loads 兼容；裸字符串也兼容
            try:
                value = _json.loads(raw)
                if isinstance(value, str):
                    return value.strip()
            except (_json.JSONDecodeError, ValueError):
                pass
            return str(raw).strip()
        except Exception:
            return ""

    def _persist_gateway_url(self, aid: str, gateway_url: str) -> None:
        """持久化 gateway_url 到 keystore metadata，供跨进程复用"""
        import json as _json
        if not gateway_url or not aid:
            return
        try:
            keystore = self._client._keystore
            db = keystore._get_db(aid)
            # 与 save_identity 保持一致用 JSON 编码，避免 save_identity 之后被覆盖时格式冲突
            db.set_metadata("gateway_url", _json.dumps(gateway_url, ensure_ascii=False))
        except Exception as exc:
            self._client._log.debug("auth", "persist gateway_url failed aid=%s err=%s", aid, exc)

    async def register_aid(self, params: dict[str, Any]) -> dict[str, Any]:
        import time as _t
        _t_start = _t.time()
        aid = str((params or {}).get("aid") or "")
        if not aid:
            raise ValueError("auth.register_aid requires 'aid'")
        self._client._log.debug("auth", "namespace.register_aid enter: aid=%s", aid)
        try:
            gateway_url = await self._resolve_gateway(aid)
            self._client._gateway_url = gateway_url
            result = await self._client._auth.register_aid(gateway_url, aid)
            self._client._aid = result["aid"]
            self._client._identity = self._client._auth.load_identity_or_none(result["aid"])
            self._client._log.debug("auth", "namespace.register_aid exit: elapsed=%.3fs aid=%s gateway=%s", _t.time() - _t_start, result["aid"], gateway_url)
            return {
                "aid": result["aid"],
                "cert_pem": result["cert"],
                "gateway": gateway_url,
            }
        except Exception as exc:
            self._client._log.debug("auth", "namespace.register_aid exit (error): elapsed=%.3fs aid=%s err=%s", _t.time() - _t_start, aid, exc)
            raise

    async def check_aid(self, params: dict[str, Any]) -> dict[str, Any]:
        import time as _t
        _t_start = _t.time()
        aid = str((params or {}).get("aid") or "").strip()
        if not aid:
            raise ValueError("auth.check_aid requires 'aid'")
        self._client._log.debug("auth", "namespace.check_aid enter: aid=%s", aid)
        try:
            self._client._auth._validate_aid_name(aid)
            result = self._check_local_aid(aid)
            if not result["local"]["complete"]:
                result["remote"] = await self._check_remote_aid_registration(aid)
                remote_status = result["remote"].get("status")
                if remote_status == "available":
                    result["status"] = "available"
                    result["can_register"] = True
                elif remote_status == "registered":
                    result["status"] = "registered_remote"
                    result["can_register"] = False
                else:
                    result["status"] = "unknown"
                    result["can_register"] = False
            self._client._log.debug("auth", "namespace.check_aid exit: elapsed=%.3fs aid=%s status=%s", _t.time() - _t_start, aid, result.get("status"))
            return result
        except Exception as exc:
            self._client._log.debug("auth", "namespace.check_aid exit (error): elapsed=%.3fs aid=%s err=%s", _t.time() - _t_start, aid, exc)
            raise

    def _check_local_aid(self, aid: str) -> dict[str, Any]:
        keystore = self._client._keystore
        identity = self._client._auth.load_identity_or_none(aid)
        try:
            key_pair = keystore.load_key_pair(aid)
        except Exception as exc:
            key_pair = None
            key_error = str(exc)
        else:
            key_error = ""
        try:
            cert_pem = keystore.load_cert(aid)
        except Exception as exc:
            cert_pem = None
            cert_error = str(exc)
        else:
            cert_error = ""

        private_key_present = bool(isinstance(key_pair, dict) and key_pair.get("private_key_pem"))
        public_key_present = bool(isinstance(key_pair, dict) and key_pair.get("public_key_der_b64"))
        cert_present = bool(cert_pem)
        cert_info = self._inspect_cert(aid, cert_pem) if cert_pem else {
            "present": False,
            "valid": False,
            "expired": False,
        }
        local_complete = bool(private_key_present and public_key_present and cert_present and cert_info.get("valid"))
        issues: list[str] = []
        if identity is None:
            issues.append("local identity not found")
        if not private_key_present:
            issues.append("private key missing")
        if not public_key_present:
            issues.append("public key missing")
        if not cert_present:
            issues.append("certificate missing")
        elif cert_info.get("parse_error"):
            issues.append(f"certificate invalid: {cert_info['parse_error']}")
        elif cert_info.get("expired"):
            issues.append("certificate expired")
        elif not cert_info.get("valid"):
            issues.append("certificate not currently valid")
        if key_error:
            issues.append(f"key load error: {key_error}")
        if cert_error:
            issues.append(f"certificate load error: {cert_error}")

        return {
            "aid": aid,
            "status": "local_ready" if local_complete else "local_incomplete",
            "can_register": False if local_complete else None,
            "local": {
                "exists": identity is not None,
                "complete": local_complete,
                "private_key": private_key_present,
                "public_key": public_key_present,
                "certificate": cert_info,
                "issues": issues,
            },
            "remote": {
                "status": "not_checked" if local_complete else "pending",
            },
        }

    @staticmethod
    def _inspect_cert(aid: str, cert_pem: str | None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "present": bool(cert_pem),
            "valid": False,
            "expired": False,
        }
        if not cert_pem:
            return result
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            now = datetime.now(timezone.utc)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            fingerprint = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
            try:
                cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            except Exception:
                cn = ""
            result.update({
                "valid": not_before <= now <= not_after,
                "expired": now > not_after,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "expires_at": int(not_after.timestamp()),
                "seconds_until_expiry": int((not_after - now).total_seconds()),
                "fingerprint": fingerprint,
                "subject_cn": cn,
                "aid_matches": (not cn) or cn == aid,
            })
            if cn and cn != aid:
                result["valid"] = False
                result["parse_error"] = f"certificate CN mismatch: {cn}"
        except Exception as exc:
            result["parse_error"] = str(exc)
        return result

    async def _check_remote_aid_registration(self, aid: str) -> dict[str, Any]:
        try:
            content = await self.download_agent_md(aid)
            return {
                "status": "registered",
                "registered": True,
                "available": False,
                "source": "agent.md",
                "agent_md_bytes": len(content.encode("utf-8")),
                "agent_md_aid": _extract_agent_md_aid(content),
            }
        except NotFoundError:
            return {
                "status": "available",
                "registered": False,
                "available": True,
                "source": "agent.md",
            }
        except Exception as exc:
            return {
                "status": "unknown",
                "registered": None,
                "available": None,
                "source": "agent.md",
                "error": str(exc),
            }

    async def authenticate(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        import time as _t
        _t_start = _t.time()
        request = dict(params or {})
        aid = request.get("aid")
        self._client._log.debug("auth", "namespace.authenticate enter: aid=%s", aid or "-")
        try:
            gateway_url = await self._resolve_gateway(aid)
            self._client._gateway_url = gateway_url
            result = await self._client._auth.authenticate(gateway_url, aid=aid)
            self._client._aid = result["aid"]
            self._client._identity = self._client._auth.load_identity_or_none(result["aid"])
            self._client._log.debug("auth", "namespace.authenticate exit: elapsed=%.3fs aid=%s gateway=%s", _t.time() - _t_start, result["aid"], gateway_url)
            return result  # 已包含 gateway 字段
        except Exception as exc:
            self._client._log.debug("auth", "namespace.authenticate exit (error): elapsed=%.3fs aid=%s err=%s", _t.time() - _t_start, aid or "-", exc)
            raise

    async def _resolve_agent_md_url(self, aid: str) -> str:
        resolved_aid = str(aid or "").strip()
        if not resolved_aid:
            raise ValidationError("agent.md requires non-empty aid")
        gateway_url = str(self._client._gateway_url or "")
        if not gateway_url:
            try:
                gateway_url = await self._resolve_gateway(resolved_aid)
            except Exception:
                gateway_url = ""
        discovery_port = getattr(self._client._config_model, "discovery_port", None)
        authority = _agent_md_authority(resolved_aid, discovery_port)
        return f"{_agent_md_http_scheme(gateway_url)}://{authority}/agent.md"

    def _get_cached_access_token(self, identity: dict[str, Any]) -> str:
        token = str(identity.get("access_token") or "")
        if not token:
            return ""
        expires_at = self._client._auth.get_access_token_expiry(identity)
        if expires_at is not None and expires_at <= time.time() + 30:
            return ""
        return token

    async def _ensure_agent_md_upload_token(self, aid: str, gateway_url: str) -> str:
        identity = self._client._auth.load_identity_or_none(aid)
        if identity is None:
            raise StateError("no local identity found, call auth.register_aid() first")

        token = self._get_cached_access_token(identity)
        if token:
            return token

        refresh_token = str(identity.get("refresh_token") or "")
        if refresh_token:
            try:
                identity = await self._client._auth.refresh_cached_tokens(gateway_url, identity)
                token = self._get_cached_access_token(identity)
                if token:
                    self._client._identity = self._client._auth.load_identity_or_none(aid)
                    return token
            except Exception as exc:
                self._client._log.debug(
                    "auth",
                    "agent.md upload refresh_token 失败，回退到完整 authenticate: %s",
                    exc,
                )

        auth_result = await self.authenticate({"aid": aid})
        token = str(auth_result.get("access_token") or "")
        if not token:
            raise StateError("authenticate did not return access_token")
        return token

    async def upload_agent_md(self, content: str) -> dict[str, Any]:
        import time as _t
        import secrets as _secrets
        _t_start = _t.time()
        identity = self._client._auth.load_identity_or_none(self._client._aid)
        if identity is None:
            raise StateError("no local identity found, call auth.register_aid() first")
        aid = str(identity.get("aid") or self._client._aid or "").strip()
        if not aid:
            raise StateError("no local identity found, call auth.register_aid() first")
        self._client._log.debug("auth", "upload_agent_md enter: aid=%s content_len=%d", aid, len(content or ""))
        # HTTP trace
        trace_mode = getattr(self._client._transport, "_trace_mode", "off")
        trace_id = _secrets.token_hex(16) if trace_mode != "off" else ""
        if trace_id:
            self._client._log.info("auth", "[trace=%s] http_out PUT agent.md aid=%s", trace_id, aid)
        try:
            gateway_url = await self._resolve_gateway(aid)
            self._client._gateway_url = gateway_url
            token = await self._ensure_agent_md_upload_token(aid, gateway_url)
            agent_md_url = await self._resolve_agent_md_url(aid)

            timeout = aiohttp.ClientTimeout(total=30)
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "text/markdown; charset=utf-8",
            }
            if trace_id:
                headers["X-AUN-Trace"] = trace_id
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.put(agent_md_url, data=content.encode("utf-8"), headers=headers) as response:
                    duration_ms = int((_t.time() - _t_start) * 1000)
                    if trace_id:
                        self._client._log.info("auth", "[trace=%s] http_in status=%d duration_ms=%d", trace_id, response.status, duration_ms)
                        observer = getattr(self._client._transport, "_trace_observer", None)
                        if observer:
                            try:
                                observer({"type": "http", "trace_id": trace_id, "method": "PUT", "url": agent_md_url, "status": response.status, "duration_ms": duration_ms})
                            except Exception:
                                pass
                    if response.status == 404:
                        raise NotFoundError(f"agent.md endpoint not found for aid: {aid}")
                    if response.status < 200 or response.status >= 300:
                        message = (await response.text()).strip()
                        raise AUNError(
                            f"upload agent.md failed: HTTP {response.status}"
                            + (f" - {message}" if message else "")
                        )
                    result = await response.json()
                    self._client._log.debug("auth", "upload_agent_md exit: elapsed=%.3fs aid=%s status=%d", _t.time() - _t_start, aid, response.status)
                    return result
        except Exception as exc:
            self._client._log.debug("auth", "upload_agent_md exit (error): elapsed=%.3fs aid=%s err=%s", _t.time() - _t_start, aid, exc)
            raise

    async def head_agent_md(self, aid: str) -> dict[str, Any]:
        import time as _t
        _t_start = _t.time()
        target_aid = str(aid or "").strip()
        if not target_aid:
            raise ValidationError("head_agent_md requires non-empty aid")
        self._client._log.debug("auth", "head_agent_md enter: aid=%s", target_aid)
        try:
            agent_md_url = await self._resolve_agent_md_url(target_aid)
            timeout = aiohttp.ClientTimeout(total=15)
            headers = {"Accept": "text/markdown"}
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(agent_md_url, headers=headers) as response:
                    response_headers = getattr(response, "headers", None) or {}
                    etag = str(response_headers.get("ETag") or "").strip() if hasattr(response_headers, "get") else ""
                    last_modified = str(response_headers.get("Last-Modified") or "").strip() if hasattr(response_headers, "get") else ""
                    if response.status == 404:
                        result = {
                            "aid": target_aid,
                            "found": False,
                            "etag": "",
                            "last_modified": "",
                            "status": 404,
                        }
                        self._client._log.debug(
                            "auth",
                            "head_agent_md exit (not_found): elapsed=%.3fs aid=%s",
                            _t.time() - _t_start,
                            target_aid,
                        )
                        return result
                    if response.status < 200 or response.status >= 300:
                        raise AUNError(f"head agent.md failed: HTTP {response.status}")
                    if etag or last_modified:
                        cached = dict(self._agent_md_cache_store().get(target_aid) or {})
                        cached["etag"] = etag
                        cached["last_modified"] = last_modified
                        self._agent_md_cache_store()[target_aid] = cached
                    result = {
                        "aid": target_aid,
                        "found": True,
                        "etag": etag,
                        "last_modified": last_modified,
                        "status": response.status,
                    }
                    self._client._log.debug(
                        "auth",
                        "head_agent_md exit: elapsed=%.3fs aid=%s status=%d etag=%s",
                        _t.time() - _t_start,
                        target_aid,
                        response.status,
                        etag or "-",
                    )
                    return result
        except Exception as exc:
            self._client._log.debug("auth", "head_agent_md exit (error): elapsed=%.3fs aid=%s err=%s", _t.time() - _t_start, target_aid, exc)
            raise
    async def download_agent_md(self, aid: str) -> str:
        import time as _t
        import secrets as _secrets
        _t_start = _t.time()
        target_aid = str(aid or "").strip()
        if not target_aid:
            raise ValidationError("download_agent_md requires non-empty aid")
        self._client._log.debug("auth", "download_agent_md enter: aid=%s", target_aid)
        # HTTP trace
        trace_mode = getattr(self._client._transport, "_trace_mode", "off")
        trace_id = _secrets.token_hex(16) if trace_mode != "off" else ""
        if trace_id:
            self._client._log.info("auth", "[trace=%s] http_out GET agent.md aid=%s", trace_id, target_aid)
        try:
            agent_md_url = await self._resolve_agent_md_url(target_aid)

            cache_store = self._agent_md_cache_store()
            cached = cache_store.get(target_aid) or {}
            request_headers: dict[str, str] = {"Accept": "text/markdown"}
            # 不发送条件请求头，始终做无条件 GET（服务端 302 由 aiohttp 自动跟随）
            if trace_id:
                request_headers["X-AUN-Trace"] = trace_id

            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(agent_md_url, headers=request_headers, allow_redirects=True) as response:
                    duration_ms = int((_t.time() - _t_start) * 1000)
                    if trace_id:
                        self._client._log.info("auth", "[trace=%s] http_in status=%d duration_ms=%d", trace_id, response.status, duration_ms)
                        observer = getattr(self._client._transport, "_trace_observer", None)
                        if observer:
                            try:
                                observer({"type": "http", "trace_id": trace_id, "method": "GET", "url": agent_md_url, "status": response.status, "duration_ms": duration_ms})
                            except Exception:
                                pass
                    if response.status == 304:
                        # 304 不应出现（我们不发条件头），但防御性处理
                        if cached.get("text") is not None:
                            self._client._log.debug(
                                "auth",
                                "download_agent_md exit (not_modified): elapsed=%.3fs aid=%s",
                                _t.time() - _t_start, target_aid,
                            )
                            return cached["text"]
                        # 本地缓存为空却收到 304，警告并重试无条件 GET
                        self._client._log.warn("auth", "download_agent_md got 304 but no local cache, retrying unconditional GET: aid=%s", target_aid)
                        async with session.get(agent_md_url, headers={"Accept": "text/markdown"}, allow_redirects=True) as retry_resp:
                            if retry_resp.status == 404:
                                raise NotFoundError(f"agent.md not found for aid: {target_aid}")
                            if retry_resp.status < 200 or retry_resp.status >= 300:
                                message = (await retry_resp.text()).strip()
                                raise AUNError(
                                    f"download agent.md failed (retry): HTTP {retry_resp.status}"
                                    + (f" - {message}" if message else "")
                                )
                            text = await retry_resp.text()
                            self._client._log.debug("auth", "download_agent_md exit (retry): elapsed=%.3fs aid=%s content_len=%d", _t.time() - _t_start, target_aid, len(text))
                            return text
                    if response.status == 404:
                        raise NotFoundError(f"agent.md not found for aid: {target_aid}")
                    if response.status < 200 or response.status >= 300:
                        message = (await response.text()).strip()
                        raise AUNError(
                            f"download agent.md failed: HTTP {response.status}"
                            + (f" - {message}" if message else "")
                        )
                    text = await response.text()
                    response_headers = getattr(response, "headers", None) or {}
                    etag = str(response_headers.get("ETag") or "").strip() if hasattr(response_headers, "get") else ""
                    last_modified = str(response_headers.get("Last-Modified") or "").strip() if hasattr(response_headers, "get") else ""
                    if etag or last_modified:
                        cache_store[target_aid] = {
                            "text": text,
                            "etag": etag,
                            "last_modified": last_modified,
                        }
                    self._client._log.debug("auth", "download_agent_md exit: elapsed=%.3fs aid=%s content_len=%d", _t.time() - _t_start, target_aid, len(text))
                    return text
        except Exception as exc:
            self._client._log.debug("auth", "download_agent_md exit (error): elapsed=%.3fs aid=%s err=%s", _t.time() - _t_start, target_aid, exc)
            raise

    def _agent_md_cache_store(self) -> dict[str, dict[str, str]]:
        store = getattr(self, "_agent_md_cache", None)
        if store is None:
            store = {}
            self._agent_md_cache = store
        return store

    async def sign_agent_md(self, content: str, *, aid: str | None = None) -> str:
        import time as _t
        _t_start = _t.time()
        target_aid = str(aid or self._client._aid or "").strip()
        self._client._log.debug("auth", "sign_agent_md enter: aid=%s content_len=%d", target_aid or "-", len(content or ""))
        try:
            identity = self._client._auth.load_identity_or_none(target_aid or None)
            if identity is None:
                raise StateError("no local identity found, call auth.register_aid() first")

            private_key_pem = str(identity.get("private_key_pem") or "").strip()
            cert_pem = str(identity.get("cert") or "").strip()
            if not private_key_pem or not cert_pem:
                raise StateError("local identity missing private key or certificate")

            payload, _, _ = _parse_agent_md_tail_signature(str(content or ""))
            if payload and not payload.endswith(("\n", "\r")):
                payload += "\n"

            private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise StateError("agent.md signing requires an EC private key")

            signature = private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            fingerprint = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
            signed_block = "\n".join([
                "<!-- AUN-SIGNATURE",
                f"cert_fingerprint: {fingerprint}",
                f"timestamp: {int(time.time())}",
                f"signature: {base64.b64encode(signature).decode('ascii')}",
                "-->",
            ])
            result = payload + signed_block
            self._client._log.debug("auth", "sign_agent_md exit: elapsed=%.3fs aid=%s signed_len=%d", _t.time() - _t_start, target_aid or "-", len(result))
            return result
        except Exception as exc:
            self._client._log.debug("auth", "sign_agent_md exit (error): elapsed=%.3fs aid=%s err=%s", _t.time() - _t_start, target_aid or "-", exc)
            raise

    async def verify_agent_md(
        self,
        content: str,
        *,
        aid: str | None = None,
        cert_pem: str | None = None,
    ) -> dict[str, Any]:
        import time as _t
        _t_start = _t.time()
        self._client._log.debug("auth", "verify_agent_md enter: aid=%s content_len=%d has_cert=%s", aid or "-", len(content or ""), bool(cert_pem))
        payload, fields, parse_error = _parse_agent_md_tail_signature(str(content or ""))
        if fields is None:
            if parse_error is None:
                self._client._log.debug("auth", "verify_agent_md exit (unsigned): elapsed=%.3fs", _t.time() - _t_start)
                return _agent_md_result("unsigned", payload)
            self._client._log.debug("auth", "verify_agent_md exit (invalid-parse): elapsed=%.3fs reason=%s", _t.time() - _t_start, parse_error)
            return _agent_md_result("invalid", payload, reason=parse_error)

        expected_aid = str(aid or "").strip()
        payload_aid = _extract_agent_md_aid(payload)
        if expected_aid and payload_aid and payload_aid != expected_aid:
            self._client._log.debug("auth", "verify_agent_md exit (aid-mismatch): elapsed=%.3fs", _t.time() - _t_start)
            return _agent_md_result("invalid", payload, reason="aid mismatch", aid=payload_aid)
        if not expected_aid:
            expected_aid = payload_aid

        cert_text = str(cert_pem or "").strip()
        if not cert_text:
            if not expected_aid:
                self._client._log.debug("auth", "verify_agent_md exit (no-aid): elapsed=%.3fs", _t.time() - _t_start)
                return _agent_md_result("invalid", payload, reason="aid required to verify agent.md")
            try:
                fetched = await self._client._fetch_peer_cert(expected_aid, fields["cert_fingerprint"])
                cert_text = fetched.decode("utf-8") if isinstance(fetched, bytes) else str(fetched)
            except Exception as exc:
                self._client._log.debug("auth", "verify_agent_md exit (fetch-fail): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
                return _agent_md_result("invalid", payload, reason=str(exc), aid=expected_aid)

        try:
            cert = x509.load_pem_x509_certificate(cert_text.encode("utf-8"))
        except Exception as exc:
            self._client._log.debug("auth", "verify_agent_md exit (bad-cert): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
            return _agent_md_result("invalid", payload, reason=f"invalid certificate: {exc}", aid=expected_aid)

        actual_fp = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
        if actual_fp.lower() != fields["cert_fingerprint"].lower():
            self._client._log.debug("auth", "verify_agent_md exit (fp-mismatch): elapsed=%.3fs", _t.time() - _t_start)
            return _agent_md_result("invalid", payload, reason="certificate fingerprint mismatch", aid=expected_aid)

        if expected_aid:
            try:
                cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            except Exception:
                cn = ""
            if cn and cn != expected_aid:
                self._client._log.debug("auth", "verify_agent_md exit (cn-mismatch): elapsed=%.3fs", _t.time() - _t_start)
                return _agent_md_result("invalid", payload, reason="certificate aid mismatch", aid=expected_aid)

        try:
            public_key = cert.public_key()
            signature = base64.b64decode(fields["signature"], validate=True)
            _verify_signature(public_key, signature, payload.encode("utf-8"))
        except Exception as exc:
            self._client._log.debug("auth", "verify_agent_md exit (sig-fail): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
            return _agent_md_result("invalid", payload, reason=f"signature verification failed: {exc}", aid=expected_aid, cert_fingerprint=fields["cert_fingerprint"], timestamp=int(fields["timestamp"]))

        self._client._log.debug("auth", "verify_agent_md exit (verified): elapsed=%.3fs aid=%s", _t.time() - _t_start, expected_aid or payload_aid)
        return _agent_md_result(
            "verified",
            payload,
            aid=expected_aid or payload_aid,
            cert_fingerprint=fields["cert_fingerprint"],
            timestamp=int(fields["timestamp"]),
        )

    async def download_cert(self, params: dict[str, Any] | None = None) -> Any:
        import time as _t
        _t_start = _t.time()
        self._client._log.debug("auth", "namespace.download_cert enter")
        try:
            result = await self._client.call("auth.download_cert", params or {})
            self._client._log.debug("auth", "namespace.download_cert exit: elapsed=%.3fs", _t.time() - _t_start)
            return result
        except Exception as exc:
            self._client._log.debug("auth", "namespace.download_cert exit (error): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
            raise

    async def request_cert(self, params: dict[str, Any]) -> Any:
        import time as _t
        _t_start = _t.time()
        self._client._log.debug("auth", "namespace.request_cert enter")
        try:
            result = await self._client.call("auth.request_cert", params)
            self._client._log.debug("auth", "namespace.request_cert exit: elapsed=%.3fs", _t.time() - _t_start)
            return result
        except Exception as exc:
            self._client._log.debug("auth", "namespace.request_cert exit (error): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
            raise

    async def renew_cert(self, params: dict[str, Any] | None = None) -> Any:
        import time as _t
        _t_start = _t.time()
        self._client._log.debug("auth", "namespace.renew_cert enter")
        try:
            result = await self._client.call("auth.renew_cert", params or {})
            self._client._log.debug("auth", "namespace.renew_cert exit: elapsed=%.3fs", _t.time() - _t_start)
            return result
        except Exception as exc:
            self._client._log.debug("auth", "namespace.renew_cert exit (error): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
            raise

    async def rekey(self, params: dict[str, Any] | None = None) -> Any:
        import time as _t
        _t_start = _t.time()
        self._client._log.debug("auth", "namespace.rekey enter")
        try:
            result = await self._client.call("auth.rekey", params or {})
            self._client._log.debug("auth", "namespace.rekey exit: elapsed=%.3fs", _t.time() - _t_start)
            return result
        except Exception as exc:
            self._client._log.debug("auth", "namespace.rekey exit (error): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
            raise

    async def trust_roots(self, params: dict[str, Any] | None = None) -> Any:
        import time as _t
        _t_start = _t.time()
        self._client._log.debug("auth", "namespace.trust_roots enter")
        try:
            result = await self._client.call("meta.trust_roots", params or {})
            self._client._log.debug("auth", "namespace.trust_roots exit: elapsed=%.3fs", _t.time() - _t_start)
            return result
        except Exception as exc:
            self._client._log.debug("auth", "namespace.trust_roots exit (error): elapsed=%.3fs err=%s", _t.time() - _t_start, exc)
            raise
