from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import secrets
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiohttp

from .aid import AID
from .errors import AUNError, ClientSignatureError, NotFoundError, StateError, ValidationError
from .logger import AUNLogger, NullLogger


AsyncOrSync = Awaitable[Any] | Any


class AgentMdManager:
    """agent.md 的本地持久化、远端同步和观察元数据管理器。

    Manager 只通过回调获取 token、gateway、AID 等能力，避免反向依赖 AUNClient/AIDStore。
    """

    def __init__(
        self,
        aun_path: str | Path,
        *,
        verify_ssl: bool = True,
        logger: AUNLogger | NullLogger | None = None,
        owner_aid_getter: Callable[[], str | None] | None = None,
        current_aid_getter: Callable[[], AID | None] | None = None,
        gateway_resolver: Callable[[str], AsyncOrSync] | None = None,
        peer_resolver: Callable[[str], AsyncOrSync] | None = None,
        token_provider: Callable[[], AsyncOrSync] | None = None,
        authenticator: Callable[[], AsyncOrSync] | None = None,
        aid_validator: Callable[[str], None] | None = None,
        trace_context_provider: Callable[[], dict[str, Any]] | None = None,
        http_head: Callable[..., AsyncOrSync] | None = None,
        http_get_text_with_headers: Callable[..., AsyncOrSync] | None = None,
        discovery_port: int | None = None,
    ) -> None:
        self.aun_path = str(aun_path)
        self.verify_ssl = bool(verify_ssl)
        self._log = logger or NullLogger()
        self._owner_aid_getter = owner_aid_getter
        self._current_aid_getter = current_aid_getter
        self._gateway_resolver = gateway_resolver
        self._peer_resolver = peer_resolver
        self._token_provider = token_provider
        self._authenticator = authenticator
        self._aid_validator = aid_validator
        self._trace_context_provider = trace_context_provider
        self._http_head = http_head
        self._http_get_text_with_headers = http_get_text_with_headers
        self._discovery_port = discovery_port
        self.cache: dict[str, dict[str, Any]] = {}
        self._download_inflight: set[str] = set()

    @staticmethod
    def content_etag(content: str) -> str:
        digest = hashlib.sha256(str(content or "").encode("utf-8")).hexdigest()
        return f'"{digest}"'

    @property
    def root(self) -> Path:
        root = Path(self.aun_path) / "AIDs"
        root.mkdir(parents=True, exist_ok=True)
        return root

    @staticmethod
    def safe_aid(aid: str) -> str:
        target = str(aid or "").strip()
        if not target or any(ch in target for ch in ("/", "\\", "\x00")):
            raise ValidationError("agent.md aid is empty or contains path separators")
        return target

    def file_path(self, aid: str) -> Path:
        return self.root / self.safe_aid(aid) / "agent.md"

    def meta_path(self, aid: str) -> Path:
        return self.root / self.safe_aid(aid) / "agentmd.json"

    def _owner_aid(self) -> str:
        if self._owner_aid_getter is None:
            return ""
        return str(self._owner_aid_getter() or "").strip()

    def _current_aid(self) -> AID | None:
        return self._current_aid_getter() if self._current_aid_getter is not None else None

    async def _maybe_await(self, value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    def _validate_aid(self, aid: str) -> str:
        target = self.safe_aid(aid)
        if self._aid_validator is not None:
            self._aid_validator(target)
        return target

    @contextmanager
    def _record_lock(self, aid: str):
        meta_path = self.meta_path(aid)
        lock_path = meta_path.parent / "agentmd.json.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a+b") as fp:
            try:
                if os.name == "nt":
                    import msvcrt

                    fp.seek(0)
                    msvcrt.locking(fp.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
                yield
            finally:
                try:
                    if os.name == "nt":
                        import msvcrt

                        fp.seek(0)
                        msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass

    @staticmethod
    def _atomic_write_text(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as fp:
                fp.write(content)
                fp.flush()
                os.fsync(fp.fileno())
            os.replace(tmp, path)
            if os.name != "nt":
                try:
                    dir_fd = os.open(str(path.parent), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except Exception:
                    pass
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass

    def _write_record_unlocked(self, aid: str, record: dict[str, Any]) -> None:
        payload = {k: v for k, v in record.items() if k != "content" and v is not None}
        payload["aid"] = self.safe_aid(aid)
        self._atomic_write_text(
            self.meta_path(aid),
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )

    def _normalize_record(self, aid: str, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            return {}
        record: dict[str, Any] = {k: v for k, v in data.items() if k != "content"}
        record["aid"] = self.safe_aid(str(record.get("aid") or aid))
        for key in ("fetched_at", "observed_at", "checked_at", "updated_at"):
            try:
                record[key] = int(record.get(key) or 0)
            except Exception:
                record[key] = 0
        return record

    def _read_record_unlocked(self, aid: str) -> dict[str, Any]:
        path = self.meta_path(aid)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return self._normalize_record(aid, data)
        except Exception as exc:
            self._log.warn("agent_md", "agent.md metadata damaged, ignoring: aid=%s err=%s", aid, exc)
            return {}

    def read_content(self, aid: str) -> str:
        return self.file_path(aid).read_text(encoding="utf-8")

    def write_content(self, aid: str, content: str) -> str:
        path = self.file_path(aid)
        self._atomic_write_text(path, str(content or ""))
        return str(path)

    def load_record(self, aid: str) -> dict[str, Any] | None:
        target = str(aid or "").strip()
        if not target:
            return None
        try:
            with self._record_lock(target):
                record = self._read_record_unlocked(target)
            loaded: dict[str, Any] = dict(record) if record else {"aid": target}
            loaded["aid"] = target
            try:
                content = self.read_content(target)
                loaded["content"] = content
                loaded["local_etag"] = self.content_etag(content)
            except Exception as exc:
                if self.meta_path(target).exists():
                    self._log.warn("agent_md", "agent.md content read failed: aid=%s err=%s", target, exc)
            if len(loaded) <= 1:
                return None
            if not record and "content" in loaded:
                with self._record_lock(target):
                    self._write_record_unlocked(target, {
                        "aid": target,
                        "local_etag": loaded.get("local_etag"),
                        "updated_at": int(time.time() * 1000),
                    })
            self.cache[target] = dict(loaded)
            return dict(loaded)
        except Exception as exc:
            self._log.debug("agent_md", "agent.md cache load skipped: aid=%s err=%s", target, exc)
            return None

    def save_record(self, aid: str, **fields: Any) -> dict[str, Any]:
        target = str(aid or "").strip()
        if not target:
            return {}
        try:
            content_marker = object()
            content = fields.pop("content", content_marker)
            saved_to = ""
            if content is not content_marker and content is not None:
                saved_to = self.write_content(target, str(content))
                fields.setdefault("local_etag", self.content_etag(str(content)))
                fields.setdefault("fetched_at", int(time.time() * 1000))
            with self._record_lock(target):
                record = dict(self._read_record_unlocked(target) or {})
                record["aid"] = target
                for key, value in fields.items():
                    if value is not None:
                        record[key] = value
                record["updated_at"] = int(time.time() * 1000)
                self._write_record_unlocked(target, record)
            loaded = dict(record)
            if content is not content_marker and content is not None:
                loaded["content"] = str(content)
                if saved_to:
                    loaded["saved_to"] = saved_to
            else:
                current = self.load_record(target)
                if current and "content" in current:
                    loaded["content"] = current["content"]
            self.cache[target] = dict(loaded)
            return dict(loaded)
        except Exception as exc:
            self._log.debug("agent_md", "agent.md cache save skipped: aid=%s err=%s", target, exc)
            return {}

    def has_local_content(self, aid: str, record: dict[str, Any] | None = None) -> bool:
        if isinstance(record, dict) and record.get("content"):
            return True
        try:
            return self.file_path(aid).is_file()
        except Exception:
            return False

    @staticmethod
    def checked_at_fresh(checked_at_ms: int, ttl_days: float) -> bool:
        try:
            days = float(ttl_days or 0)
        except (TypeError, ValueError):
            return False
        if days <= 0 or checked_at_ms <= 0:
            return False
        return (time.time() * 1000 - float(checked_at_ms)) <= days * 86400_000

    def _agent_md_url(self, aid: str, gateway_url: str = "") -> str:
        raw_gateway = str(gateway_url or "").strip().lower()
        scheme = "http" if raw_gateway.startswith("ws://") else "https"
        host = self.safe_aid(aid)
        if self._discovery_port and ":" not in host:
            host = f"{host}:{int(self._discovery_port)}"
        return f"{scheme}://{host}/agent.md"

    async def _resolve_gateway(self, aid: str) -> str:
        if self._gateway_resolver is None:
            return ""
        return str(await self._maybe_await(self._gateway_resolver(aid)))

    async def _resolve_peer(self, aid: str) -> AID:
        current = self._current_aid()
        if current is not None and current.aid == aid:
            return current
        if self._peer_resolver is None:
            raise StateError("agent.md peer resolver is not configured")
        peer = await self._maybe_await(self._peer_resolver(aid))
        if not isinstance(peer, AID):
            raise StateError(f"agent.md peer resolver did not return AID for {aid}")
        return peer

    async def _access_token(self) -> str:
        if self._token_provider is not None:
            token = str(await self._maybe_await(self._token_provider()) or "").strip()
            if token:
                return token
        if self._authenticator is not None:
            auth_result = await self._maybe_await(self._authenticator())
            if isinstance(auth_result, dict):
                token = str(auth_result.get("access_token") or "").strip()
                if token:
                    return token
        raise StateError("authenticate did not return access_token")

    async def upload(self, content: str | None = None) -> dict[str, Any]:
        """签名并上传 owner AID 的 agent.md。"""
        target = self._owner_aid()
        if not target:
            raise ValidationError("upload_agent_md requires local AID")
        current = self._current_aid()
        if current is None or not current.is_private_key_valid():
            raise StateError("upload_agent_md requires loaded AID with a valid private key")
        raw_content = self.read_content(target) if content is None else str(content)
        if not raw_content.strip():
            raise ValidationError("upload_agent_md requires non-empty content")
        signed_result = current.sign_agent_md(raw_content)
        if not signed_result.ok or signed_result.data is None:
            message = signed_result.error.message if signed_result.error else "agent.md signing failed"
            raise ClientSignatureError(message)
        signed = signed_result.data["signed"]

        _t_start = time.time()
        self._log.debug("agent_md", "upload_agent_md enter: aid=%s content_len=%d", target, len(signed))
        gateway_url = await self._resolve_gateway(target)
        token = await self._access_token()
        agent_md_url = self._agent_md_url(target, gateway_url)
        trace = self._trace_context_provider() if self._trace_context_provider is not None else {}
        trace_mode = str(trace.get("mode") or "off") if isinstance(trace, dict) else "off"
        trace_id = secrets.token_hex(16) if trace_mode != "off" else ""
        observer = trace.get("observer") if isinstance(trace, dict) else None
        if trace_id:
            self._log.info("agent_md", "[trace=%s] http_out PUT agent.md aid=%s", trace_id, target)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "text/markdown; charset=utf-8",
        }
        if trace_id:
            headers["X-AUN-Trace"] = trace_id
        timeout = aiohttp.ClientTimeout(total=30)
        ssl_param = None if self.verify_ssl else False
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.put(
                    agent_md_url,
                    data=signed.encode("utf-8"),
                    headers=headers,
                    ssl=ssl_param,
                ) as response:
                    duration_ms = int((time.time() - _t_start) * 1000)
                    if trace_id:
                        self._log.info("agent_md", "[trace=%s] http_in status=%d duration_ms=%d", trace_id, response.status, duration_ms)
                        if observer:
                            try:
                                observer({
                                    "type": "http",
                                    "trace_id": trace_id,
                                    "method": "PUT",
                                    "url": agent_md_url,
                                    "status": response.status,
                                    "duration_ms": duration_ms,
                                })
                            except Exception:
                                pass
                    if response.status == 404:
                        raise NotFoundError(f"agent.md endpoint not found for aid: {target}")
                    if response.status < 200 or response.status >= 300:
                        message = (await response.text()).strip()
                        raise AUNError(
                            f"upload agent.md failed: HTTP {response.status}"
                            + (f" - {message}" if message else "")
                        )
                    result = await response.json()
        except Exception as exc:
            self._log.debug("agent_md", "upload_agent_md exit (error): elapsed=%.3fs aid=%s err=%s", time.time() - _t_start, target, exc)
            raise

        local_etag = self.content_etag(signed)
        remote_etag = str(result.get("etag") or "").strip() if isinstance(result, dict) else ""
        self.save_record(
            target,
            content=signed,
            local_etag=local_etag,
            remote_etag=remote_etag,
            last_modified=str(result.get("last_modified") or result.get("lastModified") or "").strip() if isinstance(result, dict) else "",
            fetched_at=int(time.time() * 1000),
            remote_status="found" if remote_etag else "unknown",
            last_error="",
        )
        self._log.debug("agent_md", "upload_agent_md exit: elapsed=%.3fs aid=%s", time.time() - _t_start, target)
        return dict(result) if isinstance(result, dict) else {}

    async def _default_http_head(self, url: str, *, timeout: float = 15.0) -> tuple[int, dict[str, str]]:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        ssl_param = None if self.verify_ssl else False
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.head(url, ssl=ssl_param, allow_redirects=True) as response:
                return int(response.status), dict(response.headers)

    async def _default_http_get_text_with_headers(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> tuple[str, dict[str, str], int]:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        ssl_param = None if self.verify_ssl else False
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.get(url, ssl=ssl_param, headers=headers, allow_redirects=True) as response:
                text = await response.text()
                return text, dict(response.headers), int(response.status)

    async def _head(self, aid: str, *, timeout_s: float = 15.0) -> dict[str, Any]:
        target = self._validate_aid(aid)
        gateway_url = await self._resolve_gateway(target)
        url = self._agent_md_url(target, gateway_url)
        if self._http_head is not None:
            status, headers = await self._maybe_await(self._http_head(url, timeout=timeout_s))
        else:
            status, headers = await self._default_http_head(url, timeout=timeout_s)
        if status == 404:
            self.save_record(
                target,
                remote_etag="",
                last_modified="",
                checked_at=int(time.time() * 1000),
                remote_status="missing",
            )
            raise NotFoundError(f"agent.md not found for aid: {target}")
        if status < 200 or status >= 300:
            raise AUNError(f"head agent.md failed: HTTP {status}")
        content_length = 0
        try:
            content_length = int(str(headers.get("Content-Length") or headers.get("content-length") or "0"))
        except ValueError:
            content_length = 0
        data = {
            "aid": target,
            "found": True,
            "etag": str(headers.get("ETag") or headers.get("etag") or "").strip(),
            "last_modified": str(headers.get("Last-Modified") or headers.get("last-modified") or "").strip(),
            "content_length": content_length,
            "status": int(status),
        }
        self.save_record(
            target,
            remote_etag=data["etag"],
            last_modified=data["last_modified"],
            checked_at=int(time.time() * 1000),
            remote_status="found",
            last_error="",
        )
        return data

    async def download(self, aid: str | None = None, *, timeout_s: float | None = None) -> dict[str, Any]:
        target = str(aid or self._owner_aid() or "").strip()
        if not target:
            raise ValidationError("download_agent_md requires aid (or local AID)")
        target = self._validate_aid(target)
        self._log.debug("agent_md", "download_agent_md enter: aid=%s", target)
        gateway_url = await self._resolve_gateway(target)
        url = self._agent_md_url(target, gateway_url)
        cached = self.load_record(target) or {}
        headers: dict[str, str] = {"Accept": "text/markdown"}
        etag = str(cached.get("remote_etag") or cached.get("etag") or cached.get("local_etag") or "").strip()
        last_modified = str(cached.get("last_modified") or "").strip()

        async def request_with(request_headers: dict[str, str]) -> tuple[str, dict[str, str], int]:
            if self._http_get_text_with_headers is not None:
                return await self._maybe_await(
                    self._http_get_text_with_headers(
                        url,
                        headers=request_headers,
                        timeout=timeout_s if timeout_s is not None else 30.0,
                    )
                )
            return await self._default_http_get_text_with_headers(
                url,
                headers=request_headers,
                timeout=timeout_s if timeout_s is not None else 30.0,
            )

        content, response_headers, status = await request_with(headers)
        reused_cached_not_modified = False
        if status == 304 and cached.get("content") is None:
            content, response_headers, status = await request_with({"Accept": "text/markdown"})
        if status == 304 and cached.get("content") is not None:
            reused_cached_not_modified = True
            content = str(cached["content"])
            response_headers = dict(response_headers or {})
            response_headers.setdefault("ETag", etag)
            if last_modified:
                response_headers.setdefault("Last-Modified", last_modified)
        if status == 404:
            self.save_record(target, remote_status="missing", checked_at=int(time.time() * 1000), last_error="")
            raise NotFoundError(f"agent.md not found for aid: {target}")
        if (status < 200 or status >= 300) and not reused_cached_not_modified:
            raise AUNError(f"download agent.md failed: HTTP {status}")

        peer = await self._resolve_peer(target)
        verified = peer.verify_agent_md(content)
        if not verified.ok or verified.data is None:
            message = verified.error.message if verified.error else "agent.md verification failed"
            raise AUNError(message)
        signature = dict(verified.data)
        status_text = str(signature.get("status") or "invalid")
        verification: dict[str, str] = {"status": status_text}
        reason = str(signature.get("reason") or "").strip()
        if reason:
            verification["reason"] = reason

        response_etag = str(response_headers.get("ETag") or response_headers.get("etag") or "").strip()
        response_last_modified = str(
            response_headers.get("Last-Modified") or response_headers.get("last_modified") or response_headers.get("last-modified") or ""
        ).strip()
        local_etag = self.content_etag(content)
        saved = self.save_record(
            target,
            content=content,
            local_etag=local_etag,
            remote_etag=response_etag,
            last_modified=response_last_modified,
            fetched_at=int(time.time() * 1000),
            checked_at=int(time.time() * 1000),
            remote_status="found",
            verify_status=status_text,
            verify_error=reason,
            last_error="",
        )
        owner = self._owner_aid()
        in_sync: bool | None = None
        if target == owner:
            remote = response_etag or str(saved.get("remote_etag") or "")
            in_sync = (local_etag == remote) if (local_etag and remote) else False
        result = {
            "aid": target,
            "content": content,
            "verification": verification,
            "signature": signature,
            "cert_pem": peer.cert_pem,
            "etag": response_etag,
            "last_modified": response_last_modified,
            "status": int(status),
            "in_sync": in_sync,
            "saved_to": saved.get("saved_to") or str(self.file_path(target)),
            "save_error": None,
        }
        self._log.debug("agent_md", "download_agent_md exit: aid=%s status=%s", target, status_text)
        return result

    async def check(self, aid: str, ttl_days: int | float = 1) -> dict[str, Any]:
        target = self._validate_aid(aid)
        before = self.load_record(target) or {}
        local_etag = str(before.get("local_etag") or "").strip()
        local_found = bool(before and (before.get("content") or local_etag))
        remote_etag_cached = str(before.get("remote_etag") or before.get("etag") or "").strip()
        last_modified_cached = str(before.get("last_modified") or "").strip()
        checked_at_cached = int(before.get("checked_at") or before.get("fetched_at") or 0)
        cached_in_sync = bool(local_found and local_etag and remote_etag_cached and local_etag == remote_etag_cached)
        if cached_in_sync and self.checked_at_fresh(checked_at_cached, ttl_days):
            return {
                "aid": target,
                "local_found": True,
                "remote_found": True,
                "local_etag": local_etag,
                "remote_etag": remote_etag_cached,
                "in_sync": True,
                "needs_update": False,
                "last_modified": last_modified_cached,
                "status": 200,
                "cached": True,
                "verify_status": str(before.get("verify_status") or ""),
                "verify_error": str(before.get("verify_error") or ""),
                "ttl_days": int(ttl_days),
            }
        remote_missing_cached = str(before.get("remote_status") or "") == "missing"
        if (
            not local_found
            and not remote_etag_cached
            and remote_missing_cached
            and self.checked_at_fresh(checked_at_cached, ttl_days)
        ):
            return {
                "aid": target,
                "local_found": False,
                "remote_found": False,
                "local_etag": "",
                "remote_etag": "",
                "in_sync": False,
                "needs_update": False,
                "last_modified": "",
                "status": 404,
                "cached": True,
                "verify_status": "",
                "verify_error": "",
                "ttl_days": int(ttl_days),
            }
        try:
            remote = await self._head(target)
            remote_found = bool(remote.get("found"))
            remote_etag = str(remote.get("etag") or "").strip()
            last_modified = str(remote.get("last_modified") or remote.get("lastModified") or "").strip()
            status = int(remote.get("status") or (200 if remote_found else 404))
        except NotFoundError:
            remote_found = False
            remote_etag = ""
            last_modified = ""
            status = 404

        in_sync = bool(local_found and remote_found and local_etag and remote_etag and local_etag == remote_etag)
        needs_update = bool(remote_found and not in_sync)
        saved = self.load_record(target) or before
        return {
            "aid": target,
            "local_found": local_found,
            "remote_found": remote_found,
            "local_etag": local_etag,
            "remote_etag": remote_etag,
            "in_sync": in_sync,
            "needs_update": needs_update,
            "last_modified": last_modified,
            "status": status,
            "cached": False,
            "verify_status": str(saved.get("verify_status") or before.get("verify_status") or ""),
            "verify_error": str(saved.get("verify_error") or before.get("verify_error") or ""),
            "ttl_days": int(ttl_days),
        }

    def observe_meta(self, aid: str, etag: str = "", last_modified: str = "", *, source: str = "") -> None:
        target = str(aid or "").strip()
        remote_etag = str(etag or "").strip()
        remote_last_modified = str(last_modified or "").strip()
        if not target or not (remote_etag or remote_last_modified):
            return
        before = self.load_record(target) or {}
        same = (
            (not remote_etag or str(before.get("remote_etag") or "").strip() == remote_etag)
            and (not remote_last_modified or str(before.get("last_modified") or "").strip() == remote_last_modified)
        )
        record = dict(before)
        if not same or not before:
            fields: dict[str, Any] = {
                "observed_at": int(time.time() * 1000),
                "remote_status": "found",
            }
            if remote_etag:
                fields["remote_etag"] = remote_etag
            if remote_last_modified:
                fields["last_modified"] = remote_last_modified
            record = self.save_record(target, **fields) or record
        self._schedule_download_if_missing(target, record, source=source)
        self._log.debug(
            "agent_md",
            "agent.md meta observed: aid=%s etag=%s last_modified=%s source=%s",
            target,
            remote_etag or "-",
            remote_last_modified or "-",
            source or "-",
        )

    def observe_rpc_meta(self, meta: dict[str, Any], *, owner_aid: str | None = None) -> None:
        if not isinstance(meta, dict):
            return
        owner = str(owner_aid or self._owner_aid() or "").strip()
        etag = str(meta.get("agent_md_etag") or "").strip()
        if etag and owner:
            self.observe_meta(owner, etag, "", source="rpc.self")
        etags = meta.get("agent_md_etags")
        if isinstance(etags, dict):
            for key in ("requester", "peer", "receiver", "target", "to", "sender", "from"):
                item = etags.get(key)
                if not isinstance(item, dict):
                    continue
                self.observe_meta(
                    str(item.get("aid") or ""),
                    str(item.get("etag") or ""),
                    str(item.get("last_modified") or item.get("lastModified") or ""),
                    source=f"rpc.{key}",
                )

    def observe_envelope(self, envelope: Any) -> None:
        if not isinstance(envelope, dict):
            return
        agent_md = envelope.get("agent_md")
        if not isinstance(agent_md, dict):
            return
        sender = agent_md.get("sender")
        if not isinstance(sender, dict):
            return
        sender_aid = str(sender.get("aid") or "").strip()
        if not sender_aid:
            aad = envelope.get("aad") if isinstance(envelope.get("aad"), dict) else {}
            sender_aid = str(aad.get("from") or envelope.get("from") or "").strip()
        self.observe_meta(
            sender_aid,
            str(sender.get("etag") or ""),
            str(sender.get("last_modified") or sender.get("lastModified") or ""),
            source="envelope",
        )

    def event_snapshot(self, aid: str | None = None) -> dict[str, str] | None:
        target = str(aid or self._owner_aid() or "").strip()
        if not target:
            return None
        record = self.load_record(target) or {}
        local_etag = str(record.get("local_etag") or "").strip()
        remote_etag = str(record.get("remote_etag") or record.get("etag") or "").strip()
        if not local_etag and not remote_etag:
            return None
        return {"local_etag": local_etag, "remote_etag": remote_etag}

    def _schedule_download_if_missing(self, aid: str, record: dict[str, Any] | None, *, source: str = "") -> None:
        target = str(aid or "").strip()
        if not target or self.has_local_content(target, record):
            return
        if target in self._download_inflight:
            return

        async def _download_missing() -> None:
            try:
                await self.download(target)
            except Exception as exc:
                self.save_record(target, last_error=str(exc), remote_status="found")
                self._log.debug("agent_md", "agent.md auto download failed: aid=%s source=%s err=%s", target, source or "-", exc)
            finally:
                self._download_inflight.discard(target)

        self._download_inflight.add(target)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_download_missing())
        except RuntimeError:
            asyncio.run(_download_missing())
