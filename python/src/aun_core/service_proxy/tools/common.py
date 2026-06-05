from __future__ import annotations

import asyncio
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ... import AIDStore, AUNClient
from ...errors import AuthError, RateLimitError


def log(message: str, **fields: Any) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    parts = [f"[{stamp}]", message]
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={value}")
    print(" ".join(parts), flush=True)


def load_env_file(path: str | None) -> None:
    env_path = Path(path or ".env")
    if not env_path.exists() or not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        try:
            parts = shlex.split(value, posix=(os.name != "nt"))
            if len(parts) == 1:
                value = parts[0]
        except ValueError:
            value = value.strip("\"'")
        os.environ.setdefault(key, value)


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def split_provider_aid(provider_aid: str) -> tuple[str, str]:
    aid = str(provider_aid or "").strip().lower()
    if "." not in aid:
        raise ValueError("provider_aid 必须形如 {user}.{issuer}")
    user, issuer = aid.split(".", 1)
    if not user or not issuer:
        raise ValueError("provider_aid 必须形如 {user}.{issuer}")
    return user, issuer


def default_proxy_base(provider_aid: str, *, scheme: str = "https", port: str = "") -> str:
    _user, issuer = split_provider_aid(provider_aid)
    port_part = f":{port}" if str(port or "").strip() else ""
    return f"{scheme}://proxy.{issuer}{port_part}"


def default_aun_path(provider_aid: str, tag: str) -> str:
    safe = str(provider_aid or "provider").replace("/", "_").replace("\\", "_")
    return str(Path.home() / ".aun" / "service-proxy-tools" / tag / safe)


def join_url(base: str, path: str) -> str:
    root = str(base or "").rstrip("/")
    suffix = str(path or "")
    if not suffix.startswith("/"):
        suffix = "/" + suffix
    return root + suffix


def websocket_url_from_http(url: str) -> str:
    parsed = urlparse(url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return parsed._replace(scheme=scheme).geturl()


async def load_or_register_aun_client(
    aid: str,
    *,
    aun_path: str,
    seed: str = "",
    slot_id: str = "default",
    verify_ssl: bool = False,
    root_ca_path: str | None = None,
    debug: bool = False,
    connect_options: dict[str, Any] | None = None,
    auto_register: bool = True,
    attempts: int = 4,
) -> AUNClient:
    store = AIDStore(
        aun_path=aun_path,
        encryption_seed=seed,
        slot_id=slot_id,
        verify_ssl=verify_ssl,
        root_ca_path=root_ca_path,
        debug=debug,
    )
    try:
        loaded = store.load(aid)
        has_local_private_identity = bool(
            loaded.ok
            and loaded.data is not None
            and loaded.data["aid"].is_private_key_valid()
        )
        if auto_register:
            reason = "本地身份不存在，尝试注册" if not has_local_private_identity else "校验/恢复服务端 AID 注册"
            log(reason, aid=aid, aun_path=aun_path, slot_id=slot_id)
            registered = await store.register(aid)
            if not registered.ok:
                loaded_after_conflict = store.load(aid)
                conflict = (
                    not has_local_private_identity
                    and
                    registered.error is not None
                    and getattr(registered.error, "code", "") == "IDENTITY_CONFLICT"
                    and loaded_after_conflict.ok
                    and loaded_after_conflict.data is not None
                    and loaded_after_conflict.data["aid"].is_private_key_valid()
                )
                if not conflict:
                    message = registered.error.message if registered.error else f"{aid} register failed"
                    raise RuntimeError(message)
                log("服务端已存在同名 AID，继续使用本地可用身份", aid=aid)
            loaded = store.load(aid)
        elif not has_local_private_identity:
            log("本地身份不存在或私钥不可用，尝试注册", aid=aid, aun_path=aun_path, slot_id=slot_id)
            registered = await store.register(aid)
            if not registered.ok:
                loaded_after_conflict = store.load(aid)
                conflict = (
                    registered.error is not None
                    and getattr(registered.error, "code", "") == "IDENTITY_CONFLICT"
                    and loaded_after_conflict.ok
                    and loaded_after_conflict.data is not None
                    and loaded_after_conflict.data["aid"].is_private_key_valid()
                )
                if not conflict:
                    message = registered.error.message if registered.error else f"{aid} register failed"
                    raise RuntimeError(message)
                loaded = loaded_after_conflict
            else:
                loaded = store.load(aid)
        if not loaded.ok or loaded.data is None or not loaded.data["aid"].is_private_key_valid():
            message = loaded.error.message if loaded.error else f"{aid} identity load failed"
            raise RuntimeError(message)
        aid_obj = loaded.data["aid"]
    finally:
        store.close()

    client = AUNClient(aid_obj)
    opts = {
        "auto_reconnect": True,
        "background_sync": True,
    }
    opts.update(connect_options or {})
    last_error: Exception | None = None
    for attempt in range(max(1, int(attempts or 1))):
        try:
            await client.connect(opts)
            log("AUNClient 已连接 Gateway", aid=aid, gateway=client.gateway_url, device_id=client.device_id)
            return client
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= attempts - 1:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


def exit_with_error(message: str, code: int = 2) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)
