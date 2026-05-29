from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from weakref import WeakKeyDictionary

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from aun_core import AID, AIDStore, AUNClient, ConnectionState
from aun_core.errors import AuthError, RateLimitError
from aun_core.keystore.file import FileKeyStore

_CLIENT_STORE_OPTIONS: WeakKeyDictionary[AUNClient, dict[str, Any]] = WeakKeyDictionary()


def make_client_for_path(
    aun_path: str,
    *,
    debug: bool = False,
    protected_headers: dict[str, Any] | None = None,
    **config_overrides: Any,
) -> AUNClient:
    if "gateway" in config_overrides or "gateway_url" in config_overrides:
        raise TypeError("gateway must be discovered and cannot be supplied to make_client_for_path")
    client = AUNClient(debug=debug, protected_headers=protected_headers)
    overrides = dict(config_overrides)
    overrides["aun_path"] = str(aun_path)
    options = {
        "aun_path": str(aun_path),
        "encryption_seed": str(
            overrides.get("encryption_seed")
            or overrides.get("encryptionSeed")
            or overrides.get("seed_password")
            or overrides.get("seedPassword")
            or ""
        ),
        "verify_ssl": bool(overrides.get("verify_ssl", overrides.get("verifySSL", overrides.get("verifySsl", False)))),
        "discovery_port": overrides.get("discovery_port", overrides.get("discoveryPort")),
        "root_ca_path": overrides.get("root_ca_path", overrides.get("rootCaPath")),
        "require_forward_secrecy": overrides.get("require_forward_secrecy", overrides.get("requireForwardSecrecy")),
    }
    _CLIENT_STORE_OPTIONS[client] = options
    return client


def _import_configured_root_ca(store: AIDStore, root_ca_path: str | None) -> None:
    if not root_ca_path:
        return
    pem = Path(root_ca_path).read_text(encoding="utf-8")
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    trust_list = {
        "version": int(now.timestamp()),
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "next_update": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        "root_cas": [{
            "id": cert.subject.rfc4514_string(),
            "certificate": pem,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "status": "active",
        }],
    }
    keystore = FileKeyStore(store.aun_path, encryption_seed=store.encryption_seed)
    try:
        keystore.save_trust_roots(
            trust_list,
            [{
                "id": cert.subject.rfc4514_string(),
                "cert_pem": pem,
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            }],
        )
    finally:
        keystore.close()


def _store_for_client(client: AUNClient) -> AIDStore:
    store_options = _CLIENT_STORE_OPTIONS.get(client)
    if isinstance(store_options, dict):
        store = AIDStore(
            aun_path=str(store_options.get("aun_path") or client.config.get("aun_path")),
            encryption_seed=str(store_options.get("encryption_seed") or ""),
            verify_ssl=bool(store_options.get("verify_ssl", False)),
            discovery_port=store_options.get("discovery_port"),
            root_ca_path=store_options.get("root_ca_path"),
            debug=False,
        )
        _import_configured_root_ca(store, store_options.get("root_ca_path"))
        return store
    return AIDStore(
        aun_path=str(client.aun_path or client.config.get("aun_path")),
        encryption_seed=str(client.config.get("seed_password") or ""),
        debug=False,
    )


async def ensure_registered_identity(client: AUNClient, aid: str) -> AID:
    store = _store_for_client(client)
    try:
        loaded = store.load(aid)
        if not loaded.ok or loaded.data is None or not loaded.data["aid"].is_private_key_valid():
            registered = await store.register(aid)
            if not registered.ok:
                loaded_after_conflict = store.load(aid)
                if (
                    registered.error is None
                    or registered.error.code != "IDENTITY_CONFLICT"
                    or not loaded_after_conflict.ok
                    or loaded_after_conflict.data is None
                    or not loaded_after_conflict.data["aid"].is_private_key_valid()
                ):
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

    if client.state in {ConnectionState.NO_IDENTITY, ConnectionState.CLOSED}:
        client.load_identity(aid_obj)
    elif client.current_aid is not None and client.current_aid.aid != aid_obj.aid:
        raise RuntimeError(f"client already loaded identity {client.current_aid.aid}, cannot load {aid_obj.aid}")
    return aid_obj


async def ensure_authenticated_identity(
    client: AUNClient,
    aid: str,
    *,
    attempts: int = 4,
) -> dict[str, Any]:
    await ensure_registered_identity(client, aid)
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            return await client.authenticate()
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= attempts - 1:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} authenticate failed")


async def ensure_connected_identity(
    client: AUNClient,
    aid: str,
    *,
    connect_options: dict[str, Any] | None = None,
    attempts: int = 4,
) -> str:
    await ensure_registered_identity(client, aid)
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            await client.connect(dict(connect_options or {}))
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= attempts - 1:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")
