from __future__ import annotations

import inspect
import json
import base64
import asyncio
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TypedDict
from urllib.parse import quote, urlencode, urlparse, urlunparse

import aiohttp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from . import error_codes as codes
from ._cert_utils import cert_common_name, cert_matches_fingerprint, cert_time_error, public_key_der, sign_bytes, verify_signature
from .agent_md import AgentMdManager
from .auth import AuthFlow
from .register_flow import RegisterFlow
from .aid import AID
from .config import get_device_id, normalize_slot_id, resolve_verify_ssl_from_env
from .crypto import CryptoProvider
from .discovery import GatewayDiscovery
from .errors import AUNError, ClientSignatureError, ConnectionError, IdentityConflictError, NotFoundError, StateError, ValidationError
from .keystore.local_identity_store import LocalIdentityStore
from .keystore.local_token_store import LocalTokenStore
from .logger import AUNLogger, NullLogger
from .net import DnsResilientNet
from .result import Result, result_err, result_ok


_AUTHORITY_ENDPOINT = "https://trust.aun.network/.well-known/aun/trust-roots.json"
_MAX_CLOCK_SKEW = 300


class DownloadAgentMdResult(TypedDict):
    aid: str
    content: str
    verification: dict  # { status: str, reason?: str }
    cert_pem: str
    etag: str
    last_modified: str


class CheckAgentMdResult(TypedDict):
    aid: str
    local_found: bool
    remote_found: bool
    local_etag: str
    remote_etag: str
    needs_update: bool
    ttl_days: int


class UploadAgentMdResult(TypedDict, total=False):
    aid: str
    etag: str
    last_modified: str
    agent_md_url: str


class DiagnoseResult(TypedDict):
    aid: str
    status: str
    local_valid: bool
    remote_registered: bool
    suggestions: list
    local: dict
    remote: dict


class RenewCertResult(TypedDict):
    renewed: bool
    new_cert_not_after: object  # datetime
    new_fingerprint: str


class RekeyResult(TypedDict):
    rekeyed: bool
    new_cert_not_after: object  # datetime
    new_fingerprint: str


class ImportGroupIdentityResult(TypedDict):
    imported: bool


class ChangeSeedResult(TypedDict):
    changed: bool
    count: int


class ResolveResult(TypedDict):
    aid: object  # AID
    agent_md: dict  # optional
    source: dict  # { cert_from_cache: bool, agent_md_fetched: bool }


class ListResult(TypedDict):
    identities: list  # list[AIDInfo]


class AIDStore:
    def __init__(
        self,
        aun_path: str | Path,
        encryption_seed: str,
        *,
        slot_id: str = "default",
        verify_ssl: bool | None = None,
        root_ca_path: str | None = None,
        debug: bool = False,
        logger: AUNLogger | NullLogger | None = None,
    ) -> None:
        self.aun_path = str(aun_path)
        self.encryption_seed = str(encryption_seed)
        self.device_id = get_device_id(self.aun_path)
        self.slot_id = normalize_slot_id(slot_id)
        self._gateway_cache: dict[str, str] = {}
        self._cert_op_locks: dict[str, asyncio.Lock] = {}
        self._verify_ssl = resolve_verify_ssl_from_env() if verify_ssl is None else bool(verify_ssl)
        self._root_ca_path = root_ca_path
        self._log = logger or AUNLogger(debug=debug, aun_path=self.aun_path)
        self._log.bind_device_id(self.device_id)
        self._keystore = LocalIdentityStore(
            self.aun_path,
            encryption_seed=self.encryption_seed,
            logger=self._log,
        )
        self._token_store = LocalTokenStore(
            self.aun_path,
            logger=self._log,
        )
        self._net = DnsResilientNet(
            self.aun_path,
            verify_ssl=self._verify_ssl,
            logger=self._log,
        )
        self._discovery = GatewayDiscovery(
            verify_ssl=self._verify_ssl,
            logger=self._log,
            net=self._net,
        )
        self._register_flow = RegisterFlow(
            keystore=self._keystore,
            crypto=CryptoProvider(),
            verify_ssl=self._verify_ssl,
            root_ca_path=self._root_ca_path,
            logger=self._log,
            net=self._net,
        )
        async def resolve_peer(aid: str, cert_fingerprint: str | None = None) -> AID:
            target = str(aid or "").strip()
            fp = str(cert_fingerprint or "").strip().lower()
            local_identity = self._keystore.load_identity(target)
            local_cert = (local_identity or {}).get("cert")
            local_cert_pem = local_cert if isinstance(local_cert, str) else ""
            if local_cert_pem.strip():
                try:
                    local_obj = x509.load_pem_x509_certificate(local_cert_pem.encode("utf-8"))
                    if not fp or cert_matches_fingerprint(local_obj, fp):
                        return AID._create(
                            aid=target,
                            aun_path=self.aun_path,
                            cert_pem=local_cert_pem,
                            cert_obj=local_obj,
                            private_key_obj=None,
                            cert_valid=True,
                            private_key_valid=False,
                            device_id=self.device_id,
                            slot_id=self.slot_id,
                            verify_ssl=self._verify_ssl,
                            debug=bool(getattr(self._log, "_debug", False)),
                        )
                except Exception:
                    pass
            gateway_url = await self._resolved_gateway(target)
            if fp:
                cert_pem, _headers, status = await self._http_get_text_with_headers(
                    self._pki_cert_url(gateway_url, target, fp),
                    timeout=10.0,
                )
                if status < 200 or status >= 300:
                    raise AUNError(f"certificate not found for aid: {target}")
                self._keystore.save_cert(target, cert_pem, fp, make_active=False)
            else:
                cert_pem = await self._register_flow.fetch_peer_cert(gateway_url, target)
                if not cert_pem:
                    raise AUNError(f"certificate not found for aid: {target}")
                self._keystore.save_cert(target, cert_pem)
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            return AID._create(
                aid=target,
                aun_path=self.aun_path,
                cert_pem=cert_pem,
                cert_obj=cert_obj,
                private_key_obj=None,
                cert_valid=True,
                private_key_valid=False,
                device_id=self.device_id,
                slot_id=self.slot_id,
                verify_ssl=self._verify_ssl,
                debug=bool(getattr(self._log, "_debug", False)),
            )

        self._agent_md_manager = AgentMdManager(
            self.aun_path,
            verify_ssl=self._verify_ssl,
            logger=self._log,
            gateway_resolver=lambda aid: self._resolved_gateway(aid),
            peer_resolver=resolve_peer,
            aid_validator=self._register_flow.validate_aid_name,
            http_head=lambda url, *, timeout=15.0: self._http_head(url, timeout=timeout),
            http_get_text_with_headers=lambda url, *, headers=None, timeout=30.0: self._http_get_text_with_headers(
                url,
                headers=headers,
                timeout=timeout,
            ),
        )

    def close(self) -> None:
        self._keystore.close()
        self._token_store.close()
        self._net.close()

    def load(self, aid: str) -> Result[dict[str, AID]]:
        target = str(aid or "").strip()
        cert_pem = self._keystore.load_cert(target)
        if not cert_pem:
            return result_err(codes.CERT_NOT_FOUND, f"certificate not found for aid: {target}")
        try:
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except Exception as exc:
            return result_err(codes.CERT_PARSE_ERROR, f"certificate parse failed for aid: {target}", cause=exc)

        time_error = cert_time_error(cert_obj)
        if time_error == "expired":
            return result_err(codes.CERT_EXPIRED, f"certificate expired for aid: {target}")
        if time_error == "not_yet_valid":
            return result_err(codes.CERT_NOT_YET_VALID, f"certificate not yet valid for aid: {target}")

        cert_cn = cert_common_name(cert_obj)
        if cert_cn and cert_cn != target:
            return result_err(codes.CERT_CHAIN_BROKEN, f"certificate CN mismatch: expected {target}, got {cert_cn}")

        key_pair: dict[str, Any] | None
        try:
            key_pair = self._keystore.load_key_pair(target)
        except Exception as exc:
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, f"private key load failed for aid: {target}", cause=exc)

        if not key_pair or not key_pair.get("private_key_pem"):
            return result_ok({
                "aid": AID._create(
                    aid=target,
                    aun_path=self.aun_path,
                    cert_pem=cert_pem,
                    cert_obj=cert_obj,
                    private_key_obj=None,
                    cert_valid=True,
                    private_key_valid=False,
                    device_id=self.device_id,
                    slot_id=self.slot_id,
                    verify_ssl=self._verify_ssl,
                    root_ca_path=self._root_ca_path,
                    debug=self._log._debug if hasattr(self._log, "_debug") else False,
                )
            })

        try:
            private_key = serialization.load_pem_private_key(
                str(key_pair.get("private_key_pem") or "").encode("utf-8"),
                password=None,
            )
        except Exception as exc:
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, f"private key parse failed for aid: {target}", cause=exc)

        try:
            cert_pub_der = public_key_der(cert_obj.public_key())
            declared_pub_b64 = str(key_pair.get("public_key_der_b64") or "").strip()
            if declared_pub_b64 and base64.b64decode(declared_pub_b64) != cert_pub_der:
                return result_err(codes.KEYPAIR_MISMATCH, f"keypair public key mismatch for aid: {target}")
            if public_key_der(private_key.public_key()) != cert_pub_der:
                return result_err(codes.KEYPAIR_MISMATCH, f"private key does not match certificate for aid: {target}")
            probe = b"aun-aidstore-private-key-self-test"
            signature = sign_bytes(private_key, probe)
            verify_signature(cert_obj.public_key(), signature, probe)
        except Exception as exc:
            return result_err(codes.KEYPAIR_MISMATCH, f"keypair self-test failed for aid: {target}", cause=exc)

        return result_ok({
            "aid": AID._create(
                aid=target,
                aun_path=self.aun_path,
                cert_pem=cert_pem,
                cert_obj=cert_obj,
                private_key_obj=private_key,
                cert_valid=True,
                private_key_valid=True,
                device_id=self.device_id,
                slot_id=self.slot_id,
                verify_ssl=self._verify_ssl,
                root_ca_path=self._root_ca_path,
                debug=self._log._debug if hasattr(self._log, "_debug") else False,
                private_key_pem=str(key_pair.get("private_key_pem") or ""),
            )
        })

    def list(self) -> Result[ListResult]:
        identities: list[dict[str, Any]] = []
        try:
            aids = self._keystore.list_identities()
            for aid in sorted(aids):
                loaded = self.load(aid)
                if not loaded.ok or loaded.data is None:
                    continue
                item = loaded.data["aid"]
                if not item.is_private_key_valid():
                    continue
                identities.append({
                    "aid": item.aid,
                    "cert_not_after": item.cert_not_after,
                    "cert_issuer": item.cert_issuer,
                    "cert_fingerprint": item.cert_fingerprint,
                })
            return result_ok({"identities": identities})
        except Exception as exc:
            return result_err("LIST_IDENTITIES_FAILED", str(exc), cause=exc)

    def change_seed(self, old_seed: str, new_seed: str) -> Result[ChangeSeedResult]:
        if not isinstance(old_seed, str) or not old_seed.strip():
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, "change_seed requires a non-empty old_seed")
        if not isinstance(new_seed, str) or not new_seed.strip():
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, "change_seed requires a non-empty new_seed")
        if old_seed == new_seed:
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, "new_seed must differ from old_seed")
        try:
            migration = self._keystore.change_seed(old_seed, new_seed)
            count = int(getattr(migration, "private_keys_migrated", 0) or getattr(migration, "migrated", 0) or 0)
            self.encryption_seed = str(new_seed)
            return result_ok({"changed": True, "count": count})
        except Exception as exc:
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, str(exc), cause=exc)

    async def register(self, aid: str) -> Result[dict[str, bool]]:
        target = str(aid or "").strip()
        self._log.debug("aid_store", "register enter: aid=%s", target or "-")
        try:
            self._register_flow.validate_aid_name(target)
            gateway_url = await self._resolved_gateway(target)
            result = await self._register_flow.register_aid(gateway_url, target)
            # 私钥由 AIDStore 写入，RegisterFlow 不写 key.json
            cert_pem = str(result.get("cert") or "")
            if cert_pem:
                self._keystore.save_cert(target, cert_pem)
            key_pair = {k: result[k] for k in ("private_key_pem", "public_key_der_b64", "curve") if result.get(k)}
            if key_pair:
                self._keystore.save_key_pair(target, key_pair)
            self._persist_gateway_url(target, gateway_url)
            self._log.debug("aid_store", "register exit: aid=%s gateway=%s", target, gateway_url)
            return result_ok({"registered": True})
        except IdentityConflictError as exc:
            self._log.debug("aid_store", "register exit (conflict): aid=%s err=%s", target, exc)
            return result_err(codes.IDENTITY_CONFLICT, str(exc), cause=exc)
        except (ValidationError, ValueError) as exc:
            self._log.debug("aid_store", "register exit (invalid): aid=%s err=%s", target, exc)
            return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
        except (ConnectionError, TimeoutError) as exc:
            self._log.debug("aid_store", "register exit (network): aid=%s err=%s", target, exc)
            return result_err(codes.NETWORK_ERROR, str(exc), cause=exc)
        except Exception as exc:
            self._log.debug("aid_store", "register exit (error): aid=%s err=%s", target, exc)
            return result_err(codes.SERVER_ERROR, str(exc), cause=exc)

    async def exists(self, aid: str) -> Result[dict[str, bool]]:
        target = str(aid or "").strip()
        self._log.debug("aid_store", "exists enter: aid=%s", target or "-")
        try:
            self._register_flow.validate_aid_name(target)
            gateway_url = await self._resolved_gateway(target)
            url = self._pki_cert_url(gateway_url, target)
            status, _headers = await self._http_head(url, timeout=5.0)
            if status == 200:
                self._log.debug("aid_store", "exists exit: aid=%s exists=true", target)
                return result_ok({"exists": True})
            if status == 404:
                self._log.debug("aid_store", "exists exit: aid=%s exists=false", target)
                return result_ok({"exists": False})
            self._log.warn("aid_store", "exists unexpected status: aid=%s status=%d", target, status)
            return result_err(codes.NETWORK_ERROR, f"unexpected PKI HEAD status {status}")
        except (ValidationError, ValueError) as exc:
            return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
        except Exception as exc:
            self._log.debug("aid_store", "exists exit (error): aid=%s err=%s", target, exc)
            return result_err(codes.NETWORK_ERROR, str(exc), cause=exc)

    async def resolve(self, aid: str, opts: dict[str, Any] | None = None) -> Result[ResolveResult]:
        options = dict(opts or {})
        target = str(aid or "").strip()
        force_refresh = bool(options.get("force_refresh") or options.get("forceRefresh"))
        skip_agent_md = bool(options.get("skip_agent_md") or options.get("skipAgentMd"))
        timeout_ms = options.get("timeout") or options.get("timeoutMs")
        timeout_s: float | None = float(timeout_ms) / 1000.0 if timeout_ms is not None else None
        self._log.debug(
            "aid_store",
            "resolve enter: aid=%s force_refresh=%s skip_agent_md=%s",
            target or "-",
            force_refresh,
            skip_agent_md,
        )
        try:
            self._register_flow.validate_aid_name(target)
            cert_from_cache = False
            loaded = self.load(target)
            if loaded.ok and loaded.data is not None and not force_refresh:
                cert_from_cache = True
                peer = loaded.data["aid"]
            else:
                gateway_url = await self._resolved_gateway(target)
                cert_pem = await self._register_flow.fetch_peer_cert(gateway_url, target)
                if not cert_pem:
                    return result_err(codes.CERT_NOT_FOUND, f"certificate not found for aid: {target}")
                self._keystore.save_cert(target, cert_pem)
                self._persist_gateway_url(target, gateway_url)
                loaded = self.load(target)
                if not loaded.ok or loaded.data is None:
                    return loaded
                peer = loaded.data["aid"]

            source = {
                "cert_from_cache": cert_from_cache,
                "agent_md_fetched": False,
            }
            if skip_agent_md:
                return result_ok({"aid": peer, "source": source})

            agent_md = await self.download_agent_md(target, timeout_s=timeout_s)
            if not agent_md.ok:
                return agent_md
            source["agent_md_fetched"] = True
            return result_ok({"aid": peer, "agent_md": agent_md.data, "source": source})
        except (ValidationError, ValueError) as exc:
            return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
        except Exception as exc:
            self._log.debug("aid_store", "resolve exit (error): aid=%s err=%s", target, exc)
            return result_err(codes.NETWORK_ERROR, str(exc), cause=exc)

    async def download_agent_md(self, aid: str, *, timeout_s: float | None = None) -> Result[DownloadAgentMdResult]:
        target = str(aid or "").strip()
        self._log.debug("aid_store", "download_agent_md enter: aid=%s", target or "-")
        try:
            data = await self._agent_md_manager.download(target, timeout_s=timeout_s)
            self._log.debug(
                "aid_store",
                "download_agent_md exit: aid=%s status=%s",
                target,
                (data.get("verification") or {}).get("status") if isinstance(data, dict) else "-",
            )
            return result_ok(data)
        except NotFoundError as exc:
            return result_err(codes.AGENTMD_NOT_FOUND, str(exc), cause=exc)
        except (ValidationError, ValueError) as exc:
            return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
        except Exception as exc:
            self._log.debug("aid_store", "download_agent_md exit (error): aid=%s err=%s", target, exc)
            return result_err(codes.NETWORK_ERROR, str(exc), cause=exc)

    async def check_agent_md(self, aid: str, ttl_days: int = 1) -> Result[CheckAgentMdResult]:
        target = str(aid or "").strip()
        self._log.debug("aid_store", "check_agent_md enter: aid=%s ttl_days=%s", target or "-", ttl_days)
        try:
            return result_ok(await self._agent_md_manager.check(target, ttl_days=ttl_days))
        except (ValidationError, ValueError) as exc:
            return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
        except Exception as exc:
            self._log.debug("aid_store", "check_agent_md exit (error): aid=%s err=%s", target, exc)
            return result_err(codes.NETWORK_ERROR, str(exc), cause=exc)

    def _auth_identity_from_aid(self, aid: AID) -> dict[str, Any]:
        return {
            "aid": aid.aid,
            "private_key_pem": aid.private_key_pem,
            "public_key_der_b64": aid.public_key,
            "cert": aid.cert_pem,
        }

    async def _upload_agent_md_token(self, aid: AID, gateway_url: str) -> str:
        auth = AuthFlow(
            token_store=self._token_store,
            crypto=CryptoProvider(),
            aid=aid.aid,
            device_id=self.device_id,
            slot_id=self.slot_id,
            root_ca_path=self._root_ca_path,
            verify_ssl=self._verify_ssl,
            logger=self._log,
            net=self._net,
        )
        auth.set_identity(self._auth_identity_from_aid(aid))
        result = await auth.authenticate(gateway_url, aid=aid.aid)
        token = str(result.get("access_token") or result.get("token") or result.get("kite_token") or "").strip()
        if not token:
            raise StateError("authenticate did not return access_token")
        return token

    async def upload_agent_md(self, aid: str, content: str | None = None) -> Result[UploadAgentMdResult]:
        target = str(aid or "").strip()
        self._log.debug("aid_store", "upload_agent_md enter: aid=%s", target or "-")
        try:
            self._register_flow.validate_aid_name(target)
            loaded = self.load(target)
            if not loaded.ok or loaded.data is None:
                return result_err(
                    loaded.error.code if loaded.error else codes.CERT_NOT_FOUND,
                    loaded.error.message if loaded.error else f"certificate not found for aid: {target}",
                    cause=loaded.error.cause if loaded.error else None,
                )
            current = loaded.data["aid"]
            if not current.is_private_key_valid() or not current.private_key_pem:
                return result_err(codes.PRIVATE_KEY_NOT_VALID, f"upload_agent_md requires local AID with a valid private key: {target}")

            async def token_provider() -> str:
                gateway_url = await self._resolved_gateway(target)
                return await self._upload_agent_md_token(current, gateway_url)

            manager = AgentMdManager(
                self.aun_path,
                verify_ssl=self._verify_ssl,
                logger=self._log,
                owner_aid_getter=lambda: target,
                current_aid_getter=lambda: current,
                gateway_resolver=lambda value: self._resolved_gateway(value),
                token_provider=token_provider,
                aid_validator=self._register_flow.validate_aid_name,
            )
            data = await manager.upload(content)
            self._log.debug("aid_store", "upload_agent_md exit: aid=%s", target)
            return result_ok(data)
        except NotFoundError as exc:
            return result_err(codes.AGENTMD_NOT_FOUND, str(exc), cause=exc)
        except ClientSignatureError as exc:
            return result_err(codes.SIGNATURE_OPERATION_ERROR, str(exc), cause=exc)
        except (ValidationError, ValueError) as exc:
            return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
        except StateError as exc:
            return result_err(codes.PRIVATE_KEY_NOT_VALID, str(exc), cause=exc)
        except Exception as exc:
            self._log.debug("aid_store", "upload_agent_md exit (error): aid=%s err=%s", target, exc)
            return result_err(codes.NETWORK_ERROR, str(exc), cause=exc)

    async def diagnose(self, aid: str) -> Result[DiagnoseResult]:
        target = str(aid or "").strip()
        loaded = self.load(target)
        exists = await self.exists(target)
        remote_error = exists.error.to_dict() if exists.error else None
        remote_registered = bool(exists.ok and exists.data is not None and exists.data.get("exists"))
        remote_checked = bool(exists.ok and exists.data is not None)

        local_cert = False
        local_private_key = False
        local_error = None
        local_aid: AID | None = None
        if loaded.ok and loaded.data is not None:
            local_aid = loaded.data["aid"]
            local_cert = local_aid.is_cert_valid()
            local_private_key = local_aid.is_private_key_valid()
        elif loaded.error is not None:
            local_error = loaded.error.to_dict()

        local_valid = bool(local_cert and local_private_key)
        cert_match = False
        cert_match_error = ""
        if local_aid is not None and remote_registered:
            try:
                gateway_url = await self._resolved_gateway(target)
                remote_cert_pem = await self._register_flow.fetch_peer_cert(gateway_url, target)
                remote_cert = x509.load_pem_x509_certificate(str(remote_cert_pem or "").encode("utf-8"))
                remote_fingerprint = "sha256:" + remote_cert.fingerprint(hashes.SHA256()).hex()
                cert_match = remote_fingerprint.lower() == local_aid.cert_fingerprint.lower()
            except Exception as exc:
                cert_match_error = str(exc)

        suggestions: list[str] = []
        if not local_valid:
            suggestions.append("load or register a local identity with a valid private key")
        if not remote_registered:
            suggestions.append("register the AID before using it on the network")
        if remote_registered and local_aid is not None and not cert_match:
            suggestions.append("refresh local certificate or rekey because it does not match remote PKI")
        if remote_error:
            suggestions.append(f"remote registration check failed: {remote_error.get('message') or remote_error.get('code')}")
        if cert_match_error:
            suggestions.append(f"remote certificate comparison failed: {cert_match_error}")

        local = {
            "cert": local_cert,
            "private_key": local_private_key,
            "error": local_error,
        }
        remote = {"checked": remote_checked, "exists": remote_registered if remote_checked else None}
        if remote_error:
            remote["error"] = remote_error

        if local_private_key and remote_registered:
            status = "ready"
        elif not local_private_key and remote_checked and not remote_registered:
            status = "available"
        elif remote_registered:
            status = "registered_remote"
        else:
            status = "unknown"
        return result_ok({
            "aid": target,
            "status": status,
            "local_valid": local_valid,
            "remote_registered": remote_registered,
            "suggestions": suggestions,
            "local": local,
            "remote": remote,
        })

    async def renew_cert(self, aid: str) -> Result[RenewCertResult]:
        target = str(aid or "").strip()
        self._log.debug("aid_store", "renew_cert enter: aid=%s", target or "-")
        async with self._cert_op_lock(target):
            loaded = self.load(target)
            if not loaded.ok or loaded.data is None or not loaded.data["aid"].is_private_key_valid():
                self._log.warn("aid_store", "renew_cert blocked: private key required aid=%s", target)
                return result_err(codes.PRIVATE_KEY_REQUIRED, f"private key required for aid: {target}")
            aid_obj = loaded.data["aid"]
            try:
                self._register_flow.validate_aid_name(target)
                gateway_url = await self._resolved_gateway(target)
                phase1 = await self._begin_aid_operation(gateway_url, aid_obj)
                signature = aid_obj.sign(str(phase1["nonce"]))
                if not signature.ok or signature.data is None:
                    message = signature.error.message if signature.error else "failed to sign renew_cert nonce"
                    return result_err(codes.CERT_RENEWAL_FAILED, message)

                response = await self._register_flow.short_rpc(gateway_url, "auth.renew_cert", {
                    "aid": target,
                    "request_id": str(phase1["request_id"]),
                    "nonce": str(phase1["nonce"]),
                    "signature": signature.data["signature"],
                })
                cert_pem = str(response.get("cert") or response.get("cert_pem") or "").strip()
                cert_obj = self._validate_returned_cert(
                    target,
                    cert_pem,
                    expected_public_key_b64=aid_obj.public_key,
                    operation="renew_cert",
                )
                self._keystore.save_cert(target, cert_pem)
                refreshed = self.load(target)
                if not refreshed.ok or refreshed.data is None:
                    message = refreshed.error.message if refreshed.error else "renewed certificate reload failed"
                    return result_err(codes.CERT_RENEWAL_FAILED, message)
                refreshed_aid = refreshed.data["aid"]
                self._log.debug(
                    "aid_store",
                    "renew_cert exit: aid=%s fingerprint=%s",
                    target,
                    refreshed_aid.cert_fingerprint,
                )
                return result_ok({
                    "renewed": True,
                    "new_cert_not_after": refreshed_aid.cert_not_after,
                    "new_fingerprint": refreshed_aid.cert_fingerprint,
                })
            except (ValidationError, ValueError) as exc:
                return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
            except Exception as exc:
                self._log.warn("aid_store", "renew_cert failed: aid=%s err=%s", target, exc)
                return result_err(codes.CERT_RENEWAL_FAILED, str(exc), cause=exc)

    async def rekey(self, aid: str) -> Result[RekeyResult]:
        target = str(aid or "").strip()
        self._log.debug("aid_store", "rekey enter: aid=%s", target or "-")
        async with self._cert_op_lock(target):
            loaded = self.load(target)
            if not loaded.ok or loaded.data is None or not loaded.data["aid"].is_private_key_valid():
                self._log.warn("aid_store", "rekey blocked: private key required aid=%s", target)
                return result_err(codes.PRIVATE_KEY_REQUIRED, f"private key required for aid: {target}")
            old_aid = loaded.data["aid"]
            try:
                self._register_flow.validate_aid_name(target)
                new_identity = self._register_flow.generate_identity()
                new_public_key = str(new_identity.get("public_key_der_b64") or "").strip()
                if not new_identity.get("private_key_pem") or not new_public_key:
                    return result_err(codes.REKEY_FAILED, "generated keypair is incomplete")

                gateway_url = await self._resolved_gateway(target)
                phase1 = await self._begin_aid_operation(gateway_url, old_aid)
                signed_payload = f"{phase1['nonce']}{new_public_key}".encode("utf-8")
                signature = old_aid.sign(signed_payload)
                if not signature.ok or signature.data is None:
                    message = signature.error.message if signature.error else "failed to sign rekey payload"
                    return result_err(codes.REKEY_FAILED, message)

                response = await self._register_flow.short_rpc(gateway_url, "auth.rekey", {
                    "aid": target,
                    "request_id": str(phase1["request_id"]),
                    "nonce": str(phase1["nonce"]),
                    "new_public_key": new_public_key,
                    "signature": signature.data["signature"],
                })
                cert_pem = str(response.get("cert") or response.get("cert_pem") or "").strip()
                cert_obj = self._validate_returned_cert(
                    target,
                    cert_pem,
                    expected_public_key_b64=new_public_key,
                    operation="rekey",
                )
                new_identity = dict(new_identity)
                new_identity["aid"] = target
                new_identity["cert"] = cert_pem
                self._keystore.save_identity(target, new_identity)
                refreshed = self.load(target)
                if not refreshed.ok or refreshed.data is None:
                    message = refreshed.error.message if refreshed.error else "rekeyed identity reload failed"
                    return result_err(codes.REKEY_FAILED, message)
                refreshed_aid = refreshed.data["aid"]
                self._log.debug(
                    "aid_store",
                    "rekey exit: aid=%s fingerprint=%s",
                    target,
                    refreshed_aid.cert_fingerprint,
                )
                return result_ok({
                    "rekeyed": True,
                    "new_cert_not_after": refreshed_aid.cert_not_after,
                    "new_fingerprint": refreshed_aid.cert_fingerprint,
                })
            except (ValidationError, ValueError) as exc:
                return result_err(codes.INVALID_AID_FORMAT, str(exc), cause=exc)
            except Exception as exc:
                self._log.warn("aid_store", "rekey failed: aid=%s err=%s", target, exc)
                return result_err(codes.REKEY_FAILED, str(exc), cause=exc)

    def import_group_identity(
        self,
        aid: str,
        *,
        private_key_pem: str,
        public_key_der_b64: str,
        curve: str = "P-256",
        cert_pem: str,
    ) -> Result[ImportGroupIdentityResult]:
        """导入外部生成的群 AID 身份材料。

        用于 group.fs：群主 SDK 本地生成 group_aid 私钥，服务端只签发证书。
        这里校验证书属于目标 AID 且公钥匹配，再复用 load() 做私钥/证书自检。
        """
        target = str(aid or "").strip()
        if not target:
            return result_err(codes.INVALID_AID_FORMAT, "import_group_identity requires a non-empty aid")
        if not str(private_key_pem or "").strip():
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, "import_group_identity requires private_key_pem")
        if not str(public_key_der_b64 or "").strip():
            return result_err(codes.KEYPAIR_MISMATCH, "import_group_identity requires public_key_der_b64")
        if not str(cert_pem or "").strip():
            return result_err(codes.CERT_PARSE_ERROR, "import_group_identity requires cert_pem")
        try:
            self._validate_returned_cert(
                target,
                cert_pem,
                expected_public_key_b64=public_key_der_b64,
                operation="import_group_identity",
            )
            self._keystore.save_identity(target, {
                "aid": target,
                "private_key_pem": private_key_pem,
                "public_key_der_b64": public_key_der_b64,
                "curve": curve or "P-256",
                "cert": cert_pem,
            })
            loaded = self.load(target)
            if not loaded.ok or loaded.data is None:
                message = loaded.error.message if loaded.error else "imported group identity reload failed"
                return result_err(codes.KEYPAIR_MISMATCH, message)
            aid_obj = loaded.data["aid"]
            if not aid_obj.is_private_key_valid():
                return result_err(codes.KEYPAIR_MISMATCH, "imported group identity private key self-test failed")
            self._log.info("aid_store", "group identity imported: aid=%s", target)
            return result_ok({"imported": True})
        except (ValidationError, ValueError) as exc:
            return result_err(codes.CERT_CHAIN_BROKEN, str(exc), cause=exc)
        except Exception as exc:
            return result_err(codes.PRIVATE_KEY_PARSE_ERROR, str(exc), cause=exc)

    def _cert_op_lock(self, aid: str) -> asyncio.Lock:
        key = str(aid or "").strip()
        lock = self._cert_op_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._cert_op_locks[key] = lock
        return lock

    async def _begin_aid_operation(self, gateway_url: str, aid_obj: AID) -> dict[str, str]:
        client_nonce = self._register_flow.new_client_nonce()
        self._log.debug("aid_store", "aid operation login1 start: aid=%s gateway=%s", aid_obj.aid, gateway_url)
        phase1 = await self._register_flow.short_rpc(gateway_url, "auth.aid_login1", {
            "aid": aid_obj.aid,
            "cert": aid_obj.cert_pem,
            "client_nonce": client_nonce,
        })
        await self._register_flow.verify_phase1_response(gateway_url, phase1, client_nonce)
        request_id = str(phase1.get("request_id") or "").strip()
        nonce = str(phase1.get("nonce") or "").strip()
        if not request_id:
            raise ValidationError("aid_login1 response missing request_id")
        if not nonce:
            raise ValidationError("aid_login1 response missing nonce")
        self._log.debug("aid_store", "aid operation login1 done: aid=%s request_id=%s", aid_obj.aid, request_id)
        return {"request_id": request_id, "nonce": nonce}

    def _validate_returned_cert(
        self,
        aid: str,
        cert_pem: str,
        *,
        expected_public_key_b64: str,
        operation: str,
    ) -> x509.Certificate:
        if not cert_pem or "BEGIN CERTIFICATE" not in cert_pem:
            raise ValidationError(f"{operation} response missing certificate")
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        time_error = cert_time_error(cert_obj)
        if time_error:
            raise ValidationError(f"{operation} returned certificate is {time_error}")
        cert_cn = cert_common_name(cert_obj)
        if cert_cn != aid:
            raise ValidationError(f"{operation} returned certificate CN mismatch: expected {aid}, got {cert_cn}")
        expected_der = base64.b64decode(str(expected_public_key_b64 or ""), validate=True)
        actual_der = public_key_der(cert_obj.public_key())
        if actual_der != expected_der:
            raise ValidationError(f"{operation} returned certificate public key mismatch")
        return cert_obj

    async def _download_trust_roots_or_raise(self, url: str, *, timeout: float = 10.0) -> dict[str, Any]:
        target = str(url or "").strip()
        if not target.lower().startswith(("https://", "http://")):
            raise ValidationError("trust roots url must be http(s)")
        self._log.debug("aid_store", "download_trust_roots enter: target=%s timeout=%s", target, timeout)
        http_timeout = aiohttp.ClientTimeout(total=float(timeout))
        ssl_param = None if self._verify_ssl else False
        async with aiohttp.ClientSession(timeout=http_timeout) as session:
            async with session.get(target, ssl=ssl_param, headers={"Accept": "application/json"}) as response:
                response.raise_for_status()
                payload = await response.json()
        if not isinstance(payload, dict):
            raise ValidationError("trust roots endpoint returned non-object JSON")
        self._log.debug("aid_store", "download_trust_roots exit: target=%s keys=%d", target, len(payload))
        return payload

    async def _download_issuer_root_cert_or_raise(
        self,
        issuer: str,
        url: str,
        *,
        timeout: float = 10.0,
    ) -> str:
        target = str(url or "").strip()
        if not target.lower().startswith(("https://", "http://")):
            raise ValidationError("issuer root certificate url must be http(s)")
        self._log.debug("aid_store", "download_issuer_root_cert enter: issuer=%s target=%s", issuer, target)
        http_timeout = aiohttp.ClientTimeout(total=float(timeout))
        ssl_param = None if self._verify_ssl else False
        async with aiohttp.ClientSession(timeout=http_timeout) as session:
            async with session.get(
                target,
                ssl=ssl_param,
                headers={"Accept": "application/x-pem-file,text/plain"},
            ) as response:
                response.raise_for_status()
                cert_pem = await response.text()
        normalized_pem = cert_pem.strip() + "\n"
        self._load_root_certificate(normalized_pem, issuer)
        self._log.debug("aid_store", "download_issuer_root_cert exit: issuer=%s", issuer)
        return normalized_pem

    def _verify_trust_roots_or_raise(
        self,
        trust_list: dict[str, Any],
        *,
        authority_cert_pem: str | None = None,
        authority_public_key_pem: str | None = None,
        allow_unsigned: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(trust_list, dict):
            raise ValidationError("trust roots list must be a JSON object")
        signature = str(trust_list.get("authority_signature") or "").strip()
        if not signature and not allow_unsigned:
            raise ValidationError("trust roots list missing authority_signature")
        self._validate_list_metadata(trust_list)
        if signature:
            public_key = self._load_authority_public_key(
                authority_cert_pem=authority_cert_pem,
                authority_public_key_pem=authority_public_key_pem,
                trust_list=trust_list,
            )
            signed_payload = self._canonical_signed_payload(trust_list)
            try:
                verify_signature(public_key, self._decode_signature(signature), signed_payload)
            except InvalidSignature as exc:
                raise ValidationError("trust roots authority_signature verification failed") from exc
            except Exception as exc:
                raise ValidationError("trust roots authority_signature verification failed") from exc

        imported: list[dict[str, str]] = []
        skipped: list[dict[str, str]] = []
        now = time.time()
        for item in self._extract_root_entries(trust_list):
            status = str(item.get("status") or "active").strip().lower()
            cert_pem = str(item.get("certificate") or item.get("cert_pem") or "").strip()
            root_id = str(item.get("id") or item.get("agentid") or "").strip()
            if status != "active":
                skipped.append({"id": root_id, "reason": f"status={status}"})
                continue
            cert = self._load_root_certificate(cert_pem, root_id or "root")
            self._validate_root_ca_certificate(cert, root_id or cert.subject.rfc4514_string())
            if cert.not_valid_before_utc.timestamp() > now or cert.not_valid_after_utc.timestamp() < now:
                raise ValidationError(
                    f"root certificate is not currently valid: {root_id or cert.subject.rfc4514_string()}"
                )
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            expected_fp = self._normalize_fingerprint(item.get("fingerprint_sha256"))
            if len(expected_fp) != 64:
                raise ValidationError(f"root certificate missing or invalid fingerprint_sha256: {root_id or fingerprint}")
            if expected_fp != fingerprint:
                raise ValidationError(f"root certificate fingerprint mismatch: {root_id or fingerprint}")
            imported.append({
                "id": root_id or fingerprint,
                "cert_pem": cert_pem,
                "fingerprint_sha256": fingerprint,
            })
        if not imported:
            raise ValidationError("trust roots list contains no active root certificates")
        return {"imported": imported, "skipped": skipped, "count": len(imported)}

    def _import_trust_roots_or_raise(
        self,
        trust_list: dict[str, Any],
        *,
        authority_cert_pem: str | None = None,
        authority_public_key_pem: str | None = None,
        allow_unsigned: bool = False,
    ) -> dict[str, Any]:
        verified = self._verify_trust_roots_or_raise(
            trust_list,
            authority_cert_pem=authority_cert_pem,
            authority_public_key_pem=authority_public_key_pem,
            allow_unsigned=allow_unsigned,
        )
        self._enforce_monotonic_version(trust_list)
        bundle_path = self._keystore.save_trust_roots(trust_list, verified["imported"])
        reloaded = self._register_flow.reload_trusted_roots()
        self._log.info(
            "aid_store",
            "trust roots imported: count=%d skipped=%d reloaded=%d",
            verified["count"],
            len(verified["skipped"]),
            reloaded,
        )
        return {
            "imported": verified["count"],
            "skipped": verified["skipped"],
            "bundle_path": str(bundle_path),
            "reloaded_roots": reloaded,
            "fingerprints": [item["fingerprint_sha256"] for item in verified["imported"]],
        }

    async def _update_issuer_root_cert_or_raise(
        self,
        issuer: str,
        *,
        cert_pem: str | None = None,
        url: str | None = None,
        trust_list: dict[str, Any] | None = None,
        authority_cert_pem: str | None = None,
        authority_public_key_pem: str | None = None,
        allow_unsigned: bool = False,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        normalized_issuer = self._validate_issuer(issuer)
        source_url = str(url or "").strip() or self._issuer_root_cert_url(normalized_issuer)
        root_pem = cert_pem.strip() + "\n" if isinstance(cert_pem, str) and cert_pem.strip() else ""
        if not root_pem:
            root_pem = await self._download_issuer_root_cert_or_raise(
                normalized_issuer,
                source_url,
                timeout=timeout,
            )
        cert = self._load_root_certificate(root_pem, normalized_issuer)
        self._validate_root_ca_certificate(cert, normalized_issuer)
        self._verify_self_signed_root(cert, normalized_issuer)
        now = time.time()
        if cert.not_valid_before_utc.timestamp() > now or cert.not_valid_after_utc.timestamp() < now:
            raise ValidationError(f"issuer root certificate is not currently valid: {normalized_issuer}")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        effective_trust_list = trust_list or self._load_local_trust_list()
        trust_source = "local"
        if effective_trust_list is None:
            source = self._issuer_trust_root_url(normalized_issuer)
            effective_trust_list = await self._download_trust_roots_or_raise(source, timeout=timeout)
            trust_source = source
        verified = self._verify_trust_roots_or_raise(
            effective_trust_list,
            authority_cert_pem=authority_cert_pem,
            authority_public_key_pem=authority_public_key_pem,
            allow_unsigned=allow_unsigned,
        )
        self._enforce_monotonic_version(effective_trust_list)
        trusted_fingerprints = {item["fingerprint_sha256"] for item in verified["imported"]}
        if fingerprint not in trusted_fingerprints:
            raise ValidationError("issuer root certificate is not in trusted root list")

        cert_path, bundle_path = self._keystore.save_issuer_root_cert(
            normalized_issuer,
            root_pem,
            fingerprint,
        )
        reloaded = self._register_flow.reload_trusted_roots()
        self._log.info(
            "aid_store",
            "issuer root cert updated: issuer=%s fingerprint=%s reloaded=%d trust_source=%s",
            normalized_issuer,
            fingerprint[:16] + "...",
            reloaded,
            trust_source,
        )
        return {
            "issuer": normalized_issuer,
            "fingerprint_sha256": fingerprint,
            "cert_path": str(cert_path),
            "bundle_path": str(bundle_path),
            "reloaded_roots": reloaded,
            "source_url": source_url,
            "trust_source": trust_source,
        }

    def _resolve_trust_roots_url(
        self,
        url: str | None,
        *,
        issuer: str | None = None,
        gateway_url: str | None = None,
    ) -> str:
        target = str(url or "").strip()
        if target:
            return target
        if issuer:
            return self._issuer_trust_root_url(issuer)
        gw = str(gateway_url or "").strip()
        return self._gateway_trust_roots_url(gw) if gw else _AUTHORITY_ENDPOINT

    def _issuer_trust_root_url(self, issuer: str) -> str:
        authority = self._pki_authority(issuer)
        return f"https://{authority}/trust-root.json"

    def _issuer_root_cert_url(self, issuer: str) -> str:
        authority = self._pki_authority(issuer)
        return f"https://{authority}/root.crt"

    def _pki_authority(self, issuer: str) -> str:
        normalized = self._validate_issuer(issuer)
        return f"pki.{normalized}"

    @staticmethod
    def _validate_issuer(issuer: str) -> str:
        value = str(issuer or "").strip().lower()
        if not value or "://" in value or "/" in value or "\\" in value or value.startswith("."):
            raise ValidationError("issuer must be a domain name")
        return value

    @staticmethod
    def _gateway_trust_roots_url(gateway_url: str) -> str:
        parsed = urlparse(gateway_url)
        if not parsed.netloc:
            raise ValidationError("gateway_url must include scheme and host")
        scheme = "https" if parsed.scheme in {"wss", "https"} else "http"
        return urlunparse((scheme, parsed.netloc, "/pki/trust-roots.json", "", "", ""))

    @staticmethod
    def _canonical_signed_payload(trust_list: dict[str, Any]) -> bytes:
        payload = dict(trust_list)
        payload.pop("authority_signature", None)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _decode_signature(signature: str) -> bytes:
        value = str(signature or "").strip()
        if value.startswith("base64:"):
            value = value.split(":", 1)[1]
        padding = "=" * (-len(value) % 4)
        try:
            normalized = (value + padding).replace("-", "+").replace("_", "/")
            return base64.b64decode(normalized.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValidationError("invalid authority_signature encoding") from exc

    def _load_authority_public_key(
        self,
        *,
        authority_cert_pem: str | None,
        authority_public_key_pem: str | None,
        trust_list: dict[str, Any],
    ):
        if authority_public_key_pem:
            try:
                return serialization.load_pem_public_key(authority_public_key_pem.encode("utf-8"))
            except Exception as exc:
                raise ValidationError("invalid authority public key PEM") from exc
        candidate_cert = (
            authority_cert_pem
            or str(trust_list.get("authority_cert_pem") or "")
            or self._load_local_authority_cert()
        )
        if not candidate_cert:
            raise ValidationError("authority certificate/public key is required to verify trust roots")
        try:
            cert = x509.load_pem_x509_certificate(candidate_cert.encode("utf-8"))
        except Exception as exc:
            raise ValidationError("invalid authority certificate PEM") from exc
        return cert.public_key()

    @staticmethod
    def _extract_root_entries(trust_list: dict[str, Any]) -> list[dict[str, Any]]:
        roots = trust_list.get("root_cas")
        if isinstance(roots, list):
            return [item for item in roots if isinstance(item, dict)]
        legacy = trust_list.get("roots")
        if isinstance(legacy, list):
            converted: list[dict[str, Any]] = []
            for item in legacy:
                if not isinstance(item, dict):
                    continue
                converted.append({
                    "id": item.get("agentid") or item.get("id") or item.get("cert_sn"),
                    "certificate": item.get("cert_pem") or item.get("certificate"),
                    "fingerprint_sha256": item.get("fingerprint_sha256"),
                    "status": item.get("status") or "active",
                })
            return converted
        raise ValidationError("trust roots list missing root_cas")

    @staticmethod
    def _validate_list_metadata(trust_list: dict[str, Any]) -> None:
        version = trust_list.get("version")
        if not isinstance(version, int) or version < 0:
            raise ValidationError("trust roots list version must be a non-negative integer")
        issued_at = AIDStore._parse_timestamp(trust_list.get("issued_at"), "issued_at")
        next_update = AIDStore._parse_timestamp(trust_list.get("next_update"), "next_update")
        if next_update < issued_at:
            raise ValidationError("trust roots list next_update must not be earlier than issued_at")
        future_limit = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=_MAX_CLOCK_SKEW)
        if issued_at > future_limit:
            raise ValidationError("trust roots list issued_at is too far in the future")

    @staticmethod
    def _parse_timestamp(value: Any, field: str) -> datetime:
        text = str(value or "").strip()
        if not text:
            raise ValidationError(f"trust roots list missing {field}")
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError(f"trust roots list {field} must be ISO-8601") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _normalize_fingerprint(value: Any) -> str:
        text = str(value or "").strip().lower()
        if text.startswith("sha256:"):
            text = text.split(":", 1)[1]
        return "".join(ch for ch in text if ch in "0123456789abcdef")

    @staticmethod
    def _validate_root_ca_certificate(cert: x509.Certificate, root_id: str) -> None:
        try:
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise ValidationError(f"root certificate missing BasicConstraints: {root_id}") from exc
        if not basic.ca:
            raise ValidationError(f"root certificate is not a CA certificate: {root_id}")

    @staticmethod
    def _verify_self_signed_root(cert: x509.Certificate, root_id: str) -> None:
        if cert.subject != cert.issuer:
            raise ValidationError(f"root certificate is not self-issued: {root_id}")
        try:
            verify_signature(cert.public_key(), cert.signature, cert.tbs_certificate_bytes)
        except Exception as exc:
            raise ValidationError(f"root certificate self-signature verification failed: {root_id}") from exc

    def _enforce_monotonic_version(self, trust_list: dict[str, Any]) -> None:
        version = trust_list.get("version")
        if not isinstance(version, int):
            return
        current_path = self._keystore.trust_root_dir() / "trust-roots.json"
        if not current_path.exists():
            return
        try:
            current = json.loads(current_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        current_version = current.get("version") if isinstance(current, dict) else None
        if isinstance(current_version, int) and version < current_version:
            raise ValidationError("trust roots list version rollback is not allowed")

    def _load_local_trust_list(self) -> dict[str, Any] | None:
        path = self._keystore.trust_root_dir() / "trust-roots.json"
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError("local trust roots list is invalid") from exc
        if not isinstance(payload, dict):
            raise ValidationError("local trust roots list must be a JSON object")
        return payload

    @staticmethod
    def _load_root_certificate(cert_pem: str, root_id: str) -> x509.Certificate:
        if "BEGIN CERTIFICATE" not in cert_pem:
            raise ValidationError(f"root certificate missing PEM data: {root_id}")
        try:
            return x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except Exception as exc:
            raise ValidationError(f"invalid root certificate PEM: {root_id}") from exc

    def _load_local_authority_cert(self) -> str:
        candidates = [
            self._keystore.trust_root_dir().parent / "authority" / "authority.crt",
            Path(__file__).resolve().parent / "certs" / "authority.crt",
        ]
        for path in candidates:
            try:
                if path.exists():
                    return path.read_text(encoding="utf-8")
            except OSError:
                continue
        return ""

    async def _resolved_gateway(self, aid: str) -> str:
        resolved = self._resolve_gateway(aid)
        if inspect.isawaitable(resolved):
            return str(await resolved)
        return str(resolved)

    async def _resolve_gateway(self, aid: str) -> str:
        target = str(aid or "").strip()

        parts = target.split(".", 1)
        issuer_domain = parts[1] if len(parts) > 1 else target

        cached_gateway = self._load_cached_gateway_url(target)
        if cached_gateway:
            self._gateway_cache[issuer_domain] = cached_gateway
            return cached_gateway
        if issuer_domain in self._gateway_cache:
            return self._gateway_cache[issuer_domain]

        aid_url = f"https://{target}/.well-known/aun-gateway"
        gateway_url = f"https://gateway.{issuer_domain}/.well-known/aun-gateway"
        primary_url, fallback_url = (aid_url, gateway_url) if self._verify_ssl else (gateway_url, aid_url)

        try:
            discovered = await self._discovery.discover(primary_url)
        except Exception as exc:
            self._log.debug("aid_store", "gateway discovery primary failed: aid=%s err=%s", target, exc)
            discovered = await self._discovery.discover(fallback_url)
        self._persist_gateway_url(target, discovered)
        self._gateway_cache[issuer_domain] = discovered
        return discovered

    def _load_cached_gateway_url(self, aid: str) -> str:
        if not aid:
            return ""
        try:
            return self._keystore.get_metadata_value(aid, "gateway_url")
        except Exception:
            return ""

    def _persist_gateway_url(self, aid: str, gateway_url: str) -> None:
        if not aid or not gateway_url:
            return
        try:
            if not self._has_local_aid_material(aid):
                return
            self._keystore.set_metadata_value(aid, "gateway_url", gateway_url)
        except Exception as exc:
            self._log.debug("aid_store", "persist gateway_url failed: aid=%s err=%s", aid, exc)

    def _has_local_aid_material(self, aid: str) -> bool:
        try:
            if self._keystore.load_cert(aid):
                return True
            return bool(self._keystore.load_key_pair(aid))
        except Exception:
            return False

    @staticmethod
    def _pki_cert_url(gateway_url: str, aid: str, cert_fingerprint: str | None = None) -> str:
        parsed = urlparse(gateway_url)
        scheme = "https" if parsed.scheme == "wss" else "http"
        query = urlencode({"cert_fingerprint": cert_fingerprint}) if cert_fingerprint else ""
        return urlunparse((scheme, parsed.netloc, f"/pki/cert/{quote(aid, safe='')}", "", query, ""))

    async def _http_head(self, url: str, *, timeout: float = 5.0) -> tuple[int, dict[str, str]]:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        ssl_param = None if self._verify_ssl else False
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.head(url, ssl=ssl_param, allow_redirects=True) as response:
                return int(response.status), dict(response.headers)

    async def _http_get_text_with_headers(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> tuple[str, dict[str, str], int]:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        ssl_param = None if self._verify_ssl else False
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.get(url, ssl=ssl_param, headers=headers, allow_redirects=True) as response:
                text = await response.text()
                return text, dict(response.headers), int(response.status)

