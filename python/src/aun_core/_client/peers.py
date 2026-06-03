from __future__ import annotations

from typing import Any

from cryptography import x509

from .._cert_utils import cert_common_name, cert_time_error
from ..aid import AID
from ..errors import AUNError, StateError, ValidationError
from .runtime import ClientRuntime


class PeerDirectory:
    """Peer AID、证书与网关发现协调器。"""

    def __init__(self, runtime: Any) -> None:
        self.runtime = ClientRuntime.coerce(runtime)
        self.client = self.runtime.client

    def require_peer_management_state(self) -> None:
        if not self.client.has_identity:
            raise StateError("peer management requires a loaded identity")

    def cache_peer(self, aid: AID) -> AID:
        self.require_peer_management_state()
        if not isinstance(aid, AID) or not aid.is_cert_valid():
            raise ValidationError("cache_peer requires an AID with a valid certificate")
        self.client._peer_cache[aid.aid] = aid
        return aid

    def get_peer(self, aid: str) -> AID | None:
        self.require_peer_management_state()
        target = str(aid or "").strip()
        if not target:
            raise ValidationError("get_peer requires non-empty aid")
        return self.client._peer_cache.get(target)

    async def lookup_peer(self, aid: str) -> AID:
        self.require_peer_management_state()
        target = str(aid or "").strip()
        if not target:
            raise ValidationError("lookup_peer requires non-empty aid")
        cached = self.client._peer_cache.get(target)
        if cached is not None:
            return cached
        return await self.resolve_peer_aid(target)

    def peers(self) -> list[AID]:
        self.require_peer_management_state()
        return [self.client._peer_cache[key] for key in sorted(self.client._peer_cache)]

    async def discover_gateway_for_aid(self, aid: str) -> str:
        client = self.client
        target = str(aid or "").strip()
        if not target:
            raise StateError("gateway discovery requires aid")
        if client._gateway_url:
            return client._gateway_url
        cached_gateway = self.load_cached_gateway_url(target)
        if cached_gateway:
            self.runtime.lifecycle.set_gateway_url(cached_gateway)
            return cached_gateway
        gateway_url = await self.discover_gateway_url(target)
        self.runtime.lifecycle.set_gateway_url(gateway_url)
        self.persist_gateway_url(target, gateway_url)
        return gateway_url

    @staticmethod
    def issuer_domain_for_aid(aid: str) -> str:
        target = str(aid or "").strip().lower()
        if not target:
            return ""
        if "." not in target:
            return target
        return target.split(".", 1)[1].strip(".")

    async def discover_gateway_for_peer_aid(self, peer_aid: str) -> str:
        client = self.client
        target = str(peer_aid or "").strip()
        if not target:
            raise ValidationError("peer aid is required for gateway discovery")

        peer_issuer = self.issuer_domain_for_aid(target)
        local_issuer = client._local_issuer_domain()
        current_gateway = client.gateway_url
        cache_key = peer_issuer or target.lower()

        if peer_issuer and local_issuer and peer_issuer == local_issuer and current_gateway:
            return current_gateway

        cached_gateway = client._peer_gateway_cache.get(cache_key)
        if cached_gateway:
            return cached_gateway

        discovery_aid = target
        if peer_issuer and local_issuer and peer_issuer == local_issuer and client._aid:
            discovery_aid = client._aid

        cached_gateway = self.load_cached_gateway_url(discovery_aid)
        if cached_gateway:
            client._peer_gateway_cache[cache_key] = cached_gateway
            return cached_gateway

        gateway_url = await self.discover_gateway_url(discovery_aid)
        self.persist_gateway_url(discovery_aid, gateway_url)
        if discovery_aid != target:
            self.persist_gateway_url(target, gateway_url)
        if gateway_url:
            client._peer_gateway_cache[cache_key] = gateway_url
        return gateway_url

    async def discover_gateway_url(self, aid: str) -> str:
        client = self.client
        target = str(aid or "").strip()
        if not target:
            raise StateError("gateway discovery requires aid")
        issuer_domain = self.issuer_domain_for_aid(target)
        aid_url = f"https://{target}/.well-known/aun-gateway"
        gateway_url = f"https://gateway.{issuer_domain}/.well-known/aun-gateway"
        primary_url, fallback_url = (
            (aid_url, gateway_url)
            if client._config_model.verify_ssl
            else (gateway_url, aid_url)
        )
        try:
            return await client._discovery.discover(primary_url)
        except Exception as exc:
            client._log.debug("client", "gateway discovery primary failed: aid=%s err=%s", target, exc)
            return await client._discovery.discover(fallback_url)

    def load_cached_gateway_url(self, aid: str) -> str:
        client = self.client
        if not aid:
            return ""
        try:
            getter = getattr(client._token_store, "get_metadata_value", None)
            if callable(getter):
                return str(getter(aid, "gateway_url") or "").strip()
            metadata = client._token_store.load_metadata(aid) or {}
            fields = metadata.get("fields") if isinstance(metadata, dict) else None
            return str((fields or {}).get("gateway_url") or "").strip()
        except Exception:
            return ""

    def persist_gateway_url(self, aid: str, gateway_url: str) -> None:
        client = self.client
        if not aid or not gateway_url:
            return
        try:
            setter = getattr(client._token_store, "set_metadata_value", None)
            if callable(setter):
                setter(aid, "gateway_url", gateway_url)
        except Exception as exc:
            client._log.debug("client", "persist gateway_url failed: aid=%s err=%s", aid, exc)

    async def resolve_peer_aid(self, aid: str, cert_fingerprint: str | None = None) -> AID:
        client = self.client
        target = str(aid or "").strip()
        expected_fp = str(cert_fingerprint or "").strip().lower()
        if not target:
            raise ValidationError("peer aid is required")
        if client._current_aid is not None and client._current_aid.aid == target:
            if expected_fp and client._current_aid.cert_fingerprint.lower() != expected_fp:
                raise AUNError(f"peer certificate fingerprint mismatch: {target}")
            return client._current_aid
        cached = None if expected_fp else client._peer_cache.get(target)
        if cached is not None:
            return cached

        cert_bytes = await client._fetch_peer_cert(target, expected_fp or None)
        peer = self.public_aid_from_cert(target, cert_bytes.decode("utf-8"))
        if not expected_fp:
            client._peer_cache[peer.aid] = peer
        return peer

    def public_aid_from_cert(self, aid: str, cert_pem: str) -> AID:
        client = self.client
        target = str(aid or "").strip()
        try:
            cert_obj = x509.load_pem_x509_certificate(str(cert_pem or "").encode("utf-8"))
        except Exception as exc:
            raise AUNError(f"peer certificate parse failed: {target}") from exc
        time_error = cert_time_error(cert_obj)
        if time_error == "expired":
            raise AUNError(f"peer certificate expired: {target}")
        if time_error == "not_yet_valid":
            raise AUNError(f"peer certificate not yet valid: {target}")
        cert_cn = cert_common_name(cert_obj)
        if cert_cn and cert_cn != target:
            raise AUNError(f"peer certificate CN mismatch: expected {target}, got {cert_cn}")
        return AID._create(
            aid=target,
            aun_path=client._config_model.aun_path,
            cert_pem=cert_pem,
            cert_obj=cert_obj,
            private_key_obj=None,
            cert_valid=True,
            private_key_valid=False,
            device_id=client._device_id,
            slot_id=client._slot_id or "default",
            verify_ssl=client._config_model.verify_ssl,
            root_ca_path=client._config_model.root_ca_path,
            debug=bool(getattr(client._log, "_debug", False)),
        )
