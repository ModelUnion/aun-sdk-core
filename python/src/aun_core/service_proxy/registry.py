from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from ..errors import ValidationError


_SERVICE_NAME_RE = re.compile(r"^[a-z0-9_-]+$")
_ALLOWED_SCHEMES = {"http", "https", "ws", "wss"}
_RESERVED_SERVICE_NAMES = {
    "api",
    "health",
    "metrics",
    "status",
    "proxy",
    "admin",
    "ws",
    "wss",
    "static",
    "favicon.ico",
}
_SENSITIVE_METADATA_KEYS = {
    "endpoint",
    "url",
    "uri",
    "token",
    "access_token",
    "authorization",
    "cookie",
    "secret",
    "password",
    "private_key",
    "key",
    "cert",
    "certificate",
}


def _normalize_service_name(service_name: str) -> str:
    value = str(service_name or "").strip()
    if not value:
        raise ValidationError("service_name is required")
    if value in _RESERVED_SERVICE_NAMES:
        raise ValidationError("service_name is reserved")
    if not _SERVICE_NAME_RE.fullmatch(value):
        raise ValidationError("service_name must match [a-z0-9_-]+")
    return value


def _normalize_host(host: str) -> str:
    return str(host or "").strip().lower().rstrip(".")


def _is_sensitive_metadata_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key or "").strip().lower()).strip("_")
    if normalized in _SENSITIVE_METADATA_KEYS:
        return True
    return normalized.endswith(("_token", "_secret", "_password", "_private_key"))


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in metadata.items():
        if _is_sensitive_metadata_key(key):
            continue
        if isinstance(value, dict):
            result[str(key)] = _sanitize_metadata(value)
        elif isinstance(value, list):
            result[str(key)] = [
                _sanitize_metadata(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[str(key)] = value
    return result


@dataclass(frozen=True, slots=True)
class ServiceRecord:
    service_name: str
    endpoint: str
    service_type: str = "http"
    visibility: str = "private"
    metadata: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "service_name": self.service_name,
            "service_type": self.service_type,
            "visibility": self.visibility,
            "metadata": _sanitize_metadata(dict(self.metadata)),
        }


@dataclass(frozen=True, slots=True)
class EndpointPolicy:
    allowed_hosts: set[str] = field(default_factory=set)

    def is_allowed(self, endpoint: str) -> bool:
        parsed = urlparse(str(endpoint or ""))
        if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
            return False
        host = _normalize_host(parsed.hostname or "")
        if not host:
            return False

        allowed_hosts = {_normalize_host(item) for item in self.allowed_hosts}
        if host in allowed_hosts:
            return True
        if host == "localhost":
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip.version == 4 and ip.is_loopback


class EmbeddedServiceRegistry:
    def __init__(
        self,
        *,
        endpoint_policy: EndpointPolicy | None = None,
        replace_existing: bool = True,
    ) -> None:
        self._endpoint_policy = endpoint_policy or EndpointPolicy()
        self._replace_existing = bool(replace_existing)
        self._records: dict[str, ServiceRecord] = {}

    def register(
        self,
        service_name: str,
        endpoint: str,
        *,
        service_type: str = "http",
        visibility: str = "private",
        metadata: dict[str, Any] | None = None,
    ) -> ServiceRecord:
        normalized_name = _normalize_service_name(service_name)
        endpoint_text = str(endpoint or "").strip()
        if not self._endpoint_policy.is_allowed(endpoint_text):
            raise ValidationError("endpoint is not allowed")
        if normalized_name in self._records and not self._replace_existing:
            raise ValidationError(f"service already registered: {normalized_name}")

        record = ServiceRecord(
            service_name=normalized_name,
            endpoint=endpoint_text,
            service_type=str(service_type or "http").strip() or "http",
            visibility=str(visibility or "private").strip() or "private",
            metadata=_sanitize_metadata(dict(metadata or {})),
        )
        self._records[normalized_name] = record
        return record

    def unregister(self, service_name: str) -> bool:
        normalized_name = _normalize_service_name(service_name)
        return self._records.pop(normalized_name, None) is not None

    def get(self, service_name: str) -> ServiceRecord | None:
        normalized_name = _normalize_service_name(service_name)
        return self._records.get(normalized_name)

    def list_records(self) -> list[ServiceRecord]:
        return [self._records[name] for name in sorted(self._records)]

    def list_summaries(self) -> list[dict[str, Any]]:
        return [record.summary() for record in self.list_records()]
