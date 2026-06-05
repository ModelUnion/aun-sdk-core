import pytest

from aun_core.errors import ValidationError
from aun_core.service_proxy import EmbeddedServiceRegistry, ServiceProxyClient


def test_service_proxy_registry_registers_and_summarizes_without_endpoint():
    registry = EmbeddedServiceRegistry()

    record = registry.register(
        "fileshare",
        "http://127.0.0.1:8080/root",
        service_type="http",
        visibility="public",
        metadata={"title": "Files"},
    )

    assert record.service_name == "fileshare"
    assert registry.get("fileshare").endpoint == "http://127.0.0.1:8080/root"

    summaries = registry.list_summaries()
    assert summaries == [
        {
            "service_name": "fileshare",
            "service_type": "http",
            "visibility": "public",
            "metadata": {"title": "Files"},
        }
    ]
    assert "endpoint" not in summaries[0]


def test_service_proxy_registry_strips_sensitive_metadata_from_summary():
    registry = EmbeddedServiceRegistry()

    registry.register(
        "fileshare",
        "http://127.0.0.1:8080/root",
        service_type="http",
        visibility="public",
        metadata={
            "title": "Files",
            "endpoint": "http://127.0.0.1:8080/root",
            "token": "SECRET",
            "nested": {"access_token": "SECRET", "label": "ok"},
            "items": [{"password": "SECRET", "name": "one"}],
        },
    )

    summary = registry.list_summaries()[0]

    assert summary["metadata"] == {
        "title": "Files",
        "nested": {"label": "ok"},
        "items": [{"name": "one"}],
    }


def test_service_proxy_registry_rejects_invalid_service_names():
    registry = EmbeddedServiceRegistry()

    for name in ("", "api", "proxy", "../x", "file.share", "Upper"):
        with pytest.raises(ValidationError):
            registry.register(name, "http://127.0.0.1:8080")


def test_service_proxy_registry_replaces_duplicate_service_by_default():
    registry = EmbeddedServiceRegistry()

    first = registry.register("fileshare", "http://127.0.0.1:8080", service_type="http")
    second = registry.register("fileshare", "http://127.0.0.1:9090", service_type="sse")

    assert first.endpoint == "http://127.0.0.1:8080"
    assert second.endpoint == "http://127.0.0.1:9090"
    assert registry.get("fileshare").service_type == "sse"
    assert len(registry.list_records()) == 1


def test_service_proxy_registry_can_reject_duplicate_service():
    registry = EmbeddedServiceRegistry(replace_existing=False)
    registry.register("fileshare", "http://127.0.0.1:8080")

    with pytest.raises(ValidationError, match="already registered"):
        registry.register("fileshare", "http://127.0.0.1:9090")


def test_service_proxy_registry_unregisters_service():
    registry = EmbeddedServiceRegistry()
    registry.register("fileshare", "http://127.0.0.1:8080")

    assert registry.unregister("fileshare") is True
    assert registry.unregister("fileshare") is False
    assert registry.get("fileshare") is None
    assert registry.list_summaries() == []


def test_service_proxy_client_wraps_registry_without_auto_connecting():
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")

    client.register_service("fileshare", "http://127.0.0.1:8080")

    assert client.provider_aid == "alice.agentid.pub"
    assert client.is_running is False
    assert client.list_service_summaries()[0]["service_name"] == "fileshare"
