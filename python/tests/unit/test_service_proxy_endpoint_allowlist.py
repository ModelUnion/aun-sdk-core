import pytest

from aun_core.errors import ValidationError
from aun_core.service_proxy import EndpointPolicy, EmbeddedServiceRegistry


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:8080",
        "https://127.0.0.1:8443",
        "http://localhost:8080",
        "ws://127.0.0.1:8765",
        "wss://localhost:8765",
    ],
)
def test_default_endpoint_policy_allows_loopback(endpoint):
    policy = EndpointPolicy()

    assert policy.is_allowed(endpoint) is True


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.com:8080",
        "http://10.0.0.1:8080",
        "http://172.16.0.1:8080",
        "http://192.168.1.10:8080",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]:8080",
        "ftp://127.0.0.1:21",
        "file:///tmp/service.sock",
        "http://",
    ],
)
def test_default_endpoint_policy_rejects_non_loopback_or_bad_scheme(endpoint):
    policy = EndpointPolicy()

    assert policy.is_allowed(endpoint) is False


def test_endpoint_policy_allows_explicit_hosts():
    policy = EndpointPolicy(allowed_hosts={"10.0.0.8", "service.internal"})

    assert policy.is_allowed("http://10.0.0.8:8080") is True
    assert policy.is_allowed("http://service.internal:8080") is True
    assert policy.is_allowed("http://10.0.0.9:8080") is False


def test_registry_uses_endpoint_policy():
    registry = EmbeddedServiceRegistry()

    with pytest.raises(ValidationError, match="endpoint is not allowed"):
        registry.register("fileshare", "http://10.0.0.1:8080")

    registry = EmbeddedServiceRegistry(endpoint_policy=EndpointPolicy(allowed_hosts={"10.0.0.1"}))
    record = registry.register("fileshare", "http://10.0.0.1:8080")
    assert record.endpoint == "http://10.0.0.1:8080"

