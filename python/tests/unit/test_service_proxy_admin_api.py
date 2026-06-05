import pytest
from aiohttp.test_utils import TestClient, TestServer

from aun_core.service_proxy import ServiceProxyClient


async def _make_client(service_proxy_client: ServiceProxyClient, *, admin_token: str = "secret"):
    server = TestServer(service_proxy_client.create_admin_app(admin_token=admin_token))
    http = TestClient(server)
    await http.start_server()
    return http


@pytest.mark.asyncio
async def test_service_proxy_admin_api_health_and_auth():
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")
    http = await _make_client(client, admin_token="secret")
    try:
        unauthorized = await http.get("/health")
        assert unauthorized.status == 401

        ok = await http.get("/health", headers={"Authorization": "Bearer secret"})
        assert ok.status == 200
        body = await ok.json()
        assert body["status"] == "ok"
        assert body["provider_aid"] == "alice.agentid.pub"
        assert body["running"] is False
        assert body["services"] == 0
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_service_proxy_admin_api_register_list_unregister():
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")
    http = await _make_client(client, admin_token="secret")
    headers = {"Authorization": "Bearer secret"}
    try:
        registered = await http.post(
            "/services",
            headers=headers,
            json={
                "service_name": "fileshare",
                "endpoint": "http://127.0.0.1:8080/root",
                "service_type": "http",
                "visibility": "public",
                "metadata": {"title": "Files"},
            },
        )
        assert registered.status == 200
        registered_body = await registered.json()
        assert registered_body["service_name"] == "fileshare"
        assert "endpoint" not in registered_body

        listed = await http.get("/services", headers=headers)
        assert listed.status == 200
        listed_body = await listed.json()
        assert listed_body["services"] == [registered_body]

        deleted = await http.delete("/services/fileshare", headers=headers)
        assert deleted.status == 200
        assert await deleted.json() == {"removed": True}

        listed_after = await http.get("/services", headers=headers)
        assert (await listed_after.json())["services"] == []
    finally:
        await http.close()


@pytest.mark.asyncio
async def test_service_proxy_admin_api_rejects_bad_payload_and_endpoint():
    client = ServiceProxyClient(provider_aid="alice.agentid.pub")
    http = await _make_client(client, admin_token="secret")
    headers = {"Authorization": "Bearer secret"}
    try:
        bad_json = await http.post("/services", headers=headers, data="not-json")
        assert bad_json.status == 400

        bad_endpoint = await http.post(
            "/services",
            headers=headers,
            json={"service_name": "fileshare", "endpoint": "http://10.0.0.1:8080"},
        )
        assert bad_endpoint.status == 400
        assert "endpoint is not allowed" in (await bad_endpoint.json())["error"]
    finally:
        await http.close()

