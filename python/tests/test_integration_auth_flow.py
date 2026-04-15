from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from aun_core import AUNClient


def _build_ca(subject_cn: str, issuer_cert=None, issuer_key=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer_name = issuer_cert.subject if issuer_cert is not None else subject
    signer = issuer_key or key
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=signer, algorithm=hashes.SHA256())
    )
    return key, cert, cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _build_leaf_cert(subject_cn: str, public_key, issuer_cert, issuer_key):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _build_empty_crl(issuer_cert, issuer_key) -> str:
    now = datetime.now(timezone.utc)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(hours=1))
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _build_good_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, issuer_key) -> str:
    now = datetime.now(timezone.utc)
    issuer_name_hash = hashes.Hash(hashes.SHA256())
    issuer_name_hash.update(issuer_cert.subject.public_bytes())
    issuer_name_digest = issuer_name_hash.finalize()
    issuer_key_hash = hashes.Hash(hashes.SHA256())
    issuer_key_hash.update(
        issuer_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    issuer_key_digest = issuer_key_hash.finalize()
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response_by_hash(
            issuer_name_hash=issuer_name_digest,
            issuer_key_hash=issuer_key_digest,
            serial_number=cert.serial_number,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=now + timedelta(minutes=5),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer_cert)
        .sign(issuer_key, hashes.SHA256())
    )
    return base64.b64encode(response.public_bytes(serialization.Encoding.DER)).decode("ascii")


@dataclass(slots=True)
class _GatewayState:
    root_pem: str
    issuer_cert: x509.Certificate
    issuer_key: ec.EllipticCurvePrivateKey
    auth_key: ec.EllipticCurvePrivateKey
    auth_cert: x509.Certificate
    auth_cert_pem: str
    crl_pem: str
    registrations: dict[str, dict]
    accepted_tokens: set[str]
    rejected_tokens: set[str]
    refresh_to_aid: dict[str, str]
    connect_tokens: list[str]
    connect_requests: list[dict]
    refresh_calls: list[str]
    downloaded_certs: list[str]
    next_token_id: int = 0

    def issue_tokens(self, aid: str) -> tuple[str, str]:
        self.next_token_id += 1
        access_token = f"access-{aid}-{self.next_token_id}"
        refresh_token = f"refresh-{aid}-{self.next_token_id}"
        self.accepted_tokens.add(access_token)
        self.refresh_to_aid[refresh_token] = aid
        return access_token, refresh_token


@dataclass(slots=True)
class LocalGateway:
    ws_url: str
    root_ca_path: str
    state: _GatewayState


@pytest_asyncio.fixture
async def local_gateway(tmp_path) -> LocalGateway:
    root_key, root_cert, root_pem = _build_ca("local-root")
    issuer_key, issuer_cert, issuer_pem = _build_ca("local-issuer", root_cert, root_key)
    auth_key = ec.generate_private_key(ec.SECP256R1())
    auth_cert_pem = _build_leaf_cert("auth.gateway.local", auth_key.public_key(), issuer_cert, issuer_key)
    auth_cert = x509.load_pem_x509_certificate(auth_cert_pem.encode("utf-8"))
    crl_pem = _build_empty_crl(issuer_cert, issuer_key)
    root_ca_path = tmp_path / "root-ca.pem"
    root_ca_path.write_text(root_pem, encoding="utf-8")

    state = _GatewayState(
        root_pem=root_pem,
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        auth_key=auth_key,
        auth_cert=auth_cert,
        auth_cert_pem=auth_cert_pem,
        crl_pem=crl_pem,
        registrations={},
        accepted_tokens=set(),
        rejected_tokens=set(),
        refresh_to_aid={},
        connect_tokens=[],
        connect_requests=[],
        refresh_calls=[],
        downloaded_certs=[],
    )

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({"jsonrpc": "2.0", "method": "challenge", "params": {"nonce": "gateway-nonce"}})

        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                continue
            request_obj = json.loads(msg.data)
            rpc_id = request_obj.get("id")
            method = request_obj.get("method", "")
            params = request_obj.get("params", {}) if isinstance(request_obj.get("params"), dict) else {}

            try:
                if method == "auth.create_aid":
                    aid = str(params.get("aid") or "")
                    if aid in state.registrations:
                        await ws.send_json({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "error": {"code": 5001, "message": f"AID {aid} already exists"},
                        })
                        continue
                    public_key = serialization.load_der_public_key(base64.b64decode(params["public_key"]))
                    cert_pem = _build_leaf_cert(aid, public_key, issuer_cert, issuer_key)
                    state.registrations[aid] = {"cert_pem": cert_pem}
                    result = {"cert": cert_pem}
                elif method == "auth.aid_login1":
                    client_nonce = str(params.get("client_nonce") or "")
                    signature = state.auth_key.sign(client_nonce.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
                    result = {
                        "request_id": "req-1",
                        "nonce": "server-login-nonce",
                        "auth_cert": state.auth_cert_pem,
                        "client_nonce_signature": base64.b64encode(signature).decode("ascii"),
                    }
                elif method == "auth.aid_login2":
                    aid = str(params.get("aid") or "")
                    access_token, refresh_token = state.issue_tokens(aid)
                    result = {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "expires_in": 3600,
                    }
                elif method == "auth.refresh_token":
                    refresh_token = str(params.get("refresh_token") or "")
                    state.refresh_calls.append(refresh_token)
                    aid = state.refresh_to_aid.get(refresh_token)
                    if not aid:
                        result = {"success": False, "error": "invalid refresh token"}
                    else:
                        access_token, new_refresh = state.issue_tokens(aid)
                        result = {
                            "success": True,
                            "access_token": access_token,
                            "refresh_token": new_refresh,
                            "expires_in": 3600,
                        }
                elif method == "auth.connect":
                    token = str(params.get("auth", {}).get("token") or "")
                    state.connect_tokens.append(token)
                    state.connect_requests.append(dict(params))
                    status = "ok" if token in state.accepted_tokens and token not in state.rejected_tokens else "denied"
                    result = {"status": status}
                elif method == "meta.ping":
                    result = {"pong": True}
                elif method == "message.e2ee.put_prekey":
                    result = {"ok": True}
                else:
                    await ws.send_json({
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "error": {"code": -32601, "message": f"method not found: {method}"},
                    })
                    continue

                await ws.send_json({"jsonrpc": "2.0", "id": rpc_id, "result": result})
            except Exception as exc:  # pragma: no cover - 测试辅助兜底
                await ws.send_json({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32603, "message": str(exc)},
                })

        return ws

    async def chain_handler(_request: web.Request) -> web.Response:
        return web.Response(text=issuer_pem + root_pem, content_type="text/plain")

    async def crl_handler(_request: web.Request) -> web.Response:
        return web.json_response({"crl_pem": state.crl_pem})

    async def ocsp_handler(request: web.Request) -> web.Response:
        serial_hex = request.match_info["serial"].lower()
        if serial_hex == format(state.auth_cert.serial_number, "x").lower():
            cert = state.auth_cert
        else:
            for registration in state.registrations.values():
                candidate = x509.load_pem_x509_certificate(registration["cert_pem"].encode("utf-8"))
                if format(candidate.serial_number, "x").lower() == serial_hex:
                    cert = candidate
                    break
            else:
                return web.Response(status=404, text="ocsp not found")
        return web.json_response({
            "status": "good",
            "ocsp_response": _build_good_ocsp(cert, issuer_cert, issuer_key),
        })

    async def cert_handler(request: web.Request) -> web.Response:
        aid = request.match_info["aid"]
        registration = state.registrations.get(aid)
        if registration is None:
            return web.Response(status=404, text="cert not found")
        state.downloaded_certs.append(aid)
        return web.Response(text=registration["cert_pem"], content_type="text/plain")

    app = web.Application()
    app.router.add_get("/aun", ws_handler)
    app.router.add_get("/pki/chain", chain_handler)
    app.router.add_get("/pki/crl.json", crl_handler)
    app.router.add_get("/pki/ocsp/{serial}", ocsp_handler)
    app.router.add_get("/pki/cert/{aid}", cert_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        yield LocalGateway(
            ws_url=f"ws://127.0.0.1:{port}/aun",
            root_ca_path=str(root_ca_path),
            state=state,
        )
    finally:
        await runner.cleanup()


def _make_client(tmp_path, gateway: LocalGateway) -> AUNClient:
    client = AUNClient({
        "aun_path": str(tmp_path / "aun"),
        "root_ca_path": gateway.root_ca_path,
    })
    client._gateway_url = gateway.ws_url
    return client


@pytest.mark.asyncio
async def test_local_gateway_full_auth_and_connect(tmp_path, local_gateway: LocalGateway):
    client = _make_client(tmp_path, local_gateway)
    aid = "local-auth-full.agentid.pub"

    try:
        created = await client.auth.create_aid({"aid": aid})
        assert created["aid"] == aid
        assert "BEGIN CERTIFICATE" in created["cert_pem"]

        auth = await client.auth.authenticate({"aid": aid})
        assert auth["aid"] == aid
        assert auth["gateway"] == local_gateway.ws_url
        assert auth["access_token"].startswith("access-")
        assert auth["refresh_token"].startswith("refresh-")

        await client.connect({
            **auth,
            "slot_id": "slot-a",
            "delivery_mode": "queue",
            "queue_routing": "sender_affinity",
            "affinity_ttl_ms": 600,
        }, {"auto_reconnect": False, "heartbeat_interval": 0})
        assert client.state == "connected"

        pong = await client.call("meta.ping", {})
        assert pong["pong"] is True
        assert any(token == auth["access_token"] for token in local_gateway.state.connect_tokens)
        connect_request = local_gateway.state.connect_requests[-1]
        assert connect_request["device"] == {"id": client._device_id, "type": "sdk"}
        assert connect_request["client"] == {"slot_id": "slot-a"}
        assert connect_request["delivery_mode"] == {
            "mode": "queue",
            "routing": "sender_affinity",
            "affinity_ttl_ms": 600,
        }
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_create_aid_recovers_missing_cert_via_download(tmp_path, local_gateway: LocalGateway):
    aid = "recover-cert.agentid.pub"
    client1 = _make_client(tmp_path / "source", local_gateway)
    client2 = _make_client(tmp_path / "restore", local_gateway)

    try:
        await client1.auth.create_aid({"aid": aid})
        identity = client1._keystore.load_identity(aid)
        client2._keystore.save_key_pair(aid, {
            "private_key_pem": identity["private_key_pem"],
            "public_key_der_b64": identity["public_key_der_b64"],
            "curve": identity["curve"],
        })
        remaining = {
            key: value
            for key, value in identity.items()
            if key not in {"private_key_pem", "public_key_der_b64", "curve", "cert"}
        }
        client2._keystore.save_identity(aid, remaining)

        recovered = await client2.auth.create_aid({"aid": aid})
        restored = client2._keystore.load_identity(aid)

        assert recovered["aid"] == aid
        assert "BEGIN CERTIFICATE" in restored["cert"]
        assert aid in local_gateway.state.downloaded_certs
    finally:
        await client1.close()
        await client2.close()


@pytest.mark.asyncio
async def test_reconnect_flow_refreshes_stale_access_token(tmp_path, local_gateway: LocalGateway):
    client = _make_client(tmp_path, local_gateway)
    aid = "refresh-reconnect.agentid.pub"

    try:
        await client.auth.create_aid({"aid": aid})
        auth = await client.auth.authenticate({"aid": aid})
        stale_token = auth["access_token"]

        await client.connect(auth, {"auto_reconnect": False, "heartbeat_interval": 0})
        local_gateway.state.rejected_tokens.add(stale_token)

        await client._transport.close()
        await client._invoke_reconnect_connect_once()

        assert client.state == "connected"
        assert client._session_params["access_token"] != stale_token
        assert client._identity["access_token"] == client._session_params["access_token"]
        assert local_gateway.state.refresh_calls == [auth["refresh_token"]]
        assert local_gateway.state.connect_tokens.count(stale_token) >= 2
    finally:
        await client.close()
