from __future__ import annotations

from typing import Any

from ..aid import AID
from ..auth import AuthFlow
from ..config import AUNConfig, get_device_id, normalize_slot_id
from ..crypto import CryptoProvider
from ..discovery import GatewayDiscovery
from ..errors import StateError
from ..keystore.local_token_store import LocalTokenStore
from ..logger import AUNLogger
from ..transport import RPCTransport


class IdentityRuntimeManager:
    """身份加载与运行时重建协调器。"""

    def __init__(self, client: Any) -> None:
        self.client = client

    def load_identity(self, aid: AID) -> None:
        client = self.client
        if client._state not in {"no_identity", "closed"}:
            raise StateError(f"load_identity not allowed in state {client._public_state.value}")
        if not isinstance(aid, AID) or not aid.is_private_key_valid():
            raise StateError("load_identity requires an AID with a valid private key")
        self.rebuild_runtime_for_identity(aid)
        client._current_aid = aid
        client._aid = aid.aid
        client._auth._aid = aid.aid
        client._state = "standby"
        client._closing = False
        client._identity = {
            "aid": aid.aid,
            "private_key_pem": aid.private_key_pem,
            "public_key_der_b64": aid.public_key,
            "cert": aid.cert_pem,
        }
        client._auth.set_identity(client._identity)
        client._last_error = None
        client._last_error_code = None
        client._next_retry_at = None
        client._retry_attempt = 0

    def rebuild_runtime_for_identity(self, aid: AID) -> None:
        """让无身份客户端切换到 AID 所属的运行时。"""
        from ..client import (
            _DEFAULT_SESSION_OPTIONS,
            _build_client_runtime_manager,
            _make_connection_factory,
        )
        from ..net import DnsResilientNet

        client = self.client
        raw_config = {
            "aun_path": aid.aun_path,
            "verify_ssl": aid.verify_ssl,
            "debug": aid.debug,
        }
        if aid.root_ca_path:
            raw_config["root_ca_path"] = aid.root_ca_path
        next_config = AUNConfig.from_dict(raw_config)
        current_path = str(getattr(client._config_model, "aun_path", ""))
        next_path = str(next_config.aun_path)
        next_slot_id = normalize_slot_id(aid.slot_id)
        next_device_id = (aid.device_id or None) or get_device_id(next_config.aun_path)
        if (
            current_path == next_path
            and client._auth._aid == aid.aid
            and getattr(client._config_model, "verify_ssl", True) == next_config.verify_ssl
            and getattr(client._config_model, "root_ca_path", None) == next_config.root_ca_path
            and getattr(client, "_slot_id", "default") == next_slot_id
            and getattr(client, "_device_id", "") == next_device_id
        ):
            return

        debug_enabled = bool(aid.debug)
        try:
            client._token_store.close()
        except Exception as exc:
            client._log.warn("client", "old token store cleanup failed during identity runtime rebuild: %s", exc)
        try:
            client._net.close()
        except Exception as exc:
            client._log.warn("client", "old network runtime cleanup failed during identity runtime rebuild: %s", exc)

        client._config_model = next_config
        client._device_id = next_device_id
        client._slot_id = next_slot_id
        client._log = AUNLogger(debug=debug_enabled, aun_path=str(client._config_model.aun_path))
        client._log.bind_device_id(client._device_id)
        client.config = {
            "aun_path": str(client._config_model.aun_path),
            "root_ca_path": client._config_model.root_ca_path,
            "seed_password": client._config_model.seed_password,
        }
        client._dispatcher._log = client._log

        client._net = DnsResilientNet(
            aun_path=client._config_model.aun_path,
            verify_ssl=client._config_model.verify_ssl,
            logger=client._log,
        )
        client._discovery = GatewayDiscovery(
            verify_ssl=client._config_model.verify_ssl,
            logger=client._log,
            net=client._net,
        )
        connection_factory = _make_connection_factory(
            client._config_model.verify_ssl,
            client._log,
            net=client._net,
        )
        client._token_store = LocalTokenStore(
            client._config_model.aun_path,
            logger=client._log,
        )
        client._auth = AuthFlow(
            token_store=client._token_store,
            crypto=CryptoProvider(),
            aid=aid.aid,
            device_id=client._device_id,
            slot_id=client._slot_id,
            connection_factory=connection_factory,
            root_ca_path=client._config_model.root_ca_path,
            verify_ssl=client._config_model.verify_ssl,
            logger=client._log,
            net=client._net,
        )
        client._transport = RPCTransport(
            event_dispatcher=client._dispatcher,
            connection_factory=connection_factory,
            timeout=client._session_options.get("timeouts", {}).get(
                "call",
                _DEFAULT_SESSION_OPTIONS["timeouts"]["call"],
            ),
            on_disconnect=client._handle_transport_disconnect,
            logger=client._log,
        )
        client._transport.set_meta_observer(client._observe_rpc_meta)
        client._agent_md_manager = _build_client_runtime_manager(client)
        client._peer_gateway_cache.clear()
