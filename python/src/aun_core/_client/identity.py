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
from .runtime import ClientRuntime


class IdentityRuntimeManager:
    """身份加载与运行时重建协调器。"""

    def __init__(self, runtime: Any) -> None:
        self.runtime = ClientRuntime.coerce(runtime)
        self.client = self.runtime.client

    def load_identity(self, aid: AID) -> None:
        client = self.client
        if client._state not in {"no_identity", "closed"}:
            raise StateError(f"load_identity not allowed in state {client._public_state.value}")
        if not isinstance(aid, AID) or not aid.is_private_key_valid():
            raise StateError("load_identity requires an AID with a valid private key")
        self.rebuild_runtime_for_identity(aid)
        identity = {
            "aid": aid.aid,
            "private_key_pem": aid.private_key_pem,
            "public_key_der_b64": aid.public_key,
            "cert": aid.cert_pem,
        }
        self.runtime.identity.set_loaded_identity(aid, identity)
        self.runtime.lifecycle.set_state("standby")
        self.runtime.lifecycle.set_closing(False)
        self.runtime.lifecycle.clear_retry_state()

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

        log = AUNLogger(debug=debug_enabled, aun_path=str(next_config.aun_path))
        log.bind_device_id(next_device_id)
        net = DnsResilientNet(
            aun_path=next_config.aun_path,
            verify_ssl=next_config.verify_ssl,
            logger=log,
        )
        discovery = GatewayDiscovery(
            verify_ssl=next_config.verify_ssl,
            logger=log,
            net=net,
        )
        connection_factory = _make_connection_factory(
            next_config.verify_ssl,
            log,
            net=net,
        )
        token_store = LocalTokenStore(
            next_config.aun_path,
            logger=log,
        )
        auth = AuthFlow(
            token_store=token_store,
            crypto=CryptoProvider(),
            aid=aid.aid,
            device_id=next_device_id,
            slot_id=next_slot_id,
            connection_factory=connection_factory,
            root_ca_path=next_config.root_ca_path,
            verify_ssl=next_config.verify_ssl,
            logger=log,
            net=net,
        )
        transport = RPCTransport(
            event_dispatcher=client._dispatcher,
            connection_factory=connection_factory,
            timeout=client._session_options.get("timeouts", {}).get(
                "call",
                _DEFAULT_SESSION_OPTIONS["timeouts"]["call"],
            ),
            on_disconnect=client._handle_transport_disconnect,
            logger=log,
        )
        transport.set_meta_observer(client._observe_rpc_meta)
        self.runtime.identity.apply_runtime_context(
            config_model=next_config,
            device_id=next_device_id,
            slot_id=next_slot_id,
            log=log,
            net=net,
            discovery=discovery,
            token_store=token_store,
            auth=auth,
            transport=transport,
            agent_md_manager=None,
        )
        self.runtime.services.set_agent_md_manager(_build_client_runtime_manager(client))
