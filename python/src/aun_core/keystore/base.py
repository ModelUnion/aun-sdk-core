from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


class KeyStore(Protocol):
    def load_key_pair(self, aid: str) -> dict | None: ...

    def save_key_pair(self, aid: str, key_pair: dict) -> None: ...

    def load_cert(self, aid: str, cert_fingerprint: str | None = None) -> str | None: ...

    def save_cert(
        self,
        aid: str,
        cert_pem: str,
        cert_fingerprint: str | None = None,
        *,
        make_active: bool = True,
    ) -> None: ...

    def load_identity(self, aid: str) -> dict | None: ...

    def save_identity(self, aid: str, identity: dict) -> None: ...

    def list_identities(self) -> list[str]: ...

    def load_metadata(self, aid: str) -> dict[str, Any] | None: ...

    def load_e2ee_prekeys(self, aid: str, device_id: str) -> dict[str, dict[str, Any]]: ...

    def save_e2ee_prekey(self, aid: str, prekey_id: str, prekey_data: dict[str, Any], device_id: str) -> None: ...

    def cleanup_e2ee_prekeys(self, aid: str, cutoff_ms: int, keep_latest: int = 5, device_id: str = "") -> list[str]: ...

    def list_group_secret_ids(self, aid: str) -> list[str]: ...

    def cleanup_group_old_epochs_state(self, aid: str, group_id: str, cutoff_ms: int) -> int: ...

    def load_group_secret_epoch(self, aid: str, group_id: str, epoch: int | None = None) -> dict[str, Any] | None: ...

    def load_group_secret_epochs(self, aid: str, group_id: str) -> list[dict[str, Any]]: ...

    def store_group_secret_transition(
        self,
        aid: str,
        group_id: str,
        *,
        epoch: int,
        secret: str,
        commitment: str,
        member_aids: list[str],
        epoch_chain: str | None = None,
        pending_rotation_id: str = "",
        epoch_chain_unverified: bool | None = None,
        epoch_chain_unverified_reason: str | None = None,
        old_epoch_retention_ms: int,
    ) -> bool: ...

    def store_group_secret_epoch(
        self,
        aid: str,
        group_id: str,
        *,
        epoch: int,
        secret: str,
        commitment: str,
        member_aids: list[str],
        epoch_chain: str | None = None,
        pending_rotation_id: str = "",
        epoch_chain_unverified: bool | None = None,
        epoch_chain_unverified_reason: str | None = None,
        old_epoch_retention_ms: int,
    ) -> bool: ...

    def discard_pending_group_secret_state(self, aid: str, group_id: str, epoch: int, rotation_id: str) -> bool: ...

    def load_instance_state(self, aid: str, device_id: str, slot_id: str = "") -> dict[str, Any] | None: ...

    def save_instance_state(self, aid: str, device_id: str, slot_id: str, state: dict[str, Any]) -> None: ...

    def update_instance_state(
        self,
        aid: str,
        device_id: str,
        slot_id: str,
        updater: Callable[[dict[str, Any]], dict[str, Any] | None],
    ) -> dict[str, Any]: ...

    def save_seq(self, aid: str, device_id: str, slot_id: str, namespace: str, contiguous_seq: int) -> None: ...

    def load_seq(self, aid: str, device_id: str, slot_id: str, namespace: str) -> int: ...

    def load_all_seqs(self, aid: str, device_id: str, slot_id: str) -> dict[str, int]: ...
