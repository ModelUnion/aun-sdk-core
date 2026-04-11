from __future__ import annotations

import copy
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .base import KeyStore
from ..secret_store import SecretStore, create_default_secret_store

import logging

_log = logging.getLogger("aun_core.keystore")

_SENSITIVE_TOKEN_FIELDS = ("access_token", "refresh_token", "kite_token")
_CRITICAL_METADATA_KEYS = ("e2ee_prekeys", "e2ee_sessions", "group_secrets")
_STRUCTURED_RECOVERY_RETENTION_MS = 7 * 24 * 3600 * 1000
_STRUCTURED_PREKEY_MIN_KEEP_COUNT = 7


def _prekey_created_marker(record: dict[str, Any]) -> int:
    for key in ("created_at", "updated_at", "expires_at"):
        marker = record.get(key)
        if isinstance(marker, (int, float)):
            return int(marker)
    return 0


def _latest_prekey_ids(
    prekeys: dict[str, dict[str, Any]],
    keep_latest: int,
) -> set[str]:
    if keep_latest <= 0:
        return set()
    ordered: list[tuple[str, int]] = []
    for prekey_id, prekey_data in prekeys.items():
        if not isinstance(prekey_data, dict):
            continue
        ordered.append((prekey_id, _prekey_created_marker(prekey_data)))
    ordered.sort(key=lambda item: (item[1], item[0]), reverse=True)
    return {prekey_id for prekey_id, _marker in ordered[:keep_latest]}


def _secure_file_permissions(path: Path) -> None:
    """在 Unix 系统上将文件权限设为 0o600（仅属主可读写）"""
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # 平台兼容 fallback


class FileKeyStore(KeyStore):
    # 按 AID 粒度的并发锁，防止 save_metadata 竞态
    _metadata_locks: dict[str, threading.RLock] = {}
    _locks_lock = threading.Lock()

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        secret_store: SecretStore | None = None,
        encryption_seed: str | None = None,
        sqlite_backup: Any = None,
    ) -> None:
        from .sqlite_backup import SQLiteBackup

        preferred = Path(root or Path.home() / ".aun")
        fallback = Path.cwd() / ".aun"
        resolved_root = self._prepare_root(preferred, fallback)
        self._sqlite_backup: SQLiteBackup | None = sqlite_backup
        self._secret_store = secret_store or create_default_secret_store(
            root=resolved_root, encryption_seed=encryption_seed,
            sqlite_backup=self._sqlite_backup,
        )
        if resolved_root.name == "keys":
            self._root = resolved_root.parent
            self._legacy_roots = [resolved_root, self._root / "keys"]
        else:
            self._root = resolved_root
            self._legacy_roots = [self._root / "keys", self._root]
        self._aids_root = self._root / "AIDs"
        self._aids_root.mkdir(parents=True, exist_ok=True)
        self._sync_bundled_root_ca()

    def load_identity(self, aid: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            identity = self._load_identity_from_split_files(aid)
            if identity is not None:
                return identity
            path = self._identity_path(aid)
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
            # 兼容旧格式：~/.aun/{aid}/AIDs/{aid}/（旧版 SDK 按 cwd 生成子目录）
            legacy_subdir = self._root / self._safe_aid(aid)
            if legacy_subdir.is_dir():
                legacy_ks = FileKeyStore(legacy_subdir, secret_store=self._secret_store)
                return legacy_ks._load_identity_from_split_files(aid)
            return None

    def save_identity(self, aid: str, identity: dict) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            key_pair = {
                key: identity[key]
                for key in ("private_key_pem", "public_key_der_b64", "curve")
                if key in identity
            }
            if key_pair:
                self.save_key_pair(aid, key_pair)
            cert = identity.get("cert")
            if isinstance(cert, str) and cert:
                self.save_cert(aid, cert)
            # 合并 metadata 而非覆盖：先加载已有数据，再更新 identity 中的字段
            # 保护 e2ee_prekeys、group_secrets 等由其他流程写入的关键数据不被丢失
            new_fields = {
                key: value
                for key, value in identity.items()
                if key not in {"private_key_pem", "public_key_der_b64", "curve", "cert"}
            }

            def _merge(existing: dict[str, Any]) -> dict[str, Any]:
                existing.update(new_fields)
                return existing

            self.update_metadata(aid, _merge)

    def load_key_pair(self, aid: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._key_pair_path(aid)
            if path.exists():
                key_pair = json.loads(path.read_text(encoding="utf-8"))
                result = self._restore_key_pair(aid, key_pair)
                # 双读：文件有，确保 SQLite 也有
                self._backup_key_pair_to_sqlite(aid, path)
                return result
            legacy_key_path = self._load_legacy_split_file(aid, ".key.json")
            if legacy_key_path is not None:
                key_pair = json.loads(legacy_key_path.read_text(encoding="utf-8"))
                return self._restore_key_pair(aid, key_pair)
            identity = self._load_legacy_identity(aid)
            if identity is not None:
                key_pair = {k: identity[k] for k in ("private_key_pem", "public_key_der_b64", "curve") if k in identity}
                return key_pair or None
            # fallback: 旧格式子目录 ~/.aun/{aid}/AIDs/{aid}/
            lks = self._legacy_subdir_ks(aid)
            if lks:
                return lks.load_key_pair(aid)
            # 最终 fallback: 从 SQLite 恢复
            return self._restore_key_pair_from_sqlite(aid)

    def save_key_pair(self, aid: str, key_pair: dict) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._key_pair_path(aid)
            path.parent.mkdir(parents=True, exist_ok=True)

            # 保护私钥
            protected_key_pair = copy.deepcopy(key_pair)
            scope = self._safe_aid(aid)
            private_key_pem = protected_key_pair.pop("private_key_pem", None)
            if isinstance(private_key_pem, str) and private_key_pem:
                protection = self._secret_store.protect(
                    scope,
                    "identity/private_key",
                    private_key_pem.encode("utf-8"),
                )
                if not protection.get("persisted"):
                    raise RuntimeError(
                        f"SecretStore 无法持久化私钥 (scheme={protection.get('scheme')})。"
                        f"私钥必须能跨进程重启保留，请检查密钥存储配置。"
                    )
                protected_key_pair["private_key_protection"] = protection
            path.write_text(json.dumps(protected_key_pair, ensure_ascii=False, indent=2), encoding="utf-8")
            _secure_file_permissions(path)
            # 双写：备份到 SQLite
            self._backup_key_pair_to_sqlite(aid, path)

    def load_cert(self, aid: str) -> str | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._cert_path(aid)
            if path.exists():
                cert = path.read_text(encoding="utf-8")
                # 双读：文件有，确保 SQLite 也有
                self._backup_cert_to_sqlite(aid, cert)
                return cert
            legacy_cert_path = self._load_legacy_split_file(aid, ".cert.pem")
            if legacy_cert_path is not None:
                return legacy_cert_path.read_text(encoding="utf-8")
            identity = self._load_legacy_identity(aid)
            cert = identity.get("cert") if identity else None
            if isinstance(cert, str) and cert:
                return cert
            lks = self._legacy_subdir_ks(aid)
            if lks:
                return lks.load_cert(aid)
            # 最终 fallback: 从 SQLite 恢复
            return self._restore_cert_from_sqlite(aid)

    def save_cert(self, aid: str, cert_pem: str) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._cert_path(aid)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(cert_pem, encoding="utf-8")
            # 双写：备份到 SQLite
            self._backup_cert_to_sqlite(aid, cert_pem)

    def load_metadata(self, aid: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            merged = self._build_merged_metadata_locked(aid)
            return copy.deepcopy(merged) if isinstance(merged, dict) else None

    def save_metadata(self, aid: str, metadata: dict) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            self._save_metadata_locked(aid, metadata)

    def update_metadata(
        self,
        aid: str,
        updater: Callable[[dict[str, Any]], dict[str, Any] | None],
    ) -> dict[str, Any]:
        """在同一把 AID 级锁内完成 load -> mutate -> save。"""
        lock = self._get_metadata_lock(aid)
        with lock:
            current = self._build_merged_metadata_locked(aid) or {}
            working = copy.deepcopy(current)
            updated = updater(working)
            if updated is None:
                updated = working
            if not isinstance(updated, dict):
                raise TypeError("update_metadata updater must return dict | None")
            self._save_metadata_locked(aid, updated)
            return copy.deepcopy(updated)

    def _save_metadata_locked(self, aid: str, metadata: dict) -> None:
        current = self._build_merged_metadata_locked(aid) or {}
        merged = copy.deepcopy(metadata)
        for key in _CRITICAL_METADATA_KEYS:
            if key in current and current[key] and key not in merged:
                _log.warning(
                    "save_metadata: 传入数据缺少 '%s' (aid=%s)，自动合并已有数据",
                    key, aid,
                )
                merged[key] = copy.deepcopy(current[key])

        if self._sqlite_enabled():
            prekeys = merged.get("e2ee_prekeys")
            if isinstance(prekeys, dict):
                self._replace_prekeys_sqlite_locked(aid, prekeys)
            group_secrets = merged.get("group_secrets")
            if isinstance(group_secrets, dict):
                self._replace_group_states_sqlite_locked(aid, group_secrets)

        self._save_meta_json_only_locked(aid, merged)

    def load_any_identity(self) -> dict | None:
        candidates: set[str] = set()
        if not self._root.exists():
            return None
        if self._aids_root.exists():
            for path in self._aids_root.iterdir():
                if path.is_dir():
                    candidates.add(path.name)
        for legacy_root in self._legacy_roots:
            if not legacy_root.exists():
                continue
            for path in legacy_root.glob("*.meta.json"):
                candidates.add(path.name.removesuffix(".meta.json"))
            for path in legacy_root.glob("*.key.json"):
                candidates.add(path.name.removesuffix(".key.json"))
            for path in legacy_root.glob("*.cert.pem"):
                candidates.add(path.name.removesuffix(".cert.pem"))
            for path in legacy_root.glob("*.json"):
                name = path.name
                if name.endswith(".meta.json") or name.endswith(".key.json"):
                    continue
                candidates.add(path.name.removesuffix(".json"))
        for aid in sorted(candidates):
            identity = self.load_identity(aid)
            if identity is not None:
                return identity
        return None

    def load_e2ee_prekeys(self, aid: str) -> dict[str, dict[str, Any]]:
        lock = self._get_metadata_lock(aid)
        with lock:
            meta_only = self._load_meta_json_only(aid) or {}
            self._sync_structured_state_from_meta_locked(aid, meta_only)
            if self._sqlite_enabled():
                return self._load_prekeys_from_sqlite_locked(aid)
            prekeys = meta_only.get("e2ee_prekeys")
            return copy.deepcopy(prekeys) if isinstance(prekeys, dict) else {}

    def save_e2ee_prekey(self, aid: str, prekey_id: str, prekey_data: dict[str, Any]) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            if self._sqlite_enabled():
                meta_only = self._load_meta_json_only(aid) or {}
                self._sync_structured_state_from_meta_locked(aid, meta_only)
                existing = self._load_prekeys_from_sqlite_locked(aid)
            else:
                existing = {}
            existing[prekey_id] = copy.deepcopy(prekey_data)
            if self._sqlite_enabled():
                self._replace_prekeys_sqlite_locked(aid, existing)
            self._update_meta_json_only_locked(
                aid,
                lambda meta: self._set_prekey_backup(meta, prekey_id, prekey_data),
            )

    def cleanup_e2ee_prekeys(
        self,
        aid: str,
        cutoff_ms: int,
        keep_latest: int = _STRUCTURED_PREKEY_MIN_KEEP_COUNT,
    ) -> list[str]:
        lock = self._get_metadata_lock(aid)
        with lock:
            meta_only = self._load_meta_json_only(aid) or {}
            self._sync_structured_state_from_meta_locked(aid, meta_only)
            removed: list[str] = []
            if self._sqlite_enabled():
                removed = self._sqlite_backup.cleanup_prekeys_before(aid, cutoff_ms, keep_latest)
            else:
                prekeys = meta_only.get("e2ee_prekeys")
                if isinstance(prekeys, dict):
                    retained_prekey_ids = _latest_prekey_ids(prekeys, keep_latest)
                    for prekey_id, prekey_data in list(prekeys.items()):
                        if not isinstance(prekey_data, dict) or prekey_id in retained_prekey_ids:
                            continue
                        if _prekey_created_marker(prekey_data) < cutoff_ms:
                            removed.append(prekey_id)
                    for prekey_id in removed:
                        prekeys.pop(prekey_id, None)
            if removed:
                self._update_meta_json_only_locked(
                    aid,
                    lambda meta: self._remove_prekeys_from_backup(meta, removed),
                )
            return removed

    def load_group_secret_state(self, aid: str, group_id: str) -> dict[str, Any] | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            meta_only = self._load_meta_json_only(aid) or {}
            self._sync_structured_state_from_meta_locked(aid, meta_only)
            if self._sqlite_enabled():
                groups = self._load_group_states_from_sqlite_locked(aid)
                entry = groups.get(group_id)
                return copy.deepcopy(entry) if isinstance(entry, dict) else None
            group_secrets = meta_only.get("group_secrets")
            if isinstance(group_secrets, dict):
                entry = group_secrets.get(group_id)
                return copy.deepcopy(entry) if isinstance(entry, dict) else None
            return None

    def load_all_group_secret_states(self, aid: str) -> dict[str, dict[str, Any]]:
        lock = self._get_metadata_lock(aid)
        with lock:
            meta_only = self._load_meta_json_only(aid) or {}
            self._sync_structured_state_from_meta_locked(aid, meta_only)
            if self._sqlite_enabled():
                return self._load_group_states_from_sqlite_locked(aid)
            group_secrets = meta_only.get("group_secrets")
            return copy.deepcopy(group_secrets) if isinstance(group_secrets, dict) else {}

    def save_group_secret_state(self, aid: str, group_id: str, entry: dict[str, Any]) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            if self._sqlite_enabled():
                meta_only = self._load_meta_json_only(aid) or {}
                self._sync_structured_state_from_meta_locked(aid, meta_only)
                current_groups = self._load_group_states_from_sqlite_locked(aid)
                current_groups[group_id] = copy.deepcopy(entry)
                self._replace_group_states_sqlite_locked(aid, current_groups)
            self._update_meta_json_only_locked(
                aid,
                lambda meta: self._set_group_backup(meta, group_id, entry),
            )

    def cleanup_group_old_epochs_state(self, aid: str, group_id: str, cutoff_ms: int) -> int:
        lock = self._get_metadata_lock(aid)
        with lock:
            meta_only = self._load_meta_json_only(aid) or {}
            self._sync_structured_state_from_meta_locked(aid, meta_only)
            removed_epochs: list[int] = []
            if self._sqlite_enabled():
                removed_epochs = self._sqlite_backup.cleanup_group_old_epochs(aid, group_id, cutoff_ms)
            else:
                group_secrets = meta_only.get("group_secrets")
                if isinstance(group_secrets, dict):
                    entry = group_secrets.get(group_id)
                    if isinstance(entry, dict):
                        old_epochs = entry.get("old_epochs")
                        if isinstance(old_epochs, list):
                            remaining: list[dict[str, Any]] = []
                            for old in old_epochs:
                                if not isinstance(old, dict):
                                    continue
                                marker = old.get("updated_at") or old.get("expires_at") or 0
                                if isinstance(marker, (int, float)) and int(marker) < cutoff_ms:
                                    epoch = old.get("epoch")
                                    if isinstance(epoch, (int, float)):
                                        removed_epochs.append(int(epoch))
                                    continue
                                remaining.append(old)
                            entry["old_epochs"] = remaining
            if removed_epochs:
                self._update_meta_json_only_locked(
                    aid,
                    lambda meta: self._remove_group_old_epochs_from_backup(meta, group_id, removed_epochs),
                )
            return len(removed_epochs)

    def _identity_path(self, aid: str) -> Path:
        return self._legacy_file_path(self._root, aid, ".json")

    def _key_pair_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "private" / "key.json"

    def _cert_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "public" / "cert.pem"

    def _metadata_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "tokens" / "meta.json"

    def _load_legacy_identity(self, aid: str) -> dict | None:
        for legacy_root in self._legacy_roots:
            path = self._legacy_file_path(legacy_root, aid, ".json")
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        return None

    def _load_identity_from_split_files(self, aid: str) -> dict | None:
        key_pair = self.load_key_pair(aid)
        cert = self.load_cert(aid)
        metadata = self.load_metadata(aid)
        if key_pair is None and cert is None and metadata is None:
            return None
        identity: dict = {}
        if isinstance(metadata, dict):
            identity.update(metadata)
        if isinstance(key_pair, dict):
            identity.update(key_pair)
        if cert:
            identity["cert"] = cert
        return identity

    def _load_legacy_split_file(self, aid: str, suffix: str) -> Path | None:
        for legacy_root in self._legacy_roots:
            path = self._legacy_file_path(legacy_root, aid, suffix)
            if path.exists():
                return path
        return None

    def _identity_dir(self, aid: str) -> Path:
        return self._aids_root / self._safe_aid(aid)

    @staticmethod
    def _safe_aid(aid: str) -> str:
        return aid.replace("/", "_").replace("\\", "_").replace(":", "_")

    def _legacy_file_path(self, legacy_root: Path, aid: str, suffix: str) -> Path:
        return legacy_root / f"{self._safe_aid(aid)}{suffix}"

    def _delete_legacy_identity_files(self, legacy_root: Path, aid: str) -> None:
        _log.warning(
            "legacy 身份文件删除已禁用 (aid=%s, root=%s)；SDK 不再删除旧格式身份文件。",
            aid,
            legacy_root,
        )

    def _load_meta_json_only(self, aid: str) -> dict[str, Any] | None:
        path = self._metadata_path(aid)
        if path.exists():
            try:
                result = self._restore_metadata(aid, json.loads(path.read_text(encoding="utf-8")))
                self._backup_metadata_to_sqlite(aid, path)
                return result
            except (json.JSONDecodeError, ValueError) as exc:
                _log.warning("meta.json 损坏 (aid=%s): %s，尝试从 SQLite 恢复", aid, exc)
                # fallback 到 SQLite 恢复
                return self._restore_metadata_from_sqlite(aid)
        legacy_meta_path = self._load_legacy_split_file(aid, ".meta.json")
        if legacy_meta_path is not None:
            return self._restore_metadata(aid, json.loads(legacy_meta_path.read_text(encoding="utf-8")))
        identity = self._load_legacy_identity(aid)
        if identity is not None:
            return self._restore_metadata(aid, {
                key: value
                for key, value in identity.items()
                if key not in {"private_key_pem", "public_key_der_b64", "curve", "cert"}
            })
        lks = self._legacy_subdir_ks(aid)
        if lks:
            return lks.load_metadata(aid)
        return self._restore_metadata_from_sqlite(aid)

    def _build_merged_metadata_locked(self, aid: str) -> dict[str, Any] | None:
        metadata = self._load_meta_json_only(aid) or {}
        self._sync_structured_state_from_meta_locked(aid, metadata)
        if self._sqlite_enabled():
            metadata.pop("e2ee_prekeys", None)
            metadata.pop("group_secrets", None)
            prekeys = self._load_prekeys_from_sqlite_locked(aid)
            if prekeys:
                metadata["e2ee_prekeys"] = prekeys
            group_secrets = self._load_group_states_from_sqlite_locked(aid)
            if group_secrets:
                metadata["group_secrets"] = group_secrets
        return metadata or None

    def _save_meta_json_only_locked(self, aid: str, metadata: dict[str, Any]) -> None:
        path = self._metadata_path(aid)
        path.parent.mkdir(parents=True, exist_ok=True)
        protected = self._protect_metadata(aid, metadata)
        path.write_text(json.dumps(protected, ensure_ascii=False, indent=2), encoding="utf-8")
        _secure_file_permissions(path)
        self._backup_metadata_to_sqlite(aid, path)

    def _update_meta_json_only_locked(
        self,
        aid: str,
        updater: Callable[[dict[str, Any]], dict[str, Any] | None],
    ) -> None:
        current = self._load_meta_json_only(aid) or {}
        working = copy.deepcopy(current)
        updated = updater(working)
        if updated is None:
            updated = working
        self._save_meta_json_only_locked(aid, updated)

    def _sync_structured_state_from_meta_locked(self, aid: str, metadata: dict[str, Any]) -> None:
        if not self._sqlite_enabled() or not isinstance(metadata, dict):
            return

        meta_prekeys = metadata.get("e2ee_prekeys")
        if isinstance(meta_prekeys, dict):
            sqlite_prekeys = self._load_prekeys_from_sqlite_locked(aid)
            retained_prekey_ids = _latest_prekey_ids(meta_prekeys, _STRUCTURED_PREKEY_MIN_KEEP_COUNT)
            changed = False
            for prekey_id, prekey_data in meta_prekeys.items():
                if (
                    prekey_id in sqlite_prekeys
                    or not isinstance(prekey_data, dict)
                    or self._is_explicitly_expired(prekey_data)
                    or (
                        prekey_id not in retained_prekey_ids
                        and not self._is_prekey_recoverable(prekey_data)
                    )
                ):
                    continue
                sqlite_prekeys[prekey_id] = copy.deepcopy(prekey_data)
                changed = True
            if changed:
                self._replace_prekeys_sqlite_locked(aid, sqlite_prekeys)

        meta_groups = metadata.get("group_secrets")
        if isinstance(meta_groups, dict):
            sqlite_groups = self._load_group_states_from_sqlite_locked(aid)
            changed = False
            for group_id, incoming in meta_groups.items():
                if not isinstance(incoming, dict):
                    continue
                merged = self._merge_group_entry_from_meta(sqlite_groups.get(group_id), incoming)
                if merged != sqlite_groups.get(group_id):
                    sqlite_groups[group_id] = merged
                    changed = True
            if changed:
                self._replace_group_states_sqlite_locked(aid, sqlite_groups)

    def _load_prekeys_from_sqlite_locked(self, aid: str) -> dict[str, dict[str, Any]]:
        if not self._sqlite_enabled():
            return {}
        protected = self._sqlite_backup.load_prekeys(aid)
        return self._restore_prekeys(aid, protected)

    def _replace_prekeys_sqlite_locked(self, aid: str, prekeys: dict[str, dict[str, Any]]) -> None:
        if not self._sqlite_enabled():
            return
        protected = self._protect_prekeys(aid, prekeys)
        self._sqlite_backup.replace_prekeys(aid, protected)

    def _load_group_states_from_sqlite_locked(self, aid: str) -> dict[str, dict[str, Any]]:
        if not self._sqlite_enabled():
            return {}
        protected = self._sqlite_backup.load_group_entries(aid)
        return self._restore_group_secrets(aid, protected)

    def _replace_group_states_sqlite_locked(self, aid: str, group_states: dict[str, dict[str, Any]]) -> None:
        if not self._sqlite_enabled():
            return
        protected = self._protect_group_secrets(aid, group_states)
        self._sqlite_backup.replace_group_entries(aid, protected)

    def _merge_group_entry_from_meta(
        self,
        existing: dict[str, Any] | None,
        incoming: dict[str, Any],
    ) -> dict[str, Any]:
        current: dict[str, Any] | None = None
        if isinstance(existing, dict) and isinstance(existing.get("epoch"), (int, float)):
            current = {
                key: copy.deepcopy(value)
                for key, value in existing.items()
                if key != "old_epochs"
            }

        old_by_epoch: dict[int, dict[str, Any]] = {}
        if isinstance(existing, dict):
            for old in existing.get("old_epochs", []):
                if isinstance(old, dict) and isinstance(old.get("epoch"), (int, float)):
                    old_by_epoch[int(old["epoch"])] = copy.deepcopy(old)

        incoming_current: dict[str, Any] | None = None
        incoming_epoch = incoming.get("epoch")
        if isinstance(incoming_epoch, (int, float)) and self._is_group_epoch_recoverable(incoming):
            incoming_current = {
                key: copy.deepcopy(value)
                for key, value in incoming.items()
                if key != "old_epochs"
            }

        if incoming_current is not None:
            incoming_epoch_int = int(incoming_current["epoch"])
            if current is None:
                current = incoming_current
            else:
                current_epoch = int(current["epoch"])
                if incoming_epoch_int > current_epoch:
                    old_by_epoch[current_epoch] = self._prefer_newer_group_epoch_record(
                        old_by_epoch.get(current_epoch),
                        current,
                    )
                    current = incoming_current
                elif incoming_epoch_int == current_epoch:
                    current = self._prefer_newer_group_epoch_record(current, incoming_current)
                else:
                    old_by_epoch[incoming_epoch_int] = self._prefer_newer_group_epoch_record(
                        old_by_epoch.get(incoming_epoch_int),
                        incoming_current,
                    )

        for old in incoming.get("old_epochs", []):
            if (
                not isinstance(old, dict)
                or not isinstance(old.get("epoch"), (int, float))
                or not self._is_group_epoch_recoverable(old)
            ):
                continue
            epoch = int(old["epoch"])
            old_by_epoch[epoch] = self._prefer_newer_group_epoch_record(
                old_by_epoch.get(epoch),
                old,
            )

        merged: dict[str, Any] = {}
        if current is not None and isinstance(current.get("epoch"), (int, float)):
            old_by_epoch.pop(int(current["epoch"]), None)
            merged.update(copy.deepcopy(current))
        if old_by_epoch:
            merged["old_epochs"] = [
                copy.deepcopy(old_by_epoch[epoch])
                for epoch in sorted(old_by_epoch)
            ]
        return merged

    @staticmethod
    def _prefer_newer_group_epoch_record(
        existing: dict[str, Any] | None,
        incoming: dict[str, Any],
    ) -> dict[str, Any]:
        if existing is None:
            return copy.deepcopy(incoming)
        existing_updated = existing.get("updated_at", 0)
        incoming_updated = incoming.get("updated_at", 0)
        if isinstance(incoming_updated, (int, float)) and int(incoming_updated) > int(existing_updated or 0):
            return copy.deepcopy(incoming)
        return copy.deepcopy(existing)

    @staticmethod
    def _is_unexpired_record(record: dict[str, Any], fallback_key: str) -> bool:
        now_ms = int(time.time() * 1000)
        expires_at = record.get("expires_at")
        if isinstance(expires_at, (int, float)):
            return int(expires_at) >= now_ms
        marker = record.get(fallback_key)
        if isinstance(marker, (int, float)):
            return int(marker) + _STRUCTURED_RECOVERY_RETENTION_MS >= now_ms
        return False

    def _is_prekey_recoverable(self, record: dict[str, Any]) -> bool:
        return self._is_unexpired_record(record, "created_at")

    @staticmethod
    def _is_explicitly_expired(record: dict[str, Any]) -> bool:
        """有明确 expires_at 且已过期。retained 保底不应覆盖此检查。"""
        expires_at = record.get("expires_at")
        if isinstance(expires_at, (int, float)):
            return int(expires_at) < int(time.time() * 1000)
        return False

    def _is_group_epoch_recoverable(self, record: dict[str, Any]) -> bool:
        return self._is_unexpired_record(record, "updated_at")

    def _set_prekey_backup(
        self,
        metadata: dict[str, Any],
        prekey_id: str,
        prekey_data: dict[str, Any],
    ) -> dict[str, Any]:
        prekeys = metadata.get("e2ee_prekeys")
        if not isinstance(prekeys, dict):
            prekeys = {}
        prekeys[prekey_id] = copy.deepcopy(prekey_data)
        metadata["e2ee_prekeys"] = prekeys
        return metadata

    def _remove_prekeys_from_backup(
        self,
        metadata: dict[str, Any],
        prekey_ids: list[str],
    ) -> dict[str, Any]:
        prekeys = metadata.get("e2ee_prekeys")
        if isinstance(prekeys, dict):
            for prekey_id in prekey_ids:
                prekeys.pop(prekey_id, None)
        return metadata

    def _set_group_backup(
        self,
        metadata: dict[str, Any],
        group_id: str,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        group_secrets = metadata.get("group_secrets")
        if not isinstance(group_secrets, dict):
            group_secrets = {}
        group_secrets[group_id] = copy.deepcopy(entry)
        metadata["group_secrets"] = group_secrets
        return metadata

    def _remove_group_old_epochs_from_backup(
        self,
        metadata: dict[str, Any],
        group_id: str,
        removed_epochs: list[int],
    ) -> dict[str, Any]:
        group_secrets = metadata.get("group_secrets")
        if not isinstance(group_secrets, dict):
            return metadata
        entry = group_secrets.get(group_id)
        if not isinstance(entry, dict):
            return metadata
        old_epochs = entry.get("old_epochs")
        if not isinstance(old_epochs, list):
            return metadata
        entry["old_epochs"] = [
            old for old in old_epochs
            if not (isinstance(old, dict) and isinstance(old.get("epoch"), (int, float)) and int(old["epoch"]) in removed_epochs)
        ]
        return metadata

    def _protect_sessions(
        self,
        aid: str,
        sessions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        scope = self._safe_aid(aid)
        sanitized_sessions: list[dict[str, Any]] = []
        for raw in sessions:
            if not isinstance(raw, dict):
                continue
            session = copy.deepcopy(raw)
            secret_name = self._session_secret_name(session)
            value = session.pop("key", None)
            if isinstance(value, str) and value and secret_name:
                session["key_protection"] = self._secret_store.protect(
                    scope,
                    secret_name,
                    value.encode("utf-8"),
                )
            sanitized_sessions.append(session)
        return sanitized_sessions

    def _restore_sessions(
        self,
        aid: str,
        sessions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        scope = self._safe_aid(aid)
        restored_sessions: list[dict[str, Any]] = []
        for raw in sessions:
            if not isinstance(raw, dict):
                continue
            session = copy.deepcopy(raw)
            record = session.get("key_protection")
            secret_name = self._session_secret_name(session)
            if isinstance(record, dict) and secret_name:
                value = self._secret_store.reveal(scope, secret_name, record)
                if value is not None:
                    session["key"] = value.decode("utf-8")
                else:
                    session.pop("key", None)
            restored_sessions.append(session)
        return restored_sessions

    def _protect_prekeys(
        self,
        aid: str,
        prekeys: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        scope = self._safe_aid(aid)
        sanitized_prekeys: dict[str, dict[str, Any]] = {}
        for prekey_id, prekey_data in prekeys.items():
            if not isinstance(prekey_data, dict):
                continue
            prekey = copy.deepcopy(prekey_data)
            secret_name = f"e2ee_prekeys/{prekey_id}/private_key"
            value = prekey.pop("private_key_pem", None)
            if isinstance(value, str) and value:
                prekey["private_key_protection"] = self._secret_store.protect(
                    scope,
                    secret_name,
                    value.encode("utf-8"),
                )
            sanitized_prekeys[prekey_id] = prekey
        return sanitized_prekeys

    def _restore_prekeys(
        self,
        aid: str,
        prekeys: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        scope = self._safe_aid(aid)
        restored_prekeys: dict[str, dict[str, Any]] = {}
        for prekey_id, prekey_data in prekeys.items():
            if not isinstance(prekey_data, dict):
                continue
            prekey = copy.deepcopy(prekey_data)
            record = prekey.get("private_key_protection")
            secret_name = f"e2ee_prekeys/{prekey_id}/private_key"
            if isinstance(record, dict):
                value = self._secret_store.reveal(scope, secret_name, record)
                if value is not None:
                    prekey["private_key_pem"] = value.decode("utf-8")
                else:
                    prekey.pop("private_key_pem", None)
            restored_prekeys[prekey_id] = prekey
        return restored_prekeys

    def _protect_group_secrets(
        self,
        aid: str,
        group_secrets: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        scope = self._safe_aid(aid)
        sanitized_groups: dict[str, dict[str, Any]] = {}
        for group_id, group_data in group_secrets.items():
            if not isinstance(group_data, dict):
                continue
            group = copy.deepcopy(group_data)
            secret_name = f"group_secrets/{group_id}/secret"
            value = group.pop("secret", None)
            if isinstance(value, str) and value:
                group["secret_protection"] = self._secret_store.protect(
                    scope, secret_name, value.encode("utf-8"),
                )
            old_epochs = group.get("old_epochs")
            if isinstance(old_epochs, list):
                sanitized_old: list[dict[str, Any]] = []
                for old_data in old_epochs:
                    if not isinstance(old_data, dict):
                        continue
                    old = copy.deepcopy(old_data)
                    old_epoch = old.get("epoch", "?")
                    old_secret_name = f"group_secrets/{group_id}/old/{old_epoch}"
                    old_value = old.pop("secret", None)
                    if isinstance(old_value, str) and old_value:
                        old["secret_protection"] = self._secret_store.protect(
                            scope, old_secret_name, old_value.encode("utf-8"),
                        )
                    sanitized_old.append(old)
                group["old_epochs"] = sanitized_old
            sanitized_groups[group_id] = group
        return sanitized_groups

    def _restore_group_secrets(
        self,
        aid: str,
        group_secrets: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        scope = self._safe_aid(aid)
        restored_groups: dict[str, dict[str, Any]] = {}
        for group_id, group_data in group_secrets.items():
            if not isinstance(group_data, dict):
                continue
            group = copy.deepcopy(group_data)
            record = group.get("secret_protection")
            secret_name = f"group_secrets/{group_id}/secret"
            if isinstance(record, dict):
                value = self._secret_store.reveal(scope, secret_name, record)
                if value is not None:
                    group["secret"] = value.decode("utf-8")
                else:
                    group.pop("secret", None)
            old_epochs = group.get("old_epochs")
            if isinstance(old_epochs, list):
                restored_old: list[dict[str, Any]] = []
                for old_data in old_epochs:
                    if not isinstance(old_data, dict):
                        continue
                    old = copy.deepcopy(old_data)
                    old_record = old.get("secret_protection")
                    old_epoch = old.get("epoch", "?")
                    old_secret_name = f"group_secrets/{group_id}/old/{old_epoch}"
                    if isinstance(old_record, dict):
                        old_value = self._secret_store.reveal(scope, old_secret_name, old_record)
                        if old_value is not None:
                            old["secret"] = old_value.decode("utf-8")
                        else:
                            old.pop("secret", None)
                    restored_old.append(old)
                group["old_epochs"] = restored_old
            restored_groups[group_id] = group
        return restored_groups

    def _protect_metadata(self, aid: str, metadata: dict[str, Any]) -> dict[str, Any]:
        protected = copy.deepcopy(metadata)
        scope = self._safe_aid(aid)
        for field in _SENSITIVE_TOKEN_FIELDS:
            value = protected.pop(field, None)
            if isinstance(value, str) and value:
                protected[f"{field}_protection"] = self._secret_store.protect(scope, field, value.encode("utf-8"))
        sessions = protected.get("e2ee_sessions")
        if isinstance(sessions, list):
            protected["e2ee_sessions"] = self._protect_sessions(aid, sessions)

        prekeys = protected.get("e2ee_prekeys")
        if isinstance(prekeys, dict):
            protected["e2ee_prekeys"] = self._protect_prekeys(aid, prekeys)

        group_secrets = protected.get("group_secrets")
        if isinstance(group_secrets, dict):
            protected["group_secrets"] = self._protect_group_secrets(aid, group_secrets)

        return protected

    def _restore_metadata(self, aid: str, metadata: dict[str, Any]) -> dict[str, Any]:
        restored = copy.deepcopy(metadata)
        scope = self._safe_aid(aid)
        for field in _SENSITIVE_TOKEN_FIELDS:
            record = restored.get(f"{field}_protection")
            if isinstance(record, dict):
                value = self._secret_store.reveal(scope, field, record)
                if value is not None:
                    restored[field] = value.decode("utf-8")
                else:
                    restored.pop(field, None)

        sessions = restored.get("e2ee_sessions")
        if isinstance(sessions, list):
            restored["e2ee_sessions"] = self._restore_sessions(aid, sessions)

        prekeys = restored.get("e2ee_prekeys")
        if isinstance(prekeys, dict):
            restored["e2ee_prekeys"] = self._restore_prekeys(aid, prekeys)

        group_secrets = restored.get("group_secrets")
        if isinstance(group_secrets, dict):
            restored["group_secrets"] = self._restore_group_secrets(aid, group_secrets)

        return restored

    @staticmethod
    def _session_secret_name(session: dict[str, Any]) -> str | None:
        session_id = str(session.get("session_id") or "")
        if not session_id:
            return None
        return f"e2ee_sessions/{session_id}/key"

    def _restore_key_pair(self, aid: str, key_pair: dict[str, Any]) -> dict[str, Any]:
        """从 SecretStore 恢复身份私钥（如果被保护）"""
        restored = copy.deepcopy(key_pair)
        scope = self._safe_aid(aid)
        record = restored.get("private_key_protection")
        if isinstance(record, dict):
            value = self._secret_store.reveal(scope, "identity/private_key", record)
            if value is not None:
                restored["private_key_pem"] = value.decode("utf-8")
            else:
                restored.pop("private_key_pem", None)
        return restored

    def _sync_bundled_root_ca(self) -> None:
        """将 SDK 内置根证书同步到 {aun_path}/CA/root/。"""
        bundled_dir = Path(__file__).resolve().parent.parent / "certs"
        if not bundled_dir.exists():
            return
        dest_dir = self._root / "CA" / "root"
        for src in sorted(bundled_dir.glob("*.crt")):
            dest = dest_dir / src.name
            if dest.exists():
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(src.read_bytes())
            except OSError:
                pass  # 平台兼容 fallback

    @staticmethod
    def _prepare_root(preferred: Path, fallback: Path) -> Path:
        try:
            preferred.mkdir(parents=True, exist_ok=True)
            return preferred
        except Exception:
            fallback.mkdir(parents=True, exist_ok=True)
            return fallback

    def _legacy_subdir_ks(self, aid: str) -> "FileKeyStore | None":
        """返回旧格式子目录的 FileKeyStore，不存在则返回 None。
        旧版 SDK 把 aun_path 设为 ~/.aun/{aid}，数据在 ~/.aun/{aid}/AIDs/{aid}/。
        """
        subdir = self._root / self._safe_aid(aid)
        if subdir.is_dir() and (subdir / "AIDs").is_dir():
            return FileKeyStore(subdir, secret_store=self._secret_store)
        return None

    # ── 并发锁管理 ──────────────────────────────────────────

    @classmethod
    def _get_metadata_lock(cls, aid: str) -> threading.RLock:
        with cls._locks_lock:
            if aid not in cls._metadata_locks:
                cls._metadata_locks[aid] = threading.RLock()
            return cls._metadata_locks[aid]

    def _sqlite_enabled(self) -> bool:
        return bool(self._sqlite_backup and getattr(self._sqlite_backup, "_available", True))

    # ── SQLite 双写双读辅助方法 ──────────────────────────────

    def _backup_key_pair_to_sqlite(self, aid: str, path: Path) -> None:
        if self._sqlite_backup and path.exists():
            try:
                self._sqlite_backup.backup_key_pair(aid, path.read_text(encoding="utf-8"))
            except Exception as exc:
                _log.warning("key_pair SQLite 备份失败 (aid=%s): %s", aid, exc)

    def _restore_key_pair_from_sqlite(self, aid: str) -> dict | None:
        if not self._sqlite_backup:
            return None
        data = self._sqlite_backup.restore_key_pair(aid)
        if data is None:
            return None
        _log.info("从 SQLite 恢复 key_pair (aid=%s)", aid)
        try:
            key_pair = json.loads(data)
            # 写回文件系统
            path = self._key_pair_path(aid)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data, encoding="utf-8")
            _secure_file_permissions(path)
            return self._restore_key_pair(aid, key_pair)
        except Exception as exc:
            _log.warning("从 SQLite 恢复 key_pair 失败 (aid=%s): %s", aid, exc)
            return None

    def _backup_cert_to_sqlite(self, aid: str, cert_pem: str) -> None:
        if self._sqlite_backup:
            try:
                self._sqlite_backup.backup_cert(aid, cert_pem)
            except Exception as exc:
                _log.warning("cert SQLite 备份失败 (aid=%s): %s", aid, exc)

    def _restore_cert_from_sqlite(self, aid: str) -> str | None:
        if not self._sqlite_backup:
            return None
        cert = self._sqlite_backup.restore_cert(aid)
        if cert is None:
            return None
        _log.info("从 SQLite 恢复 cert (aid=%s)", aid)
        try:
            path = self._cert_path(aid)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(cert, encoding="utf-8")
            return cert
        except Exception as exc:
            _log.warning("从 SQLite 恢复 cert 失败 (aid=%s): %s", aid, exc)
            return None

    def _backup_metadata_to_sqlite(self, aid: str, path: Path) -> None:
        if self._sqlite_backup and path.exists():
            try:
                self._sqlite_backup.backup_metadata(aid, path.read_text(encoding="utf-8"))
            except Exception as exc:
                _log.warning("metadata SQLite 备份失败 (aid=%s): %s", aid, exc)

    def _restore_metadata_from_sqlite(self, aid: str) -> dict | None:
        if not self._sqlite_backup:
            return None
        data = self._sqlite_backup.restore_metadata(aid)
        if data is None:
            return None
        _log.info("从 SQLite 恢复 metadata (aid=%s)", aid)
        try:
            protected = json.loads(data)
            # 写回文件系统
            path = self._metadata_path(aid)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data, encoding="utf-8")
            _secure_file_permissions(path)
            return self._restore_metadata(aid, protected)
        except Exception as exc:
            _log.warning("从 SQLite 恢复 metadata 失败 (aid=%s): %s", aid, exc)
            return None
