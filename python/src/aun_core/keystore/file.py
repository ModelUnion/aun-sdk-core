from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

from .base import KeyStore
from ..secret_store import SecretStore, create_default_secret_store


_SENSITIVE_TOKEN_FIELDS = ("access_token", "refresh_token", "kite_token")


class FileKeyStore(KeyStore):
    def __init__(self, root: str | Path | None = None, *, secret_store: SecretStore | None = None) -> None:
        preferred = Path(root or Path.home() / ".aun")
        fallback = Path.cwd() / ".aun"
        resolved_root = self._prepare_root(preferred, fallback)
        self._secret_store = secret_store or create_default_secret_store()
        if resolved_root.name == "keys":
            self._root = resolved_root.parent
            self._legacy_roots = [resolved_root, self._root / "keys"]
        else:
            self._root = resolved_root
            self._legacy_roots = [self._root / "keys", self._root]
        self._aids_root = self._root / "AIDs"
        self._aids_root.mkdir(parents=True, exist_ok=True)

    def load_identity(self, aid: str) -> dict | None:
        identity = self._load_identity_from_split_files(aid)
        if identity is not None:
            return identity
        path = self._identity_path(aid)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_identity(self, aid: str, identity: dict) -> None:
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
        metadata = {
            key: value
            for key, value in identity.items()
            if key not in {"private_key_pem", "public_key_der_b64", "curve", "cert"}
        }
        self.save_metadata(aid, metadata)

    def delete_identity(self, aid: str) -> None:
        self.delete_key_pair(aid)
        cert_path = self._cert_path(aid)
        if cert_path.exists():
            cert_path.unlink()
        meta_path = self._metadata_path(aid)
        if meta_path.exists():
            meta_path.unlink()
        identity_dir = self._identity_dir(aid)
        if identity_dir.exists():
            shutil.rmtree(identity_dir, ignore_errors=True)
        for legacy_root in self._legacy_roots:
            self._delete_legacy_identity_files(legacy_root, aid)

    def load_key_pair(self, aid: str) -> dict | None:
        path = self._key_pair_path(aid)
        if path.exists():
            key_pair = json.loads(path.read_text(encoding="utf-8"))
            return self._restore_key_pair(aid, key_pair)
        legacy_key_path = self._load_legacy_split_file(aid, ".key.json")
        if legacy_key_path is not None:
            key_pair = json.loads(legacy_key_path.read_text(encoding="utf-8"))
            return self._restore_key_pair(aid, key_pair)
        identity = self._load_legacy_identity(aid)
        if identity is None:
            return None
        key_pair = {
            key: identity[key]
            for key in ("private_key_pem", "public_key_der_b64", "curve")
            if key in identity
        }
        return key_pair or None

    def save_key_pair(self, aid: str, key_pair: dict) -> None:
        path = self._key_pair_path(aid)
        path.parent.mkdir(parents=True, exist_ok=True)

        # 保护私钥
        protected_key_pair = copy.deepcopy(key_pair)
        scope = self._safe_aid(aid)
        private_key_pem = protected_key_pair.pop("private_key_pem", None)
        if isinstance(private_key_pem, str) and private_key_pem:
            protected_key_pair["private_key_protection"] = self._secret_store.protect(
                scope,
                "identity/private_key",
                private_key_pem.encode("utf-8"),
            )
        elif "private_key_protection" not in protected_key_pair:
            self._secret_store.clear(scope, "identity/private_key")

        path.write_text(json.dumps(protected_key_pair, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_cert(self, aid: str) -> str | None:
        path = self._cert_path(aid)
        if path.exists():
            return path.read_text(encoding="utf-8")
        legacy_cert_path = self._load_legacy_split_file(aid, ".cert.pem")
        if legacy_cert_path is not None:
            return legacy_cert_path.read_text(encoding="utf-8")
        identity = self._load_legacy_identity(aid)
        cert = identity.get("cert") if identity else None
        return cert if isinstance(cert, str) and cert else None

    def save_cert(self, aid: str, cert_pem: str) -> None:
        path = self._cert_path(aid)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cert_pem, encoding="utf-8")

    def load_metadata(self, aid: str) -> dict | None:
        path = self._metadata_path(aid)
        if path.exists():
            return self._restore_metadata(aid, json.loads(path.read_text(encoding="utf-8")))
        legacy_meta_path = self._load_legacy_split_file(aid, ".meta.json")
        if legacy_meta_path is not None:
            return self._restore_metadata(aid, json.loads(legacy_meta_path.read_text(encoding="utf-8")))
        identity = self._load_legacy_identity(aid)
        if identity is None:
            return None
        return self._restore_metadata(aid, {
            key: value
            for key, value in identity.items()
            if key not in {"private_key_pem", "public_key_der_b64", "curve", "cert"}
        })

    def save_metadata(self, aid: str, metadata: dict) -> None:
        path = self._metadata_path(aid)
        path.parent.mkdir(parents=True, exist_ok=True)
        protected = self._protect_metadata(aid, metadata)
        path.write_text(json.dumps(protected, ensure_ascii=False, indent=2), encoding="utf-8")

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

    def delete_key_pair(self, aid: str) -> None:
        path = self._key_pair_path(aid)
        if path.exists():
            path.unlink()

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
        for suffix in (".json", ".key.json", ".cert.pem", ".meta.json"):
            path = self._legacy_file_path(legacy_root, aid, suffix)
            if path.exists():
                path.unlink()

    def _protect_metadata(self, aid: str, metadata: dict[str, Any]) -> dict[str, Any]:
        protected = copy.deepcopy(metadata)
        scope = self._safe_aid(aid)
        for field in _SENSITIVE_TOKEN_FIELDS:
            value = protected.pop(field, None)
            if isinstance(value, str) and value:
                protected[f"{field}_protection"] = self._secret_store.protect(scope, field, value.encode("utf-8"))
            elif f"{field}_protection" not in protected:
                self._secret_store.clear(scope, field)

        sessions = protected.get("e2ee_sessions")
        if isinstance(sessions, list):
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
                elif secret_name and "key_protection" not in session:
                    self._secret_store.clear(scope, secret_name)
                sanitized_sessions.append(session)
            protected["e2ee_sessions"] = sanitized_sessions

        # 保护 prekey 私钥
        prekeys = protected.get("e2ee_prekeys")
        if isinstance(prekeys, dict):
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
                elif "private_key_protection" not in prekey:
                    self._secret_store.clear(scope, secret_name)
                sanitized_prekeys[prekey_id] = prekey
            protected["e2ee_prekeys"] = sanitized_prekeys

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
            for raw in sessions:
                if not isinstance(raw, dict):
                    continue
                record = raw.get("key_protection")
                secret_name = self._session_secret_name(raw)
                if isinstance(record, dict) and secret_name:
                    value = self._secret_store.reveal(scope, secret_name, record)
                    if value is not None:
                        raw["key"] = value.decode("utf-8")
                    else:
                        raw.pop("key", None)

        # 恢复 prekey 私钥
        prekeys = restored.get("e2ee_prekeys")
        if isinstance(prekeys, dict):
            for prekey_id, prekey_data in prekeys.items():
                if not isinstance(prekey_data, dict):
                    continue
                record = prekey_data.get("private_key_protection")
                secret_name = f"e2ee_prekeys/{prekey_id}/private_key"
                if isinstance(record, dict):
                    value = self._secret_store.reveal(scope, secret_name, record)
                    if value is not None:
                        prekey_data["private_key_pem"] = value.decode("utf-8")
                    else:
                        prekey_data.pop("private_key_pem", None)

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

    @staticmethod
    def _prepare_root(preferred: Path, fallback: Path) -> Path:
        try:
            preferred.mkdir(parents=True, exist_ok=True)
            return preferred
        except Exception:
            fallback.mkdir(parents=True, exist_ok=True)
            return fallback
