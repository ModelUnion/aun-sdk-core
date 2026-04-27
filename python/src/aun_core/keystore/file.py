from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base import KeyStore
from .sqlite_db import AIDDatabase, derive_sqlite_key, load_or_create_seed
from ..config import normalize_instance_id

import logging

_log = logging.getLogger("aun_core.keystore")

_STRUCTURED_PREKEY_MIN_KEEP_COUNT = 7


def _secure_file_permissions(path: Path) -> None:
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            _log.warning("设置文件权限 0o600 失败 (path=%s): %s", path, exc)


def _prekey_created_marker(record: dict[str, Any]) -> int:
    for key in ("created_at", "updated_at", "expires_at"):
        marker = record.get(key)
        if isinstance(marker, (int, float)):
            return int(marker)
    return 0


def _latest_prekey_ids(prekeys: dict[str, dict[str, Any]], keep_latest: int) -> set[str]:
    if keep_latest <= 0:
        return set()
    ordered = sorted(
        ((pid, _prekey_created_marker(d)) for pid, d in prekeys.items() if isinstance(d, dict)),
        key=lambda x: (x[1], x[0]),
        reverse=True,
    )
    return {pid for pid, _ in ordered[:keep_latest]}


# ── key.json 内联加密（与旧 SecretStore file_aes scheme 完全兼容）──────────────


def _derive_field_key(master_key: bytes, scope: str, name: str) -> bytes:
    """派生字段级加密密钥，与旧 SecretStore 格式完全一致。"""
    # 防御性校验：scope/name 不能包含分隔符 ':'，避免域混淆
    if ':' in scope or ':' in name:
        raise ValueError(f"scope/name 不能包含 ':'（scope={scope!r}, name={name!r}）")
    msg = f"aun:{scope}:{name}\x01".encode("utf-8")
    return hmac.new(master_key, msg, hashlib.sha256).digest()


def _derive_master_key(seed_bytes: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", seed_bytes, b"aun_file_secret_store_v1", 100_000)


def _protect_field(seed_bytes: bytes, scope: str, name: str, plaintext: bytes) -> dict:
    master_key = _derive_master_key(seed_bytes)
    field_key = _derive_field_key(master_key, scope, name)
    nonce = os.urandom(12)
    aesgcm = AESGCM(field_key)
    ct_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_tag[:-16]
    tag = ct_tag[-16:]
    return {
        "scheme": "file_aes",
        "name": name,
        "persisted": True,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }


def _decode_field_bytes(value: str) -> bytes:
    """兼容旧 base64 和新 hex 两种编码格式。"""
    import base64
    try:
        return bytes.fromhex(value)
    except ValueError:
        return base64.b64decode(value)


def _reveal_field(seed_bytes: bytes, scope: str, name: str, record: dict) -> bytes | None:
    scheme = record.get("scheme")
    if scheme not in ("file_aes", "file_secret_store"):
        return None
    try:
        master_key = _derive_master_key(seed_bytes)
        field_key = _derive_field_key(master_key, scope, name)
        nonce = _decode_field_bytes(record["nonce"])
        ciphertext = _decode_field_bytes(record["ciphertext"])
        tag = _decode_field_bytes(record["tag"])
        aesgcm = AESGCM(field_key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception as exc:
        _log.warning("解密字段失败 (scope=%s, name=%s): %s", scope, name, exc)
        return None


_METADATA_LOCKS_LIMIT = 256

class FileKeyStore(KeyStore):

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        encryption_seed: str | None = None,
    ) -> None:
        preferred = Path(root or Path.home() / ".aun")
        fallback = Path.cwd() / ".aun"
        resolved_root = self._prepare_root(preferred, fallback)

        if resolved_root.name == "keys":
            self._root = resolved_root.parent
            self._legacy_roots = [resolved_root, self._root / "keys"]
        else:
            self._root = resolved_root
            self._legacy_roots = [self._root / "keys", self._root]

        self._aids_root = self._root / "AIDs"
        self._aids_root.mkdir(parents=True, exist_ok=True)

        self._seed_bytes = load_or_create_seed(self._root, encryption_seed=encryption_seed)
        self._sqlite_key = derive_sqlite_key(self._seed_bytes)

        # 每 AID 一个 AIDDatabase，lazy 初始化
        self._aid_dbs: dict[str, AIDDatabase] = {}
        self._aid_dbs_lock = threading.Lock()

        # 实例级别的元数据锁（不同 aun_path 的实例互不竞争）
        self._metadata_locks: dict[str, threading.RLock] = {}
        self._locks_lock = threading.Lock()

        self._sync_bundled_root_ca()

    # ── AIDDatabase 访问 ─────────────────────────────────────

    def _get_db(self, aid: str) -> AIDDatabase:
        safe = self._safe_aid(aid)
        with self._aid_dbs_lock:
            if safe not in self._aid_dbs:
                db_path = self._identity_dir(aid) / "aun.db"
                self._aid_dbs[safe] = AIDDatabase(db_path, self._sqlite_key)
            return self._aid_dbs[safe]

    # ── 公共 API ─────────────────────────────────────────────

    def load_identity(self, aid: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            identity = self._load_identity_from_split_files(aid)
            if identity is not None:
                identity.setdefault("aid", aid)
                return identity
            # 兼容旧格式整体 identity.json
            path = self._identity_path(aid)
            if path.exists():
                identity = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(identity, dict):
                    identity.setdefault("aid", aid)
                return identity
            # 兼容旧格式子目录
            legacy_subdir = self._root / self._safe_aid(aid)
            if legacy_subdir.is_dir():
                lks = FileKeyStore(legacy_subdir, encryption_seed=None)
                lks._seed_bytes = self._seed_bytes
                lks._sqlite_key = self._sqlite_key
                identity = lks._load_identity_from_split_files(aid)
                if isinstance(identity, dict):
                    identity.setdefault("aid", aid)
                return identity
            return None

    def save_identity(self, aid: str, identity: dict) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            key_pair = {k: identity[k] for k in ("private_key_pem", "public_key_der_b64", "curve") if k in identity}
            if key_pair:
                self.save_key_pair(aid, key_pair)
            cert = identity.get("cert")
            if isinstance(cert, str) and cert:
                self.save_cert(aid, cert)
            # 直接写入 tokens + KV
            db = self._get_db(aid)
            token_fields = {"access_token", "refresh_token", "kite_token"}
            skip = token_fields | {"private_key_pem", "public_key_der_b64", "curve", "cert", "e2ee_prekeys", "group_secrets", "e2ee_sessions"}
            for field in token_fields:
                if field not in identity:
                    continue
                value = identity.get(field)
                if isinstance(value, str) and value:
                    db.set_token(field, value)
                else:
                    db.delete_token(field)
            for k, v in identity.items():
                if k in skip:
                    continue
                db.set_metadata(k, json.dumps(v, ensure_ascii=False, separators=(",", ":")))

    def load_key_pair(self, aid: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._key_pair_path(aid)
            if path.exists():
                key_pair = json.loads(path.read_text(encoding="utf-8"))
                return self._restore_key_pair(aid, key_pair)
            # 旧格式 fallback
            legacy_path = self._load_legacy_split_file(aid, ".key.json")
            if legacy_path is not None:
                key_pair = json.loads(legacy_path.read_text(encoding="utf-8"))
                return self._restore_key_pair(aid, key_pair)
            identity = self._load_legacy_identity(aid)
            if identity is not None:
                return {k: identity[k] for k in ("private_key_pem", "public_key_der_b64", "curve") if k in identity} or None
            return None

    def save_key_pair(self, aid: str, key_pair: dict) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._key_pair_path(aid)
            path.parent.mkdir(parents=True, exist_ok=True)
            protected = copy.deepcopy(key_pair)
            private_key_pem = protected.pop("private_key_pem", None)
            if isinstance(private_key_pem, str) and private_key_pem:
                scope = self._safe_aid(aid)
                protection = _protect_field(self._seed_bytes, scope, "identity/private_key", private_key_pem.encode("utf-8"))
                protected["private_key_protection"] = protection
            path.write_text(json.dumps(protected, ensure_ascii=False, indent=2), encoding="utf-8")
            _secure_file_permissions(path)

    def load_cert(self, aid: str, cert_fingerprint: str | None = None) -> str | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            normalized_fp = self._normalize_cert_fingerprint(cert_fingerprint)
            if normalized_fp:
                version_path = self._cert_version_path(aid, normalized_fp)
                if version_path.exists():
                    return version_path.read_text(encoding="utf-8")
                path = self._cert_path(aid)
                if path.exists():
                    cert = path.read_text(encoding="utf-8")
                    if self._fingerprint_from_cert_pem(cert) == normalized_fp:
                        return cert
                return None
            path = self._cert_path(aid)
            if path.exists():
                return path.read_text(encoding="utf-8")
            legacy_path = self._load_legacy_split_file(aid, ".cert.pem")
            if legacy_path is not None:
                return legacy_path.read_text(encoding="utf-8")
            identity = self._load_legacy_identity(aid)
            cert = identity.get("cert") if identity else None
            return cert if isinstance(cert, str) and cert else None

    def save_cert(self, aid: str, cert_pem: str, cert_fingerprint: str | None = None, *, make_active: bool = True) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            normalized_fp = self._normalize_cert_fingerprint(cert_fingerprint) or self._fingerprint_from_cert_pem(cert_pem)
            if normalized_fp:
                version_path = self._cert_version_path(aid, normalized_fp)
                version_path.parent.mkdir(parents=True, exist_ok=True)
                version_path.write_text(cert_pem, encoding="utf-8")
            if make_active:
                path = self._cert_path(aid)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(cert_pem, encoding="utf-8")

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
            for path in legacy_root.glob("*.key.json"):
                candidates.add(path.name.removesuffix(".key.json"))
            for path in legacy_root.glob("*.cert.pem"):
                candidates.add(path.name.removesuffix(".cert.pem"))
            for path in legacy_root.glob("*.json"):
                name = path.name
                if name.endswith(".key.json"):
                    continue
                candidates.add(name.removesuffix(".json"))
        for aid in sorted(candidates):
            identity = self.load_identity(aid)
            if identity is not None:
                return identity
        return None

    def list_identities(self) -> list[str]:
        """遍历 AIDs 目录，返回所有已存储的 AID 名称列表。"""
        result: list[str] = []
        if self._aids_root.exists():
            for path in sorted(self._aids_root.iterdir()):
                if path.is_dir():
                    result.append(path.name)
        return result

    def load_metadata(self, aid: str) -> dict[str, Any] | None:
        """返回指定 AID 的元数据摘要（证书指纹、创建时间等），不含私钥。"""
        identity_dir = self._identity_dir(aid)
        if not identity_dir.exists():
            return None
        metadata: dict[str, Any] = {"aid": aid}
        # 证书指纹
        cert_pem = self.load_cert(aid)
        if cert_pem:
            fp = self._fingerprint_from_cert_pem(cert_pem)
            if fp:
                metadata["cert_fingerprint"] = fp
        # 从 DB 读取 KV 元数据（不含 token 等敏感信息）
        try:
            db = self._get_db(aid)
            kv = db.get_all_metadata()
            if kv:
                metadata["fields"] = dict(kv)
        except Exception as exc:
            _log.warning("加载 %s 元数据失败: %s", aid, exc)
        return metadata

    # ── Prekeys ──────────────────────────────────────────────

    def load_e2ee_prekeys(self, aid: str, device_id: str) -> dict[str, dict[str, Any]]:
        lock = self._get_metadata_lock(aid)
        with lock:
            device_id = str(device_id or "").strip()
            return self._get_db(aid).load_prekeys(device_id)

    def save_e2ee_prekey(self, aid: str, prekey_id: str, prekey_data: dict[str, Any], device_id: str) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            device_id = str(device_id or "").strip()
            db = self._get_db(aid)
            extra = {k: v for k, v in prekey_data.items() if k not in ("private_key_pem", "created_at", "updated_at", "expires_at")}
            db.save_prekey(
                prekey_id,
                prekey_data.get("private_key_pem", ""),
                device_id=device_id,
                created_at=prekey_data.get("created_at"),
                expires_at=prekey_data.get("expires_at"),
                extra_data=extra or None,
            )

    def cleanup_e2ee_prekeys(self, aid: str, cutoff_ms: int, keep_latest: int = _STRUCTURED_PREKEY_MIN_KEEP_COUNT, device_id: str = "") -> list[str]:
        lock = self._get_metadata_lock(aid)
        with lock:
            device_id = str(device_id or "").strip()
            return self._get_db(aid).cleanup_prekeys(cutoff_ms, keep_latest=keep_latest, device_id=device_id)

    # ── Group Secrets ────────────────────────────────────────

    def list_group_secret_ids(self, aid: str) -> list[str]:
        lock = self._get_metadata_lock(aid)
        with lock:
            db = self._get_db(aid)
            ids = set(db.load_all_group_current().keys())
            ids.update(db.load_all_group_ids_with_old_epochs())
            return sorted(ids)

    def cleanup_group_old_epochs_state(self, aid: str, group_id: str, cutoff_ms: int) -> int:
        lock = self._get_metadata_lock(aid)
        with lock:
            db = self._get_db(aid)
            old_epochs = db.load_group_old_epochs(group_id)
            if not old_epochs:
                return 0
            to_delete: list[int] = []
            for old in old_epochs:
                marker = old.get("updated_at") or 0
                if isinstance(marker, (int, float)) and int(marker) <= cutoff_ms:
                    epoch = old.get("epoch")
                    if isinstance(epoch, (int, float)):
                        to_delete.append(int(epoch))
            if to_delete:
                conn = db._get_conn()
                placeholders = ",".join("?" for _ in to_delete)
                conn.execute(
                    f"DELETE FROM group_old_epochs WHERE group_id = ? AND epoch IN ({placeholders})",
                    [group_id, *to_delete],
                )
                conn.commit()
            return len(to_delete)

    def load_group_secret_epoch(self, aid: str, group_id: str, epoch: int | None = None) -> dict[str, Any] | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_group_secret_epoch(group_id, epoch)

    def load_group_secret_epochs(self, aid: str, group_id: str) -> list[dict[str, Any]]:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_group_secret_epochs(group_id)

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
    ) -> bool:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).store_group_secret_transition(
                group_id,
                epoch=epoch,
                secret=secret,
                commitment=commitment,
                member_aids=member_aids,
                epoch_chain=epoch_chain,
                pending_rotation_id=pending_rotation_id,
                epoch_chain_unverified=epoch_chain_unverified,
                epoch_chain_unverified_reason=epoch_chain_unverified_reason,
                old_epoch_retention_ms=old_epoch_retention_ms,
            )

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
    ) -> bool:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).store_group_secret_epoch(
                group_id,
                epoch=epoch,
                secret=secret,
                commitment=commitment,
                member_aids=member_aids,
                epoch_chain=epoch_chain,
                pending_rotation_id=pending_rotation_id,
                epoch_chain_unverified=epoch_chain_unverified,
                epoch_chain_unverified_reason=epoch_chain_unverified_reason,
                old_epoch_retention_ms=old_epoch_retention_ms,
            )

    def discard_pending_group_secret_state(self, aid: str, group_id: str, epoch: int, rotation_id: str) -> bool:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).discard_pending_group_secret_state(group_id, epoch, rotation_id)

    # ── Instance State ───────────────────────────────────────

    def load_instance_state(self, aid: str, device_id: str, slot_id: str = "") -> dict[str, Any] | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_instance_state(device_id, slot_id)

    def save_instance_state(self, aid: str, device_id: str, slot_id: str, state: dict[str, Any]) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            self._get_db(aid).save_instance_state(device_id, slot_id, state)

    def update_instance_state(self, aid: str, device_id: str, slot_id: str, updater: Callable[[dict[str, Any]], dict[str, Any] | None]) -> dict[str, Any]:
        lock = self._get_metadata_lock(aid)
        with lock:
            current = self._get_db(aid).load_instance_state(device_id, slot_id) or {}
            working = copy.deepcopy(current)
            updated = updater(working)
            if updated is None:
                updated = working
            if not isinstance(updated, dict):
                raise TypeError("update_instance_state updater must return dict | None")
            self._get_db(aid).save_instance_state(device_id, slot_id, updated)
            return copy.deepcopy(updated)

    # ── Seq Tracker ───────────────────────────────────────────

    def save_seq(self, aid: str, device_id: str, slot_id: str, namespace: str, contiguous_seq: int) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            self._get_db(aid).save_seq(device_id, slot_id, namespace, contiguous_seq)

    def load_seq(self, aid: str, device_id: str, slot_id: str, namespace: str) -> int:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_seq(device_id, slot_id, namespace)

    def load_all_seqs(self, aid: str, device_id: str, slot_id: str) -> dict[str, int]:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_all_seqs(device_id, slot_id)

    # ── key.json 解密 ────────────────────────────────────────

    def _restore_key_pair(self, aid: str, key_pair: dict[str, Any]) -> dict[str, Any]:
        restored = copy.deepcopy(key_pair)
        scope = self._safe_aid(aid)
        record = restored.get("private_key_protection")
        if isinstance(record, dict):
            value = _reveal_field(self._seed_bytes, scope, "identity/private_key", record)
            if value is not None:
                restored["private_key_pem"] = value.decode("utf-8")
            else:
                restored.pop("private_key_pem", None)
        return restored

    # ── 路径辅助 ─────────────────────────────────────────────

    def _identity_dir(self, aid: str) -> Path:
        return self._aids_root / self._safe_aid(aid)

    def _key_pair_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "private" / "key.json"

    def _cert_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "public" / "cert.pem"

    def _cert_version_path(self, aid: str, cert_fingerprint: str) -> Path:
        return self._identity_dir(aid) / "public" / "certs" / f"{self._safe_cert_fingerprint(cert_fingerprint)}.pem"

    def _identity_path(self, aid: str) -> Path:
        return self._legacy_file_path(self._root, aid, ".json")

    def _legacy_file_path(self, legacy_root: Path, aid: str, suffix: str) -> Path:
        return legacy_root / f"{self._safe_aid(aid)}{suffix}"

    def _load_legacy_split_file(self, aid: str, suffix: str) -> Path | None:
        for legacy_root in self._legacy_roots:
            path = self._legacy_file_path(legacy_root, aid, suffix)
            if path.exists():
                return path
        return None

    def _load_legacy_identity(self, aid: str) -> dict | None:
        for legacy_root in self._legacy_roots:
            path = self._legacy_file_path(legacy_root, aid, ".json")
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        return None

    def _load_identity_from_split_files(self, aid: str) -> dict | None:
        key_pair = self.load_key_pair(aid)
        cert = self.load_cert(aid)
        # 直接从 DB 读取 tokens + KV
        db = self._get_db(aid)
        tokens = db.get_all_tokens()
        kv = db.get_all_metadata()
        has_meta = bool(tokens or kv)
        if key_pair is None and cert is None and not has_meta:
            return None
        identity: dict = {}
        for k, v in kv.items():
            try:
                identity[k] = json.loads(v)
            except (json.JSONDecodeError, ValueError):
                identity[k] = v
        identity.update(tokens)
        if isinstance(key_pair, dict):
            identity.update(key_pair)
        if cert:
            identity["cert"] = cert
        # key/cert 公钥一致性校验：防止 cert.pem 被意外覆盖导致签名验证失败
        if isinstance(key_pair, dict) and cert:
            try:
                local_pub_b64 = key_pair.get("public_key_der_b64", "")
                if local_pub_b64:
                    import base64 as _b64
                    cert_obj = x509.load_pem_x509_certificate(cert.encode("utf-8"))
                    cert_pub_der = cert_obj.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    local_pub_der = _b64.b64decode(local_pub_b64)
                    if cert_pub_der != local_pub_der:
                        import base64
                        cert_pub_b64 = base64.b64encode(cert_pub_der).decode()[:20]
                        local_pub_b64_short = local_pub_b64[:20]
                        _log.error(
                            "身份 %s 的 key.json 公钥与 cert.pem 公钥不匹配！"
                            "key.json=%s... cert.pem=%s... "
                            "cert.pem 可能被 peer 证书覆盖，将忽略损坏的 cert.pem",
                            aid, local_pub_b64_short, cert_pub_b64,
                        )
                        # 丢弃损坏的 cert，以 key_pair 为准（后续登录会重新获取正确证书）
                        del identity["cert"]
            except Exception as exc:
                _log.warning("身份 %s key/cert 一致性校验异常: %s", aid, exc)
        return identity

    # ── 静态辅助 ─────────────────────────────────────────────

    @staticmethod
    def _safe_aid(aid: str) -> str:
        return aid.replace("/", "_").replace("\\", "_").replace(":", "_")

    @staticmethod
    def _safe_instance_component(value: str, field: str, *, allow_empty: bool = False) -> str:
        return normalize_instance_id(value, field, allow_empty=allow_empty)

    @staticmethod
    def _normalize_cert_fingerprint(cert_fingerprint: str | None) -> str:
        value = str(cert_fingerprint or "").strip().lower()
        if not value or not value.startswith("sha256:"):
            return ""
        hex_part = value[7:]
        if len(hex_part) != 64 or any(ch not in "0123456789abcdef" for ch in hex_part):
            return ""
        return value

    @staticmethod
    def _safe_cert_fingerprint(cert_fingerprint: str) -> str:
        return cert_fingerprint.replace(":", "_")

    @staticmethod
    def _fingerprint_from_cert_pem(cert_pem: str) -> str:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except Exception:
            return ""
        return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()

    # ── 并发锁 ───────────────────────────────────────────────

    def _get_metadata_lock(self, aid: str) -> threading.RLock:
        with self._locks_lock:
            if aid not in self._metadata_locks:
                # 超过上限时，清理真正空闲的锁（非当前线程持有 ≠ 无人持有，
                # 须用 acquire(blocking=False) 确认无任何线程持有后再淘汰）
                if len(self._metadata_locks) >= _METADATA_LOCKS_LIMIT:
                    to_remove = []
                    for k, v in self._metadata_locks.items():
                        if v.acquire(blocking=False):
                            v.release()
                            to_remove.append(k)
                    for k in to_remove[:len(self._metadata_locks) - _METADATA_LOCKS_LIMIT + 1]:
                        del self._metadata_locks[k]
                self._metadata_locks[aid] = threading.RLock()
            return self._metadata_locks[aid]

    # ── 根证书同步 ───────────────────────────────────────────

    def _sync_bundled_root_ca(self) -> None:
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
            except OSError as exc:
                _log.warning("同步根证书失败 (src=%s, dest=%s): %s", src, dest, exc)

    def trust_root_dir(self) -> Path:
        """返回本地信任根证书目录。"""
        path = self._root / "CA" / "root"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def trust_root_bundle_path(self) -> Path:
        """返回动态导入的信任根证书 bundle 路径。"""
        return self.trust_root_dir() / "trust-roots.pem"

    def save_trust_roots(self, trust_list: dict[str, Any], root_certs: list[dict[str, str]]) -> Path:
        """保存已通过管理局签名校验的信任根列表和 PEM bundle。"""
        dest_dir = self.trust_root_dir()
        bundle_parts: list[str] = []
        for index, item in enumerate(root_certs):
            cert_pem = str(item.get("cert_pem") or "").strip()
            if not cert_pem:
                continue
            cert_id = str(item.get("id") or item.get("fingerprint_sha256") or f"root-{index + 1}").strip()
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", cert_id)[:120] or f"root-{index + 1}"
            (dest_dir / f"{safe_name}.crt").write_text(cert_pem + "\n", encoding="utf-8")
            bundle_parts.append(cert_pem + "\n")
        bundle_path = self.trust_root_bundle_path()
        bundle_path.write_text("".join(bundle_parts), encoding="utf-8")
        (dest_dir / "trust-roots.json").write_text(
            json.dumps(trust_list, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        return bundle_path

    def save_issuer_root_cert(self, issuer: str, cert_pem: str, fingerprint_sha256: str = "") -> tuple[Path, Path]:
        """保存指定 issuer 发布的 Root CA 证书，并合并进动态 trust-roots bundle。"""
        dest_dir = self.trust_root_dir()
        issuer_dir = dest_dir / "issuers"
        issuer_dir.mkdir(parents=True, exist_ok=True)
        safe_issuer = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(issuer or "").strip())[:120] or "issuer"
        cert_path = issuer_dir / f"{safe_issuer}.root.crt"
        normalized_pem = cert_pem.strip() + "\n"
        cert_path.write_text(normalized_pem, encoding="utf-8")

        bundle_path = self.trust_root_bundle_path()
        bundle_parts: list[str] = []
        if bundle_path.exists():
            try:
                bundle_parts.extend(self._split_pem_bundle(bundle_path.read_text(encoding="utf-8")))
            except OSError:
                pass
        bundle_parts.append(normalized_pem)

        deduped: list[str] = []
        seen: set[str] = set()
        for pem in bundle_parts:
            key = self._fingerprint_from_cert_pem(pem) or hashlib.sha256(pem.encode("utf-8")).hexdigest()
            if fingerprint_sha256:
                normalized_fp = fingerprint_sha256.lower().removeprefix("sha256:")
                if key.endswith(normalized_fp):
                    key = f"sha256:{normalized_fp}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(pem.strip() + "\n")
        bundle_path.write_text("".join(deduped), encoding="utf-8")
        return cert_path, bundle_path

    @staticmethod
    def _split_pem_bundle(bundle_text: str) -> list[str]:
        marker = "-----END CERTIFICATE-----"
        certs: list[str] = []
        for part in bundle_text.split(marker):
            part = part.strip()
            if not part:
                continue
            certs.append(f"{part}\n{marker}\n")
        return certs

    @staticmethod
    def _prepare_root(preferred: Path, fallback: Path) -> Path:
        try:
            preferred.mkdir(parents=True, exist_ok=True)
            return preferred
        except OSError as exc:
            _log.warning("无法创建首选目录 %s: %s，使用 fallback %s", preferred, exc, fallback)
            fallback.mkdir(parents=True, exist_ok=True)
            return fallback
