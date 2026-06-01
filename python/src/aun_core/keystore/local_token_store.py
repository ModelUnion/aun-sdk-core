"""LocalTokenStore — TokenStore 的文件系统实现（SQLite + cert 文件）。

不含任何私钥操作，AuthFlow / AUNClient 持有此类型。
"""
from __future__ import annotations

import copy
import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .sqlite_db import AIDDatabase
from ._utils import safe_aid, prepare_root
from ..config import normalize_instance_id

if TYPE_CHECKING:
    from ..logger import AUNLogger, NullLogger

_METADATA_LOCKS_LIMIT = 256


class LocalTokenStore:
    """TokenStore Protocol 的文件系统实现。

    存储：
    - cert.pem → 文件系统 AIDs/{aid}/public/
    - token / seq / prekey / group secret / instance state → SQLite AIDs/{aid}/aun.db
    - 信任根 → CA/root/
    """

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        logger: "AUNLogger | NullLogger | None" = None,
    ) -> None:
        from ..logger import NullLogger as _NL
        self._log = logger or _NL()
        preferred = Path(root or Path.home() / ".aun")
        fallback = Path.cwd() / ".aun"
        self._root = prepare_root(preferred, fallback)
        self._aids_root = self._root / "AIDs"
        self._aids_root.mkdir(parents=True, exist_ok=True)

        self._aid_dbs: dict[str, AIDDatabase] = {}
        self._aid_dbs_lock = threading.Lock()
        self._metadata_locks: dict[str, threading.RLock] = {}
        self._locks_lock = threading.Lock()

        self._sync_bundled_root_ca()
        self._log.debug("keystore", "LocalTokenStore initialized: root=%s", self._root)

    # ── AIDDatabase ──────────────────────────────────────────

    def _get_db(self, aid: str) -> AIDDatabase:
        key = safe_aid(aid)
        with self._aid_dbs_lock:
            if key not in self._aid_dbs:
                db_path = self._identity_dir(aid) / "aun.db"
                self._aid_dbs[key] = AIDDatabase(db_path, logger=self._log)
            return self._aid_dbs[key]

    def close(self) -> None:
        with self._aid_dbs_lock:
            dbs = list(self._aid_dbs.values())
            self._aid_dbs.clear()
        self._log.debug("keystore", "LocalTokenStore close: closing %d AID databases", len(dbs))
        for db in dbs:
            try:
                db.close()
            except Exception as exc:
                self._log.error("keystore", "failed to close AID database: %s", exc, err=exc)

    def close_aid(self, aid: str) -> None:
        """关闭指定 AID 的 SQLite 连接（供 LocalIdentityStore.promote_pending_identity 调用）。"""
        key = safe_aid(aid)
        with self._aid_dbs_lock:
            db = self._aid_dbs.pop(key, None)
        if db is not None:
            try:
                db.close()
            except Exception as exc:
                self._log.error("keystore", "failed to close AID database for %s: %s", aid, exc, err=exc)

    # ── Cert ─────────────────────────────────────────────────

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
            return None

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

    # ── Metadata ─────────────────────────────────────────────

    def load_metadata(self, aid: str) -> dict[str, Any] | None:
        identity_dir = self._identity_dir(aid)
        if not identity_dir.exists():
            return None
        metadata: dict[str, Any] = {"aid": aid}
        cert_pem = self.load_cert(aid)
        if cert_pem:
            fp = self._fingerprint_from_cert_pem(cert_pem)
            if fp:
                metadata["cert_fingerprint"] = fp
        try:
            db = self._get_db(aid)
            kv = db.get_all_metadata()
            if kv:
                metadata["fields"] = dict(kv)
        except Exception as exc:
            self._log.error("keystore", "load_metadata failed aid=%s: %s", aid, exc, err=exc)
        return metadata

    def get_metadata_value(self, aid: str, key: str) -> str:
        db_path = self._identity_dir(aid) / "aun.db"
        if not db_path.exists():
            return ""
        try:
            raw = self._get_db(aid).get_metadata(key)
            if not raw:
                return ""
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, str):
                    return parsed.strip()
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
            return str(raw).strip()
        except Exception:
            return ""

    def set_metadata_value(self, aid: str, key: str, value: str) -> None:
        try:
            self._get_db(aid).set_metadata(key, json.dumps(value, ensure_ascii=False))
        except Exception as exc:
            self._log.debug("keystore", "set_metadata_value failed: aid=%s key=%s err=%s", aid, key, exc)

    # ── Prekeys ──────────────────────────────────────────────

    def load_e2ee_prekeys(self, aid: str, device_id: str) -> dict[str, dict[str, Any]]:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_prekeys(str(device_id or "").strip())

    def load_e2ee_prekey_by_id(self, aid: str, prekey_id: str) -> dict[str, Any] | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_prekey_by_id(prekey_id)

    def save_e2ee_prekey(self, aid: str, prekey_id: str, prekey_data: dict[str, Any], device_id: str) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            device_id = str(device_id or "").strip()
            extra = {k: v for k, v in prekey_data.items() if k not in ("private_key_pem", "created_at", "updated_at", "expires_at")}
            self._get_db(aid).save_prekey(
                prekey_id,
                prekey_data.get("private_key_pem", ""),
                device_id=device_id,
                created_at=prekey_data.get("created_at"),
                expires_at=prekey_data.get("expires_at"),
                extra_data=extra or None,
            )

    def cleanup_e2ee_prekeys(self, aid: str, cutoff_ms: int, keep_latest: int = 7, device_id: str = "") -> list[str]:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).cleanup_prekeys(cutoff_ms, keep_latest=keep_latest, device_id=str(device_id or "").strip())

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

    def store_group_secret_transition(self, aid: str, group_id: str, *, epoch: int, secret: str, commitment: str,
                                       member_aids: list[str], epoch_chain: str | None = None,
                                       pending_rotation_id: str = "", epoch_chain_unverified: bool | None = None,
                                       epoch_chain_unverified_reason: str | None = None, old_epoch_retention_ms: int) -> bool:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).store_group_secret_transition(
                group_id, epoch=epoch, secret=secret, commitment=commitment, member_aids=member_aids,
                epoch_chain=epoch_chain, pending_rotation_id=pending_rotation_id,
                epoch_chain_unverified=epoch_chain_unverified,
                epoch_chain_unverified_reason=epoch_chain_unverified_reason,
                old_epoch_retention_ms=old_epoch_retention_ms,
            )

    def store_group_secret_epoch(self, aid: str, group_id: str, *, epoch: int, secret: str, commitment: str,
                                  member_aids: list[str], epoch_chain: str | None = None,
                                  pending_rotation_id: str = "", epoch_chain_unverified: bool | None = None,
                                  epoch_chain_unverified_reason: str | None = None, old_epoch_retention_ms: int) -> bool:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).store_group_secret_epoch(
                group_id, epoch=epoch, secret=secret, commitment=commitment, member_aids=member_aids,
                epoch_chain=epoch_chain, pending_rotation_id=pending_rotation_id,
                epoch_chain_unverified=epoch_chain_unverified,
                epoch_chain_unverified_reason=epoch_chain_unverified_reason,
                old_epoch_retention_ms=old_epoch_retention_ms,
            )

    def discard_pending_group_secret_state(self, aid: str, group_id: str, epoch: int, rotation_id: str) -> bool:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).discard_pending_group_secret_state(group_id, epoch, rotation_id)

    def save_group_state(self, aid: str, **kwargs) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            self._get_db(aid).save_group_state(**kwargs)

    def load_group_state(self, aid: str, group_id: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_group_state(group_id)

    # ── Instance State ───────────────────────────────────────

    def load_instance_state(self, aid: str, device_id: str, slot_id: str = "") -> dict[str, Any] | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            return self._get_db(aid).load_instance_state(device_id, slot_id)

    def save_instance_state(self, aid: str, device_id: str, slot_id: str, state: dict[str, Any]) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            self._get_db(aid).save_instance_state(device_id, slot_id, state)

    def update_instance_state(self, aid: str, device_id: str, slot_id: str,
                               updater: Callable[[dict[str, Any]], dict[str, Any] | None]) -> dict[str, Any]:
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

    # ── Seq ──────────────────────────────────────────────────

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

    def delete_seq(self, aid: str, device_id: str, slot_id: str, namespace: str) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            self._get_db(aid).delete_seq(device_id, slot_id, namespace)

    # ── 信任根 ───────────────────────────────────────────────

    def trust_root_dir(self) -> Path:
        path = self._root / "CA" / "root"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def trust_root_bundle_path(self) -> Path:
        return self.trust_root_dir() / "trust-roots.pem"

    def save_trust_roots(self, trust_list: dict[str, Any], root_certs: list[dict[str, str]]) -> Path:
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
            json.dumps(trust_list, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8",
        )
        return bundle_path

    def save_issuer_root_cert(self, issuer: str, cert_pem: str, fingerprint_sha256: str = "") -> tuple[Path, Path]:
        import hashlib as _hl
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
            key = self._fingerprint_from_cert_pem(pem) or _hl.sha256(pem.encode("utf-8")).hexdigest()
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

    # ── 路径辅助 ─────────────────────────────────────────────

    def _identity_dir(self, aid: str) -> Path:
        return self._aids_root / safe_aid(aid)

    def _cert_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "public" / "cert.pem"

    def _cert_version_path(self, aid: str, cert_fingerprint: str) -> Path:
        return self._identity_dir(aid) / "public" / "certs" / f"{cert_fingerprint.replace(':', '_')}.pem"

    # ── 并发锁 ───────────────────────────────────────────────

    def _get_metadata_lock(self, aid: str) -> threading.RLock:
        with self._locks_lock:
            if aid not in self._metadata_locks:
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
                self._log.warn("keystore", "sync root cert failed (src=%s, dest=%s): %s", src, dest, exc)

    # ── 静态辅助 ─────────────────────────────────────────────

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
    def _fingerprint_from_cert_pem(cert_pem: str) -> str:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except Exception:
            return ""
        return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()

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
