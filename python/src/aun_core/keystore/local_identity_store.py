"""LocalIdentityStore — KeyStore 的实现（文件系统 + SQLite）。

身份存储独立实现：
- private/key.json  → 私钥（加密）
- public/cert.pem   → 证书
- CA/root/          → 信任根证书
- _pending/         → 原子注册临时目录
- aun.db            → metadata KV（gateway_url 等）
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from ._utils import safe_aid, prepare_root, protect_field, reveal_field, write_key_json_atomic, next_versioned_backup_path
from .sqlite_db import AIDDatabase

if TYPE_CHECKING:
    from ..logger import AUNLogger, NullLogger

_METADATA_LOCKS_LIMIT = 256


class LocalIdentityStore:
    """KeyStore Protocol 的实现（文件系统 + SQLite，完全独立）。"""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        encryption_seed: str | None = None,
        logger: "AUNLogger | NullLogger | None" = None,
    ) -> None:
        from ..logger import NullLogger as _NL
        self._log = logger or _NL()
        preferred = Path(root or Path.home() / ".aun")
        fallback = Path.cwd() / ".aun"
        self._root = prepare_root(preferred, fallback)
        self._aids_root = self._root / "AIDs"
        self._aids_root.mkdir(parents=True, exist_ok=True)
        self._seed_bytes = str(encryption_seed or "").encode("utf-8")
        self._aid_dbs: dict[str, AIDDatabase] = {}
        self._aid_dbs_lock = threading.Lock()
        self._metadata_locks: dict[str, threading.RLock] = {}
        self._locks_lock = threading.Lock()
        self._sync_bundled_root_ca()
        self._log.debug("keystore", "LocalIdentityStore initialized: root=%s", self._root)

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
        for db in dbs:
            try:
                db.close()
            except Exception as exc:
                self._log.error("keystore", "failed to close AID database: %s", exc, err=exc)

    def close_aid(self, aid: str) -> None:
        key = safe_aid(aid)
        with self._aid_dbs_lock:
            db = self._aid_dbs.pop(key, None)
        if db is not None:
            try:
                db.close()
            except Exception as exc:
                self._log.error("keystore", "failed to close AID database for %s: %s", aid, exc, err=exc)

    # ── Identity ─────────────────────────────────────────────

    def load_identity(self, aid: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            key_pair = self.load_key_pair(aid)
            cert = self.load_cert(aid)
            db_path = self._identity_dir(aid) / "aun.db"
            kv = {}
            if db_path.exists():
                db = self._get_db(aid)
                kv = db.get_all_metadata()
            if key_pair is None and cert is None and not kv:
                return None
            identity: dict = {}
            for k, v in kv.items():
                try:
                    identity[k] = json.loads(v)
                except (json.JSONDecodeError, ValueError):
                    identity[k] = v
            if isinstance(key_pair, dict):
                identity.update(key_pair)
            if cert:
                identity["cert"] = cert
            identity.setdefault("aid", aid)
            return identity

    def save_identity(self, aid: str, identity: dict) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            key_pair = {k: identity[k] for k in ("private_key_pem", "public_key_der_b64", "curve") if k in identity}
            if key_pair:
                self.save_key_pair(aid, key_pair)
            cert = identity.get("cert")
            if isinstance(cert, str) and cert:
                self.save_cert(aid, cert)
            db = self._get_db(aid)
            skip = {"private_key_pem", "public_key_der_b64", "curve", "cert", "e2ee_prekeys", "group_secrets", "e2ee_sessions"}
            for k, v in identity.items():
                if k in skip:
                    continue
                db.set_metadata(k, json.dumps(v, ensure_ascii=False, separators=(",", ":")))

    def list_identities(self) -> list[str]:
        if not self._aids_root.exists():
            return []
        return [p.name for p in sorted(self._aids_root.iterdir()) if p.is_dir() and not p.name.startswith("_")]

    def load_any_identity(self) -> dict | None:
        for name in self.list_identities():
            identity = self.load_identity(name)
            if identity is not None:
                return identity
        return None

    # ── Key Pair ─────────────────────────────────────────────

    def load_key_pair(self, aid: str) -> dict | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._key_pair_path(aid)
            if not path.exists():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            return self._restore_key_pair(aid, data, path)

    def save_key_pair(self, aid: str, key_pair: dict) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            self._save_key_pair_at_path(aid, self._key_pair_path(aid), key_pair)

    # ── Cert ─────────────────────────────────────────────────

    def load_cert(self, aid: str, cert_fingerprint: str | None = None) -> str | None:
        lock = self._get_metadata_lock(aid)
        with lock:
            path = self._cert_path(aid)
            return path.read_text(encoding="utf-8") if path.exists() else None

    def save_cert(self, aid: str, cert_pem: str, cert_fingerprint: str | None = None, *, make_active: bool = True) -> None:
        lock = self._get_metadata_lock(aid)
        with lock:
            if make_active:
                path = self._cert_path(aid)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(cert_pem, encoding="utf-8")

    # ── Metadata KV（gateway_url 等）────────────────────────

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

    # ── 信任根（纯文件系统）──────────────────────────────────

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

    # ── Pending ───────────────────────────────────────────────

    def pending_identity_dir(self, aid: str) -> Path:
        nonce = os.urandom(4).hex()
        ts = int(time.time())
        path = self._pending_root() / f"{safe_aid(aid)}-{nonce}-{ts}"
        (path / "private").mkdir(parents=True, exist_ok=True)
        (path / "public").mkdir(parents=True, exist_ok=True)
        return path

    def list_pending_identity_dirs(self, aid: str) -> list[Path]:
        root = self._pending_root()
        if not root.exists():
            return []
        prefix = f"{safe_aid(aid)}-"
        candidates = [p for p in root.iterdir() if p.is_dir() and p.name.startswith(prefix)]
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return candidates

    def save_pending_key_pair(self, pending_dir: str | Path, aid: str, key_pair: dict) -> None:
        pending_path = self._clean_pending_path(pending_dir)
        lock = self._get_metadata_lock(aid)
        with lock:
            self._save_key_pair_at_path(aid, pending_path / "private" / "key.json", key_pair)

    def load_pending_key_pair(self, pending_dir: str | Path, aid: str) -> dict | None:
        pending_path = self._clean_pending_path(pending_dir)
        key_path = pending_path / "private" / "key.json"
        if not key_path.exists():
            return None
        try:
            data = json.loads(key_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return self._restore_key_pair(aid, data, key_path) if isinstance(data, dict) else None

    def save_pending_cert(self, pending_dir: str | Path, cert_pem: str) -> None:
        pending_path = self._clean_pending_path(pending_dir)
        cert_path = pending_path / "public" / "cert.pem"
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(cert_pem, encoding="utf-8")

    def promote_pending_identity(self, pending_dir: str | Path, aid: str) -> Path:
        """原子提升 pending 目录为正式身份目录。

        rename 前关闭当前 IdentityStore 持有的 SQLite 连接，避免 Windows 文件锁。
        """
        pending_path = self._clean_pending_path(pending_dir)
        self._ensure_pending_key_pair_protected(pending_path, aid)
        target = self._identity_dir(aid)
        if target.exists():
            raise FileExistsError(f"promote_pending_identity target exists: {target}")
        # 关闭本地 db 连接
        self.close_aid(aid)
        self._aids_root.mkdir(parents=True, exist_ok=True)
        pending_path.rename(target)
        return target

    def discard_pending_identity(self, pending_dir: str | Path) -> None:
        shutil.rmtree(self._clean_pending_path(pending_dir), ignore_errors=True)

    def cleanup_pending_dirs(self, max_age_ms: int = 600_000) -> int:
        root = self._pending_root()
        if not root.exists():
            return 0
        now_ms = time.time() * 1000
        removed = 0
        for path in root.iterdir():
            if not path.is_dir():
                continue
            try:
                if (now_ms - path.stat().st_mtime * 1000) >= max_age_ms:
                    shutil.rmtree(path, ignore_errors=True)
                    removed += 1
            except OSError as exc:
                self._log.warn("keystore", "cleanup pending dir failed (path=%s): %s", path, exc)
        return removed

    # ── Pending group bind 槽位 ──────────────────────────────
    # bind_group_aid 首次生成的 group_aid 密钥在 import 落盘前先暂存到此，
    # 以 group_id 为键。崩溃/重试时复用同一密钥，保证 bind 幂等（私钥加密落盘）。

    def _pending_binds_root(self) -> Path:
        return self._aids_root / "_pending_binds"

    def _pending_bind_path(self, group_id: str) -> Path:
        return self._pending_binds_root() / f"{safe_aid(str(group_id or '').strip())}.json"

    def save_pending_group_bind(self, group_id: str, key_pair: dict) -> None:
        """暂存待绑定 group_aid 密钥（私钥字段加密）。"""
        gid = str(group_id or "").strip()
        if not gid:
            raise ValueError("save_pending_group_bind requires non-empty group_id")
        lock = self._get_metadata_lock(f"_pending_bind:{gid}")
        with lock:
            self._pending_binds_root().mkdir(parents=True, exist_ok=True)
            record = {
                "group_id": gid,
                "public_key_der_b64": str(key_pair.get("public_key_der_b64") or ""),
                "curve": str(key_pair.get("curve") or "P-256"),
            }
            private_key_pem = str(key_pair.get("private_key_pem") or "")
            if not record["public_key_der_b64"] or not private_key_pem:
                raise ValueError("save_pending_group_bind requires public_key_der_b64 and private_key_pem")
            record["private_key_protection"] = protect_field(
                self._seed_bytes, safe_aid(gid), "pending_bind/private_key", private_key_pem.encode("utf-8")
            )
            write_key_json_atomic(self._pending_bind_path(gid), record, self._log)

    def load_pending_group_bind(self, group_id: str) -> dict | None:
        """读取待绑定 group_aid 密钥（解密私钥）。无则返回 None。"""
        gid = str(group_id or "").strip()
        if not gid:
            return None
        lock = self._get_metadata_lock(f"_pending_bind:{gid}")
        with lock:
            path = self._pending_bind_path(gid)
            if not path.exists():
                return None
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                self._log.warn("keystore", "load_pending_group_bind read failed (group_id=%s): %s", gid, exc)
                return None
            if not isinstance(data, dict):
                return None
            protection = data.get("private_key_protection")
            private_key_pem = None
            if isinstance(protection, dict):
                revealed = reveal_field(
                    self._seed_bytes, safe_aid(gid), "pending_bind/private_key", protection, self._log
                )
                if revealed is not None:
                    private_key_pem = revealed.decode("utf-8")
            if not private_key_pem or not data.get("public_key_der_b64"):
                return None
            return {
                "group_id": gid,
                "public_key_der_b64": str(data.get("public_key_der_b64") or ""),
                "private_key_pem": private_key_pem,
                "curve": str(data.get("curve") or "P-256"),
            }

    def clear_pending_group_bind(self, group_id: str) -> None:
        gid = str(group_id or "").strip()
        if not gid:
            return
        lock = self._get_metadata_lock(f"_pending_bind:{gid}")
        with lock:
            try:
                self._pending_bind_path(gid).unlink(missing_ok=True)
            except OSError as exc:
                self._log.warn("keystore", "clear_pending_group_bind failed (group_id=%s): %s", gid, exc)

    # ── Seed 迁移 ────────────────────────────────────────────

    def change_seed(self, old_seed: str, new_seed: str) -> Any:
        from .seed_migration import change_seed
        self.close()
        return change_seed(self._root, old_seed, new_seed, logger=self._log)

    @staticmethod
    def ChangeSeed(aun_path: str | Path, old_seed: str, new_seed: str) -> Any:
        from .seed_migration import change_seed
        return change_seed(aun_path, old_seed, new_seed)

    # ── 私有辅助 ─────────────────────────────────────────────

    def _save_key_pair_at_path(self, aid: str, path: Path, key_pair: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        protected = copy.deepcopy(key_pair)
        private_key_pem = protected.pop("private_key_pem", None)
        if isinstance(private_key_pem, str) and private_key_pem:
            protected["private_key_protection"] = protect_field(
                self._seed_bytes, safe_aid(aid), "identity/private_key", private_key_pem.encode("utf-8")
            )
        # 覆盖已有 key.json 前备份（.v1/.v2 递增）
        if path.exists():
            bak = next_versioned_backup_path(path)
            try:
                bak.write_bytes(path.read_bytes())
            except OSError as exc:
                self._log.warn("keystore", "key.json backup failed (path=%s): %s", path, exc)
        write_key_json_atomic(path, protected, self._log)

    def _restore_key_pair(self, aid: str, key_pair: dict, persist_path: Path | None = None) -> dict:
        restored = copy.deepcopy(key_pair)
        record = restored.get("private_key_protection")
        if isinstance(record, dict):
            value = reveal_field(self._seed_bytes, safe_aid(aid), "identity/private_key", record, self._log)
            if value is None:
                raise ValueError(f"private key decrypt failed for aid {aid}: seed_password mismatch or key.json corrupted")
            restored["private_key_pem"] = value.decode("utf-8")
            return restored
        if persist_path is not None and isinstance(restored.get("private_key_pem"), str) and restored["private_key_pem"]:
            self._save_key_pair_at_path(aid, persist_path, restored)
        return restored

    def _ensure_pending_key_pair_protected(self, pending_path: Path, aid: str) -> None:
        key_path = pending_path / "private" / "key.json"
        if not key_path.exists():
            raise FileNotFoundError(f"pending identity missing key pair for {aid}")
        data = json.loads(key_path.read_text(encoding="utf-8"))
        if isinstance(data.get("private_key_pem"), str) and data["private_key_pem"]:
            raise ValueError(f"pending identity private key is plaintext for {aid}")
        if not isinstance(data.get("private_key_protection"), dict):
            raise ValueError(f"pending identity private key is not encrypted for {aid}")

    def _identity_dir(self, aid: str) -> Path:
        return self._aids_root / safe_aid(aid)

    def _key_pair_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "private" / "key.json"

    def _cert_path(self, aid: str) -> Path:
        return self._identity_dir(aid) / "public" / "cert.pem"

    def _pending_root(self) -> Path:
        return self._aids_root / "_pending"

    def _clean_pending_path(self, pending_dir: str | Path) -> Path:
        root = self._pending_root().resolve(strict=False)
        path = Path(pending_dir).resolve(strict=False)
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"pending dir outside pending root: {pending_dir}") from exc
        return path

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

    @staticmethod
    def _fingerprint_from_cert_pem(cert_pem: str) -> str:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
        except Exception:
            return ""

    @staticmethod
    def _split_pem_bundle(bundle_text: str) -> list[str]:
        marker = "-----END CERTIFICATE-----"
        certs: list[str] = []
        for part in bundle_text.split(marker):
            part = part.strip()
            if part:
                certs.append(f"{part}\n{marker}\n")
        return certs

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
