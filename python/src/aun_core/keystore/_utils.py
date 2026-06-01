"""keystore 私有工具函数 — 加密、路径辅助，供 LocalTokenStore / LocalIdentityStore 共用。"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from ..logger import AUNLogger, NullLogger

# ── 路径辅助 ─────────────────────────────────────────────────


def safe_aid(aid: str) -> str:
    return aid.replace("/", "_").replace("\\", "_").replace(":", "_")


def prepare_root(preferred: Path, fallback: Path) -> Path:
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        return preferred
    except OSError as exc:
        print(
            f"[keystore] preferred root mkdir failed ({preferred}): {exc}; falling back to {fallback}",
            file=sys.stderr,
            flush=True,
        )
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def secure_file_permissions(path: Path, logger: "AUNLogger | NullLogger | None" = None) -> None:
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            if logger:
                logger.warn("keystore", "chmod 0600 failed (path=%s): %s", path, exc)


def write_key_json_atomic(path: Path, data: dict[str, Any], logger: "AUNLogger | NullLogger | None" = None) -> None:
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}-{time.time_ns()}")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        secure_file_permissions(tmp, logger)
        os.replace(tmp, path)
        secure_file_permissions(path, logger)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# ── key.json 加密（与旧 SecretStore file_aes scheme 完全兼容）────────────────


def derive_master_key(seed_bytes: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", seed_bytes, b"aun_file_secret_store_v1", 100_000)


def derive_field_key(master_key: bytes, scope: str, name: str) -> bytes:
    if ":" in scope or ":" in name:
        raise ValueError(f"scope/name 不能包含 ':'（scope={scope!r}, name={name!r}）")
    msg = f"aun:{scope}:{name}\x01".encode("utf-8")
    return hmac.new(master_key, msg, hashlib.sha256).digest()


def protect_field(seed_bytes: bytes, scope: str, name: str, plaintext: bytes) -> dict:
    master_key = derive_master_key(seed_bytes)
    field_key = derive_field_key(master_key, scope, name)
    nonce = os.urandom(12)
    aesgcm = AESGCM(field_key)
    ct_tag = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "scheme": "file_aes",
        "name": name,
        "persisted": True,
        "nonce": nonce.hex(),
        "ciphertext": ct_tag[:-16].hex(),
        "tag": ct_tag[-16:].hex(),
    }


def decode_field_bytes(value: str) -> bytes:
    import base64
    try:
        return bytes.fromhex(value)
    except ValueError:
        return base64.b64decode(value)


def reveal_field(seed_bytes: bytes, scope: str, name: str, record: dict, logger=None) -> bytes | None:
    scheme = record.get("scheme")
    if scheme not in ("file_aes", "file_secret_store"):
        return None
    try:
        master_key = derive_master_key(seed_bytes)
        field_key = derive_field_key(master_key, scope, name)
        nonce = decode_field_bytes(record["nonce"])
        ciphertext = decode_field_bytes(record["ciphertext"])
        tag = decode_field_bytes(record["tag"])
        aesgcm = AESGCM(field_key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception as exc:
        if logger:
            logger.error("keystore", "decrypt field failed (scope=%s, name=%s): %s", scope, name, exc, err=exc)
        return None
