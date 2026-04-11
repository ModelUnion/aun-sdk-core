"""基于文件的 SecretStore（AES-256-GCM 加密）。

密钥派生：
  - 传入 encryption_seed → 从 seed 字符串派生
  - 未传 → 从 {root}/.seed 文件派生（首次自动生成）
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import sys
from pathlib import Path
from typing import Any

_log = logging.getLogger("aun_core.secret_store")


class FileSecretStore:
    def __init__(self, root: Path, *, encryption_seed: str | None = None, sqlite_backup: Any = None) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)
        self._sqlite_backup = sqlite_backup
        if encryption_seed:
            seed_bytes = encryption_seed.encode("utf-8")
        else:
            seed_bytes = self._load_or_create_seed()
        self._master_key = hashlib.pbkdf2_hmac(
            "sha256", seed_bytes, b"aun_file_secret_store_v1", iterations=100_000,
        )

    def protect(self, scope: str, name: str, plaintext: bytes) -> dict[str, Any]:
        key = self._derive_key(scope, name)
        nonce = os.urandom(12)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
        return {
            "scheme": "file_aes",
            "name": name,
            "persisted": True,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ct_tag[:-16]).decode("ascii"),
            "tag": base64.b64encode(ct_tag[-16:]).decode("ascii"),
        }

    def reveal(self, scope: str, name: str, record: dict[str, Any]) -> bytes | None:
        if record.get("scheme") != "file_aes":
            return None
        if str(record.get("name") or "") != name:
            return None
        nonce_b64 = record.get("nonce", "")
        ct_b64 = record.get("ciphertext", "")
        tag_b64 = record.get("tag", "")
        if not all([nonce_b64, ct_b64, tag_b64]):
            return None
        key = self._derive_key(scope, name)
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(key).decrypt(
                base64.b64decode(nonce_b64),
                base64.b64decode(ct_b64) + base64.b64decode(tag_b64),
                None,
            )
        except Exception:
            return None

    def _derive_key(self, scope: str, name: str) -> bytes:
        import hmac
        return hmac.new(
            self._master_key,
            f"aun:{scope}:{name}".encode("utf-8") + b"\x01",
            hashlib.sha256,
        ).digest()

    def _load_or_create_seed(self) -> bytes:
        seed_path = self._root / ".seed"
        seed: bytes | None = None
        source = ""

        # 1. 先读文件
        if seed_path.exists():
            seed = seed_path.read_bytes()
            source = "file"

        # 2. 文件没有 → 读 SQLite
        if seed is None and self._sqlite_backup:
            seed = self._sqlite_backup.restore_seed()
            if seed is not None:
                source = "sqlite"
                # 恢复到文件系统
                seed_path.write_bytes(seed)
                if sys.platform != "win32":
                    try:
                        os.chmod(seed_path, 0o600)
                    except OSError:
                        pass

        # 3. 都没有 → 生成新 seed
        if seed is None:
            seed = os.urandom(32)
            source = "new"
            seed_path.write_bytes(seed)
            if sys.platform != "win32":
                try:
                    os.chmod(seed_path, 0o600)
                except OSError:
                    pass

        # 双写：确保 SQLite 中也有
        if self._sqlite_backup and source != "sqlite":
            self._sqlite_backup.backup_seed(seed)

        return seed
