from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_PBKDF2_SALT = b"aun_file_secret_store_v1"
_PBKDF2_ITERATIONS = 100_000
_PRIVATE_KEY_NAME = "identity/private_key"


class SeedMigrationError(RuntimeError):
    pass


@dataclass(slots=True)
class SeedMigrationResult:
    migrated: int = 0
    skipped: int = 0
    errors: int = 0
    seed_files_processed: int = 0
    seed_files_renamed: int = 0
    private_keys_verified: int = 0
    private_keys_migrated: int = 0
    active_seed: bytes | None = field(default=None, repr=False)


@dataclass(slots=True)
class _PrivateKeyMigration:
    aid: str
    path: Path
    plaintext: bytes


def derive_master_key(seed_bytes: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", seed_bytes, _PBKDF2_SALT, _PBKDF2_ITERATIONS)


def derive_field_key(master_key: bytes, scope: str, name: str) -> bytes:
    if ":" in scope or ":" in name:
        raise ValueError(f"scope/name 不能包含 ':'（scope={scope!r}, name={name!r}）")
    msg = f"aun:{scope}:{name}\x01".encode("utf-8")
    return hmac.new(master_key, msg, hashlib.sha256).digest()


def decode_secret_part(value: str) -> bytes:
    text = str(value or "")
    if len(text) % 2 == 0 and text and all(ch in "0123456789abcdefABCDEF" for ch in text):
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    return base64.b64decode(text, validate=True)


def decrypt_record(master_key: bytes, scope: str, name: str, record: dict[str, Any]) -> bytes | None:
    if record.get("scheme") != "file_aes":
        return None
    if str(record.get("name") or name) != name:
        return None
    try:
        field_key = derive_field_key(master_key, scope, name)
        nonce = decode_secret_part(str(record.get("nonce") or ""))
        ciphertext = decode_secret_part(str(record.get("ciphertext") or ""))
        tag = decode_secret_part(str(record.get("tag") or ""))
        return AESGCM(field_key).decrypt(nonce, ciphertext + tag, None)
    except Exception:
        return None


def encrypt_record(seed_bytes: bytes, scope: str, name: str, plaintext: bytes) -> dict[str, Any]:
    master_key = derive_master_key(seed_bytes)
    return _encrypt_record_with_master(master_key, scope, name, plaintext)


def change_seed(
    aun_path: str | Path,
    old_seed: str,
    new_seed: str,
    *,
    logger: Any = None,
    emit: Callable[[str], None] | None = None,
) -> SeedMigrationResult:
    root = Path(aun_path).expanduser()
    old_seed_bytes, rename_path = _resolve_old_seed(root, old_seed)
    return _change_seed_bytes(
        root,
        old_seed_bytes,
        str(new_seed).encode("utf-8"),
        rename_seed_path=rename_path,
        logger=logger,
        emit=emit,
    )


def ChangeSeed(
    aun_path: str | Path,
    old_seed: str,
    new_seed: str,
    *,
    logger: Any = None,
    emit: Callable[[str], None] | None = None,
) -> SeedMigrationResult:
    return change_seed(aun_path, old_seed, new_seed, logger=logger, emit=emit)


def migrate_seed_materials(
    aun_path: str | Path,
    seed_password: str,
    *,
    logger: Any = None,
    emit: Callable[[str], None] | None = None,
) -> SeedMigrationResult:
    """自动迁移旧 seed；失败时保留旧数据并告诉调用方继续用旧 seed。"""
    root = Path(aun_path).expanduser()
    new_seed = str(seed_password).encode("utf-8")
    seed_path = root / ".seed"

    if seed_path.exists():
        try:
            result = change_seed(root, ".seed", seed_password, logger=logger, emit=emit)
            result.active_seed = new_seed
            return result
        except Exception as exc:
            result = SeedMigrationResult(errors=1)
            try:
                old_seed = seed_path.read_bytes()
            except OSError:
                old_seed = b""
            result.active_seed = old_seed or new_seed
            _emit(logger, emit, "warn", "seed migration failed; continuing with legacy .seed: %s", exc)
            return result

    for migrated in sorted(root.glob(".seed.migrated.*")):
        if not migrated.is_file():
            continue
        try:
            old_seed = migrated.read_bytes()
            if not old_seed:
                continue
            result = _change_seed_bytes(
                root,
                old_seed,
                new_seed,
                rename_seed_path=None,
                logger=logger,
                emit=emit,
            )
            result.seed_files_processed += 1
            result.active_seed = new_seed
            return result
        except Exception as exc:
            _emit(logger, emit, "debug", "migrated seed replay skipped: file=%s err=%s", migrated.name, exc)

    _emit(logger, emit, "debug", "seed migration skipped: no usable .seed files under %s", root)
    return SeedMigrationResult(active_seed=new_seed)


def _change_seed_bytes(
    root: Path,
    old_seed: bytes,
    new_seed: bytes,
    *,
    rename_seed_path: Path | None,
    logger: Any = None,
    emit: Callable[[str], None] | None = None,
) -> SeedMigrationResult:
    if old_seed is None:
        raise SeedMigrationError("seed migration refused: old seed is missing")
    old_master = derive_master_key(old_seed)
    new_master = derive_master_key(new_seed)
    migrations = _verify_private_keys(root, old_master)

    result = SeedMigrationResult(
        seed_files_processed=1 if rename_seed_path is not None else 0,
        private_keys_verified=len(migrations),
    )
    if hmac.compare_digest(old_master, new_master):
        if rename_seed_path is not None:
            result.seed_files_renamed = _rename_seed_file(rename_seed_path)
        result.active_seed = new_seed
        return result

    for item in migrations:
        _rewrite_key_json(item, new_seed, new_master)
        result.private_keys_migrated += 1
        result.migrated += 1

    db_m, db_s, db_e = _migrate_all_aun_dbs(root, old_master, new_seed, new_master)
    result.migrated += db_m
    result.skipped += db_s
    result.errors += db_e
    if result.errors:
        raise SeedMigrationError(f"seed migration failed while migrating database fields: errors={result.errors}")

    if rename_seed_path is not None:
        result.seed_files_renamed = _rename_seed_file(rename_seed_path)

    result.active_seed = new_seed
    _emit(
        logger,
        emit,
        "info",
        "seed migration complete: migrated=%d skipped=%d private_keys=%d renamed=%d",
        result.migrated,
        result.skipped,
        result.private_keys_migrated,
        result.seed_files_renamed,
    )
    return result


def _resolve_old_seed(root: Path, old_seed: str) -> tuple[bytes, Path | None]:
    if old_seed != ".seed":
        return str(old_seed).encode("utf-8"), None
    seed_path = root / ".seed"
    try:
        data = seed_path.read_bytes()
    except OSError as exc:
        raise SeedMigrationError(f"read .seed failed: {exc}") from exc
    if not data:
        raise SeedMigrationError("seed migration refused: .seed is empty")
    return data, seed_path


def _verify_private_keys(root: Path, old_master: bytes) -> list[_PrivateKeyMigration]:
    aids_root = root / "AIDs"
    if not aids_root.exists():
        raise SeedMigrationError("seed migration refused: AIDs directory not found")

    migrations: list[_PrivateKeyMigration] = []
    for aid_dir in sorted(p for p in aids_root.iterdir() if p.is_dir() and not p.name.startswith("_")):
        aid = aid_dir.name
        path = aid_dir / "private" / "key.json"
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SeedMigrationError(f"seed migration refused: invalid key.json for {aid}: {exc}") from exc
        if not isinstance(data, dict):
            raise SeedMigrationError(f"seed migration refused: key.json is not an object for {aid}")
        record = data.get("private_key_protection")
        if record is None:
            continue
        if not isinstance(record, dict) or record.get("scheme") != "file_aes":
            continue
        if str(record.get("name") or _PRIVATE_KEY_NAME) != _PRIVATE_KEY_NAME:
            raise SeedMigrationError(f"seed migration refused: unexpected private key record name for {aid}")
        plaintext = decrypt_record(old_master, aid, _PRIVATE_KEY_NAME, record)
        if plaintext is None:
            raise SeedMigrationError(f"seed migration refused: private key is not encrypted by old seed: aid={aid}")
        migrations.append(_PrivateKeyMigration(aid=aid, path=path, plaintext=plaintext))

    if not migrations:
        raise SeedMigrationError("seed migration refused: no encrypted private key verified with old seed")
    return migrations


def _rewrite_key_json(item: _PrivateKeyMigration, new_seed: bytes, new_master: bytes) -> None:
    try:
        data = json.loads(item.path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SeedMigrationError(f"read key.json failed after verification: aid={item.aid}: {exc}") from exc
    if not isinstance(data, dict):
        raise SeedMigrationError(f"key.json changed during migration: aid={item.aid}")
    record = encrypt_record(new_seed, item.aid, _PRIVATE_KEY_NAME, item.plaintext)
    verified = decrypt_record(new_master, item.aid, _PRIVATE_KEY_NAME, record)
    if verified != item.plaintext:
        raise SeedMigrationError(f"new seed verification failed for private key: aid={item.aid}")
    data["private_key_protection"] = record
    _write_json_atomic(item.path, data)


def _migrate_all_aun_dbs(root: Path, old_master: bytes, new_seed: bytes, new_master: bytes) -> tuple[int, int, int]:
    aids_root = root / "AIDs"
    if not aids_root.exists():
        return 0, 0, 0
    migrated = 0
    skipped = 0
    errors = 0
    for aid_dir in sorted(p for p in aids_root.iterdir() if p.is_dir() and not p.name.startswith("_")):
        db_m, db_s, db_e = _migrate_aun_db(aid_dir / "aun.db", aid_dir.name, old_master, new_seed, new_master)
        migrated += db_m
        skipped += db_s
        errors += db_e
    return migrated, skipped, errors


def _migrate_aun_db(path: Path, scope: str, old_master: bytes, new_seed: bytes, new_master: bytes) -> tuple[int, int, int]:
    if not path.is_file():
        return 0, 0, 0

    specs: list[tuple[str, str, str, Callable[[tuple[Any, ...]], str]]] = [
        ("prekeys", "prekey_id, device_id", "private_key_enc", lambda row: f"prekey/{row[0]}"),
        ("group_current", "group_id", "secret_enc", lambda row: f"group/{row[0]}/current"),
        ("group_old_epochs", "group_id, epoch", "secret_enc", lambda row: f"group/{row[0]}/epoch/{int(row[1])}"),
        ("e2ee_sessions", "session_id", "data_enc", lambda row: f"session/{row[0]}"),
        ("v2_spk", "spk_id", "private_key_enc", lambda row: f"v2/spk/{row[0]}"),
    ]
    migrated = 0
    skipped = 0
    errors = 0
    try:
        conn = sqlite3.connect(str(path), timeout=5.0)
        conn.execute("PRAGMA busy_timeout = 5000")
    except Exception:
        return 0, 0, 1
    try:
        for table, key_cols, enc_col, name_fn in specs:
            try:
                rows = conn.execute(f"SELECT {key_cols}, {enc_col} FROM {table}").fetchall()
            except sqlite3.Error:
                continue
            key_col_list = [col.strip() for col in key_cols.split(",")]
            where = " AND ".join(f"{col} = ?" for col in key_col_list)
            for row in rows:
                key_values = tuple(row[:-1])
                stored = row[-1]
                if not stored:
                    skipped += 1
                    continue
                try:
                    record = json.loads(stored) if isinstance(stored, str) else stored
                except Exception:
                    skipped += 1
                    continue
                if not isinstance(record, dict) or record.get("scheme") != "file_aes":
                    skipped += 1
                    continue
                name = name_fn(key_values)
                plaintext = decrypt_record(old_master, scope, name, record)
                if plaintext is None:
                    skipped += 1
                    continue
                new_record = encrypt_record(new_seed, scope, name, plaintext)
                if decrypt_record(new_master, scope, name, new_record) != plaintext:
                    errors += 1
                    continue
                rewritten = json.dumps(new_record, ensure_ascii=False, separators=(",", ":"))
                try:
                    conn.execute(f"UPDATE {table} SET {enc_col} = ? WHERE {where}", (rewritten, *key_values))
                    migrated += 1
                except sqlite3.Error:
                    errors += 1
        conn.commit()
    except Exception:
        errors += 1
    finally:
        conn.close()
    return migrated, skipped, errors


def _encrypt_record_with_master(master_key: bytes, scope: str, name: str, plaintext: bytes) -> dict[str, Any]:
    field_key = derive_field_key(master_key, scope, name)
    nonce = os.urandom(12)
    sealed = AESGCM(field_key).encrypt(nonce, plaintext, None)
    return {
        "scheme": "file_aes",
        "name": name,
        "persisted": True,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(sealed[:-16]).decode("ascii"),
        "tag": base64.b64encode(sealed[-16:]).decode("ascii"),
    }


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise SeedMigrationError(f"write key.json failed: {path}: {exc}") from exc


def _rename_seed_file(seed_path: Path) -> int:
    ts = int(time.time())
    target = seed_path.with_name(f"{seed_path.name}.migrated.{ts}")
    index = 0
    while target.exists():
        index += 1
        target = seed_path.with_name(f"{seed_path.name}.migrated.{ts}.{index}")
    try:
        seed_path.rename(target)
        return 1
    except OSError:
        return 0


def _emit(logger: Any, emit: Callable[[str], None] | None, level: str, message: str, *args: Any) -> None:
    text = message % args if args else message
    if emit is not None:
        emit(text)
    if logger is None:
        return
    fn = getattr(logger, level, None)
    if callable(fn):
        try:
            fn("keystore", message, *args)
        except TypeError:
            fn(text)
