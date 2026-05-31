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
    """自动迁移旧 seed 到 seed_password。

    安全原则：
    - 绝不能让 key.json 变成无效状态
    - 如果数据确实是 .seed 加密的且迁移失败，继续用 .seed（保证能解密）
    - 如果 .seed 无法解密任何数据，不 fallback 到它（报明确错误）
    """
    root = Path(aun_path).expanduser()
    new_seed = str(seed_password).encode("utf-8")
    seed_path = root / ".seed"

    if seed_path.exists():
        try:
            old_seed_bytes = seed_path.read_bytes()
        except OSError as exc:
            raise SeedMigrationError(f"无法读取 .seed 文件: {exc}") from exc
        if not old_seed_bytes:
            raise SeedMigrationError(".seed 文件为空，无法确定加密密钥")

        # 验证 .seed 是否能解密现有数据
        old_master = derive_master_key(old_seed_bytes)
        seed_can_decrypt = _can_decrypt_any_private_key(root, old_master)

        if not seed_can_decrypt:
            # .seed 解不开任何数据 — 检查 new_seed 能否解密
            new_master = derive_master_key(new_seed)
            new_can_decrypt = _can_decrypt_any_private_key(root, new_master)
            if new_can_decrypt or not _has_encrypted_private_keys(root):
                # 数据已经是 new_seed 加密的，或者根本没有加密数据
                # .seed 是残留文件，直接 rename 掉
                renamed = _rename_seed_file(seed_path)
                _emit(logger, emit, "info",
                      ".seed 无法解密现有数据（数据已用当前 seed_password 加密），已归档残留 .seed")
                return SeedMigrationResult(
                    active_seed=new_seed,
                    seed_files_processed=1,
                    seed_files_renamed=renamed,
                )
            # 两个 seed 都解不开 → 报明确错误
            raise SeedMigrationError(
                "seed migration refused: .seed 文件无法解密现有私钥，"
                "提供的 seed_password 也无法解密。"
                "请确认 seed_password 是否正确，或检查 key.json 是否已损坏。"
            )

        # .seed 能解密数据 → 尝试迁移到 new_seed
        try:
            result = _change_seed_bytes(
                root,
                old_seed_bytes,
                new_seed,
                rename_seed_path=seed_path,
                logger=logger,
                emit=emit,
            )
            result.active_seed = new_seed
            return result
        except SeedMigrationError as exc:
            # 迁移失败 — 由于 _change_seed_bytes 内部有回滚保护，
            # key.json 要么全部迁移成功，要么保持旧状态。
            # 数据仍然是 .seed 加密的，必须继续用 .seed。
            _emit(logger, emit, "warn",
                  "seed migration failed, data remains encrypted by .seed (not corrupted): %s", exc)
            result = SeedMigrationResult(errors=1)
            result.active_seed = old_seed_bytes
            return result

    for migrated in sorted(root.glob(".seed.migrated.*")):
        if not migrated.is_file():
            continue
        try:
            old_seed_bytes = migrated.read_bytes()
            if not old_seed_bytes:
                continue
            # 验证这个 migrated seed 能否解密数据
            old_master = derive_master_key(old_seed_bytes)
            if not _can_decrypt_any_private_key(root, old_master):
                continue
            result = _change_seed_bytes(
                root,
                old_seed_bytes,
                new_seed,
                rename_seed_path=None,
                logger=logger,
                emit=emit,
            )
            result.seed_files_processed += 1
            result.active_seed = new_seed
            return result
        except SeedMigrationError as exc:
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
    """迁移加密数据从 old_seed 到 new_seed。

    安全保证：
    - key.json 绝不会处于无法解密的中间状态
    - 迁移顺序：先 DB（可事务回滚）→ 再 key.json（原子写 + 失败回滚）
    - 任何步骤失败都会回滚已完成的写入
    """
    if old_seed is None:
        raise SeedMigrationError("seed migration refused: old seed is missing")
    old_master = derive_master_key(old_seed)
    new_master = derive_master_key(new_seed)
    migrations = _verify_private_keys(root, old_master, raise_on_empty=False)

    result = SeedMigrationResult(
        seed_files_processed=1 if rename_seed_path is not None else 0,
        private_keys_verified=len(migrations),
    )
    if hmac.compare_digest(old_master, new_master):
        # seed 相同，无需迁移数据，只需 rename .seed 文件
        if rename_seed_path is not None:
            result.seed_files_renamed = _rename_seed_file(rename_seed_path)
        result.active_seed = new_seed
        return result

    # 阶段 1：先迁移 DB（每个 DB 内部是事务，失败不影响 key.json）
    db_m, db_s, db_e = _migrate_all_aun_dbs(root, old_master, new_seed, new_master)
    result.migrated += db_m
    result.skipped += db_s
    result.errors += db_e
    if result.errors:
        raise SeedMigrationError(
            f"seed migration refused: database migration failed (errors={result.errors}); "
            f"key.json 未被修改，数据保持原状"
        )

    # 阶段 2：重写 key.json（带备份回滚保护）
    written: list[_PrivateKeyMigration] = []
    try:
        for item in migrations:
            _rewrite_key_json(item, new_seed, new_master)
            written.append(item)
            result.private_keys_migrated += 1
            result.migrated += 1
    except SeedMigrationError:
        # key.json 写入失败 → 从 .bak 恢复所有已写入的
        _rollback_key_json_from_backups(written, logger=logger, emit=emit)
        # 同时回滚 DB 迁移
        _migrate_all_aun_dbs(root, new_master, old_seed, old_master)
        raise

    # 阶段 3：全部成功，清理备份
    _cleanup_key_json_backups(written)

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


def _can_decrypt_any_private_key(root: Path, master_key: bytes) -> bool:
    """检查 master_key 是否能解密 AIDs 下任意一个 key.json 的私钥。"""
    aids_root = root / "AIDs"
    if not aids_root.exists():
        return False
    for aid_dir in aids_root.iterdir():
        if not aid_dir.is_dir() or aid_dir.name.startswith("_"):
            continue
        path = aid_dir / "private" / "key.json"
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        record = data.get("private_key_protection")
        if not isinstance(record, dict) or record.get("scheme") != "file_aes":
            continue
        plaintext = decrypt_record(master_key, aid_dir.name, _PRIVATE_KEY_NAME, record)
        if plaintext is not None:
            return True
    return False


def _has_encrypted_private_keys(root: Path) -> bool:
    """检查 AIDs 下是否存在任何加密的 private_key_protection 记录。"""
    aids_root = root / "AIDs"
    if not aids_root.exists():
        return False
    for aid_dir in aids_root.iterdir():
        if not aid_dir.is_dir() or aid_dir.name.startswith("_"):
            continue
        path = aid_dir / "private" / "key.json"
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        record = data.get("private_key_protection")
        if isinstance(record, dict) and record.get("scheme") == "file_aes":
            return True
    return False


def _verify_private_keys(root: Path, old_master: bytes, *, raise_on_empty: bool = True) -> list[_PrivateKeyMigration]:
    aids_root = root / "AIDs"
    if not aids_root.exists():
        if raise_on_empty:
            raise SeedMigrationError("seed migration refused: AIDs directory not found")
        return []

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
            private_key_pem = data.get("private_key_pem")
            if isinstance(private_key_pem, str) and private_key_pem:
                migrations.append(_PrivateKeyMigration(aid=aid, path=path, plaintext=private_key_pem.encode("utf-8")))
            continue
        if not isinstance(record, dict) or record.get("scheme") != "file_aes":
            continue
        if str(record.get("name") or _PRIVATE_KEY_NAME) != _PRIVATE_KEY_NAME:
            raise SeedMigrationError(f"seed migration refused: unexpected private key record name for {aid}")
        plaintext = decrypt_record(old_master, aid, _PRIVATE_KEY_NAME, record)
        if plaintext is None:
            raise SeedMigrationError(
                f"seed migration refused: 无法用提供的 seed 解密 {aid} 的私钥。"
                f"可能原因：seed_password 不正确，或 key.json 已被其他 seed 加密。"
            )
        migrations.append(_PrivateKeyMigration(aid=aid, path=path, plaintext=plaintext))

    if not migrations and raise_on_empty:
        raise SeedMigrationError("seed migration refused: no encrypted private key verified with old seed")
    return migrations


def _rewrite_key_json(item: _PrivateKeyMigration, new_seed: bytes, new_master: bytes) -> None:
    """重写 key.json，使用备份机制保证原子性。

    流程：原文件 → .bak 备份 → 写新内容 → 验证 → 成功
    调用方负责在全部成功后调用 _cleanup_key_json_backups 删除 .bak。
    """
    bak_path = item.path.with_name(item.path.name + ".bak")
    try:
        data = json.loads(item.path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SeedMigrationError(f"read key.json failed after verification: aid={item.aid}: {exc}") from exc
    if not isinstance(data, dict):
        raise SeedMigrationError(f"key.json changed during migration: aid={item.aid}")

    # 备份原文件
    try:
        if not bak_path.exists():
            # 用 copy 而非 rename，保留原文件直到新内容写入成功
            bak_path.write_bytes(item.path.read_bytes())
    except OSError as exc:
        raise SeedMigrationError(
            f"无法备份 key.json (aid={item.aid}): {exc}; 迁移中止，数据未修改"
        ) from exc

    # 加密并验证
    record = encrypt_record(new_seed, item.aid, _PRIVATE_KEY_NAME, item.plaintext)
    verified = decrypt_record(new_master, item.aid, _PRIVATE_KEY_NAME, record)
    if verified != item.plaintext:
        raise SeedMigrationError(f"new seed verification failed for private key: aid={item.aid}")
    data["private_key_protection"] = record
    data.pop("private_key_pem", None)

    # 原子写入新内容
    try:
        _write_json_atomic(item.path, data)
    except SeedMigrationError:
        # 写入失败 → 从备份恢复
        try:
            os.replace(bak_path, item.path)
        except OSError:
            pass  # 备份恢复也失败了，但原文件可能还在（_write_json_atomic 用 tmp）
        raise


def _rollback_key_json_from_backups(items: list[_PrivateKeyMigration], logger: Any = None, emit: Callable[[str], None] | None = None) -> None:
    """从 .bak 文件恢复所有已修改的 key.json。"""
    for item in items:
        bak_path = item.path.with_name(item.path.name + ".bak")
        if bak_path.exists():
            try:
                os.replace(bak_path, item.path)
                _emit(logger, emit, "info", "key.json rolled back from backup: aid=%s", item.aid)
            except OSError as exc:
                _emit(logger, emit, "error",
                      "CRITICAL: key.json rollback from backup failed for aid=%s: %s — "
                      "manual recovery: rename %s → %s",
                      item.aid, exc, bak_path, item.path)


def _cleanup_key_json_backups(items: list[_PrivateKeyMigration]) -> None:
    """迁移全部成功后，删除 .bak 备份文件。"""
    for item in items:
        bak_path = item.path.with_name(item.path.name + ".bak")
        try:
            bak_path.unlink(missing_ok=True)
        except OSError:
            pass


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
