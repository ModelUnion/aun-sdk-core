import json
import sqlite3

import pytest

from aun_core.keystore.seed_migration import (
    SeedMigrationError,
    change_seed,
    decrypt_record,
    derive_master_key,
    encrypt_record,
    migrate_seed_materials,
)


def _key_json_record(root, aid):
    path = root / "AIDs" / aid / "private" / "key.json"
    return json.loads(path.read_text(encoding="utf-8"))["private_key_protection"]


def test_change_seed_migrates_key_json_after_private_key_verification(tmp_path):
    old_seed = b"old-seed"
    new_seed = b""
    (tmp_path / ".seed").write_bytes(old_seed)

    aid = "good.agentid.pub"
    path = tmp_path / "AIDs" / aid / "private" / "key.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"private_key_protection": encrypt_record(old_seed, aid, "identity/private_key", b"GOOD_PRIVATE")}),
        encoding="utf-8",
    )

    result = change_seed(tmp_path, ".seed", "")
    assert result.migrated == 1
    assert result.private_keys_migrated == 1
    assert not (tmp_path / ".seed").exists()

    new_master = derive_master_key(new_seed)
    good = _key_json_record(tmp_path, aid)
    assert decrypt_record(new_master, aid, "identity/private_key", good) == b"GOOD_PRIVATE"


def test_change_seed_refuses_when_private_key_is_not_old_seed(tmp_path):
    old_seed = b"old-seed"
    other_seed = b"other-seed"
    (tmp_path / ".seed").write_bytes(old_seed)

    cases = {
        "good.agentid.pub": encrypt_record(old_seed, "good.agentid.pub", "identity/private_key", b"GOOD_PRIVATE"),
        "wrong-seed.agentid.pub": encrypt_record(other_seed, "wrong-seed.agentid.pub", "identity/private_key", b"WRONG_SEED"),
    }
    for aid, record in cases.items():
        path = tmp_path / "AIDs" / aid / "private" / "key.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"private_key_protection": record}), encoding="utf-8")

    with pytest.raises(SeedMigrationError):
        change_seed(tmp_path, ".seed", "")

    assert (tmp_path / ".seed").exists()
    old_master = derive_master_key(old_seed)
    other_master = derive_master_key(other_seed)
    good = _key_json_record(tmp_path, "good.agentid.pub")
    assert decrypt_record(old_master, "good.agentid.pub", "identity/private_key", good) == b"GOOD_PRIVATE"

    wrong_seed = _key_json_record(tmp_path, "wrong-seed.agentid.pub")
    assert decrypt_record(other_master, "wrong-seed.agentid.pub", "identity/private_key", wrong_seed) == b"WRONG_SEED"


def test_auto_migration_falls_back_to_legacy_seed_when_strict_verification_fails(tmp_path):
    old_seed = b"old-seed"
    other_seed = b"other-seed"
    (tmp_path / ".seed").write_bytes(old_seed)

    for aid, record in {
        "good.agentid.pub": encrypt_record(old_seed, "good.agentid.pub", "identity/private_key", b"GOOD_PRIVATE"),
        "wrong-seed.agentid.pub": encrypt_record(other_seed, "wrong-seed.agentid.pub", "identity/private_key", b"WRONG_SEED"),
    }.items():
        path = tmp_path / "AIDs" / aid / "private" / "key.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"private_key_protection": record}), encoding="utf-8")

    result = migrate_seed_materials(tmp_path, "")
    assert result.errors == 1
    assert result.active_seed == old_seed
    assert (tmp_path / ".seed").exists()


def test_seed_migration_db_columns_only_rewrite_records_decryptable_by_old_seed(tmp_path):
    old_seed = b"old-db-seed"
    new_seed = b""
    other_seed = b"other-db-seed"
    aid = "db.agentid.pub"
    (tmp_path / ".seed").write_bytes(old_seed)
    aid_dir = tmp_path / "AIDs" / aid
    aid_dir.mkdir(parents=True)
    key_path = aid_dir / "private" / "key.json"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(
        json.dumps({"private_key_protection": encrypt_record(old_seed, aid, "identity/private_key", b"PRIVATE")}),
        encoding="utf-8",
    )
    db_path = aid_dir / "aun.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "CREATE TABLE prekeys ("
            "prekey_id TEXT NOT NULL, device_id TEXT NOT NULL DEFAULT '', "
            "private_key_enc TEXT NOT NULL DEFAULT '', data TEXT NOT NULL DEFAULT '{}', "
            "created_at INTEGER, updated_at INTEGER NOT NULL, expires_at INTEGER, "
            "PRIMARY KEY (prekey_id, device_id))"
        )
        rows = [
            ("p1", json.dumps(encrypt_record(old_seed, aid, "prekey/p1", b"GOOD_PREKEY"))),
            ("p2", json.dumps(encrypt_record(old_seed, aid, "prekey/not-p2", b"WRONG_NAME_PREKEY"))),
            ("p3", json.dumps(encrypt_record(other_seed, aid, "prekey/p3", b"WRONG_SEED_PREKEY"))),
            ("p4", "PLAINTEXT_PREKEY"),
        ]
        for prekey_id, stored in rows:
            conn.execute(
                "INSERT INTO prekeys (prekey_id, device_id, private_key_enc, updated_at) VALUES (?, '', ?, 1)",
                (prekey_id, stored),
            )
        conn.commit()
    finally:
        conn.close()

    result = migrate_seed_materials(tmp_path, "")
    assert result.migrated == 2

    new_master = derive_master_key(new_seed)
    old_master = derive_master_key(old_seed)
    other_master = derive_master_key(other_seed)
    conn = sqlite3.connect(str(db_path))
    try:
        stored = dict(conn.execute("SELECT prekey_id, private_key_enc FROM prekeys").fetchall())
    finally:
        conn.close()

    p1 = json.loads(stored["p1"])
    assert decrypt_record(new_master, aid, "prekey/p1", p1) == b"GOOD_PREKEY"

    p2 = json.loads(stored["p2"])
    assert decrypt_record(new_master, aid, "prekey/p2", p2) is None
    assert decrypt_record(old_master, aid, "prekey/not-p2", p2) == b"WRONG_NAME_PREKEY"

    p3 = json.loads(stored["p3"])
    assert decrypt_record(new_master, aid, "prekey/p3", p3) is None
    assert decrypt_record(other_master, aid, "prekey/p3", p3) == b"WRONG_SEED_PREKEY"

    assert stored["p4"] == "PLAINTEXT_PREKEY"
