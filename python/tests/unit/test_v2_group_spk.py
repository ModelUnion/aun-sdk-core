import asyncio
import sqlite3

import pytest

from aun_core.keystore.sqlite_db import AIDDatabase
from aun_core.v2.crypto.ecdh import generate_p256_keypair
from aun_core.v2.keystore import V2KeyStore
from aun_core.v2.session import V2Session


def _make_session(tmp_path):
    db = AIDDatabase(tmp_path / "aun.db")
    aid_priv, aid_pub = generate_p256_keypair()
    session = V2Session(
        db,
        device_id="dev-1",
        aid="alice.agentid.pub",
        aid_priv_der=aid_priv,
        aid_pub_der=aid_pub,
    )
    session.ensure_keys()
    return db, session


def test_group_decrypt_keys_prefer_group_spk_when_id_collides(tmp_path):
    db, session = _make_session(tmp_path)
    try:
        p2p_spk_id = session._spk_id
        p2p_spk_priv = session._spk_priv
        group_spk_priv, group_spk_pub = generate_p256_keypair()
        V2KeyStore(db).save_group_spk(
            "dev-1",
            "group.agentid.pub/1",
            p2p_spk_id,
            group_spk_priv,
            group_spk_pub,
        )

        _ik_priv, spk_priv = session.get_group_decrypt_keys("group.agentid.pub/1", p2p_spk_id)

        assert spk_priv == group_spk_priv
        assert spk_priv != p2p_spk_priv
    finally:
        db.close()


def test_group_decrypt_keys_accept_legacy_composite_group_spk_id(tmp_path):
    db, session = _make_session(tmp_path)
    try:
        group_id = "group.agentid.pub/legacy"
        group_spk_priv, group_spk_pub = generate_p256_keypair()
        spk_id = "sha256:legacy_group"
        V2KeyStore(db).save_group_spk("dev-1", group_id, spk_id, group_spk_priv, group_spk_pub)

        _ik_priv, spk_priv = session.get_group_decrypt_keys(group_id, f"{group_id}\0{spk_id}")

        assert spk_priv == group_spk_priv
        # 字典键必须使用 normalized group_id
        from aun_core.v2.session import V2Session
        normalized_group_id = V2Session._group_key(group_id)
        session._last_uploaded_group_spk_ids[normalized_group_id] = spk_id
        assert session.is_last_uploaded_group_spk(group_id, f"{group_id}\0{spk_id}") is True
    finally:
        db.close()


def test_group_decrypt_keys_fallback_to_p2p_spk_for_legacy_wrap(tmp_path):
    db, session = _make_session(tmp_path)
    try:
        p2p_spk_id = session._spk_id
        p2p_spk_priv = session._spk_priv

        _ik_priv, spk_priv = session.get_group_decrypt_keys("group.agentid.pub/legacy", p2p_spk_id)

        assert spk_priv == p2p_spk_priv
    finally:
        db.close()


def test_group_decrypt_keys_allow_ik_only_fallback(tmp_path):
    db, session = _make_session(tmp_path)
    try:
        _ik_priv, spk_priv = session.get_group_decrypt_keys("group.agentid.pub/1", "")

        assert spk_priv is None
    finally:
        db.close()


def test_group_decrypt_keys_missing_spk_reports_error(tmp_path):
    db, session = _make_session(tmp_path)
    try:
        with pytest.raises(ValueError, match="spk_missing"):
            session.get_group_decrypt_keys("group.agentid.pub/1", "sha256:missing")
    finally:
        db.close()


def test_group_last_uploaded_spk_is_isolated_by_group(tmp_path):
    db, session = _make_session(tmp_path)
    calls = []

    async def call_fn(method, params):
        calls.append((method, dict(params)))
        return {"ok": True}

    try:
        from aun_core.v2.session import V2Session
        asyncio.run(session.ensure_group_registered("group.agentid.pub/1", call_fn))
        # 字典键使用 normalized group_id
        group1_normalized = V2Session._group_key("group.agentid.pub/1")
        group1_spk = session._last_uploaded_group_spk_ids[group1_normalized]
        asyncio.run(session.ensure_group_registered("group.agentid.pub/2", call_fn))
        group2_normalized = V2Session._group_key("group.agentid.pub/2")
        group2_spk = session._last_uploaded_group_spk_ids[group2_normalized]

        assert group1_spk
        assert group2_spk
        assert session.is_last_uploaded_group_spk("group.agentid.pub/1", group1_spk)
        assert session.is_last_uploaded_group_spk(" group.agentid.pub/1 ", group1_spk)
        assert session.is_last_uploaded_group_spk("group.agentid.pub/2", group2_spk)
        assert not session.is_last_uploaded_group_spk("group.agentid.pub/1", group2_spk)
        assert not session.is_last_uploaded_group_spk("group.agentid.pub/2", group1_spk)
        assert [method for method, _params in calls] == ["group.v2.put_group_pk", "group.v2.put_group_pk"]
    finally:
        db.close()


def test_p2p_last_uploaded_spk_updates_only_after_upload_success(tmp_path):
    db, session = _make_session(tmp_path)

    async def fail_call(_method, _params):
        raise RuntimeError("upload failed")

    async def ok_call(_method, _params):
        return {"ok": True}

    try:
        first_spk = session._spk_id
        assert not session.is_last_uploaded_spk(first_spk)

        try:
            asyncio.run(session.rotate_spk(fail_call))
        except RuntimeError:
            pass
        failed_spk = session._spk_id
        assert not session.is_last_uploaded_spk(failed_spk)

        asyncio.run(session.rotate_spk(ok_call))
        uploaded_spk = session._spk_id
        assert session.is_last_uploaded_spk(uploaded_spk)
        assert not session.is_last_uploaded_spk(first_spk)
    finally:
        db.close()


def test_p2p_uploaded_marker_reuploads_to_heal_remote_state(tmp_path):
    db, session = _make_session(tmp_path)
    calls = []

    async def call_fn(method, params):
        calls.append((method, dict(params)))
        return {"ok": True}

    try:
        asyncio.run(session.ensure_registered(call_fn))
        uploaded_spk = session._last_uploaded_spk_id
        assert uploaded_spk
        assert [method for method, _params in calls] == ["message.v2.put_peer_pk"]

        session2 = V2Session(
            db,
            device_id="dev-1",
            aid="alice.agentid.pub",
            aid_priv_der=session._aid_priv_der,
            aid_pub_der=session._aid_pub_der,
        )
        asyncio.run(session2.ensure_registered(call_fn))

        assert session2.is_last_uploaded_spk(uploaded_spk)
        assert [method for method, _params in calls] == ["message.v2.put_peer_pk", "message.v2.put_peer_pk"]
    finally:
        db.close()


def test_group_uploaded_marker_restores_without_rpc(tmp_path):
    db, session = _make_session(tmp_path)
    calls = []

    async def call_fn(method, params):
        calls.append((method, dict(params)))
        return {"ok": True}

    async def fail_if_called(method, params):
        raise AssertionError(f"unexpected RPC: {method} {params}")

    try:
        from aun_core.v2.session import V2Session
        group_id = "group.agentid.pub/marker"
        asyncio.run(session.ensure_group_registered(group_id, call_fn))
        # 字典键使用 normalized group_id
        group_normalized = V2Session._group_key(group_id)
        uploaded_spk = session._last_uploaded_group_spk_ids[group_normalized]
        assert uploaded_spk
        assert [method for method, _params in calls] == ["group.v2.put_group_pk"]

        session2 = V2Session(
            db,
            device_id="dev-1",
            aid="alice.agentid.pub",
            aid_priv_der=session._aid_priv_der,
            aid_pub_der=session._aid_pub_der,
        )
        asyncio.run(session2.ensure_group_registered(group_id, fail_if_called))

        assert session2.is_last_uploaded_group_spk(group_id, uploaded_spk)
    finally:
        db.close()


def test_legacy_v2_device_keys_migration_accepts_null_uploaded_markers(tmp_path):
    db_path = tmp_path / "aun.db"
    conn = sqlite3.connect(db_path)
    composite = "group.agentid.pub/legacy\0sha256:legacy_group"
    conn.execute(
        """CREATE TABLE v2_device_keys (
            device_id TEXT NOT NULL,
            key_type TEXT NOT NULL,
            key_id TEXT NOT NULL DEFAULT '',
            private_key BLOB,
            public_key BLOB,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (device_id, key_type, key_id)
        )"""
    )
    conn.executemany(
        "INSERT INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("dev-1", "spk", "spk-1", b"p", b"q", 1),
            ("dev-1", "spk_uploaded", "spk-1", None, None, 2),
            ("dev-1", "group_spk", composite, b"gp", b"gq", 3),
            ("dev-1", "group_spk_uploaded", composite, None, None, 4),
        ],
    )
    conn.commit()
    conn.close()

    db = AIDDatabase(db_path)
    try:
        from aun_core.v2.session import V2Session
        store = V2KeyStore(db)
        assert store.load_latest_uploaded_spk_id("dev-1") == "spk-1"
        assert store.load_latest_uploaded_group_spk_id("dev-1", "group.agentid.pub/legacy") == "sha256:legacy_group"
        rows = db._get_conn().execute(
            "SELECT group_id, key_id FROM v2_device_keys WHERE key_type IN ('group_spk', 'group_spk_uploaded')"
        ).fetchall()
        assert rows
        # 迁移后 group_id 已被 normalize
        normalized_group_id = V2Session._group_key("group.agentid.pub/legacy")
        assert all(row[0] == normalized_group_id for row in rows)
        assert all("\0" not in str(row[1]) for row in rows)
    finally:
        db.close()


def test_group_spk_new_records_do_not_use_legacy_nul_composite_key(tmp_path):
    db = AIDDatabase(tmp_path / "aun.db")
    try:
        from aun_core.v2.session import V2Session
        store = V2KeyStore(db)
        store.save_group_spk("dev-1", "group.agentid.pub/new", "sha256:new_group", b"gpriv", b"gpub")
        store.mark_group_spk_uploaded("dev-1", "group.agentid.pub/new", "sha256:new_group")
        rows = db._get_conn().execute(
            "SELECT group_id, key_id FROM v2_device_keys WHERE key_type IN ('group_spk', 'group_spk_uploaded')"
        ).fetchall()
        assert len(rows) == 2
        # group_id 会被 normalize
        normalized_group_id = V2Session._group_key("group.agentid.pub/new")
        assert all(row[0] == normalized_group_id for row in rows)
        assert all(row[1] == "sha256:new_group" for row in rows)
        assert all("\0" not in str(row[1]) for row in rows)
    finally:
        db.close()
