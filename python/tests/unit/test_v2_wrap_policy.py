from aun_core.client import _v2_apply_wrap_policy_to_targets


def test_aid_scope_wrap_policy_preserves_self_sync_device_ids():
    targets = [
        {"aid": "bob.aid.net", "device_id": "bob-1", "role": "peer", "key_source": "peer_device_prekey", "spk_pk_der": b"x", "spk_id": "spk-1"},
        {"aid": "bob.aid.net", "device_id": "bob-2", "role": "peer", "key_source": "peer_device_prekey", "spk_pk_der": b"x", "spk_id": "spk-2"},
        {"aid": "alice.aid.com", "device_id": "alice-sync-1", "role": "self_sync", "key_source": "peer_device_prekey", "spk_pk_der": b"x", "spk_id": "spk-3"},
        {"aid": "alice.aid.com", "device_id": "alice-sync-2", "role": "self_sync", "key_source": "peer_device_prekey", "spk_pk_der": b"x", "spk_id": "spk-4"},
    ]

    normalized = _v2_apply_wrap_policy_to_targets(targets, {"protocol": "1DH", "scope": "aid"})

    peer_rows = [row for row in normalized if row["role"] == "peer"]
    self_rows = [row for row in normalized if row["role"] == "self_sync"]
    assert len(peer_rows) == 1
    assert peer_rows[0]["device_id"] == ""
    assert {row["device_id"] for row in self_rows} == {"alice-sync-1", "alice-sync-2"}
    assert {row["key_source"] for row in normalized} == {"aid_master"}
