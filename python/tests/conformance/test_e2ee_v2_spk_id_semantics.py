from aun_core.v2.e2ee.decrypt import decrypt_message
from aun_core.v2.e2ee.encrypt_group import encrypt_group_message
from aun_core.v2.e2ee.encrypt_p2p import encrypt_p2p_message
from aun_core.v2.crypto.ecdh import generate_p256_keypair
from aun_core import __version__ as AUN_SDK_VERSION
import pytest


def _sender():
    alice_priv, alice_pub = generate_p256_keypair()
    return {
        "aid": "alice.agentid.pub",
        "device_id": "dev-alice-1",
        "ik_priv": alice_priv,
        "ik_pub_der": alice_pub,
    }


def _target(role: str, key_source: str):
    bob_priv, bob_pub = generate_p256_keypair()
    _bob_spk_priv, bob_spk_pub = generate_p256_keypair()
    return (
        {
            "aid": "bob.agentid.pub",
            "device_id": "dev-bob-1",
            "role": role,
            "key_source": key_source,
            "ik_pk_der": bob_pub,
            "spk_pk_der": bob_spk_pub,
            "spk_id": "",
        },
        bob_priv,
    )


def test_p2p_spk_public_key_without_spk_id_uses_1dh():
    sender = _sender()
    target, bob_priv = _target("peer", "peer_device_prekey")
    payload = {"text": "SPK pub without SPK ID uses 1DH"}

    envelope = encrypt_p2p_message(sender, {"targets": [target]}, payload)

    assert envelope["aad"]["wrap_protocol"] == "1DH"
    row = envelope["recipients"][0]
    assert row[3] == "aid_master"
    assert row[5] == ""
    assert decrypt_message(
        envelope,
        "bob.agentid.pub",
        "dev-bob-1",
        bob_priv,
        None,
        sender["ik_pub_der"],
    ) == payload


def test_group_spk_public_key_without_spk_id_uses_1dh():
    sender = _sender()
    target, bob_priv = _target("member", "group_device_prekey")
    payload = {"text": "group SPK pub without SPK ID uses 1DH"}

    envelope = encrypt_group_message(sender, "group.agentid.pub/1", 1, [target], payload)

    assert envelope["aad"]["wrap_protocol"] == "1DH"
    row = envelope["recipients"][0]
    assert row[3] == "aid_master"
    assert row[5] == ""
    assert decrypt_message(
        envelope,
        "bob.agentid.pub",
        "dev-bob-1",
        bob_priv,
        None,
        sender["ik_pub_der"],
    ) == payload



def test_group_payload_type_is_copied_to_top_level_envelope():
    sender = _sender()
    target, _bob_priv = _target("member", "aid_master")
    payload = {"type": "group-text", "text": "group visible type"}

    envelope = encrypt_group_message(sender, "group.agentid.pub/1", 1, [target], payload)

    assert envelope["payload_type"] == "group-text"
    assert envelope["protected_headers"]["payload_type"] == "group-text"
    assert envelope["protected_headers"]["sdk_lang"] == "python"
    assert envelope["protected_headers"]["sdk_version"] == AUN_SDK_VERSION
    assert "sdk_vesion" not in envelope["protected_headers"]


def test_group_sdk_metadata_is_injected_without_payload_type():
    sender = _sender()
    target, _bob_priv = _target("member", "aid_master")
    payload = {"text": "group payload without type"}

    envelope = encrypt_group_message(sender, "group.agentid.pub/1", 1, [target], payload)

    assert "payload_type" not in envelope
    assert envelope["protected_headers"]["sdk_lang"] == "python"
    assert envelope["protected_headers"]["sdk_version"] == AUN_SDK_VERSION
def test_group_wrong_spk_reports_wrap_key_decrypt_failed():
    sender = _sender()
    bob_priv, bob_pub = generate_p256_keypair()
    _bob_spk_priv, bob_spk_pub = generate_p256_keypair()
    wrong_spk_priv, _wrong_spk_pub = generate_p256_keypair()
    payload = {"text": "wrong group SPK should be classified precisely"}
    target = {
        "aid": "bob.agentid.pub",
        "device_id": "dev-bob-1",
        "role": "member",
        "key_source": "group_device_prekey",
        "ik_pk_der": bob_pub,
        "spk_pk_der": bob_spk_pub,
        "spk_id": "sha256:bob_group_spk",
    }

    envelope = encrypt_group_message(sender, "group.agentid.pub/1", 1, [target], payload)

    with pytest.raises(ValueError, match=r"wrap_key_decrypt_failed: .*key_source=group_device_prekey.*spk_id=sha256:bob_group_spk"):
        decrypt_message(
            envelope,
            "bob.agentid.pub",
            "dev-bob-1",
            bob_priv,
            wrong_spk_priv,
            sender["ik_pub_der"],
        )
