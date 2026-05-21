#!/usr/bin/env python
"""生成 V2 e2ee envelope 互通测试向量。

输出固定格式的 envelope JSON，供其它 SDK 加载并验证：
- 解密成功 + payload 与原文一致
- sender_signature 验证通过
- recipients_digest 与重算结果一致
"""
import sys
import os
import json
import base64
from pathlib import Path

# 添加 src 到 path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python" / "src"))

from aun_core.v2.e2ee.encrypt_p2p import encrypt_p2p_message
from aun_core.v2.e2ee.encrypt_group import encrypt_group_message
from aun_core.v2.e2ee.decrypt import decrypt_message
from aun_core.v2.crypto.ecdh import generate_p256_keypair, private_to_public_der

# 固定测试密钥（与 fixtures.py 一致）
ALICE_PRIV = base64.b64decode("pixVw1Nzw9kwG88AXzwvln1EDj59XpREtdl19ohv84E=")
ALICE_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDU8HhWlb8vRbPSiisDf/jOfGz72hFuyLcJ/+EGJM4fu6KPzKFPAGPWe+QTjqUKmklvGNk9BlKYnCRYM+hwyT1w==")
BOB_PRIV = base64.b64decode("kucXls+1l1JEL84puz+hIVGNMQpaBu2GVO1FSAC1Gpg=")
BOB_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAy/dR85gB8u3wafx7xGDfHfQaCFsOEiHsVRyLTiMoWnIj2Hqp3/HaX9fx1XLbWTG7q5v8HAO202Yj8WtYH1YEA==")
CAROL_PRIV = base64.b64decode("90MdEDhLSFBux7S2xNkl76QhMr42LY3gMr6ccoVMjwc=")
CAROL_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVVsLCk1RJUoJ7QInnmFYn6uImW5P9KljxPLD3F827MBZVJAgTuGX21KxZIwjikOGl7jX4fvCY3R8ZtlHICHhZQ==")

# Bob 的 SPK（随便选一个 P-256 keypair 作为 SPK）
BOB_SPK_PRIV = base64.b64decode("YSJfT/BHTE6J9sDXN495hou7PdjbRqBMLvi46W0NSI4=")
BOB_SPK_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEez5QV1egBYYIgT90RFSMD/Aw9mlpVEBVhGgaSHe7/ek+9pkEBYFmNF7ISWNlBKknsbl2YOD+z/fvFLlcFhM9HQ==")


def make_p2p_envelope_3dh():
    """Alice → Bob 的 P2P 加密消息（3DH 路径，带 SPK）。"""
    sender = {
        "aid": "alice.aid.com",
        "device_id": "dev-alice-1",
        "ik_priv": ALICE_PRIV,
        "ik_pub_der": ALICE_PUB_DER,
    }
    target_set = {
        "targets": [
            {
                "aid": "bob.aid.com",
                "device_id": "dev-bob-1",
                "role": "peer",
                "key_source": "peer_device_prekey",
                "ik_pk_der": BOB_PUB_DER,
                "spk_pk_der": BOB_SPK_PUB_DER,
                "spk_id": "sha256:bob_spk_1",
            },
        ],
        "audit_recipients": [],
    }
    payload = {"text": "Hello from Alice (3DH)", "type": "text"}

    # 用固定 message_id 和 timestamp 让输出更稳定（虽然 sender_session 仍随机）
    envelope = encrypt_p2p_message(
        sender=sender,
        target_set=target_set,
        payload=payload,
        message_id="m-test-3dh-001",
        timestamp=1710504000000,
    )

    # 即时自验证：解密
    decrypted = decrypt_message(
        envelope=envelope,
        self_aid="bob.aid.com",
        self_device_id="dev-bob-1",
        self_ik_priv=BOB_PRIV,
        self_spk_priv=BOB_SPK_PRIV,
        sender_pub_der=ALICE_PUB_DER,
    )
    assert decrypted == payload, f"self-decrypt mismatch: {decrypted} vs {payload}"
    print(f"[3DH] envelope size: {len(json.dumps(envelope))} bytes, recipients_digest: {envelope['recipients_digest'][:16]}...")

    return {
        "description": "P2P encrypted message (3DH path with SPK)",
        "envelope": envelope,
        "decryption_inputs": {
            "self_aid": "bob.aid.com",
            "self_device_id": "dev-bob-1",
            "self_ik_priv_b64": base64.b64encode(BOB_PRIV).decode("ascii"),
            "self_spk_priv_b64": base64.b64encode(BOB_SPK_PRIV).decode("ascii"),
            "sender_pub_der_b64": base64.b64encode(ALICE_PUB_DER).decode("ascii"),
        },
        "expected_payload": payload,
    }


def make_p2p_envelope_1dh():
    """Alice → Bob 的 P2P 加密消息（1DH 路径，无 SPK）。"""
    sender = {
        "aid": "alice.aid.com",
        "device_id": "dev-alice-1",
        "ik_priv": ALICE_PRIV,
        "ik_pub_der": ALICE_PUB_DER,
    }
    target_set = {
        "targets": [
            {
                "aid": "bob.aid.com",
                "device_id": "dev-bob-1",
                "role": "peer",
                "key_source": "aid_master",  # 1DH 触发条件：非 prekey 来源
                "ik_pk_der": BOB_PUB_DER,
                "spk_pk_der": None,
                "spk_id": "",
            },
        ],
        "audit_recipients": [],
    }
    payload = {"text": "Hello from Alice (1DH)", "type": "text"}

    envelope = encrypt_p2p_message(
        sender=sender,
        target_set=target_set,
        payload=payload,
        message_id="m-test-1dh-001",
        timestamp=1710504000000,
    )

    decrypted = decrypt_message(
        envelope=envelope,
        self_aid="bob.aid.com",
        self_device_id="dev-bob-1",
        self_ik_priv=BOB_PRIV,
        self_spk_priv=None,
        sender_pub_der=ALICE_PUB_DER,
    )
    assert decrypted == payload, f"self-decrypt mismatch: {decrypted} vs {payload}"
    print(f"[1DH] envelope size: {len(json.dumps(envelope))} bytes, recipients_digest: {envelope['recipients_digest'][:16]}...")

    return {
        "description": "P2P encrypted message (1DH path, no SPK)",
        "envelope": envelope,
        "decryption_inputs": {
            "self_aid": "bob.aid.com",
            "self_device_id": "dev-bob-1",
            "self_ik_priv_b64": base64.b64encode(BOB_PRIV).decode("ascii"),
            "self_spk_priv_b64": None,
            "sender_pub_der_b64": base64.b64encode(ALICE_PUB_DER).decode("ascii"),
        },
        "expected_payload": payload,
    }


def make_p2p_envelope_multi_recipient():
    """Alice → Bob + Carol（多设备 fan-out）。"""
    sender = {
        "aid": "alice.aid.com",
        "device_id": "dev-alice-1",
        "ik_priv": ALICE_PRIV,
        "ik_pub_der": ALICE_PUB_DER,
    }
    target_set = {
        "targets": [
            {
                "aid": "bob.aid.com",
                "device_id": "dev-bob-1",
                "role": "peer",
                "key_source": "peer_device_prekey",
                "ik_pk_der": BOB_PUB_DER,
                "spk_pk_der": BOB_SPK_PUB_DER,
                "spk_id": "sha256:bob_spk_1",
            },
            {
                "aid": "alice.aid.com",  # self-sync 到 Alice 的另一台设备
                "device_id": "dev-alice-2",
                "role": "self_sync",
                "key_source": "peer_device_prekey",
                "ik_pk_der": CAROL_PUB_DER,  # 借用 Carol 的密钥模拟 alice-2
                "spk_pk_der": None,
                "spk_id": "",
            },
        ],
        "audit_recipients": [],
    }
    payload = {"text": "Multi-recipient", "to_devices": 2}

    envelope = encrypt_p2p_message(
        sender=sender,
        target_set=target_set,
        payload=payload,
        message_id="m-test-multi-001",
        timestamp=1710504000000,
    )

    # Bob 解密
    decrypted = decrypt_message(
        envelope=envelope,
        self_aid="bob.aid.com",
        self_device_id="dev-bob-1",
        self_ik_priv=BOB_PRIV,
        self_spk_priv=BOB_SPK_PRIV,
        sender_pub_der=ALICE_PUB_DER,
    )
    assert decrypted == payload

    # Alice-2（用 Carol priv）解密
    decrypted2 = decrypt_message(
        envelope=envelope,
        self_aid="alice.aid.com",
        self_device_id="dev-alice-2",
        self_ik_priv=CAROL_PRIV,
        self_spk_priv=None,
        sender_pub_der=ALICE_PUB_DER,
    )
    assert decrypted2 == payload
    print(f"[multi] envelope size: {len(json.dumps(envelope))} bytes, recipients count: {len(envelope['recipients'])}")

    return {
        "description": "P2P multi-recipient (Bob 3DH + Alice-2 1DH self-sync)",
        "envelope": envelope,
        "decryption_inputs_bob": {
            "self_aid": "bob.aid.com",
            "self_device_id": "dev-bob-1",
            "self_ik_priv_b64": base64.b64encode(BOB_PRIV).decode("ascii"),
            "self_spk_priv_b64": base64.b64encode(BOB_SPK_PRIV).decode("ascii"),
            "sender_pub_der_b64": base64.b64encode(ALICE_PUB_DER).decode("ascii"),
        },
        "decryption_inputs_alice2": {
            "self_aid": "alice.aid.com",
            "self_device_id": "dev-alice-2",
            "self_ik_priv_b64": base64.b64encode(CAROL_PRIV).decode("ascii"),
            "self_spk_priv_b64": None,
            "sender_pub_der_b64": base64.b64encode(ALICE_PUB_DER).decode("ascii"),
        },
        "expected_payload": payload,
    }


def make_group_envelope():
    """Group 加密消息：Alice → Bob + Carol。"""
    sender = {
        "aid": "alice.aid.com",
        "device_id": "dev-alice-1",
        "ik_priv": ALICE_PRIV,
        "ik_pub_der": ALICE_PUB_DER,
    }
    targets = [
        {
            "aid": "bob.aid.com",
            "device_id": "dev-bob-1",
            "role": "member",
            "key_source": "group_device_prekey",
            "ik_pk_der": BOB_PUB_DER,
            "spk_pk_der": BOB_SPK_PUB_DER,
            "spk_id": "sha256:bob_spk_1",
        },
        {
            "aid": "carol.aid.com",
            "device_id": "dev-carol-1",
            "role": "member",
            "key_source": "aid_master",
            "ik_pk_der": CAROL_PUB_DER,
            "spk_pk_der": None,
            "spk_id": "",
        },
    ]
    payload = {"text": "Group message", "type": "group_text"}
    state_commitment = {"state_version": 1, "state_hash": "abc123", "state_chain": "chain-link-1"}

    envelope = encrypt_group_message(
        sender=sender,
        group_id="g-test.aid.com",
        epoch=5,
        targets=targets,
        payload=payload,
        message_id="m-group-001",
        timestamp=1710504000000,
        state_commitment=state_commitment,
    )

    # Bob 解密
    decrypted = decrypt_message(
        envelope=envelope,
        self_aid="bob.aid.com",
        self_device_id="dev-bob-1",
        self_ik_priv=BOB_PRIV,
        self_spk_priv=BOB_SPK_PRIV,
        sender_pub_der=ALICE_PUB_DER,
    )
    assert decrypted == payload

    # Carol 解密（1DH）
    decrypted2 = decrypt_message(
        envelope=envelope,
        self_aid="carol.aid.com",
        self_device_id="dev-carol-1",
        self_ik_priv=CAROL_PRIV,
        self_spk_priv=None,
        sender_pub_der=ALICE_PUB_DER,
    )
    assert decrypted2 == payload
    print(f"[group] envelope size: {len(json.dumps(envelope))} bytes, epoch: {envelope['epoch']}")

    return {
        "description": "Group encrypted message (Bob 3DH + Carol 1DH)",
        "envelope": envelope,
        "decryption_inputs_bob": {
            "self_aid": "bob.aid.com",
            "self_device_id": "dev-bob-1",
            "self_ik_priv_b64": base64.b64encode(BOB_PRIV).decode("ascii"),
            "self_spk_priv_b64": base64.b64encode(BOB_SPK_PRIV).decode("ascii"),
            "sender_pub_der_b64": base64.b64encode(ALICE_PUB_DER).decode("ascii"),
        },
        "decryption_inputs_carol": {
            "self_aid": "carol.aid.com",
            "self_device_id": "dev-carol-1",
            "self_ik_priv_b64": base64.b64encode(CAROL_PRIV).decode("ascii"),
            "self_spk_priv_b64": None,
            "sender_pub_der_b64": base64.b64encode(ALICE_PUB_DER).decode("ascii"),
        },
        "expected_payload": payload,
    }


def main():
    out_dir = Path(__file__).parent.parent / "python" / "tests" / "conformance" / "golden" / "envelope"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Generating V2 e2ee envelope interop vectors...\n")

    vectors = {
        "p2p_3dh.json": make_p2p_envelope_3dh(),
        "p2p_1dh.json": make_p2p_envelope_1dh(),
        "p2p_multi.json": make_p2p_envelope_multi_recipient(),
        "group_3dh_1dh.json": make_group_envelope(),
    }

    for filename, vector in vectors.items():
        out_path = out_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(vector, f, indent=2, ensure_ascii=False)
        print(f"  wrote {out_path}")

    print(f"\nDone. {len(vectors)} envelope vectors written to {out_dir}")


if __name__ == "__main__":
    main()
