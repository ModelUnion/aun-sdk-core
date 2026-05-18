"""
AUN E2EE V2 Conformance: Golden 输出生成器

用法:
  cd aun-sdk-core/python
  python -X utf8 tests/conformance/generate_golden_outputs.py
"""
import json
import os
import sys
import base64
import hashlib
import struct
from pathlib import Path

# 确保能 import aun_core
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from aun_core.v2.crypto.canonical import canonical_json
from aun_core.v2.crypto.ecdh import ecdh_compute_shared, generate_p256_keypair, private_to_public_der
from aun_core.v2.crypto.hkdf import hkdf_sha256
from aun_core.v2.crypto.aead import aes_gcm_encrypt, aes_gcm_decrypt
from aun_core.v2.crypto.ecdsa import ecdsa_sign_raw, ecdsa_verify_raw
from aun_core.v2.crypto.dh_path import compute_3dh_wrap, compute_1dh_wrap
from aun_core.v2.crypto.recipients import sort_recipients, compute_recipients_digest
from aun_core.v2.state.commitment import compute_state_commitment

# fixtures 在同目录，直接 import
sys.path.insert(0, str(Path(__file__).parent))
from fixtures import (
    ALICE_PRIV, ALICE_PUB_DER,
    BOB_PRIV, BOB_PUB_DER,
    CAROL_PRIV, CAROL_PUB_DER,
    SENDER_SESSION_PRIV, SENDER_SESSION_PUB_DER,
)

GOLDEN_DIR = Path(__file__).parent / "golden"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def write_golden(category: str, case_id: str, data: dict):
    path = GOLDEN_DIR / category / f"{case_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  ✓ {category}/{case_id}.json")


# ══════════════════════════════════════════════════════════════
def generate_canonical_golden():
    cases = [
        ("empty_object", {}),
        ("empty_array", []),
        ("null", None),
        ("true", True),
        ("false", False),
        ("integer_zero", 0),
        ("integer_negative", -1),
        ("integer_large", 1710504000000),
        ("string_simple", "hello"),
        ("string_unicode", "中文"),
        ("string_emoji", "😀"),
        ("key_order_two", {"b": 1, "a": 2}),
        ("key_order_nested", {"z": {"b": 2, "a": 1}, "a": 0}),
        ("array_preserves_order", [3, 1, 2]),
        ("string_escape_backslash", "a\\b"),
        ("string_escape_quote", 'a"b'),
        ("string_escape_newline", "a\nb"),
        ("string_escape_control", "a\x01b"),
        ("aad_structure", {
            "epoch": 12,
            "from": "alice.agentid.pub",
            "from_device": "dev-uuid-A",
            "group_id": "g-abc.agentid.pub",
            "message_id": "gm-550e8400",
            "state_commitment": "a" * 64,
            "suite": "P256_HKDF_SHA256_AES_256_GCM",
            "timestamp": 1710504000000,
            "wrap_protocol": "3DH",
        }),
    ]
    for case_id, input_val in cases:
        output = canonical_json(input_val)
        write_golden("canonical", case_id, {
            "description": f"canonical_json input",
            "input": input_val,
            "expected_output_b64": b64(output),
        })


# ══════════════════════════════════════════════════════════════
def generate_ecdh_golden():
    shared = ecdh_compute_shared(ALICE_PRIV, BOB_PUB_DER)
    write_golden("ecdh", "alice_bob", {
        "description": "ECDH(Alice_priv, Bob_pub) = shared_secret",
        "alice_priv_b64": b64(ALICE_PRIV),
        "bob_pub_der_b64": b64(BOB_PUB_DER),
        "expected_shared_b64": b64(shared),
    })

    shared2 = ecdh_compute_shared(SENDER_SESSION_PRIV, ALICE_PUB_DER)
    write_golden("ecdh", "session_alice", {
        "description": "ECDH(Session_priv, Alice_pub)",
        "session_priv_b64": b64(SENDER_SESSION_PRIV),
        "alice_pub_der_b64": b64(ALICE_PUB_DER),
        "expected_shared_b64": b64(shared2),
    })


# ══════════════════════════════════════════════════════════════
def generate_hkdf_golden():
    # RFC 5869 Test Case 1
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_sha256(ikm=ikm, salt=salt, info=info, length=42)
    write_golden("hkdf", "rfc5869_case1", {
        "description": "RFC 5869 Test Case 1",
        "ikm_hex": ikm.hex(),
        "salt_hex": salt.hex(),
        "info_hex": info.hex(),
        "length": 42,
        "expected_okm_b64": b64(okm),
    })

    # V2 3DH
    ikm2 = b"\xaa" * 96
    salt2 = b"\xbb" * 16
    okm2 = hkdf_sha256(ikm=ikm2, salt=salt2, info=b"AUN-V2-3DH", length=32)
    write_golden("hkdf", "aun_v2_3dh", {
        "description": "HKDF with AUN-V2-3DH info",
        "ikm_b64": b64(ikm2),
        "salt_b64": b64(salt2),
        "info": "AUN-V2-3DH",
        "length": 32,
        "expected_okm_b64": b64(okm2),
    })

    # V2 1DH
    ikm3 = b"\xaa" * 32
    okm3 = hkdf_sha256(ikm=ikm3, salt=salt2, info=b"AUN-V2-1DH", length=32)
    write_golden("hkdf", "aun_v2_1dh", {
        "description": "HKDF with AUN-V2-1DH info",
        "ikm_b64": b64(ikm3),
        "salt_b64": b64(salt2),
        "info": "AUN-V2-1DH",
        "length": 32,
        "expected_okm_b64": b64(okm3),
    })


# ══════════════════════════════════════════════════════════════
def generate_aead_golden():
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    plaintext = b"hello aun v2 e2ee"
    aad = b'{"from":"alice.aid","to":"bob.aid"}'

    ct, tag = aes_gcm_encrypt(key=key, nonce=nonce, plaintext=plaintext, aad=aad)
    write_golden("aead", "basic_encrypt", {
        "description": "AES-256-GCM basic encryption",
        "key_hex": key.hex(),
        "nonce_hex": nonce.hex(),
        "plaintext_b64": b64(plaintext),
        "aad_b64": b64(aad),
        "expected_ciphertext_b64": b64(ct),
        "expected_tag_b64": b64(tag),
    })

    # wrap master_key 场景
    master_key = b"\xab" * 32
    wrap_key = b"\xcd" * 32
    wrap_nonce = b"\xef" * 12
    ct2, tag2 = aes_gcm_encrypt(key=wrap_key, nonce=wrap_nonce, plaintext=master_key, aad=b"")
    write_golden("aead", "wrap_master_key", {
        "description": "Wrap 32-byte master_key (V2 scenario)",
        "wrap_key_b64": b64(wrap_key),
        "wrap_nonce_b64": b64(wrap_nonce),
        "master_key_b64": b64(master_key),
        "expected_wrapped_key_b64": b64(ct2 + tag2),
    })


# ══════════════════════════════════════════════════════════════
def generate_ecdsa_golden():
    msg = b"hello aun v2"
    sig = ecdsa_sign_raw(ALICE_PRIV, msg)
    write_golden("ecdsa", "basic_sign", {
        "description": "ECDSA-SHA256 RAW sign (RFC 6979)",
        "private_key_b64": b64(ALICE_PRIV),
        "public_key_der_b64": b64(ALICE_PUB_DER),
        "message_b64": b64(msg),
        "expected_signature_b64": b64(sig),
    })

    # V2 sign_input 场景
    sign_input = b"\x01" * 100 + b"\x02" * 16 + b'{"from":"alice"}' + b"\x03" * 32
    sig2 = ecdsa_sign_raw(ALICE_PRIV, sign_input)
    write_golden("ecdsa", "v2_sign_input", {
        "description": "ECDSA sign V2 sign_input (ct||tag||aad||digest)",
        "private_key_b64": b64(ALICE_PRIV),
        "public_key_der_b64": b64(ALICE_PUB_DER),
        "message_b64": b64(sign_input),
        "expected_signature_b64": b64(sig2),
    })


# ══════════════════════════════════════════════════════════════
def generate_recipients_digest_golden():
    rows = [
        ["alice.aid", "dev-1", "member", "group_device_prekey", "sha256:fp1", "sha256:spk1", "nonce1", "wrap1"],
        ["audit.aid", "", "audit", "aid_master", "sha256:fp2", "", "nonce2", "wrap2"],
        ["bob.aid", "dev-2", "member", "group_device", "sha256:fp3", "", "nonce3", "wrap3"],
    ]
    sorted_rows = sort_recipients(rows)
    digest = compute_recipients_digest(sorted_rows)
    write_golden("recipients_digest", "three_members", {
        "description": "3 recipients (sorted) → digest",
        "input_rows": rows,
        "expected_sorted_rows": sorted_rows,
        "expected_digest_hex": digest,
    })

    # 空
    digest_empty = compute_recipients_digest([])
    write_golden("recipients_digest", "empty", {
        "description": "empty recipients → digest",
        "input_rows": [],
        "expected_sorted_rows": [],
        "expected_digest_hex": digest_empty,
    })


# ══════════════════════════════════════════════════════════════
def generate_state_commitment_golden():
    group_id = "g-test-group.agentid.pub"
    epoch = 12
    payload = {
        "members": [
            {"aid": "alice.agentid.pub", "devices": [{"device_id": "dev-a1", "fp": "sha256:fp_alice"}]},
            {"aid": "bob.agentid.pub", "devices": [
                {"device_id": "dev-b1", "fp": "sha256:fp_bob_b1"},
                {"device_id": "dev-b2", "fp": "sha256:fp_bob_b2"},
            ]},
        ],
        "audit_aids": ["audit1.regulator.pub"],
        "join_policy_hash": None,
        "admin_set": {"admin_aids": ["alice.agentid.pub"], "threshold": 1},
        "recovery_quorum": {
            "trigger": "all_admins_offline_30d",
            "quorum_aids": ["alice.agentid.pub", "bob.agentid.pub"],
            "threshold": 2,
        },
        "history_policy": "none",
        "wrap_protocol": "3DH",
    }
    commitment = compute_state_commitment(group_id, epoch, payload)
    write_golden("state_commitment", "basic", {
        "description": "Basic state_commitment with 2 members",
        "group_id": group_id,
        "epoch": epoch,
        "state_payload": payload,
        "expected_commitment_hex": commitment,
    })


# ══════════════════════════════════════════════════════════════
def generate_3dh_golden():
    salt = b"\xef" * 16
    result = compute_3dh_wrap(
        sender_session_priv=SENDER_SESSION_PRIV,
        sender_master_priv=ALICE_PRIV,
        recv_ik_pub=ALICE_PUB_DER,
        recv_spk_pub=BOB_PUB_DER,
        salt=salt,
    )
    write_golden("3dh", "basic", {
        "description": "3DH wrap_key computation",
        "sender_session_priv_b64": b64(SENDER_SESSION_PRIV),
        "sender_master_priv_b64": b64(ALICE_PRIV),
        "recv_ik_pub_der_b64": b64(ALICE_PUB_DER),
        "recv_spk_pub_der_b64": b64(BOB_PUB_DER),
        "salt_b64": b64(salt),
        "expected_wrap_key_b64": b64(result["wrap_key"]),
    })


# ══════════════════════════════════════════════════════════════
def generate_1dh_golden():
    salt = b"\xef" * 16
    result = compute_1dh_wrap(
        sender_session_priv=SENDER_SESSION_PRIV,
        recv_ik_pub=ALICE_PUB_DER,
        salt=salt,
    )
    write_golden("1dh", "basic", {
        "description": "1DH wrap_key computation",
        "sender_session_priv_b64": b64(SENDER_SESSION_PRIV),
        "recv_ik_pub_der_b64": b64(ALICE_PUB_DER),
        "salt_b64": b64(salt),
        "expected_wrap_key_b64": b64(result["wrap_key"]),
    })


# ══════════════════════════════════════════════════════════════
def main():
    print("=" * 60)
    print("AUN E2EE V2 Conformance Golden Generator")
    print("=" * 60)
    print()

    generators = [
        ("canonical", generate_canonical_golden),
        ("ecdh", generate_ecdh_golden),
        ("hkdf", generate_hkdf_golden),
        ("aead", generate_aead_golden),
        ("ecdsa", generate_ecdsa_golden),
        ("recipients_digest", generate_recipients_digest_golden),
        ("state_commitment", generate_state_commitment_golden),
        ("3dh", generate_3dh_golden),
        ("1dh", generate_1dh_golden),
    ]

    for category, gen_func in generators:
        print(f"[{category}]")
        gen_func()
        print()

    print("=" * 60)
    print("Golden 生成完毕。请 commit golden/ 目录。")
    print("=" * 60)


if __name__ == "__main__":
    main()
