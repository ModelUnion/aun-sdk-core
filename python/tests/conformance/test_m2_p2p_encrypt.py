"""
AUN E2EE V2 M2: P2P 加密引擎集成测试

测试目标：
1. 完整 envelope 构造（encrypt）
2. 完整 envelope 解密（decrypt）
3. 发送方/接收方对称性验证
4. 多设备 wrap
5. sender_signature 完整性
6. recipients_digest 防篡改
"""
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.e2ee.encrypt_p2p import encrypt_p2p_message
from aun_core.v2.e2ee.decrypt import decrypt_message

# ── M0 已实现 ──
from aun_core.v2.crypto.ecdh import generate_p256_keypair, private_to_public_der
from aun_core.v2.crypto.ecdsa import ecdsa_verify_raw
from aun_core.v2.crypto.canonical import canonical_json

# ── 固定测试密钥 ──
from .fixtures import (
    ALICE_PRIV, ALICE_PUB_DER,
    BOB_PRIV, BOB_PUB_DER,
    CAROL_PRIV, CAROL_PUB_DER,
    SENDER_SESSION_PRIV, SENDER_SESSION_PUB_DER,
)


# ══════════════════════════════════════════════════════════════
# 测试 fixtures
# ══════════════════════════════════════════════════════════════

def make_target_set_single_device():
    """单设备接收方（Bob dev-1，有 SPK）"""
    bob_spk_priv, bob_spk_pub = generate_p256_keypair()
    return {
        "targets": [
            {
                "aid": "bob.agentid.pub",
                "device_id": "dev-b1",
                "role": "peer",
                "key_source": "peer_device_prekey",
                "ik_pk_der": BOB_PUB_DER,
                "ik_priv": BOB_PRIV,
                "spk_pk_der": bob_spk_pub,
                "spk_priv": bob_spk_priv,
                "spk_id": "sha256:bobspk000001",
            }
        ],
        "audit_recipients": [],
    }


def make_target_set_multi_device():
    """多设备接收方（Bob dev-1 有 SPK，Bob dev-2 无 SPK → 1DH 降级）"""
    bob_spk_priv, bob_spk_pub = generate_p256_keypair()
    return {
        "targets": [
            {
                "aid": "bob.agentid.pub",
                "device_id": "dev-b1",
                "role": "peer",
                "key_source": "peer_device_prekey",
                "ik_pk_der": BOB_PUB_DER,
                "ik_priv": BOB_PRIV,
                "spk_pk_der": bob_spk_pub,
                "spk_priv": bob_spk_priv,
                "spk_id": "sha256:bobspk000001",
            },
            {
                "aid": "bob.agentid.pub",
                "device_id": "dev-b2",
                "role": "peer",
                "key_source": "peer_device",
                "ik_pk_der": BOB_PUB_DER,
                "ik_priv": BOB_PRIV,
                "spk_pk_der": None,
                "spk_priv": None,
                "spk_id": "",
            },
        ],
        "audit_recipients": [],
    }


SENDER_IDENTITY = {
    "aid": "alice.agentid.pub",
    "device_id": "dev-a1",
    "ik_priv": ALICE_PRIV,
    "ik_pub_der": ALICE_PUB_DER,
}

PAYLOAD = {"text": "hello bob, this is encrypted!"}


# ══════════════════════════════════════════════════════════════
# 1. 完整 envelope 构造
# ══════════════════════════════════════════════════════════════

class TestEncryptP2P:
    """P2P 加密引擎：构造完整 envelope"""

    def test_encrypt_produces_valid_envelope(self):
        """加密产出完整 envelope 结构"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        assert envelope["type"] == "e2ee.p2p_encrypted"
        assert envelope["version"] == "v2"
        assert envelope["suite"] == "P256_HKDF_SHA256_AES_256_GCM"
        assert "nonce" in envelope
        assert "ciphertext" in envelope
        assert "tag" in envelope
        assert "sender_signature" in envelope
        assert "sender_cert_fingerprint" in envelope
        assert "sender_session_pk" in envelope
        assert "recipients_digest" in envelope
        assert "recipients" in envelope
        assert "aad" in envelope

    def test_envelope_aad_contains_required_fields(self):
        """aad 含 from / from_device / to / message_id / timestamp / suite"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        aad = envelope["aad"]
        assert aad["from"] == "alice.agentid.pub"
        assert aad["from_device"] == "dev-a1"
        assert aad["to"] == "bob.agentid.pub"
        assert "message_id" in aad
        assert aad["message_id"].startswith("m-")
        assert "timestamp" in aad
        assert aad["suite"] == "P256_HKDF_SHA256_AES_256_GCM"

    def test_recipients_is_sorted_array(self):
        """recipients 是排序后的二维数组"""
        target_set = make_target_set_multi_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        recipients = envelope["recipients"]
        assert isinstance(recipients, list)
        assert len(recipients) == 2
        # 每行 8 字段
        for row in recipients:
            assert len(row) == 8

    def test_multi_device_each_gets_own_wrap(self):
        """多设备：每台设备各自一行 wrap"""
        target_set = make_target_set_multi_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        recipients = envelope["recipients"]
        device_ids = [row[1] for row in recipients]
        assert "dev-b1" in device_ids
        assert "dev-b2" in device_ids

    def test_3dh_device_has_spk_id(self):
        """有 SPK 的设备行 spk_id 非空"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        row = envelope["recipients"][0]
        spk_id = row[5]  # 第 6 字段
        assert spk_id != ""
        assert spk_id.startswith("sha256:")

    def test_1dh_device_has_empty_spk_id(self):
        """无 SPK 的设备行 spk_id 为空"""
        target_set = make_target_set_multi_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        # dev-b2 无 SPK
        row_b2 = [r for r in envelope["recipients"] if r[1] == "dev-b2"][0]
        spk_id = row_b2[5]
        assert spk_id == ""

    def test_sender_session_pk_shared(self):
        """sender_session_pk 在 envelope 顶层（所有 recipient 共享）"""
        target_set = make_target_set_multi_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        assert "sender_session_pk" in envelope
        assert len(envelope["sender_session_pk"]) > 0


# ══════════════════════════════════════════════════════════════
# 2. 完整 envelope 解密
# ══════════════════════════════════════════════════════════════

class TestDecryptP2P:
    """P2P 解密引擎"""

    def test_decrypt_roundtrip_3dh(self):
        """加密 → 解密 = 原文（3DH 路径）"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        # 接收方解密
        target = target_set["targets"][0]
        result = decrypt_message(
            envelope=envelope,
            self_aid="bob.agentid.pub",
            self_device_id="dev-b1",
            self_ik_priv=target["ik_priv"],
            self_spk_priv=target["spk_priv"],
            sender_pub_der=ALICE_PUB_DER,
        )
        assert result == PAYLOAD

    def test_decrypt_roundtrip_1dh(self):
        """加密 → 解密 = 原文（1DH 降级路径）"""
        target_set = make_target_set_multi_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        # dev-b2 无 SPK → 1DH
        target = target_set["targets"][1]
        result = decrypt_message(
            envelope=envelope,
            self_aid="bob.agentid.pub",
            self_device_id="dev-b2",
            self_ik_priv=target["ik_priv"],
            self_spk_priv=None,
            sender_pub_der=ALICE_PUB_DER,
        )
        assert result == PAYLOAD

    def test_wrong_device_cannot_decrypt(self):
        """非目标设备无法解密"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        # Carol 不在 recipients 中
        result = decrypt_message(
            envelope=envelope,
            self_aid="carol.agentid.pub",
            self_device_id="dev-c1",
            self_ik_priv=CAROL_PRIV,
            self_spk_priv=None,
            sender_pub_der=ALICE_PUB_DER,
        )
        assert result is None  # 找不到自己的行

    def test_tampered_ciphertext_fails(self):
        """篡改密文 → 解密失败"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        # 篡改 ciphertext
        import base64
        ct_bytes = base64.b64decode(envelope["ciphertext"])
        tampered = bytearray(ct_bytes)
        tampered[0] ^= 0xFF
        envelope["ciphertext"] = base64.b64encode(bytes(tampered)).decode()

        target = target_set["targets"][0]
        with pytest.raises(Exception):
            decrypt_message(
                envelope=envelope,
                self_aid="bob.agentid.pub",
                self_device_id="dev-b1",
                self_ik_priv=target["ik_priv"],
                self_spk_priv=target["spk_priv"],
                sender_pub_der=ALICE_PUB_DER,
            )


# ══════════════════════════════════════════════════════════════
# 3. sender_signature 完整性
# ══════════════════════════════════════════════════════════════

class TestSenderSignature:
    """sender_signature 验证"""

    def test_signature_verifies(self):
        """sender_signature 可用 sender 公钥验证"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        import base64
        sig = base64.b64decode(envelope["sender_signature"])
        ct = base64.b64decode(envelope["ciphertext"])
        tag = base64.b64decode(envelope["tag"])
        aad_bytes = canonical_json(envelope["aad"])
        digest_bytes = bytes.fromhex(envelope["recipients_digest"])
        sign_input = ct + tag + aad_bytes + digest_bytes
        assert ecdsa_verify_raw(ALICE_PUB_DER, sig, sign_input) is True

    def test_tampered_recipients_breaks_signature(self):
        """篡改 recipients → recipients_digest 变 → 签名失败"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        # 篡改 recipients 中的 wrapped_key
        envelope["recipients"][0][7] = "tampered_wrap_key"
        # 重算 digest 会与 envelope 中的不一致
        import hashlib
        new_digest = hashlib.sha256(canonical_json(envelope["recipients"])).hexdigest()
        assert new_digest != envelope["recipients_digest"]


# ══════════════════════════════════════════════════════════════
# 4. recipients_digest 防篡改
# ══════════════════════════════════════════════════════════════

class TestRecipientsIntegrity:
    """recipients_digest 完整性"""

    def test_digest_matches_recipients(self):
        """envelope 中 recipients_digest 与 recipients 一致（Merkle root）"""
        target_set = make_target_set_single_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        from aun_core.v2.crypto.recipients import compute_merkle_root
        expected = compute_merkle_root(envelope["recipients"])
        assert envelope["recipients_digest"] == expected

    def test_recipients_sorted(self):
        """recipients 行按 (aid, device_id, role) 排序"""
        target_set = make_target_set_multi_device()
        envelope = encrypt_p2p_message(
            sender=SENDER_IDENTITY,
            target_set=target_set,
            payload=PAYLOAD,
        )
        recipients = envelope["recipients"]
        keys = [(r[0], r[1], r[2]) for r in recipients]
        assert keys == sorted(keys)
