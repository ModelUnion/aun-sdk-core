"""
AUN E2EE V2 M2: P2P E2EE 完整 Mock E2E 测试

模拟完整链路（无 docker / 无网络），覆盖所有 P2P E2EE 场景：

场景清单：
1. 基础：Alice → Bob 单设备 3DH 加密收发
2. 多设备：Alice → Bob 两台设备各自能解
3. 1DH 降级：Bob 某设备无 SPK → 该设备走 1DH 仍能解
4. 双向通信：Alice → Bob + Bob → Alice
5. 多条消息：连续发 3 条，各自独立 master_key
6. 篡改检测：密文篡改 → 解密失败
7. 签名篡改：sender_signature 篡改 → 验签失败
8. recipients 篡改：wrapped_key 篡改 → digest 不匹配
9. 非目标设备：Carol 拿到 envelope 无法解密
10. SPK 轮换后旧消息仍可解（接收方保留旧 SPK 私钥）
11. SPK 轮换后新消息用新 SPK
12. 发送方缓存旧 SPK 仍可用（接收方未销毁）
"""
import base64
import copy
import hashlib
import json
import pytest

from aun_core.v2.crypto.ecdh import generate_p256_keypair, private_to_public_der
from aun_core.v2.crypto.canonical import canonical_json
from aun_core.v2.crypto.ecdsa import ecdsa_verify_raw
from aun_core.v2.e2ee.encrypt_p2p import encrypt_p2p_message
from aun_core.v2.e2ee.decrypt import decrypt_message


# ══════════════════════════════════════════════════════════════
# 测试 Fixtures：模拟用户身份
# ══════════════════════════════════════════════════════════════

def make_identity(name: str) -> dict:
    """生成一个完整的用户身份（AID 主密钥 + 设备）"""
    ik_priv, ik_pub_der = generate_p256_keypair()
    return {
        "aid": f"{name}.agentid.pub",
        "device_id": f"dev-{name}-1",
        "ik_priv": ik_priv,
        "ik_pub_der": ik_pub_der,
    }


def make_device_with_spk(identity: dict, device_id: str) -> dict:
    """为某身份生成一个有 SPK 的设备条目"""
    spk_priv, spk_pub_der = generate_p256_keypair()
    spk_id = "sha256:" + hashlib.sha256(spk_pub_der).hexdigest()[:16]
    return {
        "aid": identity["aid"],
        "device_id": device_id,
        "role": "peer",
        "key_source": "peer_device_prekey",
        "ik_pk_der": identity["ik_pub_der"],
        "ik_priv": identity["ik_priv"],
        "spk_pk_der": spk_pub_der,
        "spk_priv": spk_priv,
        "spk_id": spk_id,
    }


def make_device_without_spk(identity: dict, device_id: str) -> dict:
    """为某身份生成一个无 SPK 的设备条目（1DH 降级）"""
    return {
        "aid": identity["aid"],
        "device_id": device_id,
        "role": "peer",
        "key_source": "peer_device",
        "ik_pk_der": identity["ik_pub_der"],
        "ik_priv": identity["ik_priv"],
        "spk_pk_der": None,
        "spk_priv": None,
        "spk_id": "",
    }


def make_target_set(devices: list[dict]) -> dict:
    return {"targets": devices, "audit_recipients": []}


def decrypt_for_device(envelope: dict, device: dict, sender_pub_der: bytes) -> dict | None:
    """模拟某设备解密"""
    return decrypt_message(
        envelope=envelope,
        self_aid=device["aid"],
        self_device_id=device["device_id"],
        self_ik_priv=device["ik_priv"],
        self_spk_priv=device.get("spk_priv"),
        sender_pub_der=sender_pub_der,
    )


# ══════════════════════════════════════════════════════════════
# 场景 1：基础 3DH 加密收发
# ══════════════════════════════════════════════════════════════

class TestBasic3DH:
    """Alice → Bob 单设备 3DH"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.bob_dev1 = make_device_with_spk(self.bob, "dev-bob-1")
        self.payload = {"text": "hello bob!"}

    def test_encrypt_decrypt_roundtrip(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev1]),
            payload=self.payload,
        )
        result = decrypt_for_device(envelope, self.bob_dev1, self.alice["ik_pub_der"])
        assert result == self.payload

    def test_envelope_structure(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev1]),
            payload=self.payload,
        )
        assert envelope["type"] == "e2ee.p2p_encrypted"
        assert envelope["version"] == "v2"
        assert envelope["aad"]["from"] == "alice.agentid.pub"
        assert envelope["aad"]["to"] == "bob.agentid.pub"
        assert envelope["aad"]["message_id"].startswith("m-")
        assert len(envelope["recipients"]) == 1
        assert envelope["recipients"][0][5] != ""  # spk_id 非空 = 3DH


# ══════════════════════════════════════════════════════════════
# 场景 2：多设备
# ══════════════════════════════════════════════════════════════

class TestMultiDevice:
    """Alice → Bob 两台设备"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.bob_dev1 = make_device_with_spk(self.bob, "dev-bob-1")
        self.bob_dev2 = make_device_with_spk(self.bob, "dev-bob-2")
        self.payload = {"text": "hello both devices!"}

    def test_both_devices_can_decrypt(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev1, self.bob_dev2]),
            payload=self.payload,
        )
        r1 = decrypt_for_device(envelope, self.bob_dev1, self.alice["ik_pub_der"])
        r2 = decrypt_for_device(envelope, self.bob_dev2, self.alice["ik_pub_der"])
        assert r1 == self.payload
        assert r2 == self.payload

    def test_recipients_has_two_rows(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev1, self.bob_dev2]),
            payload=self.payload,
        )
        assert len(envelope["recipients"]) == 2
        device_ids = {r[1] for r in envelope["recipients"]}
        assert device_ids == {"dev-bob-1", "dev-bob-2"}


# ══════════════════════════════════════════════════════════════
# 场景 3：1DH 降级
# ══════════════════════════════════════════════════════════════

class Test1DHFallback:
    """Bob dev-2 无 SPK → 1DH 降级"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.bob_dev1 = make_device_with_spk(self.bob, "dev-bob-1")
        self.bob_dev2 = make_device_without_spk(self.bob, "dev-bob-2")
        self.payload = {"text": "mixed 3dh and 1dh"}

    def test_3dh_device_decrypts(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev1, self.bob_dev2]),
            payload=self.payload,
        )
        result = decrypt_for_device(envelope, self.bob_dev1, self.alice["ik_pub_der"])
        assert result == self.payload

    def test_1dh_device_decrypts(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev1, self.bob_dev2]),
            payload=self.payload,
        )
        result = decrypt_for_device(envelope, self.bob_dev2, self.alice["ik_pub_der"])
        assert result == self.payload

    def test_1dh_row_has_empty_spk_id(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev1, self.bob_dev2]),
            payload=self.payload,
        )
        row_dev2 = [r for r in envelope["recipients"] if r[1] == "dev-bob-2"][0]
        assert row_dev2[5] == ""  # spk_id 为空


# ══════════════════════════════════════════════════════════════
# 场景 4：双向通信
# ══════════════════════════════════════════════════════════════

class TestBidirectional:
    """Alice → Bob + Bob → Alice"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.alice_dev = make_device_with_spk(self.alice, "dev-alice-1")
        self.bob_dev = make_device_with_spk(self.bob, "dev-bob-1")

    def test_alice_to_bob(self):
        payload = {"text": "hi bob from alice"}
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload=payload,
        )
        result = decrypt_for_device(envelope, self.bob_dev, self.alice["ik_pub_der"])
        assert result == payload

    def test_bob_to_alice(self):
        payload = {"text": "hi alice from bob"}
        envelope = encrypt_p2p_message(
            sender=self.bob,
            target_set=make_target_set([self.alice_dev]),
            payload=payload,
        )
        result = decrypt_for_device(envelope, self.alice_dev, self.bob["ik_pub_der"])
        assert result == payload


# ══════════════════════════════════════════════════════════════
# 场景 5：多条消息独立性
# ══════════════════════════════════════════════════════════════

class TestMultipleMessages:
    """连续发 3 条消息，各自独立 master_key"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.bob_dev = make_device_with_spk(self.bob, "dev-bob-1")

    def test_three_messages_independent(self):
        payloads = [{"n": 1}, {"n": 2}, {"n": 3}]
        envelopes = []
        for p in payloads:
            env = encrypt_p2p_message(
                sender=self.alice,
                target_set=make_target_set([self.bob_dev]),
                payload=p,
            )
            envelopes.append(env)

        # 各自解密正确
        for i, env in enumerate(envelopes):
            result = decrypt_for_device(env, self.bob_dev, self.alice["ik_pub_der"])
            assert result == payloads[i]

        # 密文各不相同（独立 master_key）
        ciphertexts = [e["ciphertext"] for e in envelopes]
        assert len(set(ciphertexts)) == 3

        # message_id 各不相同
        msg_ids = [e["aad"]["message_id"] for e in envelopes]
        assert len(set(msg_ids)) == 3

        # sender_session_pk 各不相同（每条消息独立 ephemeral）
        session_pks = [e["sender_session_pk"] for e in envelopes]
        assert len(set(session_pks)) == 3


# ══════════════════════════════════════════════════════════════
# 场景 6：密文篡改检测
# ══════════════════════════════════════════════════════════════

class TestCiphertextTamper:
    """密文篡改 → 解密失败"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.bob_dev = make_device_with_spk(self.bob, "dev-bob-1")

    def test_tampered_ciphertext_fails(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "data"},
        )
        # 篡改 ciphertext
        ct = bytearray(base64.b64decode(envelope["ciphertext"]))
        ct[0] ^= 0xFF
        envelope["ciphertext"] = base64.b64encode(bytes(ct)).decode()

        with pytest.raises(Exception):
            decrypt_for_device(envelope, self.bob_dev, self.alice["ik_pub_der"])

    def test_tampered_tag_fails(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "data"},
        )
        tag = bytearray(base64.b64decode(envelope["tag"]))
        tag[0] ^= 0xFF
        envelope["tag"] = base64.b64encode(bytes(tag)).decode()

        with pytest.raises(Exception):
            decrypt_for_device(envelope, self.bob_dev, self.alice["ik_pub_der"])


# ══════════════════════════════════════════════════════════════
# 场景 7：签名篡改检测
# ══════════════════════════════════════════════════════════════

class TestSignatureTamper:
    """sender_signature 篡改 → 验签失败"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.bob_dev = make_device_with_spk(self.bob, "dev-bob-1")

    def test_tampered_signature_fails(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "data"},
        )
        sig = bytearray(base64.b64decode(envelope["sender_signature"]))
        sig[0] ^= 0xFF
        envelope["sender_signature"] = base64.b64encode(bytes(sig)).decode()

        with pytest.raises(ValueError, match="signature"):
            decrypt_for_device(envelope, self.bob_dev, self.alice["ik_pub_der"])

    def test_wrong_sender_key_fails(self):
        """用错误的 sender 公钥验签 → 失败"""
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "data"},
        )
        # 用 Bob 的公钥验 Alice 的签名
        with pytest.raises(ValueError, match="signature"):
            decrypt_for_device(envelope, self.bob_dev, self.bob["ik_pub_der"])


# ══════════════════════════════════════════════════════════════
# 场景 8：recipients 篡改检测
# ══════════════════════════════════════════════════════════════

class TestRecipientsTamper:
    """recipients 篡改 → digest 不匹配"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.bob_dev = make_device_with_spk(self.bob, "dev-bob-1")

    def test_tampered_wrapped_key_fails(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "data"},
        )
        # 篡改 wrapped_key
        envelope["recipients"][0][7] = base64.b64encode(b"\x00" * 48).decode()

        with pytest.raises(ValueError, match="digest"):
            decrypt_for_device(envelope, self.bob_dev, self.alice["ik_pub_der"])

    def test_tampered_recipients_digest_fails(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "data"},
        )
        # 篡改 digest 本身
        envelope["recipients_digest"] = "0" * 64

        with pytest.raises(ValueError):
            decrypt_for_device(envelope, self.bob_dev, self.alice["ik_pub_der"])


# ══════════════════════════════════════════════════════════════
# 场景 9：非目标设备无法解密
# ══════════════════════════════════════════════════════════════

class TestNonRecipient:
    """Carol 不在 recipients 中 → 无法解密"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        self.carol = make_identity("carol")
        self.bob_dev = make_device_with_spk(self.bob, "dev-bob-1")
        self.carol_dev = make_device_with_spk(self.carol, "dev-carol-1")

    def test_carol_cannot_decrypt(self):
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "only for bob"},
        )
        # Carol 不在 recipients 中 → 返回 None
        result = decrypt_for_device(envelope, self.carol_dev, self.alice["ik_pub_der"])
        assert result is None

    def test_carol_with_bobs_device_id_still_fails(self):
        """Carol 伪造 device_id 与 Bob 相同 → 仍无法解密（私钥不同）"""
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev]),
            payload={"secret": "only for bob"},
        )
        # Carol 用 Bob 的 device_id 但自己的私钥
        fake_device = {
            "aid": self.bob["aid"],  # 冒充 Bob 的 AID
            "device_id": "dev-bob-1",
            "ik_priv": self.carol["ik_priv"],  # 但用 Carol 的私钥
            "spk_priv": self.carol_dev["spk_priv"],
        }
        # 签名验证会通过（用正确的 sender pub），但 ECDH 共享秘密不同 → AES-GCM 解密失败
        with pytest.raises(Exception):
            decrypt_message(
                envelope=envelope,
                self_aid=fake_device["aid"],
                self_device_id=fake_device["device_id"],
                self_ik_priv=fake_device["ik_priv"],
                self_spk_priv=fake_device["spk_priv"],
                sender_pub_der=self.alice["ik_pub_der"],
            )


# ══════════════════════════════════════════════════════════════
# 场景 10：SPK 轮换后旧消息仍可解
# ══════════════════════════════════════════════════════════════

class TestSPKRotationOldMessages:
    """接收方轮换 SPK 后，用旧 SPK 加密的消息仍可解（保留旧私钥）"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        # Bob 初始 SPK
        self.bob_dev_v1 = make_device_with_spk(self.bob, "dev-bob-1")

    def test_old_spk_message_still_decryptable(self):
        # 用旧 SPK 加密
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev_v1]),
            payload={"msg": "before rotation"},
        )

        # Bob 轮换 SPK（生成新的）
        bob_dev_v2 = make_device_with_spk(self.bob, "dev-bob-1")
        # 但 Bob 仍保留旧 SPK 私钥
        old_spk_priv = self.bob_dev_v1["spk_priv"]

        # 用旧 SPK 私钥解密旧消息 → 成功
        result = decrypt_message(
            envelope=envelope,
            self_aid=self.bob["aid"],
            self_device_id="dev-bob-1",
            self_ik_priv=self.bob["ik_priv"],
            self_spk_priv=old_spk_priv,
            sender_pub_der=self.alice["ik_pub_der"],
        )
        assert result == {"msg": "before rotation"}


# ══════════════════════════════════════════════════════════════
# 场景 11：SPK 轮换后新消息用新 SPK
# ══════════════════════════════════════════════════════════════

class TestSPKRotationNewMessages:
    """轮换后发送方用新 SPK 加密 → 接收方用新 SPK 私钥解密"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")

    def test_new_spk_message_decryptable(self):
        # Bob 新 SPK
        bob_dev_new = make_device_with_spk(self.bob, "dev-bob-1")

        # Alice 用新 SPK 加密
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([bob_dev_new]),
            payload={"msg": "after rotation"},
        )

        # Bob 用新 SPK 私钥解密
        result = decrypt_for_device(envelope, bob_dev_new, self.alice["ik_pub_der"])
        assert result == {"msg": "after rotation"}


# ══════════════════════════════════════════════════════════════
# 场景 12：发送方缓存旧 SPK 仍可用
# ══════════════════════════════════════════════════════════════

class TestSenderCachedOldSPK:
    """发送方缓存了旧 SPK，接收方未销毁  仍可解"""

    def setup_method(self):
        self.alice = make_identity("alice")
        self.bob = make_identity("bob")
        # Bob 旧 SPK（发送方缓存的）
        self.bob_dev_old = make_device_with_spk(self.bob, "dev-bob-1")
        # Bob 新 SPK（已轮换但发送方不知道）
        self.bob_dev_new = make_device_with_spk(self.bob, "dev-bob-1")

    def test_cached_old_spk_still_works(self):
        # Alice 用缓存的旧 SPK 加密
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev_old]),
            payload={"msg": "sent with cached old spk"},
        )

        # Bob 用旧 SPK 私钥解密（未销毁）
        result = decrypt_message(
            envelope=envelope,
            self_aid=self.bob["aid"],
            self_device_id="dev-bob-1",
            self_ik_priv=self.bob["ik_priv"],
            self_spk_priv=self.bob_dev_old["spk_priv"],
            sender_pub_der=self.alice["ik_pub_der"],
        )
        assert result == {"msg": "sent with cached old spk"}

    def test_new_spk_priv_cannot_decrypt_old_spk_message(self):
        """新 SPK 私钥无法解密用旧 SPK 加密的消息"""
        envelope = encrypt_p2p_message(
            sender=self.alice,
            target_set=make_target_set([self.bob_dev_old]),
            payload={"msg": "old spk"},
        )

        # 用新 SPK 私钥尝试解密 → 失败
        with pytest.raises(Exception):
            decrypt_message(
                envelope=envelope,
                self_aid=self.bob["aid"],
                self_device_id="dev-bob-1",
                self_ik_priv=self.bob["ik_priv"],
                self_spk_priv=self.bob_dev_new["spk_priv"],
                sender_pub_der=self.alice["ik_pub_der"],
            )
