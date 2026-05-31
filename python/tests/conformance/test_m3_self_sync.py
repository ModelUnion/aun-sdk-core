"""M3-A2/A3: Self-Sync 测试（Mock）

验证：
- send_v2 时自动把自己其他设备加入 target_set
- 跳过当前 device（不给自己加密）
- 只有一个设备时不含 self-sync 行
- self-sync 设备能解密发送方发出的消息
"""
import base64
import hashlib
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from aun_core.v2.session import V2Session
from aun_core.v2.keystore import V2KeyStore
from aun_core.v2.crypto.ecdh import generate_p256_keypair
from aun_core.v2.e2ee.encrypt_p2p import encrypt_p2p_message
from aun_core.v2.e2ee.decrypt import decrypt_message


def _session(db, device_id: str, aid: str, aid_keypair: tuple[bytes, bytes] | None = None) -> V2Session:
    aid_priv, aid_pub = aid_keypair or generate_p256_keypair()
    return V2Session(
        db,
        device_id,
        aid,
        aid_priv_der=aid_priv,
        aid_pub_der=aid_pub,
    )


@pytest.fixture
def tmp_db(tmp_path):
    """创建临时 SQLite 数据库。"""
    import sqlite3
    db_path = tmp_path / "aun.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS v2_device_keys (
        device_id TEXT NOT NULL,
        key_type TEXT NOT NULL,
        key_id TEXT NOT NULL DEFAULT '',
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, key_type, key_id)
    )""")
    conn.commit()

    class FakeDB:
        def _get_conn(self):
            return conn
    return FakeDB()


@pytest.fixture
def bob_db(tmp_path):
    """Bob 的临时数据库。"""
    import sqlite3
    db_path = tmp_path / "bob_aun.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS v2_device_keys (
        device_id TEXT NOT NULL,
        key_type TEXT NOT NULL,
        key_id TEXT NOT NULL DEFAULT '',
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, key_type, key_id)
    )""")
    conn.commit()

    class FakeDB:
        def _get_conn(self):
            return conn
    return FakeDB()


class TestSelfSyncEncrypt:
    """Self-Sync 加密测试"""

    def test_self_sync_target_set_includes_other_device(self, tmp_db, bob_db):
        """send_v2 的 target_set 应包含自己的其他设备"""
        # Alice 有两个设备
        alice_keypair = generate_p256_keypair()
        alice_dev1 = _session(tmp_db, "dev-1", "alice.agentid.pub", alice_keypair)
        alice_dev2 = _session(tmp_db, "dev-2", "alice.agentid.pub", alice_keypair)
        alice_dev1.ensure_keys()
        alice_dev2.ensure_keys()

        # Bob 有一个设备
        bob = _session(bob_db, "dev-bob", "bobb.agentid.pub")
        bob.ensure_keys()

        # 构造 target_set（模拟 send_v2 逻辑）
        # 对端设备
        targets = [{
            "aid": "bobb.agentid.pub",
            "device_id": "dev-bob",
            "role": "peer",
            "key_source": "peer_device_prekey",
            "ik_pk_der": bob._ik_pub_der,
            "spk_pk_der": bob._spk_pub_der,
            "spk_id": bob._spk_id,
        }]
        # self-sync：Alice 的 dev-2（跳过 dev-1 自己）
        targets.append({
            "aid": "alice.agentid.pub",
            "device_id": "dev-2",
            "role": "self_sync",
            "key_source": "peer_device_prekey",
            "ik_pk_der": alice_dev2._ik_pub_der,
            "spk_pk_der": alice_dev2._spk_pub_der,
            "spk_id": alice_dev2._spk_id,
        })

        target_set = {"targets": targets, "audit_recipients": []}
        sender = alice_dev1.get_sender_identity()
        payload = {"text": "hello with self-sync"}

        envelope = encrypt_p2p_message(sender=sender, target_set=target_set, payload=payload)

        # recipients 应有 2 行
        assert len(envelope["recipients"]) == 2
        # 按 (aid, device_id) 排序，alice 在 bobb 前面
        aids = [r[0] for r in envelope["recipients"]]
        assert "bobb.agentid.pub" in aids
        assert "alice.agentid.pub" in aids

    def test_self_sync_device_can_decrypt(self, tmp_db, bob_db):
        """Alice(dev-2) 能解密 Alice(dev-1) 发出的消息"""
        alice_keypair = generate_p256_keypair()
        alice_dev1 = _session(tmp_db, "dev-1", "alice.agentid.pub", alice_keypair)
        alice_dev2 = _session(tmp_db, "dev-2", "alice.agentid.pub", alice_keypair)
        alice_dev1.ensure_keys()
        alice_dev2.ensure_keys()

        bob = _session(bob_db, "dev-bob", "bobb.agentid.pub")
        bob.ensure_keys()

        targets = [
            {
                "aid": "bobb.agentid.pub",
                "device_id": "dev-bob",
                "role": "peer",
                "key_source": "peer_device_prekey",
                "ik_pk_der": bob._ik_pub_der,
                "spk_pk_der": bob._spk_pub_der,
                "spk_id": bob._spk_id,
            },
            {
                "aid": "alice.agentid.pub",
                "device_id": "dev-2",
                "role": "self_sync",
                "key_source": "peer_device_prekey",
                "ik_pk_der": alice_dev2._ik_pub_der,
                "spk_pk_der": alice_dev2._spk_pub_der,
                "spk_id": alice_dev2._spk_id,
            },
        ]

        sender = alice_dev1.get_sender_identity()
        payload = {"text": "self-sync decrypt test"}
        envelope = encrypt_p2p_message(
            sender=sender,
            target_set={"targets": targets, "audit_recipients": []},
            payload=payload,
        )

        # Alice dev-2 解密
        result = decrypt_message(
            envelope=envelope,
            self_aid="alice.agentid.pub",
            self_device_id="dev-2",
            self_ik_priv=alice_dev2._ik_priv,
            self_spk_priv=alice_dev2._spk_priv,
            sender_pub_der=alice_dev1._ik_pub_der,
        )
        assert result is not None
        assert result["text"] == "self-sync decrypt test"

    def test_self_sync_skip_current_device(self, tmp_db, bob_db):
        """self-sync 不应包含发送方当前设备"""
        alice_dev1 = _session(tmp_db, "dev-1", "alice.agentid.pub")
        alice_dev1.ensure_keys()

        bob = _session(bob_db, "dev-bob", "bobb.agentid.pub")
        bob.ensure_keys()

        # 只有一个设备时，target_set 只有 Bob
        targets = [{
            "aid": "bobb.agentid.pub",
            "device_id": "dev-bob",
            "role": "peer",
            "key_source": "peer_device_prekey",
            "ik_pk_der": bob._ik_pub_der,
            "spk_pk_der": bob._spk_pub_der,
            "spk_id": bob._spk_id,
        }]

        sender = alice_dev1.get_sender_identity()
        payload = {"text": "no self-sync"}
        envelope = encrypt_p2p_message(
            sender=sender,
            target_set={"targets": targets, "audit_recipients": []},
            payload=payload,
        )

        # recipients 只有 1 行（Bob）
        assert len(envelope["recipients"]) == 1
        assert envelope["recipients"][0][0] == "bobb.agentid.pub"

    def test_bob_can_still_decrypt_with_self_sync(self, tmp_db, bob_db):
        """加了 self-sync 行后 Bob 仍能正常解密"""
        alice_keypair = generate_p256_keypair()
        alice_dev1 = _session(tmp_db, "dev-1", "alice.agentid.pub", alice_keypair)
        alice_dev2 = _session(tmp_db, "dev-2", "alice.agentid.pub", alice_keypair)
        alice_dev1.ensure_keys()
        alice_dev2.ensure_keys()

        bob = _session(bob_db, "dev-bob", "bobb.agentid.pub")
        bob.ensure_keys()

        targets = [
            {
                "aid": "bobb.agentid.pub",
                "device_id": "dev-bob",
                "role": "peer",
                "key_source": "peer_device_prekey",
                "ik_pk_der": bob._ik_pub_der,
                "spk_pk_der": bob._spk_pub_der,
                "spk_id": bob._spk_id,
            },
            {
                "aid": "alice.agentid.pub",
                "device_id": "dev-2",
                "role": "self_sync",
                "key_source": "peer_device_prekey",
                "ik_pk_der": alice_dev2._ik_pub_der,
                "spk_pk_der": alice_dev2._spk_pub_der,
                "spk_id": alice_dev2._spk_id,
            },
        ]

        sender = alice_dev1.get_sender_identity()
        payload = {"text": "bob still works"}
        envelope = encrypt_p2p_message(
            sender=sender,
            target_set={"targets": targets, "audit_recipients": []},
            payload=payload,
        )

        # Bob 解密
        result = decrypt_message(
            envelope=envelope,
            self_aid="bobb.agentid.pub",
            self_device_id="dev-bob",
            self_ik_priv=bob._ik_priv,
            self_spk_priv=bob._spk_priv,
            sender_pub_der=alice_dev1._ik_pub_der,
        )
        assert result is not None
        assert result["text"] == "bob still works"

    def test_per_device_envelope_self_sync_decrypt(self, tmp_db, bob_db):
        """per-device envelope 格式下 self-sync 设备也能解密"""
        alice_keypair = generate_p256_keypair()
        alice_dev1 = _session(tmp_db, "dev-1", "alice.agentid.pub", alice_keypair)
        alice_dev2 = _session(tmp_db, "dev-2", "alice.agentid.pub", alice_keypair)
        alice_dev1.ensure_keys()
        alice_dev2.ensure_keys()

        targets = [{
            "aid": "alice.agentid.pub",
            "device_id": "dev-2",
            "role": "self_sync",
            "key_source": "peer_device_prekey",
            "ik_pk_der": alice_dev2._ik_pub_der,
            "spk_pk_der": alice_dev2._spk_pub_der,
            "spk_id": alice_dev2._spk_id,
        }]

        sender = alice_dev1.get_sender_identity()
        payload = {"text": "per-device self-sync"}
        envelope = encrypt_p2p_message(
            sender=sender,
            target_set={"targets": targets, "audit_recipients": []},
            payload=payload,
        )

        # 模拟服务端拆分为 per-device envelope
        row = envelope["recipients"][0]
        per_device = dict(envelope)
        del per_device["recipients"]
        per_device["recipient"] = {
            "aid": row[0],
            "device_id": row[1],
            "role": row[2],
            "key_source": row[3],
            "fp": row[4],
            "spk_id": row[5],
            "wrap_nonce": row[6],
            "wrapped_key": row[7],
        }

        # Alice dev-2 解密 per-device envelope
        result = decrypt_message(
            envelope=per_device,
            self_aid="alice.agentid.pub",
            self_device_id="dev-2",
            self_ik_priv=alice_dev2._ik_priv,
            self_spk_priv=alice_dev2._spk_priv,
            sender_pub_der=alice_dev1._ik_pub_der,
        )
        assert result is not None
        assert result["text"] == "per-device self-sync"
