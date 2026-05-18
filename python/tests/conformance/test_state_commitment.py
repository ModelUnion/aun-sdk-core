"""
AUN E2EE V2 Conformance: state_commitment

规范引用: §6.2
state_commitment = SHA256(
  "AUN-V2-SC-v1" ||
  group_id ||
  uint32(epoch) ||
  canonical_json({
    "members": [...sorted by aid, devices sorted by device_id...],
    "audit_aids": [...sorted...],
    "join_policy_hash": "64hex" | null,
    "admin_set": {"admin_aids": [...sorted...], "threshold": 1},
    "recovery_quorum": {...} | null,
    "history_policy": "none" | "recent_N_days" | "full",
    "wrap_protocol": "3DH" | "1DH"
  })
)
"""
import hashlib
import struct
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.canonical import canonical_json
from aun_core.v2.state.commitment import compute_state_commitment


# 固定测试数据
GROUP_ID = "g-test-group.agentid.pub"
EPOCH = 12

STATE_PAYLOAD_BASIC = {
    "members": [
        {"aid": "alice.agentid.pub", "devices": [{"device_id": "dev-a1", "fp": "sha256:fp_alice_a1"}]},
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

STATE_PAYLOAD_1DH = {**STATE_PAYLOAD_BASIC, "wrap_protocol": "1DH"}

STATE_PAYLOAD_NO_AUDIT = {**STATE_PAYLOAD_BASIC, "audit_aids": []}

STATE_PAYLOAD_OPEN_GROUP = {
    **STATE_PAYLOAD_BASIC,
    "join_policy_hash": "a" * 64,
}


class TestStateCommitmentBasic:
    """state_commitment 基础计算"""

    def test_output_is_64_hex(self):
        """输出是 64 hex 字符（SHA-256）"""
        commitment = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        assert len(commitment) == 64
        int(commitment, 16)  # 合法 hex

    def test_deterministic(self):
        """同输入同输出"""
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        assert c1 == c2

    def test_different_group_id(self):
        """不同 group_id → 不同 commitment"""
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment("g-other.agentid.pub", EPOCH, STATE_PAYLOAD_BASIC)
        assert c1 != c2

    def test_different_epoch(self):
        """不同 epoch → 不同 commitment"""
        c1 = compute_state_commitment(GROUP_ID, 12, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, 13, STATE_PAYLOAD_BASIC)
        assert c1 != c2

    def test_epoch_as_uint32_big_endian(self):
        """epoch 编码为 uint32 big-endian（4 字节）"""
        # 验证方式：手动计算并比对
        prefix = b"AUN-V2-SC-v1"
        group_bytes = GROUP_ID.encode("utf-8")
        epoch_bytes = struct.pack(">I", EPOCH)
        payload_bytes = canonical_json(STATE_PAYLOAD_BASIC)
        expected = hashlib.sha256(prefix + group_bytes + epoch_bytes + payload_bytes).hexdigest()
        actual = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        assert actual == expected


class TestStateCommitmentFields:
    """state_commitment 字段变化敏感性"""

    def test_wrap_protocol_change(self):
        """wrap_protocol 变化 → commitment 变化"""
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_1DH)
        assert c1 != c2

    def test_audit_aids_change(self):
        """audit_aids 变化 → commitment 变化"""
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_NO_AUDIT)
        assert c1 != c2

    def test_join_policy_hash_change(self):
        """join_policy_hash 变化 → commitment 变化"""
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_OPEN_GROUP)
        assert c1 != c2

    def test_member_added(self):
        """新增成员 → commitment 变化"""
        payload_with_carol = {
            **STATE_PAYLOAD_BASIC,
            "members": STATE_PAYLOAD_BASIC["members"] + [
                {"aid": "carol.agentid.pub", "devices": [{"device_id": "dev-c1", "fp": "sha256:fp_carol"}]}
            ],
        }
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, payload_with_carol)
        assert c1 != c2

    def test_device_added(self):
        """新增设备 → commitment 变化"""
        payload_new_device = {
            **STATE_PAYLOAD_BASIC,
            "members": [
                {"aid": "alice.agentid.pub", "devices": [
                    {"device_id": "dev-a1", "fp": "sha256:fp_alice_a1"},
                    {"device_id": "dev-a2", "fp": "sha256:fp_alice_a2"},
                ]},
                STATE_PAYLOAD_BASIC["members"][1],
            ],
        }
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, payload_new_device)
        assert c1 != c2

    def test_admin_threshold_change(self):
        """admin threshold 变化 → commitment 变化"""
        payload_threshold_2 = {
            **STATE_PAYLOAD_BASIC,
            "admin_set": {"admin_aids": ["alice.agentid.pub", "bob.agentid.pub"], "threshold": 2},
        }
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, payload_threshold_2)
        assert c1 != c2

    def test_history_policy_change(self):
        """history_policy 变化 → commitment 变化"""
        payload_full_history = {**STATE_PAYLOAD_BASIC, "history_policy": "full"}
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, payload_full_history)
        assert c1 != c2


class TestStateCommitmentSorting:
    """state_commitment 内部排序"""

    def test_members_sorted_by_aid(self):
        """members 按 aid 排序后 commitment 不变"""
        payload_reversed = {
            **STATE_PAYLOAD_BASIC,
            "members": list(reversed(STATE_PAYLOAD_BASIC["members"])),
        }
        # compute_state_commitment 内部应先排序再序列化
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, payload_reversed)
        assert c1 == c2  # 排序后一致

    def test_devices_sorted_by_device_id(self):
        """devices 按 device_id 排序后 commitment 不变"""
        payload_reversed_devices = {
            **STATE_PAYLOAD_BASIC,
            "members": [
                STATE_PAYLOAD_BASIC["members"][0],
                {"aid": "bob.agentid.pub", "devices": [
                    {"device_id": "dev-b2", "fp": "sha256:fp_bob_b2"},
                    {"device_id": "dev-b1", "fp": "sha256:fp_bob_b1"},
                ]},
            ],
        }
        c1 = compute_state_commitment(GROUP_ID, EPOCH, STATE_PAYLOAD_BASIC)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, payload_reversed_devices)
        assert c1 == c2  # 排序后一致

    def test_audit_aids_sorted(self):
        """audit_aids 排序后 commitment 不变"""
        payload_multi_audit = {
            **STATE_PAYLOAD_BASIC,
            "audit_aids": ["z-audit.pub", "a-audit.pub"],
        }
        payload_multi_audit_sorted = {
            **STATE_PAYLOAD_BASIC,
            "audit_aids": ["a-audit.pub", "z-audit.pub"],
        }
        c1 = compute_state_commitment(GROUP_ID, EPOCH, payload_multi_audit)
        c2 = compute_state_commitment(GROUP_ID, EPOCH, payload_multi_audit_sorted)
        assert c1 == c2  # 内部排序
