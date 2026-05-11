"""群组 state_hash 客户端处理测试"""
import json
import pytest


class TestComputeStateHashIntegration:
    """compute_state_hash 集成验证"""

    def test_chain_continuity_verification(self):
        """验证 state_hash 链连续性"""
        from aun_core.e2ee import compute_state_hash
        h1 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}],
            policy={"require_signature": True, "rotation_policy": "on_member_change"},
            prev_state_hash="",
        )
        h2 = compute_state_hash(
            group_id="grp_test", state_version=2, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}, {"aid": "bob.aid.com", "role": "admin"}],
            policy={"require_signature": True, "rotation_policy": "on_member_change"},
            prev_state_hash=h1,
        )
        # 用 h1 作为 prev 重算 h2 应一致
        h2_verify = compute_state_hash(
            group_id="grp_test", state_version=2, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}, {"aid": "bob.aid.com", "role": "admin"}],
            policy={"require_signature": True, "rotation_policy": "on_member_change"},
            prev_state_hash=h1,
        )
        assert h2 == h2_verify

    def test_detect_tampered_membership(self):
        """检测被篡改的成员角色"""
        from aun_core.e2ee import compute_state_hash
        h1 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}],
            policy={}, prev_state_hash="",
        )
        # 合法变更：添加 bob 为 member
        h_legit = compute_state_hash(
            group_id="grp_test", state_version=2, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}, {"aid": "bob.aid.com", "role": "member"}],
            policy={}, prev_state_hash=h1,
        )
        # 篡改：bob 变成 owner
        h_tampered = compute_state_hash(
            group_id="grp_test", state_version=2, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}, {"aid": "bob.aid.com", "role": "owner"}],
            policy={}, prev_state_hash=h1,
        )
        assert h_legit != h_tampered

    def test_key_epoch_binding(self):
        """state_hash 绑定 key_epoch，防止跨 epoch 重放"""
        from aun_core.e2ee import compute_state_hash
        members = [{"aid": "alice.aid.com", "role": "owner"}]
        h_epoch1 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=1,
            members=members, policy={}, prev_state_hash="",
        )
        h_epoch2 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=2,
            members=members, policy={}, prev_state_hash="",
        )
        assert h_epoch1 != h_epoch2

    def test_membership_snapshot_format(self):
        """membership_snapshot JSON 格式验证"""
        from aun_core.e2ee import compute_state_hash
        members = [{"aid": "alice.aid.com", "role": "owner"}, {"aid": "bob.aid.com", "role": "member"}]
        snapshot = json.dumps(members, sort_keys=False, separators=(",", ":"))
        # 从 snapshot 解析后计算 hash 应与直接传入一致
        parsed = json.loads(snapshot)
        h1 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=1,
            members=members, policy={}, prev_state_hash="",
        )
        h2 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=1,
            members=parsed, policy={}, prev_state_hash="",
        )
        assert h1 == h2

    def test_policy_snapshot_format(self):
        """policy_snapshot 规范化 JSON 验证"""
        from aun_core.e2ee import compute_state_hash
        # 不同 key 顺序应产生相同 hash
        h1 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}],
            policy={"rotation_policy": "on_member_change", "require_signature": True},
            prev_state_hash="",
        )
        h2 = compute_state_hash(
            group_id="grp_test", state_version=1, key_epoch=1,
            members=[{"aid": "alice.aid.com", "role": "owner"}],
            policy={"require_signature": True, "rotation_policy": "on_member_change"},
            prev_state_hash="",
        )
        assert h1 == h2
