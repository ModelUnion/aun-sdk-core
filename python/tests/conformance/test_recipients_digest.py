"""
AUN E2EE V2 Conformance: recipients_digest

规范引用: §10.3
- recipients_digest = SHA256(canonical_json(recipients))
- recipients 是二维数组（无 columns 表头）
- 行按 (aid asc, device_id asc, role asc) 字典序排序
- 每行固定 8 字段: [aid, device_id, role, key_source, fp, spk_id, wrap_nonce, wrapped_key]
"""
import hashlib
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.canonical import canonical_json
from aun_core.v2.crypto.recipients import compute_recipients_digest, sort_recipients


# 固定测试数据
RECIPIENTS_UNSORTED = [
    ["carol.aid", "dev-3", "member", "group_device_prekey", "sha256:fp_carol", "sha256:spk_carol", "bm9uY2UzMTIz", "d3JhcDM="],
    ["alice.aid", "dev-1", "member", "group_device_prekey", "sha256:fp_alice", "sha256:spk_alice", "bm9uY2UxMTIz", "d3JhcDE="],
    ["bob.aid", "dev-2", "member", "group_device", "sha256:fp_bob", "", "bm9uY2UyMTIz", "d3JhcDI="],
    ["audit.regulator.pub", "", "audit", "aid_master", "sha256:fp_audit", "", "bm9uY2U0MTIz", "d3JhcDQ="],
]

# 排序后期望顺序: alice → audit → bob → carol（按 aid 字典序）
RECIPIENTS_SORTED = [
    ["alice.aid", "dev-1", "member", "group_device_prekey", "sha256:fp_alice", "sha256:spk_alice", "bm9uY2UxMTIz", "d3JhcDE="],
    ["audit.regulator.pub", "", "audit", "aid_master", "sha256:fp_audit", "", "bm9uY2U0MTIz", "d3JhcDQ="],
    ["bob.aid", "dev-2", "member", "group_device", "sha256:fp_bob", "", "bm9uY2UyMTIz", "d3JhcDI="],
    ["carol.aid", "dev-3", "member", "group_device_prekey", "sha256:fp_carol", "sha256:spk_carol", "bm9uY2UzMTIz", "d3JhcDM="],
]


class TestRecipientsSort:
    """recipients 行排序"""

    def test_sort_by_aid(self):
        """按 aid 字典序排序"""
        result = sort_recipients(RECIPIENTS_UNSORTED)
        aids = [row[0] for row in result]
        assert aids == sorted(aids)

    def test_sort_preserves_row_content(self):
        """排序不改变行内容"""
        result = sort_recipients(RECIPIENTS_UNSORTED)
        assert len(result) == len(RECIPIENTS_UNSORTED)
        for row in RECIPIENTS_UNSORTED:
            assert row in result

    def test_sort_same_aid_by_device_id(self):
        """同 AID 按 device_id 排序"""
        rows = [
            ["bob.aid", "dev-2", "member", "group_device", "fp", "", "n", "w"],
            ["bob.aid", "dev-1", "member", "group_device_prekey", "fp", "spk", "n", "w"],
        ]
        result = sort_recipients(rows)
        assert result[0][1] == "dev-1"
        assert result[1][1] == "dev-2"

    def test_sort_same_aid_device_by_role(self):
        """同 AID + device_id 按 role 排序"""
        rows = [
            ["bob.aid", "dev-1", "member", "group_device", "fp", "", "n", "w"],
            ["bob.aid", "dev-1", "audit", "aid_master", "fp", "", "n", "w"],
        ]
        result = sort_recipients(rows)
        assert result[0][2] == "audit"
        assert result[1][2] == "member"


class TestRecipientsDigest:
    """recipients_digest 计算"""

    def test_digest_is_sha256_hex(self):
        """输出是 64 hex 字符"""
        digest = compute_recipients_digest(RECIPIENTS_SORTED)
        assert len(digest) == 64
        # 验证是合法 hex
        int(digest, 16)

    def test_digest_deterministic(self):
        """同输入同输出"""
        d1 = compute_recipients_digest(RECIPIENTS_SORTED)
        d2 = compute_recipients_digest(RECIPIENTS_SORTED)
        assert d1 == d2

    def test_digest_changes_on_row_change(self):
        """任一行变化 → digest 变化"""
        modified = [row[:] for row in RECIPIENTS_SORTED]
        modified[0][7] = "tampered_wrap"  # 改 wrapped_key
        d1 = compute_recipients_digest(RECIPIENTS_SORTED)
        d2 = compute_recipients_digest(modified)
        assert d1 != d2

    def test_digest_changes_on_order_change(self):
        """行顺序变化 → digest 变化（所以排序必须在计算前完成）"""
        reversed_rows = list(reversed(RECIPIENTS_SORTED))
        d1 = compute_recipients_digest(RECIPIENTS_SORTED)
        d2 = compute_recipients_digest(reversed_rows)
        assert d1 != d2

    def test_digest_includes_wrapped_key(self):
        """wrapped_key 整段纳入摘要（防 service 篡改）"""
        rows_a = [["a.aid", "d1", "member", "gd", "fp", "spk", "nonce", "wrap_original"]]
        rows_b = [["a.aid", "d1", "member", "gd", "fp", "spk", "nonce", "wrap_tampered"]]
        assert compute_recipients_digest(rows_a) != compute_recipients_digest(rows_b)

    def test_empty_recipients(self):
        """空 recipients（边界）"""
        digest = compute_recipients_digest([])
        # Merkle root 空时返回空字符串
        assert digest == ""

    def test_single_recipient(self):
        """单行 recipients"""
        rows = [["alice.aid", "dev-1", "member", "group_device_prekey", "fp", "spk", "n", "w"]]
        digest = compute_recipients_digest(rows)
        assert len(digest) == 64

    def test_manual_computation(self):
        """手动验证: Merkle root 单叶 = leaf hash"""
        from aun_core.v2.crypto.recipients import compute_leaf_hash
        rows = [["a.aid", "d1", "member", "gd", "fp", "", "n", "w"]]
        expected = compute_leaf_hash(rows[0]).hex()
        assert compute_recipients_digest(rows) == expected
