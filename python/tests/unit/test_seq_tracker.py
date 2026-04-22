"""SeqTracker 单元测试。

覆盖场景：
- 正常递进
- 空洞检测
- 乱序到达 + pull 补齐
- pull 结果补齐
- 退避策略
- 永久缺失（5 次探测后 resolved）
- 多命名空间独立
"""

from __future__ import annotations

import time

from aun_core.seq_tracker import SeqTracker, GapProbe, _BACKOFF_INTERVALS, _MAX_PROBE_COUNT


class TestSeqTrackerBasic:
    """基础功能测试。"""

    def test_initial_state(self):
        """初始状态：contiguous=0, max_seen=0。"""
        t = SeqTracker()
        assert t.get_contiguous_seq("g1") == 0
        assert t.get_max_seen_seq("g1") == 0

    def test_sequential_advance(self):
        """正常递进：1,2,3 → contiguous=3。"""
        t = SeqTracker()
        for seq in [1, 2, 3]:
            need_pull = t.on_message_seq("g1", seq)
            assert need_pull is False
        assert t.get_contiguous_seq("g1") == 3
        assert t.get_max_seen_seq("g1") == 3

    def test_duplicate_seq_ignored(self):
        """重复 seq 不会影响状态。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 2)
        t.on_message_seq("g1", 1)  # 重复
        t.on_message_seq("g1", 2)  # 重复
        assert t.get_contiguous_seq("g1") == 2

    def test_zero_and_negative_seq_ignored(self):
        """seq <= 0 不处理。"""
        t = SeqTracker()
        assert t.on_message_seq("g1", 0) is False
        assert t.on_message_seq("g1", -1) is False
        assert t.get_contiguous_seq("g1") == 0


class TestSeqTrackerGapDetection:
    """空洞检测测试。"""

    def test_gap_detected(self):
        """seq=1 后 seq=3 → 检测到空洞 (2,2)，需要 pull。"""
        t = SeqTracker()
        assert t.on_message_seq("g1", 1) is False
        assert t.on_message_seq("g1", 3) is True  # 空洞 [2]
        assert t.get_contiguous_seq("g1") == 1
        assert t.get_max_seen_seq("g1") == 3

    def test_out_of_order_contiguous_partial(self):
        """乱序到达：1,3,2 → contiguous=3。
        seq=3 到达时记入 received_seqs，seq=2 推进后连续检查到 3。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)  # received_seqs={3}
        t.on_message_seq("g1", 2)  # 推进到 2 → received 有 3 → 推到 3
        assert t.get_contiguous_seq("g1") == 3
        assert t.get_max_seen_seq("g1") == 3

    def test_out_of_order_fills_via_pull(self):
        """pull 补齐空洞后也能连续推进。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)  # received_seqs={3}
        # 不发 seq=2，通过 pull 补齐
        t.on_pull_result("g1", [{"seq": 2}])
        # pull 后 received_seqs={2,3}，推进到 3
        assert t.get_contiguous_seq("g1") == 3

    def test_multiple_gaps(self):
        """多个空洞：1, 3, 5 → contiguous=1, max_seen=5。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)
        t.on_message_seq("g1", 5)
        assert t.get_contiguous_seq("g1") == 1
        assert t.get_max_seen_seq("g1") == 5

    def test_partial_fill(self):
        """部分填补：1, 5, 2 → contiguous=2（3,4 仍缺失）。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 5)
        t.on_message_seq("g1", 2)
        assert t.get_contiguous_seq("g1") == 2
        assert t.get_max_seen_seq("g1") == 5

    def test_large_gap(self):
        """大空洞：seq=1 后 seq=100 → 需要 pull。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        assert t.on_message_seq("g1", 100) is True
        assert t.get_contiguous_seq("g1") == 1
        assert t.get_max_seen_seq("g1") == 100

    def test_first_message_baseline(self):
        """S2: 首条消息 seq>1 时应构造 [1, seq-1] 历史空洞，
        避免离线期积压的历史消息被丢弃。
        """
        t = SeqTracker()
        # 首次 seq=5 → 构造 [1,4] 历史 gap，需要 pull
        assert t.on_message_seq("g1", 5) is True
        assert t.get_contiguous_seq("g1") == 0  # 历史 gap 未补齐前不推进
        assert t.get_max_seen_seq("g1") == 5
        state = t._trackers["g1"]
        assert (1, 4) in state.pending_gaps
        # 之后 seq=7 → 又一个空洞 (6,6)
        assert t.on_message_seq("g1", 7) is True
        assert t.get_contiguous_seq("g1") == 0

    def test_first_message_seq1_baseline(self):
        """S2: 首条消息 seq==1 时直接设为 baseline（无历史）。"""
        t = SeqTracker()
        assert t.on_message_seq("g1", 1) is False
        assert t.get_contiguous_seq("g1") == 1

    def test_set_baseline_skips_history(self):
        """S2: 通过 set_baseline 预置后，首条消息不会构造历史 gap。"""
        t = SeqTracker()
        t.set_baseline("g1", 4)
        assert t.get_contiguous_seq("g1") == 4
        # 首条 seq=5 正常递进，不产生历史 gap
        assert t.on_message_seq("g1", 5) is False
        assert t.get_contiguous_seq("g1") == 5


class TestSeqTrackerPullResult:
    """pull 结果补齐测试。"""

    def test_pull_fills_single_gap(self):
        """pull 返回缺失的 seq 后 contiguous 推进到 trigger_seq。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)  # 空洞 [2], trigger_seq=3
        t.on_pull_result("g1", [{"seq": 2}])
        assert t.get_contiguous_seq("g1") == 3

    def test_pull_partial_fill(self):
        """pull 只返回部分缺失 seq。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 5)  # 空洞 [2,3,4]
        t.on_pull_result("g1", [{"seq": 2}, {"seq": 3}])
        assert t.get_contiguous_seq("g1") == 3  # 4 仍缺失

    def test_pull_complete_fill(self):
        """pull 返回所有缺失 seq → contiguous 推进到 trigger seq。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 5)  # 空洞 [2,3,4], received_seqs={5}
        t.on_pull_result("g1", [{"seq": 2}, {"seq": 3}, {"seq": 4}])
        # 空洞全补齐 → resolved → contiguous 推到 4 → received 有 5 → 推到 5
        assert t.get_contiguous_seq("g1") == 5

    def test_pull_empty_result(self):
        """pull 返回空结果不影响状态。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)
        t.on_pull_result("g1", [])
        assert t.get_contiguous_seq("g1") == 1

    def test_pull_with_invalid_seq(self):
        """pull 返回无 seq 字段的消息被忽略，有效的被处理。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)  # received_seqs={3}
        t.on_pull_result("g1", [{"data": "no seq"}, {"seq": 2}])
        # seq=2 补齐空洞 → received_seqs 有 3 → 连续推到 3
        assert t.get_contiguous_seq("g1") == 3


class TestSeqTrackerBackoff:
    """退避策略测试。"""

    def test_gap_returns_true_on_creation(self):
        """空洞首次创建时返回 True（需要 pull）。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        assert t.on_message_seq("g1", 3) is True

    def test_probe_after_backoff(self):
        """退避间隔后重新探测。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)  # 创建 probe

        # 模拟 pull 结果（空的），触发 probe_count 递增
        t.on_pull_result("g1", [])

        # 模拟经过退避间隔
        state = t._trackers["g1"]
        gap_key = (2, 2)
        probe = state.pending_gaps[gap_key]
        probe.last_probe_at = time.monotonic() - 5  # 超过退避间隔 (3s for count=1)

        assert t.on_message_seq("g1", 3) is True  # 退避结束 → 可以 pull

    def test_max_probe_count_no_auto_resolve(self):
        """S2: 达到 _MAX_PROBE_COUNT 不再自动 resolved，
        仅作为退避索引上限（超出后使用最长间隔 60s 持续重试）。
        resolved 只由完整补齐或服务端 tombstone 驱动。
        """
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)

        state = t._trackers["g1"]
        gap_key = (2, 2)
        probe = state.pending_gaps[gap_key]
        probe.probe_count = _MAX_PROBE_COUNT  # 达到上限
        probe.last_probe_at = time.monotonic() - 120  # 超过 60s 退避

        # 未 resolved → 仍应触发 pull
        result = t.on_message_seq("g1", 3)
        assert result is True
        assert probe.resolved is False

    def test_tombstone_resolves_gap(self):
        """S2: 服务端通过 tombstone 明确标记区间无消息 → resolved 并推进。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 5)  # 空洞 [2,4]

        # 服务端 tombstone 告知 [2,4] 无消息
        t.mark_gap_resolved_by_tombstone("g1", 2, 4)
        # gap resolved → contiguous 推到 4 → received 有 5 → 推到 5
        assert t.get_contiguous_seq("g1") == 5

    def test_resolved_gap_advances_contiguous(self):
        """resolved 的空洞在下一条消息到达时允许 contiguous 推进。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)

        # 手动标记 resolved
        state = t._trackers["g1"]
        gap_key = (2, 2)
        state.pending_gaps[gap_key].resolved = True

        # seq=3 再次到达（或新消息 seq=4），触发递归检查
        # on_message_seq 会发现 gap(2,2) resolved → contiguous 跳到 2 → seq=3 == contiguous+1 → 推到 3
        t.on_message_seq("g1", 3)
        assert t.get_contiguous_seq("g1") == 3

    def test_three_empty_pulls_do_not_resolve_gap(self):
        """S2: 连续 pull 没命中空洞内的 seq → 不再自动 resolved，
        避免消息因探测无回应被静默放弃。仅由完整补齐或 tombstone 驱动。
        """
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 5)  # 空洞 [2,3,4]

        state = t._trackers["g1"]
        gap_key = (2, 4)
        assert gap_key in state.pending_gaps

        for _ in range(3):
            t.on_pull_result("g1", [{"seq": 10}])  # 没命中空洞

        # 不再自动 resolved，gap 仍 pending
        assert state.pending_gaps[gap_key].resolved is False
        assert t.get_contiguous_seq("g1") == 1

    def test_backoff_intervals(self):
        """退避间隔序列正确：1, 3, 10, 30, 60 秒。"""
        assert _BACKOFF_INTERVALS == [1.0, 3.0, 10.0, 30.0, 60.0]
        assert _MAX_PROBE_COUNT == 5


class TestSeqTrackerNamespace:
    """多命名空间独立测试。"""

    def test_independent_namespaces(self):
        """不同命名空间互不影响。"""
        t = SeqTracker()
        t.on_message_seq("group:g1", 1)
        t.on_message_seq("group:g1", 2)
        t.on_message_seq("group:g2", 1)
        t.on_message_seq("p2p:alice", 1)

        assert t.get_contiguous_seq("group:g1") == 2
        assert t.get_contiguous_seq("group:g2") == 1
        assert t.get_contiguous_seq("p2p:alice") == 1
        assert t.get_contiguous_seq("nonexistent") == 0

    def test_gap_in_one_ns_does_not_affect_other(self):
        """一个命名空间的空洞不影响其他。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)  # g1 有空洞
        t.on_message_seq("g2", 1)
        t.on_message_seq("g2", 2)  # g2 正常

        assert t.get_contiguous_seq("g1") == 1
        assert t.get_contiguous_seq("g2") == 2

    def test_pull_result_only_affects_target_ns(self):
        """pull 结果只影响目标命名空间。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)
        t.on_message_seq("g2", 1)
        t.on_message_seq("g2", 3)

        t.on_pull_result("g1", [{"seq": 2}])
        assert t.get_contiguous_seq("g1") == 3  # received_seqs 有 3 → 推到 3
        assert t.get_contiguous_seq("g2") == 1  # 未受影响


class TestSeqTrackerMemoryBound:
    """PY-006: received_seqs 不应无限增长。"""

    def test_received_seqs_bounded_with_permanent_gap(self):
        """当存在永久空洞时，received_seqs 不应无限增长。
        模拟：seq 2 永远不到达，但 3..10002 全部到达。
        内存保护应触发，强制跳过空洞推进 contiguous_seq。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        # 跳过 seq 2，直接发送 3..10002
        for seq in range(3, 10003):
            t.on_message_seq("g1", seq)

        state = t._get("g1")
        # 内存保护触发后，contiguous_seq 应被推进（跳过空洞 2）
        assert state.contiguous_seq == 10002
        # received_seqs 应被清空或保持在合理范围
        assert len(state.received_seqs) <= 5000
        # pending_gaps 也不应无限增长
        assert len(state.pending_gaps) <= 5000

    def test_received_seqs_cleanup_after_advance(self):
        """推进后 received_seqs 中 <= contiguous_seq 的元素应被清理。"""
        t = SeqTracker()
        t.on_message_seq("g1", 1)
        t.on_message_seq("g1", 3)
        t.on_message_seq("g1", 4)
        t.on_message_seq("g1", 5)
        # 此时 contiguous=1, received_seqs 应含 {3,4,5}
        state = t._get("g1")
        assert 3 in state.received_seqs

        # 补齐 seq 2 → 推进到 5
        t.on_message_seq("g1", 2)
        assert state.contiguous_seq == 5
        # 推进后 received_seqs 应为空
        assert len(state.received_seqs) == 0
