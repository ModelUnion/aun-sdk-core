"""消息序列号跟踪与空洞检测。

SeqTracker 维护按命名空间（group_id 或 conversation_id）分组的消息序列连续性：
- contiguous_seq：连续已确认的最大 seq
- max_seen_seq：见过的最大 seq
- received_seqs：已收到但尚未纳入连续前缀的 seq 集合
- pending_gaps：待补齐的空洞区间（含退避探测状态）

空洞检测逻辑：
- seq == contiguous_seq + 1 → 正常推进
- seq > contiguous_seq + 1 → 发现空洞，触发 pull 补齐
- 探测退避：1s, 3s, 10s, 30s, 60s
- 探测 5 次仍无结果 → 标记 resolved，不再拉取

推进逻辑：
- _try_advance 从 contiguous_seq+1 开始，逐个检查 received_seqs 中是否有该 seq
- 连续存在则推进，遇到空洞停止
- 已推进的 seq 从 received_seqs 中清除（控制内存）

用法：
- 群消息：key = group_id
- P2P 消息：key = my_aid 或 conversation_id（预留，当前未使用）
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


_BACKOFF_INTERVALS = [1.0, 3.0, 10.0, 30.0, 60.0]
_MAX_PROBE_COUNT = 5


@dataclass
class GapProbe:
    """单个空洞的探测状态。"""
    gap_start: int
    gap_end: int
    last_probe_at: float = 0.0
    probe_count: int = 0
    resolved: bool = False


@dataclass
class _TrackerState:
    """单个命名空间的序列跟踪状态。"""
    contiguous_seq: int = 0
    max_seen_seq: int = 0
    received_seqs: set[int] = field(default_factory=set)
    pending_gaps: dict[tuple[int, int], GapProbe] = field(default_factory=dict)


class SeqTracker:
    """消息序列号跟踪器。按命名空间（group_id 等）维护独立状态。"""

    def __init__(self) -> None:
        self._trackers: dict[str, _TrackerState] = {}

    def _get(self, ns: str) -> _TrackerState:
        t = self._trackers.get(ns)
        if t is None:
            t = _TrackerState()
            self._trackers[ns] = t
        return t

    def get_contiguous_seq(self, ns: str) -> int:
        return self._get(ns).contiguous_seq

    def get_max_seen_seq(self, ns: str) -> int:
        return self._get(ns).max_seen_seq

    def on_message_seq(self, ns: str, seq: int) -> bool:
        """记录收到的 seq，返回 True 表示需要 pull 补齐空洞。"""
        if seq <= 0:
            return False
        t = self._get(ns)

        if seq <= t.contiguous_seq:
            return False  # 重复或旧消息

        # 首次收到消息：以当前 seq 为基线，不创建历史空洞
        if t.contiguous_seq == 0 and t.max_seen_seq == 0:
            t.contiguous_seq = seq
            t.max_seen_seq = seq
            return False

        # 记录到 received_seqs
        t.received_seqs.add(seq)
        t.max_seen_seq = max(t.max_seen_seq, seq)

        if seq == t.contiguous_seq + 1:
            # 正常递进
            t.contiguous_seq = seq
            t.received_seqs.discard(seq)
            self._try_advance(t)
            return False

        # seq > contiguous_seq + 1 → 发现空洞
        gap_start = t.contiguous_seq + 1
        gap_end = seq - 1
        gap_key = (gap_start, gap_end)

        probe = t.pending_gaps.get(gap_key)
        if probe is not None:
            if probe.resolved:
                # 空洞已确认不存在，推进 contiguous 并继续
                t.contiguous_seq = max(t.contiguous_seq, probe.gap_end)
                del t.pending_gaps[gap_key]
                self._try_advance(t)
                return False
            if not self._should_probe(probe):
                return False  # 冷却中
        else:
            t.pending_gaps[gap_key] = GapProbe(gap_start=gap_start, gap_end=gap_end)

        return True

    def on_pull_result(self, ns: str, pulled_messages: list[dict]) -> None:
        """pull 返回后更新 tracker 状态。"""
        t = self._get(ns)
        pulled_seqs: set[int] = set()
        for m in pulled_messages:
            s = m.get("seq")
            if isinstance(s, int) and s > 0:
                pulled_seqs.add(s)

        # 将 pulled 的 seq 加入 received_seqs
        t.received_seqs.update(pulled_seqs)

        now = time.monotonic()
        for gap_key in list(t.pending_gaps):
            probe = t.pending_gaps[gap_key]
            if probe.resolved:
                continue
            probe.last_probe_at = now
            probe.probe_count += 1

            gap_range = set(range(probe.gap_start, probe.gap_end + 1))
            if gap_range <= pulled_seqs:
                # 完全补齐
                probe.resolved = True
            elif not (gap_range & pulled_seqs) and probe.probe_count >= 3:
                # 连续 3 次没拉到任何空洞内的消息 → 认定不存在
                probe.resolved = True

        t.max_seen_seq = max(t.max_seen_seq, max(pulled_seqs) if pulled_seqs else 0)
        self._try_advance(t)

    def _try_advance(self, t: _TrackerState) -> None:
        """从 contiguous_seq+1 开始，连续推进所有已收到的 seq。"""
        # 先清理已解决的空洞
        changed = True
        while changed:
            changed = False
            for gap_key in list(t.pending_gaps):
                probe = t.pending_gaps[gap_key]
                if probe.resolved and probe.gap_start <= t.contiguous_seq + 1:
                    t.contiguous_seq = max(t.contiguous_seq, probe.gap_end)
                    del t.pending_gaps[gap_key]
                    changed = True

        # 从 contiguous+1 逐个推进（检查 received_seqs）
        while (t.contiguous_seq + 1) in t.received_seqs:
            t.contiguous_seq += 1
            t.received_seqs.discard(t.contiguous_seq)

    @staticmethod
    def _should_probe(probe: GapProbe) -> bool:
        """判断是否应该再次探测（指数退避）。"""
        if probe.probe_count >= _MAX_PROBE_COUNT:
            probe.resolved = True
            return False
        now = time.monotonic()
        idx = min(probe.probe_count, len(_BACKOFF_INTERVALS) - 1)
        interval = _BACKOFF_INTERVALS[idx]
        return now - probe.last_probe_at >= interval

    def export_state(self) -> dict[str, int]:
        """导出各命名空间的 contiguous_seq，用于持久化。"""
        return {ns: t.contiguous_seq for ns, t in self._trackers.items() if t.contiguous_seq > 0}

    def restore_state(self, state: dict[str, int]) -> None:
        """从持久化数据恢复各命名空间的 contiguous_seq。"""
        for ns, seq in state.items():
            if isinstance(seq, int) and seq > 0:
                t = self._get(ns)
                t.contiguous_seq = max(t.contiguous_seq, seq)
                t.max_seen_seq = max(t.max_seen_seq, seq)
