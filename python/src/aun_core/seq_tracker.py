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
# S2: 删除"probe_count >= 5 强制 resolved"的硬限制。resolved 只应由"完整补齐"或
# 服务端明确 tombstone 驱动，否则漏消息窗口里所有 gap 都会在探测 5 次后被静默放弃。
# 保留 _MAX_PROBE_COUNT 变量仅用作退避索引上限。
_MAX_PROBE_COUNT = 5
# received_seqs 内存上限：超过此值时强制跳过空洞推进 contiguous_seq
_RECEIVED_SEQS_LIMIT = 5000


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

    def update_max_seen(self, ns: str, seq: int) -> None:
        """Push 专用：只扩展上界 max_seen_seq，不动 contiguous_seq。

        语义：服务端告诉 SDK"我有 seq 这条消息"，SDK 仅更新已知上界。
        消息内容是否解密成功、是否进入连续前缀，由 pull/decrypt 路径决定。

        防御：
        - seq <= 0 直接忽略（防御负数/恶意值）
        - 不会让 max_seen_seq 倒退（仅取 max）
        """
        if seq <= 0:
            return
        t = self._get(ns)
        if seq > t.max_seen_seq:
            t.max_seen_seq = seq

    def set_baseline(self, ns: str, baseline_seq: int) -> None:
        """S2: 从持久化（keystore 最近 ack seq）恢复 baseline，
        以便首条 push 消息能构造 [baseline+1, seq-1] 的历史 gap。
        必须在收到首条消息前调用（否则 (0,0) 自动 baseline 会跳过历史）。
        """
        if baseline_seq <= 0:
            return
        t = self._get(ns)
        if t.contiguous_seq == 0 and t.max_seen_seq == 0:
            t.contiguous_seq = baseline_seq
            t.max_seen_seq = baseline_seq

    def on_message_seq(self, ns: str, seq: int) -> bool:
        """记录收到的 seq，返回 True 表示需要 pull 补齐空洞。"""
        if seq <= 0:
            return False
        t = self._get(ns)

        if seq <= t.contiguous_seq:
            return False  # 重复或旧消息

        # S2: 首次收到消息（且未通过 set_baseline 初始化）时，必须构造 [1, seq-1] gap，
        # 触发补洞拉取离线期积压的历史消息，而不是直接把 seq 作为 baseline 丢弃历史。
        if t.contiguous_seq == 0 and t.max_seen_seq == 0:
            if seq == 1:
                t.contiguous_seq = seq
                t.max_seen_seq = seq
                return False
            # seq > 1 → 视作存在 [1, seq-1] 的历史空洞
            t.max_seen_seq = seq
            t.received_seqs.add(seq)
            gap_key = (1, seq - 1)
            t.pending_gaps[gap_key] = GapProbe(gap_start=1, gap_end=seq - 1)
            return True

        # 记录到 received_seqs
        t.received_seqs.add(seq)
        t.max_seen_seq = max(t.max_seen_seq, seq)

        # 内存保护：received_seqs 超过上限时，强制跳过空洞推进 contiguous_seq
        if len(t.received_seqs) > _RECEIVED_SEQS_LIMIT:
            self._force_compact(t)

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

    def on_pull_result(self, ns: str, pulled_messages: list[dict], *, after_seq: int | None = None) -> None:
        """pull 返回后更新 tracker 状态。

        after_seq: pull 请求使用的 after_seq 参数。如果等于当前 contiguous_seq（gap fill 场景），
        直接把 pull 到的最大 seq 作为新的 contiguous_seq——服务端返回的就是当前可用的全部消息，
        中间的空洞是永久性的（竞态跳跃/未持久化/过期清理），不应阻塞后续消息投递。
        """
        t = self._get(ns)
        pulled_seqs: set[int] = set()
        for m in pulled_messages:
            s = m.get("seq")
            if not (isinstance(s, int) and s > 0):
                s = m.get("event_seq")
            if isinstance(s, int) and s > 0:
                pulled_seqs.add(s)

        # 将 pulled 的 seq 加入 received_seqs
        t.received_seqs.update(pulled_seqs)

        # gap fill 场景：从 contiguous_seq 开始 pull，直接推进到 pull 返回的最大 seq
        if pulled_seqs and after_seq is not None and after_seq == t.contiguous_seq:
            max_pulled = max(pulled_seqs)
            if max_pulled > t.contiguous_seq:
                t.contiguous_seq = max_pulled
                # 清理被跳过区间内的 pending_gaps 和 received_seqs
                for gap_key in list(t.pending_gaps):
                    probe = t.pending_gaps[gap_key]
                    if probe.gap_end <= t.contiguous_seq:
                        del t.pending_gaps[gap_key]
                t.received_seqs = {s for s in t.received_seqs if s > t.contiguous_seq}

        now = time.monotonic()
        for gap_key in list(t.pending_gaps):
            probe = t.pending_gaps[gap_key]
            if probe.resolved:
                continue
            probe.last_probe_at = now
            probe.probe_count += 1

            gap_range = set(range(probe.gap_start, probe.gap_end + 1))
            if gap_range <= pulled_seqs:
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

    def _force_compact(self, t: _TrackerState) -> None:
        """内存保护：received_seqs 超限时强制跳过空洞推进 contiguous_seq。"""
        min_seq = min(t.received_seqs)
        t.contiguous_seq = min_seq - 1
        # 正常推进
        while (t.contiguous_seq + 1) in t.received_seqs:
            t.contiguous_seq += 1
            t.received_seqs.discard(t.contiguous_seq)
        # 清理被跳过区间内的 pending_gaps（gap_end <= 最终 contiguous_seq）
        for gap_key in list(t.pending_gaps):
            if gap_key[1] <= t.contiguous_seq:
                del t.pending_gaps[gap_key]

    @staticmethod
    def _should_probe(probe: GapProbe) -> bool:
        """判断是否应该再次探测（指数退避）。

        S2: 不再以 probe_count >= _MAX_PROBE_COUNT 为由将 probe 标记为 resolved，
        避免 5 次拉取失败后历史消息被永久丢弃。这里仅决定"是否到下一次探测时间"，
        超出 backoff 表长度后按最长间隔（60s）持续重试。
        """
        now = time.monotonic()
        idx = min(probe.probe_count, len(_BACKOFF_INTERVALS) - 1)
        interval = _BACKOFF_INTERVALS[idx]
        return now - probe.last_probe_at >= interval

    def mark_gap_resolved_by_tombstone(self, ns: str, gap_start: int, gap_end: int) -> None:
        """S2: 服务端明确告知某区间无消息（tombstone），才将 gap 标记为 resolved。"""
        t = self._get(ns)
        for gap_key in list(t.pending_gaps):
            probe = t.pending_gaps[gap_key]
            # 完全覆盖的 gap 才算由服务端 tombstone 解决
            if probe.gap_start >= gap_start and probe.gap_end <= gap_end:
                probe.resolved = True
        self._try_advance(t)

    def export_state(self) -> dict[str, int]:
        """导出各命名空间的 contiguous_seq，用于持久化。"""
        return {ns: t.contiguous_seq for ns, t in self._trackers.items() if t.contiguous_seq > 0}

    def has_pending_gaps(self, ns: str) -> bool:
        """检查指定命名空间是否有未解决的空洞。

        用于 Pull 返回空时判断是否有 Push 通知标记的上界（双重修复机制）。
        """
        t = self._trackers.get(ns)
        if not t:
            return False
        # 检查是否有未解决的 pending_gaps 或 received_seqs 中有跳跃
        return bool(t.pending_gaps) or bool(t.received_seqs)

    def force_contiguous_seq(self, ns: str, seq: int) -> None:
        """Pull 专用：强制推进 contiguous_seq（已连续到达的下界）。

        语义：用于 pull 返回 server_ack_seq 后跳过被 GC/已 ack 的历史区间。
        仅增不减（防御 server_ack 倒退）。

        防御：
        - seq <= 0 直接忽略（防御负数/恶意值）
        - 仅推进，不倒退（与 max_seen_seq 共同维护不变式 contiguous_seq ≤ max_seen_seq）
        """
        if seq <= 0:
            return
        t = self._get(ns)
        if seq > t.contiguous_seq:
            # 清除被跳过区间内的 pending_gaps
            for gap_key in list(t.pending_gaps):
                if gap_key[1] <= seq:
                    del t.pending_gaps[gap_key]
            # 清除被跳过区间内的 received_seqs
            t.received_seqs = {s for s in t.received_seqs if s > seq}
            t.contiguous_seq = seq
            t.max_seen_seq = max(t.max_seen_seq, seq)
            self._try_advance(t)

    def repair_contiguous_seq(self, ns: str, seq: int) -> None:
        """脏数据修复：允许 contiguous_seq 倒退到指定值。

        仅在以下场景使用：
        - Push 路径检测到 contiguous_seq > push_seq（contiguous_seq 被之前的脏数据污染）
        - 持久化恢复后发现 contiguous_seq > 服务端真实最大值

        与 force_contiguous_seq 的区别：force_contiguous_seq 只增不减；本方法允许倒退修复。

        防御：
        - seq < 0 视为 0（不允许负数）
        - 倒退后 received_seqs / pending_gaps 重置（已知状态作废）
        """
        if seq < 0:
            seq = 0
        t = self._get(ns)
        if seq < t.contiguous_seq:
            # 倒退修复：重置 received_seqs（之前认为已收到的 seq 可能是脏数据）
            t.received_seqs = {s for s in t.received_seqs if s > seq}
            # 清除所有覆盖被倒退区间的 pending_gaps
            for gap_key in list(t.pending_gaps):
                if gap_key[0] > seq:
                    # 保留：此 gap 在新 contiguous_seq 之后
                    continue
                del t.pending_gaps[gap_key]
            t.contiguous_seq = seq
            # max_seen_seq 不动（push 已经告诉我们上界存在）

    def remove_namespace(self, ns: str) -> None:
        """移除指定命名空间的所有跟踪状态（dissolve/leave 时调用）。"""
        self._trackers.pop(ns, None)

    def restore_state(self, state: dict[str, int]) -> None:
        """从持久化数据恢复各命名空间的 contiguous_seq。

        防御：
        - seq <= 0 跳过（防御负数/恶意值）
        - 仅取 max（防御回退/竞态）
        - 同步更新 max_seen_seq 保持不变式
        """
        for ns, seq in state.items():
            if isinstance(seq, int) and seq > 0:
                t = self._get(ns)
                t.contiguous_seq = max(t.contiguous_seq, seq)
                t.max_seen_seq = max(t.max_seen_seq, seq)
