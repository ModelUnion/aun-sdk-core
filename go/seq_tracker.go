package aun

// 消息序列号跟踪与空洞检测
//
// SeqTracker 维护按命名空间（group_id 或 conversation_id）分组的消息序列连续性。
// 用法：群消息 key = "group:" + groupID，P2P 消息 key = "p2p:" + myAID

import (
	"strconv"
	"sync"
	"time"
)

var backoffIntervals = []float64{1, 3, 10, 30, 60} // 秒

// S2: 删除"probeCount >= 5 强制 resolved"的硬限制；该常量仅作 backoff 索引上限。
// resolved 只应由"完整补齐"或服务端明确 tombstone 驱动。
const maxProbeCount = 5

type gapProbe struct {
	gapStart    int
	gapEnd      int
	lastProbeAt float64 // monotonic seconds
	probeCount  int
	resolved    bool
}

type trackerState struct {
	contiguousSeq int
	maxSeenSeq    int
	receivedSeqs  map[int]bool         // 已收到但尚未纳入连续前缀的 seq
	pendingGaps   map[string]*gapProbe // key = "start:end"
}

func gapKey(start, end int) string {
	// 使用 strconv.Itoa 而非 string(rune(...))：
	// rune 转字符串会把整数当成码点，超出有效 Unicode 范围（>0x10FFFF 或 surrogate 段）时
	// 会产出 U+FFFD 替换字符，导致不同输入的 gap 映射到同一 key，出现键碰撞。
	return strconv.Itoa(start) + ":" + strconv.Itoa(end)
}

// SeqTracker 消息序列号跟踪器
type SeqTracker struct {
	mu       sync.Mutex
	trackers map[string]*trackerState
}

// NewSeqTracker 创建序列号跟踪器
func NewSeqTracker() *SeqTracker {
	return &SeqTracker{
		trackers: make(map[string]*trackerState),
	}
}

func (st *SeqTracker) getState(ns string) *trackerState {
	t := st.trackers[ns]
	if t == nil {
		t = &trackerState{
			receivedSeqs: make(map[int]bool),
			pendingGaps:  make(map[string]*gapProbe),
		}
		st.trackers[ns] = t
	}
	return t
}

// GetContiguousSeq 获取连续已确认的最大 seq
func (st *SeqTracker) GetContiguousSeq(ns string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.getState(ns).contiguousSeq
}

// GetMaxSeenSeq 获取见过的最大 seq
func (st *SeqTracker) GetMaxSeenSeq(ns string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.getState(ns).maxSeenSeq
}

// OnMessageSeq 记录收到的 seq，返回 true 表示需要 pull 补齐空洞
func (st *SeqTracker) OnMessageSeq(ns string, seq int) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.onMessageSeqLocked(ns, seq)
}

// SetBaseline S2: 从持久化（keystore 最近 ack seq）恢复 baseline，
// 以便首条 push 消息能构造 [baseline+1, seq-1] 的历史 gap。
// 必须在收到首条消息前调用。
func (st *SeqTracker) SetBaseline(ns string, baselineSeq int) {
	if baselineSeq <= 0 {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	t := st.getState(ns)
	if t.contiguousSeq == 0 && t.maxSeenSeq == 0 {
		t.contiguousSeq = baselineSeq
		t.maxSeenSeq = baselineSeq
	}
}

func (st *SeqTracker) onMessageSeqLocked(ns string, seq int) bool {
	if seq <= 0 {
		return false
	}
	t := st.getState(ns)

	if seq <= t.contiguousSeq {
		return false
	}

	// S2: 首次收到消息（且未 SetBaseline 初始化）必须构造 [1, seq-1] 历史 gap，
	// 触发补洞拉取离线期消息，而不是直接把 seq 当 baseline 丢弃历史。
	if t.contiguousSeq == 0 && t.maxSeenSeq == 0 {
		if seq == 1 {
			t.contiguousSeq = seq
			t.maxSeenSeq = seq
			return false
		}
		t.maxSeenSeq = seq
		t.receivedSeqs[seq] = true
		histKey := seqGapKey(1, seq-1)
		t.pendingGaps[histKey] = &gapProbe{gapStart: 1, gapEnd: seq - 1}
		return true
	}

	t.receivedSeqs[seq] = true
	if seq > t.maxSeenSeq {
		t.maxSeenSeq = seq
	}

	if seq == t.contiguousSeq+1 {
		t.contiguousSeq = seq
		delete(t.receivedSeqs, seq) // 已纳入连续前缀
		st.tryAdvance(t)
		return false
	}

	// 空洞
	gs := t.contiguousSeq + 1
	ge := seq - 1
	key := seqGapKey(gs, ge)

	probe, exists := t.pendingGaps[key]
	if exists {
		if probe.resolved {
			if probe.gapEnd > t.contiguousSeq {
				t.contiguousSeq = probe.gapEnd
			}
			delete(t.pendingGaps, key)
			st.tryAdvance(t)
			return false
		}
		if !st.shouldProbe(probe) {
			return false
		}
	} else {
		t.pendingGaps[key] = &gapProbe{
			gapStart: gs, gapEnd: ge,
		}
	}
	return true
}

// OnPullResult pull 返回后更新 tracker 状态
func (st *SeqTracker) OnPullResult(ns string, messages []map[string]any) {
	st.mu.Lock()
	defer st.mu.Unlock()

	t := st.getState(ns)
	pulledSeqs := make(map[int]bool)
	maxPulled := 0
	for _, m := range messages {
		s := int(toInt64(m["seq"]))
		if s > 0 {
			pulledSeqs[s] = true
			if s > maxPulled {
				maxPulled = s
			}
		}
	}

	for s := range pulledSeqs {
		t.receivedSeqs[s] = true
	}

	now := float64(time.Now().UnixNano()) / 1e9
	for key, probe := range t.pendingGaps {
		if probe.resolved {
			continue
		}
		probe.lastProbeAt = now
		probe.probeCount++

		allCovered := true
		anyHit := false
		for s := probe.gapStart; s <= probe.gapEnd; s++ {
			if pulledSeqs[s] {
				anyHit = true
			} else {
				allCovered = false
			}
		}
		if allCovered {
			probe.resolved = true
		}
		// S2: 不再因 probeCount >= 3 自动 resolved。
		_ = anyHit
		_ = key // suppress unused
	}

	if maxPulled > t.maxSeenSeq {
		t.maxSeenSeq = maxPulled
	}
	st.tryAdvance(t)
}

func (st *SeqTracker) tryAdvance(t *trackerState) {
	// 先清理已解决的空洞
	changed := true
	for changed {
		changed = false
		for key, probe := range t.pendingGaps {
			if probe.resolved && probe.gapStart <= t.contiguousSeq+1 {
				if probe.gapEnd > t.contiguousSeq {
					t.contiguousSeq = probe.gapEnd
				}
				delete(t.pendingGaps, key)
				changed = true
			}
		}
	}
	// 从 contiguous+1 逐个推进（检查 receivedSeqs）
	for t.receivedSeqs[t.contiguousSeq+1] {
		t.contiguousSeq++
		delete(t.receivedSeqs, t.contiguousSeq)
	}
}

func (st *SeqTracker) shouldProbe(probe *gapProbe) bool {
	// S2: 不再以 probeCount >= maxProbeCount 为由将 probe 置为 resolved。
	// 超出 backoff 表长度后按最长间隔持续重试。
	now := float64(time.Now().UnixNano()) / 1e9
	idx := probe.probeCount
	if idx >= len(backoffIntervals) {
		idx = len(backoffIntervals) - 1
	}
	interval := backoffIntervals[idx]
	return now-probe.lastProbeAt >= interval
}

// MarkGapResolvedByTombstone S2: 服务端明确告知某区间无消息（tombstone）→ 标 resolved
func (st *SeqTracker) MarkGapResolvedByTombstone(ns string, gapStart, gapEnd int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	t := st.getState(ns)
	for _, probe := range t.pendingGaps {
		if probe.gapStart >= gapStart && probe.gapEnd <= gapEnd {
			probe.resolved = true
		}
	}
	st.tryAdvance(t)
}

func seqGapKey(start, end int) string {
	// 使用简单字符串拼接（不导入 fmt 减少依赖）
	return intToStr(start) + ":" + intToStr(end)
}

// ForceContiguousSeq 强制跳过不连续区间，将 contiguousSeq 拨到指定位置。
// 当服务端返回 server_ack_seq 且本地 contiguousSeq 落后时调用，
// 跳过 [contiguousSeq, server_ack_seq) 这段不连续区间。
func (st *SeqTracker) ForceContiguousSeq(ns string, seq int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	t := st.getState(ns)
	if seq > t.contiguousSeq {
		// 清除被跳过区间内的 pendingGaps
		for key, probe := range t.pendingGaps {
			if probe.gapEnd <= seq {
				delete(t.pendingGaps, key)
			}
		}
		// 清除被跳过区间内的 receivedSeqs
		for s := range t.receivedSeqs {
			if s <= seq {
				delete(t.receivedSeqs, s)
			}
		}
		t.contiguousSeq = seq
		if seq > t.maxSeenSeq {
			t.maxSeenSeq = seq
		}
		st.tryAdvance(t)
	}
}

// ExportState 导出各命名空间的 contiguousSeq，用于持久化
func (st *SeqTracker) ExportState() map[string]int {
	st.mu.Lock()
	defer st.mu.Unlock()
	result := make(map[string]int)
	for ns, t := range st.trackers {
		if t.contiguousSeq > 0 {
			result[ns] = t.contiguousSeq
		}
	}
	return result
}

// RestoreState 从持久化数据恢复各命名空间的 contiguousSeq
func (st *SeqTracker) RestoreState(state map[string]int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for ns, seq := range state {
		if seq > 0 {
			t := st.getState(ns)
			if seq > t.contiguousSeq {
				t.contiguousSeq = seq
			}
			if seq > t.maxSeenSeq {
				t.maxSeenSeq = seq
			}
		}
	}
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	// 反转
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
