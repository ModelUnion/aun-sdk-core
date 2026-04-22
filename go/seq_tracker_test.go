package aun

import (
	"testing"
)

// TestSeqTracker_BasicAdvance 基本连续推进
func TestSeqTracker_BasicAdvance(t *testing.T) {
	st := NewSeqTracker()
	ns := "test"

	// seq=1 直接推进
	needPull := st.OnMessageSeq(ns, 1)
	if needPull {
		t.Fatal("seq=1 不应触发 pull")
	}
	if got := st.GetContiguousSeq(ns); got != 1 {
		t.Fatalf("contiguousSeq 应为 1，实际 %d", got)
	}

	// seq=2 连续推进
	needPull = st.OnMessageSeq(ns, 2)
	if needPull {
		t.Fatal("seq=2 不应触发 pull")
	}
	if got := st.GetContiguousSeq(ns); got != 2 {
		t.Fatalf("contiguousSeq 应为 2，实际 %d", got)
	}
}

// TestSeqTracker_ForceCompact_TriggeredAtLimit 验证 receivedSeqs 超过上限时触发 forceCompact
func TestSeqTracker_ForceCompact_TriggeredAtLimit(t *testing.T) {
	st := NewSeqTracker()
	ns := "test"

	// 先设置 baseline，让 contiguousSeq=0, maxSeenSeq=0 的首条消息逻辑不干扰
	st.SetBaseline(ns, 0)

	// 手动设置 contiguousSeq=1（通过发送 seq=1）
	st.OnMessageSeq(ns, 1)
	if got := st.GetContiguousSeq(ns); got != 1 {
		t.Fatalf("baseline 后 contiguousSeq 应为 1，实际 %d", got)
	}

	// 跳过 seq=2，从 seq=3 开始发送大量不连续消息
	// 这样 seq=2 是空洞，seq=3..5003 都进入 receivedSeqs
	// 总共 5001 个 seq 在 receivedSeqs 中，超过 5000 上限
	for i := 3; i <= 5003; i++ {
		st.OnMessageSeq(ns, i)
	}

	// forceCompact 应该已触发：
	// 1. receivedSeqs 中最小值是 3，contiguousSeq 先设为 3-1=2
	// 2. 然后从 3 开始连续推进到 5003（因为 3..5003 都在 receivedSeqs 中）
	// 3. 最终 contiguousSeq 应为 5003
	got := st.GetContiguousSeq(ns)
	if got != 5003 {
		t.Fatalf("forceCompact 后 contiguousSeq 应为 5003，实际 %d", got)
	}

	// receivedSeqs 应该被清空（所有 seq 都已纳入连续前缀）
	st.mu.Lock()
	state := st.getState(ns)
	remaining := len(state.receivedSeqs)
	st.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("forceCompact 后 receivedSeqs 应为空，实际剩余 %d", remaining)
	}
}

// TestSeqTracker_ForceCompact_ClearsPendingGaps 验证 forceCompact 清理被跳过区间的 pendingGaps
func TestSeqTracker_ForceCompact_ClearsPendingGaps(t *testing.T) {
	st := NewSeqTracker()
	ns := "test"

	st.OnMessageSeq(ns, 1)

	// 发送 seq=3，产生 gap [2,2]
	st.OnMessageSeq(ns, 3)

	st.mu.Lock()
	state := st.getState(ns)
	gapCount := len(state.pendingGaps)
	st.mu.Unlock()
	if gapCount == 0 {
		t.Fatal("应存在 pending gap [2,2]")
	}

	// 发送大量不连续 seq 触发 forceCompact
	for i := 4; i <= 5004; i++ {
		st.OnMessageSeq(ns, i)
	}

	// forceCompact 后，gap [2,2] 应被清理（因为 gapEnd=2 <= 新的 contiguousSeq）
	st.mu.Lock()
	state = st.getState(ns)
	gapCount = len(state.pendingGaps)
	st.mu.Unlock()
	if gapCount != 0 {
		t.Fatalf("forceCompact 后 pendingGaps 应为空，实际剩余 %d", gapCount)
	}
}

// TestSeqTracker_ForceCompact_NotTriggeredBelowLimit 验证未超限时不触发 forceCompact
func TestSeqTracker_ForceCompact_NotTriggeredBelowLimit(t *testing.T) {
	st := NewSeqTracker()
	ns := "test"

	st.OnMessageSeq(ns, 1)

	// 发送 4999 个不连续 seq（跳过 seq=2），receivedSeqs 大小为 4999，不超限
	for i := 3; i <= 5001; i++ {
		st.OnMessageSeq(ns, i)
	}

	// contiguousSeq 应仍为 1（seq=2 缺失，未触发 forceCompact）
	got := st.GetContiguousSeq(ns)
	if got != 1 {
		t.Fatalf("未超限时 contiguousSeq 应为 1，实际 %d", got)
	}
}

// TestSeqTracker_ForceCompact_WithSparseSeqs 验证稀疏 seq 场景下 forceCompact 的行为
func TestSeqTracker_ForceCompact_WithSparseSeqs(t *testing.T) {
	st := NewSeqTracker()
	ns := "test"

	st.OnMessageSeq(ns, 1)

	// 发送稀疏的 seq：每隔 2 个发一个（3, 5, 7, 9, ...）
	// 需要超过 5000 个 receivedSeqs 条目
	count := 0
	seq := 3
	for count <= 5000 {
		st.OnMessageSeq(ns, seq)
		seq += 2 // 跳一个
		count++
	}

	// forceCompact 应已触发
	got := st.GetContiguousSeq(ns)
	// forceCompact 找到 receivedSeqs 中最小值（3），设 contiguousSeq=2，
	// 然后从 3 开始推进，但 4 不在 receivedSeqs 中，所以停在 3
	if got < 3 {
		t.Fatalf("forceCompact 后 contiguousSeq 至少应为 3，实际 %d", got)
	}

	// receivedSeqs 应该减少了（至少清掉了 <= contiguousSeq 的部分）
	st.mu.Lock()
	state := st.getState(ns)
	remaining := len(state.receivedSeqs)
	st.mu.Unlock()
	// 稀疏场景下只能推进 1 步（3），剩余约 5000 个
	// 关键是 forceCompact 被触发了且没有 panic
	if remaining > 5001 {
		t.Fatalf("forceCompact 后 receivedSeqs 不应增长，实际 %d", remaining)
	}
}
