package aun

import "testing"

func TestEventNameMapContainsGroupMessageCreated(t *testing.T) {
	requiredEvents := []string{
		"message.received",
		"message.recalled",
		"message.ack",
		"group.changed",
		"group.message_created",
		"storage.object_changed",
	}
	for _, evt := range requiredEvents {
		if _, ok := eventNameMap[evt]; !ok {
			t.Errorf("eventNameMap 缺少 %s 映射", evt)
		}
	}
}

func TestSeqTrackerRemoveNamespace(t *testing.T) {
	st := NewSeqTracker()
	ns := "group:g-dissolved"

	st.OnMessageSeq(ns, 1)
	st.OnMessageSeq(ns, 2)
	st.OnMessageSeq(ns, 3)

	if st.GetContiguousSeq(ns) != 3 {
		t.Fatalf("contiguousSeq 应为 3，实际: %d", st.GetContiguousSeq(ns))
	}

	st.RemoveNamespace(ns)

	if st.GetContiguousSeq(ns) != 0 {
		t.Fatalf("RemoveNamespace 后 contiguousSeq 应为 0，实际: %d", st.GetContiguousSeq(ns))
	}
	if st.GetMaxSeenSeq(ns) != 0 {
		t.Fatalf("RemoveNamespace 后 maxSeenSeq 应为 0，实际: %d", st.GetMaxSeenSeq(ns))
	}
}

// TestGroupRecallDedupKeyIgnoresRecalledAt 锁定 group recall 去重键修复（#1）：
// 去重键只由 group_id 和排序后的 message_ids 构成，不含 recalled_at。
// 这样同一条撤回在不同时间点重放时仍命中同一去重键，不会被重复发布。
func TestGroupRecallDedupKeyIgnoresRecalledAt(t *testing.T) {
	// recalled_at 不同，但去重键必须相同，且等于 "grp-1|m-aaa"
	keyEarly := groupRecallDedupKey("grp-1", map[string]any{
		"message_ids": []any{"m-aaa"},
		"recalled_at": int64(1000),
	})
	keyLate := groupRecallDedupKey("grp-1", map[string]any{
		"message_ids": []any{"m-aaa"},
		"recalled_at": int64(1007),
	})
	if keyEarly != keyLate {
		t.Fatalf("recalled_at 不应影响去重键: early=%q late=%q", keyEarly, keyLate)
	}
	if keyEarly != "grp-1|m-aaa" {
		t.Fatalf("去重键格式不符: 期望 %q, 实际 %q", "grp-1|m-aaa", keyEarly)
	}

	// message_ids 顺序不同，但去重键必须相同（内部排序）
	keyOrderA := groupRecallDedupKey("grp-1", map[string]any{
		"message_ids": []any{"m-bbb", "m-aaa"},
	})
	keyOrderB := groupRecallDedupKey("grp-1", map[string]any{
		"message_ids": []any{"m-aaa", "m-bbb"},
	})
	if keyOrderA != keyOrderB {
		t.Fatalf("message_ids 顺序不应影响去重键: A=%q B=%q", keyOrderA, keyOrderB)
	}
	if keyOrderA != "grp-1|m-aaa,m-bbb" {
		t.Fatalf("排序后去重键格式不符: 期望 %q, 实际 %q", "grp-1|m-aaa,m-bbb", keyOrderA)
	}

	// 不同 message_ids 必须得到不同的去重键
	keyOther := groupRecallDedupKey("grp-1", map[string]any{
		"message_ids": []any{"m-ccc"},
	})
	if keyOther == keyEarly {
		t.Fatalf("不同 message_ids 应得到不同去重键，但都为 %q", keyOther)
	}
}
