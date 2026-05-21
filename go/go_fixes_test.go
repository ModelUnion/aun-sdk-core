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
