package aun

import (
	"strings"
	"testing"
)

func TestSortTraceSpansForDisplay(t *testing.T) {
	spans := []map[string]any{
		{"node": "gateway", "action": "enter", "ts": int64(1000)},
		{"node": "sdk", "action": "send", "ts": int64(900)},
		{"node": "auth", "action": "enter", "ts": int64(1001)},
		{"node": "auth", "action": "exit", "ts": int64(1002)},
		{"node": "gateway", "action": "exit", "ts": int64(1003)},
		{"node": "sdk", "action": "recv", "ts": int64(1100), "ms": int64(200)},
	}

	sorted := sortTraceSpansForDisplay(spans)
	if len(sorted) != 6 {
		t.Fatalf("expected 6 spans, got %d", len(sorted))
	}

	// sdk.send 应该排第一
	if sorted[0]["node"] != "sdk" || sorted[0]["action"] != "send" {
		t.Errorf("first span should be sdk.send, got %s.%s", sorted[0]["node"], sorted[0]["action"])
	}
	// gateway.enter 应该排第二
	if sorted[1]["node"] != "gateway" || sorted[1]["action"] != "enter" {
		t.Errorf("second span should be gateway.enter, got %s.%s", sorted[1]["node"], sorted[1]["action"])
	}
	// auth spans (stage 50) 在中间
	if sorted[2]["node"] != "auth" || sorted[2]["action"] != "enter" {
		t.Errorf("third span should be auth.enter, got %s.%s", sorted[2]["node"], sorted[2]["action"])
	}
	// gateway.exit 在 stage 90
	if sorted[4]["node"] != "gateway" || sorted[4]["action"] != "exit" {
		t.Errorf("fifth span should be gateway.exit, got %s.%s", sorted[4]["node"], sorted[4]["action"])
	}
	// sdk.recv 应该排最后
	if sorted[5]["node"] != "sdk" || sorted[5]["action"] != "recv" {
		t.Errorf("last span should be sdk.recv, got %s.%s", sorted[5]["node"], sorted[5]["action"])
	}
}

func TestTraceLogicalOffsets_Monotonic(t *testing.T) {
	spans := []map[string]any{
		{"node": "sdk", "action": "send", "ts": int64(1000)},
		{"node": "gateway", "action": "enter", "ts": int64(5000)},
		{"node": "auth", "action": "enter", "ts": int64(5001)},
		{"node": "auth", "action": "exit", "ts": int64(5010), "ms": int64(9)},
		{"node": "gateway", "action": "exit", "ts": int64(5015), "ms": int64(15)},
		{"node": "sdk", "action": "recv", "ts": int64(1050), "ms": int64(50)},
	}

	offsets := traceLogicalOffsets(spans)
	if len(offsets) != 6 {
		t.Fatalf("expected 6 offsets, got %d", len(offsets))
	}

	// sdk.send 应该是 0
	if offsets[0] != 0 {
		t.Errorf("sdk.send offset should be 0, got %d", offsets[0])
	}
	// sdk.recv 应该是 total_ms (50)
	if offsets[5] != 50 {
		t.Errorf("sdk.recv offset should be 50, got %d", offsets[5])
	}
	// 单调递增
	for i := 1; i < len(offsets); i++ {
		if offsets[i] < offsets[i-1] {
			t.Errorf("offsets not monotonic at index %d: %d < %d", i, offsets[i], offsets[i-1])
		}
	}
}

func TestFormatTraceFields(t *testing.T) {
	span := map[string]any{
		"method":   "message.push",
		"aid":      "alice.aid.com",
		"to_aid":   "bob.aid.com",
		"status":   "ok",
		"irrelevant_field": "should not appear",
	}
	result := formatTraceFields(span)
	if !strings.Contains(result, "method=message.push") {
		t.Errorf("expected method=message.push in result: %s", result)
	}
	if !strings.Contains(result, "aid=alice.aid.com") {
		t.Errorf("expected aid=alice.aid.com in result: %s", result)
	}
	if strings.Contains(result, "irrelevant_field") {
		t.Errorf("unexpected field in result: %s", result)
	}
}

func TestFormatTraceFields_Truncation(t *testing.T) {
	span := map[string]any{
		"method": strings.Repeat("x", 100),
	}
	result := formatTraceFields(span)
	// 超过 48 字符应截断为 45 + "..."
	if len(result) > len("method=")+48 {
		t.Errorf("field value should be truncated, got len=%d: %s", len(result), result)
	}
	if !strings.HasSuffix(result, "...") {
		t.Errorf("truncated field should end with ...: %s", result)
	}
}

func TestFormatTraceTree_EnterExit(t *testing.T) {
	spans := []map[string]any{
		{"node": "sdk", "action": "send", "ts": int64(1000)},
		{"node": "gateway", "action": "enter", "ts": int64(1010), "method": "relay"},
		{"node": "auth", "action": "enter", "ts": int64(1011), "method": "verify"},
		{"node": "auth", "action": "exit", "ts": int64(1015), "ms": int64(4)},
		{"node": "gateway", "action": "exit", "ts": int64(1020), "ms": int64(10)},
		{"node": "sdk", "action": "recv", "ts": int64(1050), "ms": int64(50)},
	}

	tree := formatTraceTree(spans)
	if tree == "" {
		t.Fatal("expected non-empty tree")
	}

	lines := strings.Split(tree, "\n")
	// 应该有 6 行
	if len(lines) != 6 {
		t.Errorf("expected 6 lines, got %d:\n%s", len(lines), tree)
	}

	// 验证嵌套结构
	if !strings.Contains(lines[1], "gateway.enter") {
		t.Errorf("line 1 should contain gateway.enter: %s", lines[1])
	}
	if !strings.Contains(lines[2], "  ") && strings.Contains(lines[2], "auth.enter") {
		// auth.enter 应该有缩进
	}
	if !strings.Contains(lines[4], "gateway.exit") {
		t.Errorf("line 4 should contain gateway.exit: %s", lines[4])
	}
	if !strings.Contains(lines[4], "dur=10ms") {
		t.Errorf("gateway.exit should show dur=10ms: %s", lines[4])
	}
}

func TestTraceDisplay(t *testing.T) {
	trace := map[string]any{"trace_id": "abc123"}
	spans := []map[string]any{
		{"node": "sdk", "action": "send", "ts": int64(1000)},
		{"node": "sdk", "action": "recv", "ts": int64(1050), "ms": int64(50)},
	}

	result := traceDisplay("message.push", "ok", 50, trace, spans)
	if !strings.Contains(result, "[TRACE][message.push][ok]") {
		t.Errorf("header missing: %s", result)
	}
	if !strings.Contains(result, "total=50ms") {
		t.Errorf("total missing: %s", result)
	}
	if !strings.Contains(result, "trace_id=abc123") {
		t.Errorf("trace_id missing: %s", result)
	}
}

func TestTraceDisplay_EmptySpans(t *testing.T) {
	trace := map[string]any{"trace_id": "xyz"}
	result := traceDisplay("auth.login", "ok", 100, trace, nil)
	if strings.Contains(result, "\n") {
		t.Errorf("empty spans should produce single-line output: %s", result)
	}
	if !strings.Contains(result, "[TRACE][auth.login][ok]") {
		t.Errorf("header missing: %s", result)
	}
}
