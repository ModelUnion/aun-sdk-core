package aun

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// traceSpanDetailFields 用于 trace span 展示的业务字段白名单
var traceSpanDetailFields = []string{
	"method", "route", "namespace", "instance_id", "aid", "caller_aid",
	"peer_aid", "to_aid", "from_aid", "group_id", "message_id", "event",
	"status", "error_code", "error_msg", "found", "delivered_count",
	"success", "created", "connection_id", "device_id", "slot_id",
	"key_source", "spk_id", "curve", "lifecycle_state", "auth_method",
}

// sortTraceSpansForDisplay 按因果顺序排序 trace spans。
//
// 不按绝对 ts 全局排序：客户端、Gateway、服务模块可能存在毫秒级时钟偏差，
// 纯 ts 排序会把 sdk.recv 排到服务端处理之前。这里使用固定链路阶段排序，
// 并在同一阶段内保持服务端返回的原始嵌套顺序。
func sortTraceSpansForDisplay(spans []map[string]any) []map[string]any {
	type indexed struct {
		idx  int
		span map[string]any
	}
	items := make([]indexed, 0, len(spans))
	for i, span := range spans {
		if span != nil {
			items = append(items, indexed{idx: i, span: span})
		}
	}

	sort.SliceStable(items, func(a, b int) bool {
		stageA := spanStage(items[a].span)
		stageB := spanStage(items[b].span)
		if stageA != stageB {
			return stageA < stageB
		}
		return items[a].idx < items[b].idx
	})

	result := make([]map[string]any, len(items))
	for i, item := range items {
		result[i] = item.span
	}
	return result
}

// spanStage 返回 span 的因果阶段编号
func spanStage(span map[string]any) int {
	node, _ := span["node"].(string)
	action, _ := span["action"].(string)
	if action == "" {
		action = "process"
	}
	switch {
	case node == "sdk" && action == "send":
		return 0
	case node == "gateway" && (action == "relay_in" || action == "enter"):
		return 10
	case node == "gateway" && (action == "relay_out" || action == "exit"):
		return 90
	case node == "sdk" && action == "recv":
		return 100
	default:
		return 50
	}
}

// traceLogicalOffsets 为已排序 spans 生成单调逻辑时间偏移。
//
// 服务端时钟可能整体领先或落后 SDK。这里保留服端内部相对间隔，
// 并把服务端片段放进 SDK 总耗时窗口内。
func traceLogicalOffsets(spans []map[string]any) []int {
	// 找 sdk.recv 的 ms 作为总耗时窗口
	totalMs := -1
	for _, span := range spans {
		node, _ := span["node"].(string)
		action, _ := span["action"].(string)
		if node == "sdk" && action == "recv" {
			if ms, ok := toInt(span["ms"]); ok && ms >= 0 {
				totalMs = ms
				break
			}
		}
	}

	// 收集服务端 ts
	var serverTs []int
	for _, span := range spans {
		node, _ := span["node"].(string)
		if node == "sdk" {
			continue
		}
		if ts, ok := toInt(span["ts"]); ok && ts > 0 {
			serverTs = append(serverTs, ts)
		}
	}

	var serverMin, serverMax int
	if len(serverTs) > 0 {
		serverMin = serverTs[0]
		serverMax = serverTs[0]
		for _, ts := range serverTs[1:] {
			if ts < serverMin {
				serverMin = ts
			}
			if ts > serverMax {
				serverMax = ts
			}
		}
	}
	serverDur := serverMax - serverMin

	var serverBase float64
	var serverScale float64 = 1.0
	if totalMs >= 0 && len(serverTs) > 0 {
		if serverDur > totalMs && serverDur > 0 {
			serverBase = 0
			serverScale = float64(totalMs) / float64(serverDur)
		} else {
			serverBase = float64(max(0, totalMs-serverDur))
			serverScale = 1.0
		}
	}

	offsets := make([]int, len(spans))
	lastOffset := 0
	for idx, span := range spans {
		node, _ := span["node"].(string)
		action, _ := span["action"].(string)
		ts, hasTs := toInt(span["ts"])

		var offset int
		switch {
		case node == "sdk" && action == "send":
			offset = 0
		case node == "sdk" && action == "recv" && totalMs >= 0:
			offset = totalMs
		case node != "sdk" && len(serverTs) > 0 && hasTs && ts > 0:
			offset = int(math.Round(serverBase + float64(ts-serverMin)*serverScale))
		default:
			if idx == 0 {
				offset = 0
			} else {
				offset = lastOffset
			}
		}
		// 保证单调递增
		if offset < lastOffset {
			offset = lastOffset
		}
		offsets[idx] = offset
		lastOffset = offset
	}
	return offsets
}

// formatTraceFields 遍历 traceSpanDetailFields，输出 key=value 格式
func formatTraceFields(span map[string]any) string {
	var parts []string
	for _, key := range traceSpanDetailFields {
		v, exists := span[key]
		if !exists || v == nil {
			continue
		}
		s := fmt.Sprintf("%v", v)
		if s == "" {
			continue
		}
		if len(s) > 48 {
			s = s[:45] + "..."
		}
		parts = append(parts, fmt.Sprintf("%s=%s", key, s))
	}
	return strings.Join(parts, " ")
}

// formatTraceTree 将 span 列表格式化为树状结构字符串。
//
// 按因果顺序展示，维护栈识别嵌套，enter/exit 配对显示。
// 输出使用以 sdk.send 为 0 点的逻辑时间 +Nms，避免跨进程时钟偏差造成倒序。
func formatTraceTree(spans []map[string]any) string {
	if len(spans) == 0 {
		return ""
	}

	sortedSpans := sortTraceSpansForDisplay(spans)
	offsets := traceLogicalOffsets(sortedSpans)

	var lines []string
	type stackEntry struct {
		node string
		span map[string]any
	}
	var stack []stackEntry

	for idx, span := range sortedSpans {
		node, _ := span["node"].(string)
		if node == "" {
			node = "?"
		}
		action, _ := span["action"].(string)
		if action == "" {
			action = "process"
		}
		timePart := fmt.Sprintf(" +%dms", offsets[idx])

		switch action {
		case "enter":
			indent := strings.Repeat("  ", len(stack))
			fieldsStr := formatTraceFields(span)
			detail := ""
			if fieldsStr != "" {
				detail = " " + fieldsStr
			}
			lines = append(lines, fmt.Sprintf("%s├─ %s.enter%s%s", indent, node, detail, timePart))
			stack = append(stack, stackEntry{node: node, span: span})

		case "exit":
			if len(stack) > 0 && stack[len(stack)-1].node == node {
				stack = stack[:len(stack)-1]
			}
			indent := strings.Repeat("  ", len(stack))
			dur, _ := toInt(span["ms"])
			fieldsStr := formatTraceFields(span)
			detail := ""
			if fieldsStr != "" {
				detail = " " + fieldsStr
			}
			lines = append(lines, fmt.Sprintf("%s└─ %s.exit%s dur=%dms%s", indent, node, detail, dur, timePart))

		default:
			indent := strings.Repeat("  ", len(stack))
			fieldsStr := formatTraceFields(span)
			dur, hasDur := toInt(span["ms"])
			durPart := ""
			if hasDur {
				durPart = fmt.Sprintf(" dur=%dms", dur)
			}
			detail := ""
			if fieldsStr != "" {
				detail = " " + fieldsStr
			}
			lines = append(lines, fmt.Sprintf("%s├─ %s.%s%s%s%s", indent, node, action, detail, durPart, timePart))
		}
	}
	return strings.Join(lines, "\n")
}

// traceDisplay 生成完整的 trace 展示字符串
func traceDisplay(method, status string, durationMs int, trace map[string]any, spans []map[string]any) string {
	tree := formatTraceTree(spans)
	traceID, _ := trace["trace_id"].(string)
	header := fmt.Sprintf("[TRACE][%s][%s] total=%dms trace_id=%s", method, status, durationMs, traceID)
	if tree != "" {
		return header + "\n" + tree
	}
	return header
}

// toInt 将 any 类型转换为 int（支持 int64/float64/int）
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case uint:
		return int(n), true
	case uint64:
		return int(n), true
	default:
		return 0, false
	}
}
