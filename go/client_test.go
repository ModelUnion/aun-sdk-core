package aun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"nhooyr.io/websocket"
)

type testRPCCall struct {
	Method string
	Params map[string]any
}

func TestPeerCertCacheTTLIsOneHour(t *testing.T) {
	if peerCertCacheTTL != 3600 {
		t.Fatalf("peer cert cache TTL must be 3600 seconds, got %d", peerCertCacheTTL)
	}
}

func TestPublicConnectionOptionsDoNotExposeGatewayOrToken(t *testing.T) {
	forbidden := []string{
		"Gateway",
		"Gateways",
		"GatewayURL",
		"GatewayUrl",
		"AccessToken",
		"Token",
		"KiteToken",
	}
	types := []struct {
		name string
		typ  reflect.Type
	}{
		{name: "ConnectionOptions", typ: reflect.TypeOf(ConnectionOptions{})},
		{name: "ConnectOptions", typ: reflect.TypeOf(ConnectOptions{})},
	}
	for _, item := range types {
		for _, field := range forbidden {
			if _, ok := item.typ.FieldByName(field); ok {
				t.Fatalf("%s must not expose external %s; gateway/token must be resolved internally", item.name, field)
			}
		}
	}
}

func cloneRPCParamsForTest(t *testing.T, params map[string]any) map[string]any {
	t.Helper()
	if params == nil {
		return nil
	}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("序列化测试 RPC 参数失败: %v", err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatalf("反序列化测试 RPC 参数失败: %v", err)
	}
	return cloned
}

func TestOrderedP2PPublishWaitsForGapFill(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ns := "p2p:alice.example.com"
	c.seqTracker.OnMessageSeq(ns, 1)
	var received []int
	c.events.Subscribe("message.received", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received = append(received, int(toInt64(msg["seq"])))
		}
	})

	if c.publishOrderedMessage("message.received", ns, 3, map[string]any{"seq": 3}) {
		t.Fatal("seq=3 越过空洞时不应立即发布")
	}
	if len(received) != 0 {
		t.Fatalf("空洞补齐前不应发布消息: %v", received)
	}

	c.seqTracker.OnPullResult(ns, []map[string]any{{"seq": 2}, {"seq": 3}})
	if !c.publishOrderedMessage("message.received", ns, 2, map[string]any{"seq": 2}) {
		t.Fatal("seq=2 应触发有序放行")
	}
	if fmt.Sprint(received) != "[2 3]" {
		t.Fatalf("消息应按 [2 3] 顺序发布，实际: %v", received)
	}
}

func TestOrderedGroupPublishWaitsForGapFill(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ns := "group:g1"
	c.seqTracker.OnMessageSeq(ns, 1)
	var received []int
	c.events.Subscribe("group.message_created", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received = append(received, int(toInt64(msg["seq"])))
		}
	})

	if c.publishOrderedMessage("group.message_created", ns, 3, map[string]any{"seq": 3}) {
		t.Fatal("群 seq=3 越过空洞时不应立即发布")
	}
	c.seqTracker.OnPullResult(ns, []map[string]any{{"seq": 2}, {"seq": 3}})
	if !c.publishOrderedMessage("group.message_created", ns, 2, map[string]any{"seq": 2}) {
		t.Fatal("群 seq=2 应触发有序放行")
	}
	if fmt.Sprint(received) != "[2 3]" {
		t.Fatalf("群消息应按 [2 3] 顺序发布，实际: %v", received)
	}
}

func TestOrderedGroupEventPublishWaitsForGapFillAndDedups(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	groupID := "group.example.com/g-events"
	ns := "group_event:" + groupID
	c.seqTracker.OnMessageSeq(ns, 1)
	c.mu.Lock()
	c.v2State = &v2P2PState{
		bootstrapCache:      make(map[string]v2BootstrapEntry),
		groupBootstrapCache: map[string]*v2GroupBootstrapEntry{groupID: {CachedAt: time.Now()}},
	}
	c.mu.Unlock()

	var received []int
	c.events.Subscribe("group.changed", func(payload any) {
		if evt, ok := payload.(map[string]any); ok {
			received = append(received, int(toInt64(evt["event_seq"])))
		}
	})

	c.enqueueOrderedMessage(ns, "group.changed", 3, map[string]any{
		"group_id":   groupID,
		"event_seq":  3,
		"event_type": "group.member_removed",
		"action":     "member_removed",
	})
	if !c.seqTracker.OnMessageSeq(ns, 3) {
		t.Fatal("event_seq=3 越过空洞时应触发补洞")
	}
	c.drainOrderedMessages(ns)
	if len(received) != 0 {
		t.Fatalf("空洞补齐前不应发布群事件: %v", received)
	}

	c.enqueueOrderedMessage(ns, "group.changed", 2, map[string]any{
		"group_id":   groupID,
		"event_seq":  2,
		"event_type": "group.member_added",
		"action":     "member_added",
	})
	c.seqTracker.OnPullResult(ns, []map[string]any{{"event_seq": 2}}, 1)
	c.drainOrderedMessages(ns)

	if fmt.Sprint(received) != "[2 3]" {
		t.Fatalf("群事件应按 [2 3] 顺序发布，实际: %v", received)
	}
	if !c.isPushedSeq(ns, 2) || !c.isPushedSeq(ns, 3) {
		t.Fatal("已发布群事件 seq 应进入应用层去重集合")
	}
	state := c.v2GetState()
	state.bootstrapCacheM.Lock()
	_, cached := state.groupBootstrapCache[groupID]
	state.bootstrapCacheM.Unlock()
	if cached {
		t.Fatal("有序 drain 应先执行 SDK 内部群事件消费并清理 group bootstrap cache")
	}

	c.delivery().handleGroupChangedEventSeq(map[string]any{
		"group_id":   groupID,
		"event_seq":  3,
		"event_type": "group.member_removed",
		"action":     "member_removed",
	}, groupID)
	if fmt.Sprint(received) != "[2 3]" {
		t.Fatalf("重复 event_seq=3 不应再次发布，实际: %v", received)
	}
}

func TestOrderedGroupEventPullSkipsPermanentHoleAndPublishesReadyEvents(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	groupID := "group.example.com/g-events-hole"
	ns := "group_event:" + groupID
	c.seqTracker.ForceContiguousSeq(ns, 1)

	var received []int
	c.events.Subscribe("group.changed", func(payload any) {
		if evt, ok := payload.(map[string]any); ok {
			received = append(received, int(toInt64(evt["event_seq"])))
		}
	})

	c.enqueueOrderedMessage(ns, "group.changed", 5, map[string]any{
		"group_id":   groupID,
		"event_seq":  5,
		"event_type": "group.member_removed",
		"action":     "member_removed",
	})
	if !c.seqTracker.OnMessageSeq(ns, 5) {
		t.Fatal("event_seq=5 越过空洞时应触发补洞")
	}
	c.drainOrderedMessages(ns)
	if len(received) != 0 {
		t.Fatalf("空洞补齐前不应发布群事件: %v", received)
	}

	c.enqueueOrderedMessage(ns, "group.changed", 2, map[string]any{
		"group_id":   groupID,
		"event_seq":  2,
		"event_type": "group.member_added",
		"action":     "member_added",
	})
	c.enqueueOrderedMessage(ns, "group.changed", 4, map[string]any{
		"group_id":   groupID,
		"event_seq":  4,
		"event_type": "group.announcement_updated",
		"action":     "announcement_updated",
	})
	c.seqTracker.OnPullResult(ns, []map[string]any{{"event_seq": 2}, {"event_seq": 4}}, 1)
	c.drainOrderedMessages(ns)

	if fmt.Sprint(received) != "[2 4 5]" {
		t.Fatalf("永久空洞不应阻塞已拉取群事件发布，实际: %v", received)
	}
	if got := c.seqTracker.GetContiguousSeq(ns); got != 5 {
		t.Fatalf("group_event contiguousSeq 应跳过永久空洞推进到 5，got=%d", got)
	}
	if !c.isPushedSeq(ns, 2) || !c.isPushedSeq(ns, 4) || !c.isPushedSeq(ns, 5) {
		t.Fatal("已发布群事件 seq 应进入应用层去重集合")
	}

	c.delivery().handleGroupChangedEventSeq(map[string]any{
		"group_id":   groupID,
		"event_seq":  5,
		"event_type": "group.member_removed",
		"action":     "member_removed",
	}, groupID)
	if fmt.Sprint(received) != "[2 4 5]" {
		t.Fatalf("重复 event_seq=5 不应再次发布，实际: %v", received)
	}
}

func TestPulledBatchPublishesInternalGap(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ns := "p2p:alice.example.com"
	c.seqTracker.OnMessageSeq(ns, 1)
	var received []int
	c.events.Subscribe("message.received", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received = append(received, int(toInt64(msg["seq"])))
		}
	})

	c.seqTracker.ForceContiguousSeq(ns, 2)
	if !c.publishPulledMessage("message.received", ns, 2, map[string]any{"seq": 2}) {
		t.Fatal("pull 批 seq=2 应发布")
	}
	if !c.publishPulledMessage("message.received", ns, 4, map[string]any{"seq": 4}) {
		t.Fatal("pull 批内部缺 seq=3 时，seq=4 也应发布")
	}
	c.seqTracker.ForceContiguousSeq(ns, 4)
	c.drainOrderedMessages(ns)

	if fmt.Sprint(received) != "[2 4]" {
		t.Fatalf("pull 批内部空洞不应阻塞发布，实际: %v", received)
	}
	if !c.isPushedSeq(ns, 2) || !c.isPushedSeq(ns, 4) {
		t.Fatal("pull 批已发布 seq 应进入 republish guard")
	}
	c.prunePushedSeqs(ns)
	if !c.isPushedSeq(ns, 2) || !c.isPushedSeq(ns, 4) {
		t.Fatal("republish guard 不应仅因 contiguous 推进而清理")
	}
}

func TestP2PRecallTombstonePublishesRecalledEvent(t *testing.T) {
	event, payload := p2pAppEventForMessage(map[string]any{
		"message_id": "recall-1",
		"from":       "alice.agentid.pub",
		"to":         "bob.agentid.pub",
		"seq":        int64(9),
		"type":       "message.recalled",
		"payload": map[string]any{
			"kind":        "message.recalled",
			"message_ids": []any{"m-1"},
			"recalled_at": int64(123),
		},
	})
	if event != "message.recalled" {
		t.Fatalf("recall tombstone 应发布 message.recalled，实际 %s", event)
	}
	msg, ok := payload.(map[string]any)
	if !ok {
		t.Fatalf("payload 类型错误: %#v", payload)
	}
	if fmt.Sprint(msg["message_ids"]) != "[m-1]" {
		t.Fatalf("message_ids 归一化错误: %#v", msg["message_ids"])
	}
	if msg["message_id"] != "recall-1" {
		t.Fatalf("message_id 应保留撤回通知自身 ID: %#v", msg)
	}
	if msg["tombstone_message_id"] != "recall-1" {
		t.Fatalf("tombstone_message_id 错误: %#v", msg)
	}
	if toInt64(msg["seq"]) != 9 {
		t.Fatalf("seq 错误: %#v", msg)
	}
	published, ok := attachAppMessageEnvelope(msg).(map[string]any)
	if !ok {
		t.Fatalf("发布 payload 类型错误: %#v", msg)
	}
	envelope, ok := published["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("撤回事件应包含 envelope: %#v", published)
	}
	if published["message_id"] != "recall-1" || toInt64(published["seq"]) != 9 {
		t.Fatalf("撤回事件旧顶层字段应继续保留: %#v", published)
	}
	if envelope["from"] != "alice.agentid.pub" || envelope["to"] != "bob.agentid.pub" ||
		envelope["type"] != "message.recalled" || envelope["kind"] != "message.recalled" ||
		toInt64(envelope["timestamp"]) != 123 {
		t.Fatalf("撤回事件 envelope 不正确: %#v", published["envelope"])
	}
	for _, key := range []string{"message_id", "seq", "device_id", "slot_id"} {
		if _, exists := envelope[key]; exists {
			t.Fatalf("撤回事件 envelope 不应包含投递字段 %s: %#v", key, envelope)
		}
	}
}

func TestGroupRecallTombstonePublishesNoticeEnvelope(t *testing.T) {
	payload, ok := recallEventFromGroupMessage(map[string]any{
		"module_id":  "group",
		"group_id":   "g1",
		"message_id": "notice-1",
		"seq":        int64(43),
		"type":       "group.message_recalled",
		"payload": map[string]any{
			"message_ids":         []any{"gm-1"},
			"target_message_seqs": []any{int64(42)},
			"sender_aid":          "alice.agentid.pub",
			"recalled_by":         "owner.agentid.pub",
		},
	})
	if !ok {
		t.Fatal("群撤回 tombstone 应归一化为 group.message_recalled")
	}
	if payload["message_id"] != "notice-1" || payload["tombstone_message_id"] != "notice-1" {
		t.Fatalf("群撤回通知 message_id 不正确: %#v", payload)
	}
	published, ok := attachAppMessageEnvelope(payload).(map[string]any)
	if !ok {
		t.Fatalf("发布 payload 类型错误: %#v", payload)
	}
	envelope, ok := published["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("群撤回事件应包含 envelope: %#v", published)
	}
	if published["message_id"] != "notice-1" || toInt64(published["seq"]) != 43 {
		t.Fatalf("群撤回旧顶层字段应继续保留: %#v", published)
	}
	if envelope["group_id"] != "g1" || envelope["type"] != "group.message_recalled" ||
		envelope["kind"] != "group.message_recalled" {
		t.Fatalf("群撤回 envelope 不正确: %#v", envelope)
	}
	for _, key := range []string{"module_id", "message_id", "seq", "device_id", "slot_id"} {
		if _, exists := envelope[key]; exists {
			t.Fatalf("群撤回 envelope 不应包含投递字段 %s: %#v", key, envelope)
		}
	}
}

func TestPublishedMessageEventsFallbackCurrentInstanceContext(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.deviceID = "dev-1"
	c.slotID = "slot-a"
	p2pNS := "p2p:alice.example.com"
	groupNS := "group:g1"
	c.seqTracker.OnMessageSeq(p2pNS, 1)
	c.seqTracker.OnMessageSeq(groupNS, 1)

	var p2pEvent map[string]any
	var groupEvent map[string]any
	var groupChangedEvent map[string]any
	c.events.Subscribe("message.received", func(payload any) {
		p2pEvent, _ = payload.(map[string]any)
	})
	c.events.Subscribe("group.message_created", func(payload any) {
		groupEvent, _ = payload.(map[string]any)
	})
	c.events.Subscribe("group.changed", func(payload any) {
		groupChangedEvent, _ = payload.(map[string]any)
	})

	if !c.publishOrderedMessage("message.received", p2pNS, 1, map[string]any{
		"message_id": "m-1",
		"seq":        1,
		"from":       "bob.example.com",
		"to":         "alice.example.com",
		"payload":    map[string]any{"type": "text"},
		"e2ee":       map[string]any{"payload_type": "text"},
	}) {
		t.Fatal("P2P seq=1 应发布")
	}
	if !c.publishOrderedMessage("group.message_created", groupNS, 1, map[string]any{
		"group_id":     "g1",
		"message_id":   "gm-1",
		"seq":          1,
		"sender_aid":   "bob.example.com",
		"message_type": "group.message",
		"payload":      map[string]any{"type": "text"},
	}) {
		t.Fatal("群 seq=1 应发布")
	}
	if p2pEvent["device_id"] != "dev-1" || p2pEvent["slot_id"] != "slot-a" {
		t.Fatalf("P2P 事件未 fallback 当前实例: %#v", p2pEvent)
	}
	if p2pEvent["message_id"] != "m-1" || p2pEvent["payload"] == nil || p2pEvent["e2ee"] == nil {
		t.Fatalf("P2P 旧顶层字段应继续保留: %#v", p2pEvent)
	}
	p2pEnvelope, ok := p2pEvent["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("P2P 事件应包含 envelope: %#v", p2pEvent)
	}
	if p2pEnvelope["from"] != "bob.example.com" || p2pEnvelope["to"] != "alice.example.com" ||
		p2pEnvelope["type"] != "text" {
		t.Fatalf("P2P envelope 不正确: %#v", p2pEnvelope)
	}
	for _, key := range []string{"message_id", "seq", "device_id", "slot_id"} {
		if _, exists := p2pEnvelope[key]; exists {
			t.Fatalf("P2P envelope 不应包含投递字段 %s: %#v", key, p2pEnvelope)
		}
	}
	if groupEvent["device_id"] != "dev-1" || groupEvent["slot_id"] != "slot-a" {
		t.Fatalf("群消息事件未 fallback 当前实例: %#v", groupEvent)
	}
	if groupEvent["group_id"] != "g1" || groupEvent["payload"] == nil {
		t.Fatalf("群消息旧顶层字段应继续保留: %#v", groupEvent)
	}
	groupEnvelope, ok := groupEvent["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("群消息事件应包含 envelope: %#v", groupEvent)
	}
	if groupEnvelope["from"] != "bob.example.com" || groupEnvelope["group_id"] != "g1" ||
		groupEnvelope["type"] != "text" {
		t.Fatalf("群消息 envelope 不正确: %#v", groupEnvelope)
	}
	for _, key := range []string{"message_id", "seq", "device_id", "slot_id"} {
		if _, exists := groupEnvelope[key]; exists {
			t.Fatalf("群消息 envelope 不应包含投递字段 %s: %#v", key, groupEnvelope)
		}
	}

	c.publishAppEventSync("group.changed", map[string]any{
		"module_id":  "group",
		"group_id":   "g1",
		"event_seq":  2,
		"event_type": "group.member_added",
		"action":     "member_added",
		"actor_aid":  "alice.example.com",
		"member_aid": "bob.example.com",
	})
	if groupChangedEvent["group_id"] != "g1" || toInt64(groupChangedEvent["event_seq"]) != 2 ||
		groupChangedEvent["action"] != "member_added" {
		t.Fatalf("群事件旧顶层字段应继续保留: %#v", groupChangedEvent)
	}
	if groupChangedEvent["device_id"] != "dev-1" || groupChangedEvent["slot_id"] != "slot-a" {
		t.Fatalf("群事件未 fallback 当前实例: %#v", groupChangedEvent)
	}
	groupChangedEnvelope, ok := groupChangedEvent["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("群事件应包含 envelope: %#v", groupChangedEvent)
	}
	if groupChangedEnvelope["module_id"] != "group" || groupChangedEnvelope["group_id"] != "g1" ||
		toInt64(groupChangedEnvelope["event_seq"]) != 2 || groupChangedEnvelope["event_type"] != "group.member_added" ||
		groupChangedEnvelope["action"] != "member_added" || groupChangedEnvelope["actor_aid"] != "alice.example.com" ||
		groupChangedEnvelope["member_aid"] != "bob.example.com" ||
		groupChangedEnvelope["device_id"] != "dev-1" || groupChangedEnvelope["slot_id"] != "slot-a" {
		t.Fatalf("群事件 envelope 不正确: %#v", groupChangedEnvelope)
	}
}

func TestPublishedMessageEventsAttachEmptyDeviceID(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.deviceID = ""
	c.slotID = "slot-a"
	payload := c.attachCurrentInstanceContext(map[string]any{"seq": 1}).(map[string]any)
	if _, ok := payload["device_id"]; !ok {
		t.Fatalf("空 device_id 是显式设备值，事件 payload 应保留字段: %#v", payload)
	}
	if payload["device_id"] != "" || payload["slot_id"] != "slot-a" {
		t.Fatalf("事件实例上下文不正确: %#v", payload)
	}
}

func TestAppMessageEnvelopeKeepsForwardableMetadata(t *testing.T) {
	envelope := appMessageEnvelope(map[string]any{
		"message_id": "m-1",
		"seq":        9,
		"from_aid":   "alice.example.com",
		"to_aid":     "bob.example.com",
		"created_at": int64(1234567890000),
		"payload":    map[string]any{"type": "text", "text": "hello"},
		"headers":    map[string]any{"trace_id": "trace-1", "_auth": "drop"},
		"context":    map[string]any{"run_id": "run-1", "_auth": "drop"},
		"device_id":  "dev-1",
		"slot_id":    "slot-a",
	})

	want := map[string]any{
		"from":              "alice.example.com",
		"to":                "bob.example.com",
		"type":              "text",
		"timestamp":         int64(1234567890000),
		"context":           map[string]any{"run_id": "run-1"},
		"protected_headers": map[string]any{"trace_id": "trace-1"},
	}
	if !reflect.DeepEqual(envelope, want) {
		t.Fatalf("应用层 envelope 应只保留可转发元数据: %#v", envelope)
	}
	for _, key := range []string{"message_id", "seq", "device_id", "slot_id", "headers", "from_aid", "to_aid", "created_at"} {
		if _, exists := envelope[key]; exists {
			t.Fatalf("应用层 envelope 不应包含 %s: %#v", key, envelope)
		}
	}
}

func TestProtectedHeadersFromParamsSupportsHeadersAlias(t *testing.T) {
	got := protectedHeadersFromParams(map[string]any{
		"headers": map[string]any{"trace": "alias", "payload_type": "text"},
	})
	if got["trace"] != "alias" || got["payload_type"] != "text" {
		t.Fatalf("headers 别名应作为 protected_headers 读取: %#v", got)
	}

	got = protectedHeadersFromParams(map[string]any{
		"protected_headers": map[string]any{"trace": "primary"},
		"headers":           map[string]any{"trace": "alias"},
	})
	if got["trace"] != "primary" {
		t.Fatalf("protected_headers 应优先于 headers 别名: %#v", got)
	}

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.SetProtectedHeaders(map[string]string{"tenant": "global", "trace": "root"})
	params := map[string]any{
		"headers": map[string]any{"trace": "alias", "payload_type": "text"},
	}
	c.mergeInstanceProtectedHeaders("message.send", params)
	merged, ok := params["protected_headers"].(map[string]any)
	if !ok {
		t.Fatalf("实例级合并应写入 protected_headers: %#v", params)
	}
	if merged["tenant"] != "global" || merged["trace"] != "alias" || merged["payload_type"] != "text" {
		t.Fatalf("headers 别名合并结果不正确: %#v", merged)
	}
}

func TestMessageTargetsCurrentInstanceTreatsEmptyDeviceIDAsExplicit(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.deviceID = "device-1"
	c.slotID = "slot-a"
	if !c.messageTargetsCurrentInstance(map[string]any{}) {
		t.Fatal("缺省 device_id 的广播消息应允许投递")
	}
	if !c.messageTargetsCurrentInstance(map[string]any{"device_id": "device-1"}) {
		t.Fatal("匹配当前 device_id 的消息应允许投递")
	}
	if c.messageTargetsCurrentInstance(map[string]any{"device_id": ""}) {
		t.Fatal("显式空 device_id 不应投递给非空 device_id 实例")
	}

	c.deviceID = ""
	if !c.messageTargetsCurrentInstance(map[string]any{"device_id": ""}) {
		t.Fatal("显式空 device_id 应投递给空 device_id 实例")
	}
}
func TestP2PPushIgnoresOtherSlotContext(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.deviceID = "dev-1"
	c.slotID = "slot-a"

	var received int32
	c.events.Subscribe("message.received", func(payload any) {
		atomic.AddInt32(&received, 1)
	})

	c.processAndPublishMessage(map[string]any{
		"message_id": "m-other-slot",
		"from":       "bob.example.com",
		"to":         "alice.example.com",
		"slot_id":    "slot-b",
		"payload":    map[string]any{"type": "text", "text": "wrong slot"},
	})

	if atomic.LoadInt32(&received) != 0 {
		t.Fatal("P2P push 明确指向其它 slot 时不应发布 message.received")
	}
}

func TestGroupPushAcceptsOtherSlotContext(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.deviceID = "dev-1"
	c.slotID = "slot-a"

	delivered := make(chan map[string]any, 1)
	c.events.Subscribe("group.message_created", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			delivered <- msg
		}
	})

	c.processAndPublishGroupMessage(map[string]any{
		"message_id": "gm-other-slot",
		"group_id":   "g1",
		"from":       "bob.example.com",
		"device_id":  "dev-2",
		"slot_id":    "slot-b",
		"payload":    map[string]any{"type": "text", "text": "group"},
	})

	select {
	case msg := <-delivered:
		if msg["device_id"] != "dev-2" || msg["slot_id"] != "slot-b" {
			t.Fatalf("群消息不应覆盖显式实例字段: %#v", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("group push 明确带其它 slot 时仍应投递")
	}
}

func TestOrderedQueueClearedOnSeqTrackerContextSwitch(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.mu.Lock()
	c.aid = "alice.example.com"
	c.deviceID = "device-a"
	c.slotID = "slot-a"
	c.seqTrackerContext = buildSeqTrackerContext(c.aid, c.deviceID, c.slotID)
	c.mu.Unlock()
	c.enqueueOrderedMessage("p2p:alice.example.com", "message.received", 3, map[string]any{"seq": 3})

	c.mu.Lock()
	c.slotID = "slot-b"
	c.refreshSeqTrackerContextLocked()
	c.mu.Unlock()

	c.pendingOrderedMsgsMu.Lock()
	size := len(c.pendingOrderedMsgs)
	c.pendingOrderedMsgsMu.Unlock()
	if size != 0 {
		t.Fatalf("slot 上下文切换后有序待发布队列应清空，实际 size=%d", size)
	}
}

func TestShouldRetryReconnectOnLoginPhaseAuthError(t *testing.T) {
	if !shouldRetryReconnect(NewAuthError("aid_login2_failed")) {
		t.Fatal("aid_login2_failed 应视为可重试")
	}
	if shouldRetryReconnect(NewAuthError("token invalid")) {
		t.Fatal("普通 AuthError 不应被视为可重试")
	}
}

func startTestRPCServer(
	t *testing.T,
	handler func(method string, params map[string]any) any,
) (string, func() []testRPCCall, func()) {
	t.Helper()

	var (
		mu    sync.Mutex
		calls []testRPCCall
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 非 WebSocket 请求（如证书获取 HTTP GET）直接返回 200
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusOK)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("接受 WebSocket 失败: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		challenge, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"method":  "challenge",
			"params":  map[string]any{"nonce": "test-nonce"},
		})
		if err != nil {
			t.Errorf("序列化 challenge 失败: %v", err)
			return
		}
		if err := conn.Write(r.Context(), websocket.MessageText, challenge); err != nil {
			t.Errorf("发送 challenge 失败: %v", err)
			return
		}

		for {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var request map[string]any
			if err := json.Unmarshal(data, &request); err != nil {
				t.Errorf("解析测试请求失败: %v", err)
				return
			}
			method, _ := request["method"].(string)
			params, _ := request["params"].(map[string]any)
			if params == nil {
				params = make(map[string]any)
			}

			mu.Lock()
			calls = append(calls, testRPCCall{
				Method: method,
				Params: cloneRPCParamsForTest(t, params),
			})
			mu.Unlock()

			response, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      request["id"],
				"result":  handler(method, cloneRPCParamsForTest(t, params)),
			})
			if err != nil {
				t.Errorf("序列化测试响应失败: %v", err)
				return
			}
			if err := conn.Write(r.Context(), websocket.MessageText, response); err != nil {
				t.Errorf("发送测试响应失败: %v", err)
				return
			}
		}
	}))

	getCalls := func() []testRPCCall {
		mu.Lock()
		defer mu.Unlock()
		out := make([]testRPCCall, len(calls))
		for i, call := range calls {
			out[i] = testRPCCall{
				Method: call.Method,
				Params: cloneRPCParamsForTest(t, call.Params),
			}
		}
		return out
	}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	return wsURL, getCalls, server.Close
}

func connectWithTestAuth(t *testing.T, c *AUNClient, ctx context.Context, params map[string]any, opts ...*ConnectOptions) error {
	t.Helper()
	var opt *ConnectOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	return c.connectWithParams(ctx, params, opt, false, true)
}

// ── 客户端构造测试 ───────────────────────────────────────

// TestConstructNoArgs 验证使用空配置创建客户端
func TestConstructNoArgs(t *testing.T) {
	c := newClient(map[string]any{})
	defer func() { _ = c.Close() }()
	if c == nil {
		t.Fatal("NewClient 不应返回 nil")
	}
	if c.State() != ConnStateNoIdentity {
		t.Errorf("初始公开状态应为 no_identity: %s", c.State())
	}
	if c.AID() != "" {
		t.Errorf("初始 AID 应为空: %s", c.AID())
	}
}

// TestConstructWithAunPath 验证使用自定义 AUNPath 创建客户端
func TestConstructWithAunPath(t *testing.T) {
	tmpDir := t.TempDir()
	c := newClient(map[string]any{
		"aun_path": tmpDir,
	})
	defer func() { _ = c.Close() }()
	if c == nil {
		t.Fatal("NewClient 不应返回 nil")
	}
	if c.configModel.AUNPath != tmpDir {
		t.Errorf("AUNPath 不正确: %s", c.configModel.AUNPath)
	}
}

func TestConstructDefaultSQLiteBackupUsesAUNPath(t *testing.T) {
	tmpDir := t.TempDir()
	c := newClient(map[string]any{
		"aun_path": tmpDir,
	})
	defer func() { _ = c.Close() }()
	tokenStore, ok := c.tokenStore.(*keystore.LocalTokenStore)
	if !ok {
		t.Fatalf("默认 tokenStore 类型不正确: %T", c.tokenStore)
	}
	if tokenStore == nil {
		t.Fatal("默认 LocalTokenStore 不应为 nil")
	}
	// 新架构：SQLite DB 按 AID 懒初始化，不再预创建 .aun_backup
	aidsDir := filepath.Join(tmpDir, "AIDs")
	if err := os.MkdirAll(aidsDir, 0o700); err != nil {
		t.Fatalf("AIDs 目录创建失败: %v", err)
	}
}

// ── 连接验证测试 ─────────────────────────────────────────

// TestConnectRequiresAccessToken 验证连接需要 access_token
func TestConnectRequiresAccessToken(t *testing.T) {
	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	err := connectWithTestAuth(t, c, context.Background(), map[string]any{
		"gateway": "ws://localhost:20001",
	}, nil)
	if err == nil {
		t.Error("缺少 access_token 应返回错误")
	}
	// 应为 StateError
	if _, ok := err.(*StateError); !ok {
		t.Errorf("错误类型不正确: %T", err)
	}
}

// TestConnectRequiresGateway 验证连接需要 gateway
func TestConnectRequiresGateway(t *testing.T) {
	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	err := connectWithTestAuth(t, c, context.Background(), map[string]any{
		"access_token": "test-token",
	}, nil)
	if err == nil {
		t.Error("缺少 gateway 应返回错误")
	}
}

// ── 状态测试 ─────────────────────────────────────────────

// TestClientState 验证客户端初始状态
func TestClientState(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	if c.State() != ConnStateNoIdentity {
		t.Errorf("初始公开状态应为 no_identity: %s", c.State())
	}
}

func TestEffectiveHeartbeatIntervalSeconds(t *testing.T) {
	cases := []struct {
		name string
		in   float64
		want float64
	}{
		{name: "zero disables heartbeat", in: 0, want: 0},
		{name: "negative disables heartbeat", in: -1, want: 0},
		{name: "positive value below floor", in: 1, want: 10},
		{name: "fractional positive value below floor", in: 0.01, want: 10},
		{name: "floor stays floor", in: 10, want: 10},
		{name: "larger value preserved", in: 45, want: 45},
		{name: "value above ceiling", in: 1000, want: 600},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveHeartbeatIntervalSeconds(tc.in); got != tc.want {
				t.Fatalf("effectiveHeartbeatIntervalSeconds(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestClampHeartbeatInterval 验证 clampHeartbeatInterval 接受多种数值类型并落在 [10, 600]。
func TestClampHeartbeatInterval(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want float64
	}{
		{"int zero", int(0), 0},
		{"int floor", int(5), 10},
		{"int ok", int(45), 45},
		{"int ceiling", int(9999), 600},
		{"float ok", float64(60), 60},
		{"float negative", float64(-1), 0},
		{"unsupported string", "abc", 0},
		{"nil", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampHeartbeatInterval(tc.in); got != tc.want {
				t.Fatalf("clampHeartbeatInterval(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestApplyServerHeartbeatInterval 验证 applyServerHeartbeatInterval 写回 sessionOptions。
func TestApplyServerHeartbeatInterval(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.sessionOptions["heartbeat_interval"] = float64(30)

	c.applyServerHeartbeatInterval(60, "auth")
	if got := c.sessionOptions["heartbeat_interval"]; got != float64(60) {
		t.Fatalf("after apply 60: got %v, want 60", got)
	}
	c.applyServerHeartbeatInterval(5, "pong")
	if got := c.sessionOptions["heartbeat_interval"]; got != float64(10) {
		t.Fatalf("after apply 5 (clamp): got %v, want 10", got)
	}
	c.applyServerHeartbeatInterval(9999, "pong")
	if got := c.sessionOptions["heartbeat_interval"]; got != float64(600) {
		t.Fatalf("after apply 9999 (clamp): got %v, want 600", got)
	}
	c.applyServerHeartbeatInterval(0, "pong")
	if got := c.sessionOptions["heartbeat_interval"]; got != float64(0) {
		t.Fatalf("after apply 0: got %v, want 0", got)
	}
}

// ── RPC 调用测试 ─────────────────────────────────────────

// TestCallNotConnected 验证未连接时调用 RPC 返回错误
func TestCallNotConnected(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	_, err := c.Call(context.Background(), "meta.ping", nil)
	if err == nil {
		t.Error("未连接时调用应返回错误")
	}
	if _, ok := err.(*ConnectionError); !ok {
		t.Errorf("错误类型应为 ConnectionError: %T", err)
	}
}

// TestCallInternalOnlyBlocked 验证内部专用方法被阻止
func TestCallInternalOnlyBlocked(t *testing.T) {
	// 需要先让状态变为 Connected 才能测到 internalOnly 检查
	// 由于无法真正连接，我们创建一个假连接状态
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	for _, method := range []string{
		"auth.login1", "auth.aid_login1", "auth.login2",
		"auth.aid_login2", "auth.connect", "auth.refresh_token",
		"initialize",
	} {
		_, err := c.Call(context.Background(), method, nil)
		if err == nil {
			t.Errorf("内部方法 %s 应被阻止", method)
			continue
		}
		if _, ok := err.(*PermissionError); !ok {
			// 可能是 ConnectionError（transport 未连接）
			// 但只要不是 nil 就说明被拦截了
			if _, ok2 := err.(*ConnectionError); ok2 {
				// transport 未连接的错误在 internalOnly 检查之后
				// 说明没被阻止（不正确）—— 但实际上代码先检查 state 再检查 internalOnly
				// 我们已设置 state = Connected，所以应先命中 internalOnly
				t.Errorf("方法 %s: 期望 PermissionError, 实际: %T", method, err)
			}
		}
	}
}

func TestCallRejectsMessageSendToGroupService(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	_, err := c.Call(context.Background(), "message.send", map[string]any{
		"to":      "group.example.com",
		"payload": map[string]any{"type": "text", "text": "hello"},
		"encrypt": false,
	})
	if err == nil {
		t.Fatal("向 group.{issuer} 发送 message.send 应被拦截")
	}
	if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("错误类型应为 ValidationError: %T", err)
	}
}

func TestCallRejectsMessageSendDeliveryModeOverride(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	_, err := c.Call(context.Background(), "message.send", map[string]any{
		"to":            "bob.example.com",
		"payload":       map[string]any{"type": "text", "text": "hello"},
		"encrypt":       false,
		"delivery_mode": map[string]any{"mode": "queue"},
	})
	if err == nil {
		t.Fatal("message.send 传入发送级 delivery_mode 应被拒绝")
	}
	if !strings.Contains(err.Error(), "message.send does not accept delivery_mode") {
		t.Fatalf("错误信息不正确: %v", err)
	}
}

func TestAuthFlowEmptyDeviceIDLoadsInstanceState(t *testing.T) {
	ks, err := keystore.NewLocalTokenStore(t.TempDir(), nil, "seed")
	if err != nil {
		t.Fatalf("创建 LocalTokenStore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	aid := "auth-empty-device.example"

	identity := map[string]any{
		"aid":                aid,
		"private_key_pem":    "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
		"public_key_der_b64": "pub",
		"curve":              "P-256",
	}
	if err := ks.SaveInstanceState(aid, "", "slot-a", map[string]any{
		"access_token":            "empty-device-token",
		"refresh_token":           "empty-device-refresh",
		"access_token_expires_at": int64(234567),
	}); err != nil {
		t.Fatalf("保存空 device instance_state 失败: %v", err)
	}

	flow := NewAuthFlow(AuthFlowConfig{TokenStore: ks, Crypto: &CryptoProvider{}, VerifySSL: false})
	flow.SetInstanceContext("", "slot-a")
	flow.SetIdentity(identity)
	loaded, err := flow.LoadIdentity(aid)
	if err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if loaded["access_token"] != "empty-device-token" || loaded["refresh_token"] != "empty-device-refresh" {
		t.Fatalf("空 device_id 未加载 instance_state token: %#v", loaded)
	}
}

func TestAuthFlowEmptyDeviceIDPersistsInstanceState(t *testing.T) {
	ks, err := keystore.NewLocalTokenStore(t.TempDir(), nil, "seed")
	if err != nil {
		t.Fatalf("创建 LocalTokenStore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	aid := "persist-empty-device.example"

	flow := NewAuthFlow(AuthFlowConfig{TokenStore: ks, Crypto: &CryptoProvider{}, VerifySSL: false})
	flow.SetInstanceContext("", "slot-a")
	if err := flow.persistIdentity(map[string]any{
		"aid":                     aid,
		"private_key_pem":         "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
		"public_key_der_b64":      "pub",
		"curve":                   "P-256",
		"access_token":            "empty-device-token",
		"refresh_token":           "empty-device-refresh",
		"access_token_expires_at": int64(345678),
	}); err != nil {
		t.Fatalf("persistIdentity 失败: %v", err)
	}

	state, err := ks.LoadInstanceState(aid, "", "slot-a")
	if err != nil {
		t.Fatalf("LoadInstanceState 失败: %v", err)
	}
	if state["access_token"] != "empty-device-token" || state["refresh_token"] != "empty-device-refresh" {
		t.Fatalf("空 device_id 未持久化 instance_state token: %#v", state)
	}
}
func TestNormalizeConnectParamsIncludesSlotAndDeliveryMode(t *testing.T) {
	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	normalized, err := c.normalizeConnectParams(map[string]any{
		"access_token":    "tok",
		"gateway":         "ws://gateway.example.test/aun",
		"slot_id":         "slot-a",
		"delivery_mode":   "queue",
		"queue_routing":   "sender_affinity",
		"affinity_ttl_ms": 900,
	})
	if err != nil {
		t.Fatalf("normalizeConnectParams 失败: %v", err)
	}
	if normalized["device_id"] != c.deviceID {
		t.Fatalf("device_id 未正确注入: %v", normalized["device_id"])
	}
	if normalized["slot_id"] != "slot-a" {
		t.Fatalf("slot_id 不正确: %v", normalized["slot_id"])
	}
	deliveryMode, _ := normalized["delivery_mode"].(map[string]any)
	if deliveryMode == nil {
		t.Fatal("delivery_mode 不应为空")
	}
	if deliveryMode["mode"] != "queue" || deliveryMode["routing"] != "sender_affinity" || toInt64(deliveryMode["affinity_ttl_ms"]) != 900 {
		t.Fatalf("delivery_mode 规范化结果不正确: %#v", deliveryMode)
	}
}

func TestGroupCallInjectsEmptyDeviceIDValue(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{"access_token": "tok", "gateway": wsURL, "slot_id": "slot-a"}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	c.deviceID = ""
	c.slotID = "slot-a"

	if _, err := c.Call(ctx, "group.get_state", map[string]any{"group_id": "group.agentid.pub/1"}); err != nil {
		t.Fatalf("group.get_state 失败: %v", err)
	}

	for _, call := range getCalls() {
		if call.Method == "group.get_state" {
			if _, ok := call.Params["device_id"]; !ok {
				t.Fatalf("group.get_state 应显式携带空 device_id: %#v", call.Params)
			}
			if call.Params["device_id"] != "" || call.Params["slot_id"] != "slot-a" {
				t.Fatalf("group.get_state 实例上下文不正确: %#v", call.Params)
			}
			return
		}
	}
	t.Fatalf("未捕获 group.get_state: %#v", getCalls())
}
func TestConnectIncludesDeviceSlotAndDeliveryMode(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token":    "tok",
		"gateway":         wsURL,
		"slot_id":         "slot-a",
		"delivery_mode":   "queue",
		"queue_routing":   "sender_affinity",
		"affinity_ttl_ms": 900,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	var authConnect *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "auth.connect" {
			callCopy := call
			authConnect = &callCopy
			break
		}
	}
	if authConnect == nil {
		t.Fatal("未捕获 auth.connect")
	}

	device, _ := authConnect.Params["device"].(map[string]any)
	clientParams, _ := authConnect.Params["client"].(map[string]any)
	deliveryMode, _ := authConnect.Params["delivery_mode"].(map[string]any)
	if device == nil || clientParams == nil || deliveryMode == nil {
		t.Fatalf("auth.connect 缺少实例上下文字段: %#v", authConnect.Params)
	}
	if device["id"] != c.deviceID {
		t.Fatalf("auth.connect device.id 不正确: %v", device["id"])
	}
	if clientParams["slot_id"] != "slot-a" {
		t.Fatalf("auth.connect client.slot_id 不正确: %v", clientParams["slot_id"])
	}
	if clientParams["sdk_lang"] != "go" {
		t.Fatalf("auth.connect client.sdk_lang 不正确: %v", clientParams["sdk_lang"])
	}
	if clientParams["sdk_version"] != Version {
		t.Fatalf("auth.connect client.sdk_version 不正确: %v", clientParams["sdk_version"])
	}
	if deliveryMode["mode"] != "queue" || deliveryMode["routing"] != "sender_affinity" || toInt64(deliveryMode["affinity_ttl_ms"]) != 900 {
		t.Fatalf("auth.connect delivery_mode 不正确: %#v", deliveryMode)
	}
}

func TestCallInjectsMessageSlotContext(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "message.pull":
			return map[string]any{"messages": []any{}, "count": 0, "latest_seq": 0}
		case "message.ack":
			return map[string]any{"success": true, "ack_seq": 7}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	pullResult, err := c.Call(ctx, "message.pull", map[string]any{"after_seq": 0, "limit": 10})
	if err != nil {
		t.Fatalf("message.pull 失败: %v", err)
	}
	pullMap, _ := pullResult.(map[string]any)
	if toInt64(pullMap["count"]) != 0 {
		t.Fatalf("message.pull 返回值不正确: %#v", pullMap)
	}

	ackResult, err := c.Call(ctx, "message.ack", map[string]any{"seq": 7})
	if err != nil {
		t.Fatalf("message.ack 失败: %v", err)
	}
	ackMap, _ := ackResult.(map[string]any)
	if !ackMap["success"].(bool) || toInt64(ackMap["ack_seq"]) != 7 {
		t.Fatalf("message.ack 返回值不正确: %#v", ackMap)
	}

	var pullCall, ackCall *testRPCCall
	for _, call := range getCalls() {
		switch call.Method {
		case "message.pull":
			callCopy := call
			pullCall = &callCopy
		case "message.ack":
			callCopy := call
			ackCall = &callCopy
		}
	}
	if pullCall == nil || ackCall == nil {
		t.Fatalf("未捕获 message.pull/message.ack: %#v", getCalls())
	}
	if pullCall.Params["device_id"] != c.deviceID || pullCall.Params["slot_id"] != "slot-a" {
		t.Fatalf("message.pull 未注入当前实例上下文: %#v", pullCall.Params)
	}
	if ackCall.Params["device_id"] != c.deviceID || ackCall.Params["slot_id"] != "slot-a" {
		t.Fatalf("message.ack 未注入当前实例上下文: %#v", ackCall.Params)
	}
}

func TestPullEmptyResultAppliesRetentionFloor(t *testing.T) {
	groupID := "g-empty.example.com"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "message.pull":
			return map[string]any{"messages": []any{}, "count": 0, "latest_seq": 7, "server_ack_seq": 7}
		case "message.ack":
			return map[string]any{"success": true, "ack_seq": params["seq"]}
		case "group.pull":
			return map[string]any{
				"messages": []any{},
				"count":    0,
				"cursor":   map[string]any{"current_seq": 9},
			}
		case "group.pull_events":
			return map[string]any{
				"events": []any{},
				"count":  0,
				"cursor": map[string]any{"current_seq": 11},
			}
		case "group.ack_messages":
			return map[string]any{"success": true, "ack_seq": params["msg_seq"]}
		case "group.ack_events":
			return map[string]any{"success": true, "ack_seq": params["event_seq"]}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	if _, err := c.Call(ctx, "message.pull", map[string]any{"after_seq": 0, "limit": 5}); err != nil {
		t.Fatalf("message.pull 失败: %v", err)
	}
	if got := c.seqTracker.GetContiguousSeq("p2p:alice.example.com"); got != 7 {
		t.Fatalf("空 message.pull 应推进 contiguous 到 server_ack_seq=7, got=%d", got)
	}

	if _, err := c.Call(ctx, "group.pull", map[string]any{"group_id": groupID, "after_message_seq": 0, "limit": 5}); err != nil {
		t.Fatalf("group.pull 失败: %v", err)
	}
	if got := c.seqTracker.GetContiguousSeq("group:" + NormalizeGroupID(groupID, "")); got != 9 {
		t.Fatalf("空 group.pull 应推进 contiguous 到 cursor.current_seq=9, got=%d", got)
	}

	c.fillGroupEventGap(groupID)
	if got := c.seqTracker.GetContiguousSeq("group_event:" + groupID); got != 11 {
		t.Fatalf("空 group.pull_events 应推进 contiguous 到 cursor.current_seq=11, got=%d", got)
	}
	sawPullEventsZero := false
	for _, call := range getCalls() {
		if call.Method == "group.pull_events" && toInt64(call.Params["after_event_seq"]) == 0 {
			if call.Params["device_id"] != c.deviceID || call.Params["slot_id"] != "slot-a" {
				t.Fatalf("group.pull_events 未注入当前实例上下文: %#v", call.Params)
			}
			sawPullEventsZero = true
			break
		}
	}
	if !sawPullEventsZero {
		t.Fatalf("group event 补洞应允许 after_event_seq=0: %#v", getCalls())
	}

	time.Sleep(120 * time.Millisecond)
	for _, call := range getCalls() {
		if call.Method == "group.ack_events" {
			t.Fatalf("空 group.pull_events 不应触发 ack_events: %#v", getCalls())
		}
	}
}

func TestP2PGapFillEmptyResultAcksRetentionFloor(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "message.pull":
			return map[string]any{"messages": []any{}, "count": 0, "latest_seq": 7, "server_ack_seq": 7}
		case "message.ack":
			return map[string]any{"success": true, "ack_seq": params["seq"]}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	c.fillP2pGap()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, call := range getCalls() {
			if call.Method == "message.ack" && toInt64(call.Params["seq"]) == 7 &&
				call.Params["device_id"] == c.deviceID && call.Params["slot_id"] == "slot-a" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("空 P2P gap fill 应按 server_ack_seq 触发 message.ack: %#v", getCalls())
}

func TestGroupGapFillEmptyResultAcksRetentionFloor(t *testing.T) {
	groupID := "group.example.com/g-empty"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "message.pull":
			return map[string]any{"messages": []any{}, "count": 0}
		case "group.pull":
			return map[string]any{
				"messages": []any{},
				"count":    0,
				"cursor":   map[string]any{"current_seq": 9},
			}
		case "group.ack_messages":
			return map[string]any{"success": true, "ack_seq": params["msg_seq"]}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	c.fillGroupGap(groupID)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, call := range getCalls() {
			if call.Method == "group.ack_messages" && toInt64(call.Params["msg_seq"]) == 9 &&
				call.Params["device_id"] == c.deviceID && call.Params["slot_id"] == "slot-a" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("空 group gap fill 应按 cursor.current_seq 触发 group.ack_messages: %#v", getCalls())
}

func TestOnRawGroupChangedTriggersGroupEventGapFill(t *testing.T) {
	groupID := "g-gap.example.com"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "group.pull_events":
			return map[string]any{
				"events": []any{
					map[string]any{
						"group_id":   groupID,
						"event_seq":  4,
						"event_type": "group.announcement_updated",
						"action":     "announcement_updated",
					},
				},
				"count":  1,
				"cursor": map[string]any{"current_seq": 11},
			}
		case "group.ack_events":
			return map[string]any{"success": true, "ack_seq": params["event_seq"]}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	c.onRawGroupChanged(map[string]any{
		"group_id":  groupID,
		"event_seq": 5,
		"action":    "foo",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var sawPullEvents, sawEventAck bool
		for _, call := range getCalls() {
			if call.Method == "group.pull_events" &&
				toInt64(call.Params["after_event_seq"]) == 0 &&
				call.Params["device_id"] == c.deviceID &&
				call.Params["slot_id"] == "slot-a" {
				sawPullEvents = true
			}
			if call.Method == "group.ack_events" &&
				toInt64(call.Params["event_seq"]) == 11 &&
				call.Params["device_id"] == c.deviceID &&
				call.Params["slot_id"] == "slot-a" {
				sawEventAck = true
			}
		}
		if sawPullEvents && sawEventAck &&
			c.seqTracker.GetContiguousSeq("group_event:"+groupID) == 11 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("group.changed gap fill 未触发 pull/ack: %#v", getCalls())
}

func TestOnRawGroupChangedPushPersistsAndAcksContiguousEventSeq(t *testing.T) {
	groupID := "g-push.example.com"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "group.ack_events":
			return map[string]any{"success": true, "ack_seq": params["event_seq"]}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	ns := "group_event:" + groupID
	c.seqTracker.ForceContiguousSeq(ns, 5)
	c.onRawGroupChanged(map[string]any{
		"group_id":  groupID,
		"event_seq": 6,
		"action":    "member_added",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, call := range getCalls() {
			if call.Method == "group.ack_events" &&
				toInt64(call.Params["event_seq"]) == 6 &&
				call.Params["device_id"] == c.deviceID &&
				call.Params["slot_id"] == "slot-a" {
				seqStore, ok := c.tokenStore.(interface {
					LoadSeq(aid, deviceID, slotID, namespace string) (int, error)
				})
				if !ok {
					t.Fatal("测试 token store 应支持 LoadSeq")
				}
				persisted, err := seqStore.LoadSeq("alice.example.com", c.deviceID, "slot-a", ns)
				if err != nil {
					t.Fatalf("读取 group_event seq 失败: %v", err)
				}
				if persisted != 6 {
					t.Fatalf("group_event seq 未持久化到 6，got=%d", persisted)
				}
				if got := c.seqTracker.GetContiguousSeq(ns); got != 6 {
					t.Fatalf("group_event contiguous 未推进到 6，got=%d", got)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("group.changed 连续 push 未触发 group.ack_events: %#v", getCalls())
}

func TestOnRawGroupChangedSelfJoinStartsVisibleEventBaseline(t *testing.T) {
	groupID := "g-self-join.example.com"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "group.ack_events":
			return map[string]any{"success": true, "ack_seq": params["event_seq"]}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	c.mu.Lock()
	c.aid = "bob.example.com"
	c.mu.Unlock()

	published := make(chan int64, 1)
	sub := c.On("group.changed", func(payload any) {
		if evt, ok := payload.(map[string]any); ok {
			published <- toInt64(evt["event_seq"])
		}
	})
	defer sub.Unsubscribe()

	c.onRawGroupChanged(map[string]any{
		"group_id":   groupID,
		"event_seq":  5,
		"action":     "member_added",
		"joined_aid": "bob.example.com",
	})

	deadline := time.Now().Add(2 * time.Second)
	sawPublished := false
	for time.Now().Before(deadline) {
		var sawAck, sawPull bool
		for _, call := range getCalls() {
			if call.Method == "group.pull_events" {
				sawPull = true
			}
			if call.Method == "group.ack_events" &&
				toInt64(call.Params["event_seq"]) == 5 &&
				call.Params["device_id"] == c.deviceID &&
				call.Params["slot_id"] == "slot-a" {
				sawAck = true
			}
		}
		if sawPull {
			t.Fatalf("自己入群首个 group.changed 不应触发 group.pull_events: %#v", getCalls())
		}
		select {
		case seq := <-published:
			if seq != 5 {
				t.Fatalf("发布 event_seq 错误: got=%d", seq)
			}
			sawPublished = true
		default:
		}
		if sawPublished && sawAck && c.seqTracker.GetContiguousSeq("group_event:"+groupID) == 5 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("自己入群首个 group.changed 未发布或未 ack: calls=%#v contiguous=%d",
		getCalls(), c.seqTracker.GetContiguousSeq("group_event:"+groupID))
}

func TestOnRawGroupChangedInviteCodeUsedTriggersV2AutoPropose(t *testing.T) {
	groupID := "group.example.com/g-invite"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "group.get_online_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "alice.example.com", "role": "owner", "online": true, "device_id": "dev-1"},
			}}
		case "group.get_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "alice.example.com", "role": "owner"},
				map[string]any{"aid": "bob.example.com", "role": "member"},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	c.onRawGroupChanged(map[string]any{
		"group_id":   groupID,
		"action":     "invite_code_used",
		"member_aid": "bob.example.com",
		"actor_aid":  "bob.example.com",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, call := range getCalls() {
			if call.Method == "group.get_online_members" && call.Params["group_id"] == groupID {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("invite_code_used 成员变更未触发 V2 event-path auto propose: %#v", getCalls())
}

func TestGroupEventGapFillAcksFinalContiguousAfterPublish(t *testing.T) {
	groupID := "g-event-publish.example.com"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "group.pull_events":
			return map[string]any{
				"events": []any{
					map[string]any{
						"group_id":   groupID,
						"event_seq":  2,
						"event_type": "group.announcement_updated",
						"action":     "announcement_updated",
					},
				},
				"count":  1,
				"cursor": map[string]any{"current_seq": 2},
			}
		case "group.ack_events":
			return map[string]any{"success": true, "ack_seq": params["event_seq"]}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	ns := "group_event:" + groupID
	if !c.seqTracker.OnMessageSeq(ns, 3) {
		t.Fatal("预置 event_seq=3 应产生 group_event gap")
	}
	c.events.Subscribe("group.changed", func(payload any) {
		if evt, ok := payload.(map[string]any); ok && evt["_from_gap_fill"] == true {
			c.seqTracker.OnMessageSeq(ns, 4)
		}
	})

	c.fillGroupEventGap(groupID)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var ackCount int
		var ackSeq int64
		for _, call := range getCalls() {
			if call.Method == "group.ack_events" {
				ackCount++
				ackSeq = toInt64(call.Params["event_seq"])
			}
		}
		if ackCount == 1 && ackSeq == 3 && c.seqTracker.GetContiguousSeq(ns) == 4 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("group.pull_events 应只 ack SDK 内部消费 contiguous_seq=3，且不受应用回调推进影响: %#v", getCalls())
}

func TestCallDoesNotForwardMessageSendDeliveryMode(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token":    "tok",
		"gateway":         wsURL,
		"delivery_mode":   "queue",
		"queue_routing":   "sender_affinity",
		"affinity_ttl_ms": 900,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	if _, err := c.Call(ctx, "message.send", map[string]any{
		"to":      "bob.example.com",
		"payload": map[string]any{"type": "text", "text": "hello"},
		"encrypt": false,
	}); err != nil {
		t.Fatalf("message.send 失败: %v", err)
	}

	var sendCall *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "message.send" {
			callCopy := call
			sendCall = &callCopy
		}
	}
	if sendCall == nil {
		t.Fatal("未捕获 message.send")
	}
	if _, exists := sendCall.Params["delivery_mode"]; exists {
		t.Fatalf("message.send 不应转发连接级 delivery_mode: %#v", sendCall.Params)
	}
}

func TestCallNormalizesOutboundMessagePayload(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	if _, err := c.Call(ctx, "message.send", map[string]any{
		"to":      "bob.example.com",
		"content": map[string]any{"text": "hello"},
		"encrypt": false,
	}); err != nil {
		t.Fatalf("message.send 失败: %v", err)
	}
	if _, err := c.Call(ctx, "group.send", map[string]any{
		"group_id": "group.example.com/g-normalize",
		"payload":  map[string]any{"text": "群明文"},
		"encrypt":  false,
	}); err != nil {
		t.Fatalf("group.send 失败: %v", err)
	}

	var messageCall *testRPCCall
	var groupCall *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "message.send" {
			cc := call
			messageCall = &cc
		}
		if call.Method == "group.send" {
			cc := call
			groupCall = &cc
		}
	}
	if messageCall == nil || groupCall == nil {
		t.Fatalf("未捕获发送调用: %#v", getCalls())
	}
	if _, exists := messageCall.Params["content"]; exists {
		t.Fatalf("message.send 不应继续转发 content: %#v", messageCall.Params)
	}
	messagePayload, _ := messageCall.Params["payload"].(map[string]any)
	if messagePayload["type"] != "text" || messagePayload["text"] != "hello" {
		t.Fatalf("message.send payload 应补齐 type=text: %#v", messageCall.Params)
	}
	groupPayload, _ := groupCall.Params["payload"].(map[string]any)
	if groupPayload["type"] != "text" || groupPayload["text"] != "群明文" {
		t.Fatalf("group.send payload 应补齐 type=text: %#v", groupCall.Params)
	}
}
func TestCallDoesNotForwardPlaintextMessageProtectedHeaders(t *testing.T) {
	// message.send 明文路径应保留 protected_headers/headers（信封元数据，加密与否都保留）
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	headers, err := NewProtectedHeaders(map[string]any{"Device_ID": "dev-a", "slot_id": "slot-a"})
	if err != nil {
		t.Fatalf("创建 protected headers 失败: %v", err)
	}
	if _, err := c.Call(ctx, "message.send", map[string]any{
		"to":                "bob.example.com",
		"payload":           map[string]any{"type": "text", "text": "hello"},
		"encrypt":           false,
		"protected_headers": headers,
		"headers":           map[string]any{"device_id": "dev-b"},
	}); err != nil {
		t.Fatalf("message.send 失败: %v", err)
	}

	var sendCall *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "message.send" {
			callCopy := call
			sendCall = &callCopy
		}
	}
	if sendCall == nil {
		t.Fatal("未捕获 message.send")
	}
	if _, exists := sendCall.Params["protected_headers"]; !exists {
		t.Fatalf("message.send 明文路径应保留 protected_headers: %#v", sendCall.Params)
	}
	if _, exists := sendCall.Params["headers"]; !exists {
		t.Fatalf("message.send 明文路径应保留 headers: %#v", sendCall.Params)
	}
}

func TestCallPlaintextMessageThoughtPutPassesThrough(t *testing.T) {
	// message.thought.put encrypt=false 应走通用 RPC 路径，保留 payload/protected_headers/context
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	if _, err := c.Call(ctx, "message.thought.put", map[string]any{
		"to":                "bob.example.com",
		"payload":           map[string]any{"type": "thought", "text": "明文 thought"},
		"encrypt":           false,
		"protected_headers": map[string]any{"trace": "t1"},
		"context":           map[string]any{"type": "message", "id": "m-1"},
	}); err != nil {
		t.Fatalf("message.thought.put 失败: %v", err)
	}

	var call *testRPCCall
	for _, c := range getCalls() {
		if c.Method == "message.thought.put" {
			cc := c
			call = &cc
		}
	}
	if call == nil {
		t.Fatal("未捕获 message.thought.put")
	}
	if _, exists := call.Params["encrypt"]; exists {
		t.Fatalf("encrypt 字段应被剥离: %#v", call.Params)
	}
	if _, exists := call.Params["protected_headers"]; !exists {
		t.Fatalf("明文 thought.put 应保留 protected_headers: %#v", call.Params)
	}
	if _, exists := call.Params["payload"]; !exists {
		t.Fatalf("明文 thought.put 应透传 payload: %#v", call.Params)
	}
	if _, exists := call.Params["context"]; !exists {
		t.Fatalf("明文 thought.put 应透传 context: %#v", call.Params)
	}
}

func TestCallPlaintextGroupSendPreservesProtectedHeaders(t *testing.T) {
	// group.send encrypt=false 明文路径应保留 protected_headers/headers，且不触发 epoch floor 预检
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	if _, err := c.Call(ctx, "group.send", map[string]any{
		"group_id":          "group.example.com/g-test",
		"payload":           map[string]any{"type": "text", "text": "群明文"},
		"encrypt":           false,
		"protected_headers": map[string]any{"trace": "t1"},
		"headers":           map[string]any{"misc": "h"},
	}); err != nil {
		t.Fatalf("group.send 失败: %v", err)
	}

	for _, cc := range getCalls() {
		if strings.Contains(cc.Method, "e2ee") || cc.Method == "group.get_members" {
			t.Fatalf("明文 group.send 不应触发加密/成员预检 (%s)", cc.Method)
		}
	}

	var call *testRPCCall
	for _, c := range getCalls() {
		if c.Method == "group.send" {
			cc := c
			call = &cc
		}
	}
	if call == nil {
		t.Fatal("未捕获 group.send")
	}
	if _, exists := call.Params["protected_headers"]; !exists {
		t.Fatalf("明文 group.send 应保留 protected_headers: %#v", call.Params)
	}
	if _, exists := call.Params["headers"]; !exists {
		t.Fatalf("明文 group.send 应保留 headers: %#v", call.Params)
	}
}

func TestCallRejectsMessageSlotContextOverride(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, c, ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
		"slot_id":      "slot-a",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	if _, err := c.Call(ctx, "message.pull", map[string]any{
		"after_seq": 0,
		"device_id": "other-device",
	}); err == nil || !strings.Contains(err.Error(), "device_id must match") {
		t.Fatalf("覆盖 device_id 应被拒绝: %v", err)
	}
	if _, err := c.Call(ctx, "message.ack", map[string]any{
		"seq":     1,
		"slot_id": "slot-b",
	}); err == nil || !strings.Contains(err.Error(), "slot_id must match") {
		t.Fatalf("覆盖 slot_id 应被拒绝: %v", err)
	}

	for _, call := range getCalls() {
		if call.Method == "message.pull" || call.Method == "message.ack" {
			t.Fatalf("参数校验失败前不应发出 message.pull/message.ack: %#v", call)
		}
	}
}

// ── Close 测试 ───────────────────────────────────────────

// TestCloseIdleClient 验证关闭空闲客户端
func TestCloseIdleClient(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	err := c.Close()
	if err != nil {
		t.Errorf("关闭空闲客户端不应报错: %v", err)
	}
	if c.State() != ConnStateClosed {
		t.Errorf("关闭后状态应为 closed: %s", c.State())
	}
}

// TestCloseIdempotent 验证重复关闭不报错
func TestCloseIdempotent(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	_ = c.Close()
	err := c.Close()
	if err != nil {
		t.Errorf("重复关闭不应报错: %v", err)
	}
}

// ── ISSUE-GO-005: Disconnect / Logout 测试 ──────────────────

func TestDisconnectFromIdleIsNoop(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// idle 状态下 Disconnect 应无错误返回
	if err := c.Disconnect(); err != nil {
		t.Fatalf("idle 状态 Disconnect 不应报错: %v", err)
	}
	// 公开状态应保持 no_identity（未连接过，无需变为 standby）
	if c.State() != ConnStateNoIdentity {
		t.Fatalf("no_identity 状态 Disconnect 后应保持 no_identity，实际: %s", c.State())
	}
}

func TestDisconnectSetsStateDisconnected(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 模拟已连接状态
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	if err := c.Disconnect(); err != nil {
		t.Fatalf("Disconnect 不应报错: %v", err)
	}
	if c.State() != ConnStateNoIdentity {
		t.Fatalf("无身份模拟连接 Disconnect 后公开状态应为 no_identity，实际: %s", c.State())
	}
}

func TestLogoutClearsTokens(t *testing.T) {
	dir := t.TempDir()
	c := newClient(map[string]any{"aun_path": dir})
	defer func() { _ = c.Close() }()

	// 设置身份和 token
	aid := "logout-test.aid.com"
	c.SetAID(aid)
	c.SetIdentity(map[string]any{
		"aid":           aid,
		"access_token":  "tok-123",
		"refresh_token": "ref-456",
	})
	if store, ok := c.tokenStore.(keystore.InstanceStateStore); ok {
		_ = store.SaveInstanceState(aid, c.deviceID, c.slotID, map[string]any{
			"access_token":  "tok-123",
			"refresh_token": "ref-456",
		})
	}

	if err := c.Logout(); err != nil {
		t.Fatalf("Logout 不应报错: %v", err)
	}

	// 状态应为 closed
	if c.State() != ConnStateClosed {
		t.Fatalf("Logout 后状态应为 closed，实际: %s", c.State())
	}

	// 重新加载实例态，token 应已清除；AUNClient 不再读取 AID 身份私钥。
	store, ok := c.tokenStore.(keystore.InstanceStateStore)
	if !ok {
		t.Fatal("tokenStore 不支持 InstanceStateStore 接口")
	}
	loaded, err := store.LoadInstanceState(aid, c.deviceID, c.slotID)
	if err != nil {
		t.Fatalf("LoadInstanceState 失败: %v", err)
	}
	if loaded != nil {
		if tok, ok := loaded["access_token"].(string); ok && tok != "" {
			t.Fatal("Logout 后 access_token 应已清除")
		}
		if tok, ok := loaded["refresh_token"].(string); ok && tok != "" {
			t.Fatal("Logout 后 refresh_token 应已清除")
		}
	}
}

// ── On 事件订阅测试 ──────────────────────────────────────

// TestOnEventSubscription 验证通过客户端订阅事件
// ISSUE-SDK-GO-006: Publish 异步化后需等待 handler 完成
func TestOnEventSubscription(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	var received atomic.Value
	sub := c.On("test.event", func(payload any) {
		received.Store(payload)
	})
	if sub == nil {
		t.Fatal("On 应返回 Subscription")
	}
	c.events.Publish("test.event", "hello")
	// 等待异步 handler 完成
	time.Sleep(50 * time.Millisecond)
	if received.Load() != "hello" {
		t.Errorf("收到的 payload 不正确: %v", received.Load())
	}
}

// TestOff 验证 Off/Unsubscribe 取消事件订阅
func TestOff(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	var count atomic.Int32
	sub := c.On("test.off", func(payload any) {
		count.Add(1)
	})
	if sub == nil {
		t.Fatal("On 应返回 Subscription")
	}

	// 第一次发布，handler 应触发
	c.events.Publish("test.off", nil)
	time.Sleep(50 * time.Millisecond)
	if count.Load() != 1 {
		t.Fatalf("取消前 handler 应触发 1 次，实际 %d", count.Load())
	}

	// 取消订阅
	sub.Unsubscribe()

	// 第二次发布，handler 不应触发
	c.events.Publish("test.off", nil)
	time.Sleep(50 * time.Millisecond)
	if count.Load() != 1 {
		t.Fatalf("取消后 handler 不应再触发，实际 %d", count.Load())
	}
}

func TestOnReregisterSubscriptionUsesActualPublishDispatcher(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	dispatcher := c.events
	if dispatcher == nil {
		t.Fatal("client events dispatcher must not be nil")
	}
	if c.transport == nil || c.transport.dispatcher != dispatcher {
		t.Fatal("transport must route pushed events through the same dispatcher used by client.On")
	}

	var oldCount atomic.Int32
	var newCount atomic.Int32
	sub := c.On("message.received", func(payload any) {
		oldCount.Add(1)
	})
	sub.Unsubscribe()
	sub = c.On("message.received", func(payload any) {
		newCount.Add(1)
	})

	dispatcher.Publish("message.received", map[string]any{"id": "after-reregister"})
	time.Sleep(50 * time.Millisecond)

	if oldCount.Load() != 0 {
		t.Fatalf("重新注册后旧 handler 不应再触发，实际 %d", oldCount.Load())
	}
	if newCount.Load() != 1 {
		t.Fatalf("重新注册后新 handler 应挂在实际发布 dispatcher 上，实际 %d", newCount.Load())
	}
	sub.Unsubscribe()
}

// ── Client 配置测试 ──────────────────────────────────────

// TestClientGroupE2EEAlwaysEnabled 验证群组 E2EE 是必备能力，不可关闭
func TestClientGroupE2EEAlwaysEnabled(t *testing.T) {
	c := newClient(map[string]any{
		"aun_path":   t.TempDir(),
		"group_e2ee": false, // 尝试关闭应被忽略
	})
	defer func() { _ = c.Close() }()
	if !c.configModel.GroupE2EE {
		t.Error("group_e2ee 是必备能力，即使传入 false 也应保持 true")
	}
}

// TestClientVerifySSLConfig 验证 SSL 验证配置传递
func TestClientVerifySSLConfig(t *testing.T) {
	t.Setenv("AUN_ENV", "development")
	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	if c.configModel.VerifySSL {
		t.Error("development 环境下 verify_ssl 应为 false")
	}
}

// ── 静态辅助函数测试 ─────────────────────────────────────

// TestBuildCertURL 验证证书 URL 构建
func TestBuildCertURL(t *testing.T) {
	url := buildCertURL("wss://gateway.example.com:20001", "alice.example.com", "")
	if url != "https://gateway.example.com:20001/pki/cert/alice.example.com" {
		t.Errorf("URL 不正确: %s", url)
	}

	url2 := buildCertURL("ws://gateway.local:20001", "bob.local", "")
	if url2 != "http://gateway.local:20001/pki/cert/bob.local" {
		t.Errorf("ws URL 不正确: %s", url2)
	}

	url3 := buildCertURL("wss://gateway.example.com:20001", "alice.example.com", "sha256:abc")
	if url3 != "https://gateway.example.com:20001/pki/cert/alice.example.com?cert_fingerprint=sha256%3Aabc" {
		t.Errorf("带 cert_fingerprint 的 URL 不正确: %s", url3)
	}
}

func TestOnRawGroupChanged_MemberDoesNotRotateEpoch(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "group.get_members":
			return map[string]any{
				"members": []any{
					map[string]any{"aid": "owner.example.com", "role": "owner"},
					map[string]any{"aid": "bob.example.com", "role": "member"},
				},
			}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "bob.example.com"
	c.state = StateConnected
	c.gatewayURL = wsURL
	c.mu.Unlock()
	c.transport = NewRPCTransport(c.events, 2*time.Second, nil, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.transport.Connect(ctx, wsURL); err != nil {
		t.Fatalf("transport.Connect 失败: %v", err)
	}

	c.onRawGroupChanged(map[string]any{
		"group_id": "g-1.example.com",
		"action":   "member_removed",
	})

	time.Sleep(500 * time.Millisecond)

	for _, call := range getCalls() {
		if strings.Contains(call.Method, "rotate_epoch") {
			t.Fatalf("member 不应触发 epoch rotate: method=%s params=%#v", call.Method, call.Params)
		}
	}
}

func TestThoughtSelectorValidation(t *testing.T) {
	c := newClient(nil)
	valid := map[string]any{
		"to":      "bob.example.com",
		"context": map[string]any{"type": "run", "id": "run-1"},
	}
	if err := c.validateOutboundCall("message.thought.put", valid); err != nil {
		t.Fatalf("context selector 应通过校验: %v", err)
	}
	missing := map[string]any{"to": "bob.example.com"}
	if err := c.validateOutboundCall("message.thought.put", missing); err == nil || !strings.Contains(err.Error(), "context.type") {
		t.Fatalf("缺少 context selector 应报 context.type，实际: %v", err)
	}
}

// TestResolvePeerGatewayURL 验证跨域 Gateway URL 解析
func TestResolvePeerGatewayURL(t *testing.T) {
	// 同域
	url := resolvePeerGatewayURL("wss://gateway.example.com:20001", "alice.example.com")
	if url != "wss://gateway.example.com:20001" {
		t.Errorf("同域 URL 应不变: %s", url)
	}

	// 不含点的 AID（无域信息）
	url2 := resolvePeerGatewayURL("wss://gateway.example.com:20001", "alice")
	if url2 != "wss://gateway.example.com:20001" {
		t.Errorf("无域 AID URL 应不变: %s", url2)
	}
}

// TestShouldRetryReconnect 验证重连重试判断
func TestShouldRetryReconnect(t *testing.T) {
	if shouldRetryReconnect(NewAuthError("auth")) {
		t.Error("AuthError 不应重试")
	}
	if shouldRetryReconnect(NewPermissionError("perm")) {
		t.Error("PermissionError 不应重试")
	}
	if !shouldRetryReconnect(NewConnectionError("conn")) {
		t.Error("ConnectionError 应重试")
	}
	if !shouldRetryReconnect(NewTimeoutError("timeout")) {
		t.Error("TimeoutError 应重试")
	}
}

func TestGroupDispatchModeDefaultsToBroadcast(t *testing.T) {
	msg := attachGroupDispatchModeToPayload(map[string]any{
		"message_id": "group-plain-default",
		"group_id":   "g-1.example.com",
		"from":       "bob.example.com",
		"payload":    map[string]any{"type": "text", "text": "hello"},
	})
	if msg["dispatch_mode"] != "broadcast" {
		t.Fatalf("缺省 dispatch_mode 应默认 broadcast: %#v", msg)
	}
	payload, _ := msg["payload"].(map[string]any)
	if payload["dispatch_mode"] != "broadcast" {
		t.Fatalf("缺省 dispatch_mode 应向 payload 注入 broadcast: %#v", msg)
	}
}

// TestPushedSeqsNoDuplicateOnGapFill 验证：推送路径已分发的 seq，
// 补洞路径不得重复投递（功能正确性测试）。
func TestPushedSeqsNoDuplicateOnGapFill(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ns := "p2p:alice.example.com"
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	// 模拟推送路径已标记 seq=5
	c.pushedSeqsMu.Lock()
	if c.pushedSeqs[ns] == nil {
		c.pushedSeqs[ns] = make(map[int]bool)
	}
	c.pushedSeqs[ns][5] = true
	c.pushedSeqsMu.Unlock()

	// 补洞场景：seqTracker 已被 onPullResult 推进到覆盖所有消息
	c.seqTracker.ForceContiguousSeq(ns, 6)

	// 模拟补洞路径返回包含 seq=5 和 seq=6 的消息列表
	messages := []any{
		map[string]any{"message_id": "m5", "seq": float64(5), "payload": map[string]any{"type": "text", "text": "dup"}},
		map[string]any{"message_id": "m6", "seq": float64(6), "payload": map[string]any{"type": "text", "text": "new"}},
	}

	var mu sync.Mutex
	var received []string
	c.On("message.received", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			mu.Lock()
			received = append(received, m["message_id"].(string))
			mu.Unlock()
		}
	})

	// 调用 publishGapFillMessages 验证去重逻辑
	c.publishGapFillMessages(ns, messages)

	// ISSUE-SDK-GO-006: Publish 异步化，等待 handler 完成
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("补洞路径应跳过已推送的 seq=5，只投递 seq=6，实际投递: %v", received)
	}
	if received[0] != "m6" {
		t.Fatalf("补洞路径应投递 m6，实际: %v", received)
	}
}

// TestPushedSeqsGroupNoDuplicateOnGapFill 验证：群消息推送路径已分发的 seq，
// 补洞路径不得重复投递（群消息功能正确性测试）。
func TestPushedSeqsGroupNoDuplicateOnGapFill(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	groupID := "g-test.example.com"
	ns := "group:" + groupID

	// 模拟推送路径已标记 seq=10
	c.pushedSeqsMu.Lock()
	if c.pushedSeqs[ns] == nil {
		c.pushedSeqs[ns] = make(map[int]bool)
	}
	c.pushedSeqs[ns][10] = true
	c.pushedSeqsMu.Unlock()

	// 补洞场景：seqTracker 已被 onPullResult 推进到覆盖所有消息
	c.seqTracker.ForceContiguousSeq(ns, 11)

	messages := []any{
		map[string]any{"message_id": "gm10", "group_id": groupID, "seq": float64(10), "payload": map[string]any{"type": "text", "text": "dup"}},
		map[string]any{"message_id": "gm11", "group_id": groupID, "seq": float64(11), "payload": map[string]any{"type": "text", "text": "new"}},
	}

	var mu sync.Mutex
	var created []string
	c.On("group.message_created", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			mu.Lock()
			created = append(created, m["message_id"].(string))
			mu.Unlock()
		}
	})

	c.publishGapFillGroupMessages(ns, messages)

	// ISSUE-SDK-GO-006: Publish 异步化，等待 handler 完成
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(created) != 1 {
		t.Fatalf("群补洞路径应跳过已推送的 seq=10，只投递 seq=11，实际投递: %v", created)
	}
	if created[0] != "gm11" {
		t.Fatalf("群补洞路径应投递 gm11，实际: %v", created)
	}
}

// TestPushedSeqsPreMarkBeforeGapFill 验证：推送路径必须在启动补洞 goroutine 之前
// 完成 pushedSeqs 预标记，否则补洞路径可能在预标记前读取到空 map 而重复投递。
// 此测试通过 markPushedSeq 方法验证预标记的原子性。
func TestPushedSeqsPreMarkBeforeGapFill(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ns := "p2p:premark.example.com"
	c.mu.Lock()
	c.aid = "premark.example.com"
	c.mu.Unlock()

	// 模拟：推送路径先预标记 seq=7（在启动补洞 goroutine 之前）
	c.markPushedSeq(ns, 7)

	// 补洞场景：seqTracker 已被 onPullResult 推进到覆盖所有消息
	c.seqTracker.ForceContiguousSeq(ns, 8)

	// 然后补洞路径立即读取（模拟 goroutine 调度到补洞路径先执行）
	messages := []any{
		map[string]any{"message_id": "pm7", "seq": float64(7), "payload": map[string]any{"type": "text", "text": "dup"}},
		map[string]any{"message_id": "pm8", "seq": float64(8), "payload": map[string]any{"type": "text", "text": "new"}},
	}

	var mu sync.Mutex
	var received []string
	c.On("message.received", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			mu.Lock()
			received = append(received, m["message_id"].(string))
			mu.Unlock()
		}
	})

	c.publishGapFillMessages(ns, messages)

	// ISSUE-SDK-GO-006: Publish 异步化，等待 handler 完成
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || received[0] != "pm8" {
		t.Fatalf("预标记后补洞路径应跳过 seq=7，只投递 seq=8，实际: %v", received)
	}
}

// TestPushedSeqsConcurrentMarkAndRead 验证：并发标记和读取 pushedSeqs 不产生 data race。
// 修复后通过锁内逐条查询避免锁外持有 map 引用；在支持 -race 的环境下应干净通过。
// 注：Windows 环境无 gcc，-race 不可用；此测试作为逻辑正确性验证。
func TestPushedSeqsConcurrentMarkAndRead(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ns := "p2p:concurrent.example.com"
	c.mu.Lock()
	c.aid = "concurrent.example.com"
	c.mu.Unlock()

	const n = 100
	var wg sync.WaitGroup

	// 并发写：模拟推送路径标记 seq
	for i := 1; i <= n; i++ {
		wg.Add(1)
		s := i
		go func() {
			defer wg.Done()
			c.markPushedSeq(ns, s)
		}()
	}

	// 并发读：模拟补洞路径读取快照
	results := make([]bool, n+1)
	for i := 1; i <= n; i++ {
		wg.Add(1)
		s := i
		go func() {
			defer wg.Done()
			// 使用 isPushedSeq 方法（修复后的安全读取）
			results[s] = c.isPushedSeq(ns, s)
		}()
	}

	wg.Wait()
	// 验证最终所有 seq 都被标记
	for i := 1; i <= n; i++ {
		if !c.isPushedSeq(ns, i) {
			t.Errorf("seq=%d 应已被标记", i)
		}
	}
}

// ── 抑制重连测试 ──────────────────────────────────────────

func makeDisconnectClient(t *testing.T) *AUNClient {
	t.Helper()
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	c.mu.Lock()
	c.state = StateConnected
	c.sessionOptions = map[string]any{
		"auto_reconnect": true,
		"retry": map[string]any{
			"initial_delay": 0.01,
			"max_delay":     0.05,
			"max_attempts":  float64(0),
		},
	}
	c.mu.Unlock()
	return c
}

func TestNoReconnectOnFatalCloseCode(t *testing.T) {
	fatalCodes := []int{4001, 4003, 4008, 4009, 4010, 4011}
	for _, code := range fatalCodes {
		t.Run(fmt.Sprintf("code_%d", code), func(t *testing.T) {
			c := makeDisconnectClient(t)
			defer func() { _ = c.Close() }()

			c.handleTransportDisconnect(errors.New("test"), code)
			// 等一小段时间让异步逻辑执行
			time.Sleep(50 * time.Millisecond)

			c.mu.RLock()
			state := c.state
			c.mu.RUnlock()
			if state != StateTerminalFailed {
				t.Errorf("close code %d 应进入 terminal_failed，实际: %s", code, state)
			}
			if c.reconnecting.Load() {
				t.Errorf("close code %d 不应触发重连", code)
			}
		})
	}
}

func TestReconnectOnRetryableCloseCode(t *testing.T) {
	retryableCodes := []int{4000, 4029, 4500, 4503}
	for _, code := range retryableCodes {
		t.Run(fmt.Sprintf("code_%d", code), func(t *testing.T) {
			c := makeDisconnectClient(t)
			defer func() {
				c.closing.Store(true) // 停止重连循环
				_ = c.Close()
			}()

			c.handleTransportDisconnect(errors.New("test"), code)
			time.Sleep(50 * time.Millisecond)

			c.mu.RLock()
			state := c.state
			c.mu.RUnlock()
			if state == StateTerminalFailed {
				t.Errorf("close code %d 不应进入 terminal_failed", code)
			}
		})
	}
}

func TestGatewayDisconnectSuppressesReconnect(t *testing.T) {
	c := makeDisconnectClient(t)
	defer func() { _ = c.Close() }()

	// 模拟 gateway.disconnect 通知
	c.onGatewayDisconnect(map[string]any{"code": 4009, "reason": "Connection replaced"})
	if !c.serverKicked.Load() {
		t.Fatal("onGatewayDisconnect 应设置 serverKicked 标志")
	}

	c.handleTransportDisconnect(errors.New("test"), 4009)
	time.Sleep(50 * time.Millisecond)

	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	if state != StateTerminalFailed {
		t.Errorf("gateway.disconnect 后断线应进入 terminal_failed，实际: %s", state)
	}
}

func TestServerKickedSuppressesAnyCode(t *testing.T) {
	c := makeDisconnectClient(t)
	defer func() { _ = c.Close() }()
	c.serverKicked.Store(true)

	// 使用一个"可重连"的 close code
	c.handleTransportDisconnect(errors.New("test"), -1) // -1 = 网络异常
	time.Sleep(50 * time.Millisecond)

	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	if state != StateTerminalFailed {
		t.Errorf("serverKicked=true 应抑制重连，实际: %s", state)
	}
}

func TestBuildSeqTrackerContextDoesNotUseNULSeparator(t *testing.T) {
	ctx := buildSeqTrackerContext(" alice ", "dev", "slot")
	if strings.Contains(ctx, "\x00") {
		t.Fatalf("seq tracker context must not generate NUL separators: %q", ctx)
	}
	if buildSeqTrackerContext("ab", "c", "") == buildSeqTrackerContext("a", "bc", "") {
		t.Fatal("length-prefixed seq tracker context should be unambiguous")
	}
}

func TestBuildLengthPrefixedBytesKeyDoesNotUseNULSeparator(t *testing.T) {
	key := buildLengthPrefixedBytesKey([]byte("actor"), []byte("payload"), []byte("signature"))
	if strings.Contains(string(key), "\x00") {
		t.Fatalf("length-prefixed bytes key must not generate NUL separators: %q", string(key))
	}
	left := string(buildLengthPrefixedBytesKey([]byte("ab"), []byte("c")))
	right := string(buildLengthPrefixedBytesKey([]byte("a"), []byte("bc")))
	if left == right {
		t.Fatal("length-prefixed bytes key should be unambiguous")
	}
}
