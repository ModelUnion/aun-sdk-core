package aun

import (
	"context"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/session"
)

func newConnectedV2PullClientForTest(t *testing.T, wsURL string) *AUNClient {
	t.Helper()
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.deviceID = "dev-1"
	c.slotID = "slot-1"
	c.state = StateConnected
	c.v2State = &v2P2PState{
		session:             &session.V2Session{},
		bootstrapCache:      make(map[string]v2BootstrapEntry),
		groupBootstrapCache: make(map[string]*v2GroupBootstrapEntry),
	}
	c.mu.Unlock()
	c.transport = NewRPCTransport(c.events, 2*time.Second, nil, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.transport.Connect(ctx, wsURL); err != nil {
		_ = c.Close()
		t.Fatalf("transport.Connect 失败: %v", err)
	}
	return c
}

func TestPullV2LegacyV1PlaintextAndEncryptedSkip(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "message.v2.pull":
			return map[string]any{"messages": []any{
				map[string]any{
					"version":    "v1",
					"seq":        1,
					"message_id": "m-plain",
					"from_aid":   "bob1.example.com",
					"t_server":   int64(100),
					"legacy_v1": map[string]any{
						"to":      "alice.example.com",
						"payload": map[string]any{"type": "text", "text": "plain-v1"},
					},
				},
				map[string]any{
					"version":    "v1",
					"seq":        2,
					"message_id": "m-encrypted",
					"from_aid":   "bob1.example.com",
					"legacy_v1": map[string]any{
						"payload": map[string]any{"type": "e2ee.encrypted", "ciphertext": "x"},
					},
				},
				map[string]any{
					"version":    "v1",
					"seq":        3,
					"message_id": "m-empty",
					"from_aid":   "bob1.example.com",
					"legacy_v1":  map[string]any{},
				},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msgs, err := c.pullV2(ctx, 0, 10)
	if err != nil {
		t.Fatalf("PullV2 失败: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("只应返回 V1 明文消息，got=%d msgs=%#v", len(msgs), msgs)
	}
	payload, _ := msgs[0]["payload"].(map[string]any)
	if payload["text"] != "plain-v1" || msgs[0]["encrypted"] != false {
		t.Fatalf("V1 明文消息未正确透传: %#v", msgs[0])
	}
	if got := c.seqTracker.GetContiguousSeq("p2p:alice.example.com"); got != 3 {
		t.Fatalf("V1 加密/空 payload 跳过后仍应推进 contiguous seq 到 3，got=%d", got)
	}
	for _, call := range getCalls() {
		if call.Method == "message.v2.pull" {
			if _, ok := call.Params["device_id"]; ok {
				t.Fatalf("message.v2.pull 不应由业务层显式携带 device_id: %#v", call.Params)
			}
			if _, ok := call.Params["slot_id"]; ok {
				t.Fatalf("message.v2.pull 不应由业务层显式携带 slot_id: %#v", call.Params)
			}
		}
	}
}

func TestPullGroupV2LegacyV1PlaintextAndEncryptedSkip(t *testing.T) {
	groupID := "group.example.com/g1"
	groupAID := NormalizeGroupID(groupID, "")
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.v2.pull":
			return map[string]any{"messages": []any{
				map[string]any{
					"version":    "v1",
					"seq":        1,
					"message_id": "gm-plain",
					"from_aid":   "bob1.example.com",
					"t_server":   int64(100),
					"payload":    map[string]any{"type": "text", "text": "group-plain-v1"},
				},
				map[string]any{
					"version":    "v1",
					"seq":        2,
					"message_id": "gm-encrypted",
					"from_aid":   "bob1.example.com",
					"payload":    map[string]any{"type": "e2ee.group_encrypted", "ciphertext": "x"},
				},
				map[string]any{
					"version":    "v1",
					"seq":        3,
					"message_id": "gm-empty",
					"from_aid":   "bob1.example.com",
				},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msgs, err := c.pullGroupV2(ctx, groupID, 0, 10)
	if err != nil {
		t.Fatalf("PullGroupV2 失败: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("只应返回 V1 群明文消息，got=%d msgs=%#v", len(msgs), msgs)
	}
	payload, _ := msgs[0]["payload"].(map[string]any)
	if payload["text"] != "group-plain-v1" || msgs[0]["encrypted"] != false {
		t.Fatalf("V1 群明文消息未正确透传: %#v", msgs[0])
	}
	if got := c.seqTracker.GetContiguousSeq("group:" + groupAID); got != 3 {
		t.Fatalf("V1 群加密/空 payload 跳过后仍应推进 contiguous seq 到 3，got=%d", got)
	}
}

func TestGroupPullExternalCursorPreservesExplicitZeroAndDeviceSlot(t *testing.T) {
	groupID := "g1"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.v2.pull":
			return map[string]any{
				"messages": []any{
					map[string]any{
						"version":    "v1",
						"seq":        1,
						"message_id": "gm-sync-1",
						"from_aid":   "bob1.example.com",
						"payload":    map[string]any{"type": "text", "text": "sync-1"},
					},
				},
				"cursor": map[string]any{"latest_seq": 3},
			}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.seqTracker.ForceContiguousSeq("group:"+groupID, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "group.pull", map[string]any{
		"group_id":          groupID,
		"after_message_seq": int64(0),
		"limit":             int64(2),
		"device_id":         "sync-dev-a",
		"slot_id":           "sync-slot-a",
		"device_name":       "同步测试设备 A",
		"device_type":       "test",
	})
	if err != nil {
		t.Fatalf("group.pull 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if len(v2ToMapList(resultMap["messages"])) != 1 {
		t.Fatalf("group.pull 应返回外部 cursor 的消息: %#v", result)
	}

	var pullCalls []testRPCCall
	for _, call := range getCalls() {
		if call.Method == "group.v2.pull" {
			pullCalls = append(pullCalls, call)
		}
		if call.Method == "group.v2.ack" {
			t.Fatalf("外部 cursor 的 group.pull 不应自动 group.v2.ack: %#v", getCalls())
		}
	}
	if len(pullCalls) != 1 {
		t.Fatalf("应只调用一次 group.v2.pull，实际: %#v", getCalls())
	}
	params := pullCalls[0].Params
	if toInt64(params["after_seq"]) != 0 {
		t.Fatalf("group.v2.pull 应保留显式 after_message_seq=0，实际参数: %#v", params)
	}
	if params["device_id"] != "sync-dev-a" || params["slot_id"] != "sync-slot-a" ||
		params["device_name"] != "同步测试设备 A" || params["device_type"] != "test" {
		t.Fatalf("group.v2.pull 应透传外部 cursor 元信息，实际参数: %#v", params)
	}
}

func TestGroupAckMessagesExternalCursorUsesRawRPC(t *testing.T) {
	groupID := "g1"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		return map[string]any{"ok": true, "acked": params["msg_seq"]}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.seqTracker.ForceContiguousSeq("group:"+groupID, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Call(ctx, "group.ack_messages", map[string]any{
		"group_id":  groupID,
		"msg_seq":   int64(1),
		"device_id": "sync-dev-a",
		"slot_id":   "sync-slot-a",
	}); err != nil {
		t.Fatalf("group.ack_messages 失败: %v", err)
	}

	var rawAck *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "group.v2.ack" {
			t.Fatalf("外部 cursor 的 group.ack_messages 不应路由到 group.v2.ack: %#v", getCalls())
		}
		if call.Method == "group.ack_messages" {
			callCopy := call
			rawAck = &callCopy
		}
	}
	if rawAck == nil {
		t.Fatalf("外部 cursor 的 group.ack_messages 应走原始 RPC，实际调用: %#v", getCalls())
	}
	if toInt64(rawAck.Params["msg_seq"]) != 1 || rawAck.Params["device_id"] != "sync-dev-a" || rawAck.Params["slot_id"] != "sync-slot-a" {
		t.Fatalf("group.ack_messages 原始 RPC 参数不正确: %#v", rawAck.Params)
	}
}
