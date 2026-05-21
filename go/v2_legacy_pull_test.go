package aun

import (
	"context"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/session"
)

func newConnectedV2PullClientForTest(t *testing.T, wsURL string) *AUNClient {
	t.Helper()
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
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
					"from_aid":   "bob.example.com",
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
					"from_aid":   "bob.example.com",
					"legacy_v1": map[string]any{
						"payload": map[string]any{"type": "e2ee.encrypted", "ciphertext": "x"},
					},
				},
				map[string]any{
					"version":    "v1",
					"seq":        3,
					"message_id": "m-empty",
					"from_aid":   "bob.example.com",
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
	msgs, err := c.PullV2(ctx, 0, 10)
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
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.v2.pull":
			return map[string]any{"messages": []any{
				map[string]any{
					"version":    "v1",
					"seq":        1,
					"message_id": "gm-plain",
					"from_aid":   "bob.example.com",
					"t_server":   int64(100),
					"payload":    map[string]any{"type": "text", "text": "group-plain-v1"},
				},
				map[string]any{
					"version":    "v1",
					"seq":        2,
					"message_id": "gm-encrypted",
					"from_aid":   "bob.example.com",
					"payload":    map[string]any{"type": "e2ee.group_encrypted", "ciphertext": "x"},
				},
				map[string]any{
					"version":    "v1",
					"seq":        3,
					"message_id": "gm-empty",
					"from_aid":   "bob.example.com",
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
	msgs, err := c.PullGroupV2(ctx, groupID, 0, 10)
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
	if got := c.seqTracker.GetContiguousSeq("group:" + groupID); got != 3 {
		t.Fatalf("V1 群加密/空 payload 跳过后仍应推进 contiguous seq 到 3，got=%d", got)
	}
}
