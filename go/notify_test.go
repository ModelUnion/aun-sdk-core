package aun

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func startNotifyCaptureServer(t *testing.T) (string, <-chan map[string]any, func()) {
	t.Helper()
	messages := make(chan map[string]any, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("接受 WebSocket 失败: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		challenge, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"method":  "challenge",
			"params":  map[string]any{"nonce": "notify-test"},
		})
		if err := conn.Write(r.Context(), websocket.MessageText, challenge); err != nil {
			return
		}
		_, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		var msg map[string]any
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Errorf("notification JSON 解析失败: %v", err)
			return
		}
		messages <- msg
	}))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	return wsURL, messages, server.Close
}

func connectNotifyTransport(t *testing.T, wsURL string) *RPCTransport {
	t.Helper()
	transport := NewRPCTransport(NewEventDispatcher(), time.Second, nil, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := transport.Connect(ctx, wsURL); err != nil {
		t.Fatalf("连接 notify 测试 WebSocket 失败: %v", err)
	}
	return transport
}

func TestTransportNotifySendsNotificationWithoutID(t *testing.T) {
	wsURL, messages, cleanup := startNotifyCaptureServer(t)
	defer cleanup()
	transport := connectNotifyTransport(t, wsURL)
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := transport.Notify(ctx, "notification/client.activity", map[string]any{"state": "idle"}); err != nil {
		t.Fatalf("Notify 返回错误: %v", err)
	}

	select {
	case msg := <-messages:
		if _, exists := msg["id"]; exists {
			t.Fatalf("notification 不应包含 id: %v", msg)
		}
		if msg["method"] != "notification/client.activity" {
			t.Fatalf("method 错误: %v", msg["method"])
		}
		params, _ := msg["params"].(map[string]any)
		if params["state"] != "idle" {
			t.Fatalf("params 错误: %v", params)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未捕获到 notification")
	}
}

func TestClientNotifyToAIDWrapsRouteNotification(t *testing.T) {
	wsURL, messages, cleanup := startNotifyCaptureServer(t)
	defer cleanup()
	client := NewAUNClientEmpty()
	client.transport = connectNotifyTransport(t, wsURL)
	defer client.transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := client.Notify(ctx, "event/app.typing", map[string]any{"thread_id": "t1"}, NotifyOptions{
		To:       "bob1.agentid.pub",
		DeviceID: "dev-1",
		SlotID:   "slot-1",
		TTLMS:    5000,
	})
	if err != nil {
		t.Fatalf("Notify 返回错误: %v", err)
	}

	select {
	case msg := <-messages:
		if msg["method"] != "notification/route" {
			t.Fatalf("method 错误: %v", msg["method"])
		}
		params, _ := msg["params"].(map[string]any)
		target, _ := params["target"].(map[string]any)
		if target["aid"] != "bob1.agentid.pub" || target["device_id"] != "dev-1" || target["slot_id"] != "slot-1" {
			t.Fatalf("target 错误: %v", target)
		}
		deliver, _ := params["deliver"].(map[string]any)
		if deliver["method"] != "event/app.typing" {
			t.Fatalf("deliver.method 错误: %v", deliver["method"])
		}
		if params["ttl_ms"] != float64(5000) {
			t.Fatalf("ttl_ms 错误: %v", params["ttl_ms"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未捕获到 route notification")
	}
}

func TestTransportAppEventPublishedDirectly(t *testing.T) {
	dispatcher := NewEventDispatcher()
	received := make(chan any, 1)
	dispatcher.Subscribe("app.typing", func(payload any) {
		received <- payload
	})
	transport := NewRPCTransport(dispatcher, time.Second, nil, false)

	transport.routeMessage(map[string]any{
		"jsonrpc": "2.0",
		"method":  "event/app.typing",
		"params":  map[string]any{"thread_id": "t1"},
	})

	select {
	case payload := <-received:
		data, _ := payload.(map[string]any)
		if data["thread_id"] != "t1" {
			t.Fatalf("payload 错误: %v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到 app.typing 事件")
	}
}
