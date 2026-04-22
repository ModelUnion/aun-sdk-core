package aun

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func TestRecvInitialMessageNonChallengeThenChallenge(t *testing.T) {
	// GO-015: 服务端先发非 challenge 消息，再发 challenge，应成功返回 challenge
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("接受 WebSocket 失败: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		// 先发一条非 challenge 的事件通知
		eventMsg, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"method":  "event/some.event",
			"params":  map[string]any{"data": "hello"},
		})
		if err := conn.Write(r.Context(), websocket.MessageText, eventMsg); err != nil {
			return
		}

		// 短暂延迟后发送 challenge
		time.Sleep(100 * time.Millisecond)
		challengeMsg, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"method":  "challenge",
			"params":  map[string]any{"nonce": "test-nonce"},
		})
		if err := conn.Write(r.Context(), websocket.MessageText, challengeMsg); err != nil {
			return
		}

		// 保持连接
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	dispatcher := NewEventDispatcher()
	transport := NewRPCTransport(dispatcher, 5*time.Second, nil, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	challenge, err := transport.Connect(ctx, wsURL)
	if err != nil {
		t.Fatalf("GO-015: 非 challenge 消息后跟 challenge 应成功，但返回 error: %v", err)
	}
	if challenge == nil {
		t.Fatal("GO-015: challenge 不应为 nil")
	}
	// 验证返回的确实是 challenge 消息
	if method, ok := challenge["method"].(string); !ok || method != "challenge" {
		t.Fatalf("GO-015: 返回的消息应为 challenge，实际为: %v", challenge["method"])
	}
	_ = transport.Close()
}

func TestRecvInitialMessageOnlyNonChallengeTimesOut(t *testing.T) {
	// GO-015: 仅收到非 challenge 消息时，应在超时后返回 error（而非 nil, nil）
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("接受 WebSocket 失败: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		// 只发送非 challenge 消息
		msg, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"method":  "event/some.event",
			"params":  map[string]any{"data": "hello"},
		})
		if err := conn.Write(r.Context(), websocket.MessageText, msg); err != nil {
			return
		}
		// 保持连接直到客户端超时
		time.Sleep(15 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	dispatcher := NewEventDispatcher()
	transport := NewRPCTransport(dispatcher, 5*time.Second, nil, false)

	// 使用短超时，避免测试耗时过长
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	challenge, err := transport.Connect(ctx, wsURL)
	if err == nil && challenge == nil {
		t.Fatal("GO-015: 无 challenge 时应返回 error，而非 nil, nil")
	}
	if err == nil {
		t.Fatal("GO-015: 仅收到非 challenge 消息且超时，应返回 error")
	}
	_ = transport.Close()
}

// TestCallOnClosedTransportReturnsError 验证未连接时 Call 返回连接错误（ISSUE-GO-004 前置条件）
func TestCallOnClosedTransportReturnsError(t *testing.T) {
	dispatcher := NewEventDispatcher()
	tr := NewRPCTransport(dispatcher, 5*time.Second, nil, false)

	// 未连接时调用 Call 应返回连接错误
	_, err := tr.Call(context.Background(), "message.send", map[string]any{"to": "test.aid.com"})
	if err == nil {
		t.Fatal("ISSUE-GO-004: 未连接时 Call 应返回错误")
	}
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("应返回 ConnectionError，实际: %T", err)
	}
}
func TestSetTimeoutConcurrentSafety(t *testing.T) {
	dispatcher := NewEventDispatcher()
	tr := NewRPCTransport(dispatcher, 10*time.Second, nil, false)

	var wg sync.WaitGroup
	wg.Add(3)

	// 并发写入
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tr.SetTimeout(time.Duration(i) * time.Millisecond)
		}
	}()

	// 并发读取
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			got := tr.getTimeout()
			if got < 0 {
				t.Errorf("超时值不应为负: %v", got)
			}
		}
	}()

	// 并发写入不同值
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tr.SetTimeout(time.Duration(1000-i) * time.Millisecond)
		}
	}()

	wg.Wait()

	// 验证最终值可读取
	final := tr.getTimeout()
	if final < 0 {
		t.Errorf("最终超时值不应为负: %v", final)
	}
}

// TestChallengeConcurrentAccess 验证 challenge 字段的并发读写安全性
// 使用 -race 运行时，如果存在数据竞争会被检测到
func TestChallengeConcurrentAccess(t *testing.T) {
	dispatcher := NewEventDispatcher()
	tr := NewRPCTransport(dispatcher, 10*time.Second, nil, false)

	var wg sync.WaitGroup
	wg.Add(2)

	// 并发读取
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = tr.Challenge()
		}
	}()

	// 并发写入
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tr.setChallenge(map[string]any{"nonce": i})
		}
	}()

	wg.Wait()
}
