package aun

import (
	"sync"
	"testing"
	"time"
)

// 与 Python SDK 对齐：gateway.disconnect 事件 detail 透传 + terminal_failed 携带 detail。
//
// 参考实现：python/src/aun_core/client.py:_on_gateway_disconnect
// 1. 服务端发 event/gateway.disconnect 时透传 code/reason/detail 到应用层 'gateway.disconnect'
// 2. 缓存最近一次 disconnect 信息
// 3. 后续 transport 断线走 terminal_failed 路径时，connection.state 事件携带 detail / code

// 用例 1：detail 透传到 'gateway.disconnect'
func TestGatewayDisconnectDetail_PassThrough(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	var captured map[string]any
	sub := c.events.Subscribe("gateway.disconnect", func(payload any) {
		data, _ := payload.(map[string]any)
		captured = data
		wg.Done()
	})
	defer sub.Unsubscribe()

	// 模拟服务端 _raw.gateway.disconnect 事件（已由内置订阅转 onGatewayDisconnect）
	c.events.Publish("_raw.gateway.disconnect", map[string]any{
		"code":   4015,
		"reason": "long_connection_quota_exceeded",
		"detail": map[string]any{
			"aid":        "agent.aid.com",
			"device_id":  "dev-123",
			"slot_id":    "slot-A",
			"quota_kind": "aid_device_slot",
			"limit":      1.0,
			"evicted_by": map[string]any{"device_id": "dev-456"},
		},
	})

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("未收到 gateway.disconnect 事件")
	}

	if captured == nil {
		t.Fatal("captured payload 为 nil")
	}
	if code, _ := captured["code"].(int); code != 4015 {
		t.Fatalf("code 应为 4015, got %v (type %T)", captured["code"], captured["code"])
	}
	if reason, _ := captured["reason"].(string); reason != "long_connection_quota_exceeded" {
		t.Fatalf("reason 不匹配: %v", captured["reason"])
	}
	detail, ok := captured["detail"].(map[string]any)
	if !ok {
		t.Fatalf("detail 应为 map, got %T", captured["detail"])
	}
	if detail["aid"] != "agent.aid.com" {
		t.Fatalf("detail.aid 不匹配: %v", detail["aid"])
	}
	if detail["quota_kind"] != "aid_device_slot" {
		t.Fatalf("detail.quota_kind 不匹配: %v", detail["quota_kind"])
	}
	if _, ok := detail["evicted_by"].(map[string]any); !ok {
		t.Fatalf("detail.evicted_by 应为 map, got %T", detail["evicted_by"])
	}
}

// 用例 2：服务端未带 detail 时，detail 应为空 map（非 nil）
func TestGatewayDisconnectDetail_EmptyDetail(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	var captured map[string]any
	sub := c.events.Subscribe("gateway.disconnect", func(payload any) {
		data, _ := payload.(map[string]any)
		captured = data
		wg.Done()
	})
	defer sub.Unsubscribe()

	c.events.Publish("_raw.gateway.disconnect", map[string]any{
		"code":   4009,
		"reason": "server_kick",
		// detail 缺失
	})

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("未收到 gateway.disconnect 事件")
	}

	detail, ok := captured["detail"].(map[string]any)
	if !ok {
		t.Fatalf("detail 应为 map（即便为空）, got %T", captured["detail"])
	}
	if len(detail) != 0 {
		t.Fatalf("detail 应为空 map, got %v", detail)
	}
}

// 用例 3：terminal_failed 状态变更带 detail（缓存路径）
func TestGatewayDisconnectDetail_TerminalFailedCarriesDetail(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 1. 先模拟服务端发 gateway.disconnect（缓存 lastDisconnectInfo + 标记 serverKicked）
	c.onGatewayDisconnect(map[string]any{
		"code":   4015,
		"reason": "long_connection_quota_exceeded",
		"detail": map[string]any{
			"aid":        "agent.aid.com",
			"slot_id":    "slot-A",
			"quota_kind": "aid_device_slot",
			"evicted_by": map[string]any{"device_id": "dev-456"},
		},
	})

	// 2. 准备订阅 connection.state(connection_failed)
	var wg sync.WaitGroup
	wg.Add(1)
	var captured map[string]any
	sub := c.events.Subscribe("connection.state", func(payload any) {
		data, _ := payload.(map[string]any)
		if s, _ := data["state"].(string); s == string(ConnStateConnectionFailed) {
			captured = data
			wg.Done()
		}
	})
	defer sub.Unsubscribe()

	// 3. 触发传输断线（auto_reconnect=true 才会走到 connection_failed 抑制分支）
	c.mu.Lock()
	c.state = StateConnected
	c.sessionOptions = map[string]any{"auto_reconnect": true}
	c.mu.Unlock()
	c.closing.Store(false)
	c.reconnecting.Store(false)

	// closeCode=4015 命中 noReconnectCodes，且 serverKicked 已置位
	c.handleTransportDisconnect(nil, 4015)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("未收到 connection.state(connection_failed) 事件")
	}

	if captured == nil {
		t.Fatal("connection_failed payload 为 nil")
	}
	// reason 字段
	if reason, _ := captured["reason"].(string); reason != "server kicked" {
		t.Fatalf("reason 应为 'server kicked', got %v", captured["reason"])
	}
	// detail 透传
	detail, ok := captured["detail"].(map[string]any)
	if !ok {
		t.Fatalf("terminal_failed 事件应携带 detail, got %T", captured["detail"])
	}
	if detail["aid"] != "agent.aid.com" {
		t.Fatalf("detail.aid 不匹配: %v", detail["aid"])
	}
	if detail["quota_kind"] != "aid_device_slot" {
		t.Fatalf("detail.quota_kind 不匹配: %v", detail["quota_kind"])
	}
	// code 透传
	if code, _ := captured["code"].(int); code != 4015 {
		t.Fatalf("terminal_failed 事件应携带 code=4015, got %v (type %T)", captured["code"], captured["code"])
	}
}
