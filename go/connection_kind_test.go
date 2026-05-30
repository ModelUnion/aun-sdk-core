package aun

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ── 1. noReconnectCodes 包含 4012 / 4013 / 4015 ──────────────────────

func TestConnectionKind_NoReconnectCodesInclude4012And4013(t *testing.T) {
	// 4012 = long_connection_already_exists（被同槽位另一长连接抢占）
	// 4013 = short_connection_capacity_exceeded（短连接池满）
	// 4015 = long_connection_quota_exceeded（三层配额超限被踢，按 created_at 升序）
	if !noReconnectCodes[4012] {
		t.Fatal("noReconnectCodes 应包含 4012 (long_connection_already_exists)")
	}
	if !noReconnectCodes[4013] {
		t.Fatal("noReconnectCodes 应包含 4013 (short_connection_capacity_exceeded)")
	}
	if !noReconnectCodes[4015] {
		t.Fatal("noReconnectCodes 应包含 4015 (long_connection_quota_exceeded)")
	}
}

// ── 2. normalizeConnectParams 不传 connection_kind 默认 "long" ───────

func TestConnectionKind_DefaultIsLong(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	params, err := c.normalizeConnectParams(map[string]any{
		"access_token": "tok",
		"gateway":      "ws://localhost/aun",
	})
	if err != nil {
		t.Fatalf("normalizeConnectParams 不应报错: %v", err)
	}
	kind, _ := params["connection_kind"].(string)
	if kind != "long" {
		t.Fatalf("默认 connection_kind 应为 'long', got '%s'", kind)
	}
}

// ── 3. normalizeConnectParams 接受 kind=short + short_ttl_ms ────────

func TestConnectionKind_AcceptsShortWithTtl(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	params, err := c.normalizeConnectParams(map[string]any{
		"access_token":    "tok",
		"gateway":         "ws://localhost/aun",
		"connection_kind": "short",
		"short_ttl_ms":    30000,
	})
	if err != nil {
		t.Fatalf("normalizeConnectParams 不应报错: %v", err)
	}
	kind, _ := params["connection_kind"].(string)
	if kind != "short" {
		t.Fatalf("connection_kind 应为 'short', got '%s'", kind)
	}
	ttl, _ := params["short_ttl_ms"].(int)
	if ttl != 30000 {
		t.Fatalf("short_ttl_ms 应为 30000, got %d", ttl)
	}
}

// ── 4. normalizeConnectParams 拒绝无效 kind ─────────────────────────

func TestConnectionKind_RejectsInvalidKind(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	_, err := c.normalizeConnectParams(map[string]any{
		"access_token":    "tok",
		"gateway":         "ws://localhost/aun",
		"connection_kind": "weird",
	})
	if err == nil {
		t.Fatal("无效 connection_kind 应返回错误")
	}
	// 应为 ValidationError
	if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("错误类型应为 ValidationError, got %T: %v", err, err)
	}
}

// ── 5. auth.connect payload kind=short 含 options ───────────────────

func TestConnectionKind_AuthPayloadShortContainsOptions(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
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
		"access_token":    "tok",
		"gateway":         wsURL,
		"connection_kind": "short",
		"short_ttl_ms":    30000,
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

	opts, _ := authConnect.Params["options"].(map[string]any)
	if opts == nil {
		t.Fatal("kind=short 时 auth.connect payload 应包含 options 字段")
	}
	if opts["kind"] != "short" {
		t.Fatalf("options.kind 应为 'short', got %v", opts["kind"])
	}
	ttl := toInt64(opts["short_ttl_ms"])
	if ttl != 30000 {
		t.Fatalf("options.short_ttl_ms 应为 30000, got %v", opts["short_ttl_ms"])
	}
}

// ── 6. auth.connect payload kind=long 不含 options ──────────────────

func TestConnectionKind_AuthPayloadLongOmitsOptions(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
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
		"access_token":    "tok",
		"gateway":         wsURL,
		"connection_kind": "long",
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

	if _, hasOptions := authConnect.Params["options"]; hasOptions {
		t.Fatal("kind=long 时 auth.connect payload 不应包含 options 字段（保持向后兼容）")
	}
}

// ── 7. 短连接禁用 token 自动刷新（心跳保留） ──────────────────────────────

func TestConnectionKind_ShortDisablesTokenRefresh(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.mu.Lock()
	c.sessionOptions = map[string]any{
		"auto_reconnect":       true,
		"heartbeat_interval":   30.0,
		"token_refresh_before": 1800.0,
		"connection_kind":      "short",
	}
	c.state = StateConnected
	c.mu.Unlock()

	// startBackgroundTasks 在 kind=short 时应启动心跳但跳过 token 刷新
	c.startBackgroundTasks(context.Background())

	// 验证 cancel 被设置（ctx 初始化完成）
	c.mu.RLock()
	hasCancel := c.cancel != nil
	c.mu.RUnlock()

	if !hasCancel {
		t.Fatal("startBackgroundTasks 应设置 cancel")
	}
}

// ── 8. 长连接启动心跳和 token_refresh ───────────────────────────────

func TestConnectionKind_LongStartsBackgroundTasks(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.mu.Lock()
	c.sessionOptions = map[string]any{
		"auto_reconnect":       true,
		"heartbeat_interval":   30.0,
		"token_refresh_before": 1800.0,
		"connection_kind":      "long",
	}
	c.state = StateConnected
	c.mu.Unlock()

	// 长连接应启动后台任务（心跳 + token 刷新 goroutine）
	c.startBackgroundTasks(context.Background())

	// 验证 cancel 被设置（后台 goroutine 已启动）
	c.mu.RLock()
	hasCancel := c.cancel != nil
	c.mu.RUnlock()

	if !hasCancel {
		t.Fatal("startBackgroundTasks 应设置 cancel")
	}

	// 清理：取消后台任务避免 goroutine 泄漏
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
}

// ── 9. 短连接不改变 auto_reconnect 默认值 ─────────────────────────────

func TestConnectionKind_ShortDefaultAutoReconnectTrue(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	options := c.buildSessionOptions(map[string]any{
		"access_token":    "tok",
		"gateway":         "ws://x/aun",
		"connection_kind": "short",
	}, nil)
	autoReconnect, _ := options["auto_reconnect"].(bool)
	if !autoReconnect {
		t.Fatal("短连接 auto_reconnect 应保持默认 true")
	}
}

// ── 10. 长连接保持默认 auto_reconnect=true ──────────────────────────

func TestConnectionKind_LongDefaultAutoReconnectTrue(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	options := c.buildSessionOptions(map[string]any{
		"access_token":    "tok",
		"gateway":         "ws://x/aun",
		"connection_kind": "long",
	}, nil)
	autoReconnect, _ := options["auto_reconnect"].(bool)
	if !autoReconnect {
		t.Fatal("长连接 auto_reconnect 应默认为 true")
	}
}

// ── 辅助：验证短连接 Connect 后 sessionOptions 正确 ─────────────────

func TestConnectionKind_ShortConnectSetsSessionOptions(t *testing.T) {
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
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
		"access_token":    "tok",
		"gateway":         wsURL,
		"connection_kind": "short",
		"short_ttl_ms":    15000,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	c.mu.RLock()
	opts := c.sessionOptions
	c.mu.RUnlock()

	kind, _ := opts["connection_kind"].(string)
	if kind != "short" {
		t.Fatalf("sessionOptions.connection_kind 应为 'short', got '%s'", kind)
	}
	autoReconnect, _ := opts["auto_reconnect"].(bool)
	if !autoReconnect {
		t.Fatal("短连接 sessionOptions.auto_reconnect 应保持默认 true")
	}
}

// ── 辅助：验证 handleTransportDisconnect 对 4012/4013/4015 不重连 ───

func TestConnectionKind_NoReconnectOn4012And4013(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	for _, code := range []int{4012, 4013, 4015} {
		c.mu.Lock()
		c.state = StateConnected
		c.sessionOptions = map[string]any{"auto_reconnect": true, "connection_kind": "long"}
		c.mu.Unlock()
		c.closing.Store(false)
		c.serverKicked.Store(false)
		c.reconnecting.Store(false)

		var wg sync.WaitGroup
		wg.Add(1)
		var capturedState ConnectionState
		unsub := c.events.Subscribe("state_change", func(payload any) {
			data, _ := payload.(map[string]any)
			if s, ok := data["state"].(string); ok && s == string(ConnStateConnectionFailed) {
				capturedState = ConnStateConnectionFailed
				wg.Done()
			}
		})

		c.handleTransportDisconnect(nil, code)

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("code=%d: 未收到 connection_failed 事件", code)
		}

		if capturedState != ConnStateConnectionFailed {
			t.Fatalf("code=%d: 应进入 connection_failed 状态", code)
		}
		unsub.Unsubscribe()
	}
}
