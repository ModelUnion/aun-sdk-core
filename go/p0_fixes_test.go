package aun

import (
	"fmt"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════
// Fix-01: NewClient 应为包内私有（newClient）
// ═══════════════════════════════════════════════════════════

// TestFix01_NewClientIsPrivate 验证 newClient 在包内可用（编译即守卫）
func TestFix01_NewClientIsPrivate(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	if c == nil {
		t.Fatal("newClient 应返回非 nil 客户端")
	}
	_ = c.Close()
}

// ═══════════════════════════════════════════════════════════
// Fix-02: Publish 应顺序执行 handler
// ═══════════════════════════════════════════════════════════

// TestFix02_PublishSequential 验证 Publish 按注册顺序同步执行 handler
func TestFix02_PublishSequential(t *testing.T) {
	d := NewEventDispatcher()
	var order []int

	d.Subscribe("test", func(payload any) { order = append(order, 1) })
	d.Subscribe("test", func(payload any) { order = append(order, 2) })
	d.Subscribe("test", func(payload any) { order = append(order, 3) })

	d.Publish("test", nil)

	if len(order) != 3 {
		t.Fatalf("期望 3 个 handler 执行，实际 %d 个", len(order))
	}
	if order[0] != 1 || order[1] != 2 || order[2] != 3 {
		t.Fatalf("期望顺序 [1,2,3]，实际 %v", order)
	}
}

// TestFix02_PublishSyncAfterReturn 验证 Publish 返回后 handler 已全部执行
func TestFix02_PublishSyncAfterReturn(t *testing.T) {
	d := NewEventDispatcher()
	executed := false
	d.Subscribe("test", func(payload any) { executed = true })
	d.Publish("test", nil)
	if !executed {
		t.Fatal("Publish 应同步执行 handler，返回后 executed 应为 true")
	}
}

// ═══════════════════════════════════════════════════════════
// Fix-03: SetProtectedHeaders / GetProtectedHeaders
// ═══════════════════════════════════════════════════════════

func TestFix03_SetGetProtectedHeaders(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	c.SetProtectedHeaders(map[string]string{"x-app": "kite", "x-version": "1.0"})
	got := c.GetProtectedHeaders()
	if got["x-app"] != "kite" || got["x-version"] != "1.0" {
		t.Fatalf("GetProtectedHeaders 返回值不符: %v", got)
	}
}

func TestFix03_SetProtectedHeadersFiltersAuth(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	c.SetProtectedHeaders(map[string]string{"_auth": "should-be-filtered", "x-ok": "yes"})
	got := c.GetProtectedHeaders()
	if _, exists := got["_auth"]; exists {
		t.Fatal("_auth 保留键应被过滤")
	}
	if got["x-ok"] != "yes" {
		t.Fatalf("合法 key 应保留: %v", got)
	}
}

func TestFix03_SetProtectedHeadersFiltersInvalidKeys(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	c.SetProtectedHeaders(map[string]string{
		"valid-key":  "ok",
		"UPPER":      "bad",
		"has space":  "bad",
		"x_under":    "ok",
		"123numeric": "ok",
	})
	got := c.GetProtectedHeaders()
	if _, exists := got["UPPER"]; exists {
		t.Fatal("大写 key 应被过滤")
	}
	if _, exists := got["has space"]; exists {
		t.Fatal("含空格 key 应被过滤")
	}
	if got["valid-key"] != "ok" {
		t.Fatalf("合法 key 应保留: %v", got)
	}
}

func TestFix03_OptionsProtectedHeadersInitialized(t *testing.T) {
	c := NewAUNClientEmpty()
	defer c.Close()
	c.SetProtectedHeaders(map[string]string{"x-init": "from-options"})

	got := c.GetProtectedHeaders()
	if got["x-init"] != "from-options" {
		t.Fatalf("SetProtectedHeaders 应正确初始化: %v", got)
	}
}

// ═══════════════════════════════════════════════════════════
// Fix-04: connect 守卫放行 StateReconnecting / StateTerminalFailed
// ═══════════════════════════════════════════════════════════

func TestFix04_ConnectFromReconnecting(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	c.mu.Lock()
	c.state = StateReconnecting
	c.mu.Unlock()

	err := c.connectWithParams(nil, map[string]any{
		"gateway":      "ws://192.0.2.1:1",
		"access_token": "test",
	}, nil, false, true)
	if isStateErr(err) {
		t.Fatalf("StateReconnecting 下 connect 不应返回 StateError，实际: %v", err)
	}
}

func TestFix04_ConnectFromTerminalFailed(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	c.mu.Lock()
	c.state = StateTerminalFailed
	c.mu.Unlock()

	err := c.connectWithParams(nil, map[string]any{
		"gateway":      "ws://192.0.2.1:1",
		"access_token": "test",
	}, nil, false, true)
	if isStateErr(err) {
		t.Fatalf("StateTerminalFailed 下 connect 不应返回 StateError，实际: %v", err)
	}
}

func TestFix04_ConnectFromConnecting(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	c.mu.Lock()
	c.state = StateConnecting
	c.mu.Unlock()

	err := c.connectWithParams(nil, map[string]any{
		"gateway":      "ws://192.0.2.1:1",
		"access_token": "test",
	}, nil, false, true)
	if !isStateErr(err) {
		t.Fatalf("StateConnecting 下 connect 应返回 StateError，实际: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════
// Fix-05: loadIdentityFromAID 复位 state→idle
// ═══════════════════════════════════════════════════════════

func TestFix05_LoadIdentityResetsState(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	_ = c.Close()

	// 用 keystore 直接生成一个本地 AID（不需要服务端）
	aid, err := generateLocalAIDForTest(t)
	if err != nil {
		t.Fatalf("生成测试 AID 失败: %v", err)
	}

	if err := c.LoadIdentity(aid); err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	defer func() { _ = c.Close() }() // 确保 rebuildRuntimeForIdentity 创建的资源被释放

	if !c.HasIdentity() {
		t.Fatal("LoadIdentity 后 HasIdentity 应为 true")
	}

	c.mu.RLock()
	st := c.state
	c.mu.RUnlock()
	if st != StateIdle {
		t.Fatalf("LoadIdentity 后 state 应为 StateIdle，实际: %s", st)
	}
}

// ═══════════════════════════════════════════════════════════
// Fix-06: 缺失 getter
// ═══════════════════════════════════════════════════════════

func TestFix06_NextRetryInSeconds_Zero(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	if secs := c.NextRetryInSeconds(); secs != 0 {
		t.Fatalf("非重连状态 NextRetryInSeconds 应为 0，实际: %f", secs)
	}
}

func TestFix06_NextRetryInSeconds_Positive(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	c.mu.Lock()
	c.state = StateReconnecting
	c.nextRetryAt = time.Now().Add(30 * time.Second)
	c.mu.Unlock()

	if secs := c.NextRetryInSeconds(); secs <= 0 {
		t.Fatalf("重连退避状态 NextRetryInSeconds 应 > 0，实际: %f", secs)
	}
}

func TestFix06_RetryMaxAttempts(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	if n := c.RetryMaxAttempts(); n != 0 {
		t.Fatalf("默认 RetryMaxAttempts 应为 0，实际: %d", n)
	}
}

func TestFix06_LastError(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	if c.LastError() != nil {
		t.Fatal("初始 LastError 应为 nil")
	}
	testErr := NewConnectionError("test error")
	c.mu.Lock()
	c.lastConnectError = testErr
	c.mu.Unlock()
	if c.LastError() != testErr {
		t.Fatal("LastError 应返回注入的错误")
	}
}

func TestFix06_LastErrorCode(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	if c.LastErrorCode() != "" {
		t.Fatal("无错误时 LastErrorCode 应为空字符串")
	}
	c.mu.Lock()
	c.lastConnectError = NewConnectionError("test")
	c.mu.Unlock()
	if code := c.LastErrorCode(); code == "" {
		t.Fatal("有 ConnectionError 时 LastErrorCode 应返回非空字符串")
	}
}

// ═══════════════════════════════════════════════════════════
// 辅助函数
// ═══════════════════════════════════════════════════════════

func isStateErr(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*StateError)
	return ok
}

// generateLocalAIDForTest 生成一个仅含本地私钥的 AID（不需要服务端注册）
func generateLocalAIDForTest(t *testing.T) (*AID, error) {
	t.Helper()
	s := newTestAIDStore(t)
	aidStr := "testaid.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aidStr, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	saveTestIdentity(t, s, aidStr, certPEM, privPEM, pubB64)
	r := s.Load(aidStr)
	if !r.Ok {
		return nil, fmt.Errorf("%s: %s", r.Error.Code, r.Error.Message)
	}
	return r.Data.AID, nil
}
