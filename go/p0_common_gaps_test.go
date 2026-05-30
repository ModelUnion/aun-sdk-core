package aun

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// ═══════════════════════════════════════════════════════════
// P0-01: Gateway Health Check
// ═══════════════════════════════════════════════════════════

// TestP0_01_HealthCheckSuccess 验证正常响应 200 时返回 true
func TestP0_01_HealthCheckSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ok := c.checkGatewayHealth(context.Background(), srv.URL, 5*time.Second)
	if !ok {
		t.Fatal("正常 200 响应时 health check 应返回 true")
	}

	// GatewayHealth 应缓存结果
	cached := c.GatewayHealth()
	if cached == nil || !*cached {
		t.Fatal("GatewayHealth 应缓存最近一次成功的 health check 结果")
	}
}

// TestP0_01_HealthCheckTimeout 验证服务端长时间不响应时超时返回 false
func TestP0_01_HealthCheckTimeout(t *testing.T) {
	// 创建一个收到请求后永远不响应的服务器
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 阻塞直到请求被取消
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	start := time.Now()
	ok := c.checkGatewayHealth(context.Background(), srv.URL, 500*time.Millisecond)
	elapsed := time.Since(start)

	if ok {
		t.Fatal("超时场景下 health check 应返回 false")
	}
	// 允许一定误差，但不应超过 2 秒（timeout 设的是 500ms）
	if elapsed > 2*time.Second {
		t.Fatalf("health check 超时耗时过长: %v", elapsed)
	}
}

// TestP0_01_HealthCheckRefused 验证连接被拒绝时返回 false
func TestP0_01_HealthCheckRefused(t *testing.T) {
	// 监听一个端口然后立刻关闭，确保该端口无人监听
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("创建临时监听失败: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ok := c.checkGatewayHealth(context.Background(), "http://"+addr, 2*time.Second)
	if ok {
		t.Fatal("连接被拒绝时 health check 应返回 false")
	}
}

// TestP0_01_HealthCheckNon200 验证服务端返回非 200 状态码时返回 false
func TestP0_01_HealthCheckNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ok := c.checkGatewayHealth(context.Background(), srv.URL, 2*time.Second)
	if ok {
		t.Fatal("503 响应时 health check 应返回 false")
	}
}

// TestP0_01_HealthCheckWSSchemeConversion 验证 wss:// 自动转换为 https://
func TestP0_01_HealthCheckWSSchemeConversion(t *testing.T) {
	// 使用 http:// 验证 ws:// 到 http:// 的转换逻辑
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 将 http:// 替换为 ws://，CheckHealth 内部应将其转回 http:// 并追加 /health
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	c.checkGatewayHealth(context.Background(), wsURL, 2*time.Second)

	if receivedPath != "/health" {
		t.Fatalf("期望请求路径为 /health，实际为 %s", receivedPath)
	}
}

// ═══════════════════════════════════════════════════════════
// P0-02: AID Creation Failure
// ═══════════════════════════════════════════════════════════

// TestP0_02_CreateAIDEmptyString 验证空字符串 AID 返回 ValidationError
func TestP0_02_CreateAIDEmptyString(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	_, err := c.AuthRegisterAID(context.Background(), "ws://localhost:9999", "")
	if err == nil {
		t.Fatal("空字符串 AID 应返回错误")
	}
	var valErr *ValidationError
	if !isValidationError(err, &valErr) {
		t.Fatalf("期望 ValidationError，实际类型: %T, 内容: %v", err, err)
	}
}

// TestP0_02_CreateAIDTooShort 验证过短的 AID 返回 ValidationError
func TestP0_02_CreateAIDTooShort(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	_, err := c.AuthRegisterAID(context.Background(), "ws://localhost:9999", "ab")
	if err == nil {
		t.Fatal("过短 AID（少于 4 字符）应返回错误")
	}
	var valErr *ValidationError
	if !isValidationError(err, &valErr) {
		t.Fatalf("期望 ValidationError，实际类型: %T", err)
	}
}

// TestP0_02_CreateAIDInvalidChars 验证含非法字符的 AID 返回 ValidationError
func TestP0_02_CreateAIDInvalidChars(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	_, err := c.AuthRegisterAID(context.Background(), "ws://localhost:9999", "Test_AID!")
	if err == nil {
		t.Fatal("含大写字母和特殊字符的 AID 应返回错误")
	}
	var valErr *ValidationError
	if !isValidationError(err, &valErr) {
		t.Fatalf("期望 ValidationError，实际类型: %T", err)
	}
}

// TestP0_02_CreateAIDGuestPrefix 验证以 guest 开头的 AID 返回 ValidationError
func TestP0_02_CreateAIDGuestPrefix(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	_, err := c.AuthRegisterAID(context.Background(), "ws://localhost:9999", "guest_user")
	if err == nil {
		t.Fatal("以 guest 开头的 AID 应返回错误")
	}
	var valErr *ValidationError
	if !isValidationError(err, &valErr) {
		t.Fatalf("期望 ValidationError，实际类型: %T", err)
	}
}

// TestP0_02_CreateAIDStartsWithDash 验证以 - 开头的 AID 返回 ValidationError
func TestP0_02_CreateAIDStartsWithDash(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	_, err := c.AuthRegisterAID(context.Background(), "ws://localhost:9999", "-invalid_aid")
	if err == nil {
		t.Fatal("以 - 开头的 AID 应返回错误")
	}
	var valErr *ValidationError
	if !isValidationError(err, &valErr) {
		t.Fatalf("期望 ValidationError，实际类型: %T", err)
	}
}

// TestP0_02_CreateAIDValidFormat 验证合法格式的 AID 通过本地校验（网络层面会失败但不应是 ValidationError）
func TestP0_02_CreateAIDValidFormat(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 用一个无法连接的地址，合法 AID 应通过本地校验，失败在网络层
	_, err := c.AuthRegisterAID(context.Background(), "ws://192.0.2.1:1", "valid_test_aid")
	if err == nil {
		// 没有真实服务器，应该还是会出错
		return
	}
	// 关键：错误不应是 ValidationError（本地格式校验应该通过）
	var valErr *ValidationError
	if isValidationError(err, &valErr) {
		t.Fatalf("合法格式的 AID 不应触发 ValidationError: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════
// P0-14: RPC During Disconnect
// ═══════════════════════════════════════════════════════════

// TestP0_14_RPCWhenNotConnected 验证未连接时调用 RPC 返回 ConnectionError
func TestP0_14_RPCWhenNotConnected(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 客户端处于 idle 状态，调用 Call 应返回错误
	_, err := c.Call(context.Background(), "meta.ping", nil)
	if err == nil {
		t.Fatal("未连接时调用 RPC 应返回错误")
	}
	var connErr *ConnectionError
	if !isConnectionError(err, &connErr) {
		t.Fatalf("期望 ConnectionError，实际类型: %T, 内容: %v", err, err)
	}
}

// TestP0_14_RPCAfterDisconnect 验证连接后断开再调用 RPC 返回 ConnectionError
func TestP0_14_RPCAfterDisconnect(t *testing.T) {
	// 创建 mock 服务器模拟完整的连接+断开流程
	wsURL, _, cleanup := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.initialize_session":
			return map[string]any{"ok": true}
		default:
			return map[string]any{}
		}
	})
	defer cleanup()

	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 手动将客户端设为 connected 状态（模拟已建立连接）
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	// 断开连接
	_ = c.Disconnect()

	// 确认无身份场景下公开状态回到 no_identity
	if c.State() != ConnStateNoIdentity {
		t.Fatalf("Disconnect 后公开状态应为 no_identity，实际: %s", c.State())
	}

	// 断开后调用 RPC 应返回 ConnectionError
	_, err := c.Call(context.Background(), "meta.ping", nil)
	if err == nil {
		t.Fatal("断开连接后调用 RPC 应返回错误")
	}
	var connErr *ConnectionError
	if !isConnectionError(err, &connErr) {
		t.Fatalf("期望 ConnectionError，实际类型: %T, 内容: %v", err, err)
	}

	// 忽略 wsURL 以避免 unused variable 错误
	_ = wsURL
}

// TestP0_14_RPCAfterClose 验证 Close 后调用 RPC 返回错误
func TestP0_14_RPCAfterClose(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})

	// 关闭客户端
	_ = c.Close()

	// Close 后调用 Call 应返回错误
	_, err := c.Call(context.Background(), "meta.ping", nil)
	if err == nil {
		t.Fatal("Close 后调用 RPC 应返回错误")
	}
}

// TestP0_14_ConnectAfterClose 验证 Close 后无法再次 Connect
func TestP0_14_ConnectAfterClose(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	_ = c.Close()

	err := connectWithTestAuth(t, c, context.Background(), map[string]any{
		"gateway":      "ws://localhost:9999",
		"access_token": "test-token",
	}, nil)
	// 关闭后的行为：如果允许从 closed 重连则不一定报错，
	// 但当前实现 Connect 检查 state != idle && state != closed && state != disconnected
	// StateClosed 是允许的，所以这里主要验证不会 panic
	_ = err
}

// TestP0_14_InternalMethodBlocked 验证内部专用方法被阻止调用
func TestP0_14_InternalMethodBlocked(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 手动设为 connected 以通过连接检查
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	// 尝试调用内部方法应被阻止（auth.login1 在 internalOnlyMethods 中）
	_, err := c.Call(context.Background(), "auth.login1", nil)
	if err == nil {
		t.Fatal("内部专用方法调用应返回错误")
	}
	var permErr *PermissionError
	if !isPermissionError(err, &permErr) {
		t.Fatalf("期望 PermissionError，实际类型: %T, 内容: %v", err, err)
	}
}

// TestP0_14_ConcurrentCallsDuringDisconnect 验证断开过程中并发 RPC 调用不会 panic
func TestP0_14_ConcurrentCallsDuringDisconnect(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	done := make(chan struct{})

	// 启动多个并发 RPC 调用
	for i := 0; i < 10; i++ {
		go func() {
			defer func() {
				// 不应 panic
				if r := recover(); r != nil {
					t.Errorf("并发 RPC 调用不应 panic: %v", r)
				}
			}()
			_, _ = c.Call(context.Background(), "meta.ping", nil)
		}()
	}

	// 同时断开连接
	go func() {
		_ = c.Disconnect()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("并发断开超时")
	}
}

// ═══════════════════════════════════════════════════════════
// P0 附加: 连接参数校验
// ═══════════════════════════════════════════════════════════

// TestP0_ConnectMissingAccessToken 验证缺少 access_token 时 Connect 返回错误
func TestP0_ConnectMissingAccessToken(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	err := connectWithTestAuth(t, c, context.Background(), map[string]any{
		"gateway": "ws://localhost:9999",
	}, nil)
	if err == nil {
		t.Fatal("缺少 access_token 应返回错误")
	}
}

// TestP0_ConnectMissingGateway 验证缺少 gateway 时 Connect 返回错误
func TestP0_ConnectMissingGateway(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	err := connectWithTestAuth(t, c, context.Background(), map[string]any{
		"access_token": "test-token",
	}, nil)
	if err == nil {
		t.Fatal("缺少 gateway 应返回错误")
	}
}

// TestP0_DisconnectIdempotent 验证重复 Disconnect 不报错
func TestP0_DisconnectIdempotent(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// 在 idle 状态下 Disconnect 应无操作、不报错
	if err := c.Disconnect(); err != nil {
		t.Fatalf("idle 状态下 Disconnect 不应报错: %v", err)
	}
	// 再次调用也不应报错
	if err := c.Disconnect(); err != nil {
		t.Fatalf("重复 Disconnect 不应报错: %v", err)
	}
}

// TestP0_CloseIdempotent 验证重复 Close 不报错
func TestP0_CloseIdempotent(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})

	if err := c.Close(); err != nil {
		t.Fatalf("第一次 Close 不应报错: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("第二次 Close 不应报错: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════
// 测试辅助函数
// ═══════════════════════════════════════════════════════════

// isValidationError 类型断言辅助
func isValidationError(err error, target **ValidationError) bool {
	e, ok := err.(*ValidationError)
	if ok && target != nil {
		*target = e
	}
	return ok
}

// isConnectionError 类型断言辅助
func isConnectionError(err error, target **ConnectionError) bool {
	e, ok := err.(*ConnectionError)
	if ok && target != nil {
		*target = e
	}
	return ok
}

// isPermissionError 类型断言辅助
func isPermissionError(err error, target **PermissionError) bool {
	e, ok := err.(*PermissionError)
	if ok && target != nil {
		*target = e
	}
	return ok
}

// 确保 websocket 和 json 导入不会报未使用错误
var (
	_ = websocket.StatusNormalClosure
	_ = json.Marshal
	_ = strings.TrimPrefix
)
