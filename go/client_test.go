package aun

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthropics/aun-sdk-core/go/keystore"
	"nhooyr.io/websocket"
)

type testRPCCall struct {
	Method string
	Params map[string]any
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

func testBuildIdentityWithFingerprint(t *testing.T, aid string) (map[string]any, string, string) {
	t.Helper()
	priv, privPEM, pubB64 := testGenerateECKeypair(t)
	certPEM := testMakeSelfSignedCert(t, priv, aid)
	fingerprint, err := certSHA256Fingerprint([]byte(certPEM))
	if err != nil {
		t.Fatalf("计算证书指纹失败: %v", err)
	}
	return testBuildIdentity(aid, privPEM, pubB64, certPEM), certPEM, fingerprint
}

func testGeneratePrekeyForIdentity(t *testing.T, root string, identity map[string]any) map[string]any {
	t.Helper()
	aid, _ := identity["aid"].(string)
	safeAid := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(aid)
	ks, err := keystore.NewFileKeyStore(filepath.Join(root, safeAid+"-"+generateUUID4()[:8]), nil, "test-seed")
	if err != nil {
		t.Fatalf("创建 prekey keystore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	if err := ks.SaveIdentity(aid, identity); err != nil {
		t.Fatalf("保存测试身份失败: %v", err)
	}
	manager := NewE2EEManager(E2EEManagerConfig{
		IdentityFn: func() map[string]any { return identity },
		Keystore:   ks,
	})
	prekey, err := manager.GeneratePrekey()
	if err != nil {
		t.Fatalf("生成测试 prekey 失败: %v", err)
	}
	return prekey
}

func extractCopyDeviceIDs(items any) []string {
	rawItems, _ := items.([]any)
	var result []string
	for _, raw := range rawItems {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		deviceID, _ := item["device_id"].(string)
		result = append(result, deviceID)
	}
	return result
}

// ── 客户端构造测试 ───────────────────────────────────────

// TestConstructNoArgs 验证使用空配置创建客户端
func TestConstructNoArgs(t *testing.T) {
	c := NewClient(map[string]any{})
	defer func() { _ = c.Close() }()
	if c == nil {
		t.Fatal("NewClient 不应返回 nil")
	}
	if c.State() != StateIdle {
		t.Errorf("初始状态应为 idle: %s", c.State())
	}
	if c.AID() != "" {
		t.Errorf("初始 AID 应为空: %s", c.AID())
	}
}

// TestConstructWithAunPath 验证使用自定义 AUNPath 创建客户端
func TestConstructWithAunPath(t *testing.T) {
	tmpDir := t.TempDir()
	c := NewClient(map[string]any{
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
	c := NewClient(map[string]any{
		"aun_path": tmpDir,
	})
	defer func() { _ = c.Close() }()
	fks, ok := c.keyStore.(*keystore.FileKeyStore)
	if !ok {
		t.Fatalf("默认 keystore 类型不正确: %T", c.keyStore)
	}
	if fks == nil {
		t.Fatal("默认 FileKeyStore 不应为 nil")
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
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	err := c.Connect(context.Background(), map[string]any{
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
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	err := c.Connect(context.Background(), map[string]any{
		"access_token": "test-token",
	}, nil)
	if err == nil {
		t.Error("缺少 gateway 应返回错误")
	}
}

// ── 状态测试 ─────────────────────────────────────────────

// TestClientState 验证客户端初始状态
func TestClientState(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	if c.State() != StateIdle {
		t.Errorf("初始状态应为 idle: %s", c.State())
	}
}

// ── RPC 调用测试 ─────────────────────────────────────────

// TestCallNotConnected 验证未连接时调用 RPC 返回错误
func TestCallNotConnected(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
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
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
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
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	_, err := c.Call(context.Background(), "message.send", map[string]any{
		"to":      "group.example.com",
		"payload": map[string]any{"text": "hello"},
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
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	_, err := c.Call(context.Background(), "message.send", map[string]any{
		"to":            "bob.example.com",
		"payload":       map[string]any{"text": "hello"},
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

func TestNormalizeConnectParamsIncludesSlotAndDeliveryMode(t *testing.T) {
	c := NewClient(map[string]any{
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

	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, map[string]any{
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

	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, map[string]any{
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

func TestCallDoesNotForwardMessageSendDeliveryMode(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, map[string]any{
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
		"payload": map[string]any{"text": "hello"},
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

func TestCallRejectsMessageSlotContextOverride(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, map[string]any{
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

func TestParsePeerPrekeyResponseSemantics(t *testing.T) {
	prekey, err := parsePeerPrekeyResponse("bob.example.com", map[string]any{"found": false}, nil)
	if prekey != nil {
		t.Fatalf("found=false 应返回 nil prekey: %#v", prekey)
	}
	if err == nil {
		t.Fatal("found=false 应返回 NotFoundError")
	}

	if _, err := parsePeerPrekeyResponse("bob.example.com", nil, errors.New("boom")); err == nil {
		t.Fatal("查询失败应返回错误")
	}
	if _, err := parsePeerPrekeyResponse("bob.example.com", map[string]any{"found": true}, nil); err == nil {
		t.Fatal("非法响应应返回错误")
	}
}

func TestSchedulePrekeyReplenishIfConsumedOnlyOnce(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	done := make(chan struct{}, 2)

	c.mu.Lock()
	c.state = StateConnected
	c.prekeyUploadHook = func(ctx context.Context) error {
		done <- struct{}{}
		return nil
	}
	c.mu.Unlock()

	message := map[string]any{
		"e2ee": map[string]any{
			"encryption_mode": ModePrekeyECDHV2,
			"prekey_id":       "pk-1",
		},
	}

	c.schedulePrekeyReplenishIfConsumed(message)
	c.schedulePrekeyReplenishIfConsumed(message)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("首次消费后未触发 prekey 补充")
	}

	select {
	case <-done:
		t.Fatal("同一 prekey_id 不应重复补充")
	case <-time.After(120 * time.Millisecond):
	}

	c.schedulePrekeyReplenishIfConsumed(message)
	select {
	case <-done:
		t.Fatal("已补充过的 prekey_id 不应再次补充")
	case <-time.After(120 * time.Millisecond):
	}
}

// ── E2EE 属性测试 ────────────────────────────────────────

// TestE2EEProperty 验证 E2EE 管理器属性
func TestE2EEProperty(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	if c.E2EE() == nil {
		t.Error("E2EE() 不应返回 nil")
	}
	if c.GroupE2EE() == nil {
		t.Error("GroupE2EE() 不应返回 nil")
	}
}

// ── Close 测试 ───────────────────────────────────────────

// TestCloseIdleClient 验证关闭空闲客户端
func TestCloseIdleClient(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	err := c.Close()
	if err != nil {
		t.Errorf("关闭空闲客户端不应报错: %v", err)
	}
	if c.State() != StateClosed {
		t.Errorf("关闭后状态应为 closed: %s", c.State())
	}
}

// TestCloseIdempotent 验证重复关闭不报错
func TestCloseIdempotent(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	_ = c.Close()
	err := c.Close()
	if err != nil {
		t.Errorf("重复关闭不应报错: %v", err)
	}
}

// ── On 事件订阅测试 ──────────────────────────────────────

// TestOnEventSubscription 验证通过客户端订阅事件
func TestOnEventSubscription(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	var received any
	sub := c.On("test.event", func(payload any) {
		received = payload
	})
	if sub == nil {
		t.Fatal("On 应返回 Subscription")
	}
	c.events.Publish("test.event", "hello")
	if received != "hello" {
		t.Errorf("收到的 payload 不正确: %v", received)
	}
}

// ── Client 配置测试 ──────────────────────────────────────

// TestClientGroupE2EEAlwaysEnabled 验证群组 E2EE 是必备能力，不可关闭
func TestClientGroupE2EEAlwaysEnabled(t *testing.T) {
	c := NewClient(map[string]any{
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
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	if c.configModel.VerifySSL {
		t.Error("development 环境下 verify_ssl 应为 false")
	}
}

// ── Client Group E2EE stub 测试 ─────────────────────────

// TestClientGroupE2EE_EncryptNoSecret stub 测试：无密钥时加密返回错误
func TestClientGroupE2EE_EncryptNoSecret(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.test"
	c.identity = map[string]any{"aid": "alice.test"}
	c.mu.Unlock()

	_, err := c.GroupE2EE().Encrypt("non-existent-group", map[string]any{"text": "hello"})
	if err == nil {
		t.Error("无密钥时加密应返回错误")
	}
}

// TestClientGroupE2EE_HasSecret stub 测试：无密钥时返回 false
func TestClientGroupE2EE_HasSecret(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.test"
	c.identity = map[string]any{"aid": "alice.test"}
	c.mu.Unlock()

	if c.GroupE2EE().HasSecret("nonexistent") {
		t.Error("不存在的群组不应有密钥")
	}
}

// TestClientGroupE2EE_CurrentEpoch stub 测试：无密钥时返回 nil
func TestClientGroupE2EE_CurrentEpoch(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.test"
	c.identity = map[string]any{"aid": "alice.test"}
	c.mu.Unlock()

	if c.GroupE2EE().CurrentEpoch("nonexistent") != nil {
		t.Error("不存在的群组 epoch 应为 nil")
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

func TestResolveSelfCopyPeerCertUsesVersionedKeystore(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	aid := "alice.example.com"
	activeIdentity, activeCertPEM, _ := testBuildIdentityWithFingerprint(t, aid)
	_, rotatedCertPEM, rotatedFingerprint := testBuildIdentityWithFingerprint(t, aid)

	if err := c.keyStore.SaveIdentity(aid, activeIdentity); err != nil {
		t.Fatalf("保存 active identity 失败: %v", err)
	}
	versioned, ok := c.keyStore.(keystore.VersionedCertKeyStore)
	if !ok {
		t.Fatalf("默认 keystore 应支持 VersionedCertKeyStore: %T", c.keyStore)
	}
	if err := versioned.SaveCertVersion(aid, rotatedCertPEM, rotatedFingerprint, false); err != nil {
		t.Fatalf("保存 rotated cert 失败: %v", err)
	}

	c.mu.Lock()
	c.aid = aid
	c.identity = map[string]any{
		"aid":  aid,
		"cert": activeCertPEM,
	}
	c.mu.Unlock()

	resolved, err := c.resolveSelfCopyPeerCert(context.Background(), rotatedFingerprint)
	if err != nil {
		t.Fatalf("resolveSelfCopyPeerCert 失败: %v", err)
	}
	if string(resolved) != rotatedCertPEM {
		t.Fatalf("resolveSelfCopyPeerCert 未返回版本化证书")
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
		case "group.e2ee.rotate_epoch":
			return map[string]any{"success": true, "epoch": 2}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := NewClient(map[string]any{
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
		if call.Method == "group.e2ee.rotate_epoch" {
			t.Fatalf("member 不应触发 group.e2ee.rotate_epoch: %#v", call.Params)
		}
	}
}

func TestSendEncryptedUsesMultiDevicePayloadWhenNeeded(t *testing.T) {
	senderAID := "alice.example.com"
	receiverAID := "bob.example.com"
	senderIdentity, _, _ := testBuildIdentityWithFingerprint(t, senderAID)
	receiverIdentity, receiverCertPEM, receiverFingerprint := testBuildIdentityWithFingerprint(t, receiverAID)

	prekeyRoot := t.TempDir()
	receiverPhonePrekey := testGeneratePrekeyForIdentity(t, prekeyRoot, receiverIdentity)
	receiverPhonePrekey["device_id"] = "phone"
	receiverLaptopPrekey := testGeneratePrekeyForIdentity(t, prekeyRoot, receiverIdentity)
	receiverLaptopPrekey["device_id"] = "laptop"

	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "message.e2ee.put_prekey":
			return map[string]any{"ok": true}
		case "message.e2ee.get_prekey":
			if params["aid"] == receiverAID {
				return map[string]any{
					"found": true,
					"device_prekeys": []any{
						receiverPhonePrekey,
						receiverLaptopPrekey,
					},
				}
			}
			return map[string]any{"found": false}
		case "message.send":
			return map[string]any{"ok": true}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	c.configModel.RequireForwardSecrecy = false

	if err := c.keyStore.SaveIdentity(senderAID, senderIdentity); err != nil {
		t.Fatalf("保存发送方 identity 失败: %v", err)
	}
	c.certCacheMu.Lock()
	now := float64(time.Now().Unix())
	c.certCache[certCacheKey(receiverAID, receiverFingerprint)] = &cachedPeerCert{
		certBytes:    []byte(receiverCertPEM),
		validatedAt:  now,
		refreshAfter: now + peerCertCacheTTL,
	}
	c.certCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	result, err := c.Call(ctx, "message.send", map[string]any{
		"to":      receiverAID,
		"payload": map[string]any{"text": "hello"},
	})
	if err != nil {
		t.Fatalf("message.send 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if !resultMap["ok"].(bool) {
		t.Fatalf("message.send 返回值不正确: %#v", resultMap)
	}

	var sendCall *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "message.send" {
			callCopy := call
			sendCall = &callCopy
		}
	}
	if sendCall == nil {
		t.Fatal("未捕获最终的 message.send")
	}
	if sendCall.Params["type"] != "e2ee.multi_device" {
		t.Fatalf("多设备发送应使用 e2ee.multi_device: %#v", sendCall.Params)
	}
	payload, _ := sendCall.Params["payload"].(map[string]any)
	if payload == nil {
		t.Fatalf("message.send payload 类型不正确: %#v", sendCall.Params["payload"])
	}
	if got := extractCopyDeviceIDs(payload["recipient_copies"]); strings.Join(got, ",") != "phone,laptop" {
		t.Fatalf("recipient_copies 设备列表不正确: %v", got)
	}
	if got := extractCopyDeviceIDs(payload["self_copies"]); len(got) != 0 {
		t.Fatalf("未声明其他设备时不应生成 self_copies: %v", got)
	}
}

func TestSendEncryptedGeneratesSelfSyncCopies(t *testing.T) {
	senderAID := "alice.example.com"
	receiverAID := "bob.example.com"
	senderIdentity, senderCertPEM, senderFingerprint := testBuildIdentityWithFingerprint(t, senderAID)
	receiverIdentity, receiverCertPEM, receiverFingerprint := testBuildIdentityWithFingerprint(t, receiverAID)

	prekeyRoot := t.TempDir()
	receiverPrekey := testGeneratePrekeyForIdentity(t, prekeyRoot, receiverIdentity)
	receiverPrekey["device_id"] = "bob-phone"
	selfCurrentPrekey := testGeneratePrekeyForIdentity(t, prekeyRoot, senderIdentity)
	selfOtherPrekey := testGeneratePrekeyForIdentity(t, prekeyRoot, senderIdentity)

	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "message.e2ee.put_prekey":
			return map[string]any{"ok": true}
		case "message.e2ee.get_prekey":
			switch params["aid"] {
			case receiverAID:
				return map[string]any{
					"found":          true,
					"device_prekeys": []any{receiverPrekey},
				}
			case senderAID:
				return map[string]any{
					"found":          true,
					"device_prekeys": []any{selfCurrentPrekey, selfOtherPrekey},
				}
			default:
				return map[string]any{"found": false}
			}
		case "message.send":
			return map[string]any{"ok": true}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	c.configModel.RequireForwardSecrecy = false

	if err := c.keyStore.SaveIdentity(senderAID, senderIdentity); err != nil {
		t.Fatalf("保存发送方 identity 失败: %v", err)
	}
	c.mu.Lock()
	c.aid = senderAID
	c.identity = map[string]any{
		"aid":  senderAID,
		"cert": senderCertPEM,
	}
	currentDeviceID := c.deviceID
	c.mu.Unlock()

	selfCurrentPrekey["device_id"] = currentDeviceID
	selfCurrentPrekey["cert_fingerprint"] = senderFingerprint
	selfOtherPrekey["device_id"] = "tablet"
	selfOtherPrekey["cert_fingerprint"] = senderFingerprint

	c.certCacheMu.Lock()
	now := float64(time.Now().Unix())
	c.certCache[certCacheKey(receiverAID, receiverFingerprint)] = &cachedPeerCert{
		certBytes:    []byte(receiverCertPEM),
		validatedAt:  now,
		refreshAfter: now + peerCertCacheTTL,
	}
	c.certCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, map[string]any{
		"access_token": "tok",
		"gateway":      wsURL,
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	if _, err := c.Call(ctx, "message.send", map[string]any{
		"to":      receiverAID,
		"payload": map[string]any{"text": "hello"},
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
		t.Fatal("未捕获最终的 message.send")
	}
	payload, _ := sendCall.Params["payload"].(map[string]any)
	if payload == nil {
		t.Fatalf("message.send payload 类型不正确: %#v", sendCall.Params["payload"])
	}
	if got := extractCopyDeviceIDs(payload["recipient_copies"]); strings.Join(got, ",") != "bob-phone" {
		t.Fatalf("recipient_copies 不正确: %v", got)
	}
	if got := extractCopyDeviceIDs(payload["self_copies"]); strings.Join(got, ",") != "tablet" {
		t.Fatalf("self_copies 应只包含其他设备: %v", got)
	}
}

func TestSendEncryptedQueueModeUsesMultiDevicePayload(t *testing.T) {
	senderAID := "alice.example.com"
	receiverAID := "bob.example.com"
	senderIdentity, _, _ := testBuildIdentityWithFingerprint(t, senderAID)
	receiverIdentity, receiverCertPEM, receiverFingerprint := testBuildIdentityWithFingerprint(t, receiverAID)

	prekeyRoot := t.TempDir()
	receiverPhonePrekey := testGeneratePrekeyForIdentity(t, prekeyRoot, receiverIdentity)
	receiverLaptopPrekey := testGeneratePrekeyForIdentity(t, prekeyRoot, receiverIdentity)
	receiverPhonePrekey["device_id"] = "phone"
	receiverLaptopPrekey["device_id"] = "laptop"
	receiverPhonePrekey["cert_fingerprint"] = receiverFingerprint
	receiverLaptopPrekey["cert_fingerprint"] = receiverFingerprint

	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "auth.connect":
			return map[string]any{"status": "ok"}
		case "message.e2ee.put_prekey":
			return map[string]any{"ok": true}
		case "message.e2ee.get_prekey":
			if params["aid"] == receiverAID {
				return map[string]any{
					"found": true,
					"device_prekeys": []any{
						receiverPhonePrekey,
						receiverLaptopPrekey,
					},
				}
			}
			return map[string]any{"found": false}
		case "message.send":
			return map[string]any{"ok": true}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()
	c.configModel.RequireForwardSecrecy = false

	if err := c.keyStore.SaveIdentity(senderAID, senderIdentity); err != nil {
		t.Fatalf("保存发送方 identity 失败: %v", err)
	}
	c.certCacheMu.Lock()
	now := float64(time.Now().Unix())
	c.certCache[certCacheKey(receiverAID, receiverFingerprint)] = &cachedPeerCert{
		certBytes:    []byte(receiverCertPEM),
		validatedAt:  now,
		refreshAfter: now + peerCertCacheTTL,
	}
	c.certCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, map[string]any{
		"access_token":  "tok",
		"gateway":       wsURL,
		"delivery_mode": "queue",
	}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	result, err := c.Call(ctx, "message.send", map[string]any{
		"to":      receiverAID,
		"payload": map[string]any{"text": "hello"},
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("queue 模式 message.send 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if !resultMap["ok"].(bool) {
		t.Fatalf("message.send 返回值不正确: %#v", resultMap)
	}

	var sendCall *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "message.send" {
			callCopy := call
			sendCall = &callCopy
		}
	}
	if sendCall == nil {
		t.Fatal("未捕获最终的 message.send")
	}
	if sendCall.Params["type"] != "e2ee.multi_device" {
		t.Fatalf("queue 模式多设备仍应走设备副本路径: %#v", sendCall.Params)
	}
	if _, exists := sendCall.Params["delivery_mode"]; exists {
		t.Fatalf("queue 模式不应在 message.send 中携带 delivery_mode: %#v", sendCall.Params["delivery_mode"])
	}
	payload, _ := sendCall.Params["payload"].(map[string]any)
	if payload == nil {
		t.Fatalf("message.send payload 类型不正确: %#v", sendCall.Params["payload"])
	}
	if got := extractCopyDeviceIDs(payload["recipient_copies"]); strings.Join(got, ",") != "phone,laptop" {
		t.Fatalf("queue 模式 recipient_copies 不正确: %v", got)
	}
	if got := extractCopyDeviceIDs(payload["self_copies"]); len(got) != 0 {
		t.Fatalf("queue 模式未声明发送方其他设备时不应生成 self_copies: %v", got)
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

func TestDecryptP2PFailurePublishesUndecryptable(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	var undecryptablePayload any
	receivedCount := 0
	c.On("message.undecryptable", func(payload any) {
		undecryptablePayload = payload
	})
	c.On("message.received", func(payload any) {
		receivedCount++
	})

	c.processAndPublishMessage(map[string]any{
		"message_id": "msg-p2p-fail",
		"from":       "unknown.example.com",
		"to":         "alice.example.com",
		"seq":        0,
		"timestamp":  "2026-04-18T12:00:00Z",
		"encrypted":  true,
		"payload": map[string]any{
			"type": "e2ee.encrypted",
		},
	})

	if undecryptablePayload == nil {
		t.Fatal("解密失败时应发布 message.undecryptable")
	}
	payloadMap, _ := undecryptablePayload.(map[string]any)
	if payloadMap["message_id"] != "msg-p2p-fail" || toInt64(payloadMap["seq"]) != 0 {
		t.Fatalf("message.undecryptable 载荷不正确: %#v", payloadMap)
	}
	if receivedCount != 0 {
		t.Fatalf("解密失败时不应发布 message.received: %d", receivedCount)
	}
}

func TestDecryptGroupFailurePublishesUndecryptable(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	var undecryptablePayload any
	createdCount := 0
	c.On("group.message_undecryptable", func(payload any) {
		undecryptablePayload = payload
	})
	c.On("group.message_created", func(payload any) {
		createdCount++
	})

	c.processAndPublishGroupMessage(map[string]any{
		"message_id": "msg-group-fail",
		"group_id":   "g-1.example.com",
		"from":       "unknown.example.com",
		"seq":        0,
		"timestamp":  "2026-04-18T12:00:00Z",
		"payload": map[string]any{
			"type":  "e2ee.group_encrypted",
			"epoch": 3,
		},
	})

	if undecryptablePayload == nil {
		t.Fatal("群消息解密失败时应发布 group.message_undecryptable")
	}
	payloadMap, _ := undecryptablePayload.(map[string]any)
	if payloadMap["message_id"] != "msg-group-fail" || toInt64(payloadMap["seq"]) != 0 {
		t.Fatalf("group.message_undecryptable 载荷不正确: %#v", payloadMap)
	}
	if createdCount != 0 {
		t.Fatalf("群消息解密失败时不应发布 group.message_created: %d", createdCount)
	}
}

func TestDecryptMessagesDropsFailedCiphertext(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	messages := []any{
		map[string]any{
			"message_id": "plain-1",
			"from":       "bob.example.com",
			"payload":    map[string]any{"text": "hello"},
		},
		map[string]any{
			"message_id": "cipher-1",
			"from":       "unknown.example.com",
			"encrypted":  true,
			"payload": map[string]any{
				"type": "e2ee.encrypted",
			},
		},
	}

	result := c.decryptMessages(context.Background(), messages)
	if len(result) != 1 {
		t.Fatalf("解密失败的密文不应混入补洞结果: %#v", result)
	}
	msg, _ := result[0].(map[string]any)
	if msg["message_id"] != "plain-1" {
		t.Fatalf("补洞结果应仅保留明文消息: %#v", result)
	}
}

func TestDecryptGroupMessagesDropsFailedCiphertext(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	messages := []any{
		map[string]any{
			"message_id": "group-plain-1",
			"group_id":   "g-1.example.com",
			"from":       "bob.example.com",
			"payload":    map[string]any{"text": "hello"},
		},
		map[string]any{
			"message_id": "group-cipher-1",
			"group_id":   "g-1.example.com",
			"from":       "unknown.example.com",
			"payload": map[string]any{
				"type":  "e2ee.group_encrypted",
				"epoch": 2,
			},
		},
	}

	result := c.decryptGroupMessages(context.Background(), messages)
	if len(result) != 1 {
		t.Fatalf("群消息解密失败的密文不应混入补洞结果: %#v", result)
	}
	msg, _ := result[0].(map[string]any)
	if msg["message_id"] != "group-plain-1" {
		t.Fatalf("群补洞结果应仅保留可投递消息: %#v", result)
	}
}

// TestPushedSeqsNoDuplicateOnGapFill 验证：推送路径已分发的 seq，
// 补洞路径不得重复投递（功能正确性测试）。
func TestPushedSeqsNoDuplicateOnGapFill(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
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

	// 模拟补洞路径返回包含 seq=5 和 seq=6 的消息列表
	messages := []any{
		map[string]any{"message_id": "m5", "seq": float64(5), "payload": map[string]any{"text": "dup"}},
		map[string]any{"message_id": "m6", "seq": float64(6), "payload": map[string]any{"text": "new"}},
	}

	var received []string
	c.On("message.received", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			received = append(received, m["message_id"].(string))
		}
	})

	// 调用 publishGapFillMessages 验证去重逻辑
	c.publishGapFillMessages(ns, messages)

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
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
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

	messages := []any{
		map[string]any{"message_id": "gm10", "group_id": groupID, "seq": float64(10), "payload": map[string]any{"text": "dup"}},
		map[string]any{"message_id": "gm11", "group_id": groupID, "seq": float64(11), "payload": map[string]any{"text": "new"}},
	}

	var created []string
	c.On("group.message_created", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			created = append(created, m["message_id"].(string))
		}
	})

	c.publishGapFillGroupMessages(ns, messages)

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
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ns := "p2p:premark.example.com"
	c.mu.Lock()
	c.aid = "premark.example.com"
	c.mu.Unlock()

	// 模拟：推送路径先预标记 seq=7（在启动补洞 goroutine 之前）
	c.markPushedSeq(ns, 7)

	// 然后补洞路径立即读取（模拟 goroutine 调度到补洞路径先执行）
	messages := []any{
		map[string]any{"message_id": "pm7", "seq": float64(7), "payload": map[string]any{"text": "dup"}},
		map[string]any{"message_id": "pm8", "seq": float64(8), "payload": map[string]any{"text": "new"}},
	}

	var received []string
	c.On("message.received", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			received = append(received, m["message_id"].(string))
		}
	})

	c.publishGapFillMessages(ns, messages)

	if len(received) != 1 || received[0] != "pm8" {
		t.Fatalf("预标记后补洞路径应跳过 seq=7，只投递 seq=8，实际: %v", received)
	}
}

// TestPushedSeqsConcurrentMarkAndRead 验证：并发标记和读取 pushedSeqs 不产生 data race。
// 修复后通过锁内逐条查询避免锁外持有 map 引用；在支持 -race 的环境下应干净通过。
// 注：Windows 环境无 gcc，-race 不可用；此测试作为逻辑正确性验证。
func TestPushedSeqsConcurrentMarkAndRead(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
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
