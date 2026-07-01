//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"nhooyr.io/websocket"
)

// ---------------------------------------------------------------------------
// Token + gateway_url 复用集成测试（CLI 重启场景）
//
// 与 Python SDK tests/integration_test_token_gateway_reuse.py 一一对齐：
//   Test 1: 第一次 Authenticate 后 keystore 持久化 access_token + refresh_token + gateway_url
//   Test 2: 同 aun_path 新建第二个 client，Authenticate 时不调用 login + 不调用 discover
//   Test 3: 第二个 client 用 cached 直接 Connect + meta.ping 成功
//   Test 4: 手动把 expires_at 改成已过期，第二次 Authenticate 应走 login
//
// 运行：
//   MSYS_NO_PATHCONV=1 docker exec kite-go-tester sh -lc \
//     "cd /workspace/go && /usr/local/go/bin/go test -tags integration . \
//      -run TestTokenGatewayReuseIntegration -count=1 -v"
// ---------------------------------------------------------------------------

// makeReuseClient 构造共享 aun_path 的客户端，用于模拟 CLI 重启场景。
func makeReuseClient(t *testing.T, sharedPath string) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := newClient(map[string]any{
		"aun_path": sharedPath,
	}, true)
	client.configModel.RequireForwardSecrecy = false
	return client
}

// loadInstanceTokens 加载某个 AID 的 instance_state（device_id+slot_id 维度）。
// Go SDK 在 deviceID 非空时会把 access_token / refresh_token / kite_token /
// access_token_expires_at 保存到 instance_state 表（不在 tokens 表）。
func loadInstanceTokens(t *testing.T, c *AUNClient, aid string) map[string]any {
	t.Helper()
	store, ok := c.tokenStore.(keystore.InstanceStateStore)
	if !ok {
		t.Fatalf("tokenStore 未实现 InstanceStateStore: %T", c.tokenStore)
	}
	state, err := store.LoadInstanceState(aid, c.deviceID, c.slotID)
	if err != nil {
		t.Fatalf("LoadInstanceState 失败: %v", err)
	}
	return state
}

// expiryUnixFromIdentity 兼容 int / float64 / int64 等多种数值类型，从 identity
// 中读取 access_token_expires_at（Unix 秒）。
func expiryUnixFromIdentity(identity map[string]any) int64 {
	if identity == nil {
		return 0
	}
	switch v := identity["access_token_expires_at"].(type) {
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Test 1: 第一次 Authenticate 后 keystore 持久化 token + gateway_url
// ---------------------------------------------------------------------------

func TestTokenGatewayReuseIntegration_FirstAuthPersists(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-tgw-t1-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()

	client := makeReuseClient(t, sharedPath)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	loaded := integrationRegisterOrLoadAID(t, client.configModel.AUNPath, aid)
	if err := client.LoadIdentity(loaded); err != nil {
		t.Fatalf("加载身份失败: %v", err)
	}
	authResult, err := client.Authenticate(ctx)
	if err != nil {
		skipIfGatewayRateLimited(t, "首次 Authenticate", err)
		t.Fatalf("首次 Authenticate 失败: %v", err)
	}

	// 1. 返回值应包含非空 access_token
	accessToken, _ := authResult["access_token"].(string)
	if accessToken == "" {
		t.Fatal("首次 Authenticate 未返回 access_token")
	}

	// 2. instance_state 中持久化了 access_token + refresh_token + expires_at
	instanceState := loadInstanceTokens(t, client, aid)
	if got, _ := instanceState["access_token"].(string); got != accessToken {
		t.Fatalf("instance_state.access_token 与返回值不一致: got=%q want=%q", got, accessToken)
	}
	if got, _ := instanceState["refresh_token"].(string); got == "" {
		t.Fatal("instance_state 未保存 refresh_token")
	}
	if expiresAt := expiryUnixFromIdentity(instanceState); expiresAt <= time.Now().Unix() {
		t.Fatalf("instance_state.access_token_expires_at 应在未来: %d", expiresAt)
	}
	t.Logf("[OK] instance_state 持久化 access_token (len=%d) + refresh_token", len(accessToken))

	// 3. keystore metadata 中持久化了 gateway_url
	cachedGateway := strings.TrimSpace(client.AuthLoadCachedGatewayURL(aid))
	if cachedGateway == "" {
		t.Fatal("keystore metadata 未持久化 gateway_url")
	}
	gatewayInResult, _ := authResult["gateway"].(string)
	if cachedGateway != gatewayInResult {
		t.Fatalf("metadata gateway_url 与返回值不一致: cached=%q result=%q", cachedGateway, gatewayInResult)
	}
	t.Logf("[OK] keystore metadata 持久化 gateway_url=%s", cachedGateway)
}

// ---------------------------------------------------------------------------
// Test 2: 同 aun_path 第二个 client，Authenticate 不调 login 也不调 discover
// ---------------------------------------------------------------------------

func TestTokenGatewayReuseIntegration_SecondAuthSkipsNetwork(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-tgw-t2-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()

	// 第一次：完整流程
	client1 := makeReuseClient(t, sharedPath)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()
	loaded := integrationRegisterOrLoadAID(t, client1.configModel.AUNPath, aid)
	if err := client1.LoadIdentity(loaded); err != nil {
		_ = client1.Close()
		t.Fatalf("加载身份失败: %v", err)
	}
	first, err := client1.Authenticate(ctx1)
	if err != nil {
		_ = client1.Close()
		skipIfGatewayRateLimited(t, "第一次 Authenticate", err)
		t.Fatalf("第一次 Authenticate 失败: %v", err)
	}
	firstToken, _ := first["access_token"].(string)
	firstGW, _ := first["gateway"].(string)
	if firstToken == "" || firstGW == "" {
		_ = client1.Close()
		t.Fatalf("第一次返回值不完整: %v", first)
	}
	_ = client1.Close()

	// 第二次：新 client 同 aun_path（模拟 CLI 重启）
	client2 := makeReuseClient(t, sharedPath)
	defer func() { _ = client2.Close() }()

	// 关键拦截 1：把 connectionFactory 替换成会立即报错的桩。
	// 走 cached 路径 → 不调 connectionFactory → 安全；走 _login 路径 → 立即失败。
	var loginCalls atomic.Int32
	client2.auth.connectionFactory = func(_ context.Context, _ string) (*websocket.Conn, error) {
		loginCalls.Add(1)
		return nil, fmt.Errorf("connectionFactory should not be called when cached token is reused")
	}

	// 关键拦截 2：清空内存 gateway URL，并把底层 GatewayDiscovery 的 httpClient
	// 指向一个不可达地址。但 GatewayDiscovery 没有暴露注入点——这里改用第二种思路：
	// 直接验证 namespace.resolveGateway 第一步走了 keystore cache。
	//   - 内存 gateway 必须为空（namespace 第一步会跳过）
	//   - keystore metadata 必须有 cached gateway_url（namespace 第二步命中）
	// 如果第二步未命中，将进入 DiscoverGateway，由于我们不破坏 discovery 行为，
	// 它仍然能跑通；为此我们用副作用断言：第二次返回的 gateway 必须等于
	// 第一次的 gateway，且过程中不需要新发起 login。
	client2.setGatewayURL("")
	if cached := client2.AuthLoadCachedGatewayURL(aid); cached == "" {
		t.Fatal("第二个 client 应能从 keystore metadata 读到 cached gateway_url")
	}
	integrationLoadAIDIntoClient(t, client2, aid)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	second, err := client2.Authenticate(ctx2)
	if err != nil {
		t.Fatalf("第二次 Authenticate 失败（预期走 cached 不报错）: %v", err)
	}
	secondToken, _ := second["access_token"].(string)
	secondGW, _ := second["gateway"].(string)

	// 1. token 一致 → 没重新 login
	if secondToken != firstToken {
		t.Fatalf("第二次 token 与第一次不同（说明 _login 被触发）: first=%q second=%q",
			firstToken, secondToken)
	}
	t.Log("[OK] _login 未被触发（cached token 被复用）")

	// 2. connectionFactory 调用次数为 0（再次确认 _login / shortRPC 没被触发）
	if loginCalls.Load() != 0 {
		t.Fatalf("connectionFactory 被调用 %d 次（应为 0，说明 _login/shortRPC 被错误触发）",
			loginCalls.Load())
	}
	t.Log("[OK] connectionFactory 未被调用（无任何 _login/shortRPC 网络往返）")

	// 3. gateway 一致
	if secondGW != firstGW {
		t.Fatalf("gateway 不一致: first=%q second=%q", firstGW, secondGW)
	}
	t.Log("[OK] 第二次返回的 gateway 与第一次一致（cached gateway_url 被复用）")
}

// ---------------------------------------------------------------------------
// Test 3: 第二个 client 用 cached 直接 Connect + meta.ping
// ---------------------------------------------------------------------------

func TestTokenGatewayReuseIntegration_ReusedCachedConnects(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-tgw-t3-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()

	// 第一次：完整 create + authenticate
	client1 := makeReuseClient(t, sharedPath)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()
	loaded := integrationRegisterOrLoadAID(t, client1.configModel.AUNPath, aid)
	if err := client1.LoadIdentity(loaded); err != nil {
		_ = client1.Close()
		t.Fatalf("加载身份失败: %v", err)
	}
	if _, err := client1.Authenticate(ctx1); err != nil {
		_ = client1.Close()
		skipIfGatewayRateLimited(t, "第一次 Authenticate", err)
		t.Fatalf("第一次 Authenticate 失败: %v", err)
	}
	_ = client1.Close()

	// 第二次：完全重新 new client，复用 keystore，直接 connect + ping
	client2 := makeReuseClient(t, sharedPath)
	defer func() { _ = client2.Close() }()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	integrationLoadAIDIntoClient(t, client2, aid)
	_, err := client2.Authenticate(ctx2)
	if err != nil {
		t.Fatalf("第二次 Authenticate 失败: %v", err)
	}
	if err := client2.Connect(ctx2, ConnectionOptions{
		AutoReconnect:     boolPtr(false),
		HeartbeatInterval: 30 * time.Second,
	}); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	if client2.ConnectionState() != ConnStateReady {
		t.Fatalf("client2 连接状态异常: %s", client2.ConnectionState())
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()
	pingResult, err := client2.Call(pingCtx, "meta.ping", nil)
	if err != nil {
		t.Fatalf("meta.ping 失败: %v", err)
	}
	if _, ok := pingResult.(map[string]any); !ok {
		t.Fatalf("meta.ping 返回非 map: %T", pingResult)
	}
	t.Log("[OK] 第二个 client 用 cached → connect + ping 成功")
}

// ---------------------------------------------------------------------------
// Test 4: cached token 过期时回退到完整 login
// ---------------------------------------------------------------------------

func TestTokenGatewayReuseIntegration_ExpiredFallsBackToLogin(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-tgw-t4-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()

	// 第一次完整 Authenticate
	client1 := makeReuseClient(t, sharedPath)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()
	loaded := integrationRegisterOrLoadAID(t, client1.configModel.AUNPath, aid)
	if err := client1.LoadIdentity(loaded); err != nil {
		_ = client1.Close()
		t.Fatalf("加载身份失败: %v", err)
	}
	first, err := client1.Authenticate(ctx1)
	if err != nil {
		_ = client1.Close()
		skipIfGatewayRateLimited(t, "第一次 Authenticate", err)
		t.Fatalf("第一次 Authenticate 失败: %v", err)
	}
	firstToken, _ := first["access_token"].(string)
	if firstToken == "" {
		_ = client1.Close()
		t.Fatal("第一次未返回 access_token")
	}
	_ = client1.Close()

	// 手动把 instance_state 里的 access_token_expires_at 改成已过期
	clientForEdit := makeReuseClient(t, sharedPath)
	integrationLoadAIDIntoClient(t, clientForEdit, aid)
	identity := clientForEdit.auth.LoadIdentityOrNil(aid)
	if identity == nil {
		_ = clientForEdit.Close()
		t.Fatal("LoadIdentityOrNil 返回 nil")
	}
	identity["access_token_expires_at"] = time.Now().Unix() - 100
	if err := clientForEdit.auth.persistIdentity(identity); err != nil {
		_ = clientForEdit.Close()
		t.Fatalf("persistIdentity 失败: %v", err)
	}
	_ = clientForEdit.Close()

	// 第二次：token 过期 → 应走完整 login，新 token 不同于第一次
	client2 := makeReuseClient(t, sharedPath)
	defer func() { _ = client2.Close() }()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	integrationLoadAIDIntoClient(t, client2, aid)
	second, err := client2.Authenticate(ctx2)
	if err != nil {
		skipIfGatewayRateLimited(t, "第二次 Authenticate", err)
		t.Fatalf("第二次 Authenticate 失败: %v", err)
	}
	secondToken, _ := second["access_token"].(string)
	if secondToken == "" {
		t.Fatal("第二次未返回 access_token")
	}
	if secondToken == firstToken {
		t.Fatal("token 过期时应触发 _login 拿新 token，但仍返回旧 token")
	}
	t.Log("[OK] cached 过期 → _login 触发 → 新 token 已发放")
}
