package aun

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// loadTestAID 通过 AIDStore 加载一个有效私钥的 AID（供 client 测试用）。
func loadTestAID(t *testing.T, aid string) (*AID, string) {
	t.Helper()
	dir := t.TempDir()
	s := NewAIDStore(dir, "test-seed")
	t.Cleanup(func() { s.Close() })
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)
	r := s.Load(aid)
	if !r.Ok {
		t.Fatalf("加载测试 AID 失败: %v", r.Error.Message)
	}
	return r.Data.AID, dir
}

// ── NewAUNClient / NewAUNClientEmpty ──────────────────────────

func TestNewAUNClient_WithIdentity(t *testing.T) {
	aid, _ := loadTestAID(t, "alice.aid.com")
	c := NewAUNClient(aid)
	defer func() { _ = c.Close() }()

	if !c.HasIdentity() {
		t.Error("有身份时 HasIdentity 应为 true")
	}
	if !c.CanSign() {
		t.Error("有有效私钥时 CanSign 应为 true")
	}
	if !c.CanConnect() {
		t.Error("有身份时 CanConnect 应为 true")
	}
	if c.CanSend() {
		t.Error("未连接时 CanSend 应为 false")
	}
	if c.ConnectionState() != ConnStateStandby {
		t.Errorf("有身份未连接时状态应为 standby, 实际: %s", c.ConnectionState())
	}
	if got := c.CurrentAID(); got == nil || got.Aid != "alice.aid.com" {
		t.Errorf("CurrentAID 不匹配: %v", got)
	}
}

func TestNewAUNClientEmpty_NoIdentity(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()

	if c.HasIdentity() {
		t.Error("无身份时 HasIdentity 应为 false")
	}
	if c.CanSign() {
		t.Error("无身份时 CanSign 应为 false")
	}
	if c.CanConnect() {
		t.Error("无身份时 CanConnect 应为 false")
	}
	if c.ConnectionState() != ConnStateNoIdentity {
		t.Errorf("无身份时状态应为 no_identity, 实际: %s", c.ConnectionState())
	}
	if c.CurrentAID() != nil {
		t.Error("无身份时 CurrentAID 应为 nil")
	}
}

func TestNewAUNClient_OptionsOnly(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()

	if c.HasIdentity() {
		t.Error("无身份构造不应加载身份")
	}
	if c.ConnectionState() != ConnStateNoIdentity {
		t.Errorf("无身份状态应为 no_identity, 实际: %s", c.ConnectionState())
	}
}

func TestNewAUNClient_RejectsNilAIDWithPrivKey(t *testing.T) {
	// 新设计：NewAUNClient(nil) 合法，返回无身份客户端（等价于 NewAUNClientEmpty）。
	// 私钥无效的 AID 才应 panic。
	c := NewAUNClient(nil)
	defer func() { _ = c.Close() }()
	if c.HasIdentity() {
		t.Error("nil AID 构造不应加载身份")
	}
}

func TestNewAUNClient_OptionsRejectStringAID(t *testing.T) {
	// AUNClientOptions 已删除，字符串 AID 的防护由 NewAUNClient 签名（只接受 *AID）在编译期保证。
	// 此测试保留为文档，不再需要运行时 panic 检查。
}

func TestAUNClientStrictPublicAPIRemovedLegacyMethods(t *testing.T) {
	clientType := reflect.TypeOf(&AUNClient{})
	removed := []string{
		"FetchAgentMD",
		"CheckAgentMD",
		"CheckAgentMd",
		"SetAgentMDPath",
		"SetAgentMdPath",
		"ListIdentities",
		"CheckGatewayHealth",
		"Ping",
		"Status",
		"TrustRoots",
		"LoadIdentityFromAID",
	}
	for _, name := range removed {
		if _, ok := clientType.MethodByName(name); ok {
			t.Fatalf("AUNClient 不应继续暴露旧公开方法 %s", name)
		}
	}
}

// ── LoadIdentity ───────────────────────────────────────────────

func TestLoadIdentity_FromEmptyClient(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()
	aid, _ := loadTestAID(t, "bob.aid.com")

	if err := c.LoadIdentity(aid); err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if !c.HasIdentity() {
		t.Error("加载身份后 HasIdentity 应为 true")
	}
	if c.ConnectionState() != ConnStateStandby {
		t.Errorf("加载身份后状态应为 standby, 实际: %s", c.ConnectionState())
	}
}

func TestLoadIdentity_FromEmpty(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()
	aid, _ := loadTestAID(t, "load-alias.aid.com")

	if err := c.LoadIdentity(aid); err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if c.ConnectionState() != ConnStateStandby {
		t.Errorf("LoadIdentity 后状态应为 standby, 实际: %s", c.ConnectionState())
	}
}

func TestLoadIdentity_ReplacesStaleDeviceIDWithAIDStoreDevice(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()
	c.deviceID = "stale-device-from-previous-aun-path"
	c.auth.SetInstanceContext(c.deviceID, c.slotID)

	aid, aunPath := loadTestAID(t, "load-device-context.aid.com")
	wantDeviceID := GetDeviceID(aunPath)
	if aid.DeviceID != wantDeviceID {
		t.Fatalf("测试 AID 应携带 AIDStore 的 device_id: got=%q want=%q", aid.DeviceID, wantDeviceID)
	}
	if err := c.LoadIdentity(aid); err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if c.deviceID != wantDeviceID {
		t.Fatalf("LoadIdentity 应切换到 AIDStore device_id: got=%q want=%q", c.deviceID, wantDeviceID)
	}
	if c.auth.deviceID != wantDeviceID {
		t.Fatalf("AuthFlow device_id 未同步: got=%q want=%q", c.auth.deviceID, wantDeviceID)
	}
	if got := c.AunPath(); got != aunPath {
		t.Fatalf("LoadIdentity 应切换 aun_path: got=%q want=%q", got, aunPath)
	}
}

func TestLoadIdentity_NilRejected(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()
	if err := c.LoadIdentity(nil); err == nil {
		t.Fatal("传入 nil 应报错")
	}
}

// ── Connect 新 API ───────────────────────────────────────────

func TestConnectNewAPIRequiresLoadedAID(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()

	c.setGatewayURL("ws://127.0.0.1:1")
	err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("未加载 AID 时 Connect(ctx) 应报错")
	}
	if _, ok := err.(*StateError); !ok {
		t.Fatalf("错误类型应为 StateError, 实际: %T %v", err, err)
	}
}

func TestConnectNewAPIDoesNotRequireAccessToken(t *testing.T) {
	aid, _ := loadTestAID(t, "connect-new-api.aid.com")
	c := NewAUNClient(aid)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	c.setGatewayURL("ws://127.0.0.1:1")
	err := c.Connect(ctx)
	if err == nil {
		t.Fatal("不可达 gateway 应返回连接错误")
	}
	if strings.Contains(err.Error(), "access_token") {
		t.Fatalf("新 Connect(ctx) 不应要求传 access_token: %v", err)
	}
}

func TestConnectNewAPIRejectsUnexpectedArgument(t *testing.T) {
	// Connect 现在只接受 ctx，不再接受任何额外参数（编译期保证）。
	// 该约束由方法签名 Connect(ctx context.Context) error 直接强制。
	t.Skip("Connect 签名已收敛为仅接受 ctx，额外参数由编译期拒绝")
}

// ── ConnectionState 映射 ──────────────────────────────────────

func TestConnectionState_ClosedAfterClose(t *testing.T) {
	c := NewAUNClientEmpty()
	if err := c.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if c.ConnectionState() != ConnStateClosed {
		t.Errorf("Close 后状态应为 closed, 实际: %s", c.ConnectionState())
	}
	if !c.IsClosed() {
		t.Error("Close 后 IsClosed 应为 true")
	}
	if c.HasIdentity() {
		t.Error("Close 后 HasIdentity 应为 false")
	}
}

// ── getter 默认值 ─────────────────────────────────────────────

func TestClientGetters_Defaults(t *testing.T) {
	c := NewAUNClientEmpty()
	defer func() { _ = c.Close() }()

	if c.NextRetryAt() != nil {
		t.Error("未重连时 NextRetryAt 应为 nil")
	}
	if c.RetryAttempt() != 0 {
		t.Error("初始 RetryAttempt 应为 0")
	}
	if c.LastConnectError() != nil {
		t.Error("初始 LastConnectError 应为 nil")
	}
	if c.IsReady() {
		t.Error("初始 IsReady 应为 false")
	}
	if c.IsOnline() {
		t.Error("初始 IsOnline 应为 false")
	}
}

// ── ConnectionState 常量值 ────────────────────────────────────

func TestConnectionStateConstants(t *testing.T) {
	cases := map[ConnectionState]string{
		ConnStateNoIdentity:       "no_identity",
		ConnStateStandby:          "standby",
		ConnStateAuthenticated:    "authenticated",
		ConnStateConnecting:       "connecting",
		ConnStateReady:            "ready",
		ConnStateRetryBackoff:     "retry_backoff",
		ConnStateReconnecting:     "reconnecting",
		ConnStateConnectionFailed: "connection_failed",
		ConnStateClosed:           "closed",
	}
	for state, expected := range cases {
		if string(state) != expected {
			t.Errorf("状态常量值不匹配: %s != %s", string(state), expected)
		}
	}
}
