package aun

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// 本测试文件覆盖两个改进：
//   A. AuthFlow.Authenticate 优先复用 cached access_token + refresh_token
//   B. gateway_url 持久化到 keystore metadata（LoadCachedGatewayURL / PersistGatewayURL）
//
// 与 Python SDK auth.py 和 namespaces/auth_namespace.py 的实现对齐。

// ── 测试公共 helper ─────────────────────────────────────────

// newTestAuthFlow 使用真实 FileKeyStore + 临时目录构造 AuthFlow，避免触网。
func newTestAuthFlow(t *testing.T) (*AuthFlow, *keystore.FileKeyStore) {
	t.Helper()
	dir := t.TempDir()
	ks, err := keystore.NewFileKeyStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("NewFileKeyStore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	flow := NewAuthFlow(AuthFlowConfig{
		Keystore:  ks,
		Crypto:    &CryptoProvider{},
		VerifySSL: false,
	})
	return flow, ks
}

// seedIdentityWithCachedToken 写入一份带 cached access_token 的身份。
func seedIdentityWithCachedToken(t *testing.T, ks keystore.KeyStore, aid, accessToken, refreshToken string, expiresAt int64) {
	t.Helper()
	// 直接构造一个最小 identity（无证书）— 走 cached 路径不需要解析证书。
	identity := map[string]any{
		"aid":                      aid,
		"private_key_pem":          "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
		"access_token":             accessToken,
		"refresh_token":            refreshToken,
		"access_token_expires_at":  expiresAt,
	}
	if err := ks.SaveIdentity(aid, identity); err != nil {
		t.Fatalf("SaveIdentity 失败: %v", err)
	}
}

// ── 改进 A：Authenticate 缓存复用 ─────────────────────────────

// 用例 1：identity 持有未过期的 access_token + refresh_token 时，Authenticate
// 直接命中缓存返回，不会发起 login 网络请求（用一个明显不可达的 URL 来证明）。
func TestTokenGatewayReuse_AuthenticateUsesCachedToken(t *testing.T) {
	flow, ks := newTestAuthFlow(t)
	const aid = "alice.test.local"
	expiresAt := time.Now().Unix() + 3600
	seedIdentityWithCachedToken(t, ks, aid, "cached-access", "cached-refresh", expiresAt)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// gateway URL 故意指向不可达地址：若 cached 路径未命中，login 会立即报网络错误。
	result, err := flow.Authenticate(ctx, "ws://127.0.0.1:1/aun", aid)
	if err != nil {
		t.Fatalf("cached 路径应直接返回，未触发 login，但收到 err=%v", err)
	}
	if result["access_token"] != "cached-access" {
		t.Fatalf("access_token 期望 cached-access，得到 %v", result["access_token"])
	}
	if result["refresh_token"] != "cached-refresh" {
		t.Fatalf("refresh_token 期望 cached-refresh，得到 %v", result["refresh_token"])
	}
	if result["aid"] != aid {
		t.Fatalf("aid 不匹配: %v", result["aid"])
	}
	if result["gateway"] != "ws://127.0.0.1:1/aun" {
		t.Fatalf("gateway 应原样回填: %v", result["gateway"])
	}
}

// 用例 2：identity 没有 access_token 时不会走 cache，会进入 login 路径并因
// 不可达而报错（验证 cache 检查没有错误地短路非缓存场景）。
func TestTokenGatewayReuse_AuthenticateFallsThroughWhenNoCachedToken(t *testing.T) {
	flow, ks := newTestAuthFlow(t)
	const aid = "bob.test.local"
	identity := map[string]any{
		"aid":             aid,
		"private_key_pem": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
		"cert":            "", // 无证书 → 进入 cert 恢复路径，依然会触网失败
	}
	if err := ks.SaveIdentity(aid, identity); err != nil {
		t.Fatalf("SaveIdentity 失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := flow.Authenticate(ctx, "ws://127.0.0.1:1/aun", aid)
	if err == nil {
		t.Fatal("无 cached_token 时应触发 login（或证书恢复），不应静默返回成功")
	}
}

// 用例 3：identity 持有已过期的 access_token 时不复用缓存，会进入 login 路径
// 并因不可达而报错。
func TestTokenGatewayReuse_AuthenticateFallsThroughWhenTokenExpired(t *testing.T) {
	flow, ks := newTestAuthFlow(t)
	const aid = "carol.test.local"
	// expires_at 设为已经过去 → authGetCachedAccessToken 返回 ""
	expiresAt := time.Now().Unix() - 60
	seedIdentityWithCachedToken(t, ks, aid, "stale-access", "stale-refresh", expiresAt)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := flow.Authenticate(ctx, "ws://127.0.0.1:1/aun", aid)
	if err == nil {
		t.Fatal("过期 token 不应被复用，应触发 login 失败")
	}
}

// ── 改进 B：gateway_url 持久化 ───────────────────────────────

// 用例 4：keystore metadata 中存在缓存的 gateway_url 时，LoadCachedGatewayURL
// 直接返回该值（resolveGateway 据此跳过 well-known discovery）。
func TestTokenGatewayReuse_LoadCachedGatewayURLHitsKeystore(t *testing.T) {
	flow, ks := newTestAuthFlow(t)
	const aid = "dave.test.local"

	// 直接通过 MetadataKeyStore 接口预置缓存值。
	mks, ok := any(ks).(keystore.MetadataKeyStore)
	if !ok {
		t.Fatal("FileKeyStore 应实现 MetadataKeyStore")
	}
	if err := mks.SetMetadataValue(aid, "gateway_url", "wss://gw.cached.example/aun"); err != nil {
		t.Fatalf("SetMetadataValue 失败: %v", err)
	}

	got := flow.LoadCachedGatewayURL(aid)
	if got != "wss://gw.cached.example/aun" {
		t.Fatalf("LoadCachedGatewayURL 期望命中缓存，得到 %q", got)
	}
}

// 用例 5：PersistGatewayURL 写入后，LoadCachedGatewayURL 能读回（discovery
// 成功后的持久化往返）。
func TestTokenGatewayReuse_PersistGatewayURLRoundTrip(t *testing.T) {
	flow, _ := newTestAuthFlow(t)
	const aid = "erin.test.local"

	flow.PersistGatewayURL(aid, "wss://gw.discovered.example/aun")
	got := flow.LoadCachedGatewayURL(aid)
	if got != "wss://gw.discovered.example/aun" {
		t.Fatalf("PersistGatewayURL→Load 往返失败: 得到 %q", got)
	}
}

// 用例 6：内存中已设置 gatewayURL 时，AUNClient.GetGatewayURL 优先于
// keystore 缓存。这与 namespace.resolveGateway 第一步的行为对齐：
// 只要 GetGatewayURL 非空即直接返回，不会触碰 keystore。
func TestTokenGatewayReuse_InMemoryGatewayURLTakesPriority(t *testing.T) {
	dir := t.TempDir()
	c := NewClient(map[string]any{"aun_path": dir})
	defer func() { _ = c.Close() }()

	const aid = "frank.test.local"
	// 同时在 keystore 中放一个不同的 cached URL，确保它不会被选中。
	c.AuthPersistGatewayURL(aid, "wss://gw.cached.example/aun")

	c.SetGatewayURL("wss://gw.in-memory.example/aun")
	if got := c.GetGatewayURL(); got != "wss://gw.in-memory.example/aun" {
		t.Fatalf("GetGatewayURL 应优先返回内存值，得到 %q", got)
	}

	// 手动验证：keystore 仍保留独立的缓存，不会被 SetGatewayURL 污染。
	cached := c.AuthLoadCachedGatewayURL(aid)
	if cached != "wss://gw.cached.example/aun" {
		t.Fatalf("keystore 缓存应未被修改，得到 %q", cached)
	}
}

// 用例 7：传空字符串给 PersistGatewayURL 时，不应写入 keystore（避免污染缓存）。
func TestTokenGatewayReuse_PersistGatewayURLIgnoresEmpty(t *testing.T) {
	flow, _ := newTestAuthFlow(t)
	const aid = "grace.test.local"

	// 先写一个真实值，再用 "" / "   " 调一次，应保持原值不变。
	flow.PersistGatewayURL(aid, "wss://gw.kept.example/aun")
	flow.PersistGatewayURL(aid, "")
	flow.PersistGatewayURL(aid, "   ")

	got := flow.LoadCachedGatewayURL(aid)
	if got != "wss://gw.kept.example/aun" {
		t.Fatalf("空字符串不应覆盖原 cached 值，得到 %q", got)
	}
	// 同时确认 trim 之后的内容存进去也是干净的——下一次写入正常。
	flow.PersistGatewayURL(aid, "  wss://gw.trimmed.example/aun  ")
	got = flow.LoadCachedGatewayURL(aid)
	if got != "wss://gw.trimmed.example/aun" {
		t.Fatalf("PersistGatewayURL 应 trim 后再写入，得到 %q", got)
	}
}

// 用例 8：keystore metadata 中没有 gateway_url 记录时，LoadCachedGatewayURL
// 返回空字符串（resolveGateway 据此进入 discovery 路径）。
func TestTokenGatewayReuse_LoadCachedGatewayURLReturnsEmptyWhenAbsent(t *testing.T) {
	flow, _ := newTestAuthFlow(t)
	got := flow.LoadCachedGatewayURL("nobody.test.local")
	if got != "" {
		t.Fatalf("无记录应返回空字符串，得到 %q", got)
	}
	// 空 aid 也应返回空，避免越界查询。
	if got := flow.LoadCachedGatewayURL(""); got != "" {
		t.Fatalf("空 aid 应返回空字符串，得到 %q", got)
	}
	// 兼容性：strings.TrimSpace 在 namespace 层做，AuthFlow 直接读裸值。
	_ = strings.TrimSpace(got)
}
