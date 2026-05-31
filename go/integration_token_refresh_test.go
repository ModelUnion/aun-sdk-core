//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestIntegration_TokenRefreshRotatesAccessToken(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-refresh-%s.%s", rid, testIssuer())
	client := makeClient(t)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	loaded := integrationRegisterOrLoadAID(t, client.configModel.AUNPath, aid)
	if err := client.LoadIdentity(loaded); err != nil {
		t.Fatalf("加载身份失败: %v", err)
	}
	authResult, err := client.Authenticate(ctx)
	if err != nil {
		t.Fatalf("认证失败: %v", err)
	}
	initialToken := fmt.Sprint(authResult["access_token"])
	if initialToken == "" {
		t.Fatal("初始 access_token 为空")
	}

	forcedExpiresAt := time.Now().Unix() + 60
	client.mu.Lock()
	if client.identity == nil {
		client.mu.Unlock()
		t.Fatal("认证后 client.identity 为空")
	}
	client.identity["access_token_expires_at"] = forcedExpiresAt
	identityForPersist := copyMapShallow(client.identity)
	client.mu.Unlock()
	if err := client.auth.persistIdentity(identityForPersist); err != nil {
		t.Fatalf("调整 access_token_expires_at 失败: %v", err)
	}
	t.Logf("token refresh prepared: aid=%s forced_expires_at=%d", aid, forcedExpiresAt)

	if err := client.Connect(ctx, ConnectionOptions{
		AutoReconnect: boolPtr(false),
	}); err != nil {
		t.Fatalf("连接失败: %v", err)
	}

	deadline := time.Now().Add(45 * time.Second)
	var refreshedToken string
	nextLog := time.Now()
	for time.Now().Before(deadline) {
		client.mu.RLock()
		if client.identity != nil {
			refreshedToken = fmt.Sprint(client.identity["access_token"])
		}
		client.mu.RUnlock()
		if refreshedToken != "" && refreshedToken != initialToken {
			break
		}
		if !time.Now().Before(nextLog) {
			t.Logf("waiting token refresh: aid=%s refreshed=%t", aid, refreshedToken != "")
			nextLog = time.Now().Add(5 * time.Second)
		}
		time.Sleep(time.Second)
	}

	if refreshedToken == "" || refreshedToken == initialToken {
		t.Fatalf("45 秒内未刷新 access_token: initial=%q refreshed=%q", initialToken, refreshedToken)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()
	if _, err := client.Call(pingCtx, "meta.ping", nil); err != nil {
		t.Fatalf("刷新后 ping 失败: %v", err)
	}

	client.mu.RLock()
	expiresAt := toInt64(client.identity["access_token_expires_at"])
	client.mu.RUnlock()
	if expiresAt-time.Now().Unix() < 3000 {
		t.Fatalf("刷新后的 token 有效期异常: expires_at=%d now=%d", expiresAt, time.Now().Unix())
	}
}
