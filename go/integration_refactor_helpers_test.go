//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func integrationStoreForPath(t *testing.T, aunPath string) *AIDStore {
	t.Helper()
	store := NewAIDStore(aunPath, "")
	t.Cleanup(store.Close)
	return store
}

func integrationRegisterOrLoadAID(t *testing.T, aunPath, aid string) *AID {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := integrationStoreForPath(t, aunPath)
	if err := store.Register(ctx, aid); err != nil {
		loaded, loadErr := store.Load(aid)
		if loadErr != nil {
			t.Skipf("无法创建 AID（Docker 环境可能未运行）: %v", err)
		}
		return loaded
	}
	loaded, err := store.Load(aid)
	if err != nil {
		t.Fatalf("注册后加载 AID 失败: %v", err)
	}
	return loaded
}

func integrationLoadAIDIntoClient(t *testing.T, client *AUNClient, aid string) *AID {
	t.Helper()
	store := integrationStoreForPath(t, client.configModel.AUNPath)
	if gatewayURL := client.GetGatewayURL(); gatewayURL != "" {
		store.SetGatewayURL(gatewayURL)
	}
	loaded, err := store.Load(aid)
	if err != nil {
		t.Fatalf("加载 AID 失败: %v", err)
	}
	if current := client.CurrentAID(); current == nil || current.Aid != loaded.Aid {
		if err := client.LoadIdentity(loaded); err != nil {
			t.Fatalf("加载身份到客户端失败: %v", err)
		}
	}
	return loaded
}

func integrationConnectLoadedAID(t *testing.T, client *AUNClient, aid string, opts *ConnectOptions) {
	t.Helper()
	integrationLoadAIDIntoClient(t, client, aid)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if opts == nil {
		opts = &ConnectOptions{}
	}
	if err := client.Connect(ctx, opts); err != nil {
		t.Fatalf("连接失败: %v", err)
	}
}

func integrationAuthenticateLoadedAID(t *testing.T, client *AUNClient, aid string, opts ...ConnectOptions) map[string]any {
	t.Helper()
	integrationLoadAIDIntoClient(t, client, aid)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := client.Authenticate(ctx, opts...)
	if err != nil {
		t.Fatalf("认证失败: %v", err)
	}
	return result
}

func integrationConnectAIDInPath(t *testing.T, client *AUNClient, aid string, opts *ConnectOptions) string {
	t.Helper()
	integrationRegisterOrLoadAID(t, client.configModel.AUNPath, aid)
	integrationConnectLoadedAID(t, client, aid, opts)
	if client.ConnectionState() != ConnStateReady {
		t.Fatalf("连接后状态异常: %s", client.ConnectionState())
	}
	return aid
}

func integrationConnectError(t *testing.T, client *AUNClient, aid string, opts *ConnectOptions, timeout time.Duration) error {
	t.Helper()
	integrationLoadAIDIntoClient(t, client, aid)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if opts == nil {
		opts = &ConnectOptions{}
	}
	return client.Connect(ctx, opts)
}

func integrationRegisterAIDInPath(t *testing.T, aunPath, aid string) {
	t.Helper()
	integrationRegisterOrLoadAID(t, aunPath, aid)
}

func integrationAuthenticateError(t *testing.T, client *AUNClient, aid string) error {
	t.Helper()
	integrationLoadAIDIntoClient(t, client, aid)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := client.Authenticate(ctx)
	if err != nil {
		return fmt.Errorf("authenticate failed: %w", err)
	}
	return nil
}
