//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func integrationStoreForPath(t *testing.T, aunPath string, slotID ...string) *AIDStore {
	t.Helper()
	opts := AIDStoreOptions{}
	if len(slotID) > 0 && slotID[0] != "" {
		opts.SlotID = slotID[0]
	}
	store := NewAIDStore(aunPath, "", opts)
	t.Cleanup(store.Close)
	return store
}

func integrationRegisterOrLoadAID(t *testing.T, aunPath, aid string, slotID ...string) *AID {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := integrationStoreForPath(t, aunPath, slotID...)
	if rr := store.Register(ctx, aid); !rr.Ok {
		lr := store.Load(aid)
		if !lr.Ok {
			t.Skipf("无法创建 AID（Docker 环境可能未运行）: %v", rr.Error.Message)
		}
		return lr.Data.AID
	}
	lr := store.Load(aid)
	if !lr.Ok {
		t.Fatalf("注册后加载 AID 失败: %v", lr.Error.Message)
	}
	return lr.Data.AID
}

func skipIfGatewayRateLimited(t *testing.T, phase string, err error) {
	t.Helper()
	if isGatewayRateLimitedError(err) {
		t.Skipf("%s 遇到网关限流（Docker 环境繁忙）: %v", phase, err)
	}
}

func isGatewayRateLimitedError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "StatusCode(4029)") && strings.Contains(msg, "Too many requests")
}

func TestGatewayRateLimitedErrorPredicate(t *testing.T) {
	err := fmt.Errorf("websocket: bad handshake: StatusCode(4029): Too many requests")
	if !isGatewayRateLimitedError(err) {
		t.Fatalf("4029 Too many requests 应识别为网关限流")
	}
}

func integrationClientSlotID(client *AUNClient) string {
	if client == nil {
		return ""
	}
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.slotID
}

func integrationLoadAIDIntoClient(t *testing.T, client *AUNClient, aid string, slotID ...string) *AID {
	t.Helper()
	effectiveSlotID := ""
	if len(slotID) > 0 {
		effectiveSlotID = slotID[0]
	} else {
		effectiveSlotID = integrationClientSlotID(client)
	}
	store := integrationStoreForPath(t, client.configModel.AUNPath, effectiveSlotID)
	lr := store.Load(aid)
	if !lr.Ok {
		t.Fatalf("加载 AID 失败: %v", lr.Error.Message)
	}
	loaded := lr.Data.AID
	if current := client.CurrentAID(); current == nil ||
		current.Aid != loaded.Aid ||
		current.DeviceID != loaded.DeviceID ||
		current.SlotID != loaded.SlotID {
		if err := client.LoadIdentity(loaded); err != nil {
			t.Fatalf("加载身份到客户端失败: %v", err)
		}
	}
	return loaded
}

func integrationConnectLoadedAID(t *testing.T, client *AUNClient, aid string, opts *ConnectionOptions) {
	t.Helper()
	integrationLoadAIDIntoClient(t, client, aid)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var err error
	if opts != nil {
		err = client.Connect(ctx, *opts)
	} else {
		err = client.Connect(ctx)
	}
	if err != nil {
		skipIfGatewayRateLimited(t, "连接", err)
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
		skipIfGatewayRateLimited(t, "认证", err)
		t.Fatalf("认证失败: %v", err)
	}
	return result
}

func integrationConnectAIDInPath(t *testing.T, client *AUNClient, aid string, opts *ConnectionOptions) string {
	t.Helper()
	integrationRegisterOrLoadAID(t, client.configModel.AUNPath, aid, integrationClientSlotID(client))
	integrationConnectLoadedAID(t, client, aid, opts)
	if client.ConnectionState() != ConnStateReady {
		t.Fatalf("连接后状态异常: %s", client.ConnectionState())
	}
	return aid
}

func integrationConnectError(t *testing.T, client *AUNClient, aid string, opts *ConnectionOptions, timeout time.Duration) error {
	t.Helper()
	integrationLoadAIDIntoClient(t, client, aid)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if opts != nil {
		return client.Connect(ctx, *opts)
	}
	return client.Connect(ctx)
}

func integrationRegisterAIDInPath(t *testing.T, aunPath, aid string) {
	t.Helper()
	integrationRegisterOrLoadAID(t, aunPath, aid)
}

// boolPtr 返回指向 bool 值的指针（供 ConnectionOptions.AutoReconnect 使用）。
func boolPtr(b bool) *bool { return &b }

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
