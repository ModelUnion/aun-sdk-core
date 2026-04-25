//go:build integration

package aun

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func ensureFederationReconnectConnected(t *testing.T, client *AUNClient, aid string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Auth.CreateAID(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("无法创建双域 AID（federation Docker 环境可能未运行）: %v", err)
	}

	authResult, err := client.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("双域认证失败: %v", err)
	}
	if err := client.Connect(ctx, authResult, &ConnectOptions{
		AutoReconnect:     true,
		HeartbeatInterval: 3,
		Retry: &RetryConfig{
			InitialDelay: 1,
			MaxDelay:     5,
		},
	}); err != nil {
		t.Fatalf("双域连接失败: %v", err)
	}
	return aid
}

func writeFederationReconnectMarker(t *testing.T) {
	t.Helper()
	marker := strings.TrimSpace(os.Getenv("AUN_RECONNECT_MARKER"))
	if marker == "" {
		t.Skip("AUN_RECONNECT_MARKER 未设置")
	}
	if err := os.WriteFile(marker, []byte("ready"), 0o644); err != nil {
		t.Fatalf("写入重连标记失败: %v", err)
	}
}

func waitForFederationCondition(timeout, interval time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(interval)
	}
	return false
}

func waitForFederationDelivery(
	t *testing.T,
	alice *AUNClient,
	bob *AUNClient,
	aliceAID string,
	bobAID string,
	rid string,
) {
	t.Helper()

	var lastMessages []map[string]any
	for attempt := 1; attempt <= 30; attempt++ {
		text := fmt.Sprintf("go federation reconnect %s-%d", rid, attempt)

		sendCtx, sendCancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, sendErr := alice.Call(sendCtx, "message.send", map[string]any{
			"to":      bobAID,
			"payload": map[string]any{"type": "text", "text": text},
			"encrypt": false,
		})
		sendCancel()
		if sendErr == nil {
			pullCtx, pullCancel := context.WithTimeout(context.Background(), 10*time.Second)
			pullResult, pullErr := bob.Call(pullCtx, "message.pull", map[string]any{
				"after_seq": 0,
				"limit":     50,
			})
			pullCancel()
			if pullErr == nil {
				if pullMap, _ := pullResult.(map[string]any); pullMap != nil {
					msgsAny, _ := pullMap["messages"].([]any)
					lastMessages = lastMessages[:0]
					for _, raw := range msgsAny {
						if msg, ok := raw.(map[string]any); ok {
							lastMessages = append(lastMessages, msg)
							from, _ := msg["from"].(string)
							if from == aliceAID && getPayloadText(msg) == text {
								return
							}
						}
					}
				}
			}
		}

		time.Sleep(2 * time.Second)
	}

	t.Fatalf("等待 Bob 在重连后收到跨域消息 超时: %+v", lastMessages)
}

func TestFederationReconnectAfterRemoteGatewayRestart(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationReconnectConnected(t, alice, fmt.Sprintf("go-fed-rc-a-%s.aid.com", rid))
	bobAID := ensureFederationReconnectConnected(t, bob, fmt.Sprintf("go-fed-rc-b-%s.aid.net", rid))

	var bobStatesMu sync.Mutex
	var bobStates []string

	bobSub := bob.On("connection.state", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		state, _ := data["state"].(string)
		if state == "" {
			return
		}
		bobStatesMu.Lock()
		bobStates = append(bobStates, state)
		bobStatesMu.Unlock()
	})
	defer bobSub.Unsubscribe()

	if alice.State() != StateConnected {
		t.Fatalf("Alice 初始状态异常: %s", alice.State())
	}
	if bob.State() != StateConnected {
		t.Fatalf("Bob 初始状态异常: %s", bob.State())
	}

	writeFederationReconnectMarker(t)

	sawDisconnect := waitForFederationCondition(45*time.Second, 500*time.Millisecond, func() bool {
		bobStatesMu.Lock()
		defer bobStatesMu.Unlock()
		for _, state := range bobStates {
			if state == string(StateDisconnected) || state == string(StateReconnecting) {
				return true
			}
		}
		return bob.State() != StateConnected
	})
	if !sawDisconnect {
		bobStatesMu.Lock()
		snapshot := append([]string(nil), bobStates...)
		bobStatesMu.Unlock()
		t.Fatalf("Bob 未进入断线/重连状态: current=%s states=%v", bob.State(), snapshot)
	}

	reconnected := waitForFederationCondition(90*time.Second, 500*time.Millisecond, func() bool {
		if bob.State() != StateConnected {
			return false
		}
		bobStatesMu.Lock()
		defer bobStatesMu.Unlock()
		for _, state := range bobStates {
			if state == string(StateDisconnected) || state == string(StateReconnecting) {
				return true
			}
		}
		return false
	})
	if !reconnected {
		bobStatesMu.Lock()
		snapshot := append([]string(nil), bobStates...)
		bobStatesMu.Unlock()
		t.Fatalf("Bob 重连超时: current=%s states=%v", bob.State(), snapshot)
	}

	if alice.State() != StateConnected {
		t.Fatalf("Alice 在远端域重启后不应断开: %s", alice.State())
	}

	waitForFederationDelivery(t, alice, bob, aliceAID, bobAID, rid)
}
