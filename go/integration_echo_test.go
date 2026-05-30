//go:build integration

package aun

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Echo 链路追踪 E2E 测试
//
// 验证明文 echo 消息经过 SDK.send → Gateway.route → Message.relay → SDK.receive 的完整 trace 链。
// 使用动态 AID（每次测试创建新身份），不依赖固定身份目录。
//
// 运行：
//   MSYS_NO_PATHCONV=1 docker exec kite-go-tester sh -lc \
//     "cd /workspace/go && go test -tags integration . -run Echo -count=1 -v"
// ---------------------------------------------------------------------------

func echoIssuer() string {
	if v := strings.TrimSpace(os.Getenv("AUN_TEST_ISSUER")); v != "" {
		return v
	}
	return "agentid.pub"
}

func echoMakeClient(t *testing.T, aunPath string) *AUNClient {
	t.Helper()
	os.Setenv("AUN_ENV", "development")
	c := newClient(map[string]any{"aun_path": aunPath, "debug": true})
	c.configModel.RequireForwardSecrecy = false
	return c
}

func echoCreateAndConnect(t *testing.T, c *AUNClient, aid string, slotID string) {
	t.Helper()
	integrationRegisterOrLoadAID(t, c.configModel.AUNPath, aid)
	integrationConnectLoadedAID(t, c, aid, &ConnectionOptions{
		SlotID:        slotID,
		AutoReconnect: boolPtr(false),
	})
}

func echoTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func TestEcho_P2PFullTrace(t *testing.T) {
	aunPath := t.TempDir()
	r := rid8()
	aliceAID := fmt.Sprintf("echo-alice-%s.%s", r, echoIssuer())
	bobAID := fmt.Sprintf("echo-bob-%s.%s", r, echoIssuer())
	alice := echoMakeClient(t, aunPath)
	bob := echoMakeClient(t, aunPath)
	defer func() { _ = alice.Close(); _ = bob.Close() }()

	echoCreateAndConnect(t, alice, aliceAID, "echo-a-"+r)
	echoCreateAndConnect(t, bob, bobAID, "echo-b-"+r)

	received := make(chan map[string]any, 1)
	bob.On("message.received", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received <- msg
		}
	})

	echoText := fmt.Sprintf("echo 测试-%s", r)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": echoText},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("message.send failed: %v", err)
	}
	t.Logf("发送: %s", echoText)

	select {
	case msg := <-received:
		payload, _ := msg["payload"].(map[string]any)
		text, _ := payload["text"].(string)
		t.Logf("收到: %s", echoTruncate(text, 300))

		markers := []string{"[AUN-SDK.send]", "[AUN-Gateway.route]", "[AUN-Message.relay]", "[AUN-SDK.receive]"}
		for _, m := range markers {
			if !strings.Contains(text, m) {
				t.Errorf("缺少 trace: %s", m)
			}
		}
	case <-ctx.Done():
		t.Fatal("bob 未收到消息（超时 15s）")
	}
}

func TestEcho_EncryptedNoTrace(t *testing.T) {
	aunPath := t.TempDir()
	r := rid8()
	aliceAID := fmt.Sprintf("echo-enc-a-%s.%s", r, echoIssuer())
	bobAID := fmt.Sprintf("echo-enc-b-%s.%s", r, echoIssuer())
	alice := echoMakeClient(t, aunPath)
	bob := echoMakeClient(t, aunPath)
	defer func() { _ = alice.Close(); _ = bob.Close() }()

	echoCreateAndConnect(t, alice, aliceAID, "echo-enc-a-"+r)
	echoCreateAndConnect(t, bob, bobAID, "echo-enc-b-"+r)

	received := make(chan map[string]any, 1)
	bob.On("message.received", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received <- msg
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("echo 加密-%s", r)},
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("message.send failed: %v", err)
	}

	select {
	case msg := <-received:
		payload, _ := msg["payload"].(map[string]any)
		text, _ := payload["text"].(string)
		if strings.Contains(text, "[AUN-SDK.send]") || strings.Contains(text, "[AUN-Gateway.route]") {
			t.Errorf("加密消息不应包含 echo trace: %s", echoTruncate(text, 100))
		} else {
			t.Log("[OK] 加密消息无 echo trace")
		}
	case <-ctx.Done():
		t.Fatal("bob 未收到消息（超时 15s）")
	}
}

func TestEcho_NonEchoNoTrace(t *testing.T) {
	aunPath := t.TempDir()
	r := rid8()
	aliceAID := fmt.Sprintf("echo-norm-a-%s.%s", r, echoIssuer())
	bobAID := fmt.Sprintf("echo-norm-b-%s.%s", r, echoIssuer())
	alice := echoMakeClient(t, aunPath)
	bob := echoMakeClient(t, aunPath)
	defer func() { _ = alice.Close(); _ = bob.Close() }()

	echoCreateAndConnect(t, alice, aliceAID, "echo-norm-a-"+r)
	echoCreateAndConnect(t, bob, bobAID, "echo-norm-b-"+r)

	received := make(chan map[string]any, 1)
	bob.On("message.received", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received <- msg
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("普通消息-%s", r)},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("message.send failed: %v", err)
	}

	select {
	case msg := <-received:
		payload, _ := msg["payload"].(map[string]any)
		text, _ := payload["text"].(string)
		if strings.Contains(text, "[AUN-SDK.send]") || strings.Contains(text, "[AUN-Gateway.route]") {
			t.Errorf("非 echo 消息不应有 trace: %s", echoTruncate(text, 100))
		} else {
			t.Log("[OK] 非 echo 消息无 trace")
		}
	case <-ctx.Done():
		t.Fatal("bob 未收到消息（超时 15s）")
	}
}

func TestEcho_TraceOrder(t *testing.T) {
	aunPath := t.TempDir()
	r := rid8()
	aliceAID := fmt.Sprintf("echo-ord-a-%s.%s", r, echoIssuer())
	bobAID := fmt.Sprintf("echo-ord-b-%s.%s", r, echoIssuer())
	alice := echoMakeClient(t, aunPath)
	bob := echoMakeClient(t, aunPath)
	defer func() { _ = alice.Close(); _ = bob.Close() }()

	echoCreateAndConnect(t, alice, aliceAID, "echo-ord-a-"+r)
	echoCreateAndConnect(t, bob, bobAID, "echo-ord-b-"+r)

	received := make(chan map[string]any, 1)
	bob.On("message.received", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received <- msg
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("echo order-%s", r)},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("message.send failed: %v", err)
	}

	select {
	case msg := <-received:
		payload, _ := msg["payload"].(map[string]any)
		text, _ := payload["text"].(string)
		lines := strings.Split(text, "\n")

		markers := []string{"[AUN-SDK.send]", "[AUN-Gateway.route]", "[AUN-Message.relay]", "[AUN-SDK.receive]"}
		positions := make([]int, len(markers))
		for i, m := range markers {
			positions[i] = -1
			for j, line := range lines {
				if strings.Contains(line, m) {
					positions[i] = j
					break
				}
			}
		}

		for i, p := range positions {
			if p == -1 {
				t.Errorf("缺少 trace: %s", markers[i])
			}
		}
		for i := 1; i < len(positions); i++ {
			if positions[i] >= 0 && positions[i-1] >= 0 && positions[i] <= positions[i-1] {
				t.Errorf("trace 顺序错误: %s (line %d) 应在 %s (line %d) 之后",
					markers[i], positions[i], markers[i-1], positions[i-1])
			}
		}
		if !t.Failed() {
			t.Log("[OK] trace 顺序正确")
		}
	case <-ctx.Done():
		t.Fatal("bob 未收到消息（超时 15s）")
	}
}
