//go:build integration

// federation_v2_thought_test.go — V2 thought.put / thought.get 跨域测试。
//
// Alice (aid.com) ↔ Bob (aid.net) 跨域 V2 P2P / Group thought put + get。
// 服务端对 V2 thought envelope 透传，客户端单设备解密。
//
// 用法（在 federation Docker 环境内）：
//   MSYS_NO_PATHCONV=1 docker exec go-tester sh -lc "cd /workspace/go && \
//       /usr/local/go/bin/go test -tags integration . -run TestFederationV2Thought -count=1 -v"

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestFederationV2Thought_P2P 验证 P2P thought 跨域加密 + 解密。
func TestFederationV2Thought_P2P(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-v2t-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-v2t-b-%s.aid.net", rid))

	if alice.v2GetState() == nil || bob.v2GetState() == nil {
		t.Skipf("跨域 V2 session 未就绪: aliceV2=%v bobV2=%v",
			alice.v2GetState() != nil, bob.v2GetState() != nil)
	}

	p2pCtx := map[string]any{"type": "fed-v2-thought", "id": fmt.Sprintf("fed-%s", rid)}
	text := fmt.Sprintf("fed-v2-thought-%s-%d", rid, time.Now().UnixNano())

	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		put, err := alice.Call(ctx, "message.thought.put", map[string]any{
			"to":         bobAID,
			"context":    p2pCtx,
			"thought_id": fmt.Sprintf("mt-fed-%s", rid),
			"payload":    map[string]any{"type": "thought", "text": text},
		})
		if err != nil {
			t.Fatalf("跨域 P2P thought.put 失败: %v", err)
		}
		putMap, _ := put.(map[string]any)
		if int(toInt64(putMap["stored_count"])) < 1 {
			t.Fatalf("跨域 P2P thought.put stored_count<1: %#v", put)
		}
	}

	// 服务端原始返回：必须为 V2 envelope（type=e2ee.p2p_encrypted, recipients[]）
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		raw, err := bob.transport.Call(ctx, "message.thought.get", map[string]any{
			"sender_aid": aliceAID,
			"context":    p2pCtx,
		})
		if err != nil {
			t.Fatalf("raw 跨域 P2P thought.get 失败: %v", err)
		}
		rawMap, _ := raw.(map[string]any)
		items, _ := rawMap["thoughts"].([]any)
		if len(items) == 0 {
			t.Fatalf("跨域 P2P thoughts 服务端为空: %#v", rawMap)
		}
		first, _ := items[0].(map[string]any)
		payload, _ := first["payload"].(map[string]any)
		if !isV2P2PThoughtEnvelope(payload) {
			t.Fatalf("跨域 P2P thought 必须是 V2 envelope, payload=%#v", payload)
		}
		recipients, _ := payload["recipients"].([]any)
		if len(recipients) == 0 {
			t.Fatalf("跨域 V2 P2P thought envelope.recipients 必须非空: %#v", payload)
		}
		t.Logf("跨域 V2 P2P thought envelope OK: recipients=%d", len(recipients))
	}

	// SDK 解密路径
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result, err := bob.Call(ctx, "message.thought.get", map[string]any{
			"sender_aid": aliceAID,
			"context":    p2pCtx,
		})
		if err != nil {
			t.Fatalf("跨域 SDK 解密 thought.get 失败: %v", err)
		}
		resultMap, _ := result.(map[string]any)
		texts := v2ThoughtPayloadTexts(t, resultMap)
		if !containsString(texts, text) {
			t.Fatalf("跨域 V2 P2P thought 解密返回不含期望文本: texts=%v want %q", texts, text)
		}
		t.Logf("跨域 V2 P2P thought 解密 OK: %s", text)
	}
}
