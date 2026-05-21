//go:build integration

// integration_v2_thought_test.go — V2 thought.put / thought.get 端到端测试
//
// 与 Python e2e_test_v2_thought.py 对齐，覆盖 5 个场景：
//   1. P2P thought.put 走 V2 envelope（payload.type == "e2ee.p2p_encrypted"，含 recipients[]）
//   2. P2P thought.get 解密回明文
//   3. P2P thought 重复读取不消耗（无 replay guard）
//   4. Group thought.put 走 V2 envelope（payload.type == "e2ee.group_encrypted"，含 recipients[]）
//   5. Group thought.get 解密回明文
//
// 用法：
//   MSYS_NO_PATHCONV=1 docker exec kite-go-tester sh -lc "cd /workspace/go && \
//       /usr/local/go/bin/go test -tags integration . -run TestV2Thought -count=1 -v"

package aun

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// v2ThoughtPayloadTexts 从 thought.get 结果中收集 payload.text。
func v2ThoughtPayloadTexts(t *testing.T, result map[string]any) []string {
	t.Helper()
	rawThoughts, _ := result["thoughts"].([]any)
	texts := make([]string, 0, len(rawThoughts))
	for _, raw := range rawThoughts {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		payload, _ := item["payload"].(map[string]any)
		if payload == nil {
			continue
		}
		if text, _ := payload["text"].(string); text != "" {
			texts = append(texts, text)
		}
	}
	return texts
}

// TestV2Thought_FullFlow 5 个场景串行执行，与 Python e2e_test_v2_thought.py 对齐。
func TestV2Thought_FullFlow(t *testing.T) {
	rid := runID()

	alice := makeV2Client(t)
	bob := makeV2Client(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2t-a-%s.%s", rid, testIssuer()))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2t-b-%s.%s", rid, testIssuer()))

	if alice.v2GetState() == nil || bob.v2GetState() == nil {
		t.Fatalf("V2 session 未初始化（aliceV2=%v, bobV2=%v）",
			alice.v2GetState() != nil, bob.v2GetState() != nil)
	}

	// 创建 V2 群（V2 默认能力声明会让服务端创建 V2 群）
	groupID := v2CreateGroup(t, alice, fmt.Sprintf("v2-thought-%s", rid))
	v2AddMember(t, alice, groupID, bobAID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)

	// ── 场景 1：P2P thought.put 写 V2 envelope ─────────────────────
	p2pCtx := map[string]any{"type": "v2-run", "id": fmt.Sprintf("v2-thought-run-%s", rid)}
	p2pText := fmt.Sprintf("v2-thought-p2p-%s-%d", rid, time.Now().UnixNano())

	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		put, err := alice.Call(ctx, "message.thought.put", map[string]any{
			"to":         bobAID,
			"context":    p2pCtx,
			"thought_id": fmt.Sprintf("mt-v2-%s", rid),
			"payload":    map[string]any{"type": "thought", "text": p2pText},
		})
		if err != nil {
			t.Fatalf("P2P thought.put 失败: %v", err)
		}
		putMap, _ := put.(map[string]any)
		if int(toInt64(putMap["stored_count"])) < 1 {
			t.Fatalf("P2P thought.put stored_count<1: %#v", put)
		}
	}

	// 服务端原始返回：直接 transport.Call，绕过 SDK 解密路径
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		raw, err := bob.transport.Call(ctx, "message.thought.get", map[string]any{
			"sender_aid": aliceAID,
			"context":    p2pCtx,
		})
		if err != nil {
			t.Fatalf("raw P2P thought.get 失败: %v", err)
		}
		rawMap, _ := raw.(map[string]any)
		items, _ := rawMap["thoughts"].([]any)
		if len(items) == 0 {
			t.Fatalf("服务端 P2P thoughts 为空: %#v", rawMap)
		}
		first, _ := items[0].(map[string]any)
		payload, _ := first["payload"].(map[string]any)
		envType, _ := payload["type"].(string)
		if envType != "e2ee.p2p_encrypted" {
			t.Fatalf("V2 P2P thought payload.type 必须为 e2ee.p2p_encrypted, got=%s payload=%#v", envType, payload)
		}
		recipients, _ := payload["recipients"].([]any)
		if len(recipients) == 0 {
			t.Fatalf("V2 P2P thought envelope.recipients 必须非空: %#v", payload)
		}
		t.Logf("[场景 1] V2 P2P thought envelope OK: type=%s recipients=%d", envType, len(recipients))
	}

	// ── 场景 2：P2P thought.get 解密回明文 ──────────────────────────
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result, err := bob.Call(ctx, "message.thought.get", map[string]any{
			"sender_aid": aliceAID,
			"context":    p2pCtx,
		})
		if err != nil {
			t.Fatalf("SDK P2P thought.get 失败: %v", err)
		}
		resultMap, _ := result.(map[string]any)
		texts := v2ThoughtPayloadTexts(t, resultMap)
		if !containsString(texts, p2pText) {
			t.Fatalf("V2 P2P thought 解密返回不含期望文本: texts=%v want %q", texts, p2pText)
		}
		t.Logf("[场景 2] V2 P2P thought 解密 OK: text=%s", p2pText)
	}

	// ── 场景 3：P2P thought 重复读取（无 replay guard） ────────────
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result, err := bob.Call(ctx, "message.thought.get", map[string]any{
			"sender_aid": aliceAID,
			"context":    p2pCtx,
		})
		if err != nil {
			t.Fatalf("重复 P2P thought.get 失败: %v", err)
		}
		resultMap, _ := result.(map[string]any)
		texts := v2ThoughtPayloadTexts(t, resultMap)
		if !containsString(texts, p2pText) {
			t.Fatalf("V2 P2P thought 重复读失败: texts=%v want %q", texts, p2pText)
		}
		// 验证 e2ee.protected_headers / e2ee.context 暴露
		rawThoughts, _ := resultMap["thoughts"].([]any)
		if len(rawThoughts) > 0 {
			first, _ := rawThoughts[0].(map[string]any)
			e2ee, _ := first["e2ee"].(map[string]any)
			if e2ee == nil {
				t.Fatalf("P2P thought e2ee metadata 缺失")
			}
			if e2ee["version"] != "v2" {
				t.Fatalf("P2P thought e2ee.version != v2, got=%v", e2ee["version"])
			}
			// protected_headers 不应含 _auth
			if ph, ok := e2ee["protected_headers"].(map[string]any); ok {
				if _, hasAuth := ph["_auth"]; hasAuth {
					t.Fatalf("P2P thought e2ee.protected_headers 不应包含 _auth")
				}
			}
			// context 不应含 _auth，且应包含原始字段
			if ctx, ok := e2ee["context"].(map[string]any); ok {
				if _, hasAuth := ctx["_auth"]; hasAuth {
					t.Fatalf("P2P thought e2ee.context 不应包含 _auth")
				}
				if ctx["type"] != p2pCtx["type"] || ctx["id"] != p2pCtx["id"] {
					t.Fatalf("P2P thought e2ee.context 不匹配: got=%v want=%v", ctx, p2pCtx)
				}
			}
		}
		t.Logf("[场景 3] V2 P2P thought 重复读 OK")
	}

	// ── 场景 4：Group thought.put 写 V2 envelope ───────────────────
	gCtx := map[string]any{"type": "v2-group-run", "id": fmt.Sprintf("v2-group-thought-%s", rid)}
	gText := fmt.Sprintf("v2-group-thought-%s-%d", rid, time.Now().UnixNano())
	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := alice.Call(ctx, "group.thought.put", map[string]any{
			"group_id": groupID,
			"context":  gCtx,
			"payload":  map[string]any{"type": "thought", "text": gText},
		})
		if err != nil {
			t.Fatalf("Group thought.put 失败: %v", err)
		}
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		raw, err := bob.transport.Call(ctx, "group.thought.get", map[string]any{
			"group_id":   groupID,
			"sender_aid": aliceAID,
			"context":    gCtx,
		})
		if err != nil {
			t.Fatalf("raw group thought.get 失败: %v", err)
		}
		rawMap, _ := raw.(map[string]any)
		items, _ := rawMap["thoughts"].([]any)
		if len(items) == 0 {
			t.Fatalf("服务端 Group thoughts 为空: %#v", rawMap)
		}
		first, _ := items[0].(map[string]any)
		payload, _ := first["payload"].(map[string]any)
		envType, _ := payload["type"].(string)
		if envType != "e2ee.group_encrypted" {
			t.Fatalf("V2 Group thought payload.type 必须为 e2ee.group_encrypted, got=%s payload=%#v", envType, payload)
		}
		recipients, _ := payload["recipients"].([]any)
		if len(recipients) == 0 {
			t.Fatalf("V2 Group thought envelope.recipients 必须非空: %#v", payload)
		}
		t.Logf("[场景 4] V2 Group thought envelope OK: type=%s recipients=%d", envType, len(recipients))
	}

	// ── 场景 5：Group thought.get 解密 ──────────────────────────────
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result, err := bob.Call(ctx, "group.thought.get", map[string]any{
			"group_id":   groupID,
			"sender_aid": aliceAID,
			"context":    gCtx,
		})
		if err != nil {
			t.Fatalf("SDK Group thought.get 失败: %v", err)
		}
		resultMap, _ := result.(map[string]any)
		texts := v2ThoughtPayloadTexts(t, resultMap)
		if !containsString(texts, gText) {
			t.Fatalf("V2 Group thought 解密返回不含期望文本: texts=%v want %q", texts, gText)
		}
		// 验证 e2ee.protected_headers / e2ee.context 暴露
		rawThoughts, _ := resultMap["thoughts"].([]any)
		if len(rawThoughts) > 0 {
			first, _ := rawThoughts[0].(map[string]any)
			e2ee, _ := first["e2ee"].(map[string]any)
			if e2ee == nil {
				t.Fatalf("Group thought e2ee metadata 缺失")
			}
			if e2ee["version"] != "v2" {
				t.Fatalf("Group thought e2ee.version != v2, got=%v", e2ee["version"])
			}
			// protected_headers 不应含 _auth
			if ph, ok := e2ee["protected_headers"].(map[string]any); ok {
				if _, hasAuth := ph["_auth"]; hasAuth {
					t.Fatalf("Group thought e2ee.protected_headers 不应包含 _auth")
				}
			}
			// context 不应含 _auth，且应包含原始字段
			if ctxMap, ok := e2ee["context"].(map[string]any); ok {
				if _, hasAuth := ctxMap["_auth"]; hasAuth {
					t.Fatalf("Group thought e2ee.context 不应包含 _auth")
				}
				if ctxMap["type"] != gCtx["type"] || ctxMap["id"] != gCtx["id"] {
					t.Fatalf("Group thought e2ee.context 不匹配: got=%v want=%v", ctxMap, gCtx)
				}
			}
		}
		t.Logf("[场景 5] V2 Group thought 解密 OK: text=%s", gText)
	}
}

func containsString(arr []string, want string) bool {
	for _, s := range arr {
		if s == want {
			return true
		}
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}
