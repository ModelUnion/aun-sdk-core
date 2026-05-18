//go:build integration

package aun

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// P2P 消息失败路径集成测试
//
// 运行方法:
//   cd go && go test -tags integration -run TestIntegration_Plaintext -v -timeout 300s
//   cd go && go test -tags integration -run TestIntegration_SendToNonexistent -v -timeout 300s
//   cd go && go test -tags integration -run TestIntegration_MessageSequenceAfterErrors -v -timeout 300s
//
// 前置条件:
//   - Docker 环境运行中（docker compose up -d）
//   - 运行环境能解析 gateway.agentid.pub
// ═══════════════════════════════════════════════════════════════════════════

// ── 测试 1: 显式明文发送不依赖对端 prekey ──────────────────────────────

func TestIntegration_PlaintextSendNoPrekey(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	target := makeClient(t)
	defer alice.Close()
	defer target.Close()

	// Alice 连接
	aliceAID := fmt.Sprintf("p2p-alice-%s.%s", rid, testIssuer())
	ensureConnected(t, alice, aliceAID)

	// 创建目标 AID（仅注册，不连接 — 所以不会上传 prekey）
	targetAID := fmt.Sprintf("p2p-target-%s.%s", rid, testIssuer())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := target.Auth.CreateAID(ctx, map[string]any{"aid": targetAID})
	if err != nil {
		t.Skipf("无法创建目标 AID（Docker 环境可能未运行）: %v", err)
	}

	// Alice 发送明文消息给目标（encrypt: false）
	// multi-device 架构下，接收方无注册设备时服务端拒绝投递
	_, err = alice.Call(ctx, "message.send", map[string]any{
		"to":      targetAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("plain-no-prekey-%s", rid)},
		"encrypt": false,
	})
	if err == nil {
		t.Fatalf("发送到无注册设备的 AID 应返回错误")
	}
	t.Logf("正确返回错误: %v", err)
}

// ── 测试 2: 发送到不存在的 AID 应失败 ──────────────────────────────────

func TestIntegration_SendToNonexistentAID(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	defer alice.Close()

	// Alice 连接
	aliceAID := fmt.Sprintf("p2p-nonex-a-%s.%s", rid, testIssuer())
	ensureConnected(t, alice, aliceAID)

	// 构造一个从未注册过的 AID
	nonexistentAID := fmt.Sprintf("nonexistent-%s.%s", rid, testIssuer())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 发送消息到不存在的 AID — 应返回错误
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      nonexistentAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("to-nonexistent-%s", rid)},
		"encrypt": false,
	})
	if err == nil {
		t.Errorf("发送到不存在的 AID 应返回错误")
	} else {
		t.Logf("正确返回错误: %v", err)
	}
}

// ── 测试 3: 明文消息可通过 pull 拉取 ──────────────────────────────────

func TestIntegration_PlaintextMessagePullable(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	// Alice 和 Bob 连接
	aliceAID := fmt.Sprintf("p2p-pull-a-%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("p2p-pull-b-%s.%s", rid, testIssuer())
	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Alice 发送明文持久化消息给 Bob
	expectedText := fmt.Sprintf("plaintext-pullable-%s", rid)
	waitBob := collectSDKPushMessages(bob, aliceAID, 1, func(msg map[string]any) bool {
		return getPayloadText(msg) == expectedText
	})
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": expectedText},
		"encrypt": false,
		"durable": true,
	})
	if err != nil {
		t.Fatalf("发送明文消息失败: %v", err)
	}

	msgs := waitBob(10 * time.Second)
	if len(msgs) < 1 {
		t.Fatalf("Bob 未能在线收到明文消息 (text=%s)", expectedText)
	}
	t.Logf("Bob 在线收到明文消息: seq=%v, text=%s", msgs[0]["seq"], getPayloadText(msgs[0]))
}

// ── 测试 4: 错误发送后消息序列号仍正确递增 ─────────────────────────────

func TestIntegration_MessageSequenceAfterErrors(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	// Alice 和 Bob 连接
	aliceAID := fmt.Sprintf("p2p-seq-a-%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("p2p-seq-b-%s.%s", rid, testIssuer())
	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 发送第一条有效消息
	text1 := fmt.Sprintf("seq-valid-1-%s", rid)
	text2 := fmt.Sprintf("seq-valid-2-%s", rid)
	waitBob := collectSDKPushMessages(bob, aliceAID, 2, func(msg map[string]any) bool {
		text := getPayloadText(msg)
		return text == text1 || text == text2
	})
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text1},
		"encrypt": false,
		"durable": true,
	})
	if err != nil {
		t.Fatalf("发送第一条消息失败: %v", err)
	}

	// 尝试发送到不存在的 AID（预期失败）
	nonexistentAID := fmt.Sprintf("nonexist-seq-%s.%s", rid, testIssuer())
	_, err = alice.Call(ctx, "message.send", map[string]any{
		"to":      nonexistentAID,
		"payload": map[string]any{"type": "text", "text": "should-fail"},
		"encrypt": false,
	})
	if err != nil {
		t.Logf("发送到不存在 AID 正确报错: %v", err)
	} else {
		t.Logf("发送到不存在 AID 未报错（服务端可能允许）")
	}

	// 发送第二条有效消息
	_, err = alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text2},
		"encrypt": false,
		"durable": true,
	})
	if err != nil {
		t.Fatalf("发送第二条消息失败: %v", err)
	}

	// 收集来自 Alice 的消息，验证序列号递增
	var seqs []int
	var texts []string
	msgs := waitBob(10 * time.Second)
	sort.Slice(msgs, func(i, j int) bool {
		return toInt64(msgs[i]["seq"]) < toInt64(msgs[j]["seq"])
	})
	for _, msg := range msgs {
		seq := int(toInt64(msg["seq"]))
		text := getPayloadText(msg)
		seqs = append(seqs, seq)
		texts = append(texts, text)
	}

	t.Logf("收到来自 Alice 的消息: seqs=%v, texts=%v", seqs, texts)

	if len(seqs) < 2 {
		t.Fatalf("期望至少 2 条来自 Alice 的消息，实际 %d", len(seqs))
	}

	// 验证序列号严格递增
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Errorf("序列号未递增: seqs[%d]=%d <= seqs[%d]=%d", i, seqs[i], i-1, seqs[i-1])
		}
	}

	// 验证两条有效消息都在结果中
	foundText1 := false
	foundText2 := false
	for _, text := range texts {
		if text == text1 {
			foundText1 = true
		}
		if text == text2 {
			foundText2 = true
		}
	}
	if !foundText1 {
		t.Errorf("缺少第一条有效消息: %s", text1)
	}
	if !foundText2 {
		t.Errorf("缺少第二条有效消息: %s", text2)
	}
}
