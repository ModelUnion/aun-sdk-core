//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// Replay Guard 集成测试 — 验证消息重放保护行为
//
// 运行方法:
//   cd go && go test -tags integration -run TestIntegration_ReplayGuard -v -timeout 300s
//
// 前置条件:
//   - Docker 环境运行中（docker compose up -d）
//   - 运行环境能解析 gateway.agentid.pub
// ═══════════════════════════════════════════════════════════════════════════

// TestIntegration_ReplayGuardBasicMessageFlow 基本消息收发 + replay guard 字段验证
//
// 场景：
//   1. Alice 和 Bob 连接
//   2. Alice 发送加密消息给 Bob
//   3. Bob 通过推送或 pull 接收
//   4. 验证消息包含 timestamp 和 message_id
//   5. 发送第二条消息，验证 message_id 不同
func TestIntegration_ReplayGuardBasicMessageFlow(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("rg%s-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("rg%s-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ── Alice 发送第一条加密消息 ──────────────────────────────────
	waitBob := collectSDKPushMessages(bob, aliceAID, 1, nil)

	result1, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("rg-basic-1-%s", rid)},
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("发送第一条消息失败: %v", err)
	}

	resultMap1, _ := result1.(map[string]any)
	msgID1, _ := resultMap1["message_id"].(string)
	t.Logf("第一条消息 message_id: %s", msgID1)

	// ── Bob 接收第一条消息 ────────────────────────────────────────
	msgs := recvSDKAfterSend(t, waitBob, bob, aliceAID, 0, 10*time.Second)
	if len(msgs) < 1 {
		t.Fatalf("Bob 期望至少收到 1 条消息，实际 %d", len(msgs))
	}

	msg1 := msgs[0]

	// 验证 timestamp 字段存在
	if _, ok := msg1["timestamp"]; !ok {
		t.Errorf("消息缺少 timestamp 字段: %v", msg1)
	} else {
		t.Logf("消息 timestamp: %v", msg1["timestamp"])
	}

	// 验证 message_id 字段存在
	recvMsgID1 := ""
	if id, ok := msg1["message_id"].(string); ok && id != "" {
		recvMsgID1 = id
		t.Logf("消息 message_id: %s", id)
	} else {
		t.Errorf("消息缺少 message_id 字段: %v", msg1)
	}

	// ── Alice 发送第二条加密消息 ──────────────────────────────────
	waitBob2 := collectSDKPushMessages(bob, aliceAID, 1, func(m map[string]any) bool {
		payload, _ := m["payload"].(map[string]any)
		if payload == nil {
			return false
		}
		text, _ := payload["text"].(string)
		return text == fmt.Sprintf("rg-basic-2-%s", rid)
	})

	result2, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("rg-basic-2-%s", rid)},
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("发送第二条消息失败: %v", err)
	}

	resultMap2, _ := result2.(map[string]any)
	msgID2, _ := resultMap2["message_id"].(string)
	t.Logf("第二条消息 message_id: %s", msgID2)

	// ── Bob 接收第二条消息 ────────────────────────────────────────
	msgs2 := recvSDKAfterSend(t, waitBob2, bob, aliceAID, 0, 10*time.Second)
	if len(msgs2) < 1 {
		t.Fatalf("Bob 期望至少收到第二条消息，实际 %d", len(msgs2))
	}

	// 查找第二条消息的 message_id
	recvMsgID2 := ""
	for _, m := range msgs2 {
		payload, _ := m["payload"].(map[string]any)
		if payload == nil {
			continue
		}
		text, _ := payload["text"].(string)
		if text == fmt.Sprintf("rg-basic-2-%s", rid) {
			if id, ok := m["message_id"].(string); ok {
				recvMsgID2 = id
			}
			break
		}
	}

	// ── 验证两条消息的 message_id 不同 ───────────────────────────
	if recvMsgID1 != "" && recvMsgID2 != "" {
		if recvMsgID1 == recvMsgID2 {
			t.Fatalf("两条消息的 message_id 不应相同: %s", recvMsgID1)
		}
		t.Logf("两条消息 message_id 不同（正确）: %s vs %s", recvMsgID1, recvMsgID2)
	}

	if msgID1 != "" && msgID2 != "" && msgID1 == msgID2 {
		t.Fatalf("发送端两次返回的 message_id 不应相同: %s", msgID1)
	}
}

// TestIntegration_ReplayGuardDuplicatePullIdempotent 重复 pull 幂等性验证
//
// 场景：
//   1. Alice 发送消息给 Bob
//   2. Bob 以 after_seq=0 拉取
//   3. Bob 再次以 after_seq=0 拉取
//   4. 两次 pull 应返回相同消息（幂等），不应崩溃或报错
func TestIntegration_ReplayGuardDuplicatePullIdempotent(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("rg%s-dp-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("rg%s-dp-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ── Alice 发送一条消息 ────────────────────────────────────────
	uniqueText := fmt.Sprintf("rg-dup-%s-%d", rid, time.Now().UnixMilli())
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": uniqueText},
		"durable": true,
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("发送消息失败: %v", err)
	}

	// 等待消息到达服务端
	time.Sleep(2 * time.Second)

	// ── 第一次 pull（after_seq=0）──────────────────────────────
	pull1Result, err := bob.Call(ctx, "message.pull", map[string]any{
		"after_seq": 0,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("第一次 pull 失败: %v", err)
	}

	pull1Map, _ := pull1Result.(map[string]any)
	pull1Msgs, _ := pull1Map["messages"].([]any)
	t.Logf("第一次 pull 返回 %d 条消息", len(pull1Msgs))

	// ── 第二次 pull（同样 after_seq=0）────────────────────────
	pull2Result, err := bob.Call(ctx, "message.pull", map[string]any{
		"after_seq": 0,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("第二次 pull 失败（幂等性破坏）: %v", err)
	}

	pull2Map, _ := pull2Result.(map[string]any)
	pull2Msgs, _ := pull2Map["messages"].([]any)
	t.Logf("第二次 pull 返回 %d 条消息", len(pull2Msgs))

	if len(pull1Msgs) != len(pull2Msgs) {
		t.Errorf("两次 pull 消息数不一致: 第一次=%d, 第二次=%d", len(pull1Msgs), len(pull2Msgs))
	}

	var pull1FromAlice []map[string]any
	for _, m := range pull1Msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		from, _ := msg["from"].(string)
		if from == aliceAID {
			pull1FromAlice = append(pull1FromAlice, msg)
		}
	}

	var pull2FromAlice []map[string]any
	for _, m := range pull2Msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		from, _ := msg["from"].(string)
		if from == aliceAID {
			pull2FromAlice = append(pull2FromAlice, msg)
		}
	}
	if len(pull2FromAlice) < len(pull1FromAlice) {
		t.Errorf("第二次 pull 消息数 (%d) 不应少于第一次 (%d)", len(pull2FromAlice), len(pull1FromAlice))
	}

	// 对比两次 pull 的 message_id 集合，确认一致
	ids1 := make(map[string]bool)
	for _, msg := range pull1FromAlice {
		if id, ok := msg["message_id"].(string); ok {
			ids1[id] = true
		}
	}

	matchCount := 0
	for _, msg := range pull2FromAlice {
		if id, ok := msg["message_id"].(string); ok && ids1[id] {
			matchCount++
		}
	}

	t.Logf("两次 pull 共有 message_id 数: %d / %d", matchCount, len(ids1))
	if matchCount < len(ids1) {
		t.Errorf("第二次 pull 缺少第一次 pull 中的部分消息（幂等性问题）")
	}
	if len(pull1FromAlice) == 0 {
		t.Logf("在线消息可能已通过 push 自动 ack，pull 未返回本轮消息；幂等性按两次 pull 结果一致验证")
	}
}

// TestIntegration_ReplayGuardSequenceProgression 消息序列号严格递增验证
//
// 场景：
//   1. Alice 连续发送 5 条消息给 Bob
//   2. Bob 拉取所有消息
//   3. 验证 seq 严格递增
//   4. 验证 seq 无间隙
func TestIntegration_ReplayGuardSequenceProgression(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("rg%s-sq-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("rg%s-sq-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 获取当前基线 seq
	baseSeq := currentMaxSeq(t, bob, 200)
	t.Logf("基线 seq: %d", baseSeq)

	// ── Alice 连续发送 5 条消息 ──────────────────────────────────
	const msgCount = 5
	prefix := fmt.Sprintf("rg-seq-%s-", rid)
	waitBob := collectSDKPushMessages(bob, aliceAID, msgCount, func(msg map[string]any) bool {
		return strings.HasPrefix(getPayloadText(msg), prefix)
	})
	for i := 0; i < msgCount; i++ {
		_, err := alice.Call(ctx, "message.send", map[string]any{
			"to": bobAID,
			"payload": map[string]any{
				"type": "text",
				"text": fmt.Sprintf("%s%d", prefix, i),
			},
			"durable": true,
			"encrypt": true,
		})
		if err != nil {
			t.Fatalf("发送第 %d 条消息失败: %v", i, err)
		}
	}

	testMsgs := waitBob(15 * time.Second)

	t.Logf("在线收到 %d 条本轮测试消息", len(testMsgs))
	if len(testMsgs) < msgCount {
		t.Fatalf("期望至少 %d 条消息，实际 %d", msgCount, len(testMsgs))
	}

	// ── 提取并排序 seq ──────────────────────────────────────────
	seqs := make([]int, 0, len(testMsgs))
	for _, msg := range testMsgs {
		seq := int(toInt64(msg["seq"]))
		seqs = append(seqs, seq)
	}

	// 按 seq 排序（消息可能乱序返回）
	for i := 0; i < len(seqs); i++ {
		for j := i + 1; j < len(seqs); j++ {
			if seqs[j] < seqs[i] {
				seqs[i], seqs[j] = seqs[j], seqs[i]
			}
		}
	}

	t.Logf("消息 seq 序列: %v", seqs)

	// ── 验证 seq 严格递增 ────────────────────────────────────────
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("seq 不是严格递增: seqs[%d]=%d <= seqs[%d]=%d", i, seqs[i], i-1, seqs[i-1])
		}
	}
	t.Logf("seq 严格递增验证通过")

	// ── 验证 seq 无间隙 ──────────────────────────────────────────
	for i := 1; i < len(seqs); i++ {
		gap := seqs[i] - seqs[i-1]
		if gap != 1 {
			t.Errorf("seq 存在间隙: seqs[%d]=%d -> seqs[%d]=%d (gap=%d)",
				i-1, seqs[i-1], i, seqs[i], gap)
		}
	}
	t.Logf("seq 连续性验证完成")
}
