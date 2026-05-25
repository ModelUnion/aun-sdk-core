//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func waitFederationMessageByPushOrPull(
	t *testing.T,
	waitPush func(time.Duration) []map[string]any,
	client *AUNClient,
	fromAID string,
	afterSeq int,
	expectedText string,
	label string,
) []map[string]any {
	t.Helper()
	matches := func(items []map[string]any) bool {
		for _, item := range items {
			from, _ := item["from"].(string)
			if from == fromAID && getPayloadText(item) == expectedText {
				return true
			}
		}
		return false
	}
	if waitPush != nil {
		if msgs := waitPush(20 * time.Second); matches(msgs) {
			return msgs
		}
	}
	return federationWaitForMessages(t, client, func() []map[string]any {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pullResult, err := client.Call(ctx, "message.pull", map[string]any{
			"after_seq": afterSeq,
			"limit":     50,
		})
		if err != nil {
			return nil
		}
		pullMap, _ := pullResult.(map[string]any)
		if pullMap == nil {
			return nil
		}
		msgsAny, _ := pullMap["messages"].([]any)
		var items []map[string]any
		for _, raw := range msgsAny {
			if msg, ok := raw.(map[string]any); ok {
				items = append(items, msg)
			}
		}
		return items
	}, 20*time.Second, matches, label)
}

func findFederationMessageByText(t *testing.T, msgs []map[string]any, fromAID string, text string) map[string]any {
	t.Helper()
	for _, msg := range msgs {
		from, _ := msg["from"].(string)
		if from == fromAID && getPayloadText(msg) == text {
			return msg
		}
	}
	t.Fatalf("未找到目标消息: from=%s text=%q messages=%#v", fromAID, text, msgs)
	return nil
}

// TestFederationAckMainChain 跨域消息 ack 主链验证：ack_seq 正确推进。
func TestFederationAckMainChain(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-ack-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-ack-b-%s.aid.net", rid))

	// Alice 发送消息给 Bob
	text := fmt.Sprintf("fed-ack-test-%s", rid)
	waitBob := collectSDKPushMessages(bob, aliceAID, 1, func(msg map[string]any) bool {
		return getPayloadText(msg) == text
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("跨域发送失败: %v", err)
	}

	msgs := waitFederationMessageByPushOrPull(t, waitBob, bob, aliceAID, 0, text, "等待 Bob 收到跨域消息")
	targetMsg := findFederationMessageByText(t, msgs, aliceAID, text)
	targetSeq := int(toInt64(targetMsg["seq"]))
	if targetSeq == 0 {
		t.Fatalf("目标消息缺少 seq: %#v", targetMsg)
	}

	// Bob ack
	ctxAck, cancelAck := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelAck()
	ackResult, err := bob.Call(ctxAck, "message.ack", map[string]any{"seq": targetSeq})
	if err != nil {
		t.Fatalf("跨域 ack 失败: %v", err)
	}
	ackMap, _ := ackResult.(map[string]any)
	if int(toInt64(ackMap["ack_seq"])) != targetSeq {
		t.Fatalf("ack_seq 不正确: got=%v want=%d", ackMap["ack_seq"], targetSeq)
	}
}

// TestFederationMultiDeviceAck 跨域多设备 ack 隔离验证：
// 同一 AID 两个 slot 各自 ack，cursor 互不污染。
func TestFederationMultiDeviceAck(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	sharedRoot := t.TempDir()
	bobSlotA := makeIsolatedClient(t, sharedRoot, "fed-slot-a")
	bobSlotB := makeIsolatedClient(t, sharedRoot, "fed-slot-b")
	defer alice.Close()
	defer bobSlotA.Close()
	defer bobSlotB.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-mack-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bobSlotA, fmt.Sprintf("go-mack-b-%s.aid.net", rid))
	ensureFederationConnected(t, bobSlotB, bobAID)

	// 两个 slot 各自记录基线 seq（必须在 Alice 发送之前）
	baseA := currentMaxSeq(t, bobSlotA, 200)
	baseB := currentMaxSeq(t, bobSlotB, 200)

	// Alice 发送
	text := fmt.Sprintf("fed-multi-ack-%s", rid)
	textPredicate := func(msg map[string]any) bool {
		return getPayloadText(msg) == text
	}
	waitSlotA := collectSDKPushMessages(bobSlotA, aliceAID, 1, textPredicate)
	waitSlotB := collectSDKPushMessages(bobSlotB, aliceAID, 1, textPredicate)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("跨域发送失败: %v", err)
	}

	// 两个 slot 各自接收。full-direct 下在线收件方会优先收到 push 并自动 ACK。
	msgsA := waitFederationMessageByPushOrPull(t, waitSlotA, bobSlotA, aliceAID, baseA, text, "等待 slot-a 收到跨域消息")
	msgsB := waitFederationMessageByPushOrPull(t, waitSlotB, bobSlotB, aliceAID, baseB, text, "等待 slot-b 收到跨域消息")
	msgA := findFederationMessageByText(t, msgsA, aliceAID, text)
	msgB := findFederationMessageByText(t, msgsB, aliceAID, text)

	seqA := int(toInt64(msgA["seq"]))
	seqB := int(toInt64(msgB["seq"]))
	if seqA == 0 || seqB == 0 {
		t.Fatalf("目标消息缺少 seq: slotA=%#v slotB=%#v", msgA, msgB)
	}
	if seqA != seqB {
		t.Fatalf("同 AID 不同 slot seq 应一致: %d != %d", seqA, seqB)
	}

	// 各自 ack
	ctxA, cancelA := context.WithTimeout(context.Background(), 10*time.Second)
	ackA, err := bobSlotA.Call(ctxA, "message.ack", map[string]any{"seq": seqA})
	cancelA()
	if err != nil {
		t.Fatalf("slot-a ack 失败: %v", err)
	}
	ctxB, cancelB := context.WithTimeout(context.Background(), 10*time.Second)
	ackB, err := bobSlotB.Call(ctxB, "message.ack", map[string]any{"seq": seqB})
	cancelB()
	if err != nil {
		t.Fatalf("slot-b ack 失败: %v", err)
	}
	ackAMap, _ := ackA.(map[string]any)
	ackBMap, _ := ackB.(map[string]any)
	if int(toInt64(ackAMap["ack_seq"])) != seqA {
		t.Fatalf("slot-a ack_seq 不正确: %#v", ackAMap)
	}
	if int(toInt64(ackBMap["ack_seq"])) != seqB {
		t.Fatalf("slot-b ack_seq 不正确: %#v", ackBMap)
	}
}

// TestFederationAckIdempotent 跨域 ack 幂等性验证：
// 同一 seq 重复 ack 不报错，ack_seq 保持不变。
func TestFederationAckIdempotent(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-idem-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-idem-b-%s.aid.net", rid))

	text := fmt.Sprintf("fed-idem-ack-%s", rid)
	waitBob := collectSDKPushMessages(bob, aliceAID, 1, func(msg map[string]any) bool {
		return getPayloadText(msg) == text
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	msgs := waitFederationMessageByPushOrPull(t, waitBob, bob, aliceAID, 0, text, "等待 Bob 收到消息")
	targetMsg := findFederationMessageByText(t, msgs, aliceAID, text)
	targetSeq := int(toInt64(targetMsg["seq"]))
	if targetSeq == 0 {
		t.Fatalf("目标消息缺少 seq: %#v", targetMsg)
	}

	// 第一次 ack
	ctxAck1, cancelAck1 := context.WithTimeout(context.Background(), 10*time.Second)
	ack1, err := bob.Call(ctxAck1, "message.ack", map[string]any{"seq": targetSeq})
	cancelAck1()
	if err != nil {
		t.Fatalf("第一次 ack 失败: %v", err)
	}
	ack1Map, _ := ack1.(map[string]any)
	seq1 := int(toInt64(ack1Map["ack_seq"]))

	// 第二次 ack（幂等）
	ctxAck2, cancelAck2 := context.WithTimeout(context.Background(), 10*time.Second)
	ack2, err := bob.Call(ctxAck2, "message.ack", map[string]any{"seq": targetSeq})
	cancelAck2()
	if err != nil {
		t.Fatalf("第二次 ack 失败（应幂等）: %v", err)
	}
	ack2Map, _ := ack2.(map[string]any)
	seq2 := int(toInt64(ack2Map["ack_seq"]))

	if seq1 != seq2 {
		t.Fatalf("幂等 ack 返回不一致: %d != %d", seq1, seq2)
	}
	if seq1 != targetSeq {
		t.Fatalf("ack_seq 不正确: got=%d want=%d", seq1, targetSeq)
	}
}
