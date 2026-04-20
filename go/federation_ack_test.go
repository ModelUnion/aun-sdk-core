//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFederationAckMainChain 跨域消息 ack 主链验证：
// 发送方收到 ack 事件，ack_seq 正确，device_id 非空。
func TestFederationAckMainChain(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-ack-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-ack-b-%s.aid.net", rid))

	// 监听 alice 收到的 ack 事件
	var ackMu sync.Mutex
	var ackEvents []map[string]any
	ackDone := make(chan struct{}, 1)

	sub := alice.On("message.ack", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		to, _ := data["to"].(string)
		if to != bobAID {
			return
		}
		ackMu.Lock()
		ackEvents = append(ackEvents, data)
		ackMu.Unlock()
		select {
		case ackDone <- struct{}{}:
		default:
		}
	})
	defer sub.Unsubscribe()

	// Alice 发送消息给 Bob
	text := fmt.Sprintf("fed-ack-test-%s", rid)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"text": text},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("跨域发送失败: %v", err)
	}

	// Bob 拉取消息
	msgs := federationWaitForMessages(t, bob, func() []map[string]any {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		pullResult, err := bob.Call(ctx2, "message.pull", map[string]any{
			"after_seq": 0,
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
	}, 20*time.Second, func(items []map[string]any) bool {
		for _, item := range items {
			from, _ := item["from"].(string)
			if from == aliceAID && getPayloadText(item) == text {
				return true
			}
		}
		return false
	}, "等待 Bob 收到跨域消息")

	// 找到目标消息的 seq
	var targetSeq int
	for _, msg := range msgs {
		from, _ := msg["from"].(string)
		if from == aliceAID && getPayloadText(msg) == text {
			targetSeq = int(toInt64(msg["seq"]))
			break
		}
	}
	if targetSeq == 0 {
		t.Fatalf("未找到目标消息 seq")
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

	// 等待 Alice 收到 ack 事件
	timer := time.NewTimer(10 * time.Second)
	select {
	case <-ackDone:
	case <-timer.C:
		t.Fatalf("等待跨域 ack 事件超时")
	}
	timer.Stop()

	ackMu.Lock()
	defer ackMu.Unlock()
	if len(ackEvents) == 0 {
		t.Fatalf("未收到 ack 事件")
	}
	evt := ackEvents[0]
	deviceID := strings.TrimSpace(getStr(evt, "device_id", ""))
	if deviceID == "" {
		t.Fatalf("ack 事件缺少 device_id: %+v", evt)
	}
	ackSeq := int(toInt64(evt["ack_seq"]))
	if ackSeq != targetSeq {
		t.Fatalf("ack 事件 ack_seq 不正确: got=%d want=%d", ackSeq, targetSeq)
	}
}

// TestFederationMultiDeviceAck 跨域多设备 ack 隔离验证：
// 同一 AID 两个 slot 各自 ack，发送方收到两个独立 ack 事件。
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

	// 监听 ack 事件
	expectedSlots := map[string]bool{"fed-slot-a": true, "fed-slot-b": true}
	var ackMu sync.Mutex
	ackEvents := make([]map[string]any, 0, 2)
	ackDone := make(chan struct{}, 1)

	sub := alice.On("message.ack", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		to, _ := data["to"].(string)
		if to != bobAID {
			return
		}
		slotID := strings.TrimSpace(getStr(data, "slot_id", ""))
		if !expectedSlots[slotID] {
			return
		}
		ackMu.Lock()
		ackEvents = append(ackEvents, data)
		seen := map[string]bool{}
		for _, item := range ackEvents {
			seen[strings.TrimSpace(getStr(item, "slot_id", ""))] = true
		}
		complete := len(seen) == len(expectedSlots)
		ackMu.Unlock()
		if complete {
			select {
			case ackDone <- struct{}{}:
			default:
			}
		}
	})
	defer sub.Unsubscribe()

	// Alice 发送
	text := fmt.Sprintf("fed-multi-ack-%s", rid)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"text": text},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("跨域发送失败: %v", err)
	}

	// 两个 slot 各自拉取
	baseA := currentMaxSeq(t, bobSlotA, 200)
	baseB := currentMaxSeq(t, bobSlotB, 200)
	msgA := waitForSDKPullMessage(t, bobSlotA, aliceAID, baseA, text, 20*time.Second)
	msgB := waitForSDKPullMessage(t, bobSlotB, aliceAID, baseB, text, 20*time.Second)

	seqA := int(toInt64(msgA["seq"]))
	seqB := int(toInt64(msgB["seq"]))
	if seqA != seqB {
		t.Fatalf("同 AID 不同 slot seq 应一致: %d != %d", seqA, seqB)
	}

	// 各自 ack
	ctxA, cancelA := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = bobSlotA.Call(ctxA, "message.ack", map[string]any{"seq": seqA})
	cancelA()
	if err != nil {
		t.Fatalf("slot-a ack 失败: %v", err)
	}
	ctxB, cancelB := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = bobSlotB.Call(ctxB, "message.ack", map[string]any{"seq": seqB})
	cancelB()
	if err != nil {
		t.Fatalf("slot-b ack 失败: %v", err)
	}

	// 等待 Alice 收到两个 ack 事件
	timer := time.NewTimer(10 * time.Second)
	select {
	case <-ackDone:
	case <-timer.C:
		t.Fatalf("等待双 slot ack 事件超时: %+v", ackEvents)
	}
	timer.Stop()

	ackMu.Lock()
	defer ackMu.Unlock()
	slotsSeen := map[string]bool{}
	deviceIDs := map[string]bool{}
	for _, item := range ackEvents {
		slotsSeen[strings.TrimSpace(getStr(item, "slot_id", ""))] = true
		deviceIDs[strings.TrimSpace(getStr(item, "device_id", ""))] = true
	}
	if len(slotsSeen) != 2 {
		t.Fatalf("应收到 2 个不同 slot 的 ack 事件: %+v", ackEvents)
	}
	if len(deviceIDs) != 2 {
		t.Fatalf("应收到 2 个不同 device_id 的 ack 事件: %+v", ackEvents)
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"text": text},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	msgs := federationWaitForMessages(t, bob, func() []map[string]any {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		pullResult, _ := bob.Call(ctx2, "message.pull", map[string]any{
			"after_seq": 0,
			"limit":     50,
		})
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
	}, 20*time.Second, func(items []map[string]any) bool {
		for _, item := range items {
			from, _ := item["from"].(string)
			if from == aliceAID && getPayloadText(item) == text {
				return true
			}
		}
		return false
	}, "等待 Bob 收到消息")

	var targetSeq int
	for _, msg := range msgs {
		from, _ := msg["from"].(string)
		if from == aliceAID && getPayloadText(msg) == text {
			targetSeq = int(toInt64(msg["seq"]))
			break
		}
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
