//go:build integration

package aun

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 消息 ACK 测试
// ---------------------------------------------------------------------------

// TestIntegration_MessageAckBasic 基础 ACK 流程：发送 → 拉取 → 确认
func TestIntegration_MessageAckBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureConnected(t, alice, fmt.Sprintf("ack-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("ack-bob-%s.%s", rid, testIssuer()))

	// 记录 Bob 当前最大 seq，作为 pull 起点
	baseSeq := currentMaxSeq(t, bob, 200)
	t.Logf("Bob 基线 seq: %d", baseSeq)

	// Alice 发送持久化明文消息给 Bob
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": "ack_basic_test"},
		"persist": true,
		"encrypt": false,
	})
	if err != nil {
		t.Skipf("发送消息失败（Docker 环境可能未运行）: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Bob 拉取消息
	pullResult, err := bob.Call(ctx, "message.pull", map[string]any{
		"after_seq": baseSeq,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("Bob pull 失败: %v", err)
	}
	pullMap, _ := pullResult.(map[string]any)
	msgs, _ := pullMap["messages"].([]any)

	// 找到来自 Alice 的消息
	var msgSeq int
	found := false
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		from, _ := msg["from"].(string)
		if from == aliceAID {
			msgSeq = int(toInt64(msg["seq"]))
			found = true
			t.Logf("收到消息 seq=%d from=%s", msgSeq, from)
			break
		}
	}
	if !found {
		t.Fatalf("Bob 未收到来自 Alice 的消息, pull 结果: %#v", pullMap)
	}

	// Bob 确认消息
	ackResult, err := bob.Call(ctx, "message.ack", map[string]any{"seq": msgSeq})
	if err != nil {
		t.Fatalf("Bob ack 失败: %v", err)
	}
	ackMap, _ := ackResult.(map[string]any)
	t.Logf("ack 结果: %#v", ackMap)

	// 验证 ack 结果
	success, _ := ackMap["success"].(bool)
	if !success {
		t.Errorf("ack 应返回 success=true, 实际: %#v", ackMap)
	}
	ackSeq := int(toInt64(ackMap["ack_seq"]))
	if ackSeq < msgSeq {
		t.Errorf("ack_seq(%d) 应 >= msg_seq(%d)", ackSeq, msgSeq)
	}
}

// TestIntegration_MessageAckEvent 验证 ACK 事件通知：发送方收到接收方的 ack 事件
func TestIntegration_MessageAckEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	_ = ensureConnected(t, alice, fmt.Sprintf("ackev-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("ackev-bob-%s.%s", rid, testIssuer()))

	baseSeq := currentMaxSeq(t, bob, 200)

	// Alice 订阅 ack 事件
	var mu sync.Mutex
	var ackEvents []map[string]any
	ackDone := make(chan struct{}, 1)

	sub := alice.On("message.ack", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		mu.Lock()
		ackEvents = append(ackEvents, data)
		mu.Unlock()
		select {
		case ackDone <- struct{}{}:
		default:
		}
	})
	defer sub.Unsubscribe()

	// Alice 发送消息给 Bob
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": "ack_event_test"},
		"persist": true,
		"encrypt": false,
	})
	if err != nil {
		t.Skipf("发送消息失败: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Bob 拉取并确认
	pullResult, err := bob.Call(ctx, "message.pull", map[string]any{
		"after_seq": baseSeq,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("Bob pull 失败: %v", err)
	}
	pullMap, _ := pullResult.(map[string]any)
	msgs, _ := pullMap["messages"].([]any)

	var msgSeq int
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		msgSeq = int(toInt64(msg["seq"]))
	}
	if msgSeq == 0 {
		t.Fatalf("Bob 未收到消息")
	}

	_, err = bob.Call(ctx, "message.ack", map[string]any{"seq": msgSeq})
	if err != nil {
		t.Fatalf("Bob ack 失败: %v", err)
	}

	// 等待 Alice 收到 ack 事件
	timer := time.NewTimer(10 * time.Second)
	select {
	case <-ackDone:
	case <-timer.C:
		t.Fatalf("等待 ack 事件超时")
	}
	timer.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(ackEvents) == 0 {
		t.Fatalf("Alice 未收到 ack 事件")
	}

	evt := ackEvents[0]
	t.Logf("ack 事件: %#v", evt)

	// 验证事件中的 to 字段（接收方 AID）和 ack_seq
	to := getStr(evt, "to", "")
	if to != bobAID {
		t.Errorf("ack 事件 to 应为 %s, 实际: %s", bobAID, to)
	}
	evtAckSeq := int(toInt64(evt["ack_seq"]))
	if evtAckSeq < msgSeq {
		t.Errorf("ack 事件 ack_seq(%d) 应 >= msg_seq(%d)", evtAckSeq, msgSeq)
	}
}

// TestIntegration_MessageAckSequence 顺序 ACK：连续发送 3 条消息，逐条确认，验证 ack_seq 递增
func TestIntegration_MessageAckSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	_ = ensureConnected(t, alice, fmt.Sprintf("ackseq-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("ackseq-bob-%s.%s", rid, testIssuer()))

	baseSeq := currentMaxSeq(t, bob, 200)

	// Alice 连续发送 3 条消息
	for i := 1; i <= 3; i++ {
		_, err := alice.Call(ctx, "message.send", map[string]any{
			"to":      bobAID,
			"payload": map[string]any{"type": "text", "text": fmt.Sprintf("seq_test_%d", i)},
			"persist": true,
			"encrypt": false,
		})
		if err != nil {
			if i == 1 {
				t.Skipf("发送消息失败: %v", err)
			}
			t.Fatalf("发送第 %d 条消息失败: %v", i, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	time.Sleep(1 * time.Second)

	// Bob 拉取所有消息
	pullResult, err := bob.Call(ctx, "message.pull", map[string]any{
		"after_seq": baseSeq,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("Bob pull 失败: %v", err)
	}
	pullMap, _ := pullResult.(map[string]any)
	allMsgs, _ := pullMap["messages"].([]any)

	// 收集消息的 seq
	var seqs []int
	for _, m := range allMsgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		seq := int(toInt64(msg["seq"]))
		if seq > baseSeq {
			seqs = append(seqs, seq)
		}
	}
	if len(seqs) < 3 {
		t.Fatalf("期望至少 3 条消息，实际 %d 条 (seqs=%v)", len(seqs), seqs)
	}
	t.Logf("收到消息 seqs: %v", seqs)

	// 逐条确认，验证 ack_seq 递增
	prevAckSeq := 0
	for i, seq := range seqs[:3] {
		ackResult, err := bob.Call(ctx, "message.ack", map[string]any{"seq": seq})
		if err != nil {
			t.Fatalf("第 %d 次 ack(seq=%d) 失败: %v", i+1, seq, err)
		}
		ackMap, _ := ackResult.(map[string]any)
		ackSeq := int(toInt64(ackMap["ack_seq"]))
		t.Logf("第 %d 次 ack: seq=%d -> ack_seq=%d", i+1, seq, ackSeq)

		if ackSeq < seq {
			t.Errorf("第 %d 次: ack_seq(%d) 应 >= seq(%d)", i+1, ackSeq, seq)
		}
		if ackSeq < prevAckSeq {
			t.Errorf("第 %d 次: ack_seq(%d) 应 >= 上次 ack_seq(%d)", i+1, ackSeq, prevAckSeq)
		}
		prevAckSeq = ackSeq
	}
}

// ---------------------------------------------------------------------------
// 在线状态测试
// ---------------------------------------------------------------------------

// TestIntegration_OnlineAfterConnect 连接后查询在线状态
func TestIntegration_OnlineAfterConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	_ = ensureConnected(t, alice, fmt.Sprintf("on-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("on-bob-%s.%s", rid, testIssuer()))

	time.Sleep(1 * time.Second)

	// Alice 查询 Bob 的在线状态
	result, err := alice.Call(ctx, "message.query_online", map[string]any{
		"aids": []string{bobAID},
	})
	if err != nil {
		t.Skipf("查询在线状态失败（Docker 环境可能未运行）: %v", err)
	}

	resultMap, _ := result.(map[string]any)
	t.Logf("在线状态查询结果: %#v", resultMap)

	// 验证 Bob 在线
	online, _ := resultMap["online"].(map[string]any)
	if online == nil {
		// 尝试 results 字段格式
		results, _ := resultMap["results"].(map[string]any)
		if results != nil {
			bobStatus, _ := results[bobAID].(map[string]any)
			if bobStatus != nil {
				isOnline, _ := bobStatus["online"].(bool)
				if !isOnline {
					t.Errorf("Bob 应为在线状态, 实际: %#v", bobStatus)
				}
				return
			}
		}
		// 尝试直接在顶层查找
		bobOnline, _ := resultMap[bobAID].(bool)
		if !bobOnline {
			// 也可能是 map[aid]->status 格式
			t.Logf("无法解析在线状态格式，完整结果: %#v", resultMap)
		}
		return
	}

	bobOnline, exists := online[bobAID]
	if !exists {
		t.Errorf("查询结果中缺少 Bob AID: %s", bobAID)
	}
	isOnline, _ := bobOnline.(bool)
	if !isOnline {
		t.Errorf("Bob 应为在线状态, 实际: %v", bobOnline)
	}
}

// TestIntegration_OfflineAfterDisconnect 断开后查询应为离线
func TestIntegration_OfflineAfterDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()

	_ = ensureConnected(t, alice, fmt.Sprintf("off-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("off-bob-%s.%s", rid, testIssuer()))

	time.Sleep(1 * time.Second)

	// 先验证 Bob 在线
	result, err := alice.Call(ctx, "message.query_online", map[string]any{
		"aids": []string{bobAID},
	})
	if err != nil {
		t.Skipf("查询在线状态失败: %v", err)
	}
	t.Logf("断开前在线状态: %#v", result)

	// Bob 断开连接
	bob.Close()
	t.Logf("Bob 已断开连接")

	// 轮询等待 Bob 变为离线（最多 10 秒）
	deadline := time.Now().Add(10 * time.Second)
	offline := false
	for time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
		result, err = alice.Call(ctx, "message.query_online", map[string]any{
			"aids": []string{bobAID},
		})
		if err != nil {
			t.Logf("查询出错（重试中）: %v", err)
			continue
		}
		if isAIDOffline(result, bobAID) {
			offline = true
			t.Logf("Bob 已离线")
			break
		}
		t.Logf("Bob 仍在线，继续等待...")
	}
	if !offline {
		t.Errorf("Bob 断开 10 秒后仍显示在线, 最后结果: %#v", result)
	}
}

// TestIntegration_BatchQueryOnline 批量查询多个 AID 的在线状态
func TestIntegration_BatchQueryOnline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	charlie := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureConnected(t, alice, fmt.Sprintf("batch-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("batch-bob-%s.%s", rid, testIssuer()))
	charlieAID := ensureConnected(t, charlie, fmt.Sprintf("batch-charlie-%s.%s", rid, testIssuer()))
	_ = aliceAID

	// 一个从未连接过的 AID
	neverAID := fmt.Sprintf("batch-never-%s.%s", rid, testIssuer())

	time.Sleep(1 * time.Second)

	// 查询所有四个 AID
	result, err := alice.Call(ctx, "message.query_online", map[string]any{
		"aids": []string{bobAID, charlieAID, neverAID},
	})
	if err != nil {
		t.Skipf("批量查询在线状态失败: %v", err)
	}
	t.Logf("批量查询结果: %#v", result)

	// 验证已连接的应在线
	if isAIDOffline(result, bobAID) {
		t.Errorf("Bob 应为在线状态")
	}
	if isAIDOffline(result, charlieAID) {
		t.Errorf("Charlie 应为在线状态")
	}

	// 从未连接的应离线
	if !isAIDOffline(result, neverAID) {
		t.Errorf("从未连接的 AID 应为离线状态")
	}

	// Charlie 断开
	charlie.Close()
	t.Logf("Charlie 已断开")

	// 等待 Charlie 变为离线
	deadline := time.Now().Add(10 * time.Second)
	charlieOffline := false
	for time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
		result, err = alice.Call(ctx, "message.query_online", map[string]any{
			"aids": []string{bobAID, charlieAID},
		})
		if err != nil {
			continue
		}
		if isAIDOffline(result, charlieAID) && !isAIDOffline(result, bobAID) {
			charlieOffline = true
			break
		}
	}
	if !charlieOffline {
		t.Errorf("Charlie 断开后应为离线, 最后结果: %#v", result)
	}
	t.Logf("最终查询结果: %#v", result)
}

// TestIntegration_ReconnectOnlineStatus 断开后重连，验证重新变为在线
func TestIntegration_ReconnectOnlineStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()

	_ = ensureConnected(t, alice, fmt.Sprintf("recon-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("recon-bob-%s.%s", rid, testIssuer()))

	time.Sleep(1 * time.Second)

	// 验证 Bob 在线
	result, err := alice.Call(ctx, "message.query_online", map[string]any{
		"aids": []string{bobAID},
	})
	if err != nil {
		t.Skipf("查询在线状态失败: %v", err)
	}
	if isAIDOffline(result, bobAID) {
		t.Fatalf("Bob 连接后应为在线状态, 结果: %#v", result)
	}
	t.Logf("Bob 初次连接: 在线")

	// Bob 断开
	bob.Close()
	t.Logf("Bob 已断开")

	// 等待 Bob 变为离线
	deadline := time.Now().Add(10 * time.Second)
	offline := false
	for time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
		result, err = alice.Call(ctx, "message.query_online", map[string]any{
			"aids": []string{bobAID},
		})
		if err != nil {
			continue
		}
		if isAIDOffline(result, bobAID) {
			offline = true
			break
		}
	}
	if !offline {
		t.Errorf("Bob 断开后应为离线状态")
	}
	t.Logf("Bob 断开后: 离线")

	// Bob 用新客户端重连
	bob2 := makeClient(t)
	defer bob2.Close()
	ensureConnected(t, bob2, bobAID)
	time.Sleep(1 * time.Second)

	// 验证 Bob 重新在线
	result, err = alice.Call(ctx, "message.query_online", map[string]any{
		"aids": []string{bobAID},
	})
	if err != nil {
		t.Fatalf("重连后查询在线状态失败: %v", err)
	}
	if isAIDOffline(result, bobAID) {
		t.Errorf("Bob 重连后应为在线状态, 结果: %#v", result)
	}
	t.Logf("Bob 重连后: 在线")
}

// ---------------------------------------------------------------------------
// 辅助函数（仅本文件使用）
// ---------------------------------------------------------------------------

// isAIDOffline 判断查询结果中指定 AID 是否离线。
// 兼容多种服务端返回格式。
func isAIDOffline(result any, aid string) bool {
	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		return true
	}

	// 格式 1: {"online": {"aid": true/false}}
	if online, ok := resultMap["online"].(map[string]any); ok {
		v, exists := online[aid]
		if !exists {
			return true
		}
		isOn, _ := v.(bool)
		return !isOn
	}

	// 格式 2: {"results": {"aid": {"online": true/false}}}
	if results, ok := resultMap["results"].(map[string]any); ok {
		status, _ := results[aid].(map[string]any)
		if status == nil {
			return true
		}
		isOn, _ := status["online"].(bool)
		return !isOn
	}

	// 格式 3: {"aid": true/false}（直接映射）
	v, exists := resultMap[aid]
	if !exists {
		return true
	}
	isOn, _ := v.(bool)
	return !isOn
}
