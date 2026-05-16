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

	// 持久化消息需要 queue 投递模式（connect 级别配置）
	alice.auth.SetDeliveryMode(map[string]any{"mode": "queue"})

	aliceAID := ensureConnected(t, alice, fmt.Sprintf("ack-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("ack-bob-%s.%s", rid, testIssuer()))

	// 通过事件订阅接收消息（SDK connect 后会自动触发一次 P2P pull，推送+pull 都走 message.received）
	var mu sync.Mutex
	var received []map[string]any
	done := make(chan struct{}, 1)
	sub := bob.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		if from != aliceAID {
			return
		}
		mu.Lock()
		received = append(received, data)
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})
	defer sub.Unsubscribe()

	// Alice 发送持久化明文消息给 Bob
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": "ack_basic_test"},
		"encrypt": false,
	})
	if err != nil {
		t.Skipf("发送消息失败（Docker 环境可能未运行）: %v", err)
	}

	// 等待 Bob 通过推送或自动 pull 收到消息
	timer := time.NewTimer(10 * time.Second)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()

	mu.Lock()
	msgs := append([]map[string]any(nil), received...)
	mu.Unlock()
	if len(msgs) == 0 {
		t.Fatalf("Bob 未收到来自 Alice 的消息")
	}
	msgSeq := int(toInt64(msgs[0]["seq"]))
	t.Logf("收到消息 seq=%d from=%s", msgSeq, aliceAID)

	// Bob 确认消息（SDK 自动 pull 后已 ack 一次，这里再次 ack 验证幂等返回值）
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

	// 持久化消息需要 queue 投递模式（connect 级别配置）
	alice.auth.SetDeliveryMode(map[string]any{"mode": "queue"})

	aliceAID := ensureConnected(t, alice, fmt.Sprintf("ackev-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("ackev-bob-%s.%s", rid, testIssuer()))

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

	// Bob 订阅消息（SDK connect 后自动 P2P pull 即触发 message.received）
	var bmu sync.Mutex
	var bobInbox []map[string]any
	bobDone := make(chan struct{}, 1)
	bobSub := bob.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		if from != aliceAID {
			return
		}
		bmu.Lock()
		bobInbox = append(bobInbox, data)
		bmu.Unlock()
		select {
		case bobDone <- struct{}{}:
		default:
		}
	})
	defer bobSub.Unsubscribe()

	// Alice 发送消息给 Bob
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": "ack_event_test"},
		"encrypt": false,
	})
	if err != nil {
		t.Skipf("发送消息失败: %v", err)
	}

	// 等待 Bob 收到消息（SDK 自动 pull 已 ack 一次，但事件应触发）
	timer := time.NewTimer(10 * time.Second)
	select {
	case <-bobDone:
	case <-timer.C:
	}
	timer.Stop()

	bmu.Lock()
	bobMsgs := append([]map[string]any(nil), bobInbox...)
	bmu.Unlock()
	if len(bobMsgs) == 0 {
		t.Fatalf("Bob 未收到消息")
	}
	msgSeq := int(toInt64(bobMsgs[0]["seq"]))

	// Bob 主动再 ack 一次，确保 alice 一定能收到 ack 事件
	if _, err := bob.Call(ctx, "message.ack", map[string]any{"seq": msgSeq}); err != nil {
		t.Fatalf("Bob ack 失败: %v", err)
	}

	// 等待 Alice 收到 ack 事件
	timer2 := time.NewTimer(10 * time.Second)
	select {
	case <-ackDone:
	case <-timer2.C:
		t.Fatalf("等待 ack 事件超时")
	}
	timer2.Stop()

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

	// 持久化消息需要 queue 投递模式（connect 级别配置）
	alice.auth.SetDeliveryMode(map[string]any{"mode": "queue"})

	aliceAID := ensureConnected(t, alice, fmt.Sprintf("ackseq-alice-%s.%s", rid, testIssuer()))
	bobAID := ensureConnected(t, bob, fmt.Sprintf("ackseq-bob-%s.%s", rid, testIssuer()))

	// Bob 订阅消息事件，统一通过事件路径接收（push + 自动 pull 都通过 message.received 投递）
	const expected = 3
	var mu sync.Mutex
	var inbox []map[string]any
	done := make(chan struct{}, 1)
	sub := bob.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		if from != aliceAID {
			return
		}
		mu.Lock()
		inbox = append(inbox, data)
		complete := len(inbox) >= expected
		mu.Unlock()
		if complete {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	})
	defer sub.Unsubscribe()

	// Alice 连续发送 3 条消息
	for i := 1; i <= expected; i++ {
		_, err := alice.Call(ctx, "message.send", map[string]any{
			"to":      bobAID,
			"payload": map[string]any{"type": "text", "text": fmt.Sprintf("seq_test_%d", i)},
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

	timer := time.NewTimer(15 * time.Second)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()

	mu.Lock()
	msgs := append([]map[string]any(nil), inbox...)
	mu.Unlock()
	if len(msgs) < expected {
		t.Fatalf("期望至少 %d 条消息，实际 %d 条", expected, len(msgs))
	}

	// 收集 seq
	seqs := make([]int, 0, expected)
	for _, msg := range msgs[:expected] {
		seqs = append(seqs, int(toInt64(msg["seq"])))
	}
	t.Logf("收到消息 seqs: %v", seqs)

	// 逐条 ack，验证 ack_seq 递增（SDK 内部已经 ack 过，再次 ack 是幂等操作）
	prevAckSeq := 0
	for i, seq := range seqs {
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
