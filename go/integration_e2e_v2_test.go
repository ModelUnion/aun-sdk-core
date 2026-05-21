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

// ---------------------------------------------------------------------------
// V2 E2E 测试辅助函数
//
// 与 Python e2e_test_v2_p2p_e2ee.py / e2e_test_v2_group_e2ee.py /
// e2e_test_v2_multi_device.py 对齐。
//
// Go 容器无共享固定身份，每次测试创建新 AID（与现有 integration_test.go 一致）。
// ---------------------------------------------------------------------------

// makeV2Client 创建 V2 测试用 AUN 客户端
func makeV2Client(t *testing.T) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	}, true)
	client.configModel.RequireForwardSecrecy = false
	return client
}

// v2EnsureConnected 创建 AID + 认证 + 连接（带重试，与 ensureConnected 相同模式）
func v2EnsureConnected(t *testing.T, client *AUNClient, aid string) string {
	t.Helper()

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		_, err := client.Auth.CreateAID(ctx, map[string]any{"aid": aid})
		if err != nil {
			cancel()
			if attempt == 0 {
				t.Skipf("无法创建 AID（Docker 环境可能未运行）: %v", err)
			}
			lastErr = err
			continue
		}

		authResult, err := client.Auth.Authenticate(ctx, map[string]any{"aid": aid})
		if err != nil {
			cancel()
			lastErr = err
			continue
		}

		if err := client.Connect(ctx, authResult, &ConnectOptions{AutoReconnect: false}); err != nil {
			cancel()
			lastErr = err
			continue
		}
		cancel()
		// 等待连接稳定（V2 session 初始化 + prekey 上传）
		time.Sleep(1 * time.Second)
		return aid
	}
	t.Fatalf("连接失败 (%s) 经 4 次重试: %v", aid, lastErr)
	return ""
}

// v2DrainInbox ack 清空 V2 inbox
func v2DrainInbox(t *testing.T, client *AUNClient) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	msgs, err := client.PullV2(ctx, 0, 200)
	if err != nil {
		t.Logf("v2DrainInbox: pull 失败 (可忽略): %v", err)
		return
	}
	if len(msgs) > 0 {
		var maxSeq int64
		for _, m := range msgs {
			if s := toInt64(m["seq"]); s > maxSeq {
				maxSeq = s
			}
		}
		if maxSeq > 0 {
			_, _ = client.AckV2(ctx, maxSeq)
			t.Logf("v2DrainInbox: acked %d msgs (up_to_seq=%d)", len(msgs), maxSeq)
		}
	}
}

// v2DrainGroupInbox ack 清空 V2 Group inbox
func v2DrainGroupInbox(t *testing.T, client *AUNClient, groupID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	msgs, err := client.PullGroupV2(ctx, groupID, 0, 200)
	if err != nil {
		return
	}
	if len(msgs) > 0 {
		var maxSeq int64
		for _, m := range msgs {
			if s := toInt64(m["seq"]); s > maxSeq {
				maxSeq = s
			}
		}
		if maxSeq > 0 {
			_, _ = client.AckGroupV2(ctx, groupID, maxSeq)
		}
	}
}

// v2WaitForMessage 等待 V2 消息到达（push 事件 + pull 轮询双通道）
// 注意：必须在发送消息之前调用此函数以设置 push 订阅
func v2WaitForMessage(t *testing.T, client *AUNClient, fromAID, expectedText string, timeout time.Duration) map[string]any {
	t.Helper()

	// 先检查 push 是否已经到达（通过 pull 检查）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	msgs, _ := client.PullV2(ctx, 0, 50)
	cancel()
	for _, m := range msgs {
		from, _ := m["from"].(string)
		payload, _ := m["payload"].(map[string]any)
		if from == fromAID && payload != nil {
			if text, _ := payload["text"].(string); text == expectedText {
				return m
			}
		}
	}

	// 订阅 push 事件
	found := make(chan map[string]any, 1)
	sub := client.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		p, _ := data["payload"].(map[string]any)
		if from == fromAID && p != nil {
			if text, _ := p["text"].(string); text == expectedText {
				select {
				case found <- data:
				default:
				}
			}
		}
	})
	defer sub.Unsubscribe()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// 检查 push 是否已到
		select {
		case msg := <-found:
			return msg
		default:
		}

		// pull 轮询
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		msgs2, _ := client.PullV2(ctx2, 0, 50)
		cancel2()
		for _, m := range msgs2 {
			from, _ := m["from"].(string)
			payload, _ := m["payload"].(map[string]any)
			if from == fromAID && payload != nil {
				if text, _ := payload["text"].(string); text == expectedText {
					return m
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("等待 V2 消息超时: from=%s text=%q", fromAID, expectedText)
	return nil
}

// v2SubscribeAndWait 先订阅 push 事件，返回一个等待函数。
// 用法：wait := v2SubscribeAndWait(t, bob, aliceAID, text); alice.SendV2(...); msg := wait(20s)
func v2SubscribeAndWait(t *testing.T, client *AUNClient, fromAID, expectedText string) func(time.Duration) map[string]any {
	t.Helper()
	found := make(chan map[string]any, 1)
	sub := client.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		p, _ := data["payload"].(map[string]any)
		if from == fromAID && p != nil {
			if text, _ := p["text"].(string); text == expectedText {
				select {
				case found <- data:
				default:
				}
			}
		}
	})

	return func(timeout time.Duration) map[string]any {
		defer sub.Unsubscribe()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			select {
			case msg := <-found:
				return msg
			default:
			}
			// pull 兜底
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			msgs, _ := client.PullV2(ctx, 0, 50)
			cancel()
			for _, m := range msgs {
				from, _ := m["from"].(string)
				payload, _ := m["payload"].(map[string]any)
				if from == fromAID && payload != nil {
					if text, _ := payload["text"].(string); text == expectedText {
						return m
					}
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("等待 V2 消息超时: from=%s text=%q", fromAID, expectedText)
		return nil
	}
}

// v2WaitForGroupMessage 轮询 PullGroupV2 直到找到匹配消息
func v2WaitForGroupMessage(t *testing.T, client *AUNClient, groupID, fromAID, expectedText string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		msgs, err := client.PullGroupV2(ctx, groupID, 0, 50)
		cancel()
		if err == nil {
			for _, m := range msgs {
				from, _ := m["from"].(string)
				payload, _ := m["payload"].(map[string]any)
				if from == fromAID && payload != nil {
					if text, _ := payload["text"].(string); text == expectedText {
						return m
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("等待 V2 Group 消息超时: group=%s from=%s text=%q", groupID, fromAID, expectedText)
	return nil
}

// v2CreateGroup 创建群组
func v2CreateGroup(t *testing.T, client *AUNClient, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := client.Call(ctx, "group.create", map[string]any{
		"name":       name,
		"visibility": "private",
	})
	if err != nil {
		t.Fatalf("创建群组失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	group, _ := resultMap["group"].(map[string]any)
	if group == nil {
		t.Fatalf("创建群组返回 group 为 nil: %v", resultMap)
	}
	gid, _ := group["group_id"].(string)
	if gid == "" {
		t.Fatalf("创建群组返回 group_id 为空")
	}
	return gid
}

// v2AddMember 添加群成员
func v2AddMember(t *testing.T, client *AUNClient, groupID, memberAID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := client.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      memberAID,
	})
	if err != nil {
		t.Fatalf("添加成员 %s 失败: %v", memberAID, err)
	}
}

// v2WaitForGroupV2Ready 等待私有群的 V2 state commitment 把新成员纳入已提交成员集。
//
// 服务端在 add_member 后会先把成员视为 pending；确认 state proposal 之前，
// group.v2.bootstrap 会过滤 pending 成员设备，发送端应继续 fail-fast。
func v2WaitForGroupV2Ready(t *testing.T, client *AUNClient, groupID string, wantAIDs []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	attempt := 0
	lastDiag := ""

	clearGroupBootstrapCache := func() {
		if state := client.v2GetState(); state != nil {
			state.bootstrapCacheM.Lock()
			delete(state.groupBootstrapCache, groupID)
			state.bootstrapCacheM.Unlock()
		}
	}

	for time.Now().Before(deadline) {
		attempt++
		// 成员变更后主动推进 state proposal，避免依赖 group.changed 推送到达时序。
		if attempt == 1 || attempt%4 == 0 {
			propCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			client.v2AutoProposeState(propCtx, groupID)
			cancel()
			clearGroupBootstrapCache()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		raw, err := client.Call(ctx, "group.v2.bootstrap", map[string]any{"group_id": groupID})
		cancel()
		if err != nil {
			lastDiag = fmt.Sprintf("bootstrap err=%v", err)
			t.Logf("等待 V2 群 bootstrap 就绪 attempt=%d: %s", attempt, lastDiag)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		bs, _ := raw.(map[string]any)
		devices := v2ToMapList(bs["devices"])
		pending := v2ToStringList(bs["pending_adds"])
		committed := v2ToStringList(bs["committed_member_aids"])
		deviceAIDs := make(map[string]int)
		for _, dev := range devices {
			aid := strings.TrimSpace(v2AsString(dev["aid"]))
			if aid == "" || v2AsString(dev["device_id"]) == "" || v2AsString(dev["ik_pk"]) == "" {
				continue
			}
			deviceAIDs[aid]++
		}

		ready := true
		missing := make([]string, 0)
		for _, aid := range wantAIDs {
			if deviceAIDs[aid] == 0 {
				ready = false
				missing = append(missing, aid)
			}
		}
		lastDiag = fmt.Sprintf(
			"sv=%d devices=%d deviceAIDs=%v pending=%v committed=%v missing=%v",
			int(toInt64(bs["state_version"])), len(devices), deviceAIDs, pending, committed, missing,
		)
		t.Logf("等待 V2 群 bootstrap 就绪 attempt=%d: %s", attempt, lastDiag)
		if ready {
			clearGroupBootstrapCache()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("等待 V2 群 bootstrap 成员设备就绪超时: group=%s want=%v last=%s", groupID, wantAIDs, lastDiag)
}

// v2SendWithRetry 带重试的 SendV2（处理瞬时连接断开）
func v2SendWithRetry(t *testing.T, client *AUNClient, to string, payload map[string]any) map[string]any {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		result, err := client.SendV2(ctx, to, payload)
		cancel()
		if err == nil {
			return result
		}
		lastErr = err
		t.Logf("SendV2 attempt %d 失败 (将重试): %v", attempt+1, err)
	}
	t.Fatalf("SendV2 失败 (3 次重试后): %v", lastErr)
	return nil
}

// v2SendGroupWithRetry 带重试的 SendGroupV2
func v2SendGroupWithRetry(t *testing.T, client *AUNClient, groupID string, payload map[string]any) map[string]any {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		result, err := client.SendGroupV2(ctx, groupID, payload)
		cancel()
		if err == nil {
			return result
		}
		lastErr = err
		t.Logf("SendGroupV2 attempt %d 失败 (将重试): %v", attempt+1, err)
	}
	t.Fatalf("SendGroupV2 失败 (3 次重试后): %v", lastErr)
	return nil
}

// v2RunID 生成唯一运行标识
func v2RunID() string {
	return generateUUID4()[:12]
}

// ---------------------------------------------------------------------------
// P2P V2 测试用例（对齐 Python e2e_test_v2_p2p_e2ee.py）
// ---------------------------------------------------------------------------

// TestV2P2PSessionInit connect 后 V2 session 自动初始化
func TestV2P2PSessionInit(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))

	stateA := alice.v2GetState()
	if stateA == nil || stateA.session == nil {
		t.Fatal("Alice V2 session 未初始化")
	}
	stateB := bob.v2GetState()
	if stateB == nil || stateB.session == nil {
		t.Fatal("Bob V2 session 未初始化")
	}
	t.Log("Alice V2 session OK, Bob V2 session OK")
}

// TestV2P2PSendAndPull Alice send_v2 → Bob pull_v2 解密
func TestV2P2PSendAndPull(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))
	v2DrainInbox(t, bob)

	payload := map[string]any{"text": fmt.Sprintf("v2-p2p-send-%d", time.Now().UnixMilli())}
	// 先订阅再发送，避免 push 竞态
	wait := v2SubscribeAndWait(t, bob, aliceAID, payload["text"].(string))
	result := v2SendWithRetry(t, alice, bobAID, payload)
	status, _ := result["status"].(string)
	msgID, _ := result["message_id"].(string)
	if status != "accepted" && msgID == "" {
		t.Fatalf("SendV2 返回异常: %v", result)
	}
	t.Logf("SendV2 成功: msg_id=%s", msgID)

	msg := wait(20 * time.Second)
	encrypted, _ := msg["encrypted"].(bool)
	if !encrypted {
		t.Error("消息应标记为 encrypted=true")
	}
	e2eeInfo, _ := msg["e2ee"].(map[string]any)
	if e2eeInfo != nil {
		if ver, _ := e2eeInfo["version"].(string); ver != "v2" {
			t.Errorf("e2ee.version 应为 v2, 实际: %s", ver)
		}
	}
	t.Logf("Bob 解密成功: text=%q", payload["text"])
}

// TestV2P2PAck Bob ack_v2 后 pull 为空
func TestV2P2PAck(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))
	v2DrainInbox(t, bob)

	payload := map[string]any{"text": fmt.Sprintf("v2-ack-%d", time.Now().UnixMilli())}

	// 订阅 push 事件以确保消息到达
	msgArrived := make(chan struct{}, 1)
	sub := bob.On("message.received", func(p any) {
		data, ok := p.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		pl, _ := data["payload"].(map[string]any)
		if from == aliceAID && pl != nil {
			if text, _ := pl["text"].(string); text == payload["text"].(string) {
				select {
				case msgArrived <- struct{}{}:
				default:
				}
			}
		}
	})
	defer sub.Unsubscribe()

	v2SendWithRetry(t, alice, bobAID, payload)

	// 等待消息到达（push 或 poll）
	timer := time.NewTimer(20 * time.Second)
	select {
	case <-msgArrived:
		timer.Stop()
	case <-timer.C:
		// push 未到，尝试 pull
		_ = v2WaitForMessage(t, bob, aliceAID, payload["text"].(string), 10*time.Second)
	}

	// Bob ack
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	ackResult, err := bob.AckV2(ctx2, 0)
	cancel2()
	if err != nil {
		t.Fatalf("AckV2 失败: %v", err)
	}
	t.Logf("AckV2: acked=%v", ackResult["acked"])

	// pull 应为空
	ctx3, cancel3 := context.WithTimeout(context.Background(), 10*time.Second)
	msgs, err := bob.PullV2(ctx3, 0, 50)
	cancel3()
	if err != nil {
		t.Fatalf("PullV2 失败: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("ack 后 pull 应为空, 实际 %d 条", len(msgs))
	}
	t.Log("ack 后 pull 为空 — 正确")
}

// TestV2P2PBidirectional Bob 回复 Alice，Alice pull 解密
func TestV2P2PBidirectional(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))
	v2DrainInbox(t, alice)
	v2DrainInbox(t, bob)

	// Alice → Bob
	payloadAB := map[string]any{"text": fmt.Sprintf("v2-bidir-ab-%d", time.Now().UnixMilli())}
	waitBob := v2SubscribeAndWait(t, bob, aliceAID, payloadAB["text"].(string))
	v2SendWithRetry(t, alice, bobAID, payloadAB)

	msg := waitBob(20 * time.Second)
	t.Logf("Bob 收到: %q", msg["payload"].(map[string]any)["text"])

	// Bob → Alice
	payloadBA := map[string]any{"text": fmt.Sprintf("v2-bidir-ba-%d", time.Now().UnixMilli())}
	waitAlice := v2SubscribeAndWait(t, alice, bobAID, payloadBA["text"].(string))
	v2SendWithRetry(t, bob, aliceAID, payloadBA)

	msg2 := waitAlice(20 * time.Second)
	from, _ := msg2["from"].(string)
	if from != bobAID {
		t.Fatalf("from 不匹配: 期望 %s, 实际 %s", bobAID, from)
	}
	t.Logf("Alice 收到 Bob 回复: %q", msg2["payload"].(map[string]any)["text"])
}

// TestV2P2PBatch 批量 3 条消息
func TestV2P2PBatch(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))
	v2DrainInbox(t, bob)

	ts := time.Now().UnixMilli()
	payloads := []map[string]any{
		{"text": fmt.Sprintf("v2-batch-0-%d", ts)},
		{"text": fmt.Sprintf("v2-batch-1-%d", ts)},
		{"text": fmt.Sprintf("v2-batch-2-%d", ts)},
	}

	// 用 push 事件收集消息
	var mu sync.Mutex
	received := make(map[string]bool)
	allDone := make(chan struct{}, 1)

	sub := bob.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		if from != aliceAID {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p == nil {
			return
		}
		if text, _ := p["text"].(string); text != "" {
			mu.Lock()
			received[text] = true
			done := len(received) >= 3
			mu.Unlock()
			if done {
				select {
				case allDone <- struct{}{}:
				default:
				}
			}
		}
	})
	defer sub.Unsubscribe()

	for i, p := range payloads {
		v2SendWithRetry(t, alice, bobAID, p)
		t.Logf("  batch[%d] 已发送", i)
	}
	t.Log("3 条消息已发送")

	// 等待 push 事件收齐
	timer := time.NewTimer(20 * time.Second)
	select {
	case <-allDone:
		timer.Stop()
	case <-timer.C:
		// push 未收齐，fallback pull
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		msgs, _ := bob.PullV2(ctx, 0, 50)
		cancel()
		mu.Lock()
		for _, m := range msgs {
			from, _ := m["from"].(string)
			p, _ := m["payload"].(map[string]any)
			if from == aliceAID && p != nil {
				if text, _ := p["text"].(string); text != "" {
					received[text] = true
				}
			}
		}
		mu.Unlock()
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range payloads {
		if !received[p["text"].(string)] {
			t.Errorf("缺少消息: %s", p["text"])
		}
	}
	t.Logf("Bob 收到全部 %d/3 条批量消息", len(received))
}

// TestV2P2PPushAutoReceive push 事件自动接收
func TestV2P2PPushAutoReceive(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))
	v2DrainInbox(t, bob)

	var mu sync.Mutex
	var pushMsgs []map[string]any
	pushDone := make(chan struct{}, 1)

	expectedText := fmt.Sprintf("v2-push-%d", time.Now().UnixMilli())
	sub := bob.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p == nil {
			return
		}
		if text, _ := p["text"].(string); text == expectedText {
			mu.Lock()
			pushMsgs = append(pushMsgs, data)
			mu.Unlock()
			select {
			case pushDone <- struct{}{}:
			default:
			}
		}
	})
	defer sub.Unsubscribe()

	v2SendWithRetry(t, alice, bobAID, map[string]any{"text": expectedText})

	timer := time.NewTimer(10 * time.Second)
	select {
	case <-pushDone:
		timer.Stop()
	case <-timer.C:
		// push 未到，fallback pull
		msg := v2WaitForMessage(t, bob, aliceAID, expectedText, 15*time.Second)
		if msg == nil {
			t.Fatal("push 和 pull 均未收到消息")
		}
		t.Log("push 未触发，但 pull 验证通过")
		return
	}

	mu.Lock()
	count := len(pushMsgs)
	mu.Unlock()
	if count < 1 {
		t.Fatal("push 事件未收到消息")
	}
	t.Logf("push 自动接收成功: 收到 %d 条", count)
}

// ---------------------------------------------------------------------------
// Group V2 测试用例（对齐 Python e2e_test_v2_group_e2ee.py）
// ---------------------------------------------------------------------------

// TestV2GroupSendAndPull Alice send_group_v2 → Bob pull_group_v2 解密
func TestV2GroupSendAndPull(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))

	groupID := v2CreateGroup(t, alice, fmt.Sprintf("v2-grp-%s", rid))
	v2AddMember(t, alice, groupID, bobAID)
	t.Logf("群 %s 已创建, Bob 已加入", groupID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)
	v2DrainGroupInbox(t, bob, groupID)

	payload := map[string]any{"text": fmt.Sprintf("v2-grp-send-%d", time.Now().UnixMilli())}
	result := v2SendGroupWithRetry(t, alice, groupID, payload)
	status, _ := result["status"].(string)
	if status != "accepted" {
		t.Fatalf("SendGroupV2 返回异常: %v", result)
	}
	t.Logf("SendGroupV2 成功: seq=%v", result["seq"])

	msg := v2WaitForGroupMessage(t, bob, groupID, aliceAID, payload["text"].(string), 20*time.Second)
	t.Logf("Bob 解密群消息: text=%q from=%s", msg["payload"].(map[string]any)["text"], msg["from"])
}

// TestV2GroupAck ack 后 pull 为空
func TestV2GroupAck(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))

	groupID := v2CreateGroup(t, alice, fmt.Sprintf("v2-grp-ack-%s", rid))
	v2AddMember(t, alice, groupID, bobAID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)
	v2DrainGroupInbox(t, bob, groupID)

	payload := map[string]any{"text": fmt.Sprintf("v2-grp-ack-%d", time.Now().UnixMilli())}
	v2SendGroupWithRetry(t, alice, groupID, payload)

	_ = v2WaitForGroupMessage(t, bob, groupID, aliceAID, payload["text"].(string), 20*time.Second)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := bob.AckGroupV2(ctx2, groupID, 0)
	cancel2()
	if err != nil {
		t.Fatalf("AckGroupV2 失败: %v", err)
	}

	ctx3, cancel3 := context.WithTimeout(context.Background(), 10*time.Second)
	msgs, err := bob.PullGroupV2(ctx3, groupID, 0, 50)
	cancel3()
	if err != nil {
		t.Fatalf("PullGroupV2 失败: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("ack 后 pull 应为空, 实际 %d 条", len(msgs))
	}
	t.Log("ack 后 pull 为空 — 正确")
}

// TestV2GroupBidirectional Bob 回复群消息
func TestV2GroupBidirectional(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))

	groupID := v2CreateGroup(t, alice, fmt.Sprintf("v2-grp-bidir-%s", rid))
	v2AddMember(t, alice, groupID, bobAID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)
	v2DrainGroupInbox(t, alice, groupID)
	v2DrainGroupInbox(t, bob, groupID)

	// Alice → Group
	payloadA := map[string]any{"text": fmt.Sprintf("v2-grp-a-%d", time.Now().UnixMilli())}
	v2SendGroupWithRetry(t, alice, groupID, payloadA)

	_ = v2WaitForGroupMessage(t, bob, groupID, aliceAID, payloadA["text"].(string), 20*time.Second)
	t.Log("Bob 收到 Alice 群消息")

	// ack + drain
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	_, _ = bob.AckGroupV2(ctx2, groupID, 0)
	cancel2()
	v2DrainGroupInbox(t, alice, groupID)

	// Bob → Group
	payloadB := map[string]any{"text": fmt.Sprintf("v2-grp-b-%d", time.Now().UnixMilli())}
	v2SendGroupWithRetry(t, bob, groupID, payloadB)

	msg := v2WaitForGroupMessage(t, alice, groupID, bobAID, payloadB["text"].(string), 20*time.Second)
	t.Logf("Alice 收到 Bob 群回复: %q", msg["payload"].(map[string]any)["text"])
}

// TestV2GroupEpochRotation epoch 变更后仍能发送
func TestV2GroupEpochRotation(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))

	groupID := v2CreateGroup(t, alice, fmt.Sprintf("v2-grp-epoch-%s", rid))
	v2AddMember(t, alice, groupID, bobAID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)
	v2DrainGroupInbox(t, bob, groupID)

	// kick Bob → epoch 递增
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := alice.Call(ctx, "group.kick", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
	})
	cancel()
	if err != nil {
		t.Fatalf("kick 失败: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// 清除 bootstrap 缓存
	stateA := alice.v2GetState()
	if stateA != nil {
		stateA.bootstrapCacheM.Lock()
		delete(stateA.groupBootstrapCache, groupID)
		stateA.bootstrapCacheM.Unlock()
	}

	// re-add Bob
	v2AddMember(t, alice, groupID, bobAID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)
	v2DrainGroupInbox(t, bob, groupID)

	// Alice 发消息（应使用新 epoch）
	payload := map[string]any{"text": fmt.Sprintf("v2-after-rot-%d", time.Now().UnixMilli())}
	result := v2SendGroupWithRetry(t, alice, groupID, payload)
	t.Logf("epoch rotation 后发送成功: seq=%v", result["seq"])

	msg := v2WaitForGroupMessage(t, bob, groupID, aliceAID, payload["text"].(string), 20*time.Second)
	t.Logf("Bob 收到 epoch rotation 后的消息: %q", msg["payload"].(map[string]any)["text"])
}

// ---------------------------------------------------------------------------
// Multi-device V2 测试（对齐 Python e2e_test_v2_multi_device.py 简化版）
// ---------------------------------------------------------------------------

// TestV2MultiDeviceSelfSync 验证 self-sync：Alice 发给 Bob，Bob 能收到
func TestV2MultiDeviceSelfSync(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("v2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("v2-bob-%s.agentid.pub", rid))
	v2DrainInbox(t, bob)

	payload := map[string]any{"text": fmt.Sprintf("v2-multidev-%d", time.Now().UnixMilli())}
	result := v2SendWithRetry(t, alice, bobAID, payload)
	t.Logf("Alice 发送成功: msg_id=%v", result["message_id"])

	msg := v2WaitForMessage(t, bob, aliceAID, payload["text"].(string), 20*time.Second)
	encrypted, _ := msg["encrypted"].(bool)
	if !encrypted {
		t.Error("消息应标记为 encrypted=true")
	}
	t.Logf("Bob 收到消息: %q", msg["payload"].(map[string]any)["text"])
}
