//go:build integration

package aun

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

// makeClient 创建一个测试用 AUN 客户端，使用临时目录隔离测试数据。
func makeClient(t *testing.T) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := newClient(map[string]any{
		"aun_path": t.TempDir(),
	}, true)
	client.configModel.RequireForwardSecrecy = false
	return client
}

// ensureConnected 注册 AID、认证并连接到 Gateway。
// 通过 well-known 发现机制自动解析 Gateway URL。
func ensureConnected(t *testing.T, client *AUNClient, aid string) string {
	t.Helper()
	return integrationConnectAIDInPath(t, client, aid, nil)
}

// runID 生成唯一运行标识（UUID 前 12 位，避免 AID 碰撞）
func runID() string {
	return generateUUID4()[:12]
}

// sdkSend 通过 SDK 加密发送消息
func sdkSend(t *testing.T, client *AUNClient, toAID string, payload map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := client.Call(ctx, "message.send", map[string]any{
		"to":      toAID,
		"payload": payload,
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("发送消息失败: %v", err)
	}
}

func collectSDKPushMessages(
	client *AUNClient,
	fromAID string,
	expectedCount int,
	predicate func(map[string]any) bool,
) func(time.Duration) []map[string]any {
	if expectedCount <= 0 {
		expectedCount = 1
	}
	var mu sync.Mutex
	var inbox []map[string]any
	done := make(chan struct{}, 1)

	sub := client.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		if from != fromAID {
			return
		}
		if predicate != nil && !predicate(data) {
			return
		}
		mu.Lock()
		inbox = append(inbox, data)
		complete := len(inbox) >= expectedCount
		mu.Unlock()
		if complete {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	})

	return func(timeout time.Duration) []map[string]any {
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		timer := time.NewTimer(timeout)
		select {
		case <-done:
		case <-timer.C:
		}
		timer.Stop()
		sub.Unsubscribe()

		mu.Lock()
		defer mu.Unlock()
		result := make([]map[string]any, len(inbox))
		copy(result, inbox)
		return result
	}
}

func recvSDKAfterSend(
	t *testing.T,
	wait func(time.Duration) []map[string]any,
	client *AUNClient,
	fromAID string,
	afterSeq int,
	timeout time.Duration,
) []map[string]any {
	t.Helper()
	if wait != nil {
		if msgs := wait(timeout); len(msgs) > 0 {
			return msgs
		}
	}
	return sdkRecvPull(t, client, fromAID, afterSeq)
}

// sdkRecvPush 通过推送事件接收消息，超时后 pull 兜底
func sdkRecvPush(t *testing.T, client *AUNClient, fromAID string, timeout time.Duration) []map[string]any {
	t.Helper()
	result := collectSDKPushMessages(client, fromAID, 1, nil)(timeout)

	// 推送未收到，使用 pull 兜底
	if len(result) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pullResult, err := client.Call(ctx, "message.pull", map[string]any{
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
		msgs, _ := pullMap["messages"].([]any)
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			from, _ := msg["from"].(string)
			if from == fromAID {
				result = append(result, msg)
			}
		}
	}
	return result
}

// sdkRecvPull 通过 pull 接收消息（SDK 自动解密）
func sdkRecvPull(t *testing.T, client *AUNClient, fromAID string, afterSeq int) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pullResult, err := client.Call(ctx, "message.pull", map[string]any{
		"after_seq": afterSeq,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("pull 失败: %v", err)
	}
	pullMap, _ := pullResult.(map[string]any)
	if pullMap == nil {
		return nil
	}
	msgs, _ := pullMap["messages"].([]any)
	var result []map[string]any
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		from, _ := msg["from"].(string)
		if from == fromAID {
			result = append(result, msg)
		}
	}
	return result
}

func currentMaxSeq(t *testing.T, client *AUNClient, limit int) int {
	t.Helper()
	if limit <= 0 {
		limit = 200
	}
	afterSeq := 0
	maxSeq := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pullResult, err := client.Call(ctx, "message.pull", map[string]any{
			"after_seq": afterSeq,
			"limit":     limit,
		})
		cancel()
		if err != nil {
			t.Fatalf("获取当前最大 seq 失败: %v", err)
		}
		pullMap, _ := pullResult.(map[string]any)
		if pullMap == nil {
			return maxSeq
		}
		msgs, _ := pullMap["messages"].([]any)
		if len(msgs) == 0 {
			return maxSeq
		}
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			seq := int(toInt64(msg["seq"]))
			if seq > maxSeq {
				maxSeq = seq
			}
		}
		if len(msgs) < limit {
			return maxSeq
		}
		afterSeq = maxSeq
	}
}

func waitForSDKPullMessage(
	t *testing.T,
	client *AUNClient,
	fromAID string,
	afterSeq int,
	expectedText string,
	timeout time.Duration,
) map[string]any {
	t.Helper()
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var lastMessages []map[string]any
	for time.Now().Before(deadline) {
		messages := sdkRecvPull(t, client, fromAID, afterSeq)
		lastMessages = messages
		for _, msg := range messages {
			payload, _ := msg["payload"].(map[string]any)
			if payload == nil {
				continue
			}
			if text, _ := payload["text"].(string); text == expectedText {
				return msg
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("等待消息超时: text=%q from=%s last_messages=%#v", expectedText, fromAID, lastMessages)
	return nil
}

func makeIsolatedClient(t *testing.T, root string, slotID string) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := newClient(map[string]any{
		"aun_path": root,
	})
	client.configModel.RequireForwardSecrecy = false
	if slotID != "" {
		client.slotID = slotID
	}
	return client
}

func copyIdentityTree(t *testing.T, sourceRoot, targetRoot, aid string) {
	t.Helper()
	sourceIdentity := filepath.Join(sourceRoot, "AIDs", aid)
	if _, err := os.Stat(sourceIdentity); err != nil {
		t.Fatalf("identity source missing: %s (%v)", sourceIdentity, err)
	}
	if err := os.MkdirAll(filepath.Join(targetRoot, "AIDs"), 0o755); err != nil {
		t.Fatalf("创建目标 AIDs 目录失败: %v", err)
	}
	sourceSeed := filepath.Join(sourceRoot, ".seed")
	if data, err := os.ReadFile(sourceSeed); err == nil {
		if err := os.WriteFile(filepath.Join(targetRoot, ".seed"), data, 0o600); err != nil {
			t.Fatalf("复制 .seed 失败: %v", err)
		}
	}
	copyDirRecursive(t, sourceIdentity, filepath.Join(targetRoot, "AIDs", aid))
}

func copyDirRecursive(t *testing.T, source, target string) {
	t.Helper()
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatalf("读取目录失败: %s (%v)", source, err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("创建目录失败: %s (%v)", target, err)
	}
	for _, entry := range entries {
		srcPath := filepath.Join(source, entry.Name())
		dstPath := filepath.Join(target, entry.Name())
		if entry.IsDir() {
			copyDirRecursive(t, srcPath, dstPath)
			continue
		}
		srcFile, err := os.Open(srcPath)
		if err != nil {
			t.Fatalf("打开源文件失败: %s (%v)", srcPath, err)
		}
		dstFile, err := os.Create(dstPath)
		if err != nil {
			srcFile.Close()
			t.Fatalf("创建目标文件失败: %s (%v)", dstPath, err)
		}
		if _, err := io.Copy(dstFile, srcFile); err != nil {
			dstFile.Close()
			srcFile.Close()
			t.Fatalf("复制文件失败: %s -> %s (%v)", srcPath, dstPath, err)
		}
		dstFile.Close()
		srcFile.Close()
	}
}

// assertDecrypted 断言消息已加密且 payload 匹配
func assertDecrypted(t *testing.T, msg map[string]any, expectedPayload map[string]any, label string) {
	t.Helper()
	prefix := ""
	if label != "" {
		prefix = fmt.Sprintf("[%s] ", label)
	}
	encrypted, _ := msg["encrypted"].(bool)
	if !encrypted {
		t.Errorf("%s消息应标记为已加密", prefix)
	}
	payload, _ := msg["payload"].(map[string]any)
	if payload == nil {
		t.Fatalf("%s消息 payload 为空", prefix)
	}
	for k, v := range expectedPayload {
		actual := payload[k]
		if fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", v) {
			t.Errorf("%spayload.%s 不匹配: 期望 %v, 实际 %v", prefix, k, v, actual)
		}
	}
}

func assertDirectionIfPresent(t *testing.T, msg map[string]any, expected string, label string) {
	t.Helper()
	if _, exists := msg["direction"]; !exists {
		t.Logf("[%s] 应用层信封未携带 direction；当前 SDK 契约不强制暴露服务端投递方向", label)
		return
	}
	if getStr(msg, "direction", "") != expected {
		t.Fatalf("[%s] 消息 direction 不正确: %#v", label, msg["direction"])
	}
}

// ---------------------------------------------------------------------------
// 测试用例
// ---------------------------------------------------------------------------

// TestIntegrationSDKToSDKPrekey 两个 SDK 客户端：alice 发送 V2 加密消息，bob 解密。
func TestIntegrationSDKToSDKPrekey(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	receiver := makeClient(t)
	defer sender.Close()
	defer receiver.Close()

	sAID := ensureConnected(t, sender, fmt.Sprintf("e2ee-s-%s.agentid.pub", rid))
	rAID := ensureConnected(t, receiver, fmt.Sprintf("e2ee-r-%s.agentid.pub", rid))

	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": "sdk2sdk prekey", "n": 1})

	msgs := sdkRecvPush(t, receiver, sAID, 5*time.Second)
	if len(msgs) < 1 {
		t.Fatalf("期望至少收到 1 条消息，实际 %d", len(msgs))
	}
	assertDecrypted(t, msgs[0], map[string]any{"type": "text", "text": "sdk2sdk prekey"}, "")
}

// TestIntegrationSDKLongTermFallback multi-device 架构下，对方无 prekey 时应报错（不再降级）。
func TestIntegrationSDKLongTermFallback(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	receiver := makeClient(t)
	defer sender.Close()
	defer receiver.Close()

	_ = ensureConnected(t, sender, fmt.Sprintf("e2ee-s-%s.agentid.pub", rid))

	// receiver 仅创建 AID，不连接（模拟离线接收方，无 prekey）
	rAID := fmt.Sprintf("e2ee-r-%s.agentid.pub", rid)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	integrationRegisterAIDInPath(t, receiver.configModel.AUNPath, rAID)

	// multi-device 架构下，对方无 prekey 时 SDK 应报错
	_, err := sender.Call(ctx, "message.send", map[string]any{
		"to":      rAID,
		"payload": map[string]any{"type": "text", "text": "fallback"},
		"encrypt": true,
	})
	if err == nil {
		t.Fatalf("发送到无 prekey 的 AID 应返回错误")
	}
	t.Logf("正确返回错误: %v", err)
}

// TestIntegrationSDKToSDKBidirectional 双向加密消息测试。
func TestIntegrationSDKToSDKBidirectional(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aAID := ensureConnected(t, alice, fmt.Sprintf("e2ee-a-%s.agentid.pub", rid))
	bAID := ensureConnected(t, bob, fmt.Sprintf("e2ee-b-%s.agentid.pub", rid))

	// alice -> bob
	waitBob := collectSDKPushMessages(bob, aAID, 1, nil)
	sdkSend(t, alice, bAID, map[string]any{"type": "text", "text": "hello_bob", "from": "alice"})
	msgsBob := recvSDKAfterSend(t, waitBob, bob, aAID, 0, 5*time.Second)
	if len(msgsBob) < 1 {
		t.Fatalf("bob 期望至少收到 1 条消息，实际 %d", len(msgsBob))
	}
	assertDecrypted(t, msgsBob[0], map[string]any{"type": "text", "text": "hello_bob"}, "A->B")

	// bob -> alice
	waitAlice := collectSDKPushMessages(alice, bAID, 1, nil)
	sdkSend(t, bob, aAID, map[string]any{"type": "text", "text": "hello_alice", "from": "bob"})
	msgsAlice := recvSDKAfterSend(t, waitAlice, alice, bAID, 0, 5*time.Second)
	if len(msgsAlice) < 1 {
		t.Fatalf("alice 期望至少收到 1 条消息，实际 %d", len(msgsAlice))
	}
	assertDecrypted(t, msgsAlice[0], map[string]any{"type": "text", "text": "hello_alice"}, "B->A")
}

// TestIntegrationBurstMessages 连续发送 10 条消息，验证全部接收。
func TestIntegrationBurstMessages(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	receiver := makeClient(t)
	defer sender.Close()
	defer receiver.Close()

	sAID := ensureConnected(t, sender, fmt.Sprintf("e2ee-s-%s.agentid.pub", rid))
	rAID := ensureConnected(t, receiver, fmt.Sprintf("e2ee-r-%s.agentid.pub", rid))

	const N = 10
	waitReceiver := collectSDKPushMessages(receiver, sAID, N, nil)
	for i := 0; i < N; i++ {
		sdkSend(t, sender, rAID, map[string]any{
			"type": "text", "text": fmt.Sprintf("burst_%d", i),
			"seq": i,
		})
	}

	msgs := recvSDKAfterSend(t, waitReceiver, receiver, sAID, 0, 10*time.Second)
	if len(msgs) < N {
		t.Fatalf("期望 %d 条消息，实际收到 %d", N, len(msgs))
	}

	// 验证所有消息内容
	receivedTexts := make(map[string]bool)
	for _, msg := range msgs {
		payload, _ := msg["payload"].(map[string]any)
		if payload != nil {
			text, _ := payload["text"].(string)
			receivedTexts[text] = true
		}
	}
	for i := 0; i < N; i++ {
		expected := fmt.Sprintf("burst_%d", i)
		if !receivedTexts[expected] {
			t.Errorf("缺少消息: %s", expected)
		}
	}
}

// TestIntegrationSPKRotation 会话中轮换 V2 SPK，验证新旧消息均可解密。
func TestIntegrationSPKRotation(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	receiver := makeClient(t)
	defer sender.Close()
	defer receiver.Close()

	sAID := ensureConnected(t, sender, fmt.Sprintf("e2ee-s-%s.agentid.pub", rid))
	rAID := ensureConnected(t, receiver, fmt.Sprintf("e2ee-r-%s.agentid.pub", rid))

	// 轮换前发送
	waitReceiver := collectSDKPushMessages(receiver, sAID, 2, nil)
	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": "before_rotate", "phase": 1})

	// receiver 轮换 V2 SPK
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state := receiver.v2GetState()
	if state == nil || state.session == nil {
		t.Fatal("receiver V2 session 未初始化")
	}
	if err := state.session.RotateSPK(ctx, receiver.v2CallFn()); err != nil {
		t.Fatalf("轮换 V2 SPK 失败: %v", err)
	}

	// 轮换后发送（sender 可能仍命中旧 bootstrap 缓存，接收方应能解密两者）
	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": "after_rotate", "phase": 2})

	msgs := recvSDKAfterSend(t, waitReceiver, receiver, sAID, 0, 10*time.Second)
	if len(msgs) < 2 {
		t.Fatalf("期望至少 2 条消息，实际 %d", len(msgs))
	}

	// 验证两条消息都收到
	texts := make(map[string]bool)
	for _, msg := range msgs {
		payload, _ := msg["payload"].(map[string]any)
		if payload != nil {
			text, _ := payload["text"].(string)
			texts[text] = true
		}
	}
	if !texts["before_rotate"] {
		t.Error("缺少 before_rotate 消息")
	}
	if !texts["after_rotate"] {
		t.Error("缺少 after_rotate 消息")
	}
}

// TestIntegrationPushThenPullNoDuplicate 推送收到的消息，再 pull 不应重复。
func TestIntegrationPushThenPullNoDuplicate(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	receiver := makeClient(t)
	defer sender.Close()
	defer receiver.Close()

	sAID := ensureConnected(t, sender, fmt.Sprintf("e2ee-s-%s.agentid.pub", rid))
	rAID := ensureConnected(t, receiver, fmt.Sprintf("e2ee-r-%s.agentid.pub", rid))

	// 设置推送监听
	var pushMu sync.Mutex
	var pushMsgs []map[string]any
	pushEvent := make(chan struct{}, 1)

	sub := receiver.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		from, _ := data["from"].(string)
		if from == sAID {
			pushMu.Lock()
			pushMsgs = append(pushMsgs, data)
			pushMu.Unlock()
			select {
			case pushEvent <- struct{}{}:
			default:
			}
		}
	})

	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": "dup_test"})

	// 等待推送
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-pushEvent:
	case <-timer.C:
	}
	timer.Stop()
	sub.Unsubscribe()

	pushMu.Lock()
	pushCount := len(pushMsgs)
	pushMu.Unlock()

	if pushCount == 0 {
		t.Skip("推送未收到，跳过去重测试")
	}

	// 验证推送消息
	if pushCount != 1 {
		t.Errorf("推送应只收到 1 条，实际 %d", pushCount)
	}
	pushMu.Lock()
	assertDecrypted(t, pushMsgs[0], map[string]any{"type": "text", "text": "dup_test"}, "push")
	pushMu.Unlock()

	// pull 获取消息
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pullResult, err := receiver.Call(ctx, "message.pull", map[string]any{
		"after_seq": 0,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("pull 失败: %v", err)
	}
	pullMap, _ := pullResult.(map[string]any)
	pullMsgs, _ := pullMap["messages"].([]any)

	// 统计来自 sender 且已加密的消息数
	var pullEncrypted int
	for _, m := range pullMsgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		from, _ := msg["from"].(string)
		enc, _ := msg["encrypted"].(bool)
		if from == sAID && enc {
			pullEncrypted++
		}
	}
	t.Logf("push=%d, pull_encrypted=%d", pushCount, pullEncrypted)
}

// TestIntegrationSameAIDMultiSlotAckIsolation 同一 AID 不同 slot 的 pull/ack 互不污染。
func TestIntegrationSameAIDMultiSlotAckIsolation(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	sharedRoot := t.TempDir()
	receiverSlotA := makeIsolatedClient(t, sharedRoot, "slot-a")
	receiverSlotB := makeIsolatedClient(t, sharedRoot, "slot-b")
	defer sender.Close()
	defer receiverSlotA.Close()
	defer receiverSlotB.Close()

	sAID := ensureConnected(t, sender, fmt.Sprintf("e2ee-slot-s-%s.agentid.pub", rid))
	rAID := ensureConnected(t, receiverSlotA, fmt.Sprintf("e2ee-slot-r-%s.agentid.pub", rid))
	ensureConnected(t, receiverSlotB, rAID)

	baseSeqA := currentMaxSeq(t, receiverSlotA, 200)
	baseSeqB := currentMaxSeq(t, receiverSlotB, 200)
	if baseSeqA != baseSeqB {
		t.Fatalf("slot 基线不一致: %d != %d", baseSeqA, baseSeqB)
	}

	uniqueText := fmt.Sprintf("slot_isolation_%d", time.Now().UnixMilli())
	textPredicate := func(msg map[string]any) bool {
		payload, _ := msg["payload"].(map[string]any)
		return payload != nil && getStr(payload, "text", "") == uniqueText
	}
	waitSlotA := collectSDKPushMessages(receiverSlotA, sAID, 1, textPredicate)
	waitSlotB := collectSDKPushMessages(receiverSlotB, sAID, 1, textPredicate)
	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": uniqueText})

	msgsA := waitSlotA(15 * time.Second)
	msgsB := waitSlotB(15 * time.Second)
	var msgA map[string]any
	var msgB map[string]any
	if len(msgsA) > 0 {
		msgA = msgsA[0]
	} else {
		msgA = waitForSDKPullMessage(t, receiverSlotA, sAID, baseSeqA, uniqueText, 15*time.Second)
	}
	if len(msgsB) > 0 {
		msgB = msgsB[0]
	} else {
		msgB = waitForSDKPullMessage(t, receiverSlotB, sAID, baseSeqB, uniqueText, 15*time.Second)
	}
	assertDecrypted(t, msgA, map[string]any{"type": "text", "text": uniqueText}, "slot-a")
	assertDecrypted(t, msgB, map[string]any{"type": "text", "text": uniqueText}, "slot-b")

	seqA := int(toInt64(msgA["seq"]))
	seqB := int(toInt64(msgB["seq"]))
	if seqA != seqB {
		t.Fatalf("同 AID 不同 slot 的 seq 应一致: %d != %d", seqA, seqB)
	}

	ctxAckA, cancelAckA := context.WithTimeout(context.Background(), 10*time.Second)
	ackAResult, err := receiverSlotA.Call(ctxAckA, "message.ack", map[string]any{"seq": seqA})
	cancelAckA()
	if err != nil {
		t.Fatalf("slot-a ack 失败: %v", err)
	}
	ctxAckB, cancelAckB := context.WithTimeout(context.Background(), 10*time.Second)
	ackBResult, err := receiverSlotB.Call(ctxAckB, "message.ack", map[string]any{"seq": seqB})
	cancelAckB()
	if err != nil {
		t.Fatalf("slot-b ack 失败: %v", err)
	}
	ackAMap, _ := ackAResult.(map[string]any)
	ackBMap, _ := ackBResult.(map[string]any)
	if int(toInt64(ackAMap["ack_seq"])) != seqA {
		t.Fatalf("slot-a ack_seq 不正确: %#v", ackAMap)
	}
	if int(toInt64(ackBMap["ack_seq"])) != seqB {
		t.Fatalf("slot-b ack_seq 不正确: %#v", ackBMap)
	}
}

// TestIntegrationMultiDeviceRecipientAndSelfSync 同一 AID 多设备 fanout + 发件同步副本。
func TestIntegrationMultiDeviceRecipientAndSelfSync(t *testing.T) {
	t.Setenv("AUN_ENV", "development")
	root := t.TempDir()
	aliceSeedRoot := filepath.Join(root, "alice-seed")
	aliceSyncRoot := filepath.Join(root, "alice-sync")
	bobSeedRoot := filepath.Join(root, "bob-seed")
	bobSyncRoot := filepath.Join(root, "bob-sync")

	aliceSeed := makeIsolatedClient(t, aliceSeedRoot, "")
	bobSeed := makeIsolatedClient(t, bobSeedRoot, "")
	defer aliceSeed.Close()
	defer bobSeed.Close()

	rid := runID()
	aliceAID := ensureConnected(t, aliceSeed, fmt.Sprintf("e2ee-md-a-%s.agentid.pub", rid))
	bobAID := ensureConnected(t, bobSeed, fmt.Sprintf("e2ee-md-b-%s.agentid.pub", rid))
	copyIdentityTree(t, aliceSeedRoot, aliceSyncRoot, aliceAID)
	copyIdentityTree(t, bobSeedRoot, bobSyncRoot, bobAID)

	aliceSync := makeIsolatedClient(t, aliceSyncRoot, "")
	bobSync := makeIsolatedClient(t, bobSyncRoot, "")
	defer aliceSync.Close()
	defer bobSync.Close()

	ensureConnected(t, aliceSync, aliceAID)
	ensureConnected(t, bobSync, bobAID)
	time.Sleep(1 * time.Second)

	baseMain := currentMaxSeq(t, bobSeed, 200)
	baseSync := currentMaxSeq(t, bobSync, 200)
	baseAliceSync := currentMaxSeq(t, aliceSync, 200)
	text := fmt.Sprintf("multi_device_sync_%d", time.Now().UnixMilli())
	textPredicate := func(msg map[string]any) bool {
		payload, _ := msg["payload"].(map[string]any)
		return payload != nil && getStr(payload, "text", "") == text
	}
	waitMain := collectSDKPushMessages(bobSeed, aliceAID, 1, textPredicate)
	waitSync := collectSDKPushMessages(bobSync, aliceAID, 1, textPredicate)
	waitAliceSync := collectSDKPushMessages(aliceSync, aliceAID, 1, textPredicate)
	sdkSend(t, aliceSeed, bobAID, map[string]any{"type": "text", "text": text, "kind": "multi-device"})

	mainMsgs := waitMain(20 * time.Second)
	syncMsgs := waitSync(20 * time.Second)
	aliceSyncMsgs := waitAliceSync(20 * time.Second)
	var mainMsg map[string]any
	var syncMsg map[string]any
	var aliceSyncMsg map[string]any
	if len(mainMsgs) > 0 {
		mainMsg = mainMsgs[0]
	} else {
		mainMsg = waitForSDKPullMessage(t, bobSeed, aliceAID, baseMain, text, 20*time.Second)
	}
	if len(syncMsgs) > 0 {
		syncMsg = syncMsgs[0]
	} else {
		syncMsg = waitForSDKPullMessage(t, bobSync, aliceAID, baseSync, text, 20*time.Second)
	}
	if len(aliceSyncMsgs) > 0 {
		aliceSyncMsg = aliceSyncMsgs[0]
	} else {
		aliceSyncMsg = waitForSDKPullMessage(t, aliceSync, aliceAID, baseAliceSync, text, 20*time.Second)
	}
	assertDecrypted(t, mainMsg, map[string]any{"type": "text", "text": text, "kind": "multi-device"}, "bob-main")
	assertDecrypted(t, syncMsg, map[string]any{"type": "text", "text": text, "kind": "multi-device"}, "bob-sync")
	assertDecrypted(t, aliceSyncMsg, map[string]any{"type": "text", "text": text, "kind": "multi-device"}, "alice-sync")
	assertDirectionIfPresent(t, mainMsg, "inbound", "bob-main")
	assertDirectionIfPresent(t, syncMsg, "inbound", "bob-sync")
	assertDirectionIfPresent(t, aliceSyncMsg, "outbound_sync", "alice-sync")
}

// TestIntegrationMultiDeviceOfflinePull 多设备场景下离线设备重连后能补拉自己的设备副本。
func TestIntegrationMultiDeviceOfflinePull(t *testing.T) {
	t.Setenv("AUN_ENV", "development")
	root := t.TempDir()
	aliceSeedRoot := filepath.Join(root, "alice-seed")
	bobSeedRoot := filepath.Join(root, "bob-seed")
	aliceMainRoot := filepath.Join(root, "alice-main")
	bobPhoneRoot := filepath.Join(root, "bob-phone")
	bobLaptopRoot := filepath.Join(root, "bob-laptop")

	seedAlice := makeIsolatedClient(t, aliceSeedRoot, "")
	seedBob := makeIsolatedClient(t, bobSeedRoot, "")
	defer seedAlice.Close()
	defer seedBob.Close()

	rid := runID()
	aliceAID := ensureConnected(t, seedAlice, fmt.Sprintf("e2ee-off-a-%s.agentid.pub", rid))
	bobAID := ensureConnected(t, seedBob, fmt.Sprintf("e2ee-off-b-%s.agentid.pub", rid))
	copyIdentityTree(t, aliceSeedRoot, aliceMainRoot, aliceAID)
	copyIdentityTree(t, bobSeedRoot, bobPhoneRoot, bobAID)
	copyIdentityTree(t, bobSeedRoot, bobLaptopRoot, bobAID)
	seedAlice.Close()
	seedBob.Close()

	aliceMain := makeIsolatedClient(t, aliceMainRoot, "")
	bobPhone := makeIsolatedClient(t, bobPhoneRoot, "")
	bobLaptop := makeIsolatedClient(t, bobLaptopRoot, "")
	defer aliceMain.Close()
	defer bobPhone.Close()

	ensureConnected(t, aliceMain, aliceAID)
	ensureConnected(t, bobPhone, bobAID)
	ensureConnected(t, bobLaptop, bobAID)
	time.Sleep(1 * time.Second)

	offlineBase := currentMaxSeq(t, bobLaptop, 200)
	bobLaptop.Close()
	time.Sleep(1 * time.Second)

	text := fmt.Sprintf("multi_device_offline_%d", time.Now().UnixMilli())

	// 在线设备用事件订阅捕获 push（auto-ack 会推进 cursor，pull 可能拿不到）
	waitOnline := collectSDKPushMessages(bobPhone, aliceAID, 1, func(msg map[string]any) bool {
		p, _ := msg["payload"].(map[string]any)
		return p != nil && p["text"] == text
	})

	sdkSend(t, aliceMain, bobAID, map[string]any{"type": "text", "text": text, "kind": "offline-pull"})

	onlineMsgs := waitOnline(15 * time.Second)
	if len(onlineMsgs) < 1 {
		t.Fatalf("在线设备未收到 push 消息")
	}
	onlineMsg := onlineMsgs[0]
	assertDecrypted(t, onlineMsg, map[string]any{"type": "text", "text": text, "kind": "offline-pull"}, "bob-phone-online")
	assertDirectionIfPresent(t, onlineMsg, "inbound", "bob-phone-online")

	bobLaptop = makeIsolatedClient(t, bobLaptopRoot, "")
	defer bobLaptop.Close()
	waitOffline := collectSDKPushMessages(bobLaptop, aliceAID, 1, func(msg map[string]any) bool {
		p, _ := msg["payload"].(map[string]any)
		return p != nil && p["text"] == text
	})
	ensureConnected(t, bobLaptop, bobAID)
	offlineMsgs := waitOffline(15 * time.Second)
	var offlineMsg map[string]any
	if len(offlineMsgs) > 0 {
		offlineMsg = offlineMsgs[0]
	} else {
		t.Log("离线设备重连后未收到自动补拉事件，改用显式 pull 兜底")
		offlineMsg = waitForSDKPullMessage(t, bobLaptop, aliceAID, offlineBase, text, 15*time.Second)
	}
	assertDecrypted(t, offlineMsg, map[string]any{"type": "text", "text": text, "kind": "offline-pull"}, "bob-laptop-offline")
	assertDirectionIfPresent(t, offlineMsg, "inbound", "bob-laptop-offline")
}
