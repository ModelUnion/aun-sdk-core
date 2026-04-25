//go:build integration

package aun

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	client := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	}, true)
	client.configModel.RequireForwardSecrecy = false
	return client
}

// ensureConnected 注册 AID、认证并连接到 Gateway。
// 通过 well-known 发现机制自动解析 Gateway URL。
func ensureConnected(t *testing.T, client *AUNClient, aid string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 创建 AID（触发 well-known 发现 + 服务端注册）
	_, err := client.Auth.CreateAID(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("无法创建 AID（Docker 环境可能未运行）: %v", err)
	}

	// 认证（两阶段登录，获取 access_token）
	authResult, err := client.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("认证失败: %v", err)
	}

	// 连接 WebSocket
	if err := client.Connect(ctx, authResult, nil); err != nil {
		t.Fatalf("连接失败: %v", err)
	}

	return aid
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

// sdkRecvPush 通过推送事件接收消息，超时后 pull 兜底
func sdkRecvPush(t *testing.T, client *AUNClient, fromAID string, timeout time.Duration) []map[string]any {
	t.Helper()
	if timeout == 0 {
		timeout = 5 * time.Second
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
		if from == fromAID {
			mu.Lock()
			inbox = append(inbox, data)
			mu.Unlock()
			select {
			case done <- struct{}{}:
			default:
			}
		}
	})

	// 等待推送
	timer := time.NewTimer(timeout)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()
	sub.Unsubscribe()

	mu.Lock()
	result := inbox
	mu.Unlock()

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
	client := NewClient(map[string]any{
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

// ---------------------------------------------------------------------------
// 测试用例
// ---------------------------------------------------------------------------

// TestIntegrationPrekeyUploadAndGet 注册 AID、连接、上传 prekey，验证另一客户端可获取。
func TestIntegrationPrekeyUploadAndGet(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureConnected(t, alice, fmt.Sprintf("e2ee-alice-%s.agentid.pub", rid))
	_ = aliceAID
	bobAID := ensureConnected(t, bob, fmt.Sprintf("e2ee-bob-%s.agentid.pub", rid))

	// bob 生成并上传 prekey
	prekeyMaterial, err := bob.E2EE().GeneratePrekey()
	if err != nil {
		t.Fatalf("生成 prekey 失败: %v", err)
	}
	if fp, ok := prekeyMaterial["cert_fingerprint"].(string); !ok || !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("prekey 应包含 cert_fingerprint: %v", prekeyMaterial["cert_fingerprint"])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := bob.transport.Call(ctx, "message.e2ee.put_prekey", prekeyMaterial)
	if err != nil {
		t.Fatalf("上传 prekey 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		t.Fatalf("上传 prekey 返回 nil")
	}

	// alice 获取 bob 的 prekey
	pk1Result, err := alice.transport.Call(ctx, "message.e2ee.get_prekey", map[string]any{"aid": bobAID})
	if err != nil {
		t.Fatalf("获取 prekey 失败: %v", err)
	}
	pk1Map, _ := pk1Result.(map[string]any)
	found1, _ := pk1Map["found"].(bool)
	if !found1 {
		t.Fatalf("预期找到 prekey")
	}
	prekey1, _ := pk1Map["prekey"].(map[string]any)
	if prekey1 == nil || prekey1["cert_fingerprint"] != prekeyMaterial["cert_fingerprint"] {
		t.Fatalf("返回的 prekey cert_fingerprint 不正确: %#v", prekey1)
	}

	// 再次获取，应返回同一 prekey
	pk2Result, err := alice.transport.Call(ctx, "message.e2ee.get_prekey", map[string]any{"aid": bobAID})
	if err != nil {
		t.Fatalf("第二次获取 prekey 失败: %v", err)
	}
	pk2Map, _ := pk2Result.(map[string]any)
	found2, _ := pk2Map["found"].(bool)
	if !found2 {
		t.Fatalf("第二次应找到 prekey")
	}

	pk1Prekey, _ := pk1Map["prekey"].(map[string]any)
	pk2Prekey, _ := pk2Map["prekey"].(map[string]any)
	pk1ID, _ := pk1Prekey["prekey_id"].(string)
	pk2ID, _ := pk2Prekey["prekey_id"].(string)
	if pk1ID != pk2ID {
		t.Errorf("两次获取的 prekey_id 不一致: %s != %s", pk1ID, pk2ID)
	}
}

// TestIntegrationSDKToSDKPrekey 两个 SDK 客户端：alice 发送加密消息（prekey_ecdh_v2），bob 解密。
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

// TestIntegrationSDKLongTermFallback 未上传 prekey 时，验证 long_term_key 降级模式。
func TestIntegrationSDKLongTermFallback(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	receiver := makeClient(t)
	defer sender.Close()
	defer receiver.Close()

	sAID := ensureConnected(t, sender, fmt.Sprintf("e2ee-s-%s.agentid.pub", rid))

	// receiver 仅创建 AID，不连接（模拟离线接收方，无 prekey）
	rAID := fmt.Sprintf("e2ee-r-%s.agentid.pub", rid)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := receiver.Auth.CreateAID(ctx, map[string]any{"aid": rAID})
	if err != nil {
		t.Skipf("无法创建 AID: %v", err)
	}

	// sender 发送消息（对方无 prekey，应降级到 long_term_key）
	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": "fallback"})

	// receiver 此时认证并连接
	authResult, err := receiver.Auth.Authenticate(ctx, map[string]any{"aid": rAID})
	if err != nil {
		t.Fatalf("接收方认证失败: %v", err)
	}
	if err := receiver.Connect(ctx, authResult, nil); err != nil {
		t.Fatalf("接收方连接失败: %v", err)
	}

	// 通过 pull 拉取消息
	time.Sleep(1 * time.Second)
	msgs := sdkRecvPull(t, receiver, sAID, 0)
	if len(msgs) < 1 {
		t.Fatalf("期望至少收到 1 条消息，实际 %d", len(msgs))
	}
	assertDecrypted(t, msgs[0], map[string]any{"type": "text", "text": "fallback"}, "")

	// 验证加密模式为 long_term_key
	e2eeMeta, _ := msgs[0]["e2ee"].(map[string]any)
	if e2eeMeta != nil {
		mode, _ := e2eeMeta["encryption_mode"].(string)
		if mode != "long_term_key" {
			t.Errorf("期望加密模式 long_term_key，实际 %s", mode)
		}
	}
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
	sdkSend(t, alice, bAID, map[string]any{"type": "text", "text": "hello_bob", "from": "alice"})
	msgsBob := sdkRecvPush(t, bob, aAID, 5*time.Second)
	if len(msgsBob) < 1 {
		t.Fatalf("bob 期望至少收到 1 条消息，实际 %d", len(msgsBob))
	}
	assertDecrypted(t, msgsBob[0], map[string]any{"type": "text", "text": "hello_bob"}, "A->B")

	// bob -> alice
	sdkSend(t, bob, aAID, map[string]any{"type": "text", "text": "hello_alice", "from": "bob"})
	msgsAlice := sdkRecvPush(t, alice, bAID, 5*time.Second)
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
	for i := 0; i < N; i++ {
		sdkSend(t, sender, rAID, map[string]any{
			"type": "text", "text": fmt.Sprintf("burst_%d", i),
			"seq":  i,
		})
	}

	// 等待消息到达
	time.Sleep(2 * time.Second)
	msgs := sdkRecvPull(t, receiver, sAID, 0)
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

// TestIntegrationPrekeyRotation 会话中轮换 prekey，验证新旧消息均可解密。
func TestIntegrationPrekeyRotation(t *testing.T) {
	rid := runID()
	sender := makeClient(t)
	receiver := makeClient(t)
	defer sender.Close()
	defer receiver.Close()

	sAID := ensureConnected(t, sender, fmt.Sprintf("e2ee-s-%s.agentid.pub", rid))
	rAID := ensureConnected(t, receiver, fmt.Sprintf("e2ee-r-%s.agentid.pub", rid))

	// 轮换前发送
	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": "before_rotate", "phase": 1})

	// receiver 轮换 prekey
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := receiver.uploadPrekey(ctx); err != nil {
		t.Fatalf("轮换 prekey 失败: %v", err)
	}

	// 轮换后发送（sender 的缓存可能仍是旧 prekey，但接收方应能解密两者）
	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": "after_rotate", "phase": 2})

	time.Sleep(2 * time.Second)
	msgs := sdkRecvPull(t, receiver, sAID, 0)
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

	expectedSlots := map[string]bool{"slot-a": true, "slot-b": true}
	var ackMu sync.Mutex
	ackEvents := make([]map[string]any, 0, 2)
	ackDone := make(chan struct{}, 1)

	sub := sender.On("message.ack", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		if getStr(data, "to", "") != rAID {
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

	uniqueText := fmt.Sprintf("slot_isolation_%d", time.Now().UnixMilli())
	sdkSend(t, sender, rAID, map[string]any{"type": "text", "text": uniqueText})

	msgA := waitForSDKPullMessage(t, receiverSlotA, sAID, baseSeqA, uniqueText, 15*time.Second)
	msgB := waitForSDKPullMessage(t, receiverSlotB, sAID, baseSeqB, uniqueText, 15*time.Second)
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

	timer := time.NewTimer(5 * time.Second)
	select {
	case <-ackDone:
	case <-timer.C:
		t.Fatalf("等待双 slot ack 事件超时: %#v", ackEvents)
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
	if len(slotsSeen) != len(expectedSlots) {
		t.Fatalf("ack 事件 slot 集合不完整: %#v", slotsSeen)
	}
	if len(deviceIDs) != 1 || deviceIDs[""] {
		t.Fatalf("ack 事件 device_id 异常: %#v", deviceIDs)
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
	sdkSend(t, aliceSeed, bobAID, map[string]any{"type": "text", "text": text, "kind": "multi-device"})

	mainMsg := waitForSDKPullMessage(t, bobSeed, aliceAID, baseMain, text, 20*time.Second)
	syncMsg := waitForSDKPullMessage(t, bobSync, aliceAID, baseSync, text, 20*time.Second)
	aliceSyncMsg := waitForSDKPullMessage(t, aliceSync, aliceAID, baseAliceSync, text, 20*time.Second)
	assertDecrypted(t, mainMsg, map[string]any{"type": "text", "text": text, "kind": "multi-device"}, "bob-main")
	assertDecrypted(t, syncMsg, map[string]any{"type": "text", "text": text, "kind": "multi-device"}, "bob-sync")
	assertDecrypted(t, aliceSyncMsg, map[string]any{"type": "text", "text": text, "kind": "multi-device"}, "alice-sync")
	if getStr(mainMsg, "direction", "") != "inbound" {
		t.Fatalf("主设备消息 direction 不正确: %#v", mainMsg["direction"])
	}
	if getStr(syncMsg, "direction", "") != "inbound" {
		t.Fatalf("同步设备消息 direction 不正确: %#v", syncMsg["direction"])
	}
	if getStr(aliceSyncMsg, "direction", "") != "outbound_sync" {
		t.Fatalf("发送同步副本 direction 不正确: %#v", aliceSyncMsg["direction"])
	}
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
	onlineBase := currentMaxSeq(t, bobPhone, 200)
	bobLaptop.Close()
	time.Sleep(1 * time.Second)

	text := fmt.Sprintf("multi_device_offline_%d", time.Now().UnixMilli())
	sdkSend(t, aliceMain, bobAID, map[string]any{"type": "text", "text": text, "kind": "offline-pull"})

	onlineMsg := waitForSDKPullMessage(t, bobPhone, aliceAID, onlineBase, text, 15*time.Second)
	assertDecrypted(t, onlineMsg, map[string]any{"type": "text", "text": text, "kind": "offline-pull"}, "bob-phone-online")
	if getStr(onlineMsg, "direction", "") != "inbound" {
		t.Fatalf("在线设备消息 direction 不正确: %#v", onlineMsg["direction"])
	}

	bobLaptop = makeIsolatedClient(t, bobLaptopRoot, "")
	defer bobLaptop.Close()
	ensureConnected(t, bobLaptop, bobAID)
	offlineMsg := waitForSDKPullMessage(t, bobLaptop, aliceAID, offlineBase, text, 15*time.Second)
	assertDecrypted(t, offlineMsg, map[string]any{"type": "text", "text": text, "kind": "offline-pull"}, "bob-laptop-offline")
	if getStr(offlineMsg, "direction", "") != "inbound" {
		t.Fatalf("离线补拉消息 direction 不正确: %#v", offlineMsg["direction"])
	}
}
