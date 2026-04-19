// +build integration

package aun

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// TestUndecryptableEventOnly 验证解密失败时只发布 message.undecryptable 事件，不泄漏密文 payload
func TestUndecryptableEventOnly(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(map[string]any{
		"aun_path": tmpDir,
	})
	defer client.Close()

	// 构造假身份
	identity := testBuildIdentity("test.agentid.pub", "fake-priv", "fake-pub", "fake-cert")
	client.identity = identity
	client.aid = "test.agentid.pub"

	// 订阅事件
	var (
		mu                    sync.Mutex
		receivedEvents        []string
		undecryptableEvents   []map[string]any
		normalReceivedEvents  []map[string]any
	)

	client.On("message.undecryptable", func(data any) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, "undecryptable")
		if dataMap, ok := data.(map[string]any); ok {
			undecryptableEvents = append(undecryptableEvents, dataMap)
		}
	})

	client.On("message.received", func(data any) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, "received")
		if dataMap, ok := data.(map[string]any); ok {
			normalReceivedEvents = append(normalReceivedEvents, dataMap)
		}
	})

	// 构造无法解密的消息（加密 payload 但没有对应密钥）
	fakeEncryptedMsg := map[string]any{
		"message_id": "test-msg-1",
		"from":       "sender.agentid.pub",
		"to":         "test.agentid.pub",
		"seq":        1,
		"timestamp":  time.Now().UnixMilli(),
		"encrypted":  true,
		"payload": map[string]any{
			"type":       "e2ee.single",
			"ciphertext": "fake-ciphertext-data",
			"nonce":      "fake-nonce",
		},
	}

	// 直接调用 processAndPublishMessage（模拟推送路径）
	client.processAndPublishMessage(fakeEncryptedMsg)

	// 等待事件处理
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// 验证：只应该收到 undecryptable 事件
	if len(receivedEvents) != 1 {
		t.Errorf("期望收到 1 个事件，实际 %d 个: %v", len(receivedEvents), receivedEvents)
	}
	if len(receivedEvents) > 0 && receivedEvents[0] != "undecryptable" {
		t.Errorf("期望收到 undecryptable 事件，实际 %s", receivedEvents[0])
	}

	// 验证：不应该收到 message.received 事件
	if len(normalReceivedEvents) > 0 {
		t.Errorf("不应该收到 message.received 事件，实际收到 %d 个", len(normalReceivedEvents))
	}

	// 验证：undecryptable 事件不包含原始 payload
	if len(undecryptableEvents) == 0 {
		t.Fatal("未收到 undecryptable 事件")
	}
	event := undecryptableEvents[0]
	if _, hasPayload := event["payload"]; hasPayload {
		t.Error("undecryptable 事件不应包含 payload 字段")
	}

	// 验证：undecryptable 事件包含安全的 header 信息
	if event["message_id"] != "test-msg-1" {
		t.Errorf("message_id 不匹配: %v", event["message_id"])
	}
	if event["from"] != "sender.agentid.pub" {
		t.Errorf("from 不匹配: %v", event["from"])
	}
	if event["seq"] != 1 && event["seq"] != int64(1) {
		t.Errorf("seq 不匹配: %v", event["seq"])
	}
}

// TestPushFillGapNoDuplicateDelivery 验证 pushedSeqs 去重：push 路径 + fill-gap 路径不重复投递同一 seq
func TestPushFillGapNoDuplicateDelivery(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(map[string]any{
		"aun_path": tmpDir,
	})
	defer client.Close()

	// 构造假身份
	identity := testBuildIdentity("test.agentid.pub", "fake-priv", "fake-pub", "fake-cert")
	client.identity = identity
	client.aid = "test.agentid.pub"

	// 订阅事件
	var (
		mu             sync.Mutex
		receivedSeqs   []int
		receivedEvents []map[string]any
	)

	client.On("message.received", func(data any) {
		mu.Lock()
		defer mu.Unlock()
		if dataMap, ok := data.(map[string]any); ok {
			seq := int(toInt64(dataMap["seq"]))
			receivedSeqs = append(receivedSeqs, seq)
			receivedEvents = append(receivedEvents, dataMap)
		}
	})

	// 模拟场景：
	// 1. 收到 seq=1 的推送（明文消息，可以直接投递）
	// 2. 收到 seq=3 的推送（触发 gap 检测）
	// 3. fill-gap 返回 seq=1,2,3（其中 seq=1 已经通过推送路径投递）

	ns := "p2p:test.agentid.pub"

	// 步骤 1: 推送 seq=1
	msg1 := map[string]any{
		"message_id": "msg-1",
		"from":       "sender.agentid.pub",
		"to":         "test.agentid.pub",
		"seq":        1,
		"timestamp":  time.Now().UnixMilli(),
		"encrypted":  false,
		"payload":    "message 1",
	}

	// 预标记 seq=1（模拟 processAndPublishMessage 的行为）
	client.markPushedSeq(ns, 1)
	client.seqTracker.OnMessageSeq(ns, 1)
	client.events.Publish("message.received", msg1)

	time.Sleep(100 * time.Millisecond)

	// 步骤 2: 推送 seq=3（跳过 seq=2，触发 gap）
	msg3 := map[string]any{
		"message_id": "msg-3",
		"from":       "sender.agentid.pub",
		"to":         "test.agentid.pub",
		"seq":        3,
		"timestamp":  time.Now().UnixMilli(),
		"encrypted":  false,
		"payload":    "message 3",
	}

	client.markPushedSeq(ns, 3)
	needPull := client.seqTracker.OnMessageSeq(ns, 3)
	if !needPull {
		t.Error("seq=3 应该触发 gap 检测")
	}
	client.events.Publish("message.received", msg3)

	time.Sleep(100 * time.Millisecond)

	// 步骤 3: 模拟 fill-gap 返回 seq=1,2,3
	gapMessages := []any{
		map[string]any{
			"message_id": "msg-1",
			"from":       "sender.agentid.pub",
			"seq":        1,
			"payload":    "message 1",
		},
		map[string]any{
			"message_id": "msg-2",
			"from":       "sender.agentid.pub",
			"seq":        2,
			"payload":    "message 2",
		},
		map[string]any{
			"message_id": "msg-3",
			"from":       "sender.agentid.pub",
			"seq":        3,
			"payload":    "message 3",
		},
	}

	// 调用 publishGapFillMessages（应该跳过 seq=1 和 seq=3）
	client.publishGapFillMessages(ns, gapMessages)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// 验证：应该收到 3 条消息（seq=1 推送，seq=2 补洞，seq=3 推送）
	// 但不应该有重复的 seq
	if len(receivedSeqs) != 3 {
		t.Errorf("期望收到 3 条消息，实际 %d 条: %v", len(receivedSeqs), receivedSeqs)
	}

	// 统计每个 seq 出现的次数
	seqCount := make(map[int]int)
	for _, seq := range receivedSeqs {
		seqCount[seq]++
	}

	// 验证：每个 seq 只应该出现一次
	for seq, count := range seqCount {
		if count != 1 {
			t.Errorf("seq=%d 出现了 %d 次，期望 1 次", seq, count)
		}
	}

	// 验证：应该包含 seq=1,2,3
	expectedSeqs := map[int]bool{1: true, 2: true, 3: true}
	for seq := range expectedSeqs {
		if seqCount[seq] != 1 {
			t.Errorf("缺少 seq=%d", seq)
		}
	}
}

// TestGroupUndecryptableEventOnly 验证群消息解密失败时只发布 group.message_undecryptable 事件
func TestGroupUndecryptableEventOnly(t *testing.T) {
	tmpDir := t.TempDir()
	client := NewClient(map[string]any{
		"aun_path": tmpDir,
	})
	defer client.Close()

	// 构造假身份
	identity := testBuildIdentity("test.agentid.pub", "fake-priv", "fake-pub", "fake-cert")
	client.identity = identity
	client.aid = "test.agentid.pub"

	// 订阅事件
	var (
		mu                    sync.Mutex
		receivedEvents        []string
		undecryptableEvents   []map[string]any
		normalCreatedEvents   []map[string]any
	)

	client.On("group.message_undecryptable", func(data any) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, "undecryptable")
		if dataMap, ok := data.(map[string]any); ok {
			undecryptableEvents = append(undecryptableEvents, dataMap)
		}
	})

	client.On("group.message_created", func(data any) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, "created")
		if dataMap, ok := data.(map[string]any); ok {
			normalCreatedEvents = append(normalCreatedEvents, dataMap)
		}
	})

	// 构造无法解密的群消息
	fakeEncryptedGroupMsg := map[string]any{
		"message_id": "test-group-msg-1",
		"group_id":   "test-group-id",
		"from":       "sender.agentid.pub",
		"seq":        1,
		"timestamp":  time.Now().UnixMilli(),
		"encrypted":  true,
		"payload": map[string]any{
			"type":       "e2ee.group",
			"ciphertext": "fake-group-ciphertext",
			"nonce":      "fake-nonce",
			"epoch":      1,
		},
	}

	// 直接调用 processAndPublishGroupMessage
	client.processAndPublishGroupMessage(fakeEncryptedGroupMsg)

	// 等待事件处理
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// 验证：只应该收到 undecryptable 事件
	if len(receivedEvents) != 1 {
		t.Errorf("期望收到 1 个事件，实际 %d 个: %v", len(receivedEvents), receivedEvents)
	}
	if len(receivedEvents) > 0 && receivedEvents[0] != "undecryptable" {
		t.Errorf("期望收到 undecryptable 事件，实际 %s", receivedEvents[0])
	}

	// 验证：不应该收到 group.message_created 事件
	if len(normalCreatedEvents) > 0 {
		t.Errorf("不应该收到 group.message_created 事件，实际收到 %d 个", len(normalCreatedEvents))
	}

	// 验证：undecryptable 事件不包含原始 payload
	if len(undecryptableEvents) == 0 {
		t.Fatal("未收到 undecryptable 事件")
	}
	event := undecryptableEvents[0]
	if _, hasPayload := event["payload"]; hasPayload {
		t.Error("undecryptable 事件不应包含 payload 字段")
	}

	// 验证：undecryptable 事件包含安全的 header 信息
	if event["message_id"] != "test-group-msg-1" {
		t.Errorf("message_id 不匹配: %v", event["message_id"])
	}
	if event["group_id"] != "test-group-id" {
		t.Errorf("group_id 不匹配: %v", event["group_id"])
	}
	if event["from"] != "sender.agentid.pub" {
		t.Errorf("from 不匹配: %v", event["from"])
	}
}

// testBuildIdentity 构造测试用身份
func testBuildIdentity(aid, privPEM, pubB64, certPEM string) map[string]any {
	return map[string]any{
		"aid":             aid,
		"private_key_pem": privPEM,
		"public_key_b64":  pubB64,
		"cert":            certPEM,
	}
}
