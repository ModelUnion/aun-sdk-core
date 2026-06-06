//go:build integration

package aun

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestGroupRecall 群组消息撤回 E2E（对齐 Python integration_test_group_recall.py）。
// SDK 把撤回 tombstone 归一化为 group.message_recalled 事件（不在 pull 消息列表里出现），
// 并按 (group_id, message_ids, recalled_at) 去重，应用层只回调一次。
func TestGroupRecall(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	aliceAID := v2EnsureConnected(t, alice, fmt.Sprintf("grecall-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("grecall-bob-%s.agentid.pub", rid))

	groupID := v2CreateGroup(t, alice, fmt.Sprintf("grecall-%s", rid))
	v2AddMember(t, alice, groupID, bobAID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)
	v2DrainGroupInbox(t, bob, groupID)

	// Bob 订阅 group.message_recalled
	var recallEvents []map[string]any
	var recallMu sync.Mutex
	sub := bob.On("group.message_recalled", func(payload any) {
		if d, ok := payload.(map[string]any); ok {
			if getStr(d, "group_id", "") == groupID {
				recallMu.Lock()
				recallEvents = append(recallEvents, d)
				recallMu.Unlock()
			}
		}
	})
	defer sub.Unsubscribe()

	// Alice 发加密消息
	payload := map[string]any{"text": fmt.Sprintf("grecall-target-%s", rid)}
	sendResult := v2SendGroupWithRetry(t, alice, groupID, payload)
	msgID, _ := sendResult["message_id"].(string)
	origSeq := int(toInt64(sendResult["seq"]))
	if msgID == "" {
		t.Fatalf("send 未返回 message_id: %v", sendResult)
	}
	t.Logf("已发送 msg_id=%s seq=%d", msgID, origSeq)

	// Bob 先收一次原消息（成为"已读客户端"）
	_ = v2WaitForGroupMessage(t, bob, groupID, aliceAID, payload["text"].(string), 20*time.Second)

	// Alice 撤回
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	recallRes, err := alice.Call(ctx, "group.recall", map[string]any{
		"group_id":    groupID,
		"message_ids": []string{msgID},
	})
	cancel()
	if err != nil {
		t.Fatalf("group.recall 失败: %v", err)
	}
	recallMap, _ := recallRes.(map[string]any)
	recalled, _ := recallMap["recalled"].([]any)
	found := false
	for _, r := range recalled {
		if stringFromAny(r) == msgID {
			found = true
		}
	}
	if !found {
		t.Fatalf("recall 未成功: %v", recallMap)
	}
	t.Logf("撤回成功: %v", recalled)

	// 等待推送 + Bob 再 pull 兜底（触发 tombstone 归一化）。
	// 用 Call("group.pull") 走 pullGroupV2Internal 发布路径（pullGroupV2 仅解密不发布）。
	time.Sleep(1500 * time.Millisecond)
	pullCtx, pullCancel := context.WithTimeout(context.Background(), 15*time.Second)
	_, _ = bob.Call(pullCtx, "group.pull", map[string]any{
		"group_id": groupID, "after_seq": 0, "limit": 50, "force": true,
	})
	pullCancel()
	time.Sleep(600 * time.Millisecond)

	// SDK 去重：group.message_recalled 恰好一次
	recallMu.Lock()
	gotEvents := len(recallEvents)
	recallMu.Unlock()
	if gotEvents != 1 {
		t.Fatalf("期望 1 次 group.message_recalled 回调，实际 %d", gotEvents)
	}
	t.Logf("SDK 去重正确: 回调 %d 次", gotEvents)

	// 服务端 raw 校验：双 tombstone 落库，密文已删（绕过 SDK 归一化）
	rawCtx, rawCancel := context.WithTimeout(context.Background(), 15*time.Second)
	rawResult, err := alice.rawGroupV2Pull(rawCtx, groupID, 0, 50, map[string]any{"force": true})
	rawCancel()
	if err != nil {
		t.Fatalf("rawGroupV2Pull 失败: %v", err)
	}
	rawMap, _ := rawResult.(map[string]any)
	rawMsgs, _ := rawMap["messages"].([]any)
	tombstones := 0
	placeholderAtOrigSeq := false
	ciphertextPresent := false
	for _, raw := range rawMsgs {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		mtype := getStr(m, "type", "")
		if mtype == "" {
			mtype = getStr(m, "message_type", "")
		}
		if mtype == "group.message_recalled" {
			tombstones++
			if int(toInt64(m["seq"])) == origSeq {
				placeholderAtOrigSeq = true
			}
		}
		if getStr(m, "message_id", "") == msgID && m["envelope_json"] != nil {
			ciphertextPresent = true
		}
	}
	if tombstones < 2 {
		t.Fatalf("期望 >=2 个 tombstone，实际 %d", tombstones)
	}
	if !placeholderAtOrigSeq {
		t.Fatalf("占位 tombstone 应在原 seq=%d", origSeq)
	}
	if ciphertextPresent {
		t.Fatalf("原始密文不应再可拉取")
	}
	t.Logf("服务端双 tombstone 校验通过: count=%d placeholder@%d ciphertext_deleted=%v",
		tombstones, origSeq, !ciphertextPresent)
}

// TestGroupRecallNotSender 非发送者撤回被拒绝（not_sender）。
func TestGroupRecallNotSender(t *testing.T) {
	rid := v2RunID()
	alice := makeV2Client(t)
	defer alice.Close()
	bob := makeV2Client(t)
	defer bob.Close()

	_ = v2EnsureConnected(t, alice, fmt.Sprintf("grecall2-alice-%s.agentid.pub", rid))
	bobAID := v2EnsureConnected(t, bob, fmt.Sprintf("grecall2-bob-%s.agentid.pub", rid))

	groupID := v2CreateGroup(t, alice, fmt.Sprintf("grecall2-%s", rid))
	v2AddMember(t, alice, groupID, bobAID)
	v2WaitForGroupV2Ready(t, alice, groupID, []string{bobAID}, 20*time.Second)
	v2DrainGroupInbox(t, bob, groupID)

	payload := map[string]any{"text": fmt.Sprintf("not-sender-%s", rid)}
	sendResult := v2SendGroupWithRetry(t, alice, groupID, payload)
	msgID, _ := sendResult["message_id"].(string)
	time.Sleep(500 * time.Millisecond)

	// Bob（非发送者）撤回 → not_sender
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	res, err := bob.Call(ctx, "group.recall", map[string]any{
		"group_id":    groupID,
		"message_ids": []string{msgID},
	})
	cancel()
	if err != nil {
		t.Fatalf("group.recall 调用失败: %v", err)
	}
	resMap, _ := res.(map[string]any)
	errors, _ := resMap["errors"].([]any)
	notSender := false
	for _, e := range errors {
		if em, ok := e.(map[string]any); ok && getStr(em, "error", "") == "not_sender" {
			notSender = true
		}
	}
	if !notSender {
		t.Fatalf("期望 not_sender 错误，实际 %v", resMap)
	}
	t.Logf("非发送者撤回正确拒绝: %v", errors)
}
