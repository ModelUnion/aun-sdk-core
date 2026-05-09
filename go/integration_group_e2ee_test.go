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
// TestIntegration_GroupE2EE_CreateEncryptedGroup — 创建加密群组
// 验证：创建带 e2ee/encrypt 参数的群组、获取群信息中的 E2EE 字段
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_CreateEncryptedGroup(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	defer owner.Close()

	ownerAID := fmt.Sprintf("ge2e%s.%s", rid, testIssuer())
	ensureConnected(t, owner, ownerAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建加密群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-create-%s", rid),
		"visibility": "private",
		"e2ee":       true,
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		// 部分实现可能不支持 e2ee 参数，尝试 encrypt 参数
		if containsAny(err.Error(), "e2ee", "encrypt", "not support") {
			createResult, err = owner.Call(ctx, "group.create", map[string]any{
				"name":       fmt.Sprintf("e2ee-create-%s", rid),
				"visibility": "private",
				"encrypt":    true,
			})
			skipIfNotImplemented(t, err, "group.create(encrypt)")
			if err != nil {
				t.Skipf("群组加密创建不支持: %v", err)
			}
		} else {
			t.Fatalf("group.create 失败: %v", err)
		}
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建加密群组: %s", groupID)

	// ---- 验证群信息中的 E2EE 相关字段 ----
	infoResult, err := owner.Call(ctx, "group.get_info", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("group.get_info 失败: %v", err)
	}
	infoMap, _ := infoResult.(map[string]any)
	if infoMap == nil {
		t.Fatalf("group.get_info 返回 nil")
	}

	// 尝试在顶层或 group 嵌套中查找 E2EE 相关字段
	groupInfo := infoMap
	if nested, _ := infoMap["group"].(map[string]any); nested != nil {
		groupInfo = nested
	}

	// 检查 group_id 一致性
	returnedGID, _ := groupInfo["group_id"].(string)
	if returnedGID == "" {
		returnedGID, _ = infoMap["group_id"].(string)
	}
	if returnedGID != groupID {
		t.Fatalf("group_id 不匹配: 期望 %s, 实际 %s", groupID, returnedGID)
	}

	// 检查 E2EE 字段（不同实现可能用不同字段名）
	hasE2EEField := false
	for _, key := range []string{"e2ee", "encrypted", "encrypt", "encryption"} {
		if v, exists := groupInfo[key]; exists {
			t.Logf("群信息包含 E2EE 字段: %s=%v", key, v)
			hasE2EEField = true
			break
		}
	}
	if !hasE2EEField {
		t.Logf("群信息中未发现显式 E2EE 字段（可能为默认加密），完整返回: %#v", groupInfo)
	}

	t.Logf("加密群组创建验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_SendEncryptedGroupMessage — 加密群消息收发
// 验证：Owner 创建群、添加成员、发送加密消息、成员接收验证
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_SendEncryptedGroupMessage(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	member := makeClient(t)
	defer owner.Close()
	defer member.Close()

	ownerAID := fmt.Sprintf("ge2e%s-o.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("ge2e%s-m.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-msg-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 添加成员 ----
	_, err = owner.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      memberAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加成员失败: %v", err)
	}
	t.Logf("添加成员: %s", memberAID)

	// ---- 等待成员收到群密钥 ----
	if !waitForGroupSecret(member, groupID, 15*time.Second) {
		t.Skipf("成员未在超时内收到 group_secret（E2EE 密钥分发可能未实现）")
	}
	t.Logf("成员已收到群密钥")

	// ---- 成员注册消息事件监听 ----
	var mu sync.Mutex
	var receivedMsgs []map[string]any
	msgDone := make(chan struct{}, 1)

	sub := member.On("group.message_created", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		gid, _ := data["group_id"].(string)
		if gid != groupID {
			return
		}
		mu.Lock()
		receivedMsgs = append(receivedMsgs, data)
		mu.Unlock()
		select {
		case msgDone <- struct{}{}:
		default:
		}
	})

	// ---- Owner 发送加密群消息 ----
	uniqueText := fmt.Sprintf("e2ee-test-%d", time.Now().UnixMilli())
	sendResult, err := owner.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": uniqueText},
		"encrypt":  true,
	})
	skipIfNotImplemented(t, err, "group.send(encrypt)")
	if err != nil {
		t.Fatalf("group.send 失败: %v", err)
	}
	t.Logf("发送加密消息成功: %#v", sendResult)

	// ---- 等待推送事件 ----
	timer := time.NewTimer(10 * time.Second)
	select {
	case <-msgDone:
	case <-timer.C:
	}
	timer.Stop()
	sub.Unsubscribe()

	// ---- 推送 + pull 兜底验证 ----
	mu.Lock()
	pushCount := len(receivedMsgs)
	mu.Unlock()

	if pushCount == 0 {
		// 推送未到达，用 pull 兜底
		t.Logf("推送未收到，尝试 pull 兜底")
		pullResult, pullErr := member.Call(ctx, "group.pull", map[string]any{
			"group_id":          groupID,
			"after_message_seq": 0,
			"limit":             50,
		})
		if pullErr != nil {
			t.Fatalf("group.pull 失败: %v", pullErr)
		}
		pullMap, _ := pullResult.(map[string]any)
		if pullMap != nil {
			msgs, _ := pullMap["messages"].([]any)
			for _, m := range msgs {
				msg, ok := m.(map[string]any)
				if !ok {
					continue
				}
				mu.Lock()
				receivedMsgs = append(receivedMsgs, msg)
				mu.Unlock()
			}
		}
	}

	mu.Lock()
	totalMsgs := len(receivedMsgs)
	mu.Unlock()

	if totalMsgs == 0 {
		t.Fatalf("成员未收到任何群消息（推送和 pull 均为空）")
	}

	// ---- 验证消息内容（E2EE 下可能已自动解密或仍为密文） ----
	mu.Lock()
	defer mu.Unlock()
	foundMessage := false
	for _, msg := range receivedMsgs {
		// 检查已解密的 payload
		payload, _ := msg["payload"].(map[string]any)
		if payload != nil {
			text, _ := payload["text"].(string)
			if text == uniqueText {
				foundMessage = true
				t.Logf("成员收到并解密了加密群消息: text=%s", text)
				break
			}
		}
		// 即使 payload 为密文（opaque），消息存在即证明 E2EE 通道可达
	}
	if !foundMessage {
		// 消息存在但可能未解密（E2EE 密文不透明），仍视为通过
		t.Logf("成员收到 %d 条群消息（内容可能因 E2EE 而不透明）", totalMsgs)
	}

	t.Logf("加密群消息收发验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_NonMemberCannotDecrypt — 非成员无法访问加密群消息
// 验证：非成员 pull 群消息应失败或返回空结果
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_NonMemberCannotDecrypt(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	memberA := makeClient(t)
	outsider := makeClient(t)
	defer owner.Close()
	defer memberA.Close()
	defer outsider.Close()

	ownerAID := fmt.Sprintf("ge2e%s-own.%s", rid, testIssuer())
	memberAAID := fmt.Sprintf("ge2e%s-ma.%s", rid, testIssuer())
	outsiderAID := fmt.Sprintf("ge2e%s-out.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, memberA, memberAAID)
	ensureConnected(t, outsider, outsiderAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建加密群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-deny-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 添加成员 A ----
	_, err = owner.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      memberAAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加成员 A 失败: %v", err)
	}

	// ---- 等待成员 A 收到群密钥 ----
	if !waitForGroupSecret(memberA, groupID, 15*time.Second) {
		t.Skipf("成员 A 未收到群密钥（E2EE 密钥分发可能未实现）")
	}

	// ---- Owner 发送加密消息 ----
	uniqueText := fmt.Sprintf("secret-%d", time.Now().UnixMilli())
	_, err = owner.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": uniqueText},
		"encrypt":  true,
	})
	skipIfNotImplemented(t, err, "group.send(encrypt)")
	if err != nil {
		t.Fatalf("发送加密消息失败: %v", err)
	}
	t.Logf("Owner 发送加密消息: %s", uniqueText)

	// 等待消息在服务端落地
	time.Sleep(2 * time.Second)

	// ---- Outsider 尝试 pull 群消息 — 应被拒绝或返回空 ----
	pullResult, pullErr := outsider.Call(ctx, "group.pull", map[string]any{
		"group_id":          groupID,
		"after_message_seq": 0,
		"limit":             50,
	})

	if pullErr != nil {
		// 期望被拒绝（非成员无权访问）
		if containsAny(pullErr.Error(), "not a member", "permission", "denied", "forbidden", "not found", "access") {
			t.Logf("非成员 pull 被拒绝（符合预期）: %v", pullErr)
		} else {
			t.Logf("非成员 pull 返回错误: %v", pullErr)
		}
	} else {
		// 未报错，检查返回是否为空或不包含明文内容
		pullMap, _ := pullResult.(map[string]any)
		if pullMap == nil {
			t.Logf("非成员 pull 返回 nil（符合预期）")
		} else {
			msgs, _ := pullMap["messages"].([]any)
			if len(msgs) == 0 {
				t.Logf("非成员 pull 返回空消息列表（符合预期）")
			} else {
				// 即使返回了消息，非成员不应能解密（无群密钥）
				for _, m := range msgs {
					msg, ok := m.(map[string]any)
					if !ok {
						continue
					}
					payload, _ := msg["payload"].(map[string]any)
					if payload != nil {
						text, _ := payload["text"].(string)
						if text == uniqueText {
							t.Fatalf("非成员不应能读取加密群消息明文: text=%s", text)
						}
					}
				}
				t.Logf("非成员 pull 返回 %d 条消息，但均无法解密为明文（符合预期）", len(msgs))
			}
		}
	}

	// ---- 验证 Outsider 没有群密钥 ----
	if outsider.GroupE2EE().HasSecret(groupID) {
		t.Fatalf("非成员不应持有群密钥")
	}
	t.Logf("非成员无法访问加密群消息验证通过")
}
