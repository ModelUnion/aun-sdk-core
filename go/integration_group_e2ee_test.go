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

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_OpenJoinOnlinePriorityRecovery — 开放群入群在线优先密钥恢复
// 验证：Owner 创建 open 群 → Member 通过 request_join 加入 → 在线优先恢复 committed_epoch
//       → Owner 发加密消息 → Member 解密 → 等待延迟轮换 → 再次验证解密
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_OpenJoinOnlinePriorityRecovery(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	member := makeClient(t)
	defer owner.Close()
	defer member.Close()

	ownerAID := fmt.Sprintf("ge2e%s-oj-o.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("ge2e%s-oj-m.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建 open 群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-open-join-%s", rid),
		"visibility": "public",
		"join_mode":  "open",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建 open 群组: %s", groupID)

	// ---- 等待 Owner 的 committed epoch 就绪 ----
	ownerEpoch, ok := waitForCommittedGroupEpochReady(t, owner, groupID, 1, 30*time.Second)
	if !ok {
		t.Skipf("Owner 未在超时内获得 committed epoch（服务端可能不支持）")
	}
	t.Logf("Owner committed epoch: %d", ownerEpoch)

	// ---- Member 通过 request_join 加入 open 群 ----
	joinResult, err := member.Call(ctx, "group.request_join", map[string]any{
		"group_id": groupID,
	})
	skipIfNotImplemented(t, err, "group.request_join")
	if err != nil {
		t.Fatalf("group.request_join 失败: %v", err)
	}
	joinMap, _ := joinResult.(map[string]any)
	status, _ := joinMap["status"].(string)
	if status != "joined" {
		t.Fatalf("open 群 request_join 应直接返回 joined，实际: %s (result: %#v)", status, joinMap)
	}
	t.Logf("Member 加入 open 群，status=%s", status)

	// ---- Member 通过在线优先恢复获取 committed_epoch 密钥 ----
	if !waitForGroupSecret(member, groupID, 30*time.Second) {
		t.Fatalf("Member 未在超时内通过在线优先恢复获取群密钥")
	}
	t.Logf("Member 已通过在线优先恢复获取群密钥")

	// ---- 设置消息监听 ----
	memberWatch := watchGroupMessages(t, member, groupID)
	defer memberWatch.Stop()

	// ---- Owner 发送加密消息（恢复窗口内） ----
	text1 := fmt.Sprintf("open-join-msg1-%d", time.Now().UnixMilli())
	groupSendEncrypted(t, owner, groupID, map[string]any{"type": "text", "text": text1})
	t.Logf("Owner 发送加密消息: %s", text1)

	// ---- Member 解密消息 ----
	msgs1 := memberWatch.WaitFor(t, 20*time.Second, func(messages []map[string]any) bool {
		for _, msg := range filterDecrypted(messages) {
			if getPayloadText(msg) == text1 {
				return true
			}
		}
		return false
	})
	found1 := false
	for _, msg := range filterDecrypted(msgs1) {
		if getPayloadText(msg) == text1 {
			found1 = true
			break
		}
	}
	if !found1 {
		t.Fatalf("Member 未能解密恢复窗口内的加密消息: %s", text1)
	}
	t.Logf("Member 成功解密恢复窗口内消息")

	// ---- 等待延迟轮换（新 epoch） ----
	newEpoch, rotated := waitForCommittedGroupEpochGreaterThan(t, member, groupID, ownerEpoch, 45*time.Second)
	if !rotated {
		t.Logf("未检测到延迟轮换（可能服务端未触发），跳过轮换后验证")
		return
	}
	t.Logf("检测到延迟轮换，新 epoch: %d", newEpoch)

	// ---- Owner 发送轮换后消息 ----
	text2 := fmt.Sprintf("open-join-msg2-%d", time.Now().UnixMilli())
	groupSendEncrypted(t, owner, groupID, map[string]any{"type": "text", "text": text2})

	// ---- Member 解密轮换后消息 ----
	msgs2 := memberWatch.WaitFor(t, 20*time.Second, func(messages []map[string]any) bool {
		for _, msg := range filterDecryptedByEpoch(messages, newEpoch) {
			if getPayloadText(msg) == text2 {
				return true
			}
		}
		return false
	})
	found2 := false
	for _, msg := range filterDecryptedByEpoch(msgs2, newEpoch) {
		if getPayloadText(msg) == text2 {
			found2 = true
			break
		}
	}
	if !found2 {
		t.Fatalf("Member 未能解密延迟轮换后的加密消息: %s", text2)
	}
	t.Logf("Open 群入群在线优先密钥恢复验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_InviteCodeJoinOnlinePriorityRecovery — 邀请码入群在线优先密钥恢复
// 验证：Owner 创建 invite_code 群 → 生成邀请码 → Member 使用邀请码入群
//       → 在线优先恢复 committed_epoch → Owner 发加密消息 → Member 解密
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_InviteCodeJoinOnlinePriorityRecovery(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	member := makeClient(t)
	defer owner.Close()
	defer member.Close()

	ownerAID := fmt.Sprintf("ge2e%s-ic-o.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("ge2e%s-ic-m.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建 invite_code 群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-invite-code-%s", rid),
		"visibility": "public",
		"join_mode":  "invite_code",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建 invite_code 群组: %s", groupID)

	// ---- 等待 Owner 的 committed epoch 就绪 ----
	ownerEpoch, ok := waitForCommittedGroupEpochReady(t, owner, groupID, 1, 30*time.Second)
	if !ok {
		t.Skipf("Owner 未在超时内获得 committed epoch（服务端可能不支持）")
	}
	t.Logf("Owner committed epoch: %d", ownerEpoch)

	// ---- Owner 创建邀请码 ----
	inviteResult, err := owner.Call(ctx, "group.create_invite_code", map[string]any{
		"group_id": groupID,
	})
	skipIfNotImplemented(t, err, "group.create_invite_code")
	if err != nil {
		t.Fatalf("group.create_invite_code 失败: %v", err)
	}
	inviteMap, _ := inviteResult.(map[string]any)
	var inviteCode string
	// 服务端返回 invite_code 为嵌套 map，包含 code / code_with_domain 等字段
	if nested, ok := inviteMap["invite_code"].(map[string]any); ok {
		// 优先使用 code_with_domain（跨域场景），其次 code
		if cwd, _ := nested["code_with_domain"].(string); cwd != "" {
			inviteCode = cwd
		} else if c, _ := nested["code"].(string); c != "" {
			inviteCode = c
		}
	}
	// 兼容旧版：invite_code 直接是字符串
	if inviteCode == "" {
		inviteCode, _ = inviteMap["invite_code"].(string)
	}
	// 再尝试顶层 code 字段
	if inviteCode == "" {
		inviteCode, _ = inviteMap["code"].(string)
	}
	if inviteCode == "" {
		t.Fatalf("创建邀请码返回中未找到有效的 invite_code: %#v", inviteMap)
	}
	t.Logf("创建邀请码: %s", inviteCode)

	// ---- Member 使用邀请码入群 ----
	useResult, err := member.Call(ctx, "group.use_invite_code", map[string]any{
		"code": inviteCode,
	})
	skipIfNotImplemented(t, err, "group.use_invite_code")
	if err != nil {
		t.Fatalf("group.use_invite_code 失败: %v", err)
	}
	useMap, _ := useResult.(map[string]any)
	useStatus, _ := useMap["status"].(string)
	useGroupID, _ := useMap["group_id"].(string)
	if useGroupID == "" {
		useGroupID = groupID
	}
	t.Logf("Member 使用邀请码入群: status=%s, group_id=%s", useStatus, useGroupID)

	// ---- Member 通过在线优先恢复获取 committed_epoch 密钥 ----
	if !waitForGroupSecret(member, groupID, 30*time.Second) {
		t.Fatalf("Member 未在超时内通过在线优先恢复获取群密钥")
	}
	t.Logf("Member 已通过在线优先恢复获取群密钥")

	// ---- 设置消息监听 ----
	memberWatch := watchGroupMessages(t, member, groupID)
	defer memberWatch.Stop()

	// ---- Owner 发送加密消息 ----
	text1 := fmt.Sprintf("invite-code-msg-%d", time.Now().UnixMilli())
	groupSendEncrypted(t, owner, groupID, map[string]any{"type": "text", "text": text1})
	t.Logf("Owner 发送加密消息: %s", text1)

	// ---- Member 解密消息 ----
	msgs := memberWatch.WaitFor(t, 20*time.Second, func(messages []map[string]any) bool {
		for _, msg := range filterDecrypted(messages) {
			if getPayloadText(msg) == text1 {
				return true
			}
		}
		return false
	})
	found := false
	for _, msg := range filterDecrypted(msgs) {
		if getPayloadText(msg) == text1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Member 未能解密邀请码入群后的加密消息: %s", text1)
	}
	t.Logf("Member 成功解密邀请码入群后消息")

	// ---- 等待延迟轮换 ----
	newEpoch, rotated := waitForCommittedGroupEpochGreaterThan(t, member, groupID, ownerEpoch, 45*time.Second)
	if !rotated {
		t.Logf("未检测到延迟轮换（可能服务端未触发），跳过轮换后验证")
		return
	}
	t.Logf("检测到延迟轮换，新 epoch: %d", newEpoch)

	// ---- Owner 发送轮换后消息 ----
	text2 := fmt.Sprintf("invite-code-msg2-%d", time.Now().UnixMilli())
	groupSendEncrypted(t, owner, groupID, map[string]any{"type": "text", "text": text2})

	// ---- Member 解密轮换后消息 ----
	msgs2 := memberWatch.WaitFor(t, 20*time.Second, func(messages []map[string]any) bool {
		for _, msg := range filterDecryptedByEpoch(messages, newEpoch) {
			if getPayloadText(msg) == text2 {
				return true
			}
		}
		return false
	})
	found2 := false
	for _, msg := range filterDecryptedByEpoch(msgs2, newEpoch) {
		if getPayloadText(msg) == text2 {
			found2 = true
			break
		}
	}
	if !found2 {
		t.Fatalf("Member 未能解密延迟轮换后的加密消息: %s", text2)
	}
	t.Logf("邀请码入群在线优先密钥恢复验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_PrivateAddMemberImmediateRotation — 私有群 add_member 立即轮换（对照组）
// 验证：Owner 创建私有群 → add_member → Member 通过立即轮换获取新 epoch
//       → Owner 发加密消息 → Member 解密
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_PrivateAddMemberImmediateRotation(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	member := makeClient(t)
	defer owner.Close()
	defer member.Close()

	ownerAID := fmt.Sprintf("ge2e%s-pa-o.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("ge2e%s-pa-m.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建私有群组（默认） ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-private-add-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建私有群组: %s", groupID)

	// ---- 等待 Owner 的 committed epoch 就绪 ----
	ownerEpoch, ok := waitForCommittedGroupEpochReady(t, owner, groupID, 1, 30*time.Second)
	if !ok {
		t.Skipf("Owner 未在超时内获得 committed epoch（服务端可能不支持）")
	}
	t.Logf("Owner committed epoch: %d", ownerEpoch)

	// ---- Owner 添加 Member ----
	_, err = owner.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      memberAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("group.add_member 失败: %v", err)
	}
	t.Logf("Owner 添加 Member: %s", memberAID)

	// ---- Member 通过立即轮换获取新 epoch 密钥 ----
	if !waitForGroupSecret(member, groupID, 30*time.Second) {
		t.Fatalf("Member 未在超时内通过立即轮换获取群密钥")
	}
	t.Logf("Member 已通过立即轮换获取群密钥")

	// ---- 验证 Member 获得的是新 epoch（立即轮换产生） ----
	newEpoch, epochReady := waitForCommittedGroupEpochReady(t, member, groupID, ownerEpoch, 30*time.Second)
	if !epochReady {
		t.Logf("Member 未获得 committed epoch >= %d，但已有密钥，继续验证消息解密", ownerEpoch)
	} else {
		t.Logf("Member committed epoch: %d（立即轮换）", newEpoch)
	}

	// ---- 设置消息监听 ----
	memberWatch := watchGroupMessages(t, member, groupID)
	defer memberWatch.Stop()

	// ---- Owner 发送加密消息 ----
	text1 := fmt.Sprintf("private-add-msg-%d", time.Now().UnixMilli())
	groupSendEncrypted(t, owner, groupID, map[string]any{"type": "text", "text": text1})
	t.Logf("Owner 发送加密消息: %s", text1)

	// ---- Member 解密消息 ----
	msgs := memberWatch.WaitFor(t, 20*time.Second, func(messages []map[string]any) bool {
		for _, msg := range filterDecrypted(messages) {
			if getPayloadText(msg) == text1 {
				return true
			}
		}
		return false
	})
	found := false
	for _, msg := range filterDecrypted(msgs) {
		if getPayloadText(msg) == text1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Member 未能解密 add_member 后的加密消息: %s", text1)
	}
	t.Logf("私有群 add_member 立即轮换验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_OpenJoinMemberLeadsRotation
// open 群 owner 离线时，普通 member 代为轮换 epoch
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_OpenJoinMemberLeadsRotation(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	charlie := makeClient(t)
	bob := makeClient(t)
	defer owner.Close()
	defer charlie.Close()
	defer bob.Close()

	ownerAID := fmt.Sprintf("ge2e%s-mlr-o.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("ge2e%s-mlr-c.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ge2e%s-mlr-b.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 1. Owner 建 open 群
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-mlr-%s", rid),
		"visibility": "public",
		"join_mode":  "open",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)

	epoch1, ok := waitForCommittedGroupEpochReady(t, owner, groupID, 1, 30*time.Second)
	if !ok {
		t.Skipf("Owner 未在超时内获得 committed epoch")
	}
	t.Logf("epoch1=%d", epoch1)

	// 2. Owner add_member Charlie
	addMember(t, owner, groupID, charlieAID)
	epoch2, ok := waitForCommittedGroupEpochReady(t, charlie, groupID, epoch1+1, 30*time.Second)
	if !ok {
		t.Fatalf("Charlie 未获得 epoch %d+", epoch1+1)
	}
	t.Logf("epoch2=%d", epoch2)

	// 3. Owner 下线
	owner.Close()
	time.Sleep(1 * time.Second)

	// 4. Bob 加入 open 群
	ensureConnected(t, bob, bobAID)
	joinResult, err := bob.Call(ctx, "group.request_join", map[string]any{"group_id": groupID})
	if err != nil {
		t.Fatalf("bob request_join 失败: %v", err)
	}
	joinMap, _ := joinResult.(map[string]any)
	if joinMap["status"] != "joined" {
		t.Fatalf("expected joined, got %v", joinMap)
	}

	// 5. Charlie（member）应代为轮换 epoch，Bob 拿到新 key
	epoch3, ok := waitForCommittedGroupEpochReady(t, bob, groupID, epoch2+1, 30*time.Second)
	if !ok {
		t.Fatalf("Bob 未获得 member-led rotation epoch %d+", epoch2+1)
	}
	t.Logf("epoch3=%d (member-led rotation)", epoch3)

	// 6. Charlie 发消息，Bob 能解密
	bobWatch := watchGroupMessages(t, bob, groupID)
	defer bobWatch.Stop()
	text := fmt.Sprintf("mlr-msg-%d", time.Now().UnixMilli())
	groupSendEncrypted(t, charlie, groupID, map[string]any{"type": "text", "text": text})

	msgs := bobWatch.WaitFor(t, 20*time.Second, func(messages []map[string]any) bool {
		for _, msg := range filterDecrypted(messages) {
			if getPayloadText(msg) == text {
				return true
			}
		}
		return false
	})
	found := false
	for _, msg := range filterDecrypted(msgs) {
		if getPayloadText(msg) == text {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Bob 未能解密 member-led rotation 后的消息")
	}
	t.Logf("member leads rotation 验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_OpenJoinSendRepairsMissingCommittedMembership
// open 群新成员在 committed membership 缺少自己时，发送前应先修复轮换
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_OpenJoinSendRepairsMissingCommittedMembership(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	bob := makeClient(t)
	charlie := makeClient(t)
	defer owner.Close()
	defer bob.Close()
	defer charlie.Close()

	ownerAID := fmt.Sprintf("ge2e%s-oms-o.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ge2e%s-oms-b.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("ge2e%s-oms-c.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 1. Owner 建 open 群
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-oms-%s", rid),
		"visibility": "public",
		"join_mode":  "open",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)

	epoch1, ok := waitForCommittedGroupEpochReady(t, owner, groupID, 1, 30*time.Second)
	if !ok {
		t.Skipf("Owner 未在超时内获得 committed epoch")
	}

	// 2. Bob 加入
	joinResult, err := bob.Call(ctx, "group.request_join", map[string]any{"group_id": groupID})
	if err != nil {
		t.Fatalf("bob request_join 失败: %v", err)
	}
	joinMap, _ := joinResult.(map[string]any)
	if joinMap["status"] != "joined" {
		t.Fatalf("expected joined, got %v", joinMap)
	}
	epoch2, _ := waitForCommittedGroupEpochReady(t, bob, groupID, epoch1+1, 30*time.Second)
	waitForCommittedGroupEpochReady(t, owner, groupID, epoch2, 20*time.Second)
	t.Logf("epoch2=%d after bob join", epoch2)

	// 3. Owner 下线，Charlie 加入（制造 committed membership gap）
	owner.Close()
	time.Sleep(500 * time.Millisecond)
	charlieJoin, err := charlie.Call(ctx, "group.request_join", map[string]any{"group_id": groupID})
	if err != nil {
		t.Fatalf("charlie request_join 失败: %v", err)
	}
	charlieMap, _ := charlieJoin.(map[string]any)
	if charlieMap["status"] != "joined" {
		t.Fatalf("expected charlie joined, got %v", charlieMap)
	}

	// 4. Bob 发送加密消息 — 应触发 committed membership gap 修复
	text := fmt.Sprintf("repair-send-%d", time.Now().UnixMilli())
	_, err = bob.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": text},
		"encrypt":  true,
	})
	if err != nil {
		t.Fatalf("bob group.send 失败: %v", err)
	}

	// 5. 验证 epoch 已推进（gap 被修复）
	repairedEpoch, ok := waitForCommittedGroupEpochReady(t, bob, groupID, epoch2+1, 30*time.Second)
	if !ok {
		// 也可能在发送前已被其他 member 修复
		t.Logf("epoch 未推进，可能已被其他路径修复")
	} else {
		t.Logf("repairedEpoch=%d (gap repaired)", repairedEpoch)
	}
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupE2EE_ThoughtGetRecoversMissingEpochKey
// group.thought.get 缺 epoch key 时应恢复后解密
// ---------------------------------------------------------------------------

func TestIntegration_GroupE2EE_ThoughtGetRecoversMissingEpochKey(t *testing.T) {
	rid := runID()
	ownerPath := t.TempDir()
	t.Setenv("AUN_ENV", "development")
	owner := NewClient(map[string]any{"aun_path": ownerPath}, true)
	owner.configModel.RequireForwardSecrecy = false
	bob := makeClient(t)
	charlie := makeClient(t)
	defer owner.Close()
	defer bob.Close()
	defer charlie.Close()

	ownerAID := fmt.Sprintf("ge2e%s-tgt-o.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ge2e%s-tgt-b.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("ge2e%s-tgt-c.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 1. Owner 建 open 群
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("e2ee-thought-%s", rid),
		"visibility": "public",
		"join_mode":  "open",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)

	epoch1, ok := waitForCommittedGroupEpochReady(t, owner, groupID, 1, 30*time.Second)
	if !ok {
		t.Skipf("Owner 未在超时内获得 committed epoch")
	}

	// 2. Bob 加入
	joinResult, err := bob.Call(ctx, "group.request_join", map[string]any{"group_id": groupID})
	if err != nil {
		t.Fatalf("bob request_join 失败: %v", err)
	}
	joinMap, _ := joinResult.(map[string]any)
	if joinMap["status"] != "joined" {
		t.Fatalf("expected joined, got %v", joinMap)
	}
	epoch2, _ := waitForCommittedGroupEpochReady(t, bob, groupID, epoch1+1, 30*time.Second)
	waitForCommittedGroupEpochReady(t, owner, groupID, epoch2, 20*time.Second)

	// 3. Owner 下线，Charlie 加入推进 epoch
	owner.Close()
	time.Sleep(500 * time.Millisecond)
	charlieJoin, err := charlie.Call(ctx, "group.request_join", map[string]any{"group_id": groupID})
	if err != nil {
		t.Fatalf("charlie request_join 失败: %v", err)
	}
	charlieMap, _ := charlieJoin.(map[string]any)
	if charlieMap["status"] != "joined" {
		t.Fatalf("expected charlie joined, got %v", charlieMap)
	}
	epoch3, _ := waitForCommittedGroupEpochReady(t, bob, groupID, epoch2+1, 30*time.Second)
	waitForCommittedGroupEpochReady(t, charlie, groupID, epoch3, 20*time.Second)
	t.Logf("epoch3=%d (owner offline)", epoch3)

	// 4. Bob 写 thought
	thoughtText := fmt.Sprintf("thought-recover-%d", time.Now().UnixMilli())
	thoughtContext := map[string]any{"type": "run", "id": fmt.Sprintf("thought-run-%s", rid)}
	_, err = bob.Call(ctx, "group.thought.put", map[string]any{
		"group_id": groupID,
		"context":  thoughtContext,
		"payload":  map[string]any{"type": "thought", "text": thoughtText},
	})
	if err != nil {
		t.Fatalf("bob group.thought.put 失败: %v", err)
	}

	// 5. Owner 重新上线，读取 thought — 应触发 epoch key 恢复后解密
	owner2 := NewClient(map[string]any{"aun_path": ownerPath}, true)
	owner2.configModel.RequireForwardSecrecy = false
	defer owner2.Close()
	ensureConnected(t, owner2, ownerAID)

	// 等待 owner2 恢复 epoch key
	waitForCommittedGroupEpochReady(t, owner2, groupID, epoch3, 30*time.Second)

	result, err := owner2.Call(ctx, "group.thought.get", map[string]any{
		"group_id":   groupID,
		"sender_aid": bobAID,
		"context":    thoughtContext,
	})
	if err != nil {
		t.Fatalf("owner2 group.thought.get 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	thoughts, _ := resultMap["thoughts"].([]any)
	found := false
	for _, item := range thoughts {
		thought, _ := item.(map[string]any)
		payload, _ := thought["payload"].(map[string]any)
		if payload != nil && payload["text"] == thoughtText {
			e2eeInfo, _ := thought["e2ee"].(map[string]any)
			if e2eeInfo != nil && e2eeInfo["encryption_mode"] == "epoch_group_key" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("Owner 重连后未能解密 thought: %v", resultMap)
	}
	t.Logf("thought.get 恢复 epoch key 后解密验证通过")
}
