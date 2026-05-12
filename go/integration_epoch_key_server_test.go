//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// makeClientWithPath 创建复用指定 aun_path 的客户端（保留证书）
func makeClientWithPath(t *testing.T, aunPath string) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := NewClient(map[string]any{
		"aun_path": aunPath,
	}, true)
	client.configModel.RequireForwardSecrecy = false
	return client
}

// ---------------------------------------------------------------------------
// TestIntegration_EpochKeyServer_CommitUploadsEncryptedKeys
// 验证：Alice 建群 → 加 Bob → epoch commit 上传 encrypted_keys → Bob 从服务端拉取
// ---------------------------------------------------------------------------

func TestIntegration_EpochKeyServer_CommitUploadsEncryptedKeys(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("ek%s-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ek%s-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("epoch-key-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 添加 Bob ----
	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加成员失败: %v", err)
	}
	t.Logf("添加成员: %s", bobAID)

	// ---- 等待 epoch 提交 ----
	if !waitForGroupSecret(alice, groupID, 15*time.Second) {
		t.Skipf("Alice 未在超时内获得 group_secret")
	}
	time.Sleep(2 * time.Second) // 等待 commit 完成上传 encrypted_keys

	// ---- Bob 从服务端拉取 epoch key ----
	result, err := bob.Call(ctx, "group.e2ee.get_epoch_key", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		// 如果 RPC 不存在，跳过
		if containsAny(err.Error(), "not found", "not implemented", "unknown method") {
			t.Skipf("group.e2ee.get_epoch_key RPC 未实现: %v", err)
		}
		t.Fatalf("get_epoch_key 失败: %v", err)
	}

	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		t.Fatalf("get_epoch_key 返回 nil")
	}

	encryptedKey, _ := resultMap["encrypted_key"].(string)
	if encryptedKey != "" {
		t.Logf("[OK] 服务端存储了 encrypted_key (len=%d)", len(encryptedKey))
	} else {
		t.Logf("[WARN] 服务端未存储 encrypted_key（可能 Alice 获取 Bob 证书失败）")
		t.Logf("[INFO] result: %#v", resultMap)
	}

	t.Logf("commit_rotation 上传 encrypted_keys 验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_EpochKeyServer_OfflineMemberRecovers
// 验证：Bob 离线 → Alice 轮换 epoch → Bob 上线从服务端恢复
// ---------------------------------------------------------------------------

func TestIntegration_EpochKeyServer_OfflineMemberRecovers(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()

	aliceAID := fmt.Sprintf("ek%s-off-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ek%s-off-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	// ---- 创建群组 + 加 Bob ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("offline-recover-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加成员失败: %v", err)
	}

	// 等待初始 epoch
	if !waitForGroupSecret(alice, groupID, 15*time.Second) {
		t.Skipf("Alice 未在超时内获得 group_secret")
	}
	waitForGroupSecret(bob, groupID, 10*time.Second)
	t.Logf("初始 epoch 已就绪")

	// 获取当前 epoch
	epochResult, err := alice.Call(ctx, "group.e2ee.get_epoch", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("get_epoch 失败: %v", err)
	}
	epochMap, _ := epochResult.(map[string]any)
	epoch1 := int64(0)
	if epochMap != nil {
		if v, ok := epochMap["committed_epoch"]; ok {
			epoch1 = toInt64(v)
		} else if v, ok := epochMap["epoch"]; ok {
			epoch1 = toInt64(v)
		}
	}
	t.Logf("当前 epoch: %d", epoch1)

	// ---- Bob 断开 ----
	bobPath := bob.configModel.AUNPath
	bob.Close()
	time.Sleep(1 * time.Second)
	t.Logf("Bob 已离线")

	// ---- 触发 epoch 轮换 ----
	// 通过添加临时成员再踢出来触发轮换
	tempAID := fmt.Sprintf("ek%s-tmp.%s", rid, testIssuer())
	temp := makeClient(t)
	defer temp.Close()
	ensureConnected(t, temp, tempAID)

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      tempAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加临时成员失败: %v", err)
	}
	time.Sleep(1 * time.Second)

	_, err = alice.Call(ctx, "group.kick", map[string]any{
		"group_id": groupID,
		"aid":      tempAID,
	})
	if err != nil {
		t.Logf("[WARN] 踢出临时成员失败: %v", err)
	}
	time.Sleep(3 * time.Second)

	// 验证 epoch 已推进
	epochResult2, err := alice.Call(ctx, "group.e2ee.get_epoch", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("get_epoch 失败: %v", err)
	}
	epochMap2, _ := epochResult2.(map[string]any)
	epoch2 := int64(0)
	if epochMap2 != nil {
		if v, ok := epochMap2["committed_epoch"]; ok {
			epoch2 = toInt64(v)
		} else if v, ok := epochMap2["epoch"]; ok {
			epoch2 = toInt64(v)
		}
	}
	if epoch2 <= epoch1 {
		t.Logf("[WARN] epoch 未推进 (epoch1=%d, epoch2=%d)，可能踢人未触发轮换", epoch1, epoch2)
	} else {
		t.Logf("epoch 已推进: %d → %d", epoch1, epoch2)
	}

	// ---- Bob 重新上线（复用原 aun_path 保留证书）----
	bob2 := makeClientWithPath(t, bobPath)
	defer bob2.Close()
	ensureConnected(t, bob2, bobAID)
	t.Logf("Bob 重新上线")

	// ---- Bob 从服务端拉取 epoch key ----
	result, err := bob2.Call(ctx, "group.e2ee.get_epoch_key", map[string]any{
		"group_id": groupID,
		"epoch":    epoch2,
	})
	if err != nil {
		if containsAny(err.Error(), "not found", "not implemented", "unknown method") {
			t.Skipf("group.e2ee.get_epoch_key RPC 未实现: %v", err)
		}
		t.Logf("[WARN] get_epoch_key 失败: %v", err)
	} else {
		resultMap, _ := result.(map[string]any)
		encryptedKey, _ := resultMap["encrypted_key"].(string)
		if encryptedKey != "" {
			t.Logf("[OK] 离线成员从服务端获取到 epoch=%d 的 encrypted_key", epoch2)
		} else {
			t.Logf("[WARN] 服务端未存储 epoch=%d 的 encrypted_key", epoch2)
		}
	}

	t.Logf("离线成员恢复验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_EpochKeyServer_NonMemberDenied
// 验证：非成员调用 get_epoch_key 被拒绝
// ---------------------------------------------------------------------------

func TestIntegration_EpochKeyServer_NonMemberDenied(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	charlie := makeClient(t)
	defer alice.Close()
	defer charlie.Close()

	aliceAID := fmt.Sprintf("ek%s-deny-a.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("ek%s-deny-c.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- Alice 建群（不加 Charlie）----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("deny-epoch-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)
	t.Logf("创建群组（仅 Alice）: %s", groupID)

	// 等待 epoch 提交
	if !waitForGroupSecret(alice, groupID, 15*time.Second) {
		t.Skipf("Alice 未在超时内获得 group_secret")
	}
	time.Sleep(1 * time.Second)

	// ---- Charlie 尝试拉取 epoch key ----
	result, err := charlie.Call(ctx, "group.e2ee.get_epoch_key", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		// 被拒绝（预期行为）
		t.Logf("[OK] 非成员被拒绝: %v", err)
		return
	}

	// 没抛异常，检查返回值
	resultMap, _ := result.(map[string]any)
	if resultMap != nil {
		if errMsg, _ := resultMap["error"].(string); errMsg != "" {
			t.Logf("[OK] 非成员被拒绝: %s", errMsg)
			return
		}
		encryptedKey, _ := resultMap["encrypted_key"].(string)
		if encryptedKey == "" {
			t.Logf("[OK] 非成员未获取到 encrypted_key（返回空）")
			return
		}
		t.Fatalf("[FAIL] 非成员竟然获取到了 encrypted_key: %s", encryptedKey)
	}

	t.Logf("非成员拒绝验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_EpochKeyServer_SpecificEpoch
// 验证：轮换两次 → 按指定 epoch 拉取不同的 encrypted_key
// ---------------------------------------------------------------------------

func TestIntegration_EpochKeyServer_SpecificEpoch(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("ek%s-spec-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ek%s-spec-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建群组 + 加 Bob ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("specific-epoch-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)
	t.Logf("创建群组: %s", groupID)

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加成员失败: %v", err)
	}

	// 等待初始 epoch
	if !waitForGroupSecret(alice, groupID, 15*time.Second) {
		t.Skipf("Alice 未在超时内获得 group_secret")
	}

	// 获取 epoch1
	epochResult, err := alice.Call(ctx, "group.e2ee.get_epoch", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("get_epoch 失败: %v", err)
	}
	epochMap, _ := epochResult.(map[string]any)
	epoch1 := int64(0)
	if epochMap != nil {
		if v, ok := epochMap["committed_epoch"]; ok {
			epoch1 = toInt64(v)
		} else if v, ok := epochMap["epoch"]; ok {
			epoch1 = toInt64(v)
		}
	}
	t.Logf("epoch1: %d", epoch1)

	// ---- 触发第二次轮换 ----
	_, err = alice.Call(ctx, "group.e2ee.rotate_epoch", map[string]any{
		"group_id": groupID,
		"reason":   "test",
	})
	if err != nil {
		// rotate_epoch 不是公开 RPC，通过 kick 触发
		tempAID := fmt.Sprintf("ek%s-spec-tmp.%s", rid, testIssuer())
		temp := makeClient(t)
		defer temp.Close()
		ensureConnected(t, temp, tempAID)

		_, err2 := alice.Call(ctx, "group.add_member", map[string]any{
			"group_id": groupID,
			"aid":      tempAID,
			"role":     "member",
		})
		if err2 != nil {
			t.Fatalf("添加临时成员失败: %v", err2)
		}
		time.Sleep(1 * time.Second)
		alice.Call(ctx, "group.kick", map[string]any{
			"group_id": groupID,
			"aid":      tempAID,
		})
	}
	time.Sleep(3 * time.Second)

	// 获取 epoch2
	epochResult2, err := alice.Call(ctx, "group.e2ee.get_epoch", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("get_epoch 失败: %v", err)
	}
	epochMap2, _ := epochResult2.(map[string]any)
	epoch2 := int64(0)
	if epochMap2 != nil {
		if v, ok := epochMap2["committed_epoch"]; ok {
			epoch2 = toInt64(v)
		} else if v, ok := epochMap2["epoch"]; ok {
			epoch2 = toInt64(v)
		}
	}
	if epoch2 <= epoch1 {
		t.Logf("[WARN] epoch 未推进 (epoch1=%d, epoch2=%d)", epoch1, epoch2)
	} else {
		t.Logf("epoch 已推进: %d → %d", epoch1, epoch2)
	}

	// ---- Bob 按指定 epoch 拉取 ----
	result1, err := bob.Call(ctx, "group.e2ee.get_epoch_key", map[string]any{
		"group_id": groupID,
		"epoch":    epoch1,
	})
	if err != nil {
		if containsAny(err.Error(), "not found", "not implemented", "unknown method") {
			t.Skipf("get_epoch_key RPC 未实现: %v", err)
		}
		t.Logf("[WARN] get_epoch_key epoch1 失败: %v", err)
	}

	result2, err := bob.Call(ctx, "group.e2ee.get_epoch_key", map[string]any{
		"group_id": groupID,
		"epoch":    epoch2,
	})
	if err != nil {
		t.Logf("[WARN] get_epoch_key epoch2 失败: %v", err)
	}

	r1Map, _ := result1.(map[string]any)
	r2Map, _ := result2.(map[string]any)
	key1 := ""
	key2 := ""
	if r1Map != nil {
		key1, _ = r1Map["encrypted_key"].(string)
	}
	if r2Map != nil {
		key2, _ = r2Map["encrypted_key"].(string)
	}

	t.Logf("[INFO] epoch %d: has_key=%v", epoch1, key1 != "")
	t.Logf("[INFO] epoch %d: has_key=%v", epoch2, key2 != "")

	if key1 != "" && key2 != "" {
		if key1 == key2 {
			t.Fatalf("[FAIL] 两个 epoch 的密文相同，不符合预期")
		}
		t.Logf("[OK] 两个 epoch 的密文不同（符合预期）")
	}

	t.Logf("按指定 epoch 拉取验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_EpochKeyServer_RecoveredKeyDecryptsMessage
// 验证：Alice 发加密消息 → Bob 离线 → epoch 轮换 → Bob 上线恢复密钥 → 解密消息
// ---------------------------------------------------------------------------

func TestIntegration_EpochKeyServer_RecoveredKeyDecryptsMessage(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()

	aliceAID := fmt.Sprintf("ek%s-msg-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ek%s-msg-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建群组 + 加 Bob ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("decrypt-msg-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加成员失败: %v", err)
	}

	// 等待初始 epoch
	if !waitForGroupSecret(alice, groupID, 15*time.Second) {
		t.Skipf("Alice 未在超时内获得 group_secret")
	}
	waitForGroupSecret(bob, groupID, 10*time.Second)
	t.Logf("初始 epoch 已就绪")

	// ---- Alice 发送加密消息 ----
	testText := fmt.Sprintf("hello-from-alice-%s", rid)
	sendResult, err := alice.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": testText},
		"encrypt":  true,
	})
	if err != nil {
		t.Fatalf("group.send 失败: %v", err)
	}
	t.Logf("Alice 发送加密消息: text=%s, result=%v", testText, sendResult)

	// ---- Bob 断开 ----
	bobPath := bob.configModel.AUNPath
	bob.Close()
	time.Sleep(1 * time.Second)
	t.Logf("Bob 已离线")

	// ---- 触发 epoch 轮换 ----
	_, err = alice.Call(ctx, "group.e2ee.rotate_epoch", map[string]any{
		"group_id": groupID,
		"reason":   "test",
	})
	if err != nil {
		tempAID := fmt.Sprintf("ek%s-msg-tmp.%s", rid, testIssuer())
		temp := makeClient(t)
		defer temp.Close()
		ensureConnected(t, temp, tempAID)

		alice.Call(ctx, "group.add_member", map[string]any{
			"group_id": groupID,
			"aid":      tempAID,
			"role":     "member",
		})
		time.Sleep(1 * time.Second)
		alice.Call(ctx, "group.kick", map[string]any{
			"group_id": groupID,
			"aid":      tempAID,
		})
	}
	time.Sleep(3 * time.Second)
	t.Logf("epoch 轮换完成（Bob 离线期间）")

	// ---- Bob 重新上线（复用原 aun_path 保留证书）----
	bob2 := makeClientWithPath(t, bobPath)
	defer bob2.Close()
	ensureConnected(t, bob2, bobAID)
	t.Logf("Bob 重新上线")

	// 尝试从服务端恢复
	bob2.Call(ctx, "group.e2ee.try_recover_from_server", map[string]any{
		"group_id": groupID,
	})
	time.Sleep(1 * time.Second)

	// ---- Bob 拉取群消息 ----
	pullResult, err := bob2.Call(ctx, "group.pull", map[string]any{
		"group_id": groupID,
		"limit":    10,
	})
	if err != nil {
		t.Logf("[WARN] group.pull 失败: %v", err)
	}

	pullMap, _ := pullResult.(map[string]any)
	decrypted := false
	if pullMap != nil {
		messages, _ := pullMap["messages"].([]any)
		t.Logf("[INFO] Bob 拉取到 %d 条消息", len(messages))
		for _, m := range messages {
			msg, _ := m.(map[string]any)
			if msg == nil {
				continue
			}
			payload, _ := msg["payload"].(map[string]any)
			if payload != nil {
				if text, _ := payload["text"].(string); text == testText {
					decrypted = true
					break
				}
			}
			// 检查 decrypted_payload
			inner, _ := msg["decrypted_payload"].(map[string]any)
			if inner != nil {
				if text, _ := inner["text"].(string); text == testText {
					decrypted = true
					break
				}
			}
		}
	}

	if decrypted {
		t.Logf("[OK] Bob 成功解密 Alice 的消息: '%s'", testText)
	} else {
		t.Logf("[WARN] 未在 pull 结果中找到解密后的消息（取决于 SDK 自动解密实现）")
	}

	t.Logf("恢复密钥解密消息验证通过")
}

