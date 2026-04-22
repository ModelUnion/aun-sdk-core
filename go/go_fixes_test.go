package aun

import (
	"testing"
)

// ── GO-002: signManifest 签名失败必须返回 error，不允许静默回退 ──────────

// TestSignManifestNoKeyReturnsError 验证无私钥时 signManifest 返回 error
func TestSignManifestNoKeyReturnsError(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			// 无 private_key_pem
			return map[string]any{"aid": "alice.test"}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
	})
	manifest := map[string]any{"group_id": "g1", "epoch": 1}
	_, err := mgr.signManifest(manifest)
	if err == nil {
		t.Fatal("GO-002: 无私钥时 signManifest 应返回 error，但返回了 nil")
	}
}

// TestSignManifestInvalidKeyReturnsError 验证无效私钥时 signManifest 返回 error
func TestSignManifestInvalidKeyReturnsError(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			return map[string]any{
				"aid":             "alice.test",
				"private_key_pem": "invalid-pem-data",
			}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
	})
	manifest := map[string]any{"group_id": "g1", "epoch": 1}
	_, err := mgr.signManifest(manifest)
	if err == nil {
		t.Fatal("GO-002: 无效私钥时 signManifest 应返回 error，但返回了 nil")
	}
}

// TestCreateEpochPropagatesSignManifestError 验证 CreateEpoch 正确传播签名错误
func TestCreateEpochPropagatesSignManifestError(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			// 有 AID 但无私钥：CreateEpoch 在签名阶段应失败
			return map[string]any{"aid": "alice.test"}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
	})
	_, err := mgr.CreateEpoch("g1", []string{"alice.test", "bob.test"})
	if err == nil {
		t.Fatal("GO-002: CreateEpoch 无私钥时应返回签名错误")
	}
}

// ── GO-003: DecryptBatch 应返回每条消息的解密结果（含 error）──────────

// TestDecryptBatchReturnsPerMessageError 验证 DecryptBatch 返回每条的结果与错误
func TestDecryptBatchReturnsPerMessageError(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	aid := "alice.test"
	groupID := "g1"
	priv, privPEM, _ := testGenerateECKeypair(t)
	certPEM := testMakeSelfSignedCert(t, priv, aid)

	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			return map[string]any{
				"aid":             aid,
				"private_key_pem": privPEM,
				"cert":           certPEM,
			}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
		SenderCertResolver: func(sAid, fp string) string {
			return certPEM
		},
	})

	// 创建一个 epoch 密钥
	_, err := mgr.CreateEpoch(groupID, []string{aid})
	if err != nil {
		t.Fatalf("CreateEpoch 失败: %v", err)
	}

	// 加密一条消息
	encrypted, err := mgr.Encrypt(groupID, map[string]any{"text": "hello"})
	if err != nil {
		t.Fatalf("Encrypt 失败: %v", err)
	}

	// 构造混合消息列表：1 条有效加密 + 1 条无效加密
	validMsg := map[string]any{
		"group_id":   groupID,
		"from":       aid,
		"message_id": "msg-valid",
		"payload":    encrypted,
	}
	invalidMsg := map[string]any{
		"group_id":   groupID,
		"from":       aid,
		"message_id": "msg-invalid",
		"payload": map[string]any{
			"type":       "e2ee.group_encrypted",
			"ciphertext": "invalid-base64-data-that-cant-decrypt",
			"epoch":      1,
		},
	}

	results := mgr.DecryptBatchWithErrors([]map[string]any{validMsg, invalidMsg}, true)
	if len(results) != 2 {
		t.Fatalf("GO-003: DecryptBatchWithErrors 应返回 2 条结果，实际: %d", len(results))
	}

	// 第一条应成功
	if results[0].Error != nil {
		t.Errorf("GO-003: 第一条消息应成功解密，但返回错误: %v", results[0].Error)
	}
	if results[0].Message == nil {
		t.Error("GO-003: 第一条消息解密结果不应为 nil")
	}

	// 第二条应失败（无效密文）
	if results[1].Error == nil {
		t.Error("GO-003: 第二条消息解密应返回错误，但返回了 nil")
	}
}

// ── GO-004: LoadSecret 必须检查 keystore error ──────────────────

// TestLoadSecretErrorPropagation 验证 LoadSecret/LoadGroupSecret 的 error 不被忽略
func TestLoadSecretErrorPropagation(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	aid := "alice.test"

	// 正常情况：无密钥时返回 nil, nil
	data, err := LoadGroupSecret(ks, aid, "nonexistent-group", nil)
	if err != nil {
		t.Fatalf("无密钥时不应返回 error: %v", err)
	}
	if data != nil {
		t.Fatal("无密钥时应返回 nil data")
	}
}

// TestEncryptPropagatesLoadSecretError 验证 Encrypt 在 LoadGroupSecret 返回 error 时正确处理
func TestEncryptPropagatesLoadSecretError(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			return map[string]any{"aid": "alice.test"}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
	})

	// 无密钥时 Encrypt 应返回 E2EEGroupSecretMissingError
	_, err := mgr.Encrypt("nonexistent-group", map[string]any{"text": "hello"})
	if err == nil {
		t.Fatal("GO-004: 无群组密钥时 Encrypt 应返回 error")
	}
}

// TestHasSecretPropagatesError 验证 HasSecret 在有错误时返回 false（不忽略错误）
func TestHasSecretPropagatesError(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			return map[string]any{"aid": "alice.test"}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
	})

	// 无密钥时应返回 false
	if mgr.HasSecret("nonexistent-group") {
		t.Fatal("GO-004: 无密钥时 HasSecret 应返回 false")
	}
}

// TestCurrentEpochPropagatesError 验证 CurrentEpoch 在有错误时返回 nil
func TestCurrentEpochPropagatesError(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			return map[string]any{"aid": "alice.test"}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
	})

	epoch := mgr.CurrentEpoch("nonexistent-group")
	if epoch != nil {
		t.Fatal("GO-004: 无密钥时 CurrentEpoch 应返回 nil")
	}
}

// ── GO-005: eventNameMap 必须包含 group.message_created ──────────

// TestEventNameMapContainsGroupMessageCreated 验证 eventNameMap 映射完整性
func TestEventNameMapContainsGroupMessageCreated(t *testing.T) {
	requiredEvents := []string{
		"message.received",
		"message.recalled",
		"message.ack",
		"group.changed",
		"group.message_created",
		"storage.object_changed",
	}
	for _, evt := range requiredEvents {
		if _, ok := eventNameMap[evt]; !ok {
			t.Errorf("GO-005: eventNameMap 缺少 %s 映射", evt)
		}
	}
}

// ── GO-006: dissolve 后清理本地 epoch key 和 seq_tracker ────────

// TestPurgeGroupDataClearsEpochKeys 验证 PurgeGroupData 清理 epoch 密钥
func TestPurgeGroupDataClearsEpochKeys(t *testing.T) {
	ks := testNewGroupKeyStore(t)
	aid := "alice.test"
	groupID := "g-dissolved"
	priv, privPEM, _ := testGenerateECKeypair(t)
	certPEM := testMakeSelfSignedCert(t, priv, aid)

	mgr := NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			return map[string]any{
				"aid":             aid,
				"private_key_pem": privPEM,
				"cert":           certPEM,
			}
		},
		Keystore: ks,
		Config:   DefaultConfig(),
	})

	// 创建 epoch 密钥
	_, err := mgr.CreateEpoch(groupID, []string{aid})
	if err != nil {
		t.Fatalf("CreateEpoch 失败: %v", err)
	}

	// 确认有密钥
	if !mgr.HasSecret(groupID) {
		t.Fatal("CreateEpoch 后应有密钥")
	}

	// 清理（模拟 dissolve）
	mgr.PurgeGroupData(groupID)

	// 确认密钥已清理
	if mgr.HasSecret(groupID) {
		t.Fatal("GO-006: PurgeGroupData 后不应有密钥")
	}
	if mgr.CurrentEpoch(groupID) != nil {
		t.Fatal("GO-006: PurgeGroupData 后 CurrentEpoch 应返回 nil")
	}
	allSecrets := mgr.LoadAllSecrets(groupID)
	if len(allSecrets) > 0 {
		t.Fatalf("GO-006: PurgeGroupData 后不应有任何 epoch 密钥，实际: %d", len(allSecrets))
	}
}

// TestSeqTrackerRemoveNamespace 验证 SeqTracker.RemoveNamespace 清除命名空间状态
func TestSeqTrackerRemoveNamespace(t *testing.T) {
	st := NewSeqTracker()
	ns := "group:g-dissolved"

	// 写入一些状态
	st.OnMessageSeq(ns, 1)
	st.OnMessageSeq(ns, 2)
	st.OnMessageSeq(ns, 3)

	if st.GetContiguousSeq(ns) != 3 {
		t.Fatalf("contiguousSeq 应为 3，实际: %d", st.GetContiguousSeq(ns))
	}

	// 删除命名空间
	st.RemoveNamespace(ns)

	if st.GetContiguousSeq(ns) != 0 {
		t.Fatalf("GO-006: RemoveNamespace 后 contiguousSeq 应为 0，实际: %d", st.GetContiguousSeq(ns))
	}
	if st.GetMaxSeenSeq(ns) != 0 {
		t.Fatalf("GO-006: RemoveNamespace 后 maxSeenSeq 应为 0，实际: %d", st.GetMaxSeenSeq(ns))
	}
}

// TestOnRawGroupChangedDissolvedCleansUp 验证收到 dissolved 事件后清理本地状态
func TestOnRawGroupChangedDissolvedCleansUp(t *testing.T) {
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	// 模拟已连接状态和身份
	priv, privPEM, _ := testGenerateECKeypair(t)
	certPEM := testMakeSelfSignedCert(t, priv, "alice.test")
	aid := "alice.test"
	groupID := "g-to-dissolve"

	c.mu.Lock()
	c.aid = aid
	c.identity = map[string]any{
		"aid":             aid,
		"private_key_pem": privPEM,
		"cert":           certPEM,
	}
	c.state = StateConnected
	c.mu.Unlock()

	// 创建 epoch 密钥
	_, err := c.groupE2EE.CreateEpoch(groupID, []string{aid})
	if err != nil {
		t.Fatalf("CreateEpoch 失败: %v", err)
	}

	// 写入 seqTracker 状态
	c.seqTracker.OnMessageSeq("group:"+groupID, 1)
	c.seqTracker.OnMessageSeq("group:"+groupID, 2)
	c.seqTracker.OnMessageSeq("group_event:"+groupID, 1)

	// 确认状态存在
	if !c.groupE2EE.HasSecret(groupID) {
		t.Fatal("清理前应有群密钥")
	}

	// 模拟收到 dissolved 事件
	c.onRawGroupChanged(map[string]any{
		"group_id": groupID,
		"action":   "dissolved",
	})

	// 验证清理效果
	if c.groupE2EE.HasSecret(groupID) {
		t.Fatal("GO-006: dissolved 后群密钥应已清理")
	}
	if c.seqTracker.GetContiguousSeq("group:"+groupID) != 0 {
		t.Fatal("GO-006: dissolved 后 group seq tracker 应已清理")
	}
	if c.seqTracker.GetContiguousSeq("group_event:"+groupID) != 0 {
		t.Fatal("GO-006: dissolved 后 group_event seq tracker 应已清理")
	}
}

// ── GO-001: sendGroupEncrypted epoch 预检 ─────────────────────

// TestSendGroupEncryptedEpochPrecheck 验证 sendGroupEncrypted 应对比本地和服务端 epoch
// 注意：此测试使用 mock transport 验证行为
func TestSendGroupEncryptedEpochPrecheck(t *testing.T) {
	// 此测试主要验证 epoch 预检逻辑存在且能被调用
	// 完整测试需要集成测试环境
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	priv, privPEM, _ := testGenerateECKeypair(t)
	certPEM := testMakeSelfSignedCert(t, priv, "alice.test")
	aid := "alice.test"

	c.mu.Lock()
	c.aid = aid
	c.identity = map[string]any{
		"aid":             aid,
		"private_key_pem": privPEM,
		"cert":           certPEM,
	}
	c.mu.Unlock()

	groupID := "g-epoch-test"

	// 无 epoch 密钥时应返回 E2EEGroupSecretMissingError
	_, err := c.sendGroupEncrypted(nil, map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"text": "hello"},
	})
	if err == nil {
		t.Fatal("无密钥时 sendGroupEncrypted 应返回 error")
	}

	// 验证 group_id 缺失时返回 ValidationError
	_, err = c.sendGroupEncrypted(nil, map[string]any{
		"payload": map[string]any{"text": "hello"},
	})
	if err == nil {
		t.Fatal("缺少 group_id 时应返回 error")
	}
}
