package aun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/aun-sdk-core/go/keystore"
	"github.com/anthropics/aun-sdk-core/go/secretstore"
)

func testNewFileKeyStoreWithSQLite(t *testing.T) *keystore.FileKeyStore {
	t.Helper()
	dir := t.TempDir()
	ks, _ := testNewFileKeyStoreWithSQLiteAndDir(t, dir)
	return ks
}

func testNewFileKeyStoreWithSQLiteAndDir(t *testing.T, dir string) (*keystore.FileKeyStore, string) {
	t.Helper()
	backup := keystore.NewSQLiteBackup(filepath.Join(dir, ".aun_backup", "aun_backup.db"))
	t.Cleanup(func() {
		backup.Close()
	})
	ks, err := keystore.NewFileKeyStore(dir, nil, "test-seed", backup)
	if err != nil {
		t.Fatalf("创建带 SQLite 的 FileKeyStore 失败: %v", err)
	}
	return ks, dir
}

func testSeedMetaOnly(t *testing.T, root, aid string, metadata map[string]any) {
	t.Helper()
	safeAid := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(aid)
	metaDir := filepath.Join(root, "AIDs", safeAid, "tokens")
	if err := os.MkdirAll(metaDir, 0o700); err != nil {
		t.Fatalf("创建 meta 目录失败: %v", err)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("序列化 meta-only 数据失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "meta.json"), data, 0o600); err != nil {
		t.Fatalf("写入 meta-only 文件失败: %v", err)
	}
}

// ── FileSecretStore 测试 ─────────────────────────────────

// TestFileSecretStore_ProtectReveal 验证加密保护和还原往返
func TestFileSecretStore_ProtectReveal(t *testing.T) {
	dir := t.TempDir()
	ss, err := secretstore.NewFileSecretStore(dir, "test-seed")
	if err != nil {
		t.Fatalf("创建 FileSecretStore 失败: %v", err)
	}
	plaintext := []byte("hello-secret-data")
	record, err := ss.Protect("scope1", "key1", plaintext)
	if err != nil {
		t.Fatalf("Protect 失败: %v", err)
	}
	if record["scheme"] != "file_aes" {
		t.Errorf("scheme 应为 file_aes: %v", record["scheme"])
	}
	if record["persisted"] != true {
		t.Error("FileSecretStore 应标记 persisted=true")
	}

	revealed, err := ss.Reveal("scope1", "key1", record)
	if err != nil {
		t.Fatalf("Reveal 失败: %v", err)
	}
	if string(revealed) != "hello-secret-data" {
		t.Errorf("还原数据不匹配: %s", string(revealed))
	}
}

// TestFileSecretStore_RestartWithSeed 验证相同 seed 重启后能还原数据
func TestFileSecretStore_RestartWithSeed(t *testing.T) {
	dir := t.TempDir()
	ss1, _ := secretstore.NewFileSecretStore(dir, "stable-seed")
	plaintext := []byte("persistent-data")
	record, _ := ss1.Protect("scope", "name", plaintext)

	// 模拟重启：用相同 seed 创建新实例
	ss2, _ := secretstore.NewFileSecretStore(dir, "stable-seed")
	revealed, err := ss2.Reveal("scope", "name", record)
	if err != nil {
		t.Fatalf("重启后 Reveal 失败: %v", err)
	}
	if string(revealed) != "persistent-data" {
		t.Errorf("重启后数据不匹配: %s", string(revealed))
	}
}

// TestFileSecretStore_WrongSeed 验证错误 seed 无法还原数据
func TestFileSecretStore_WrongSeed(t *testing.T) {
	dir := t.TempDir()
	ss1, _ := secretstore.NewFileSecretStore(dir, "correct-seed")
	plaintext := []byte("secret-data")
	record, _ := ss1.Protect("scope", "name", plaintext)

	// 用错误 seed 创建新实例
	dir2 := t.TempDir()
	ss2, _ := secretstore.NewFileSecretStore(dir2, "wrong-seed")
	revealed, _ := ss2.Reveal("scope", "name", record)
	if revealed != nil && string(revealed) == "secret-data" {
		t.Error("错误 seed 不应能还原数据")
	}
}

// TestFileSecretStore_DifferentScopes 验证不同 scope 互相隔离
func TestFileSecretStore_DifferentScopes(t *testing.T) {
	dir := t.TempDir()
	ss, _ := secretstore.NewFileSecretStore(dir, "seed")

	record1, _ := ss.Protect("scope-a", "name", []byte("data-a"))
	record2, _ := ss.Protect("scope-b", "name", []byte("data-b"))

	rev1, _ := ss.Reveal("scope-a", "name", record1)
	rev2, _ := ss.Reveal("scope-b", "name", record2)

	if string(rev1) != "data-a" {
		t.Errorf("scope-a 数据不正确: %s", string(rev1))
	}
	if string(rev2) != "data-b" {
		t.Errorf("scope-b 数据不正确: %s", string(rev2))
	}

	// 交叉 scope 不应还原
	cross, _ := ss.Reveal("scope-a", "name", record2)
	if cross != nil && string(cross) == "data-b" {
		t.Error("不同 scope 的记录不应交叉还原")
	}
}

// ── FileKeyStore 测试 ────────────────────────────────────

// testNewFileKeyStore 创建测试用 FileKeyStore
func testNewFileKeyStore(t *testing.T) keystore.KeyStore {
	t.Helper()
	dir := t.TempDir()
	ks, err := keystore.NewFileKeyStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	return ks
}

// TestFileKeyStore_SaveLoadKeyPair 验证密钥对保存和加载
func TestFileKeyStore_SaveLoadKeyPair(t *testing.T) {
	ks := testNewFileKeyStore(t)
	aid := "test-agent.example"

	kp := map[string]any{
		"private_key_pem":    "-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----",
		"public_key_der_b64": "dGVzdA==",
		"curve":              "P-256",
	}
	if err := ks.SaveKeyPair(aid, kp); err != nil {
		t.Fatalf("SaveKeyPair 失败: %v", err)
	}

	loaded, err := ks.LoadKeyPair(aid)
	if err != nil {
		t.Fatalf("LoadKeyPair 失败: %v", err)
	}
	if loaded == nil {
		t.Fatal("加载的密钥对不应为 nil")
	}
	if loaded["curve"] != "P-256" {
		t.Errorf("curve 不正确: %v", loaded["curve"])
	}
}

// TestFileKeyStore_KeyPairSurvivesRestart 验证密钥对在重建 KeyStore 后仍可读取
func TestFileKeyStore_KeyPairSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	aid := "test-agent.example"

	ks1, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	_, privPEM, pubB64 := testGenerateECKeypair(t)
	kp := map[string]any{
		"private_key_pem":    privPEM,
		"public_key_der_b64": pubB64,
		"curve":              "P-256",
	}
	_ = ks1.SaveKeyPair(aid, kp)

	// 模拟重启
	ks2, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	loaded, err := ks2.LoadKeyPair(aid)
	if err != nil {
		t.Fatalf("重启后 LoadKeyPair 失败: %v", err)
	}
	if loaded == nil {
		t.Fatal("重启后密钥对不应为 nil")
	}
	if loaded["private_key_pem"] != privPEM {
		t.Error("重启后私钥不匹配")
	}
}

// TestFileKeyStore_SaveLoadCert 验证证书保存和加载
func TestFileKeyStore_SaveLoadCert(t *testing.T) {
	ks := testNewFileKeyStore(t)
	aid := "test-agent.example"
	certPEM := "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----"

	if err := ks.SaveCert(aid, certPEM); err != nil {
		t.Fatalf("SaveCert 失败: %v", err)
	}
	loaded, err := ks.LoadCert(aid)
	if err != nil {
		t.Fatalf("LoadCert 失败: %v", err)
	}
	if loaded != certPEM {
		t.Errorf("证书不匹配: %s", loaded)
	}
}

// TestFileKeyStore_SaveLoadIdentity 验证完整身份保存和加载
func TestFileKeyStore_SaveLoadIdentity(t *testing.T) {
	ks := testNewFileKeyStore(t)
	aid := "test-agent.example"
	_, privPEM, pubB64 := testGenerateECKeypair(t)

	identity := map[string]any{
		"aid":                aid,
		"private_key_pem":    privPEM,
		"public_key_der_b64": pubB64,
		"curve":              "P-256",
		"cert":               "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}
	if err := ks.SaveIdentity(aid, identity); err != nil {
		t.Fatalf("SaveIdentity 失败: %v", err)
	}

	loaded, err := ks.LoadIdentity(aid)
	if err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if loaded == nil {
		t.Fatal("加载的身份不应为 nil")
	}
	if loaded["private_key_pem"] != privPEM {
		t.Error("私钥不匹配")
	}
	if loaded["curve"] != "P-256" {
		t.Error("curve 不匹配")
	}
}

// TestFileKeyStore_UpdateMetadataSerializesConcurrentWriters 验证原子 metadata 更新不会互相覆盖
func TestFileKeyStore_UpdateMetadataSerializesConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.NewFileKeyStore(dir, nil, "atomic-seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	aid := "atomic.agent.example"

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondDone := make(chan struct{})
	errCh := make(chan error, 2)

	go func() {
		_, err := ks.UpdateMetadata(aid, func(metadata map[string]any) (map[string]any, error) {
			prekeys, _ := metadata["e2ee_prekeys"].(map[string]any)
			if prekeys == nil {
				prekeys = make(map[string]any)
			}
			prekeys["pk1"] = map[string]any{"private_key_pem": "PK1"}
			metadata["e2ee_prekeys"] = prekeys
			close(firstEntered)
			<-releaseFirst
			return metadata, nil
		})
		errCh <- err
	}()

	<-firstEntered

	go func() {
		_, err := ks.UpdateMetadata(aid, func(metadata map[string]any) (map[string]any, error) {
			prekeys, _ := metadata["e2ee_prekeys"].(map[string]any)
			if prekeys == nil {
				prekeys = make(map[string]any)
			}
			prekeys["pk2"] = map[string]any{"private_key_pem": "PK2"}
			metadata["e2ee_prekeys"] = prekeys
			return metadata, nil
		})
		if err == nil {
			close(secondDone)
		}
		errCh <- err
	}()

	select {
	case <-secondDone:
		t.Fatal("第二个 updateMetadata 不应在第一个释放前完成")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("UpdateMetadata 失败: %v", err)
		}
	}

	loaded, err := ks.LoadMetadata(aid)
	if err != nil {
		t.Fatalf("LoadMetadata 失败: %v", err)
	}
	prekeys, _ := loaded["e2ee_prekeys"].(map[string]any)
	if _, ok := prekeys["pk1"]; !ok {
		t.Fatal("缺少 pk1")
	}
	if _, ok := prekeys["pk2"]; !ok {
		t.Fatal("缺少 pk2")
	}
}

// TestFileKeyStore_SaveIdentityPreservesExistingPrekeys 验证 SaveIdentity 不覆盖已有 prekey
func TestFileKeyStore_SaveIdentityPreservesExistingPrekeys(t *testing.T) {
	ks := testNewFileKeyStore(t)
	aid := "identity-preserve.example"

	if err := ks.SaveMetadata(aid, map[string]any{
		"e2ee_prekeys": map[string]any{
			"pk1": map[string]any{"private_key_pem": "KEEP_ME"},
		},
	}); err != nil {
		t.Fatalf("SaveMetadata 失败: %v", err)
	}

	if err := ks.SaveIdentity(aid, map[string]any{
		"aid":           aid,
		"access_token":  "tok-new",
		"refresh_token": "rt-new",
	}); err != nil {
		t.Fatalf("SaveIdentity 失败: %v", err)
	}

	loaded, err := ks.LoadMetadata(aid)
	if err != nil {
		t.Fatalf("LoadMetadata 失败: %v", err)
	}
	prekeys, _ := loaded["e2ee_prekeys"].(map[string]any)
	if loaded["access_token"] != "tok-new" {
		t.Fatalf("access_token 未更新: %v", loaded["access_token"])
	}
	pk1, _ := prekeys["pk1"].(map[string]any)
	if pk1["private_key_pem"] != "KEEP_ME" {
		t.Fatalf("prekey 被覆盖: %v", pk1["private_key_pem"])
	}
}

// TestFileKeyStore_MultipleAids 验证多个 AID 互不干扰
func TestFileKeyStore_MultipleAids(t *testing.T) {
	ks := testNewFileKeyStore(t)
	aid1 := "agent-1.example"
	aid2 := "agent-2.example"

	_ = ks.SaveCert(aid1, "cert-1")
	_ = ks.SaveCert(aid2, "cert-2")

	cert1, _ := ks.LoadCert(aid1)
	cert2, _ := ks.LoadCert(aid2)
	if cert1 != "cert-1" {
		t.Errorf("aid1 证书不正确: %s", cert1)
	}
	if cert2 != "cert-2" {
		t.Errorf("aid2 证书不正确: %s", cert2)
	}
}

// TestFileKeyStore_PrivateKeyNotPlaintext 验证私钥不以明文存储在文件中
func TestFileKeyStore_PrivateKeyNotPlaintext(t *testing.T) {
	dir := t.TempDir()
	ks, _ := keystore.NewFileKeyStore(dir, nil, "test-seed")
	aid := "test-agent.example"
	_, privPEM, pubB64 := testGenerateECKeypair(t)

	kp := map[string]any{
		"private_key_pem":    privPEM,
		"public_key_der_b64": pubB64,
		"curve":              "P-256",
	}
	_ = ks.SaveKeyPair(aid, kp)

	// 检查文件中不包含明文私钥
	keyFile := filepath.Join(dir, "AIDs", "test-agent.example", "private", "key.json")
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("读取密钥文件失败: %v", err)
	}
	if strings.Contains(string(data), "BEGIN PRIVATE KEY") {
		t.Error("私钥不应以明文 PEM 存储在文件中")
	}
	// 应包含 private_key_protection
	if !strings.Contains(string(data), "private_key_protection") {
		t.Error("文件中应包含 private_key_protection 字段")
	}
}

// ── Token 持久化测试 ─────────────────────────────────────

// TestTokenPersistence 验证 token 通过 metadata 持久化
func TestTokenPersistence(t *testing.T) {
	dir := t.TempDir()
	ks, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	aid := "test-agent.example"

	metadata := map[string]any{
		"access_token":  "at-12345",
		"refresh_token": "rt-67890",
	}
	if err := ks.SaveMetadata(aid, metadata); err != nil {
		t.Fatalf("SaveMetadata 失败: %v", err)
	}

	loaded, err := ks.LoadMetadata(aid)
	if err != nil {
		t.Fatalf("LoadMetadata 失败: %v", err)
	}
	if loaded["access_token"] != "at-12345" {
		t.Errorf("access_token 不匹配: %v", loaded["access_token"])
	}
	if loaded["refresh_token"] != "rt-67890" {
		t.Errorf("refresh_token 不匹配: %v", loaded["refresh_token"])
	}

	// 验证 token 不以明文存储
	metaFile := filepath.Join(dir, "AIDs", "test-agent.example", "tokens", "meta.json")
	data, _ := os.ReadFile(metaFile)
	if strings.Contains(string(data), "at-12345") {
		t.Error("access_token 不应以明文存储")
	}
}

// ── Prekey 持久化测试 ────────────────────────────────────

// TestPrekeyPersistence 验证 prekey 私钥持久化（通过 metadata）
func TestPrekeyPersistence(t *testing.T) {
	dir := t.TempDir()
	ks, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	aid := "test-agent.example"

	metadata := map[string]any{
		"e2ee_prekeys": map[string]any{
			"pk-001": map[string]any{
				"private_key_pem": "-----BEGIN PRIVATE KEY-----\nprekey-data\n-----END PRIVATE KEY-----",
				"created_at":      int64(1700000000000),
			},
		},
	}
	_ = ks.SaveMetadata(aid, metadata)

	loaded, _ := ks.LoadMetadata(aid)
	prekeys, ok := loaded["e2ee_prekeys"].(map[string]any)
	if !ok {
		t.Fatal("加载的 e2ee_prekeys 类型不正确")
	}
	pkData, ok := prekeys["pk-001"].(map[string]any)
	if !ok {
		t.Fatal("prekey pk-001 不存在或类型不正确")
	}
	if pkData["private_key_pem"] != "-----BEGIN PRIVATE KEY-----\nprekey-data\n-----END PRIVATE KEY-----" {
		t.Errorf("prekey 私钥不匹配: %v", pkData["private_key_pem"])
	}
}

// ── Group Secret 持久化测试 ──────────────────────────────

// TestGroupSecretPersistence 验证 group secret 持久化
func TestGroupSecretPersistence(t *testing.T) {
	dir := t.TempDir()
	ks, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	aid := "test-agent.example"

	metadata := map[string]any{
		"group_secrets": map[string]any{
			"group-1": map[string]any{
				"epoch":       1,
				"secret":      "dGVzdC1zZWNyZXQ=", // base64("test-secret")
				"commitment":  "abc123",
				"member_aids": []any{"alice", "bob"},
			},
		},
	}
	_ = ks.SaveMetadata(aid, metadata)

	loaded, _ := ks.LoadMetadata(aid)
	gs, ok := loaded["group_secrets"].(map[string]any)
	if !ok {
		t.Fatal("group_secrets 类型不正确")
	}
	g1, ok := gs["group-1"].(map[string]any)
	if !ok {
		t.Fatal("group-1 不存在或类型不正确")
	}
	if g1["secret"] != "dGVzdC1zZWNyZXQ=" {
		t.Errorf("group secret 不匹配: %v", g1["secret"])
	}
}

func TestStructuredPrekeysPrimaryAndRecoverUnexpiredMeta(t *testing.T) {
	dir := t.TempDir()
	ks, root := testNewFileKeyStoreWithSQLiteAndDir(t, dir)
	aid := "structured-prekeys.example"

	nowMs := time.Now().UnixMilli()
	testSeedMetaOnly(t, root, aid, map[string]any{
		"e2ee_prekeys": map[string]any{
			"pk-recover": map[string]any{
				"private_key_pem": "META_RECOVER",
				"created_at":      nowMs,
				"updated_at":      nowMs,
				"expires_at":      nowMs + int64(time.Minute/time.Millisecond),
			},
			"pk-expired": map[string]any{
				"private_key_pem": "META_EXPIRED",
				"created_at":      nowMs - int64(8*24*time.Hour/time.Millisecond),
				"updated_at":      nowMs - int64(8*24*time.Hour/time.Millisecond),
				"expires_at":      nowMs - 1,
			},
		},
	})

	if err := ks.SaveE2EEPrekey(aid, "pk-sql", map[string]any{
		"private_key_pem": "SQLITE_SQL",
		"created_at":      nowMs,
	}); err != nil {
		t.Fatalf("SaveE2EEPrekey 失败: %v", err)
	}

	loaded, err := ks.LoadMetadata(aid)
	if err != nil {
		t.Fatalf("LoadMetadata 失败: %v", err)
	}
	prekeys, _ := loaded["e2ee_prekeys"].(map[string]any)
	if _, ok := prekeys["pk-sql"]; !ok {
		t.Fatal("缺少 sqlite 主存 prekey")
	}
	if _, ok := prekeys["pk-recover"]; !ok {
		t.Fatal("缺少从 meta 回捞的未过期 prekey")
	}
	if _, ok := prekeys["pk-expired"]; ok {
		t.Fatal("过期 prekey 不应被回捞")
	}
}

func TestSaveStructuredPrekeyPreservesRecoverableMetaOnlyRecords(t *testing.T) {
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "structured-prekeys-preserve.example"
	nowMs := time.Now().UnixMilli()

	if err := ks.SaveMetadata(aid, map[string]any{
		"e2ee_prekeys": map[string]any{
			"pk-meta": map[string]any{
				"private_key_pem": "META_ONLY",
				"created_at":      nowMs,
			},
		},
	}); err != nil {
		t.Fatalf("SaveMetadata 失败: %v", err)
	}

	if err := ks.SaveE2EEPrekey(aid, "pk-new", map[string]any{
		"private_key_pem": "NEW_ONE",
		"created_at":      nowMs,
	}); err != nil {
		t.Fatalf("SaveE2EEPrekey 失败: %v", err)
	}

	prekeys, err := ks.LoadE2EEPrekeys(aid)
	if err != nil {
		t.Fatalf("LoadE2EEPrekeys 失败: %v", err)
	}
	if prekeys["pk-meta"]["private_key_pem"] != "META_ONLY" {
		t.Fatalf("meta-only prekey 被覆盖: %v", prekeys["pk-meta"]["private_key_pem"])
	}
	if prekeys["pk-new"]["private_key_pem"] != "NEW_ONE" {
		t.Fatalf("新 prekey 未写入: %v", prekeys["pk-new"]["private_key_pem"])
	}
}

func TestStructuredGroupSecretsPrimaryAndRecoverMetaEpochs(t *testing.T) {
	dir := t.TempDir()
	ks, root := testNewFileKeyStoreWithSQLiteAndDir(t, dir)
	aid := "structured-group.example"
	nowMs := time.Now().UnixMilli()

	testSeedMetaOnly(t, root, aid, map[string]any{
		"group_secrets": map[string]any{
			"grp-1": map[string]any{
				"epoch":       2,
				"secret":      "META_CURRENT",
				"updated_at":  nowMs,
				"expires_at":  nowMs + int64(time.Minute/time.Millisecond),
				"member_aids": []any{"alice"},
				"old_epochs": []any{
					map[string]any{
						"epoch":      1,
						"secret":     "META_OLD",
						"updated_at": nowMs,
						"expires_at": nowMs + int64(time.Minute/time.Millisecond),
					},
				},
			},
		},
	})

	backup := keystore.NewSQLiteBackup(filepath.Join(root, ".aun_backup", "aun_backup.db"))
	t.Cleanup(func() {
		backup.Close()
	})
	backup.ReplaceGroupEntries(aid, map[string]map[string]any{
		"grp-1": {
			"epoch":       3,
			"secret":      "SQLITE_CURRENT",
			"updated_at":  nowMs + 1000,
			"member_aids": []any{"alice", "bob"},
		},
	})

	loaded, err := ks.LoadGroupSecretState(aid, "grp-1")
	if err != nil {
		t.Fatalf("LoadGroupSecretState 失败: %v", err)
	}
	if int(toInt64(loaded["epoch"])) != 3 {
		t.Fatalf("当前 epoch 应为 3，实际: %v", loaded["epoch"])
	}
	oldEpochs, _ := loaded["old_epochs"].([]any)
	if len(oldEpochs) != 2 {
		t.Fatalf("应保留两个 old epoch，实际: %d", len(oldEpochs))
	}
}

// ── Metadata 合并保护测试 ────────────────────────────────

// TestMetadataCriticalFieldsMerge 验证关键 metadata 字段不被覆盖
func TestMetadataCriticalFieldsMerge(t *testing.T) {
	dir := t.TempDir()
	ks, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	aid := "test.example"

	// 第一次保存包含 e2ee_prekeys
	meta1 := map[string]any{
		"e2ee_prekeys": map[string]any{
			"pk-1": map[string]any{"private_key_pem": "key1"},
		},
		"other_field": "value1",
	}
	_ = ks.SaveMetadata(aid, meta1)

	// 第二次保存不包含 e2ee_prekeys（应自动合并已有数据）
	meta2 := map[string]any{
		"other_field": "value2",
	}
	_ = ks.SaveMetadata(aid, meta2)

	loaded, _ := ks.LoadMetadata(aid)
	prekeys, ok := loaded["e2ee_prekeys"].(map[string]any)
	if !ok || prekeys == nil {
		t.Error("e2ee_prekeys 不应被覆盖丢失")
	}
	if loaded["other_field"] != "value2" {
		t.Errorf("other_field 应更新为 value2: %v", loaded["other_field"])
	}
}

// TestFileKeyStore_LoadNonExistent 验证加载不存在的 AID 返回 nil
func TestFileKeyStore_LoadNonExistent(t *testing.T) {
	ks := testNewFileKeyStore(t)
	kp, err := ks.LoadKeyPair("nonexistent.example")
	if err != nil {
		t.Fatalf("加载不存在的密钥对不应返回错误: %v", err)
	}
	if kp != nil {
		t.Error("加载不存在的密钥对应返回 nil")
	}

	cert, err := ks.LoadCert("nonexistent.example")
	if err != nil {
		t.Fatalf("加载不存在的证书不应返回错误: %v", err)
	}
	if cert != "" {
		t.Error("加载不存在的证书应返回空字符串")
	}

	meta, err := ks.LoadMetadata("nonexistent.example")
	if err != nil {
		t.Fatalf("加载不存在的元数据不应返回错误: %v", err)
	}
	if meta != nil {
		t.Error("加载不存在的元数据应返回 nil")
	}
}

// TestFileSecretStore_AutoSeed 验证自动生成 seed 文件
func TestFileSecretStore_AutoSeed(t *testing.T) {
	dir := t.TempDir()
	ss, err := secretstore.NewFileSecretStore(dir, "")
	if err != nil {
		t.Fatalf("自动 seed 创建失败: %v", err)
	}
	// 验证 seed 文件存在
	seedPath := filepath.Join(dir, ".seed")
	if _, err := os.Stat(seedPath); os.IsNotExist(err) {
		t.Error(".seed 文件应自动生成")
	}
	// 验证加解密正常工作
	record, _ := ss.Protect("s", "n", []byte("data"))
	revealed, _ := ss.Reveal("s", "n", record)
	if string(revealed) != "data" {
		t.Errorf("自动 seed 加解密不正确: %s", string(revealed))
	}
}

// TestFileKeyStore_SaveIdentity_Roundtrip_WithRealKeys 验证真实密钥的完整往返
func TestFileKeyStore_SaveIdentity_Roundtrip_WithRealKeys(t *testing.T) {
	dir := t.TempDir()
	ks, _ := keystore.NewFileKeyStore(dir, nil, "test-seed")
	aid := "real-agent.example"
	priv, privPEM, pubB64 := testGenerateECKeypair(t)
	certPEM := testMakeSelfSignedCert(t, priv, aid)

	identity := map[string]any{
		"aid": aid, "private_key_pem": privPEM,
		"public_key_der_b64": pubB64, "curve": "P-256",
		"cert":          certPEM,
		"access_token":  "test-at",
		"refresh_token": "test-rt",
	}
	_ = ks.SaveIdentity(aid, identity)

	loaded, err := ks.LoadIdentity(aid)
	if err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if loaded["private_key_pem"] != privPEM {
		t.Error("私钥不匹配")
	}
	if loaded["cert"] != certPEM {
		t.Error("证书不匹配")
	}
	if loaded["access_token"] != "test-at" {
		t.Errorf("access_token 不匹配: %v", loaded["access_token"])
	}

	// 验证磁盘上的 meta.json 不包含明文 token
	metaFile := filepath.Join(dir, "AIDs", "real-agent.example", "tokens", "meta.json")
	fileData, _ := os.ReadFile(metaFile)
	var rawMeta map[string]any
	json.Unmarshal(fileData, &rawMeta)
	if _, hasPlain := rawMeta["access_token"]; hasPlain {
		t.Error("磁盘 meta.json 不应包含明文 access_token")
	}
	if _, hasProtected := rawMeta["access_token_protection"]; !hasProtected {
		t.Error("磁盘 meta.json 应包含 access_token_protection")
	}
}
