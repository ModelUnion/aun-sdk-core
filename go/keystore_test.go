package aun

import (
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
	ks, err := keystore.NewFileKeyStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	return ks, dir
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
	t.Cleanup(func() { ks.Close() })
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
	ks1.Close()

	// 模拟重启
	ks2, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	t.Cleanup(func() { ks2.Close() })
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

func TestFileKeyStore_SaveLoadCertVersion(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.NewFileKeyStore(dir, nil, "seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	aid := "versioned-cert.example"

	priv1, _, _ := testGenerateECKeypair(t)
	cert1 := testMakeSelfSignedCert(t, priv1, aid)
	fp1, err := certSHA256Fingerprint([]byte(cert1))
	if err != nil {
		t.Fatalf("计算 cert1 指纹失败: %v", err)
	}
	if err := ks.SaveCertVersion(aid, cert1, fp1, false); err != nil {
		t.Fatalf("SaveCertVersion(cert1) 失败: %v", err)
	}

	versioned1, err := ks.LoadCertVersion(aid, fp1)
	if err != nil {
		t.Fatalf("LoadCertVersion(cert1) 失败: %v", err)
	}
	if versioned1 != cert1 {
		t.Fatalf("版本化证书内容不匹配")
	}
	active, err := ks.LoadCert(aid)
	if err != nil {
		t.Fatalf("LoadCert 失败: %v", err)
	}
	if active != "" {
		t.Fatalf("makeActive=false 时 active cert 应为空: %q", active)
	}

	priv2, _, _ := testGenerateECKeypair(t)
	cert2 := testMakeSelfSignedCert(t, priv2, aid)
	fp2, err := certSHA256Fingerprint([]byte(cert2))
	if err != nil {
		t.Fatalf("计算 cert2 指纹失败: %v", err)
	}
	if err := ks.SaveCertVersion(aid, cert2, fp2, true); err != nil {
		t.Fatalf("SaveCertVersion(cert2) 失败: %v", err)
	}

	versioned2, err := ks.LoadCertVersion(aid, fp2)
	if err != nil {
		t.Fatalf("LoadCertVersion(cert2) 失败: %v", err)
	}
	if versioned2 != cert2 {
		t.Fatalf("active 版本化证书内容不匹配")
	}
	active, err = ks.LoadCert(aid)
	if err != nil {
		t.Fatalf("LoadCert(active) 失败: %v", err)
	}
	if active != cert2 {
		t.Fatalf("makeActive=true 时应同步更新 active cert")
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

// TestFileKeyStore_UpdateInstanceStateSerializesConcurrentWriters 验证原子 instance state 更新不会互相覆盖
func TestFileKeyStore_UpdateInstanceStateSerializesConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.NewFileKeyStore(dir, nil, "atomic-seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	aid := "atomic.agent.example"

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondDone := make(chan struct{})
	errCh := make(chan error, 2)

	go func() {
		_, err := ks.UpdateInstanceState(aid, "device-a", "", func(state map[string]any) (map[string]any, error) {
			state["field1"] = "value1"
			close(firstEntered)
			<-releaseFirst
			return state, nil
		})
		errCh <- err
	}()

	<-firstEntered

	go func() {
		_, err := ks.UpdateInstanceState(aid, "device-a", "", func(state map[string]any) (map[string]any, error) {
			state["field2"] = "value2"
			return state, nil
		})
		if err == nil {
			close(secondDone)
		}
		errCh <- err
	}()

	select {
	case <-secondDone:
		t.Fatal("第二个 UpdateInstanceState 不应在第一个释放前完成")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("UpdateInstanceState 失败: %v", err)
		}
	}

	loaded, err := ks.LoadInstanceState(aid, "device-a", "")
	if err != nil {
		t.Fatalf("LoadInstanceState 失败: %v", err)
	}
	if loaded["field1"] != "value1" {
		t.Fatal("缺少 field1")
	}
	if loaded["field2"] != "value2" {
		t.Fatal("缺少 field2")
	}
}

// TestFileKeyStore_SaveIdentityPreservesExistingPrekeys 验证 SaveIdentity 不覆盖已有 prekey
func TestFileKeyStore_SaveIdentityPreservesExistingPrekeys(t *testing.T) {
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "identity-preserve.example"

	// 通过 StructuredKeyStore 接口写入 prekey
	if err := ks.SaveE2EEPrekey(aid, "pk1", map[string]any{
		"private_key_pem": "KEEP_ME",
		"created_at":      time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("SaveE2EEPrekey 失败: %v", err)
	}

	// SaveIdentity 写入 token
	if err := ks.SaveIdentity(aid, map[string]any{
		"aid":           aid,
		"access_token":  "tok-new",
		"refresh_token": "rt-new",
	}); err != nil {
		t.Fatalf("SaveIdentity 失败: %v", err)
	}

	// 验证 token 通过 LoadIdentity 可读
	loaded, err := ks.LoadIdentity(aid)
	if err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if loaded["access_token"] != "tok-new" {
		t.Fatalf("access_token 未更新: %v", loaded["access_token"])
	}

	// 验证 prekey 未被覆盖
	prekeys, err := ks.LoadE2EEPrekeys(aid)
	if err != nil {
		t.Fatalf("LoadE2EEPrekeys 失败: %v", err)
	}
	pk1 := prekeys["pk1"]
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
	t.Cleanup(func() { ks.Close() })
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

// TestTokenPersistence 验证 token 通过 SaveIdentity 持久化
func TestTokenPersistence(t *testing.T) {
	dir := t.TempDir()
	ks, _ := keystore.NewFileKeyStore(dir, nil, "seed")
	t.Cleanup(func() { ks.Close() })
	aid := "test-agent.example"

	identity := map[string]any{
		"aid":           aid,
		"access_token":  "at-12345",
		"refresh_token": "rt-67890",
	}
	if err := ks.SaveIdentity(aid, identity); err != nil {
		t.Fatalf("SaveIdentity 失败: %v", err)
	}

	loaded, err := ks.LoadIdentity(aid)
	if err != nil {
		t.Fatalf("LoadIdentity 失败: %v", err)
	}
	if loaded["access_token"] != "at-12345" {
		t.Errorf("access_token 不匹配: %v", loaded["access_token"])
	}
	if loaded["refresh_token"] != "rt-67890" {
		t.Errorf("refresh_token 不匹配: %v", loaded["refresh_token"])
	}

	// 验证 token 不会回落写入 meta.json
	metaFile := filepath.Join(dir, "AIDs", "test-agent.example", "tokens", "meta.json")
	data, _ := os.ReadFile(metaFile)
	if strings.Contains(string(data), "at-12345") {
		t.Error("access_token 不应出现在 meta.json 中")
	}
}

// ── Prekey 持久化测试 ────────────────────────────────────

// TestPrekeyPersistence 验证 prekey 私钥持久化（通过 StructuredKeyStore 接口）
func TestPrekeyPersistence(t *testing.T) {
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "test-agent.example"

	if err := ks.SaveE2EEPrekey(aid, "pk-001", map[string]any{
		"private_key_pem": "-----BEGIN PRIVATE KEY-----\nprekey-data\n-----END PRIVATE KEY-----",
		"created_at":      int64(1700000000000),
	}); err != nil {
		t.Fatalf("SaveE2EEPrekey 失败: %v", err)
	}

	prekeys, err := ks.LoadE2EEPrekeys(aid)
	if err != nil {
		t.Fatalf("LoadE2EEPrekeys 失败: %v", err)
	}
	pkData, ok := prekeys["pk-001"]
	if !ok {
		t.Fatal("prekey pk-001 不存在")
	}
	if pkData["private_key_pem"] != "-----BEGIN PRIVATE KEY-----\nprekey-data\n-----END PRIVATE KEY-----" {
		t.Errorf("prekey 私钥不匹配: %v", pkData["private_key_pem"])
	}
}

// ── Group Secret 持久化测试 ──────────────────────────────

// TestGroupSecretPersistence 验证 group secret 持久化
func TestGroupSecretPersistence(t *testing.T) {
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "test-agent.example"

	if err := ks.SaveGroupSecretState(aid, "group-1", map[string]any{
		"epoch":       int64(1),
		"secret":      "dGVzdC1zZWNyZXQ=", // base64("test-secret")
		"commitment":  "abc123",
		"member_aids": []any{"alice", "bob"},
	}); err != nil {
		t.Fatalf("SaveGroupSecretState 失败: %v", err)
	}

	g1, err := ks.LoadGroupSecretState(aid, "group-1")
	if err != nil {
		t.Fatalf("LoadGroupSecretState 失败: %v", err)
	}
	if g1 == nil {
		t.Fatal("group-1 不存在")
	}
	if g1["secret"] != "dGVzdC1zZWNyZXQ=" {
		t.Errorf("group secret 不匹配: %v", g1["secret"])
	}
}

func TestStructuredPrekeysPrimaryAndRecoverUnexpiredMeta(t *testing.T) {
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "structured-prekeys.example"
	nowMs := time.Now().UnixMilli()

	// 直接写入两个 prekey
	_ = ks.SaveE2EEPrekey(aid, "pk-recover", map[string]any{
		"private_key_pem": "META_RECOVER",
		"created_at":      nowMs,
		"expires_at":      nowMs + int64(time.Minute/time.Millisecond),
	})
	_ = ks.SaveE2EEPrekey(aid, "pk-sql", map[string]any{
		"private_key_pem": "SQLITE_SQL",
		"created_at":      nowMs,
	})

	prekeys, err := ks.LoadE2EEPrekeys(aid)
	if err != nil {
		t.Fatalf("LoadE2EEPrekeys 失败: %v", err)
	}
	if _, ok := prekeys["pk-sql"]; !ok {
		t.Fatal("缺少 pk-sql prekey")
	}
	if _, ok := prekeys["pk-recover"]; !ok {
		t.Fatal("缺少 pk-recover prekey")
	}
}

func TestSaveStructuredPrekeyPreservesRecoverableMetaOnlyRecords(t *testing.T) {
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "structured-prekeys-preserve.example"
	nowMs := time.Now().UnixMilli()

	// 先写入一个 prekey
	if err := ks.SaveE2EEPrekey(aid, "pk-meta", map[string]any{
		"private_key_pem": "META_ONLY",
		"created_at":      nowMs,
	}); err != nil {
		t.Fatalf("SaveE2EEPrekey(pk-meta) 失败: %v", err)
	}

	// 再写入另一个 prekey，不应覆盖第一个
	if err := ks.SaveE2EEPrekey(aid, "pk-new", map[string]any{
		"private_key_pem": "NEW_ONE",
		"created_at":      nowMs,
	}); err != nil {
		t.Fatalf("SaveE2EEPrekey(pk-new) 失败: %v", err)
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
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "structured-group.example"
	nowMs := time.Now().UnixMilli()

	// 写入 group secret（含 old_epochs）
	_ = ks.SaveGroupSecretState(aid, "grp-1", map[string]any{
		"epoch":       int64(3),
		"secret":      "SQLITE_CURRENT",
		"updated_at":  nowMs,
		"member_aids": []any{"alice", "bob"},
		"old_epochs": []any{
			map[string]any{
				"epoch":      int64(1),
				"secret":     "OLD_1",
				"updated_at": nowMs,
				"expires_at": nowMs + int64(time.Minute/time.Millisecond),
			},
			map[string]any{
				"epoch":      int64(2),
				"secret":     "OLD_2",
				"updated_at": nowMs,
				"expires_at": nowMs + int64(time.Minute/time.Millisecond),
			},
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

func TestDeviceScopedPrekeysAllowSamePrekeyAcrossDevices(t *testing.T) {
	ks := testNewFileKeyStoreWithSQLite(t)
	aid := "device-prekeys.example"
	cutoffMs := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()

	if err := ks.SaveE2EEPrekeyForDevice(aid, "phone", "pk-same", map[string]any{
		"private_key_pem": "PHONE",
		"created_at":      cutoffMs - 1000,
	}); err != nil {
		t.Fatalf("SaveE2EEPrekeyForDevice(phone) 失败: %v", err)
	}
	if err := ks.SaveE2EEPrekeyForDevice(aid, "laptop", "pk-same", map[string]any{
		"private_key_pem": "LAPTOP",
		"created_at":      cutoffMs - 1000,
	}); err != nil {
		t.Fatalf("SaveE2EEPrekeyForDevice(laptop) 失败: %v", err)
	}

	phone, err := ks.LoadE2EEPrekeysForDevice(aid, "phone")
	if err != nil {
		t.Fatalf("LoadE2EEPrekeysForDevice(phone) 失败: %v", err)
	}
	laptop, err := ks.LoadE2EEPrekeysForDevice(aid, "laptop")
	if err != nil {
		t.Fatalf("LoadE2EEPrekeysForDevice(laptop) 失败: %v", err)
	}
	legacy, err := ks.LoadE2EEPrekeys(aid)
	if err != nil {
		t.Fatalf("LoadE2EEPrekeys 失败: %v", err)
	}
	if phone["pk-same"]["private_key_pem"] != "PHONE" {
		t.Fatalf("phone prekey 不正确: %v", phone["pk-same"]["private_key_pem"])
	}
	if laptop["pk-same"]["private_key_pem"] != "LAPTOP" {
		t.Fatalf("laptop prekey 不正确: %v", laptop["pk-same"]["private_key_pem"])
	}
	if len(legacy) != 0 {
		t.Fatalf("默认 device prekeys 应为空: %v", legacy)
	}

	removed, err := ks.CleanupE2EEPrekeysForDevice(aid, "phone", cutoffMs, 0)
	if err != nil {
		t.Fatalf("CleanupE2EEPrekeysForDevice(phone) 失败: %v", err)
	}
	if len(removed) != 1 || removed[0] != "pk-same" {
		t.Fatalf("cleanup 结果不正确: %v", removed)
	}

	phone, _ = ks.LoadE2EEPrekeysForDevice(aid, "phone")
	laptop, _ = ks.LoadE2EEPrekeysForDevice(aid, "laptop")
	if len(phone) != 0 {
		t.Fatalf("phone prekeys 应被清空: %v", phone)
	}
	if laptop["pk-same"]["private_key_pem"] != "LAPTOP" {
		t.Fatalf("cleanup 不应影响 laptop: %v", laptop["pk-same"]["private_key_pem"])
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

	identity, err := ks.LoadIdentity("nonexistent.example")
	if err != nil {
		t.Fatalf("加载不存在的身份不应返回错误: %v", err)
	}
	if identity != nil {
		t.Error("加载不存在的身份应返回 nil")
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
	t.Cleanup(func() { ks.Close() })
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

	// token 存储在 SQLite DB 中，key.json 不含明文私钥
	keyFile := filepath.Join(dir, "AIDs", "real-agent.example", "private", "key.json")
	keyData, _ := os.ReadFile(keyFile)
	if strings.Contains(string(keyData), privPEM) {
		t.Error("key.json 不应包含明文私钥")
	}
	ks.Close()
}

func TestFileKeyStore_InstanceStateIsolationAndProtection(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.NewFileKeyStore(dir, nil, "seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	aid := "instance-state.example"

	if err := ks.SaveInstanceState(aid, "device-a", "", map[string]any{
		"access_token": "tok-singleton",
		"kite_token":   "kite-singleton",
		"updated_at":   int64(1),
	}); err != nil {
		t.Fatalf("保存单实例状态失败: %v", err)
	}
	if err := ks.SaveInstanceState(aid, "device-a", "slot-2", map[string]any{
		"access_token": "tok-slot-2",
		"updated_at":   int64(2),
	}); err != nil {
		t.Fatalf("保存多槽位状态失败: %v", err)
	}
	if _, err := ks.UpdateInstanceState(aid, "device-a", "slot-2", func(current map[string]any) (map[string]any, error) {
		current["refresh_token"] = "refresh-slot-2"
		return current, nil
	}); err != nil {
		t.Fatalf("更新多槽位状态失败: %v", err)
	}

	singleton, err := ks.LoadInstanceState(aid, "device-a", "")
	if err != nil {
		t.Fatalf("LoadInstanceState(singleton) 失败: %v", err)
	}
	slot2, err := ks.LoadInstanceState(aid, "device-a", "slot-2")
	if err != nil {
		t.Fatalf("LoadInstanceState(slot-2) 失败: %v", err)
	}
	if singleton["access_token"] != "tok-singleton" {
		t.Fatalf("singleton access_token 不正确: %v", singleton["access_token"])
	}
	if singleton["kite_token"] != "kite-singleton" {
		t.Fatalf("singleton kite_token 不正确: %v", singleton["kite_token"])
	}
	if slot2["access_token"] != "tok-slot-2" {
		t.Fatalf("slot-2 access_token 不正确: %v", slot2["access_token"])
	}
	if slot2["refresh_token"] != "refresh-slot-2" {
		t.Fatalf("slot-2 refresh_token 不正确: %v", slot2["refresh_token"])
	}
	// 验证两个槽位互相隔离
	if singleton["refresh_token"] != nil {
		t.Fatal("singleton 不应有 refresh_token")
	}
	ks.Close()
}
