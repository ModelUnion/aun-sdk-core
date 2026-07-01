package keystore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelunion/aun-sdk-core/go/secretstore"
	_ "modernc.org/sqlite"
)

func TestMetaLocksBounded(t *testing.T) {
	ks, err := NewLocalIdentityStore(t.TempDir(), nil, "")
	if err != nil {
		t.Fatalf("创建 LocalIdentityStore 失败: %v", err)
	}
	defer ks.Close()

	// 创建超过上限数量的锁
	for i := 0; i < metaLocksLimit+100; i++ {
		ks.getLock(fmt.Sprintf("aid-%d.test", i))
	}

	ks.metaLocksLock.Lock()
	count := len(ks.metaLocks)
	ks.metaLocksLock.Unlock()

	if count > metaLocksLimit {
		t.Fatalf("metaLocks 应被限制在 %d 以内，实际: %d", metaLocksLimit, count)
	}
}

func writeSeedProtectedKeyJSON(t *testing.T, root, aid, seed, plaintext string) map[string]any {
	t.Helper()
	ss, err := secretstore.NewFileSecretStore(root, seed)
	if err != nil {
		t.Fatalf("创建 SecretStore 失败: %v", err)
	}
	rec, err := ss.Protect(aid, "identity/private_key", []byte(plaintext))
	if err != nil {
		t.Fatalf("加密 key.json 私钥失败: %v", err)
	}
	keyPath := filepath.Join(root, "AIDs", aid, "private", "key.json")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"private_key_protection": rec})
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestChangeSeedMigratesKeyJSONAfterPrivateKeyVerification(t *testing.T) {
	dir := t.TempDir()
	aid := "good.agentid.pub"
	writeSeedProtectedKeyJSON(t, dir, aid, "old-seed", "GOOD_PRIVATE")
	if err := os.WriteFile(filepath.Join(dir, ".seed"), []byte("old-seed"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ChangeSeed(dir, ".seed", "")
	if err != nil {
		t.Fatalf("ChangeSeed 失败: %v", err)
	}
	if result.PrivateKeysMigrated != 1 {
		t.Fatalf("应迁移 1 个私钥，实际: %d", result.PrivateKeysMigrated)
	}
	if _, err := os.Stat(filepath.Join(dir, ".seed")); !os.IsNotExist(err) {
		t.Fatalf(".seed 应在迁移成功后被 rename，stat err=%v", err)
	}

	ks, err := NewLocalIdentityStore(dir, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	loaded, err := ks.LoadKeyPair(aid)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["private_key_pem"] != "GOOD_PRIVATE" {
		t.Fatalf("迁移后私钥读取错误: %v", loaded["private_key_pem"])
	}
}

func TestChangeSeedMigratesPlaintextKeyJSON(t *testing.T) {
	dir := t.TempDir()
	aid := "plaintext-change-seed.agentid.pub"
	keyPath := filepath.Join(dir, "AIDs", aid, "private", "key.json")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(`{"private_key_pem":"PLAINTEXT_PRIVATE","public_key_der_b64":"pub","curve":"P-256"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ChangeSeed(dir, "legacy-unused", "new-seed")
	if err != nil {
		t.Fatalf("ChangeSeed 失败: %v", err)
	}
	if result.PrivateKeysMigrated != 1 {
		t.Fatalf("应迁移 1 个明文私钥，实际: %d", result.PrivateKeysMigrated)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PLAINTEXT_PRIVATE") {
		t.Fatal("迁移后 key.json 不应包含明文私钥")
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["private_key_pem"]; ok {
		t.Fatal("迁移后 key.json 不应保留 private_key_pem")
	}
}

func TestChangeSeedWrongOldSeedDoesNotModifyKeyJSON(t *testing.T) {
	dir := t.TempDir()
	aid := "wrong-old-seed.agentid.pub"
	writeSeedProtectedKeyJSON(t, dir, aid, "old-seed", "KEEP_OLD_PRIVATE")
	keyPath := filepath.Join(dir, "AIDs", aid, "private", "key.json")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ChangeSeed(dir, "wrong-seed", "new-seed"); err == nil {
		t.Fatal("ChangeSeed 应因旧 seed 不匹配而失败")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(before) {
		t.Fatal("旧 seed 不匹配时不应修改原 key.json")
	}
}

// ── GO-008: initSchema 版本迁移框架测试 ──────────────────────

func TestInitSchema_NewDB_SetsCurrentVersion(t *testing.T) {
	// 新建的数据库应记录当前 schema 版本
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	adb, err := newAIDDatabase(dbPath, "")
	if err != nil {
		t.Fatalf("创建 AIDDatabase 失败: %v", err)
	}
	defer adb.close()

	var ver int
	row := adb.db.QueryRow("SELECT version FROM _schema_version WHERE id = 1")
	if err := row.Scan(&ver); err != nil {
		t.Fatalf("读取 schema 版本失败: %v", err)
	}
	if ver != aidDBSchemaVersion {
		t.Fatalf("新 DB schema 版本应为 %d，实际: %d", aidDBSchemaVersion, ver)
	}
}

func TestInitSchema_OldVersion_TriggersUpgrade(t *testing.T) {
	// 模拟旧版本数据库 → 打开时应升级版本号
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "old.db")

	// 手动创建旧版本 DB
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// 建所有表
	for _, ddl := range aidDBDDL {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("DDL 执行失败: %v", err)
		}
	}
	// 写入旧版本号 0（低于当前版本）
	if _, err := db.Exec("INSERT INTO _schema_version (id, version) VALUES (1, 0)"); err != nil {
		t.Fatalf("写入旧版本号失败: %v", err)
	}
	db.Close()

	// 重新打开 → initSchema 应检测到旧版本并升级
	adb, err := newAIDDatabase(dbPath, "")
	if err != nil {
		t.Fatalf("打开旧版本 DB 失败: %v", err)
	}
	defer adb.close()

	var ver int
	row := adb.db.QueryRow("SELECT version FROM _schema_version WHERE id = 1")
	if err := row.Scan(&ver); err != nil {
		t.Fatalf("读取 schema 版本失败: %v", err)
	}
	if ver != aidDBSchemaVersion {
		t.Fatalf("旧版本 DB 应升级到 %d，实际: %d", aidDBSchemaVersion, ver)
	}
}

func TestInitSchema_LegacyTablesWithoutVersionGetSlotIDFullColumns(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy-no-version.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE instance_state (
		device_id TEXT NOT NULL,
		slot_id TEXT NOT NULL DEFAULT '_singleton',
		data TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, slot_id)
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE seq_tracker (
		device_id TEXT NOT NULL,
		slot_id TEXT NOT NULL DEFAULT '_singleton',
		namespace TEXT NOT NULL,
		contiguous_seq INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, slot_id, namespace)
	)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	adb, err := newAIDDatabase(dbPath, "")
	if err != nil {
		t.Fatalf("打开旧 schema DB 失败: %v", err)
	}
	defer adb.close()

	adb.SaveInstanceState("device-1", "slot-a", map[string]any{"access_token": "token-a"})
	state := adb.LoadInstanceState("device-1", "slot-a")
	if state["access_token"] != "token-a" {
		t.Fatalf("旧 schema 迁移后应可写入 instance_state，实际: %#v", state)
	}
	adb.SaveSeq("device-1", "slot-a", "inbox", 7)
	if got := adb.LoadSeq("device-1", "slot-a", "inbox"); got != 7 {
		t.Fatalf("旧 schema 迁移后应可写入 seq_tracker，got=%d", got)
	}
}

func TestInitSchema_SameVersion_NoOp(t *testing.T) {
	// 版本相同时不应出错
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "same.db")

	// 第一次创建
	adb1, err := newAIDDatabase(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	// 写点数据确保不丢
	adb1.SetToken("test_key", "test_value")
	adb1.close()

	// 第二次打开（同版本）
	adb2, err := newAIDDatabase(dbPath, "")
	if err != nil {
		t.Fatalf("同版本重新打开失败: %v", err)
	}
	defer adb2.close()

	// 数据不应丢失
	val := adb2.GetToken("test_key")
	if val != "test_value" {
		t.Fatalf("同版本重新打开后数据丢失: 期望 test_value，实际 %q", val)
	}
}

// ── ISSUE-GO-003: Windows os.Rename 原子写入测试 ──────────────────

func TestSaveKeyPairOverwriteExisting(t *testing.T) {
	// ISSUE-GO-003: 目标文件已存在时 SaveKeyPair 应成功覆盖
	dir := t.TempDir()
	ks, err := NewLocalIdentityStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("创建 LocalIdentityStore 失败: %v", err)
	}
	defer ks.Close()

	aid := "overwrite-test.aid.com"
	kp1 := map[string]any{
		"private_key_pem":    "pem-v1",
		"public_key_der_b64": "pub-v1",
		"curve":              "P-256",
	}
	// 第一次写入
	if err := ks.SaveKeyPair(aid, kp1); err != nil {
		t.Fatalf("第一次 SaveKeyPair 失败: %v", err)
	}

	// 第二次覆盖写入（目标文件已存在）
	kp2 := map[string]any{
		"private_key_pem":    "pem-v2",
		"public_key_der_b64": "pub-v2",
		"curve":              "P-256",
	}
	if err := ks.SaveKeyPair(aid, kp2); err != nil {
		t.Fatalf("ISSUE-GO-003: 覆盖写入 SaveKeyPair 失败: %v", err)
	}

	// 验证读取到的是新值
	loaded, err := ks.LoadKeyPair(aid)
	if err != nil {
		t.Fatalf("LoadKeyPair 失败: %v", err)
	}
	if loaded["public_key_der_b64"] != "pub-v2" {
		t.Fatalf("覆盖写入后应读到 pub-v2，实际: %v", loaded["public_key_der_b64"])
	}
}

func TestSaveCertOverwriteExisting(t *testing.T) {
	// ISSUE-GO-003: 目标文件已存在时 SaveCert 应成功覆盖
	dir := t.TempDir()
	ks, err := NewLocalIdentityStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("创建 LocalIdentityStore 失败: %v", err)
	}
	defer ks.Close()

	aid := "cert-overwrite.aid.com"
	if err := ks.SaveCert(aid, "cert-v1"); err != nil {
		t.Fatalf("第一次 SaveCert 失败: %v", err)
	}
	if err := ks.SaveCert(aid, "cert-v2"); err != nil {
		t.Fatalf("ISSUE-GO-003: 覆盖写入 SaveCert 失败: %v", err)
	}

	loaded, err := ks.LoadCert(aid)
	if err != nil {
		t.Fatalf("LoadCert 失败: %v", err)
	}
	if loaded != "cert-v2" {
		t.Fatalf("覆盖写入后应读到 cert-v2，实际: %v", loaded)
	}
}

func TestLoadKeyPairMigratesPlaintextAndWrongSeedPreservesFile(t *testing.T) {
	dir := t.TempDir()
	aid := "legacy-plaintext.agentid.pub"
	keyPath := filepath.Join(dir, "AIDs", aid, "private", "key.json")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(`{"private_key_pem":"LEGACY_PLAINTEXT_PRIVATE","public_key_der_b64":"pub","curve":"P-256"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := NewLocalIdentityStore(dir, nil, "new-seed")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ks.LoadKeyPair(aid)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["private_key_pem"] != "LEGACY_PLAINTEXT_PRIVATE" {
		t.Fatalf("应读取到历史明文私钥，实际: %v", loaded["private_key_pem"])
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "LEGACY_PLAINTEXT_PRIVATE") {
		t.Fatal("load 后 key.json 不应保留明文私钥")
	}

	encryptedDir := t.TempDir()
	ks2, err := NewLocalIdentityStore(encryptedDir, nil, "correct-seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := ks2.SaveKeyPair("wrong-load-seed.agentid.pub", map[string]any{
		"private_key_pem":    "CORRECT_SEED_PRIVATE",
		"public_key_der_b64": "pub",
		"curve":              "P-256",
	}); err != nil {
		t.Fatal(err)
	}
	loadPath := filepath.Join(encryptedDir, "AIDs", "wrong-load-seed.agentid.pub", "private", "key.json")
	before, err := os.ReadFile(loadPath)
	if err != nil {
		t.Fatal(err)
	}
	ksWrong, err := NewLocalIdentityStore(encryptedDir, nil, "wrong-seed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ksWrong.LoadKeyPair("wrong-load-seed.agentid.pub"); err == nil {
		t.Fatal("错误 seed 应返回错误")
	}
	after, err := os.ReadFile(loadPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("错误 seed 不应修改 key.json")
	}
}

func TestLoadPendingKeyPairMigratesPlaintextAndWrongSeedPreservesPending(t *testing.T) {
	dir := t.TempDir()
	aid := "pending-plaintext.agentid.pub"
	ks, err := NewLocalIdentityStore(dir, nil, "pending-seed")
	if err != nil {
		t.Fatal(err)
	}
	pendingDir, err := ks.PendingIdentityDir(aid)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(pendingDir, "private", "key.json")
	if err := os.WriteFile(keyPath, []byte(`{"private_key_pem":"PENDING_PLAINTEXT_PRIVATE","public_key_der_b64":"pub","curve":"P-256"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ks.LoadPendingKeyPair(pendingDir, aid)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["private_key_pem"] != "PENDING_PLAINTEXT_PRIVATE" {
		t.Fatalf("应读取到 pending 明文私钥，实际: %v", loaded["private_key_pem"])
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PENDING_PLAINTEXT_PRIVATE") {
		t.Fatal("pending 读取后不应保留明文私钥")
	}

	wrongDir := t.TempDir()
	ks2, err := NewLocalIdentityStore(wrongDir, nil, "correct-seed")
	if err != nil {
		t.Fatal(err)
	}
	pendingDir2, err := ks2.PendingIdentityDir("pending-wrong-seed.agentid.pub")
	if err != nil {
		t.Fatal(err)
	}
	if err := ks2.SavePendingKeyPair(pendingDir2, "pending-wrong-seed.agentid.pub", map[string]any{
		"private_key_pem":    "PENDING_CORRECT_PRIVATE",
		"public_key_der_b64": "pub",
		"curve":              "P-256",
	}); err != nil {
		t.Fatal(err)
	}
	pendingPath := filepath.Join(pendingDir2, "private", "key.json")
	before, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	ksWrong, err := NewLocalIdentityStore(wrongDir, nil, "wrong-seed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ksWrong.LoadPendingKeyPair(pendingDir2, "pending-wrong-seed.agentid.pub"); err == nil {
		t.Fatal("错误 seed 应返回错误")
	}
	after, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("错误 seed 不应修改 pending key.json")
	}
}

func TestPromotePendingIdentityAfterPendingKeyAndCertSaved(t *testing.T) {
	dir := t.TempDir()
	aid := "pending-promote.agentid.pub"
	ks, err := NewLocalIdentityStore(dir, nil, "pending-seed")
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()

	pendingDir, err := ks.PendingIdentityDir(aid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.SavePendingKeyPair(pendingDir, aid, map[string]any{
		"private_key_pem":    "PENDING_PRIVATE",
		"public_key_der_b64": "PENDING_PUBLIC",
		"curve":              "P-256",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ks.SavePendingCert(pendingDir, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"); err != nil {
		t.Fatal(err)
	}

	target, err := ks.PromotePendingIdentity(pendingDir, aid)
	if err != nil {
		t.Fatalf("PromotePendingIdentity failed: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("promoted identity dir missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "AIDs", "_pending")); err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat pending root failed: %v", err)
	}
}

func TestPromotePendingIdentityPreservesPreexistingMetadataDB(t *testing.T) {
	dir := t.TempDir()
	aid := "pending-metadata.agentid.pub"
	ks, err := NewLocalIdentityStore(dir, nil, "pending-seed")
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()

	if err := ks.SetMetadataValue(aid, "gateway_url", "wss://gateway.agentid.pub/aun"); err != nil {
		t.Fatal(err)
	}
	pendingDir, err := ks.PendingIdentityDir(aid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.SavePendingKeyPair(pendingDir, aid, map[string]any{
		"private_key_pem":    "PENDING_PRIVATE",
		"public_key_der_b64": "PENDING_PUBLIC",
		"curve":              "P-256",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ks.SavePendingCert(pendingDir, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"); err != nil {
		t.Fatal(err)
	}

	target, err := ks.PromotePendingIdentity(pendingDir, aid)
	if err != nil {
		t.Fatalf("PromotePendingIdentity should merge into metadata-only dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "private", "key.json")); err != nil {
		t.Fatalf("promoted key missing: %v", err)
	}
	if got := ks.GetMetadataValue(aid, "gateway_url"); got != "wss://gateway.agentid.pub/aun" {
		t.Fatalf("gateway_url metadata lost: %q", got)
	}
}

func TestChangeSeedCreatesVersionedBackup(t *testing.T) {
	dir := t.TempDir()
	aid := "backup-test.agentid.pub"
	writeSeedProtectedKeyJSON(t, dir, aid, "old-seed", "BACKUP_PRIVATE")

	if _, err := ChangeSeed(dir, "old-seed", "new-seed"); err != nil {
		t.Fatalf("ChangeSeed failed: %v", err)
	}

	keyPath := filepath.Join(dir, "AIDs", aid, "private", "key.json")
	bakPath := keyPath + ".v1"
	if _, err := os.Stat(bakPath); os.IsNotExist(err) {
		t.Fatal("key.json.v1 backup not created after ChangeSeed")
	}
	// .v1 内容应可用旧 seed 解密
	raw, _ := os.ReadFile(bakPath)
	var bakData map[string]any
	if err := json.Unmarshal(raw, &bakData); err != nil {
		t.Fatalf("backup JSON parse failed: %v", err)
	}
	rec, _ := bakData["private_key_protection"].(map[string]any)
	if rec == nil {
		t.Fatal("backup missing private_key_protection")
	}
	oldMaster := deriveSeedMasterKey([]byte("old-seed"))
	plain, ok := decryptSeedRecord(oldMaster, aid, "identity/private_key", rec)
	if !ok || string(plain) != "BACKUP_PRIVATE" {
		t.Fatal("backup not decryptable with old seed")
	}
}

func TestSaveKeyPairCreatesVersionedBackupOnOverwrite(t *testing.T) {
	dir := t.TempDir()
	aid := "overwrite-backup.agentid.pub"
	ks, err := NewLocalIdentityStore(dir, nil, "seed1")
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	ks.SaveKeyPair(aid, map[string]any{"private_key_pem": "FIRST", "public_key_der_b64": "pub", "curve": "P-256"})
	ks.SaveKeyPair(aid, map[string]any{"private_key_pem": "SECOND", "public_key_der_b64": "pub", "curve": "P-256"})

	bakPath := filepath.Join(dir, "AIDs", aid, "private", "key.json.v1")
	if _, err := os.Stat(bakPath); os.IsNotExist(err) {
		t.Fatal("key.json.v1 backup not created on overwrite")
	}
}
