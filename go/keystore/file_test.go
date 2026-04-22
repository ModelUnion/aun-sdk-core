package keystore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anthropics/aun-sdk-core/go/secretstore"
	_ "modernc.org/sqlite"
)

func TestMetaLocksBounded(t *testing.T) {
	ks, err := NewFileKeyStore(t.TempDir(), nil, "")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
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

// ── GO-008: initSchema 版本迁移框架测试 ──────────────────────

func TestInitSchema_NewDB_SetsCurrentVersion(t *testing.T) {
	// 新建的数据库应记录当前 schema 版本
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	adb, err := newAIDDatabase(dbPath, nil, "")
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
	adb, err := newAIDDatabase(dbPath, nil, "")
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

func TestInitSchema_SameVersion_NoOp(t *testing.T) {
	// 版本相同时不应出错
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "same.db")

	// 第一次创建
	adb1, err := newAIDDatabase(dbPath, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// 写点数据确保不丢
	adb1.SetToken("test_key", "test_value")
	adb1.close()

	// 第二次打开（同版本）
	adb2, err := newAIDDatabase(dbPath, nil, "")
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

// ── ISSUE-GO-002: session 私钥加密存储测试 ──────────────────────

func TestSaveSessionEncryptsDataInDB(t *testing.T) {
	// ISSUE-GO-002: session 数据应通过 SecretStore 加密后存入 DB
	dir := t.TempDir()
	ss, err := secretstore.NewFileSecretStore(dir, "test-seed")
	if err != nil {
		t.Fatalf("创建 SecretStore 失败: %v", err)
	}
	dbPath := filepath.Join(dir, "test.db")
	adb, err := newAIDDatabase(dbPath, ss, "test.aid.com")
	if err != nil {
		t.Fatalf("创建 AIDDatabase 失败: %v", err)
	}
	defer adb.close()

	// 保存包含敏感私钥的 session 数据
	sessionData := map[string]any{
		"private_key_pem": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----",
		"peer_aid":        "peer.aid.com",
		"session_key":     "super-secret-session-key",
	}
	adb.SaveSession("sess-001", sessionData)

	// 直接读取 DB 中的 data_enc 字段，验证不是明文
	var rawEnc string
	row := adb.db.QueryRow("SELECT data_enc FROM e2ee_sessions WHERE session_id = ?", "sess-001")
	if err := row.Scan(&rawEnc); err != nil {
		t.Fatalf("读取 DB 中 session 数据失败: %v", err)
	}

	// 如果 data_enc 中包含明文私钥，说明没有加密
	if strings.Contains(rawEnc, "SECRET") || strings.Contains(rawEnc, "PRIVATE KEY") {
		t.Fatal("ISSUE-GO-002: session 数据在 DB 中应加密存储，但发现明文私钥")
	}

	// 通过正常接口加载，应能解密还原
	loaded := adb.LoadSession("sess-001")
	if loaded == nil {
		t.Fatal("LoadSession 返回 nil")
	}
	if loaded["session_key"] != "super-secret-session-key" {
		t.Fatalf("LoadSession 解密后数据不正确: %v", loaded["session_key"])
	}
}

func TestSaveSessionWithoutSecretStoreFallsBackToPlaintext(t *testing.T) {
	// 无 SecretStore 时应降级为明文存储（向后兼容）
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	adb, err := newAIDDatabase(dbPath, nil, "test.aid.com")
	if err != nil {
		t.Fatalf("创建 AIDDatabase 失败: %v", err)
	}
	defer adb.close()

	sessionData := map[string]any{
		"peer_aid": "peer.aid.com",
	}
	adb.SaveSession("sess-002", sessionData)

	loaded := adb.LoadSession("sess-002")
	if loaded == nil {
		t.Fatal("LoadSession 返回 nil")
	}
	if loaded["peer_aid"] != "peer.aid.com" {
		t.Fatalf("无 SecretStore 时 LoadSession 数据不正确: %v", loaded["peer_aid"])
	}
}

func TestLoadSessionDecryptsLegacyPlaintext(t *testing.T) {
	// 已有明文 session 数据应能正常加载（向后兼容）
	dir := t.TempDir()
	ss, err := secretstore.NewFileSecretStore(dir, "test-seed")
	if err != nil {
		t.Fatalf("创建 SecretStore 失败: %v", err)
	}
	dbPath := filepath.Join(dir, "test.db")

	// 先用无加密的 DB 写入明文数据
	adbPlain, err := newAIDDatabase(dbPath, nil, "test.aid.com")
	if err != nil {
		t.Fatalf("创建 AIDDatabase 失败: %v", err)
	}
	plainData := map[string]any{"peer_aid": "legacy.aid.com", "key": "value"}
	dataJSON, _ := json.Marshal(plainData)
	adbPlain.db.Exec(
		`INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?)`,
		"legacy-sess", string(dataJSON), 1000,
	)
	adbPlain.close()

	// 用带 SecretStore 的 DB 重新打开，应能读取旧明文数据
	adbEnc, err := newAIDDatabase(dbPath, ss, "test.aid.com")
	if err != nil {
		t.Fatalf("重新打开 AIDDatabase 失败: %v", err)
	}
	defer adbEnc.close()

	loaded := adbEnc.LoadSession("legacy-sess")
	if loaded == nil {
		t.Fatal("LoadSession 应能读取旧明文 session 数据")
	}
	if loaded["peer_aid"] != "legacy.aid.com" {
		t.Fatalf("旧明文 session 数据读取不正确: %v", loaded["peer_aid"])
	}
}

// ── ISSUE-GO-003: Windows os.Rename 原子写入测试 ──────────────────

func TestSaveKeyPairOverwriteExisting(t *testing.T) {
	// ISSUE-GO-003: 目标文件已存在时 SaveKeyPair 应成功覆盖
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
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
	ks, err := NewFileKeyStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
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
