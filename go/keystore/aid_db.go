// aid_db.go — 单个 AID 的 SQLite 数据库（对标 Python sqlcipher_db.py）
//
// 加密方案：Go 无 SQLCipher，敏感字段（private_key_pem、secret、session data）
// 通过 SecretStore.Protect/Reveal 字段级加密后存入 DB。
package keystore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/secretstore"
	_ "modernc.org/sqlite"
)

const (
	aidDBSchemaVersion = 1
	aidDBBusyTimeout   = 5000
)

var aidDBDDL = []string{
	`CREATE TABLE IF NOT EXISTS _schema_version (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS tokens (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS prekeys (
		prekey_id TEXT NOT NULL,
		device_id TEXT NOT NULL DEFAULT '',
		private_key_enc TEXT NOT NULL DEFAULT '',
		data TEXT NOT NULL DEFAULT '{}',
		created_at INTEGER,
		updated_at INTEGER NOT NULL,
		expires_at INTEGER,
		PRIMARY KEY (prekey_id, device_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_prekeys_device ON prekeys (device_id, created_at)`,
	`CREATE TABLE IF NOT EXISTS group_current (
		group_id TEXT PRIMARY KEY,
		epoch INTEGER NOT NULL,
		secret_enc TEXT NOT NULL DEFAULT '',
		data TEXT NOT NULL DEFAULT '{}',
		updated_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS group_old_epochs (
		group_id TEXT NOT NULL,
		epoch INTEGER NOT NULL,
		secret_enc TEXT NOT NULL DEFAULT '',
		data TEXT NOT NULL DEFAULT '{}',
		updated_at INTEGER NOT NULL,
		expires_at INTEGER,
		PRIMARY KEY (group_id, epoch)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_group_old_expires ON group_old_epochs (group_id, expires_at)`,
	`CREATE TABLE IF NOT EXISTS e2ee_sessions (
		session_id TEXT PRIMARY KEY,
		data_enc TEXT NOT NULL DEFAULT '{}',
		updated_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS instance_state (
		device_id TEXT NOT NULL,
		slot_id TEXT NOT NULL DEFAULT '_singleton',
		data TEXT NOT NULL DEFAULT '{}',
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, slot_id)
	)`,
	`CREATE TABLE IF NOT EXISTS seq_tracker (
		device_id TEXT NOT NULL,
		slot_id TEXT NOT NULL DEFAULT '_singleton',
		namespace TEXT NOT NULL,
		contiguous_seq INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, slot_id, namespace)
	)`,
	`CREATE TABLE IF NOT EXISTS metadata_kv (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS agent_md_cache (
		aid TEXT PRIMARY KEY,
		content TEXT NOT NULL DEFAULT '',
		local_etag TEXT NOT NULL DEFAULT '',
		remote_etag TEXT NOT NULL DEFAULT '',
		last_modified TEXT NOT NULL DEFAULT '',
		fetched_at INTEGER NOT NULL DEFAULT 0,
		observed_at INTEGER NOT NULL DEFAULT 0,
		checked_at INTEGER NOT NULL DEFAULT 0,
		remote_status TEXT NOT NULL DEFAULT '',
		verify_status TEXT NOT NULL DEFAULT '',
		verify_error TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL DEFAULT 0
	)`, `CREATE TABLE IF NOT EXISTS group_state (
		group_id TEXT PRIMARY KEY,
		state_version INTEGER NOT NULL DEFAULT 0,
		state_hash TEXT NOT NULL DEFAULT '',
		key_epoch INTEGER NOT NULL DEFAULT 0,
		membership_json TEXT NOT NULL DEFAULT '',
		policy_json TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL DEFAULT 0
	)`,
}

// AIDDatabase 单个 AID 的 SQLite 数据库。
type AIDDatabase struct {
	mu          sync.Mutex
	db          *sql.DB
	dbPath      string
	secretStore secretstore.SecretStore // 字段级加密，nil 时降级为明文
	aid         string                  // 当前 AID 标识，用于 SecretStore scope
}

// newAIDDatabase 创建或打开 AID 数据库。
// ss 和 aid 用于 prekey 私钥字段级加密；ss 为 nil 时降级为明文存储。
func newAIDDatabase(dbPath string, ss secretstore.SecretStore, aid string) (*AIDDatabase, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("创建 AID DB 目录失败: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开 AID DB 失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	adb := &AIDDatabase{db: db, dbPath: dbPath, secretStore: ss, aid: aid}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		pkgLogKeystore().Warn("AIDDatabase WAL setup failed: %v", err)
		if _, lockErr := db.Exec("PRAGMA locking_mode = EXCLUSIVE"); lockErr != nil {
			pkgLogKeystore().Warn("AIDDatabase EXCLUSIVE locking setup failed: %v", lockErr)
		}
		if _, delErr := db.Exec("PRAGMA journal_mode = DELETE"); delErr != nil {
			pkgLogKeystore().Warn("AIDDatabase DELETE journal setup failed: %v", delErr)
		}
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", aidDBBusyTimeout)); err != nil {
		pkgLogKeystore().Warn("AIDDatabase busy_timeout setup failed: %v", err)
	}
	if err := adb.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("AIDDatabase 建表失败: %w", err)
	}
	return adb, nil
}

func (a *AIDDatabase) close() {
	if a.db != nil {
		_ = a.db.Close()
	}
}

func (a *AIDDatabase) initSchema() error {
	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	for _, ddl := range aidDBDDL {
		if _, err := tx.Exec(ddl); err != nil {
			return fmt.Errorf("DDL 执行失败 (%s...): %w", ddl[:min(40, len(ddl))], err)
		}
	}
	var ver int
	row := tx.QueryRow("SELECT version FROM _schema_version WHERE id = 1")
	if err := row.Scan(&ver); err != nil {
		// 首次创建，写入当前版本
		if _, err2 := tx.Exec("INSERT INTO _schema_version (id, version) VALUES (1, ?)", aidDBSchemaVersion); err2 != nil {
			return err2
		}
	} else if ver < aidDBSchemaVersion {
		// 检测到旧版本 → 执行迁移
		if err := migrateSchema(tx, ver, aidDBSchemaVersion); err != nil {
			return fmt.Errorf("schema 迁移失败 (from v%d to v%d): %w", ver, aidDBSchemaVersion, err)
		}
		// 更新版本号
		if _, err := tx.Exec("UPDATE _schema_version SET version = ? WHERE id = 1", aidDBSchemaVersion); err != nil {
			return fmt.Errorf("更新 schema 版本号失败: %w", err)
		}
		pkgLogKeystore().Warn("schema migrated from v%d to v%d", ver, aidDBSchemaVersion)
	}
	return tx.Commit()
}

// migrateSchema 按版本顺序执行增量迁移。
// 当前版本为 1，无需实际迁移操作；预留此函数作为未来版本升级的扩展点。
func migrateSchema(tx *sql.Tx, fromVer, toVer int) error {
	for v := fromVer; v < toVer; v++ {
		switch v {
		// case 1:
		//     // v1 → v2 迁移逻辑（未来添加）
		//     if _, err := tx.Exec("ALTER TABLE ..."); err != nil { return err }
		default:
			// 当前无需迁移操作，仅升级版本号
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func nowMs() int64 { return time.Now().UnixMilli() }

// ── Tokens ───────────────────────────────────────────────────

func (a *AIDDatabase) GetToken(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var val string
	row := a.db.QueryRow("SELECT value FROM tokens WHERE key = ?", key)
	if err := row.Scan(&val); err != nil {
		return ""
	}
	return val
}

func (a *AIDDatabase) SetToken(key, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec(
		"INSERT INTO tokens (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
		key, value, nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SetToken failed (key=%s): %v", key, err)
	}
}

func (a *AIDDatabase) DeleteToken(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM tokens WHERE key = ?", key); err != nil {
		pkgLogKeystore().Warn("DeleteToken failed (key=%s): %v", key, err)
	}
}

func (a *AIDDatabase) GetAllTokens() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query("SELECT key, value FROM tokens")
	if err != nil {
		return nil
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			result[k] = v
		}
	}
	return result
}

// ── Prekeys ──────────────────────────────────────────────────

func (a *AIDDatabase) SavePrekey(prekeyID, privateKeyPEM, deviceID string, createdAt, expiresAt *int64, extraData map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := nowMs()

	// 字段级加密：如果 secretStore 可用且私钥非空，加密后存储
	storedKey := privateKeyPEM
	if a.secretStore != nil && privateKeyPEM != "" {
		scope := safeAID(a.aid)
		rec, err := a.secretStore.Protect(scope, "prekey/"+prekeyID, []byte(privateKeyPEM))
		if err != nil {
			// 加密失败降级为明文，记录日志
			pkgLogKeystore().Warn("SavePrekey encryption failed (id=%s), fallback to plaintext storage: %v", prekeyID, err)
		} else {
			encJSON, err2 := json.Marshal(rec)
			if err2 != nil {
				pkgLogKeystore().Warn("SavePrekey serialize encrypted record failed (id=%s), fallback to plaintext storage: %v", prekeyID, err2)
			} else {
				storedKey = string(encJSON)
			}
		}
	}

	dataJSON, err := json.Marshal(extraData)
	if err != nil {
		pkgLogKeystore().Warn("SavePrekey json.Marshal failed: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(prekey_id, device_id) DO UPDATE SET
		   private_key_enc=excluded.private_key_enc, data=excluded.data,
		   updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
		prekeyID, deviceID, storedKey, string(dataJSON),
		nullInt64Ptr(createdAt, now), now, nullInt64PtrSQL(expiresAt),
	); err != nil {
		pkgLogKeystore().Warn("SavePrekey failed (id=%s): %v", prekeyID, err)
	}
}

func (a *AIDDatabase) LoadPrekeys(deviceID string) map[string]map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query(
		`SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at
		 FROM prekeys WHERE device_id = ?`, deviceID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	result := make(map[string]map[string]any)
	for rows.Next() {
		var id, enc, dataStr string
		var createdAt, updatedAt sql.NullInt64
		var expiresAt sql.NullInt64
		if err := rows.Scan(&id, &enc, &dataStr, &createdAt, &updatedAt, &expiresAt); err != nil {
			continue
		}

		// 字段级解密：尝试将 enc 解析为加密记录并解密
		privateKeyPEM := enc
		if a.secretStore != nil && enc != "" {
			var rec map[string]any
			if err := json.Unmarshal([]byte(enc), &rec); err == nil {
				// 成功解析为 JSON → 尝试解密
				scope := safeAID(a.aid)
				if plain, err2 := a.secretStore.Reveal(scope, "prekey/"+id, rec); err2 != nil {
					pkgLogKeystore().Error("LoadPrekeys decryption failed (id=%s): %v", id, err2)
					// 解密失败保留原始值（可能是旧的明文 PEM）
				} else if plain != nil {
					privateKeyPEM = string(plain)
				}
				// plain == nil 表示 scheme/name 不匹配，保留原始值（明文兼容）
			}
			// JSON 解析失败 → 原始值就是明文 PEM，直接使用
		}

		entry := map[string]any{
			"private_key_pem": privateKeyPEM,
		}
		if createdAt.Valid {
			entry["created_at"] = createdAt.Int64
		}
		if updatedAt.Valid {
			entry["updated_at"] = updatedAt.Int64
		}
		if expiresAt.Valid {
			entry["expires_at"] = expiresAt.Int64
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
			for k, v := range extra {
				entry[k] = v
			}
		}
		result[id] = entry
	}
	return result
}

// LoadPrekeyByID 按 prekey_id 单点查询（WHERE prekey_id = ? LIMIT 1）。
// 解密入站消息时信封里都带 prekey_id，应优先走这条路径，避免 LoadPrekeys 的全量扫描。
// 不限 device_id，与 Python 实现保持一致（兼容旧数据）。未命中返回 nil。
func (a *AIDDatabase) LoadPrekeyByID(prekeyID string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	row := a.db.QueryRow(
		`SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at
		 FROM prekeys WHERE prekey_id = ? LIMIT 1`, prekeyID,
	)
	var id, enc, dataStr string
	var createdAt, updatedAt sql.NullInt64
	var expiresAt sql.NullInt64
	if err := row.Scan(&id, &enc, &dataStr, &createdAt, &updatedAt, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		pkgLogKeystore().Warn("LoadPrekeyByID scan failed (id=%s): %v", prekeyID, err)
		return nil
	}

	// 字段级解密：与 LoadPrekeys 保持一致
	privateKeyPEM := enc
	if a.secretStore != nil && enc != "" {
		var rec map[string]any
		if err := json.Unmarshal([]byte(enc), &rec); err == nil {
			scope := safeAID(a.aid)
			if plain, err2 := a.secretStore.Reveal(scope, "prekey/"+id, rec); err2 != nil {
				pkgLogKeystore().Error("LoadPrekeyByID decryption failed (id=%s): %v", id, err2)
			} else if plain != nil {
				privateKeyPEM = string(plain)
			}
		}
	}

	entry := map[string]any{
		"private_key_pem": privateKeyPEM,
	}
	if createdAt.Valid {
		entry["created_at"] = createdAt.Int64
	}
	if updatedAt.Valid {
		entry["updated_at"] = updatedAt.Int64
	}
	if expiresAt.Valid {
		entry["expires_at"] = expiresAt.Int64
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
		for k, v := range extra {
			entry[k] = v
		}
	}
	return entry
}

func (a *AIDDatabase) DeletePrekey(prekeyID, deviceID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM prekeys WHERE prekey_id = ? AND device_id = ?", prekeyID, deviceID); err != nil {
		pkgLogKeystore().Warn("DeletePrekey failed (id=%s, device=%s): %v", prekeyID, deviceID, err)
	}
}

func (a *AIDDatabase) CleanupPrekeys(deviceID string, cutoffMs int64, keepLatest int) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query(
		"SELECT prekey_id, created_at FROM prekeys WHERE device_id = ? ORDER BY created_at DESC",
		deviceID,
	)
	if err != nil {
		return nil
	}
	type row struct {
		id        string
		createdAt sql.NullInt64
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.createdAt); err == nil {
			all = append(all, r)
		}
	}
	rows.Close()

	latestIDs := make(map[string]bool)
	for i, r := range all {
		if i < keepLatest {
			latestIDs[r.id] = true
		}
	}
	var toDelete []string
	for _, r := range all {
		if latestIDs[r.id] {
			continue
		}
		if r.createdAt.Valid && r.createdAt.Int64 < cutoffMs {
			toDelete = append(toDelete, r.id)
		}
	}
	for _, id := range toDelete {
		if _, err := a.db.Exec("DELETE FROM prekeys WHERE device_id = ? AND prekey_id = ?", deviceID, id); err != nil {
			pkgLogKeystore().Warn("CleanupPrekeys deletefailed (device=%s, id=%s): %v", deviceID, id, err)
		}
	}
	return toDelete
}

// ── Group Current ────────────────────────────────────────────

func (a *AIDDatabase) SaveGroupCurrent(groupID string, epoch int64, secret string, data map[string]any) {
	tStart := time.Now()
	pkgLogKeystore().Debug("SaveGroupCurrent enter: group=%s epoch=%d", groupID, epoch)
	defer func() {
		pkgLogKeystore().Debug("SaveGroupCurrent exit: group=%s epoch=%d elapsed=%dms", groupID, epoch, time.Since(tStart).Milliseconds())
	}()
	a.mu.Lock()
	defer a.mu.Unlock()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		pkgLogKeystore().Warn("SaveGroupCurrent json.Marshal failed: %v", err)
		dataJSON = []byte("{}")
	}
	storedSecret := a.encryptText("group/"+groupID+"/current", secret, "SaveGroupCurrent")
	if _, err := a.db.Exec(
		`INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(group_id) DO UPDATE SET
		   epoch=excluded.epoch, secret_enc=excluded.secret_enc,
		   data=excluded.data, updated_at=excluded.updated_at`,
		groupID, epoch, storedSecret, string(dataJSON), nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SaveGroupCurrent failed (group=%s): %v", groupID, err)
	}
}

func (a *AIDDatabase) LoadGroupCurrent(groupID string) map[string]any {
	tStart := time.Now()
	pkgLogKeystore().Debug("LoadGroupCurrent enter: group=%s", groupID)
	defer func() {
		pkgLogKeystore().Debug("LoadGroupCurrent exit: group=%s elapsed=%dms", groupID, time.Since(tStart).Milliseconds())
	}()
	a.mu.Lock()
	defer a.mu.Unlock()
	var epoch int64
	var enc, dataStr string
	var updatedAt int64
	row := a.db.QueryRow(
		"SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?", groupID,
	)
	if err := row.Scan(&epoch, &enc, &dataStr, &updatedAt); err != nil {
		return nil
	}
	result := map[string]any{
		"group_id":   groupID,
		"epoch":      epoch,
		"secret":     a.decryptText("group/"+groupID+"/current", enc, "LoadGroupCurrent"),
		"updated_at": updatedAt,
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
		for k, v := range extra {
			result[k] = v
		}
	}
	return result
}

func (a *AIDDatabase) LoadGroupSecretEpoch(groupID string, epoch *int) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current, err := a.loadGroupCurrentLocked(groupID)
	if err != nil {
		return nil, err
	}
	if epoch == nil {
		return current, nil
	}
	if current != nil && int(toInt64Local(current["epoch"])) == *epoch {
		return current, nil
	}
	var oldEpoch, updatedAt int64
	var enc, dataStr string
	var expiresAt sql.NullInt64
	row := a.db.QueryRow(
		"SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? AND epoch = ?",
		groupID, *epoch,
	)
	if err := row.Scan(&oldEpoch, &enc, &dataStr, &updatedAt, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	entry := map[string]any{
		"epoch":      oldEpoch,
		"secret":     a.decryptText(fmt.Sprintf("group/%s/epoch/%d", groupID, oldEpoch), enc, "LoadGroupSecretEpoch"),
		"updated_at": updatedAt,
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
		for k, v := range extra {
			entry[k] = v
		}
	}
	if expiresAt.Valid {
		entry["expires_at"] = expiresAt.Int64
	}
	return entry, nil
}

func (a *AIDDatabase) LoadGroupSecretEpochs(groupID string) ([]map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current, err := a.loadGroupCurrentLocked(groupID)
	if err != nil {
		return nil, err
	}
	var result []map[string]any
	if current != nil {
		result = append(result, current)
	}
	rows, err := a.db.Query(
		"SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC",
		groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var oldEpoch, updatedAt int64
		var enc, dataStr string
		var expiresAt sql.NullInt64
		if err := rows.Scan(&oldEpoch, &enc, &dataStr, &updatedAt, &expiresAt); err != nil {
			return nil, err
		}
		entry := map[string]any{
			"epoch":      oldEpoch,
			"secret":     a.decryptText(fmt.Sprintf("group/%s/epoch/%d", groupID, oldEpoch), enc, "LoadGroupSecretEpochs"),
			"updated_at": updatedAt,
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
			for k, v := range extra {
				entry[k] = v
			}
		}
		if expiresAt.Valid {
			entry["expires_at"] = expiresAt.Int64
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}

func (a *AIDDatabase) loadGroupCurrentLocked(groupID string) (map[string]any, error) {
	var epoch int64
	var enc, dataStr string
	var updatedAt int64
	row := a.db.QueryRow(
		"SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?", groupID,
	)
	if err := row.Scan(&epoch, &enc, &dataStr, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	result := map[string]any{
		"group_id":   groupID,
		"epoch":      epoch,
		"secret":     a.decryptText("group/"+groupID+"/current", enc, "LoadGroupCurrent"),
		"updated_at": updatedAt,
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
		for k, v := range extra {
			result[k] = v
		}
	}
	return result, nil
}

func (a *AIDDatabase) LoadAllGroupCurrent() map[string]map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query("SELECT group_id, epoch, secret_enc, data, updated_at FROM group_current")
	if err != nil {
		return nil
	}
	defer rows.Close()
	result := make(map[string]map[string]any)
	for rows.Next() {
		var gid string
		var epoch, updatedAt int64
		var enc, dataStr string
		if err := rows.Scan(&gid, &epoch, &enc, &dataStr, &updatedAt); err != nil {
			continue
		}
		entry := map[string]any{
			"group_id":   gid,
			"epoch":      epoch,
			"secret":     a.decryptText("group/"+gid+"/current", enc, "LoadAllGroupCurrent"),
			"updated_at": updatedAt,
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
			for k, v := range extra {
				entry[k] = v
			}
		}
		result[gid] = entry
	}
	return result
}

func (a *AIDDatabase) DeleteGroupCurrent(groupID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM group_current WHERE group_id = ?", groupID); err != nil {
		pkgLogKeystore().Warn("DeleteGroupCurrent failed (group=%s): %v", groupID, err)
	}
}

// ── Group Old Epochs ─────────────────────────────────────────

func (a *AIDDatabase) SaveGroupOldEpoch(groupID string, epoch int64, secret string, data map[string]any, updatedAt *int64, expiresAt *int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := nowMs()
	if updatedAt != nil {
		now = *updatedAt
	}
	dataJSON, err := json.Marshal(data)
	if err != nil {
		pkgLogKeystore().Warn("SaveGroupOldEpoch json.Marshal failed: %v", err)
		dataJSON = []byte("{}")
	}
	storedSecret := a.encryptText(fmt.Sprintf("group/%s/epoch/%d", groupID, epoch), secret, "SaveGroupOldEpoch")
	if _, err := a.db.Exec(
		`INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(group_id, epoch) DO UPDATE SET
		   secret_enc=excluded.secret_enc, data=excluded.data,
		   updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
		groupID, epoch, storedSecret, string(dataJSON), now, nullInt64PtrSQL(expiresAt),
	); err != nil {
		pkgLogKeystore().Warn("SaveGroupOldEpoch failed (group=%s, epoch=%d): %v", groupID, epoch, err)
	}
}

func (a *AIDDatabase) LoadGroupOldEpochs(groupID string) []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query(
		"SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC",
		groupID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var epoch, updatedAt int64
		var enc, dataStr string
		var expiresAt sql.NullInt64
		if err := rows.Scan(&epoch, &enc, &dataStr, &updatedAt, &expiresAt); err != nil {
			continue
		}
		entry := map[string]any{
			"epoch":      epoch,
			"secret":     a.decryptText(fmt.Sprintf("group/%s/epoch/%d", groupID, epoch), enc, "LoadGroupOldEpochs"),
			"updated_at": updatedAt,
		}
		if expiresAt.Valid {
			entry["expires_at"] = expiresAt.Int64
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(dataStr), &extra); err == nil {
			for k, v := range extra {
				entry[k] = v
			}
		}
		result = append(result, entry)
	}
	return result
}

func (a *AIDDatabase) DeleteAllGroupOldEpochs(groupID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM group_old_epochs WHERE group_id = ?", groupID); err != nil {
		pkgLogKeystore().Warn("DeleteAllGroupOldEpochs failed (group=%s): %v", groupID, err)
	}
}

func (a *AIDDatabase) LoadAllGroupIDsWithOldEpochs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query("SELECT DISTINCT group_id FROM group_old_epochs")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err == nil {
			result = append(result, groupID)
		}
	}
	return result
}

func (a *AIDDatabase) CleanupGroupOldEpochs(groupID string, cutoffMs int64) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	res, err := a.db.Exec(
		`DELETE FROM group_old_epochs WHERE group_id = ? AND updated_at <= ?`,
		groupID, cutoffMs,
	)
	if err != nil {
		pkgLogKeystore().Warn("CleanupGroupOldEpochs failed (group=%s): %v", groupID, err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

func (a *AIDDatabase) StoreGroupSecretTransition(groupID string, opts GroupSecretTransitionOptions) (ok bool, err error) {
	tStart := time.Now()
	pkgLogKeystore().Debug("StoreGroupSecretTransition enter: group=%s", groupID)
	defer func() {
		if err != nil {
			pkgLogKeystore().Debug("StoreGroupSecretTransition exit (error): group=%s ok=%v elapsed=%dms err=%v", groupID, ok, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogKeystore().Debug("StoreGroupSecretTransition exit: group=%s ok=%v elapsed=%dms", groupID, ok, time.Since(tStart).Milliseconds())
		}
	}()
	a.mu.Lock()
	defer a.mu.Unlock()

	tx, err := a.db.Begin()
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	now := nowMs()
	epoch := int64(opts.Epoch)
	members := normalizeStringSlice(opts.MemberAIDs)
	pendingID := strings.TrimSpace(opts.PendingRotationID)

	var currentEpoch, currentUpdatedAt int64
	var currentEnc, currentDataStr string
	row := tx.QueryRow(
		"SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?",
		groupID,
	)
	hasCurrent := true
	if err := row.Scan(&currentEpoch, &currentEnc, &currentDataStr, &currentUpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			hasCurrent = false
		} else {
			return false, err
		}
	}

	if hasCurrent {
		currentSecret := a.decryptText("group/"+groupID+"/current", currentEnc, "StoreGroupSecretTransition")
		currentData := jsonObjectLocal(currentDataStr)
		if epoch < currentEpoch {
			if err := tx.Commit(); err != nil {
				return false, err
			}
			committed = true
			return false, nil
		}
		if epoch == currentEpoch && currentSecret != "" {
			if currentSecret != opts.Secret {
				if strings.TrimSpace(fmt.Sprint(currentData["pending_rotation_id"])) != "" {
					if err := a.upsertGroupCurrentTx(tx, groupID, epoch, opts.Secret, buildGroupCurrentData(opts, members, now), now); err != nil {
						return false, err
					}
					if err := tx.Commit(); err != nil {
						return false, err
					}
					committed = true
					return true, nil
				}
				if err := tx.Commit(); err != nil {
					return false, err
				}
				committed = true
				return false, nil
			}

			updated := copyMapLocal(currentData)
			changed := false
			oldMembers := normalizeStringSliceFromAny(updated["member_aids"])
			if len(members) > 0 && !stringSliceEqualLocal(oldMembers, members) {
				updated["member_aids"] = members
				updated["commitment"] = opts.Commitment
				changed = true
			}
			if opts.EpochChain != "" && updated["epoch_chain"] != opts.EpochChain {
				updated["epoch_chain"] = opts.EpochChain
				changed = true
			}
			if opts.EpochChainUnverifiedSet && opts.EpochChainUnverified {
				if updated["epoch_chain_unverified"] != true {
					updated["epoch_chain_unverified"] = true
					changed = true
				}
				if opts.EpochChainUnverifiedReason != "" && updated["epoch_chain_unverified_reason"] != opts.EpochChainUnverifiedReason {
					updated["epoch_chain_unverified_reason"] = opts.EpochChainUnverifiedReason
					changed = true
				}
			} else if opts.EpochChainUnverifiedSet && (updated["epoch_chain_unverified"] != nil || updated["epoch_chain_unverified_reason"] != nil) {
				delete(updated, "epoch_chain_unverified")
				delete(updated, "epoch_chain_unverified_reason")
				changed = true
			}
			if pendingID != "" && updated["pending_rotation_id"] != pendingID {
				updated["pending_rotation_id"] = pendingID
				updated["pending_created_at"] = now
				changed = true
			}
			if pendingID == "" && updated["pending_rotation_id"] != nil {
				delete(updated, "pending_rotation_id")
				delete(updated, "pending_created_at")
				changed = true
			}
			if changed {
				if err := a.upsertGroupCurrentTx(tx, groupID, epoch, currentSecret, updated, now); err != nil {
					return false, err
				}
			}
			if err := tx.Commit(); err != nil {
				return false, err
			}
			committed = true
			return true, nil
		}
		if currentEpoch != epoch {
			expiresAt := currentUpdatedAt + opts.OldEpochRetentionMillis
			if err := a.upsertGroupOldEpochTx(tx, groupID, currentEpoch, currentSecret, currentData, currentUpdatedAt, &expiresAt); err != nil {
				return false, err
			}
		} else {
			// epoch == currentEpoch 但 currentSecret 为空：合并 data，保留已有字段
			newData := buildGroupCurrentData(opts, members, now)
			if opts.EpochChain == "" {
				if ec, ok := currentData["epoch_chain"].(string); ok && ec != "" {
					newData["epoch_chain"] = ec
				}
			}
			if pendingID == "" {
				if pid, ok := currentData["pending_rotation_id"].(string); ok && pid != "" {
					newData["pending_rotation_id"] = pid
					if pca, ok := currentData["pending_created_at"]; ok {
						newData["pending_created_at"] = pca
					}
				}
			}
			if err := a.upsertGroupCurrentTx(tx, groupID, epoch, opts.Secret, newData, now); err != nil {
				return false, err
			}
			if err := tx.Commit(); err != nil {
				return false, err
			}
			committed = true
			return true, nil
		}
	}

	if err := a.upsertGroupCurrentTx(tx, groupID, epoch, opts.Secret, buildGroupCurrentData(opts, members, now), now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	committed = true
	return true, nil
}

func (a *AIDDatabase) StoreGroupSecretEpoch(groupID string, opts GroupSecretTransitionOptions) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	tx, err := a.db.Begin()
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	now := nowMs()
	epoch := int64(opts.Epoch)
	members := normalizeStringSlice(opts.MemberAIDs)
	pendingID := strings.TrimSpace(opts.PendingRotationID)

	var currentEpoch int64
	var currentEnc, currentDataStr string
	var currentUpdatedAt int64
	row := tx.QueryRow(
		"SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?",
		groupID,
	)
	hasCurrent := true
	if err := row.Scan(&currentEpoch, &currentEnc, &currentDataStr, &currentUpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			hasCurrent = false
		} else {
			return false, err
		}
	}

	if !hasCurrent {
		if err := a.upsertGroupCurrentTx(tx, groupID, epoch, opts.Secret, buildGroupCurrentData(opts, members, now), now); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		committed = true
		return true, nil
	}

	if epoch > currentEpoch {
		// 归档旧 epoch 到 old_epochs，然后用新 epoch 更新 current
		oldSecret := a.decryptText("group/"+groupID+"/current", currentEnc, "StoreGroupSecretEpoch")
		oldData := jsonObjectLocal(currentDataStr)
		expiresAt := now + opts.OldEpochRetentionMillis
		if err := a.upsertGroupOldEpochTx(tx, groupID, currentEpoch, oldSecret, oldData, currentUpdatedAt, &expiresAt); err != nil {
			return false, err
		}
		if err := a.upsertGroupCurrentTx(tx, groupID, epoch, opts.Secret, buildGroupCurrentData(opts, members, now), now); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		committed = true
		return true, nil
	}

	if epoch == currentEpoch {
		currentSecret := a.decryptText("group/"+groupID+"/current", currentEnc, "StoreGroupSecretEpoch")
		currentData := jsonObjectLocal(currentDataStr)
		if currentSecret != "" && currentSecret != opts.Secret {
			if strings.TrimSpace(fmt.Sprint(currentData["pending_rotation_id"])) == "" {
				if err := tx.Commit(); err != nil {
					return false, err
				}
				committed = true
				return false, nil
			}
			if err := a.upsertGroupCurrentTx(tx, groupID, epoch, opts.Secret, buildGroupCurrentData(opts, members, now), now); err != nil {
				return false, err
			}
			if err := tx.Commit(); err != nil {
				return false, err
			}
			committed = true
			return true, nil
		}

		updated := copyMapLocal(currentData)
		changed := false
		oldMembers := normalizeStringSliceFromAny(updated["member_aids"])
		if len(members) > 0 && !stringSliceEqualLocal(oldMembers, members) {
			updated["member_aids"] = members
			updated["commitment"] = opts.Commitment
			changed = true
		}
		if opts.EpochChain != "" && updated["epoch_chain"] != opts.EpochChain {
			updated["epoch_chain"] = opts.EpochChain
			changed = true
		}
		if opts.EpochChainUnverifiedSet && opts.EpochChainUnverified {
			if updated["epoch_chain_unverified"] != true {
				updated["epoch_chain_unverified"] = true
				changed = true
			}
			if opts.EpochChainUnverifiedReason != "" && updated["epoch_chain_unverified_reason"] != opts.EpochChainUnverifiedReason {
				updated["epoch_chain_unverified_reason"] = opts.EpochChainUnverifiedReason
				changed = true
			}
		} else if opts.EpochChainUnverifiedSet && (updated["epoch_chain_unverified"] != nil || updated["epoch_chain_unverified_reason"] != nil) {
			delete(updated, "epoch_chain_unverified")
			delete(updated, "epoch_chain_unverified_reason")
			changed = true
		}
		if pendingID != "" && updated["pending_rotation_id"] != pendingID {
			updated["pending_rotation_id"] = pendingID
			updated["pending_created_at"] = now
			changed = true
		}
		if pendingID == "" && updated["pending_rotation_id"] != nil {
			delete(updated, "pending_rotation_id")
			delete(updated, "pending_created_at")
			changed = true
		}
		if changed {
			if err := a.upsertGroupCurrentTx(tx, groupID, epoch, currentSecret, updated, now); err != nil {
				return false, err
			}
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		committed = true
		return true, nil
	}

	var oldEnc string
	oldRow := tx.QueryRow(
		"SELECT secret_enc FROM group_old_epochs WHERE group_id = ? AND epoch = ?",
		groupID, epoch,
	)
	if err := oldRow.Scan(&oldEnc); err != nil && err != sql.ErrNoRows {
		return false, err
	} else if err == nil {
		oldSecret := a.decryptText(fmt.Sprintf("group/%s/epoch/%d", groupID, epoch), oldEnc, "StoreGroupSecretEpoch")
		if oldSecret != "" && oldSecret != opts.Secret {
			if err := tx.Commit(); err != nil {
				return false, err
			}
			committed = true
			return false, nil
		}
	}

	expiresAt := now + opts.OldEpochRetentionMillis
	if err := a.upsertGroupOldEpochTx(tx, groupID, epoch, opts.Secret, buildGroupCurrentData(opts, members, now), now, &expiresAt); err != nil {
		return false, err
	}
	_ = currentUpdatedAt
	if err := tx.Commit(); err != nil {
		return false, err
	}
	committed = true
	return true, nil
}

func (a *AIDDatabase) DiscardPendingGroupSecretState(groupID string, epoch int, rotationID string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rid := strings.TrimSpace(rotationID)
	if rid == "" {
		return false, nil
	}
	tx, err := a.db.Begin()
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var currentEpoch int64
	var dataStr string
	row := tx.QueryRow("SELECT epoch, data FROM group_current WHERE group_id = ?", groupID)
	if err := row.Scan(&currentEpoch, &dataStr); err != nil {
		if err == sql.ErrNoRows {
			_ = tx.Commit()
			committed = true
			return false, nil
		}
		return false, err
	}
	if int(currentEpoch) != epoch {
		_ = tx.Commit()
		committed = true
		return false, nil
	}
	data := jsonObjectLocal(dataStr)
	if strings.TrimSpace(fmt.Sprint(data["pending_rotation_id"])) != rid {
		_ = tx.Commit()
		committed = true
		return false, nil
	}

	var oldEpoch, oldUpdatedAt int64
	var oldEnc, oldData string
	var oldExpires sql.NullInt64
	oldRow := tx.QueryRow(
		"SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? AND epoch < ? ORDER BY epoch DESC LIMIT 1",
		groupID, epoch,
	)
	if err := oldRow.Scan(&oldEpoch, &oldEnc, &oldData, &oldUpdatedAt, &oldExpires); err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
		if _, err := tx.Exec("DELETE FROM group_current WHERE group_id = ?", groupID); err != nil {
			return false, err
		}
		if _, err := tx.Exec("DELETE FROM group_old_epochs WHERE group_id = ?", groupID); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		committed = true
		return true, nil
	}
	secret := a.decryptText(fmt.Sprintf("group/%s/epoch/%d", groupID, oldEpoch), oldEnc, "DiscardPendingGroupSecretState")
	if err := a.upsertGroupCurrentTx(tx, groupID, oldEpoch, secret, jsonObjectLocal(oldData), nowMs()); err != nil {
		return false, err
	}
	if _, err := tx.Exec("DELETE FROM group_old_epochs WHERE group_id = ? AND epoch = ?", groupID, oldEpoch); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	committed = true
	return true, nil
}

func (a *AIDDatabase) upsertGroupCurrentTx(tx *sql.Tx, groupID string, epoch int64, secret string, data map[string]any, updatedAt int64) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		dataJSON = []byte("{}")
	}
	storedSecret := a.encryptText("group/"+groupID+"/current", secret, "StoreGroupSecretTransition")
	_, err = tx.Exec(
		`INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(group_id) DO UPDATE SET
		   epoch=excluded.epoch, secret_enc=excluded.secret_enc,
		   data=excluded.data, updated_at=excluded.updated_at`,
		groupID, epoch, storedSecret, string(dataJSON), updatedAt,
	)
	return err
}

func (a *AIDDatabase) upsertGroupOldEpochTx(tx *sql.Tx, groupID string, epoch int64, secret string, data map[string]any, updatedAt int64, expiresAt *int64) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		dataJSON = []byte("{}")
	}
	storedSecret := a.encryptText(fmt.Sprintf("group/%s/epoch/%d", groupID, epoch), secret, "StoreGroupSecretTransition")
	_, err = tx.Exec(
		`INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(group_id, epoch) DO UPDATE SET
		   secret_enc=excluded.secret_enc, data=excluded.data,
		   updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
		groupID, epoch, storedSecret, string(dataJSON), updatedAt, nullInt64PtrSQL(expiresAt),
	)
	return err
}

// ── E2EE Sessions ────────────────────────────────────────────

func (a *AIDDatabase) SaveSession(sessionID string, data map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		pkgLogKeystore().Warn("SaveSession json.Marshal failed: %v", err)
		dataJSON = []byte("{}")
	}

	// 字段级加密：如果 secretStore 可用，加密整个 session 数据
	stored := string(dataJSON)
	if a.secretStore != nil {
		scope := safeAID(a.aid)
		rec, err := a.secretStore.Protect(scope, "session/"+sessionID, dataJSON)
		if err != nil {
			pkgLogKeystore().Warn("SaveSession encryption failed (id=%s), fallback to plaintext storage: %v", sessionID, err)
		} else {
			encJSON, err2 := json.Marshal(rec)
			if err2 != nil {
				pkgLogKeystore().Warn("SaveSession serialize encrypted record failed (id=%s), fallback to plaintext storage: %v", sessionID, err2)
			} else {
				stored = string(encJSON)
			}
		}
	}

	if _, err := a.db.Exec(
		`INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(session_id) DO UPDATE SET data_enc=excluded.data_enc, updated_at=excluded.updated_at`,
		sessionID, stored, nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SaveSession failed (id=%s): %v", sessionID, err)
	}
}

func (a *AIDDatabase) LoadSession(sessionID string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	var enc string
	var updatedAt int64
	row := a.db.QueryRow("SELECT data_enc, updated_at FROM e2ee_sessions WHERE session_id = ?", sessionID)
	if err := row.Scan(&enc, &updatedAt); err != nil {
		return nil
	}
	plain := a.decryptSessionData(sessionID, enc)
	var result map[string]any
	if err := json.Unmarshal([]byte(plain), &result); err != nil {
		return nil
	}
	result["session_id"] = sessionID
	result["updated_at"] = updatedAt
	return result
}

func (a *AIDDatabase) LoadAllSessions() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query("SELECT session_id, data_enc, updated_at FROM e2ee_sessions")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var sid, enc string
		var updatedAt int64
		if err := rows.Scan(&sid, &enc, &updatedAt); err != nil {
			continue
		}
		plain := a.decryptSessionData(sid, enc)
		var entry map[string]any
		if err := json.Unmarshal([]byte(plain), &entry); err != nil {
			continue
		}
		entry["session_id"] = sid
		entry["updated_at"] = updatedAt
		result = append(result, entry)
	}
	return result
}

func (a *AIDDatabase) DeleteSession(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM e2ee_sessions WHERE session_id = ?", sessionID); err != nil {
		pkgLogKeystore().Warn("DeleteSession failed (id=%s): %v", sessionID, err)
	}
}

// decryptSessionData 尝试解密 session 数据，兼容旧明文格式
func (a *AIDDatabase) decryptSessionData(sessionID, enc string) string {
	return a.decryptText("session/"+sessionID, enc, "LoadSession")
}

func (a *AIDDatabase) encryptText(name, plaintext, label string) string {
	if a.secretStore == nil || plaintext == "" {
		return plaintext
	}
	rec, err := a.secretStore.Protect(safeAID(a.aid), name, []byte(plaintext))
	if err != nil {
		pkgLogKeystore().Warn("%s encryption failed (name=%s), fallback to plaintext storage: %v", label, name, err)
		return plaintext
	}
	encJSON, err := json.Marshal(rec)
	if err != nil {
		pkgLogKeystore().Warn("%s serialize encrypted record failed (name=%s), fallback to plaintext storage: %v", label, name, err)
		return plaintext
	}
	return string(encJSON)
}

func (a *AIDDatabase) decryptText(name, enc, label string) string {
	if a.secretStore == nil || enc == "" {
		return enc
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(enc), &rec); err == nil {
		if plain, err2 := a.secretStore.Reveal(safeAID(a.aid), name, rec); err2 != nil {
			pkgLogKeystore().Error("%s decryption failed (name=%s): %v", label, name, err2)
		} else if plain != nil {
			return string(plain)
		}
	}
	return enc
}

// ── Instance State ───────────────────────────────────────────

func (a *AIDDatabase) SaveInstanceState(deviceID, slotID string, state map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if slotID == "" {
		slotID = "_singleton"
	}
	dataJSON, err := json.Marshal(state)
	if err != nil {
		pkgLogKeystore().Warn("SaveInstanceState json.Marshal failed: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO instance_state (device_id, slot_id, data, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(device_id, slot_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`,
		deviceID, slotID, string(dataJSON), nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SaveInstanceState failed (device=%s, slot=%s): %v", deviceID, slotID, err)
	}
}

func (a *AIDDatabase) LoadInstanceState(deviceID, slotID string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if slotID == "" {
		slotID = "_singleton"
	}
	var dataStr string
	row := a.db.QueryRow("SELECT data FROM instance_state WHERE device_id = ? AND slot_id = ?", deviceID, slotID)
	if err := row.Scan(&dataStr); err != nil {
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(dataStr), &result); err != nil {
		return nil
	}
	return result
}

// ── Seq Tracker ─────────────────────────────────────────────

func (a *AIDDatabase) SaveSeq(deviceID, slotID, namespace string, contiguousSeq int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if slotID == "" {
		slotID = "_singleton"
	}
	if _, err := a.db.Exec(
		`INSERT INTO seq_tracker (device_id, slot_id, namespace, contiguous_seq, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, slot_id, namespace)
		 DO UPDATE SET contiguous_seq=excluded.contiguous_seq, updated_at=excluded.updated_at`,
		deviceID, slotID, namespace, contiguousSeq, nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SaveSeq failed (device=%s, ns=%s): %v", deviceID, namespace, err)
	}
}

func (a *AIDDatabase) LoadSeq(deviceID, slotID, namespace string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if slotID == "" {
		slotID = "_singleton"
	}
	var seq int
	row := a.db.QueryRow(
		"SELECT contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?",
		deviceID, slotID, namespace,
	)
	if err := row.Scan(&seq); err != nil {
		return 0
	}
	return seq
}

func (a *AIDDatabase) LoadAllSeqs(deviceID, slotID string) map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if slotID == "" {
		slotID = "_singleton"
	}
	rows, err := a.db.Query(
		"SELECT namespace, contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ?",
		deviceID, slotID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	result := make(map[string]int)
	for rows.Next() {
		var ns string
		var seq int
		if err := rows.Scan(&ns, &seq); err == nil {
			result[ns] = seq
		}
	}
	return result
}

// DeleteSeq 删除单个 namespace 的 contiguous_seq 行。
func (a *AIDDatabase) DeleteSeq(deviceID, slotID, namespace string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if slotID == "" {
		slotID = "_singleton"
	}
	_, err := a.db.Exec(
		"DELETE FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?",
		deviceID, slotID, namespace,
	)
	return err
}

// ── Metadata KV ──────────────────────────────────────────────

func (a *AIDDatabase) GetMetadata(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var val string
	row := a.db.QueryRow("SELECT value FROM metadata_kv WHERE key = ?", key)
	if err := row.Scan(&val); err != nil {
		return ""
	}
	return val
}

func (a *AIDDatabase) SetMetadata(key, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec(
		"INSERT INTO metadata_kv (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
		key, value, nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SetMetadata failed (key=%s): %v", key, err)
	}
}

func (a *AIDDatabase) DeleteMetadata(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM metadata_kv WHERE key = ?", key); err != nil {
		pkgLogKeystore().Warn("DeleteMetadata failed (key=%s): %v", key, err)
	}
}

func (a *AIDDatabase) GetAllMetadata() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.Query("SELECT key, value FROM metadata_kv")
	if err != nil {
		return nil
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			result[k] = v
		}
	}
	return result
}

// ── 工具函数 ─────────────────────────────────────────────────

func nullInt64Ptr(p *int64, fallback int64) any {
	if p != nil {
		return *p
	}
	return fallback
}

func nullInt64PtrSQL(p *int64) sql.NullInt64 {
	if p != nil {
		return sql.NullInt64{Int64: *p, Valid: true}
	}
	return sql.NullInt64{}
}

func buildGroupCurrentData(opts GroupSecretTransitionOptions, members []string, now int64) map[string]any {
	data := map[string]any{
		"commitment":  opts.Commitment,
		"member_aids": members,
	}
	if opts.EpochChain != "" {
		data["epoch_chain"] = opts.EpochChain
	}
	if strings.TrimSpace(opts.PendingRotationID) != "" {
		data["pending_rotation_id"] = strings.TrimSpace(opts.PendingRotationID)
		data["pending_created_at"] = now
	}
	if opts.EpochChainUnverifiedSet && opts.EpochChainUnverified {
		data["epoch_chain_unverified"] = true
		if opts.EpochChainUnverifiedReason != "" {
			data["epoch_chain_unverified_reason"] = opts.EpochChainUnverifiedReason
		}
	}
	return data
}

func jsonObjectLocal(data string) map[string]any {
	var result map[string]any
	if err := json.Unmarshal([]byte(data), &result); err != nil || result == nil {
		return map[string]any{}
	}
	return result
}

func copyMapLocal(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func normalizeStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		s := strings.TrimSpace(v)
		if s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeStringSliceFromAny(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return normalizeStringSlice(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	default:
		return nil
	}
}

func stringSliceEqualLocal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func toInt64Local(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case int32:
		return int64(x)
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	default:
		return 0
	}
}

// ── Agent.md Cache ───────────────────────────────────────────

type agentMDCacheScanner interface {
	Scan(dest ...any) error
}

func scanAgentMDCacheRecord(scanner agentMDCacheScanner) (*AgentMDCacheRecord, error) {
	var rec AgentMDCacheRecord
	err := scanner.Scan(
		&rec.AID,
		&rec.Content,
		&rec.LocalEtag,
		&rec.RemoteEtag,
		&rec.LastModified,
		&rec.FetchedAt,
		&rec.ObservedAt,
		&rec.CheckedAt,
		&rec.RemoteStatus,
		&rec.VerifyStatus,
		&rec.VerifyError,
		&rec.LastError,
		&rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func applyAgentMDCacheUpsert(rec *AgentMDCacheRecord, fields AgentMDCacheUpsert) {
	if fields.Content != nil {
		rec.Content = *fields.Content
	}
	if fields.LocalEtag != nil {
		rec.LocalEtag = *fields.LocalEtag
	}
	if fields.RemoteEtag != nil {
		rec.RemoteEtag = *fields.RemoteEtag
	}
	if fields.LastModified != nil {
		rec.LastModified = *fields.LastModified
	}
	if fields.FetchedAt != nil {
		rec.FetchedAt = *fields.FetchedAt
	}
	if fields.ObservedAt != nil {
		rec.ObservedAt = *fields.ObservedAt
	}
	if fields.CheckedAt != nil {
		rec.CheckedAt = *fields.CheckedAt
	}
	if fields.RemoteStatus != nil {
		rec.RemoteStatus = *fields.RemoteStatus
	}
	if fields.VerifyStatus != nil {
		rec.VerifyStatus = *fields.VerifyStatus
	}
	if fields.VerifyError != nil {
		rec.VerifyError = *fields.VerifyError
	}
	if fields.LastError != nil {
		rec.LastError = *fields.LastError
	}
	rec.UpdatedAt = nowMs()
}

func (a *AIDDatabase) LoadAgentMDCache(aid string) (*AgentMDCacheRecord, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, err := scanAgentMDCacheRecord(a.db.QueryRow(
		`SELECT aid, content, local_etag, remote_etag, last_modified,
			fetched_at, observed_at, checked_at, remote_status, verify_status,
			verify_error, last_error, updated_at
		 FROM agent_md_cache WHERE aid = ?`,
		target,
	))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (a *AIDDatabase) UpsertAgentMDCache(aid string, fields AgentMDCacheUpsert) (*AgentMDCacheRecord, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, fmt.Errorf("UpsertAgentMDCache requires non-empty aid")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	rec, err := scanAgentMDCacheRecord(a.db.QueryRow(
		`SELECT aid, content, local_etag, remote_etag, last_modified,
			fetched_at, observed_at, checked_at, remote_status, verify_status,
			verify_error, last_error, updated_at
		 FROM agent_md_cache WHERE aid = ?`,
		target,
	))
	if err == sql.ErrNoRows {
		rec = &AgentMDCacheRecord{AID: target}
	} else if err != nil {
		return nil, err
	}

	applyAgentMDCacheUpsert(rec, fields)
	_, err = a.db.Exec(
		`INSERT INTO agent_md_cache
			(aid, content, local_etag, remote_etag, last_modified,
			 fetched_at, observed_at, checked_at, remote_status, verify_status,
			 verify_error, last_error, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(aid) DO UPDATE SET
			content=excluded.content,
			local_etag=excluded.local_etag,
			remote_etag=excluded.remote_etag,
			last_modified=excluded.last_modified,
			fetched_at=excluded.fetched_at,
			observed_at=excluded.observed_at,
			checked_at=excluded.checked_at,
			remote_status=excluded.remote_status,
			verify_status=excluded.verify_status,
			verify_error=excluded.verify_error,
			last_error=excluded.last_error,
			updated_at=excluded.updated_at`,
		rec.AID,
		rec.Content,
		rec.LocalEtag,
		rec.RemoteEtag,
		rec.LastModified,
		rec.FetchedAt,
		rec.ObservedAt,
		rec.CheckedAt,
		rec.RemoteStatus,
		rec.VerifyStatus,
		rec.VerifyError,
		rec.LastError,
		rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	out := *rec
	return &out, nil
}

// ── Group State ──────────────────────────────────────────────

// SaveGroupState 保存群组 state_hash 状态（UPSERT）
func (a *AIDDatabase) SaveGroupState(groupID string, stateVersion int64, stateHash string, keyEpoch int64, membershipJSON, policyJSON string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.db.Exec(
		`INSERT INTO group_state (group_id, state_version, state_hash, key_epoch, membership_json, policy_json, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(group_id) DO UPDATE SET
		   state_version=excluded.state_version,
		   state_hash=excluded.state_hash,
		   key_epoch=excluded.key_epoch,
		   membership_json=excluded.membership_json,
		   policy_json=excluded.policy_json,
		   updated_at=excluded.updated_at`,
		groupID, stateVersion, stateHash, keyEpoch, membershipJSON, policyJSON, nowMs(),
	)
	if err != nil {
		return fmt.Errorf("SaveGroupState 失败 (group=%s): %w", groupID, err)
	}
	return nil
}

// LoadGroupState 加载群组 state_hash 状态
func (a *AIDDatabase) LoadGroupState(groupID string) (*GroupState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	row := a.db.QueryRow(
		`SELECT group_id, state_version, state_hash, key_epoch, membership_json, policy_json, updated_at
		 FROM group_state WHERE group_id = ?`, groupID,
	)
	var gs GroupState
	err := row.Scan(&gs.GroupID, &gs.StateVersion, &gs.StateHash, &gs.KeyEpoch, &gs.MembershipJSON, &gs.PolicyJSON, &gs.UpdatedAt)
	if err != nil {
		return nil, nil // 不存在时返回 nil
	}
	return &gs, nil
}
