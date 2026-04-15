// aid_db.go — 单个 AID 的 SQLite 数据库（对标 Python sqlcipher_db.py）
//
// 加密方案：Go 无 SQLCipher，敏感字段（private_key_pem、secret、session data）
// 通过 SecretStore.Protect/Reveal 字段级加密后存入 DB。
package keystore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

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
}

// AIDDatabase 单个 AID 的 SQLite 数据库。
type AIDDatabase struct {
	mu     sync.Mutex
	db     *sql.DB
	dbPath string
}

// newAIDDatabase 创建或打开 AID 数据库。
func newAIDDatabase(dbPath string) (*AIDDatabase, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("创建 AID DB 目录失败: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开 AID DB 失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	adb := &AIDDatabase{db: db, dbPath: dbPath}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		log.Printf("[WARN] AIDDatabase WAL 设置失败: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", aidDBBusyTimeout)); err != nil {
		log.Printf("[WARN] AIDDatabase busy_timeout 设置失败: %v", err)
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
	for _, ddl := range aidDBDDL {
		if _, err := a.db.Exec(ddl); err != nil {
			return fmt.Errorf("DDL 执行失败 (%s...): %w", ddl[:min(40, len(ddl))], err)
		}
	}
	var ver int
	row := a.db.QueryRow("SELECT version FROM _schema_version WHERE id = 1")
	if err := row.Scan(&ver); err != nil {
		_, err2 := a.db.Exec("INSERT INTO _schema_version (id, version) VALUES (1, ?)", aidDBSchemaVersion)
		return err2
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
		log.Printf("[aid_db] SetToken 失败 (key=%s): %v", key, err)
	}
}

func (a *AIDDatabase) DeleteToken(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM tokens WHERE key = ?", key); err != nil {
		log.Printf("[aid_db] DeleteToken 失败 (key=%s): %v", key, err)
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
	// 明文存储（无 SQLCipher，与 Python 降级行为一致）
	dataJSON, err := json.Marshal(extraData)
	if err != nil {
		log.Printf("[aid_db] SavePrekey json.Marshal 失败: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(prekey_id, device_id) DO UPDATE SET
		   private_key_enc=excluded.private_key_enc, data=excluded.data,
		   updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
		prekeyID, deviceID, privateKeyPEM, string(dataJSON),
		nullInt64Ptr(createdAt, now), now, nullInt64PtrSQL(expiresAt),
	); err != nil {
		log.Printf("[aid_db] SavePrekey 失败 (id=%s): %v", prekeyID, err)
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
		entry := map[string]any{
			"private_key_pem": enc,
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

func (a *AIDDatabase) DeletePrekey(prekeyID, deviceID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM prekeys WHERE prekey_id = ? AND device_id = ?", prekeyID, deviceID); err != nil {
		log.Printf("[aid_db] DeletePrekey 失败 (id=%s, device=%s): %v", prekeyID, deviceID, err)
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
			log.Printf("[aid_db] CleanupPrekeys 删除失败 (device=%s, id=%s): %v", deviceID, id, err)
		}
	}
	return toDelete
}

// ── Group Current ────────────────────────────────────────────

func (a *AIDDatabase) SaveGroupCurrent(groupID string, epoch int64, secret string, data map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		log.Printf("[aid_db] SaveGroupCurrent json.Marshal 失败: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(group_id) DO UPDATE SET
		   epoch=excluded.epoch, secret_enc=excluded.secret_enc,
		   data=excluded.data, updated_at=excluded.updated_at`,
		groupID, epoch, secret, string(dataJSON), nowMs(),
	); err != nil {
		log.Printf("[aid_db] SaveGroupCurrent 失败 (group=%s): %v", groupID, err)
	}
}

func (a *AIDDatabase) LoadGroupCurrent(groupID string) map[string]any {
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
		"secret":     enc,
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
			"secret":     enc,
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
		log.Printf("[aid_db] DeleteGroupCurrent 失败 (group=%s): %v", groupID, err)
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
		log.Printf("[aid_db] SaveGroupOldEpoch json.Marshal 失败: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(group_id, epoch) DO UPDATE SET
		   secret_enc=excluded.secret_enc, data=excluded.data,
		   updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
		groupID, epoch, secret, string(dataJSON), now, nullInt64PtrSQL(expiresAt),
	); err != nil {
		log.Printf("[aid_db] SaveGroupOldEpoch 失败 (group=%s, epoch=%d): %v", groupID, epoch, err)
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
			"secret":     enc,
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
		log.Printf("[aid_db] DeleteAllGroupOldEpochs 失败 (group=%s): %v", groupID, err)
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
		`DELETE FROM group_old_epochs WHERE group_id = ?
		 AND (CASE WHEN expires_at IS NOT NULL THEN expires_at ELSE updated_at END) < ?`,
		groupID, cutoffMs,
	)
	if err != nil {
		log.Printf("[aid_db] CleanupGroupOldEpochs 失败 (group=%s): %v", groupID, err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// ── E2EE Sessions ────────────────────────────────────────────

func (a *AIDDatabase) SaveSession(sessionID string, data map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		log.Printf("[aid_db] SaveSession json.Marshal 失败: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(session_id) DO UPDATE SET data_enc=excluded.data_enc, updated_at=excluded.updated_at`,
		sessionID, string(dataJSON), nowMs(),
	); err != nil {
		log.Printf("[aid_db] SaveSession 失败 (id=%s): %v", sessionID, err)
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
	plain := enc
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
		plain := enc
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
		log.Printf("[aid_db] DeleteSession 失败 (id=%s): %v", sessionID, err)
	}
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
		log.Printf("[aid_db] SaveInstanceState json.Marshal 失败: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO instance_state (device_id, slot_id, data, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(device_id, slot_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`,
		deviceID, slotID, string(dataJSON), nowMs(),
	); err != nil {
		log.Printf("[aid_db] SaveInstanceState 失败 (device=%s, slot=%s): %v", deviceID, slotID, err)
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
		log.Printf("[aid_db] SaveSeq 失败 (device=%s, ns=%s): %v", deviceID, namespace, err)
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
		log.Printf("[aid_db] SetMetadata 失败 (key=%s): %v", key, err)
	}
}

func (a *AIDDatabase) DeleteMetadata(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("DELETE FROM metadata_kv WHERE key = ?", key); err != nil {
		log.Printf("[aid_db] DeleteMetadata 失败 (key=%s): %v", key, err)
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
