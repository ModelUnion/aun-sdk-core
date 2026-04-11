// Package keystore 提供密钥存储实现。
// sqlite_backup.go — SQLite 冗余备份层 + 结构化主存。
//
// 说明：
//   - 仍然保留 key_pair / cert / metadata 的冗余备份能力；
//   - 新增 prekeys / group_current / group_old_epochs 结构化主存，
//     避免继续依赖整块 metadata JSON 的读改写。
package keystore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	schemaVersion      = 2
	sqliteBusyTimeout  = 3000
	sqliteBusyRetries  = 5
	sqliteRetryBackoff = 50 * time.Millisecond
)

// SQLiteBackup 为 KeyStore/SecretStore 的私密数据提供冗余存储。
type SQLiteBackup struct {
	mu        sync.Mutex
	db        *sql.DB
	available bool
}

// NewSQLiteBackup 创建 SQLite 备份实例。
// dbPath 为空时默认使用 cwd/.aun_backup/aun_backup.db。
func NewSQLiteBackup(dbPath string) *SQLiteBackup {
	if dbPath == "" {
		dir := filepath.Join(".", ".aun_backup")
		_ = os.MkdirAll(dir, 0o755)
		dbPath = filepath.Join(dir, "aun_backup.db")
	} else {
		_ = os.MkdirAll(filepath.Dir(dbPath), 0o755)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("[WARN] SQLite 备份初始化失败: %v", err)
		return &SQLiteBackup{available: false}
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	sb := &SQLiteBackup{db: db, available: true}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		log.Printf("[WARN] SQLite 设置 WAL 失败: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA busy_timeout = %d", sqliteBusyTimeout)); err != nil {
		log.Printf("[WARN] SQLite 设置 busy_timeout 失败: %v", err)
	}
	if err := sb.initTables(); err != nil {
		log.Printf("[WARN] SQLite 建表失败: %v", err)
		sb.available = false
	}
	return sb
}

// Close 关闭数据库连接。
func (s *SQLiteBackup) Close() {
	if s == nil {
		return
	}
	if s.db != nil {
		_ = s.db.Close()
	}
}

// ── seed 备份 ──────────────────────────────────────────────

func (s *SQLiteBackup) BackupSeed(seed []byte) {
	s.exec("INSERT OR REPLACE INTO seed_backup (id, seed, updated_at) VALUES (1, ?, ?)", seed, now())
}

func (s *SQLiteBackup) RestoreSeed() []byte {
	var seed []byte
	s.queryRow("SELECT seed FROM seed_backup WHERE id = 1", &seed)
	return seed
}

// ── device_id 备份 ─────────────────────────────────────────

func (s *SQLiteBackup) BackupDeviceID(deviceID string) {
	s.exec("INSERT OR REPLACE INTO device_id_backup (id, device_id, updated_at) VALUES (1, ?, ?)", deviceID, now())
}

func (s *SQLiteBackup) RestoreDeviceID() string {
	var id string
	s.queryRow("SELECT device_id FROM device_id_backup WHERE id = 1", &id)
	return id
}

// ── key_pair 备份（按 AID 隔离）────────────────────────────

func (s *SQLiteBackup) BackupKeyPair(aid, data string) {
	s.exec("INSERT OR REPLACE INTO key_pairs (aid, data, updated_at) VALUES (?, ?, ?)", aid, data, now())
}

func (s *SQLiteBackup) RestoreKeyPair(aid string) string {
	var data string
	s.queryRow("SELECT data FROM key_pairs WHERE aid = ?", &data, aid)
	return data
}

// ── cert 备份（按 AID 隔离）────────────────────────────────

func (s *SQLiteBackup) BackupCert(aid, certPEM string) {
	s.exec("INSERT OR REPLACE INTO certs (aid, cert_pem, updated_at) VALUES (?, ?, ?)", aid, certPEM, now())
}

func (s *SQLiteBackup) RestoreCert(aid string) string {
	var cert string
	s.queryRow("SELECT cert_pem FROM certs WHERE aid = ?", &cert, aid)
	return cert
}

// ── metadata 备份（按 AID 隔离）────────────────────────────

func (s *SQLiteBackup) BackupMetadata(aid, data string) {
	s.exec("INSERT OR REPLACE INTO metadata (aid, data, updated_at) VALUES (?, ?, ?)", aid, data, now())
}

func (s *SQLiteBackup) RestoreMetadata(aid string) string {
	var data string
	s.queryRow("SELECT data FROM metadata WHERE aid = ?", &data, aid)
	return data
}

// ── prekeys 结构化主存 ────────────────────────────────────

func (s *SQLiteBackup) LoadPrekeys(aid string) map[string]map[string]any {
	if !s.available {
		return map[string]map[string]any{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]map[string]any)
	if err := s.withRetryLocked("load_prekeys", func() error {
		rows, err := s.db.Query(`
			SELECT prekey_id, data
			FROM prekeys
			WHERE aid = ?
			ORDER BY created_at ASC, prekey_id ASC
		`, aid)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var prekeyID string
			var payload string
			if err := rows.Scan(&prekeyID, &payload); err != nil {
				return err
			}
			var data map[string]any
			if err := json.Unmarshal([]byte(payload), &data); err != nil || data == nil {
				continue
			}
			result[prekeyID] = data
		}
		return rows.Err()
	}); err != nil {
		log.Printf("[WARN] SQLite 读取 prekeys 失败: %v", err)
	}
	return result
}

func (s *SQLiteBackup) ReplacePrekeys(aid string, prekeys map[string]map[string]any) {
	if !s.available {
		return
	}
	if err := s.transaction(func(tx *sql.Tx) error {
		for prekeyID, data := range prekeys {
			if data == nil {
				data = map[string]any{}
			}
			payload, err := json.Marshal(data)
			if err != nil {
				return err
			}
			createdAt, hasCreatedAt := int64OrNil(data["created_at"])
			updatedAt := int64OrDefault(data["updated_at"], createdAt, now())
			expiresAt, hasExpires := int64OrNil(data["expires_at"])
			deletedAt, hasDeleted := int64OrNil(data["deleted_at"])
			if _, err := tx.Exec(`
				INSERT OR REPLACE INTO prekeys
				  (aid, prekey_id, data, created_at, updated_at, expires_at, deleted_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)
			`,
				aid,
				prekeyID,
				string(payload),
				nullInt64(createdAt, hasCreatedAt),
				updatedAt,
				nullInt64(expiresAt, hasExpires),
				nullInt64(deletedAt, hasDeleted),
			); err != nil {
				return err
			}
		}
		return nil
	}, "replace_prekeys"); err != nil {
		log.Printf("[WARN] SQLite replace_prekeys 失败: %v", err)
	}
}

func (s *SQLiteBackup) CleanupPrekeysBefore(aid string, cutoffMs int64, keepLatest int) []string {
	if !s.available {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	type prekeyRow struct {
		prekeyID  string
		createdAt int64
		updatedAt int64
		expiresAt int64
	}
	rowsData := make([]prekeyRow, 0)
	if err := s.withRetryLocked("select_prekeys_for_cleanup", func() error {
		rows, err := s.db.Query(`
			SELECT prekey_id, created_at, updated_at, expires_at
			FROM prekeys
			WHERE aid = ?
		`, aid)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var row prekeyRow
			var createdAt sql.NullInt64
			var updatedAt sql.NullInt64
			var expiresAt sql.NullInt64
			if err := rows.Scan(&row.prekeyID, &createdAt, &updatedAt, &expiresAt); err != nil {
				return err
			}
			if createdAt.Valid {
				row.createdAt = createdAt.Int64
			}
			if updatedAt.Valid {
				row.updatedAt = updatedAt.Int64
			}
			if expiresAt.Valid {
				row.expiresAt = expiresAt.Int64
			}
			rowsData = append(rowsData, row)
		}
		return rows.Err()
	}); err != nil {
		log.Printf("[WARN] SQLite 查询待清理 prekeys 失败: %v", err)
		return nil
	}
	sort.Slice(rowsData, func(i, j int) bool {
		leftMarker := int64OrDefault(rowsData[i].createdAt, rowsData[i].updatedAt, rowsData[i].expiresAt)
		rightMarker := int64OrDefault(rowsData[j].createdAt, rowsData[j].updatedAt, rowsData[j].expiresAt)
		if leftMarker != rightMarker {
			return leftMarker > rightMarker
		}
		return rowsData[i].prekeyID > rowsData[j].prekeyID
	})
	retainedIDs := make(map[string]bool, keepLatest)
	for idx, row := range rowsData {
		if idx >= keepLatest {
			break
		}
		retainedIDs[row.prekeyID] = true
	}
	prekeyIDs := make([]string, 0)
	for _, row := range rowsData {
		marker := int64OrDefault(row.createdAt, row.updatedAt, row.expiresAt)
		if marker < cutoffMs && !retainedIDs[row.prekeyID] {
			prekeyIDs = append(prekeyIDs, row.prekeyID)
		}
	}
	if len(prekeyIDs) == 0 {
		return nil
	}

	if err := s.transactionLocked(func(tx *sql.Tx) error {
		for _, prekeyID := range prekeyIDs {
			if _, err := tx.Exec("DELETE FROM prekeys WHERE aid = ? AND prekey_id = ?", aid, prekeyID); err != nil {
				return err
			}
		}
		return nil
	}, "cleanup_prekeys"); err != nil {
		log.Printf("[WARN] SQLite cleanup_prekeys 失败: %v", err)
		return nil
	}
	return prekeyIDs
}

// ── group secrets 结构化主存 ──────────────────────────────

func (s *SQLiteBackup) LoadGroupEntries(aid string) map[string]map[string]any {
	if !s.available {
		return map[string]map[string]any{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	groups := make(map[string]map[string]any)
	if err := s.withRetryLocked("load_group_entries", func() error {
		currentRows, err := s.db.Query(`
			SELECT group_id, data
			FROM group_current
			WHERE aid = ?
			ORDER BY group_id ASC
		`, aid)
		if err != nil {
			return err
		}
		defer currentRows.Close()

		for currentRows.Next() {
			var groupID string
			var payload string
			if err := currentRows.Scan(&groupID, &payload); err != nil {
				return err
			}
			var data map[string]any
			if err := json.Unmarshal([]byte(payload), &data); err != nil || data == nil {
				continue
			}
			groups[groupID] = data
		}
		if err := currentRows.Err(); err != nil {
			return err
		}

		oldRows, err := s.db.Query(`
			SELECT group_id, data
			FROM group_old_epochs
			WHERE aid = ?
			ORDER BY group_id ASC, epoch ASC
		`, aid)
		if err != nil {
			return err
		}
		defer oldRows.Close()

		for oldRows.Next() {
			var groupID string
			var payload string
			if err := oldRows.Scan(&groupID, &payload); err != nil {
				return err
			}
			var data map[string]any
			if err := json.Unmarshal([]byte(payload), &data); err != nil || data == nil {
				continue
			}
			entry := groups[groupID]
			if entry == nil {
				entry = map[string]any{}
				groups[groupID] = entry
			}
			oldEpochs, _ := entry["old_epochs"].([]any)
			entry["old_epochs"] = append(oldEpochs, data)
		}
		return oldRows.Err()
	}); err != nil {
		log.Printf("[WARN] SQLite 读取 group entries 失败: %v", err)
	}
	return groups
}

func (s *SQLiteBackup) ReplaceGroupEntries(aid string, entries map[string]map[string]any) {
	if !s.available {
		return
	}
	if err := s.transaction(func(tx *sql.Tx) error {
		for groupID, entry := range entries {
			if entry == nil {
				entry = map[string]any{}
			}
			currentEntry := shallowCopyMap(entry)
			oldEpochsRaw, _ := currentEntry["old_epochs"].([]any)
			delete(currentEntry, "old_epochs")

			epoch, hasEpoch := int64OrNil(currentEntry["epoch"])
			updatedAt := int64OrDefault(currentEntry["updated_at"], 0, now())
			if hasEpoch {
				payload, err := json.Marshal(currentEntry)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(`
					INSERT OR REPLACE INTO group_current
					  (aid, group_id, epoch, data, updated_at)
					VALUES (?, ?, ?, ?, ?)
				`, aid, groupID, epoch, string(payload), updatedAt); err != nil {
					return err
				}
			}

			for _, raw := range oldEpochsRaw {
				old, ok := raw.(map[string]any)
				if !ok || old == nil {
					continue
				}
				oldEpoch, ok := int64OrNil(old["epoch"])
				if !ok {
					continue
				}
				payload, err := json.Marshal(old)
				if err != nil {
					return err
				}
				oldUpdatedAt := int64OrDefault(old["updated_at"], updatedAt, now())
				expiresAt, hasExpires := int64OrNil(old["expires_at"])
				deletedAt, hasDeleted := int64OrNil(old["deleted_at"])
				if _, err := tx.Exec(`
					INSERT OR REPLACE INTO group_old_epochs
					  (aid, group_id, epoch, data, updated_at, expires_at, deleted_at)
					VALUES (?, ?, ?, ?, ?, ?, ?)
				`,
					aid,
					groupID,
					oldEpoch,
					string(payload),
					oldUpdatedAt,
					nullInt64(expiresAt, hasExpires),
					nullInt64(deletedAt, hasDeleted),
				); err != nil {
					return err
				}
			}
		}
		return nil
	}, "replace_group_entries"); err != nil {
		log.Printf("[WARN] SQLite replace_group_entries 失败: %v", err)
	}
}

func (s *SQLiteBackup) CleanupGroupOldEpochs(aid, groupID string, cutoffMs int64) []int {
	if !s.available {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	epochs := make([]int, 0)
	if err := s.withRetryLocked("select_group_old_epochs_for_cleanup", func() error {
		rows, err := s.db.Query(`
			SELECT epoch
			FROM group_old_epochs
			WHERE aid = ?
			  AND group_id = ?
			  AND COALESCE(NULLIF(updated_at, 0), expires_at, 0) < ?
		`, aid, groupID, cutoffMs)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var epoch int
			if err := rows.Scan(&epoch); err != nil {
				return err
			}
			epochs = append(epochs, epoch)
		}
		return rows.Err()
	}); err != nil {
		log.Printf("[WARN] SQLite 查询待清理旧 epoch 失败: %v", err)
		return nil
	}
	if len(epochs) == 0 {
		return nil
	}

	if err := s.transactionLocked(func(tx *sql.Tx) error {
		for _, epoch := range epochs {
			if _, err := tx.Exec("DELETE FROM group_old_epochs WHERE aid = ? AND group_id = ? AND epoch = ?", aid, groupID, epoch); err != nil {
				return err
			}
		}
		return nil
	}, "cleanup_group_old_epochs"); err != nil {
		log.Printf("[WARN] SQLite cleanup_group_old_epochs 失败: %v", err)
		return nil
	}
	return epochs
}

// ── 内部方法 ───────────────────────────────────────────────

func (s *SQLiteBackup) initTables() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.withRetryLocked("init_tables", func() error {
		_, err := s.db.Exec(`
			CREATE TABLE IF NOT EXISTS _schema_version (
				id INTEGER PRIMARY KEY,
				version INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS seed_backup (
				id INTEGER PRIMARY KEY,
				seed BLOB NOT NULL,
				updated_at INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS device_id_backup (
				id INTEGER PRIMARY KEY,
				device_id TEXT NOT NULL,
				updated_at INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS key_pairs (
				aid TEXT PRIMARY KEY,
				data TEXT NOT NULL,
				updated_at INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS certs (
				aid TEXT PRIMARY KEY,
				cert_pem TEXT NOT NULL,
				updated_at INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS metadata (
				aid TEXT PRIMARY KEY,
				data TEXT NOT NULL,
				updated_at INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS prekeys (
				aid TEXT NOT NULL,
				prekey_id TEXT NOT NULL,
				data TEXT NOT NULL,
				created_at INTEGER,
				updated_at INTEGER NOT NULL,
				expires_at INTEGER,
				deleted_at INTEGER,
				PRIMARY KEY (aid, prekey_id)
			);
			CREATE TABLE IF NOT EXISTS group_current (
				aid TEXT NOT NULL,
				group_id TEXT NOT NULL,
				epoch INTEGER NOT NULL,
				data TEXT NOT NULL,
				updated_at INTEGER NOT NULL,
				PRIMARY KEY (aid, group_id)
			);
			CREATE TABLE IF NOT EXISTS group_old_epochs (
				aid TEXT NOT NULL,
				group_id TEXT NOT NULL,
				epoch INTEGER NOT NULL,
				data TEXT NOT NULL,
				updated_at INTEGER NOT NULL,
				expires_at INTEGER,
				deleted_at INTEGER,
				PRIMARY KEY (aid, group_id, epoch)
			);
			CREATE INDEX IF NOT EXISTS idx_prekeys_aid_expires
				ON prekeys (aid, expires_at, created_at, updated_at);
			CREATE INDEX IF NOT EXISTS idx_group_old_epochs_aid_group_expires
				ON group_old_epochs (aid, group_id, expires_at, updated_at);
		`)
		return err
	}); err != nil {
		return err
	}
	return s.migrateLocked()
}

func (s *SQLiteBackup) migrateLocked() error {
	var current int
	row := s.db.QueryRow("SELECT version FROM _schema_version WHERE id = 1")
	if err := row.Scan(&current); err != nil {
		current = 0
	}
	if current != schemaVersion {
		_, err := s.db.Exec("INSERT OR REPLACE INTO _schema_version (id, version) VALUES (1, ?)", schemaVersion)
		return err
	}
	return nil
}

func (s *SQLiteBackup) exec(query string, args ...any) {
	if s == nil || !s.available {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.withRetryLocked("exec", func() error {
		_, err := s.db.Exec(query, args...)
		return err
	}); err != nil {
		log.Printf("[WARN] SQLite 备份写入失败: %v", err)
	}
}

func (s *SQLiteBackup) queryRow(query string, dest any, args ...any) {
	if s == nil || !s.available {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.withRetryLocked("query_row", func() error {
		row := s.db.QueryRow(query, args...)
		if err := row.Scan(dest); err != nil {
			if err == sql.ErrNoRows {
				return nil
			}
			return err
		}
		return nil
	}); err != nil {
		log.Printf("[WARN] SQLite 备份读取失败: %v", err)
	}
}

func (s *SQLiteBackup) transaction(fn func(*sql.Tx) error, op string) error {
	if !s.available {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transactionLocked(fn, op)
}

func (s *SQLiteBackup) transactionLocked(fn func(*sql.Tx) error, op string) error {
	return s.withRetryLocked(op, func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer func() {
			_ = tx.Rollback()
		}()
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s *SQLiteBackup) withRetryLocked(op string, fn func() error) error {
	var lastErr error
	for i := 0; i < sqliteBusyRetries; i++ {
		if err := fn(); err != nil {
			lastErr = err
			if !isSQLiteBusyErr(err) {
				return err
			}
			time.Sleep(time.Duration(i+1) * sqliteRetryBackoff)
			continue
		}
		return nil
	}
	return fmt.Errorf("%s after retries: %w", op, lastErr)
}

func isSQLiteBusyErr(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "sqlitedb busy") ||
		strings.Contains(text, "sqlite_busy") ||
		strings.Contains(text, "database is locked") ||
		strings.Contains(text, "database table is locked") ||
		strings.Contains(text, "busy")
}

func int64OrNil(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case json.Number:
		value, err := n.Int64()
		if err == nil {
			return value, true
		}
	}
	return 0, false
}

func int64OrDefault(values ...any) int64 {
	for _, value := range values {
		if value == nil {
			continue
		}
		if number, ok := int64OrNil(value); ok {
			return number
		}
	}
	return 0
}

func nullInt64(value int64, valid bool) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: valid}
}

func shallowCopyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func now() int64 {
	return time.Now().UnixMilli()
}

// IsAvailable 返回 SQLite 备份是否可用。
func (s *SQLiteBackup) IsAvailable() bool {
	return s != nil && s.available
}

// String 实现 fmt.Stringer 接口。
func (s *SQLiteBackup) String() string {
	if s == nil || !s.available {
		return "SQLiteBackup(unavailable)"
	}
	return fmt.Sprintf("SQLiteBackup(available)")
}
