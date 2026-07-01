// aid_db.go — 单个 AID 的 SQLite 数据库（对标 Python sqlite_db.py）
//
// 所有字段明文存储，不再使用字段级加密。
package keystore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	aidDBSchemaVersion = 3
	aidDBBusyTimeout   = 5000
)

// slotIsolationKey 提取 slot_id 的隔离键：第一个分隔符（/ : 空格）之前的部分。
func slotIsolationKey(slotID string) string {
	for i, ch := range slotID {
		if ch == '/' || ch == ':' || ch == ' ' {
			return slotID[:i]
		}
	}
	return slotID
}

func groupTrimDots(value string) string {
	return strings.Trim(value, ".")
}

func issuerFromAID(aid string) string {
	value := strings.ToLower(strings.TrimSpace(aid))
	if dot := strings.Index(value, "."); dot > 0 && dot < len(value)-1 {
		return strings.Trim(value[dot+1:], ".")
	}
	return ""
}

func convertToGroupAIDLocal(raw string, localIssuer string) string {
	value := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "/"))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "group.") && strings.Contains(value, "/") {
		issuerAndBase := value[6:]
		if slash := strings.Index(issuerAndBase, "/"); slash > 0 && slash < len(issuerAndBase)-1 {
			domain := groupTrimDots(issuerAndBase[:slash])
			baseTail := strings.Trim(issuerAndBase[slash+1:], "/")
			if at := strings.Index(baseTail, "@"); at > 0 {
				base := groupTrimDots(baseTail[:at])
				suffixDomain := groupTrimDots(baseTail[at+1:])
				if base != "" && suffixDomain != "" {
					merged := suffixDomain
					if domain != "" {
						merged = suffixDomain + "." + domain
					}
					return base + "." + merged
				}
			}
			base := groupTrimDots(baseTail)
			if base != "" && domain != "" {
				return base + "." + domain
			}
			return value
		}
		return value
	}
	if at := strings.Index(value, "@"); at > 0 {
		base := groupTrimDots(value[:at])
		domain := groupTrimDots(value[at+1:])
		if base != "" && domain != "" {
			return base + "." + domain
		}
		return value
	}
	if strings.Contains(value, ".") {
		return value
	}
	issuer := strings.ToLower(groupTrimDots(strings.TrimSpace(localIssuer)))
	if issuer != "" {
		return value + "." + issuer
	}
	return value
}

func groupLookupCandidates(groupID string, localIssuer string) []string {
	raw := strings.TrimSpace(groupID)
	if raw == "" {
		return nil
	}
	normalized := convertToGroupAIDLocal(raw, localIssuer)
	candidates := make([]string, 0, 5)
	seen := map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		candidates = append(candidates, value)
	}
	add(raw)
	add(normalized)
	if dot := strings.Index(normalized, "."); dot > 0 && dot < len(normalized)-1 {
		base := normalized[:dot]
		issuer := normalized[dot+1:]
		add("group." + issuer + "/" + base)
		add(base + "@" + issuer)
		if localIssuer != "" && issuer == strings.ToLower(groupTrimDots(strings.TrimSpace(localIssuer))) {
			add(base)
		}
	}
	return candidates
}

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
	`CREATE TABLE IF NOT EXISTS instance_state (
		device_id TEXT NOT NULL,
		slot_id TEXT NOT NULL DEFAULT '_singleton',
		slot_id_full TEXT NOT NULL DEFAULT '',
		data TEXT NOT NULL DEFAULT '{}',
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, slot_id)
	)`,
	`CREATE TABLE IF NOT EXISTS seq_tracker (
		device_id TEXT NOT NULL,
		slot_id TEXT NOT NULL DEFAULT '_singleton',
		slot_id_full TEXT NOT NULL DEFAULT '',
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
	`CREATE TABLE IF NOT EXISTS group_state (
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
	mu     sync.Mutex
	db     *sql.DB
	dbPath string
	aid    string // 当前 AID 标识，用于 SecretStore scope
}

// newAIDDatabase 创建或打开 AID 数据库。
// ss 和 aid 用于 prekey 私钥字段级加密；ss 为 nil 时降级为明文存储。
func newAIDDatabase(dbPath string, aid string) (*AIDDatabase, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("创建 AID DB 目录失败: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开 AID DB 失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	adb := &AIDDatabase{db: db, dbPath: dbPath, aid: aid}
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
	if err := ensureSlotIDFullColumns(tx); err != nil {
		return fmt.Errorf("补齐 slot_id_full schema 失败: %w", err)
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
func migrateSchema(tx *sql.Tx, fromVer, toVer int) error {
	for v := fromVer; v < toVer; v++ {
		switch v {
		case 0:
			// v0 → v1：无需操作
		case 1:
			// v1 → v2：instance_state / seq_tracker 加 slot_id_full 列（幂等）
			if err := ensureSlotIDFullColumns(tx); err != nil {
				return err
			}
		case 2:
			// v2 → v3：移除已废弃的 agent_md_cache 表（agent.md 改由文件系统 + 内存缓存承载）
			if _, err := tx.Exec("DROP TABLE IF EXISTS agent_md_cache"); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureSlotIDFullColumns(tx *sql.Tx) error {
	for _, stmt := range []struct{ table, col string }{
		{"instance_state", "slot_id_full"},
		{"seq_tracker", "slot_id_full"},
	} {
		if !columnExists(tx, stmt.table, stmt.col) {
			if _, err := tx.Exec("ALTER TABLE " + stmt.table + " ADD COLUMN " + stmt.col + " TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
	}
	return nil
}

func columnExists(tx *sql.Tx, table, col string) bool {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err == nil && name == col {
			return true
		}
	}
	return false
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

// ── Instance State ───────────────────────────────────────────

func (a *AIDDatabase) SaveInstanceState(deviceID, slotID string, state map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	slotKey := slotIsolationKey(slotID)
	if slotKey == "" {
		slotKey = "_singleton"
	}
	dataJSON, err := json.Marshal(state)
	if err != nil {
		pkgLogKeystore().Warn("SaveInstanceState json.Marshal failed: %v", err)
		dataJSON = []byte("{}")
	}
	if _, err := a.db.Exec(
		`INSERT INTO instance_state (device_id, slot_id, slot_id_full, data, updated_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, slot_id) DO UPDATE SET slot_id_full=excluded.slot_id_full, data=excluded.data, updated_at=excluded.updated_at`,
		deviceID, slotKey, slotID, string(dataJSON), nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SaveInstanceState failed (device=%s, slot=%s): %v", deviceID, slotID, err)
	}
}

func (a *AIDDatabase) LoadInstanceState(deviceID, slotID string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	slotKey := slotIsolationKey(slotID)
	if slotKey == "" {
		slotKey = "_singleton"
	}
	var dataStr string
	row := a.db.QueryRow("SELECT data FROM instance_state WHERE device_id = ? AND slot_id = ?", deviceID, slotKey)
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
	slotKey := slotIsolationKey(slotID)
	if slotKey == "" {
		slotKey = "_singleton"
	}
	if _, err := a.db.Exec(
		`INSERT INTO seq_tracker (device_id, slot_id, slot_id_full, namespace, contiguous_seq, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, slot_id, namespace)
		 DO UPDATE SET slot_id_full=excluded.slot_id_full, contiguous_seq=excluded.contiguous_seq, updated_at=excluded.updated_at`,
		deviceID, slotKey, slotID, namespace, contiguousSeq, nowMs(),
	); err != nil {
		pkgLogKeystore().Warn("SaveSeq failed (device=%s, ns=%s): %v", deviceID, namespace, err)
	}
}

func (a *AIDDatabase) LoadSeq(deviceID, slotID, namespace string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	slotKey := slotIsolationKey(slotID)
	if slotKey == "" {
		slotKey = "_singleton"
	}
	var seq int
	row := a.db.QueryRow(
		"SELECT contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?",
		deviceID, slotKey, namespace,
	)
	if err := row.Scan(&seq); err != nil {
		return 0
	}
	return seq
}

func (a *AIDDatabase) LoadAllSeqs(deviceID, slotID string) map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	slotKey := slotIsolationKey(slotID)
	if slotKey == "" {
		slotKey = "_singleton"
	}
	rows, err := a.db.Query(
		"SELECT namespace, contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ?",
		deviceID, slotKey,
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
	slotKey := slotIsolationKey(slotID)
	if slotKey == "" {
		slotKey = "_singleton"
	}
	_, err := a.db.Exec(
		"DELETE FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?",
		deviceID, slotKey, namespace,
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
	var gs GroupState
	for _, candidate := range groupLookupCandidates(groupID, issuerFromAID(a.aid)) {
		row := a.db.QueryRow(
			`SELECT group_id, state_version, state_hash, key_epoch, membership_json, policy_json, updated_at
			 FROM group_state WHERE group_id = ?`, candidate,
		)
		err := row.Scan(&gs.GroupID, &gs.StateVersion, &gs.StateHash, &gs.KeyEpoch, &gs.MembershipJSON, &gs.PolicyJSON, &gs.UpdatedAt)
		if err == nil {
			return &gs, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	return nil, nil
}
