// Package session 提供 V2 E2EE 会话和设备密钥持久化能力。
//
// 设计要点：
//   - IK = AID 长期密钥（多设备共享 AID 身份），由调用方注入，不在本包生成
//   - SPK 是设备级密钥（P-256），由 IK 签名背书，本包负责生成、轮换、销毁
//   - 持久化通过 SQLite（modernc.org/sqlite）实现，与 Python SDK 表结构互通
package session

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// V2DeviceKeysDDL V2 设备密钥表 DDL，与 Python SDK 一致。
const V2DeviceKeysDDL = `CREATE TABLE IF NOT EXISTS v2_device_keys (
    device_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    group_id TEXT NOT NULL DEFAULT '',
    key_id TEXT NOT NULL DEFAULT '',
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, key_type, group_id, key_id)
)`

// V2KeyStore 设备密钥持久化。
//
// key_type 取值：
//   - "ik"   IK 主密钥；key_id 为空串或 IK fallback alias，但不进入普通 SPK 生命周期
//   - "spk"  SPK 设备密钥；key_id 为 spk_id
type V2KeyStore struct {
	db *sql.DB
}

// NewV2KeyStore 创建 V2KeyStore，并确保表已存在。
func NewV2KeyStore(db *sql.DB) (*V2KeyStore, error) {
	if db == nil {
		return nil, fmt.Errorf("V2KeyStore: db 不能为空")
	}
	if _, err := db.Exec(V2DeviceKeysDDL); err != nil {
		return nil, fmt.Errorf("V2KeyStore: v2_device_keys DDL 失败: %w", err)
	}
	if err := migrateV2DeviceKeys(db); err != nil {
		return nil, err
	}
	return &V2KeyStore{db: db}, nil
}

func ikSPKIDFromPubDER(pubDER []byte) string {
	h := sha256.Sum256(pubDER)
	return "sha256:" + hex.EncodeToString(h[:])[:16]
}

func isUploadedMarkerKeyType(keyType string) bool {
	return keyType == "spk_uploaded" || keyType == "group_spk_uploaded"
}

func migrateV2DeviceKeys(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(v2_device_keys)`)
	if err != nil {
		return fmt.Errorf("V2KeyStore migrate table_info: %w", err)
	}
	type columnInfo struct {
		name string
		pk   int
	}
	var pkCols []columnInfo
	hasGroupID := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("V2KeyStore migrate scan table_info: %w", err)
		}
		if name == "group_id" {
			hasGroupID = true
		}
		if pk > 0 {
			pkCols = append(pkCols, columnInfo{name: name, pk: pk})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("V2KeyStore migrate table_info rows: %w", err)
	}
	rows.Close()
	for i := 0; i < len(pkCols); i++ {
		for j := i + 1; j < len(pkCols); j++ {
			if pkCols[j].pk < pkCols[i].pk {
				pkCols[i], pkCols[j] = pkCols[j], pkCols[i]
			}
		}
	}
	wantPK := []string{"device_id", "key_type", "group_id", "key_id"}
	pkOK := len(pkCols) == len(wantPK)
	if pkOK {
		for i, col := range pkCols {
			if col.name != wantPK[i] {
				pkOK = false
				break
			}
		}
	}
	if hasGroupID && pkOK {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_v2_device_keys_scope_created
			ON v2_device_keys(device_id, key_type, group_id, created_at)`)
		if err != nil {
			return fmt.Errorf("V2KeyStore migrate index: %w", err)
		}
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("V2KeyStore migrate begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE v2_device_keys RENAME TO v2_device_keys_legacy`); err != nil {
		return fmt.Errorf("V2KeyStore migrate rename: %w", err)
	}
	if _, err := tx.Exec(`CREATE TABLE v2_device_keys (
		device_id TEXT NOT NULL,
		key_type TEXT NOT NULL,
		group_id TEXT NOT NULL DEFAULT '',
		key_id TEXT NOT NULL DEFAULT '',
		private_key BLOB NOT NULL,
		public_key BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, key_type, group_id, key_id)
	)`); err != nil {
		return fmt.Errorf("V2KeyStore migrate create: %w", err)
	}
	selectSQL := `SELECT device_id, key_type, '' AS group_id, key_id, private_key, public_key, created_at FROM v2_device_keys_legacy`
	if hasGroupID {
		selectSQL = `SELECT device_id, key_type, group_id, key_id, private_key, public_key, created_at FROM v2_device_keys_legacy`
	}
	legacyRows, err := tx.Query(selectSQL)
	if err != nil {
		return fmt.Errorf("V2KeyStore migrate select legacy: %w", err)
	}
	for legacyRows.Next() {
		var deviceID, keyType, groupID, keyID string
		var priv, pub []byte
		var createdAt int64
		if err := legacyRows.Scan(&deviceID, &keyType, &groupID, &keyID, &priv, &pub, &createdAt); err != nil {
			legacyRows.Close()
			return fmt.Errorf("V2KeyStore migrate scan legacy: %w", err)
		}
		if (keyType == "group_spk" || keyType == "group_spk_uploaded") && strings.Contains(keyID, "\x00") {
			parts := strings.SplitN(keyID, "\x00", 2)
			groupID, keyID = parts[0], parts[1]
		}
		if priv == nil || pub == nil {
			if !isUploadedMarkerKeyType(keyType) {
				continue
			}
			if priv == nil {
				priv = []byte{}
			}
			if pub == nil {
				pub = []byte{}
			}
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO v2_device_keys
			(device_id, key_type, group_id, key_id, private_key, public_key, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, deviceID, keyType, groupID, keyID, priv, pub, createdAt); err != nil {
			legacyRows.Close()
			return fmt.Errorf("V2KeyStore migrate insert: %w", err)
		}
	}
	if err := legacyRows.Err(); err != nil {
		legacyRows.Close()
		return fmt.Errorf("V2KeyStore migrate legacy rows: %w", err)
	}
	legacyRows.Close()
	if _, err := tx.Exec(`DROP TABLE v2_device_keys_legacy`); err != nil {
		return fmt.Errorf("V2KeyStore migrate drop legacy: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_v2_device_keys_scope_created
		ON v2_device_keys(device_id, key_type, group_id, created_at)`); err != nil {
		return fmt.Errorf("V2KeyStore migrate index: %w", err)
	}
	return tx.Commit()
}

// SaveIK 保存 IK 主密钥（IK = AID 主密钥，通常无需调用，保留 API 兼容）。
func (s *V2KeyStore) SaveIK(deviceID string, priv, pubDER []byte) error {
	now := time.Now().UnixMilli()
	for _, keyID := range []string{"", ikSPKIDFromPubDER(pubDER)} {
		_, err := s.db.Exec(
			`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
			 VALUES (?, 'ik', '', ?, ?, ?, ?)`,
			deviceID, keyID, priv, pubDER, now)
		if err != nil {
			return fmt.Errorf("V2KeyStore.SaveIK: %w", err)
		}
	}
	return nil
}

// LoadIK 加载 IK 主密钥；不存在时返回 (nil, nil, nil)。
func (s *V2KeyStore) LoadIK(deviceID string) (priv, pubDER []byte, err error) {
	row := s.db.QueryRow(
		`SELECT private_key, public_key FROM v2_device_keys
		 WHERE device_id=? AND key_type='ik' AND group_id='' AND key_id=''`,
		deviceID)
	err = row.Scan(&priv, &pubDER)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("V2KeyStore.LoadIK: %w", err)
	}
	return priv, pubDER, nil
}

func (s *V2KeyStore) LoadIKSPK(deviceID, spkID string) (priv, pubDER []byte, err error) {
	row := s.db.QueryRow(
		`SELECT private_key, public_key FROM v2_device_keys
		 WHERE device_id=? AND key_type='ik' AND group_id='' AND key_id=?`,
		deviceID, spkID)
	err = row.Scan(&priv, &pubDER)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("V2KeyStore.LoadIKSPK: %w", err)
	}
	return priv, pubDER, nil
}

// SaveSPK 保存指定 spk_id 的 SPK 密钥。
func (s *V2KeyStore) SaveSPK(deviceID, spkID string, priv, pubDER []byte) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
		 VALUES (?, 'spk', '', ?, ?, ?, ?)`,
		deviceID, spkID, priv, pubDER, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("V2KeyStore.SaveSPK: %w", err)
	}
	return nil
}

// SaveSPKWithCreatedAt 保存 SPK 并指定 created_at（毫秒时间戳，仅供测试模拟时间使用）。
func (s *V2KeyStore) SaveSPKWithCreatedAt(deviceID, spkID string, priv, pubDER []byte, createdAtMs int64) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
		 VALUES (?, 'spk', '', ?, ?, ?, ?)`,
		deviceID, spkID, priv, pubDER, createdAtMs)
	if err != nil {
		return fmt.Errorf("V2KeyStore.SaveSPKWithCreatedAt: %w", err)
	}
	return nil
}

// LoadSPK 加载指定 spk_id 的 SPK 私钥；不存在时返回 (nil, nil)。
func (s *V2KeyStore) LoadSPK(deviceID, spkID string) ([]byte, error) {
	row := s.db.QueryRow(
		`SELECT private_key FROM v2_device_keys
		 WHERE device_id=? AND key_type='spk' AND group_id='' AND key_id=?`,
		deviceID, spkID)
	var priv []byte
	err := row.Scan(&priv)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("V2KeyStore.LoadSPK: %w", err)
	}
	return priv, nil
}

// LoadCurrentSPK 加载最新的 SPK（按 created_at 降序）。
// 不存在时返回 ("", nil, nil, nil)。
func (s *V2KeyStore) LoadCurrentSPK(deviceID string) (string, []byte, []byte, error) {
	row := s.db.QueryRow(
		`SELECT key_id, private_key, public_key FROM v2_device_keys
		 WHERE device_id=? AND key_type='spk' AND group_id='' ORDER BY created_at DESC LIMIT 1`,
		deviceID)
	var spkID string
	var priv, pub []byte
	err := row.Scan(&spkID, &priv, &pub)
	if err == sql.ErrNoRows {
		return "", nil, nil, nil
	}
	if err != nil {
		return "", nil, nil, fmt.Errorf("V2KeyStore.LoadCurrentSPK: %w", err)
	}
	return spkID, priv, pub, nil
}

// ── Group SPK 存储 ──────────────────────────────────────────────

// SaveGroupSPK 保存指定群的 group SPK 密钥。
func (s *V2KeyStore) SaveGroupSPK(deviceID, groupID, spkID string, priv, pubDER []byte) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
		 VALUES (?, 'group_spk', ?, ?, ?, ?, ?)`,
		deviceID, groupID, spkID, priv, pubDER, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("V2KeyStore.SaveGroupSPK: %w", err)
	}
	return nil
}

// LoadGroupSPK 加载指定群的指定 spk_id 的 group SPK 私钥；不存在时返回 (nil, nil)。
func (s *V2KeyStore) LoadGroupSPK(deviceID, groupID, spkID string) ([]byte, error) {
	row := s.db.QueryRow(
		`SELECT private_key FROM v2_device_keys
		 WHERE device_id=? AND key_type='group_spk' AND group_id=? AND key_id=?`,
		deviceID, groupID, spkID)
	var priv []byte
	err := row.Scan(&priv)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("V2KeyStore.LoadGroupSPK: %w", err)
	}
	return priv, nil
}

// LoadCurrentGroupSPK 加载指定群最新的 group SPK（按 created_at 降序）。
// 不存在时返回 ("", nil, nil, nil)。
func (s *V2KeyStore) LoadCurrentGroupSPK(deviceID, groupID string) (string, []byte, []byte, error) {
	row := s.db.QueryRow(
		`SELECT key_id, private_key, public_key FROM v2_device_keys
		 WHERE device_id=? AND key_type='group_spk' AND group_id=?
		 ORDER BY created_at DESC LIMIT 1`,
		deviceID, groupID)
	var spkID string
	var priv, pub []byte
	err := row.Scan(&spkID, &priv, &pub)
	if err == sql.ErrNoRows {
		return "", nil, nil, nil
	}
	if err != nil {
		return "", nil, nil, fmt.Errorf("V2KeyStore.LoadCurrentGroupSPK: %w", err)
	}
	return spkID, priv, pub, nil
}

// DeleteSPK 销毁指定 SPK 私钥（用于 PFS）。
func (s *V2KeyStore) DeleteSPK(deviceID, spkID string) error {
	_, err := s.db.Exec(
		`DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND group_id='' AND key_id=?`,
		deviceID, spkID)
	if err != nil {
		return fmt.Errorf("V2KeyStore.DeleteSPK: %w", err)
	}
	_, err = s.db.Exec(
		`DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk_uploaded' AND group_id='' AND key_id=?`,
		deviceID, spkID)
	if err != nil {
		return fmt.Errorf("V2KeyStore.DeleteSPK marker: %w", err)
	}
	return nil
}

func (s *V2KeyStore) MarkSPKUploaded(deviceID, spkID string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
		 VALUES (?, 'spk_uploaded', '', ?, ?, ?, ?)`,
		deviceID, spkID, []byte{}, []byte{}, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("V2KeyStore.MarkSPKUploaded: %w", err)
	}
	return nil
}

func (s *V2KeyStore) LoadLatestUploadedSPKID(deviceID string) (string, error) {
	row := s.db.QueryRow(
		`SELECT marker.key_id FROM v2_device_keys AS marker
		 WHERE marker.device_id=? AND marker.key_type='spk_uploaded' AND marker.group_id=''
		   AND EXISTS (
		     SELECT 1 FROM v2_device_keys AS key
		     WHERE key.device_id=marker.device_id AND key.key_type='spk' AND key.group_id='' AND key.key_id=marker.key_id
		   )
		 ORDER BY marker.created_at DESC LIMIT 1`,
		deviceID)
	var spkID string
	err := row.Scan(&spkID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("V2KeyStore.LoadLatestUploadedSPKID: %w", err)
	}
	return spkID, nil
}

func (s *V2KeyStore) MarkGroupSPKUploaded(deviceID, groupID, spkID string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
		 VALUES (?, 'group_spk_uploaded', ?, ?, ?, ?, ?)`,
		deviceID, groupID, spkID, []byte{}, []byte{}, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("V2KeyStore.MarkGroupSPKUploaded: %w", err)
	}
	return nil
}

func (s *V2KeyStore) LoadLatestUploadedGroupSPKID(deviceID, groupID string) (string, error) {
	row := s.db.QueryRow(
		`SELECT marker.key_id FROM v2_device_keys AS marker
		 WHERE marker.device_id=? AND marker.key_type='group_spk_uploaded' AND marker.group_id=?
		   AND EXISTS (
		     SELECT 1 FROM v2_device_keys AS key
		     WHERE key.device_id=marker.device_id AND key.key_type='group_spk' AND key.group_id=marker.group_id AND key.key_id=marker.key_id
		   )
		 ORDER BY marker.created_at DESC LIMIT 1`,
		deviceID, groupID)
	var spkID string
	err := row.Scan(&spkID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("V2KeyStore.LoadLatestUploadedGroupSPKID: %w", err)
	}
	return spkID, nil
}

// ListRecentSPKIDs 返回最近 N 代 SPK 的 spk_id 列表（按 created_at 降序）。
//
// 用于销毁判定中的 "最近 N 代保留窗口"——即便其它销毁条件已满足，落在最近
// N 代窗口内的 SPK 也不销毁，给低频群提供额外冗余。
func (s *V2KeyStore) ListRecentSPKIDs(deviceID string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(
		`SELECT key_id FROM v2_device_keys
		 WHERE device_id=? AND key_type='spk' AND group_id='' ORDER BY created_at DESC LIMIT ?`,
		deviceID, n)
	if err != nil {
		return nil, fmt.Errorf("V2KeyStore.ListRecentSPKIDs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("V2KeyStore.ListRecentSPKIDs scan: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("V2KeyStore.ListRecentSPKIDs rows: %w", err)
	}
	return out, nil
}

// ListExpiredSPKIDs 返回 created_at 超过 maxAgeSeconds 的 SPK key_id 列表。
//
// 注意：使用 time.Now() 作为基准。测试场景需要注入虚拟时间时改用 ListExpiredSPKIDsAt。
func (s *V2KeyStore) ListExpiredSPKIDs(deviceID string, maxAgeSeconds float64) ([]string, error) {
	return s.ListExpiredSPKIDsAt(deviceID, maxAgeSeconds, time.Now())
}

// ListExpiredSPKIDsAt 是 ListExpiredSPKIDs 的可注入时间版本：以 now 为基准计算 cutoff。
// 用于让 V2Session 的 SetNowFnForTest 能贯穿到"180 天硬上限"判定。
func (s *V2KeyStore) ListExpiredSPKIDsAt(deviceID string, maxAgeSeconds float64, now time.Time) ([]string, error) {
	cutoff := float64(now.Unix()) - maxAgeSeconds
	rows, err := s.db.Query(
		`SELECT key_id FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND group_id='' AND created_at < ?`,
		deviceID, cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("V2KeyStore.ListExpiredSPKIDs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("V2KeyStore.ListExpiredSPKIDs scan: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("V2KeyStore.ListExpiredSPKIDs rows: %w", err)
	}
	return out, nil
}
