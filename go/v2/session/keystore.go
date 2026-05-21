// Package session 提供 V2 E2EE 会话和设备密钥持久化能力。
//
// 设计要点：
//   - IK = AID 长期密钥（多设备共享 AID 身份），由调用方注入，不在本包生成
//   - SPK 是设备级密钥（P-256），由 IK 签名背书，本包负责生成、轮换、销毁
//   - 持久化通过 SQLite（modernc.org/sqlite）实现，与 Python SDK 表结构互通
package session

import (
	"database/sql"
	"fmt"
	"time"
)

// V2DeviceKeysDDL V2 设备密钥表 DDL，与 Python SDK 一致。
const V2DeviceKeysDDL = `CREATE TABLE IF NOT EXISTS v2_device_keys (
    device_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    key_id TEXT NOT NULL DEFAULT '',
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, key_type, key_id)
)`

// V2KeyStore 设备密钥持久化。
//
// key_type 取值：
//   - "ik"   IK 主密钥；key_id 固定空串
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
	return &V2KeyStore{db: db}, nil
}

// SaveIK 保存 IK 主密钥（IK = AID 主密钥，通常无需调用，保留 API 兼容）。
func (s *V2KeyStore) SaveIK(deviceID string, priv, pubDER []byte) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at)
		 VALUES (?, 'ik', '', ?, ?, ?)`,
		deviceID, priv, pubDER, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("V2KeyStore.SaveIK: %w", err)
	}
	return nil
}

// LoadIK 加载 IK 主密钥；不存在时返回 (nil, nil, nil)。
func (s *V2KeyStore) LoadIK(deviceID string) (priv, pubDER []byte, err error) {
	row := s.db.QueryRow(
		`SELECT private_key, public_key FROM v2_device_keys
		 WHERE device_id=? AND key_type='ik' AND key_id=''`,
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

// SaveSPK 保存指定 spk_id 的 SPK 密钥。
func (s *V2KeyStore) SaveSPK(deviceID, spkID string, priv, pubDER []byte) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at)
		 VALUES (?, 'spk', ?, ?, ?, ?)`,
		deviceID, spkID, priv, pubDER, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("V2KeyStore.SaveSPK: %w", err)
	}
	return nil
}

// SaveSPKWithCreatedAt 保存 SPK 并指定 created_at（毫秒时间戳，仅供测试模拟时间使用）。
func (s *V2KeyStore) SaveSPKWithCreatedAt(deviceID, spkID string, priv, pubDER []byte, createdAtMs int64) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at)
		 VALUES (?, 'spk', ?, ?, ?, ?)`,
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
		 WHERE device_id=? AND key_type='spk' AND key_id=?`,
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
		 WHERE device_id=? AND key_type='spk' ORDER BY created_at DESC LIMIT 1`,
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

// DeleteSPK 销毁指定 SPK 私钥（用于 PFS）。
func (s *V2KeyStore) DeleteSPK(deviceID, spkID string) error {
	_, err := s.db.Exec(
		`DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND key_id=?`,
		deviceID, spkID)
	if err != nil {
		return fmt.Errorf("V2KeyStore.DeleteSPK: %w", err)
	}
	return nil
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
		 WHERE device_id=? AND key_type='spk' ORDER BY created_at DESC LIMIT ?`,
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
		`SELECT key_id FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND created_at < ?`,
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
