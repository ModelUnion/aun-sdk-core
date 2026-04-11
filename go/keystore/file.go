package keystore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/aun-sdk-core/go/secretstore"
)

// 需要加密保护的 token 字段
var sensitiveTokenFields = []string{"access_token", "refresh_token", "kite_token"}

// 需要合并保护的关键 metadata 字段
var criticalMetadataKeys = []string{"e2ee_prekeys", "e2ee_sessions", "group_secrets"}

const structuredRecoveryRetentionMs = int64(7 * 24 * time.Hour / time.Millisecond)

// secureFilePermissions 在 Unix 系统上设置文件权限为 0o600
func secureFilePermissions(path string) {
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
	}
}

// FileKeyStore 基于文件的密钥存储
// 目录结构: {root}/AIDs/{safe_aid}/private/key.json, public/cert.pem, tokens/meta.json
// 与 Python SDK keystore/file.py 完全对应。
type FileKeyStore struct {
	root          string
	aidsRoot      string
	secretStore   secretstore.SecretStore
	backup        *SQLiteBackup
	metaLocks     map[string]*sync.Mutex
	metaLocksLock sync.Mutex
}

// NewFileKeyStore 创建文件密钥存储
// backup 可为 nil（不启用 SQLite 备份）。
func NewFileKeyStore(root string, ss secretstore.SecretStore, encryptionSeed string, backup ...*SQLiteBackup) (*FileKeyStore, error) {
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			root = ".aun"
		} else {
			root = filepath.Join(home, ".aun")
		}
	}

	// 确保目录存在
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("创建密钥存储根目录失败: %w", err)
	}

	var sb *SQLiteBackup
	if len(backup) > 0 {
		sb = backup[0]
	}

	// 如果未提供 SecretStore，创建默认的 FileSecretStore
	if ss == nil {
		var err error
		if sb != nil {
			ss, err = secretstore.CreateDefaultSecretStore(root, encryptionSeed, sb)
		} else {
			ss, err = secretstore.CreateDefaultSecretStore(root, encryptionSeed)
		}
		if err != nil {
			return nil, fmt.Errorf("创建默认 SecretStore 失败: %w", err)
		}
	}

	aidsRoot := filepath.Join(root, "AIDs")
	if err := os.MkdirAll(aidsRoot, 0o700); err != nil {
		return nil, fmt.Errorf("创建 AIDs 目录失败: %w", err)
	}

	return &FileKeyStore{
		root:        root,
		aidsRoot:    aidsRoot,
		secretStore: ss,
		backup:      sb,
		metaLocks:   make(map[string]*sync.Mutex),
	}, nil
}

// safeAID 将 AID 中的特殊字符替换为下划线
func safeAID(aid string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_")
	return r.Replace(aid)
}

// identityDir 返回指定 AID 的身份目录
func (f *FileKeyStore) identityDir(aid string) string {
	return filepath.Join(f.aidsRoot, safeAID(aid))
}

// keyPairPath 返回密钥对文件路径
func (f *FileKeyStore) keyPairPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "private", "key.json")
}

// certPath 返回证书文件路径
func (f *FileKeyStore) certPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "public", "cert.pem")
}

// metadataPath 返回元数据文件路径
func (f *FileKeyStore) metadataPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "tokens", "meta.json")
}

// LoadKeyPair 加载密钥对
func (f *FileKeyStore) LoadKeyPair(aid string) (map[string]any, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()
	return f.loadKeyPairUnlocked(aid)
}

func (f *FileKeyStore) loadKeyPairUnlocked(aid string) (map[string]any, error) {
	path := f.keyPairPath(aid)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在 → 从 SQLite 恢复
			return f.restoreKeyPairFromSQLite(aid)
		}
		return nil, fmt.Errorf("读取密钥对文件失败: %w", err)
	}

	var keyPair map[string]any
	if err := json.Unmarshal(data, &keyPair); err != nil {
		return nil, fmt.Errorf("解析密钥对 JSON 失败: %w", err)
	}

	// 双读：文件有，确保 SQLite 也有
	f.backupKeyPairToSQLite(aid, data)
	return f.restoreKeyPair(aid, keyPair), nil
}

// SaveKeyPair 保存密钥对（保护私钥）
func (f *FileKeyStore) SaveKeyPair(aid string, keyPair map[string]any) error {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()
	return f.saveKeyPairUnlocked(aid, keyPair)
}

func (f *FileKeyStore) saveKeyPairUnlocked(aid string, keyPair map[string]any) error {
	path := f.keyPairPath(aid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建密钥对目录失败: %w", err)
	}

	// 深拷贝并保护私钥
	protected := copyMap(keyPair)
	scope := safeAID(aid)

	if privateKeyPEM, ok := protected["private_key_pem"].(string); ok && privateKeyPEM != "" {
		delete(protected, "private_key_pem")
		protection, err := f.secretStore.Protect(scope, "identity/private_key", []byte(privateKeyPEM))
		if err != nil {
			return fmt.Errorf("保护私钥失败: %w", err)
		}
		persisted, _ := protection["persisted"].(bool)
		if !persisted {
			return fmt.Errorf("SecretStore 无法持久化私钥 (scheme=%v)。私钥必须能跨进程重启保留", protection["scheme"])
		}
		protected["private_key_protection"] = protection
	}

	data, err := json.MarshalIndent(protected, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化密钥对 JSON 失败: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("写入密钥对文件失败: %w", err)
	}
	secureFilePermissions(path)
	// 双写：备份到 SQLite
	f.backupKeyPairToSQLite(aid, data)
	return nil
}

// LoadCert 加载证书（PEM 字符串）
func (f *FileKeyStore) LoadCert(aid string) (string, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()
	return f.loadCertUnlocked(aid)
}

func (f *FileKeyStore) loadCertUnlocked(aid string) (string, error) {
	path := f.certPath(aid)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在 → 从 SQLite 恢复
			return f.restoreCertFromSQLite(aid)
		}
		return "", fmt.Errorf("读取证书文件失败: %w", err)
	}
	cert := string(data)
	// 双读：文件有，确保 SQLite 也有
	f.backupCertToSQLite(aid, cert)
	return cert, nil
}

// SaveCert 保存证书（PEM 字符串）
func (f *FileKeyStore) SaveCert(aid string, certPEM string) error {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()
	return f.saveCertUnlocked(aid, certPEM)
}

func (f *FileKeyStore) saveCertUnlocked(aid string, certPEM string) error {
	path := f.certPath(aid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}
	if err := os.WriteFile(path, []byte(certPEM), 0o644); err != nil {
		return fmt.Errorf("写入证书文件失败: %w", err)
	}
	// 双写：备份到 SQLite
	f.backupCertToSQLite(aid, certPEM)
	return nil
}

// LoadMetadata 加载元数据
func (f *FileKeyStore) LoadMetadata(aid string) (map[string]any, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()
	return f.buildMergedMetadataLocked(aid), nil
}

// SaveMetadata 保存元数据（保护敏感字段，带并发锁）
func (f *FileKeyStore) SaveMetadata(aid string, metadata map[string]any) error {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()
	return f.saveMetadataLocked(aid, metadata)
}

// UpdateMetadata 在同一把 AID 级锁内完成 load -> mutate -> save。
func (f *FileKeyStore) UpdateMetadata(
	aid string,
	updater func(map[string]any) (map[string]any, error),
) (map[string]any, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	current := f.buildMergedMetadataLocked(aid)
	if current == nil {
		current = make(map[string]any)
	}
	working := deepCopyMap(current)
	updated, err := updater(working)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		updated = working
	}
	if err := f.saveMetadataLocked(aid, updated); err != nil {
		return nil, err
	}
	return deepCopyMap(updated), nil
}

func (f *FileKeyStore) saveMetadataLocked(aid string, metadata map[string]any) error {
	current := f.buildMergedMetadataLocked(aid)
	merged := deepCopyMap(metadata)
	if merged == nil {
		merged = make(map[string]any)
	}

	for _, key := range criticalMetadataKeys {
		if val, ok := current[key]; ok && val != nil {
			if _, hasNew := merged[key]; !hasNew {
				log.Printf("save_metadata: 传入数据缺少 '%s' (aid=%s)，自动合并已有数据", key, aid)
				merged[key] = cloneAny(val)
			}
		}
	}

	if f.sqliteEnabled() {
		if _, ok := merged["e2ee_prekeys"].(map[string]any); ok {
			f.replacePrekeysSQLiteLocked(aid, prekeysAnyToTyped(merged["e2ee_prekeys"]))
		}
		if _, ok := merged["group_secrets"].(map[string]any); ok {
			f.replaceGroupStatesSQLiteLocked(aid, groupStatesAnyToTyped(merged["group_secrets"]))
		}
	}

	return f.saveMetaJSONOnlyLocked(aid, merged)
}

// LoadIdentity 加载完整身份信息
func (f *FileKeyStore) LoadIdentity(aid string) (map[string]any, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	keyPair, err := f.loadKeyPairUnlocked(aid)
	if err != nil {
		return nil, err
	}
	cert, err := f.loadCertUnlocked(aid)
	if err != nil {
		return nil, err
	}
	metadata := f.buildMergedMetadataLocked(aid)

	if keyPair == nil && cert == "" && metadata == nil {
		return nil, nil
	}

	identity := make(map[string]any)
	if metadata != nil {
		for k, v := range metadata {
			identity[k] = v
		}
	}
	if keyPair != nil {
		for k, v := range keyPair {
			identity[k] = v
		}
	}
	if cert != "" {
		identity["cert"] = cert
	}
	return identity, nil
}

// SaveIdentity 保存完整身份信息（自动拆分）
func (f *FileKeyStore) SaveIdentity(aid string, identity map[string]any) error {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	// 提取密钥对字段
	keyPair := make(map[string]any)
	for _, k := range []string{"private_key_pem", "public_key_der_b64", "curve"} {
		if v, ok := identity[k]; ok {
			keyPair[k] = v
		}
	}
	if len(keyPair) > 0 {
		if err := f.saveKeyPairUnlocked(aid, keyPair); err != nil {
			return err
		}
	}

	// 保存证书
	if cert, ok := identity["cert"].(string); ok && cert != "" {
		if err := f.saveCertUnlocked(aid, cert); err != nil {
			return err
		}
	}

	// 合并 metadata（先加载已有数据，再更新新字段）
	newFields := make(map[string]any)
	skipKeys := map[string]bool{"private_key_pem": true, "public_key_der_b64": true, "curve": true, "cert": true}
	for k, v := range identity {
		if !skipKeys[k] {
			newFields[k] = v
		}
	}

	current := f.buildMergedMetadataLocked(aid)
	if current == nil {
		current = make(map[string]any)
	}
	updated := deepCopyMap(current)
	for k, v := range newFields {
		updated[k] = v
	}
	return f.saveMetadataLocked(aid, updated)
}

// LoadAnyIdentity 加载任意已存在的身份（用于首次启动场景）
func (f *FileKeyStore) LoadAnyIdentity() (map[string]any, error) {
	entries, err := os.ReadDir(f.aidsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		aid := entry.Name()
		identity, err := f.LoadIdentity(aid)
		if err != nil {
			continue
		}
		if identity != nil {
			return identity, nil
		}
	}
	return nil, nil
}

// LoadE2EEPrekeys 加载结构化 prekeys 主存。
func (f *FileKeyStore) LoadE2EEPrekeys(aid string) (map[string]map[string]any, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	metaOnly := f.loadMetaJSONOnly(aid)
	f.syncStructuredStateFromMetaLocked(aid, metaOnly)
	if f.sqliteEnabled() {
		return f.loadPrekeysFromSQLiteLocked(aid), nil
	}
	return prekeysAnyToTyped(metaOnly["e2ee_prekeys"]), nil
}

// SaveE2EEPrekey 保存结构化 prekey 主存，并同步兼容 metadata 视图。
func (f *FileKeyStore) SaveE2EEPrekey(aid, prekeyID string, prekeyData map[string]any) error {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	existing := make(map[string]map[string]any)
	if f.sqliteEnabled() {
		metaOnly := f.loadMetaJSONOnly(aid)
		f.syncStructuredStateFromMetaLocked(aid, metaOnly)
		existing = f.loadPrekeysFromSQLiteLocked(aid)
	}
	existing[prekeyID] = deepCopyTypedMap(prekeyData)
	if f.sqliteEnabled() {
		f.replacePrekeysSQLiteLocked(aid, existing)
	}
	return f.updateMetaJSONOnlyLocked(aid, func(meta map[string]any) map[string]any {
		return f.setPrekeyBackup(meta, prekeyID, prekeyData)
	})
}

// CleanupE2EEPrekeys 清理结构化 prekeys。
func (f *FileKeyStore) CleanupE2EEPrekeys(aid string, cutoffMs int64, keepLatest int) ([]string, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	metaOnly := f.loadMetaJSONOnly(aid)
	f.syncStructuredStateFromMetaLocked(aid, metaOnly)
	var removed []string
	if f.sqliteEnabled() {
		removed = f.backup.CleanupPrekeysBefore(aid, cutoffMs, keepLatest)
	} else {
		prekeys := prekeysAnyToTyped(metaOnly["e2ee_prekeys"])
		retainedIDs := latestPrekeyIDs(prekeys, keepLatest)
		for prekeyID, prekeyData := range prekeys {
			marker := prekeyCreatedMarker(prekeyData)
			if marker < cutoffMs && !retainedIDs[prekeyID] {
				removed = append(removed, prekeyID)
			}
		}
	}
	if len(removed) > 0 {
		if err := f.updateMetaJSONOnlyLocked(aid, func(meta map[string]any) map[string]any {
			return f.removePrekeysFromBackup(meta, removed)
		}); err != nil {
			return nil, err
		}
	}
	return removed, nil
}

// LoadGroupSecretState 加载单个群组结构化密钥状态。
func (f *FileKeyStore) LoadGroupSecretState(aid, groupID string) (map[string]any, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	metaOnly := f.loadMetaJSONOnly(aid)
	f.syncStructuredStateFromMetaLocked(aid, metaOnly)
	if f.sqliteEnabled() {
		groups := f.loadGroupStatesFromSQLiteLocked(aid)
		if entry, ok := groups[groupID]; ok {
			return deepCopyMap(entry), nil
		}
		return nil, nil
	}
	groups := groupStatesAnyToTyped(metaOnly["group_secrets"])
	if entry, ok := groups[groupID]; ok {
		return deepCopyMap(entry), nil
	}
	return nil, nil
}

// LoadAllGroupSecretStates 加载全部群组结构化密钥状态。
func (f *FileKeyStore) LoadAllGroupSecretStates(aid string) (map[string]map[string]any, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	metaOnly := f.loadMetaJSONOnly(aid)
	f.syncStructuredStateFromMetaLocked(aid, metaOnly)
	if f.sqliteEnabled() {
		return f.loadGroupStatesFromSQLiteLocked(aid), nil
	}
	return groupStatesAnyToTyped(metaOnly["group_secrets"]), nil
}

// SaveGroupSecretState 保存单个群组结构化密钥状态。
func (f *FileKeyStore) SaveGroupSecretState(aid, groupID string, entry map[string]any) error {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	if f.sqliteEnabled() {
		metaOnly := f.loadMetaJSONOnly(aid)
		f.syncStructuredStateFromMetaLocked(aid, metaOnly)
		currentGroups := f.loadGroupStatesFromSQLiteLocked(aid)
		currentGroups[groupID] = deepCopyTypedMap(entry)
		f.replaceGroupStatesSQLiteLocked(aid, currentGroups)
	}
	return f.updateMetaJSONOnlyLocked(aid, func(meta map[string]any) map[string]any {
		return f.setGroupBackup(meta, groupID, entry)
	})
}

// CleanupGroupOldEpochsState 清理过期旧 epoch 状态。
func (f *FileKeyStore) CleanupGroupOldEpochsState(aid, groupID string, cutoffMs int64) (int, error) {
	lock := f.getMetadataLock(aid)
	lock.Lock()
	defer lock.Unlock()

	metaOnly := f.loadMetaJSONOnly(aid)
	f.syncStructuredStateFromMetaLocked(aid, metaOnly)
	var removedEpochs []int
	if f.sqliteEnabled() {
		removedEpochs = f.backup.CleanupGroupOldEpochs(aid, groupID, cutoffMs)
	} else {
		groupStates := groupStatesAnyToTyped(metaOnly["group_secrets"])
		entry := groupStates[groupID]
		oldEpochs, _ := entry["old_epochs"].([]any)
		remaining := make([]any, 0, len(oldEpochs))
		for _, raw := range oldEpochs {
			old, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			marker := int64OrDefault(old["updated_at"], old["expires_at"])
			if marker < cutoffMs {
				if epoch, ok := int64OrNil(old["epoch"]); ok {
					removedEpochs = append(removedEpochs, int(epoch))
				}
				continue
			}
			remaining = append(remaining, old)
		}
		if entry != nil {
			entry["old_epochs"] = remaining
		}
	}
	if len(removedEpochs) > 0 {
		if err := f.updateMetaJSONOnlyLocked(aid, func(meta map[string]any) map[string]any {
			return f.removeGroupOldEpochsFromBackup(meta, groupID, removedEpochs)
		}); err != nil {
			return 0, err
		}
	}
	return len(removedEpochs), nil
}

// ── 内部方法：保护与还原 ─────────────────────────────────

// restoreKeyPair 还原被保护的密钥对
func (f *FileKeyStore) restoreKeyPair(aid string, keyPair map[string]any) map[string]any {
	restored := copyMap(keyPair)
	scope := safeAID(aid)

	if record, ok := restored["private_key_protection"].(map[string]any); ok {
		value, err := f.secretStore.Reveal(scope, "identity/private_key", record)
		if err == nil && value != nil {
			restored["private_key_pem"] = string(value)
		} else {
			delete(restored, "private_key_pem")
		}
	}
	return restored
}

// protectMetadata 保护元数据中的敏感字段
func (f *FileKeyStore) protectMetadata(aid string, metadata map[string]any) map[string]any {
	protected := copyMap(metadata)
	scope := safeAID(aid)

	// 保护 token 字段
	for _, field := range sensitiveTokenFields {
		if value, ok := protected[field].(string); ok && value != "" {
			delete(protected, field)
			protection, err := f.secretStore.Protect(scope, field, []byte(value))
			if err == nil {
				protected[field+"_protection"] = protection
			}
		}
	}

	// 保护 e2ee_sessions 中的 key
	if sessions, ok := protected["e2ee_sessions"].([]any); ok {
		sanitized := make([]any, 0, len(sessions))
		for _, raw := range sessions {
			session, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			s := copyMap(session)
			secretName := sessionSecretName(s)
			if value, ok := s["key"].(string); ok && value != "" && secretName != "" {
				delete(s, "key")
				protection, err := f.secretStore.Protect(scope, secretName, []byte(value))
				if err == nil {
					s["key_protection"] = protection
				}
			}
			sanitized = append(sanitized, s)
		}
		protected["e2ee_sessions"] = sanitized
	}

	// 保护 e2ee_prekeys 中的 private_key_pem
	if prekeys, ok := protected["e2ee_prekeys"].(map[string]any); ok {
		sanitized := make(map[string]any)
		for prekeyID, raw := range prekeys {
			prekeyData, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			prekey := copyMap(prekeyData)
			secretName := fmt.Sprintf("e2ee_prekeys/%s/private_key", prekeyID)
			if value, ok := prekey["private_key_pem"].(string); ok && value != "" {
				delete(prekey, "private_key_pem")
				protection, err := f.secretStore.Protect(scope, secretName, []byte(value))
				if err == nil {
					prekey["private_key_protection"] = protection
				}
			}
			sanitized[prekeyID] = prekey
		}
		protected["e2ee_prekeys"] = sanitized
	}

	// 保护 group_secrets 中的 secret
	if groupSecrets, ok := protected["group_secrets"].(map[string]any); ok {
		sanitized := make(map[string]any)
		for groupID, raw := range groupSecrets {
			groupData, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			group := copyMap(groupData)
			secretName := fmt.Sprintf("group_secrets/%s/secret", groupID)
			if value, ok := group["secret"].(string); ok && value != "" {
				delete(group, "secret")
				protection, err := f.secretStore.Protect(scope, secretName, []byte(value))
				if err == nil {
					group["secret_protection"] = protection
				}
			}

			// 保护 old_epochs 中的 secret
			if oldEpochs, ok := group["old_epochs"].([]any); ok {
				sanitizedOld := make([]any, 0, len(oldEpochs))
				for _, oldRaw := range oldEpochs {
					oldData, ok := oldRaw.(map[string]any)
					if !ok {
						continue
					}
					old := copyMap(oldData)
					oldEpoch := fmt.Sprintf("%v", old["epoch"])
					oldSecretName := fmt.Sprintf("group_secrets/%s/old/%s", groupID, oldEpoch)
					if value, ok := old["secret"].(string); ok && value != "" {
						delete(old, "secret")
						protection, err := f.secretStore.Protect(scope, oldSecretName, []byte(value))
						if err == nil {
							old["secret_protection"] = protection
						}
					}
					sanitizedOld = append(sanitizedOld, old)
				}
				group["old_epochs"] = sanitizedOld
			}

			sanitized[groupID] = group
		}
		protected["group_secrets"] = sanitized
	}

	return protected
}

// restoreMetadata 还原被保护的元数据
func (f *FileKeyStore) restoreMetadata(aid string, metadata map[string]any) map[string]any {
	restored := copyMap(metadata)
	scope := safeAID(aid)

	// 还原 token 字段
	for _, field := range sensitiveTokenFields {
		if record, ok := restored[field+"_protection"].(map[string]any); ok {
			value, err := f.secretStore.Reveal(scope, field, record)
			if err == nil && value != nil {
				restored[field] = string(value)
			} else {
				delete(restored, field)
			}
		}
	}

	// 还原 e2ee_sessions 中的 key
	if sessions, ok := restored["e2ee_sessions"].([]any); ok {
		for _, raw := range sessions {
			session, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if record, ok := session["key_protection"].(map[string]any); ok {
				secretName := sessionSecretName(session)
				if secretName != "" {
					value, err := f.secretStore.Reveal(scope, secretName, record)
					if err == nil && value != nil {
						session["key"] = string(value)
					} else {
						delete(session, "key")
					}
				}
			}
		}
	}

	// 还原 e2ee_prekeys 中的 private_key_pem
	if prekeys, ok := restored["e2ee_prekeys"].(map[string]any); ok {
		for prekeyID, raw := range prekeys {
			prekeyData, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if record, ok := prekeyData["private_key_protection"].(map[string]any); ok {
				secretName := fmt.Sprintf("e2ee_prekeys/%s/private_key", prekeyID)
				value, err := f.secretStore.Reveal(scope, secretName, record)
				if err == nil && value != nil {
					prekeyData["private_key_pem"] = string(value)
				} else {
					delete(prekeyData, "private_key_pem")
				}
			}
		}
	}

	// 还原 group_secrets 中的 secret
	if groupSecrets, ok := restored["group_secrets"].(map[string]any); ok {
		for groupID, raw := range groupSecrets {
			groupData, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if record, ok := groupData["secret_protection"].(map[string]any); ok {
				secretName := fmt.Sprintf("group_secrets/%s/secret", groupID)
				value, err := f.secretStore.Reveal(scope, secretName, record)
				if err == nil && value != nil {
					groupData["secret"] = string(value)
				} else {
					delete(groupData, "secret")
				}
			}
			// 还原 old_epochs 中的 secret
			if oldEpochs, ok := groupData["old_epochs"].([]any); ok {
				for _, oldRaw := range oldEpochs {
					oldData, ok := oldRaw.(map[string]any)
					if !ok {
						continue
					}
					if oldRecord, ok := oldData["secret_protection"].(map[string]any); ok {
						oldEpoch := fmt.Sprintf("%v", oldData["epoch"])
						oldSecretName := fmt.Sprintf("group_secrets/%s/old/%s", groupID, oldEpoch)
						value, err := f.secretStore.Reveal(scope, oldSecretName, oldRecord)
						if err == nil && value != nil {
							oldData["secret"] = string(value)
						} else {
							delete(oldData, "secret")
						}
					}
				}
			}
			_ = groupID // 避免 unused 警告
		}
	}

	return restored
}

// sessionSecretName 构建 session 密钥的 secret name
func sessionSecretName(session map[string]any) string {
	sessionID, _ := session["session_id"].(string)
	if sessionID == "" {
		return ""
	}
	return fmt.Sprintf("e2ee_sessions/%s/key", sessionID)
}

// copyMap 浅拷贝 map（一层深度）
func copyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func deepCopyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = cloneAny(value)
	}
	return dst
}

func cloneAny(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return deepCopyMap(v)
	case []any:
		items := make([]any, len(v))
		for i, item := range v {
			items[i] = cloneAny(item)
		}
		return items
	default:
		return v
	}
}

func deepCopyTypedMap(src map[string]any) map[string]any {
	return deepCopyMap(src)
}

// ── 并发锁管理 ──────────────────────────────────────────────

func (f *FileKeyStore) getMetadataLock(aid string) *sync.Mutex {
	f.metaLocksLock.Lock()
	defer f.metaLocksLock.Unlock()
	if lock, ok := f.metaLocks[aid]; ok {
		return lock
	}
	lock := &sync.Mutex{}
	f.metaLocks[aid] = lock
	return lock
}

// ── SQLite 双写双读辅助方法 ─────────────────────────────────

func (f *FileKeyStore) sqliteEnabled() bool {
	return f.backup != nil && f.backup.IsAvailable()
}

// Close 释放 FileKeyStore 持有的 SQLite 资源。
func (f *FileKeyStore) Close() {
	if f == nil || f.backup == nil {
		return
	}
	f.backup.Close()
}

func (f *FileKeyStore) loadMetaJSONOnly(aid string) map[string]any {
	path := f.metadataPath(aid)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			metadata, _ := f.restoreMetadataFromSQLite(aid)
			return metadata
		}
		return nil
	}

	var metadata map[string]any
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil
	}
	f.backupMetadataToSQLite(aid, data)
	return f.restoreMetadata(aid, metadata)
}

func (f *FileKeyStore) buildMergedMetadataLocked(aid string) map[string]any {
	metadata := f.loadMetaJSONOnly(aid)
	if metadata == nil {
		metadata = make(map[string]any)
	}
	f.syncStructuredStateFromMetaLocked(aid, metadata)
	if f.sqliteEnabled() {
		delete(metadata, "e2ee_prekeys")
		delete(metadata, "group_secrets")
		if prekeys := f.loadPrekeysFromSQLiteLocked(aid); len(prekeys) > 0 {
			metadata["e2ee_prekeys"] = typedPrekeysToAny(prekeys)
		}
		if groups := f.loadGroupStatesFromSQLiteLocked(aid); len(groups) > 0 {
			metadata["group_secrets"] = typedGroupsToAny(groups)
		}
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

func (f *FileKeyStore) saveMetaJSONOnlyLocked(aid string, metadata map[string]any) error {
	path := f.metadataPath(aid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建元数据目录失败: %w", err)
	}

	protected := f.protectMetadata(aid, metadata)
	data, err := json.MarshalIndent(protected, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化元数据 JSON 失败: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("写入元数据文件失败: %w", err)
	}
	secureFilePermissions(path)
	f.backupMetadataToSQLite(aid, data)
	return nil
}

func (f *FileKeyStore) updateMetaJSONOnlyLocked(
	aid string,
	updater func(map[string]any) map[string]any,
) error {
	current := f.loadMetaJSONOnly(aid)
	if current == nil {
		current = make(map[string]any)
	}
	working := deepCopyMap(current)
	updated := updater(working)
	if updated == nil {
		updated = working
	}
	return f.saveMetaJSONOnlyLocked(aid, updated)
}

func (f *FileKeyStore) syncStructuredStateFromMetaLocked(aid string, metadata map[string]any) {
	if !f.sqliteEnabled() || metadata == nil {
		return
	}

	metaPrekeys := prekeysAnyToTyped(metadata["e2ee_prekeys"])
	if len(metaPrekeys) > 0 {
		latestIDs := latestPrekeyIDs(metaPrekeys, 7)
		sqlitePrekeys := f.loadPrekeysFromSQLiteLocked(aid)
		changed := false
		for prekeyID, prekeyData := range metaPrekeys {
			if _, ok := sqlitePrekeys[prekeyID]; ok {
				continue
			}
			if !isPrekeyRecoverable(prekeyData, latestIDs[prekeyID]) {
				continue
			}
			sqlitePrekeys[prekeyID] = deepCopyTypedMap(prekeyData)
			changed = true
		}
		if changed {
			f.replacePrekeysSQLiteLocked(aid, sqlitePrekeys)
		}
	}

	metaGroups := groupStatesAnyToTyped(metadata["group_secrets"])
	if len(metaGroups) > 0 {
		sqliteGroups := f.loadGroupStatesFromSQLiteLocked(aid)
		changed := false
		for groupID, incoming := range metaGroups {
			merged := mergeGroupEntryFromMeta(sqliteGroups[groupID], incoming)
			if !mapsEqual(sqliteGroups[groupID], merged) {
				sqliteGroups[groupID] = merged
				changed = true
			}
		}
		if changed {
			f.replaceGroupStatesSQLiteLocked(aid, sqliteGroups)
		}
	}
}

func (f *FileKeyStore) loadPrekeysFromSQLiteLocked(aid string) map[string]map[string]any {
	if !f.sqliteEnabled() {
		return map[string]map[string]any{}
	}
	protected := f.backup.LoadPrekeys(aid)
	return restoreTypedPrekeys(f, aid, protected)
}

func (f *FileKeyStore) replacePrekeysSQLiteLocked(aid string, prekeys map[string]map[string]any) {
	if !f.sqliteEnabled() {
		return
	}
	protected := protectTypedPrekeys(f, aid, prekeys)
	f.backup.ReplacePrekeys(aid, protected)
}

func (f *FileKeyStore) loadGroupStatesFromSQLiteLocked(aid string) map[string]map[string]any {
	if !f.sqliteEnabled() {
		return map[string]map[string]any{}
	}
	protected := f.backup.LoadGroupEntries(aid)
	return restoreTypedGroups(f, aid, protected)
}

func (f *FileKeyStore) replaceGroupStatesSQLiteLocked(aid string, groups map[string]map[string]any) {
	if !f.sqliteEnabled() {
		return
	}
	protected := protectTypedGroups(f, aid, groups)
	f.backup.ReplaceGroupEntries(aid, protected)
}

func (f *FileKeyStore) setPrekeyBackup(metadata map[string]any, prekeyID string, prekeyData map[string]any) map[string]any {
	prekeys, _ := metadata["e2ee_prekeys"].(map[string]any)
	if prekeys == nil {
		prekeys = make(map[string]any)
	}
	prekeys[prekeyID] = deepCopyMap(prekeyData)
	metadata["e2ee_prekeys"] = prekeys
	return metadata
}

func (f *FileKeyStore) removePrekeysFromBackup(metadata map[string]any, prekeyIDs []string) map[string]any {
	prekeys, _ := metadata["e2ee_prekeys"].(map[string]any)
	for _, prekeyID := range prekeyIDs {
		delete(prekeys, prekeyID)
	}
	return metadata
}

func (f *FileKeyStore) setGroupBackup(metadata map[string]any, groupID string, entry map[string]any) map[string]any {
	groupSecrets, _ := metadata["group_secrets"].(map[string]any)
	if groupSecrets == nil {
		groupSecrets = make(map[string]any)
	}
	groupSecrets[groupID] = deepCopyMap(entry)
	metadata["group_secrets"] = groupSecrets
	return metadata
}

func (f *FileKeyStore) removeGroupOldEpochsFromBackup(metadata map[string]any, groupID string, removedEpochs []int) map[string]any {
	groupSecrets, _ := metadata["group_secrets"].(map[string]any)
	entry, _ := groupSecrets[groupID].(map[string]any)
	oldEpochs, _ := entry["old_epochs"].([]any)
	remaining := make([]any, 0, len(oldEpochs))
	for _, raw := range oldEpochs {
		old, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		epoch, ok := int64OrNil(old["epoch"])
		if ok && containsInt(removedEpochs, int(epoch)) {
			continue
		}
		remaining = append(remaining, old)
	}
	if entry != nil {
		entry["old_epochs"] = remaining
	}
	return metadata
}

func (f *FileKeyStore) backupKeyPairToSQLite(aid string, data []byte) {
	if f.backup != nil && f.backup.IsAvailable() {
		f.backup.BackupKeyPair(aid, string(data))
	}
}

func (f *FileKeyStore) restoreKeyPairFromSQLite(aid string) (map[string]any, error) {
	if f.backup == nil || !f.backup.IsAvailable() {
		return nil, nil
	}
	data := f.backup.RestoreKeyPair(aid)
	if data == "" {
		return nil, nil
	}
	log.Printf("从 SQLite 恢复 key_pair (aid=%s)", aid)
	var keyPair map[string]any
	if err := json.Unmarshal([]byte(data), &keyPair); err != nil {
		log.Printf("[WARN] 从 SQLite 恢复 key_pair 失败 (aid=%s): %v", aid, err)
		return nil, nil
	}
	// 写回文件系统
	path := f.keyPairPath(aid)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(data), 0o600)
	secureFilePermissions(path)
	return f.restoreKeyPair(aid, keyPair), nil
}

func (f *FileKeyStore) backupCertToSQLite(aid string, cert string) {
	if f.backup != nil && f.backup.IsAvailable() {
		f.backup.BackupCert(aid, cert)
	}
}

func (f *FileKeyStore) restoreCertFromSQLite(aid string) (string, error) {
	if f.backup == nil || !f.backup.IsAvailable() {
		return "", nil
	}
	cert := f.backup.RestoreCert(aid)
	if cert == "" {
		return "", nil
	}
	log.Printf("从 SQLite 恢复 cert (aid=%s)", aid)
	path := f.certPath(aid)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(cert), 0o644)
	return cert, nil
}

func (f *FileKeyStore) backupMetadataToSQLite(aid string, data []byte) {
	if f.backup != nil && f.backup.IsAvailable() {
		f.backup.BackupMetadata(aid, string(data))
	}
}

func (f *FileKeyStore) restoreMetadataFromSQLite(aid string) (map[string]any, error) {
	if f.backup == nil || !f.backup.IsAvailable() {
		return nil, nil
	}
	data := f.backup.RestoreMetadata(aid)
	if data == "" {
		return nil, nil
	}
	log.Printf("从 SQLite 恢复 metadata (aid=%s)", aid)
	var protected map[string]any
	if err := json.Unmarshal([]byte(data), &protected); err != nil {
		log.Printf("[WARN] 从 SQLite 恢复 metadata 失败 (aid=%s): %v", aid, err)
		return nil, nil
	}
	// 写回文件系统
	path := f.metadataPath(aid)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(data), 0o600)
	secureFilePermissions(path)
	return f.restoreMetadata(aid, protected), nil
}

func prekeysAnyToTyped(value any) map[string]map[string]any {
	raw, _ := value.(map[string]any)
	result := make(map[string]map[string]any, len(raw))
	for prekeyID, item := range raw {
		if data, ok := item.(map[string]any); ok {
			result[prekeyID] = deepCopyMap(data)
		}
	}
	return result
}

func typedPrekeysToAny(prekeys map[string]map[string]any) map[string]any {
	if len(prekeys) == 0 {
		return nil
	}
	result := make(map[string]any, len(prekeys))
	for prekeyID, data := range prekeys {
		result[prekeyID] = deepCopyMap(data)
	}
	return result
}

func groupStatesAnyToTyped(value any) map[string]map[string]any {
	raw, _ := value.(map[string]any)
	result := make(map[string]map[string]any, len(raw))
	for groupID, item := range raw {
		if data, ok := item.(map[string]any); ok {
			result[groupID] = deepCopyMap(data)
		}
	}
	return result
}

func typedGroupsToAny(groups map[string]map[string]any) map[string]any {
	if len(groups) == 0 {
		return nil
	}
	result := make(map[string]any, len(groups))
	for groupID, data := range groups {
		result[groupID] = deepCopyMap(data)
	}
	return result
}

func protectTypedPrekeys(f *FileKeyStore, aid string, prekeys map[string]map[string]any) map[string]map[string]any {
	protected := f.protectMetadata(aid, map[string]any{
		"e2ee_prekeys": typedPrekeysToAny(prekeys),
	})
	return prekeysAnyToTyped(protected["e2ee_prekeys"])
}

func restoreTypedPrekeys(f *FileKeyStore, aid string, prekeys map[string]map[string]any) map[string]map[string]any {
	restored := f.restoreMetadata(aid, map[string]any{
		"e2ee_prekeys": typedPrekeysToAny(prekeys),
	})
	return prekeysAnyToTyped(restored["e2ee_prekeys"])
}

func protectTypedGroups(f *FileKeyStore, aid string, groups map[string]map[string]any) map[string]map[string]any {
	protected := f.protectMetadata(aid, map[string]any{
		"group_secrets": typedGroupsToAny(groups),
	})
	return groupStatesAnyToTyped(protected["group_secrets"])
}

func restoreTypedGroups(f *FileKeyStore, aid string, groups map[string]map[string]any) map[string]map[string]any {
	restored := f.restoreMetadata(aid, map[string]any{
		"group_secrets": typedGroupsToAny(groups),
	})
	return groupStatesAnyToTyped(restored["group_secrets"])
}

func prekeyCreatedMarker(record map[string]any) int64 {
	return int64OrDefault(record["created_at"], record["updated_at"], record["expires_at"])
}

func latestPrekeyIDs(prekeys map[string]map[string]any, keepLatest int) map[string]bool {
	if keepLatest <= 0 {
		return map[string]bool{}
	}
	type prekeyEntry struct {
		id     string
		marker int64
	}
	entries := make([]prekeyEntry, 0, len(prekeys))
	for prekeyID, record := range prekeys {
		entries = append(entries, prekeyEntry{
			id:     prekeyID,
			marker: prekeyCreatedMarker(record),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].marker != entries[j].marker {
			return entries[i].marker > entries[j].marker
		}
		return entries[i].id > entries[j].id
	})
	result := make(map[string]bool, keepLatest)
	for idx, entry := range entries {
		if idx >= keepLatest {
			break
		}
		result[entry.id] = true
	}
	return result
}

func isPrekeyRecoverable(record map[string]any, keepBecauseLatest bool) bool {
	return isUnexpiredRecord(record, "created_at", keepBecauseLatest)
}

func isGroupEpochRecoverable(record map[string]any) bool {
	return isUnexpiredRecord(record, "updated_at", false)
}

func isUnexpiredRecord(record map[string]any, fallbackKey string, keepBecauseLatest bool) bool {
	nowMs := time.Now().UnixMilli()
	if expiresAt, ok := int64OrNil(record["expires_at"]); ok {
		return expiresAt >= nowMs
	}
	if marker, ok := int64OrNil(record[fallbackKey]); ok {
		if keepBecauseLatest {
			return true
		}
		return marker+structuredRecoveryRetentionMs >= nowMs
	}
	return false
}

func mergeGroupEntryFromMeta(existing, incoming map[string]any) map[string]any {
	var current map[string]any
	if existing != nil {
		if _, ok := int64OrNil(existing["epoch"]); ok {
			current = deepCopyMap(existing)
			delete(current, "old_epochs")
		}
	}

	oldByEpoch := make(map[int]map[string]any)
	if existing != nil {
		if oldEpochs, ok := existing["old_epochs"].([]any); ok {
			for _, raw := range oldEpochs {
				old, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				if epoch, ok := int64OrNil(old["epoch"]); ok {
					oldByEpoch[int(epoch)] = deepCopyMap(old)
				}
			}
		}
	}

	var incomingCurrent map[string]any
	if incoming != nil {
		if incomingEpoch, ok := int64OrNil(incoming["epoch"]); ok && isGroupEpochRecoverable(incoming) {
			incomingCurrent = deepCopyMap(incoming)
			delete(incomingCurrent, "old_epochs")
			if current == nil {
				current = incomingCurrent
			} else {
				currentEpoch, _ := int64OrNil(current["epoch"])
				switch {
				case incomingEpoch > currentEpoch:
					oldByEpoch[int(currentEpoch)] = preferNewerGroupEpochRecord(oldByEpoch[int(currentEpoch)], current)
					current = incomingCurrent
				case incomingEpoch == currentEpoch:
					current = preferNewerGroupEpochRecord(current, incomingCurrent)
				default:
					oldByEpoch[int(incomingEpoch)] = preferNewerGroupEpochRecord(oldByEpoch[int(incomingEpoch)], incomingCurrent)
				}
			}
		}

		if oldEpochs, ok := incoming["old_epochs"].([]any); ok {
			for _, raw := range oldEpochs {
				old, ok := raw.(map[string]any)
				if !ok || !isGroupEpochRecoverable(old) {
					continue
				}
				epoch, ok := int64OrNil(old["epoch"])
				if !ok {
					continue
				}
				oldByEpoch[int(epoch)] = preferNewerGroupEpochRecord(oldByEpoch[int(epoch)], old)
			}
		}
	}

	merged := make(map[string]any)
	if current != nil {
		if currentEpoch, ok := int64OrNil(current["epoch"]); ok {
			delete(oldByEpoch, int(currentEpoch))
		}
		for key, value := range current {
			merged[key] = cloneAny(value)
		}
	}
	if len(oldByEpoch) > 0 {
		epochs := make([]int, 0, len(oldByEpoch))
		for epoch := range oldByEpoch {
			epochs = append(epochs, epoch)
		}
		sortInts(epochs)
		oldEpochs := make([]any, 0, len(epochs))
		for _, epoch := range epochs {
			oldEpochs = append(oldEpochs, deepCopyMap(oldByEpoch[epoch]))
		}
		merged["old_epochs"] = oldEpochs
	}
	return merged
}

func preferNewerGroupEpochRecord(existing, incoming map[string]any) map[string]any {
	if existing == nil {
		return deepCopyMap(incoming)
	}
	existingUpdated := int64OrDefault(existing["updated_at"])
	incomingUpdated := int64OrDefault(incoming["updated_at"])
	if incomingUpdated > existingUpdated {
		return deepCopyMap(incoming)
	}
	return deepCopyMap(existing)
}

func mapsEqual(a, b map[string]any) bool {
	left, _ := json.Marshal(cloneAny(a))
	right, _ := json.Marshal(cloneAny(b))
	return string(left) == string(right)
}

func containsInt(items []int, target int) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func sortInts(items []int) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j] < items[i] {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}
