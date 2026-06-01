package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/modelunion/aun-sdk-core/go/secretstore"
)

// LocalTokenStore 基于文件（cert.pem）+ AIDDatabase（SQLite）的 token/状态存储。
// 实现 TokenStore + StructuredKeyStore + InstanceStateStore + SeqTrackerStore +
// SessionKeyStore + MetadataKeyStore + TrustRootStore + VersionedCertKeyStore。
// AUNClient / AuthFlow 持有此类型。
type LocalTokenStore struct {
	root          string
	aidsRoot      string
	secretStore   secretstore.SecretStore
	aidDBs        map[string]*AIDDatabase
	aidDBsLock    sync.Mutex
	metaLocks     map[string]*sync.Mutex
	metaLocksLock sync.Mutex
}

// NewLocalTokenStore 创建 LocalTokenStore。
func NewLocalTokenStore(root string, ss secretstore.SecretStore, encryptionSeed string, _ ...interface{}) (*LocalTokenStore, error) {
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			root = ".aun"
		} else {
			root = filepath.Join(home, ".aun")
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("创建密钥存储根目录失败: %w", err)
	}
	if ss == nil {
		var err error
		ss, err = secretstore.NewFileSecretStore(root, encryptionSeed)
		if err != nil {
			return nil, fmt.Errorf("创建 SecretStore 失败: %w", err)
		}
	}
	aidsRoot := filepath.Join(root, "AIDs")
	if err := os.MkdirAll(aidsRoot, 0o700); err != nil {
		return nil, fmt.Errorf("创建 AIDs 目录失败: %w", err)
	}
	return &LocalTokenStore{
		root:        root,
		aidsRoot:    aidsRoot,
		secretStore: ss,
		aidDBs:      make(map[string]*AIDDatabase),
		metaLocks:   make(map[string]*sync.Mutex),
	}, nil
}

func (f *LocalTokenStore) identityDir(aid string) string {
	return filepath.Join(f.aidsRoot, safeAID(aid))
}

func (f *LocalTokenStore) certPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "public", "cert.pem")
}

func (f *LocalTokenStore) certVersionPath(aid, fp string) string {
	return filepath.Join(f.identityDir(aid), "public", "certs", strings.ReplaceAll(fp, ":", "_")+".pem")
}

func (f *LocalTokenStore) getDB(aid string) (*AIDDatabase, error) {
	safe := safeAID(aid)
	f.aidDBsLock.Lock()
	defer f.aidDBsLock.Unlock()
	if db, ok := f.aidDBs[safe]; ok {
		return db, nil
	}
	dbPath := filepath.Join(f.identityDir(aid), "aun.db")
	db, err := newAIDDatabase(dbPath, aid)
	if err != nil {
		return nil, err
	}
	f.aidDBs[safe] = db
	return db, nil
}

func (f *LocalTokenStore) getLock(aid string) *sync.Mutex {
	f.metaLocksLock.Lock()
	defer f.metaLocksLock.Unlock()
	if l, ok := f.metaLocks[aid]; ok {
		return l
	}
	if len(f.metaLocks) >= metaLocksLimit {
		for k, v := range f.metaLocks {
			if v.TryLock() {
				v.Unlock()
				delete(f.metaLocks, k)
				if len(f.metaLocks) < metaLocksLimit {
					break
				}
			}
		}
	}
	l := &sync.Mutex{}
	f.metaLocks[aid] = l
	return l
}

// Close 释放所有 AIDDatabase 资源。
func (f *LocalTokenStore) Close() {
	f.aidDBsLock.Lock()
	defer f.aidDBsLock.Unlock()
	for _, db := range f.aidDBs {
		db.close()
	}
	f.aidDBs = make(map[string]*AIDDatabase)
}

// ── TokenStore 实现 ──────────────────────────────────────────

func (f *LocalTokenStore) LoadCert(aid string) (string, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	data, err := os.ReadFile(f.certPath(aid))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func (f *LocalTokenStore) SaveCert(aid, certPEM string) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	return f.saveCertLocked(aid, certPEM)
}

func (f *LocalTokenStore) saveCertLocked(aid, certPEM string) error {
	path := f.certPath(aid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(certPEM), 0o644); err != nil {
		return err
	}
	if err := safeRename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// ── VersionedCertKeyStore 实现 ───────────────────────────────

func (f *LocalTokenStore) LoadCertVersion(aid, fp string) (string, error) {
	norm := normalizeCertFingerprint(fp)
	if norm == "" {
		return "", nil
	}
	data, err := os.ReadFile(f.certVersionPath(aid, norm))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func (f *LocalTokenStore) SaveCertVersion(aid, certPEM, fp string, makeActive bool) error {
	norm := normalizeCertFingerprint(fp)
	if norm == "" {
		return f.SaveCert(aid, certPEM)
	}
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	path := f.certVersionPath(aid, norm)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(certPEM), 0o644); err != nil {
		return err
	}
	if makeActive {
		return f.saveCertLocked(aid, certPEM)
	}
	return nil
}

// ── StructuredKeyStore 实现 ──────────────────────────────────

func (f *LocalTokenStore) LoadE2EEPrekeys(aid, deviceID string) (map[string]map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadPrekeys(strings.TrimSpace(deviceID)), nil
}

func (f *LocalTokenStore) LoadE2EEPrekeyByID(aid, prekeyID string) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadPrekeyByID(strings.TrimSpace(prekeyID)), nil
}

func (f *LocalTokenStore) SaveE2EEPrekey(aid, prekeyID, deviceID string, prekeyData map[string]any) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	pem, _ := prekeyData["private_key_pem"].(string)
	extra := make(map[string]any)
	for k, v := range prekeyData {
		if k != "private_key_pem" && k != "created_at" && k != "updated_at" && k != "expires_at" {
			extra[k] = v
		}
	}
	var ca, ea *int64
	if v, ok := int64OrNil(prekeyData["created_at"]); ok {
		ca = &v
	}
	if v, ok := int64OrNil(prekeyData["expires_at"]); ok {
		ea = &v
	}
	db.SavePrekey(prekeyID, pem, strings.TrimSpace(deviceID), ca, ea, extra)
	return nil
}

func (f *LocalTokenStore) CleanupE2EEPrekeys(aid, deviceID string, cutoffMs int64, keepLatest int) ([]string, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.CleanupPrekeys(strings.TrimSpace(deviceID), cutoffMs, keepLatest), nil
}

func (f *LocalTokenStore) ListGroupSecretIDs(aid string) ([]string, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for gid := range db.LoadAllGroupCurrent() {
		seen[gid] = true
	}
	for _, gid := range db.LoadAllGroupIDsWithOldEpochs() {
		seen[gid] = true
	}
	result := make([]string, 0, len(seen))
	for gid := range seen {
		result = append(result, gid)
	}
	sort.Strings(result)
	return result, nil
}

func (f *LocalTokenStore) CleanupGroupOldEpochsState(aid, groupID string, cutoffMs int64) (int, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return 0, err
	}
	return db.CleanupGroupOldEpochs(groupID, cutoffMs), nil
}

func (f *LocalTokenStore) LoadGroupSecretEpoch(aid, groupID string, epoch *int) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadGroupSecretEpoch(groupID, epoch)
}

func (f *LocalTokenStore) LoadGroupSecretEpochs(aid, groupID string) ([]map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadGroupSecretEpochs(groupID)
}

func (f *LocalTokenStore) StoreGroupSecretTransition(aid, groupID string, opts GroupSecretTransitionOptions) (bool, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return false, err
	}
	return db.StoreGroupSecretTransition(groupID, opts)
}

func (f *LocalTokenStore) StoreGroupSecretEpoch(aid, groupID string, opts GroupSecretTransitionOptions) (bool, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return false, err
	}
	return db.StoreGroupSecretEpoch(groupID, opts)
}

func (f *LocalTokenStore) DiscardPendingGroupSecretState(aid, groupID string, epoch int, rotationID string) (bool, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return false, err
	}
	return db.DiscardPendingGroupSecretState(groupID, epoch, rotationID)
}

func (f *LocalTokenStore) DeleteGroupSecretState(aid, groupID string) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	db.DeleteGroupCurrent(groupID)
	db.DeleteAllGroupOldEpochs(groupID)
	return nil
}

func (f *LocalTokenStore) SaveGroupState(aid, groupID string, stateVersion int64, stateHash string, keyEpoch int64, membershipJSON, policyJSON string) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	return db.SaveGroupState(groupID, stateVersion, stateHash, keyEpoch, membershipJSON, policyJSON)
}

func (f *LocalTokenStore) LoadGroupState(aid, groupID string) (*GroupState, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadGroupState(groupID)
}

// ── InstanceStateStore 实现 ──────────────────────────────────

func (f *LocalTokenStore) LoadInstanceState(aid, deviceID, slotID string) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadInstanceState(deviceID, slotID), nil
}

func (f *LocalTokenStore) SaveInstanceState(aid, deviceID, slotID string, state map[string]any) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	db.SaveInstanceState(deviceID, slotID, state)
	return nil
}

func (f *LocalTokenStore) UpdateInstanceState(aid, deviceID, slotID string, updater func(map[string]any) (map[string]any, error)) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	current := db.LoadInstanceState(deviceID, slotID)
	if current == nil {
		current = make(map[string]any)
	}
	updated, err := updater(deepCopyMap(current))
	if err != nil {
		return nil, err
	}
	if updated == nil {
		updated = current
	}
	db.SaveInstanceState(deviceID, slotID, updated)
	return deepCopyMap(updated), nil
}

// ── SessionKeyStore 实现 ─────────────────────────────────────

func (f *LocalTokenStore) LoadE2EESessions(aid string) ([]map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadAllSessions(), nil
}

func (f *LocalTokenStore) SaveE2EESession(aid, sessionID string, data map[string]any) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	db.SaveSession(sessionID, data)
	return nil
}

// ── SeqTrackerStore 实现 ─────────────────────────────────────

func (f *LocalTokenStore) SaveSeq(aid, deviceID, slotID, namespace string, contiguousSeq int) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	db.SaveSeq(deviceID, slotID, namespace, contiguousSeq)
	return nil
}

func (f *LocalTokenStore) LoadSeq(aid, deviceID, slotID, namespace string) (int, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return 0, err
	}
	return db.LoadSeq(deviceID, slotID, namespace), nil
}

func (f *LocalTokenStore) LoadAllSeqs(aid, deviceID, slotID string) (map[string]int, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadAllSeqs(deviceID, slotID), nil
}

func (f *LocalTokenStore) DeleteSeq(aid, deviceID, slotID, namespace string) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	return db.DeleteSeq(deviceID, slotID, namespace)
}

// ── MetadataKeyStore 实现 ────────────────────────────────────

func (f *LocalTokenStore) GetMetadataValue(aid, key string) string {
	if aid == "" || key == "" {
		return ""
	}
	dbPath := filepath.Join(f.identityDir(aid), "aun.db")
	if _, err := os.Stat(dbPath); err != nil {
		return ""
	}
	db, err := f.getDB(aid)
	if err != nil {
		return ""
	}
	raw := db.GetMetadata(key)
	if raw == "" {
		return ""
	}
	var s string
	if err := json.Unmarshal([]byte(raw), &s); err == nil {
		return s
	}
	return raw
}

func (f *LocalTokenStore) SetMetadataValue(aid, key, value string) error {
	if aid == "" || key == "" {
		return fmt.Errorf("SetMetadataValue requires non-empty aid and key")
	}
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	db.SetMetadata(key, string(encoded))
	return nil
}

// ── TrustRootStore 实现 ──────────────────────────────────────

func (f *LocalTokenStore) TrustRootDir() string {
	return filepath.Join(f.root, "CA", "root")
}

func (f *LocalTokenStore) SaveTrustRoots(trustList map[string]any, imported []map[string]string) (string, error) {
	dir := f.TrustRootDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("创建信任根目录失败: %w", err)
	}
	var bundleBuilder strings.Builder
	for _, entry := range imported {
		certPEM := entry["cert_pem"]
		safeID := safeAID(entry["id"])
		if safeID == "" || certPEM == "" {
			continue
		}
		certPath := filepath.Join(dir, safeID+".crt")
		tmpPath := certPath + ".tmp"
		if err := os.WriteFile(tmpPath, []byte(certPEM), 0o644); err != nil {
			return "", fmt.Errorf("写入根证书 %s 失败: %w", safeID, err)
		}
		if err := safeRename(tmpPath, certPath); err != nil {
			os.Remove(tmpPath)
			return "", fmt.Errorf("重命名根证书 %s 失败: %w", safeID, err)
		}
		bundleBuilder.WriteString(certPEM)
		if !strings.HasSuffix(certPEM, "\n") {
			bundleBuilder.WriteByte('\n')
		}
	}
	bundlePath := filepath.Join(dir, "trust-roots.pem")
	tmpBundle := bundlePath + ".tmp"
	if err := os.WriteFile(tmpBundle, []byte(bundleBuilder.String()), 0o644); err != nil {
		return "", fmt.Errorf("写入 trust-roots.pem 失败: %w", err)
	}
	if err := safeRename(tmpBundle, bundlePath); err != nil {
		os.Remove(tmpBundle)
		return "", fmt.Errorf("重命名 trust-roots.pem 失败: %w", err)
	}
	metaPath := filepath.Join(dir, "trust-roots.json")
	metaData, err := json.MarshalIndent(trustList, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化 trust-roots.json 失败: %w", err)
	}
	tmpMeta := metaPath + ".tmp"
	if err := os.WriteFile(tmpMeta, metaData, 0o644); err != nil {
		return "", fmt.Errorf("写入 trust-roots.json 失败: %w", err)
	}
	if err := safeRename(tmpMeta, metaPath); err != nil {
		os.Remove(tmpMeta)
		return "", fmt.Errorf("重命名 trust-roots.json 失败: %w", err)
	}
	return bundlePath, nil
}

func (f *LocalTokenStore) SaveIssuerRootCert(issuer, certPEM, fingerprint string) (string, string, error) {
	dir := filepath.Join(f.TrustRootDir(), "issuers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("创建 issuer 目录失败: %w", err)
	}
	safeIssuer := safeAID(issuer)
	certPath := filepath.Join(dir, safeIssuer+".root.crt")
	tmpPath := certPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(certPEM), 0o644); err != nil {
		return "", "", fmt.Errorf("写入 issuer 根证书失败: %w", err)
	}
	if err := safeRename(tmpPath, certPath); err != nil {
		os.Remove(tmpPath)
		return "", "", fmt.Errorf("重命名 issuer 根证书失败: %w", err)
	}
	return certPath, fingerprint, nil
}
