package keystore

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/modelunion/aun-sdk-core/go/secretstore"
)

var instanceComponentPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func secureFilePermissions(path string) {
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
	}
}

// safeRename 原子重命名，Windows 上 os.Rename 目标已存在时可能失败，
// 失败后 fallback 为先删除再重命名（ISSUE-GO-003）。
func safeRename(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// Windows fallback: 先删除目标再重命名
		if removeErr := os.Remove(dst); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("删除目标文件失败: %w (原始 rename 错误: %v)", removeErr, err)
		}
		return os.Rename(src, dst)
	}
	return nil
}

const metaLocksLimit = 256

// FileKeyStore 基于文件（key.json/cert.pem）+ AIDDatabase（SQLite）的密钥存储。
type FileKeyStore struct {
	root          string
	aidsRoot      string
	secretStore   secretstore.SecretStore
	aidDBs        map[string]*AIDDatabase
	aidDBsLock    sync.Mutex
	metaLocks     map[string]*sync.Mutex
	metaLocksLock sync.Mutex
}

// NewFileKeyStore 创建 FileKeyStore。backup 参数保留但不再使用（已废弃）。
func NewFileKeyStore(root string, ss secretstore.SecretStore, encryptionSeed string, _ ...interface{}) (*FileKeyStore, error) {
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
	return &FileKeyStore{
		root:        root,
		aidsRoot:    aidsRoot,
		secretStore: ss,
		aidDBs:      make(map[string]*AIDDatabase),
		metaLocks:   make(map[string]*sync.Mutex),
	}, nil
}

func safeAID(aid string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_")
	return r.Replace(aid)
}

func (f *FileKeyStore) identityDir(aid string) string {
	return filepath.Join(f.aidsRoot, safeAID(aid))
}

func (f *FileKeyStore) keyPairPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "private", "key.json")
}

func (f *FileKeyStore) certPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "public", "cert.pem")
}

func (f *FileKeyStore) certVersionPath(aid, fp string) string {
	return filepath.Join(f.identityDir(aid), "public", "certs", strings.ReplaceAll(fp, ":", "_")+".pem")
}

func normalizeCertFingerprint(fp string) string {
	v := strings.TrimSpace(strings.ToLower(fp))
	if !strings.HasPrefix(v, "sha256:") || len(v) != 71 {
		return ""
	}
	for _, c := range v[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return v
}

func (f *FileKeyStore) getDB(aid string) (*AIDDatabase, error) {
	safe := safeAID(aid)
	f.aidDBsLock.Lock()
	defer f.aidDBsLock.Unlock()
	if db, ok := f.aidDBs[safe]; ok {
		return db, nil
	}
	dbPath := filepath.Join(f.identityDir(aid), "aun.db")
	db, err := newAIDDatabase(dbPath, f.secretStore, aid)
	if err != nil {
		return nil, err
	}
	f.aidDBs[safe] = db
	return db, nil
}

func (f *FileKeyStore) getLock(aid string) *sync.Mutex {
	f.metaLocksLock.Lock()
	defer f.metaLocksLock.Unlock()
	if l, ok := f.metaLocks[aid]; ok {
		return l
	}
	// 超过上限时，清理未被持有的锁（TryLock 成功说明没人持有）
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
func (f *FileKeyStore) Close() {
	f.aidDBsLock.Lock()
	defer f.aidDBsLock.Unlock()
	for _, db := range f.aidDBs {
		db.close()
	}
}

// ── KeyPair ──────────────────────────────────────────────────

func (f *FileKeyStore) LoadKeyPair(aid string) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	path := f.keyPairPath(aid)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var kp map[string]any
	if err := json.Unmarshal(data, &kp); err != nil {
		return nil, err
	}
	return f.restoreKeyPair(aid, kp), nil
}

func (f *FileKeyStore) SaveKeyPair(aid string, keyPair map[string]any) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	return f.saveKeyPairLocked(aid, keyPair)
}

func (f *FileKeyStore) saveKeyPairLocked(aid string, keyPair map[string]any) error {
	path := f.keyPairPath(aid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	protected := copyMap(keyPair)
	if pem, ok := protected["private_key_pem"].(string); ok && pem != "" {
		delete(protected, "private_key_pem")
		rec, err := f.secretStore.Protect(safeAID(aid), "identity/private_key", []byte(pem))
		if err != nil {
			return err
		}
		protected["private_key_protection"] = rec
	}
	data, _ := json.MarshalIndent(protected, "", "  ")
	// 原子写入：先写临时文件，再 rename 覆盖目标文件
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := safeRename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	secureFilePermissions(path)
	return nil
}

func (f *FileKeyStore) restoreKeyPair(aid string, kp map[string]any) map[string]any {
	out := copyMap(kp)
	if rec, ok := out["private_key_protection"].(map[string]any); ok {
		if plain, err := f.secretStore.Reveal(safeAID(aid), "identity/private_key", rec); err == nil && plain != nil {
			out["private_key_pem"] = string(plain)
		}
	}
	return out
}

// ── Cert ─────────────────────────────────────────────────────

func (f *FileKeyStore) LoadCert(aid string) (string, error) {
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

func (f *FileKeyStore) SaveCert(aid, certPEM string) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	return f.saveCertLocked(aid, certPEM)
}

func (f *FileKeyStore) saveCertLocked(aid, certPEM string) error {
	path := f.certPath(aid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// 原子写入：先写临时文件，再 rename 覆盖目标文件
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

func (f *FileKeyStore) LoadCertVersion(aid, fp string) (string, error) {
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

func (f *FileKeyStore) SaveCertVersion(aid, certPEM, fp string, makeActive bool) error {
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

// ── Metadata（内部方法）───────────────────────────────

var tokenFields = map[string]bool{"access_token": true, "refresh_token": true, "kite_token": true}

var identitySkipFields = map[string]bool{
	"private_key_pem": true, "public_key_der_b64": true, "curve": true, "cert": true,
	"e2ee_prekeys": true, "group_secrets": true, "e2ee_sessions": true,
}

// ── Identity ─────────────────────────────────────────────────

func (f *FileKeyStore) LoadIdentity(aid string) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	kp, err := f.loadKeyPairUnlocked(aid)
	if err != nil {
		return nil, err
	}
	cert, err := f.loadCertUnlocked(aid)
	if err != nil {
		return nil, err
	}
	// 直接从 DB 读取 tokens + KV
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	tokens := db.GetAllTokens()
	kv := db.GetAllMetadata()
	hasMeta := len(tokens) > 0 || len(kv) > 0
	if kp == nil && cert == "" && !hasMeta {
		return nil, nil
	}
	identity := make(map[string]any)
	for k, v := range kv {
		var parsed any
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			identity[k] = parsed
		} else {
			identity[k] = v
		}
	}
	for k, v := range tokens {
		identity[k] = v
	}
	for k, v := range kp {
		identity[k] = v
	}
	if cert != "" {
		// key/cert 公钥一致性校验：防止 cert.pem 被意外覆盖
		localPubB64, _ := kp["public_key_der_b64"].(string)
		if localPubB64 != "" {
			if matched := verifyCertKeyMatch(cert, localPubB64); !matched {
				log.Printf("[keystore] 身份 %s 的 key.json 公钥与 cert.pem 公钥不匹配，丢弃 cert", aid)
				cert = ""
			}
		}
	}
	if cert != "" {
		identity["cert"] = cert
	}
	return identity, nil
}

// verifyCertKeyMatch 比对 cert PEM 中的公钥与 base64 编码的 DER 公钥是否一致
func verifyCertKeyMatch(certPEM, localPubB64 string) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return true // 解析失败不阻断
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	certPubDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return true
	}
	localPubDer, err := base64.StdEncoding.DecodeString(localPubB64)
	if err != nil {
		return true
	}
	return string(certPubDer) == string(localPubDer)
}

func (f *FileKeyStore) SaveIdentity(aid string, identity map[string]any) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	kp := make(map[string]any)
	for _, k := range []string{"private_key_pem", "public_key_der_b64", "curve"} {
		if v, ok := identity[k]; ok {
			kp[k] = v
		}
	}
	if len(kp) > 0 {
		if err := f.saveKeyPairLocked(aid, kp); err != nil {
			return err
		}
	}
	if cert, ok := identity["cert"].(string); ok && cert != "" {
		if err := f.saveCertLocked(aid, cert); err != nil {
			return err
		}
	}
	// 直接写入 tokens + KV
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	for field := range tokenFields {
		v, exists := identity[field]
		if !exists {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			db.SetToken(field, s)
		} else {
			db.DeleteToken(field)
		}
	}
	for k, v := range identity {
		if identitySkipFields[k] || tokenFields[k] {
			continue
		}
		b, _ := json.Marshal(v)
		db.SetMetadata(k, string(b))
	}
	return nil
}

func (f *FileKeyStore) loadKeyPairUnlocked(aid string) (map[string]any, error) {
	data, err := os.ReadFile(f.keyPairPath(aid))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var kp map[string]any
	if err := json.Unmarshal(data, &kp); err != nil {
		return nil, err
	}
	return f.restoreKeyPair(aid, kp), nil
}

func (f *FileKeyStore) loadCertUnlocked(aid string) (string, error) {
	data, err := os.ReadFile(f.certPath(aid))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// ── Prekeys ──────────────────────────────────────────────────

func (f *FileKeyStore) LoadE2EEPrekeys(aid, deviceID string) (map[string]map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadPrekeys(strings.TrimSpace(deviceID)), nil
}

func (f *FileKeyStore) SaveE2EEPrekey(aid, prekeyID, deviceID string, prekeyData map[string]any) error {
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

func (f *FileKeyStore) CleanupE2EEPrekeys(aid, deviceID string, cutoffMs int64, keepLatest int) ([]string, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.CleanupPrekeys(strings.TrimSpace(deviceID), cutoffMs, keepLatest), nil
}

// ── Group Secrets ────────────────────────────────────────────

func (f *FileKeyStore) CleanupGroupOldEpochsState(aid, groupID string, cutoffMs int64) (int, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return 0, err
	}
	return db.CleanupGroupOldEpochs(groupID, cutoffMs), nil
}

func (f *FileKeyStore) LoadGroupSecretEpoch(aid, groupID string, epoch *int) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadGroupSecretEpoch(groupID, epoch)
}

func (f *FileKeyStore) LoadGroupSecretEpochs(aid, groupID string) ([]map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadGroupSecretEpochs(groupID)
}

func (f *FileKeyStore) ListGroupSecretIDs(aid string) ([]string, error) {
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

func (f *FileKeyStore) StoreGroupSecretTransition(aid, groupID string, opts GroupSecretTransitionOptions) (bool, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return false, err
	}
	return db.StoreGroupSecretTransition(groupID, opts)
}

func (f *FileKeyStore) StoreGroupSecretEpoch(aid, groupID string, opts GroupSecretTransitionOptions) (bool, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return false, err
	}
	return db.StoreGroupSecretEpoch(groupID, opts)
}

func (f *FileKeyStore) DiscardPendingGroupSecretState(aid, groupID string, epoch int, rotationID string) (bool, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return false, err
	}
	return db.DiscardPendingGroupSecretState(groupID, epoch, rotationID)
}

func (f *FileKeyStore) DeleteGroupSecretState(aid, groupID string) error {
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

// ── Instance State ───────────────────────────────────────────

func (f *FileKeyStore) LoadInstanceState(aid, deviceID, slotID string) (map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadInstanceState(deviceID, slotID), nil
}

func (f *FileKeyStore) SaveInstanceState(aid, deviceID, slotID string, state map[string]any) error {
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

func (f *FileKeyStore) UpdateInstanceState(aid, deviceID, slotID string, updater func(map[string]any) (map[string]any, error)) (map[string]any, error) {
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

// ── LoadAnyIdentity ──────────────────────────────────────────

// ListIdentities 列出所有具有有效私钥的 AID（排序返回）。
func (f *FileKeyStore) ListIdentities() ([]string, error) {
	entries, err := os.ReadDir(f.aidsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var aids []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		aid := entry.Name()
		identity, err := f.LoadIdentity(aid)
		if err != nil || identity == nil {
			continue
		}
		if pk, _ := identity["private_key_pem"].(string); pk == "" {
			continue
		}
		aids = append(aids, aid)
	}
	return aids, nil
}

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
		identity, err := f.LoadIdentity(entry.Name())
		if err != nil || identity == nil {
			continue
		}
		return identity, nil
	}
	return nil, nil
}

// ── 工具函数 ─────────────────────────────────────────────────

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
	for k, v := range src {
		dst[k] = cloneAny(v)
	}
	return dst
}

func cloneAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyMap(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = cloneAny(item)
		}
		return out
	default:
		return v
	}
}

func safeInstanceComponent(value, field string, allowEmpty bool) (string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("%s must be non-empty", field)
	}
	if !instanceComponentPattern.MatchString(text) {
		return "", fmt.Errorf("%s contains unsupported characters", field)
	}
	return text, nil
}

// ── SessionKeyStore 实现 ─────────────────────────────────────

func (f *FileKeyStore) LoadE2EESessions(aid string) ([]map[string]any, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadAllSessions(), nil
}

func (f *FileKeyStore) SaveE2EESession(aid, sessionID string, data map[string]any) error {
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

func (f *FileKeyStore) SaveSeq(aid, deviceID, slotID, namespace string, contiguousSeq int) error {
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

func (f *FileKeyStore) LoadSeq(aid, deviceID, slotID, namespace string) (int, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return 0, err
	}
	return db.LoadSeq(deviceID, slotID, namespace), nil
}

func (f *FileKeyStore) LoadAllSeqs(aid, deviceID, slotID string) (map[string]int, error) {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	db, err := f.getDB(aid)
	if err != nil {
		return nil, err
	}
	return db.LoadAllSeqs(deviceID, slotID), nil
}
