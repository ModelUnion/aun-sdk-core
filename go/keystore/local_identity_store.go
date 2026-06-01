package keystore

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/secretstore"
)

// LocalIdentityStore 基于文件（key.json/cert.pem）+ AIDDatabase（SQLite）的身份存储。
// 实现 KeyStore + PendingIdentityKeyStore + MetadataKeyStore + TrustRootStore。
// AIDStore / RegisterFlow 持有此类型。
type LocalIdentityStore struct {
	root          string
	aidsRoot      string
	secretStore   secretstore.SecretStore
	aidDBs        map[string]*AIDDatabase
	aidDBsLock    sync.Mutex
	metaLocks     map[string]*sync.Mutex
	metaLocksLock sync.Mutex
}

// NewLocalIdentityStore 创建 LocalIdentityStore。
func NewLocalIdentityStore(root string, ss secretstore.SecretStore, encryptionSeed string, _ ...interface{}) (*LocalIdentityStore, error) {
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
	return &LocalIdentityStore{
		root:        root,
		aidsRoot:    aidsRoot,
		secretStore: ss,
		aidDBs:      make(map[string]*AIDDatabase),
		metaLocks:   make(map[string]*sync.Mutex),
	}, nil
}

func (f *LocalIdentityStore) identityDir(aid string) string {
	return filepath.Join(f.aidsRoot, safeAID(aid))
}

func (f *LocalIdentityStore) keyPairPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "private", "key.json")
}

func (f *LocalIdentityStore) certPath(aid string) string {
	return filepath.Join(f.identityDir(aid), "public", "cert.pem")
}

func (f *LocalIdentityStore) pendingRoot() string {
	return filepath.Join(f.aidsRoot, "_pending")
}

func (f *LocalIdentityStore) cleanPendingDir(pendingDir string) (string, error) {
	rootAbs, err := filepath.Abs(f.pendingRoot())
	if err != nil {
		return "", err
	}
	dirAbs, err := filepath.Abs(pendingDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rootAbs, dirAbs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("pending dir outside pending root: %s", pendingDir)
	}
	return dirAbs, nil
}

func (f *LocalIdentityStore) getDB(aid string) (*AIDDatabase, error) {
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

func (f *LocalIdentityStore) getLock(aid string) *sync.Mutex {
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
func (f *LocalIdentityStore) Close() {
	f.aidDBsLock.Lock()
	defer f.aidDBsLock.Unlock()
	for _, db := range f.aidDBs {
		db.close()
	}
	f.aidDBs = make(map[string]*AIDDatabase)
}

// ChangeSeed 迁移所有本地私钥的加密种子。
func (f *LocalIdentityStore) ChangeSeed(oldSeed, newSeed string) (SeedChangeResult, error) {
	f.Close()
	result, err := ChangeSeed(f.root, oldSeed, newSeed)
	if err != nil {
		return result, err
	}
	ss, err := secretstore.NewFileSecretStore(f.root, newSeed)
	if err != nil {
		return result, err
	}
	f.secretStore = ss
	return result, nil
}

// ── KeyStore 实现 ─────────────────────────────────────────────

func (f *LocalIdentityStore) LoadCert(aid string) (string, error) {
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

func (f *LocalIdentityStore) SaveCert(aid, certPEM string) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	return f.saveCertLocked(aid, certPEM)
}

func (f *LocalIdentityStore) LoadKeyPair(aid string) (map[string]any, error) {
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
	if err = json.Unmarshal(data, &kp); err != nil {
		return nil, err
	}
	return f.restoreKeyPair(aid, kp, path)
}

func (f *LocalIdentityStore) SaveKeyPair(aid string, keyPair map[string]any) error {
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	return f.saveKeyPairLocked(aid, keyPair)
}

func (f *LocalIdentityStore) saveKeyPairLocked(aid string, keyPair map[string]any) error {
	return f.saveKeyPairAtPath(aid, f.keyPairPath(aid), keyPair)
}

func (f *LocalIdentityStore) saveKeyPairAtPath(aid, path string, keyPair map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	protected := copyMap(keyPair)
	if pemStr, ok := protected["private_key_pem"].(string); ok && pemStr != "" {
		delete(protected, "private_key_pem")
		rec, err := f.secretStore.Protect(safeAID(aid), "identity/private_key", []byte(pemStr))
		if err != nil {
			return err
		}
		protected["private_key_protection"] = rec
	}
	data, _ := json.MarshalIndent(protected, "", "  ")
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

func (f *LocalIdentityStore) restoreKeyPair(aid string, kp map[string]any, persistPath ...string) (map[string]any, error) {
	out := copyMap(kp)
	if rec, ok := out["private_key_protection"].(map[string]any); ok {
		plain, err := f.secretStore.Reveal(safeAID(aid), "identity/private_key", rec)
		if err != nil || plain == nil {
			if err == nil {
				err = fmt.Errorf("secretstore returned no plaintext")
			}
			return nil, fmt.Errorf("private key decrypt failed for aid %s: seed_password mismatch or key.json corrupted: %w", aid, err)
		}
		out["private_key_pem"] = string(plain)
		return out, nil
	}
	if pemStr, _ := out["private_key_pem"].(string); len(persistPath) > 0 && strings.TrimSpace(pemStr) != "" {
		if err := f.saveKeyPairAtPath(aid, persistPath[0], out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (f *LocalIdentityStore) LoadIdentity(aid string) (map[string]any, error) {
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
	kv := map[string]string{}
	dbPath := filepath.Join(f.identityDir(aid), "aun.db")
	if _, statErr := os.Stat(dbPath); statErr == nil {
		db, err := f.getDB(aid)
		if err != nil {
			return nil, err
		}
		kv = db.GetAllMetadata()
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	hasMeta := len(kv) > 0
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
	for k, v := range kp {
		identity[k] = v
	}
	if cert != "" {
		localPubB64, _ := kp["public_key_der_b64"].(string)
		if localPubB64 != "" {
			if matched := identityVerifyCertKeyMatch(cert, localPubB64); !matched {
				pkgLogKeystore().Error("identity %s key.json public key mismatches cert.pem public key, discard cert", aid)
				cert = ""
			}
		}
	}
	if cert != "" {
		identity["cert"] = cert
	}
	return identity, nil
}

func identityVerifyCertKeyMatch(certPEM, localPubB64 string) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return true
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

var localIdentitySkipFields = map[string]bool{
	"private_key_pem": true, "public_key_der_b64": true, "curve": true, "cert": true,
	"e2ee_prekeys": true, "group_secrets": true, "e2ee_sessions": true,
}

func (f *LocalIdentityStore) SaveIdentity(aid string, identity map[string]any) error {
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
	db, err := f.getDB(aid)
	if err != nil {
		return err
	}
	for k, v := range identity {
		if localIdentitySkipFields[k] {
			continue
		}
		b, _ := json.Marshal(v)
		db.SetMetadata(k, string(b))
	}
	return nil
}

func (f *LocalIdentityStore) saveCertLocked(aid, certPEM string) error {
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

func (f *LocalIdentityStore) loadKeyPairUnlocked(aid string) (map[string]any, error) {
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
	return f.restoreKeyPair(aid, kp, f.keyPairPath(aid))
}

func (f *LocalIdentityStore) loadCertUnlocked(aid string) (string, error) {
	data, err := os.ReadFile(f.certPath(aid))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func (f *LocalIdentityStore) ListIdentities() ([]string, error) {
	entries, err := os.ReadDir(f.aidsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var idents []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		aid := entry.Name()
		if strings.HasPrefix(aid, "_") {
			continue
		}
		identity, err := f.LoadIdentity(aid)
		if err != nil || identity == nil {
			continue
		}
		if pk, _ := identity["private_key_pem"].(string); pk == "" {
			continue
		}
		idents = append(idents, aid)
	}
	return idents, nil
}

// ── PendingIdentityKeyStore 实现 ─────────────────────────────

func (f *LocalIdentityStore) PendingIdentityDir(aid string) (string, error) {
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	dir := filepath.Join(f.pendingRoot(), fmt.Sprintf("%s-%s-%d", safeAID(aid), hex.EncodeToString(nonce), time.Now().Unix()))
	if err := os.MkdirAll(filepath.Join(dir, "private"), 0o700); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dir, "public"), 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func (f *LocalIdentityStore) ListPendingIdentityDirs(aid string) ([]string, error) {
	root := f.pendingRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	prefix := safeAID(aid) + "-"
	type item struct {
		path  string
		mtime time.Time
	}
	items := make([]item, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		items = append(items, item{path: path, mtime: info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mtime.After(items[j].mtime) })
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.path)
	}
	return result, nil
}

func (f *LocalIdentityStore) SavePendingKeyPair(pendingDir, aid string, keyPair map[string]any) error {
	dir, err := f.cleanPendingDir(pendingDir)
	if err != nil {
		return err
	}
	l := f.getLock(aid)
	l.Lock()
	defer l.Unlock()
	return f.saveKeyPairAtPath(aid, filepath.Join(dir, "private", "key.json"), keyPair)
}

func (f *LocalIdentityStore) LoadPendingKeyPair(pendingDir, aid string) (map[string]any, error) {
	dir, err := f.cleanPendingDir(pendingDir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "private", "key.json"))
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
	return f.restoreKeyPair(aid, kp, filepath.Join(dir, "private", "key.json"))
}

func (f *LocalIdentityStore) SavePendingCert(pendingDir, certPEM string) error {
	dir, err := f.cleanPendingDir(pendingDir)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "public", "cert.pem")
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

func (f *LocalIdentityStore) PromotePendingIdentity(pendingDir, aid string) (string, error) {
	dir, err := f.cleanPendingDir(pendingDir)
	if err != nil {
		return "", err
	}
	if err := f.ensurePendingKeyPairProtected(dir, aid); err != nil {
		return "", err
	}
	target := f.identityDir(aid)
	if _, err := os.Stat(target); err == nil {
		merged, mergeErr := f.promotePendingIntoMetadataOnlyDir(dir, target)
		if mergeErr != nil {
			return "", mergeErr
		}
		if merged {
			return target, nil
		}
		return "", os.ErrExist
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	safe := safeAID(aid)
	f.aidDBsLock.Lock()
	if db, ok := f.aidDBs[safe]; ok {
		db.close()
		delete(f.aidDBs, safe)
	}
	f.aidDBsLock.Unlock()
	if err := os.MkdirAll(f.aidsRoot, 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(dir, target); err != nil {
		return "", err
	}
	return target, nil
}

func (f *LocalIdentityStore) promotePendingIntoMetadataOnlyDir(pendingDir, target string) (bool, error) {
	entries, err := os.ReadDir(target)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		name := entry.Name()
		switch name {
		case "aun.db", "aun.db-shm", "aun.db-wal":
			continue
		case "private", "public":
			nested, readErr := os.ReadDir(filepath.Join(target, name))
			if readErr != nil {
				return false, readErr
			}
			if len(nested) > 0 {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	moves := []string{
		filepath.Join("private", "key.json"),
		filepath.Join("public", "cert.pem"),
	}
	for _, rel := range moves {
		src := filepath.Join(pendingDir, rel)
		dst := filepath.Join(target, rel)
		if _, err := os.Stat(src); err != nil {
			return false, err
		}
		if _, err := os.Stat(dst); err == nil {
			return false, nil
		} else if err != nil && !os.IsNotExist(err) {
			return false, err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return false, err
		}
		if err := safeRename(src, dst); err != nil {
			return false, err
		}
	}
	if err := os.RemoveAll(pendingDir); err != nil {
		return false, err
	}
	return true, nil
}

func (f *LocalIdentityStore) ensurePendingKeyPairProtected(pendingDir, aid string) error {
	keyPath := filepath.Join(pendingDir, "private", "key.json")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("pending identity missing key pair for %s", aid)
		}
		return err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	privateKeyPEM, _ := raw["private_key_pem"].(string)
	if strings.TrimSpace(privateKeyPEM) != "" {
		return fmt.Errorf("pending identity private key is plaintext for %s", aid)
	}
	if _, ok := raw["private_key_protection"].(map[string]any); !ok {
		return fmt.Errorf("pending identity private key is not encrypted for %s", aid)
	}
	return nil
}

func (f *LocalIdentityStore) DiscardPendingIdentity(pendingDir string) error {
	dir, err := f.cleanPendingDir(pendingDir)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (f *LocalIdentityStore) CleanupPendingDirs(maxAge time.Duration) int {
	root := f.pendingRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	now := time.Now()
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) < maxAge {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err == nil {
			removed++
		}
	}
	return removed
}

// ── MetadataKeyStore 实现 ────────────────────────────────────

func (f *LocalIdentityStore) GetMetadataValue(aid, key string) string {
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

func (f *LocalIdentityStore) SetMetadataValue(aid, key, value string) error {
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

func (f *LocalIdentityStore) TrustRootDir() string {
	return filepath.Join(f.root, "CA", "root")
}

func (f *LocalIdentityStore) SaveTrustRoots(trustList map[string]any, imported []map[string]string) (string, error) {
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

func (f *LocalIdentityStore) SaveIssuerRootCert(issuer, certPEM, fingerprint string) (string, string, error) {
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
