package aun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

type AgentMdManager struct {
	client *AUNClient

	agentMdMu            sync.RWMutex
	agentMDPath          string
	localAgentMDPath     string
	localAgentMDEtag     string
	remoteAgentMDEtag    string
	agentMDCache         map[string]*keystore.AgentMDCacheRecord
	agentMDFetchInflight map[string]bool
	httpClientOnce       sync.Once
	httpClient           *http.Client

	agentMDOps agentMDOps
}

func newAgentMdManager(client *AUNClient, root string) *AgentMdManager {
	return &AgentMdManager{
		client:               client,
		agentMDPath:          strings.TrimSpace(root),
		agentMDCache:         make(map[string]*keystore.AgentMDCacheRecord),
		agentMDFetchInflight: make(map[string]bool),
	}
}

// agentMDOps 是测试注入点；生产路径由 AgentMdManager 直接调用 AID 与 HTTP helper。
type agentMDOps interface {
	SignAgentMD(ctx context.Context, content string) (string, error)
	VerifyAgentMD(ctx context.Context, content string, aid string) (map[string]any, error)
	UploadAgentMD(ctx context.Context, content string) (map[string]any, error)
	DownloadAgentMD(ctx context.Context, aid string) (agentMDDownloadResult, error)
	HeadAgentMD(ctx context.Context, aid string) (map[string]any, error)
}

// AgentMDInfo 描述 DownloadAgentMD 的返回结构。
type AgentMDInfo struct {
	AID          string         `json:"aid"`
	Content      string         `json:"content"`
	Signature    map[string]any `json:"signature"`
	Verification map[string]any `json:"verification,omitempty"` // 与 Python/TS/JS 对齐：{status, reason}
	CertPem      string         `json:"cert_pem,omitempty"`     // 与 Python/TS/JS 对齐
	Etag         string         `json:"etag,omitempty"`
	LastModified string         `json:"last_modified,omitempty"`
	// InSync 仅在 aid 是自身时给出指针；外部 aid 时为 nil（语义上不适用）。
	InSync    *bool  `json:"in_sync,omitempty"`
	SavedTo   string `json:"saved_to,omitempty"`
	SaveError string `json:"save_error,omitempty"`
}

// AgentMDCheckResult 描述 CheckAgentMD 的本地/云端一致性结果。
type AgentMDCheckResult struct {
	AID          string `json:"aid"`
	LocalFound   bool   `json:"local_found"`
	RemoteFound  bool   `json:"remote_found"`
	LocalEtag    string `json:"local_etag"`
	RemoteEtag   string `json:"remote_etag"`
	InSync       bool   `json:"in_sync"`
	LastModified string `json:"last_modified"`
	Status       int    `json:"status"`
	Cached       bool   `json:"cached"`
	VerifyStatus string `json:"verify_status"`
	VerifyError  string `json:"verify_error"`
}

func agentMDContentEtag(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "\"" + hex.EncodeToString(sum[:]) + "\""
}

func agentMDStringPtr(value string) *string { return &value }
func agentMDInt64Ptr(value int64) *int64    { return &value }
func agentMDBoolFromAny(value any) bool {
	if b, ok := value.(bool); ok {
		return b
	}
	if s, ok := value.(string); ok {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "1", "true", "yes", "on", "found":
			return true
		}
	}
	return false
}

func agentMDCheckedAtFresh(checkedAtMs int64, maxUnsyncedDays float64) bool {
	if maxUnsyncedDays <= 0 || checkedAtMs <= 0 {
		return false
	}
	return float64(time.Now().UnixMilli()-checkedAtMs) <= maxUnsyncedDays*float64(24*60*60*1000)
}

func agentMDLastModifiedFresh(lastModified string, maxUnsyncedDays float64) bool {
	if maxUnsyncedDays <= 0 {
		return false
	}
	parsed, err := http.ParseTime(strings.TrimSpace(lastModified))
	if err != nil {
		return false
	}
	return time.Now().Before(parsed.Add(time.Duration(maxUnsyncedDays * float64(24*time.Hour))))
}

func cloneAgentMDRecord(rec *keystore.AgentMDCacheRecord) *keystore.AgentMDCacheRecord {
	if rec == nil {
		return nil
	}
	out := *rec
	return &out
}

func applyAgentMDCacheUpsert(rec *keystore.AgentMDCacheRecord, fields keystore.AgentMDCacheUpsert) {
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
	rec.UpdatedAt = time.Now().UnixMilli()
}

func (m *AgentMdManager) agentMDOwnerAID() string {
	m.client.mu.RLock()
	defer m.client.mu.RUnlock()
	return strings.TrimSpace(m.client.aid)
}

// setAgentMDPath 设置 agent.md 本地存储根目录；空字符串恢复默认 {aun_path}/AIDs。
func (m *AgentMdManager) setAgentMDPath(root string) string {
	next := strings.TrimSpace(root)
	if next == "" {
		next = filepath.Join(m.client.configModel.AUNPath, "AIDs")
	}
	_ = os.MkdirAll(next, 0o755)
	m.agentMdMu.Lock()
	m.agentMDPath = next
	m.agentMDCache = make(map[string]*keystore.AgentMDCacheRecord)
	m.agentMdMu.Unlock()
	return next
}

func (m *AgentMdManager) agentMDRoot() string {
	m.agentMdMu.RLock()
	root := strings.TrimSpace(m.agentMDPath)
	m.agentMdMu.RUnlock()
	if root == "" {
		root = filepath.Join(m.client.configModel.AUNPath, "AIDs")
	}
	_ = os.MkdirAll(root, 0o755)
	return root
}

func agentMDSafeAID(aid string) (string, error) {
	target := strings.TrimSpace(aid)
	if target == "" || strings.ContainsAny(target, "/\\\x00") {
		return "", fmt.Errorf("agent.md aid is empty or contains path separators")
	}
	return target, nil
}

func (m *AgentMdManager) agentMDFilePath(aid string) (string, error) {
	safe, err := agentMDSafeAID(aid)
	if err != nil {
		return "", err
	}
	return filepath.Join(m.agentMDRoot(), safe, "agent.md"), nil
}

func (m *AgentMdManager) agentMDMetaPath(aid string) (string, error) {
	safe, err := agentMDSafeAID(aid)
	if err != nil {
		return "", err
	}
	return filepath.Join(m.agentMDRoot(), safe, "agentmd.json"), nil
}

func atomicWriteText(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.%d.%d.tmp", filepath.Base(path), os.Getpid(), time.Now().UnixNano()))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		_ = os.Remove(tmp)
	}()
	if _, err := f.Write(content); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (m *AgentMdManager) withAgentMDRecordLock(aid string, fn func() error) error {
	metaPath, err := m.agentMDMetaPath(aid)
	if err != nil {
		return err
	}
	lockPath := metaPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	var f *os.File
	for f == nil {
		opened, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			f = opened
			_, _ = f.WriteString(fmt.Sprintf("%d\n", os.Getpid()))
			break
		}
		if !os.IsExist(err) || time.Now().After(deadline) {
			return err
		}
		if st, statErr := os.Stat(lockPath); statErr == nil && time.Since(st.ModTime()) > 30*time.Second {
			_ = os.Remove(lockPath)
		}
		time.Sleep(25 * time.Millisecond)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(lockPath)
	}()
	return fn()
}
func agentMDRecordToMap(rec *keystore.AgentMDCacheRecord) map[string]any {
	m := map[string]any{"aid": rec.AID}
	if rec.LocalEtag != "" {
		m["local_etag"] = rec.LocalEtag
	}
	if rec.RemoteEtag != "" {
		m["remote_etag"] = rec.RemoteEtag
	}
	if rec.LastModified != "" {
		m["last_modified"] = rec.LastModified
	}
	if rec.FetchedAt != 0 {
		m["fetched_at"] = rec.FetchedAt
	}
	if rec.ObservedAt != 0 {
		m["observed_at"] = rec.ObservedAt
	}
	if rec.CheckedAt != 0 {
		m["checked_at"] = rec.CheckedAt
	}
	if rec.RemoteStatus != "" {
		m["remote_status"] = rec.RemoteStatus
	}
	if rec.VerifyStatus != "" {
		m["verify_status"] = rec.VerifyStatus
	}
	if rec.VerifyError != "" {
		m["verify_error"] = rec.VerifyError
	}
	if rec.LastError != "" {
		m["last_error"] = rec.LastError
	}
	if rec.UpdatedAt != 0 {
		m["updated_at"] = rec.UpdatedAt
	}
	return m
}

func agentMDMapToRecord(aid string, raw map[string]any) *keystore.AgentMDCacheRecord {
	rec := &keystore.AgentMDCacheRecord{AID: strings.TrimSpace(stringFromAny(raw["aid"]))}
	if rec.AID == "" {
		rec.AID = aid
	}
	rec.LocalEtag = strings.TrimSpace(stringFromAny(raw["local_etag"]))
	rec.RemoteEtag = strings.TrimSpace(stringFromAny(raw["remote_etag"]))
	rec.LastModified = strings.TrimSpace(stringFromAny(raw["last_modified"]))
	rec.FetchedAt = toInt64(raw["fetched_at"])
	rec.ObservedAt = toInt64(raw["observed_at"])
	rec.CheckedAt = toInt64(raw["checked_at"])
	rec.RemoteStatus = strings.TrimSpace(stringFromAny(raw["remote_status"]))
	rec.VerifyStatus = strings.TrimSpace(stringFromAny(raw["verify_status"]))
	rec.VerifyError = strings.TrimSpace(stringFromAny(raw["verify_error"]))
	rec.LastError = strings.TrimSpace(stringFromAny(raw["last_error"]))
	rec.UpdatedAt = toInt64(raw["updated_at"])
	return rec
}

func (m *AgentMdManager) writeAgentMDRecordUnlocked(aid string, rec *keystore.AgentMDCacheRecord) error {
	metaPath, err := m.agentMDMetaPath(aid)
	if err != nil {
		return err
	}
	payload := agentMDRecordToMap(rec)
	delete(payload, "content")
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteText(metaPath, data)
}

func (m *AgentMdManager) readAgentMDRecordUnlocked(aid string) *keystore.AgentMDCacheRecord {
	metaPath, err := m.agentMDMetaPath(aid)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		m.client.log.Warn("agent.md agentmd.json damaged, ignoring: aid=%s err=%v", aid, err)
		return nil
	}
	return agentMDMapToRecord(aid, raw)
}
func (m *AgentMdManager) loadAgentMDRecord(aid string) *keystore.AgentMDCacheRecord {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil
	}
	var rec *keystore.AgentMDCacheRecord
	if err := m.withAgentMDRecordLock(target, func() error {
		rec = m.readAgentMDRecordUnlocked(target)
		return nil
	}); err != nil {
		m.client.log.Debug("agent.md cache load skipped: aid=%s err=%v", target, err)
		return nil
	}
	if rec == nil {
		return nil
	}
	if p, err := m.agentMDFilePath(target); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			rec.Content = string(data)
			rec.LocalEtag = agentMDContentEtag(rec.Content)
		} else {
			m.client.log.Warn("agent.md content read failed: aid=%s err=%v", target, err)
		}
	}
	m.agentMdMu.Lock()
	if m.agentMDCache == nil {
		m.agentMDCache = make(map[string]*keystore.AgentMDCacheRecord)
	}
	m.agentMDCache[target] = cloneAgentMDRecord(rec)
	m.agentMdMu.Unlock()
	return cloneAgentMDRecord(rec)
}

func (m *AgentMdManager) saveAgentMDRecord(aid string, fields keystore.AgentMDCacheUpsert) *keystore.AgentMDCacheRecord {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil
	}
	if fields.Content != nil {
		p, err := m.agentMDFilePath(target)
		if err != nil {
			m.client.log.Debug("agent.md content path invalid: aid=%s err=%v", target, err)
			return nil
		}
		if err := atomicWriteText(p, []byte(*fields.Content)); err != nil {
			m.client.log.Debug("agent.md content save skipped: aid=%s err=%v", target, err)
			return nil
		}
		if fields.LocalEtag == nil {
			fields.LocalEtag = agentMDStringPtr(agentMDContentEtag(*fields.Content))
		}
		if fields.FetchedAt == nil {
			fields.FetchedAt = agentMDInt64Ptr(time.Now().UnixMilli())
		}
	}
	var rec *keystore.AgentMDCacheRecord
	if err := m.withAgentMDRecordLock(target, func() error {
		rec = m.readAgentMDRecordUnlocked(target)
		if rec == nil {
			rec = &keystore.AgentMDCacheRecord{AID: target}
		}
		applyAgentMDCacheUpsert(rec, fields)
		rec.Content = ""
		rec.UpdatedAt = time.Now().UnixMilli()
		return m.writeAgentMDRecordUnlocked(target, rec)
	}); err != nil {
		m.client.log.Debug("agent.md cache save skipped: aid=%s err=%v", target, err)
		return nil
	}
	loaded := cloneAgentMDRecord(rec)
	if fields.Content != nil {
		loaded.Content = *fields.Content
	}
	m.agentMdMu.Lock()
	if m.agentMDCache == nil {
		m.agentMDCache = make(map[string]*keystore.AgentMDCacheRecord)
	}
	m.agentMDCache[target] = cloneAgentMDRecord(loaded)
	owner := m.agentMDOwnerAID()
	if target == owner {
		if loaded.LocalEtag != "" {
			m.localAgentMDEtag = loaded.LocalEtag
		}
		if loaded.RemoteEtag != "" {
			m.remoteAgentMDEtag = loaded.RemoteEtag
		}
	}
	m.agentMdMu.Unlock()
	return cloneAgentMDRecord(loaded)
}

func (m *AgentMdManager) agentMDHasLocalContent(aid string, rec *keystore.AgentMDCacheRecord) bool {
	if rec != nil && strings.TrimSpace(rec.Content) != "" {
		return true
	}
	p, err := m.agentMDFilePath(aid)
	if err != nil {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func (m *AgentMdManager) scheduleAgentMDFetchIfMissing(aid string, rec *keystore.AgentMDCacheRecord, source string) {
	target := strings.TrimSpace(aid)
	if target == "" || m.agentMDHasLocalContent(target, rec) {
		return
	}
	m.agentMdMu.Lock()
	if m.agentMDFetchInflight == nil {
		m.agentMDFetchInflight = make(map[string]bool)
	}
	if m.agentMDFetchInflight[target] {
		m.agentMdMu.Unlock()
		return
	}
	m.agentMDFetchInflight[target] = true
	m.agentMdMu.Unlock()

	go func() {
		defer func() {
			m.agentMdMu.Lock()
			delete(m.agentMDFetchInflight, target)
			m.agentMdMu.Unlock()
		}()
		ctx := context.Background()
		m.client.mu.RLock()
		if m.client.ctx != nil {
			ctx = m.client.ctx
		}
		m.client.mu.RUnlock()
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := m.Download(fetchCtx, target); err != nil {
			m.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
				LastError:    agentMDStringPtr(err.Error()),
				RemoteStatus: agentMDStringPtr("found"),
			})
			m.client.log.Debug("agent.md auto fetch failed: aid=%s source=%s err=%v", target, source, err)
		}
	}()
}

func (m *AgentMdManager) observeAgentMDMeta(aid, etag, lastModified, source string) {
	target := strings.TrimSpace(aid)
	remoteEtag := strings.TrimSpace(etag)
	remoteLastModified := strings.TrimSpace(lastModified)
	if target == "" || (remoteEtag == "" && remoteLastModified == "") {
		return
	}
	m.agentMdMu.RLock()
	before := cloneAgentMDRecord(m.agentMDCache[target])
	m.agentMdMu.RUnlock()
	if before == nil {
		before = m.loadAgentMDRecord(target)
	}
	same := before != nil &&
		(remoteEtag == "" || strings.TrimSpace(before.RemoteEtag) == remoteEtag) &&
		(remoteLastModified == "" || strings.TrimSpace(before.LastModified) == remoteLastModified)
	record := cloneAgentMDRecord(before)
	if !same || before == nil {
		fields := keystore.AgentMDCacheUpsert{
			ObservedAt:   agentMDInt64Ptr(time.Now().UnixMilli()),
			RemoteStatus: agentMDStringPtr("found"),
		}
		if remoteEtag != "" {
			fields.RemoteEtag = agentMDStringPtr(remoteEtag)
		}
		if remoteLastModified != "" {
			fields.LastModified = agentMDStringPtr(remoteLastModified)
		}
		record = m.saveAgentMDRecord(target, fields)
	}
	if target == m.agentMDOwnerAID() && remoteEtag != "" {
		m.agentMdMu.Lock()
		m.remoteAgentMDEtag = remoteEtag
		m.agentMdMu.Unlock()
	}
	m.scheduleAgentMDFetchIfMissing(target, record, source)
	if source != "" {
		m.client.log.Debug("agent.md meta observed: aid=%s etag=%s last_modified=%s source=%s", target, remoteEtag, remoteLastModified, source)
	}
}

func (m *AgentMdManager) observeAgentMDFromEnvelope(envelope map[string]any) {
	if envelope == nil {
		return
	}
	agentMD, _ := envelope["agent_md"].(map[string]any)
	if agentMD == nil {
		return
	}
	sender, _ := agentMD["sender"].(map[string]any)
	if sender == nil {
		return
	}
	senderAID := strings.TrimSpace(v2AsString(sender["aid"]))
	if senderAID == "" {
		if aad, ok := envelope["aad"].(map[string]any); ok {
			senderAID = strings.TrimSpace(v2AsString(aad["from"]))
		}
	}
	if senderAID == "" {
		senderAID = strings.TrimSpace(v2AsString(envelope["from"]))
	}
	lastModified := strings.TrimSpace(v2AsString(sender["last_modified"]))
	if lastModified == "" {
		lastModified = strings.TrimSpace(v2AsString(sender["lastModified"]))
	}
	m.observeAgentMDMeta(senderAID, v2AsString(sender["etag"]), lastModified, "envelope")
}

func verifyAgentMDResultToMap(result *VerifyAgentMdResult, certPEM string) map[string]any {
	if result == nil {
		return map[string]any{"status": "invalid", "verified": false, "reason": "empty verification result"}
	}
	out := map[string]any{
		"status":   result.Status,
		"verified": result.Status == "verified",
		"payload":  result.Payload,
	}
	if result.Reason != "" {
		out["reason"] = result.Reason
	}
	if result.AID != "" {
		out["aid"] = result.AID
	}
	if result.CertFingerprint != "" {
		out["cert_fingerprint"] = result.CertFingerprint
	}
	if result.PublicKeyFingerprint != "" {
		out["public_key_fingerprint"] = result.PublicKeyFingerprint
	}
	if result.Timestamp > 0 {
		out["timestamp"] = result.Timestamp
	}
	if strings.TrimSpace(certPEM) != "" {
		out["cert_pem"] = strings.TrimSpace(certPEM)
	}
	return out
}

func (m *AgentMdManager) agentMDHTTPClient() *http.Client {
	m.httpClientOnce.Do(func() {
		m.httpClient = newAgentMDHTTPClient(m.client.configModel.VerifySSL, 30*time.Second)
	})
	return m.httpClient
}

func (m *AgentMdManager) resolveAgentMDGateway(ctx context.Context, aid string) (string, error) {
	if gatewayURL := strings.TrimSpace(m.client.GetGatewayURL()); gatewayURL != "" {
		return gatewayURL, nil
	}
	if strings.TrimSpace(aid) == m.agentMDOwnerAID() {
		return m.client.resolveGatewayForAID(ctx, aid)
	}
	return m.client.resolveGatewayForPeerAID(ctx, aid)
}

func (m *AgentMdManager) resolveAgentMDURL(ctx context.Context, aid string) (string, error) {
	gatewayURL, err := m.resolveAgentMDGateway(ctx, aid)
	if err != nil {
		return "", err
	}
	return agentMDURLFromGateway(gatewayURL, aid, m.client.GetConfigDiscoveryPort()), nil
}

func (m *AgentMdManager) signAgentMD(ctx context.Context, content string) (string, error) {
	if m.agentMDOps != nil {
		return m.agentMDOps.SignAgentMD(ctx, content)
	}
	m.client.mu.RLock()
	current := m.client.currentAIDObj
	m.client.mu.RUnlock()
	if current == nil || !current.IsPrivateKeyValid() {
		return "", fmt.Errorf("UploadAgentMD requires local AID with a valid private key")
	}
	return current.SignAgentMd(content)
}

func (m *AgentMdManager) verifyAgentMD(ctx context.Context, content string, aid string) (map[string]any, error) {
	if m.agentMDOps != nil {
		return m.agentMDOps.VerifyAgentMD(ctx, content, aid)
	}
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, fmt.Errorf("VerifyAgentMD requires non-empty aid")
	}
	m.client.mu.RLock()
	current := m.client.currentAIDObj
	m.client.mu.RUnlock()
	var peer *AID
	_, fields, _ := aidParseAgentMdTailSignature(content)
	expectedFP := ""
	if fields != nil {
		expectedFP = strings.TrimSpace(strings.ToLower(fields["cert_fingerprint"]))
		if expectedFP == "" {
			expectedFP = strings.TrimSpace(strings.ToLower(fields["public_key_fingerprint"]))
		}
	}
	if current != nil && current.Aid == target {
		if expectedFP != "" && !matchCertFingerprint([]byte(current.CertPem), expectedFP) {
			return nil, fmt.Errorf("current AID certificate fingerprint mismatch for %s", target)
		}
		peer = current
	} else if expectedFP != "" {
		certBytes, err := m.client.fetchPeerCert(ctx, target, expectedFP)
		if err != nil {
			return nil, err
		}
		resolved, err := m.client.getPeerDirectory().publicAIDFromCert(target, string(certBytes))
		if err != nil {
			return nil, err
		}
		peer = resolved
	} else {
		resolved, err := m.client.LookupPeer(ctx, target)
		if err != nil {
			return nil, err
		}
		peer = resolved
	}
	result, err := peer.VerifyAgentMd(content)
	if err != nil {
		return nil, err
	}
	return verifyAgentMDResultToMap(result, peer.CertPem), nil
}

func (m *AgentMdManager) ensureAgentMDUploadToken(ctx context.Context, aid, gatewayURL string) (string, error) {
	identity := m.client.AuthLoadIdentityOrNil(aid)
	if identity == nil {
		return "", fmt.Errorf("no local identity found, call AIDStore.Load and AUNClient.LoadIdentity first")
	}
	if token := authGetCachedAccessToken(identity); token != "" {
		return token, nil
	}
	result, err := m.client.AuthAuthenticate(ctx, gatewayURL, aid)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(stringFromAny(result["access_token"]))
	if token == "" {
		return "", fmt.Errorf("authenticate did not return access_token")
	}
	m.client.SetAID(aid)
	m.client.SetIdentity(m.client.AuthLoadIdentityOrNil(aid))
	m.client.setGatewayURL(gatewayURL)
	return token, nil
}

func (m *AgentMdManager) uploadAgentMD(ctx context.Context, content string) (map[string]any, error) {
	if m.agentMDOps != nil {
		return m.agentMDOps.UploadAgentMD(ctx, content)
	}
	aid := m.agentMDOwnerAID()
	if aid == "" {
		return nil, fmt.Errorf("UploadAgentMD requires local AID")
	}
	gatewayURL, err := m.resolveAgentMDGateway(ctx, aid)
	if err != nil {
		return nil, fmt.Errorf("UploadAgentMD gateway discovery failed: %w", err)
	}
	token, err := m.ensureAgentMDUploadToken(ctx, aid, gatewayURL)
	if err != nil {
		return nil, err
	}
	return agentMDUploadHTTP(ctx, m.agentMDHTTPClient(), agentMDURLFromGateway(gatewayURL, aid, m.client.GetConfigDiscoveryPort()), token, content)
}

func (m *AgentMdManager) downloadAgentMD(ctx context.Context, aid string) (agentMDDownloadResult, error) {
	if m.agentMDOps != nil {
		return m.agentMDOps.DownloadAgentMD(ctx, aid)
	}
	url, err := m.resolveAgentMDURL(ctx, aid)
	if err != nil {
		return agentMDDownloadResult{}, err
	}
	if rec := m.loadAgentMDRecord(aid); rec != nil && rec.Content != "" {
		cachedEtag := strings.TrimSpace(rec.RemoteEtag)
		if cachedEtag == "" {
			cachedEtag = strings.TrimSpace(rec.LocalEtag)
		}
		return agentMDDownloadHTTP(ctx, m.agentMDHTTPClient(), url, aid, agentMDDownloadCache{
			Content:      rec.Content,
			Etag:         cachedEtag,
			LastModified: rec.LastModified,
		})
	}
	return agentMDDownloadHTTP(ctx, m.agentMDHTTPClient(), url, aid)
}

func (m *AgentMdManager) headAgentMD(ctx context.Context, aid string) (map[string]any, error) {
	if m.agentMDOps != nil {
		return m.agentMDOps.HeadAgentMD(ctx, aid)
	}
	url, err := m.resolveAgentMDURL(ctx, aid)
	if err != nil {
		return nil, err
	}
	return agentMDHeadHTTP(ctx, m.agentMDHTTPClient(), url, aid)
}

// Upload 读取本地 agent.md 或使用传入正文，签名后上传到服务端。
func (m *AgentMdManager) Upload(ctx context.Context, contentArg ...string) (map[string]any, error) {
	target := m.agentMDOwnerAID()
	if target == "" {
		return nil, fmt.Errorf("UploadAgentMD requires local AID")
	}
	p, err := m.agentMDFilePath(target)
	if err != nil {
		return nil, err
	}
	content := ""
	if len(contentArg) > 0 {
		content = contentArg[0]
	} else {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("UploadAgentMD read default agent.md: %w", err)
		}
		content = string(data)
	}
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("UploadAgentMD requires non-empty content")
	}
	signed, err := m.signAgentMD(ctx, content)
	if err != nil {
		return nil, err
	}
	result, err := m.uploadAgentMD(ctx, signed)
	if err != nil {
		return nil, err
	}
	localEtag := agentMDContentEtag(signed)
	remoteEtag := strings.TrimSpace(stringFromAny(result["etag"]))
	lastModified := strings.TrimSpace(stringFromAny(result["last_modified"]))
	remoteStatus := "unknown"
	if remoteEtag != "" {
		remoteStatus = "found"
	}
	m.agentMdMu.Lock()
	m.localAgentMDPath = p
	m.localAgentMDEtag = localEtag
	if remoteEtag != "" {
		m.remoteAgentMDEtag = remoteEtag
	}
	m.agentMdMu.Unlock()
	m.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
		Content:      agentMDStringPtr(signed),
		LocalEtag:    agentMDStringPtr(localEtag),
		RemoteEtag:   agentMDStringPtr(remoteEtag),
		LastModified: agentMDStringPtr(lastModified),
		FetchedAt:    agentMDInt64Ptr(time.Now().UnixMilli()),
		RemoteStatus: agentMDStringPtr(remoteStatus),
		LastError:    agentMDStringPtr(""),
	})
	return result, nil
}

// Download 下载 agent.md 并自动验签；aid 为空时取自身 AID；
// 若 aid 是自己则同步刷新 localAgentMDEtag 与 InSync。
func (m *AgentMdManager) Download(ctx context.Context, aid string) (*AgentMDInfo, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		m.client.mu.RLock()
		target = strings.TrimSpace(m.client.aid)
		m.client.mu.RUnlock()
	}
	if target == "" {
		return nil, fmt.Errorf("DownloadAgentMD requires aid (or local AID)")
	}

	downloaded, err := m.downloadAgentMD(ctx, target)
	if err != nil {
		return nil, err
	}
	content := downloaded.Content
	sig, err := m.verifyAgentMD(ctx, content, target)
	if err != nil {
		return nil, err
	}

	info := &AgentMDInfo{AID: target, Content: content, Signature: sig}
	// 填充 Verification（与 Python/TS/JS 对齐）
	if status, ok := sig["status"].(string); ok {
		verification := map[string]any{"status": status}
		if reason, ok := sig["reason"].(string); ok && reason != "" {
			verification["reason"] = reason
		}
		info.Verification = verification
	}
	// 填充 CertPem（从 sig 中提取，VerifyAgentMD 会返回 cert_pem）
	if certPem, ok := sig["cert_pem"].(string); ok && certPem != "" {
		info.CertPem = certPem
	}

	m.client.mu.RLock()
	selfAid := strings.TrimSpace(m.client.aid)
	m.client.mu.RUnlock()

	localEtag := agentMDContentEtag(content)
	remoteEtag := strings.TrimSpace(downloaded.Etag)
	lastModified := strings.TrimSpace(downloaded.LastModified)
	if target == selfAid {
		m.agentMdMu.Lock()
		m.localAgentMDEtag = localEtag
		if remoteEtag != "" {
			m.remoteAgentMDEtag = remoteEtag
		}
		remote := m.remoteAgentMDEtag
		m.agentMdMu.Unlock()
		inSync := false
		if localEtag != "" && remote != "" {
			inSync = localEtag == remote
		}
		info.InSync = &inSync
	}

	fields := keystore.AgentMDCacheUpsert{
		Content:      agentMDStringPtr(content),
		LocalEtag:    agentMDStringPtr(localEtag),
		FetchedAt:    agentMDInt64Ptr(time.Now().UnixMilli()),
		RemoteStatus: agentMDStringPtr("found"),
		VerifyStatus: agentMDStringPtr(strings.TrimSpace(stringFromAny(sig["status"]))),
		VerifyError:  agentMDStringPtr(strings.TrimSpace(stringFromAny(sig["reason"]))),
		LastError:    agentMDStringPtr(""),
	}
	if remoteEtag != "" {
		fields.RemoteEtag = agentMDStringPtr(remoteEtag)
	}
	if lastModified != "" {
		fields.LastModified = agentMDStringPtr(lastModified)
	}
	m.saveAgentMDRecord(target, fields)
	if p, err := m.agentMDFilePath(target); err == nil {
		info.SavedTo = p
	}
	// 填充 Etag / LastModified（与 Python/TS/JS 对齐）
	info.Etag = remoteEtag
	info.LastModified = lastModified
	return info, nil
}

// Check 通过 HEAD 比较本地缓存 agent.md 与云端 agent.md ETag 是否一致。
func (m *AgentMdManager) Check(ctx context.Context, aid string, maxUnsyncedDays ...float64) (*AgentMDCheckResult, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		target = m.agentMDOwnerAID()
	}
	if target == "" {
		return nil, fmt.Errorf("CheckAgentMD requires aid (or local AID)")
	}
	maxDays := 0.0
	if len(maxUnsyncedDays) > 0 {
		maxDays = maxUnsyncedDays[0]
	}
	before := m.loadAgentMDRecord(target)
	localEtag := ""
	localFound := false
	remoteEtagCached := ""
	lastModifiedCached := ""
	verifyStatus := ""
	verifyError := ""
	checkedAtCached := int64(0)
	if before != nil {
		localEtag = strings.TrimSpace(before.LocalEtag)
		localFound = strings.TrimSpace(before.Content) != "" || localEtag != ""
		remoteEtagCached = strings.TrimSpace(before.RemoteEtag)
		lastModifiedCached = strings.TrimSpace(before.LastModified)
		verifyStatus = strings.TrimSpace(before.VerifyStatus)
		verifyError = strings.TrimSpace(before.VerifyError)
		checkedAtCached = before.CheckedAt
	}
	// max_unsynced_days > 0 且缓存仍在窗口内时直接返回，避免无意义 HEAD。
	cacheFresh := agentMDCheckedAtFresh(checkedAtCached, maxDays) || agentMDLastModifiedFresh(lastModifiedCached, maxDays)
	if localFound && localEtag != "" && remoteEtagCached != "" && localEtag == remoteEtagCached && cacheFresh {
		return &AgentMDCheckResult{
			AID:          target,
			LocalFound:   true,
			RemoteFound:  true,
			LocalEtag:    localEtag,
			RemoteEtag:   remoteEtagCached,
			InSync:       true,
			LastModified: lastModifiedCached,
			Status:       200,
			Cached:       true,
			VerifyStatus: verifyStatus,
			VerifyError:  verifyError,
		}, nil
	}

	now := time.Now().UnixMilli()
	remote, err := m.headAgentMD(ctx, target)
	if err != nil {
		m.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
			CheckedAt:    agentMDInt64Ptr(now),
			RemoteStatus: agentMDStringPtr("error"),
			LastError:    agentMDStringPtr(err.Error()),
		})
		return nil, err
	}
	remoteFound := agentMDBoolFromAny(remote["found"])
	remoteEtag := strings.TrimSpace(stringFromAny(remote["etag"]))
	lastModified := strings.TrimSpace(stringFromAny(remote["last_modified"]))
	if lastModified == "" {
		lastModified = strings.TrimSpace(stringFromAny(remote["lastModified"]))
	}
	status := int(toInt64(remote["status"]))
	if status == 0 {
		if remoteFound {
			status = 200
		} else {
			status = 404
		}
	}
	remoteStatus := "missing"
	if remoteFound {
		remoteStatus = "found"
	}
	saved := m.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
		RemoteEtag:   agentMDStringPtr(map[bool]string{true: remoteEtag, false: ""}[remoteFound]),
		LastModified: agentMDStringPtr(lastModified),
		CheckedAt:    agentMDInt64Ptr(now),
		RemoteStatus: agentMDStringPtr(remoteStatus),
		LastError:    agentMDStringPtr(""),
	})
	if saved != nil {
		verifyStatus = strings.TrimSpace(saved.VerifyStatus)
		verifyError = strings.TrimSpace(saved.VerifyError)
	}
	if target == m.agentMDOwnerAID() && remoteEtag != "" {
		m.agentMdMu.Lock()
		m.remoteAgentMDEtag = remoteEtag
		m.agentMdMu.Unlock()
	}
	return &AgentMDCheckResult{
		AID:          target,
		LocalFound:   localFound,
		RemoteFound:  remoteFound,
		LocalEtag:    localEtag,
		RemoteEtag:   remoteEtag,
		InSync:       localFound && remoteFound && localEtag != "" && remoteEtag != "" && localEtag == remoteEtag,
		LastModified: lastModified,
		Status:       status,
		Cached:       false,
		VerifyStatus: verifyStatus,
		VerifyError:  verifyError,
	}, nil
}

func (m *AgentMdManager) eventSnapshot() (string, string) {
	m.agentMdMu.RLock()
	defer m.agentMdMu.RUnlock()
	return m.localAgentMDEtag, m.remoteAgentMDEtag
}

// observeRPCMeta transport 的 _meta observer：吸收 gateway 注入的 agent_md_etag 等元数据。
// observer 失败 / 字段缺失时不影响业务路径。
func (m *AgentMdManager) ObserveRPCMeta(meta map[string]any) {
	if meta == nil {
		return
	}
	if etag := strings.TrimSpace(stringFromAny(meta["agent_md_etag"])); etag != "" {
		m.agentMdMu.Lock()
		m.remoteAgentMDEtag = etag
		m.agentMdMu.Unlock()
		m.observeAgentMDMeta(m.agentMDOwnerAID(), etag, "", "rpc.self")
	}
	etags, _ := meta["agent_md_etags"].(map[string]any)
	if etags == nil {
		return
	}
	// role key 优先级：requester / peer 是新规范，其余是兼容旧 SDK 的别名。
	for _, key := range []string{"requester", "peer", "receiver", "target", "to", "sender", "from"} {
		item, _ := etags[key].(map[string]any)
		if item == nil {
			continue
		}
		lastModified := strings.TrimSpace(stringFromAny(item["last_modified"]))
		if lastModified == "" {
			lastModified = strings.TrimSpace(stringFromAny(item["lastModified"]))
		}
		m.observeAgentMDMeta(
			strings.TrimSpace(stringFromAny(item["aid"])),
			strings.TrimSpace(stringFromAny(item["etag"])),
			lastModified,
			"rpc."+key,
		)
	}
}
