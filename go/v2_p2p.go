// v2_p2p.go — V2 P2P E2EE 集成（init_v2_session / send_v2 / pull_v2 / ack_v2）。
//
// 与 Python aun_core.client 的对应方法字节级对齐：
//   - _init_v2_session  → InitV2Session
//   - send_v2           → SendV2
//   - pull_v2           → PullV2
//   - ack_v2            → AckV2
//   - _decrypt_v2_message → decryptV2Message（内部）
//
// V2 keystore 单独建库 `{aun_path}/AIDs/{safe(aid)}/v2_device_keys.db`，
// 不复用主 AIDDatabase 的 schema/事务，避免污染既有 keystore 包。

package aun

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/modelunion/aun-sdk-core/go/v2/e2ee"
	"github.com/modelunion/aun-sdk-core/go/v2/session"
)

// v2BootstrapTTL bootstrap 缓存有效期（与 Python `_V2_BOOTSTRAP_TTL = 3600` 对齐）。
const v2BootstrapTTL = time.Hour

type v2PullPageMeta struct {
	rawCount     int
	serverAckSeq int64
	hasServerAck bool
}

// v2BootstrapEntry 单条 peer_aid 缓存项。
type v2BootstrapEntry struct {
	Devices         []map[string]any
	AuditRecipients []map[string]any
	CachedAt        time.Time
	WrapPolicy      *v2WrapPolicy
}

type v2WrapPolicy struct {
	Protocol string
	Scope    string
}

func v2NormalizeWrapPolicy(raw any) *v2WrapPolicy {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	protocol := strings.ToUpper(strings.TrimSpace(v2AsString(obj["protocol"])))
	scope := strings.ToLower(strings.TrimSpace(v2AsString(obj["scope"])))
	if scope != "aid" && scope != "device" {
		if b, ok := obj["per_aid_wrap"].(bool); ok && b {
			scope = "aid"
		} else if b, ok := obj["per_device_wrap"].(bool); ok && b {
			scope = "device"
		} else {
			scope = ""
		}
	}
	if protocol != "1DH" && protocol != "3DH" {
		protocol = ""
	}
	if scope == "aid" {
		protocol = "1DH"
	}
	if protocol == "" && scope == "" {
		return nil
	}
	return &v2WrapPolicy{Protocol: protocol, Scope: scope}
}

func v2WrapCapabilities() map[string]any {
	return map[string]any{
		"version":         "v2.1",
		"protocols":       []string{"1DH", "3DH"},
		"scopes":          []string{"aid", "device"},
		"per_aid_wrap":    true,
		"per_device_wrap": true,
	}
}

func v2ApplyWrapPolicyToTargets(targets []e2ee.Target, policy *v2WrapPolicy) []e2ee.Target {
	if policy == nil {
		return targets
	}
	normalized := make([]e2ee.Target, 0, len(targets))
	for _, target := range targets {
		row := target
		if policy.Protocol == "1DH" {
			row.KeySource = "aid_master"
			row.SPKPkDER = nil
			row.SPKID = ""
		}
		normalized = append(normalized, row)
	}
	if policy.Scope != "aid" {
		return normalized
	}
	seen := make(map[string]bool, len(normalized))
	collapsed := make([]e2ee.Target, 0, len(normalized))
	for _, target := range normalized {
		key := target.AID + "\x00" + target.Role
		if seen[key] {
			continue
		}
		seen[key] = true
		target.DeviceID = ""
		collapsed = append(collapsed, target)
	}
	return collapsed
}

// v2P2PState 把 V2 P2P 相关状态聚合到一个嵌入字段，避免在主结构体散布字段。
type v2P2PState struct {
	mu              sync.Mutex
	session         *session.V2Session
	keystore        *V2SQLiteStore
	bootstrapCache  map[string]v2BootstrapEntry
	bootstrapCacheM sync.Mutex
	// groupBootstrapCache 群 bootstrap 缓存（key = groupID）。
	// 与 P2P bootstrapCache 分开存储，因为群缓存多 epoch + stateCommitment 字段。
	groupBootstrapCache map[string]*v2GroupBootstrapEntry
}

type v2SenderIKPendingEntry struct {
	Msg            map[string]any
	FromAID        string
	SenderDeviceID string
	GroupID        string
	CreatedAt      time.Time
}

// V2SQLiteStore 持有底层 *sql.DB + V2KeyStore，便于 client 关闭时释放资源。
type V2SQLiteStore struct {
	db    *sql.DB
	store *session.V2KeyStore
}

// Close 关闭 V2 keystore。
func (s *V2SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// safeAIDForPath 与 keystore.safeAID 逻辑对齐（私有，避免引入跨包依赖）。
func safeAIDForPath(aid string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_")
	return r.Replace(aid)
}

// openV2Keystore 在 {aunPath}/AIDs/{safe(aid)}/v2_device_keys.db 打开 V2 设备密钥库。
func openV2Keystore(aunPath, aid string) (*V2SQLiteStore, error) {
	if aunPath == "" {
		return nil, errors.New("V2 keystore: aun_path 为空")
	}
	if aid == "" {
		return nil, errors.New("V2 keystore: aid 为空")
	}
	dir := filepath.Join(aunPath, "AIDs", safeAIDForPath(aid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("V2 keystore: 创建目录失败: %w", err)
	}
	dbPath := filepath.Join(dir, "v2_device_keys.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("V2 keystore: 打开 SQLite 失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		// WAL 失败不阻塞，继续使用 DELETE 模式
		_, _ = db.Exec("PRAGMA journal_mode = DELETE")
	}
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		// busy_timeout 失败不阻塞
		_ = err
	}
	store, err := session.NewV2KeyStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &V2SQLiteStore{db: db, store: store}, nil
}

// InitV2Session 在 connect 成功后初始化 V2 session 并注册设备 SPK。
//
//   - 若 AID 缺失或 identity 无私钥，跳过（返回 nil）。
//   - IK = AID 长期密钥，从 identity["private_key_pem"] 解析为 raw scalar (32B P-256) + DER 公钥。
//   - 调用 V2Session.EnsureKeys 加载或生成 SPK；EnsureRegistered 上传 message.v2.put_peer_pk。
func (c *AUNClient) initV2Session(ctx context.Context) error {
	c.mu.RLock()
	aid := c.aid
	currentAID := c.currentAIDObj
	deviceID := c.deviceID
	aunPath := ""
	if c.configModel != nil {
		aunPath = c.configModel.AUNPath
	}
	c.mu.RUnlock()

	if aid == "" {
		return nil
	}
	// 私钥由 AIDStore 管理，直接从 currentAID 读取明文私钥
	privPEM := ""
	if currentAID != nil {
		privPEM = currentAID.PrivateKeyPem
	}
	if privPEM == "" {
		c.logE2.Warn("V2 session init skipped: no AID private key")
		return nil
	}

	ecKey, err := parseECPrivateKeyPEM(privPEM)
	if err != nil {
		return fmt.Errorf("V2 session init: 解析 AID 私钥失败: %w", err)
	}
	if ecKey.Curve.Params().BitSize != 256 {
		return fmt.Errorf("V2 session init: AID 私钥必须为 P-256 曲线")
	}
	aidPriv := ecKey.D.FillBytes(make([]byte, 32))
	aidPubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		return fmt.Errorf("V2 session init: 编码 AID 公钥失败: %w", err)
	}

	// 关闭已有 V2 keystore（处理重连或 AID 切换场景）
	c.releaseV2State()

	store, err := openV2Keystore(aunPath, aid)
	if err != nil {
		return err
	}

	v2 := session.NewV2Session(store.store, deviceID, aid, aidPriv, aidPubDER)
	if err := v2.EnsureKeys(); err != nil {
		_ = store.Close()
		return fmt.Errorf("V2 session init: EnsureKeys 失败: %w", err)
	}

	state := &v2P2PState{
		session:             v2,
		keystore:            store,
		bootstrapCache:      make(map[string]v2BootstrapEntry),
		groupBootstrapCache: make(map[string]*v2GroupBootstrapEntry),
	}
	c.mu.Lock()
	c.v2State = state
	c.mu.Unlock()

	if err := v2.EnsureRegistered(ctx, c.v2CallFn()); err != nil {
		// 注册失败时仍保留 session 状态：消费方面（pull/decrypt）依旧可用，
		// 发送方在 send_v2 调用时会自然透传错误。这里仅日志告警。
		c.logE2.Warn("V2 session init: EnsureRegistered 失败（保留 session 状态）: %v", err)
	} else {
		c.logE2.Debug("V2 session initialized: aid=%s device=%s", aid, deviceID)
	}

	return nil
}

func (c *AUNClient) releaseV2State() {
	c.mu.Lock()
	old := c.v2State
	c.v2State = nil
	c.mu.Unlock()
	if old != nil && old.keystore != nil {
		_ = old.keystore.Close()
	}
}

// v2CallFn 把 client.Call 适配为 session.CallFn（map[string]any 返回）。
func (c *AUNClient) v2CallFn() session.CallFn {
	return func(ctx context.Context, method string, params map[string]any) (map[string]any, error) {
		raw, err := c.Call(ctx, method, params)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return map[string]any{}, nil
		}
		if m, ok := raw.(map[string]any); ok {
			return m, nil
		}
		return nil, fmt.Errorf("V2 RPC %s: 返回类型非 map[string]any (%T)", method, raw)
	}
}

func (c *AUNClient) v2GetState() *v2P2PState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.v2State
}

// asString 把 any → string；非字符串返回空串。
func v2AsString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func v2DefaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// v2ToMapList 把 RPC 返回的 []any 列表转成 []map[string]any。
func v2ToMapList(v any) []map[string]any {
	switch arr := v.(type) {
	case []map[string]any:
		out := make([]map[string]any, len(arr))
		copy(out, arr)
		return out
	case []any:
		out := make([]map[string]any, 0, len(arr))
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func v2LegacyPayload(msg map[string]any) (payload any, encrypted bool, toAID string) {
	legacy, _ := msg["legacy_v1"].(map[string]any)
	if legacy != nil {
		payload = legacy["payload"]
		encrypted = truthyBool(legacy["encrypted"])
		toAID = v2AsString(legacy["to"])
	} else {
		payload = msg["payload"]
		encrypted = truthyBool(msg["encrypted"])
	}
	if pm, ok := payload.(map[string]any); ok {
		payloadType := strings.TrimSpace(v2AsString(pm["type"]))
		if payloadType == "e2ee.encrypted" || payloadType == "e2ee.group_encrypted" {
			encrypted = true
		}
	}
	return payload, encrypted, toAID
}

func v2LegacyMessageType(msg map[string]any, payload any) string {
	msgType := v2AsString(msg["type"])
	if msgType != "" {
		return msgType
	}
	if pm, ok := payload.(map[string]any); ok {
		return v2AsString(pm["type"])
	}
	return ""
}

func v2BuildLegacyP2PMessage(msg map[string]any, selfAID string) (map[string]any, bool) {
	seq := toInt64(msg["seq"])
	if seq <= 0 {
		return nil, false
	}
	payload, encrypted, toAID := v2LegacyPayload(msg)
	if encrypted || payload == nil {
		return nil, false
	}
	if toAID == "" {
		toAID = selfAID
	}
	return map[string]any{
		"message_id": v2AsString(msg["message_id"]),
		"from":       v2AsString(msg["from_aid"]),
		"to":         toAID,
		"seq":        seq,
		"type":       v2LegacyMessageType(msg, payload),
		"timestamp":  toInt64(msg["t_server"]),
		"payload":    payload,
		"encrypted":  false,
	}, true
}

func v2BuildLegacyGroupMessage(msg map[string]any, groupID string) (map[string]any, bool) {
	seq := toInt64(msg["seq"])
	if seq <= 0 {
		return nil, false
	}
	payload := msg["payload"]
	encrypted := truthyBool(msg["encrypted"])
	if pm, ok := payload.(map[string]any); ok {
		payloadType := strings.TrimSpace(v2AsString(pm["type"]))
		if payloadType == "e2ee.encrypted" || payloadType == "e2ee.group_encrypted" {
			encrypted = true
		}
	}
	if encrypted || payload == nil {
		return nil, false
	}
	return map[string]any{
		"message_id": v2AsString(msg["message_id"]),
		"from":       v2AsString(msg["from_aid"]),
		"group_id":   groupID,
		"seq":        seq,
		"type":       v2LegacyMessageType(msg, payload),
		"timestamp":  toInt64(msg["t_server"]),
		"payload":    payload,
		"encrypted":  false,
	}, true
}

// v2DecodeBase64Field 安全解析 b64 字符串字段；空值或错误返回 nil。
func v2DecodeBase64Field(m map[string]any, key string) []byte {
	s := v2AsString(m[key])
	if s == "" {
		return nil
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

func (c *AUNClient) getV2SenderPubDER(ctx context.Context, state *v2P2PState, fromAID, senderDeviceID string) []byte {
	if state == nil || state.session == nil || strings.TrimSpace(fromAID) == "" {
		return nil
	}
	if senderPubDER := state.session.GetPeerIK(fromAID, senderDeviceID); len(senderPubDER) > 0 {
		return senderPubDER
	}

	fetchCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		fetchCtx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	} else {
		var cctx context.Context
		cctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		fetchCtx = cctx
	}
	defer cancel()

	certBytes, certErr := c.fetchPeerCert(fetchCtx, fromAID, "")
	if certErr != nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: %v", fromAID, certErr)
		return nil
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: invalid PEM", fromAID)
		return nil
	}
	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: %v", fromAID, parseErr)
		return nil
	}
	der, marshalErr := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if marshalErr != nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: %v", fromAID, marshalErr)
		return nil
	}
	state.session.CachePeerIK(fromAID, senderDeviceID, der)
	c.logE2.Debug("V2 decrypt: sender IK fallback from PKI cert for %s", fromAID)
	return der
}

func (c *AUNClient) cacheV2PeerIKFromDevice(state *v2P2PState, dev map[string]any, fallbackAID string) {
	if state == nil || state.session == nil || dev == nil {
		return
	}
	devID, hasDeviceID := v2DeviceIDFromDevice(dev)
	aid := strings.TrimSpace(v2AsString(dev["aid"]))
	if aid == "" {
		aid = strings.TrimSpace(fallbackAID)
	}
	ikDER := v2DecodeBase64Field(dev, "ik_pk")
	if !hasDeviceID || aid == "" || len(ikDER) == 0 {
		return
	}
	state.session.CachePeerIK(aid, devID, ikDER)
}

func (c *AUNClient) v2PendingSenderIKMessageKey(msg map[string]any, groupID string) string {
	messageID := strings.TrimSpace(v2AsString(msg["message_id"]))
	seqText := strings.TrimSpace(fmt.Sprint(msg["seq"]))
	prefix := "p2p:" + c.AID()
	if strings.TrimSpace(groupID) != "" {
		prefix = "group:" + groupID
	}
	if messageID != "" {
		return prefix + ":" + messageID
	}
	if seqText != "" && seqText != "<nil>" {
		return prefix + ":" + seqText
	}
	return fmt.Sprintf("%s:pending:%d", prefix, time.Now().UnixNano())
}

func v2PendingSenderIKFetchKey(fromAID, senderDeviceID, groupID string) string {
	return strings.TrimSpace(fromAID) + "#" + senderDeviceID + "#" + strings.TrimSpace(groupID)
}

func (c *AUNClient) scheduleV2SenderIKPending(msg map[string]any, fromAID, senderDeviceID, groupID string) {
	fromAID = strings.TrimSpace(fromAID)
	if fromAID == "" {
		return
	}
	groupID = strings.TrimSpace(groupID)
	messageKey := c.v2PendingSenderIKMessageKey(msg, groupID)
	fetchKey := v2PendingSenderIKFetchKey(fromAID, senderDeviceID, groupID)
	shouldFetch := false
	c.v2SenderIKMu.Lock()
	c.v2SenderIKPending[messageKey] = v2SenderIKPendingEntry{
		Msg:            copyMapShallow(msg),
		FromAID:        fromAID,
		SenderDeviceID: senderDeviceID,
		GroupID:        groupID,
		CreatedAt:      time.Now(),
	}
	if !c.v2SenderIKFetching[fetchKey] {
		c.v2SenderIKFetching[fetchKey] = true
		shouldFetch = true
	}
	pendingCount := len(c.v2SenderIKPending)
	c.v2SenderIKMu.Unlock()
	c.logE2.Debug("V2 decrypt pending sender IK: key=%s from=%s device=%s group=%s pending=%d",
		messageKey, fromAID, valueOrDefault(senderDeviceID, "-"), valueOrDefault(groupID, "<p2p>"), pendingCount)
	if shouldFetch {
		go c.resolveV2SenderIKPending(fromAID, senderDeviceID, groupID, fetchKey)
	}
}

func (c *AUNClient) scheduleV2SenderIKFetch(fromAID, senderDeviceID, groupID string) {
	fromAID = strings.TrimSpace(fromAID)
	if fromAID == "" {
		return
	}
	groupID = strings.TrimSpace(groupID)
	fetchKey := v2PendingSenderIKFetchKey(fromAID, senderDeviceID, groupID)
	c.v2SenderIKMu.Lock()
	if c.v2SenderIKFetching[fetchKey] {
		c.v2SenderIKMu.Unlock()
		return
	}
	c.v2SenderIKFetching[fetchKey] = true
	c.v2SenderIKMu.Unlock()
	go c.resolveV2SenderIKPending(fromAID, senderDeviceID, groupID, fetchKey)
}

func (c *AUNClient) resolveV2SenderIKPending(fromAID, senderDeviceID, groupID, fetchKey string) {
	defer func() {
		if r := recover(); r != nil {
			c.logE2.Warn("V2 sender IK pending resolver panic: from=%s device=%s group=%s panic=%v", fromAID, senderDeviceID, groupID, r)
		}
		c.v2SenderIKMu.Lock()
		delete(c.v2SenderIKFetching, fetchKey)
		c.v2SenderIKMu.Unlock()
	}()

	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{
		"peer_aid":               fromAID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	}); err == nil {
		if bs, _ := raw.(map[string]any); bs != nil {
			for _, dev := range v2ToMapList(bs["peer_devices"]) {
				c.cacheV2PeerIKFromDevice(state, dev, fromAID)
			}
		}
	} else {
		c.logE2.Warn("V2 sender IK pending bootstrap failed peer=%s: %v", fromAID, err)
	}
	if strings.TrimSpace(groupID) != "" {
		if raw, err := c.Call(ctx, "group.v2.bootstrap", map[string]any{
			"group_id":               groupID,
			"e2ee_wrap_capabilities": v2WrapCapabilities(),
		}); err == nil {
			if bs, _ := raw.(map[string]any); bs != nil {
				for _, dev := range v2ToMapList(bs["devices"]) {
					c.cacheV2PeerIKFromDevice(state, dev, "")
				}
				for _, dev := range v2ToMapList(bs["audit_recipients"]) {
					c.cacheV2PeerIKFromDevice(state, dev, "")
				}
			}
		} else {
			c.logE2.Warn("V2 sender IK pending group bootstrap failed group=%s: %v", groupID, err)
		}
	}
	if len(state.session.GetPeerIK(fromAID, senderDeviceID)) == 0 {
		shortCtx, shortCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = c.getV2SenderPubDER(shortCtx, state, fromAID, senderDeviceID)
		shortCancel()
	}

	c.v2SenderIKMu.Lock()
	pendingItems := make(map[string]v2SenderIKPendingEntry)
	for key, entry := range c.v2SenderIKPending {
		if entry.FromAID == fromAID && entry.SenderDeviceID == senderDeviceID && entry.GroupID == groupID {
			pendingItems[key] = entry
		}
	}
	c.v2SenderIKMu.Unlock()

	for key, entry := range pendingItems {
		retryCtx, retryCancel := context.WithTimeout(context.Background(), 30*time.Second)
		plaintext := c.decryptV2MessageWithPending(retryCtx, state, entry.Msg, false)
		retryCancel()
		c.v2SenderIKMu.Lock()
		delete(c.v2SenderIKPending, key)
		c.v2SenderIKMu.Unlock()
		if plaintext == nil {
			c.logE2.Debug("V2 sender IK pending retry failed: key=%s", key)
			continue
		}
		seq := int(toInt64(entry.Msg["seq"]))
		if entry.GroupID != "" {
			plaintext["group_id"] = entry.GroupID
			c.publishPulledMessage("group.message_created", "group:"+entry.GroupID, seq, plaintext)
		} else {
			c.publishPulledMessage("message.received", "p2p:"+c.AID(), seq, plaintext)
		}
		c.logE2.Debug("V2 sender IK pending retry delivered: key=%s", key)
	}
}

// SendV2 V2 P2P 推测性加密发送。
//
//   - 优先使用 bootstrap 缓存（TTL = v2BootstrapTTL）。
//   - 缓存命中则直接发送；命中失败时刷新缓存重试 1 次。
//   - 同时携带 audit_recipients（监管方）和 self_sync（本 AID 其它设备）。
func (c *AUNClient) sendV2(ctx context.Context, to string, payload map[string]any) (map[string]any, error) {
	return c.SendV2WithOpts(ctx, to, payload, e2ee.EncryptOptions{})
}

// SendV2WithOpts 与 SendV2 相同，但允许传入 EncryptOptions（含 ProtectedHeaders / Context）。
func (c *AUNClient) SendV2WithOpts(ctx context.Context, to string, payload map[string]any, opts e2ee.EncryptOptions) (map[string]any, error) {
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, errors.New("V2 session not initialized (not connected?)")
	}
	if to == "" {
		return nil, errors.New("send_v2: to 不能为空")
	}
	c.logMessageDebugWithPayload("send-plaintext", "message.send.v2", "message.send", map[string]any{
		"to":      to,
		"payload": payload,
	}, payload, nil)

	resp, err := c.v2SendOnce(ctx, state, to, payload, true, opts)
	if err == nil {
		return resp, nil
	}

	if isV2RetryableError(err) {
		c.logE2.Debug("V2 P2P speculative send rejected (code=%d), refreshing bootstrap", v2ErrorCode(err))
		state.bootstrapCacheM.Lock()
		delete(state.bootstrapCache, to)
		state.bootstrapCacheM.Unlock()
		return c.v2SendOnce(ctx, state, to, payload, false, opts)
	}
	return nil, err
}

func (c *AUNClient) v2SendOnce(ctx context.Context, state *v2P2PState, to string, payload map[string]any, useCache bool, opts e2ee.EncryptOptions) (map[string]any, error) {
	c.logE2.Debug("message.v2.send attempt: to=%s use_cache=%v", to, useCache)
	peerDevices, auditRaw, wrapPolicy, err := c.v2ResolveBootstrap(ctx, state, to, useCache)
	if err != nil {
		return nil, err
	}
	if len(peerDevices) == 0 {
		return nil, fmt.Errorf("V2 bootstrap: no devices found for %s", to)
	}

	targets := make([]e2ee.Target, 0, len(peerDevices))
	for _, dev := range peerDevices {
		devID := v2AsString(dev["device_id"])
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, to, devID, "peer", "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			targets = append(targets, target)
		}
	}

	auditTargets := make([]e2ee.Target, 0, len(auditRaw))
	for _, dev := range auditRaw {
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, v2AsString(dev["aid"]), v2AsString(dev["device_id"]), "audit", "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			auditTargets = append(auditTargets, target)
		}
	}

	// self-sync：同 AID 其它设备
	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()
	if myAID != "" && myAID != to {
		selfDevices := c.v2FetchSelfDevices(ctx, state, myAID)
		for _, dev := range selfDevices {
			devID, hasDeviceID := v2DeviceIDFromDevice(dev)
			if !hasDeviceID || devID == myDeviceID {
				continue
			}
			target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, myAID, devID, "self_sync", "peer_device_prekey")
			if err != nil {
				return nil, err
			}
			if ok {
				targets = append(targets, target)
			}
		}
	}

	sender, err := state.session.GetSenderIdentity()
	if err != nil {
		return nil, fmt.Errorf("send_v2: 获取 sender identity 失败: %w", err)
	}

	sendTargets := v2ApplyWrapPolicyToTargets(targets, wrapPolicy)
	sendAuditTargets := v2ApplyWrapPolicyToTargets(auditTargets, wrapPolicy)
	envelope, err := e2ee.EncryptP2PMessage(
		e2ee.Sender{
			AID:      sender.AID,
			DeviceID: sender.DeviceID,
			IKPriv:   sender.IKPriv,
			IKPubDER: sender.IKPubDER,
		},
		e2ee.TargetSet{Targets: sendTargets, AuditRecipients: sendAuditTargets},
		payload,
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("send_v2: 加密失败: %w", err)
	}
	c.logMessageDebugWithPayload("send-envelope", "message.send.v2", "message.send", map[string]any{
		"to":         to,
		"message_id": envelope["message_id"],
		"type":       envelope["type"],
		"version":    envelope["version"],
	}, envelope, map[string]any{
		"plaintext_payload": payload,
		"target_count":      len(sendTargets),
		"audit_count":       len(sendAuditTargets),
		"use_cache":         useCache,
	})

	raw, err := c.Call(ctx, "message.send", map[string]any{
		"to":      to,
		"payload": envelope,
		"encrypt": false,
	})
	if err != nil {
		return nil, err
	}
	if m, ok := raw.(map[string]any); ok {
		c.logE2.Debug("message.v2.send ok: to=%s use_cache=%v seq=%d", to, useCache, toInt64(m["seq"]))
		return m, nil
	}
	c.logE2.Debug("message.v2.send ok: to=%s use_cache=%v seq=<unknown>", to, useCache)
	return map[string]any{}, nil
}

// v2ResolveBootstrap 根据 useCache 决定是否使用缓存，未命中则调 message.v2.bootstrap。
func (c *AUNClient) v2ResolveBootstrap(ctx context.Context, state *v2P2PState, peerAID string, useCache bool) ([]map[string]any, []map[string]any, *v2WrapPolicy, error) {
	if useCache {
		state.bootstrapCacheM.Lock()
		entry, ok := state.bootstrapCache[peerAID]
		state.bootstrapCacheM.Unlock()
		if ok && time.Since(entry.CachedAt) < v2BootstrapTTL {
			c.logE2.Debug("message.v2.bootstrap cache hit: peer=%s devices=%d audit=%d", peerAID, len(entry.Devices), len(entry.AuditRecipients))
			return entry.Devices, entry.AuditRecipients, entry.WrapPolicy, nil
		}
	}
	raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{
		"peer_aid":               peerAID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("V2 bootstrap: %w", err)
	}
	bs, _ := raw.(map[string]any)
	devices := v2ToMapList(bs["peer_devices"])
	audit := v2ToMapList(bs["audit_recipients"])
	wrapPolicy := v2NormalizeWrapPolicy(bs["e2ee_wrap_policy"])
	c.logE2.Debug("message.v2.bootstrap fetched: peer=%s devices=%d audit=%d", peerAID, len(devices), len(audit))
	if len(devices) > 0 {
		state.bootstrapCacheM.Lock()
		state.bootstrapCache[peerAID] = v2BootstrapEntry{
			Devices:         devices,
			AuditRecipients: audit,
			CachedAt:        time.Now(),
			WrapPolicy:      wrapPolicy,
		}
		state.bootstrapCacheM.Unlock()
	}
	return devices, audit, wrapPolicy, nil
}

// v2FetchSelfDevices 缓存优先获取本 AID 其它设备列表（best-effort，错误吞掉返回空）。
func (c *AUNClient) v2FetchSelfDevices(ctx context.Context, state *v2P2PState, myAID string) []map[string]any {
	state.bootstrapCacheM.Lock()
	entry, ok := state.bootstrapCache[myAID]
	state.bootstrapCacheM.Unlock()
	if ok && time.Since(entry.CachedAt) < v2BootstrapTTL {
		return entry.Devices
	}
	raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{
		"peer_aid":               myAID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	})
	if err != nil {
		c.logE2.Debug("V2 self-sync bootstrap failed (non-fatal): %v", err)
		return nil
	}
	bs, _ := raw.(map[string]any)
	devices := v2ToMapList(bs["peer_devices"])
	if len(devices) > 0 {
		state.bootstrapCacheM.Lock()
		state.bootstrapCache[myAID] = v2BootstrapEntry{
			Devices:  devices,
			CachedAt: time.Now(),
		}
		state.bootstrapCacheM.Unlock()
	}
	return devices
}

// PullV2 拉取并解密 V2 P2P 消息。
//
// afterSeq=0 时使用本地 SeqTracker 的 contiguous_seq（对齐 Python pull_v2）。
// limit=0 时默认 50。
func (c *AUNClient) pullV2(ctx context.Context, afterSeq int64, limit int) ([]map[string]any, error) {
	msgs, _, err := c.pullV2WithForce(ctx, afterSeq, limit, false)
	return msgs, err
}

func (c *AUNClient) pullV2WithForce(ctx context.Context, afterSeq int64, limit int, force bool) ([]map[string]any, v2PullPageMeta, error) {
	meta := v2PullPageMeta{}
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, meta, errors.New("V2 session not initialized (not connected?)")
	}
	if limit <= 0 {
		limit = 50
	}

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	ns := ""
	if myAID != "" {
		ns = "p2p:" + myAID
	}

	effectiveAfterSeq := afterSeq
	if !force && effectiveAfterSeq == 0 && ns != "" {
		effectiveAfterSeq = int64(c.seqTracker.GetContiguousSeq(ns))
	}

	c.logE2.Debug("message.v2.pull request: after_seq=%d limit=%d ns=%s", effectiveAfterSeq, limit, ns)
	pullParams := map[string]any{
		"after_seq": effectiveAfterSeq,
		"limit":     limit,
	}
	if force {
		pullParams["force"] = true
	}
	raw, err := c.Call(ctx, "message.v2.pull", pullParams)
	if err != nil {
		return nil, meta, err
	}
	result, _ := raw.(map[string]any)
	messages := v2ToMapList(result["messages"])
	_, hasServerAckSeq := result["server_ack_seq"]
	serverAckSeq := toInt64(result["server_ack_seq"])
	meta = v2PullPageMeta{
		rawCount:     len(messages),
		serverAckSeq: serverAckSeq,
		hasServerAck: hasServerAckSeq,
	}
	c.logE2.Debug("message.v2.pull response: raw_count=%d server_ack_seq=%d has_more=%v", len(messages), serverAckSeq, result["has_more"])
	for _, msg := range messages {
		c.logMessageDebug("pull-raw", "message.v2.pull", "message.received", msg, nil)
	}

	decrypted := make([]map[string]any, 0, len(messages))
	contigBefore := 0
	if ns != "" {
		contigBefore = c.seqTracker.GetContiguousSeq(ns)
	}
	maxSeq := int64(0)
	for _, msg := range messages {
		seq := toInt64(msg["seq"])
		if seq <= 0 {
			continue
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}

	for _, msg := range messages {
		seq := toInt64(msg["seq"])
		if seq <= 0 {
			continue
		}

		if v2AsString(msg["version"]) == "v1" {
			if legacy, ok := v2BuildLegacyP2PMessage(msg, myAID); ok {
				decrypted = append(decrypted, legacy)
				c.logE2.Debug("message.v2.pull plaintext V1 decrypted: seq=%d ns=%s", seq, ns)
			} else {
				c.logE2.Debug("V2 pull skipped legacy V1 encrypted/empty message: seq=%d", seq)
			}
			continue
		}

		// 跟踪每个旧 SPK 引用的最大 seq（用于消费后销毁）
		msgSpkID := v2AsString(msg["spk_id"])
		if msgSpkID != "" && !state.session.IsCurrentSPK(msgSpkID) {
			state.session.TrackOldSPKMaxSeq(msgSpkID, seq)
		}

		plaintext := c.decryptV2Message(ctx, state, msg)
		if plaintext != nil {
			decrypted = append(decrypted, plaintext)
			c.logMessageDebug("decrypt-ok", "message.v2.pull", "message.received", plaintext, nil)
		} else {
			c.logE2.Debug("message.v2.pull decrypt returned nil: seq=%d ns=%s", seq, ns)
		}
	}

	if ns != "" {
		if maxSeq > 0 {
			currentContig := c.seqTracker.GetContiguousSeq(ns)
			if int(maxSeq) > currentContig {
				c.seqTracker.ForceContiguousSeq(ns, int(maxSeq))
				c.logE2.Debug("V2 P2P pull force-advanced contig: %d -> %d", currentContig, maxSeq)
				c.drainOrderedMessages(ns)
			}
		}
		if serverAckSeq > 0 {
			currentContig := c.seqTracker.GetContiguousSeq(ns)
			if int(serverAckSeq) > currentContig {
				c.seqTracker.ForceContiguousSeq(ns, int(serverAckSeq))
				c.logE2.Info("V2 P2P pull retention-floor advanced: ns=%s contiguous=%d -> server_ack_seq=%d", ns, currentContig, serverAckSeq)
				c.drainOrderedMessages(ns)
			}
		}
		if c.seqTracker.GetContiguousSeq(ns) != contigBefore {
			c.saveSeqTrackerState()
		}
	}

	c.logE2.Debug("message.v2.pull done: requested_after_seq=%d raw_count=%d decrypted=%d ns=%s", afterSeq, len(messages), len(decrypted), ns)
	return decrypted, meta, nil
}

// AckV2 确认 V2 消息已消费 + 自检销毁旧 SPK。
//
// upToSeq=0 时使用本地 SeqTracker 的 contiguous_seq。返回 {"acked": int64} 兜底。
func (c *AUNClient) ackV2(ctx context.Context, upToSeq int64) (map[string]any, error) {
	state := c.v2GetState()

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	ns := ""
	if myAID != "" {
		ns = "p2p:" + myAID
	}

	seq := upToSeq
	if seq == 0 && ns != "" {
		seq = int64(c.seqTracker.GetContiguousSeq(ns))
	}
	if seq <= 0 {
		c.logE2.Debug("message.v2.ack skipped: ns=%s up_to_seq=%d", ns, upToSeq)
		return map[string]any{"acked": int64(0)}, nil
	}
	if ns != "" {
		seq = c.clampAckSeq("message.v2.ack", "up_to_seq", ns, seq)
		if seq <= 0 {
			return map[string]any{"acked": int64(0)}, nil
		}
	}

	c.logE2.Debug("message.v2.ack send: ns=%s up_to_seq=%d", ns, seq)
	raw, err := c.Call(ctx, "message.v2.ack", map[string]any{"up_to_seq": seq})
	if err != nil {
		return nil, err
	}
	result, _ := raw.(map[string]any)
	if result == nil {
		result = map[string]any{}
	}
	actualAckSeq := seq
	if _, ok := result["effective_ack_seq"]; ok {
		actualAckSeq = toInt64(result["effective_ack_seq"])
	} else if _, ok := result["ack_seq"]; ok {
		actualAckSeq = toInt64(result["ack_seq"])
	} else if _, ok := result["cursor"]; ok {
		actualAckSeq = toInt64(result["cursor"])
	}

	if state != nil && state.session != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.logE2.Debug("V2 SPK destroy failed (non-fatal): %v", r)
				}
			}()
			destroyed := state.session.MaybeDestroyOldSPKs(actualAckSeq)
			if len(destroyed) > 0 {
				limit := len(destroyed)
				if limit > 3 {
					limit = 3
				}
				c.logE2.Info("V2 destroyed old SPKs after ack: %v (PFS)", destroyed[:limit])
			}
		}()
	}
	result["ack_seq"] = actualAckSeq
	result["success"] = true
	if toInt64(result["acked"]) == 0 && actualAckSeq > 0 {
		result["acked"] = actualAckSeq
	}
	c.logE2.Debug("message.v2.ack ok: ns=%s requested=%d effective=%d result=%v", ns, seq, actualAckSeq, result)
	return result, nil
}

// decryptV2Message 解密单条 V2 P2P 消息（pull 内部使用）。
//
// 返回值：
//   - 解密成功 → 应用层消息 dict（包含 message_id / from / to / seq / payload / e2ee）
//   - 解密失败或无 envelope_json → nil（必要时发布 undecryptable 事件）
func (c *AUNClient) decryptV2Message(ctx context.Context, state *v2P2PState, msg map[string]any) map[string]any {
	return c.decryptV2MessageWithPending(ctx, state, msg, true)
}

func (c *AUNClient) decryptV2MessageWithPending(ctx context.Context, state *v2P2PState, msg map[string]any, allowPending bool) map[string]any {
	envJSON := v2AsString(msg["envelope_json"])
	if envJSON == "" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(envJSON))
	dec.UseNumber()
	var envelope map[string]any
	if err := dec.Decode(&envelope); err != nil {
		c.logE2.Warn("V2 decrypt: invalid envelope_json for msg seq=%v: %v", msg["seq"], err)
		return nil
	}
	e2eeMeta := v2MessageE2EEMetadata(envelope)
	c.observeAgentMDFromEnvelope(envelope)

	// 确定 spk_id
	spkID := ""
	recipientKeySource := ""
	if r, ok := envelope["recipient"].(map[string]any); ok {
		spkID = v2AsString(r["spk_id"])
		recipientKeySource = v2AsString(r["key_source"])
	} else if rows, ok := envelope["recipients"]; ok {
		spkID = v2AsString(msg["spk_id"])
		if recipients, ok := rows.([]any); ok {
			for _, row := range recipients {
				cells, ok := row.([]any)
				if !ok || len(cells) < 6 {
					continue
				}
				if v2AsString(cells[0]) != c.aid || v2AsString(cells[1]) != c.deviceID {
					continue
				}
				if spkID == "" {
					spkID = v2AsString(cells[5])
				}
				if len(cells) > 3 {
					recipientKeySource = v2AsString(cells[3])
				}
				break
			}
		}
	}

	// group_id 只表示群上下文；GetGroupDecryptKeys 内部必须按 group SPK -> P2P device SPK -> IK fallback 查找。
	groupIDForKeys := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		groupIDForKeys = strings.TrimSpace(v2AsString(aad["group_id"]))
	}
	if groupIDForKeys == "" {
		groupIDForKeys = strings.TrimSpace(v2AsString(msg["group_id"]))
	}
	undecryptableEvent := "message.undecryptable"
	if groupIDForKeys != "" {
		undecryptableEvent = "group.message_undecryptable"
	}
	c.logE2.Debug("V2 decrypt start: seq=%v message_id=%s group=%s from=%s spk_id=%s key_source=%s has_recipient=%v has_recipients=%v",
		msg["seq"], v2AsString(msg["message_id"]), valueOrDefault(groupIDForKeys, "<p2p>"), v2AsString(msg["from_aid"]), valueOrDefault(spkID, "<empty>"), valueOrDefault(recipientKeySource, "<empty>"),
		envelope["recipient"] != nil, envelope["recipients"] != nil)
	var ikPriv, spkPriv []byte
	var err error
	if groupIDForKeys != "" {
		ikPriv, spkPriv, err = state.session.GetGroupDecryptKeys(groupIDForKeys, spkID)
	} else {
		ikPriv, spkPriv, err = state.session.GetDecryptKeys(spkID)
	}
	if err != nil {
		c.logE2.Warn("V2 decrypt: GetDecryptKeys 失败 seq=%v group=%s: %v", msg["seq"], groupIDForKeys, err)
		event := map[string]any{
			"message_id":     v2AsString(msg["message_id"]),
			"from":           v2AsString(msg["from_aid"]),
			"to":             v2AsString(msg["to"]),
			"seq":            msg["seq"],
			"timestamp":      msg["t_server"],
			"device_id":      v2AsString(msg["device_id"]),
			"slot_id":        v2AsString(msg["slot_id"]),
			"_decrypt_error": err.Error(),
			"_decrypt_stage": "spk_lookup",
			"_envelope_type": v2AsString(envelope["type"]),
			"_suite":         v2AsString(envelope["suite"]),
			"_spk_id":        spkID,
		}
		attachV2EnvelopeMetadata(event, e2eeMeta)
		c.logMessageDebug("decrypt-fail", "v2.decrypt", undecryptableEvent, event, nil)
		c.publishAppEventSync(undecryptableEvent, event)
		return nil
	}
	c.logE2.Debug("V2 decrypt key lookup ok: seq=%v group=%s ik_len=%d spk_len=%d", msg["seq"], valueOrDefault(groupIDForKeys, "<p2p>"), len(ikPriv), len(spkPriv))

	// sender 公钥（按 sender device_id 精确匹配）
	fromAID := v2AsString(msg["from_aid"])
	senderDeviceID := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		senderDeviceID = v2AsString(aad["from_device"])
	}
	senderPubDER := c.getV2SenderPubDER(ctx, state, fromAID, senderDeviceID)
	if len(senderPubDER) == 0 {
		c.logE2.Warn("V2 decrypt: no sender IK for %s device=%s", fromAID, senderDeviceID)
		if allowPending {
			c.scheduleV2SenderIKPending(msg, fromAID, senderDeviceID, groupIDForKeys)
			return nil
		}
		event := map[string]any{
			"message_id":        v2AsString(msg["message_id"]),
			"from":              fromAID,
			"to":                v2AsString(msg["to"]),
			"seq":               msg["seq"],
			"timestamp":         msg["t_server"],
			"device_id":         v2AsString(msg["device_id"]),
			"slot_id":           v2AsString(msg["slot_id"]),
			"_decrypt_error":    "sender_ik_not_found",
			"_decrypt_stage":    "sender_ik",
			"_envelope_type":    v2AsString(envelope["type"]),
			"_suite":            v2AsString(envelope["suite"]),
			"_sender_device_id": senderDeviceID,
		}
		attachV2EnvelopeMetadata(event, e2eeMeta)
		c.logMessageDebug("decrypt-fail", "v2.decrypt", undecryptableEvent, event, nil)
		c.publishAppEventSync(undecryptableEvent, event)
		return nil
	}

	c.mu.RLock()
	selfAID := c.aid
	selfDeviceID := c.deviceID
	c.mu.RUnlock()

	plaintext, err := e2ee.DecryptMessage(envelope, selfAID, selfDeviceID, ikPriv, spkPriv, senderPubDER)
	if err != nil {
		c.logE2.Warn("V2 decrypt failed for msg seq=%v: %v", msg["seq"], err)
		event := map[string]any{
			"message_id":        v2AsString(msg["message_id"]),
			"from":              fromAID,
			"to":                v2AsString(msg["to"]),
			"seq":               msg["seq"],
			"timestamp":         msg["t_server"],
			"device_id":         v2AsString(msg["device_id"]),
			"slot_id":           v2AsString(msg["slot_id"]),
			"_decrypt_error":    err.Error(),
			"_decrypt_stage":    "decrypt",
			"_envelope_type":    v2AsString(envelope["type"]),
			"_suite":            v2AsString(envelope["suite"]),
			"_sender_device_id": senderDeviceID,
		}
		attachV2EnvelopeMetadata(event, e2eeMeta)
		c.logMessageDebug("decrypt-fail", "v2.decrypt", undecryptableEvent, event, nil)
		c.publishAppEventSync(undecryptableEvent, event)
		return nil
	}
	if plaintext == nil {
		c.logE2.Debug("V2 decrypt returned nil plaintext: seq=%v group=%s", msg["seq"], valueOrDefault(groupIDForKeys, "<p2p>"))
		return nil
	}

	// SPK 轮换：当前活跃 SPK 被消费后立即轮换（后台执行，不阻塞）
	if groupIDForKeys != "" && recipientKeySource == "group_device_prekey" && state.session.IsLastUploadedGroupSPK(groupIDForKeys, spkID) {
		// Group SPK 消费触发轮换
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.logE2.Warn("V2 group SPK rotation panic: %v", r)
				}
			}()
			rotateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := state.session.RotateGroupSPK(rotateCtx, groupIDForKeys, c.v2CallFn()); err != nil {
				c.logE2.Warn("V2 group SPK rotation failed (non-fatal): group=%s %v", groupIDForKeys, err)
			} else {
				c.logE2.Debug("V2 group SPK rotated after consumption: group=%s aid=%s", groupIDForKeys, selfAID)
			}
		}()
	} else if groupIDForKeys != "" && recipientKeySource == "peer_device_prekey" {
		// peer_device_prekey fallback：补注册 group SPK
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.logE2.Warn("V2 group SPK registration panic: %v", r)
				}
			}()
			regCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := state.session.EnsureGroupRegistered(regCtx, groupIDForKeys, c.v2CallFn()); err != nil {
				c.logE2.Debug("V2 group SPK registration after peer fallback failed (non-fatal): group=%s %v", groupIDForKeys, err)
			} else {
				c.logE2.Debug("V2 group SPK registered after peer fallback: group=%s", groupIDForKeys)
			}
		}()
	} else if groupIDForKeys == "" && state.session.IsLastUploadedSPK(spkID) {
		// P2P SPK 消费触发轮换
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.logE2.Warn("V2 SPK rotation panic: %v", r)
				}
			}()
			rotateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := state.session.RotateSPK(rotateCtx, c.v2CallFn()); err != nil {
				c.logE2.Warn("V2 SPK rotation failed (non-fatal): %v", err)
			} else {
				c.logE2.Debug("V2 SPK rotated after consumption: aid=%s", selfAID)
			}
		}()
	}

	e2ee := v2MessageE2EEMetadata(envelope)
	result := map[string]any{
		"message_id": v2AsString(msg["message_id"]),
		"from":       fromAID,
		"to":         selfAID,
		"seq":        msg["seq"],
		"t_server":   msg["t_server"],
		"payload":    plaintext,
		"encrypted":  true,
		"e2ee":       e2ee,
	}
	direction := strings.TrimSpace(v2AsString(msg["direction"]))
	if direction == "" {
		if fromAID != "" && fromAID == selfAID {
			direction = "outbound_sync"
		} else {
			direction = "inbound"
		}
	}
	result["direction"] = direction
	if v, ok := msg["device_id"]; ok {
		result["device_id"] = v
	}
	if v, ok := msg["slot_id"]; ok {
		result["slot_id"] = v
	}
	attachV2EnvelopeMetadata(result, e2ee)
	if groupIDForKeys != "" {
		c.logMessageDebug("decrypt-ok", "v2.decrypt", "group.message_created", result, nil)
	} else {
		c.logMessageDebug("decrypt-ok", "v2.decrypt", "message.received", result, nil)
	}
	return result
}

// v2RetryableCodes 是推测性发送可重试的服务端错误码集合。
var v2RetryableCodes = map[int]bool{
	-33011: true, // device_not_found
	-33012: true, // prekey_stale
	-33050: true, // recipient_mismatch
	-33052: true, // epoch_mismatch
	-33054: true, // member_list_changed
}

func isV2RetryableError(err error) bool {
	var ae *AUNError
	if errors.As(err, &ae) {
		return v2RetryableCodes[ae.Code]
	}
	return false
}

func v2ErrorCode(err error) int {
	var ae *AUNError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return 0
}
