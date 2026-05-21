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

// v2BootstrapEntry 单条 peer_aid 缓存项。
type v2BootstrapEntry struct {
	Devices         []map[string]any
	AuditRecipients []map[string]any
	CachedAt        time.Time
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
func (c *AUNClient) InitV2Session(ctx context.Context) error {
	c.mu.RLock()
	aid := c.aid
	identity := c.identity
	deviceID := c.deviceID
	aunPath := ""
	if c.configModel != nil {
		aunPath = c.configModel.AUNPath
	}
	c.mu.RUnlock()

	if aid == "" {
		return nil
	}
	privPEM, _ := identity["private_key_pem"].(string)
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

// SendV2 V2 P2P 推测性加密发送。
//
//   - 优先使用 bootstrap 缓存（TTL = v2BootstrapTTL）。
//   - 缓存命中则直接发送；命中失败时刷新缓存重试 1 次。
//   - 同时携带 audit_recipients（监管方）和 self_sync（本 AID 其它设备）。
func (c *AUNClient) SendV2(ctx context.Context, to string, payload map[string]any) (map[string]any, error) {
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
	peerDevices, auditRaw, err := c.v2ResolveBootstrap(ctx, state, to, useCache)
	if err != nil {
		return nil, err
	}
	if len(peerDevices) == 0 {
		return nil, fmt.Errorf("V2 bootstrap: no devices found for %s", to)
	}

	targets := make([]e2ee.Target, 0, len(peerDevices))
	for _, dev := range peerDevices {
		ikDER := v2DecodeBase64Field(dev, "ik_pk")
		if len(ikDER) == 0 {
			continue
		}
		spkDER := v2DecodeBase64Field(dev, "spk_pk")
		devID := v2AsString(dev["device_id"])
		state.session.CachePeerIK(to, devID, ikDER)
		targets = append(targets, e2ee.Target{
			AID:       to,
			DeviceID:  devID,
			Role:      "peer",
			KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
			IKPkDER:   ikDER,
			SPKPkDER:  spkDER,
			SPKID:     v2AsString(dev["spk_id"]),
		})
	}

	auditTargets := make([]e2ee.Target, 0, len(auditRaw))
	for _, dev := range auditRaw {
		ikDER := v2DecodeBase64Field(dev, "ik_pk")
		if len(ikDER) == 0 {
			continue
		}
		spkDER := v2DecodeBase64Field(dev, "spk_pk")
		auditTargets = append(auditTargets, e2ee.Target{
			AID:       v2AsString(dev["aid"]),
			DeviceID:  v2AsString(dev["device_id"]),
			Role:      "audit",
			KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
			IKPkDER:   ikDER,
			SPKPkDER:  spkDER,
			SPKID:     v2AsString(dev["spk_id"]),
		})
	}

	// self-sync：同 AID 其它设备
	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()
	if myAID != "" && myAID != to {
		selfDevices := c.v2FetchSelfDevices(ctx, state, myAID)
		for _, dev := range selfDevices {
			devID := v2AsString(dev["owner_device_id"])
			if devID == "" {
				devID = v2AsString(dev["device_id"])
			}
			if devID == "" || devID == myDeviceID {
				continue
			}
			ikDER := v2DecodeBase64Field(dev, "ik_pk")
			if len(ikDER) == 0 {
				continue
			}
			spkDER := v2DecodeBase64Field(dev, "spk_pk")
			targets = append(targets, e2ee.Target{
				AID:       myAID,
				DeviceID:  devID,
				Role:      "self_sync",
				KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
				IKPkDER:   ikDER,
				SPKPkDER:  spkDER,
				SPKID:     v2AsString(dev["spk_id"]),
			})
		}
	}

	sender, err := state.session.GetSenderIdentity()
	if err != nil {
		return nil, fmt.Errorf("send_v2: 获取 sender identity 失败: %w", err)
	}

	envelope, err := e2ee.EncryptP2PMessage(
		e2ee.Sender{
			AID:      sender.AID,
			DeviceID: sender.DeviceID,
			IKPriv:   sender.IKPriv,
			IKPubDER: sender.IKPubDER,
		},
		e2ee.TargetSet{Targets: targets, AuditRecipients: auditTargets},
		payload,
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("send_v2: 加密失败: %w", err)
	}

	raw, err := c.Call(ctx, "message.send", map[string]any{
		"to":      to,
		"payload": envelope,
		"encrypt": false,
	})
	if err != nil {
		return nil, err
	}
	if m, ok := raw.(map[string]any); ok {
		return m, nil
	}
	return map[string]any{}, nil
}

// v2ResolveBootstrap 根据 useCache 决定是否使用缓存，未命中则调 message.v2.bootstrap。
func (c *AUNClient) v2ResolveBootstrap(ctx context.Context, state *v2P2PState, peerAID string, useCache bool) ([]map[string]any, []map[string]any, error) {
	if useCache {
		state.bootstrapCacheM.Lock()
		entry, ok := state.bootstrapCache[peerAID]
		state.bootstrapCacheM.Unlock()
		if ok && time.Since(entry.CachedAt) < v2BootstrapTTL {
			return entry.Devices, entry.AuditRecipients, nil
		}
	}
	raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{"peer_aid": peerAID})
	if err != nil {
		return nil, nil, fmt.Errorf("V2 bootstrap: %w", err)
	}
	bs, _ := raw.(map[string]any)
	devices := v2ToMapList(bs["peer_devices"])
	audit := v2ToMapList(bs["audit_recipients"])
	if len(devices) > 0 {
		state.bootstrapCacheM.Lock()
		state.bootstrapCache[peerAID] = v2BootstrapEntry{
			Devices:         devices,
			AuditRecipients: audit,
			CachedAt:        time.Now(),
		}
		state.bootstrapCacheM.Unlock()
	}
	return devices, audit, nil
}

// v2FetchSelfDevices 缓存优先获取本 AID 其它设备列表（best-effort，错误吞掉返回空）。
func (c *AUNClient) v2FetchSelfDevices(ctx context.Context, state *v2P2PState, myAID string) []map[string]any {
	state.bootstrapCacheM.Lock()
	entry, ok := state.bootstrapCache[myAID]
	state.bootstrapCacheM.Unlock()
	if ok && time.Since(entry.CachedAt) < v2BootstrapTTL {
		return entry.Devices
	}
	raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{"peer_aid": myAID})
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
func (c *AUNClient) PullV2(ctx context.Context, afterSeq int64, limit int) ([]map[string]any, error) {
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, errors.New("V2 session not initialized (not connected?)")
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
	if effectiveAfterSeq == 0 && ns != "" {
		effectiveAfterSeq = int64(c.seqTracker.GetContiguousSeq(ns))
	}

	raw, err := c.Call(ctx, "message.v2.pull", map[string]any{
		"after_seq": effectiveAfterSeq,
		"limit":     limit,
	})
	if err != nil {
		return nil, err
	}
	result, _ := raw.(map[string]any)
	messages := v2ToMapList(result["messages"])

	decrypted := make([]map[string]any, 0, len(messages))
	contigBefore := 0
	if ns != "" {
		contigBefore = c.seqTracker.GetContiguousSeq(ns)
	}
	firstSeq := int64(0)
	maxSeq := int64(0)
	for _, msg := range messages {
		seq := toInt64(msg["seq"])
		if seq <= 0 {
			continue
		}
		if firstSeq == 0 {
			firstSeq = seq
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	if ns != "" && firstSeq > 0 && int(firstSeq) > contigBefore {
		c.seqTracker.ForceContiguousSeq(ns, int(firstSeq))
	}

	for _, msg := range messages {
		seq := toInt64(msg["seq"])
		if seq <= 0 {
			continue
		}

		if v2AsString(msg["version"]) == "v1" {
			if legacy, ok := v2BuildLegacyP2PMessage(msg, myAID); ok {
				decrypted = append(decrypted, legacy)
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
		if c.seqTracker.GetContiguousSeq(ns) != contigBefore {
			c.saveSeqTrackerState()
		}
	}

	return decrypted, nil
}

// AckV2 确认 V2 消息已消费 + 自检销毁旧 SPK。
//
// upToSeq=0 时使用本地 SeqTracker 的 contiguous_seq。返回 {"acked": int64} 兜底。
func (c *AUNClient) AckV2(ctx context.Context, upToSeq int64) (map[string]any, error) {
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
		return map[string]any{"acked": int64(0)}, nil
	}

	raw, err := c.Call(ctx, "message.v2.ack", map[string]any{"up_to_seq": seq})
	if err != nil {
		return nil, err
	}
	result, _ := raw.(map[string]any)
	if result == nil {
		result = map[string]any{}
	}

	if state != nil && state.session != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.logE2.Debug("V2 SPK destroy failed (non-fatal): %v", r)
				}
			}()
			destroyed := state.session.MaybeDestroyOldSPKs(seq)
			if len(destroyed) > 0 {
				limit := len(destroyed)
				if limit > 3 {
					limit = 3
				}
				c.logE2.Info("V2 destroyed old SPKs after ack: %v (PFS)", destroyed[:limit])
			}
		}()
	}
	result["ack_seq"] = seq
	result["success"] = true
	if toInt64(result["acked"]) == 0 && seq > 0 {
		result["acked"] = seq
	}
	return result, nil
}

// decryptV2Message 解密单条 V2 P2P 消息（pull 内部使用）。
//
// 返回值：
//   - 解密成功 → 应用层消息 dict（包含 message_id / from / to / seq / payload / e2ee）
//   - 解密失败或无 envelope_json → nil（同时发布 message.undecryptable 事件）
func (c *AUNClient) decryptV2Message(ctx context.Context, state *v2P2PState, msg map[string]any) map[string]any {
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

	// 确定 spk_id
	spkID := ""
	if r, ok := envelope["recipient"].(map[string]any); ok {
		spkID = v2AsString(r["spk_id"])
	} else if _, ok := envelope["recipients"]; ok {
		spkID = v2AsString(msg["spk_id"])
	}

	ikPriv, spkPriv, err := state.session.GetDecryptKeys(spkID)
	if err != nil {
		c.logE2.Warn("V2 decrypt: GetDecryptKeys 失败 seq=%v: %v", msg["seq"], err)
		return nil
	}

	// sender 公钥（按 sender device_id 精确匹配）
	fromAID := v2AsString(msg["from_aid"])
	senderDeviceID := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		senderDeviceID = v2AsString(aad["from_device"])
	}
	senderPubDER := state.session.GetPeerIK(fromAID, senderDeviceID)
	if len(senderPubDER) == 0 && fromAID != "" {
		// 兜底：bootstrap 拉取后再查
		raw, bsErr := c.Call(ctx, "message.v2.bootstrap", map[string]any{"peer_aid": fromAID})
		if bsErr == nil {
			bs, _ := raw.(map[string]any)
			for _, dev := range v2ToMapList(bs["peer_devices"]) {
				devID := v2AsString(dev["device_id"])
				if devID == "" {
					devID = v2AsString(dev["owner_device_id"])
				}
				ikDER := v2DecodeBase64Field(dev, "ik_pk")
				if len(ikDER) > 0 && devID != "" {
					state.session.CachePeerIK(fromAID, devID, ikDER)
				}
			}
			senderPubDER = state.session.GetPeerIK(fromAID, senderDeviceID)
		} else {
			c.logE2.Warn("V2 decrypt: bootstrap for sender %s failed: %v", fromAID, bsErr)
		}
	}
	if len(senderPubDER) == 0 && fromAID != "" {
		certBytes, certErr := c.fetchPeerCert(ctx, fromAID, "")
		if certErr == nil && len(certBytes) > 0 {
			if block, _ := pem.Decode(certBytes); block != nil {
				if cert, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
					if der, marshalErr := x509.MarshalPKIXPublicKey(cert.PublicKey); marshalErr == nil {
						senderPubDER = der
						if senderDeviceID != "" {
							state.session.CachePeerIK(fromAID, senderDeviceID, der)
						}
						c.logE2.Debug("V2 decrypt: sender IK fallback from CA cert for %s", fromAID)
					}
				}
			}
		} else if certErr != nil {
			c.logE2.Warn("V2 decrypt: CA fallback for %s failed: %v", fromAID, certErr)
		}
	}
	if len(senderPubDER) == 0 {
		c.logE2.Warn("V2 decrypt: no sender IK for %s, cannot verify signature", fromAID)
		c.events.Publish("message.undecryptable", map[string]any{
			"message_id":     v2AsString(msg["message_id"]),
			"from":           fromAID,
			"seq":            msg["seq"],
			"_decrypt_error": "sender_ik_not_found",
		})
		return nil
	}

	c.mu.RLock()
	selfAID := c.aid
	selfDeviceID := c.deviceID
	c.mu.RUnlock()

	plaintext, err := e2ee.DecryptMessage(envelope, selfAID, selfDeviceID, ikPriv, spkPriv, senderPubDER)
	if err != nil {
		c.logE2.Warn("V2 decrypt failed for msg seq=%v: %v", msg["seq"], err)
		c.events.Publish("message.undecryptable", map[string]any{
			"message_id":     v2AsString(msg["message_id"]),
			"from":           fromAID,
			"seq":            msg["seq"],
			"_decrypt_error": err.Error(),
		})
		return nil
	}
	if plaintext == nil {
		return nil
	}

	// SPK 轮换：当前活跃 SPK 被消费后立即轮换（后台执行，不阻塞）
	if state.session.IsCurrentSPK(spkID) {
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

	suite := v2AsString(envelope["suite"])
	encryptionMode := "v2_unknown"
	if suite != "" {
		encryptionMode = "v2_" + suite
	}
	return map[string]any{
		"message_id": v2AsString(msg["message_id"]),
		"from":       fromAID,
		"to":         selfAID,
		"seq":        msg["seq"],
		"t_server":   msg["t_server"],
		"payload":    plaintext,
		"encrypted":  true,
		"e2ee": map[string]any{
			"version":         "v2",
			"suite":           suite,
			"encryption_mode": encryptionMode,
			"forward_secrecy": true,
		},
	}
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
