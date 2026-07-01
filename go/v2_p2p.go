// v2_p2p.go — V2 P2P E2EE 状态、keystore、工具函数和 AUNClient 兼容门面。
//
// 具体编排逻辑由 client_v2_e2ee.go 中的 v2E2EECoordinator 承接。
//
// V2 keystore 单独建库 `{aun_path}/AIDs/{safe(aid)}/v2_device_keys.db`，
// 不复用主 AIDDatabase 的 schema/事务，避免污染既有 keystore 包。

package aun

import (
	"context"
	"database/sql"
	"encoding/base64"
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
	latestSeq    int64
	hasMore      bool
}

// v2BootstrapEntry 单条 peer_aid 缓存项。
type v2BootstrapEntry struct {
	Devices         []map[string]any
	AuditRecipients []map[string]any
	CachedAt        time.Time
	WrapPolicy      *v2WrapPolicy
}

type v2P2PTargetSetCacheEntry struct {
	Targets         []e2ee.Target
	AuditRecipients []e2ee.Target
	CachedAt        time.Time
}

type v2GroupTargetSetCacheEntry struct {
	Targets  []e2ee.Target
	CachedAt time.Time
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
	targetSetCache  map[string]v2P2PTargetSetCacheEntry
	// groupBootstrapCache 群 bootstrap 缓存（key = groupID）。
	// 与 P2P bootstrapCache 分开存储，因为群缓存多 epoch + stateCommitment 字段。
	groupBootstrapCache map[string]*v2GroupBootstrapEntry
	groupTargetSetCache map[string]v2GroupTargetSetCacheEntry
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
	return c.getV2E2EECoordinator().initV2Session(ctx)
}

func (c *AUNClient) releaseV2State() {
	c.mu.Lock()
	old := c.getClientRuntime().v2.clearStateLocked()
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
	result := map[string]any{
		"message_id": v2AsString(msg["message_id"]),
		"from":       v2AsString(msg["from_aid"]),
		"to":         toAID,
		"seq":        seq,
		"type":       v2LegacyMessageType(msg, payload),
		"timestamp":  toInt64(msg["t_server"]),
		"payload":    payload,
		"encrypted":  false,
	}
	attachGatewayProximity(result, msg)
	return result, true
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
	result := map[string]any{
		"message_id": v2AsString(msg["message_id"]),
		"from":       v2AsString(msg["from_aid"]),
		"group_id":   groupID,
		"seq":        seq,
		"type":       v2LegacyMessageType(msg, payload),
		"timestamp":  toInt64(msg["t_server"]),
		"payload":    payload,
		"encrypted":  false,
	}
	attachGatewayProximity(result, msg)
	return result, true
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

// AUNClient 兼容门面：V2 P2P 主体逻辑由 V2E2EECoordinator 承接。
func (c *AUNClient) scheduleV2SenderIKPending(msg map[string]any, fromAID, senderDeviceID, groupID string) {
	c.getV2E2EECoordinator().scheduleV2SenderIKPending(msg, fromAID, senderDeviceID, groupID)
}

func (c *AUNClient) sendV2(ctx context.Context, to string, payload map[string]any) (map[string]any, error) {
	return c.getV2E2EECoordinator().sendV2(ctx, to, payload)
}

func (c *AUNClient) SendV2WithOpts(ctx context.Context, to string, payload map[string]any, opts e2ee.EncryptOptions) (map[string]any, error) {
	return c.getV2E2EECoordinator().SendV2WithOpts(ctx, to, payload, opts)
}

func (c *AUNClient) pullV2(ctx context.Context, afterSeq int64, limit int) ([]map[string]any, error) {
	return c.getV2E2EECoordinator().pullV2(ctx, afterSeq, limit)
}

func (c *AUNClient) pullV2WithForce(ctx context.Context, afterSeq int64, limit int, force bool) ([]map[string]any, v2PullPageMeta, error) {
	return c.getV2E2EECoordinator().pullV2WithForce(ctx, afterSeq, limit, force)
}

func (c *AUNClient) ackV2(ctx context.Context, upToSeq int64) (map[string]any, error) {
	return c.getV2E2EECoordinator().ackV2(ctx, upToSeq)
}
