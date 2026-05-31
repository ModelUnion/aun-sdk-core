package aun

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"github.com/modelunion/aun-sdk-core/go/namespace"
	"github.com/modelunion/aun-sdk-core/go/secretstore"
)

// stableStringify 递归排序键的 JSON 序列化（Canonical JSON for AUN）
// jsonMarshalNoHTMLEscape 等价于 json.Marshal 但不转义 HTML 特殊字符 (<, >, &)
// 使签名行为与 Python ensure_ascii=False / JS JSON.stringify 一致
func jsonMarshalNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode 追加换行符，去掉
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b, nil
}

// secureRandFloat64 使用 crypto/rand 生成 [0.0, 1.0) 范围的浮点数。
// ISSUE-SDK-GO-007: 替代 math/rand.Float64()，在并发场景下无需额外加锁。
func secureRandFloat64() float64 {
	var buf [8]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		// crypto/rand 读取失败极其罕见（系统熵源不可用），使用时间戳作为降级
		return float64(time.Now().UnixNano()%1000) / 1000.0
	}
	// 取 uint64 后转为 [0, 1) 的浮点数
	n := binary.LittleEndian.Uint64(buf[:])
	return float64(n) / float64(1<<64)
}

const (
	reconnectMinBaseDelaySeconds = 1.0
	reconnectMaxBaseDelaySeconds = 64.0
	pushedSeqsLimit              = 50000
	pendingOrderedLimit          = 50000
)

type pendingOrderedMessage struct {
	event   string
	payload any
}

// pullGateState Pull Gate 状态：序列化同一 key 的 pull 操作
type pullGateState struct {
	inflight  atomic.Bool
	startedAt atomic.Int64
	token     atomic.Uint64
}

func clampReconnectDelaySeconds(value float64, fallback float64, upper float64) float64 {
	seconds := value
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		seconds = fallback
	}
	if seconds < reconnectMinBaseDelaySeconds {
		return reconnectMinBaseDelaySeconds
	}
	if seconds > upper {
		return upper
	}
	return seconds
}

func reconnectSleepDelaySeconds(baseDelay float64, maxBaseDelay float64) float64 {
	return baseDelay + secureRandFloat64()*maxBaseDelay
}

// 心跳间隔下/上限（秒）。0 = 关闭心跳；负值视为 0；其余值 clamp 到 [10, 600]。
// 服务端通过 hello.heartbeat_interval 与 meta.ping pong 中的同名字段下发。
const (
	heartbeatMinIntervalSeconds = 10.0
	heartbeatMaxIntervalSeconds = 600.0
)

func clampHeartbeatInterval(value any) float64 {
	var v float64
	switch x := value.(type) {
	case float64:
		v = x
	case float32:
		v = float64(x)
	case int:
		v = float64(x)
	case int64:
		v = float64(x)
	case int32:
		v = float64(x)
	default:
		return 0
	}
	if v != v || v <= 0 { // NaN check via self-equality
		return 0
	}
	if v < heartbeatMinIntervalSeconds {
		return heartbeatMinIntervalSeconds
	}
	if v > heartbeatMaxIntervalSeconds {
		return heartbeatMaxIntervalSeconds
	}
	return v
}

func effectiveHeartbeatIntervalSeconds(interval float64) float64 {
	return clampHeartbeatInterval(interval)
}

// 等价于 Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
// 和 TS/JS 的 stableStringify — 无空格分隔
func stableStringify(v any) string {
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case float64:
		// json.Marshal 对 float64 的标准格式
		b, _ := json.Marshal(val)
		return string(b)
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case string:
		b, _ := jsonMarshalNoHTMLEscape(val)
		return string(b)
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = stableStringify(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			keyJSON, _ := jsonMarshalNoHTMLEscape(k)
			parts[i] = string(keyJSON) + ":" + stableStringify(val[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, _ := jsonMarshalNoHTMLEscape(val)
		return string(b)
	}
}

// summarizeCallParams 产出仅限调试日志使用的参数摘要，避免泄露敏感字段（payload/token/signature 等）。
// 仅输出常见骨架字段值和其他 key 的存在性。
func summarizeCallParams(method string, params map[string]any) string {
	if len(params) == 0 {
		return "{}"
	}
	// 允许直接展示的小字段
	safeKeys := map[string]bool{
		"group_id":          true,
		"to":                true,
		"from":              true,
		"aid":               true,
		"device_id":         true,
		"slot_id":           true,
		"seq":               true,
		"after_seq":         true,
		"after_message_seq": true,
		"after_event_seq":   true,
		"event_seq":         true,
		"msg_seq":           true,
		"limit":             true,
		"epoch":             true,
		"rotation_id":       true,
		"thought_id":        true,
		"message_id":        true,
		"type":              true,
		"mode":              true,
		"encrypt":           true,
		"encrypted":         true,
		"force":             true,
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := params[k]
		if safeKeys[k] {
			switch vv := v.(type) {
			case string:
				parts = append(parts, fmt.Sprintf("%s=%s", k, vv))
			case bool, int, int64, float64:
				parts = append(parts, fmt.Sprintf("%s=%v", k, vv))
			default:
				parts = append(parts, fmt.Sprintf("%s=<%T>", k, v))
			}
		} else {
			parts = append(parts, fmt.Sprintf("%s=<set>", k))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func messagePayloadForDebug(message any) any {
	msg, ok := message.(map[string]any)
	if !ok || msg == nil {
		return message
	}
	if payload, exists := msg["payload"]; exists {
		return payload
	}
	if content, exists := msg["content"]; exists {
		return content
	}
	if raw := strings.TrimSpace(stringFromAny(msg["envelope_json"])); raw != "" {
		var parsed any
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			return parsed
		}
		return raw
	}
	if legacy, ok := msg["legacy_v1"].(map[string]any); ok {
		if payload, exists := legacy["payload"]; exists {
			return payload
		}
		if content, exists := legacy["content"]; exists {
			return content
		}
	}
	return nil
}

func messageEnvelopeFieldsForDebug(message any) map[string]any {
	msg, ok := message.(map[string]any)
	if !ok || msg == nil {
		return map[string]any{"value_type": fmt.Sprintf("%T", message)}
	}
	keys := []string{
		"message_id", "id", "from", "from_aid", "sender_aid", "to", "to_aid",
		"group_id", "seq", "msg_seq", "type", "version", "timestamp", "t_server",
		"device_id", "slot_id", "encrypted", "dispatch_mode", "dispatch",
		"thought_id", "key", "from_device", "to_device",
		"e2ee", "headers", "protected_headers", "context", "status",
		"_decrypt_error", "_decrypt_stage",
	}
	out := make(map[string]any)
	for _, key := range keys {
		if value, exists := msg[key]; exists {
			out[key] = value
		}
	}
	return out
}

func anySlice(value any) []any {
	if rows, ok := value.([]any); ok {
		return rows
	}
	return nil
}

func (c *AUNClient) logMessageDebug(stage, source, event string, message any, extra map[string]any) {
	c.logMessageDebugWithPayload(stage, source, event, message, messagePayloadForDebug(message), extra)
}

func (c *AUNClient) logMessageDebugWithPayload(stage, source, event string, message any, payload any, extra map[string]any) {
	if c == nil || c.log == nil {
		return
	}
	record := map[string]any{
		"stage":    stage,
		"source":   source,
		"event":    event,
		"envelope": messageEnvelopeFieldsForDebug(message),
		"payload":  payload,
	}
	if len(extra) > 0 {
		record["extra"] = extra
	}
	data, err := jsonMarshalNoHTMLEscape(record)
	if err != nil {
		c.log.Debug("message.debug <marshal_error: %v>", err)
		return
	}
	c.log.Debug("message.debug %s", string(data))
}

// ClientState 客户端状态
type ClientState string

const (
	StateIdle           ClientState = "idle"            // 空闲，尚未连接
	StateConnecting     ClientState = "connecting"      // 正在建立连接
	StateAuthenticating ClientState = "authenticating"  // 正在进行认证
	StateConnected      ClientState = "connected"       // 已连接并认证
	StateDisconnected   ClientState = "disconnected"    // 连接断开
	StateReconnecting   ClientState = "reconnecting"    // 正在重连
	StateTerminalFailed ClientState = "terminal_failed" // 不可恢复的失败
	StateClosed         ClientState = "closed"          // 已关闭
)

// ConnectionState 新版 9 态状态机，与 Python SDK types.py ConnectionState 对应。
// 注意：常量用 ConnState 前缀，避免与旧 ClientState 的 State* 常量冲突。
type ConnectionState string

const (
	ConnStateNoIdentity       ConnectionState = "no_identity"       // 无身份
	ConnStateStandby          ConnectionState = "standby"           // 有身份，未连接
	ConnStateAuthenticated    ConnectionState = "authenticated"     // 已认证，未建立长连接
	ConnStateConnecting       ConnectionState = "connecting"        // 正在连接
	ConnStateReady            ConnectionState = "ready"             // 已就绪，可发消息
	ConnStateRetryBackoff     ConnectionState = "retry_backoff"     // 退避等待重连
	ConnStateReconnecting     ConnectionState = "reconnecting"      // 正在重连
	ConnStateConnectionFailed ConnectionState = "connection_failed" // 不可恢复失败
	ConnStateClosed           ConnectionState = "closed"            // 已关闭
)

// ConnectOptions 连接选项（供 Authenticate 使用）
type ConnectOptions struct {
	AutoReconnect      bool           // 是否自动重连
	HeartbeatInterval  int            // 心跳间隔（秒）；0 表示不发，>0 时最小 30；opts 为 nil 时默认 30
	TokenRefreshBefore int            // token 到期前多少秒刷新，默认 1800
	Retry              *RetryConfig   // 重试配置
	Timeouts           *TimeoutConfig // 超时配置
	ConnectionKind     string         // "long"（默认）或 "short"；短连接用于 CLI 工具发 RPC 后立即断开
	ShortTtlMs         int            // 仅 kind=short 时有效，服务端兜底超时（毫秒）
	ExtraInfo          map[string]any // 应用层自定义信息（PID/HOME/备注等），踢人时透传给被踢方
	DeliveryMode       map[string]any // message.send 的连接级投递模式（fanout/queue，路由细节由后端配置）
	BackgroundSync     bool           // 连接后是否启动后台同步
}

// ConnectionOptions 控制连接行为（超时、重连退避等）。
// gateway URL 和 token 来自 Authenticate 缓存，不在此传入。
// slot_id / device_id 来自 AID，不在此传入。
type ConnectionOptions struct {
	AutoReconnect     *bool          // 是否自动重连，默认 true
	ConnectTimeout    time.Duration  // 连接超时，默认 5s
	RetryInitialDelay time.Duration  // 最小退避间隔，默认 1s
	RetryMaxDelay     time.Duration  // 最大退避间隔，默认 64s
	RetryMaxAttempts  int            // 最大重试次数，0=无限，默认 0
	HeartbeatInterval time.Duration  // 心跳间隔，默认 30s
	CallTimeout       time.Duration  // RPC 调用超时，默认 35s
	ConnectionKind    string         // "long"（默认）或 "short"
	ShortTtlMs        int            // 仅 kind=short 时有效，服务端兜底超时（毫秒）
	ExtraInfo         map[string]any // 应用层自定义信息（PID/HOME/备注等），踢人时透传给被踢方
	DeliveryMode      map[string]any // message.send 的连接级投递模式（fanout/queue，路由细节由后端配置）
	BackgroundSync    bool           // 连接后是否启动后台同步
}

// newClientForStore 是供 AIDStore 内部使用的非导出构造入口。
// AIDStore 需要一个无身份客户端来承载联网 RPC（resolve/register/fetch 等），
// 这些配置不对外暴露，只能由 AIDStore 在内部注入。
func newClientForStore(aunPath, seedPassword string, verifySSL bool, rootCaPath string, debug bool) *AUNClient {
	raw := map[string]any{
		"aun_path":   aunPath,
		"verify_ssl": verifySSL,
	}
	if seedPassword != "" {
		raw["seed_password"] = seedPassword
	}
	if rootCaPath != "" {
		raw["root_ca_path"] = rootCaPath
	}
	c := newClient(raw, debug)
	return c
}

// RetryConfig 重试配置
type RetryConfig struct {
	InitialDelay float64 // 初始延迟（秒）
	MaxDelay     float64 // 最大延迟（秒）
	MaxAttempts  int     // 最大重试次数，0=无限
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	Connect float64 // 连接超时（秒）
	Call    float64 // RPC 调用超时（秒）
}

// 内部专用方法集合，禁止用户直接调用
var internalOnlyMethods = map[string]bool{
	"auth.login1":        true,
	"auth.aid_login1":    true,
	"auth.login2":        true,
	"auth.aid_login2":    true,
	"auth.connect":       true,
	"auth.refresh_token": true,
	"initialize":         true,
}

// 需要客户端签名的关键方法
var signedMethods = map[string]bool{
	"message.send":                    true,
	"message.v2.put_peer_pk":          true,
	"message.v2.bootstrap":            true,
	"message.v2.group_bootstrap":      true,
	"message.v2.pull":                 true,
	"message.v2.ack":                  true,
	"group.send":                      true,
	"group.v2.put_group_pk":           true,
	"group.v2.bootstrap":              true,
	"group.v2.send":                   true,
	"group.v2.pull":                   true,
	"group.v2.ack":                    true,
	"group.v2.propose_state":          true,
	"group.v2.confirm_state":          true,
	"group.v2.get_proposal":           true,
	"group.kick":                      true,
	"group.add_member":                true,
	"group.leave":                     true,
	"group.remove_member":             true,
	"group.update_rules":              true,
	"group.update":                    true,
	"group.update_announcement":       true,
	"group.update_join_requirements":  true,
	"group.set_role":                  true,
	"group.transfer_owner":            true,
	"group.review_join_request":       true,
	"group.batch_review_join_request": true,
	"group.request_join":              true,
	"group.use_invite_code":           true,
	"group.thought.put":               true,
	"message.thought.put":             true,
	"group.set_settings":              true,
	"group.resources.put":             true,
	"group.resources.update":          true,
	"group.resources.delete":          true,
	"group.resources.request_add":     true,
	"group.resources.direct_add":      true,
	"group.resources.approve_request": true,
	"group.resources.reject_request":  true,
	"group.commit_state":              true,
	"group.ban":                       true,
	"group.unban":                     true,
	"group.dissolve":                  true,
	"group.suspend":                   true,
	"group.resume":                    true,
}

// 对端证书缓存 TTL（秒）
const peerCertCacheTTL = 3600

// P1-23: 非幂等方法使用更长超时（35s），避免 SDK 10s 超时 < gateway 30s 处理时间
const nonIdempotentTimeout = 35 * time.Second

var nonIdempotentMethods = map[string]bool{
	"message.send":              true,
	"group.send":                true,
	"group.create":              true,
	"group.invite":              true,
	"group.kick":                true,
	"group.remove_member":       true,
	"group.leave":               true,
	"group.dissolve":            true,
	"group.update_name":         true,
	"group.update_avatar":       true,
	"group.update_announcement": true,
	"group.update_settings":     true,
	"group.rotate_epoch":        true,
	"storage.upload":            true,
	"storage.complete_upload":   true,
	"storage.delete":            true,
	"auth.create_aid":           true,
	"auth.renew_cert":           true,
	"auth.rekey":                true,
	"message.thought.put":       true,
	"group.thought.put":         true,
	"group.add_member":          true,
}

// cachedPeerCert 缓存的对端证书条目
type cachedPeerCert struct {
	certBytes    []byte  // PEM 编码的证书
	validatedAt  float64 // PKI 验证通过的时间（Unix 秒）
	refreshAfter float64 // 缓存过期时间（Unix 秒）
}

// AUNClient AUN 协议客户端主类
type AUNClient struct {
	mu                   sync.RWMutex
	config               map[string]any
	configModel          *AUNConfig
	state                ClientState
	aid                  string
	connectedAt          time.Time
	identity             map[string]any
	gatewayURL           string
	deviceID             string
	slotID               string
	closing              atomic.Bool
	reconnecting         atomic.Bool
	serverKicked         atomic.Bool
	tokenRefreshFailures atomic.Int32

	// 重连 loop 取消函数：手动 connect 从 reconnecting/terminal_failed 恢复时用于停止旧 loop
	reconnectCancel context.CancelFunc

	// 新版 API 字段（重构）
	currentAIDObj    *AID      // 当前加载的 AID 值对象
	authenticated    bool      // 已完成短认证但未必建立长连接
	nextRetryAt      time.Time // 下次重连时间
	retryAttempt     int       // 当前重连尝试次数
	lastConnectError error     // 最近一次连接错误

	// 实例级 protected_headers，自动合并到 message.send/group.send/thought.put 调用
	instanceProtectedHeaders map[string]string

	// 缓存最近一次服务端 gateway.disconnect 信息（含 code/reason/detail），
	// 让后续 connection.state(connection_failed) 也能携带 detail（如配额超限信息）。
	lastDisconnectMu   sync.Mutex
	lastDisconnectInfo map[string]any

	// 组件
	crypto    *CryptoProvider
	tokenStore keystore.TokenStore // 仅 AIDStore 内部传完整 KeyStore
	auth      *AuthFlow
	transport *RPCTransport
	events    *EventDispatcher
	discovery *GatewayDiscovery
	dnsNet    *DnsResilientNet

	// 会话参数
	sessionParams  map[string]any
	sessionOptions map[string]any

	// 心跳唤醒：interval 通过 sessionOptions 写入；nudge channel 让心跳循环立即重读
	heartbeatNudge chan struct{}

	// 对端证书缓存
	certCache                  map[string]*cachedPeerCert
	certCacheMu                sync.RWMutex
	connectDeliveryMode        map[string]any
	defaultConnectDeliveryMode map[string]any

	// 消息序列号跟踪器（群消息 + P2P 空洞检测）
	seqTracker        *SeqTracker
	seqTrackerContext string

	// 补洞去重：已完成/进行中的 key 集合，防止重复 pull 同一区间
	gapFillDone   map[string]bool
	gapFillDoneMu sync.Mutex

	// 推送路径已分发的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发
	pushedSeqs   map[string]map[int]bool
	pushedSeqsMu sync.Mutex

	// 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq）
	pendingOrderedMsgs   map[string]map[int]pendingOrderedMessage
	pendingOrderedMsgsMu sync.Mutex

	// 群惰性同步标志：首次对群发消息/收到推送后标记，避免重复 pull
	groupSynced   map[string]bool
	groupSyncedMu sync.Mutex

	// P2P 惰性同步标志：首次发送/收到 P2P 消息后标记 — 已废弃，由 fillP2pGap 在 connect 后异步触发，字段删除

	// 后台任务上下文
	ctx    context.Context
	cancel context.CancelFunc

	// 旧 namespace 仅作为内部适配实现，不再作为 AUNClient 公开字段暴露。
	authNamespace *namespace.AuthNamespace

	// AIDs 目录：{agentMDPath}/{aid}/agentmd.json 保存元数据，{agentMDPath}/{aid}/agent.md 保存正文。
	// gateway 在 RPC envelope._meta.agent_md_etag 注入服务端 etag；纯观察，无下游依赖。
	agentMdMu            sync.RWMutex
	agentMDPath          string
	localAgentMDPath     string
	localAgentMDEtag     string
	remoteAgentMDEtag    string
	agentMDCache         map[string]*keystore.AgentMDCacheRecord
	agentMDFetchInflight map[string]bool

	// 测试可注入的 agent.md 底层操作；nil 时使用内部 authNamespace。
	agentMDOps agentMDOps

	// 日志
	logger *AUNLogger
	log    *ModuleLogger // aun_core.client
	logE2  *ModuleLogger // aun_core.e2ee
	logEG  *ModuleLogger // aun_core.e2ee-group
	logAuS *ModuleLogger // aun_core.auth (client 内使用)

	// V2 E2EE 状态（参见 v2_p2p.go）
	v2State *v2P2PState
	// V2 安全增强状态（验签缓存 + fork 检测，参见 v2_state.go）
	v2Security *v2StateSecurityState
	// V2 sender IK 缺失 pending 队列：解密路径不在 RPC 回调栈内同步 bootstrap。
	v2SenderIKMu       sync.Mutex
	v2SenderIKPending  map[string]v2SenderIKPendingEntry
	v2SenderIKFetching map[string]bool

	// V2 push 通知 → auto-pull 串行化（only-one-in-flight + drain pending）
	v2PushPullInflight atomic.Bool
	v2PushPullPending  atomic.Bool

	// V2 P2P / Group push 通知 only-one-in-flight 序列化（gap fill 拉取）
	// 与 v2PushPullInflight 区分：那个是 _raw.peer.v2.message_received 触发；
	// 这个用于一般 V2 拉取去重。
	v2PullInflight atomic.Bool
	v2PullPending  atomic.Bool

	// 同一 group 的 V2 自动提案串行化，避免建群初始化 state 与后续成员变更抢同一 state_version。
	v2AutoProposeLocksMu      sync.Mutex
	v2AutoProposeLocks        map[string]*sync.Mutex
	v2AutoProposeLastSnapshot map[string]string
	v2LazyProposeTriggered    map[string]int64

	// Pull Gate：序列化同一 key 的 pull 操作，避免重复并发 pull
	pullGates       sync.Map // key -> *pullGateState
	pullGateStaleMs int64    // 默认 30000ms

	// 对端 AID 缓存（CachePeer / GetPeer / LookupPeer / Peers）
	peerCache   map[string]*AID
	peerCacheMu sync.RWMutex
}

// NewClient 创建 AUN 客户端
func newClient(config map[string]any, debug ...bool) *AUNClient {
	rawConfig := make(map[string]any)
	for k, v := range config {
		rawConfig[k] = v
	}
	cfg := ConfigFromMap(rawConfig)
	events := NewEventDispatcher()
	crypto := &CryptoProvider{}

	fks, err := keystore.NewFileKeyStore(cfg.AUNPath, nil, cfg.SeedPassword)
	if err != nil {
		// logger 尚未初始化，临时输出到 stderr
		fmt.Fprintf(os.Stderr, "[aun_core.keystore] WARN 创建默认 FileKeyStore 失败: %v, 使用空路径\n", err)
		fks, _ = keystore.NewFileKeyStore(cfg.AUNPath, nil, "")
	}
	var ks keystore.TokenStore = fks

	// 创建 DNS 容灾网络层（需在 AuthFlow 之前，因为 AuthFlow 依赖它）
	dnsNet := NewDnsResilientNet(cfg.AUNPath, cfg.VerifySSL)

	// 创建 AuthFlow
	initAid := ""
	if v, ok := rawConfig["aid"].(string); ok {
		initAid = strings.TrimSpace(v)
	}
	authFlow := NewAuthFlow(AuthFlowConfig{
		TokenStore: ks,
		Crypto:     crypto,
		AID:        initAid,
		VerifySSL:  cfg.VerifySSL,
		RootCAPath: cfg.RootCAPath,
		DnsNet:     dnsNet,
	})

	deviceID := cfg.DeviceID()
	slotID := ""
	connectDeliveryMode := normalizeDeliveryModeConfig(map[string]any{"mode": "fanout"})
	authFlow.SetInstanceContext(deviceID, slotID)
	authFlow.SetDeliveryMode(connectDeliveryMode)

	debugFlag := false
	if len(debug) > 0 {
		debugFlag = debug[0]
	}
	aunLogger := NewAUNLogger(debugFlag, cfg.AUNPath)
	aunLogger.BindDeviceID(deviceID)
	clientLog := aunLogger.For("aun_core.client")
	clientLog.Info("AUNClient initialized: debug=%v aunPath=%s aid=%s", debugFlag, cfg.AUNPath, initAidOrDash(initAid))

	// 注入子包 logger
	keystore.SetLogger(aunLogger.For("aun_core.keystore"))
	namespace.SetLogger(aunLogger.For("aun_core.auth"))
	secretstore.SetLogger(aunLogger.For("aun_core.secret-store"))

	c := &AUNClient{
		config:                     rawConfig,
		configModel:                cfg,
		state:                      StateIdle,
		deviceID:                   deviceID,
		slotID:                     slotID,
		aid:                        initAid,
		crypto:                     crypto,
		tokenStore:                   ks,
		auth:                       authFlow,
		events:                     events,
		dnsNet:                     dnsNet,
		discovery:                  NewGatewayDiscovery(cfg.VerifySSL, dnsNet),
		certCache:                  make(map[string]*cachedPeerCert),
		peerCache:                  make(map[string]*AID),
		connectDeliveryMode:        copyMapShallow(connectDeliveryMode),
		defaultConnectDeliveryMode: copyMapShallow(connectDeliveryMode),
		seqTracker:                 NewSeqTracker(),
		gapFillDone:                make(map[string]bool),
		pushedSeqs:                 make(map[string]map[int]bool),
		pendingOrderedMsgs:         make(map[string]map[int]pendingOrderedMessage),
		groupSynced:                make(map[string]bool),
		agentMDPath:                filepath.Join(cfg.AUNPath, "AIDs"),
		agentMDCache:               make(map[string]*keystore.AgentMDCacheRecord),
		agentMDFetchInflight:       make(map[string]bool),
		v2AutoProposeLocks:         make(map[string]*sync.Mutex),
		v2AutoProposeLastSnapshot:  make(map[string]string),
		v2SenderIKPending:          make(map[string]v2SenderIKPendingEntry),
		v2SenderIKFetching:         make(map[string]bool),
		heartbeatNudge:             make(chan struct{}, 1),
		pullGateStaleMs:            30000,
		sessionOptions: map[string]any{
			"auto_reconnect":       true,
			"heartbeat_interval":   30.0,
			"token_refresh_before": 1800.0,
			"retry": map[string]any{
				"initial_delay": 1.0,
				"max_delay":     64.0,
			},
			"timeouts": map[string]any{
				"connect": 5.0,
				"call":    35.0,
				"http":    30.0,
			},
		},
		logger: aunLogger,
		log:    clientLog,
		logE2:  aunLogger.For("aun_core.e2ee"),
		logEG:  aunLogger.For("aun_core.e2ee-group"),
		logAuS: aunLogger.For("aun_core.auth"),
	}

	// 创建 RPCTransport（使用断线回调）
	c.transport = NewRPCTransport(events, 10*time.Second, func(err error, closeCode int) {
		c.handleTransportDisconnect(err, closeCode)
	}, cfg.VerifySSL, dnsNet)
	// 注册 RPC envelope._meta 观察者（吸收 gateway 注入的 agent_md_etag 等元数据）
	c.transport.SetMetaObserver(c.observeRPCMeta)

	c.authNamespace = namespace.NewAuthNamespace(c)

	// 订阅内部事件：推送消息自动解密后 re-publish
	events.Subscribe("_raw.message.received", func(payload any) {
		c.onRawMessageReceived(payload)
	})
	// 群组消息推送：自动解密后 re-publish
	events.Subscribe("_raw.group.message_created", func(payload any) {
		c.onRawGroupMessageCreated(payload)
	})
	// 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
	events.Subscribe("_raw.group.changed", func(payload any) {
		c.onRawGroupChanged(payload)
	})
	// 群组 state_committed 事件：验证 state_hash 链并更新本地存储
	events.Subscribe("_raw.group.state_committed", func(payload any) {
		c.onRawGroupStateCommitted(payload)
	})
	// 其他事件直接透传
	events.Subscribe("_raw.message.recalled", func(payload any) {
		events.Publish("message.recalled", payload)
	})
	events.Subscribe("_raw.message.ack", func(payload any) {
		events.Publish("message.ack", payload)
	})
	// P1-15: storage.object_changed 事件透传
	events.Subscribe("_raw.storage.object_changed", func(payload any) {
		events.Publish("storage.object_changed", payload)
	})
	// 服务端主动断开通知：记录日志并标记不重连
	events.Subscribe("_raw.gateway.disconnect", func(payload any) {
		c.onGatewayDisconnect(payload)
	})
	// V2 事件订阅：push 通知 + epoch 轮换
	c.registerV2EventSubscriptions()

	return c
}

// ── 属性访问 ──────────────────────────────────────────────

// AID 返回当前认证的 Agent ID
func (c *AUNClient) AID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.aid
}

// State 返回对外的 9 态连接状态。
func (c *AUNClient) State() ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return mapPublicConnectionState(c.state, c.currentAIDObj != nil, c.authenticated, c.nextRetryAt)
}

// agentMDOps 是 PublishAgentMD / FetchAgentMD 调用底层 sign/verify/upload/download 的接口。
// 默认指向内部 authNamespace；测试可替换以隔离 HTTP/签名逻辑，专门验证主 API 编排。
type agentMDOps interface {
	SignAgentMD(ctx context.Context, content string, opts *namespace.AgentMDSignOptions) (string, error)
	VerifyAgentMD(ctx context.Context, content string, opts *namespace.AgentMDVerifyOptions) (map[string]any, error)
	UploadAgentMD(ctx context.Context, content string) (map[string]any, error)
	DownloadAgentMD(ctx context.Context, aid string) (string, error)
	HeadAgentMD(ctx context.Context, aid string) (map[string]any, error)
}

// AgentMDInfo 描述 FetchAgentMD 的返回结构。
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

func (c *AUNClient) agentMDOwnerAID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return strings.TrimSpace(c.aid)
}

// setAgentMDPath 设置 agent.md 本地存储根目录；空字符串恢复默认 {aun_path}/AIDs。
func (c *AUNClient) setAgentMDPath(root string) string {
	next := strings.TrimSpace(root)
	if next == "" {
		next = filepath.Join(c.configModel.AUNPath, "AIDs")
	}
	_ = os.MkdirAll(next, 0o755)
	c.agentMdMu.Lock()
	c.agentMDPath = next
	c.agentMDCache = make(map[string]*keystore.AgentMDCacheRecord)
	c.agentMdMu.Unlock()
	return next
}

func (c *AUNClient) setAgentMdPath(root string) string { return c.setAgentMDPath(root) }

func (c *AUNClient) agentMDRoot() string {
	c.agentMdMu.RLock()
	root := strings.TrimSpace(c.agentMDPath)
	c.agentMdMu.RUnlock()
	if root == "" {
		root = filepath.Join(c.configModel.AUNPath, "AIDs")
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

func (c *AUNClient) agentMDFilePath(aid string) (string, error) {
	safe, err := agentMDSafeAID(aid)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.agentMDRoot(), safe, "agent.md"), nil
}

func (c *AUNClient) agentMDMetaPath(aid string) (string, error) {
	safe, err := agentMDSafeAID(aid)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.agentMDRoot(), safe, "agentmd.json"), nil
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

func (c *AUNClient) withAgentMDRecordLock(aid string, fn func() error) error {
	metaPath, err := c.agentMDMetaPath(aid)
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

func (c *AUNClient) writeAgentMDRecordUnlocked(aid string, rec *keystore.AgentMDCacheRecord) error {
	metaPath, err := c.agentMDMetaPath(aid)
	if err != nil {
		return err
	}
	m := agentMDRecordToMap(rec)
	delete(m, "content")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteText(metaPath, data)
}

func (c *AUNClient) readAgentMDRecordUnlocked(aid string) *keystore.AgentMDCacheRecord {
	metaPath, err := c.agentMDMetaPath(aid)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		c.log.Warn("agent.md agentmd.json damaged, ignoring: aid=%s err=%v", aid, err)
		return nil
	}
	return agentMDMapToRecord(aid, raw)
}
func (c *AUNClient) loadAgentMDRecord(aid string) *keystore.AgentMDCacheRecord {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil
	}
	var rec *keystore.AgentMDCacheRecord
	if err := c.withAgentMDRecordLock(target, func() error {
		rec = c.readAgentMDRecordUnlocked(target)
		return nil
	}); err != nil {
		c.log.Debug("agent.md cache load skipped: aid=%s err=%v", target, err)
		return nil
	}
	if rec == nil {
		return nil
	}
	if p, err := c.agentMDFilePath(target); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			rec.Content = string(data)
			rec.LocalEtag = agentMDContentEtag(rec.Content)
		} else {
			c.log.Warn("agent.md content read failed: aid=%s err=%v", target, err)
		}
	}
	c.agentMdMu.Lock()
	if c.agentMDCache == nil {
		c.agentMDCache = make(map[string]*keystore.AgentMDCacheRecord)
	}
	c.agentMDCache[target] = cloneAgentMDRecord(rec)
	c.agentMdMu.Unlock()
	return cloneAgentMDRecord(rec)
}

func (c *AUNClient) saveAgentMDRecord(aid string, fields keystore.AgentMDCacheUpsert) *keystore.AgentMDCacheRecord {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil
	}
	if fields.Content != nil {
		p, err := c.agentMDFilePath(target)
		if err != nil {
			c.log.Debug("agent.md content path invalid: aid=%s err=%v", target, err)
			return nil
		}
		if err := atomicWriteText(p, []byte(*fields.Content)); err != nil {
			c.log.Debug("agent.md content save skipped: aid=%s err=%v", target, err)
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
	if err := c.withAgentMDRecordLock(target, func() error {
		rec = c.readAgentMDRecordUnlocked(target)
		if rec == nil {
			rec = &keystore.AgentMDCacheRecord{AID: target}
		}
		applyAgentMDCacheUpsert(rec, fields)
		rec.Content = ""
		rec.UpdatedAt = time.Now().UnixMilli()
		return c.writeAgentMDRecordUnlocked(target, rec)
	}); err != nil {
		c.log.Debug("agent.md cache save skipped: aid=%s err=%v", target, err)
		return nil
	}
	loaded := cloneAgentMDRecord(rec)
	if fields.Content != nil {
		loaded.Content = *fields.Content
	}
	c.agentMdMu.Lock()
	if c.agentMDCache == nil {
		c.agentMDCache = make(map[string]*keystore.AgentMDCacheRecord)
	}
	c.agentMDCache[target] = cloneAgentMDRecord(loaded)
	owner := c.agentMDOwnerAID()
	if target == owner {
		if loaded.LocalEtag != "" {
			c.localAgentMDEtag = loaded.LocalEtag
		}
		if loaded.RemoteEtag != "" {
			c.remoteAgentMDEtag = loaded.RemoteEtag
		}
	}
	c.agentMdMu.Unlock()
	return cloneAgentMDRecord(loaded)
}

func (c *AUNClient) agentMDHasLocalContent(aid string, rec *keystore.AgentMDCacheRecord) bool {
	if rec != nil && strings.TrimSpace(rec.Content) != "" {
		return true
	}
	p, err := c.agentMDFilePath(aid)
	if err != nil {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func (c *AUNClient) scheduleAgentMDFetchIfMissing(aid string, rec *keystore.AgentMDCacheRecord, source string) {
	target := strings.TrimSpace(aid)
	if target == "" || c.agentMDHasLocalContent(target, rec) {
		return
	}
	c.agentMdMu.Lock()
	if c.agentMDFetchInflight == nil {
		c.agentMDFetchInflight = make(map[string]bool)
	}
	if c.agentMDFetchInflight[target] {
		c.agentMdMu.Unlock()
		return
	}
	c.agentMDFetchInflight[target] = true
	c.agentMdMu.Unlock()

	go func() {
		defer func() {
			c.agentMdMu.Lock()
			delete(c.agentMDFetchInflight, target)
			c.agentMdMu.Unlock()
		}()
		ctx := context.Background()
		c.mu.RLock()
		if c.ctx != nil {
			ctx = c.ctx
		}
		c.mu.RUnlock()
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := c.fetchAgentMD(fetchCtx, target); err != nil {
			c.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
				LastError:    agentMDStringPtr(err.Error()),
				RemoteStatus: agentMDStringPtr("found"),
			})
			c.log.Debug("agent.md auto fetch failed: aid=%s source=%s err=%v", target, source, err)
		}
	}()
}

func (c *AUNClient) observeAgentMDMeta(aid, etag, lastModified, source string) {
	target := strings.TrimSpace(aid)
	remoteEtag := strings.TrimSpace(etag)
	remoteLastModified := strings.TrimSpace(lastModified)
	if target == "" || (remoteEtag == "" && remoteLastModified == "") {
		return
	}
	c.agentMdMu.RLock()
	before := cloneAgentMDRecord(c.agentMDCache[target])
	c.agentMdMu.RUnlock()
	if before == nil {
		before = c.loadAgentMDRecord(target)
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
		record = c.saveAgentMDRecord(target, fields)
	}
	if target == c.agentMDOwnerAID() && remoteEtag != "" {
		c.agentMdMu.Lock()
		c.remoteAgentMDEtag = remoteEtag
		c.agentMdMu.Unlock()
	}
	c.scheduleAgentMDFetchIfMissing(target, record, source)
	if source != "" {
		c.log.Debug("agent.md meta observed: aid=%s etag=%s last_modified=%s source=%s", target, remoteEtag, remoteLastModified, source)
	}
}

func (c *AUNClient) observeAgentMDEtag(aid, etag, source string) {
	c.observeAgentMDMeta(aid, etag, "", source)
}

func (c *AUNClient) observeAgentMDFromEnvelope(envelope map[string]any) {
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
	c.observeAgentMDMeta(senderAID, v2AsString(sender["etag"]), lastModified, "envelope")
}

func (c *AUNClient) agentMDAuthCacheMeta(aid string) (string, string) {
	if c.authNamespace == nil {
		return "", ""
	}
	meta := c.authNamespace.CachedAgentMDMeta(aid)
	if meta == nil {
		return "", ""
	}
	return strings.TrimSpace(meta["etag"]), strings.TrimSpace(meta["last_modified"])
}

// PublishAgentMD 读取本地 agent.md → 签名 → 上传到服务端，并刷新内部 localAgentMDEtag。
//
// path 为空 / 文件不存在时返回 error；上传失败时透传底层错误。
// PublishAgentMD 读取 {agentMDPath}/{self_aid}/agent.md → 签名 → 上传到服务端，并刷新内部 localAgentMDEtag。
func (c *AUNClient) PublishAgentMD(ctx context.Context, _legacyPath ...string) (map[string]any, error) {
	target := c.agentMDOwnerAID()
	if target == "" {
		return nil, fmt.Errorf("PublishAgentMD requires local AID")
	}
	p, err := c.agentMDFilePath(target)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("PublishAgentMD read default agent.md: %w", err)
	}
	content := string(data)
	ops := c.resolveAgentMDOps()
	signed, err := ops.SignAgentMD(ctx, content, nil)
	if err != nil {
		return nil, err
	}
	result, err := ops.UploadAgentMD(ctx, signed)
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
	c.agentMdMu.Lock()
	c.localAgentMDPath = p
	c.localAgentMDEtag = localEtag
	if remoteEtag != "" {
		c.remoteAgentMDEtag = remoteEtag
	}
	c.agentMdMu.Unlock()
	c.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
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

// fetchAgentMD 下载 agent.md 并自动验签；aid 为空时取自身 AID；可选 savePath 写盘；
// 若 aid 是自己则同步刷新 localAgentMDEtag 与 InSync。
//
// 写盘失败不影响 fetchAgentMD 整体成功，错误信息回填到 AgentMDInfo.SaveError。
func (c *AUNClient) fetchAgentMD(ctx context.Context, aid string, _legacySavePath ...string) (*AgentMDInfo, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		c.mu.RLock()
		target = strings.TrimSpace(c.aid)
		c.mu.RUnlock()
	}
	if target == "" {
		return nil, fmt.Errorf("FetchAgentMD requires aid (or local AID)")
	}

	ops := c.resolveAgentMDOps()
	content, err := ops.DownloadAgentMD(ctx, target)
	if err != nil {
		return nil, err
	}
	sig, err := ops.VerifyAgentMD(ctx, content, &namespace.AgentMDVerifyOptions{AID: target})
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

	c.mu.RLock()
	selfAid := strings.TrimSpace(c.aid)
	c.mu.RUnlock()

	localEtag := agentMDContentEtag(content)
	remoteEtag, lastModified := c.agentMDAuthCacheMeta(target)
	if target == selfAid {
		c.agentMdMu.Lock()
		c.localAgentMDEtag = localEtag
		if remoteEtag != "" {
			c.remoteAgentMDEtag = remoteEtag
		}
		remote := c.remoteAgentMDEtag
		c.agentMdMu.Unlock()
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
	c.saveAgentMDRecord(target, fields)
	if p, err := c.agentMDFilePath(target); err == nil {
		info.SavedTo = p
	}
	// 填充 Etag / LastModified（与 Python/TS/JS 对齐）
	info.Etag = remoteEtag
	info.LastModified = lastModified
	return info, nil
}

// checkAgentMD 通过 HEAD 比较本地缓存 agent.md 与云端 agent.md ETag 是否一致。
func (c *AUNClient) checkAgentMD(ctx context.Context, aid string, maxUnsyncedDays ...float64) (*AgentMDCheckResult, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		target = c.agentMDOwnerAID()
	}
	if target == "" {
		return nil, fmt.Errorf("CheckAgentMD requires aid (or local AID)")
	}
	maxDays := 0.0
	if len(maxUnsyncedDays) > 0 {
		maxDays = maxUnsyncedDays[0]
	}
	before := c.loadAgentMDRecord(target)
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
	remote, err := c.resolveAgentMDOps().HeadAgentMD(ctx, target)
	if err != nil {
		c.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
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
	saved := c.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
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
	if target == c.agentMDOwnerAID() && remoteEtag != "" {
		c.agentMdMu.Lock()
		c.remoteAgentMDEtag = remoteEtag
		c.agentMdMu.Unlock()
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

func (c *AUNClient) checkAgentMd(ctx context.Context, aid string, maxUnsyncedDays ...float64) (*AgentMDCheckResult, error) {
	return c.checkAgentMD(ctx, aid, maxUnsyncedDays...)
}

// resolveAgentMDOps 返回测试注入的 agentMDOps 或默认内部 authNamespace。
func (c *AUNClient) resolveAgentMDOps() agentMDOps {
	if c.agentMDOps != nil {
		return c.agentMDOps
	}
	return c.authNamespace
}

// observeRPCMeta transport 的 _meta observer：吸收 gateway 注入的 agent_md_etag 等元数据。
// observer 失败 / 字段缺失时不影响业务路径。
func (c *AUNClient) observeRPCMeta(meta map[string]any) {
	if meta == nil {
		return
	}
	if etag := strings.TrimSpace(stringFromAny(meta["agent_md_etag"])); etag != "" {
		c.agentMdMu.Lock()
		c.remoteAgentMDEtag = etag
		c.agentMdMu.Unlock()
		c.observeAgentMDMeta(c.agentMDOwnerAID(), etag, "", "rpc.self")
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
		c.observeAgentMDMeta(
			strings.TrimSpace(stringFromAny(item["aid"])),
			strings.TrimSpace(stringFromAny(item["etag"])),
			lastModified,
			"rpc."+key,
		)
	}
}

// ── namespace.ClientInterface 实现 ─────────────────────────

// GetGatewayURL 返回当前 Gateway URL
func (c *AUNClient) GetGatewayURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gatewayURL
}

// SetGatewayURL 设置 Gateway URL
func (c *AUNClient) setGatewayURL(u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gatewayURL = u
}

// CacheDiscoveredGatewayURL 缓存 discovery 得到的 Gateway URL（内部使用，供 namespace 层调用）。
func (c *AUNClient) CacheDiscoveredGatewayURL(u string) {
	c.setGatewayURL(u)
}

// GetAID 返回当前 AID
func (c *AUNClient) GetAID() string {
	return c.AID()
}

// SetAID 设置当前 AID
func (c *AUNClient) SetAID(aid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.aid = aid
	if c.logger != nil {
		c.logger.BindAID(aid)
	}
}

// GetConfigDiscoveryPort 已移除 DiscoveryPort，始终返回 0（保留兼容性）
func (c *AUNClient) GetConfigDiscoveryPort() int {
	return 0
}

// GetConfigVerifySSL 返回是否验证 SSL
func (c *AUNClient) GetConfigVerifySSL() bool {
	return c.configModel.VerifySSL
}

// GetKeyStoreRootPath 返回密钥存储根目录路径
func (c *AUNClient) GetKeyStoreRootPath() string {
	return c.configModel.AUNPath
}

// GetTrustRootStore 返回支持信任根持久化的 keystore 扩展。
func (c *AUNClient) GetTrustRootStore() keystore.TrustRootStore {
	store, ok := c.tokenStore.(keystore.TrustRootStore)
	if !ok {
		return nil
	}
	return store
}

// ReloadTrustedRoots 重新加载 AuthFlow 信任根缓存。
func (c *AUNClient) ReloadTrustedRoots() int {
	if c.auth == nil {
		return 0
	}
	return c.auth.ReloadTrustedRoots()
}

// AuthRegisterAID 是兼容保留入口；AUNClient 不再注册或保存 AID 身份私钥。
// 新注册流程必须通过 AIDStore.Register，由 AIDStore 持有 KeyStore。
func (c *AUNClient) AuthRegisterAID(ctx context.Context, gatewayURL, aid string) (map[string]any, error) {
	return nil, NewStateError("AUNClient cannot register AID; use AIDStore.Register")
}

// AuthAuthenticate 通过 AuthFlow 认证 AID
func (c *AUNClient) AuthAuthenticate(ctx context.Context, gatewayURL, aid string) (map[string]any, error) {
	return c.auth.Authenticate(ctx, gatewayURL, aid)
}

// AuthLoadIdentityOrNil 通过 AuthFlow 加载身份，不存在返回 nil
func (c *AUNClient) AuthLoadIdentityOrNil(aid string) map[string]any {
	return c.auth.LoadIdentityOrNil(aid)
}

// AuthLoadCachedGatewayURL 从 keystore metadata 读取已缓存的 gateway_url。
// 与 Python SDK namespaces/auth_namespace.py:_load_cached_gateway_url 对应。
func (c *AUNClient) AuthLoadCachedGatewayURL(aid string) string {
	if c.auth == nil {
		return ""
	}
	return c.auth.LoadCachedGatewayURL(aid)
}

// AuthPersistGatewayURL 将 gateway_url 持久化到 keystore metadata。
// 与 Python SDK namespaces/auth_namespace.py:_persist_gateway_url 对应。
func (c *AUNClient) AuthPersistGatewayURL(aid, gatewayURL string) {
	if c.auth == nil {
		return
	}
	c.auth.PersistGatewayURL(aid, gatewayURL)
}

func (c *AUNClient) resolveGatewayForAID(ctx context.Context, aid string) (string, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		return "", NewStateError("gateway discovery requires a loaded AID")
	}
	if cached := strings.TrimSpace(c.AuthLoadCachedGatewayURL(target)); cached != "" {
		c.setGatewayURL(cached)
		return cached, nil
	}
	issuer := target
	if parts := strings.SplitN(target, ".", 2); len(parts) > 1 {
		issuer = parts[1]
	}
	wellKnownURL := fmt.Sprintf("https://gateway.%s/.well-known/aun-gateway", issuer)
	discovered, err := c.discovery.Discover(ctx, wellKnownURL, 0)
	if err != nil {
		return "", err
	}
	c.setGatewayURL(discovered)
	c.AuthPersistGatewayURL(target, discovered)
	return discovered, nil
}

// AuthFetchPeerCert 通过 AuthFlow 获取并验证对端证书。
func (c *AUNClient) AuthFetchPeerCert(ctx context.Context, aid, certFingerprint string) ([]byte, error) {
	return c.fetchPeerCert(ctx, aid, certFingerprint)
}

// AuthLoadKeyPair 是兼容保留入口；AUNClient 不再从持久化存储读取 AID 身份私钥。
func (c *AUNClient) AuthLoadKeyPair(aid string) (map[string]any, error) {
	return nil, NewStateError("AUNClient cannot load AID private keys; use AIDStore.Load")
}

// AuthLoadCert 加载指定 AID 的证书 PEM（供 CheckAID 使用）
func (c *AUNClient) AuthLoadCert(aid string) (string, error) {
	return c.tokenStore.LoadCert(aid)
}

// DiscoverGateway 通过 GatewayDiscovery 发现 Gateway URL
func (c *AUNClient) DiscoverGateway(ctx context.Context, wellKnownURL string, timeout time.Duration) (string, error) {
	return c.discovery.Discover(ctx, wellKnownURL, timeout)
}

// checkGatewayHealth 向 gatewayURL 的 /health 端点发送 GET 请求，检查网关可用性。
func (c *AUNClient) checkGatewayHealth(ctx context.Context, gatewayURL string, timeout time.Duration) bool {
	return c.discovery.CheckHealth(ctx, gatewayURL, timeout)
}

// GatewayHealth 返回最近一次 health check 结果，nil 表示尚未检查。
func (c *AUNClient) GatewayHealth() *bool {
	return c.discovery.LastHealthy()
}

// SetIdentity 设置当前身份信息
func (c *AUNClient) SetIdentity(identity map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.identity = identity
}

// GetIdentity 返回当前身份信息
func (c *AUNClient) GetIdentity() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.identity
}

// ── 生命周期 ──────────────────────────────────────────────

// Connect 连接到 AUN Gateway。
// 若未 authenticate，内部自动调用 Authenticate()。
// opts 为可选的连接行为配置（超时、重连退避等）；gateway URL 和 token 来自 Authenticate 缓存。
func (c *AUNClient) Connect(ctx context.Context, opts ...ConnectionOptions) error {
	c.mu.RLock()
	current := c.currentAIDObj
	authenticated := c.authenticated
	c.mu.RUnlock()
	if current == nil || !current.IsPrivateKeyValid() {
		return NewStateError("Connect requires a loaded AID with a valid private key")
	}
	if !authenticated {
		if _, err := c.Authenticate(ctx); err != nil {
			return fmt.Errorf("connect: authenticate failed: %w", err)
		}
	}
	var connOpt *ConnectionOptions
	if len(opts) > 0 {
		connOpt = &opts[0]
	}
	return c.connectWithLoadedIdentity(ctx, connectionOptionsToConnectOptions(connOpt, c))
}

// connectionOptionsToConnectOptions 将 ConnectionOptions 转换为内部 ConnectOptions。
// slot_id 优先取 opt.SlotID，其次从 AID 对象读取。
func connectionOptionsToConnectOptions(opt *ConnectionOptions, c *AUNClient) *ConnectOptions {
	if opt == nil {
		return nil
	}
	co := &ConnectOptions{}
	if opt.AutoReconnect != nil {
		co.AutoReconnect = *opt.AutoReconnect
	}
	if opt.HeartbeatInterval > 0 {
		co.HeartbeatInterval = int(opt.HeartbeatInterval.Seconds())
	}
	if opt.ConnectTimeout > 0 || opt.CallTimeout > 0 {
		co.Timeouts = &TimeoutConfig{}
		if opt.ConnectTimeout > 0 {
			co.Timeouts.Connect = opt.ConnectTimeout.Seconds()
		}
		if opt.CallTimeout > 0 {
			co.Timeouts.Call = opt.CallTimeout.Seconds()
		}
	}
	if opt.RetryInitialDelay > 0 || opt.RetryMaxDelay > 0 || opt.RetryMaxAttempts > 0 {
		co.Retry = &RetryConfig{
			InitialDelay: opt.RetryInitialDelay.Seconds(),
			MaxDelay:     opt.RetryMaxDelay.Seconds(),
			MaxAttempts:  opt.RetryMaxAttempts,
		}
	}
	co.ConnectionKind = opt.ConnectionKind
	co.ShortTtlMs = opt.ShortTtlMs
	co.ExtraInfo = opt.ExtraInfo
	co.DeliveryMode = opt.DeliveryMode
	co.BackgroundSync = opt.BackgroundSync
	// slot_id 来自 AID，不从 ConnectionOptions 传入
	if c != nil {
		c.mu.RLock()
		if aid := c.currentAIDObj; aid != nil && aid.SlotID != "" {
			// slot_id 在 connectWithParams 里直接从 c.slotID 注入，无需经过 ConnectOptions
		}
		c.mu.RUnlock()
	}
	return co
}

func (c *AUNClient) connectWithLoadedIdentity(ctx context.Context, opts *ConnectOptions) error {
	c.mu.RLock()
	current := c.currentAIDObj
	gatewayURL := c.gatewayURL
	c.mu.RUnlock()
	if current == nil || !current.IsPrivateKeyValid() {
		return NewStateError("Connect requires a loaded AID with a valid private key")
	}
	if gatewayURL == "" {
		resolved, err := c.resolveGatewayForAID(ctx, current.Aid)
		if err != nil {
			return fmt.Errorf("connect gateway discovery failed: %w", err)
		}
		gatewayURL = resolved
	}
	params := map[string]any{
		"gateway": gatewayURL,
	}
	return c.connectWithParams(ctx, params, opts, true, false)
}

// Authenticate 使用当前加载的 AID 完成两阶段认证并缓存 token，不建立长连接。
// 只允许在 standby 状态下调用。
func (c *AUNClient) Authenticate(ctx context.Context, opts ...ConnectOptions) (map[string]any, error) {
	if len(opts) > 1 {
		return nil, NewValidationError("Authenticate accepts at most one options object")
	}
	pubState := c.State()
	if pubState != ConnStateStandby {
		return nil, NewStateError(fmt.Sprintf("authenticate not allowed in state %s", pubState))
	}
	c.mu.RLock()
	current := c.currentAIDObj
	gatewayURL := c.gatewayURL
	c.mu.RUnlock()
	if current == nil || !current.IsPrivateKeyValid() {
		return nil, NewStateError("Authenticate requires a loaded AID with a valid private key")
	}
	if gatewayURL == "" {
		resolved, err := c.resolveGatewayForAID(ctx, current.Aid)
		if err != nil {
			return nil, fmt.Errorf("authenticate gateway discovery failed: %w", err)
		}
		gatewayURL = resolved
	}
	result, err := c.auth.Authenticate(ctx, gatewayURL, current.Aid)
	if err != nil {
		c.mu.Lock()
		c.lastConnectError = err
		c.authenticated = false
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	c.identity = c.auth.LoadIdentityOrNil(current.Aid)
	c.aid = current.Aid
	c.gatewayURL = gatewayURL
	c.authenticated = true
	if c.state == StateIdle {
		c.state = StateDisconnected
	}
	c.lastConnectError = nil
	c.mu.Unlock()
	return result, nil
}

func (c *AUNClient) connectWithParams(ctx context.Context, params map[string]any, opts *ConnectOptions, allowReauth bool, requireAccessToken bool) (err error) {
	tStart := time.Now()
	gatewayURL := ""
	if params != nil {
		gatewayURL, _ = params["gateway"].(string)
		if gatewayURL == "" {
			gatewayURL, _ = params["gateway_url"].(string)
		}
	}
	c.log.Debug("Connect enter: gateway=%s", gatewayURL)
	defer func() {
		if err != nil {
			c.log.Debug("Connect exit (error): gateway=%s elapsed=%dms err=%v", gatewayURL, time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Connect exit: gateway=%s elapsed=%dms", gatewayURL, time.Since(tStart).Milliseconds())
		}
	}()

	// 原子检查+状态转换，避免 TOCTOU 竞态
	// ISSUE-SDK-GO-009: 允许从 disconnected 状态重新连接
	// Fix-04: 同时放行 reconnecting(retry_backoff) 与 terminal_failed(connection_failed)，
	// 与 Python SDK connect() 守卫对齐。从 reconnecting 恢复时需先停止旧重连 loop。
	c.mu.Lock()
	switch c.state {
	case StateIdle, StateClosed, StateDisconnected, StateReconnecting, StateTerminalFailed:
		// 放行
	default:
		st := c.state
		c.mu.Unlock()
		return NewStateError(fmt.Sprintf("connect 不允许在状态 %s 下调用", st))
	}
	// 从 reconnecting 状态进入：取消正在运行的重连 loop，避免与本次手动 connect 抢占
	if c.state == StateReconnecting && c.reconnectCancel != nil {
		cancel := c.reconnectCancel
		c.reconnectCancel = nil
		c.mu.Unlock()
		cancel()
		// 等待旧 loop 让出 reconnecting 标志（loop 收到 ctx.Done 后会 Store(false)）
		for i := 0; i < 200 && c.reconnecting.Load(); i++ {
			time.Sleep(5 * time.Millisecond)
		}
		c.mu.Lock()
	}
	// 从 terminal_failed 恢复：复位重试计数与错误状态
	if c.state == StateTerminalFailed {
		c.retryAttempt = 0
		c.lastConnectError = nil
	}
	c.nextRetryAt = time.Time{}
	c.state = StateConnecting
	c.mu.Unlock()

	// 合并参数：只放传给 gateway 的字段
	merged := make(map[string]any)
	for k, v := range params {
		merged[k] = v
	}
	if opts != nil {
		if opts.ConnectionKind != "" {
			merged["connection_kind"] = opts.ConnectionKind
		}
		if opts.ShortTtlMs > 0 {
			merged["short_ttl_ms"] = opts.ShortTtlMs
		}
		if len(opts.ExtraInfo) > 0 {
			merged["extra_info"] = opts.ExtraInfo
		}
		if len(opts.DeliveryMode) > 0 {
			merged["delivery_mode"] = copyMapShallow(opts.DeliveryMode)
		}
	}

	// 规范化参数
	normalized, normErr := c.normalizeConnectParamsWithTokenPolicy(merged, requireAccessToken)
	if normErr != nil {
		c.mu.Lock()
		c.state = StateDisconnected
		c.mu.Unlock()
		err = normErr
		return err
	}

	c.mu.Lock()
	c.sessionParams = normalized
	c.sessionOptions = c.buildSessionOptions(normalized, opts)
	c.closing.Store(false)
	c.mu.Unlock()

	// 设置传输层超时
	c.mu.RLock()
	if timeouts, ok := c.sessionOptions["timeouts"].(map[string]any); ok {
		if callTimeout, ok := timeouts["call"].(float64); ok {
			c.transport.SetTimeout(time.Duration(callTimeout * float64(time.Second)))
		}
	}
	c.mu.RUnlock()

	gateways := c.resolveGateways(normalized)
	var lastErr error
	for _, gw := range gateways {
		gwParams := make(map[string]any)
		for k, v := range normalized {
			gwParams[k] = v
		}
		gwParams["gateway"] = gw
		lastErr = c.connectOnce(ctx, gwParams, allowReauth)
		if lastErr == nil {
			c.mu.Lock()
			c.authenticated = true
			c.lastConnectError = nil
			c.mu.Unlock()
			return nil
		}
		if len(gateways) > 1 {
			c.log.Warn("Connect: gateway %s failed, trying next: %v", gw, lastErr)
		}
		c.mu.Lock()
		if c.state == StateConnecting || c.state == StateAuthenticating {
			c.state = StateConnecting
		}
		c.mu.Unlock()
	}
	err = lastErr
	if err != nil {
		c.log.Error("Connect failed: err=%v", err)
		c.mu.Lock()
		c.lastConnectError = err
		if c.state == StateConnecting || c.state == StateAuthenticating {
			c.state = StateDisconnected
		}
		c.mu.Unlock()
	}
	return err
}

// listIdentities 列出本地所有具有有效私钥的身份摘要。
func (c *AUNClient) listIdentities() (summaries []map[string]any, err error) {
	tStart := time.Now()
	c.log.Debug("ListIdentities enter")
	defer func() {
		if err != nil {
			c.log.Debug("ListIdentities exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("ListIdentities exit: count=%d elapsed=%dms", len(summaries), time.Since(tStart).Milliseconds())
		}
	}()
	type lister interface {
		ListIdentities() ([]string, error)
	}
	ks, ok := c.tokenStore.(lister)
	if !ok {
		return nil, nil
	}
	aids, err := ks.ListIdentities()
	if err != nil {
		return nil, err
	}
	for _, aid := range aids {
		summary := map[string]any{"aid": aid}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

// Disconnect 主动断开连接但保留身份，可重新 Connect（ISSUE-GO-005）
func (c *AUNClient) Disconnect() (err error) {
	tStart := time.Now()
	c.log.Debug("Disconnect enter")
	defer func() {
		if err != nil {
			c.log.Debug("Disconnect exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Disconnect exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	c.mu.Lock()
	state := c.state
	if state != StateConnected && state != StateReconnecting {
		c.mu.Unlock()
		return nil // idle/closed/disconnected 等状态无需操作
	}
	cancelFn := c.cancel
	c.mu.Unlock()

	c.saveSeqTrackerState()

	// 取消后台任务
	if cancelFn != nil {
		cancelFn()
	}

	// 关闭传输层
	if err := c.transport.Close(); err != nil {
		c.log.Warn("Disconnect failed to close transport: %v", err)
	}

	c.mu.Lock()
	c.state = StateDisconnected
	c.authenticated = false
	c.mu.Unlock()

	c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState())})
	return nil
}

// Logout 完全登出：断开连接、清除 token、关闭客户端（ISSUE-GO-005）
func (c *AUNClient) Logout() (err error) {
	tStart := time.Now()
	c.log.Debug("Logout enter")
	defer func() {
		if err != nil {
			c.log.Debug("Logout exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Logout exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	// 先断开连接
	_ = c.Disconnect()

	// 清除 token
	c.mu.RLock()
	aid := c.aid
	c.mu.RUnlock()

	if aid != "" {
		if store, ok := c.tokenStore.(keystore.InstanceStateStore); ok {
			_, _ = store.UpdateInstanceState(aid, c.deviceID, c.slotID, func(current map[string]any) (map[string]any, error) {
				if current == nil {
					current = make(map[string]any)
				}
				current["access_token"] = ""
				current["refresh_token"] = ""
				current["kite_token"] = ""
				return current, nil
			})
		}
	}

	return c.Close()
}

// Close 关闭客户端，取消所有后台任务
func (c *AUNClient) Close() (err error) {
	tStart := time.Now()
	c.log.Debug("Close enter")
	defer func() {
		if err != nil {
			c.log.Debug("Close exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Close exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	c.mu.Lock()
	c.closing.Store(true)
	state := c.state
	cancelFn := c.cancel
	c.mu.Unlock()

	c.saveSeqTrackerState()

	// 取消所有后台任务
	if cancelFn != nil {
		cancelFn()
	}

	if state == StateIdle || state == StateClosed {
		if closer, ok := c.tokenStore.(interface{ Close() }); ok {
			closer.Close()
		}
		if c.dnsNet != nil {
			c.dnsNet.Close()
		}
		c.releaseV2State()
		c.mu.Lock()
		c.state = StateClosed
		c.authenticated = false
		c.resetSeqTrackingStateLocked()
		c.mu.Unlock()
		return nil
	}

	// 关闭传输层
	if err := c.transport.Close(); err != nil {
		c.log.Warn("failed to close transport: %v", err)
	}
	if closer, ok := c.tokenStore.(interface{ Close() }); ok {
		closer.Close()
	}
	if c.dnsNet != nil {
		c.dnsNet.Close()
	}
	c.releaseV2State()

	c.mu.Lock()
	c.state = StateClosed
	c.authenticated = false
	c.resetSeqTrackingStateLocked()
	c.mu.Unlock()

	c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState())})
	return nil
}

// ── RPC 调用 ──────────────────────────────────────────────

// Call 发送 RPC 调用（自动 E2EE 加解密）
func (c *AUNClient) Call(ctx context.Context, method string, params map[string]any) (result any, err error) {
	tStart := time.Now()
	c.log.Debug("Call enter: method=%s paramsSummary=%s", method, summarizeCallParams(method, params))
	defer func() {
		if err != nil {
			c.log.Debug("Call exit (error): method=%s elapsed=%dms err=%v", method, time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Call exit: method=%s elapsed=%dms", method, time.Since(tStart).Milliseconds())
		}
	}()

	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()

	if state != StateConnected {
		return nil, NewConnectionError("客户端未连接")
	}
	if internalOnlyMethods[method] {
		return nil, NewPermissionError(fmt.Sprintf("方法 %s 为内部专用", method))
	}

	if params == nil {
		params = make(map[string]any)
	} else {
		// 浅拷贝，避免修改调用方的 params
		copied := make(map[string]any, len(params))
		for k, v := range params {
			copied[k] = v
		}
		params = copied
	}

	// Fix-03: 对 message.send/group.send/message.thought.put/group.thought.put 自动合并实例级 protected_headers。
	// 调用方在 params["protected_headers"] 显式传的键优先，实例级仅补充缺失键。
	c.mergeInstanceProtectedHeaders(method, params)

	if method == "message.send" || method == "group.send" {
		c.normalizeOutboundMessagePayload(params, method)
	}
	if err := c.validateOutboundCall(method, params); err != nil {
		return nil, err
	}
	if err := c.injectMessageCursorContext(method, params); err != nil {
		return nil, err
	}

	// group.* 方法的 group_id 归一化为 canonical 格式（兼容老/污染数据）
	if strings.HasPrefix(method, "group.") {
		if rawGid, ok := params["group_id"]; ok {
			if s, ok2 := rawGid.(string); ok2 && s != "" {
				params["group_id"] = NormalizeGroupID(s, "")
			}
		}
	}

	// group.* 方法注入 device_id（服务端用于多设备消息路由）
	if strings.HasPrefix(method, "group.") {
		if _, exists := params["device_id"]; !exists {
			params["device_id"] = c.deviceID
		}
	}
	if strings.HasPrefix(method, "group.") {
		if _, exists := params["slot_id"]; !exists {
			params["slot_id"] = c.slotID
		}
	}

	c.clampAckParams(method, params)

	// 自动加密：message.send 默认加密
	if method == "message.send" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			// V2-only：必须走 V2 路径
			if c.v2GetState() != nil {
				c.log.Debug("call route: message.send → V2 send")
				return c.sendV2Internal(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot send encrypted message")
		}
		// encrypt=false：明文走通用 RPC 路径；protected_headers/headers 是信封元数据，加密与否都保留
		c.maybeAppendEchoTraceSend(params)
	}

	// 自动加密：group.send 默认加密
	if method == "group.send" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			// V2-only：必须走 V2 路径
			if c.v2GetState() != nil {
				c.logEG.Debug("call route: group.send → V2 send")
				return c.sendGroupV2Internal(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot send encrypted group message")
		}
		c.maybeAppendEchoTraceSend(params)
	}

	// V2 就绪时把 message.pull / message.ack / group.pull / group.ack_messages 路由到 V2 内部方法。
	if method == "message.pull" && c.v2GetState() != nil {
		c.log.Debug("call route: message.pull → V2 pull")
		return c.pullV2Internal(ctx, params)
	}
	if method == "message.ack" && c.v2GetState() != nil {
		c.log.Debug("call route: message.ack → V2 ack")
		return c.ackV2Internal(ctx, params)
	}
	if method == "group.pull" {
		gid, _ := params["group_id"].(string)
		if c.v2GetState() != nil && gid != "" {
			c.logEG.Debug("call route: group.pull → V2 pull group=%s", gid)
			return c.pullGroupV2Internal(ctx, params)
		}
	}
	if method == "group.ack_messages" {
		gid, _ := params["group_id"].(string)
		if c.v2GetState() != nil && gid != "" {
			if c.groupCursorTargetsCurrentInstance(params) {
				c.logEG.Debug("call route: group.ack_messages → V2 ack group=%s", gid)
				return c.ackGroupV2Internal(ctx, params)
			}
			c.logEG.Debug("call route: group.ack_messages external cursor → raw ack group=%s device_id=%s slot_id=%s", gid, stringFromAny(params["device_id"]), stringFromAny(params["slot_id"]))
		}
	}

	if method == "group.thought.put" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			gid, _ := params["group_id"].(string)
			if c.v2GetState() != nil && gid != "" {
				c.logEG.Debug("call route: group.thought.put → V2 encrypted put group=%s", gid)
				return c.putGroupThoughtEncryptedV2(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot encrypt group thought")
		}
	}
	if method == "message.thought.put" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			toAID, _ := params["to"].(string)
			if c.v2GetState() != nil && toAID != "" {
				c.log.Debug("call route: message.thought.put → V2 encrypted put to=%s", toAID)
				return c.putMessageThoughtEncryptedV2(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot encrypt message thought")
		}
	}

	// 关键操作自动附加客户端签名
	if signedMethods[method] {
		if c.shouldSkipClientSignature(method, params) {
			delete(params, "client_signature")
		} else {
			c.signClientOperation(method, params)
		}
	}

	// P1-23: 非幂等方法使用更长超时
	callCtx := ctx
	if nonIdempotentMethods[method] {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, nonIdempotentTimeout)
		defer cancel()
	}

	if method == "message.thought.get" || method == "group.thought.get" {
		c.log.Debug("thought.get transport call start: method=%s params=%s", method, summarizeCallParams(method, params))
	}

	// Pull Gate：序列化同一 key 的 pull 操作
	pullGateKey := c.pullGateKeyForCall(method, params)
	if pullGateKey != "" {
		gatedResult, gatedErr := c.runPullSerialized(callCtx, pullGateKey, func() (any, error) {
			return c.transport.Call(callCtx, method, params)
		})
		if gatedErr != nil {
			return nil, gatedErr
		}
		result = gatedResult
	} else {
		result, err = c.transport.Call(callCtx, method, params)
		if err != nil {
			return nil, err
		}
	}

	// V2-only thought.get：服务端只存 envelope，SDK 读取时按当前设备解密。
	if method == "message.thought.get" && c.v2GetState() != nil {
		if m, ok := result.(map[string]any); ok {
			c.log.Debug("message.thought.get transport result: found=%v raw_count=%d", m["found"], len(anySlice(m["thoughts"])))
		}
		fromAID := strings.TrimSpace(getStr(params, "sender_aid", ""))
		c.decryptV2ThoughtGetResult(ctx, result, fromAID, false)
	}
	if method == "group.thought.get" && c.v2GetState() != nil {
		if m, ok := result.(map[string]any); ok {
			c.log.Debug("group.thought.get transport result: found=%v raw_count=%d", m["found"], len(anySlice(m["thoughts"])))
		}
		fromAID := strings.TrimSpace(getStr(params, "sender_aid", ""))
		c.decryptV2ThoughtGetResult(ctx, result, fromAID, true)
	}

	// 自动解密：message.pull 返回的消息（V2-only：V1 解密已移除，仅做 seq 跟踪）
	if method == "message.pull" {
		if resultMap, ok := result.(map[string]any); ok {
			messages, _ := resultMap["messages"].([]any)
			c.log.Debug("message.pull returned %d messages", len(messages))
			// 更新 SeqTracker；server_ack_seq 即使空 pull 也必须生效。
			c.mu.RLock()
			myAID := c.aid
			c.mu.RUnlock()
			if myAID != "" {
				ns := "p2p:" + myAID
				contigBefore := c.seqTracker.GetContiguousSeq(ns)
				var pullMsgs []map[string]any
				for _, raw := range messages {
					if m, ok := raw.(map[string]any); ok {
						pullMsgs = append(pullMsgs, m)
					}
				}
				if len(pullMsgs) > 0 {
					pullAfterSeq := int(toInt64(params["after_seq"]))
					c.seqTracker.OnPullResult(ns, pullMsgs, pullAfterSeq)
				}
				// ⚠️ 逻辑边界 L1/L3：P2P retention floor 通道 = server_ack_seq
				// 服务端在持久化/设备视图分支返回 server_ack_seq，客户端若 contiguous 落后必须 force 跳过
				// retention window 外的空洞。与 S2 [1,seq-1] 历史 gap 配合；若去掉 force，首条消息建的 gap 会
				// 永远悬挂触发无限 pull。临时消息淘汰走 ephemeral_earliest_available_seq（仅提示），与此互斥。
				serverAck := int(toInt64(resultMap["server_ack_seq"]))
				if serverAck > 0 {
					contig := c.seqTracker.GetContiguousSeq(ns)
					if contig < serverAck {
						c.log.Info("message.pull retention-floor advanced: ns=%s contiguous=%d -> server_ack_seq=%d", ns, contig, serverAck)
						c.seqTracker.ForceContiguousSeq(ns, serverAck)
					}
				}
				c.saveSeqTrackerState()
				// auto-ack 延迟到 publish 完成后（由 fillP2pGap 负责）
				resultMap["_contig_before"] = contigBefore
			}
		}
	}

	// 自动解密：group.pull 返回的群消息（V2-only：V1 解密已移除，仅做 seq 跟踪）
	if method == "group.pull" {
		if resultMap, ok := result.(map[string]any); ok {
			messages, _ := resultMap["messages"].([]any)
			gid, _ := params["group_id"].(string)
			c.logEG.Debug("group.pull returned %d messages: group=%s", len(messages), gid)
			// 更新 SeqTracker；cursor.current_seq 即使空 pull 也必须生效。
			if gid != "" {
				ns := "group:" + gid
				contigBefore := c.seqTracker.GetContiguousSeq(ns)
				var pullMsgs []map[string]any
				for _, raw := range messages {
					if m, ok := raw.(map[string]any); ok {
						pullMsgs = append(pullMsgs, m)
					}
				}
				if len(pullMsgs) > 0 {
					pullAfterSeq := int(toInt64(params["after_seq"]))
					if pullAfterSeq == 0 {
						pullAfterSeq = int(toInt64(params["after_message_seq"]))
					}
					c.seqTracker.OnPullResult(ns, pullMsgs, pullAfterSeq)
				}
				// ⚠️ 逻辑边界 L4：group retention floor 通道 = cursor.current_seq
				// 群路径目前无独立 earliest_available_seq 字段；若未来引入 group retention，需新增字段并同步更新此处。
				// 与 S2 [1,seq-1] 历史 gap 配合使用，ForceContiguousSeq 是跳过空洞的唯一手段。
				serverAck := 0
				if cursor, ok := resultMap["cursor"].(map[string]any); ok {
					serverAck = int(toInt64(cursor["current_seq"]))
					if serverAck > 0 {
						contig := c.seqTracker.GetContiguousSeq(ns)
						if contig < serverAck {
							c.logEG.Info("group.pull retention-floor advanced: ns=%s contiguous=%d -> cursor.current_seq=%d", ns, contig, serverAck)
							c.seqTracker.ForceContiguousSeq(ns, serverAck)
						}
					}
				}
				c.saveSeqTrackerState()
				// auto-ack 延迟到 publish 完成后（由 fillGroupGap 负责）
				resultMap["_contig_before"] = contigBefore
			}
		}
	}
	// V2-only: thought 解密通过 V2 push 路径处理，RPC 结果直接透传

	// V2-only 群状态编排：建群/成员变更后同步 propose+confirm state。
	if isV2StateMembershipMethod(method) && c.v2GetState() != nil {
		groupID := extractGroupIDFromMutationResult(result, params)
		if groupID != "" {
			c.v2AutoProposeState(ctx, groupID)
		}
	}

	return result, nil
}

func isV2StateMembershipMethod(method string) bool {
	switch method {
	case "group.create", "group.add_member", "group.kick", "group.remove_member", "group.leave",
		"group.review_join_request", "group.batch_review_join_request",
		"group.use_invite_code", "group.request_join":
		return true
	default:
		return false
	}
}

func extractGroupIDFromMutationResult(result any, params map[string]any) string {
	if resultMap, ok := result.(map[string]any); ok {
		if group, ok := resultMap["group"].(map[string]any); ok {
			if gid := strings.TrimSpace(stringFromAny(group["group_id"])); gid != "" {
				return NormalizeGroupID(gid, "")
			}
		}
		if gid := strings.TrimSpace(stringFromAny(resultMap["group_id"])); gid != "" {
			return NormalizeGroupID(gid, "")
		}
		if member, ok := resultMap["member"].(map[string]any); ok {
			if gid := strings.TrimSpace(stringFromAny(member["group_id"])); gid != "" {
				return NormalizeGroupID(gid, "")
			}
		}
	}
	if params != nil {
		if gid := strings.TrimSpace(stringFromAny(params["group_id"])); gid != "" {
			return NormalizeGroupID(gid, "")
		}
	}
	return ""
}

// signClientOperation 为关键操作附加客户端 ECDSA 签名
func (c *AUNClient) signClientOperation(method string, params map[string]any) {
	c.mu.RLock()
	currentAID := c.currentAIDObj
	c.mu.RUnlock()
	if currentAID == nil || currentAID.PrivateKeyPem == "" {
		return
	}
	privPEM := currentAID.PrivateKeyPem
	aidStr := currentAID.Aid
	ts := fmt.Sprintf("%d", time.Now().Unix())

	// 计算 params hash：签名覆盖所有非 _ 前缀且非 client_signature 的业务字段
	paramsForHash := make(map[string]any)
	for k, v := range params {
		if k != "client_signature" && !strings.HasPrefix(k, "_") {
			paramsForHash[k] = v
		}
	}
	paramsJSON := stableStringify(paramsForHash)
	// stableStringify 保证递归排序键 + 无空格分隔，与 Python/TS/JS 的 Canonical JSON 一致
	paramsHash := fmt.Sprintf("%x", sha256.Sum256([]byte(paramsJSON)))
	signData := []byte(fmt.Sprintf("%s|%s|%s|%s", method, aidStr, ts, paramsHash))

	pk, err := parseECPrivateKeyPEM(privPEM)
	if err != nil {
		c.log.Warn("client signature private key parse failed: %v", err)
		return
	}
	hash := sha256.Sum256(signData)
	sig, err := ecdsa.SignASN1(cryptorand.Reader, pk, hash[:])
	if err != nil {
		c.log.Error("client signature failed: %v", err)
		return
	}

	// 证书指纹
	certFingerprint := ""
	if certPEM := currentAID.CertPem; certPEM != "" {
		block, _ := pem.Decode([]byte(certPEM))
		if block != nil {
			fp := sha256.Sum256(block.Bytes)
			certFingerprint = "sha256:" + fmt.Sprintf("%x", fp)
		}
	}

	params["client_signature"] = map[string]any{
		"aid":              aidStr,
		"cert_fingerprint": certFingerprint,
		"timestamp":        ts,
		"params_hash":      paramsHash,
		"signature":        base64.StdEncoding.EncodeToString(sig),
	}
}

func (c *AUNClient) shouldSkipClientSignature(method string, params map[string]any) bool {
	if method != "message.send" && method != "group.send" {
		return false
	}
	if params == nil || truthyBool(params["encrypted"]) || truthyBool(params["encrypt"]) {
		return false
	}
	_, _, ok := c.isEchoPayload(params["payload"])
	return ok
}

// ── 便利方法 ──────────────────────────────────────────────

// On 订阅事件
func (c *AUNClient) On(event string, handler EventHandler) *Subscription {
	return c.events.Subscribe(event, handler)
}

// Off 取消事件订阅。
// 注意：Go 中函数不可直接比较，此方法使用尽力而为的移除策略。
// 推荐使用 On() 返回的 Subscription.Unsubscribe() 替代。
func (c *AUNClient) Off(event string, handler EventHandler) {
	c.events.Unsubscribe(event, handler)
}

func (c *AUNClient) ping(ctx context.Context) (any, error) {
	return c.Call(ctx, "meta.ping", nil)
}

func (c *AUNClient) status(ctx context.Context) (any, error) {
	return c.Call(ctx, "meta.status", nil)
}

func (c *AUNClient) trustRoots(ctx context.Context) (any, error) {
	return c.Call(ctx, "meta.trust_roots", nil)
}

// ── 事件处理 ──────────────────────────────────────────────

func isInstanceScopedMessageEvent(event string) bool {
	switch event {
	case "message.received", "message.undecryptable",
		"group.message_created", "group.message_undecryptable":
		return true
	default:
		return false
	}
}

func (c *AUNClient) attachCurrentInstanceContext(payload any) any {
	message, ok := payload.(map[string]any)
	if !ok {
		return payload
	}
	result := copyMapShallow(message)
	if _, exists := result["device_id"]; !exists {
		result["device_id"] = c.deviceID
	}
	if c.slotID != "" && strings.TrimSpace(stringFromAny(result["slot_id"])) == "" {
		result["slot_id"] = c.slotID
	}
	return result
}

func (c *AUNClient) normalizePublishedMessagePayload(event string, payload any) any {
	if !isInstanceScopedMessageEvent(event) {
		return payload
	}
	return c.attachCurrentInstanceContext(payload)
}

func (c *AUNClient) publishAppEvent(event string, payload any) {
	if event == "message.received" || event == "group.message_created" {
		if msg, ok := payload.(map[string]any); ok {
			c.maybeAppendEchoTraceReceive(msg)
		}
	}
	if event == "message.received" || event == "message.undecryptable" ||
		event == "group.message_created" || event == "group.message_undecryptable" {
		c.logMessageDebug("publish", "direct", event, payload, nil)
	}
	c.injectAgentMDEtag(payload)
	c.events.Publish(event, c.normalizePublishedMessagePayload(event, payload))
}

func (c *AUNClient) publishAppEventSync(event string, payload any) {
	if event == "message.received" || event == "group.message_created" {
		if msg, ok := payload.(map[string]any); ok {
			c.maybeAppendEchoTraceReceive(msg)
		}
	}
	if event == "message.received" || event == "message.undecryptable" ||
		event == "group.message_created" || event == "group.message_undecryptable" {
		c.logMessageDebug("publish", "sync", event, payload, nil)
	}
	c.injectAgentMDEtag(payload)
	c.events.publishSync(event, c.normalizePublishedMessagePayload(event, payload))
}

// injectAgentMDEtag 在应用层事件 payload 中注入 _agent_md 字段，让应用层判断版本一致性；
// 仅当 payload 是 map 且尚未携带 _agent_md 时注入；任一 etag 非空即注入；失败不影响业务。
func (c *AUNClient) injectAgentMDEtag(payload any) {
	m, ok := payload.(map[string]any)
	if !ok || m == nil {
		return
	}
	if _, exists := m["_agent_md"]; exists {
		return
	}
	c.agentMdMu.RLock()
	localEtag := c.localAgentMDEtag
	remoteEtag := c.remoteAgentMDEtag
	c.agentMdMu.RUnlock()
	if localEtag == "" && remoteEtag == "" {
		return
	}
	m["_agent_md"] = map[string]any{
		"local_etag":  localEtag,
		"remote_etag": remoteEtag,
	}
}

func (c *AUNClient) isEchoPayload(payload any) (map[string]any, string, bool) {
	p, ok := payload.(map[string]any)
	if !ok {
		return nil, "", false
	}
	text, ok := p["text"].(string)
	if !ok || len(text) > 4096 {
		return nil, "", false
	}
	firstLine := text
	if idx := strings.IndexByte(text, '\n'); idx >= 0 {
		firstLine = text[:idx]
	}
	if !strings.Contains(strings.ToLower(firstLine), "echo") {
		return nil, "", false
	}
	return p, text, true
}

func (c *AUNClient) echoTimestamp() string {
	now := time.Now()
	return fmt.Sprintf("%02d:%02d:%02d.%03d", now.Hour(), now.Minute(), now.Second(), now.Nanosecond()/1e6)
}

func (c *AUNClient) maybeAppendEchoTraceSend(params map[string]any) {
	if enc, ok := params["encrypted"].(bool); ok && enc {
		return
	}
	p, text, ok := c.isEchoPayload(params["payload"])
	if !ok {
		return
	}
	c.mu.RLock()
	aid := c.aid
	connAt := c.connectedAt
	c.mu.RUnlock()
	uptime := int(time.Since(connAt).Seconds())
	trace := fmt.Sprintf("%s [AUN-SDK.send] aid=%s conn_uptime=%ds", c.echoTimestamp(), aid, uptime)
	newPayload := make(map[string]any, len(p))
	for k, v := range p {
		newPayload[k] = v
	}
	newPayload["text"] = text + "\n" + trace
	params["payload"] = newPayload
}

func (c *AUNClient) maybeAppendEchoTraceReceive(msg map[string]any) {
	if enc, ok := msg["encrypted"].(bool); ok && enc {
		return
	}
	p, text, ok := c.isEchoPayload(msg["payload"])
	if !ok {
		return
	}
	c.mu.RLock()
	aid := c.aid
	connAt := c.connectedAt
	c.mu.RUnlock()
	uptime := int(time.Since(connAt).Seconds())
	trace := fmt.Sprintf("%s [AUN-SDK.receive] aid=%s conn_uptime=%ds", c.echoTimestamp(), aid, uptime)
	newPayload := make(map[string]any, len(p))
	for k, v := range p {
		newPayload[k] = v
	}
	newPayload["text"] = text + "\n" + trace
	msg["payload"] = newPayload
}

func (c *AUNClient) messageTargetsCurrentInstance(message any) bool {
	msg, ok := message.(map[string]any)
	if !ok {
		return true
	}
	if _, exists := msg["device_id"]; exists {
		targetDeviceID := strings.TrimSpace(stringFromAny(msg["device_id"]))
		if targetDeviceID != c.deviceID {
			return false
		}
	}
	targetSlotID := strings.TrimSpace(stringFromAny(msg["slot_id"]))
	if targetSlotID != "" && c.slotID != "" && SlotIsolationKey(targetSlotID) != SlotIsolationKey(c.slotID) {
		return false
	}
	return true
}

func encryptedPushEnvelope(msg map[string]any) (map[string]any, bool) {
	if msg == nil {
		return nil, false
	}
	if pm, ok := msg["payload"].(map[string]any); ok && isEncryptedEnvelopePayload(pm) {
		return pm, true
	}
	raw := strings.TrimSpace(stringFromAny(msg["envelope_json"]))
	if raw == "" {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var envelope map[string]any
	if err := dec.Decode(&envelope); err != nil {
		return nil, false
	}
	if !isEncryptedEnvelopePayload(envelope) {
		return nil, false
	}
	return envelope, true
}

func isEncryptedPushMessage(msg map[string]any) bool {
	if msg == nil {
		return false
	}
	if truthyBool(msg["encrypted"]) {
		return true
	}
	_, ok := encryptedPushEnvelope(msg)
	return ok
}

func isEncryptedEnvelopePayload(payload any) bool {
	pm, ok := payload.(map[string]any)
	if !ok || pm == nil {
		return false
	}
	payloadType := strings.TrimSpace(stringFromAny(pm["type"]))
	if strings.HasPrefix(payloadType, "e2ee.") {
		return true
	}
	if strings.TrimSpace(stringFromAny(pm["ciphertext"])) == "" {
		return false
	}
	return pm["nonce"] != nil || pm["tag"] != nil || pm["recipient"] != nil ||
		pm["recipients"] != nil || pm["wrapped_key"] != nil || pm["recipients_digest"] != nil
}

func isV2EncryptedEnvelopePayload(envelope map[string]any) bool {
	if envelope == nil {
		return false
	}
	payloadType := strings.TrimSpace(stringFromAny(envelope["type"]))
	if payloadType == "e2ee.p2p_encrypted" || payloadType == "e2ee.group_encrypted" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(stringFromAny(envelope["version"])), "v2") &&
		strings.HasPrefix(payloadType, "e2ee.")
}

func safeUndecryptablePushEvent(msg map[string]any, group bool) map[string]any {
	event := map[string]any{
		"message_id":     msg["message_id"],
		"from":           msg["from"],
		"seq":            msg["seq"],
		"timestamp":      msg["timestamp"],
		"device_id":      msg["device_id"],
		"slot_id":        msg["slot_id"],
		"_decrypt_error": "encrypted push payload is not decryptable on raw push path",
		"_decrypt_stage": "push_envelope",
	}
	if event["timestamp"] == nil {
		event["timestamp"] = msg["t_server"]
	}
	if group {
		event["group_id"] = msg["group_id"]
	} else {
		event["to"] = msg["to"]
	}
	if envelope, ok := encryptedPushEnvelope(msg); ok {
		event["_envelope_type"] = stringFromAny(envelope["type"])
		event["_suite"] = stringFromAny(envelope["suite"])
		if isV2EncryptedEnvelopePayload(envelope) {
			attachV2EnvelopeMetadata(event, v2MessageE2EEMetadata(envelope))
		}
	}
	return event
}

func (c *AUNClient) publishEncryptedPushAsUndecryptable(eventName, ns string, seq int, msg map[string]any, group bool) bool {
	safeEvent := safeUndecryptablePushEvent(msg, group)
	c.logMessageDebug("decrypt-fail", "push.encrypted", eventName, safeEvent, nil)
	if ns != "" && seq > 0 {
		return c.publishOrderedMessage(eventName, ns, seq, safeEvent)
	}
	c.publishAppEvent(eventName, safeEvent)
	return true
}

func (c *AUNClient) decryptEncryptedPushPayload(msg map[string]any, group bool) map[string]any {
	envelope, ok := encryptedPushEnvelope(msg)
	if !ok || !isV2EncryptedEnvelopePayload(envelope) {
		return nil
	}
	fromAID := strings.TrimSpace(stringFromAny(msg["from_aid"]))
	if fromAID == "" {
		fromAID = strings.TrimSpace(stringFromAny(msg["from"]))
	}
	if fromAID == "" {
		fromAID = strings.TrimSpace(stringFromAny(msg["sender_aid"]))
	}
	if fromAID == "" {
		if aad, ok := envelope["aad"].(map[string]any); ok {
			fromAID = strings.TrimSpace(stringFromAny(aad["from"]))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plaintext := c.decryptV2EnvelopeForThought(ctx, envelope, fromAID)
	if plaintext == nil {
		return nil
	}
	meta := v2MessageE2EEMetadata(envelope)
	result := map[string]any{
		"message_id": stringFromAny(msg["message_id"]),
		"from":       fromAID,
		"seq":        msg["seq"],
		"timestamp":  msg["timestamp"],
		"payload":    plaintext,
		"encrypted":  true,
		"e2ee":       meta,
	}
	direction := strings.TrimSpace(stringFromAny(msg["direction"]))
	if direction == "" {
		c.mu.RLock()
		selfAID := c.aid
		c.mu.RUnlock()
		if fromAID != "" && fromAID == selfAID {
			direction = "outbound_sync"
		} else {
			direction = "inbound"
		}
	}
	result["direction"] = direction
	if msg["t_server"] != nil {
		result["t_server"] = msg["t_server"]
		result["timestamp"] = msg["t_server"]
	}
	if msg["device_id"] != nil {
		result["device_id"] = msg["device_id"]
	}
	if msg["slot_id"] != nil {
		result["slot_id"] = msg["slot_id"]
	}
	if group {
		groupID := msg["group_id"]
		if groupID == nil {
			if aad, ok := envelope["aad"].(map[string]any); ok {
				groupID = aad["group_id"]
			}
		}
		if groupID == nil {
			groupID = envelope["group_id"]
		}
		result["group_id"] = groupID
	} else {
		to := msg["to"]
		if to == nil {
			c.mu.RLock()
			to = c.aid
			c.mu.RUnlock()
		}
		result["to"] = to
	}
	attachV2EnvelopeMetadata(result, meta)
	c.logMessageDebug("decrypt-ok", "push.encrypted", map[bool]string{true: "group.message_created", false: "message.received"}[group], result, nil)
	return result
}

func (c *AUNClient) publishEncryptedPushMessage(normalEvent, undecryptableEvent, ns string, seq int, msg map[string]any, group bool) bool {
	decrypted := c.decryptEncryptedPushPayload(msg, group)
	if decrypted != nil {
		if ns != "" && seq > 0 {
			return c.publishOrderedMessage(normalEvent, ns, seq, decrypted)
		}
		c.publishAppEvent(normalEvent, decrypted)
		return true
	}
	return c.publishEncryptedPushAsUndecryptable(undecryptableEvent, ns, seq, msg, group)
}

// onRawMessageReceived 处理 transport 层推送的原始消息
func (c *AUNClient) onRawMessageReceived(data any) {
	tStart := time.Now()
	c.log.Debug("onRawMessageReceived enter")
	c.logMessageDebug("server-push", "_raw.message.received", "message.received", data, nil)
	defer func() {
		c.log.Debug("onRawMessageReceived exit: elapsed=%dms", time.Since(tStart).Milliseconds())
	}()
	go c.processAndPublishMessage(data)
}

// processAndPublishMessage 实际处理推送消息的 goroutine
func (c *AUNClient) processAndPublishMessage(data any) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("processAndPublishMessage panic: %v", r)
		}
	}()

	dataMap, ok := data.(map[string]any)
	if !ok {
		c.publishAppEvent("message.received", data)
		return
	}

	msg := copyMapShallow(dataMap)
	if !c.messageTargetsCurrentInstance(msg) {
		c.log.Debug("P2P push filtered by instance: message_id=%s seq=%d target_device=%s target_slot=%s local_device=%s local_slot=%s",
			stringFromAny(msg["message_id"]), int(toInt64(msg["seq"])), stringFromAny(msg["device_id"]), stringFromAny(msg["slot_id"]), c.deviceID, c.slotID)
		return
	}

	// P2P 空洞检测
	seq := int(toInt64(msg["seq"]))
	fromAID, _ := msg["from"].(string)
	c.log.Debug("P2P message push: from=%s seq=%d", fromAID, seq)
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	p2pNS := ""
	if seq > 0 && myAID != "" {
		p2pNS = "p2p:" + myAID
		c.seqTracker.UpdateMaxSeen(p2pNS, seq)
		needPull := c.seqTracker.OnMessageSeq(p2pNS, seq)
		if needPull {
			c.log.Debug("P2P seq gap detected, triggering gap fill: seq=%d", seq)
			go c.fillP2pGap()
		}
		// auto-ack contiguous_seq
		contig := c.seqTracker.GetContiguousSeq(p2pNS)
		if contig > 0 {
			ackSeq := c.clampAckSeq("message.ack", "seq", p2pNS, int64(contig))
			c.log.Debug("P2P push auto-ack send: ns=%s seq=%d contiguous=%d", p2pNS, ackSeq, contig)
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "message.ack", map[string]any{
					"seq":       ackSeq,
					"device_id": c.deviceID,
					"slot_id":   c.slotID,
				}); ackErr != nil {
					c.log.Warn("P2P auto-ack failed: %v", ackErr)
				} else {
					c.log.Debug("P2P push auto-ack ok: ns=%s seq=%d", p2pNS, ackSeq)
				}
			}()
		}
		// 即时持久化 cursor，异常断连后不回退
		c.saveSeqTrackerState()
	}

	if isEncryptedPushMessage(msg) {
		c.log.Debug("encrypted P2P push attempting inline decrypt: from=%s seq=%d", fromAID, seq)
		c.publishEncryptedPushMessage("message.received", "message.undecryptable", p2pNS, seq, msg, false)
		return
	}

	// V2-only: V2 P2P 消息通过 V2 push 路径解密；明文/兼容消息在此处透传
	decrypted := msg
	if seq > 0 && myAID != "" {
		c.publishOrderedMessage("message.received", "p2p:"+myAID, seq, decrypted)
	} else {
		c.publishAppEvent("message.received", decrypted)
	}
}

// onRawGroupMessageCreated 处理群组消息推送
func (c *AUNClient) onRawGroupMessageCreated(data any) {
	tStart := time.Now()
	c.logEG.Debug("onRawGroupMessageCreated enter")
	c.logMessageDebug("server-push", "_raw.group.message_created", "group.message_created", data, nil)
	defer func() {
		c.logEG.Debug("onRawGroupMessageCreated exit: elapsed=%dms", time.Since(tStart).Milliseconds())
	}()
	go c.processAndPublishGroupMessage(data)
}

// processAndPublishGroupMessage 处理群组推送消息的 goroutine
//
// 带 payload 的事件（消息推送）：解密后 re-publish。
// 不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。
func (c *AUNClient) processAndPublishGroupMessage(data any) {
	defer func() {
		if r := recover(); r != nil {
			c.logEG.Error("processAndPublishGroupMessage panic: %v", r)
		}
	}()

	dataMap, ok := data.(map[string]any)
	if !ok {
		c.publishAppEvent("group.message_created", data)
		return
	}

	msg := copyMapShallow(dataMap)
	groupID, _ := msg["group_id"].(string)
	seq := int(toInt64(msg["seq"]))
	fromAID, _ := msg["from"].(string)
	c.logEG.Debug("group message push: group=%s from=%s seq=%d", groupID, fromAID, seq)

	if groupID != "" {
		c.groupSyncedMu.Lock()
		c.groupSynced[groupID] = true
		c.groupSyncedMu.Unlock()
	}

	// 检查是否带 payload
	payload := msg["payload"]
	hasPayload := false
	if payload != nil {
		if pm, ok := payload.(map[string]any); ok && len(pm) > 0 {
			hasPayload = true
		} else if _, ok := payload.(string); ok {
			hasPayload = true
		}
	}

	if !hasPayload {
		// 不带 payload 的通知不能先推进 seq，否则 auto-pull 会用推进后的 cursor 跳过该消息。
		if groupID != "" && seq > 0 {
			ns := "group:" + groupID
			c.seqTracker.UpdateMaxSeen(ns, seq)
			contigBefore := c.seqTracker.GetContiguousSeq(ns)
			if contigBefore == seq {
				c.logEG.Debug("group message notification: push seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
					seq, contigBefore)
				return
			}
			if contigBefore > seq {
				c.logEG.Warn("group message notification: contiguous_seq=%d 越界（> push_seq=%d），脏数据修复倒退至 %d",
					contigBefore, seq, seq-1)
				c.seqTracker.RepairContiguousSeq(ns, seq-1)
				c.saveSeqTrackerState()
			}
		}
		c.autoPullGroupMessages(msg)
		return
	}

	encryptedPush := isEncryptedPushMessage(msg)

	// V2-only: V2 群组消息通过 V2 push 路径解密；明文/兼容消息在此处透传
	decrypted := msg

	if decrypted != nil && groupID != "" && seq > 0 {
		ns := "group:" + groupID
		c.seqTracker.UpdateMaxSeen(ns, seq)
		contigBefore := c.seqTracker.GetContiguousSeq(ns)
		if contigBefore == seq {
			c.logEG.Debug("group message payload push: seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
				seq, contigBefore)
			return
		}
		needPull := c.seqTracker.OnMessageSeq(ns, seq)
		if needPull {
			c.logEG.Debug("group message seq gap detected, triggering gap fill: group=%s seq=%d", groupID, seq)
			go c.fillGroupGap(groupID)
		}
		contig := c.seqTracker.GetContiguousSeq(ns)
		if contig > 0 {
			ackSeq := c.clampAckSeq("group.ack_messages", "msg_seq", ns, int64(contig))
			c.logEG.Debug("group push auto-ack send: group=%s ns=%s seq=%d contiguous=%d", groupID, ns, ackSeq, contig)
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
					"group_id":  groupID,
					"msg_seq":   ackSeq,
					"device_id": c.deviceID,
					"slot_id":   c.slotID,
				}); ackErr != nil {
					c.logEG.Warn("group message auto-ack failed: group=%s %v", groupID, ackErr)
				} else {
					c.logEG.Debug("group push auto-ack ok: group=%s ns=%s seq=%d", groupID, ns, ackSeq)
				}
			}()
		}
		c.saveSeqTrackerState()
	}

	if encryptedPush {
		c.logEG.Debug("encrypted group push attempting inline decrypt: group=%s seq=%d", groupID, seq)
		ns := ""
		if groupID != "" && seq > 0 {
			ns = "group:" + groupID
		}
		c.publishEncryptedPushMessage("group.message_created", "group.message_undecryptable", ns, seq, msg, true)
		return
	}

	// V2-only: 不再有 pending decrypt 队列，decrypted 始终非 nil
	if groupID != "" && seq > 0 {
		c.publishOrderedMessage("group.message_created", "group:"+groupID, seq, decrypted)
	} else {
		c.publishAppEvent("group.message_created", decrypted)
	}
}

// autoPullGroupMessages 收到不带 payload 的通知后自动 pull 最新消息
func (c *AUNClient) autoPullGroupMessages(notification map[string]any) {
	groupID, _ := notification["group_id"].(string)
	if groupID == "" {
		c.publishAppEvent("group.message_created", notification)
		return
	}
	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// V2-only 模式：走 group.v2.pull（合并 V1 明文 + V2 密文并自动解密）
	v2State := c.v2GetState()
	if v2State != nil && v2State.session != nil {
		_, err := c.pullGroupV2Internal(ctx, map[string]any{
			"group_id":  groupID,
			"after_seq": afterSeq,
			"limit":     50,
		})
		if err != nil {
			c.logEG.Warn("auto pull group messages (v2) failed: %v", err)
			c.publishAppEvent("group.message_created", notification)
		}
		return
	}

	result, err := c.Call(ctx, "group.pull", map[string]any{
		"group_id":  groupID,
		"after_seq": afterSeq,
		"limit":     50,
	})
	if err != nil {
		c.logEG.Warn("auto pull group messages failed: %v", err)
		c.publishAppEvent("group.message_created", notification)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		c.publishAppEvent("group.message_created", notification)
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok || len(messages) == 0 {
		c.publishAppEvent("group.message_created", notification)
		return
	}
	// 更新 SeqTracker
	var pullMsgs []map[string]any
	for _, raw := range messages {
		if m, ok := raw.(map[string]any); ok {
			pullMsgs = append(pullMsgs, m)
		}
	}
	c.seqTracker.OnPullResult(ns, pullMsgs, afterSeq)
	// pushedSeqs 去重：使用 publishGapFillGroupMessages 安全发布，避免锁外读取竞态
	c.publishGapFillGroupMessages(ns, messages)
}

// fillGroupGap 后台补齐群消息空洞
func (c *AUNClient) fillGroupGap(groupID string) {
	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	c.logEG.Debug("fillGroupGap triggered: group=%s afterSeq=%d", groupID, afterSeq)
	// per-namespace 去重：同一 group namespace 只允许 1 个 in-flight pull
	dedupKey := "group_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	// S1: 使用 defer 在所有出口（成功/异常/空返）清理 dedup 键，避免"成功但返回 0 条"永久污染。
	defer func() {
		c.gapFillDoneMu.Lock()
		delete(c.gapFillDone, dedupKey)
		c.gapFillDoneMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "group.pull", map[string]any{
		"group_id":  groupID,
		"after_seq": afterSeq,
		"limit":     50,
	})
	if err != nil {
		c.logEG.Warn("background gap fill failed (fillGroupGap group=%s): %v", groupID, err)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok {
		return
	}
	// seq_tracker 更新已在 Call() 拦截器中完成；auto-ack 在 publish 后执行
	nsKey := "group:" + groupID
	contigBefore := afterSeq
	if rawBefore, ok := resultMap["_contig_before"]; ok {
		contigBefore = int(toInt64(rawBefore))
	}
	c.logEG.Debug("fillGroupGap completed: group=%s recovered %d messages", groupID, len(messages))
	c.publishGapFillGroupMessages(nsKey, messages)
	// publish 完成后 auto-ack
	contig := c.seqTracker.GetContiguousSeq(nsKey)
	if contig > 0 && contig != contigBefore {
		ackSeq := c.clampAckSeq("group.ack_messages", "msg_seq", nsKey, int64(contig))
		go func() {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ackCancel()
			if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
				"group_id":  groupID,
				"msg_seq":   ackSeq,
				"device_id": c.deviceID,
				"slot_id":   c.slotID,
			}); ackErr != nil {
				c.logEG.Warn("fillGroupGap auto-ack failed: group=%s %v", groupID, ackErr)
			}
		}()
	}
}

// lazySyncGroup 惰性同步：首次激活群时 pull 最近消息，建立 seq 基线。
func (c *AUNClient) lazySyncGroup(groupID string) {
	c.logEG.Debug("lazySyncGroup entry: group=%s", groupID)
	c.groupSyncedMu.Lock()
	c.groupSynced[groupID] = true
	c.groupSyncedMu.Unlock()

	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.transport.Call(ctx, "group.pull", map[string]any{
		"group_id":          groupID,
		"after_message_seq": afterSeq,
		"limit":             200,
	})
	if err != nil {
		c.logEG.Warn("lazy sync group %s failed: %v", groupID, err)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok {
		return
	}
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if s > 0 {
				c.seqTracker.UpdateMaxSeen(ns, s)
				c.seqTracker.OnMessageSeq(ns, s)
			}
		}
	}
	if len(messages) > 0 {
		c.saveSeqTrackerState()
		c.logEG.Warn("lazy sync group %s: pulled %d messages, after_seq=%d", groupID, len(messages), afterSeq)
	}
}

// fillGroupEventGap 后台补齐群事件空洞
func (c *AUNClient) fillGroupEventGap(groupID string) {
	ns := "group_event:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	c.logEG.Debug("fillGroupEventGap triggered: group=%s afterSeq=%d", groupID, afterSeq)
	// per-namespace 去重：同一 group_event namespace 只允许 1 个 in-flight pull
	dedupKey := "group_event_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	// S1: defer 清理 dedup 键
	defer func() {
		c.gapFillDoneMu.Lock()
		delete(c.gapFillDone, dedupKey)
		c.gapFillDoneMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nextAfterSeq := afterSeq
	const maxPages = 100
	pageCount := 0
	totalEvents := 0
	for pageCount < maxPages {
		pageCount++
		result, err := c.Call(ctx, "group.pull_events", map[string]any{
			"group_id":        groupID,
			"after_event_seq": nextAfterSeq,
			"device_id":       c.deviceID,
			"limit":           50,
		})
		if err != nil {
			c.logEG.Warn("background gap fill failed (fillGroupEventGap group=%s): %v", groupID, err)
			return
		}
		resultMap, ok := result.(map[string]any)
		if !ok {
			return
		}
		events, ok := resultMap["events"].([]any)
		if !ok {
			return
		}
		var pullEvts []map[string]any
		maxEventSeq := nextAfterSeq
		for _, raw := range events {
			if e, ok := raw.(map[string]any); ok {
				pullEvts = append(pullEvts, e)
				if es := int(toInt64(e["event_seq"])); es > maxEventSeq {
					maxEventSeq = es
				}
			}
		}
		pageContigBefore := c.seqTracker.GetContiguousSeq(ns)
		if len(pullEvts) > 0 {
			c.seqTracker.OnPullResult(ns, pullEvts, nextAfterSeq)
		}
		serverAck := 0
		if cursor, ok := resultMap["cursor"].(map[string]any); ok {
			serverAck = int(toInt64(cursor["current_seq"]))
			if serverAck > 0 {
				contigBeforeFloor := c.seqTracker.GetContiguousSeq(ns)
				if contigBeforeFloor < serverAck {
					c.logEG.Info("group.pull_events retention-floor advanced: ns=%s contiguous=%d -> cursor.current_seq=%d", ns, contigBeforeFloor, serverAck)
					c.seqTracker.ForceContiguousSeq(ns, serverAck)
				}
			}
		}
		for _, evt := range pullEvts {
			evt["_from_gap_fill"] = true
			et, _ := evt["event_type"].(string)
			// 消息事件由 fillGroupGap 负责，事件补洞不重复投递
			if et == "group.message_created" {
				continue
			}
			// 验签：有 client_signature 就验（与实时事件路径对齐）
			if cs, ok := evt["client_signature"].(map[string]any); ok {
				if c.shouldSkipEventSignature(evt) {
					delete(evt, "client_signature")
				} else {
					evt["_verified"] = c.verifyEventSignature(cs)
				}
			}
			// group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
			c.events.publishSync("group.changed", evt)
		}
		contig := c.seqTracker.GetContiguousSeq(ns)
		if contig != pageContigBefore {
			c.saveSeqTrackerState()
		}
		if len(pullEvts) > 0 && contig > 0 && contig != pageContigBefore {
			ackSeq := c.clampAckSeq("group.ack_events", "event_seq", ns, int64(contig))
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "group.ack_events", map[string]any{
					"group_id":  groupID,
					"event_seq": ackSeq,
					"device_id": c.deviceID,
					"slot_id":   c.slotID,
				}); ackErr != nil {
					c.logEG.Warn("group event auto-ack failed: group=%s %v", groupID, ackErr)
				}
			}()
		}
		totalEvents += len(events)
		hasMore, _ := resultMap["has_more"].(bool)
		if len(pullEvts) == 0 || maxEventSeq <= nextAfterSeq || !hasMore {
			break
		}
		nextAfterSeq = maxEventSeq
	}
	if pageCount >= maxPages {
		c.logEG.Warn("fillGroupEventGap reached max_pages=%d group=%s afterSeq=%d", maxPages, groupID, nextAfterSeq)
	}
	c.logEG.Debug("fillGroupEventGap completed: group=%s recovered %d events", groupID, totalEvents)
}

// fillP2pGap 后台补齐 P2P 消息空洞
func (c *AUNClient) fillP2pGap() {
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}
	ns := "p2p:" + myAID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	c.log.Debug("fillP2pGap triggered: afterSeq=%d", afterSeq)
	// per-namespace 去重：同一 namespace 只允许 1 个 in-flight pull
	dedupKey := "p2p_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	// S1: defer 清理 dedup 键
	defer func() {
		c.gapFillDoneMu.Lock()
		delete(c.gapFillDone, dedupKey)
		c.gapFillDoneMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "message.pull", map[string]any{
		"after_seq": afterSeq,
		"limit":     50,
	})
	if err != nil {
		c.log.Warn("background gap fill failed (fillP2pGap): %v", err)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok {
		return
	}
	// seq_tracker 更新已在 Call() 拦截器中完成；auto-ack 在 publish 后执行
	nsKey := "p2p:" + myAID
	contigBefore := afterSeq
	if rawBefore, ok := resultMap["_contig_before"]; ok {
		contigBefore = int(toInt64(rawBefore))
	}
	c.log.Debug("fillP2pGap completed: recovered %d messages", len(messages))
	c.publishGapFillMessages(nsKey, messages)
	// publish 完成后 auto-ack
	contig := c.seqTracker.GetContiguousSeq(nsKey)
	if contig > 0 && contig != contigBefore {
		ackSeq := c.clampAckSeq("message.ack", "seq", nsKey, int64(contig))
		go func() {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ackCancel()
			if _, ackErr := c.transport.Call(ackCtx, "message.ack", map[string]any{
				"seq":       ackSeq,
				"device_id": c.deviceID,
				"slot_id":   c.slotID,
			}); ackErr != nil {
				c.log.Warn("fillP2pGap auto-ack failed: %v", ackErr)
			}
		}()
	}
}

// prunePushedSeqs 只按硬上限裁剪 published guard。
// 不能按 contiguousSeq 清理：pull/补洞可能在 cursor 推进后再次拿到旧消息，
// 去重状态必须保留，否则会重复 publish。
func (c *AUNClient) prunePushedSeqs(ns string) {
	c.pushedSeqsMu.Lock()
	defer c.pushedSeqsMu.Unlock()
	pushed := c.pushedSeqs[ns]
	if pushed == nil {
		return
	}
	if len(pushed) > pushedSeqsLimit {
		seqs := make([]int, 0, len(pushed))
		for s := range pushed {
			seqs = append(seqs, s)
		}
		sort.Ints(seqs)
		keepStart := len(seqs) - pushedSeqsLimit
		next := make(map[int]bool, pushedSeqsLimit)
		for _, s := range seqs[keepStart:] {
			next[s] = true
		}
		c.pushedSeqs[ns] = next
	}
}

// markPushedSeq 在锁内安全标记指定 ns 的 seq 已发布到应用层。
func (c *AUNClient) markPushedSeq(ns string, seq int) {
	if seq <= 0 || ns == "" {
		return
	}
	c.pushedSeqsMu.Lock()
	if c.pushedSeqs[ns] == nil {
		c.pushedSeqs[ns] = make(map[int]bool)
	}
	c.pushedSeqs[ns][seq] = true
	if len(c.pushedSeqs[ns]) > pushedSeqsLimit {
		seqs := make([]int, 0, len(c.pushedSeqs[ns]))
		for s := range c.pushedSeqs[ns] {
			seqs = append(seqs, s)
		}
		sort.Ints(seqs)
		keepStart := len(seqs) - pushedSeqsLimit
		next := make(map[int]bool, pushedSeqsLimit)
		for _, s := range seqs[keepStart:] {
			next[s] = true
		}
		c.pushedSeqs[ns] = next
	}
	c.pushedSeqsMu.Unlock()
}

// isPushedSeq 在锁内安全查询指定 ns 的 seq 是否已通过推送路径分发。
// 不取出内层 map 引用，避免锁外读写竞态。
func (c *AUNClient) isPushedSeq(ns string, seq int) bool {
	if seq <= 0 || ns == "" {
		return false
	}
	c.pushedSeqsMu.Lock()
	defer c.pushedSeqsMu.Unlock()
	pushed := c.pushedSeqs[ns]
	if pushed == nil {
		return false
	}
	return pushed[seq]
}

// clampAckSeq 在所有 ack 出口前做本地边界保护。
//
// 上界来自 push/pull 维护的 maxSeenSeq；这样本地脏 contiguousSeq 不会被回传给服务端。
// 下界固定为 0，避免负数/恶意值进入 RPC 参数。
func (c *AUNClient) clampAckSeq(method, field, ns string, seq int64) int64 {
	original := seq
	if seq < 0 {
		seq = 0
	}
	if ns != "" {
		maxSeen := c.seqTracker.GetMaxSeenSeq(ns)
		if maxSeen > 0 && seq > int64(maxSeen) {
			if strings.HasPrefix(method, "group.") {
				c.logEG.Warn("ack clamp: method=%s %s=%d > max_seen=%d, clamp", method, field, original, maxSeen)
			} else {
				c.log.Warn("ack clamp: method=%s %s=%d > max_seen=%d, clamp", method, field, original, maxSeen)
			}
			seq = int64(maxSeen)
		}
	}
	return seq
}

func (c *AUNClient) clampAckParams(method string, params map[string]any) {
	if params == nil {
		return
	}
	switch method {
	case "message.ack":
		c.mu.RLock()
		myAID := c.aid
		c.mu.RUnlock()
		if myAID != "" {
			params["seq"] = c.clampAckSeq(method, "seq", "p2p:"+myAID, toInt64(params["seq"]))
		}
	case "message.v2.ack":
		c.mu.RLock()
		myAID := c.aid
		c.mu.RUnlock()
		if myAID != "" {
			params["up_to_seq"] = c.clampAckSeq(method, "up_to_seq", "p2p:"+myAID, toInt64(params["up_to_seq"]))
		}
	case "group.ack_messages":
		groupID := strings.TrimSpace(stringFromAny(params["group_id"]))
		if groupID != "" {
			params["msg_seq"] = c.clampAckSeq(method, "msg_seq", "group:"+groupID, toInt64(params["msg_seq"]))
		}
	case "group.v2.ack":
		groupID := strings.TrimSpace(stringFromAny(params["group_id"]))
		if groupID != "" {
			params["up_to_seq"] = c.clampAckSeq(method, "up_to_seq", "group:"+groupID, toInt64(params["up_to_seq"]))
		}
	case "group.ack_events":
		groupID := strings.TrimSpace(stringFromAny(params["group_id"]))
		if groupID != "" {
			params["event_seq"] = c.clampAckSeq(method, "event_seq", "group_event:"+groupID, toInt64(params["event_seq"]))
		}
	}
}

func (c *AUNClient) enqueueOrderedMessage(ns, event string, seq int, payload any) {
	if ns == "" || seq <= 0 {
		return
	}
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	if c.pendingOrderedMsgs == nil {
		c.pendingOrderedMsgs = make(map[string]map[int]pendingOrderedMessage)
	}
	queue := c.pendingOrderedMsgs[ns]
	if queue == nil {
		queue = make(map[int]pendingOrderedMessage)
		c.pendingOrderedMsgs[ns] = queue
	}
	queue[seq] = pendingOrderedMessage{event: event, payload: payload}
	if len(queue) > pendingOrderedLimit {
		seqs := make([]int, 0, len(queue))
		for s := range queue {
			seqs = append(seqs, s)
		}
		sort.Ints(seqs)
		for _, s := range seqs[:len(queue)-pendingOrderedLimit] {
			delete(queue, s)
		}
	}
}

func (c *AUNClient) popReadyOrderedMessages(ns string, beforeSeq int) []struct {
	seq  int
	item pendingOrderedMessage
} {
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	queue := c.pendingOrderedMsgs[ns]
	if len(queue) == 0 {
		return nil
	}
	contig := c.seqTracker.GetContiguousSeq(ns)
	seqs := make([]int, 0, len(queue))
	for seq := range queue {
		if seq <= contig && (beforeSeq <= 0 || seq < beforeSeq) {
			seqs = append(seqs, seq)
		}
	}
	sort.Ints(seqs)
	ready := make([]struct {
		seq  int
		item pendingOrderedMessage
	}, 0, len(seqs))
	for _, seq := range seqs {
		ready = append(ready, struct {
			seq  int
			item pendingOrderedMessage
		}{seq: seq, item: queue[seq]})
		delete(queue, seq)
	}
	if len(queue) == 0 {
		delete(c.pendingOrderedMsgs, ns)
	}
	return ready
}

func (c *AUNClient) removePendingOrderedSeq(ns string, seq int) {
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	queue := c.pendingOrderedMsgs[ns]
	if queue == nil {
		return
	}
	delete(queue, seq)
	if len(queue) == 0 {
		delete(c.pendingOrderedMsgs, ns)
	}
}

func (c *AUNClient) drainOrderedMessages(ns string, beforeSeq ...int) {
	limit := 0
	if len(beforeSeq) > 0 {
		limit = beforeSeq[0]
	}
	for _, ready := range c.popReadyOrderedMessages(ns, limit) {
		if c.isPushedSeq(ns, ready.seq) {
			c.log.Debug("publish ordered drain skipped duplicate: ns=%s seq=%d event=%s", ns, ready.seq, ready.item.event)
			continue
		}
		c.publishAppEventSync(ready.item.event, ready.item.payload)
		c.markPushedSeq(ns, ready.seq)
		c.log.Debug("publish ordered drain delivered: ns=%s seq=%d event=%s", ns, ready.seq, ready.item.event)
	}
}

func (c *AUNClient) publishOrderedMessage(event, ns string, seq int, payload any) bool {
	if ns == "" || seq <= 0 {
		c.log.Debug("publish ordered direct(no-seq): event=%s ns=%s seq=%d", event, ns, seq)
		c.publishAppEvent(event, payload)
		return true
	}
	if c.isPushedSeq(ns, seq) {
		c.log.Debug("publish ordered skipped duplicate: event=%s ns=%s seq=%d", event, ns, seq)
		c.removePendingOrderedSeq(ns, seq)
		return false
	}
	contig := c.seqTracker.GetContiguousSeq(ns)
	if seq > contig {
		c.log.Debug("publish ordered enqueue(gap): event=%s ns=%s seq=%d contiguous=%d", event, ns, seq, contig)
		c.enqueueOrderedMessage(ns, event, seq, payload)
		return false
	}
	c.drainOrderedMessages(ns, seq)
	if c.isPushedSeq(ns, seq) {
		c.log.Debug("publish ordered skipped after-drain duplicate: event=%s ns=%s seq=%d", event, ns, seq)
		return false
	}
	c.removePendingOrderedSeq(ns, seq)
	c.publishAppEventSync(event, payload)
	c.markPushedSeq(ns, seq)
	c.log.Debug("publish ordered delivered: event=%s ns=%s seq=%d", event, ns, seq)
	c.drainOrderedMessages(ns)
	return true
}

// publishPulledMessage 发布 pull 批中的消息，只做 seq 级去重，不受 contiguous gate 限制。
// pull 返回的批内部空洞可能是永久空洞，不能因此阻塞批内后续消息投递。
func (c *AUNClient) publishPulledMessage(event, ns string, seq int, payload any) bool {
	if ns == "" || seq <= 0 {
		c.log.Debug("publish pulled direct(no-seq): event=%s ns=%s seq=%d", event, ns, seq)
		c.publishAppEventSync(event, payload)
		return true
	}
	if c.isPushedSeq(ns, seq) {
		c.log.Debug("publish pulled skipped duplicate: event=%s ns=%s seq=%d", event, ns, seq)
		c.removePendingOrderedSeq(ns, seq)
		return false
	}
	c.removePendingOrderedSeq(ns, seq)
	c.publishAppEventSync(event, payload)
	c.markPushedSeq(ns, seq)
	c.log.Debug("publish pulled delivered: event=%s ns=%s seq=%d", event, ns, seq)
	return true
}

// publishGapFillMessages 补洞路径发布 P2P 消息，跳过已发布到应用层的 seq。
// 使用 isPushedSeq 逐条检查，避免取出内层 map 引用后在锁外读取的竞态。
func (c *AUNClient) publishGapFillMessages(ns string, messages []any) {
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if s > 0 {
				c.publishPulledMessage("message.received", ns, s, msg)
			} else {
				c.publishPulledMessage("message.received", ns, s, msg)
			}
		}
	}
	c.prunePushedSeqs(ns)
}

// publishGapFillGroupMessages 补洞路径发布群消息，跳过已发布到应用层的 seq。
func (c *AUNClient) publishGapFillGroupMessages(ns string, messages []any) {
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if s > 0 {
				c.publishPulledMessage("group.message_created", ns, s, msg)
			} else {
				c.publishPulledMessage("group.message_created", ns, s, msg)
			}
		}
	}
	c.prunePushedSeqs(ns)
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func truthyBool(value any) bool {
	v, ok := value.(bool)
	return ok && v
}

// onRawGroupChanged 处理群组变更事件
func (c *AUNClient) onRawGroupChanged(data any) {
	tStart := time.Now()
	c.logEG.Debug("onRawGroupChanged enter")
	defer func() {
		c.logEG.Debug("onRawGroupChanged exit: elapsed=%dms", time.Since(tStart).Milliseconds())
	}()
	dataMap, ok := data.(map[string]any)
	if !ok {
		c.events.Publish("group.changed", data)
		return
	}

	groupID, _ := dataMap["group_id"].(string)
	action, _ := dataMap["action"].(string)
	c.logEG.Debug("received group.changed event: group=%s action=%s", groupID, action)
	if cs, ok := dataMap["client_signature"].(map[string]any); ok {
		if c.shouldSkipEventSignature(dataMap) {
			delete(dataMap, "client_signature")
		} else {
			dataMap["_verified"] = c.verifyEventSignature(cs)
		}
	}

	c.events.Publish("group.changed", dataMap)

	// V2 bootstrap 缓存失效 + auto_propose 触发
	c.onRawGroupChangedV2(groupID, action, dataMap)

	// event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq
	needPull := false
	if rawES, ok := dataMap["event_seq"]; ok && groupID != "" {
		if es := toInt64(rawES); es > 0 {
			ns := "group_event:" + groupID
			c.seqTracker.UpdateMaxSeen(ns, int(es))
			needPull = c.seqTracker.OnMessageSeq(ns, int(es))
		}
	}

	// 仅在检测到 event gap 时才触发补洞（补洞回来的事件不再触发新补洞）
	if needPull && groupID != "" && dataMap["_from_gap_fill"] == nil {
		c.logEG.Debug("group.changed event_seq gap detected, triggering gap fill: group=%s", groupID)
		go c.fillGroupEventGap(groupID)
	}

	// V2-only: epoch 轮换由 V2 session 层处理，此处不再触发 V1 轮换逻辑

	// 群组解散：清理本地 V2/seq 运行态。V1 epoch key 编排已移除。
	if action == "dissolved" && groupID != "" {
		c.seqTracker.RemoveNamespace("group:" + groupID)
		c.seqTracker.RemoveNamespace("group_event:" + groupID)
		c.pushedSeqsMu.Lock()
		delete(c.pushedSeqs, "group:"+groupID)
		delete(c.pushedSeqs, "group_event:"+groupID)
		c.pushedSeqsMu.Unlock()
		c.pendingOrderedMsgsMu.Lock()
		delete(c.pendingOrderedMsgs, "group:"+groupID)
		c.pendingOrderedMsgsMu.Unlock()
		if state := c.v2GetState(); state != nil {
			state.bootstrapCacheM.Lock()
			delete(state.groupBootstrapCache, groupID)
			state.bootstrapCacheM.Unlock()
		}
		c.logEG.Info("group %s dissolved, cleaned up local V2 group runtime state and seq tracker", groupID)
	}
}

// onRawGroupStateCommitted 处理 event/group.state_committed：验证 state_hash 链并更新本地存储
func (c *AUNClient) onRawGroupStateCommitted(data any) {
	tStart := time.Now()
	c.logEG.Debug("onRawGroupStateCommitted enter")
	defer func() {
		c.logEG.Debug("onRawGroupStateCommitted exit: elapsed=%dms", time.Since(tStart).Milliseconds())
	}()
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := strings.TrimSpace(stringFromAny(dataMap["group_id"]))
	if groupID == "" {
		return
	}

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}

	// 提交者签名验证（兼容旧版：无签名时跳过）
	if cs, ok := dataMap["client_signature"].(map[string]any); ok {
		if c.shouldSkipEventSignature(dataMap) {
			delete(dataMap, "client_signature")
		} else {
			verified := c.verifyEventSignature(cs)
			if verified == false {
				c.logEG.Error("state_committed actor signature verification failed group=%s actor=%s",
					groupID, stringFromAny(dataMap["actor_aid"]))
				return
			}
		}
	}

	structured, ok := c.tokenStore.(keystore.StructuredKeyStore)
	if !ok {
		c.logEG.Warn("keystore does not support StructuredKeyStore, skipping group state committed handling group=%s", groupID)
		return
	}

	stateVersion := toInt64(dataMap["state_version"])
	stateHash := strings.TrimSpace(stringFromAny(dataMap["state_hash"]))
	prevStateHash := strings.TrimSpace(stringFromAny(dataMap["prev_state_hash"]))
	keyEpoch := toInt64(dataMap["key_epoch"])
	membershipSnapshot := strings.TrimSpace(stringFromAny(dataMap["membership_snapshot"]))
	policySnapshot := strings.TrimSpace(stringFromAny(dataMap["policy_snapshot"]))

	// 1. 验证 prev_state_hash 连续性
	localState, err := structured.LoadGroupState(myAID, groupID)
	if err != nil {
		c.logEG.Warn("failed to load group %s local state: %v", groupID, err)
	}
	if localState != nil && localState.StateHash != "" && localState.StateHash != prevStateHash {
		c.logEG.Error("state_hash chain discontinuous group=%s local_sv=%d event_sv=%d",
			groupID, localState.StateVersion, stateVersion)
		// 回源同步
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		serverResult, callErr := c.transport.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
		if callErr != nil {
			c.logEG.Warn("state fetch from source failed group=%s: %v", groupID, callErr)
			return
		}
		serverState, _ := serverResult.(map[string]any)
		if serverState == nil || serverState["state_version"] == nil {
			c.logEG.Warn("state fetch from source returned empty group=%s", groupID)
			return
		}
		sv := toInt64(serverState["state_version"])
		sHash := strings.TrimSpace(stringFromAny(serverState["state_hash"]))
		sEpoch := toInt64(serverState["key_epoch"])
		sMembersJSON := strings.TrimSpace(stringFromAny(serverState["membership_snapshot"]))
		sPolicyJSON := strings.TrimSpace(stringFromAny(serverState["policy_snapshot"]))
		sPrev := strings.TrimSpace(stringFromAny(serverState["prev_state_hash"]))

		// 回源也做 hash 验证
		if sMembersJSON != "" && sHash != "" {
			sMembers := parseMemberRolesJSON(sMembersJSON)
			sPolicy := parseJSONObject(sPolicyJSON)
			computed := ComputeStateHash(groupID, sv, sEpoch, sMembers, sPolicy, sPrev)
			if computed != sHash {
				c.logEG.Error("fetched state_hash verification failed group=%s sv=%d expected=%s got=%s",
					groupID, sv, sHash, computed)
				return
			}
		}
		saveMembershipJSON := sMembersJSON
		if saveMembershipJSON == "" {
			saveMembershipJSON = membershipSnapshot
		}
		savePolicyJSON := sPolicyJSON
		if savePolicyJSON == "" {
			savePolicyJSON = policySnapshot
		}
		if saveErr := structured.SaveGroupState(myAID, groupID, sv, sHash, sEpoch, saveMembershipJSON, savePolicyJSON); saveErr != nil {
			c.logEG.Warn("failed to save group state after fetch group=%s: %v", groupID, saveErr)
		}
		return
	}

	// 2. 本地重算验证
	members := parseMemberRolesJSON(membershipSnapshot)
	policy := parseJSONObject(policySnapshot)
	computed := ComputeStateHash(groupID, stateVersion, keyEpoch, members, policy, prevStateHash)
	if computed != stateHash {
		c.logEG.Error("state_hash recomputation mismatch group=%s sv=%d expected=%s got=%s",
			groupID, stateVersion, stateHash, computed)
		return
	}

	// 3. 更新本地存储
	if saveErr := structured.SaveGroupState(myAID, groupID, stateVersion, stateHash, keyEpoch, membershipSnapshot, policySnapshot); saveErr != nil {
		c.logEG.Warn("failed to save group state group=%s: %v", groupID, saveErr)
	}
}

// parseMemberRolesJSON 解析 membership_snapshot JSON 为 []MemberRole
func parseMemberRolesJSON(jsonStr string) []MemberRole {
	if jsonStr == "" {
		return nil
	}
	var members []MemberRole
	if err := json.Unmarshal([]byte(jsonStr), &members); err != nil {
		pkgLogEG().Warn("failed to parse membership_snapshot: %v", err)
		return nil
	}
	return members
}

// parseJSONObject 解析 JSON 字符串为 map[string]interface{}
func parseJSONObject(jsonStr string) map[string]interface{} {
	if jsonStr == "" {
		return nil
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		pkgLogEG().Warn("failed to parse policy JSON: %v", err)
		return nil
	}
	return obj
}

// verifyEventSignature 验证群事件中的 client_signature。返回 true/false/"pending"。
func (c *AUNClient) verifyEventSignature(cs map[string]any) any {
	sigAID, _ := cs["aid"].(string)
	method, _ := cs["_method"].(string)
	if sigAID == "" || method == "" {
		return "pending"
	}
	// 只用已缓存的证书，不阻塞
	expectedFP := strings.TrimSpace(strings.ToLower(getStr(cs, "cert_fingerprint", "")))
	c.certCacheMu.RLock()
	cached := c.certCache[certCacheKey(sigAID, expectedFP)]
	c.certCacheMu.RUnlock()
	if cached == nil || len(cached.certBytes) == 0 {
		// 异步触发证书获取
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c.fetchPeerCert(ctx, sigAID, expectedFP)
		}()
		return "pending"
	}
	// 解析证书
	block, _ := pem.Decode(cached.certBytes)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	// cert_fingerprint 校验
	if expectedFP != "" {
		actualFP := "sha256:" + fmt.Sprintf("%x", sha256.Sum256(block.Bytes))
		if actualFP != expectedFP {
			c.log.Error("signature verification failed: cert fingerprint mismatch aid=%s", sigAID)
			return false
		}
	}
	// 验签
	paramsHash, _ := cs["params_hash"].(string)
	timestamp, _ := cs["timestamp"].(string)
	signData := []byte(fmt.Sprintf("%s|%s|%s|%s", method, sigAID, timestamp, paramsHash))
	sigB64, _ := cs["signature"].(string)
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(signData)
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	if !ecdsa.VerifyASN1(pub, hash[:], sigBytes) {
		c.logEG.Warn("group event signature verification failed aid=%s method=%s", sigAID, method)
		// P1-16: 签名失败统一发布事件
		if c.events != nil {
			c.events.Publish("signature.verification_failed", map[string]any{
				"aid": sigAID, "method": method, "error": "ECDSA verification failed",
			})
		}
		return false
	}
	return true
}

func (c *AUNClient) shouldSkipEventSignature(event map[string]any) bool {
	if event == nil || truthyBool(event["encrypted"]) || truthyBool(event["encrypt"]) {
		return false
	}
	_, _, ok := c.isEchoPayload(event["payload"])
	return ok
}

// ── 证书与信任辅助 ────────────────────────────────────────

func certCacheKey(aid, certFingerprint string) string {
	normalized := strings.TrimSpace(strings.ToLower(certFingerprint))
	if normalized == "" {
		return aid
	}
	return aid + "#" + normalized
}

// fetchPeerCert 获取对方证书（带缓存 + 完整 PKI 验证）
func (c *AUNClient) fetchPeerCert(ctx context.Context, aid string, certFingerprint string) (certBytes []byte, err error) {
	tStart := time.Now()
	c.log.Debug("fetchPeerCert enter: aid=%s fp=%s", aid, certFingerprint)
	defer func() {
		if err != nil {
			c.log.Debug("fetchPeerCert exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("fetchPeerCert exit: aid=%s len=%d elapsed=%dms", aid, len(certBytes), time.Since(tStart).Milliseconds())
		}
	}()
	cacheKey := certCacheKey(aid, certFingerprint)
	c.certCacheMu.RLock()
	cached := c.certCache[cacheKey]
	c.certCacheMu.RUnlock()
	if cached != nil && float64(time.Now().Unix()) < cached.refreshAfter {
		return cached.certBytes, nil
	}

	c.mu.RLock()
	gatewayURL := c.gatewayURL
	c.mu.RUnlock()
	if gatewayURL == "" {
		return nil, NewValidationError("gateway url 不可用，无法获取证书")
	}

	// 跨域时用 peer 所在域的 Gateway URL
	peerGatewayURL := resolvePeerGatewayURL(gatewayURL, aid)
	cb, fetchErr := c.fetchCertHTTP(ctx, buildCertURL(peerGatewayURL, aid, certFingerprint), aid)
	if fetchErr != nil {
		if strings.TrimSpace(certFingerprint) == "" {
			err = fetchErr
			return nil, err
		}
		fallbackCert, fallbackErr := c.fetchCertHTTP(ctx, buildCertURL(peerGatewayURL, aid, ""), aid)
		if fallbackErr != nil {
			err = fetchErr
			return nil, err
		}
		cb = fallbackCert
	}
	certBytes = cb

	// H7: 严格校验指纹（DER SHA-256 或 SPKI SHA-256 任一匹配即可）
	if strings.TrimSpace(certFingerprint) != "" {
		if !matchCertFingerprint(certBytes, certFingerprint) {
			return nil, NewValidationError(fmt.Sprintf("对端证书指纹不匹配 (%s)", aid))
		}
	}

	// 完整 PKI 验证：链 + CRL + OCSP + AID 绑定
	if err := c.auth.VerifyPeerCertificate(ctx, peerGatewayURL, certBytes, aid); err != nil {
		return nil, NewValidationError(fmt.Sprintf("对端证书验证失败 (%s): %v", aid, err))
	}

	now := float64(time.Now().Unix())
	entry := &cachedPeerCert{
		certBytes:    certBytes,
		validatedAt:  now,
		refreshAfter: now + peerCertCacheTTL,
	}
	c.certCacheMu.Lock()
	c.certCache[cacheKey] = entry
	// 同时缓存不带 fingerprint 的 key，确保无论有无 fingerprint 都能命中
	bareKey := certCacheKey(aid, "")
	if bareKey != cacheKey {
		c.certCache[bareKey] = entry
	}
	// 如果请求时没带 fingerprint，计算实际 fingerprint 也缓存一份
	if strings.TrimSpace(certFingerprint) == "" {
		if actualFP, fpErr := certSHA256Fingerprint(certBytes); fpErr == nil && actualFP != "" {
			fpKey := certCacheKey(aid, "sha256:"+actualFP)
			c.certCache[fpKey] = entry
		}
	}
	c.certCacheMu.Unlock()

	if versioned, ok := c.tokenStore.(keystore.VersionedCertKeyStore); ok {
		// peer 证书只存版本目录，不覆盖 cert.pem
		if err := versioned.SaveCertVersion(aid, string(certBytes), certFingerprint, false); err != nil {
			c.log.Warn("failed to write versioned cert (aid=%s): %v", aid, err)
		}
	} else if strings.TrimSpace(certFingerprint) == "" {
		if err := c.tokenStore.SaveCert(aid, string(certBytes)); err != nil {
			c.log.Warn("failed to write cert to keystore (aid=%s): %v", aid, err)
		}
	}

	return certBytes, nil
}

// ensureSenderCertCached 确保发送方证书在本地 keystore 中可用
func (c *AUNClient) ensureSenderCertCached(ctx context.Context, aid string, certFingerprint ...string) bool {
	requestedFingerprint := ""
	if len(certFingerprint) > 0 {
		requestedFingerprint = certFingerprint[0]
	}
	cacheKey := certCacheKey(aid, requestedFingerprint)
	c.certCacheMu.RLock()
	cached := c.certCache[cacheKey]
	c.certCacheMu.RUnlock()

	if cached != nil && float64(time.Now().Unix()) < cached.refreshAfter {
		return true
	}

	if versioned, ok := c.tokenStore.(keystore.VersionedCertKeyStore); ok && strings.TrimSpace(requestedFingerprint) != "" {
		if certPEM, err := versioned.LoadCertVersion(aid, requestedFingerprint); err == nil && certPEM != "" {
			now := float64(time.Now().Unix())
			c.certCacheMu.Lock()
			c.certCache[cacheKey] = &cachedPeerCert{certBytes: []byte(certPEM), validatedAt: now, refreshAfter: now + peerCertCacheTTL}
			c.certCacheMu.Unlock()
			return true
		}
	}
	if certPEM, err := c.tokenStore.LoadCert(aid); err == nil && certPEM != "" {
		if strings.TrimSpace(requestedFingerprint) == "" {
			now := float64(time.Now().Unix())
			c.certCacheMu.Lock()
			c.certCache[cacheKey] = &cachedPeerCert{certBytes: []byte(certPEM), validatedAt: now, refreshAfter: now + peerCertCacheTTL}
			c.certCacheMu.Unlock()
			return true
		}
		actualFingerprint, fpErr := certSHA256Fingerprint([]byte(certPEM))
		if fpErr == nil && actualFingerprint == strings.TrimSpace(strings.ToLower(requestedFingerprint)) {
			now := float64(time.Now().Unix())
			c.certCacheMu.Lock()
			c.certCache[cacheKey] = &cachedPeerCert{certBytes: []byte(certPEM), validatedAt: now, refreshAfter: now + peerCertCacheTTL}
			c.certCacheMu.Unlock()
			return true
		}
	}

	certBytes, err := c.fetchPeerCert(ctx, aid, requestedFingerprint)
	if err != nil {
		// 刷新失败时：若内存缓存有 PKI 验证过的证书则继续用
		if cached != nil && float64(time.Now().Unix()) < cached.validatedAt+peerCertCacheTTL*2 {
			c.log.Warn("failed to refresh sender %s cert, continuing with verified memory cache: %v", aid, err)
			return true
		}
		c.log.Error("failed to get sender %s cert and no verified cache available, refusing trust: %v", aid, err)
		return false
	}
	certPEM := string(certBytes)
	if versioned, ok := c.tokenStore.(keystore.VersionedCertKeyStore); ok {
		// peer 证书只存版本目录，不覆盖 cert.pem
		if err := versioned.SaveCertVersion(aid, certPEM, requestedFingerprint, false); err != nil {
			c.log.Warn("failed to save versioned cert (aid=%s): %v", aid, err)
		}
	} else if err := c.tokenStore.SaveCert(aid, certPEM); err != nil {
		c.log.Warn("failed to save cert (aid=%s): %v", aid, err)
	}
	return true
}

// getVerifiedPeerCert 获取经过 PKI 验证的 peer 证书（零信任：仅信任内存缓存中已验证的证书）
func (c *AUNClient) getVerifiedPeerCert(aid string, certFingerprint string) string {
	now := float64(time.Now().Unix())
	c.certCacheMu.RLock()
	cached := c.certCache[certCacheKey(aid, certFingerprint)]
	// 带 fingerprint 查不到时，降级用 aid 再查一次
	if cached == nil && strings.TrimSpace(certFingerprint) != "" {
		cached = c.certCache[certCacheKey(aid, "")]
	}
	c.certCacheMu.RUnlock()
	if cached != nil && now < cached.validatedAt+peerCertCacheTTL*2 {
		return string(cached.certBytes)
	}
	return ""
}

func normalizeGroupDispatchMode(value any) string {
	mode := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
	if mode == "mention" || mode == "broadcast" {
		return mode
	}
	return "broadcast"
}

func attachGroupDispatchModeToPayload(message map[string]any) map[string]any {
	if message == nil {
		return message
	}
	payload, ok := message["payload"].(map[string]any)
	if !ok {
		return message
	}
	mode := normalizeGroupDispatchMode(message["dispatch_mode"])
	result := copyMapShallow(message)
	payloadView := copyMapShallow(payload)
	payloadView["dispatch_mode"] = mode
	result["payload"] = payloadView
	result["dispatch_mode"] = mode
	return result
}

// ── 内部：连接 ──────────────────────────────────────────────

// connectOnce 单次连接尝试
func (c *AUNClient) connectOnce(ctx context.Context, params map[string]any, allowReauth bool) (err error) {
	tStart := time.Now()
	gatewayURL := c.resolveGateway(params)
	c.log.Debug("connectOnce enter: gateway=%s allowReauth=%v", gatewayURL, allowReauth)
	defer func() {
		if err != nil {
			c.log.Debug("connectOnce exit (error): gateway=%s elapsed=%dms err=%v", gatewayURL, time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("connectOnce exit: gateway=%s elapsed=%dms", gatewayURL, time.Since(tStart).Milliseconds())
		}
	}()

	c.mu.Lock()
	c.gatewayURL = gatewayURL
	c.slotID = strings.TrimSpace(fmt.Sprint(params["slot_id"]))
	if deliveryMode, ok := params["delivery_mode"].(map[string]any); ok {
		c.connectDeliveryMode = copyMapShallow(deliveryMode)
	}
	c.auth.SetInstanceContext(c.deviceID, c.slotID)
	c.auth.SetDeliveryMode(c.connectDeliveryMode)
	c.state = StateConnecting
	// 前置 restore：在 transport.Connect 启动 reader 之前完成，
	// 避免 reader 把积压 push 交给空 tracker 的 handler，触发 S2 历史 gap 误补拉。
	c.refreshSeqTrackerContextLocked()
	c.mu.Unlock()
	c.restoreSeqTrackerState()

	// 连接 WebSocket
	c.log.Debug("WebSocket connecting: gateway=%s", gatewayURL)
	challenge, connErr := c.transport.Connect(ctx, gatewayURL)
	if connErr != nil {
		c.log.Error("WebSocket connection failed: gateway=%s err=%v", gatewayURL, connErr)
		err = connErr
		return err
	}
	// 连接成功：刷新 DNS 缓存
	if c.dnsNet != nil {
		c.dnsNet.refreshDNSCacheAfterSuccess(gatewayURL)
	}
	c.log.Debug("WebSocket connected, starting auth: gateway=%s", gatewayURL)

	c.mu.Lock()
	c.state = StateAuthenticating
	c.mu.Unlock()

	// 认证
	connectionKind, _ := params["connection_kind"].(string)
	if connectionKind == "" {
		connectionKind = "long"
	}
	shortTtlMs := 0
	if v, ok := params["short_ttl_ms"].(int); ok {
		shortTtlMs = v
	}
	var extraInfo map[string]any
	if ei, ok := params["extra_info"].(map[string]any); ok && len(ei) > 0 {
		extraInfo = ei
	}

	if allowReauth {
		accessToken, _ := params["access_token"].(string)
		authContext, authErr := c.auth.ConnectSession(ctx, c.transport, challenge, gatewayURL, accessToken, connectionKind, shortTtlMs, extraInfo)
		if authErr != nil {
			c.log.Error("auth failed (ConnectSession): gateway=%s err=%v", gatewayURL, authErr)
			err = authErr
			return err
		}
		if authContext != nil {
			identity, _ := authContext["identity"].(map[string]any)
			if identity != nil {
				c.mu.Lock()
				c.identity = identity
				if aidStr, ok := identity["aid"].(string); ok {
					c.aid = aidStr
					if c.logger != nil {
						c.logger.BindAID(aidStr)
					}
				}
				if c.sessionParams != nil {
					if token, ok := authContext["token"].(string); ok && token != "" {
						c.sessionParams["access_token"] = token
					}
				}
				c.mu.Unlock()
			}
			if hello, ok := authContext["hello"].(map[string]any); ok && hello != nil {
				if raw, exists := hello["heartbeat_interval"]; exists {
					c.applyServerHeartbeatInterval(raw, "auth")
				}
			}
		}
	} else {
		accessToken, _ := params["access_token"].(string)
		hello, initErr := c.auth.InitializeWithToken(ctx, c.transport, challenge, accessToken, connectionKind, shortTtlMs, extraInfo)
		if initErr != nil {
			c.log.Error("auth failed (InitializeWithToken): gateway=%s err=%v", gatewayURL, initErr)
			err = initErr
			return err
		}
		c.syncIdentityAfterConnect(accessToken)
		if hello != nil {
			if raw, exists := hello["heartbeat_interval"]; exists {
				c.applyServerHeartbeatInterval(raw, "auth")
			}
		}
	}

	// auth 阶段 aid 可能被 identity 覆盖；若 context 发生变化，重做 refresh + restore 兜底
	c.mu.Lock()
	c.state = StateConnected
	c.connectedAt = time.Now()
	c.nextRetryAt = time.Time{}
	prevContext := c.seqTrackerContext
	c.refreshSeqTrackerContextLocked()
	contextChanged := c.seqTrackerContext != prevContext
	c.mu.Unlock()

	c.log.Debug("connection auth completed, state switched to connected: gateway=%s aid=%s", gatewayURL, c.AID())
	c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState()), "gateway": gatewayURL})

	// 启动后台任务
	if contextChanged {
		c.restoreSeqTrackerState()
	}
	c.startBackgroundTasks(ctx)

	// V2 E2EE 必须先初始化，再触发 post-connect 补拉；否则 message.pull 会走旧路径，
	// 对 V2 设备副本提前 ack，导致后续 message.v2.pull 跳过尚未解密发布的消息。
	if v2Err := c.initV2Session(ctx); v2Err != nil {
		c.logE2.Warn("V2 session init failed (non-fatal): %v", v2Err)
	}

	// connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压
	// 群消息按惰性触发，不在此处主动 pull
	// connect/reconnect 成功后自动触发一次 P2P gap fill，补齐离线期间积压
	// background_sync=false 时跳过（CLI 等短命令场景）
	bgSync := true
	if v, ok := c.sessionOptions["background_sync"].(bool); ok {
		bgSync = v
	}
	if bgSync {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.log.Warn("post-connect P2P gap fill panic: %v", r)
				}
			}()
			c.fillP2pGap()
		}()
	}

	// V2: 上线后自动确认 pending state proposals（后台执行）
	c.mu.RLock()
	bgCtx := c.ctx
	c.mu.RUnlock()
	if bgCtx == nil {
		bgCtx = context.Background()
	}
	if c.v2GetState() != nil {
		go c.v2AutoConfirmPendingProposals(bgCtx)
	}

	return nil
}

func buildSeqTrackerContext(aid, deviceID, slotID string) string {
	aid = strings.TrimSpace(aid)
	if aid == "" {
		return ""
	}
	return buildLengthPrefixedTextKey(aid, strings.TrimSpace(deviceID), strings.TrimSpace(slotID))
}

func buildLengthPrefixedTextKey(parts ...string) string {
	var b strings.Builder
	for _, part := range parts {
		_, _ = fmt.Fprintf(&b, "%d:", len(part))
		b.WriteString(part)
		b.WriteByte(';')
	}
	return b.String()
}

func buildLengthPrefixedBytesKey(parts ...[]byte) []byte {
	var b bytes.Buffer
	for _, part := range parts {
		_, _ = fmt.Fprintf(&b, "%d:", len(part))
		b.Write(part)
		b.WriteByte(';')
	}
	return b.Bytes()
}

func (c *AUNClient) resetSeqTrackingStateLocked() {
	c.seqTracker = NewSeqTracker()
	c.seqTrackerContext = ""
	c.gapFillDoneMu.Lock()
	c.gapFillDone = make(map[string]bool)
	c.gapFillDoneMu.Unlock()
	c.pushedSeqsMu.Lock()
	c.pushedSeqs = make(map[string]map[int]bool)
	c.pushedSeqsMu.Unlock()
	c.pendingOrderedMsgsMu.Lock()
	c.pendingOrderedMsgs = make(map[string]map[int]pendingOrderedMessage)
	c.pendingOrderedMsgsMu.Unlock()
	c.groupSyncedMu.Lock()
	c.groupSynced = make(map[string]bool)
	c.groupSyncedMu.Unlock()
	c.v2SenderIKMu.Lock()
	c.v2SenderIKPending = make(map[string]v2SenderIKPendingEntry)
	c.v2SenderIKFetching = make(map[string]bool)
	c.v2SenderIKMu.Unlock()
}

func (c *AUNClient) refreshSeqTrackerContextLocked() {
	nextContext := buildSeqTrackerContext(c.aid, c.deviceID, c.slotID)
	if nextContext == c.seqTrackerContext {
		return
	}
	c.seqTracker = NewSeqTracker()
	c.seqTrackerContext = nextContext
	c.gapFillDoneMu.Lock()
	c.gapFillDone = make(map[string]bool)
	c.gapFillDoneMu.Unlock()
	c.pushedSeqsMu.Lock()
	c.pushedSeqs = make(map[string]map[int]bool)
	c.pushedSeqsMu.Unlock()
	c.pendingOrderedMsgsMu.Lock()
	c.pendingOrderedMsgs = make(map[string]map[int]pendingOrderedMessage)
	c.pendingOrderedMsgsMu.Unlock()
	c.groupSyncedMu.Lock()
	c.groupSynced = make(map[string]bool)
	c.groupSyncedMu.Unlock()
	c.v2SenderIKMu.Lock()
	c.v2SenderIKPending = make(map[string]v2SenderIKPendingEntry)
	c.v2SenderIKFetching = make(map[string]bool)
	c.v2SenderIKMu.Unlock()
}

// resolveGateway 解析 Gateway URL
func (c *AUNClient) resolveGateway(params map[string]any) string {
	gateways := c.resolveGateways(params)
	if len(gateways) > 0 {
		return gateways[0]
	}
	return ""
}

// resolveGateways 解析所有 Gateway URL（支持 string 或 []string）
func (c *AUNClient) resolveGateways(params map[string]any) []string {
	if gws, ok := params["gateways"].([]string); ok && len(gws) > 0 {
		return gws
	}
	if gws, ok := params["gateways"].([]any); ok && len(gws) > 0 {
		var urls []string
		for _, g := range gws {
			if s, ok := g.(string); ok && s != "" {
				urls = append(urls, s)
			}
		}
		if len(urls) > 0 {
			return urls
		}
	}
	gateway, _ := params["gateway"].(string)
	if gateway == "" {
		c.mu.RLock()
		gateway = c.gatewayURL
		c.mu.RUnlock()
	}
	if gateway != "" {
		return []string{gateway}
	}
	return nil
}

// syncIdentityAfterConnect 使用 token 连接后同步本地身份
func (c *AUNClient) syncIdentityAfterConnect(accessToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.identity == nil {
		return
	}
	c.identity["access_token"] = accessToken
	if loadedAID, ok := c.identity["aid"].(string); ok && loadedAID != "" {
		c.aid = loadedAID
		if c.logger != nil {
			c.logger.BindAID(loadedAID)
		}
	}

	if _, ok := c.identity["aid"].(string); ok {
		if err := c.auth.persistIdentity(c.identity); err != nil {
			c.auth.lastPersistErr = err
		}
	}
}

// ── 后台任务 ──────────────────────────────────────────────

// startBackgroundTasks 启动所有后台 goroutine
// ISSUE-SDK-GO-010: 后台任务使用独立的 context.Background() 作为父 context，
// 避免用户传入的短生命周期 context（如 WithTimeout）导致心跳、token 刷新等后台任务被意外取消。
// 后台任务的生命周期由 Close()/Disconnect() 通过 cancel 函数统一管理。
func (c *AUNClient) startBackgroundTasks(_ context.Context) {
	c.mu.Lock()
	// 取消旧的后台任务
	if c.cancel != nil {
		c.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	c.cancel = cancel
	connectionKind := ""
	if opts := c.sessionOptions; opts != nil {
		connectionKind, _ = opts["connection_kind"].(string)
	}
	c.mu.Unlock()

	// 短连接不启动 heartbeat 与 token 自动刷新（短连接生命周期短，不需要长期会话维护；
	// 但 auto_reconnect 仍允许，由上层根据 sessionOptions.auto_reconnect 决定）
	if connectionKind != "short" {
		go c.heartbeatLoop(ctx)
		go c.tokenRefreshLoop(ctx)
	}
	c.startCacheCleanupTask(ctx)
}

// heartbeatLoop 心跳循环；支持运行时通过 applyServerHeartbeatInterval 调整间隔。
func (c *AUNClient) heartbeatLoop(ctx context.Context) {
	consecutiveFailures := 0
	maxFailures := 3 // 连续失败 3 次触发重连

	currentInterval := c.readEffectiveHeartbeatInterval()
	if currentInterval <= 0 {
		// 启动时已关闭：等 nudge 唤醒（pong/auth 下发新值后才会启动）
		// 这里先 return；调用方在 applyServerHeartbeatInterval 检测到值变化时会 go heartbeatLoop 重新启动
		return
	}
	timer := time.NewTimer(time.Duration(currentInterval * float64(time.Second)))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.heartbeatNudge:
			// 间隔变化：重读，重置 timer；不发心跳
			newInterval := c.readEffectiveHeartbeatInterval()
			if newInterval <= 0 {
				return
			}
			currentInterval = newInterval
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(time.Duration(currentInterval * float64(time.Second)))
		case <-timer.C:
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.mu.RLock()
			isClosing := c.closing.Load()
			state := c.state
			c.mu.RUnlock()
			if isClosing {
				return
			}
			if state != StateConnected {
				consecutiveFailures = 0
				timer.Reset(time.Duration(currentInterval * float64(time.Second)))
				continue
			}
			result, err := c.transport.Call(ctx, "meta.ping", map[string]any{})
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				consecutiveFailures++
				c.log.Warn("heartbeat failed (%d/%d): %v", consecutiveFailures, maxFailures, err)
				c.events.Publish("connection.error", map[string]any{"error": err})
				if consecutiveFailures >= maxFailures {
					c.log.Warn("consecutive %d heartbeat failures, triggering reconnect", maxFailures)
					c.handleTransportDisconnect(err, -1)
					return
				}
			} else {
				consecutiveFailures = 0
				// 服务端可在 pong 中下发新的 heartbeat_interval（秒，0=关闭）
				if pong, ok := result.(map[string]any); ok {
					if raw, exists := pong["heartbeat_interval"]; exists {
						c.applyServerHeartbeatInterval(raw, "pong")
					}
				}
			}
			// 重读，可能在上面 applyServerHeartbeatInterval 中改了
			newInterval := c.readEffectiveHeartbeatInterval()
			if newInterval <= 0 {
				return
			}
			currentInterval = newInterval
			timer.Reset(time.Duration(currentInterval * float64(time.Second)))
		}
	}
}

// readEffectiveHeartbeatInterval 读取并 clamp 当前的心跳间隔（秒）。
func (c *AUNClient) readEffectiveHeartbeatInterval() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if opts := c.sessionOptions; opts != nil {
		if raw, exists := opts["heartbeat_interval"]; exists {
			return clampHeartbeatInterval(raw)
		}
	}
	return 0
}

// applyServerHeartbeatInterval 服务端通过 hello/pong 下发心跳间隔；
// clamp 后写入 sessionOptions 并通过 heartbeatNudge 唤醒心跳循环。
// 若当前心跳未运行（之前是 0），且新值为正，则启动心跳。
func (c *AUNClient) applyServerHeartbeatInterval(raw any, source string) {
	newInterval := clampHeartbeatInterval(raw)
	c.mu.Lock()
	var oldInterval float64
	if opts := c.sessionOptions; opts != nil {
		if cur, ok := opts["heartbeat_interval"]; ok {
			oldInterval = clampHeartbeatInterval(cur)
		}
		opts["heartbeat_interval"] = newInterval
	}
	ctx := c.ctx
	c.mu.Unlock()
	if newInterval == oldInterval {
		return
	}
	c.log.Debug("heartbeat_interval updated by %s: %v -> %v", source, oldInterval, newInterval)
	// 唤醒已在跑的心跳循环
	select {
	case c.heartbeatNudge <- struct{}{}:
	default:
	}
	// 之前 interval=0 没起循环，新值为正时启动
	if oldInterval <= 0 && newInterval > 0 && ctx != nil {
		go c.heartbeatLoop(ctx)
	}
}

// tokenRefreshLoop Token 主动刷新循环
func (c *AUNClient) tokenRefreshLoop(ctx context.Context) {
	c.mu.RLock()
	lead := 1800.0
	if opts := c.sessionOptions; opts != nil {
		if v, ok := opts["token_refresh_before"].(float64); ok && v > 0 {
			lead = v
		}
	}
	c.mu.RUnlock()

	const checkInterval = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.mu.RLock()
		isClosing := c.closing.Load()
		state := c.state
		gateway := c.gatewayURL
		identity := c.identity
		c.mu.RUnlock()

		if isClosing {
			return
		}
		if state != StateConnected || gateway == "" {
			sleepWithCancel(ctx, checkInterval)
			continue
		}

		if identity == nil {
			identity = c.auth.LoadIdentityOrNil("")
			if identity != nil {
				c.mu.Lock()
				c.identity = identity
				c.mu.Unlock()
			}
		}
		if identity == nil {
			sleepWithCancel(ctx, checkInterval)
			continue
		}

		expiresAt := c.auth.GetAccessTokenExpiry(identity)
		if expiresAt == 0 {
			sleepWithCancel(ctx, checkInterval)
			continue
		}

		if expiresAt-float64(time.Now().Unix()) > lead {
			sleepWithCancel(ctx, checkInterval)
			continue
		}

		// 刷新 token
		refreshedIdentity, err := c.auth.RefreshCachedTokens(ctx, gateway, identity)
		if err != nil {
			var authErr *AuthError
			if errors.As(err, &authErr) {
				failures := int(c.tokenRefreshFailures.Add(1))
				if failures >= 3 {
					c.log.Warn("token refresh consecutive failures %d, stopping refresh loop and triggering reconnect", failures)
					c.events.Publish("token.refresh_exhausted", map[string]any{
						"consecutive_failures": failures,
						"last_error":           err.Error(),
					})
					c.tokenRefreshFailures.Store(0)
					c.handleTransportDisconnect(
						fmt.Errorf("token refresh exhausted, triggering reconnect"), -1,
					)
					return
				}
				c.log.Warn("token refresh failed (%d/3): %v", failures, err)
			} else {
				c.log.Warn("token refresh failed: %v", err)
			}
			sleepWithCancel(ctx, checkInterval)
			continue
		}
		c.tokenRefreshFailures.Store(0)

		c.mu.Lock()
		// 刷新期间可能已断线，复检状态，避免写回 stale identity
		if c.state != StateConnected {
			c.mu.Unlock()
			sleepWithCancel(ctx, checkInterval)
			continue
		}
		c.identity = refreshedIdentity
		if c.sessionParams != nil {
			if at, ok := refreshedIdentity["access_token"].(string); ok {
				c.sessionParams["access_token"] = at
			}
		}
		c.mu.Unlock()

		c.events.Publish("token.refreshed", map[string]any{
			"aid":        refreshedIdentity["aid"],
			"expires_at": refreshedIdentity["access_token_expires_at"],
		})
	}
}

// startCacheCleanupTask 启动进程内缓存清理任务。
func (c *AUNClient) startCacheCleanupTask(ctx context.Context) {
	go c.cacheCleanupLoop(ctx, 3600.0)
}

// cacheCleanupLoop 定时清理过期的内存缓存条目
func (c *AUNClient) cacheCleanupLoop(ctx context.Context, interval float64) {
	ticker := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.closing.Load() {
				return
			}
			now := float64(time.Now().Unix())

			// 证书缓存
			c.certCacheMu.Lock()
			for k, v := range c.certCache {
				if now >= v.refreshAfter {
					delete(c.certCache, k)
				}
			}
			c.certCacheMu.Unlock()

			// 补洞去重集合（保留最近 5000 条）
			c.gapFillDoneMu.Lock()
			if len(c.gapFillDone) > 10000 {
				newMap := make(map[string]bool, 5000)
				i := 0
				for k, v := range c.gapFillDone {
					if i >= 5000 {
						break
					}
					newMap[k] = v
					i++
				}
				c.gapFillDone = newMap
			}
			c.gapFillDoneMu.Unlock()

			// auth gateway 缓存
			c.auth.CleanExpiredCaches()
		}
	}
}

// restoreSeqTrackerState 从 keystore seq_tracker 表恢复 SeqTracker 状态
func (c *AUNClient) restoreSeqTrackerState() {
	c.mu.RLock()
	aid := c.aid
	deviceID := c.deviceID
	slotID := c.slotID
	c.mu.RUnlock()
	if aid == "" {
		return
	}
	if store, ok := c.tokenStore.(keystore.SeqTrackerStore); ok {
		seqs, err := store.LoadAllSeqs(aid, deviceID, slotID)
		if err != nil || len(seqs) == 0 {
			return
		}
		seqs = c.migrateSeqStateGroupIDs(aid, deviceID, slotID, seqs)
		c.seqTracker.RestoreState(seqs)
		return
	}
	// 降级：从 instance_state JSON 读取（兼容旧数据）
	if store, ok := c.tokenStore.(keystore.InstanceStateStore); ok {
		holder, _ := store.LoadInstanceState(aid, deviceID, slotID)
		if holder == nil {
			return
		}
		state, ok := holder["seq_tracker_state"].(map[string]any)
		if !ok {
			return
		}
		intState := make(map[string]int)
		for ns, v := range state {
			if seq, ok := v.(float64); ok && int(seq) > 0 {
				intState[ns] = int(seq)
			}
		}
		if len(intState) > 0 {
			intState = c.migrateSeqStateGroupIDs(aid, deviceID, slotID, intState)
			c.seqTracker.RestoreState(intState)
		}
	}
}

// migrateSeqStateGroupIDs 把 state 里 group_event:/group_msg: 前缀的老/污染 group_id 归一化。
// 冲突取 max；落盘删老 ns、写新 ns，避免下次启动重复迁移。
func (c *AUNClient) migrateSeqStateGroupIDs(aid, deviceID, slotID string, state map[string]int) map[string]int {
	if len(state) == 0 {
		return state
	}
	rename := make(map[string]string)
	for ns := range state {
		for _, prefix := range []string{"group_event:", "group_msg:"} {
			if strings.HasPrefix(ns, prefix) {
				oldGid := ns[len(prefix):]
				newGid := NormalizeGroupID(oldGid, "")
				if newGid != "" && newGid != oldGid {
					rename[ns] = prefix + newGid
				}
				break
			}
		}
	}
	if len(rename) == 0 {
		return state
	}
	newState := make(map[string]int, len(state))
	for k, v := range state {
		newState[k] = v
	}
	for oldNs, newNs := range rename {
		oldVal := newState[oldNs]
		curVal := newState[newNs]
		delete(newState, oldNs)
		if oldVal > curVal {
			newState[newNs] = oldVal
		} else {
			newState[newNs] = curVal
		}
	}
	c.logEG.Warn("SeqTracker group_id migration: %d namespaces rewritten", len(rename))
	if saver, ok := c.tokenStore.(keystore.SeqTrackerStore); ok {
		deleter, _ := c.tokenStore.(keystore.SeqTrackerDeleter)
		for oldNs, newNs := range rename {
			if deleter != nil {
				if err := deleter.DeleteSeq(aid, deviceID, slotID, oldNs); err != nil {
					c.log.Warn("failed to delete old seq ns: ns=%s err=%v", oldNs, err)
				}
			}
			if err := saver.SaveSeq(aid, deviceID, slotID, newNs, newState[newNs]); err != nil {
				c.log.Warn("failed to write new seq ns: ns=%s err=%v", newNs, err)
			}
		}
	}
	return newState
}

// saveSeqTrackerState 将 SeqTracker 状态保存到 keystore seq_tracker 表（每 namespace 一行）
func (c *AUNClient) saveSeqTrackerState() {
	c.mu.RLock()
	aid := c.aid
	deviceID := c.deviceID
	slotID := c.slotID
	c.mu.RUnlock()
	if aid == "" {
		return
	}
	state := c.seqTracker.ExportState()
	if len(state) == 0 {
		return
	}
	if store, ok := c.tokenStore.(keystore.SeqTrackerStore); ok {
		for ns, seq := range state {
			_ = store.SaveSeq(aid, deviceID, slotID, ns, seq)
		}
		return
	}
	c.log.Warn("keystore does not support SeqTrackerStore, seq_tracker_state not persisted")
}

// logE2EEError 记录 E2EE 自动编排错误

// ── 断线重连 ──────────────────────────────────────────────

// 不重连 close code 集合：认证失败/权限错误/被踢等，重连无意义
var noReconnectCodes = map[int]bool{
	4001: true, // Auth failed
	4003: true, // Invalid AID
	4008: true, // Auth timeout
	4009: true, // Server kick
	4010: true, // Invalid nonce
	4011: true, // Federation ACL denied
	4012: true, // Long connection already exists
	4013: true, // Short connection capacity exceeded
	4014: true, // Short connection idle timeout
	4015: true, // Long connection quota exceeded (evicted by newer)
}

// onGatewayDisconnect 处理服务端主动断开通知 event/gateway.disconnect
//
// 服务端可能附带结构化 detail 字段（如长连接配额超限时含
// aid/device_id/slot_id/quota_kind/evicted_by）。
// 透传到应用层可订阅事件 'gateway.disconnect'，方便业务定位被踢原因。
func (c *AUNClient) onGatewayDisconnect(payload any) {
	data, _ := payload.(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	code := data["code"]
	reason := data["reason"]
	detail, _ := data["detail"].(map[string]any)
	if detail == nil {
		detail = map[string]any{}
	}
	c.log.Warn("server initiated disconnect: code=%v, reason=%v, detail=%v", code, reason, detail)
	c.serverKicked.Store(true)
	// 缓存最近一次 disconnect 信息，让后续 connection.state(connection_failed) 也能带 detail
	c.lastDisconnectMu.Lock()
	c.lastDisconnectInfo = map[string]any{
		"code":   code,
		"reason": reason,
		"detail": detail,
	}
	c.lastDisconnectMu.Unlock()
	// 透传给应用层订阅者（与 Python SDK 对齐）
	c.events.Publish("gateway.disconnect", map[string]any{
		"code":   code,
		"reason": reason,
		"detail": detail,
	})
}

// handleTransportDisconnect 传输层断线回调
func (c *AUNClient) handleTransportDisconnect(err error, closeCode int) {
	c.log.Warn("transport disconnected: closeCode=%d err=%v", closeCode, err)
	// 原子检查+设置状态，避免锁间隙中 close() 被调用后仍启动重连
	c.mu.Lock()
	isClosing := c.closing.Load()
	state := c.state
	if isClosing || state == StateClosed {
		c.mu.Unlock()
		return
	}
	c.state = StateDisconnected
	c.authenticated = false
	c.nextRetryAt = time.Time{}
	c.mu.Unlock()

	c.events.Publish("state_change", map[string]any{
		"state": string(c.ConnectionState()),
		"error": err,
	})

	c.mu.RLock()
	autoReconnect := false
	if opts := c.sessionOptions; opts != nil {
		if v, ok := opts["auto_reconnect"].(bool); ok {
			autoReconnect = v
		}
	}
	c.mu.RUnlock()

	if !autoReconnect {
		return
	}

	// 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
	if c.serverKicked.Load() || noReconnectCodes[closeCode] {
		c.mu.Lock()
		c.state = StateTerminalFailed
		c.nextRetryAt = time.Time{}
		c.mu.Unlock()
		reason := "server kicked"
		if !c.serverKicked.Load() {
			reason = fmt.Sprintf("close code %d", closeCode)
		}
		c.log.Warn("suppressing auto-reconnect: %s", reason)
		eventPayload := map[string]any{
			"state":  string(c.ConnectionState()),
			"error":  err,
			"reason": reason,
		}
		// 把服务端 gateway.disconnect 附带的结构化 detail/code 也带给应用层（与 Python SDK 对齐）
		c.lastDisconnectMu.Lock()
		info := c.lastDisconnectInfo
		c.lastDisconnectMu.Unlock()
		if info != nil {
			if detail, ok := info["detail"].(map[string]any); ok && len(detail) > 0 {
				eventPayload["detail"] = detail
			}
			if code, ok := info["code"]; ok && code != nil {
				eventPayload["code"] = code
			}
		}
		c.events.Publish("state_change", eventPayload)
		return
	}

	if c.reconnecting.CompareAndSwap(false, true) {
		// closeCode == -1 表示网络异常断开（无 close frame），其他 code = 服务端主动关闭
		serverInitiated := closeCode != -1
		c.log.Info("triggering auto-reconnect: serverInitiated=%v closeCode=%d", serverInitiated, closeCode)
		// 创建可取消的 context，供手动 connect 从 reconnecting 状态停止旧 loop
		reconnCtx, reconnCancel := context.WithCancel(context.Background())
		c.mu.Lock()
		c.reconnectCancel = reconnCancel
		c.mu.Unlock()
		go c.reconnectLoop(reconnCtx, serverInitiated)
	}
}

// reconnectLoop 重连循环（指数退避 + 固定上限抖动，在不可重试错误、close()、ctx 取消、或超过最大重试次数时终止）
func (c *AUNClient) reconnectLoop(ctx context.Context, serverInitiated bool) {
	c.mu.RLock()
	opts := c.sessionOptions
	c.mu.RUnlock()

	retryConfig, _ := opts["retry"].(map[string]any)
	initialDelay := 1.0
	maxBaseDelay := 64.0
	maxAttempts := 0 // 0 表示无限重试
	if retryConfig != nil {
		if v, ok := retryConfig["initial_delay"].(float64); ok {
			initialDelay = v
		}
		if v, ok := retryConfig["max_delay"].(float64); ok {
			maxBaseDelay = v
		}
		if v, ok := retryConfig["max_attempts"].(float64); ok && v > 0 {
			maxAttempts = int(v)
		}
	}
	maxBaseDelay = clampReconnectDelaySeconds(maxBaseDelay, reconnectMaxBaseDelaySeconds, reconnectMaxBaseDelaySeconds)

	// 服务端主动关闭时从 16s 起跳，避免重连风暴；网络断开从 initial_delay 起跳
	delay := initialDelay
	delayFallback := 1.0
	if serverInitiated {
		delay = 16.0
		delayFallback = 16.0
	}
	delay = clampReconnectDelaySeconds(delay, delayFallback, maxBaseDelay)
	for attempt := 1; !c.closing.Load() && ctx.Err() == nil; attempt++ {
		// 超过最大重试次数时停止
		if maxAttempts > 0 && attempt > maxAttempts {
			c.log.Warn("reconnect exceeded max attempts %d, stopping retry", maxAttempts)
			c.mu.Lock()
			c.state = StateTerminalFailed
			c.nextRetryAt = time.Time{}
			c.mu.Unlock()
			c.events.Publish("state_change", map[string]any{
				"state":   string(c.ConnectionState()),
				"error":   fmt.Errorf("超过最大重连次数 %d", maxAttempts),
				"attempt": attempt - 1,
			})
			c.reconnecting.Store(false)
			return
		}

		// 固定上限抖动：base=[1s, max_base]，delay=base+rand(0..max_base)。
		// ISSUE-SDK-GO-007: 使用 crypto/rand 代替 math/rand，确保并发安全。
		jitteredDelay := reconnectSleepDelaySeconds(delay, maxBaseDelay)
		sleepDuration := time.Duration(jitteredDelay * float64(time.Second))
		nextRetryAt := time.Now().Add(sleepDuration)
		c.mu.Lock()
		c.state = StateReconnecting
		c.retryAttempt = attempt
		c.nextRetryAt = nextRetryAt
		c.mu.Unlock()

		c.events.Publish("state_change", map[string]any{
			"state":         string(c.ConnectionState()),
			"attempt":       attempt,
			"next_retry_at": nextRetryAt,
		})

		// 可中断 sleep：close() 或手动 connect 取消 ctx 时立即退出
		select {
		case <-time.After(sleepDuration):
		case <-ctx.Done():
			c.reconnecting.Store(false)
			return
		}

		// close() 可能在 sleep 期间被调用
		if c.closing.Load() || ctx.Err() != nil {
			c.reconnecting.Store(false)
			return
		}
		c.mu.Lock()
		c.nextRetryAt = time.Time{}
		c.state = StateReconnecting
		c.mu.Unlock()
		c.events.Publish("state_change", map[string]any{
			"state":   string(c.ConnectionState()),
			"attempt": attempt,
		})

		// 重连前先 GET /health 探测，不健康则跳过本轮
		c.mu.RLock()
		gw := c.gatewayURL
		c.mu.RUnlock()
		if gw != "" {
			healthy := c.discovery.CheckHealth(context.Background(), gw, 5*time.Second)
			if !healthy {
				delay = delay * 2
				if delay > maxBaseDelay {
					delay = maxBaseDelay
				}
				continue
			}
		}

		// 关闭旧连接
		_ = c.transport.Close()

		// 重新连接
		c.mu.RLock()
		params := c.sessionParams
		c.mu.RUnlock()
		if params == nil {
			c.mu.Lock()
			c.state = StateTerminalFailed
			c.nextRetryAt = time.Time{}
			c.mu.Unlock()
			c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState())})
			c.reconnecting.Store(false)
			return
		}

		err := c.connectOnce(context.Background(), params, true)
		if err == nil {
			c.log.Info("reconnect succeeded: attempt=%d", attempt)
			c.reconnecting.Store(false)
			return
		}

		c.log.Warn("reconnect failed: attempt=%d err=%v", attempt, err)
		c.events.Publish("connection.error", map[string]any{
			"error":   err,
			"attempt": attempt,
		})

		if !shouldRetryReconnect(err) {
			c.mu.Lock()
			c.state = StateTerminalFailed
			c.nextRetryAt = time.Time{}
			c.mu.Unlock()
			c.events.Publish("state_change", map[string]any{
				"state":   string(c.ConnectionState()),
				"error":   err,
				"attempt": attempt,
			})
			c.reconnecting.Store(false)
			return
		}

		delay = delay * 2
		if delay > maxBaseDelay {
			delay = maxBaseDelay
		}
	}
	c.reconnecting.Store(false)
}

// shouldRetryReconnect 判断错误是否应该重试
func shouldRetryReconnect(err error) bool {
	switch e := err.(type) {
	case *AuthError:
		message := strings.ToLower(strings.TrimSpace(e.Error()))
		if strings.Contains(message, "aid_login1_failed") || strings.Contains(message, "aid_login2_failed") {
			return true
		}
		return false
	case *PermissionError:
		return false
	case *ValidationError:
		return false
	case *StateError:
		return false
	case *ConnectionError:
		return true
	case *TimeoutError:
		return true
	case *AUNError:
		return e.Retryable
	default:
		return true
	}
}

// ── 参数处理 ──────────────────────────────────────────────

// normalizeConnectParams 规范化连接参数
func (c *AUNClient) normalizeConnectParams(params map[string]any) (map[string]any, error) {
	return c.normalizeConnectParamsWithTokenPolicy(params, true)
}

func (c *AUNClient) normalizeConnectParamsWithTokenPolicy(params map[string]any, requireAccessToken bool) (map[string]any, error) {
	request := copyMapShallow(params)

	accessToken, _ := request["access_token"].(string)
	if requireAccessToken && accessToken == "" {
		return nil, NewStateError("connect 需要非空 access_token")
	}

	gateway, _ := request["gateway"].(string)
	if gateway == "" {
		c.mu.RLock()
		gateway = c.gatewayURL
		c.mu.RUnlock()
	}
	if gateway == "" {
		return nil, NewStateError("connect 需要非空 gateway")
	}

	if accessToken != "" {
		request["access_token"] = accessToken
	} else {
		delete(request, "access_token")
	}
	request["gateway"] = gateway
	request["device_id"] = c.deviceID
	slotSource := any(c.slotID)
	if existing, ok := request["slot_id"]; ok {
		slotSource = existing
	}
	slotID, err := NormalizeSlotID(slotSource, c.slotID)
	if err != nil {
		return nil, NewValidationError(err.Error())
	}
	request["slot_id"] = slotID
	var rawDeliveryMode map[string]any
	if existing, ok := request["delivery_mode"].(map[string]any); ok {
		rawDeliveryMode = copyMapShallow(existing)
	} else if request["delivery_mode"] != nil {
		rawDeliveryMode = map[string]any{"mode": fmt.Sprint(request["delivery_mode"])}
	} else {
		rawDeliveryMode = copyMapShallow(c.defaultConnectDeliveryMode)
	}
	if routing, ok := request["queue_routing"]; ok {
		rawDeliveryMode["routing"] = routing
	}
	if ttl, ok := request["affinity_ttl_ms"]; ok {
		rawDeliveryMode["affinity_ttl_ms"] = ttl
	}
	request["delivery_mode"] = normalizeDeliveryModeConfig(rawDeliveryMode)

	if topology, exists := request["topology"]; exists {
		if topology != nil {
			if _, ok := topology.(map[string]any); !ok {
				return nil, NewValidationError("topology 必须是 map")
			}
		}
	}
	if retry, exists := request["retry"]; exists {
		if _, ok := retry.(map[string]any); !ok {
			return nil, NewValidationError("retry 必须是 map")
		}
	}
	if timeouts, exists := request["timeouts"]; exists {
		if _, ok := timeouts.(map[string]any); !ok {
			return nil, NewValidationError("timeouts 必须是 map")
		}
	}

	// 长短连接选项：默认 long，向后兼容
	kindRaw, kindExists := request["connection_kind"]
	connectionKind := "long"
	if kindExists && kindRaw != nil {
		connectionKind = strings.TrimSpace(strings.ToLower(fmt.Sprint(kindRaw)))
	}
	if connectionKind != "long" && connectionKind != "short" {
		return nil, NewValidationError("connection_kind must be 'long' or 'short'")
	}
	request["connection_kind"] = connectionKind

	shortTtlMs := 0
	if raw, ok := request["short_ttl_ms"]; ok && raw != nil {
		switch v := raw.(type) {
		case int:
			shortTtlMs = v
		case float64:
			shortTtlMs = int(v)
		case int64:
			shortTtlMs = int(v)
		default:
			return nil, NewValidationError("short_ttl_ms must be a non-negative integer")
		}
		if shortTtlMs < 0 {
			return nil, NewValidationError("short_ttl_ms must be a non-negative integer")
		}
	}
	if connectionKind != "short" {
		shortTtlMs = 0
	}
	request["short_ttl_ms"] = shortTtlMs

	return request, nil
}

// buildSessionOptions 构建会话选项
func (c *AUNClient) buildSessionOptions(params map[string]any, opts *ConnectOptions) map[string]any {
	connectionKind := "long"
	if v, ok := params["connection_kind"].(string); ok && v != "" {
		connectionKind = v
	}

	shortTtlMs := 0
	if v, ok := params["short_ttl_ms"].(int); ok {
		shortTtlMs = v
	}

	options := map[string]any{
		"auto_reconnect":       true,
		"heartbeat_interval":   30.0,
		"token_refresh_before": 1800.0,
		"retry": map[string]any{
			"initial_delay": 1.0,
			"max_delay":     30.0,
		},
		"timeouts": map[string]any{
			"connect": 5.0,
			"call":    35.0,
			"http":    30.0,
		},
		"connection_kind": connectionKind,
		"short_ttl_ms":    shortTtlMs,
	}

	// SDK 内部会话字段从 opts 读取，不经过 gateway 参数
	if opts != nil {
		if opts.AutoReconnect {
			options["auto_reconnect"] = true
		}
		if opts.HeartbeatInterval > 0 {
			options["heartbeat_interval"] = float64(opts.HeartbeatInterval)
		}
		if opts.TokenRefreshBefore > 0 {
			options["token_refresh_before"] = float64(opts.TokenRefreshBefore)
		}
		if opts.Retry != nil {
			retryOpts, _ := options["retry"].(map[string]any)
			retryOpts["initial_delay"] = opts.Retry.InitialDelay
			retryOpts["max_delay"] = opts.Retry.MaxDelay
			if opts.Retry.MaxAttempts > 0 {
				retryOpts["max_attempts"] = float64(opts.Retry.MaxAttempts)
			}
		}
		if opts.Timeouts != nil {
			timeoutOpts, _ := options["timeouts"].(map[string]any)
			timeoutOpts["connect"] = opts.Timeouts.Connect
			timeoutOpts["call"] = opts.Timeouts.Call
		}
		options["background_sync"] = opts.BackgroundSync
	}

	return options
}

func normalizeDeliveryModeConfig(raw map[string]any) map[string]any {
	mode := strings.TrimSpace(strings.ToLower(getStr(raw, "mode", "fanout")))
	if mode == "" {
		mode = "fanout"
	}
	if mode != "fanout" && mode != "queue" {
		mode = "fanout"
	}
	routing := strings.TrimSpace(strings.ToLower(getStr(raw, "routing", "")))
	if mode != "queue" {
		routing = ""
	} else {
		if routing == "" {
			routing = "round_robin"
		}
		if routing != "round_robin" && routing != "sender_affinity" {
			routing = "round_robin"
		}
	}
	affinityTTL := 0
	switch v := raw["affinity_ttl_ms"].(type) {
	case float64:
		affinityTTL = int(v)
	case int:
		affinityTTL = v
	case int64:
		affinityTTL = int(v)
	}
	if affinityTTL < 0 {
		affinityTTL = 0
	}
	return map[string]any{
		"mode":            mode,
		"routing":         routing,
		"affinity_ttl_ms": affinityTTL,
	}
}

// ── 静态辅助函数 ──────────────────────────────────────────

func intPtr(v int) *int {
	return &v
}

func isGroupServiceAID(aid string) bool {
	text := strings.TrimSpace(aid)
	parts := strings.Split(text, ".")
	if len(parts) < 2 {
		return false
	}
	return parts[0] == "group" && strings.Join(parts[1:], ".") != ""
}

func validateMessageRecipient(to any) error {
	toAID := strings.TrimSpace(fmt.Sprint(to))
	if isGroupServiceAID(toAID) {
		return NewValidationError("message.send receiver cannot be group.{issuer}; use group.send instead")
	}
	return nil
}

func stringFieldFromObject(value any, key string) string {
	switch typed := value.(type) {
	case map[string]any:
		return strings.TrimSpace(stringFromAny(typed[key]))
	case map[string]string:
		return strings.TrimSpace(typed[key])
	default:
		return ""
	}
}

func (c *AUNClient) normalizeOutboundMessagePayload(params map[string]any, method string) {
	if _, hasPayload := params["payload"]; !hasPayload {
		if content, hasContent := params["content"]; hasContent {
			params["payload"] = content
			delete(params, "content")
		}
	}
	payload, _ := params["payload"].(map[string]any)
	if payload != nil {
		if _, hasType := payload["type"]; !hasType {
			if _, ok := payload["text"].(string); ok {
				normalized := make(map[string]any, len(payload)+1)
				normalized["type"] = "text"
				for k, v := range payload {
					normalized[k] = v
				}
				params["payload"] = normalized
			}
		}
	}
}
func (c *AUNClient) validateOutboundCall(method string, params map[string]any) error {
	if method == "message.send" {
		if err := validateMessageRecipient(params["to"]); err != nil {
			return err
		}
		if _, ok := params["persist"]; ok {
			return NewValidationError("message.send no longer accepts 'persist'; configure delivery_mode during connect")
		}
		if _, ok := params["delivery_mode"]; ok {
			return NewValidationError("message.send does not accept delivery_mode; configure delivery_mode during connect")
		}
		if _, ok := params["queue_routing"]; ok {
			return NewValidationError("message.send does not accept delivery_mode; configure delivery_mode during connect")
		}
		if _, ok := params["affinity_ttl_ms"]; ok {
			return NewValidationError("message.send does not accept delivery_mode; configure delivery_mode during connect")
		}
		return nil
	}
	if method == "group.send" {
		if _, ok := params["persist"]; ok {
			return NewValidationError("group.send does not accept 'persist'; group messages are always fanout")
		}
		if _, ok := params["delivery_mode"]; ok {
			return NewValidationError("group.send does not accept delivery_mode; group messages are always fanout")
		}
		if _, ok := params["queue_routing"]; ok {
			return NewValidationError("group.send does not accept delivery_mode; group messages are always fanout")
		}
		if _, ok := params["affinity_ttl_ms"]; ok {
			return NewValidationError("group.send does not accept delivery_mode; group messages are always fanout")
		}
	}
	if method == "group.thought.put" || method == "group.thought.get" || method == "message.thought.put" || method == "message.thought.get" {
		contextType := stringFieldFromObject(params["context"], "type")
		contextID := stringFieldFromObject(params["context"], "id")
		hasContext := contextType != "" && contextID != ""
		if !hasContext {
			return NewValidationError(method + " requires context.type + context.id")
		}
	}
	if method == "group.thought.get" {
		senderAID, _ := params["sender_aid"].(string)
		if strings.TrimSpace(senderAID) == "" {
			return NewValidationError("group.thought.get requires sender_aid")
		}
	}
	if method == "message.thought.put" {
		if err := validateMessageRecipient(params["to"]); err != nil {
			return err
		}
		if strings.TrimSpace(fmt.Sprint(params["to"])) == "" {
			return NewValidationError("message.thought.put requires to")
		}
	}
	if method == "message.thought.get" {
		senderAID, _ := params["sender_aid"].(string)
		if strings.TrimSpace(senderAID) == "" {
			return NewValidationError("message.thought.get requires sender_aid")
		}
	}
	return nil
}

func (c *AUNClient) currentMessageDeliveryMode() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return copyMapShallow(c.connectDeliveryMode)
}

func (c *AUNClient) injectMessageCursorContext(method string, params map[string]any) error {
	if method != "message.pull" && method != "message.ack" {
		return nil
	}
	if existing, ok := params["device_id"]; ok && strings.TrimSpace(fmt.Sprint(existing)) != c.deviceID {
		return NewValidationError("message.pull/message.ack device_id must match the current client instance")
	}
	slotSource := any(c.slotID)
	if existing, ok := params["slot_id"]; ok {
		slotSource = existing
	}
	slotID, err := NormalizeSlotID(slotSource, c.slotID)
	if err != nil {
		return NewValidationError(err.Error())
	}
	if SlotIsolationKey(slotID) != SlotIsolationKey(c.slotID) {
		return NewValidationError("message.pull/message.ack slot_id must match the current client instance")
	}
	params["device_id"] = c.deviceID
	params["slot_id"] = c.slotID
	return nil
}

// buildCertURL 构建证书下载 URL
func buildCertURL(gatewayURL, aid, certFingerprint string) string {
	parsed, err := url.Parse(gatewayURL)
	if err != nil {
		return gatewayURL
	}
	scheme := "https"
	if parsed.Scheme == "ws" {
		scheme = "http"
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   parsed.Host,
		Path:   "/pki/cert/" + url.PathEscape(aid),
	}
	if normalized := strings.TrimSpace(strings.ToLower(certFingerprint)); normalized != "" {
		q := url.Values{}
		q.Set("cert_fingerprint", normalized)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// resolvePeerGatewayURL 跨域时将 Gateway URL 替换为 peer 所在域的 Gateway URL
func resolvePeerGatewayURL(localGatewayURL, peerAID string) string {
	if !strings.Contains(peerAID, ".") {
		return localGatewayURL
	}
	parts := strings.SplitN(peerAID, ".", 2)
	peerIssuer := parts[1]

	re := regexp.MustCompile(`gateway\.([^:/]+)`)
	m := re.FindStringSubmatch(localGatewayURL)
	if len(m) < 2 {
		return localGatewayURL
	}
	localIssuer := m[1]
	if localIssuer == peerIssuer {
		return localGatewayURL
	}
	return strings.Replace(localGatewayURL, "gateway."+localIssuer, "gateway."+peerIssuer, 1)
}

// errCertNotFound 哨兵错误：PKI 证书端点返回 404 时使用，
// 供上层（如 AIDStore.Resolve）通过 errors.Is 区分"证书不存在"与"网络错误"。
var errCertNotFound = errors.New(ErrCodeCertNotFound)

func (c *AUNClient) fetchCertHTTP(ctx context.Context, certURL string, aid string) ([]byte, error) {
	transport := &http.Transport{}
	if !c.configModel.VerifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
	if err != nil {
		return nil, NewAuthError(fmt.Sprintf("创建证书请求失败: %v", err))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, NewAuthError(fmt.Sprintf("获取证书失败 (%s): %v", aid, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// 404 表示证书不存在，包装哨兵错误供上层映射为 CERT_NOT_FOUND
		return nil, fmt.Errorf("%w: 证书不存在 (%s)", errCertNotFound, aid)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, NewAuthError(fmt.Sprintf("获取证书失败 (%s): HTTP %d", aid, resp.StatusCode))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewAuthError(fmt.Sprintf("读取证书响应失败 (%s): %v", aid, err))
	}
	return body, nil
}

func certSHA256Fingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("invalid PEM certificate")
	}
	fp := sha256.Sum256(block.Bytes)
	return "sha256:" + fmt.Sprintf("%x", fp[:]), nil
}

// spkiSHA256Fingerprint 计算证书的 SubjectPublicKeyInfo SHA-256 指纹
// （H7：CA 同时接受 DER 证书指纹与 SPKI 指纹两种格式）
func spkiSHA256Fingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("invalid PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return "", fmt.Errorf("missing RawSubjectPublicKeyInfo")
	}
	fp := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + fmt.Sprintf("%x", fp[:]), nil
}

// matchCertFingerprint 检查证书指纹是否匹配（DER 或 SPKI 任一即可）
func matchCertFingerprint(certPEM []byte, expectedFP string) bool {
	expected := strings.TrimSpace(strings.ToLower(expectedFP))
	if expected == "" {
		return true
	}
	if !strings.HasPrefix(expected, "sha256:") {
		return false
	}
	if derFP, err := certSHA256Fingerprint(certPEM); err == nil && derFP == expected {
		return true
	}
	if spkiFP, err := spkiSHA256Fingerprint(certPEM); err == nil && spkiFP == expected {
		return true
	}
	return false
}

// sleepWithCancel 可取消的 sleep
func sleepWithCancel(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (c *AUNClient) saveGroupIdentityToV2(groupAID string, identity map[string]any) error {
	groupAID = strings.TrimSpace(groupAID)
	privateKeyPEM := strings.TrimSpace(stringFromAny(identity["private_key_pem"]))
	publicKeyB64 := strings.TrimSpace(stringFromAny(identity["public_key_der_b64"]))
	if groupAID == "" || privateKeyPEM == "" || publicKeyB64 == "" {
		return NewStateError("group identity is incomplete")
	}
	publicKeyDER, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(publicKeyDER) == 0 {
		return NewStateError(fmt.Sprintf("group identity public key is invalid: %v", err))
	}

	c.mu.RLock()
	ownerAID := c.aid
	deviceID := c.deviceID
	aunPath := ""
	if c.configModel != nil {
		aunPath = c.configModel.AUNPath
	}
	if c.currentAIDObj != nil {
		if ownerAID == "" {
			ownerAID = c.currentAIDObj.Aid
		}
		if deviceID == "" {
			deviceID = c.currentAIDObj.DeviceID
		}
		if aunPath == "" {
			aunPath = c.currentAIDObj.AunPath
		}
	}
	c.mu.RUnlock()

	if ownerAID == "" {
		return NewStateError("group identity storage requires a loaded owner AID")
	}
	if deviceID == "" {
		return NewStateError("group identity storage requires a device_id")
	}
	store, err := openV2Keystore(aunPath, ownerAID)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.store.SaveGroupIdentity(deviceID, groupAID, privateKeyPEM, publicKeyDER)
}

// createNamedGroup 创建命名群：本地生成 P-256 keypair，调用 group.create 传入 public_key。
// 群身份私钥不是 AID 身份私钥，写入 V2 设备密钥库，不写入 AID KeyStore。
func (c *AUNClient) createNamedGroup(ctx context.Context, groupName string, opts map[string]any) (result map[string]any, err error) {
	tStart := time.Now()
	c.logEG.Debug("createNamedGroup enter: name=%s", groupName)
	defer func() {
		if err != nil {
			c.logEG.Debug("createNamedGroup exit (error): name=%s elapsed=%dms err=%v", groupName, time.Since(tStart).Milliseconds(), err)
		} else {
			c.logEG.Debug("createNamedGroup exit: name=%s elapsed=%dms", groupName, time.Since(tStart).Milliseconds())
		}
	}()
	identity, err := c.crypto.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("生成群密钥对失败: %w", err)
	}

	params := make(map[string]any)
	for k, v := range opts {
		params[k] = v
	}
	params["group_name"] = groupName
	params["public_key"] = identity["public_key_der_b64"]
	params["curve"] = "P-256"

	raw, err := c.Call(ctx, "group.create", params)
	if err != nil {
		return nil, err
	}
	result, _ = raw.(map[string]any)
	if result == nil {
		err = fmt.Errorf("group.create 返回非 object")
		return nil, err
	}

	// 存储群 AID 证书和群身份私钥；群身份私钥走 V2 库，不走 AID KeyStore。
	groupInfo, _ := result["group"].(map[string]any)
	aidCert, _ := result["aid_cert"].(map[string]any)
	groupAid := stringFromAny(groupInfo["group_aid"])
	if groupAid != "" && aidCert != nil {
		if saveErr := c.saveGroupIdentityToV2(groupAid, identity); saveErr != nil {
			return nil, saveErr
		}
		certPEM := stringFromAny(aidCert["cert"])
		if certPEM != "" {
			_ = c.tokenStore.SaveCert(groupAid, certPEM)
		}
	}

	return result, nil
}

// bindGroupAid 为已有普通群绑定命名 AID（升级为命名群）。
func (c *AUNClient) bindGroupAid(ctx context.Context, groupID string, groupName string) (result map[string]any, err error) {
	tStart := time.Now()
	c.logEG.Debug("bindGroupAid enter: group=%s name=%s", groupID, groupName)
	defer func() {
		if err != nil {
			c.logEG.Debug("bindGroupAid exit (error): group=%s elapsed=%dms err=%v", groupID, time.Since(tStart).Milliseconds(), err)
		} else {
			c.logEG.Debug("bindGroupAid exit: group=%s elapsed=%dms", groupID, time.Since(tStart).Milliseconds())
		}
	}()
	identity, err := c.crypto.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("生成群密钥对失败: %w", err)
	}

	params := map[string]any{
		"group_id":   groupID,
		"group_name": groupName,
		"public_key": identity["public_key_der_b64"],
		"curve":      "P-256",
	}

	raw, err := c.Call(ctx, "group.bind_aid", params)
	if err != nil {
		return nil, err
	}
	result, _ = raw.(map[string]any)
	if result == nil {
		err = fmt.Errorf("group.bind_aid 返回非 object")
		return nil, err
	}

	groupInfo, _ := result["group"].(map[string]any)
	aidCert, _ := result["aid_cert"].(map[string]any)
	groupAid := stringFromAny(groupInfo["group_aid"])
	if groupAid != "" && aidCert != nil {
		if saveErr := c.saveGroupIdentityToV2(groupAid, identity); saveErr != nil {
			return nil, saveErr
		}
		certPEM := stringFromAny(aidCert["cert"])
		if certPEM != "" {
			_ = c.tokenStore.SaveCert(groupAid, certPEM)
		}
	}

	return result, nil
}

// ── 新版 AUNClient 构造函数（重构 API）────────────────────────

// NewAUNClient 是重构后的统一构造入口：客户端只接收一个已加载且私钥有效的 *AID，
// 全部运行配置（aun_path / verify_ssl / root_ca_path / debug）由 AID 携带，不再接收 options。
//   - aid 为 nil：返回无身份客户端（等价于 NewAUNClientEmpty）
//   - aid 非 nil：必须是 AIDStore.Load() 返回的、私钥有效的 *AID
func NewAUNClient(aid *AID) *AUNClient {
	if aid == nil {
		return newClient(map[string]any{})
	}
	return newAUNClientWithAID(aid)
}

func newAUNClientWithAID(aid *AID) *AUNClient {
	if !aid.IsPrivateKeyValid() {
		panic("NewAUNClient: aid must have a valid private key; use AIDStore.Load() first")
	}
	cfg := map[string]any{
		"aun_path":   aid.AunPath,
		"verify_ssl": aid.VerifySSL,
	}
	if aid.RootCaPath != "" {
		cfg["root_ca_path"] = aid.RootCaPath
	}
	c := newClient(cfg, aid.Debug)
	c.mu.Lock()
	c.currentAIDObj = aid
	c.aid = aid.Aid
	c.authenticated = false
	if aid.DeviceID != "" {
		c.deviceID = aid.DeviceID
	}
	if aid.SlotID != "" {
		c.slotID = aid.SlotID
	}
	if c.auth != nil {
		c.auth.aid = aid.Aid
		c.auth.SetInstanceContext(c.deviceID, c.slotID)
		c.auth.SetIdentity(map[string]any{
			"aid":                aid.Aid,
			"private_key_pem":    aid.PrivateKeyPem,
			"public_key_der_b64": aid.PublicKey,
			"cert":               aid.CertPem,
		})
	}
	c.identity = map[string]any{
		"aid":                aid.Aid,
		"private_key_pem":    aid.PrivateKeyPem,
		"public_key_der_b64": aid.PublicKey,
		"cert":               aid.CertPem,
	}
	c.mu.Unlock()
	return c
}

// NewAUNClientEmpty 创建无身份的客户端，初始状态为 idle。
func NewAUNClientEmpty() *AUNClient {
	return newClient(map[string]any{})
}

// CurrentAID 返回当前加载的 AID 对象（无身份时返回 nil）
func (c *AUNClient) CurrentAID() *AID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentAIDObj
}

// HasIdentity 是否已加载身份
func (c *AUNClient) HasIdentity() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentAIDObj != nil && c.state != StateClosed
}

// CanSign 是否可以签名
func (c *AUNClient) CanSign() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentAIDObj != nil && c.currentAIDObj.IsPrivateKeyValid() && c.state != StateClosed
}

// CanConnect 是否可以连接
func (c *AUNClient) CanConnect() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentAIDObj != nil && c.state != StateClosed
}

// CanSend 是否可以发送消息（已就绪）
func (c *AUNClient) CanSend() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == StateConnected
}

// IsReady 是否已就绪（等同 CanSend）
func (c *AUNClient) IsReady() bool { return c.CanSend() }

// IsOnline 是否在线（connected / reconnecting）
func (c *AUNClient) IsOnline() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == StateConnected || c.state == StateReconnecting
}

// IsClosed 是否已关闭
func (c *AUNClient) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == StateClosed
}

// AunPath 返回 AUN 数据目录路径
func (c *AUNClient) AunPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.currentAIDObj != nil {
		return c.currentAIDObj.AunPath
	}
	return c.configModel.AUNPath
}

// NextRetryAt 返回下次重试时间（仅重连退避状态下有值）
func (c *AUNClient) NextRetryAt() *time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.state != StateReconnecting {
		return nil
	}
	if c.nextRetryAt.IsZero() {
		return nil
	}
	t := c.nextRetryAt
	return &t
}

// RetryAttempt 返回当前重试次数
func (c *AUNClient) RetryAttempt() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.retryAttempt
}

// LastConnectError 返回最近一次连接错误
func (c *AUNClient) LastConnectError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastConnectError
}

// LastError 返回最近一次连接错误（LastConnectError 的别名，与 Python SDK 对齐）
func (c *AUNClient) LastError() error {
	return c.LastConnectError()
}

// LastErrorCode 返回最近一次连接错误的错误码字符串（无错误时返回空字符串）。
// 按错误类型映射为稳定的语义码，与 Python SDK last_error_code 的字符串语义对齐。
func (c *AUNClient) LastErrorCode() string {
	c.mu.RLock()
	err := c.lastConnectError
	c.mu.RUnlock()
	if err == nil {
		return ""
	}
	switch err.(type) {
	case *ConnectionError:
		return "connection_error"
	case *TimeoutError:
		return "timeout_error"
	case *AuthError:
		return "auth_error"
	case *PermissionError:
		return "permission_error"
	case *ValidationError:
		return "validation_error"
	case *StateError:
		return "state_error"
	case *SessionError:
		return "session_error"
	case *RateLimitError:
		return "rate_limit_error"
	case *NotFoundError:
		return "not_found_error"
	default:
		// 回退：取错误类型名，保证非空
		return fmt.Sprintf("%T", err)
	}
}

// NextRetryInSeconds 返回距下次重连的剩余秒数（非重连退避状态返回 0）
func (c *AUNClient) NextRetryInSeconds() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.state != StateReconnecting || c.nextRetryAt.IsZero() {
		return 0
	}
	secs := time.Until(c.nextRetryAt).Seconds()
	if secs < 0 {
		return 0
	}
	return secs
}

// RetryMaxAttempts 返回重连最大次数配置（0 表示无限重试）
func (c *AUNClient) RetryMaxAttempts() int {
	c.mu.RLock()
	opts := c.sessionOptions
	c.mu.RUnlock()
	if opts == nil {
		return 0
	}
	retry, _ := opts["retry"].(map[string]any)
	if retry == nil {
		return 0
	}
	if v, ok := retry["max_attempts"].(float64); ok && v > 0 {
		return int(v)
	}
	return 0
}

// protectedHeaderKeyRe 合法 protected_headers key 规则：仅小写字母、数字、下划线、连字符
var protectedHeaderKeyRe = regexp.MustCompile(`^[a-z0-9_-]+$`)

// SetProtectedHeaders 设置实例级 protected_headers，自动合并到 message.send/group.send/thought.put。
// 过滤 _auth 保留键及不符合 [a-z0-9_-] 规则的 key（静默跳过）。
func (c *AUNClient) SetProtectedHeaders(headers map[string]string) {
	filtered := make(map[string]string, len(headers))
	for k, v := range headers {
		if k == "_auth" {
			continue
		}
		if !protectedHeaderKeyRe.MatchString(k) {
			continue
		}
		filtered[k] = v
	}
	c.mu.Lock()
	c.instanceProtectedHeaders = filtered
	c.mu.Unlock()
}

// CachePeer 缓存对端 AID（要求证书有效）。
func (c *AUNClient) CachePeer(aid *AID) (*AID, error) {
	if !c.HasIdentity() {
		return nil, NewStateError("CachePeer requires a loaded identity")
	}
	if aid == nil || !aid.IsCertValid() {
		return nil, NewValidationError("CachePeer requires an AID with a valid certificate")
	}
	c.peerCacheMu.Lock()
	c.peerCache[aid.Aid] = aid
	c.peerCacheMu.Unlock()
	return aid, nil
}

// GetPeer 从缓存读取对端 AID。
func (c *AUNClient) GetPeer(aid string) *AID {
	if !c.HasIdentity() {
		return nil
	}
	c.peerCacheMu.RLock()
	defer c.peerCacheMu.RUnlock()
	return c.peerCache[strings.TrimSpace(aid)]
}

// LookupPeer 先查缓存，未命中则通过 AIDStore 解析。
func (c *AUNClient) LookupPeer(ctx context.Context, aid string) (*AID, error) {
	if !c.HasIdentity() {
		return nil, NewStateError("LookupPeer requires a loaded identity")
	}
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, NewValidationError("LookupPeer requires non-empty aid")
	}
	if cached := c.GetPeer(target); cached != nil {
		return cached, nil
	}
	store := NewAIDStore(c.configModel.AUNPath, c.configModel.SeedPassword)
	defer store.Close()
	r := store.Resolve(ctx, target, AIDStoreResolveOptions{SkipAgentMD: true})
	if !r.Ok {
		return nil, fmt.Errorf("%s: %s", r.Error.Code, r.Error.Message)
	}
	peer := r.Data.AID
	if !peer.IsCertValid() {
		return nil, NewAUNError(fmt.Sprintf("resolved peer certificate is invalid: %s", target))
	}
	c.peerCacheMu.Lock()
	c.peerCache[peer.Aid] = peer
	c.peerCacheMu.Unlock()
	return peer, nil
}

// Peers 返回所有缓存的对端 AID（按 aid 排序）。
func (c *AUNClient) Peers() []*AID {
	c.peerCacheMu.RLock()
	defer c.peerCacheMu.RUnlock()
	result := make([]*AID, 0, len(c.peerCache))
	for _, v := range c.peerCache {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Aid < result[j].Aid })
	return result
}

// GetProtectedHeaders 返回实例级 protected_headers 的副本
func (c *AUNClient) GetProtectedHeaders() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.instanceProtectedHeaders) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(c.instanceProtectedHeaders))
	for k, v := range c.instanceProtectedHeaders {
		out[k] = v
	}
	return out
}

// protectedHeadersMergeMethods 需要自动合并实例级 protected_headers 的方法集合
var protectedHeadersMergeMethods = map[string]bool{
	"message.send":        true,
	"group.send":          true,
	"message.thought.put": true,
	"group.thought.put":   true,
}

// mergeInstanceProtectedHeaders 将实例级 protected_headers 合并到 params["protected_headers"]。
// 仅对指定方法生效；调用方显式传入的同名 key 优先保留。
func (c *AUNClient) mergeInstanceProtectedHeaders(method string, params map[string]any) {
	if !protectedHeadersMergeMethods[method] {
		return
	}
	c.mu.RLock()
	instance := c.instanceProtectedHeaders
	c.mu.RUnlock()
	if len(instance) == 0 {
		return
	}

	// 读取调用方已有的 protected_headers（支持 map[string]any / map[string]string）
	merged := make(map[string]any)
	switch existing := params["protected_headers"].(type) {
	case map[string]any:
		for k, v := range existing {
			merged[k] = v
		}
	case map[string]string:
		for k, v := range existing {
			merged[k] = v
		}
	}

	// 实例级仅补充缺失键，不覆盖调用方显式传入的值
	for k, v := range instance {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
	params["protected_headers"] = merged
}

// loadIdentityFromAID 是 LoadIdentity 的内部实现（仅允许在 idle/closed 状态调用）。
func (c *AUNClient) loadIdentityFromAID(aid *AID) error {
	if aid == nil || !aid.IsPrivateKeyValid() {
		return NewStateError("LoadIdentity requires an AID with a valid private key")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateIdle && c.state != StateClosed {
		return NewStateError(fmt.Sprintf("LoadIdentity not allowed in state %s", c.state))
	}
	// 让无身份客户端加载 AID 后切到该身份所属的 aun_path（对齐 Python _rebuild_runtime_for_identity）。
	c.rebuildRuntimeForIdentity(aid)
	c.currentAIDObj = aid
	c.aid = aid.Aid
	if aid.DeviceID != "" {
		c.deviceID = aid.DeviceID
	}
	if aid.SlotID != "" {
		c.slotID = aid.SlotID
	}
	if c.auth != nil {
		c.auth.aid = aid.Aid
		c.auth.SetInstanceContext(c.deviceID, c.slotID)
		// 注入内存私钥到 AuthFlow，禁止 AuthFlow 内部再走 keystore 解密
		c.auth.SetIdentity(map[string]any{
			"aid":                aid.Aid,
			"private_key_pem":    aid.PrivateKeyPem,
			"public_key_der_b64": aid.PublicKey,
			"cert":               aid.CertPem,
		})
	}
	c.identity = map[string]any{
		"aid":                aid.Aid,
		"private_key_pem":    aid.PrivateKeyPem,
		"public_key_der_b64": aid.PublicKey,
		"cert":               aid.CertPem,
	}
	c.lastConnectError = nil
	c.retryAttempt = 0
	// Fix-05: 复位 state 到 idle，使 HasIdentity/ConnectionState 正确反映 standby
	c.state = StateIdle
	return nil
}

// rebuildRuntimeForIdentity 当 AID 携带的 aun_path/verify_ssl 与当前 client 不一致时，
// 重建依赖这些配置的运行时组件（logger / keystore / dnsNet / discovery / auth）。
// 仅在配置确实变化时重建，避免无谓开销。调用方须持有 c.mu。
func (c *AUNClient) rebuildRuntimeForIdentity(aid *AID) {
	nextRaw := map[string]any{
		"aun_path":   aid.AunPath,
		"verify_ssl": aid.VerifySSL,
	}
	if aid.RootCaPath != "" {
		nextRaw["root_ca_path"] = aid.RootCaPath
	}
	nextCfg := ConfigFromMap(nextRaw)
	curPath := ""
	if c.configModel != nil {
		curPath = c.configModel.AUNPath
	}
	if curPath == nextCfg.AUNPath && c.auth != nil && c.auth.aid == aid.Aid {
		return
	}

	debugFlag := false
	if c.logger != nil {
		debugFlag = c.logger.Debug()
	}
	// 关闭旧的网络层（keystore 无显式 Close 需求）
	if c.dnsNet != nil {
		c.dnsNet.Close()
	}

	c.config = nextRaw
	c.configModel = nextCfg
	c.agentMDPath = filepath.Join(nextCfg.AUNPath, "AIDs")
	deviceID := c.deviceID
	if deviceID == "" {
		deviceID = nextCfg.DeviceID()
	}

	aunLogger := NewAUNLogger(debugFlag, nextCfg.AUNPath)
	aunLogger.BindDeviceID(deviceID)
	c.logger = aunLogger
	c.log = aunLogger.For("aun_core.client")
	c.logE2 = aunLogger.For("aun_core.e2ee")
	c.logEG = aunLogger.For("aun_core.e2ee-group")
	c.logAuS = aunLogger.For("aun_core.auth")
	keystore.SetLogger(aunLogger.For("aun_core.keystore"))
	namespace.SetLogger(aunLogger.For("aun_core.auth"))
	secretstore.SetLogger(aunLogger.For("aun_core.secret-store"))

	fks, err := keystore.NewFileKeyStore(nextCfg.AUNPath, nil, nextCfg.SeedPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aun_core.keystore] WARN LoadIdentity 重建 FileKeyStore 失败: %v, 使用空种子\n", err)
		fks, _ = keystore.NewFileKeyStore(nextCfg.AUNPath, nil, "")
	}
	c.tokenStore = fks

	dnsNet := NewDnsResilientNet(nextCfg.AUNPath, nextCfg.VerifySSL)
	c.dnsNet = dnsNet
	c.discovery = NewGatewayDiscovery(nextCfg.VerifySSL, dnsNet)
	c.auth = NewAuthFlow(AuthFlowConfig{
		TokenStore: c.tokenStore,
		Crypto:     c.crypto,
		AID:        aid.Aid,
		VerifySSL:  nextCfg.VerifySSL,
		RootCAPath: nextCfg.RootCAPath,
		DnsNet:     dnsNet,
	})
	c.auth.SetInstanceContext(deviceID, c.slotID)
	if c.transport != nil {
		c.transport.SetVerifySSL(nextCfg.VerifySSL)
		c.transport.SetDnsNet(dnsNet)
	}
}

// LoadIdentity 加载新身份。aid 必须是 AIDStore.Load 返回的 AID 对象。
func (c *AUNClient) LoadIdentity(aid *AID) error {
	return c.loadIdentityFromAID(aid)
}

// ConnectionState 返回对外的 9 态连接状态（由内部 ClientState 映射）。
// 与 Python SDK client.py 的 _public_state 对应。
func (c *AUNClient) ConnectionState() ConnectionState {
	c.mu.RLock()
	st := mapPublicConnectionState(c.state, c.currentAIDObj != nil, c.authenticated, c.nextRetryAt)
	c.mu.RUnlock()
	return st
}

func mapPublicConnectionState(st ClientState, hasIdentity bool, authenticated bool, nextRetryAt time.Time) ConnectionState {
	switch st {
	case StateIdle:
		if hasIdentity && authenticated {
			return ConnStateAuthenticated
		}
		if hasIdentity {
			return ConnStateStandby
		}
		return ConnStateNoIdentity
	case StateConnecting, StateAuthenticating:
		return ConnStateConnecting
	case StateConnected:
		return ConnStateReady
	case StateDisconnected:
		if !hasIdentity {
			return ConnStateNoIdentity
		}
		if hasIdentity && authenticated {
			return ConnStateAuthenticated
		}
		return ConnStateStandby
	case StateReconnecting:
		if !nextRetryAt.IsZero() && time.Now().Before(nextRetryAt) {
			return ConnStateRetryBackoff
		}
		return ConnStateReconnecting
	case StateTerminalFailed:
		return ConnStateConnectionFailed
	case StateClosed:
		return ConnStateClosed
	default:
		return ConnectionState(st)
	}
}
