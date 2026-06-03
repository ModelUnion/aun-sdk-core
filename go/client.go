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

// orderedReadyEntry 有序投递队列中一条已就绪（seq <= contiguous）的待发布消息。
type orderedReadyEntry struct {
	seq  int
	item pendingOrderedMessage
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
	clientRuntime   *clientRuntime
	identityRuntime *identityRuntimeManager
	peerDirectory   *peerDirectory
	lifecycle       *lifecycleController
	rpcPipeline     *rpcPipeline
	deliveryEngine  *messageDeliveryEngine
	v2E2EE          *v2E2EECoordinator
	groupState      *groupStateCoordinator
	crypto          *CryptoProvider
	tokenStore      keystore.TokenStore
	auth            *AuthFlow
	transport       *RPCTransport
	events          *EventDispatcher
	discovery       *GatewayDiscovery
	dnsNet          *DnsResilientNet

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

	// 在线未读 hint 队列：同一 group 只保留最后一条，延迟 drain 降低登录瞬时拉取压力
	onlineUnreadHintQueue        map[string]map[string]any
	onlineUnreadHintMu           sync.Mutex
	onlineUnreadHintDraining     bool
	onlineUnreadHintInitialDelay time.Duration
	onlineUnreadHintInterval     time.Duration

	// P2P 惰性同步标志：首次发送/收到 P2P 消息后标记 — 已废弃，由 fillP2pGap 在 connect 后异步触发，字段删除

	// 后台任务上下文
	ctx    context.Context
	cancel context.CancelFunc

	// 旧 namespace 仅作为内部适配实现，不再作为 AUNClient 公开字段暴露。
	authNamespace *namespace.AuthNamespace

	agentMDManager *AgentMdManager

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

	tokenStore, err := keystore.NewLocalTokenStore(cfg.AUNPath, nil, cfg.SeedPassword)
	if err != nil {
		// logger 尚未初始化，临时输出到 stderr
		fmt.Fprintf(os.Stderr, "[aun_core.keystore] WARN 创建默认 LocalTokenStore 失败: %v, 使用空种子\n", err)
		tokenStore, _ = keystore.NewLocalTokenStore(cfg.AUNPath, nil, "")
	}
	var ks keystore.TokenStore = tokenStore

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

	c := &AUNClient{
		config:                       rawConfig,
		configModel:                  cfg,
		state:                        StateIdle,
		deviceID:                     deviceID,
		slotID:                       slotID,
		aid:                          initAid,
		crypto:                       crypto,
		tokenStore:                   ks,
		auth:                         authFlow,
		events:                       events,
		dnsNet:                       dnsNet,
		discovery:                    NewGatewayDiscovery(cfg.VerifySSL, dnsNet),
		certCache:                    make(map[string]*cachedPeerCert),
		peerCache:                    make(map[string]*AID),
		connectDeliveryMode:          copyMapShallow(connectDeliveryMode),
		defaultConnectDeliveryMode:   copyMapShallow(connectDeliveryMode),
		seqTracker:                   NewSeqTracker(),
		gapFillDone:                  make(map[string]bool),
		pushedSeqs:                   make(map[string]map[int]bool),
		pendingOrderedMsgs:           make(map[string]map[int]pendingOrderedMessage),
		groupSynced:                  make(map[string]bool),
		onlineUnreadHintQueue:        make(map[string]map[string]any),
		onlineUnreadHintInitialDelay: 750 * time.Millisecond,
		onlineUnreadHintInterval:     50 * time.Millisecond,
		v2AutoProposeLocks:           make(map[string]*sync.Mutex),
		v2AutoProposeLastSnapshot:    make(map[string]string),
		v2SenderIKPending:            make(map[string]v2SenderIKPendingEntry),
		v2SenderIKFetching:           make(map[string]bool),
		heartbeatNudge:               make(chan struct{}, 1),
		pullGateStaleMs:              30000,
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
	c.clientRuntime = newClientRuntime(c)
	c.identityRuntime = newIdentityRuntimeManager(c.clientRuntime)
	c.peerDirectory = newPeerDirectory(c.clientRuntime)
	c.lifecycle = newLifecycleController(c.clientRuntime)
	c.rpcPipeline = newRpcPipeline(c.clientRuntime)
	c.deliveryEngine = newMessageDeliveryEngine(c.clientRuntime)
	c.v2E2EE = newV2E2EECoordinator(c.clientRuntime)
	c.groupState = newGroupStateCoordinator(c.clientRuntime)
	c.agentMDManager = newAgentMdManager(c, filepath.Join(cfg.AUNPath, "AIDs"))

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

// agentMD 返回 agent.md 运行时管理器。
func (c *AUNClient) agentMD() *AgentMdManager {
	if c.agentMDManager == nil {
		root := filepath.Join(c.configModel.AUNPath, "AIDs")
		c.agentMDManager = newAgentMdManager(c, root)
	}
	return c.agentMDManager
}

func (c *AUNClient) observeRPCMeta(meta map[string]any) {
	c.agentMD().ObserveRPCMeta(meta)
}

func (c *AUNClient) observeAgentMDFromEnvelope(envelope map[string]any) {
	c.agentMD().observeAgentMDFromEnvelope(envelope)
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
	if c.discovery == nil {
		return "", NewValidationError("gateway discovery unavailable")
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

func (c *AUNClient) resolveGatewayForPeerAID(ctx context.Context, aid string) (string, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		return "", NewValidationError("peer aid is required for gateway discovery")
	}
	if cached := strings.TrimSpace(c.AuthLoadCachedGatewayURL(target)); cached != "" {
		return cached, nil
	}
	issuer := target
	if parts := strings.SplitN(target, ".", 2); len(parts) > 1 {
		issuer = parts[1]
	}
	if c.discovery == nil {
		return "", NewValidationError("gateway discovery unavailable")
	}
	wellKnownURL := fmt.Sprintf("https://gateway.%s/.well-known/aun-gateway", issuer)
	discovered, err := c.discovery.Discover(ctx, wellKnownURL, 0)
	if err != nil {
		return "", err
	}
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
	return c.getLifecycleController().connect(ctx, opts...)
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
	return c.getLifecycleController().connectWithLoadedIdentity(ctx, opts)
}

// Authenticate 使用当前加载的 AID 完成两阶段认证并缓存 token，不建立长连接。
// 只允许在 standby 状态下调用。
func (c *AUNClient) Authenticate(ctx context.Context, opts ...ConnectOptions) (map[string]any, error) {
	return c.getLifecycleController().authenticate(ctx, opts...)
}

func (c *AUNClient) connectWithParams(ctx context.Context, params map[string]any, opts *ConnectOptions, allowReauth bool, requireAccessToken bool) (err error) {
	return c.getLifecycleController().connectWithParams(ctx, params, opts, allowReauth, requireAccessToken)
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

	preflight, err := c.getRpcPipeline().preflight(method, params)
	if err != nil {
		return nil, err
	}
	params = preflight.params
	pullGateLocked := truthyBool(params["_pull_gate_locked"])
	delete(params, "_pull_gate_locked")
	pullGateKey := c.getRpcPipeline().pullGateKeyForCall(method, params)
	if pullGateKey != "" && !pullGateLocked {
		lockedParams := copyRpcParams(params)
		lockedParams["_pull_gate_locked"] = true
		return c.getRpcPipeline().runPullSerialized(ctx, pullGateKey, func() (any, error) {
			return c.Call(ctx, method, lockedParams)
		})
	}

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
	if err := c.getRpcPipeline().applyClientSignature(method, params); err != nil {
		return nil, err
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
	if pullGateKey != "" && !pullGateLocked {
		gatedResult, gatedErr := c.getRpcPipeline().runPullSerialized(callCtx, pullGateKey, func() (any, error) {
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

	return c.getRpcPipeline().postprocessResult(ctx, method, params, result)
}

// signClientOperation 为关键操作附加客户端 ECDSA 签名。
func (c *AUNClient) signClientOperation(method string, params map[string]any) error {
	return c.getRpcPipeline().signClientOperation(method, params)
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

// ── 事件处理 ──────────────────────────────────────────────

func isInstanceScopedMessageEvent(event string) bool {
	switch event {
	case "message.received", "message.recalled", "message.undecryptable",
		"group.message_created", "group.message_undecryptable":
		return true
	default:
		return false
	}
}

func (c *AUNClient) attachCurrentInstanceContext(payload any) any {
	return c.delivery().attachCurrentInstanceContext(payload)
}

func (c *AUNClient) normalizePublishedMessagePayload(event string, payload any) any {
	return c.delivery().normalizePublishedMessagePayload(event, payload)
}

func (c *AUNClient) publishAppEvent(event string, payload any) {
	c.delivery().publishAppEvent(event, payload)
}

func (c *AUNClient) publishAppEventSync(event string, payload any) {
	c.delivery().publishAppEventSync(event, payload)
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
	localEtag, remoteEtag := c.agentMD().eventSnapshot()
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
	return c.delivery().messageTargetsCurrentInstance(message)
}

func (c *AUNClient) publishEncryptedPushAsUndecryptable(eventName, ns string, seq int, msg map[string]any, group bool) bool {
	return c.getV2E2EECoordinator().publishEncryptedPushAsUndecryptable(eventName, ns, seq, msg, group)
}

func (c *AUNClient) decryptEncryptedPushPayload(msg map[string]any, group bool) map[string]any {
	return c.getV2E2EECoordinator().decryptEncryptedPushPayload(msg, group)
}

func (c *AUNClient) publishEncryptedPushMessage(normalEvent, undecryptableEvent, ns string, seq int, msg map[string]any, group bool) bool {
	return c.getV2E2EECoordinator().publishEncryptedPushMessage(normalEvent, undecryptableEvent, ns, seq, msg, group)
}

// onRawMessageReceived 处理 transport 层推送的原始消息
func (c *AUNClient) onRawMessageReceived(data any) {
	c.delivery().onRawMessageReceived(data)
}

// processAndPublishMessage 实际处理推送消息的 goroutine
func (c *AUNClient) processAndPublishMessage(data any) {
	c.delivery().processAndPublishMessage(data)
}

// onRawGroupMessageCreated 处理群组消息推送
func (c *AUNClient) onRawGroupMessageCreated(data any) {
	c.delivery().onRawGroupMessageCreated(data)
}

// processAndPublishGroupMessage 处理群组推送消息的 goroutine
//
// 带 payload 的事件（消息推送）：解密后 re-publish。
// 不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。
func (c *AUNClient) processAndPublishGroupMessage(data any) {
	c.delivery().processAndPublishGroupMessage(data)
}

// autoPullGroupMessages 收到不带 payload 的通知后自动 pull 最新消息
func (c *AUNClient) autoPullGroupMessages(notification map[string]any) {
	c.delivery().autoPullGroupMessages(notification)
}

// fillGroupGap 后台补齐群消息空洞
func (c *AUNClient) fillGroupGap(groupID string) {
	c.delivery().fillGroupGap(groupID)
}

// lazySyncGroup 惰性同步：首次激活群时 pull 最近消息，建立 seq 基线。
func (c *AUNClient) lazySyncGroup(groupID string) {
	c.delivery().lazySyncGroup(groupID)
}

// fillGroupEventGap 后台补齐群事件空洞
func (c *AUNClient) fillGroupEventGap(groupID string) {
	c.delivery().fillGroupEventGap(groupID)
}

// fillP2pGap 后台补齐 P2P 消息空洞
func (c *AUNClient) fillP2pGap() {
	c.delivery().fillP2pGap()
}

// prunePushedSeqs 只按硬上限裁剪 published guard。
// 不能按 contiguousSeq 清理：pull/补洞可能在 cursor 推进后再次拿到旧消息，
// 去重状态必须保留，否则会重复 publish。
func (c *AUNClient) prunePushedSeqs(ns string) {
	c.delivery().prunePushedSeqs(ns)
}

// markPushedSeq 在锁内安全标记指定 ns 的 seq 已发布到应用层。
func (c *AUNClient) markPushedSeq(ns string, seq int) {
	c.delivery().markPushedSeq(ns, seq)
}

// isPushedSeq 在锁内安全查询指定 ns 的 seq 是否已通过推送路径分发。
// 不取出内层 map 引用，避免锁外读写竞态。
func (c *AUNClient) isPushedSeq(ns string, seq int) bool {
	return c.delivery().isPushedSeq(ns, seq)
}

// clampAckSeq 在所有 ack 出口前做本地边界保护。
//
// 上界来自 push/pull 维护的 maxSeenSeq；这样本地脏 contiguousSeq 不会被回传给服务端。
// 下界固定为 0，避免负数/恶意值进入 RPC 参数。
func (c *AUNClient) clampAckSeq(method, field, ns string, seq int64) int64 {
	return c.delivery().clampAckSeq(method, field, ns, seq)
}

func (c *AUNClient) clampAckParams(method string, params map[string]any) {
	c.getRpcPipeline().clampAckParams(method, params)
}

func (c *AUNClient) enqueueOrderedMessage(ns, event string, seq int, payload any) {
	c.delivery().enqueueOrderedMessage(ns, event, seq, payload)
}

func (c *AUNClient) popReadyOrderedMessages(ns string, beforeSeq int) []struct {
	seq  int
	item pendingOrderedMessage
} {
	ready := make([]struct {
		seq  int
		item pendingOrderedMessage
	}, 0)
	for _, entry := range c.delivery().popReadyOrderedMessages(ns, beforeSeq) {
		ready = append(ready, struct {
			seq  int
			item pendingOrderedMessage
		}{seq: entry.seq, item: entry.item})
	}
	return ready
}

func (c *AUNClient) removePendingOrderedSeq(ns string, seq int) {
	c.delivery().removePendingOrderedSeq(ns, seq)
}

func (c *AUNClient) drainOrderedMessages(ns string, beforeSeq ...int) {
	c.delivery().drainOrderedMessages(ns, beforeSeq...)
}

func (c *AUNClient) publishOrderedMessage(event, ns string, seq int, payload any) bool {
	return c.delivery().publishOrderedMessage(event, ns, seq, payload)
}

// publishPulledMessage 发布 pull 批中的消息，只做 seq 级去重，不受 contiguous gate 限制。
// pull 返回的批内部空洞可能是永久空洞，不能因此阻塞批内后续消息投递。
func (c *AUNClient) publishPulledMessage(event, ns string, seq int, payload any) bool {
	return c.delivery().publishPulledMessage(event, ns, seq, payload)
}

// publishGapFillMessages 补洞路径发布 P2P 消息，跳过已发布到应用层的 seq。
// 使用 isPushedSeq 逐条检查，避免取出内层 map 引用后在锁外读取的竞态。
func (c *AUNClient) publishGapFillMessages(ns string, messages []any) {
	c.delivery().publishGapFillMessages(ns, messages)
}

// publishGapFillGroupMessages 补洞路径发布群消息，跳过已发布到应用层的 seq。
func (c *AUNClient) publishGapFillGroupMessages(ns string, messages []any) {
	c.delivery().publishGapFillGroupMessages(ns, messages)
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

	c.delivery().handleGroupChangedEventSeq(dataMap, groupID)

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
		c.getV2E2EECoordinator().deleteGroupBootstrapCache(groupID)
		c.logEG.Info("group %s dissolved, cleaned up local V2 group runtime state and seq tracker", groupID)
	}
}

// onRawGroupStateCommitted 处理 event/group.state_committed：验证 state_hash 链并更新本地存储
func (c *AUNClient) onRawGroupStateCommitted(data any) {
	c.getGroupStateCoordinator().onRawGroupStateCommitted(data)
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
		if !matchCertFingerprint(cached.certBytes, expectedFP) {
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
	normalizedFingerprint := strings.TrimSpace(certFingerprint)
	if normalizedFingerprint != "" {
		bareKey := certCacheKey(aid, "")
		c.certCacheMu.RLock()
		bareCached := c.certCache[bareKey]
		c.certCacheMu.RUnlock()
		if bareCached != nil &&
			float64(time.Now().Unix()) < bareCached.refreshAfter &&
			matchCertFingerprint(bareCached.certBytes, normalizedFingerprint) {
			return bareCached.certBytes, nil
		}
	}

	c.mu.RLock()
	gatewayURL := c.gatewayURL
	c.mu.RUnlock()
	var peerGatewayURL string
	if gatewayURL == "" {
		peerGatewayURL, err = c.resolveGatewayForPeerAID(ctx, aid)
		if err != nil {
			return nil, err
		}
	} else {
		// 跨域时用 peer 所在域的 Gateway URL
		peerGatewayURL = resolvePeerGatewayURL(gatewayURL, aid)
	}
	cb, fetchErr := c.fetchCertHTTP(ctx, buildCertURL(peerGatewayURL, aid, certFingerprint), aid)
	if fetchErr != nil {
		err = fetchErr
		return nil, err
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
	// 如果请求时没带 fingerprint，计算实际 fingerprint 也缓存一份
	if strings.TrimSpace(certFingerprint) == "" {
		bareKey := certCacheKey(aid, "")
		c.certCache[bareKey] = entry
		if actualFP, fpErr := certSHA256Fingerprint(certBytes); fpErr == nil && actualFP != "" {
			fpKey := certCacheKey(aid, actualFP)
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
	bgSync := true
	if v, ok := c.sessionOptions["background_sync"].(bool); ok {
		bgSync = v
	}
	c.getV2E2EECoordinator().onConnected(ctx, bgSync)

	// connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压
	// 群消息按惰性触发，不在此处主动 pull
	// connect/reconnect 成功后自动触发一次 P2P gap fill，补齐离线期间积压
	// background_sync=false 时跳过（CLI 等短命令场景）
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
	c.onlineUnreadHintMu.Lock()
	c.onlineUnreadHintQueue = make(map[string]map[string]any)
	c.onlineUnreadHintDraining = false
	c.onlineUnreadHintMu.Unlock()
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
	c.onlineUnreadHintMu.Lock()
	c.onlineUnreadHintQueue = make(map[string]map[string]any)
	c.onlineUnreadHintDraining = false
	c.onlineUnreadHintMu.Unlock()
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
	c.delivery().restoreSeqTrackerState()
}

// migrateSeqStateGroupIDs 把 state 里 group_event:/group_msg: 前缀的老/污染 group_id 归一化。
// 冲突取 max；落盘删老 ns、写新 ns，避免下次启动重复迁移。
func (c *AUNClient) migrateSeqStateGroupIDs(aid, deviceID, slotID string, state map[string]int) map[string]int {
	return c.delivery().migrateSeqStateGroupIDs(aid, deviceID, slotID, state)
}

// saveSeqTrackerState 将 SeqTracker 状态保存到 keystore seq_tracker 表（每 namespace 一行）
func (c *AUNClient) saveSeqTrackerState() {
	c.delivery().saveSeqTrackerState()
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
	c.getRpcPipeline().normalizeOutboundMessagePayload(params, method)
}
func (c *AUNClient) validateOutboundCall(method string, params map[string]any) error {
	return c.getRpcPipeline().validateOutboundCall(method, params)
}

func (c *AUNClient) injectMessageCursorContext(method string, params map[string]any) error {
	return c.getRpcPipeline().injectMessageCursorContext(method, params)
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

func normalizeFingerprintHex(expectedFP string) string {
	expected := strings.TrimSpace(strings.ToLower(expectedFP))
	if expected == "" {
		return ""
	}
	if strings.HasPrefix(expected, "sha256:") {
		expected = strings.TrimPrefix(expected, "sha256:")
	}
	expected = strings.ReplaceAll(expected, ":", "")
	if len(expected) != 16 && len(expected) != 64 {
		return ""
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(expected) {
		return ""
	}
	return expected
}

// matchCertFingerprint 检查证书指纹是否匹配（DER 或 SPKI，完整或 16 位短格式任一即可）
func matchCertFingerprint(certPEM []byte, expectedFP string) bool {
	expectedHex := normalizeFingerprintHex(expectedFP)
	if expectedHex == "" {
		return false
	}
	derHex := ""
	if derFP, err := certSHA256Fingerprint(certPEM); err == nil {
		derHex = strings.TrimPrefix(derFP, "sha256:")
	}
	spkiHex := ""
	if spkiFP, err := spkiSHA256Fingerprint(certPEM); err == nil {
		spkiHex = strings.TrimPrefix(spkiFP, "sha256:")
	}
	if len(expectedHex) == 16 {
		return (len(derHex) >= 16 && derHex[:16] == expectedHex) ||
			(len(spkiHex) >= 16 && spkiHex[:16] == expectedHex)
	}
	return derHex == expectedHex || spkiHex == expectedHex
}

func matchPublicKeyFingerprint(certPEM []byte, expectedFP string) bool {
	expectedHex := normalizeFingerprintHex(expectedFP)
	if expectedHex == "" {
		return false
	}
	spkiHex := ""
	if spkiFP, err := spkiSHA256Fingerprint(certPEM); err == nil {
		spkiHex = strings.TrimPrefix(spkiFP, "sha256:")
	}
	if len(expectedHex) == 16 {
		return len(spkiHex) >= 16 && spkiHex[:16] == expectedHex
	}
	return spkiHex == expectedHex
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
	return c.getPeerDirectory().cachePeer(aid)
}

// GetPeer 从缓存读取对端 AID。
func (c *AUNClient) GetPeer(aid string) *AID {
	return c.getPeerDirectory().getPeer(aid)
}

// LookupPeer 先查缓存，未命中则通过当前客户端的 TokenStore/AuthFlow 解析。
func (c *AUNClient) LookupPeer(ctx context.Context, aid string) (*AID, error) {
	return c.getPeerDirectory().lookupPeer(ctx, aid)
}

// Peers 返回所有缓存的对端 AID（按 aid 排序）。
func (c *AUNClient) Peers() []*AID {
	return c.getPeerDirectory().peers()
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
	c.getRpcPipeline().mergeInstanceProtectedHeaders(method, params)
}

// loadIdentityFromAID 是 LoadIdentity 的内部实现（仅允许在 idle/closed 状态调用）。
func (c *AUNClient) loadIdentityFromAID(aid *AID) error {
	return c.getIdentityRuntime().loadIdentity(aid)
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
	c.agentMD().setAgentMDPath(filepath.Join(nextCfg.AUNPath, "AIDs"))
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

	tokenStore, err := keystore.NewLocalTokenStore(nextCfg.AUNPath, nil, nextCfg.SeedPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aun_core.keystore] WARN LoadIdentity 重建 LocalTokenStore 失败: %v, 使用空种子\n", err)
		tokenStore, _ = keystore.NewLocalTokenStore(nextCfg.AUNPath, nil, "")
	}
	c.tokenStore = tokenStore

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
