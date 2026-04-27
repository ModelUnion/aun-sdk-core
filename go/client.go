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
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthropics/aun-sdk-core/go/keystore"
	"github.com/anthropics/aun-sdk-core/go/namespace"
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
	groupRotationLeaseMS         = 120000
	groupRotationRetryMaxDelay   = 300 * time.Second
)

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

// ConnectOptions 连接选项
type ConnectOptions struct {
	AutoReconnect      bool           // 是否自动重连
	HeartbeatInterval  int            // 心跳间隔（秒），默认 30
	TokenRefreshBefore int            // token 到期前多少秒刷新，默认 60
	Retry              *RetryConfig   // 重试配置
	Timeouts           *TimeoutConfig // 超时配置
}

// RetryConfig 重试配置
type RetryConfig struct {
	InitialDelay float64 // 初始延迟（秒）
	MaxDelay     float64 // 最大延迟（秒）
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
	"group.send":                      true,
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
	"group.resources.put":             true,
	"group.resources.update":          true,
	"group.resources.delete":          true,
	"group.resources.request_add":     true,
	"group.resources.direct_add":      true,
	"group.resources.approve_request": true,
	"group.resources.reject_request":  true,
}

// 对端证书缓存 TTL（秒）
const peerCertCacheTTL = 600

// cachedPeerCert 缓存的对端证书条目
type cachedPeerCert struct {
	certBytes    []byte  // PEM 编码的证书
	validatedAt  float64 // PKI 验证通过的时间（Unix 秒）
	refreshAfter float64 // 缓存过期时间（Unix 秒）
}

type cachedPeerPrekeys struct {
	items    []map[string]any
	expireAt float64
}

// AUNClient AUN 协议客户端主类
// epochRecoveryResult 用于 epoch key recovery 的 singleflight 去重
type epochRecoveryResult struct {
	done chan struct{}
	ok   bool
}

type AUNClient struct {
	mu           sync.RWMutex
	config       map[string]any
	configModel  *AUNConfig
	state        ClientState
	aid          string
	identity     map[string]any
	gatewayURL   string
	deviceID     string
	slotID       string
	closing      atomic.Bool
	reconnecting atomic.Bool
	serverKicked atomic.Bool

	// 组件
	crypto    *CryptoProvider
	keyStore  keystore.KeyStore
	auth      *AuthFlow
	transport *RPCTransport
	events    *EventDispatcher
	discovery *GatewayDiscovery
	e2ee      *E2EEManager
	groupE2EE *GroupE2EEManager

	// 会话参数
	sessionParams  map[string]any
	sessionOptions map[string]any

	// 对端证书缓存
	certCache                  map[string]*cachedPeerCert
	certCacheMu                sync.RWMutex
	peerPrekeysCache           map[string]*cachedPeerPrekeys
	peerPrekeysMu              sync.RWMutex
	connectDeliveryMode        map[string]any
	defaultConnectDeliveryMode map[string]any
	prekeyReplenishInflight    map[string]bool
	prekeyReplenished          map[string]bool

	// 消息序列号跟踪器（群消息 + P2P 空洞检测）
	seqTracker        *SeqTracker
	seqTrackerContext string

	// 补洞去重：已完成/进行中的 key 集合，防止重复 pull 同一区间
	gapFillDone   map[string]bool
	gapFillDoneMu sync.Mutex

	// 推送路径已分发的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发
	pushedSeqs   map[string]map[int]bool
	pushedSeqsMu sync.Mutex

	// 群惰性同步标志：首次对群发消息/收到推送后标记，避免重复 pull
	groupSynced   map[string]bool
	groupSyncedMu sync.Mutex

	// P2P 惰性同步标志：首次发送/收到 P2P 消息后标记
	p2pSynced   bool
	p2pSyncedMu sync.Mutex

	// 群消息缺少 epoch key 时的待解队列
	pendingDecryptMsgs   map[string][]map[string]any
	pendingDecryptMsgsMu sync.Mutex

	groupEpochRotationInflight  map[string]bool
	groupEpochRotationMu        sync.Mutex
	groupMembershipRotationDone map[string]bool
	groupEpochRotationRetrying  map[string]bool

	// epoch key recovery inflight 去重（singleflight 模式）
	groupEpochRecoveryInflight   map[string]*epochRecoveryResult
	groupEpochRecoveryInflightMu sync.Mutex

	// 后台任务上下文
	ctx              context.Context
	cancel           context.CancelFunc
	prekeyUploadHook func(context.Context) error

	// Auth 命名空间
	Auth *namespace.AuthNamespace
	// AID 托管命名空间
	Custody *namespace.CustodyNamespace

	// 调试日志
	logger *AUNLogger
}

// NewClient 创建 AUN 客户端
func NewClient(config map[string]any, debug ...bool) *AUNClient {
	rawConfig := make(map[string]any)
	for k, v := range config {
		rawConfig[k] = v
	}
	cfg := ConfigFromMap(rawConfig)
	events := NewEventDispatcher()
	crypto := &CryptoProvider{}

	fks, err := keystore.NewFileKeyStore(cfg.AUNPath, nil, cfg.SeedPassword)
	if err != nil {
		log.Printf("创建默认 FileKeyStore 失败: %v, 使用空路径", err)
		fks, _ = keystore.NewFileKeyStore(cfg.AUNPath, nil, "")
	}
	var ks keystore.KeyStore = fks

	// 创建 AuthFlow
	authFlow := NewAuthFlow(AuthFlowConfig{
		Keystore:   ks,
		Crypto:     crypto,
		VerifySSL:  cfg.VerifySSL,
		RootCAPath: cfg.RootCAPath,
	})

	deviceID := cfg.DeviceID()
	slotID := ""
	connectDeliveryMode := normalizeDeliveryModeConfig(map[string]any{"mode": "fanout"})
	authFlow.SetInstanceContext(deviceID, slotID)
	authFlow.SetDeliveryMode(connectDeliveryMode)

	var aunLogger *AUNLogger
	if len(debug) > 0 && debug[0] {
		aunLogger = newAUNLogger()
		log.SetOutput(io.MultiWriter(os.Stderr, aunLogger))
		log.Printf("[aun_core] AUNClient 初始化完成 (debug=true, aunPath=%s)", cfg.AUNPath)
	}

	c := &AUNClient{
		config:                     rawConfig,
		configModel:                cfg,
		state:                      StateIdle,
		deviceID:                   deviceID,
		slotID:                     slotID,
		crypto:                     crypto,
		keyStore:                   ks,
		auth:                       authFlow,
		events:                     events,
		discovery:                  NewGatewayDiscovery(cfg.VerifySSL),
		certCache:                  make(map[string]*cachedPeerCert),
		peerPrekeysCache:           make(map[string]*cachedPeerPrekeys),
		connectDeliveryMode:        copyMapShallow(connectDeliveryMode),
		defaultConnectDeliveryMode: copyMapShallow(connectDeliveryMode),
		seqTracker:                 NewSeqTracker(),
		gapFillDone:                make(map[string]bool),
		pushedSeqs:                 make(map[string]map[int]bool),
		groupSynced:                make(map[string]bool),
		sessionOptions: map[string]any{
			"auto_reconnect":       true,
			"heartbeat_interval":   30.0,
			"token_refresh_before": 60.0,
			"retry": map[string]any{
				"initial_delay": 1.0,
				"max_delay":     64.0,
			},
			"timeouts": map[string]any{
				"connect": 5.0,
				"call":    10.0,
				"http":    30.0,
			},
		},
		pendingDecryptMsgs:          make(map[string][]map[string]any),
		groupEpochRotationInflight:  make(map[string]bool),
		groupMembershipRotationDone: make(map[string]bool),
		groupEpochRotationRetrying:  make(map[string]bool),
		groupEpochRecoveryInflight:  make(map[string]*epochRecoveryResult),
		prekeyReplenishInflight:     make(map[string]bool),
		prekeyReplenished:           make(map[string]bool),
		logger:                      aunLogger,
	}

	// 创建 RPCTransport（使用断线回调）
	c.transport = NewRPCTransport(events, 10*time.Second, func(err error, closeCode int) {
		c.handleTransportDisconnect(err, closeCode)
	}, cfg.VerifySSL)

	// 创建 E2EE 管理器
	c.e2ee = NewE2EEManager(E2EEManagerConfig{
		IdentityFn: func() map[string]any {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if c.identity != nil {
				return c.identity
			}
			return map[string]any{}
		},
		DeviceIDFn: func() string {
			c.mu.RLock()
			defer c.mu.RUnlock()
			return c.deviceID
		},
		Keystore:         ks,
		ReplayWindowSecs: cfg.ReplayWindowSeconds,
	})

	// 创建群组 E2EE 管理器
	c.groupE2EE = NewGroupE2EEManager(GroupE2EEManagerConfig{
		IdentityFn: func() map[string]any {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if c.identity != nil {
				return c.identity
			}
			return map[string]any{}
		},
		Keystore:              ks,
		Config:                cfg,
		SenderCertResolver:    func(aid, fingerprint string) string { return c.getVerifiedPeerCert(aid, fingerprint) },
		InitiatorCertResolver: func(aid, fingerprint string) string { return c.getVerifiedPeerCert(aid, fingerprint) },
	})

	// Auth 命名空间
	c.Auth = namespace.NewAuthNamespace(c)
	c.Custody = namespace.NewCustodyNamespace(c)

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
	// 其他事件直接透传
	events.Subscribe("_raw.message.recalled", func(payload any) {
		events.Publish("message.recalled", payload)
	})
	events.Subscribe("_raw.message.ack", func(payload any) {
		events.Publish("message.ack", payload)
	})
	// 服务端主动断开通知：记录日志并标记不重连
	events.Subscribe("_raw.gateway.disconnect", func(payload any) {
		c.onGatewayDisconnect(payload)
	})

	return c
}

// ── 属性访问 ──────────────────────────────────────────────

// AID 返回当前认证的 Agent ID
func (c *AUNClient) AID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.aid
}

// State 返回当前连接状态
func (c *AUNClient) State() ClientState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// E2EE 返回 P2P E2EE 管理器
func (c *AUNClient) E2EE() *E2EEManager {
	return c.e2ee
}

// GroupE2EE 返回群组 E2EE 管理器
func (c *AUNClient) GroupE2EE() *GroupE2EEManager {
	return c.groupE2EE
}

// ── namespace.ClientInterface 实现 ─────────────────────────

// GetGatewayURL 返回当前 Gateway URL
func (c *AUNClient) GetGatewayURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gatewayURL
}

// SetGatewayURL 设置 Gateway URL
func (c *AUNClient) SetGatewayURL(u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gatewayURL = u
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
		c.logger.setAID(aid)
	}
}

// GetConfigDiscoveryPort 返回发现端口
func (c *AUNClient) GetConfigDiscoveryPort() int {
	return c.configModel.DiscoveryPort
}

// GetConfigVerifySSL 返回是否验证 SSL
func (c *AUNClient) GetConfigVerifySSL() bool {
	return c.configModel.VerifySSL
}

// AuthCreateAID 通过 AuthFlow 创建 AID
func (c *AUNClient) AuthCreateAID(ctx context.Context, gatewayURL, aid string) (map[string]any, error) {
	return c.auth.CreateAID(ctx, gatewayURL, aid)
}

// AuthAuthenticate 通过 AuthFlow 认证 AID
func (c *AUNClient) AuthAuthenticate(ctx context.Context, gatewayURL, aid string) (map[string]any, error) {
	return c.auth.Authenticate(ctx, gatewayURL, aid)
}

// AuthLoadIdentityOrNil 通过 AuthFlow 加载身份，不存在返回 nil
func (c *AUNClient) AuthLoadIdentityOrNil(aid string) map[string]any {
	return c.auth.LoadIdentityOrNil(aid)
}

// DiscoverGateway 通过 GatewayDiscovery 发现 Gateway URL
func (c *AUNClient) DiscoverGateway(ctx context.Context, wellKnownURL string, timeout time.Duration) (string, error) {
	return c.discovery.Discover(ctx, wellKnownURL, timeout)
}

// CheckGatewayHealth 向 gatewayURL 的 /health 端点发送 GET 请求，检查网关可用性。
func (c *AUNClient) CheckGatewayHealth(ctx context.Context, gatewayURL string, timeout time.Duration) bool {
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

// Connect 连接到 AUN Gateway
func (c *AUNClient) Connect(ctx context.Context, auth map[string]any, opts *ConnectOptions) error {
	// 原子检查+状态转换，避免 TOCTOU 竞态
	// ISSUE-SDK-GO-009: 允许从 disconnected 状态重新连接
	c.mu.Lock()
	if c.state != StateIdle && c.state != StateClosed && c.state != StateDisconnected {
		st := c.state
		c.mu.Unlock()
		return NewStateError(fmt.Sprintf("connect 不允许在状态 %s 下调用", st))
	}
	c.state = StateConnecting
	c.mu.Unlock()

	// 合并参数
	params := make(map[string]any)
	for k, v := range auth {
		params[k] = v
	}
	if opts != nil {
		if opts.AutoReconnect {
			params["auto_reconnect"] = true
		}
		if opts.HeartbeatInterval > 0 {
			params["heartbeat_interval"] = float64(opts.HeartbeatInterval)
		}
		if opts.TokenRefreshBefore > 0 {
			params["token_refresh_before"] = float64(opts.TokenRefreshBefore)
		}
		if opts.Retry != nil {
			params["retry"] = map[string]any{
				"initial_delay": opts.Retry.InitialDelay,
				"max_delay":     opts.Retry.MaxDelay,
			}
		}
		if opts.Timeouts != nil {
			params["timeouts"] = map[string]any{
				"connect": opts.Timeouts.Connect,
				"call":    opts.Timeouts.Call,
			}
		}
	}

	// 规范化参数
	normalized, err := c.normalizeConnectParams(params)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.sessionParams = normalized
	c.sessionOptions = c.buildSessionOptions(normalized)
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

	return c.connectOnce(ctx, normalized, false)
}

// ListIdentities 列出本地所有具有有效私钥的身份摘要（对齐 Python list_identities）。
func (c *AUNClient) ListIdentities() ([]map[string]any, error) {
	type lister interface {
		ListIdentities() ([]string, error)
	}
	ks, ok := c.keyStore.(lister)
	if !ok {
		return nil, nil
	}
	aids, err := ks.ListIdentities()
	if err != nil {
		return nil, err
	}
	var summaries []map[string]any
	for _, aid := range aids {
		summary := map[string]any{"aid": aid}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

// Disconnect 主动断开连接但保留身份，可重新 Connect（ISSUE-GO-005）
func (c *AUNClient) Disconnect() error {
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
		log.Printf("Disconnect 关闭传输层失败: %v", err)
	}

	c.mu.Lock()
	c.state = StateDisconnected
	c.mu.Unlock()

	c.events.Publish("connection.state", map[string]any{"state": string(StateDisconnected)})
	return nil
}

// Logout 完全登出：断开连接、清除 token、关闭客户端（ISSUE-GO-005）
func (c *AUNClient) Logout() error {
	// 先断开连接
	_ = c.Disconnect()

	// 清除 token
	c.mu.RLock()
	aid := c.aid
	c.mu.RUnlock()

	if aid != "" {
		// 用空 token 覆盖保存，清除持久化的 token
		_ = c.keyStore.SaveIdentity(aid, map[string]any{
			"access_token":  "",
			"refresh_token": "",
			"kite_token":    "",
		})
	}

	return c.Close()
}

// Close 关闭客户端，取消所有后台任务
func (c *AUNClient) Close() error {
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
		if closer, ok := c.keyStore.(interface{ Close() }); ok {
			closer.Close()
		}
		c.mu.Lock()
		c.state = StateClosed
		c.resetSeqTrackingStateLocked()
		c.mu.Unlock()
		return nil
	}

	// 关闭传输层
	if err := c.transport.Close(); err != nil {
		log.Printf("关闭传输层失败: %v", err)
	}
	if closer, ok := c.keyStore.(interface{ Close() }); ok {
		closer.Close()
	}

	c.mu.Lock()
	c.state = StateClosed
	c.resetSeqTrackingStateLocked()
	c.mu.Unlock()

	c.events.Publish("connection.state", map[string]any{"state": string(StateClosed)})
	return nil
}

// ── RPC 调用 ──────────────────────────────────────────────

// Call 发送 RPC 调用（自动 E2EE 加解密）
func (c *AUNClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
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
	if err := c.validateOutboundCall(method, params); err != nil {
		return nil, err
	}
	if err := c.injectMessageCursorContext(method, params); err != nil {
		return nil, err
	}

	// group.* 方法注入 device_id（服务端用于多设备消息路由）
	if strings.HasPrefix(method, "group.") && c.deviceID != "" {
		if _, exists := params["device_id"]; !exists {
			params["device_id"] = c.deviceID
		}
	}
	if strings.HasPrefix(method, "group.") {
		if _, exists := params["slot_id"]; !exists {
			params["slot_id"] = c.slotID
		}
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
			return c.sendEncrypted(ctx, params)
		}
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
			return c.sendGroupEncrypted(ctx, params)
		}
	}

	// 关键操作自动附加客户端签名
	if signedMethods[method] {
		c.signClientOperation(method, params)
	}

	result, err := c.transport.Call(ctx, method, params)
	if err != nil {
		return nil, err
	}

	// 自动解密：message.pull 返回的消息
	if method == "message.pull" {
		if resultMap, ok := result.(map[string]any); ok {
			messages, _ := resultMap["messages"].([]any)
			if len(messages) > 0 {
				resultMap["messages"] = c.decryptMessages(ctx, messages)
			}
			// 更新 SeqTracker；server_ack_seq 即使空 pull 也必须生效。
			c.mu.RLock()
			myAID := c.aid
			c.mu.RUnlock()
			if myAID != "" {
				ns := "p2p:" + myAID
				var pullMsgs []map[string]any
				for _, raw := range messages {
					if m, ok := raw.(map[string]any); ok {
						pullMsgs = append(pullMsgs, m)
					}
				}
				if len(pullMsgs) > 0 {
					c.seqTracker.OnPullResult(ns, pullMsgs)
				}
				// ⚠️ 逻辑边界 L1/L3：P2P retention floor 通道 = server_ack_seq
				// 服务端在持久化/设备视图分支返回 server_ack_seq，客户端若 contiguous 落后必须 force 跳过
				// retention window 外的空洞。与 S2 [1,seq-1] 历史 gap 配合；若去掉 force，首条消息建的 gap 会
				// 永远悬挂触发无限 pull。临时消息淘汰走 ephemeral_earliest_available_seq（仅提示），与此互斥。
				serverAck := int(toInt64(resultMap["server_ack_seq"]))
				if serverAck > 0 {
					contig := c.seqTracker.GetContiguousSeq(ns)
					if contig < serverAck {
						log.Printf("[aun_core] message.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d", ns, contig, serverAck)
						c.seqTracker.ForceContiguousSeq(ns, serverAck)
					}
				}
				c.saveSeqTrackerState()
				// auto-ack contiguous_seq
				contig := c.seqTracker.GetContiguousSeq(ns)
				shouldAck := len(messages) > 0 || serverAck > 0
				if contig > 0 && shouldAck {
					go func() {
						ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer ackCancel()
						if _, ackErr := c.transport.Call(ackCtx, "message.ack", map[string]any{
							"seq":       contig,
							"device_id": c.deviceID,
						}); ackErr != nil {
							log.Printf("message.pull auto-ack 失败: %v", ackErr)
						}
					}()
				}
			}
		}
	}

	// 自动解密：group.pull 返回的群消息
	if method == "group.pull" {
		if resultMap, ok := result.(map[string]any); ok {
			messages, _ := resultMap["messages"].([]any)
			if len(messages) > 0 {
				resultMap["messages"] = c.decryptGroupMessages(ctx, messages)
			}
			// 更新 SeqTracker；cursor.current_seq 即使空 pull 也必须生效。
			gid, _ := params["group_id"].(string)
			if gid != "" {
				ns := "group:" + gid
				var pullMsgs []map[string]any
				for _, raw := range messages {
					if m, ok := raw.(map[string]any); ok {
						pullMsgs = append(pullMsgs, m)
					}
				}
				if len(pullMsgs) > 0 {
					c.seqTracker.OnPullResult(ns, pullMsgs)
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
							log.Printf("[aun_core] group.pull retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d", ns, contig, serverAck)
							c.seqTracker.ForceContiguousSeq(ns, serverAck)
						}
					}
				}
				c.saveSeqTrackerState()
				// auto-ack contiguous_seq
				contig := c.seqTracker.GetContiguousSeq(ns)
				shouldAck := len(messages) > 0 || serverAck > 0
				if contig > 0 && shouldAck {
					go func() {
						ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer ackCancel()
						if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
							"group_id":  gid,
							"msg_seq":   contig,
							"device_id": c.deviceID,
						}); ackErr != nil {
							log.Printf("group.pull auto-ack 失败: group=%s %v", gid, ackErr)
						}
					}()
				}
			}
		}
	}

	// ── Group E2EE 自动编排 ────────────────────────────────
	// 群组 E2EE 是必备能力，始终启用自动编排
	{
		c.orchestrateGroupE2EE(ctx, method, params, result)
	}

	return result, nil
}

// orchestrateGroupE2EE 群组 E2EE 自动编排（建群、加人、踢人等后自动处理密钥）
func (c *AUNClient) orchestrateGroupE2EE(ctx context.Context, method string, params map[string]any, result any) {
	resultMap, _ := result.(map[string]any)

	// 建群后自动创建 epoch
	if method == "group.create" && resultMap != nil {
		group, _ := resultMap["group"].(map[string]any)
		gid, _ := group["group_id"].(string)
		c.mu.RLock()
		myAID := c.aid
		c.mu.RUnlock()
		if gid != "" && myAID != "" && !c.groupE2EE.HasSecret(gid) {
			_, err := c.groupE2EE.CreateEpoch(gid, []string{myAID})
			if err != nil {
				c.logE2EEError("create_epoch", gid, "", err)
			} else {
				// 建群初始化必须在 group.create 返回前完成；否则调用方紧接着加成员时，
				// 初始 rotation 会因成员集变化被服务端拒绝提交。
				c.syncEpochToServer(ctx, gid)
			}
		}
	}

	// 成员集变更主要由 group.changed 事件驱动；RPC 成功返回路径做幂等兜底，避免事件丢失或延迟时不轮换。
	if isMembershipChangeMethod(method) && resultMap != nil {
		gid := extractGroupIDFromResult(resultMap)
		if gid == "" {
			gid = stringFromAny(params["group_id"])
		}
		if gid != "" && membershipRotationChanged(method, resultMap) {
			expectedEpoch := membershipRotationExpectedEpoch(resultMap)
			triggerID := membershipRotationTriggerID(gid, resultMap)
			go c.maybeLeadRotateGroupEpoch(context.Background(), gid, triggerID, expectedEpoch)
		}
	}

}

// signClientOperation 为关键操作附加客户端 ECDSA 签名
func (c *AUNClient) signClientOperation(method string, params map[string]any) {
	c.mu.RLock()
	identity := c.identity
	c.mu.RUnlock()
	if identity == nil {
		return
	}
	privPEM, _ := identity["private_key_pem"].(string)
	if privPEM == "" {
		return
	}

	aidStr, _ := identity["aid"].(string)
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
		log.Printf("客户端签名解析私钥失败: %v", err)
		return
	}
	hash := sha256.Sum256(signData)
	sig, err := ecdsa.SignASN1(cryptorand.Reader, pk, hash[:])
	if err != nil {
		log.Printf("客户端签名失败: %v", err)
		return
	}

	// 证书指纹
	certFingerprint := ""
	if certPEM, ok := identity["cert"].(string); ok && certPEM != "" {
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

// ── 自动加密发送 ────────────────────────────────────────────

// sendEncrypted 自动加密并发送 P2P 消息
func (c *AUNClient) sendEncrypted(ctx context.Context, params map[string]any) (any, error) {
	toAID, _ := params["to"].(string)
	if err := validateMessageRecipient(toAID); err != nil {
		return nil, err
	}
	payload, _ := params["payload"].(map[string]any)
	if payload == nil {
		return nil, NewValidationError("message.send payload must be an object when encrypt=true")
	}
	messageID, _ := params["message_id"].(string)
	if messageID == "" {
		messageID = generateUUID4()
	}
	timestamp := toInt64(params["timestamp"])
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}
	persistRequired := truthyBool(params["persist_required"]) || truthyBool(params["durable"])

	// 惰性同步：首次发送 P2P 消息时先 pull 一次，确保 seq 状态就绪
	c.p2pSyncedMu.Lock()
	synced := c.p2pSynced
	c.p2pSyncedMu.Unlock()
	if !synced {
		c.lazySyncP2p()
	}

	recipientPrekeys, err := c.fetchPeerPrekeys(ctx, toAID)
	if err != nil {
		return nil, err
	}
	selfSyncCopies, err := c.buildSelfSyncCopies(ctx, toAID, payload, messageID, timestamp)
	if err != nil {
		return nil, err
	}
	if len(recipientPrekeys) <= 1 && len(selfSyncCopies) == 0 {
		var prekey map[string]any
		if len(recipientPrekeys) == 1 {
			prekey = recipientPrekeys[0]
		}
		return c.sendEncryptedSingle(ctx, toAID, payload, messageID, timestamp, prekey, persistRequired)
	}
	recipientCopies, err := c.buildRecipientDeviceCopies(ctx, toAID, payload, messageID, timestamp, recipientPrekeys)
	if err != nil {
		return nil, err
	}
	sendParams := map[string]any{
		"to": toAID,
		"payload": map[string]any{
			"type":               "e2ee.multi_device",
			"logical_message_id": messageID,
			"recipient_copies":   recipientCopies,
			"self_copies":        selfSyncCopies,
		},
		"type":       "e2ee.multi_device",
		"encrypted":  true,
		"message_id": messageID,
		"timestamp":  timestamp,
	}
	if persistRequired {
		sendParams["persist_required"] = true
	}
	result, err := c.transport.Call(ctx, "message.send", sendParams)
	if err != nil {
		log.Printf("[aun_core] 警告: E2EE 多设备消息发送失败，prekey 已消耗不可回滚 (to=%s, copies=%d): %v", toAID, len(recipientCopies), err)
	}
	return result, err
}

func (c *AUNClient) sendEncryptedSingle(
	ctx context.Context,
	toAID string,
	payload map[string]any,
	messageID string,
	timestamp int64,
	prekey map[string]any,
	persistRequired bool,
) (any, error) {
	var err error
	if prekey == nil {
		prekey, err = c.fetchPeerPrekey(ctx, toAID)
		if err != nil {
			return nil, err
		}
	}
	peerCertFingerprint := strings.TrimSpace(strings.ToLower(getStr(prekey, "cert_fingerprint", "")))
	peerCertPEM, err := c.fetchPeerCert(ctx, toAID, peerCertFingerprint)
	if err != nil {
		return nil, err
	}
	envelope, encryptResult, err := c.encryptCopyPayload(toAID, payload, peerCertPEM, prekey, messageID, timestamp)
	if err != nil {
		return nil, err
	}
	if err := c.ensureEncryptResult(toAID, encryptResult); err != nil {
		return nil, err
	}
	sendParams := map[string]any{
		"to":         toAID,
		"payload":    envelope,
		"type":       "e2ee.encrypted",
		"encrypted":  true,
		"message_id": messageID,
		"timestamp":  timestamp,
	}
	if persistRequired {
		sendParams["persist_required"] = true
	}
	result, err := c.transport.Call(ctx, "message.send", sendParams)
	if err != nil {
		prekeyID, _ := prekey["prekey_id"].(string)
		log.Printf("[aun_core] 警告: E2EE 消息发送失败，prekey 已消耗不可回滚 (to=%s, prekey_id=%s): %v", toAID, prekeyID, err)
	}
	return result, err
}

func (c *AUNClient) buildRecipientDeviceCopies(
	ctx context.Context,
	toAID string,
	payload map[string]any,
	messageID string,
	timestamp int64,
	prekeys []map[string]any,
) ([]map[string]any, error) {
	recipientCopies := make([]map[string]any, 0, len(prekeys))
	certCache := make(map[string][]byte)
	for _, prekey := range prekeys {
		deviceID := strings.TrimSpace(fmt.Sprint(prekey["device_id"]))
		peerCertFingerprint := strings.TrimSpace(strings.ToLower(getStr(prekey, "cert_fingerprint", "")))
		cacheKey := peerCertFingerprint
		if cacheKey == "" {
			cacheKey = "__default__"
		}
		peerCertPEM := certCache[cacheKey]
		if peerCertPEM == nil {
			var err error
			peerCertPEM, err = c.fetchPeerCert(ctx, toAID, peerCertFingerprint)
			if err != nil {
				return nil, err
			}
			certCache[cacheKey] = peerCertPEM
		}
		envelope, encryptResult, err := c.encryptCopyPayload(toAID, payload, peerCertPEM, prekey, messageID, timestamp)
		if err != nil {
			return nil, err
		}
		if err := c.ensureEncryptResult(toAID, encryptResult); err != nil {
			return nil, err
		}
		recipientCopies = append(recipientCopies, map[string]any{
			"device_id": deviceID,
			"envelope":  envelope,
		})
	}
	if len(recipientCopies) == 0 {
		return nil, NewE2EEError(fmt.Sprintf("no recipient device copies generated for %s", toAID), "E2EE_ENCRYPT_FAILED")
	}
	return recipientCopies, nil
}

func (c *AUNClient) resolveSelfCopyPeerCert(ctx context.Context, certFingerprint string) ([]byte, error) {
	c.mu.RLock()
	myAID := c.aid
	identity := c.identity
	c.mu.RUnlock()
	if myAID == "" {
		return nil, NewE2EEError("self sync copy requires current aid", "E2EE_ENCRYPT_FAILED")
	}
	normalized := strings.TrimSpace(strings.ToLower(certFingerprint))
	if certPEM, ok := identity["cert"].(string); ok && certPEM != "" {
		if normalized == "" {
			return []byte(certPEM), nil
		}
		if fp, err := certSHA256Fingerprint([]byte(certPEM)); err == nil && fp == normalized {
			return []byte(certPEM), nil
		}
	}
	if versioned, ok := c.keyStore.(keystore.VersionedCertKeyStore); ok && normalized != "" {
		if certPEM, err := versioned.LoadCertVersion(myAID, normalized); err == nil && certPEM != "" {
			return []byte(certPEM), nil
		}
	}
	if certPEM, err := c.keyStore.LoadCert(myAID); err == nil && certPEM != "" {
		if normalized == "" {
			return []byte(certPEM), nil
		}
		if actualFingerprint, fpErr := certSHA256Fingerprint([]byte(certPEM)); fpErr == nil && actualFingerprint == normalized {
			return []byte(certPEM), nil
		}
	}
	return c.fetchPeerCert(ctx, myAID, normalized)
}

func (c *AUNClient) buildSelfSyncCopies(
	ctx context.Context,
	logicalToAID string,
	payload map[string]any,
	messageID string,
	timestamp int64,
) ([]map[string]any, error) {
	c.mu.RLock()
	myAID := c.aid
	currentDeviceID := c.deviceID
	c.mu.RUnlock()
	if myAID == "" {
		return []map[string]any{}, nil
	}
	prekeys, err := c.fetchPeerPrekeys(ctx, myAID)
	if err != nil {
		return nil, err
	}
	copies := make([]map[string]any, 0)
	for _, prekey := range prekeys {
		deviceID := strings.TrimSpace(fmt.Sprint(prekey["device_id"]))
		if deviceID != "" && deviceID == currentDeviceID {
			continue
		}
		peerCertPEM, err := c.resolveSelfCopyPeerCert(ctx, strings.TrimSpace(strings.ToLower(getStr(prekey, "cert_fingerprint", ""))))
		if err != nil {
			return nil, err
		}
		envelope, encryptResult, err := c.encryptCopyPayload(logicalToAID, payload, peerCertPEM, prekey, messageID, timestamp)
		if err != nil {
			return nil, err
		}
		if err := c.ensureEncryptResult(myAID, encryptResult); err != nil {
			return nil, err
		}
		copies = append(copies, map[string]any{
			"device_id": deviceID,
			"envelope":  envelope,
		})
	}
	return copies, nil
}

func (c *AUNClient) encryptCopyPayload(
	logicalToAID string,
	payload map[string]any,
	peerCertPEM []byte,
	prekey map[string]any,
	messageID string,
	timestamp int64,
) (map[string]any, map[string]any, error) {
	return c.e2ee.EncryptOutbound(logicalToAID, payload, peerCertPEM, prekey, messageID, timestamp)
}

func (c *AUNClient) ensureEncryptResult(toAID string, encryptResult map[string]any) error {
	encrypted, _ := encryptResult["encrypted"].(bool)
	if !encrypted {
		return NewE2EEError(fmt.Sprintf("加密消息到 %s 失败", toAID), "E2EE_ENCRYPT_FAILED")
	}
	forwardSecrecy, _ := encryptResult["forward_secrecy"].(bool)
	if c.configModel.RequireForwardSecrecy && !forwardSecrecy {
		return NewE2EEError(
			fmt.Sprintf("前向保密要求但 %s 不可用 (mode=%s)", toAID, getStr(encryptResult, "mode", "")),
			"E2EE_FORWARD_SECRECY_REQUIRED",
		)
	}
	degraded, _ := encryptResult["degraded"].(bool)
	if degraded {
		c.events.Publish("e2ee.degraded", map[string]any{
			"peer_aid": toAID,
			"mode":     encryptResult["mode"],
			"reason":   encryptResult["degradation_reason"],
		})
	}
	return nil
}

// sendGroupEncrypted 自动加密并发送群组消息
// GO-001: 发送前预检本地 epoch 是否与服务端一致
func (c *AUNClient) sendGroupEncrypted(ctx context.Context, params map[string]any) (any, error) {
	groupID, _ := params["group_id"].(string)
	payload, _ := params["payload"].(map[string]any)
	if groupID == "" {
		return nil, NewValidationError("group.send 需要 group_id")
	}
	if payload == nil {
		return nil, NewValidationError("group.send encrypt=true 时 payload 必须是对象")
	}

	// 惰性同步：首次对该群发消息时先 pull 一次，确保 epoch key 和 seq 状态就绪
	c.groupSyncedMu.Lock()
	synced := c.groupSynced[groupID]
	c.groupSyncedMu.Unlock()
	if !synced {
		c.lazySyncGroup(groupID)
	}

	if err := c.ensureGroupEpochReady(ctx, groupID, false); err != nil {
		return nil, err
	}
	c.waitForGroupMembershipEpochFloor(ctx, groupID, 2*time.Second)

	for attempt := 0; attempt < 2; attempt++ {
		epochResult := c.committedGroupEpochState(ctx, groupID)
		committedEpoch := int(toInt64(firstNonNil(epochResult["committed_epoch"], epochResult["epoch"])))
		var envelope map[string]any
		var err error
		if committedEpoch > 0 {
			readyEpoch, readyErr := c.ensureCommittedGroupSecretForSend(ctx, groupID, committedEpoch, epochResult)
			if readyErr != nil {
				return nil, readyErr
			}
			envelope, err = c.groupE2EE.EncryptWithEpoch(groupID, readyEpoch, payload)
		} else {
			envelope, err = c.groupE2EE.Encrypt(groupID, payload)
		}
		if err != nil {
			return nil, err
		}

		sendParams := map[string]any{
			"group_id":  groupID,
			"payload":   envelope,
			"type":      "e2ee.group_encrypted",
			"encrypted": true,
		}
		if c.deviceID != "" {
			sendParams["device_id"] = c.deviceID
		}
		c.signClientOperation("group.send", sendParams)
		result, err := c.transport.Call(ctx, "group.send", sendParams)
		if err == nil {
			return result, nil
		}
		if attempt == 0 && isRecoverableGroupEpochError(err) {
			log.Printf("[aun_core] 群 %s 发送时 epoch 已过旧，恢复密钥后重加密重发一次: %v", groupID, err)
			if readyErr := c.ensureGroupEpochReady(ctx, groupID, true); readyErr != nil {
				return nil, readyErr
			}
			continue
		}
		return nil, err
	}
	return nil, NewStateError(fmt.Sprintf("group %s send failed after epoch recovery retry", groupID))
}

func isGroupEpochTooOldError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "e2ee epoch too old")
}

func isGroupEpochRotationPendingError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "e2ee epoch rotation pending") || strings.Contains(text, "e2ee epoch not committed")
}

func isRecoverableGroupEpochError(err error) bool {
	return isGroupEpochTooOldError(err) || isGroupEpochRotationPendingError(err)
}

func (c *AUNClient) groupKeyRecoveryCandidates(groupID string, epochResult map[string]any) []string {
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	candidates := make([]string, 0)
	seen := make(map[string]bool)
	add := func(value any) {
		aid := strings.TrimSpace(fmt.Sprint(value))
		if aid == "" || aid == "<nil>" || aid == myAID || seen[aid] {
			return
		}
		seen[aid] = true
		candidates = append(candidates, aid)
	}
	add(epochResult["rotated_by"])
	add(epochResult["owner_aid"])
	for _, key := range []string{"recovery_candidates", "admins", "members"} {
		switch values := epochResult[key].(type) {
		case []any:
			for _, value := range values {
				if m, ok := value.(map[string]any); ok {
					add(m["aid"])
				} else {
					add(value)
				}
			}
		case []string:
			for _, value := range values {
				add(value)
			}
		}
	}
	for _, aid := range c.groupE2EE.GetMemberAIDs(groupID) {
		add(aid)
	}
	return candidates
}

func (c *AUNClient) requestGroupKeyFromCandidates(ctx context.Context, groupID string, serverEpoch int, epochResult map[string]any) {
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	for _, target := range c.groupKeyRecoveryCandidates(groupID, epochResult) {
		reqPayload := BuildKeyRequest(groupID, serverEpoch, myAID)
		c.groupE2EE.RememberKeyRequest(reqPayload, target)
		if _, err := c.Call(ctx, "message.send", map[string]any{
			"to":               target,
			"payload":          reqPayload,
			"encrypt":          true,
			"persist_required": true,
		}); err != nil {
			log.Printf("[aun_core] 向 %s 请求群 %s epoch %d 密钥失败: %v", target, groupID, serverEpoch, err)
		}
	}
}

func (c *AUNClient) recoverInitialGroupEpochIfNeeded(ctx context.Context, groupID string, localEpoch int, epochResult map[string]any) map[string]any {
	serverEpoch := int(toInt64(epochResult["epoch"]))
	if serverEpoch != 0 || localEpoch != 1 {
		return epochResult
	}
	secretData, err := c.groupE2EE.LoadSecretForEpoch(groupID, 1)
	if err != nil || secretData == nil || strings.TrimSpace(stringFromAny(secretData["pending_rotation_id"])) != "" {
		return epochResult
	}
	log.Printf("[aun_core] 群 %s 检测到本地 epoch 1 已存在但服务端 epoch 仍为 0，尝试补同步初始 epoch", groupID)
	c.syncEpochToServer(ctx, groupID)
	refreshedRaw, refreshErr := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
	if refreshErr != nil {
		log.Printf("[aun_core] 群 %s 初始 epoch 补同步后刷新服务端 epoch 失败: %v", groupID, refreshErr)
		return epochResult
	}
	if refreshedMap, ok := refreshedRaw.(map[string]any); ok {
		return refreshedMap
	}
	return epochResult
}

func (c *AUNClient) ensureGroupEpochReady(ctx context.Context, groupID string, strict bool) error {
	localEpoch := c.groupE2EE.CurrentEpoch(groupID)
	effectiveLocalEpoch := 0
	if localEpoch != nil {
		effectiveLocalEpoch = *localEpoch
	}
	epochResult, err := c.transport.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
	if err != nil {
		if strict {
			return NewStateError(fmt.Sprintf("group %s failed to query server epoch before retry: %v", groupID, err))
		}
		log.Printf("[aun_core] group %s epoch precheck failed: %v", groupID, err)
		return nil
	}
	resultMap, ok := epochResult.(map[string]any)
	if !ok {
		return nil
	}
	serverEpoch := int(toInt64(resultMap["epoch"]))
	if pending, ok := resultMap["pending_rotation"].(map[string]any); ok && !truthyBool(pending["expired"]) {
		pendingBaseEpoch := int(toInt64(firstNonNil(pending["base_epoch"], serverEpoch)))
		c.scheduleGroupRotationRetry(groupID, "pending_recovery", stringFromAny(pending["rotation_id"]), pendingBaseEpoch, pending)
	}
	if serverEpoch == 0 && effectiveLocalEpoch == 1 {
		resultMap = c.recoverInitialGroupEpochIfNeeded(ctx, groupID, effectiveLocalEpoch, resultMap)
		serverEpoch = int(toInt64(resultMap["epoch"]))
		if serverEpoch == 0 {
			return NewStateError(fmt.Sprintf("group %s initial epoch sync has not completed; refuse to send with local epoch 1 while server epoch is 0", groupID))
		}
	}
	if serverEpoch <= effectiveLocalEpoch {
		if !strict || serverEpoch <= 0 {
			return nil
		}
		waitDeadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(waitDeadline) {
			time.Sleep(150 * time.Millisecond)
			refreshedRaw, refreshErr := c.transport.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
			if refreshErr != nil {
				continue
			}
			refreshedMap, ok := refreshedRaw.(map[string]any)
			if !ok {
				continue
			}
			refreshedEpoch := int(toInt64(refreshedMap["epoch"]))
			currentLocal := c.groupE2EE.CurrentEpoch(groupID)
			if refreshedEpoch > serverEpoch {
				resultMap = refreshedMap
				serverEpoch = refreshedEpoch
				if currentLocal != nil {
					effectiveLocalEpoch = *currentLocal
				}
				break
			}
			if currentLocal != nil && *currentLocal > effectiveLocalEpoch {
				return nil
			}
		}
		if serverEpoch <= effectiveLocalEpoch {
			return NewStateError(fmt.Sprintf("group %s epoch rotation has not completed", groupID))
		}
	}
	log.Printf("[aun_core] group %s local epoch=%d < server epoch=%d; requesting key recovery", groupID, effectiveLocalEpoch, serverEpoch)
	c.requestGroupKeyFromCandidates(ctx, groupID, serverEpoch, resultMap)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		refreshed := c.groupE2EE.CurrentEpoch(groupID)
		if refreshed != nil && *refreshed >= serverEpoch {
			return nil
		}
	}
	refreshed := c.groupE2EE.CurrentEpoch(groupID)
	refreshedText := "<nil>"
	if refreshed != nil {
		refreshedText = fmt.Sprint(*refreshed)
	}
	return NewStateError(fmt.Sprintf("group %s local epoch %s is behind server epoch %d; key recovery has not completed", groupID, refreshedText, serverEpoch))
}

func (c *AUNClient) waitForGroupMembershipEpochFloor(ctx context.Context, groupID string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		epochRaw, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
		if err != nil {
			log.Printf("[aun_core] 群 %s 成员 epoch floor 预检跳过: %v", groupID, err)
			return
		}
		epochMap, _ := epochRaw.(map[string]any)
		committedEpoch := int(toInt64(firstNonNil(epochMap["committed_epoch"], epochMap["epoch"])))

		membersRaw, err := c.Call(ctx, "group.get_members", map[string]any{"group_id": groupID})
		if err != nil {
			log.Printf("[aun_core] 群 %s 成员 epoch floor 成员查询跳过: %v", groupID, err)
			return
		}
		membersMap, _ := membersRaw.(map[string]any)
		members, _ := membersMap["members"].([]any)
		maxMinReadEpoch := 0
		for _, raw := range members {
			member, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			value := int(toInt64(member["min_read_epoch"]))
			if value > maxMinReadEpoch {
				maxMinReadEpoch = value
			}
		}
		if maxMinReadEpoch <= committedEpoch {
			return
		}
		if time.Now().After(deadline) {
			log.Printf("[aun_core] 群 %s committed epoch 尚未追上成员可读下限，按当前 committed epoch 继续发送: committed=%d floor=%d",
				groupID, committedEpoch, maxMinReadEpoch)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func (c *AUNClient) committedGroupEpochState(ctx context.Context, groupID string) map[string]any {
	raw, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
	if err == nil {
		if result, ok := raw.(map[string]any); ok {
			return result
		}
	}
	if err != nil {
		log.Printf("[aun_core] 群 %s 查询 committed epoch 状态失败，回退本地 epoch: %v", groupID, err)
	}
	localEpoch := 0
	if ep := c.groupE2EE.CurrentEpoch(groupID); ep != nil {
		localEpoch = *ep
	}
	return map[string]any{"epoch": localEpoch, "committed_epoch": localEpoch}
}

func (c *AUNClient) groupSecretMatchesCommittedRotation(secretData map[string]any, committedRotation map[string]any) bool {
	if secretData == nil {
		return false
	}
	committedCommitment := ""
	if committedRotation != nil {
		committedCommitment = strings.TrimSpace(stringFromAny(committedRotation["key_commitment"]))
	}
	localCommitment := strings.TrimSpace(stringFromAny(secretData["commitment"]))
	if committedCommitment != "" && committedCommitment != localCommitment {
		return false
	}
	pendingRotationID := strings.TrimSpace(stringFromAny(secretData["pending_rotation_id"]))
	if pendingRotationID == "" {
		return true
	}
	if committedRotation == nil {
		return false
	}
	if strings.TrimSpace(stringFromAny(committedRotation["rotation_id"])) != pendingRotationID {
		return false
	}
	return true
}

func (c *AUNClient) ensureCommittedGroupSecretForSend(ctx context.Context, groupID string, committedEpoch int, epochResult map[string]any) (int, error) {
	if committedEpoch <= 0 {
		return committedEpoch, nil
	}
	secretData, err := c.groupE2EE.LoadSecretForEpoch(groupID, committedEpoch)
	if err != nil {
		return 0, err
	}
	committedRotation, _ := epochResult["committed_rotation"].(map[string]any)
	if c.groupSecretMatchesCommittedRotation(secretData, committedRotation) {
		return committedEpoch, nil
	}
	pendingRotationID := ""
	if secretData != nil {
		pendingRotationID = stringFromAny(secretData["pending_rotation_id"])
	}
	log.Printf("[aun_core] 群 %s epoch %d 本地 pending key 未匹配服务端 committed rotation，先恢复密钥: local_rotation=%s",
		groupID, committedEpoch, firstNonEmpty(pendingRotationID, "-"))
	c.recoverGroupEpochKey(ctx, groupID, committedEpoch, "", 5*time.Second)
	refreshed := c.committedGroupEpochState(ctx, groupID)
	refreshedCommittedEpoch := int(toInt64(firstNonNil(refreshed["committed_epoch"], refreshed["epoch"], committedEpoch)))
	if refreshedCommittedEpoch > committedEpoch {
		committedEpoch = refreshedCommittedEpoch
		c.recoverGroupEpochKey(ctx, groupID, committedEpoch, "", 5*time.Second)
		refreshed = c.committedGroupEpochState(ctx, groupID)
	}
	refreshedRotation, _ := refreshed["committed_rotation"].(map[string]any)
	refreshedSecret, _ := c.groupE2EE.LoadSecretForEpoch(groupID, committedEpoch)
	if !c.groupSecretMatchesCommittedRotation(refreshedSecret, refreshedRotation) {
		return 0, NewStateError(fmt.Sprintf("group %s epoch %d local key is pending or mismatched; refuse to send with uncommitted group key", groupID, committedEpoch))
	}
	return committedEpoch, nil
}

// epochPrecheck 检查本地 epoch 是否落后于服务端，落后则触发密钥恢复
// GO-001: 参考 Python SDK _send_group_encrypted 的 epoch 预检逻辑
func (c *AUNClient) epochPrecheck(ctx context.Context, groupID string) {
	localEpoch := c.groupE2EE.CurrentEpoch(groupID)
	if localEpoch == nil {
		return // 无本地密钥时跳过预检（Encrypt 会返回 SecretMissingError）
	}

	epochResult, err := c.transport.Call(ctx, "group.e2ee.get_epoch", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		log.Printf("[aun_core] 群 %s epoch 预检查询失败: %v", groupID, err)
		return // 查询失败不阻塞发送
	}

	resultMap, ok := epochResult.(map[string]any)
	if !ok {
		return
	}
	serverEpoch := int(toInt64(resultMap["epoch"]))
	if serverEpoch <= *localEpoch {
		return // 本地 epoch 不落后
	}

	log.Printf("[aun_core] 群 %s 本地 epoch=%d < 服务端 epoch=%d，触发密钥恢复",
		groupID, *localEpoch, serverEpoch)

	// 向 owner 请求最新密钥
	ownerAID, _ := resultMap["owner_aid"].(string)
	if ownerAID == "" {
		// 尝试通过 group.get_info 获取 owner
		info, infoErr := c.transport.Call(ctx, "group.get_info", map[string]any{
			"group_id": groupID,
		})
		if infoErr == nil {
			if infoMap, ok := info.(map[string]any); ok {
				ownerAID, _ = infoMap["owner_aid"].(string)
			}
		}
	}

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if ownerAID != "" && ownerAID != myAID {
		recovery := c.groupE2EE.BuildRecoveryRequest(groupID, serverEpoch, ownerAID)
		if recovery != nil {
			to, _ := recovery["to"].(string)
			recPayload, _ := recovery["payload"].(map[string]any)
			if to != "" && recPayload != nil {
				if _, sendErr := c.Call(ctx, "message.send", map[string]any{
					"to":      to,
					"payload": recPayload,
					"encrypt": true,
				}); sendErr != nil {
					log.Printf("[aun_core] epoch 预检密钥恢复请求失败: %v", sendErr)
				}
			}
		}
	}
	// 不阻塞发送：使用当前本地 epoch 发送，服务端若拒绝由上层处理
}

// ── 便利方法 ──────────────────────────────────────────────

// On 订阅事件
func (c *AUNClient) On(event string, handler EventHandler) *Subscription {
	return c.events.Subscribe(event, handler)
}

// Ping 发送心跳
func (c *AUNClient) Ping(ctx context.Context) (any, error) {
	return c.Call(ctx, "meta.ping", nil)
}

// Status 查询服务状态
func (c *AUNClient) Status(ctx context.Context) (any, error) {
	return c.Call(ctx, "meta.status", nil)
}

// TrustRoots 获取信任根
func (c *AUNClient) TrustRoots(ctx context.Context) (any, error) {
	return c.Call(ctx, "meta.trust_roots", nil)
}

// ── 事件处理 ──────────────────────────────────────────────

// onRawMessageReceived 处理 transport 层推送的原始消息
func (c *AUNClient) onRawMessageReceived(data any) {
	go c.processAndPublishMessage(data)
}

// processAndPublishMessage 实际处理推送消息的 goroutine
func (c *AUNClient) processAndPublishMessage(data any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("processAndPublishMessage panic: %v", r)
		}
	}()

	dataMap, ok := data.(map[string]any)
	if !ok {
		c.events.Publish("message.received", data)
		return
	}

	msg := copyMapShallow(dataMap)

	// 拦截 P2P 传输的群组密钥分发/请求/响应消息
	if c.tryHandleGroupKeyMessage(msg) {
		return
	}

	// P2P 空洞检测
	seq := int(toInt64(msg["seq"]))
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if seq > 0 && myAID != "" {
		// 收到推送即标记 P2P 已同步
		c.p2pSyncedMu.Lock()
		c.p2pSynced = true
		c.p2pSyncedMu.Unlock()

		ns := "p2p:" + myAID
		// 预标记：在启动补洞 goroutine 之前完成，确保补洞路径能看到此 seq 已被推送路径处理。
		// 若解密失败，补洞路径的 decryptMessages 也会过滤掉同一条消息，不会重复投递。
		c.markPushedSeq(ns, seq)
		needPull := c.seqTracker.OnMessageSeq(ns, seq)
		if needPull {
			go c.fillP2pGap()
		}
		// auto-ack contiguous_seq
		contig := c.seqTracker.GetContiguousSeq(ns)
		if contig > 0 {
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "message.ack", map[string]any{
					"seq":       contig,
					"device_id": c.deviceID,
				}); ackErr != nil {
					log.Printf("P2P auto-ack 失败: %v", ackErr)
				}
			}()
		}
		// 即时持久化 cursor，异常断连后不回退
		c.saveSeqTrackerState()
	}

	ctx := context.Background()
	decrypted := c.decryptSingleMessage(ctx, msg)
	if decrypted == nil {
		// H26: 解密失败不再投递原始密文 payload（避免元数据泄漏 + 语义混淆），
		// 改为发布 message.undecryptable 事件，仅携带安全的 header 信息。
		log.Printf("[aun_core] [WARN] P2P 消息解密失败，发布 message.undecryptable: seq=%d", seq)
		safeEvent := map[string]any{
			"message_id":     msg["message_id"],
			"from":           msg["from"],
			"to":             msg["to"],
			"seq":            msg["seq"],
			"timestamp":      msg["timestamp"],
			"_decrypt_error": "decryption failed",
		}
		c.events.Publish("message.undecryptable", safeEvent)
		return
	}
	c.events.Publish("message.received", decrypted)
}

// onRawGroupMessageCreated 处理群组消息推送
func (c *AUNClient) onRawGroupMessageCreated(data any) {
	go c.processAndPublishGroupMessage(data)
}

// processAndPublishGroupMessage 处理群组推送消息的 goroutine
//
// 带 payload 的事件（消息推送）：解密后 re-publish。
// 不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。
func (c *AUNClient) processAndPublishGroupMessage(data any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("processAndPublishGroupMessage panic: %v", r)
		}
	}()

	dataMap, ok := data.(map[string]any)
	if !ok {
		c.events.Publish("group.message_created", data)
		return
	}

	msg := copyMapShallow(dataMap)
	groupID, _ := msg["group_id"].(string)
	seq := int(toInt64(msg["seq"]))

	// 空洞检测（无论带不带 payload 都检查）
	if groupID != "" && seq > 0 {
		// 收到推送即标记该群已同步
		c.groupSyncedMu.Lock()
		c.groupSynced[groupID] = true
		c.groupSyncedMu.Unlock()

		ns := "group:" + groupID
		// 预标记：在启动补洞 goroutine 之前完成，确保补洞路径能看到此 seq 已被推送路径处理。
		c.markPushedSeq(ns, seq)
		needPull := c.seqTracker.OnMessageSeq(ns, seq)
		if needPull {
			go c.fillGroupGap(groupID)
		}
		// auto-ack contiguous_seq
		contig := c.seqTracker.GetContiguousSeq(ns)
		if contig > 0 {
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
					"group_id":  groupID,
					"msg_seq":   contig,
					"device_id": c.deviceID,
				}); ackErr != nil {
					log.Printf("群消息 auto-ack 失败: group=%s %v", groupID, ackErr)
				}
			}()
		}
		// 即时持久化 cursor，异常断连后不回退
		c.saveSeqTrackerState()
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
		// 不带 payload 的通知：自动 pull 最新消息
		c.autoPullGroupMessages(msg)
		return
	}

	ctx := context.Background()
	decrypted := c.decryptGroupMessage(ctx, msg)
	if decrypted == nil {
		c.enqueuePendingDecrypt(groupID, msg)
		// H26: 解密失败改发 group.message_undecryptable 事件，不投递原始密文 payload。
		log.Printf("[aun_core] [WARN] 群消息解密失败，发布 group.message_undecryptable: group=%s seq=%d", groupID, seq)
		safeEvent := map[string]any{
			"message_id":     msg["message_id"],
			"group_id":       msg["group_id"],
			"from":           msg["from"],
			"seq":            msg["seq"],
			"timestamp":      msg["timestamp"],
			"_decrypt_error": "decryption failed",
		}
		c.events.Publish("group.message_undecryptable", safeEvent)
		return
	}
	c.events.Publish("group.message_created", decrypted)
}

// autoPullGroupMessages 收到不带 payload 的通知后自动 pull 最新消息
func (c *AUNClient) autoPullGroupMessages(notification map[string]any) {
	groupID, _ := notification["group_id"].(string)
	if groupID == "" {
		c.events.Publish("group.message_created", notification)
		return
	}
	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "group.pull", map[string]any{
		"group_id":          groupID,
		"after_message_seq": afterSeq,
		"device_id":         c.deviceID,
		"limit":             50,
	})
	if err != nil {
		log.Printf("自动 pull 群消息失败: %v", err)
		c.events.Publish("group.message_created", notification)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		c.events.Publish("group.message_created", notification)
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok || len(messages) == 0 {
		c.events.Publish("group.message_created", notification)
		return
	}
	// 更新 SeqTracker
	var pullMsgs []map[string]any
	for _, raw := range messages {
		if m, ok := raw.(map[string]any); ok {
			pullMsgs = append(pullMsgs, m)
		}
	}
	c.seqTracker.OnPullResult(ns, pullMsgs)
	// pushedSeqs 去重：使用 publishGapFillGroupMessages 安全发布，避免锁外读取竞态
	c.publishGapFillGroupMessages(ns, messages)
}

// fillGroupGap 后台补齐群消息空洞
func (c *AUNClient) fillGroupGap(groupID string) {
	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	// 冷启动（seq=0）：服务端推送会带全量消息，SDK 不主动补洞避免重复拉取
	if afterSeq == 0 {
		return
	}
	// 去重：同一 (group:id:after_seq) 只补一次
	dedupKey := fmt.Sprintf("group_msg:%s:%d", groupID, afterSeq)
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
		"group_id":          groupID,
		"after_message_seq": afterSeq,
		"device_id":         c.deviceID,
		"limit":             50,
	})
	if err != nil {
		log.Printf("[aun_core] [WARN] 后台补洞失败 (fillGroupGap group=%s): %v", groupID, err)
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
	// seq_tracker 更新和 auto-ack 已在 Call() 拦截器中完成
	nsKey := "group:" + groupID
	c.publishGapFillGroupMessages(nsKey, messages)
}

// lazySyncGroup 惰性同步：首次激活群时 pull 最近消息，建立 seq 基线。
func (c *AUNClient) lazySyncGroup(groupID string) {
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
		log.Printf("[aun_core] [WARN] 惰性同步群 %s 失败: %v", groupID, err)
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
				c.seqTracker.OnMessageSeq(ns, s)
			}
		}
	}
	if len(messages) > 0 {
		c.saveSeqTrackerState()
		log.Printf("[aun_core] 惰性同步群 %s: pull %d 条消息, after_seq=%d", groupID, len(messages), afterSeq)
	}
}

// fillGroupEventGap 后台补齐群事件空洞
func (c *AUNClient) fillGroupEventGap(groupID string) {
	ns := "group_event:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	// 冷启动（seq=0）：服务端推送会带全量事件，SDK 不主动补洞避免重复拉取
	if afterSeq == 0 {
		return
	}
	// 去重：同一 (group_evt:id:after_seq) 只补一次
	dedupKey := fmt.Sprintf("group_evt:%s:%d", groupID, afterSeq)
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
	result, err := c.Call(ctx, "group.pull_events", map[string]any{
		"group_id":        groupID,
		"after_event_seq": afterSeq,
		"device_id":       c.deviceID,
		"limit":           50,
	})
	if err != nil {
		log.Printf("[aun_core] [WARN] 后台补洞失败 (fillGroupEventGap group=%s): %v", groupID, err)
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
	for _, raw := range events {
		if e, ok := raw.(map[string]any); ok {
			pullEvts = append(pullEvts, e)
		}
	}
	c.seqTracker.OnPullResult(ns, pullEvts)
	// 持久化 cursor + ack_events（与 Python 对齐）
	c.saveSeqTrackerState()
	contig := c.seqTracker.GetContiguousSeq(ns)
	if contig > 0 {
		go func() {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ackCancel()
			if _, ackErr := c.transport.Call(ackCtx, "group.ack_events", map[string]any{
				"group_id":  groupID,
				"event_seq": contig,
				"device_id": c.deviceID,
			}); ackErr != nil {
				log.Printf("群事件 auto-ack 失败: group=%s %v", groupID, ackErr)
			}
		}()
	}
	for _, raw := range events {
		if evt, ok := raw.(map[string]any); ok {
			evt["_from_gap_fill"] = true
			et, _ := evt["event_type"].(string)
			// 消息事件由 fillGroupGap 负责，事件补洞不重复投递
			if et == "group.message_created" {
				continue
			}
			// group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
			c.events.Publish("group.changed", evt)
		}
	}
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
	// 新设备（seq=0）没有历史 prekey，拉旧消息也解不了
	if afterSeq == 0 {
		return
	}
	// 去重：同一 (type:after_seq) 只补一次
	dedupKey := fmt.Sprintf("p2p:%d", afterSeq)
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
		"device_id": c.deviceID,
		"limit":     50,
	})
	if err != nil {
		log.Printf("[aun_core] [WARN] 后台补洞失败 (fillP2pGap): %v", err)
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
	// seq_tracker 更新和 auto-ack 已在 Call() 拦截器中完成
	nsKey := "p2p:" + myAID
	c.publishGapFillMessages(nsKey, messages)
}

// lazySyncP2p 惰性同步：首次激活 P2P 通道时 pull 最近消息，建立 seq 基线。
func (c *AUNClient) lazySyncP2p() {
	c.p2pSyncedMu.Lock()
	c.p2pSynced = true
	c.p2pSyncedMu.Unlock()

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}

	ns := "p2p:" + myAID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.transport.Call(ctx, "message.pull", map[string]any{
		"after_seq": afterSeq,
		"limit":     200,
	})
	if err != nil {
		log.Printf("[aun_core] [WARN] 惰性同步 P2P 失败: %v", err)
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
				c.seqTracker.OnMessageSeq(ns, s)
			}
		}
	}
	if len(messages) > 0 {
		c.saveSeqTrackerState()
		log.Printf("[aun_core] 惰性同步 P2P: pull %d 条消息, after_seq=%d", len(messages), afterSeq)
	}
}

// prunePushedSeqs 清理 pushedSeqs 中 <= contiguousSeq 的条目，防止无限增长
func (c *AUNClient) prunePushedSeqs(ns string) {
	contig := c.seqTracker.GetContiguousSeq(ns)
	c.pushedSeqsMu.Lock()
	defer c.pushedSeqsMu.Unlock()
	pushed := c.pushedSeqs[ns]
	if pushed == nil {
		return
	}
	for s := range pushed {
		if s <= contig {
			delete(pushed, s)
		}
	}
	if len(pushed) == 0 {
		delete(c.pushedSeqs, ns)
	}
}

// markPushedSeq 在锁内安全标记指定 ns 的 seq 已通过推送路径分发。
// 必须在启动补洞 goroutine 之前调用，确保补洞路径能看到预标记。
func (c *AUNClient) markPushedSeq(ns string, seq int) {
	if seq <= 0 || ns == "" {
		return
	}
	c.pushedSeqsMu.Lock()
	if c.pushedSeqs[ns] == nil {
		c.pushedSeqs[ns] = make(map[int]bool)
	}
	c.pushedSeqs[ns][seq] = true
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

// publishGapFillMessages 补洞路径发布 P2P 消息，跳过已通过推送路径分发的 seq。
// 使用 isPushedSeq 逐条检查，避免取出内层 map 引用后在锁外读取的竞态。
func (c *AUNClient) publishGapFillMessages(ns string, messages []any) {
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if c.isPushedSeq(ns, s) {
				continue // 已通过推送路径分发，跳过
			}
			c.events.Publish("message.received", msg)
		}
	}
	c.prunePushedSeqs(ns)
}

// publishGapFillGroupMessages 补洞路径发布群消息，跳过已通过推送路径分发的 seq。
func (c *AUNClient) publishGapFillGroupMessages(ns string, messages []any) {
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if c.isPushedSeq(ns, s) {
				continue // 已通过推送路径分发，跳过
			}
			c.events.Publish("group.message_created", msg)
		}
	}
	c.prunePushedSeqs(ns)
}

func membershipRotationExpectedEpoch(payload map[string]any) *int {
	for _, key := range []string{"old_epoch", "current_epoch", "e2ee_epoch"} {
		if value, ok := payload[key]; ok && value != nil {
			n := int(toInt64(value))
			return &n
		}
	}
	if group, ok := payload["group"].(map[string]any); ok {
		for _, key := range []string{"old_epoch", "current_epoch", "e2ee_epoch"} {
			if value, ok := group[key]; ok && value != nil {
				n := int(toInt64(value))
				return &n
			}
		}
	}
	return nil
}

func membershipRotationTriggerID(groupID string, payload map[string]any) string {
	action := strings.TrimSpace(stringFromAny(payload["action"]))
	if action == "" {
		if stringFromAny(payload["removed_aid"]) != "" {
			action = "member_removed"
		} else if stringFromAny(payload["left_aid"]) != "" {
			action = "member_left"
		} else if _, ok := payload["member"].(map[string]any); ok {
			action = "member_added"
		} else {
			action = strings.TrimSpace(stringFromAny(payload["status"]))
			if action == "" {
				action = strings.TrimSpace(stringFromAny(payload["reason"]))
			}
			if action == "" {
				action = "membership_changed"
			}
		}
	}
	eventSeq := stringFromAny(payload["event_seq"])
	if eventSeq == "" {
		eventSeq = stringFromAny(payload["seq"])
	}
	if eventSeq == "" {
		if group, ok := payload["group"].(map[string]any); ok {
			eventSeq = stringFromAny(group["event_seq"])
		}
	}
	changedAID := ""
	changedAIDs := make(map[string]bool)
	for _, key := range []string{"aid", "removed_aid", "left_aid", "member_aid", "target_aid"} {
		changedAID = stringFromAny(payload[key])
		if changedAID != "" {
			changedAIDs[changedAID] = true
			break
		}
	}
	if changedAID == "" {
		if member, ok := payload["member"].(map[string]any); ok {
			changedAID = stringFromAny(member["aid"])
			if changedAID != "" {
				changedAIDs[changedAID] = true
			}
		}
	} else if member, ok := payload["member"].(map[string]any); ok {
		if aid := stringFromAny(member["aid"]); aid != "" {
			changedAIDs[aid] = true
		}
	}
	if changedAID == "" {
		if request, ok := payload["request"].(map[string]any); ok {
			changedAID = stringFromAny(request["aid"])
			if changedAID != "" {
				changedAIDs[changedAID] = true
			}
		}
	} else if request, ok := payload["request"].(map[string]any); ok {
		if aid := stringFromAny(request["aid"]); aid != "" {
			changedAIDs[aid] = true
		}
	}
	if changedAID == "" {
		if inviteCode, ok := payload["invite_code"].(map[string]any); ok {
			changedAID = firstNonEmpty(stringFromAny(inviteCode["used_by"]), stringFromAny(inviteCode["aid"]))
			if changedAID != "" {
				changedAIDs[changedAID] = true
			}
		}
	} else if inviteCode, ok := payload["invite_code"].(map[string]any); ok {
		for _, aid := range []string{stringFromAny(inviteCode["used_by"]), stringFromAny(inviteCode["aid"])} {
			if aid != "" {
				changedAIDs[aid] = true
			}
		}
	}
	if results, ok := payload["results"].([]any); ok {
		for _, raw := range results {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			status := strings.ToLower(strings.TrimSpace(stringFromAny(item["status"])))
			if status != "approved" && !truthyBool(item["approved"]) {
				continue
			}
			for _, key := range []string{"aid", "member_aid", "target_aid"} {
				if aid := stringFromAny(item[key]); aid != "" {
					changedAIDs[aid] = true
				}
			}
			for _, key := range []string{"member", "request"} {
				if nested, ok := item[key].(map[string]any); ok {
					if aid := stringFromAny(nested["aid"]); aid != "" {
						changedAIDs[aid] = true
					}
				}
			}
		}
	}
	changedAidList := make([]string, 0, len(changedAIDs))
	for aid := range changedAIDs {
		changedAidList = append(changedAidList, aid)
	}
	sort.Strings(changedAidList)
	changedAidKey := strings.Join(changedAidList, ",")
	if changedAID == "" {
		changedAID = "-"
	}
	if expectedEpoch := membershipRotationExpectedEpoch(payload); changedAidKey != "" && expectedEpoch != nil {
		return fmt.Sprintf("%s:%s:aid:%s:epoch:%d", groupID, action, changedAidKey, *expectedEpoch)
	}
	if eventSeq != "" {
		return fmt.Sprintf("%s:%s:event:%s", groupID, action, eventSeq)
	}
	if changedAidKey != "" {
		return fmt.Sprintf("%s:%s:aid:%s", groupID, action, changedAidKey)
	}
	return fmt.Sprintf("%s:%s:aid:%s", groupID, action, changedAID)
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

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func truthyBool(value any) bool {
	v, ok := value.(bool)
	return ok && v
}

func extractGroupIDFromResult(result map[string]any) string {
	if group, ok := result["group"].(map[string]any); ok {
		if gid := stringFromAny(group["group_id"]); gid != "" {
			return gid
		}
	}
	if gid := stringFromAny(result["group_id"]); gid != "" {
		return gid
	}
	if member, ok := result["member"].(map[string]any); ok {
		if gid := stringFromAny(member["group_id"]); gid != "" {
			return gid
		}
	}
	return ""
}

func isMembershipChangeMethod(method string) bool {
	switch method {
	case "group.add_member", "group.kick", "group.remove_member", "group.leave",
		"group.review_join_request", "group.batch_review_join_request",
		"group.use_invite_code", "group.request_join":
		return true
	default:
		return false
	}
}

func membershipRotationChanged(method string, payload map[string]any) bool {
	switch method {
	case "group.add_member", "group.kick", "group.remove_member", "group.leave":
		return true
	case "group.use_invite_code", "group.request_join":
		status := strings.ToLower(strings.TrimSpace(stringFromAny(payload["status"])))
		if status == "joined" || status == "approved" {
			return true
		}
		_, hasMember := payload["member"].(map[string]any)
		return hasMember
	case "group.review_join_request":
		status := strings.ToLower(strings.TrimSpace(stringFromAny(payload["status"])))
		if status == "approved" {
			return true
		}
		if approved, ok := payload["approved"].(bool); ok && approved {
			return true
		}
		_, hasMember := payload["member"].(map[string]any)
		return hasMember
	case "group.batch_review_join_request":
		results, _ := payload["results"].([]any)
		for _, raw := range results {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			status := strings.ToLower(strings.TrimSpace(stringFromAny(item["status"])))
			if status == "approved" {
				return true
			}
			if approved, ok := item["approved"].(bool); ok && approved {
				return true
			}
		}
	}
	return false
}

// onRawGroupChanged 处理群组变更事件
func (c *AUNClient) onRawGroupChanged(data any) {
	dataMap, ok := data.(map[string]any)
	if !ok {
		c.events.Publish("group.changed", data)
		return
	}

	// 验签：有 client_signature 就验，没有默认安全
	if cs, ok := dataMap["client_signature"].(map[string]any); ok {
		dataMap["_verified"] = c.verifyEventSignature(cs)
	}

	c.events.Publish("group.changed", dataMap)

	// event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq
	groupID, _ := dataMap["group_id"].(string)
	needPull := false
	if rawES, ok := dataMap["event_seq"]; ok && groupID != "" {
		if es := toInt64(rawES); es > 0 {
			needPull = c.seqTracker.OnMessageSeq("group_event:"+groupID, int(es))
		}
	}

	// 仅在检测到 event gap 时才触发补洞（补洞回来的事件不再触发新补洞）
	if needPull && groupID != "" && dataMap["_from_gap_fill"] == nil {
		go c.fillGroupEventGap(groupID)
	}

	// 成员退出或被踢 → 剩余 admin/owner 自动补位轮换
	action, _ := dataMap["action"].(string)
	if action == "member_left" || action == "member_removed" {
		if groupID != "" {
			expectedEpoch := membershipRotationExpectedEpoch(dataMap)
			if expectedEpoch == nil {
				_ = expectedEpoch
			} else {
				go c.maybeLeadRotateGroupEpoch(context.Background(), groupID, membershipRotationTriggerID(groupID, dataMap), expectedEpoch)
			}
		}
	}

	if action == "member_added" || action == "joined" || action == "join_approved" || action == "invite_code_used" {
		if groupID != "" {
			expectedEpoch := membershipRotationExpectedEpoch(dataMap)
			if expectedEpoch == nil {
				_ = expectedEpoch
			} else {
				go c.maybeLeadRotateGroupEpoch(context.Background(), groupID, membershipRotationTriggerID(groupID, dataMap), expectedEpoch)
			}
		}
	}

	// GO-006: 群组解散 → 清理本地 epoch key 和 seq_tracker
	if action == "dissolved" && groupID != "" {
		c.groupE2EE.PurgeGroupData(groupID)
		c.seqTracker.RemoveNamespace("group:" + groupID)
		c.seqTracker.RemoveNamespace("group_event:" + groupID)
		log.Printf("[aun_core] 群 %s 已解散，已清理本地 epoch 密钥和 seq tracker", groupID)
	}
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
			log.Printf("验签失败：证书指纹不匹配 aid=%s", sigAID)
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
		log.Printf("群事件验签失败 aid=%s method=%s", sigAID, method)
		return false
	}
	return true
}

// tryHandleGroupKeyMessage 尝试处理 P2P 传输的群组密钥消息。返回 true 表示已处理。
func (c *AUNClient) tryHandleGroupKeyMessage(message map[string]any) bool {
	payload, ok := message["payload"].(map[string]any)
	if !ok {
		return false
	}

	// 先解密 P2P E2EE（如果是加密的）
	actualPayload := payload
	payloadType, _ := payload["type"].(string)
	isGroupKeyCtrl := strings.HasPrefix(payloadType, "e2ee.group_key_")
	if payloadType == "e2ee.encrypted" {
		fromAID, _ := message["from"].(string)
		if fromAID != "" {
			c.ensureSenderCertCached(context.Background(), fromAID)
		}
		// 使用内部解密，避免消耗 seen set
		decrypted, err := c.e2ee.decryptMessage(message)
		if err != nil || decrypted == nil {
			return false
		}
		c.schedulePrekeyReplenishIfConsumed(decrypted)
		ap, ok := decrypted["payload"].(map[string]any)
		if !ok {
			return false
		}
		actualPayload = ap
	}
	innerType, _ := actualPayload["type"].(string)
	if strings.HasPrefix(innerType, "e2ee.group_key_") {
		isGroupKeyCtrl = true
	}

	if innerType == "e2ee.group_key_distribution" {
		if !c.verifyActiveGroupRotationDistribution(context.Background(), actualPayload) {
			return true
		}
	} else if innerType == "e2ee.group_key_response" {
		if !c.verifyGroupKeyResponseEpoch(context.Background(), actualPayload) {
			return true
		}
	}
	result := c.groupE2EE.HandleIncoming(actualPayload)
	if result == "distribution" {
		c.discardGroupDistributionIfStale(context.Background(), actualPayload)
	}
	if result == "" {
		return isGroupKeyCtrl
	}

	if result == "request" {
		// 处理密钥请求并回复
		groupID, _ := actualPayload["group_id"].(string)
		requester, _ := actualPayload["requester_aid"].(string)
		members := c.groupE2EE.GetMemberAIDs(groupID)

		// 请求者不在本地成员列表时，回源查询服务端最新成员列表
		if requester != "" && !stringSliceContains(members, requester) {
			ctx := context.Background()
			membersResult, err := c.Call(ctx, "group.get_members", map[string]any{"group_id": groupID})
			if err == nil {
				if mr, ok := membersResult.(map[string]any); ok {
					if membersList, ok := mr["members"].([]any); ok {
						members = extractAIDsFromMembers(membersList)
						// 更新本地当前 epoch 的 member_aids/commitment
						if stringSliceContains(members, requester) {
							secretData, _ := c.groupE2EE.LoadSecret(groupID)
							if secretData != nil {
								c.mu.RLock()
								myAID := c.aid
								c.mu.RUnlock()
								epoch := int(toInt64(secretData["epoch"]))
								secret, _ := secretData["secret"].([]byte)
								commitment := ComputeMembershipCommitment(members, epoch, groupID, secret)
								StoreGroupSecret(c.keyStore, myAID, groupID, epoch, secret, commitment, members, "")
							}
						}
					}
				}
			}
		}

		response := c.groupE2EE.HandleKeyRequestMsg(actualPayload, members)
		if response != nil && requester != "" {
			ctx := context.Background()
			_, err := c.Call(ctx, "message.send", map[string]any{
				"to":               requester,
				"payload":          response,
				"encrypt":          true,
				"persist_required": true,
			})
			if err != nil {
				log.Printf("向 %s 回复群组密钥失败: %v", requester, err)
			}
		}
	}

	if result == "distribution" || result == "response" {
		groupID, _ := actualPayload["group_id"].(string)
		rotationID := strings.TrimSpace(stringFromAny(actualPayload["rotation_id"]))
		keyCommitment := strings.TrimSpace(stringFromAny(actualPayload["commitment"]))
		if rotationID != "" && keyCommitment != "" {
			go c.ackGroupRotationKey(context.Background(), rotationID, keyCommitment)
		}
		if groupID != "" {
			go c.retryPendingDecryptMsgs(groupID)
		}
	}

	return true
}

// ── E2EE 编排辅助 ────────────────────────────────────────

func certCacheKey(aid, certFingerprint string) string {
	normalized := strings.TrimSpace(strings.ToLower(certFingerprint))
	if normalized == "" {
		return aid
	}
	return aid + "#" + normalized
}

// fetchPeerCert 获取对方证书（带缓存 + 完整 PKI 验证）
func (c *AUNClient) fetchPeerCert(ctx context.Context, aid string, certFingerprint string) ([]byte, error) {
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
	certBytes, err := c.fetchCertHTTP(ctx, buildCertURL(peerGatewayURL, aid, certFingerprint), aid)
	if err != nil {
		if strings.TrimSpace(certFingerprint) == "" {
			return nil, err
		}
		fallbackCert, fallbackErr := c.fetchCertHTTP(ctx, buildCertURL(peerGatewayURL, aid, ""), aid)
		if fallbackErr != nil {
			return nil, err
		}
		certBytes = fallbackCert
	}

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
	c.certCacheMu.Lock()
	c.certCache[cacheKey] = &cachedPeerCert{
		certBytes:    certBytes,
		validatedAt:  now,
		refreshAfter: now + peerCertCacheTTL,
	}
	c.certCacheMu.Unlock()

	if versioned, ok := c.keyStore.(keystore.VersionedCertKeyStore); ok {
		// peer 证书只存版本目录，不覆盖 cert.pem
		if err := versioned.SaveCertVersion(aid, string(certBytes), certFingerprint, false); err != nil {
			log.Printf("写入版本化证书失败 (aid=%s): %v", aid, err)
		}
	} else if strings.TrimSpace(certFingerprint) == "" {
		if err := c.keyStore.SaveCert(aid, string(certBytes)); err != nil {
			log.Printf("写入证书到 keystore 失败 (aid=%s): %v", aid, err)
		}
	}

	return certBytes, nil
}

func (c *AUNClient) fetchPeerPrekeys(ctx context.Context, peerAID string) ([]map[string]any, error) {
	c.peerPrekeysMu.RLock()
	cached := c.peerPrekeysCache[peerAID]
	c.peerPrekeysMu.RUnlock()
	if cached != nil && float64(time.Now().Unix()) < cached.expireAt {
		items := make([]map[string]any, 0, len(cached.items))
		for _, item := range cached.items {
			items = append(items, copyMapShallow(item))
		}
		return items, nil
	}
	if cached := c.e2ee.GetCachedPrekey(peerAID); cached != nil {
		return []map[string]any{copyMapShallow(cached)}, nil
	}
	result, err := c.transport.Call(ctx, "message.e2ee.get_prekey", map[string]any{"aid": peerAID})
	if err != nil {
		return nil, NewValidationError(fmt.Sprintf("failed to fetch peer prekey for %s: %v", peerAID, err))
	}
	resultMap, ok := result.(map[string]any)
	if !ok || resultMap == nil {
		return nil, NewValidationError(fmt.Sprintf("invalid prekey response for %s", peerAID))
	}
	if found, ok := resultMap["found"].(bool); ok && !found {
		return []map[string]any{}, nil
	}
	if devicePrekeys, ok := resultMap["device_prekeys"].([]any); ok {
		normalized := make([]map[string]any, 0, len(devicePrekeys))
		for _, item := range devicePrekeys {
			if prekey, ok := extractPeerPrekeyMaterial(item); ok {
				normalized = append(normalized, copyMapShallow(prekey))
			}
		}
		if len(normalized) > 0 {
			c.peerPrekeysMu.Lock()
			c.peerPrekeysCache[peerAID] = &cachedPeerPrekeys{
				items:    normalized,
				expireAt: float64(time.Now().Unix()) + 300,
			}
			c.peerPrekeysMu.Unlock()
			c.e2ee.CachePrekey(peerAID, normalized[0])
			return normalized, nil
		}
	}
	prekey, err := parsePeerPrekeyResponse(peerAID, result, nil)
	if err != nil {
		if _, ok := err.(*NotFoundError); ok {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	if prekey != nil {
		c.peerPrekeysMu.Lock()
		c.peerPrekeysCache[peerAID] = &cachedPeerPrekeys{
			items:    []map[string]any{copyMapShallow(prekey)},
			expireAt: float64(time.Now().Unix()) + 300,
		}
		c.peerPrekeysMu.Unlock()
		c.e2ee.CachePrekey(peerAID, prekey)
		return []map[string]any{prekey}, nil
	}
	return []map[string]any{}, nil
}

// fetchPeerPrekey 获取对方的单个 prekey
func (c *AUNClient) fetchPeerPrekey(ctx context.Context, peerAID string) (map[string]any, error) {
	prekeys, err := c.fetchPeerPrekeys(ctx, peerAID)
	if err != nil {
		return nil, err
	}
	if len(prekeys) == 0 {
		return nil, nil
	}
	return copyMapShallow(prekeys[0]), nil
}

// uploadPrekey 生成 prekey 并上传到服务端
func (c *AUNClient) uploadPrekey(ctx context.Context) error {
	if c.prekeyUploadHook != nil {
		return c.prekeyUploadHook(ctx)
	}
	prekeyMaterial, err := c.e2ee.GeneratePrekey()
	if err != nil {
		return err
	}
	_, err = c.transport.Call(ctx, "message.e2ee.put_prekey", prekeyMaterial)
	return err
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

	if versioned, ok := c.keyStore.(keystore.VersionedCertKeyStore); ok && strings.TrimSpace(requestedFingerprint) != "" {
		if certPEM, err := versioned.LoadCertVersion(aid, requestedFingerprint); err == nil && certPEM != "" {
			now := float64(time.Now().Unix())
			c.certCacheMu.Lock()
			c.certCache[cacheKey] = &cachedPeerCert{certBytes: []byte(certPEM), validatedAt: now, refreshAfter: now + peerCertCacheTTL}
			c.certCacheMu.Unlock()
			return true
		}
	}
	if certPEM, err := c.keyStore.LoadCert(aid); err == nil && certPEM != "" {
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
			log.Printf("刷新发送方 %s 证书失败，继续使用已验证的内存缓存: %v", aid, err)
			return true
		}
		log.Printf("获取发送方 %s 证书失败且无已验证缓存，拒绝信任: %v", aid, err)
		return false
	}
	certPEM := string(certBytes)
	if versioned, ok := c.keyStore.(keystore.VersionedCertKeyStore); ok {
		// peer 证书只存版本目录，不覆盖 cert.pem
		if err := versioned.SaveCertVersion(aid, certPEM, requestedFingerprint, false); err != nil {
			log.Printf("保存版本化证书失败 (aid=%s): %v", aid, err)
		}
	} else if err := c.keyStore.SaveCert(aid, certPEM); err != nil {
		log.Printf("保存证书失败 (aid=%s): %v", aid, err)
	}
	return true
}

// getVerifiedPeerCert 获取经过 PKI 验证的 peer 证书（零信任：仅信任内存缓存中已验证的证书）
func (c *AUNClient) getVerifiedPeerCert(aid string, certFingerprint string) string {
	c.certCacheMu.RLock()
	cached := c.certCache[certCacheKey(aid, certFingerprint)]
	c.certCacheMu.RUnlock()
	if cached != nil && float64(time.Now().Unix()) < cached.validatedAt+peerCertCacheTTL*2 {
		return string(cached.certBytes)
	}
	return ""
}

// ── 解密辅助 ──────────────────────────────────────────────

// decryptSingleMessage 解密单条 P2P 消息
func (c *AUNClient) decryptSingleMessage(ctx context.Context, message map[string]any) map[string]any {
	payload, ok := message["payload"].(map[string]any)
	if !ok {
		return message
	}
	payloadType, _ := payload["type"].(string)
	if payloadType != "e2ee.encrypted" {
		if enc, ok := message["encrypted"].(bool); ok && enc {
			errMsg := fmt.Sprintf("不支持的 P2P 加密消息类型: %s", payloadType)
			log.Printf("[WARN] P2P 解密失败: %s", errMsg)
			message["_decrypt_error"] = errMsg
			return nil
		}
		return message
	}
	// 检查 encrypted 标记
	if enc, exists := message["encrypted"]; exists {
		if encBool, ok := enc.(bool); ok && !encBool {
			return message
		}
	}

	// 确保发送方证书已缓存
	fromAID, _ := message["from"].(string)
	senderCertFingerprint := ""
	if aad, ok := payload["aad"].(map[string]any); ok {
		senderCertFingerprint = strings.TrimSpace(strings.ToLower(getStr(aad, "sender_cert_fingerprint", "")))
	}
	if fp, ok := payload["sender_cert_fingerprint"].(string); ok && strings.TrimSpace(fp) != "" {
		senderCertFingerprint = strings.TrimSpace(strings.ToLower(fp))
	}
	if fromAID != "" {
		if !c.ensureSenderCertCached(ctx, fromAID, senderCertFingerprint) {
			errMsg := fmt.Sprintf("无法获取发送方 %s 的证书，跳过解密", fromAID)
			log.Printf("[WARN] P2P 解密失败: %s", errMsg)
			message["_decrypt_error"] = errMsg
			return nil
		}
	}

	// 密码学解密（E2EEManager.DecryptMessage 内含本地防重放）
	decrypted, err := c.e2ee.DecryptMessage(message)
	if err != nil || decrypted == nil {
		if err != nil {
			log.Printf("[WARN] P2P 解密失败: %v", err)
		} else {
			log.Printf("[WARN] P2P 解密失败: DecryptMessage 返回 nil")
		}
		return nil
	}
	c.schedulePrekeyReplenishIfConsumed(decrypted)
	return decrypted
}

// decryptMessages 批量解密 P2P 消息（用于 message.pull）
func (c *AUNClient) decryptMessages(ctx context.Context, messages []any) []any {
	seenInBatch := make(map[string]bool)
	var result []any
	for _, raw := range messages {
		msg, ok := raw.(map[string]any)
		if !ok {
			result = append(result, raw)
			continue
		}
		mid, _ := msg["message_id"].(string)
		if mid != "" && seenInBatch[mid] {
			continue
		}
		if mid != "" {
			seenInBatch[mid] = true
		}

		if c.tryHandleGroupKeyMessage(msg) {
			continue
		}

		payload, _ := msg["payload"].(map[string]any)
		payloadType, _ := payload["type"].(string)
		if payloadType == "e2ee.encrypted" {
			fromAID, _ := msg["from"].(string)
			if fromAID != "" {
				if !c.ensureSenderCertCached(ctx, fromAID) {
					// 证书不可用，丢弃密文，不投递给应用层
					continue
				}
			}
			// 使用内部解密，避免消耗 seen set
			decrypted, err := c.e2ee.decryptMessage(msg)
			if err == nil && decrypted != nil {
				// ISSUE-SDK-GO-002: pull 批量解密路径也需要补充 prekey
				c.schedulePrekeyReplenishIfConsumed(decrypted)
				result = append(result, decrypted)
			}
			// 解密失败：丢弃密文，不投递给应用层
		} else {
			result = append(result, raw)
		}
	}
	return result
}

// decryptGroupMessage 解密单条群组消息
func (c *AUNClient) decryptGroupMessage(ctx context.Context, message map[string]any) map[string]any {
	payload, ok := message["payload"].(map[string]any)
	if !ok {
		return message
	}
	payloadType, _ := payload["type"].(string)
	if payloadType != "e2ee.group_encrypted" {
		if enc, ok := message["encrypted"].(bool); ok && enc {
			errMsg := fmt.Sprintf("不支持的群加密消息类型: %s", payloadType)
			log.Printf("[WARN] 群消息解密失败: %s", errMsg)
			message["_decrypt_error"] = errMsg
			return nil
		}
		return message
	}

	// 确保发送方证书已缓存
	senderAID, _ := message["from"].(string)
	if senderAID == "" {
		senderAID, _ = message["sender_aid"].(string)
	}
	if senderAID != "" {
		if !c.ensureSenderCertCached(ctx, senderAID) {
			errMsg := fmt.Sprintf("群消息解密跳过：发送方 %s 证书不可用", senderAID)
			log.Printf("[WARN] %s", errMsg)
			message["_decrypt_error"] = errMsg
			return nil
		}
	}

	// 尝试直接解密
	result, decryptErr := c.groupE2EE.Decrypt(message, false)
	if decryptErr == nil && result != nil {
		if _, ok := result["e2ee"]; ok {
			return result
		}
	}

	// replay guard 命中：不是解密失败，不应触发 recover
	if errors.Is(decryptErr, ErrReplayDetected) {
		return nil
	}

	// 真正的解密失败，先同步请求目标 epoch key；5 秒内拿到则立即重解。
	groupID, _ := message["group_id"].(string)
	sender, _ := message["from"].(string)
	if sender == "" {
		sender, _ = message["sender_aid"].(string)
	}
	epoch := int(toInt64(payload["epoch"]))
	if epoch > 0 && groupID != "" {
		if c.recoverGroupEpochKey(ctx, groupID, epoch, sender, 5*time.Second) {
			retry, retryErr := c.groupE2EE.Decrypt(message, false)
			if retryErr == nil && retry != nil {
				if _, ok := retry["e2ee"]; ok {
					return retry
				}
			}
		}
	}

	// 密钥恢复后仍无法解密时返回 nil，由调用方发布 undecryptable 事件
	if decryptErr != nil {
		log.Printf("[WARN] 群消息解密失败: group=%s %v", groupID, decryptErr)
	} else {
		log.Printf("[WARN] 群消息解密失败: group=%s 解密结果无 e2ee 字段", groupID)
	}

	return nil
}

func (c *AUNClient) enqueuePendingDecrypt(groupID string, msg map[string]any) {
	if groupID == "" || msg == nil {
		return
	}
	ns := "group:" + groupID
	c.pendingDecryptMsgsMu.Lock()
	defer c.pendingDecryptMsgsMu.Unlock()
	if c.pendingDecryptMsgs == nil {
		c.pendingDecryptMsgs = make(map[string][]map[string]any)
	}
	queue := append(c.pendingDecryptMsgs[ns], copyMapShallow(msg))
	if len(queue) > 200 {
		queue = queue[len(queue)-200:]
	}
	c.pendingDecryptMsgs[ns] = queue
}

func (c *AUNClient) retryPendingDecryptMsgs(groupID string) {
	ns := "group:" + groupID
	c.pendingDecryptMsgsMu.Lock()
	queue := append([]map[string]any(nil), c.pendingDecryptMsgs[ns]...)
	c.pendingDecryptMsgs[ns] = nil
	c.pendingDecryptMsgsMu.Unlock()
	if len(queue) == 0 {
		return
	}
	stillPending := make([]map[string]any, 0)
	ctx := context.Background()
	for _, msg := range queue {
		decrypted := c.decryptGroupMessage(ctx, msg)
		if decrypted == nil {
			stillPending = append(stillPending, msg)
			continue
		}
		c.events.Publish("group.message_created", decrypted)
	}
	c.pendingDecryptMsgsMu.Lock()
	queuedDuringRetry := append([]map[string]any(nil), c.pendingDecryptMsgs[ns]...)
	mergedPending := append(stillPending, queuedDuringRetry...)
	if len(mergedPending) > 200 {
		mergedPending = mergedPending[len(mergedPending)-200:]
	}
	if len(mergedPending) > 0 {
		c.pendingDecryptMsgs[ns] = mergedPending
	} else {
		delete(c.pendingDecryptMsgs, ns)
	}
	c.pendingDecryptMsgsMu.Unlock()
}

func (c *AUNClient) recoverGroupEpochKey(ctx context.Context, groupID string, epoch int, senderAID string, timeout time.Duration) bool {
	// 快速路径：本地已有 committed epoch 密钥。pending key 必须先确认仍对应服务端状态，
	// 否则要继续发起 recovery，避免 stale pending key 阻断恢复。
	if secret, err := c.groupE2EE.LoadSecretForEpoch(groupID, epoch); err == nil && secret != nil {
		if c.groupEpochSecretReadyForRecovery(ctx, groupID, epoch, secret) {
			return true
		}
	}

	key := fmt.Sprintf("%s:%d", groupID, epoch)

	c.groupEpochRecoveryInflightMu.Lock()
	if entry, ok := c.groupEpochRecoveryInflight[key]; ok {
		// 已有恢复进行中，等待其完成
		c.groupEpochRecoveryInflightMu.Unlock()
		select {
		case <-entry.done:
			return entry.ok
		case <-ctx.Done():
			return false
		}
	}
	// 首个请求，注册 inflight 条目
	entry := &epochRecoveryResult{done: make(chan struct{})}
	c.groupEpochRecoveryInflight[key] = entry
	c.groupEpochRecoveryInflightMu.Unlock()

	// 执行实际恢复逻辑
	entry.ok = c.doRecoverGroupEpochKey(ctx, groupID, epoch, senderAID, timeout)
	close(entry.done)

	// 清理 inflight 条目
	c.groupEpochRecoveryInflightMu.Lock()
	delete(c.groupEpochRecoveryInflight, key)
	c.groupEpochRecoveryInflightMu.Unlock()

	return entry.ok
}

func (c *AUNClient) groupEpochSecretReadyForRecovery(ctx context.Context, groupID string, epoch int, secret map[string]any) bool {
	if secret == nil {
		return false
	}
	pendingRotationID := strings.TrimSpace(stringFromAny(secret["pending_rotation_id"]))
	if pendingRotationID == "" {
		return true
	}
	return c.pendingGroupSecretStillCurrent(ctx, groupID, epoch, pendingRotationID)
}

func (c *AUNClient) pendingGroupSecretStillCurrent(ctx context.Context, groupID string, epoch int, pendingRotationID string) bool {
	epochResult, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
	if err != nil {
		return false
	}
	epochMap, ok := epochResult.(map[string]any)
	if !ok {
		return false
	}
	if pending, ok := epochMap["pending_rotation"].(map[string]any); ok && !truthyBool(pending["expired"]) {
		if strings.TrimSpace(stringFromAny(pending["rotation_id"])) == pendingRotationID {
			return true
		}
	}
	if committedRotation, ok := epochMap["committed_rotation"].(map[string]any); ok {
		if int(toInt64(committedRotation["target_epoch"])) == epoch &&
			strings.TrimSpace(stringFromAny(committedRotation["rotation_id"])) == pendingRotationID {
			return true
		}
	}
	return false
}

// doRecoverGroupEpochKey 执行实际的 epoch key 恢复逻辑
func (c *AUNClient) doRecoverGroupEpochKey(ctx context.Context, groupID string, epoch int, senderAID string, timeout time.Duration) bool {
	epochResult := map[string]any{"epoch": epoch}
	if raw, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID}); err == nil {
		if m, ok := raw.(map[string]any); ok {
			for k, v := range m {
				epochResult[k] = v
			}
		}
	}
	if senderAID != "" {
		candidates, _ := epochResult["recovery_candidates"].([]any)
		epochResult["recovery_candidates"] = append([]any{senderAID}, candidates...)
	}
	c.requestGroupKeyFromCandidates(ctx, groupID, epoch, epochResult)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		if secret, err := c.groupE2EE.LoadSecretForEpoch(groupID, epoch); err == nil && secret != nil {
			if c.groupEpochSecretReadyForRecovery(ctx, groupID, epoch, secret) {
				go c.retryPendingDecryptMsgs(groupID)
				return true
			}
		}
	}
	if secret, err := c.groupE2EE.LoadSecretForEpoch(groupID, epoch); err == nil && secret != nil {
		if c.groupEpochSecretReadyForRecovery(ctx, groupID, epoch, secret) {
			go c.retryPendingDecryptMsgs(groupID)
			return true
		}
	}
	return false
}

// decryptGroupMessages 批量解密群组消息（用于 group.pull，跳过防重放）
func (c *AUNClient) decryptGroupMessages(ctx context.Context, messages []any) []any {
	var result []any
	for _, raw := range messages {
		msg, ok := raw.(map[string]any)
		if !ok {
			result = append(result, raw)
			continue
		}
		payload, ok := msg["payload"].(map[string]any)
		if !ok {
			result = append(result, raw)
			continue
		}
		payloadType, _ := payload["type"].(string)
		if payloadType != "e2ee.group_encrypted" {
			result = append(result, raw)
			continue
		}
		senderAID, _ := msg["from"].(string)
		if senderAID == "" {
			senderAID, _ = msg["sender_aid"].(string)
		}
		senderCertFingerprint := ""
		if payload, ok := msg["payload"].(map[string]any); ok {
			if aad, ok := payload["aad"].(map[string]any); ok {
				senderCertFingerprint = strings.TrimSpace(strings.ToLower(getStr(aad, "sender_cert_fingerprint", "")))
			}
			if fp, ok := payload["sender_cert_fingerprint"].(string); ok && strings.TrimSpace(fp) != "" {
				senderCertFingerprint = strings.TrimSpace(strings.ToLower(fp))
			}
		}
		if senderAID != "" {
			if !c.ensureSenderCertCached(ctx, senderAID, senderCertFingerprint) {
				// 证书不可用，丢弃密文，不投递给应用层
				continue
			}
		}
		decrypted := c.decryptGroupMessage(ctx, msg)
		if decrypted != nil {
			result = append(result, decrypted)
		} else if groupID, _ := msg["group_id"].(string); groupID != "" {
			c.enqueuePendingDecrypt(groupID, msg)
		}
		// 解密失败：保留待解队列，不投递密文给应用层
	}
	return result
}

// ── 内部：连接 ──────────────────────────────────────────────

// connectOnce 单次连接尝试
func (c *AUNClient) connectOnce(ctx context.Context, params map[string]any, allowReauth bool) error {
	gatewayURL := c.resolveGateway(params)

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
	challenge, err := c.transport.Connect(ctx, gatewayURL)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.state = StateAuthenticating
	c.mu.Unlock()

	// 认证
	if allowReauth {
		accessToken, _ := params["access_token"].(string)
		authContext, err := c.auth.ConnectSession(ctx, c.transport, challenge, gatewayURL, accessToken)
		if err != nil {
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
						c.logger.setAID(aidStr)
					}
				}
				if c.sessionParams != nil {
					if token, ok := authContext["token"].(string); ok && token != "" {
						c.sessionParams["access_token"] = token
					}
				}
				c.mu.Unlock()
			}
		}
	} else {
		accessToken, _ := params["access_token"].(string)
		if err := c.auth.InitializeWithToken(ctx, c.transport, challenge, accessToken); err != nil {
			return err
		}
		c.syncIdentityAfterConnect(accessToken)
	}

	// auth 阶段 aid 可能被 identity 覆盖；若 context 发生变化，重做 refresh + restore 兜底
	c.mu.Lock()
	c.state = StateConnected
	prevContext := c.seqTrackerContext
	c.refreshSeqTrackerContextLocked()
	contextChanged := c.seqTrackerContext != prevContext
	c.mu.Unlock()

	c.events.Publish("connection.state", map[string]any{"state": "connected", "gateway": gatewayURL})

	// 启动后台任务
	if contextChanged {
		c.restoreSeqTrackerState()
	}
	c.startBackgroundTasks(ctx)

	// 上线后自动上传 prekey
	if err := c.uploadPrekey(ctx); err != nil {
		log.Printf("prekey 上传失败: %v", err)
	}

	return nil
}

func buildSeqTrackerContext(aid, deviceID, slotID string) string {
	aid = strings.TrimSpace(aid)
	if aid == "" {
		return ""
	}
	return aid + "\x00" + strings.TrimSpace(deviceID) + "\x00" + strings.TrimSpace(slotID)
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
	c.groupSyncedMu.Lock()
	c.groupSynced = make(map[string]bool)
	c.groupSyncedMu.Unlock()
	c.p2pSyncedMu.Lock()
	c.p2pSynced = false
	c.p2pSyncedMu.Unlock()
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
	c.groupSyncedMu.Lock()
	c.groupSynced = make(map[string]bool)
	c.groupSyncedMu.Unlock()
	c.p2pSyncedMu.Lock()
	c.p2pSynced = false
	c.p2pSyncedMu.Unlock()
}

// resolveGateway 解析 Gateway URL
func (c *AUNClient) resolveGateway(params map[string]any) string {
	gateway, _ := params["gateway"].(string)
	if gateway == "" {
		c.mu.RLock()
		gateway = c.gatewayURL
		c.mu.RUnlock()
	}
	return gateway
}

// syncIdentityAfterConnect 使用 token 连接后同步本地身份
func (c *AUNClient) syncIdentityAfterConnect(accessToken string) {
	c.mu.RLock()
	aidStr := c.aid
	c.mu.RUnlock()

	identity := c.auth.LoadIdentityOrNil(aidStr)
	if identity == nil {
		c.mu.Lock()
		c.identity = nil
		c.mu.Unlock()
		return
	}
	identity["access_token"] = accessToken

	c.mu.Lock()
	c.identity = identity
	if loadedAID, ok := identity["aid"].(string); ok {
		c.aid = loadedAID
		if c.logger != nil {
			c.logger.setAID(loadedAID)
		}
	}
	c.mu.Unlock()

	if aidVal, ok := identity["aid"].(string); ok {
		if err := c.auth.persistIdentity(identity); err != nil {
			_ = c.keyStore.SaveIdentity(aidVal, identity)
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
	c.mu.Unlock()

	// 心跳循环
	go c.heartbeatLoop(ctx)
	// Token 刷新循环
	go c.tokenRefreshLoop(ctx)
	// 群组 epoch 相关任务
	c.startGroupEpochTasks(ctx)
	// 上线/重连后一次性同步所有群（消息+事件）
	go c.syncAllGroupsOnce()
}

// syncAllGroupsOnce 上线/重连后一次性同步所有已加入群：
// 1. 有 epoch key 的群 → 补消息 + 补事件
// 2. 无 epoch key 的群 → 仅补事件（事件不加密，等收到推送时触发密钥恢复）
// ISSUE-SDK-GO-011: 使用 goroutine 并发处理，加信号量限制并发数
func (c *AUNClient) syncAllGroupsOnce() {
	if c.closing.Load() {
		return
	}
	c.mu.RLock()
	state := c.state
	myAID := c.aid
	baseCtx := c.ctx
	c.mu.RUnlock()
	if state != StateConnected || myAID == "" || baseCtx == nil {
		return
	}
	ctx, cancel := context.WithTimeout(baseCtx, 30*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "group.list_my", map[string]any{})
	if err != nil {
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	items, ok := resultMap["items"].([]any)
	if !ok {
		return
	}

	// 并发限制：最多 5 个 goroutine 同时处理群同步
	const maxConcurrency = 5
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, raw := range items {
		g, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		gid, _ := g["group_id"].(string)
		if gid == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // 获取信号量
		go func(groupID string) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			// 有 epoch key → 补消息
			if c.groupE2EE.HasSecret(groupID) {
				c.fillGroupGap(groupID)
			}
			// 所有群都补事件（事件不加密）
			c.fillGroupEventGap(groupID)
		}(gid)
	}
	wg.Wait()
}

// pullAllGroupEventsOnce 兼容旧调用，委托给 syncAllGroupsOnce。
func (c *AUNClient) pullAllGroupEventsOnce() {
	c.syncAllGroupsOnce()
}

// heartbeatLoop 心跳循环
func (c *AUNClient) heartbeatLoop(ctx context.Context) {
	c.mu.RLock()
	interval := 30.0
	if opts := c.sessionOptions; opts != nil {
		if v, ok := opts["heartbeat_interval"].(float64); ok && v > 0 {
			interval = v
		}
	}
	c.mu.RUnlock()

	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer ticker.Stop()

	consecutiveFailures := 0
	maxFailures := 3 // 连续失败 3 次触发重连

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 先检查 ctx 是否已取消，避免用已取消的 context 发心跳导致误判
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
				continue
			}
			_, err := c.transport.Call(ctx, "meta.ping", map[string]any{})
			if err != nil {
				// ctx 取消导致的失败不算心跳失败
				if ctx.Err() != nil {
					return
				}
				consecutiveFailures++
				log.Printf("心跳失败 (%d/%d): %v", consecutiveFailures, maxFailures, err)
				c.events.Publish("connection.error", map[string]any{"error": err})
				if consecutiveFailures >= maxFailures {
					log.Printf("连续 %d 次心跳失败，触发断线重连", maxFailures)
					c.handleTransportDisconnect(err, -1)
					return
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

// tokenRefreshLoop Token 主动刷新循环
func (c *AUNClient) tokenRefreshLoop(ctx context.Context) {
	c.mu.RLock()
	lead := 60.0
	if opts := c.sessionOptions; opts != nil {
		if v, ok := opts["token_refresh_before"].(float64); ok && v > 0 {
			lead = v
		}
	}
	c.mu.RUnlock()

	const minimumSleep = 1 * time.Second

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
			sleepWithCancel(ctx, minimumSleep)
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
			sleepWithCancel(ctx, minimumSleep)
			continue
		}

		expiresAt := c.auth.GetAccessTokenExpiry(identity)
		if expiresAt == 0 {
			sleepWithCancel(ctx, minimumSleep)
			continue
		}

		delay := expiresAt - lead - float64(time.Now().Unix())
		if delay < 1.0 {
			delay = 1.0
		}
		sleepWithCancel(ctx, time.Duration(delay*float64(time.Second)))

		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 再次检查状态
		c.mu.RLock()
		isClosing = c.closing.Load()
		state = c.state
		gateway = c.gatewayURL
		c.mu.RUnlock()
		if isClosing || state != StateConnected || gateway == "" {
			continue
		}

		// 刷新 token
		refreshedIdentity, err := c.auth.RefreshCachedTokens(ctx, gateway, identity)
		if err != nil {
			log.Printf("token 刷新失败: %v", err)
			continue
		}

		c.mu.Lock()
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

// prekeyRefreshLoop Prekey 定时轮换循环
func (c *AUNClient) prekeyRefreshLoop(ctx context.Context) {
	return
}

// startGroupEpochTasks 启动群组 epoch 相关后台任务
func (c *AUNClient) startGroupEpochTasks(ctx context.Context) {

	// 旧 epoch 清理（每小时检查一次）
	go c.groupEpochCleanupLoop(ctx, 3600.0)

	// 定时 epoch 轮换
	rotateInterval := c.configModel.EpochAutoRotateInterval
	if rotateInterval > 0 {
		go c.groupEpochRotateLoop(ctx, float64(rotateInterval))
	}

	// 内存缓存定时清理（每小时扫描过期条目）
	go c.cacheCleanupLoop(ctx, 3600.0)
}

// groupEpochRotateLoop 定时轮换所有已知群组的 epoch
func (c *AUNClient) groupEpochRotateLoop(ctx context.Context, interval float64) {
	ticker := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			isClosing := c.closing.Load()
			state := c.state
			myAID := c.aid
			c.mu.RUnlock()
			if isClosing {
				return
			}
			if state != StateConnected || myAID == "" {
				continue
			}

			for _, gid := range listKeyStoreGroupIDs(c.keyStore, myAID) {
				c.maybeLeadRotateGroupEpoch(ctx, gid, "", nil)
			}
		}
	}
}

// groupEpochCleanupLoop 定时清理过期的旧 epoch 密钥
func (c *AUNClient) groupEpochCleanupLoop(ctx context.Context, interval float64) {
	ticker := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			isClosing := c.closing.Load()
			state := c.state
			myAID := c.aid
			c.mu.RUnlock()
			if isClosing {
				return
			}
			if state != StateConnected || myAID == "" {
				continue
			}

			retention := c.configModel.OldEpochRetentionSeconds
			for _, gid := range listKeyStoreGroupIDs(c.keyStore, myAID) {
				c.groupE2EE.Cleanup(gid, retention)
			}
		}
	}
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

			// prekey 列表缓存
			c.peerPrekeysMu.Lock()
			for k, v := range c.peerPrekeysCache {
				if now >= v.expireAt {
					delete(c.peerPrekeysCache, k)
				}
			}
			c.peerPrekeysMu.Unlock()

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

			// e2ee prekey 缓存
			c.e2ee.CleanExpiredCaches()
			// group e2ee replay guard 缓存
			c.groupE2EE.CleanExpiredCaches()
			// auth gateway 缓存
			c.auth.CleanExpiredCaches()
		}
	}
}

// ── Group E2EE 编排 ─────────────────────────────────────────

// buildRotationSignature 构建 epoch 轮换签名参数。
// 传入 source 时使用 v2 canonical JSON 签名，覆盖 rotation_id/key_commitment/成员 ack 集。
func (c *AUNClient) buildRotationSignature(groupID string, currentEpoch, newEpoch int, source ...map[string]any) map[string]any {
	c.mu.RLock()
	identity := c.identity
	c.mu.RUnlock()
	if identity == nil {
		return nil
	}
	privPEM, _ := identity["private_key_pem"].(string)
	if privPEM == "" {
		return nil
	}

	aidStr, _ := identity["aid"].(string)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	var signData []byte
	useV2 := len(source) > 0 && source[0] != nil
	if useV2 {
		src := source[0]
		signData = []byte(stableStringify(map[string]any{
			"version":            "v2",
			"group_id":           groupID,
			"base_epoch":         currentEpoch,
			"target_epoch":       newEpoch,
			"aid":                aidStr,
			"rotation_timestamp": ts,
			"rotation_id":        stringFromAny(firstNonNil(src["rotation_id"], src["new_rotation_id"])),
			"reason":             stringFromAny(src["reason"]),
			"key_commitment":     stringFromAny(src["key_commitment"]),
			"manifest_hash":      stringFromAny(src["manifest_hash"]),
			"epoch_chain":        stringFromAny(src["epoch_chain"]),
			"expected_members":   sortedStringListFromAny(src["expected_members"]),
			"required_acks":      sortedStringListFromAny(src["required_acks"]),
		}))
	} else {
		signData = []byte(fmt.Sprintf("%s|%d|%d|%s|%s", groupID, currentEpoch, newEpoch, aidStr, ts))
	}

	pk, err := parseECPrivateKeyPEM(privPEM)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(signData)
	sig, err := ecdsa.SignASN1(cryptorand.Reader, pk, hash[:])
	if err != nil {
		return nil
	}

	result := map[string]any{
		"rotation_signature": base64.StdEncoding.EncodeToString(sig),
		"rotation_timestamp": ts,
	}
	if useV2 {
		result["rotation_sig_version"] = "v2"
	}
	return result
}

func (c *AUNClient) getGroupMemberAIDs(ctx context.Context, groupID string) ([]string, error) {
	membersResult, err := c.Call(ctx, "group.get_members", map[string]any{"group_id": groupID})
	if err != nil {
		return nil, err
	}
	membersMap, ok := membersResult.(map[string]any)
	if !ok {
		return nil, NewStateError(fmt.Sprintf("group %s members response invalid", groupID))
	}
	membersList, _ := membersMap["members"].([]any)
	return extractAIDsFromMembers(membersList), nil
}

func (c *AUNClient) distributeGroupEpochKey(ctx context.Context, info map[string]any, rotationID string) (sent []string, failed []string) {
	rawDist := info["distributions"]
	distributions := make([]map[string]any, 0)
	switch v := rawDist.(type) {
	case []map[string]any:
		distributions = v
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				distributions = append(distributions, m)
			}
		}
	}

	lastHeartbeat := time.Now()
	for _, dist := range distributions {
		to, _ := dist["to"].(string)
		distPayload, _ := dist["payload"].(map[string]any)
		if to == "" || distPayload == nil {
			continue
		}
		if rotationID != "" && time.Since(lastHeartbeat) >= 20*time.Second {
			if c.heartbeatGroupRotation(ctx, rotationID) {
				lastHeartbeat = time.Now()
			}
		}
		ok := false
		for attempt := 0; attempt < 3; attempt++ {
			_, sendErr := c.Call(ctx, "message.send", map[string]any{
				"to":               to,
				"payload":          distPayload,
				"encrypt":          true,
				"persist_required": true,
			})
			if sendErr == nil {
				sent = append(sent, to)
				ok = true
				break
			}
			if attempt < 2 {
				time.Sleep(time.Duration(attempt+1) * time.Second)
			} else {
				log.Printf("epoch 密钥分发失败 (to=%s): %v", to, sendErr)
			}
		}
		if !ok {
			failed = append(failed, to)
		}
	}
	return sent, failed
}

func (c *AUNClient) heartbeatGroupRotation(ctx context.Context, rotationID string) bool {
	if strings.TrimSpace(rotationID) == "" {
		return false
	}
	result, err := c.Call(ctx, "group.e2ee.heartbeat_rotation", map[string]any{
		"rotation_id": rotationID,
		"lease_ms":    groupRotationLeaseMS,
	})
	if err != nil {
		log.Printf("刷新 epoch rotation lease 失败: rotation=%s err=%v", rotationID, err)
		return false
	}
	resultMap, _ := result.(map[string]any)
	return truthyBool(resultMap["success"])
}

func (c *AUNClient) ackGroupRotationKey(ctx context.Context, rotationID string, keyCommitment string) bool {
	if strings.TrimSpace(rotationID) == "" {
		return false
	}
	result, err := c.Call(ctx, "group.e2ee.ack_rotation_key", map[string]any{
		"rotation_id":    rotationID,
		"key_commitment": keyCommitment,
		"device_id":      c.deviceID,
	})
	if err != nil {
		log.Printf("提交 epoch key ack 失败: rotation=%s err=%v", rotationID, err)
		return false
	}
	resultMap, _ := result.(map[string]any)
	return truthyBool(resultMap["success"])
}

func (c *AUNClient) verifyActiveGroupRotationDistribution(ctx context.Context, payload map[string]any) bool {
	rotationID := strings.TrimSpace(stringFromAny(payload["rotation_id"]))
	groupID := strings.TrimSpace(stringFromAny(payload["group_id"]))
	if groupID == "" {
		return false
	}
	epoch := int(toInt64(payload["epoch"]))
	if epoch <= 0 {
		return false
	}
	commitment := strings.TrimSpace(stringFromAny(payload["commitment"]))
	epochResult, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
	if err != nil {
		log.Printf("拒绝无法校验 active rotation 的 epoch key 分发: group=%s rotation=%s err=%v", groupID, rotationID, err)
		return false
	}
	epochMap, ok := epochResult.(map[string]any)
	if !ok {
		return false
	}
	committedEpoch := int(toInt64(firstNonNil(epochMap["committed_epoch"], epochMap["epoch"])))
	committedRotation, _ := epochMap["committed_rotation"].(map[string]any)
	if rotationID == "" {
		if epoch > 0 && epoch <= committedEpoch {
			if committedRotation != nil && int(toInt64(firstNonNil(committedRotation["target_epoch"], committedEpoch))) == epoch {
				committedCommitment := strings.TrimSpace(stringFromAny(committedRotation["key_commitment"]))
				if committedCommitment != "" && commitment != "" && committedCommitment != commitment {
					return false
				}
			}
			return true
		}
		log.Printf("拒绝缺少 rotation_id 的未来 epoch key 分发: group=%s epoch=%d committed=%d", groupID, epoch, committedEpoch)
		return false
	}
	if pending, ok := epochMap["pending_rotation"].(map[string]any); ok && !truthyBool(pending["expired"]) {
		pendingCommitment := strings.TrimSpace(stringFromAny(pending["key_commitment"]))
		if strings.TrimSpace(stringFromAny(pending["rotation_id"])) == rotationID &&
			int(toInt64(pending["target_epoch"])) == epoch &&
			(pendingCommitment == "" || pendingCommitment == commitment) {
			return true
		}
	}
	if committedRotation != nil && committedEpoch >= epoch {
		committedCommitment := strings.TrimSpace(stringFromAny(committedRotation["key_commitment"]))
		if strings.TrimSpace(stringFromAny(committedRotation["rotation_id"])) == rotationID &&
			(committedCommitment == "" || committedCommitment == commitment) {
			return true
		}
	}
	log.Printf("拒绝非 pending/committed 状态的 epoch key 分发: group=%s rotation=%s epoch=%d", groupID, rotationID, epoch)
	return false
}

func (c *AUNClient) discardGroupDistributionIfStale(ctx context.Context, payload map[string]any) {
	rotationID := strings.TrimSpace(stringFromAny(payload["rotation_id"]))
	if rotationID == "" {
		return
	}
	groupID := strings.TrimSpace(stringFromAny(payload["group_id"]))
	epoch := int(toInt64(payload["epoch"]))
	if groupID == "" || epoch <= 0 {
		return
	}
	if c.verifyActiveGroupRotationDistribution(ctx, payload) {
		return
	}
	if ok, err := c.groupE2EE.DiscardPendingSecret(groupID, epoch, rotationID); err != nil {
		log.Printf("[aun_core] 清理 stale group epoch key 失败: group=%s epoch=%d rotation=%s err=%v", groupID, epoch, rotationID, err)
	} else if ok {
		log.Printf("[aun_core] 丢弃 verify 后变为 stale 的 group epoch key: group=%s epoch=%d rotation=%s", groupID, epoch, rotationID)
	}
}

func (c *AUNClient) verifyGroupKeyResponseEpoch(ctx context.Context, payload map[string]any) bool {
	groupID := strings.TrimSpace(stringFromAny(payload["group_id"]))
	if groupID == "" {
		return false
	}
	epoch := int(toInt64(payload["epoch"]))
	if epoch <= 0 {
		return false
	}
	commitment := strings.TrimSpace(stringFromAny(payload["commitment"]))
	epochResult, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
	if err != nil {
		log.Printf("拒绝无法校验 committed epoch 的 group key response: group=%s epoch=%d err=%v", groupID, epoch, err)
		return false
	}
	epochMap, ok := epochResult.(map[string]any)
	if !ok {
		return false
	}
	committedEpoch := int(toInt64(firstNonNil(epochMap["committed_epoch"], epochMap["epoch"])))
	if epoch > committedEpoch {
		log.Printf("拒绝未提交 epoch 的 group key response: group=%s epoch=%d committed=%d", groupID, epoch, committedEpoch)
		return false
	}
	committedRotation, _ := epochMap["committed_rotation"].(map[string]any)
	if committedRotation != nil && int(toInt64(firstNonNil(committedRotation["target_epoch"], committedEpoch))) == epoch {
		committedCommitment := strings.TrimSpace(stringFromAny(committedRotation["key_commitment"]))
		if committedCommitment != "" && commitment != "" && committedCommitment != commitment {
			return false
		}
	}
	return true
}

func (c *AUNClient) abortGroupRotation(ctx context.Context, rotationID string, reason string) bool {
	if strings.TrimSpace(rotationID) == "" {
		return false
	}
	if strings.TrimSpace(reason) == "" {
		reason = "client_abort"
	}
	result, err := c.Call(ctx, "group.e2ee.abort_rotation", map[string]any{
		"rotation_id": rotationID,
		"reason":      reason,
	})
	if err != nil {
		log.Printf("中止 epoch rotation 失败: rotation=%s err=%v", rotationID, err)
		return false
	}
	resultMap, _ := result.(map[string]any)
	return truthyBool(resultMap["success"])
}

func rotationExpectedMembersStale(rotation map[string]any, memberAIDs []string) bool {
	expected := sortedStringListFromAny(rotation["expected_members"])
	current := append([]string(nil), memberAIDs...)
	sort.Strings(current)
	return len(expected) > 0 && len(current) > 0 && strings.Join(expected, "\n") != strings.Join(current, "\n")
}

func (c *AUNClient) rotationRetryDelay(pending map[string]any) time.Duration {
	var leaseExpiresAt int64
	if pending != nil && !truthyBool(pending["expired"]) {
		status := strings.TrimSpace(stringFromAny(pending["status"]))
		if status == "" || status == "distributing" {
			leaseExpiresAt = toInt64(pending["lease_expires_at"])
		}
	}
	base := 5 * time.Second
	if leaseExpiresAt > 0 {
		remaining := time.Until(time.UnixMilli(leaseExpiresAt)) + time.Second
		if remaining > base {
			base = remaining
		}
	}
	jitterMs, _ := cryptorand.Int(cryptorand.Reader, big.NewInt(2000))
	delay := base + time.Duration(jitterMs.Int64())*time.Millisecond
	if delay > groupRotationRetryMaxDelay {
		return groupRotationRetryMaxDelay
	}
	return delay
}

func (c *AUNClient) scheduleGroupRotationRetry(groupID, reason, triggerID string, expectedEpoch int, pending map[string]any) {
	retryKey := fmt.Sprintf("%s:%s:%s:%d", groupID, firstNonEmpty(triggerID, reason), reason, expectedEpoch)
	c.groupEpochRotationMu.Lock()
	if c.groupEpochRotationRetrying[retryKey] {
		c.groupEpochRotationMu.Unlock()
		return
	}
	c.groupEpochRotationRetrying[retryKey] = true
	c.groupEpochRotationMu.Unlock()

	delay := c.rotationRetryDelay(pending)
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		c.mu.RLock()
		baseCtx := c.ctx
		c.mu.RUnlock()
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		select {
		case <-baseCtx.Done():
		case <-timer.C:
		}
		c.groupEpochRotationMu.Lock()
		delete(c.groupEpochRotationRetrying, retryKey)
		c.groupEpochRotationMu.Unlock()
		if baseCtx.Err() != nil || c.closing.Load() {
			return
		}
		c.mu.RLock()
		state := c.state
		c.mu.RUnlock()
		if state != StateConnected {
			return
		}
		expected := expectedEpoch
		c.maybeLeadRotateGroupEpoch(context.Background(), groupID, triggerID, &expected)
	}()
}

// syncEpochToServer 建群后将本地 epoch 1 同步到服务端，最多重试 3 次
func (c *AUNClient) syncEpochToServer(ctx context.Context, groupID string) {
	const maxRetries = 3
	started := time.Now()
	for {
		c.groupEpochRotationMu.Lock()
		if !c.groupEpochRotationInflight[groupID] {
			c.groupEpochRotationInflight[groupID] = true
			c.groupEpochRotationMu.Unlock()
			break
		}
		c.groupEpochRotationMu.Unlock()
		if time.Since(started) > 20*time.Second {
			log.Printf("group epoch create sync still in-flight; skip duplicate sync (group=%s)", groupID)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer func() {
		c.groupEpochRotationMu.Lock()
		delete(c.groupEpochRotationInflight, groupID)
		c.groupEpochRotationMu.Unlock()
	}()
	for attempt := 1; attempt <= maxRetries; attempt++ {
		c.mu.RLock()
		myAID := c.aid
		c.mu.RUnlock()
		if myAID == "" {
			return
		}
		secretData, secretErr := c.groupE2EE.LoadSecretForEpoch(groupID, 1)
		if secretErr != nil || secretData == nil {
			log.Printf("同步 epoch 到服务端失败: group=%s epoch1 secret missing err=%v", groupID, secretErr)
			return
		}
		rotationID := "rot-" + strings.ReplaceAll(generateUUID4(), "-", "")
		members := toStringSlice(secretData["member_aids"])
		if len(members) == 0 {
			members = []string{myAID}
		}
		rotateParams := map[string]any{
			"group_id":         groupID,
			"base_epoch":       0,
			"target_epoch":     1,
			"rotation_id":      rotationID,
			"reason":           "create_group",
			"key_commitment":   stringFromAny(secretData["commitment"]),
			"epoch_chain":      stringFromAny(secretData["epoch_chain"]),
			"expected_members": members,
			"required_acks":    []string{myAID},
			"lease_ms":         groupRotationLeaseMS,
		}
		sigParams := c.buildRotationSignature(groupID, 0, 1, rotateParams)
		for k, v := range sigParams {
			rotateParams[k] = v
		}
		beginResult, err := c.Call(ctx, "group.e2ee.begin_rotation", rotateParams)
		if err == nil {
			beginMap, ok := beginResult.(map[string]any)
			rotation, _ := beginMap["rotation"].(map[string]any)
			if ok && truthyBool(beginMap["success"]) && rotation != nil {
				activeRotationID := firstNonEmpty(stringFromAny(rotation["rotation_id"]), rotationID)
				if !c.ackGroupRotationKey(ctx, activeRotationID, stringFromAny(secretData["commitment"])) {
					log.Printf("group epoch self ack failed (group=%s, rotation=%s)", groupID, activeRotationID)
					c.abortGroupRotation(ctx, activeRotationID, "self_ack_failed")
					return
				}
				commitResult, commitErr := c.Call(ctx, "group.e2ee.commit_rotation", map[string]any{"rotation_id": activeRotationID})
				if commitErr == nil {
					commitMap, _ := commitResult.(map[string]any)
					if truthyBool(commitMap["success"]) {
						secret, _ := secretData["secret"].([]byte)
						StoreGroupSecret(c.keyStore, myAID, groupID, 1, secret, stringFromAny(secretData["commitment"]), members, stringFromAny(secretData["epoch_chain"]))
						return
					}
					log.Printf("group epoch commit failed (group=%s, returned=%v)", groupID, commitResult)
					return
				}
				log.Printf("group epoch commit failed (group=%s): %v", groupID, commitErr)
				return
			}
			log.Printf("group epoch begin failed; stop key distribution (group=%s, returned=%v)", groupID, beginResult)
			return
		}
		if attempt < maxRetries {
			delay := time.Duration(500*(1<<(attempt-1))) * time.Millisecond
			log.Printf("同步 epoch 到服务端失败 (group=%s, 第%d/%d次): %v, %v后重试", groupID, attempt, maxRetries, err, delay)
			time.Sleep(delay)
		} else {
			log.Printf("同步 epoch 到服务端最终失败 (group=%s, 已重试%d次): %v", groupID, maxRetries, err)
		}
	}
}

func randomLeaderRotateJitter() time.Duration {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(4000))
	if err != nil {
		return 3 * time.Second
	}
	return time.Duration(2000+n.Int64()) * time.Millisecond
}

// maybeLeadRotateGroupEpoch 基于"排序最小 admin = leader"选举自动触发 epoch 轮换。
// 非 owner/admin 不会发起 rotate；非 leader admin 在 jitter 后做一次兜底。
func (c *AUNClient) maybeLeadRotateGroupEpoch(ctx context.Context, groupID string, triggerID string, expectedEpoch *int) {
	c.mu.RLock()
	myAID := c.aid
	state := c.state
	c.mu.RUnlock()
	if groupID == "" || myAID == "" || c.closing.Load() || state != StateConnected {
		return
	}

	started := time.Now()
	for {
		c.groupEpochRotationMu.Lock()
		if !c.groupEpochRotationInflight[groupID] {
			c.groupEpochRotationInflight[groupID] = true
			c.groupEpochRotationMu.Unlock()
			break
		}
		done := triggerID != "" && c.groupMembershipRotationDone[triggerID]
		c.groupEpochRotationMu.Unlock()
		if done {
			return
		}
		c.mu.RLock()
		state = c.state
		c.mu.RUnlock()
		if c.closing.Load() || state != StateConnected {
			return
		}
		if time.Since(started) > 20*time.Second {
			log.Printf("group epoch rotation still in-flight; skip pending trigger (group=%s trigger=%s)", groupID, triggerID)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer func() {
		c.groupEpochRotationMu.Lock()
		delete(c.groupEpochRotationInflight, groupID)
		c.groupEpochRotationMu.Unlock()
	}()
	c.mu.RLock()
	state = c.state
	c.mu.RUnlock()
	if c.closing.Load() || state != StateConnected {
		return
	}

	membersResult, err := c.Call(ctx, "group.get_members", map[string]any{"group_id": groupID})
	if err != nil {
		log.Printf("_maybeLeadRotateGroupEpoch 获取成员失败: group=%s %v", groupID, err)
		return
	}
	membersMap, ok := membersResult.(map[string]any)
	if !ok {
		return
	}
	membersList, _ := membersMap["members"].([]any)
	admins := make([]string, 0, len(membersList))
	for _, item := range membersList {
		member, ok := item.(map[string]any)
		if !ok {
			continue
		}
		aid, _ := member["aid"].(string)
		role, _ := member["role"].(string)
		if aid != "" && (role == "owner" || role == "admin") {
			admins = append(admins, aid)
		}
	}
	if len(admins) == 0 {
		return
	}
	sort.Strings(admins)
	leader := admins[0]
	if leader == myAID {
		c.rotateGroupEpoch(ctx, groupID, triggerID, expectedEpoch)
		return
	}
	if !stringSliceContains(admins, myAID) {
		return
	}

	// 查询服务端 epoch（本地可能因未收到密钥分发而滞后）
	beforeEpoch := 0
	if resp, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID}); err == nil {
		if m, ok := resp.(map[string]any); ok {
			beforeEpoch = int(toInt64(m["epoch"]))
		}
	} else if epoch := c.groupE2EE.CurrentEpoch(groupID); epoch != nil {
		beforeEpoch = *epoch
	}
	timer := time.NewTimer(randomLeaderRotateJitter())
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	c.mu.RLock()
	state = c.state
	c.mu.RUnlock()
	if c.closing.Load() || state != StateConnected {
		return
	}
	afterEpoch := 0
	var afterMap map[string]any
	if resp, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID}); err == nil {
		if m, ok := resp.(map[string]any); ok {
			afterMap = m
			afterEpoch = int(toInt64(m["epoch"]))
		}
	} else if epoch := c.groupE2EE.CurrentEpoch(groupID); epoch != nil {
		afterEpoch = *epoch
	}
	if afterEpoch > beforeEpoch {
		return
	}
	if pending, ok := afterMap["pending_rotation"].(map[string]any); ok && !truthyBool(pending["expired"]) {
		exp := afterEpoch
		if expectedEpoch != nil {
			exp = *expectedEpoch
		}
		c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, pending)
		return
	}
	log.Printf("[H21] leader 未完成 epoch 轮换，非 leader 兜底: group=%s myAid=%s", groupID, myAID)
	c.rotateGroupEpoch(ctx, groupID, triggerID, expectedEpoch)
}

// rotateGroupEpoch 为指定群组轮换 epoch 并分发新密钥（使用服务端两阶段 rotation）
func (c *AUNClient) rotateGroupEpoch(ctx context.Context, groupID string, triggerID string, expectedEpoch *int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("rotateGroupEpoch panic: %v", r)
		}
	}()
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}

	memberAIDs, err := c.getGroupMemberAIDs(ctx, groupID)
	if err != nil {
		c.logE2EEError("rotate_epoch", groupID, "", err)
		return
	}
	if triggerID != "" {
		c.groupEpochRotationMu.Lock()
		done := c.groupMembershipRotationDone[triggerID]
		c.groupEpochRotationMu.Unlock()
		if done {
			return
		}
	}

	epochResult, err := c.Call(ctx, "group.e2ee.get_epoch", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2EEError("rotate_epoch", groupID, "", err)
		return
	}
	epochMap, ok := epochResult.(map[string]any)
	if !ok {
		return
	}
	serverEpoch := int(toInt64(epochMap["epoch"]))
	if pendingRotation, ok := epochMap["pending_rotation"].(map[string]any); ok && !truthyBool(pendingRotation["expired"]) {
		pendingRotationID := stringFromAny(pendingRotation["rotation_id"])
		if expectedEpoch != nil && serverEpoch == *expectedEpoch && rotationExpectedMembersStale(pendingRotation, memberAIDs) &&
			c.abortGroupRotation(ctx, pendingRotationID, "membership_changed_during_rotation") {
			log.Printf("aborted stale pending group epoch rotation: group=%s rotation=%s", groupID, firstNonEmpty(pendingRotationID, "-"))
		} else {
			exp := serverEpoch
			if expectedEpoch != nil {
				exp = *expectedEpoch
			}
			c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, pendingRotation)
			return
		}
	}
	if expectedEpoch != nil && serverEpoch != *expectedEpoch {
		if triggerID != "" {
			c.groupEpochRotationMu.Lock()
			c.groupMembershipRotationDone[triggerID] = true
			c.groupEpochRotationMu.Unlock()
		}
		log.Printf("skip membership epoch rotation: group=%s expected_epoch=%d server_epoch=%d trigger=%s", groupID, *expectedEpoch, serverEpoch, triggerID)
		return
	}
	currentEpoch := serverEpoch
	if expectedEpoch != nil {
		currentEpoch = *expectedEpoch
	}
	targetEpoch := currentEpoch + 1
	rotationID := "rot-" + strings.ReplaceAll(generateUUID4(), "-", "")

	info, err := c.groupE2EE.RotateEpochTo(groupID, targetEpoch, memberAIDs, rotationID)
	if err != nil {
		c.logE2EEError("rotate_epoch", groupID, "", err)
		return
	}
	discardGeneratedPending := func() {
		if _, err := c.groupE2EE.DiscardPendingSecret(groupID, targetEpoch, rotationID); err != nil {
			log.Printf("[aun_core] 清理本地 pending group key 失败: group=%s epoch=%d rotation=%s err=%v",
				groupID, targetEpoch, rotationID, err)
		}
	}
	commitment := stringFromAny(info["commitment"])
	rotationReason := "manual"
	if triggerID != "" || expectedEpoch != nil {
		rotationReason = "membership_changed"
	}
	rotateParams := map[string]any{
		"group_id":         groupID,
		"base_epoch":       currentEpoch,
		"target_epoch":     targetEpoch,
		"rotation_id":      rotationID,
		"reason":           rotationReason,
		"key_commitment":   commitment,
		"expected_members": memberAIDs,
		"required_acks":    []string{myAID},
		"lease_ms":         groupRotationLeaseMS,
	}
	sigParams := c.buildRotationSignature(groupID, currentEpoch, targetEpoch, rotateParams)
	for k, v := range sigParams {
		rotateParams[k] = v
	}
	beginResult, err := c.Call(ctx, "group.e2ee.begin_rotation", rotateParams)
	if err != nil {
		discardGeneratedPending()
		c.logE2EEError("rotate_epoch", groupID, "", err)
		return
	}
	beginMap, ok := beginResult.(map[string]any)
	if !ok {
		discardGeneratedPending()
		return
	}
	rotation, _ := beginMap["rotation"].(map[string]any)
	if !truthyBool(beginMap["success"]) || rotation == nil {
		if rotation != nil && !truthyBool(rotation["expired"]) {
			exp := currentEpoch
			if expectedEpoch != nil {
				exp = *expectedEpoch
			}
			if rotationExpectedMembersStale(rotation, memberAIDs) &&
				c.abortGroupRotation(ctx, stringFromAny(rotation["rotation_id"]), "membership_changed_during_rotation") {
				c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, nil)
			} else {
				c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, rotation)
			}
		} else if stringFromAny(beginMap["reason"]) == "expected_members_mismatch" {
			exp := currentEpoch
			if expectedEpoch != nil {
				exp = *expectedEpoch
			}
			c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, nil)
		}
		log.Printf("group epoch begin failed; stop key distribution (group=%s current_epoch=%d returned=%v)", groupID, currentEpoch, beginResult)
		discardGeneratedPending()
		return
	}
	activeRotationID := firstNonEmpty(stringFromAny(rotation["rotation_id"]), rotationID)
	_, failed := c.distributeGroupEpochKey(ctx, info, activeRotationID)
	if len(failed) > 0 {
		log.Printf("group epoch key distribution incomplete; abort rotation before retry (group=%s rotation=%s failed=%s)",
			groupID, activeRotationID, strings.Join(failed, ","))
		c.abortGroupRotation(ctx, activeRotationID, "distribution_failed")
		exp := currentEpoch
		if expectedEpoch != nil {
			exp = *expectedEpoch
		}
		c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, nil)
		discardGeneratedPending()
		return
	}
	c.heartbeatGroupRotation(ctx, activeRotationID)
	if !c.ackGroupRotationKey(ctx, activeRotationID, commitment) {
		log.Printf("group epoch self ack failed; abort rotation before retry (group=%s rotation=%s)", groupID, activeRotationID)
		c.abortGroupRotation(ctx, activeRotationID, "self_ack_failed")
		exp := currentEpoch
		if expectedEpoch != nil {
			exp = *expectedEpoch
		}
		c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, nil)
		discardGeneratedPending()
		return
	}
	commitResult, err := c.Call(ctx, "group.e2ee.commit_rotation", map[string]any{"rotation_id": activeRotationID})
	if err != nil {
		c.logE2EEError("rotate_epoch", groupID, "", err)
		exp := currentEpoch
		if expectedEpoch != nil {
			exp = *expectedEpoch
		}
		c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, rotation)
		return
	}
	commitMap, _ := commitResult.(map[string]any)
	if !truthyBool(commitMap["success"]) {
		pending, _ := commitMap["rotation"].(map[string]any)
		exp := currentEpoch
		if expectedEpoch != nil {
			exp = *expectedEpoch
		}
		c.scheduleGroupRotationRetry(groupID, "membership_changed", triggerID, exp, pending)
		log.Printf("group epoch commit failed (group=%s rotation=%s returned=%v)", groupID, activeRotationID, commitResult)
		if !(pending != nil &&
			stringFromAny(pending["rotation_id"]) == activeRotationID &&
			stringFromAny(pending["status"]) == "distributing") {
			discardGeneratedPending()
		}
		return
	}
	if committedSecret, _ := c.groupE2EE.LoadSecretForEpoch(groupID, targetEpoch); committedSecret != nil {
		committedRotation, _ := commitMap["rotation"].(map[string]any)
		if committedRotation == nil {
			committedRotation = map[string]any{
				"rotation_id":    activeRotationID,
				"key_commitment": commitment,
			}
		}
		if c.groupSecretMatchesCommittedRotation(committedSecret, committedRotation) {
			secret, _ := committedSecret["secret"].([]byte)
			members := toStringSlice(committedSecret["member_aids"])
			if len(members) == 0 {
				members = memberAIDs
			}
			StoreGroupSecret(c.keyStore, myAID, groupID, targetEpoch, secret, stringFromAny(committedSecret["commitment"]), members, stringFromAny(committedSecret["epoch_chain"]))
		} else {
			log.Printf("[aun_core] group epoch commit succeeded but local target key does not match committed rotation; keep pending blocked (group=%s rotation=%s epoch=%d)",
				groupID, activeRotationID, targetEpoch)
		}
	}
	if triggerID != "" {
		c.groupEpochRotationMu.Lock()
		c.groupMembershipRotationDone[triggerID] = true
		if len(c.groupMembershipRotationDone) > 2000 {
			c.groupMembershipRotationDone = make(map[string]bool)
		}
		c.groupEpochRotationMu.Unlock()
	}
}

// distributeKeyToNewMember 将当前 group_secret 通过 P2P E2EE 分发给新成员
func (c *AUNClient) distributeKeyToNewMember(ctx context.Context, groupID, newMemberAID string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("distributeKeyToNewMember panic: %v", r)
		}
	}()

	secretData, _ := c.groupE2EE.LoadSecret(groupID)
	if secretData == nil {
		return
	}

	// 拉服务端最新成员列表
	membersResult, err := c.Call(ctx, "group.get_members", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2EEError("distribute_key", groupID, newMemberAID, err)
		return
	}
	membersMap, ok := membersResult.(map[string]any)
	if !ok {
		return
	}
	membersList, _ := membersMap["members"].([]any)
	memberAIDs := extractAIDsFromMembers(membersList)

	// 更新本地 member_aids/commitment
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()

	epoch := int(toInt64(secretData["epoch"]))
	secret, _ := secretData["secret"].([]byte)
	commitment := ComputeMembershipCommitment(memberAIDs, epoch, groupID, secret)
	StoreGroupSecret(c.keyStore, myAID, groupID, epoch, secret, commitment, memberAIDs, "")

	// 构建并签名 manifest
	prevEpoch := epoch
	manifest := BuildMembershipManifest(
		groupID, epoch, &prevEpoch,
		memberAIDs, []string{newMemberAID}, nil, myAID,
	)

	c.mu.RLock()
	identity := c.identity
	c.mu.RUnlock()
	if identity != nil {
		if privPEM, ok := identity["private_key_pem"].(string); ok && privPEM != "" {
			signed, err := SignMembershipManifest(manifest, privPEM)
			if err == nil {
				manifest = signed
			}
		}
	}

	distPayload := BuildKeyDistribution(groupID, epoch, secret, memberAIDs, myAID, manifest, stringFromAny(secretData["epoch_chain"]))
	// 重试 3 次，间隔递增（1s, 2s）
	for attempt := 0; attempt < 3; attempt++ {
		_, err = c.Call(ctx, "message.send", map[string]any{
			"to":               newMemberAID,
			"payload":          distPayload,
			"encrypt":          true,
			"persist_required": true,
		})
		if err == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		} else {
			c.logE2EEError("distribute_key", groupID, newMemberAID, err)
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
	if store, ok := c.keyStore.(keystore.SeqTrackerStore); ok {
		seqs, err := store.LoadAllSeqs(aid, deviceID, slotID)
		if err != nil || len(seqs) == 0 {
			return
		}
		c.seqTracker.RestoreState(seqs)
		return
	}
	// 降级：从 instance_state JSON 读取（兼容旧数据）
	if store, ok := c.keyStore.(keystore.InstanceStateStore); ok {
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
			c.seqTracker.RestoreState(intState)
		}
	}
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
	if store, ok := c.keyStore.(keystore.SeqTrackerStore); ok {
		for ns, seq := range state {
			_ = store.SaveSeq(aid, deviceID, slotID, ns, seq)
		}
		return
	}
	log.Printf("[client] keystore 不支持 SeqTrackerStore，seq_tracker_state 未持久化")
}

// logE2EEError 记录 E2EE 自动编排错误
func (c *AUNClient) logE2EEError(stage, groupID, aid string, err error) {
	log.Printf("[e2ee] 编排错误: stage=%s group=%s aid=%s error=%v", stage, groupID, aid, err)
	c.events.Publish("e2ee.orchestration_error", map[string]any{
		"stage":    stage,
		"group_id": groupID,
		"aid":      aid,
		"error":    err.Error(),
	})
}

// ── 断线重连 ──────────────────────────────────────────────

// 不重连 close code 集合：认证失败/权限错误/被踢等，重连无意义
var noReconnectCodes = map[int]bool{
	4001: true, // Auth failed
	4003: true, // Invalid AID
	4008: true, // Auth timeout
	4009: true, // Server kick
	4010: true, // Invalid nonce
	4011: true, // Federation ACL denied
}

// onGatewayDisconnect 处理服务端主动断开通知 event/gateway.disconnect
func (c *AUNClient) onGatewayDisconnect(payload any) {
	data, _ := payload.(map[string]any)
	code := data["code"]
	reason := data["reason"]
	log.Printf("[aun_core] 服务端主动断开: code=%v, reason=%v", code, reason)
	c.serverKicked.Store(true)
}

// handleTransportDisconnect 传输层断线回调
func (c *AUNClient) handleTransportDisconnect(err error, closeCode int) {
	// 原子检查+设置状态，避免锁间隙中 close() 被调用后仍启动重连
	c.mu.Lock()
	isClosing := c.closing.Load()
	state := c.state
	if isClosing || state == StateClosed {
		c.mu.Unlock()
		return
	}
	c.state = StateDisconnected
	c.mu.Unlock()

	c.events.Publish("connection.state", map[string]any{
		"state": "disconnected",
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
		c.mu.Unlock()
		reason := "server kicked"
		if !c.serverKicked.Load() {
			reason = fmt.Sprintf("close code %d", closeCode)
		}
		log.Printf("[aun_core] 抑制自动重连: %s", reason)
		c.events.Publish("connection.state", map[string]any{
			"state":  "terminal_failed",
			"error":  err,
			"reason": reason,
		})
		return
	}

	if c.reconnecting.CompareAndSwap(false, true) {
		// closeCode == -1 表示网络异常断开（无 close frame），其他 code = 服务端主动关闭
		serverInitiated := closeCode != -1
		go c.reconnectLoop(serverInitiated)
	}
}

// reconnectLoop 重连循环（指数退避 + 固定上限抖动，在不可重试错误、close()、或超过最大重试次数时终止）
func (c *AUNClient) reconnectLoop(serverInitiated bool) {
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
	for attempt := 1; !c.closing.Load(); attempt++ {
		// 超过最大重试次数时停止
		if maxAttempts > 0 && attempt > maxAttempts {
			log.Printf("[aun_core] 重连超过最大次数 %d，停止重试", maxAttempts)
			c.mu.Lock()
			c.state = StateTerminalFailed
			c.mu.Unlock()
			c.events.Publish("connection.state", map[string]any{
				"state":   "terminal_failed",
				"error":   fmt.Errorf("超过最大重连次数 %d", maxAttempts),
				"attempt": attempt - 1,
			})
			c.reconnecting.Store(false)
			return
		}

		c.mu.Lock()
		c.state = StateReconnecting
		c.mu.Unlock()

		c.events.Publish("connection.state", map[string]any{
			"state":   "reconnecting",
			"attempt": attempt,
		})

		// 固定上限抖动：base=[1s, max_base]，delay=base+rand(0..max_base)。
		// ISSUE-SDK-GO-007: 使用 crypto/rand 代替 math/rand，确保并发安全。
		jitteredDelay := reconnectSleepDelaySeconds(delay, maxBaseDelay)
		time.Sleep(time.Duration(jitteredDelay * float64(time.Second)))

		// close() 可能在 sleep 期间被调用
		if c.closing.Load() {
			c.reconnecting.Store(false)
			return
		}

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
			c.mu.Unlock()
			c.events.Publish("connection.state", map[string]any{"state": "terminal_failed"})
			c.reconnecting.Store(false)
			return
		}

		err := c.connectOnce(context.Background(), params, true)
		if err == nil {
			c.reconnecting.Store(false)
			return
		}

		c.events.Publish("connection.error", map[string]any{
			"error":   err,
			"attempt": attempt,
		})

		if !shouldRetryReconnect(err) {
			c.mu.Lock()
			c.state = StateTerminalFailed
			c.mu.Unlock()
			c.events.Publish("connection.state", map[string]any{
				"state":   "terminal_failed",
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
	request := copyMapShallow(params)

	accessToken, _ := request["access_token"].(string)
	if accessToken == "" {
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

	request["access_token"] = accessToken
	request["gateway"] = gateway
	request["device_id"] = c.deviceID
	slotSource := any(c.slotID)
	if existing, ok := request["slot_id"]; ok {
		slotSource = existing
	}
	slotID, err := NormalizeInstanceID(slotSource, "slot_id", true)
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

	return request, nil
}

// buildSessionOptions 构建会话选项
func (c *AUNClient) buildSessionOptions(params map[string]any) map[string]any {
	options := map[string]any{
		"auto_reconnect":       true,
		"heartbeat_interval":   30.0,
		"token_refresh_before": 60.0,
		"retry": map[string]any{
			"initial_delay": 1.0,
			"max_delay":     30.0,
		},
		"timeouts": map[string]any{
			"connect": 5.0,
			"call":    10.0,
			"http":    30.0,
		},
	}

	if v, ok := params["auto_reconnect"].(bool); ok {
		options["auto_reconnect"] = v
	}
	if v, ok := params["heartbeat_interval"].(float64); ok {
		options["heartbeat_interval"] = v
	}
	if v, ok := params["token_refresh_before"].(float64); ok {
		options["token_refresh_before"] = v
	}
	if retryParams, ok := params["retry"].(map[string]any); ok {
		retryOpts, _ := options["retry"].(map[string]any)
		for k, v := range retryParams {
			retryOpts[k] = v
		}
	}
	if timeoutParams, ok := params["timeouts"].(map[string]any); ok {
		timeoutOpts, _ := options["timeouts"].(map[string]any)
		for k, v := range timeoutParams {
			timeoutOpts[k] = v
		}
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
	slotID, err := NormalizeInstanceID(slotSource, "slot_id", true)
	if err != nil {
		return NewValidationError(err.Error())
	}
	if slotID != c.slotID {
		return NewValidationError("message.pull/message.ack slot_id must match the current client instance")
	}
	params["device_id"] = c.deviceID
	params["slot_id"] = c.slotID
	return nil
}

func extractPeerPrekeyMaterial(value any) (map[string]any, bool) {
	prekey, ok := value.(map[string]any)
	if !ok || prekey == nil {
		return nil, false
	}
	prekeyID, ok := prekey["prekey_id"].(string)
	if !ok || prekeyID == "" {
		return nil, false
	}
	publicKey, ok := prekey["public_key"].(string)
	if !ok || publicKey == "" {
		return nil, false
	}
	signature, ok := prekey["signature"].(string)
	if !ok || signature == "" {
		return nil, false
	}
	return prekey, true
}

func parsePeerPrekeyResponse(peerAID string, result any, callErr error) (map[string]any, error) {
	if callErr != nil {
		return nil, NewValidationError(fmt.Sprintf("failed to fetch peer prekey for %s: %v", peerAID, callErr))
	}
	resultMap, ok := result.(map[string]any)
	if !ok || resultMap == nil {
		return nil, NewValidationError(fmt.Sprintf("invalid prekey response for %s", peerAID))
	}
	found, ok := resultMap["found"].(bool)
	if !ok {
		return nil, NewValidationError(fmt.Sprintf("invalid prekey response for %s", peerAID))
	}
	if !found {
		return nil, NewNotFoundError(fmt.Sprintf("peer prekey not found for %s", peerAID))
	}
	prekey, ok := extractPeerPrekeyMaterial(resultMap["prekey"])
	if !ok {
		return nil, NewValidationError(fmt.Sprintf("invalid prekey response for %s", peerAID))
	}
	return prekey, nil
}

func extractConsumedPrekeyID(message map[string]any) string {
	if message == nil {
		return ""
	}
	e2ee, ok := message["e2ee"].(map[string]any)
	if !ok || e2ee == nil {
		return ""
	}
	mode, _ := e2ee["encryption_mode"].(string)
	if mode != ModePrekeyECDHV2 {
		return ""
	}
	prekeyID, _ := e2ee["prekey_id"].(string)
	return strings.TrimSpace(prekeyID)
}

func (c *AUNClient) schedulePrekeyReplenishIfConsumed(message map[string]any) {
	prekeyID := extractConsumedPrekeyID(message)
	if prekeyID == "" {
		return
	}

	c.mu.Lock()
	if c.state != StateConnected || c.prekeyReplenished[prekeyID] || len(c.prekeyReplenishInflight) > 0 {
		c.mu.Unlock()
		return
	}
	c.prekeyReplenishInflight[prekeyID] = true
	c.mu.Unlock()

	go func() {
		err := c.uploadPrekey(context.Background())

		c.mu.Lock()
		delete(c.prekeyReplenishInflight, prekeyID)
		if err == nil {
			c.prekeyReplenished[prekeyID] = true
		}
		c.mu.Unlock()

		if err != nil {
			log.Printf("消费 prekey %s 后补充 current prekey 失败: %v", prekeyID, err)
		}
	}()
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

// stringSliceContains 检查字符串切片是否包含指定元素
func stringSliceContains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// extractAIDsFromMembers 从成员列表中提取 AID 列表
func extractAIDsFromMembers(membersList []any) []string {
	var aids []string
	for _, item := range membersList {
		if m, ok := item.(map[string]any); ok {
			if aid, ok := m["aid"].(string); ok {
				aids = append(aids, aid)
			}
		}
	}
	return aids
}

func sortedStringListFromAny(value any) []string {
	result := make([]string, 0)
	switch v := value.(type) {
	case []string:
		for _, item := range v {
			if s := strings.TrimSpace(item); s != "" {
				result = append(result, s)
			}
		}
	case []any:
		for _, item := range v {
			if s := strings.TrimSpace(stringFromAny(item)); s != "" {
				result = append(result, s)
			}
		}
	}
	sort.Strings(result)
	return result
}
