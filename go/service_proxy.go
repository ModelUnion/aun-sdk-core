package aun

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"nhooyr.io/websocket"
)

const (
	serviceProxyDiscoveryCacheKey   = "service_proxy_discovery"
	serviceProxyDiscoveryCacheTTL   = time.Hour
	serviceProxyTokenExpirySkewSecs = 30
)

var (
	serviceProxyNameRe               = regexp.MustCompile(`^[a-z0-9_-]+$`)
	serviceProxyReservedServiceNames = map[string]bool{
		"api": true, "health": true, "metrics": true, "status": true,
		"proxy": true, "admin": true, "ws": true, "wss": true,
		"static": true, "favicon.ico": true,
	}
	serviceProxySensitiveMetadataKeys = map[string]bool{
		"endpoint": true, "url": true, "uri": true, "token": true, "access_token": true,
		"authorization": true, "cookie": true, "secret": true, "password": true,
		"private_key": true, "key": true, "cert": true, "certificate": true,
	}
	serviceProxyAllowedSchemes  = map[string]bool{"http": true, "https": true, "ws": true, "wss": true}
	serviceProxyHopByHopHeaders = map[string]bool{
		"connection": true, "upgrade": true, "keep-alive": true, "proxy-authenticate": true,
		"proxy-authorization": true, "te": true, "trailer": true, "transfer-encoding": true,
	}
	serviceProxyAutoResponseHeaders = map[string]bool{"content-length": true, "date": true, "server": true}
	serviceProxyStreamingTypes      = map[string]bool{
		"mcp": true, "mcp-sse": true, "mcp-streamable-http": true,
		"sse": true, "stream": true, "file": true, "ws": true, "websocket": true,
	}
	serviceProxyValidStreamModes = map[string]bool{"auto": true, "stream": true, "always": true, "no_stream": true}
	serviceProxyFileContentTypes = map[string]bool{
		"application/octet-stream": true, "application/pdf": true, "application/zip": true,
		"application/x-zip-compressed": true, "application/gzip": true, "application/x-tar": true,
	}
)

// ServiceSummary 是上报到 Gateway/proxy-server 的公开服务摘要，不包含本地 endpoint。
type ServiceSummary struct {
	ServiceName string         `json:"service_name"`
	ServiceType string         `json:"service_type"`
	Visibility  string         `json:"visibility"`
	Metadata    map[string]any `json:"metadata"`
}

// ServiceRecord 是 proxy-client 本地 registry 中的服务记录。
type ServiceRecord struct {
	ServiceName string
	Endpoint    string
	ServiceType string
	Visibility  string
	Metadata    map[string]any
}

func (r ServiceRecord) Summary() ServiceSummary {
	return ServiceSummary{
		ServiceName: r.ServiceName,
		ServiceType: r.ServiceType,
		Visibility:  r.Visibility,
		Metadata:    serviceProxySanitizeMetadata(r.Metadata),
	}
}

// EndpointPolicy 限制 embedded endpoint，默认只允许 loopback/localhost。
type EndpointPolicy struct {
	AllowedHosts map[string]bool
}

func NewEndpointPolicy(allowedHosts ...string) EndpointPolicy {
	p := EndpointPolicy{AllowedHosts: map[string]bool{}}
	for _, host := range allowedHosts {
		if normalized := serviceProxyNormalizeHost(host); normalized != "" {
			p.AllowedHosts[normalized] = true
		}
	}
	return p
}

func (p EndpointPolicy) IsAllowed(endpoint string) bool {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed == nil || !serviceProxyAllowedSchemes[strings.ToLower(parsed.Scheme)] {
		return false
	}
	host := serviceProxyNormalizeHost(parsed.Hostname())
	if host == "" {
		return false
	}
	if p.AllowedHosts[host] || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && ip.IsLoopback()
}

// EmbeddedServiceRegistry 是 provider 侧本地服务注册表。
type EmbeddedServiceRegistry struct {
	mu              sync.RWMutex
	endpointPolicy  EndpointPolicy
	replaceExisting bool
	records         map[string]ServiceRecord
}

func NewEmbeddedServiceRegistry(policy *EndpointPolicy) *EmbeddedServiceRegistry {
	p := NewEndpointPolicy()
	if policy != nil {
		p = *policy
	}
	return &EmbeddedServiceRegistry{
		endpointPolicy:  p,
		replaceExisting: true,
		records:         map[string]ServiceRecord{},
	}
}

func (r *EmbeddedServiceRegistry) Register(serviceName, endpoint string, opts ...ServiceProxyRegisterOption) (ServiceRecord, error) {
	name, err := serviceProxyNormalizeServiceName(serviceName)
	if err != nil {
		return ServiceRecord{}, err
	}
	endpoint = strings.TrimSpace(endpoint)
	if !r.endpointPolicy.IsAllowed(endpoint) {
		return ServiceRecord{}, NewValidationError("endpoint is not allowed")
	}
	cfg := serviceProxyRegisterOptions{ServiceType: "http", Visibility: "private", Metadata: map[string]any{}}
	for _, opt := range opts {
		opt(&cfg)
	}
	record := ServiceRecord{
		ServiceName: name,
		Endpoint:    endpoint,
		ServiceType: strings.TrimSpace(cfg.ServiceType),
		Visibility:  strings.TrimSpace(cfg.Visibility),
		Metadata:    serviceProxySanitizeMetadata(cfg.Metadata),
	}
	if record.ServiceType == "" {
		record.ServiceType = "http"
	}
	if record.Visibility == "" {
		record.Visibility = "private"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[name]; exists && !r.replaceExisting {
		return ServiceRecord{}, NewValidationError(fmt.Sprintf("service already registered: %s", name))
	}
	r.records[name] = record
	return record, nil
}

func (r *EmbeddedServiceRegistry) Unregister(serviceName string) bool {
	name, err := serviceProxyNormalizeServiceName(serviceName)
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, exists := r.records[name]
	delete(r.records, name)
	return exists
}

func (r *EmbeddedServiceRegistry) Get(serviceName string) (ServiceRecord, bool) {
	name, err := serviceProxyNormalizeServiceName(serviceName)
	if err != nil {
		return ServiceRecord{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[name]
	return record, ok
}

func (r *EmbeddedServiceRegistry) ListRecords() []ServiceRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.records))
	for name := range r.records {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ServiceRecord, 0, len(names))
	for _, name := range names {
		out = append(out, r.records[name])
	}
	return out
}

func (r *EmbeddedServiceRegistry) ListSummaries() []ServiceSummary {
	records := r.ListRecords()
	out := make([]ServiceSummary, 0, len(records))
	for _, record := range records {
		out = append(out, record.Summary())
	}
	return out
}

type serviceProxyRegisterOptions struct {
	ServiceType string
	Visibility  string
	Metadata    map[string]any
}

type ServiceProxyRegisterOption func(*serviceProxyRegisterOptions)

func WithServiceProxyServiceType(serviceType string) ServiceProxyRegisterOption {
	return func(o *serviceProxyRegisterOptions) { o.ServiceType = serviceType }
}

func WithServiceProxyVisibility(visibility string) ServiceProxyRegisterOption {
	return func(o *serviceProxyRegisterOptions) { o.Visibility = visibility }
}

func WithServiceProxyMetadata(metadata map[string]any) ServiceProxyRegisterOption {
	return func(o *serviceProxyRegisterOptions) { o.Metadata = metadata }
}

type ServiceProxyGatewayClient interface {
	Call(ctx context.Context, method string, params map[string]any) (any, error)
}

type ServiceProxyAuthClient interface {
	Authenticate(ctx context.Context, opts ...ConnectOptions) (map[string]any, error)
}

type ServiceProxyEventClient interface {
	On(event string, handler EventHandler) *Subscription
}

type ServiceProxyClientOptions struct {
	ProviderAID               string
	Registry                  *EmbeddedServiceRegistry
	EndpointPolicy            *EndpointPolicy
	Logger                    *ModuleLogger
	AUNClient                 any
	MaxResponseBodyBytes      int64
	MaxTunnelMessageBytes     int64
	HTTPClient                *http.Client
	BackendWebSocketDialer    func(ctx context.Context, targetURL string, subprotocols []string, headers http.Header) (*websocket.Conn, error)
	ProxyWebSocketDialer      func(ctx context.Context, targetURL string, headers http.Header) (*websocket.Conn, error)
	ProxyDiscoveryHTTPClient  *http.Client
	ProxyDiscoveryURLOverride func(providerAID string) []string
}

// ServiceProxyClient 是 provider 侧 Service Proxy tunnel 客户端。
type ServiceProxyClient struct {
	ProviderAID            string
	Registry               *EmbeddedServiceRegistry
	Log                    *ModuleLogger
	AUNClient              any
	MaxResponseBodyBytes   int64
	MaxTunnelMessageBytes  int64
	HTTPClient             *http.Client
	BackendWebSocketDialer func(ctx context.Context, targetURL string, subprotocols []string, headers http.Header) (*websocket.Conn, error)
	ProxyWebSocketDialer   func(ctx context.Context, targetURL string, headers http.Header) (*websocket.Conn, error)
	DiscoveryHTTPClient    *http.Client
	discoveryURLOverride   func(providerAID string) []string
	mu                     sync.Mutex
	running                bool
	activeTunnel           *serviceProxyTunnel
}

func NewServiceProxyClient(opts ServiceProxyClientOptions) *ServiceProxyClient {
	registry := opts.Registry
	if registry == nil {
		registry = NewEmbeddedServiceRegistry(opts.EndpointPolicy)
	}
	maxResp := opts.MaxResponseBodyBytes
	if maxResp <= 0 {
		maxResp = 16 * 1024 * 1024
	}
	maxTunnel := opts.MaxTunnelMessageBytes
	if maxTunnel <= 0 {
		maxTunnel = 64 * 1024 * 1024
	}
	log := opts.Logger
	if log == nil {
		log = pkgLogFor("service_proxy")
	}
	c := &ServiceProxyClient{
		ProviderAID:            strings.TrimSpace(opts.ProviderAID),
		Registry:               registry,
		Log:                    log,
		AUNClient:              opts.AUNClient,
		MaxResponseBodyBytes:   maxResp,
		MaxTunnelMessageBytes:  maxTunnel,
		HTTPClient:             opts.HTTPClient,
		BackendWebSocketDialer: opts.BackendWebSocketDialer,
		ProxyWebSocketDialer:   opts.ProxyWebSocketDialer,
		DiscoveryHTTPClient:    opts.ProxyDiscoveryHTTPClient,
		discoveryURLOverride:   opts.ProxyDiscoveryURLOverride,
	}
	return c
}

func (c *ServiceProxyClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *ServiceProxyClient) Stop() {
	c.mu.Lock()
	c.running = false
	tunnel := c.activeTunnel
	c.mu.Unlock()
	if tunnel != nil {
		_ = tunnel.Close(websocket.StatusNormalClosure, "stopped")
	}
}

func (c *ServiceProxyClient) RegisterService(serviceName, endpoint string, opts ...ServiceProxyRegisterOption) (ServiceRecord, error) {
	return c.Registry.Register(serviceName, endpoint, opts...)
}

func (c *ServiceProxyClient) UnregisterService(serviceName string) bool {
	return c.Registry.Unregister(serviceName)
}

func (c *ServiceProxyClient) ListServiceSummaries() []ServiceSummary {
	return c.Registry.ListSummaries()
}

func (c *ServiceProxyClient) RegisterServicesWithGateway(ctx context.Context, services []ServiceSummary) (map[string]any, error) {
	callClient, ok := c.AUNClient.(ServiceProxyGatewayClient)
	if !ok || callClient == nil {
		return nil, NewValidationError("Gateway service registration requires AUNClient with Call()")
	}
	if services == nil {
		services = c.ListServiceSummaries()
	}
	result, err := callClient.Call(ctx, "proxy.register_services", map[string]any{
		"provider_aid": c.ProviderAID,
		"services":     serviceProxySummariesToAny(services),
	})
	if err != nil {
		return nil, err
	}
	if m, ok := result.(map[string]any); ok {
		if okVal, exists := m["ok"].(bool); exists && !okVal {
			return nil, NewValidationError("Gateway service registration failed")
		}
		return m, nil
	}
	return map[string]any{}, nil
}

func (c *ServiceProxyClient) UnregisterServicesFromGateway(ctx context.Context, serviceNames ...string) (map[string]any, error) {
	callClient, ok := c.AUNClient.(ServiceProxyGatewayClient)
	if !ok || callClient == nil {
		return nil, NewValidationError("Gateway service registration requires AUNClient with Call()")
	}
	params := map[string]any{"provider_aid": c.ProviderAID}
	if len(serviceNames) > 0 {
		names := make([]any, 0, len(serviceNames))
		for _, name := range serviceNames {
			names = append(names, name)
		}
		params["service_names"] = names
	}
	result, err := callClient.Call(ctx, "proxy.unregister_services", params)
	if err != nil {
		return nil, err
	}
	if m, ok := result.(map[string]any); ok {
		return m, nil
	}
	return map[string]any{}, nil
}

func (c *ServiceProxyClient) ListGatewayServices(ctx context.Context) (map[string]any, error) {
	callClient, ok := c.AUNClient.(ServiceProxyGatewayClient)
	if !ok || callClient == nil {
		return nil, NewValidationError("Gateway service registration requires AUNClient with Call()")
	}
	result, err := callClient.Call(ctx, "proxy.list_services", map[string]any{"provider_aid": c.ProviderAID})
	if err != nil {
		return nil, err
	}
	if m, ok := result.(map[string]any); ok {
		return m, nil
	}
	return map[string]any{}, nil
}

func (c *ServiceProxyClient) DiscoverProxyServer(ctx context.Context, forceRefresh bool, timeout time.Duration) (map[string]any, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if !forceRefresh {
		if cached := c.loadCachedProxyDiscovery(); cached != nil {
			return cached, nil
		}
	}
	var errors []string
	for _, wellKnownURL := range c.proxyWellKnownURLs() {
		discovery, err := c.fetchProxyWellKnown(ctx, wellKnownURL, timeout)
		if err == nil {
			c.persistProxyDiscovery(discovery)
			return discovery, nil
		}
		errors = append(errors, fmt.Sprintf("%s: %v", wellKnownURL, err))
		c.logWarn("Service Proxy discovery failed: url=%s err=%v", wellKnownURL, err)
	}
	return nil, NewConnectionError("Service Proxy discovery failed: "+strings.Join(errors, "; "), WithRetryable(true))
}

func (c *ServiceProxyClient) DiscoverProxyWSURL(ctx context.Context, forceRefresh bool, timeout time.Duration) (string, error) {
	discovery, err := c.DiscoverProxyServer(ctx, forceRefresh, timeout)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stringFromAny(discovery["ws_url"])), nil
}

func (c *ServiceProxyClient) ConnectOnce(ctx context.Context, heartbeatRequestID string) (map[string]any, error) {
	c.setRunning(true)
	defer c.setRunning(false)
	if _, err := c.autoRegisterServicesWithGateway(ctx); err != nil {
		return nil, err
	}
	tunnel, err := c.connectProxyWS(ctx)
	if err != nil {
		return nil, err
	}
	defer tunnel.Close(websocket.StatusNormalClosure, "")
	c.setActiveTunnel(tunnel)
	defer c.setActiveTunnel(nil)
	if err := tunnel.Send(ctx, map[string]any{
		"type":           "service_proxy_auth",
		"request_id":     "auth",
		"provider_aid":   c.ProviderAID,
		"client_version": "go",
	}); err != nil {
		return nil, err
	}
	authResp, err := tunnel.Recv(ctx)
	if err != nil {
		return nil, err
	}
	if ok, _ := authResp["ok"].(bool); !ok {
		return nil, NewAuthError(serviceProxyErrorMessageFromResponse(authResp, "Service Proxy auth failed"))
	}
	registered, err := c.RegisterServicesWithProxyServer(ctx, tunnel, "register-services", nil)
	if err != nil {
		return nil, err
	}
	heartbeat := false
	if heartbeatRequestID != "" {
		if err := tunnel.Send(ctx, map[string]any{"type": "heartbeat", "request_id": heartbeatRequestID}); err != nil {
			return nil, err
		}
		hb, err := tunnel.Recv(ctx)
		if err != nil {
			return nil, err
		}
		heartbeat, _ = hb["ok"].(bool)
	}
	return map[string]any{"registered": registered, "heartbeat": heartbeat}, nil
}

func (c *ServiceProxyClient) ServeOnce(ctx context.Context, maxRequests int) (map[string]any, error) {
	c.setRunning(true)
	defer c.setRunning(false)
	if _, err := c.autoRegisterServicesWithGateway(ctx); err != nil {
		return nil, err
	}
	tunnel, err := c.connectProxyWS(ctx)
	if err != nil {
		return nil, err
	}
	defer tunnel.Close(websocket.StatusNormalClosure, "")
	c.setActiveTunnel(tunnel)
	defer c.setActiveTunnel(nil)
	return c.serveTunnel(ctx, tunnel, serviceProxyServeTunnelOptions{
		AuthRequestID:     "auth",
		RegisterRequestID: "register-services",
		MaxRequests:       maxRequests,
	})
}

type ServiceProxyServeForeverOptions struct {
	ConnectionMode    string
	IdleTimeout       time.Duration
	ReconnectDelay    time.Duration
	AuthRequestID     string
	RegisterRequestID string
}

func (c *ServiceProxyClient) ServeForever(ctx context.Context, opts ServiceProxyServeForeverOptions) (map[string]any, error) {
	mode := strings.TrimSpace(opts.ConnectionMode)
	if mode == "" {
		mode = "persistent"
	}
	if mode != "persistent" && mode != "on_demand" {
		return nil, NewValidationError("connection mode must be persistent or on_demand")
	}
	if opts.ReconnectDelay <= 0 {
		opts.ReconnectDelay = time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 60 * time.Second
	}
	if opts.AuthRequestID == "" {
		opts.AuthRequestID = "auth"
	}
	if opts.RegisterRequestID == "" {
		opts.RegisterRequestID = "register-services"
	}
	c.setRunning(true)
	defer c.setRunning(false)
	stats := map[string]any{"connection_mode": mode, "connections": 0, "registered": 0, "handled_requests": 0, "wakeup_count": 0}
	if mode == "on_demand" {
		return c.serveOnDemand(ctx, stats, opts)
	}
	const maxReconnectDelay = 60 * time.Second
	delay := opts.ReconnectDelay
	for c.isRunning() {
		if _, err := c.autoRegisterServicesWithGateway(ctx); err != nil {
			return stats, err
		}
		tunnel, err := c.connectProxyWS(ctx)
		if err != nil {
			if !c.isRunning() || ctx.Err() != nil {
				break
			}
			c.handlePersistentTunnelError(ctx, err)
			sleepWithCancel(ctx, delay)
			delay = minDuration(delay*2, maxReconnectDelay)
			continue
		}
		c.setActiveTunnel(tunnel)
		result, err := c.serveTunnel(ctx, tunnel, serviceProxyServeTunnelOptions{
			AuthRequestID:     opts.AuthRequestID,
			RegisterRequestID: opts.RegisterRequestID,
		})
		_ = tunnel.Close(websocket.StatusNormalClosure, "")
		c.setActiveTunnel(nil)
		if err != nil && c.isRunning() && ctx.Err() == nil {
			c.handlePersistentTunnelError(ctx, err)
			sleepWithCancel(ctx, delay)
			delay = minDuration(delay*2, maxReconnectDelay)
			continue
		}
		stats["connections"] = intFromAny(stats["connections"]) + 1
		stats["registered"] = intFromAny(result["registered"])
		stats["handled_requests"] = intFromAny(stats["handled_requests"]) + intFromAny(result["handled_requests"])
		delay = opts.ReconnectDelay // 成功后重置退避
	}
	return stats, nil
}

// handlePersistentTunnelError 处理隧道错误：auth 失败时触发重新登录，其它错误仅记录。
func (c *ServiceProxyClient) handlePersistentTunnelError(ctx context.Context, err error) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		c.logWarn("persistent tunnel auth error, re-authenticating: %v", err)
		if _, reAuthErr := c.ensureAccessToken(ctx); reAuthErr != nil {
			c.logWarn("re-authentication failed: %v", reAuthErr)
		}
		return
	}
	c.logWarn("persistent tunnel reconnect scheduled after error: %v", err)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (c *ServiceProxyClient) RegisterServicesWithProxyServer(ctx context.Context, tunnel *serviceProxyTunnel, requestID string, services []ServiceSummary) (int, error) {
	if requestID == "" {
		requestID = "register-services"
	}
	if services == nil {
		services = c.ListServiceSummaries()
	}
	if err := tunnel.Send(ctx, map[string]any{
		"type":       "register_services",
		"request_id": requestID,
		"services":   serviceProxySummariesToAny(services),
	}); err != nil {
		return 0, err
	}
	response, err := tunnel.Recv(ctx)
	if err != nil {
		return 0, err
	}
	if ok, _ := response["ok"].(bool); !ok {
		return 0, NewValidationError("Service Proxy service registration failed")
	}
	count := intFromAny(response["count"])
	if count == 0 {
		count = len(services)
	}
	return count, nil
}

type serviceProxyServeTunnelOptions struct {
	AuthRequestID     string
	RegisterRequestID string
	MaxRequests       int
	IdleTimeout       time.Duration
}

func (c *ServiceProxyClient) serveTunnel(ctx context.Context, tunnel *serviceProxyTunnel, opts serviceProxyServeTunnelOptions) (map[string]any, error) {
	if opts.AuthRequestID == "" {
		opts.AuthRequestID = "auth"
	}
	if opts.RegisterRequestID == "" {
		opts.RegisterRequestID = "register-services"
	}
	registered, err := c.authAndRegister(ctx, tunnel, opts.AuthRequestID, opts.RegisterRequestID)
	if err != nil {
		return nil, err
	}
	handled := 0
	activeWS := map[string]chan map[string]any{}
	activeMu := sync.Mutex{}
	for c.isRunning() {
		activeMu.Lock()
		activeCount := len(activeWS)
		activeMu.Unlock()
		if opts.MaxRequests > 0 && handled >= opts.MaxRequests && activeCount == 0 {
			break
		}
		recvCtx := ctx
		cancel := func() {}
		if opts.IdleTimeout > 0 {
			recvCtx, cancel = context.WithTimeout(ctx, opts.IdleTimeout)
		}
		message, err := tunnel.Recv(recvCtx)
		cancel()
		if err != nil {
			if opts.IdleTimeout > 0 && activeCount > 0 && ctx.Err() == nil {
				continue
			}
			if ctx.Err() != nil || !c.isRunning() {
				break
			}
			return nil, err
		}
		msgType := stringFromAny(message["type"])
		switch msgType {
		case "service_proxy_request":
			requestID := stringFromAny(message["request_id"])
			var bodyReader io.Reader
			var pipeWriter *io.PipeWriter
			if boolFromAny(message["body_stream"]) {
				pr, pw := io.Pipe()
				bodyReader = pr
				pipeWriter = pw
				go c.readRequestBodyStream(ctx, tunnel, requestID, pw, activeWS, &activeMu)
			}
			err := c.IterRequestMessages(ctx, message, bodyReader, func(response map[string]any) error {
				return tunnel.Send(ctx, response)
			})
			if pipeWriter != nil {
				_ = pipeWriter.Close()
			}
			if err != nil {
				return nil, err
			}
			handled++
		case "ws_connect":
			connectionID := stringFromAny(message["connection_id"])
			if connectionID == "" {
				_ = tunnel.Send(ctx, serviceProxyWSErrorMessage("", "missing_connection_id", "connection_id is required"))
				continue
			}
			ch := make(chan map[string]any, 32)
			activeMu.Lock()
			activeWS[connectionID] = ch
			activeMu.Unlock()
			go func() {
				defer func() {
					activeMu.Lock()
					delete(activeWS, connectionID)
					activeMu.Unlock()
					close(ch)
				}()
				_ = c.HandleWSConnectMessage(ctx, message, tunnel, ch)
			}()
			handled++
		case "ws_message", "ws_close", "ws_error":
			connectionID := stringFromAny(message["connection_id"])
			activeMu.Lock()
			ch := activeWS[connectionID]
			activeMu.Unlock()
			if ch != nil {
				ch <- message
			} else if connectionID != "" {
				_ = tunnel.Send(ctx, serviceProxyWSErrorMessage(connectionID, "unknown_ws_connection", "WebSocket connection is not active"))
			}
		case "heartbeat_ack":
			continue
		default:
			_ = tunnel.Send(ctx, serviceProxyErrorMessage(stringFromAny(message["request_id"]), "unsupported_message", "unsupported Service Proxy tunnel message"))
		}
	}
	return map[string]any{"registered": registered, "handled_requests": handled}, nil
}

func (c *ServiceProxyClient) IterRequestMessages(ctx context.Context, message map[string]any, bodyReader io.Reader, emit func(map[string]any) error) error {
	requestID := stringFromAny(message["request_id"])
	serviceName := stringFromAny(message["service_name"])
	record, ok := c.Registry.Get(serviceName)
	if !ok {
		return emit(serviceProxyErrorMessage(requestID, "service_not_registered", "service is not registered"))
	}
	method := strings.ToUpper(strings.TrimSpace(stringFromAny(message["method"])))
	if method == "" {
		method = http.MethodGet
	}
	path := serviceProxyNormalizePath(stringFromAny(message["path"]))
	targetURL := serviceProxyBuildTargetURL(record.Endpoint, path, stringFromAny(message["query_string"]))
	var body io.Reader
	if boolFromAny(message["body_stream"]) {
		if bodyReader == nil {
			return emit(serviceProxyErrorMessage(requestID, "missing_body_stream", "request body stream is missing"))
		}
		body = bodyReader
	} else {
		rawBody := stringFromAny(message["body_base64"])
		if rawBody != "" {
			data, err := base64.StdEncoding.DecodeString(rawBody)
			if err != nil {
				return emit(serviceProxyErrorMessage(requestID, "invalid_body", "body_base64 is invalid"))
			}
			body = bytes.NewReader(data)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return emit(serviceProxyErrorMessage(requestID, "backend_unreachable", "backend request failed"))
	}
	for k, v := range serviceProxyBackendHeaders(asMap(message["headers"])) {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		c.logWarn("backend request failed: request_id=%s service_name=%s err=%v", requestID, serviceName, err)
		return emit(serviceProxyErrorMessage(requestID, "backend_unreachable", "backend request failed"))
	}
	defer resp.Body.Close()
	responseHeaders := serviceProxyResponseHeaders(resp.Header)
	detection := serviceProxyDetectRequestProtocol(message, record)
	shouldStream := detection.IsStream || (detection.StreamMode != "no_stream" && serviceProxyIsStreamResponseHeaders(responseHeaders))
	if !shouldStream {
		body, err := serviceProxyReadLimited(resp.Body, c.MaxResponseBodyBytes)
		if err != nil {
			return emit(serviceProxyErrorMessage(requestID, "response_body_too_large", "backend response body is too large"))
		}
		return emit(map[string]any{
			"type":        "service_proxy_response",
			"request_id":  requestID,
			"status":      resp.StatusCode,
			"headers":     responseHeaders,
			"body_base64": base64.StdEncoding.EncodeToString(body),
		})
	}
	streamType := serviceProxyStreamTypeFromResponse(responseHeaders, detection.ServiceType)
	if _, exists := responseHeaders["x-stream-type"]; !exists {
		responseHeaders["x-stream-type"] = streamType
	}
	buf := make([]byte, 65536)
	index := 0
	var pending []byte
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if pending != nil {
				if err := emit(serviceProxyStreamMessage(requestID, index, resp.StatusCode, responseHeaders, pending, false)); err != nil {
					return err
				}
				index++
			}
			pending = chunk
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return emit(serviceProxyErrorMessage(requestID, "backend_unreachable", "backend request failed"))
		}
	}
	if pending != nil {
		return emit(serviceProxyStreamMessage(requestID, index, resp.StatusCode, responseHeaders, pending, true))
	}
	return emit(map[string]any{"type": "service_proxy_stream", "request_id": requestID, "index": 0, "status": resp.StatusCode, "headers": responseHeaders, "data_base64": "", "done": true})
}

func (c *ServiceProxyClient) HandleWSConnectMessage(ctx context.Context, message map[string]any, tunnel *serviceProxyTunnel, inbound <-chan map[string]any) error {
	connectionID := stringFromAny(message["connection_id"])
	serviceName := stringFromAny(message["service_name"])
	record, ok := c.Registry.Get(serviceName)
	if !ok {
		return tunnel.Send(ctx, serviceProxyWSErrorMessage(connectionID, "service_not_registered", "service is not registered"))
	}
	targetURL := serviceProxyBuildTargetURL(record.Endpoint, serviceProxyNormalizePath(stringFromAny(message["path"])), stringFromAny(message["query_string"]))
	headers := http.Header{}
	for k, v := range serviceProxyBackendHeaders(asMap(message["headers"])) {
		headers.Set(k, v)
	}
	subprotocols := stringSliceFromAny(message["subprotocols"])
	backend, err := c.dialBackendWS(ctx, targetURL, subprotocols, headers)
	if err != nil {
		c.logWarn("backend websocket bridge failed: connection_id=%s err=%v", connectionID, err)
		return tunnel.Send(ctx, serviceProxyWSErrorMessage(connectionID, "backend_ws_unreachable", "backend websocket request failed"))
	}
	defer backend.Close(websocket.StatusNormalClosure, "")
	if err := tunnel.Send(ctx, map[string]any{
		"type":          "ws_connected",
		"connection_id": connectionID,
		"subprotocol":   backend.Subprotocol(),
	}); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			msgType, data, err := backend.Read(ctx)
			if err != nil {
				return
			}
			if msgType == websocket.MessageText {
				_ = tunnel.Send(ctx, map[string]any{"type": "ws_message", "connection_id": connectionID, "text": string(data)})
			} else if msgType == websocket.MessageBinary {
				_ = tunnel.Send(ctx, map[string]any{"type": "ws_message", "connection_id": connectionID, "data_base64": base64.StdEncoding.EncodeToString(data)})
			}
		}
	}()
	for {
		select {
		case <-done:
			return tunnel.Send(ctx, map[string]any{"type": "ws_close", "connection_id": connectionID, "code": 1000, "reason": ""})
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-inbound:
			if !ok {
				return nil
			}
			switch stringFromAny(msg["type"]) {
			case "ws_message":
				if text, ok := msg["text"].(string); ok {
					if err := backend.Write(ctx, websocket.MessageText, []byte(text)); err != nil {
						return err
					}
				} else if raw := stringFromAny(msg["data_base64"]); raw != "" {
					data, err := base64.StdEncoding.DecodeString(raw)
					if err != nil {
						_ = tunnel.Send(ctx, serviceProxyWSErrorMessage(connectionID, "invalid_ws_frame", "data_base64 is invalid"))
						return nil
					}
					if err := backend.Write(ctx, websocket.MessageBinary, data); err != nil {
						return err
					}
				}
			case "ws_close", "ws_error":
				return backend.Close(websocket.StatusNormalClosure, stringFromAny(msg["reason"]))
			}
		}
	}
}

func (c *ServiceProxyClient) authAndRegister(ctx context.Context, tunnel *serviceProxyTunnel, authRequestID, registerRequestID string) (int, error) {
	if err := tunnel.Send(ctx, map[string]any{
		"type":           "service_proxy_auth",
		"request_id":     authRequestID,
		"provider_aid":   c.ProviderAID,
		"client_version": "go",
	}); err != nil {
		return 0, err
	}
	response, err := tunnel.Recv(ctx)
	if err != nil {
		return 0, err
	}
	if ok, _ := response["ok"].(bool); !ok {
		return 0, NewAuthError(serviceProxyErrorMessageFromResponse(response, "Service Proxy auth failed"))
	}
	return c.RegisterServicesWithProxyServer(ctx, tunnel, registerRequestID, nil)
}

func (c *ServiceProxyClient) serveOnDemand(ctx context.Context, stats map[string]any, opts ServiceProxyServeForeverOptions) (map[string]any, error) {
	eventClient, ok := c.AUNClient.(ServiceProxyEventClient)
	if !ok || eventClient == nil {
		return nil, NewValidationError("on_demand mode requires AUNClient with On()")
	}
	if _, err := c.autoRegisterServicesWithGateway(ctx); err != nil {
		return nil, err
	}
	wakeupCh := make(chan map[string]any, 8)
	sub := eventClient.On("app.service_proxy.wakeup", func(payload any) {
		item := asMap(payload)
		if stringFromAny(item["type"]) != "aun.service_proxy.wakeup" {
			return
		}
		provider := strings.TrimSpace(stringFromAny(item["provider_aid"]))
		if provider != "" && provider != c.ProviderAID {
			return
		}
		select {
		case wakeupCh <- item:
		default:
		}
	})
	defer sub.Unsubscribe()
	for c.isRunning() {
		select {
		case <-ctx.Done():
			return stats, nil
		case <-wakeupCh:
			stats["wakeup_count"] = intFromAny(stats["wakeup_count"]) + 1
			if _, err := c.autoRegisterServicesWithGateway(ctx); err != nil {
				return stats, err
			}
			tunnel, err := c.connectProxyWS(ctx)
			if err != nil {
				c.logWarn("on-demand tunnel connection failed after wakeup: %v", err)
				sleepWithCancel(ctx, opts.ReconnectDelay)
				continue
			}
			c.setActiveTunnel(tunnel)
			result, err := c.serveTunnel(ctx, tunnel, serviceProxyServeTunnelOptions{
				AuthRequestID:     opts.AuthRequestID,
				RegisterRequestID: opts.RegisterRequestID,
				IdleTimeout:       opts.IdleTimeout,
			})
			_ = tunnel.Close(websocket.StatusNormalClosure, "")
			c.setActiveTunnel(nil)
			if err != nil && c.isRunning() && ctx.Err() == nil {
				c.logWarn("on-demand tunnel connection failed after wakeup: %v", err)
				sleepWithCancel(ctx, opts.ReconnectDelay)
				continue
			}
			stats["connections"] = intFromAny(stats["connections"]) + 1
			stats["registered"] = intFromAny(result["registered"])
			stats["handled_requests"] = intFromAny(stats["handled_requests"]) + intFromAny(result["handled_requests"])
		}
	}
	return stats, nil
}

func (c *ServiceProxyClient) readRequestBodyStream(ctx context.Context, tunnel *serviceProxyTunnel, requestID string, pipe *io.PipeWriter, active map[string]chan map[string]any, activeMu *sync.Mutex) {
	defer pipe.Close()
	for {
		message, err := tunnel.Recv(ctx)
		if err != nil {
			_ = pipe.CloseWithError(err)
			return
		}
		msgType := stringFromAny(message["type"])
		if msgType == "ws_message" || msgType == "ws_close" || msgType == "ws_error" {
			activeMu.Lock()
			ch := active[stringFromAny(message["connection_id"])]
			activeMu.Unlock()
			if ch != nil {
				ch <- message
				continue
			}
		}
		if msgType != "service_proxy_request_body" {
			_ = pipe.CloseWithError(NewValidationError("unexpected tunnel message while reading body"))
			return
		}
		if stringFromAny(message["request_id"]) != requestID {
			_ = pipe.CloseWithError(NewValidationError("request body stream request_id mismatch"))
			return
		}
		if errMap := asMap(message["error"]); len(errMap) > 0 {
			_ = pipe.CloseWithError(NewValidationError(stringFromAny(errMap["message"])))
			return
		}
		if raw := stringFromAny(message["data_base64"]); raw != "" {
			data, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				_ = pipe.CloseWithError(NewValidationError("data_base64 is invalid"))
				return
			}
			if len(data) > 0 {
				if _, err := pipe.Write(data); err != nil {
					return
				}
			}
		}
		if boolFromAny(message["done"]) {
			return
		}
	}
}

func (c *ServiceProxyClient) autoRegisterServicesWithGateway(ctx context.Context) (map[string]any, error) {
	if _, ok := c.AUNClient.(ServiceProxyGatewayClient); !ok {
		return map[string]any{"skipped": true}, nil
	}
	return c.RegisterServicesWithGateway(ctx, nil)
}

func (c *ServiceProxyClient) connectProxyWS(ctx context.Context) (*serviceProxyTunnel, error) {
	proxyURL, err := c.DiscoverProxyWSURL(ctx, false, 5*time.Second)
	if err != nil {
		return nil, err
	}
	token, err := c.ensureAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	headers := http.Header{"Authorization": {"Bearer " + token}}
	conn, err := c.dialProxyWS(ctx, proxyURL, headers)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(c.MaxTunnelMessageBytes)
	return &serviceProxyTunnel{conn: conn}, nil
}

func (c *ServiceProxyClient) ensureAccessToken(ctx context.Context) (string, error) {
	if token := c.resolveCachedAccessToken(); token != "" {
		return token, nil
	}
	authClient, ok := c.AUNClient.(ServiceProxyAuthClient)
	if !ok || authClient == nil {
		return "", NewAuthError("Service Proxy tunnel requires AUNClient Authenticate() for AUN token authentication")
	}
	result, err := authClient.Authenticate(ctx)
	if err != nil {
		return "", NewAuthError(fmt.Sprintf("AUNClient authenticate failed for Service Proxy tunnel: %v", err))
	}
	token := serviceProxyMappingAccessToken(result)
	if token == "" {
		return "", NewAuthError("AUNClient authenticate did not return a valid access_token")
	}
	return token, nil
}

func (c *ServiceProxyClient) resolveCachedAccessToken() string {
	if client, ok := c.AUNClient.(*AUNClient); ok && client != nil {
		client.mu.RLock()
		identity := copyMapShallow(client.identity)
		aid := client.aid
		deviceID := client.deviceID
		slotID := client.slotID
		store := client.tokenStore
		auth := client.auth
		client.mu.RUnlock()
		if token := serviceProxyMappingAccessToken(identity); token != "" {
			return token
		}
		if auth != nil {
			if loaded := auth.LoadIdentityOrNil(c.ProviderAID); loaded != nil {
				if token := serviceProxyMappingAccessToken(loaded); token != "" {
					return token
				}
			}
		}
		if aid == "" {
			aid = c.ProviderAID
		}
		if stateStore, ok := store.(keystore.InstanceStateStore); ok {
			if state, _ := stateStore.LoadInstanceState(aid, deviceID, slotID); state != nil {
				if token := serviceProxyMappingAccessToken(state); token != "" {
					return token
				}
			}
		}
	}
	return ""
}

func serviceProxyMappingAccessToken(mapping map[string]any) string {
	token := strings.TrimSpace(stringFromAny(mapping["access_token"]))
	if token == "" {
		token = strings.TrimSpace(stringFromAny(mapping["token"]))
	}
	if token == "" {
		token = strings.TrimSpace(stringFromAny(mapping["kite_token"]))
	}
	if token == "" {
		return ""
	}
	expiresAt := floatFromAny(mapping["access_token_expires_at"])
	if expiresAt == 0 {
		expiresAt = floatFromAny(mapping["expires_at"])
	}
	if expiresAt > 0 && expiresAt <= float64(time.Now().Unix()+serviceProxyTokenExpirySkewSecs) {
		return ""
	}
	return token
}

func (c *ServiceProxyClient) shouldVerifySSL() bool {
	if client, ok := c.AUNClient.(*AUNClient); ok && client != nil {
		client.mu.RLock()
		defer client.mu.RUnlock()
		if client.configModel != nil {
			return client.configModel.VerifySSL
		}
		if client.currentAIDObj != nil {
			return client.currentAIDObj.VerifySSL
		}
	}
	return true
}

func (c *ServiceProxyClient) proxyWellKnownURLs() []string {
	if c.discoveryURLOverride != nil {
		if urls := c.discoveryURLOverride(c.ProviderAID); len(urls) > 0 {
			return urls
		}
	}
	issuer := serviceProxyIssuerDomainForAID(c.ProviderAID)
	if c.ProviderAID == "" || issuer == "" {
		return nil
	}
	return []string{
		"https://" + c.ProviderAID + "/.well-known/aun-proxy",
		"https://proxy." + issuer + "/.well-known/aun-proxy",
	}
}

func (c *ServiceProxyClient) fetchProxyWellKnown(ctx context.Context, wellKnownURL string, timeout time.Duration) (map[string]any, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.discoveryHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	wsURL := c.selectProxyWSURL(payload)
	if wsURL == "" {
		return nil, NewValidationError("Service Proxy well-known missing valid ws_url")
	}
	payload["ws_url"] = wsURL
	payload["source_url"] = wellKnownURL
	payload["discovered_at"] = float64(time.Now().Unix())
	return payload, nil
}

func (c *ServiceProxyClient) selectProxyWSURL(payload map[string]any) string {
	if direct := c.normalizeProxyWSURL(stringFromAny(payload["ws_url"])); direct != "" {
		return direct
	}
	var servers []map[string]any
	for _, item := range anySlice(payload["proxy_servers"]) {
		if m := asMap(item); len(m) > 0 {
			servers = append(servers, m)
		}
	}
	sort.Slice(servers, func(i, j int) bool {
		return floatFromAny(servers[i]["priority"]) < floatFromAny(servers[j]["priority"])
	})
	for _, item := range servers {
		if wsURL := c.normalizeProxyWSURL(stringFromAny(item["ws_url"])); wsURL != "" {
			return wsURL
		}
	}
	return ""
}

func (c *ServiceProxyClient) normalizeProxyWSURL(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return ""
	}
	parsed, err := url.Parse(text)
	if err != nil || parsed == nil {
		return ""
	}
	if parsed.Scheme == "ws" && c.shouldVerifySSL() {
		return ""
	}
	if parsed.Scheme != "wss" && parsed.Scheme != "ws" {
		return ""
	}
	if parsed.User != nil || parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" {
		return ""
	}
	parsed.Fragment = ""
	return parsed.String()
}

func (c *ServiceProxyClient) loadCachedProxyDiscovery() map[string]any {
	client, ok := c.AUNClient.(*AUNClient)
	if !ok || client == nil {
		return nil
	}
	client.mu.RLock()
	store := client.tokenStore
	client.mu.RUnlock()
	metadataStore, ok := store.(keystore.MetadataKeyStore)
	if !ok {
		return nil
	}
	raw := strings.TrimSpace(metadataStore.GetMetadataValue(c.ProviderAID, serviceProxyDiscoveryCacheKey))
	if raw == "" {
		return nil
	}
	var cached map[string]any
	if err := json.Unmarshal([]byte(raw), &cached); err != nil {
		return nil
	}
	wsURL := c.normalizeProxyWSURL(stringFromAny(cached["ws_url"]))
	if wsURL == "" {
		return nil
	}
	discoveredAt := int64(floatFromAny(cached["discovered_at"]))
	if discoveredAt <= 0 || time.Since(time.Unix(discoveredAt, 0)) >= serviceProxyDiscoveryCacheTTL {
		return nil
	}
	cached["ws_url"] = wsURL
	cached["cached"] = true
	return cached
}

func (c *ServiceProxyClient) persistProxyDiscovery(discovery map[string]any) {
	client, ok := c.AUNClient.(*AUNClient)
	if !ok || client == nil {
		return
	}
	client.mu.RLock()
	store := client.tokenStore
	client.mu.RUnlock()
	metadataStore, ok := store.(keystore.MetadataKeyStore)
	if !ok {
		return
	}
	data, err := json.Marshal(discovery)
	if err != nil {
		return
	}
	if err := metadataStore.SetMetadataValue(c.ProviderAID, serviceProxyDiscoveryCacheKey, string(data)); err != nil {
		c.logWarn("Service Proxy discovery cache write failed: %v", err)
	}
}

func (c *ServiceProxyClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	tr := &http.Transport{}
	if !c.shouldVerifySSL() {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func (c *ServiceProxyClient) discoveryHTTPClient() *http.Client {
	if c.DiscoveryHTTPClient != nil {
		return c.DiscoveryHTTPClient
	}
	tr := &http.Transport{}
	if !c.shouldVerifySSL() {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: tr}
}

func (c *ServiceProxyClient) dialProxyWS(ctx context.Context, targetURL string, headers http.Header) (*websocket.Conn, error) {
	if c.ProxyWebSocketDialer != nil {
		return c.ProxyWebSocketDialer(ctx, targetURL, headers)
	}
	opts := &websocket.DialOptions{HTTPHeader: headers}
	if !c.shouldVerifySSL() {
		opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	conn, _, err := websocket.Dial(ctx, targetURL, opts)
	return conn, err
}

func (c *ServiceProxyClient) dialBackendWS(ctx context.Context, targetURL string, subprotocols []string, headers http.Header) (*websocket.Conn, error) {
	if c.BackendWebSocketDialer != nil {
		return c.BackendWebSocketDialer(ctx, targetURL, subprotocols, headers)
	}
	opts := &websocket.DialOptions{HTTPHeader: headers, Subprotocols: subprotocols}
	if !c.shouldVerifySSL() {
		opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	conn, _, err := websocket.Dial(ctx, targetURL, opts)
	return conn, err
}

func (c *ServiceProxyClient) setRunning(v bool) {
	c.mu.Lock()
	c.running = v
	c.mu.Unlock()
}

func (c *ServiceProxyClient) isRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *ServiceProxyClient) setActiveTunnel(t *serviceProxyTunnel) {
	c.mu.Lock()
	c.activeTunnel = t
	c.mu.Unlock()
}

func (c *ServiceProxyClient) logWarn(format string, args ...any) {
	if c.Log != nil {
		c.Log.Warn(format, args...)
	}
}

type serviceProxyTunnel struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (t *serviceProxyTunnel) Send(ctx context.Context, message map[string]any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return NewSerializationError("failed to serialize Service Proxy tunnel message")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.conn.Write(ctx, websocket.MessageText, data)
}

func (t *serviceProxyTunnel) Recv(ctx context.Context) (map[string]any, error) {
	msgType, data, err := t.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if msgType != websocket.MessageText && msgType != websocket.MessageBinary {
		return map[string]any{}, nil
	}
	var message map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&message); err != nil {
		return nil, NewSerializationError("invalid Service Proxy tunnel JSON payload")
	}
	return normalizeDecodedJSONNumbers(message).(map[string]any), nil
}

func (t *serviceProxyTunnel) Close(code websocket.StatusCode, reason string) error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.Close(code, reason)
}

type serviceProxyProtocolDetection struct {
	ServiceType string
	StreamMode  string
	IsStream    bool
}

func serviceProxyDetectRequestProtocol(message map[string]any, record ServiceRecord) serviceProxyProtocolDetection {
	headers := serviceProxyHeadersMap(asMap(message["headers"]))
	streamMode := serviceProxyStreamModeFrom(headers, record, message)
	serviceType := strings.ToLower(strings.TrimSpace(stringFromAny(message["service_type"])))
	if serviceType == "" {
		serviceType = strings.ToLower(strings.TrimSpace(record.ServiceType))
	}
	if serviceType == "" {
		serviceType = "http"
	}
	if streamMode == "no_stream" {
		serviceType = "http"
	} else if stringFromAny(message["service_type"]) == "" {
		if explicit := strings.ToLower(strings.TrimSpace(headers["x-service-type"])); explicit != "" {
			serviceType = explicit
		} else {
			accept := strings.ToLower(headers["accept"])
			contentType := strings.ToLower(headers["content-type"])
			method := strings.ToUpper(stringFromAny(message["method"]))
			path := strings.ToLower(stringFromAny(message["path"]))
			switch {
			case strings.Contains(accept, "text/event-stream"):
				serviceType = "sse"
			case headers["mcp-session-id"] != "":
				serviceType = "mcp"
			case method == http.MethodPost && serviceProxyBodyHasJSONRPC(message):
				serviceType = "mcp"
			case strings.HasPrefix(contentType, "application/grpc"):
				serviceType = "ws"
			case strings.Contains(path, "/mcp"):
				serviceType = "mcp"
			case strings.Contains(path, "/sse") || strings.Contains(path, "/events"):
				serviceType = "sse"
			case strings.Contains(path, "/download") || strings.Contains(path, "/files/"):
				serviceType = "file"
			}
		}
	}
	var isStream bool
	if streamMode == "stream" {
		isStream = true
	} else if streamMode == "no_stream" {
		isStream = false
	} else if _, exists := message["is_stream"]; exists {
		isStream = boolFromAny(message["is_stream"])
	} else if _, exists := message["stream"]; exists {
		isStream = boolFromAny(message["stream"])
	} else {
		isStream = serviceProxyStreamingTypes[serviceType]
	}
	return serviceProxyProtocolDetection{ServiceType: serviceType, StreamMode: streamMode, IsStream: isStream}
}

func serviceProxyStreamModeFrom(headers map[string]string, record ServiceRecord, message map[string]any) string {
	value := strings.ToLower(strings.TrimSpace(stringFromAny(message["stream_mode"])))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(headers["x-stream-mode"]))
	}
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(stringFromAny(record.Metadata["stream_mode"])))
	}
	if value == "always" {
		return "stream"
	}
	if serviceProxyValidStreamModes[value] {
		return value
	}
	return "auto"
}

func serviceProxyBodyHasJSONRPC(message map[string]any) bool {
	raw := stringFromAny(message["body_base64"])
	if raw == "" {
		return false
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return false
	}
	if bytes.Contains(data, []byte(`"jsonrpc"`)) || bytes.Contains(data, []byte(`'jsonrpc'`)) {
		return true
	}
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false
	}
	if m := asMap(parsed); len(m) > 0 {
		return stringFromAny(m["jsonrpc"]) == "2.0"
	}
	for _, item := range anySlice(parsed) {
		if m := asMap(item); len(m) > 0 && stringFromAny(m["jsonrpc"]) == "2.0" {
			return true
		}
	}
	return false
}

func serviceProxyIsStreamResponseHeaders(headers map[string]string) bool {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(headers["content-type"], ";")[0]))
	contentDisposition := strings.ToLower(headers["content-disposition"])
	if strings.Contains(strings.ToLower(headers["content-type"]), "text/event-stream") {
		return true
	}
	if serviceProxyFileContentTypes[contentType] {
		return true
	}
	return strings.HasPrefix(contentType, "image/") || strings.HasPrefix(contentType, "video/") || strings.Contains(contentDisposition, "attachment")
}

func serviceProxyStreamTypeFromResponse(headers map[string]string, fallback string) string {
	if strings.Contains(strings.ToLower(headers["content-type"]), "text/event-stream") {
		return "sse"
	}
	if serviceProxyIsStreamResponseHeaders(headers) {
		return "file"
	}
	if text := strings.ToLower(strings.TrimSpace(fallback)); text != "" {
		return text
	}
	return "stream"
}

func serviceProxyNormalizeServiceName(serviceName string) (string, error) {
	value := strings.TrimSpace(serviceName)
	if value == "" {
		return "", NewValidationError("service_name is required")
	}
	if serviceProxyReservedServiceNames[value] {
		return "", NewValidationError("service_name is reserved")
	}
	if !serviceProxyNameRe.MatchString(value) {
		return "", NewValidationError("service_name must match [a-z0-9_-]+")
	}
	return value, nil
}

func serviceProxyNormalizeHost(host string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
}

func serviceProxySanitizeMetadata(metadata map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range metadata {
		if serviceProxyIsSensitiveMetadataKey(k) {
			continue
		}
		if m := asMap(v); len(m) > 0 {
			out[k] = serviceProxySanitizeMetadata(m)
		} else if arr := anySlice(v); arr != nil {
			clean := make([]any, 0, len(arr))
			for _, item := range arr {
				if m := asMap(item); len(m) > 0 {
					clean = append(clean, serviceProxySanitizeMetadata(m))
				} else {
					clean = append(clean, item)
				}
			}
			out[k] = clean
		} else {
			out[k] = v
		}
	}
	return out
}

func serviceProxyIsSensitiveMetadataKey(key string) bool {
	normalized := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(strings.TrimSpace(key)), "_")
	normalized = strings.Trim(normalized, "_")
	return serviceProxySensitiveMetadataKeys[normalized] ||
		strings.HasSuffix(normalized, "_token") ||
		strings.HasSuffix(normalized, "_secret") ||
		strings.HasSuffix(normalized, "_password") ||
		strings.HasSuffix(normalized, "_private_key")
}

func serviceProxySummariesToAny(services []ServiceSummary) []any {
	out := make([]any, 0, len(services))
	for _, svc := range services {
		out = append(out, map[string]any{
			"service_name": svc.ServiceName,
			"service_type": svc.ServiceType,
			"visibility":   svc.Visibility,
			"metadata":     serviceProxySanitizeMetadata(svc.Metadata),
		})
	}
	return out
}

func serviceProxyErrorMessage(requestID, code, message string) map[string]any {
	return map[string]any{"type": "service_proxy_error", "request_id": requestID, "error": map[string]any{"code": code, "message": message}}
}

func serviceProxyWSErrorMessage(connectionID, code, message string) map[string]any {
	return map[string]any{"type": "ws_error", "connection_id": connectionID, "error": map[string]any{"code": code, "message": message}}
}

func serviceProxyStreamMessage(requestID string, index, status int, headers map[string]string, data []byte, done bool) map[string]any {
	msg := map[string]any{
		"type":        "service_proxy_stream",
		"request_id":  requestID,
		"index":       index,
		"status":      nil,
		"headers":     map[string]string{},
		"data_base64": base64.StdEncoding.EncodeToString(data),
		"done":        done,
	}
	if index == 0 {
		msg["status"] = status
		msg["headers"] = headers
	}
	return msg
}

func serviceProxyErrorMessageFromResponse(response map[string]any, fallback string) string {
	if errMap := asMap(response["error"]); len(errMap) > 0 {
		if message := strings.TrimSpace(stringFromAny(errMap["message"])); message != "" {
			return message
		}
	}
	return fallback
}

func serviceProxyIssuerDomainForAID(aid string) string {
	parts := strings.SplitN(strings.ToLower(strings.TrimSpace(aid)), ".", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.Trim(parts[1], ".")
}

func serviceProxyNormalizePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func serviceProxyBuildTargetURL(endpoint, path, query string) string {
	base := strings.TrimRight(endpoint, "/") + "/"
	parsed, err := url.Parse(base)
	if err != nil {
		return endpoint
	}
	ref := &url.URL{Path: strings.TrimLeft(path, "/")}
	out := parsed.ResolveReference(ref)
	if query != "" {
		out.RawQuery = strings.TrimPrefix(query, "?")
	}
	return out.String()
}

func serviceProxyBackendHeaders(headers map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range headers {
		name := strings.ToLower(k)
		if serviceProxyHopByHopHeaders[name] || name == "host" {
			continue
		}
		out[name] = stringFromAny(v)
	}
	return out
}

func serviceProxyHeadersMap(headers map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range headers {
		out[strings.ToLower(k)] = stringFromAny(v)
	}
	return out
}

func serviceProxyResponseHeaders(headers http.Header) map[string]string {
	out := map[string]string{}
	for k, values := range headers {
		name := strings.ToLower(k)
		if serviceProxyHopByHopHeaders[name] || serviceProxyAutoResponseHeaders[name] {
			continue
		}
		out[name] = strings.Join(values, ", ")
	}
	return out
}

func serviceProxyReadLimited(reader io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(reader, limit+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("response body too large")
	}
	return buf.Bytes(), nil
}

func asMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = v
		}
		return out
	default:
		return map[string]any{}
	}
}

func boolFromAny(value any) bool {
	if v, ok := value.(bool); ok {
		return v
	}
	return false
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, _ := v.Int64()
		return int(i)
	default:
		return 0
	}
}

func floatFromAny(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	default:
		return 0
	}
}

func stringSliceFromAny(value any) []string {
	var out []string
	for _, item := range anySlice(value) {
		if text := strings.TrimSpace(stringFromAny(item)); text != "" {
			out = append(out, text)
		}
	}
	return out
}
