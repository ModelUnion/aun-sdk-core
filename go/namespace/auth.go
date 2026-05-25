package namespace

import (
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClientInterface 定义 AuthNamespace 所需的客户端接口
// 避免直接依赖 AUNClient 导致的循环引用
type ClientInterface interface {
	GetGatewayURL() string
	SetGatewayURL(url string)
	GetAID() string
	SetAID(aid string)
	GetConfigDiscoveryPort() int
	GetConfigVerifySSL() bool
	Call(ctx context.Context, method string, params map[string]any) (any, error)

	// 认证流程所需方法
	AuthCreateAID(ctx context.Context, gatewayURL, aid string) (map[string]any, error)
	AuthAuthenticate(ctx context.Context, gatewayURL, aid string) (map[string]any, error)
	AuthLoadIdentityOrNil(aid string) map[string]any
	AuthFetchPeerCert(ctx context.Context, aid, certFingerprint string) ([]byte, error)
	DiscoverGateway(ctx context.Context, wellKnownURL string, timeout time.Duration) (string, error)
	SetIdentity(identity map[string]any)

	// gateway URL 缓存（keystore metadata 持久化），用于跨进程复用 discovery 结果。
	// 实现方在没有 MetadataKeyStore 能力时可返回空字符串 / 空操作。
	AuthLoadCachedGatewayURL(aid string) string
	AuthPersistGatewayURL(aid, gatewayURL string)

	// CheckAID 所需的 keystore 访问方法
	AuthLoadKeyPair(aid string) (map[string]any, error)
	AuthLoadCert(aid string) (string, error)
}

// AuthNamespace 认证命名空间
// 封装 AID 创建、认证、证书管理等操作。
// 与 Python SDK namespaces/auth_namespace.py 对应。
type AuthNamespace struct {
	client         ClientInterface
	httpClientOnce sync.Once
	httpClient     *http.Client
	agentMDCache   map[string]*agentMDCacheEntry
	agentMDCacheMu sync.Mutex
}

type agentMDCacheEntry struct {
	text         string
	etag         string
	lastModified string
}

var agentMDFingerprintRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// aidNameRe AID name 验证：4-64 字符，仅 [a-z0-9_-]，首字符不为 -
var aidNameRe = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]{3,63}$`)

// authValidateAIDName 验证 AID name 部分是否符合协议规范
func authValidateAIDName(aid string) error {
	name := aid
	if idx := strings.Index(aid, "."); idx >= 0 {
		name = aid[:idx]
	}
	if !aidNameRe.MatchString(name) {
		return fmt.Errorf(
			"invalid AID name '%s': must be 4-64 characters, only [a-z0-9_-], cannot start with '-'", name)
	}
	if strings.HasPrefix(name, "guest") {
		return fmt.Errorf("AID name must not start with 'guest'")
	}
	return nil
}

type AgentMDSignOptions struct {
	AID string
}

type AgentMDVerifyOptions struct {
	AID     string
	CertPEM string
}

// NewAuthNamespace 创建认证命名空间
func NewAuthNamespace(client ClientInterface) *AuthNamespace {
	return &AuthNamespace{client: client}
}

// resolveGateway 解析 gateway URL。优先使用已预置的 gatewayURL，否则基于 AID 自动发现。
//
// 发现流程：
//  1. 若 gatewayURL 已预置（内存），直接返回
//  2. 从 keystore metadata 读 cached gateway_url（跨进程复用，避免每次启动都做 well-known discovery）
//  3. 开发环境：先 gateway.{issuer}，再 fallback {aid}（泛域名在开发环境可能不可用）
//  4. 生产环境：先 {aid}（泛域名 nameservice），再 fallback gateway.{issuer}
//
// 与 Python SDK namespaces/auth_namespace.py:_resolve_gateway 对齐。
func (a *AuthNamespace) resolveGateway(ctx context.Context, aid string) (string, error) {
	if gw := a.client.GetGatewayURL(); gw != "" {
		return gw, nil
	}
	resolvedAID := aid
	if resolvedAID == "" {
		resolvedAID = a.client.GetAID()
	}
	if resolvedAID == "" {
		return "", fmt.Errorf("无法解析 gateway：需设置 gateway_url 或提供 'aid' 进行自动发现")
	}

	// 从 keystore metadata 读持久化的 gateway_url（避免每次进程启动都做 well-known discovery）
	if cached := strings.TrimSpace(a.client.AuthLoadCachedGatewayURL(resolvedAID)); cached != "" {
		pkgLogAuth().Debug("resolveGateway from keystore cache aid=%s gateway=%s", resolvedAID, cached)
		a.client.SetGatewayURL(cached)
		return cached, nil
	}

	parts := strings.SplitN(resolvedAID, ".", 2)
	issuerDomain := resolvedAID
	if len(parts) > 1 {
		issuerDomain = parts[1]
	}

	port := a.client.GetConfigDiscoveryPort()
	portSuffix := ""
	if port > 0 {
		portSuffix = fmt.Sprintf(":%d", port)
	}

	aidURL := fmt.Sprintf("https://%s%s/.well-known/aun-gateway", resolvedAID, portSuffix)
	gatewayURL := fmt.Sprintf("https://gateway.%s%s/.well-known/aun-gateway", issuerDomain, portSuffix)

	// 开发环境：先 gateway.{issuer}（固定域名），再 fallback {aid}（泛域名）
	// 生产环境：先 {aid}（泛域名），再 fallback gateway.{issuer}
	primaryURL, fallbackURL := aidURL, gatewayURL
	if !a.client.GetConfigVerifySSL() {
		primaryURL, fallbackURL = gatewayURL, aidURL
	}

	gwURL, err := a.client.DiscoverGateway(ctx, primaryURL, 5*time.Second)
	if err == nil {
		a.client.AuthPersistGatewayURL(resolvedAID, gwURL)
		return gwURL, nil
	}
	pkgLogAuth().Warn("gateway discovery failed (%s): %v", primaryURL, err)

	gwURL, err = a.client.DiscoverGateway(ctx, fallbackURL, 5*time.Second)
	if err == nil {
		a.client.AuthPersistGatewayURL(resolvedAID, gwURL)
	}
	return gwURL, err
}

// CreateAIDWithName 类型安全的便捷方法，通过 AID 名称创建身份。
// 内部构造 map 并调用 CreateAID。
func (a *AuthNamespace) CreateAIDWithName(ctx context.Context, aid string) (out map[string]any, err error) {
	tStart := time.Now()
	pkgLogAuth().Debug("CreateAIDWithName enter: aid=%s", aid)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("CreateAIDWithName exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("CreateAIDWithName exit: aid=%s elapsed=%dms", aid, time.Since(tStart).Milliseconds())
		}
	}()
	return a.CreateAID(ctx, map[string]any{"aid": aid})
}

// CreateAID 创建新的 AID 身份
func (a *AuthNamespace) CreateAID(ctx context.Context, params map[string]any) (out map[string]any, err error) {
	tStart := time.Now()
	aid, _ := params["aid"].(string)
	pkgLogAuth().Debug("CreateAID enter: aid=%s", aid)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("CreateAID exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("CreateAID exit: aid=%s elapsed=%dms", aid, time.Since(tStart).Milliseconds())
		}
	}()
	if aid == "" {
		err = fmt.Errorf("auth.create_aid 需要 'aid' 参数")
		return nil, err
	}

	gatewayURL, err := a.resolveGateway(ctx, aid)
	if err != nil {
		return nil, fmt.Errorf("auth.create_aid gateway 发现失败: %w", err)
	}
	a.client.SetGatewayURL(gatewayURL)

	result, err := a.client.AuthCreateAID(ctx, gatewayURL, aid)
	if err != nil {
		return nil, err
	}

	resultAID, _ := result["aid"].(string)
	a.client.SetAID(resultAID)
	identity := a.client.AuthLoadIdentityOrNil(resultAID)
	a.client.SetIdentity(identity)

	return map[string]any{
		"aid":      resultAID,
		"cert_pem": result["cert"],
		"gateway":  gatewayURL,
	}, nil
}

// Authenticate 认证已有的 AID
func (a *AuthNamespace) Authenticate(ctx context.Context, params map[string]any) (out map[string]any, err error) {
	tStart := time.Now()
	request := make(map[string]any)
	if params != nil {
		for k, v := range params {
			request[k] = v
		}
	}
	aid, _ := request["aid"].(string)
	pkgLogAuth().Debug("Authenticate enter: aid=%s", aid)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("Authenticate exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("Authenticate exit: aid=%s elapsed=%dms", aid, time.Since(tStart).Milliseconds())
		}
	}()

	gatewayURL, err := a.resolveGateway(ctx, aid)
	if err != nil {
		return nil, fmt.Errorf("auth.authenticate gateway 发现失败: %w", err)
	}
	a.client.SetGatewayURL(gatewayURL)

	result, err := a.client.AuthAuthenticate(ctx, gatewayURL, aid)
	if err != nil {
		return nil, err
	}

	resultAID, _ := result["aid"].(string)
	a.client.SetAID(resultAID)
	identity := a.client.AuthLoadIdentityOrNil(resultAID)
	a.client.SetIdentity(identity)

	return result, nil
}

func (a *AuthNamespace) SignAgentMD(ctx context.Context, content string, opts *AgentMDSignOptions) (signed string, err error) {
	tStart := time.Now()
	targetAID := strings.TrimSpace(a.client.GetAID())
	if opts != nil && strings.TrimSpace(opts.AID) != "" {
		targetAID = strings.TrimSpace(opts.AID)
	}
	pkgLogAuth().Debug("SignAgentMD enter: aid=%s len=%d", targetAID, len(content))
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("SignAgentMD exit (error): aid=%s elapsed=%dms err=%v", targetAID, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("SignAgentMD exit: aid=%s elapsed=%dms", targetAID, time.Since(tStart).Milliseconds())
		}
	}()

	identity := a.client.AuthLoadIdentityOrNil(targetAID)
	if identity == nil {
		return "", fmt.Errorf("no local identity found, call auth.create_aid() first")
	}

	privateKeyPEM, _ := identity["private_key_pem"].(string)
	privateKeyPEM = strings.TrimSpace(privateKeyPEM)
	certPEM := normalizeAgentMDCertPEM(identity)
	if privateKeyPEM == "" || certPEM == "" {
		return "", fmt.Errorf("local identity missing private key or certificate")
	}

	payload, _, _, _ := parseAgentMDTailSignature(content)
	if payload != "" && !strings.HasSuffix(payload, "\n") && !strings.HasSuffix(payload, "\r") {
		payload += "\n"
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid private key PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("invalid private key PEM: %w", err)
	}
	privateKey, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("agent.md signing requires an ECDSA private key")
	}

	hash := sha256.Sum256([]byte(payload))
	signature, err := ecdsa.SignASN1(cryptorand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("agent.md signing failed: %w", err)
	}

	fingerprint := agentMDCertFingerprint(certPEM)
	if fingerprint == "" {
		return "", fmt.Errorf("agent.md cert fingerprint failed: invalid certificate")
	}
	signedBlock := strings.Join([]string{
		"<!-- AUN-SIGNATURE",
		"cert_fingerprint: " + fingerprint,
		fmt.Sprintf("timestamp: %d", time.Now().Unix()),
		"signature: " + base64.StdEncoding.EncodeToString(signature),
		"-->",
	}, "\n")

	return payload + signedBlock, nil
}

func (a *AuthNamespace) VerifyAgentMD(ctx context.Context, content string, opts *AgentMDVerifyOptions) (out map[string]any, err error) {
	tStart := time.Now()
	pkgLogAuth().Debug("VerifyAgentMD enter: len=%d", len(content))
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("VerifyAgentMD exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("VerifyAgentMD exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	payload, fields, _, parseError := parseAgentMDTailSignature(content)
	if fields == nil {
		if parseError == "" {
			return agentMDResult("unsigned", payload, "", "", "", 0), nil
		}
		return agentMDResult("invalid", payload, parseError, "", "", 0), nil
	}

	expectedAID := ""
	if opts != nil {
		expectedAID = strings.TrimSpace(opts.AID)
	}
	payloadAID := extractAgentMDAID(payload)
	if expectedAID != "" && payloadAID != "" && expectedAID != payloadAID {
		return agentMDResult("invalid", payload, "aid mismatch", payloadAID, "", 0), nil
	}
	if expectedAID == "" {
		expectedAID = payloadAID
	}

	certPEM := ""
	if opts != nil {
		certPEM = strings.TrimSpace(opts.CertPEM)
	}
	if certPEM == "" {
		if expectedAID == "" {
			return agentMDResult("invalid", payload, "aid required to verify agent.md", payloadAID, "", 0), nil
		}
		fetched, err := a.client.AuthFetchPeerCert(ctx, expectedAID, fields["cert_fingerprint"])
		if err != nil {
			return agentMDResult("invalid", payload, err.Error(), expectedAID, fields["cert_fingerprint"], 0), nil
		}
		certPEM = strings.TrimSpace(string(fetched))
	}
	if certPEM == "" {
		return agentMDResult("invalid", payload, "invalid certificate", expectedAID, fields["cert_fingerprint"], 0), nil
	}

	certDER := mustDecodePEMCertificate(certPEM)
	if len(certDER) == 0 {
		return agentMDResult("invalid", payload, "invalid certificate", expectedAID, fields["cert_fingerprint"], 0), nil
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return agentMDResult("invalid", payload, "invalid certificate: "+err.Error(), expectedAID, fields["cert_fingerprint"], 0), nil
	}

	actualFingerprint := agentMDCertFingerprint(certPEM)
	if actualFingerprint == "" {
		return agentMDResult("invalid", payload, "invalid certificate fingerprint", expectedAID, fields["cert_fingerprint"], 0), nil
	}
	if !strings.EqualFold(actualFingerprint, fields["cert_fingerprint"]) {
		return agentMDResult("invalid", payload, "certificate fingerprint mismatch", expectedAID, fields["cert_fingerprint"], 0), nil
	}

	if expectedAID != "" && cert.Subject.CommonName != "" && cert.Subject.CommonName != expectedAID {
		return agentMDResult("invalid", payload, "certificate aid mismatch", expectedAID, fields["cert_fingerprint"], 0), nil
	}

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return agentMDResult("invalid", payload, "invalid certificate: unsupported public key", expectedAID, fields["cert_fingerprint"], 0), nil
	}

	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil || len(signature) == 0 {
		return agentMDResult("invalid", payload, "invalid signature", expectedAID, fields["cert_fingerprint"], 0), nil
	}

	hash := sha256.Sum256([]byte(payload))
	if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
		return agentMDResult("invalid", payload, "signature verification failed", expectedAID, fields["cert_fingerprint"], parseAgentMDTimestamp(fields["timestamp"])), nil
	}

	return agentMDResult("verified", payload, "", firstNonEmpty(expectedAID, payloadAID), fields["cert_fingerprint"], parseAgentMDTimestamp(fields["timestamp"])), nil
}

func mustDecodePEMCertificate(certPEM string) []byte {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil
	}
	return block.Bytes
}

func parseAgentMDTimestamp(value string) int64 {
	timestamp, err := parseInt64Strict(value)
	if err != nil {
		return 0
	}
	return timestamp
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func agentMDCertFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	hash := sha256.Sum256(block.Bytes)
	return "sha256:" + fmt.Sprintf("%x", hash[:])
}

func agentMDSchemeFromGateway(gatewayURL string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(gatewayURL)), "ws://") {
		return "http"
	}
	return "https"
}

func agentMDAuthority(aid string, discoveryPort int) string {
	host := strings.TrimSpace(aid)
	if host == "" {
		return ""
	}
	if discoveryPort > 0 && !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, discoveryPort)
	}
	return host
}

func parseAgentMDTailSignature(content string) (string, map[string]string, bool, string) {
	marker := "<!-- AUN-SIGNATURE"
	idx := strings.LastIndex(content, marker)
	if idx < 0 {
		return content, nil, false, ""
	}
	if idx > 0 {
		prev := content[idx-1]
		if prev != '\n' && prev != '\r' {
			return content, nil, false, ""
		}
	}
	tail := content[idx:]
	if !strings.HasPrefix(tail, marker) {
		return content, nil, true, "malformed signature block"
	}
	endIdx := strings.LastIndex(tail, "-->")
	if endIdx < 0 {
		return content[:idx], nil, true, "malformed signature block"
	}
	trimmed := strings.TrimSpace(tail[endIdx+3:])
	if trimmed != "" {
		return content[:idx], nil, true, "malformed signature block"
	}

	body := tail[len(marker):endIdx]
	body = strings.TrimLeft(body, "\r\n")
	body = strings.TrimRight(body, "\r\n")

	fields := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		stripped := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if stripped == "" {
			continue
		}
		parts := strings.SplitN(stripped, ":", 2)
		if len(parts) != 2 {
			return content[:idx], nil, true, "malformed signature field"
		}
		fields[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	}
	for _, key := range []string{"cert_fingerprint", "timestamp", "signature"} {
		if fields[key] == "" {
			return content[:idx], nil, true, "signature block missing " + key
		}
	}
	if !agentMDFingerprintRe.MatchString(strings.ToLower(fields["cert_fingerprint"])) {
		return content[:idx], nil, true, "invalid cert_fingerprint"
	}
	if _, err := parseInt64Strict(fields["timestamp"]); err != nil {
		return content[:idx], nil, true, "invalid timestamp"
	}
	return content[:idx], fields, true, ""
}

func parseInt64Strict(value string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(value), 10, 64)
}

func extractAgentMDAID(payload string) string {
	lines := strings.Split(strings.TrimPrefix(payload, "\ufeff"), "\n")
	if len(lines) == 0 || strings.TrimSpace(strings.TrimSuffix(lines[0], "\r")) != "---" {
		return ""
	}
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(strings.TrimSuffix(lines[i], "\r"))
		if line == "---" {
			break
		}
		if strings.HasPrefix(line, "aid:") {
			value := strings.TrimSpace(strings.TrimSpace(strings.TrimPrefix(line, "aid:")))
			value = strings.Trim(value, "\"'")
			return value
		}
	}
	return ""
}

func agentMDResult(status, payload, reason, aid, certFingerprint string, timestamp int64) map[string]any {
	result := map[string]any{
		"status":   status,
		"verified": status == "verified",
		"payload":  payload,
	}
	if reason != "" {
		result["reason"] = reason
	}
	if aid != "" {
		result["aid"] = aid
	}
	if certFingerprint != "" {
		result["cert_fingerprint"] = certFingerprint
	}
	if timestamp > 0 {
		result["timestamp"] = timestamp
	}
	return result
}

func normalizeAgentMDCertPEM(identity map[string]any) string {
	if identity == nil {
		return ""
	}
	if cert, _ := identity["cert"].(string); strings.TrimSpace(cert) != "" {
		return strings.TrimSpace(cert)
	}
	if cert, _ := identity["cert_pem"].(string); strings.TrimSpace(cert) != "" {
		return strings.TrimSpace(cert)
	}
	return ""
}

func authAccessTokenExpiryUnix(identity map[string]any) int64 {
	if identity == nil {
		return 0
	}
	switch v := identity["access_token_expires_at"].(type) {
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func authUsableAccessToken(identity map[string]any) string {
	if identity == nil {
		return ""
	}
	token, _ := identity["access_token"].(string)
	if token == "" {
		return ""
	}
	expiresAt := authAccessTokenExpiryUnix(identity)
	if expiresAt > 0 && time.Now().Unix()+30 >= expiresAt {
		return ""
	}
	return token
}

func (a *AuthNamespace) resolveAgentMDURL(ctx context.Context, aid string) string {
	gatewayURL := a.client.GetGatewayURL()
	if gatewayURL == "" {
		if resolved, err := a.resolveGateway(ctx, aid); err == nil {
			gatewayURL = resolved
		}
	}
	authority := agentMDAuthority(aid, a.client.GetConfigDiscoveryPort())
	return fmt.Sprintf("%s://%s/agent.md", agentMDSchemeFromGateway(gatewayURL), authority)
}

func (a *AuthNamespace) agentMDHTTPClient() *http.Client {
	a.httpClientOnce.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
		}
		if !a.client.GetConfigVerifySSL() {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		a.httpClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		}
	})
	return a.httpClient
}

// CachedAgentMDMeta 返回最近一次 GET/HEAD 观察到的 agent.md ETag 元数据。
func (a *AuthNamespace) CachedAgentMDMeta(aid string) map[string]string {
	targetAID := strings.TrimSpace(aid)
	if targetAID == "" {
		return nil
	}
	a.agentMDCacheMu.Lock()
	defer a.agentMDCacheMu.Unlock()
	cached := a.agentMDCache[targetAID]
	if cached == nil {
		return nil
	}
	return map[string]string{
		"etag":          cached.etag,
		"last_modified": cached.lastModified,
	}
}
func (a *AuthNamespace) ensureAgentMDUploadToken(ctx context.Context, aid string) (string, error) {
	identity := a.client.AuthLoadIdentityOrNil(aid)
	if identity == nil {
		return "", fmt.Errorf("no local identity found, call auth.create_aid() first")
	}
	if token := authUsableAccessToken(identity); token != "" {
		return token, nil
	}

	result, err := a.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		return "", err
	}
	token, _ := result["access_token"].(string)
	if token == "" {
		return "", fmt.Errorf("authenticate did not return access_token")
	}
	return token, nil
}

// UploadAgentMD 上传当前身份的 agent.md 文档。
func (a *AuthNamespace) UploadAgentMD(ctx context.Context, content string) (out map[string]any, err error) {
	tStart := time.Now()
	aid := strings.TrimSpace(a.client.GetAID())
	pkgLogAuth().Debug("UploadAgentMD enter: aid=%s len=%d", aid, len(content))
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("UploadAgentMD exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("UploadAgentMD exit: aid=%s elapsed=%dms", aid, time.Since(tStart).Milliseconds())
		}
	}()
	identity := a.client.AuthLoadIdentityOrNil(aid)
	if identity == nil {
		return nil, fmt.Errorf("no local identity found, call auth.create_aid() first")
	}
	if aid == "" {
		if identityAID, ok := identity["aid"].(string); ok {
			aid = strings.TrimSpace(identityAID)
		}
	}
	if aid == "" {
		return nil, fmt.Errorf("no local identity found, call auth.create_aid() first")
	}

	gatewayURL, err := a.resolveGateway(ctx, aid)
	if err != nil {
		return nil, fmt.Errorf("auth.upload_agent_md gateway 发现失败: %w", err)
	}
	a.client.SetGatewayURL(gatewayURL)

	token, err := a.ensureAgentMDUploadToken(ctx, aid)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, a.resolveAgentMDURL(ctx, aid), strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/markdown; charset=utf-8")

	resp, err := a.agentMDHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("agent.md endpoint not found for aid: %s", aid)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		if message != "" {
			return nil, fmt.Errorf("upload agent.md failed: HTTP %d - %s", resp.StatusCode, message)
		}
		return nil, fmt.Errorf("upload agent.md failed: HTTP %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("upload agent.md failed: invalid JSON response: %w", err)
	}
	return result, nil
}

// DownloadAgentMD 匿名下载指定 AID 的 agent.md 文档。
func (a *AuthNamespace) DownloadAgentMD(ctx context.Context, aid string) (content string, err error) {
	tStart := time.Now()
	pkgLogAuth().Debug("DownloadAgentMD enter: aid=%s", aid)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("DownloadAgentMD exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("DownloadAgentMD exit: aid=%s len=%d elapsed=%dms", aid, len(content), time.Since(tStart).Milliseconds())
		}
	}()
	targetAID := strings.TrimSpace(aid)
	if targetAID == "" {
		err = fmt.Errorf("download_agent_md requires non-empty aid")
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.resolveAgentMDURL(ctx, targetAID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/markdown")

	a.agentMDCacheMu.Lock()
	cached := a.agentMDCache[targetAID]
	a.agentMDCacheMu.Unlock()
	if cached != nil {
		if cached.etag != "" {
			req.Header.Set("If-None-Match", cached.etag)
		}
		if cached.lastModified != "" {
			req.Header.Set("If-Modified-Since", cached.lastModified)
		}
	}

	resp, err := a.agentMDHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified && cached != nil {
		pkgLogAuth().Debug("DownloadAgentMD not_modified: aid=%s", targetAID)
		return cached.text, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("agent.md not found for aid: %s", targetAID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		if message != "" {
			return "", fmt.Errorf("download agent.md failed: HTTP %d - %s", resp.StatusCode, message)
		}
		return "", fmt.Errorf("download agent.md failed: HTTP %d", resp.StatusCode)
	}
	text := string(body)
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	lastModified := strings.TrimSpace(resp.Header.Get("Last-Modified"))
	if etag != "" || lastModified != "" {
		a.agentMDCacheMu.Lock()
		if a.agentMDCache == nil {
			a.agentMDCache = make(map[string]*agentMDCacheEntry)
		}
		a.agentMDCache[targetAID] = &agentMDCacheEntry{text: text, etag: etag, lastModified: lastModified}
		a.agentMDCacheMu.Unlock()
	}
	return text, nil
}

// HeadAgentMD 通过 HEAD 检查指定 AID 的 agent.md 云端 ETag。
func (a *AuthNamespace) HeadAgentMD(ctx context.Context, aid string) (out map[string]any, err error) {
	tStart := time.Now()
	targetAID := strings.TrimSpace(aid)
	pkgLogAuth().Debug("HeadAgentMD enter: aid=%s", targetAID)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("HeadAgentMD exit (error): aid=%s elapsed=%dms err=%v", targetAID, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("HeadAgentMD exit: aid=%s found=%v etag=%s elapsed=%dms", targetAID, out["found"], out["etag"], time.Since(tStart).Milliseconds())
		}
	}()
	if targetAID == "" {
		return nil, fmt.Errorf("head_agent_md requires non-empty aid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, a.resolveAgentMDURL(ctx, targetAID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/markdown")

	resp, err := a.agentMDHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	lastModified := strings.TrimSpace(resp.Header.Get("Last-Modified"))
	result := map[string]any{
		"aid":           targetAID,
		"found":         resp.StatusCode >= 200 && resp.StatusCode < 300,
		"etag":          etag,
		"last_modified": lastModified,
		"status":        resp.StatusCode,
	}
	if resp.StatusCode == http.StatusNotFound {
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("head agent.md failed: HTTP %d", resp.StatusCode)
	}

	a.agentMDCacheMu.Lock()
	if a.agentMDCache == nil {
		a.agentMDCache = make(map[string]*agentMDCacheEntry)
	}
	cached := a.agentMDCache[targetAID]
	if cached == nil {
		cached = &agentMDCacheEntry{}
		a.agentMDCache[targetAID] = cached
	}
	cached.etag = etag
	cached.lastModified = lastModified
	a.agentMDCacheMu.Unlock()
	return result, nil
}

// DownloadCert 下载证书
func (a *AuthNamespace) DownloadCert(ctx context.Context, params map[string]any) (any, error) {
	return a.client.Call(ctx, "auth.download_cert", params)
}

// RequestCert 请求证书
func (a *AuthNamespace) RequestCert(ctx context.Context, params map[string]any) (any, error) {
	return a.client.Call(ctx, "auth.request_cert", params)
}

// RenewCert 续期证书
func (a *AuthNamespace) RenewCert(ctx context.Context, params map[string]any) (any, error) {
	return a.client.Call(ctx, "auth.renew_cert", params)
}

// Rekey 重新生成密钥
func (a *AuthNamespace) Rekey(ctx context.Context, params map[string]any) (any, error) {
	return a.client.Call(ctx, "auth.rekey", params)
}

// TrustRoots 获取信任根
func (a *AuthNamespace) TrustRoots(ctx context.Context, params map[string]any) (any, error) {
	return a.client.Call(ctx, "meta.trust_roots", params)
}

// CheckAID 检查指定 AID 的本地和远程状态。
// 与 Python SDK namespaces/auth_namespace.py:check_aid 对应。
func (a *AuthNamespace) CheckAID(ctx context.Context, params map[string]any) (out map[string]any, err error) {
	tStart := time.Now()
	aid, _ := params["aid"].(string)
	aid = strings.TrimSpace(aid)
	if aid == "" {
		return nil, fmt.Errorf("auth.check_aid requires 'aid'")
	}
	pkgLogAuth().Debug("CheckAID enter: aid=%s", aid)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("CheckAID exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			status, _ := out["status"].(string)
			pkgLogAuth().Debug("CheckAID exit: aid=%s elapsed=%dms status=%s", aid, time.Since(tStart).Milliseconds(), status)
		}
	}()

	if err := authValidateAIDName(aid); err != nil {
		return nil, err
	}

	result := a.checkLocalAID(aid)
	localMap, _ := result["local"].(map[string]any)
	localComplete := false
	if localMap != nil {
		localComplete, _ = localMap["complete"].(bool)
	}

	if !localComplete {
		remote := a.checkRemoteAIDRegistration(ctx, aid)
		result["remote"] = remote
		remoteStatus, _ := remote["status"].(string)
		switch remoteStatus {
		case "available":
			result["status"] = "available"
			result["can_register"] = true
		case "registered":
			result["status"] = "registered_remote"
			result["can_register"] = false
		default:
			result["status"] = "unknown"
			result["can_register"] = false
		}
	}

	return result, nil
}

// checkLocalAID 检查本地 AID 状态（密钥对 + 证书）
func (a *AuthNamespace) checkLocalAID(aid string) map[string]any {
	identity := a.client.AuthLoadIdentityOrNil(aid)

	keyPair, keyErr := a.client.AuthLoadKeyPair(aid)
	certPEM, certErr := a.client.AuthLoadCert(aid)

	privateKeyPresent := false
	publicKeyPresent := false
	if keyPair != nil {
		if pkPem, _ := keyPair["private_key_pem"].(string); pkPem != "" {
			privateKeyPresent = true
		}
		if pubDer, _ := keyPair["public_key_der_b64"].(string); pubDer != "" {
			publicKeyPresent = true
		}
	}

	certPresent := certPEM != ""
	certInfo := map[string]any{
		"present": false,
		"valid":   false,
		"expired": false,
	}
	if certPresent {
		certInfo = a.inspectCert(aid, certPEM)
	}

	certValid, _ := certInfo["valid"].(bool)
	localComplete := privateKeyPresent && publicKeyPresent && certPresent && certValid

	issues := []string{}
	if identity == nil {
		issues = append(issues, "local identity not found")
	}
	if !privateKeyPresent {
		issues = append(issues, "private key missing")
	}
	if !publicKeyPresent {
		issues = append(issues, "public key missing")
	}
	if !certPresent {
		issues = append(issues, "certificate missing")
	} else if parseErr, _ := certInfo["parse_error"].(string); parseErr != "" {
		issues = append(issues, "certificate invalid: "+parseErr)
	} else if expired, _ := certInfo["expired"].(bool); expired {
		issues = append(issues, "certificate expired")
	} else if !certValid {
		issues = append(issues, "certificate not currently valid")
	}
	if keyErr != nil {
		issues = append(issues, "key load error: "+keyErr.Error())
	}
	if certErr != nil {
		issues = append(issues, "certificate load error: "+certErr.Error())
	}

	status := "local_incomplete"
	if localComplete {
		status = "local_ready"
	}

	remoteStatus := "pending"
	if localComplete {
		remoteStatus = "not_checked"
	}

	var canRegister any
	if localComplete {
		canRegister = false
	} else {
		canRegister = nil
	}

	return map[string]any{
		"aid":          aid,
		"status":       status,
		"can_register": canRegister,
		"local": map[string]any{
			"exists":      identity != nil,
			"complete":    localComplete,
			"private_key": privateKeyPresent,
			"public_key":  publicKeyPresent,
			"certificate": certInfo,
			"issues":      issues,
		},
		"remote": map[string]any{
			"status": remoteStatus,
		},
	}
}

// inspectCert 检查证书有效性
func (a *AuthNamespace) inspectCert(aid, certPEM string) map[string]any {
	result := map[string]any{
		"present": true,
		"valid":   false,
		"expired": false,
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		result["parse_error"] = "invalid PEM"
		return result
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		result["parse_error"] = err.Error()
		return result
	}

	now := time.Now().UTC()
	notBefore := cert.NotBefore.UTC()
	notAfter := cert.NotAfter.UTC()
	valid := !now.Before(notBefore) && !now.After(notAfter)
	expired := now.After(notAfter)

	fingerprint := fmt.Sprintf("sha256:%x", sha256.Sum256(block.Bytes))
	cn := cert.Subject.CommonName
	aidMatches := cn == "" || cn == aid

	result["valid"] = valid
	result["expired"] = expired
	result["not_before"] = notBefore.Format(time.RFC3339)
	result["not_after"] = notAfter.Format(time.RFC3339)
	result["expires_at"] = notAfter.Unix()
	result["seconds_until_expiry"] = int64(notAfter.Sub(now).Seconds())
	result["fingerprint"] = fingerprint
	result["subject_cn"] = cn
	result["aid_matches"] = aidMatches

	if cn != "" && cn != aid {
		result["valid"] = false
		result["parse_error"] = fmt.Sprintf("certificate CN mismatch: %s", cn)
	}

	return result
}

// checkRemoteAIDRegistration 通过 DownloadAgentMD 检查远程注册状态
func (a *AuthNamespace) checkRemoteAIDRegistration(ctx context.Context, aid string) map[string]any {
	content, err := a.DownloadAgentMD(ctx, aid)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "not found") {
			return map[string]any{
				"status":     "available",
				"registered": false,
				"available":  true,
				"source":     "agent.md",
			}
		}
		return map[string]any{
			"status":     "unknown",
			"registered": nil,
			"available":  nil,
			"source":     "agent.md",
			"error":      errStr,
		}
	}
	return map[string]any{
		"status":         "registered",
		"registered":     true,
		"available":      false,
		"source":         "agent.md",
		"agent_md_bytes": len([]byte(content)),
		"agent_md_aid":   extractAgentMDAID(content),
	}
}
