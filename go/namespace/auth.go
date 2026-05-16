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
}

// AuthNamespace 认证命名空间
// 封装 AID 创建、认证、证书管理等操作。
// 与 Python SDK namespaces/auth_namespace.py 对应。
type AuthNamespace struct {
	client         ClientInterface
	httpClientOnce sync.Once
	httpClient     *http.Client
}

var agentMDFingerprintRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

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

	resp, err := a.agentMDHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

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
	return string(body), nil
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
