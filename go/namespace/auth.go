package namespace

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	DiscoverGateway(ctx context.Context, wellKnownURL string, timeout time.Duration) (string, error)
	SetIdentity(identity map[string]any)
}

// AuthNamespace 认证命名空间
// 封装 AID 创建、认证、证书管理等操作。
// 与 Python SDK namespaces/auth_namespace.py 对应。
type AuthNamespace struct {
	client         ClientInterface
	httpClientOnce sync.Once
	httpClient     *http.Client
}

// NewAuthNamespace 创建认证命名空间
func NewAuthNamespace(client ClientInterface) *AuthNamespace {
	return &AuthNamespace{client: client}
}

// resolveGateway 解析 gateway URL。优先使用已预置的 gatewayURL，否则基于 AID 自动发现。
//
// 发现流程：
//  1. 若 gatewayURL 已预置，直接返回
//  2. 开发环境：先 gateway.{issuer}，再 fallback {aid}（泛域名在开发环境可能不可用）
//  3. 生产环境：先 {aid}（泛域名 nameservice），再 fallback gateway.{issuer}
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
		return gwURL, nil
	}
	log.Printf("gateway 发现失败 (%s): %v", primaryURL, err)

	return a.client.DiscoverGateway(ctx, fallbackURL, 5*time.Second)
}

// CreateAID 创建新的 AID 身份
func (a *AuthNamespace) CreateAID(ctx context.Context, params map[string]any) (map[string]any, error) {
	aid, _ := params["aid"].(string)
	if aid == "" {
		return nil, fmt.Errorf("auth.create_aid 需要 'aid' 参数")
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
func (a *AuthNamespace) Authenticate(ctx context.Context, params map[string]any) (map[string]any, error) {
	request := make(map[string]any)
	if params != nil {
		for k, v := range params {
			request[k] = v
		}
	}
	aid, _ := request["aid"].(string)

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
func (a *AuthNamespace) UploadAgentMD(ctx context.Context, content string) (map[string]any, error) {
	aid := strings.TrimSpace(a.client.GetAID())
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
func (a *AuthNamespace) DownloadAgentMD(ctx context.Context, aid string) (string, error) {
	targetAID := strings.TrimSpace(aid)
	if targetAID == "" {
		return "", fmt.Errorf("download_agent_md requires non-empty aid")
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
