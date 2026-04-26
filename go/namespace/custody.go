package namespace

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// CustodyClientInterface 定义 CustodyNamespace 所需的客户端接口。
type CustodyClientInterface interface {
	GetAID() string
	GetIdentity() map[string]any
	GetConfigDiscoveryPort() int
	GetConfigVerifySSL() bool
}

// CustodyNamespace 封装 AID 托管服务 HTTP API。
type CustodyNamespace struct {
	client         CustodyClientInterface
	mu             sync.RWMutex
	custodyURL     string
	httpClientOnce sync.Once
	httpClient     *http.Client
}

// NewCustodyNamespace 创建 AID 托管命名空间。
func NewCustodyNamespace(client CustodyClientInterface) *CustodyNamespace {
	return &CustodyNamespace{client: client}
}

// SetURL 手动设置 custody 服务地址。
func (c *CustodyNamespace) SetURL(rawURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.custodyURL = strings.TrimRight(strings.TrimSpace(rawURL), "/")
}

// ConfigureURL 是 SetURL 的语义化别名。
func (c *CustodyNamespace) ConfigureURL(rawURL string) {
	c.SetURL(rawURL)
}

// URL 返回当前已配置或已发现的 custody 服务地址。
func (c *CustodyNamespace) URL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.custodyURL
}

// DiscoverURL 通过 AID 域名 well-known 发现官方 custody 服务地址，并缓存到当前 namespace。
func (c *CustodyNamespace) DiscoverURL(ctx context.Context, aid string) (string, error) {
	return c.DiscoverURLWithTimeout(ctx, aid, 5*time.Second)
}

// DiscoverURLWithTimeout 通过 AID 域名 well-known 发现官方 custody 服务地址，并指定超时。
func (c *CustodyNamespace) DiscoverURLWithTimeout(ctx context.Context, aid string, timeout time.Duration) (string, error) {
	resolvedAID := strings.TrimSpace(aid)
	if resolvedAID == "" {
		resolvedAID = c.client.GetAID()
	}
	if resolvedAID == "" {
		return "", fmt.Errorf("custody.discover_url requires aid or authenticated client")
	}
	var lastErr error
	for _, wellKnownURL := range c.wellKnownURLs(resolvedAID) {
		payload, err := c.getJSON(ctx, wellKnownURL, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		custodyURL, err := extractCustodyURL(payload)
		if err != nil {
			lastErr = err
			continue
		}
		custodyURL, ok := normalizeCustodyURL(custodyURL)
		if !ok {
			lastErr = fmt.Errorf("custody well-known returned invalid custody url")
			continue
		}
		c.SetURL(custodyURL)
		return custodyURL, nil
	}
	return "", fmt.Errorf("custody discovery failed for %s: %w", resolvedAID, lastErr)
}

// SendCode 发送手机验证码。
//
// 不传 aid 时为绑定/上传场景，需要当前 AID 的 access_token；
// 传 aid 时为恢复/下载场景，不需要 AID 登录。
func (c *CustodyNamespace) SendCode(ctx context.Context, params map[string]any) (map[string]any, error) {
	phone := strings.TrimSpace(asString(params["phone"]))
	if phone == "" {
		return nil, fmt.Errorf("custody.send_code requires non-empty phone")
	}
	aid := strings.TrimSpace(asString(params["aid"]))
	body := map[string]any{"phone": phone}
	token := ""
	if aid != "" {
		body["aid"] = aid
	} else {
		var err error
		token, err = c.accessToken()
		if err != nil {
			return nil, err
		}
	}
	return c.post(ctx, "/custody/accounts/send-code", body, token, aid)
}

// BindPhone 绑定手机号，并上传 AID 证书和客户端加密后的私钥密文。
func (c *CustodyNamespace) BindPhone(ctx context.Context, params map[string]any) (map[string]any, error) {
	body := map[string]any{
		"phone": strings.TrimSpace(asString(params["phone"])),
		"code":  strings.TrimSpace(asString(params["code"])),
		"cert":  strings.TrimSpace(asString(params["cert"])),
		"key":   strings.TrimSpace(asString(params["key"])),
	}
	if body["phone"] == "" || body["code"] == "" || body["cert"] == "" || body["key"] == "" {
		return nil, fmt.Errorf("custody.bind_phone requires phone, code, cert and key")
	}
	if metadata, ok := params["metadata"].(map[string]any); ok && metadata != nil {
		body["metadata"] = metadata
	}
	token, err := c.accessToken()
	if err != nil {
		return nil, err
	}
	return c.post(ctx, "/custody/accounts/bind-phone", body, token, c.client.GetAID())
}

// RestorePhone 通过手机号、验证码和 AID 下载证书及加密私钥密文。
func (c *CustodyNamespace) RestorePhone(ctx context.Context, params map[string]any) (map[string]any, error) {
	body := map[string]any{
		"phone": strings.TrimSpace(asString(params["phone"])),
		"code":  strings.TrimSpace(asString(params["code"])),
		"aid":   strings.TrimSpace(asString(params["aid"])),
	}
	if body["phone"] == "" || body["code"] == "" || body["aid"] == "" {
		return nil, fmt.Errorf("custody.restore_phone requires phone, code and aid")
	}
	return c.post(ctx, "/custody/accounts/restore-phone", body, "", asString(body["aid"]))
}

// CreateDeviceCopy 由旧设备基于 AID token 发起一次性跨设备复制会话。
func (c *CustodyNamespace) CreateDeviceCopy(ctx context.Context, params map[string]any) (map[string]any, error) {
	aid := strings.TrimSpace(asString(params["aid"]))
	if aid == "" {
		aid = c.client.GetAID()
	}
	if aid == "" {
		return nil, fmt.Errorf("custody.create_device_copy requires aid or authenticated client")
	}
	token, err := c.accessToken()
	if err != nil {
		return nil, err
	}
	return c.post(ctx, "/custody/transfers", map[string]any{"aid": aid}, token, aid)
}

// UploadDeviceCopyMaterials 上传 OTP 加密后的私钥密文。OTP 不应传给 custody。
func (c *CustodyNamespace) UploadDeviceCopyMaterials(ctx context.Context, params map[string]any) (map[string]any, error) {
	transferCode := strings.TrimSpace(asString(params["transfer_code"]))
	if transferCode == "" {
		transferCode = strings.TrimSpace(asString(params["transferCode"]))
	}
	aid := strings.TrimSpace(asString(params["aid"]))
	if aid == "" {
		aid = c.client.GetAID()
	}
	body := map[string]any{
		"aid":  aid,
		"cert": strings.TrimSpace(asString(params["cert"])),
		"key":  strings.TrimSpace(asString(params["key"])),
	}
	if metadata, ok := params["metadata"].(map[string]any); ok && metadata != nil {
		body["metadata"] = metadata
	}
	if transferCode == "" || body["aid"] == "" || body["cert"] == "" || body["key"] == "" {
		return nil, fmt.Errorf("custody.upload_device_copy_materials requires transfer_code, aid, cert and key")
	}
	token, err := c.accessToken()
	if err != nil {
		return nil, err
	}
	return c.post(ctx, "/custody/transfers/"+url.PathEscape(transferCode)+"/materials", body, token, aid)
}

// ClaimDeviceCopy 由新设备凭 AID 和复制码领取 OTP 加密材料。不要传 OTP。
func (c *CustodyNamespace) ClaimDeviceCopy(ctx context.Context, params map[string]any) (map[string]any, error) {
	body := map[string]any{
		"aid":           strings.TrimSpace(asString(params["aid"])),
		"transfer_code": strings.TrimSpace(asString(params["transfer_code"])),
	}
	if body["transfer_code"] == "" {
		body["transfer_code"] = strings.TrimSpace(asString(params["transferCode"]))
	}
	if body["aid"] == "" || body["transfer_code"] == "" {
		return nil, fmt.Errorf("custody.claim_device_copy requires aid and transfer_code")
	}
	return c.post(ctx, "/custody/transfers/claim", body, "", asString(body["aid"]))
}

func (c *CustodyNamespace) resolveURL(ctx context.Context, aid string) (string, error) {
	if u := c.URL(); u != "" {
		if normalized, ok := normalizeCustodyURL(u); ok {
			if normalized != u {
				c.SetURL(normalized)
			}
			return normalized, nil
		}
	}
	return c.DiscoverURL(ctx, aid)
}

func (c *CustodyNamespace) accessToken() (string, error) {
	identity := c.client.GetIdentity()
	if identity != nil {
		if token := strings.TrimSpace(asString(identity["access_token"])); token != "" {
			return token, nil
		}
	}
	return "", fmt.Errorf("no access_token available: call auth.authenticate() first")
}

func (c *CustodyNamespace) post(ctx context.Context, path string, body map[string]any, token string, aid string) (map[string]any, error) {
	baseURL, err := c.resolveURL(ctx, aid)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClientForRequests().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	payload, err := decodeJSONMap(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("custody returned non-JSON response: HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("custody %s", custodyErrorMessage(resp.StatusCode, payload))
	}
	return payload, nil
}

func (c *CustodyNamespace) getJSON(ctx context.Context, rawURL string, timeout time.Duration) (map[string]any, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClientForRequests().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return decodeJSONMap(resp.Body)
}

func (c *CustodyNamespace) httpClientForRequests() *http.Client {
	c.httpClientOnce.Do(func() {
		transport := &http.Transport{}
		if !c.client.GetConfigVerifySSL() {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		c.httpClient = &http.Client{Timeout: 30 * time.Second, Transport: transport}
	})
	return c.httpClient
}

func (c *CustodyNamespace) wellKnownURLs(aid string) []string {
	portSuffix := ""
	if port := c.client.GetConfigDiscoveryPort(); port > 0 {
		portSuffix = fmt.Sprintf(":%d", port)
	}
	issuerDomain := issuerDomainFromAID(aid)
	aidURL := fmt.Sprintf("https://%s%s/.well-known/aun-custody", aid, portSuffix)
	fallbackURL := fmt.Sprintf("https://aid_custody.%s%s/.well-known/aun-custody", issuerDomain, portSuffix)
	urls := []string{aidURL, fallbackURL}
	if !c.client.GetConfigVerifySSL() {
		urls = []string{fallbackURL, aidURL}
	}
	deduped := make([]string, 0, len(urls))
	seen := map[string]bool{}
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			deduped = append(deduped, u)
		}
	}
	return deduped
}

func issuerDomainFromAID(aid string) string {
	parts := strings.SplitN(strings.TrimSpace(aid), ".", 2)
	if len(parts) > 1 {
		return parts[1]
	}
	return parts[0]
}

func normalizeCustodyURL(rawURL string) (string, bool) {
	value := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if value == "" {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if parsed.Host == "" {
		return "", false
	}
	return value, true
}

func extractCustodyURL(payload map[string]any) (string, error) {
	for _, key := range []string{"custody_url", "custodyUrl", "url"} {
		if value := strings.TrimSpace(asString(payload[key])); value != "" {
			return value, nil
		}
	}
	if custody, ok := payload["custody"].(map[string]any); ok {
		if value := strings.TrimSpace(asString(custody["url"])); value != "" {
			return value, nil
		}
	}
	for _, key := range []string{"custody_services", "custodyServices", "services"} {
		items, ok := payload[key].([]any)
		if !ok || len(items) == 0 {
			continue
		}
		candidates := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if candidate, ok := item.(map[string]any); ok {
				candidates = append(candidates, candidate)
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			return priorityOf(candidates[i]) < priorityOf(candidates[j])
		})
		for _, item := range candidates {
			if value := strings.TrimSpace(asString(item["url"])); value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("custody well-known missing custody url")
}

func priorityOf(item map[string]any) int {
	switch v := item["priority"].(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	default:
		return 999
	}
}

func decodeJSONMap(r io.Reader) (map[string]any, error) {
	var payload map[string]any
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, fmt.Errorf("empty JSON object")
	}
	return payload, nil
}

func custodyErrorMessage(status int, payload map[string]any) string {
	if errObj, ok := payload["error"].(map[string]any); ok {
		code := strings.TrimSpace(asString(errObj["code"]))
		message := strings.TrimSpace(asString(errObj["message"]))
		if message != "" {
			if code != "" {
				return fmt.Sprintf("%s: %s", code, message)
			}
			return message
		}
		if code != "" {
			return code
		}
	}
	return fmt.Sprintf("HTTP %d", status)
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}
