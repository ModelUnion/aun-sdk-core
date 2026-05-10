package namespace

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// MetaClientInterface 定义 MetaNamespace 所需的客户端接口。
// 避免直接依赖 AUNClient 导致的循环引用。
type MetaClientInterface interface {
	Call(ctx context.Context, method string, params map[string]any) (any, error)
	GetGatewayURL() string
	GetConfigDiscoveryPort() int
	GetConfigVerifySSL() bool
	GetKeyStoreRootPath() string
	GetTrustRootStore() keystore.TrustRootStore
	ReloadTrustedRoots() int
}

// MetaNamespace Meta 命名空间
// 封装 ping/status/trust-roots 等元数据操作。
// 与 Python SDK namespaces/meta_namespace.py 对应。
type MetaNamespace struct {
	client         MetaClientInterface
	httpClientOnce sync.Once
	httpClient     *http.Client
}

// NewMetaNamespace 创建 Meta 命名空间
func NewMetaNamespace(client MetaClientInterface) *MetaNamespace {
	return &MetaNamespace{client: client}
}

// Ping 发送心跳（委托 client.Call）
func (m *MetaNamespace) Ping(ctx context.Context) (any, error) {
	return m.client.Call(ctx, "meta.ping", nil)
}

// Status 查询服务状态（委托 client.Call）
func (m *MetaNamespace) Status(ctx context.Context) (any, error) {
	return m.client.Call(ctx, "meta.status", nil)
}

// TrustRoots 通过 RPC 获取信任根列表（委托 client.Call）
func (m *MetaNamespace) TrustRoots(ctx context.Context) (any, error) {
	return m.client.Call(ctx, "meta.trust_roots", nil)
}

// ── URL 解析 ──────────────────────────────────────────────

// IssuerTrustRootURL 生成 issuer 信任根 JSON URL
// 规则：https://pki.{issuer}/trust-root.json
func IssuerTrustRootURL(issuer string) string {
	return fmt.Sprintf("https://pki.%s/trust-root.json", strings.TrimSpace(issuer))
}

// IssuerRootCertURL 生成 issuer 根证书 URL
// 规则：https://pki.{issuer}/root.crt
func IssuerRootCertURL(issuer string) string {
	return fmt.Sprintf("https://pki.%s/root.crt", strings.TrimSpace(issuer))
}

// GatewayTrustRootsURL 从 gateway WebSocket URL 推导 trust-roots.json 的 HTTP URL。
// wss:// → https://，ws:// → http://，路径固定为 /pki/trust-roots.json。
func GatewayTrustRootsURL(gatewayURL string) string {
	trimmed := strings.TrimSpace(gatewayURL)
	lower := strings.ToLower(trimmed)

	scheme := "https"
	hostPart := trimmed
	if strings.HasPrefix(lower, "wss://") {
		hostPart = trimmed[6:]
	} else if strings.HasPrefix(lower, "ws://") {
		scheme = "http"
		hostPart = trimmed[5:]
	} else if strings.HasPrefix(lower, "https://") {
		hostPart = trimmed[8:]
	} else if strings.HasPrefix(lower, "http://") {
		scheme = "http"
		hostPart = trimmed[7:]
	}

	// 取 host(:port) 部分，去掉路径
	if idx := strings.Index(hostPart, "/"); idx >= 0 {
		hostPart = hostPart[:idx]
	}

	return fmt.Sprintf("%s://%s/pki/trust-roots.json", scheme, hostPart)
}

// ── HTTP 客户端 ──────────────────────────────────────────

func (m *MetaNamespace) getHTTPClient() *http.Client {
	m.httpClientOnce.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
		}
		if !m.client.GetConfigVerifySSL() {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		m.httpClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		}
	})
	return m.httpClient
}

// ── 下载方法 ──────────────────────────────────────────────

// DownloadTrustRootsOptions 下载信任根列表的选项
type DownloadTrustRootsOptions struct {
	// 自定义 URL，为空则从 gatewayURL 推导
	URL string
}

// DownloadTrustRoots 通过 HTTP GET 下载信任根 JSON 列表。
func (m *MetaNamespace) DownloadTrustRoots(ctx context.Context, opts *DownloadTrustRootsOptions) (map[string]any, error) {
	targetURL := ""
	if opts != nil && opts.URL != "" {
		targetURL = opts.URL
	} else {
		gw := m.client.GetGatewayURL()
		if gw == "" {
			return nil, fmt.Errorf("meta.download_trust_roots: 需要 gateway_url 或指定 URL")
		}
		targetURL = GatewayTrustRootsURL(gw)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("meta.download_trust_roots: 创建请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.getHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("meta.download_trust_roots: HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("meta.download_trust_roots: 读取响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("meta.download_trust_roots: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var trustList map[string]any
	if err := json.Unmarshal(body, &trustList); err != nil {
		return nil, fmt.Errorf("meta.download_trust_roots: JSON 解析失败: %w", err)
	}

	return trustList, nil
}

// DownloadIssuerRootCertOptions 下载 Issuer 根证书的选项
type DownloadIssuerRootCertOptions struct {
	// 自定义 URL，为空则从 issuer 推导
	URL string
}

// DownloadIssuerRootCert 通过 HTTP GET 下载 Issuer 根证书（PEM 格式）。
func (m *MetaNamespace) DownloadIssuerRootCert(ctx context.Context, issuer string, opts *DownloadIssuerRootCertOptions) (string, error) {
	targetURL := ""
	if opts != nil && opts.URL != "" {
		targetURL = opts.URL
	} else {
		if strings.TrimSpace(issuer) == "" {
			return "", fmt.Errorf("meta.download_issuer_root_cert: 需要 issuer 参数")
		}
		targetURL = IssuerRootCertURL(issuer)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", fmt.Errorf("meta.download_issuer_root_cert: 创建请求失败: %w", err)
	}

	resp, err := m.getHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("meta.download_issuer_root_cert: HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("meta.download_issuer_root_cert: 读取响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("meta.download_issuer_root_cert: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// 校验 PEM 格式
	certPEM := string(body)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("meta.download_issuer_root_cert: 响应不是有效的 PEM 格式")
	}

	return certPEM, nil
}

// ── 校验方法 ──────────────────────────────────────────────

// VerifyTrustRootsOptions 校验信任根的选项
type VerifyTrustRootsOptions struct {
	// 期望的根证书指纹列表（SHA-256 hex），用于交叉验证
	ExpectedFingerprints []string
}

// VerifyTrustRoots 验证信任根列表的签名和证书有效性。
// trustList 为 trust-roots.json 的完整内容。
// 返回已验证的根证书摘要列表。
func (m *MetaNamespace) VerifyTrustRoots(trustList map[string]any, opts *VerifyTrustRootsOptions) ([]map[string]string, error) {
	// 提取根证书列表
	rootsRaw, ok := trustList["roots"]
	if !ok {
		return nil, fmt.Errorf("meta.verify_trust_roots: trust_list 缺少 'roots' 字段")
	}
	rootsList, ok := rootsRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("meta.verify_trust_roots: 'roots' 字段格式无效")
	}

	// 提取签名（可选）
	signatureHex, _ := trustList["signature"].(string)

	var verified []map[string]string

	for _, rootRaw := range rootsList {
		rootEntry, ok := rootRaw.(map[string]any)
		if !ok {
			continue
		}
		certPEM, _ := rootEntry["cert_pem"].(string)
		if certPEM == "" {
			continue
		}
		rootID, _ := rootEntry["id"].(string)

		// 解析 PEM → x509 证书
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, fmt.Errorf("meta.verify_trust_roots: 根证书 %s PEM 解析失败", rootID)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("meta.verify_trust_roots: 根证书 %s x509 解析失败: %w", rootID, err)
		}

		// 计算 SHA-256 指纹
		fingerprint := sha256Fingerprint(cert.Raw)

		// 自签名验证：根证书应该能用自己的公钥验证
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return nil, fmt.Errorf("meta.verify_trust_roots: 根证书 %s 自签名验证失败: %w", rootID, err)
		}

		// 指纹交叉验证（如果提供了期望列表）
		if opts != nil && len(opts.ExpectedFingerprints) > 0 {
			found := false
			for _, expected := range opts.ExpectedFingerprints {
				if strings.EqualFold(expected, fingerprint) {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("meta.verify_trust_roots: 根证书 %s 指纹 %s 不在期望列表中", rootID, fingerprint)
			}
		}

		verified = append(verified, map[string]string{
			"id":          rootID,
			"fingerprint": fingerprint,
			"cert_pem":    certPEM,
		})
	}

	// 如果有签名字段但目前仅做存在性检查（实际签名验证需要 signer 公钥）
	if signatureHex != "" {
		// 签名验证：需要 trust_list 中的 signer 信息
		signerPEM, _ := trustList["signer_cert_pem"].(string)
		signedData, _ := trustList["signed_data"].(string)
		if signerPEM != "" && signedData != "" {
			if err := verifyTrustRootsSignature(signerPEM, signedData, signatureHex); err != nil {
				return nil, fmt.Errorf("meta.verify_trust_roots: 签名验证失败: %w", err)
			}
		}
	}

	return verified, nil
}

// verifyTrustRootsSignature 验证信任根列表的 ECDSA 签名
func verifyTrustRootsSignature(signerCertPEM, signedData, signatureHex string) error {
	block, _ := pem.Decode([]byte(signerCertPEM))
	if block == nil {
		return fmt.Errorf("signer 证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("signer 证书 x509 解析失败: %w", err)
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("signer 证书公钥不是 ECDSA 类型")
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("签名 hex 解码失败: %w", err)
	}

	hash := sha256.Sum256([]byte(signedData))
	if !ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
		return fmt.Errorf("ECDSA 签名验证失败")
	}

	return nil
}

// sha256Fingerprint 计算 DER 编码证书的 SHA-256 指纹（冒号分隔的 hex）
func sha256Fingerprint(der []byte) string {
	hash := sha256.Sum256(der)
	parts := make([]string, len(hash))
	for i, b := range hash {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return "sha256:" + strings.Join(parts, "")
}

func numericVersion(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case json.Number:
		n, err := v.Float64()
		return n, err == nil
	default:
		return 0, false
	}
}

// ── 导入方法 ──────────────────────────────────────────────

// ImportTrustRootsOptions 导入信任根的选项
type ImportTrustRootsOptions struct {
	// 期望的根证书指纹列表
	ExpectedFingerprints []string
	// KeyStore 根路径（用于持久化）
	KeyStoreRootPath string
}

// ImportTrustRoots 验证并导入信任根列表。
// 执行验证 + 版本单调检查 + keystore 持久化。
func (m *MetaNamespace) ImportTrustRoots(trustList map[string]any, opts *ImportTrustRootsOptions) ([]map[string]string, error) {
	// 验证信任根
	verifyOpts := &VerifyTrustRootsOptions{}
	if opts != nil {
		verifyOpts.ExpectedFingerprints = opts.ExpectedFingerprints
	}
	verified, err := m.VerifyTrustRoots(trustList, verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("meta.import_trust_roots: 验证失败: %w", err)
	}

	// 版本单调检查
	newVersion, hasNewVersion := numericVersion(trustList["version"])
	if hasNewVersion && newVersion < 0 {
		return nil, fmt.Errorf("meta.import_trust_roots: 版本号无效: %v", newVersion)
	}
	store := m.client.GetTrustRootStore()
	if store == nil {
		return nil, fmt.Errorf("meta.import_trust_roots: keystore 不支持信任根持久化")
	}
	if hasNewVersion {
		currentPath := filepath.Join(store.TrustRootDir(), "trust-roots.json")
		if data, readErr := os.ReadFile(currentPath); readErr == nil {
			var current map[string]any
			if err := json.Unmarshal(data, &current); err == nil {
				if currentVersion, ok := numericVersion(current["version"]); ok && newVersion < currentVersion {
					return nil, fmt.Errorf("meta.import_trust_roots: 信任根版本回退被拒绝，当前 %.0f，新版本 %.0f", currentVersion, newVersion)
				}
			}
		}
	}

	if _, err := store.SaveTrustRoots(trustList, verified); err != nil {
		return nil, fmt.Errorf("meta.import_trust_roots: 持久化失败: %w", err)
	}
	m.client.ReloadTrustedRoots()

	return verified, nil
}

// ── 刷新方法 ──────────────────────────────────────────────

// RefreshTrustRootsOptions 刷新信任根的选项
type RefreshTrustRootsOptions struct {
	DownloadOpts *DownloadTrustRootsOptions
	ImportOpts   *ImportTrustRootsOptions
}

// RefreshTrustRoots 下载并导入信任根列表（download + import 组合）。
func (m *MetaNamespace) RefreshTrustRoots(ctx context.Context, opts *RefreshTrustRootsOptions) ([]map[string]string, error) {
	var dlOpts *DownloadTrustRootsOptions
	var imOpts *ImportTrustRootsOptions
	if opts != nil {
		dlOpts = opts.DownloadOpts
		imOpts = opts.ImportOpts
	}

	trustList, err := m.DownloadTrustRoots(ctx, dlOpts)
	if err != nil {
		return nil, fmt.Errorf("meta.refresh_trust_roots: 下载失败: %w", err)
	}

	verified, err := m.ImportTrustRoots(trustList, imOpts)
	if err != nil {
		return nil, fmt.Errorf("meta.refresh_trust_roots: 导入失败: %w", err)
	}

	return verified, nil
}

// ── 更新 Issuer 根证书 ──────────────────────────────────

// UpdateIssuerRootCertOptions 更新 Issuer 根证书的选项
type UpdateIssuerRootCertOptions struct {
	// 自定义下载 URL
	URL string
	// 期望的根证书指纹（SHA-256 hex），用于交叉验证
	ExpectedFingerprint string
}

// UpdateIssuerRootCert 下载并验证 Issuer 根证书。
// 返回 (certPEM, fingerprint, error)。
func (m *MetaNamespace) UpdateIssuerRootCert(ctx context.Context, issuer string, opts *UpdateIssuerRootCertOptions) (string, string, error) {
	dlOpts := &DownloadIssuerRootCertOptions{}
	if opts != nil && opts.URL != "" {
		dlOpts.URL = opts.URL
	}

	certPEM, err := m.DownloadIssuerRootCert(ctx, issuer, dlOpts)
	if err != nil {
		return "", "", fmt.Errorf("meta.update_issuer_root_cert: 下载失败: %w", err)
	}

	// 解析并验证证书
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", "", fmt.Errorf("meta.update_issuer_root_cert: PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("meta.update_issuer_root_cert: x509 解析失败: %w", err)
	}

	fingerprint := sha256Fingerprint(cert.Raw)

	// 指纹交叉验证
	if opts != nil && opts.ExpectedFingerprint != "" {
		if !strings.EqualFold(opts.ExpectedFingerprint, fingerprint) {
			return "", "", fmt.Errorf("meta.update_issuer_root_cert: 指纹不匹配，期望 %s，实际 %s",
				opts.ExpectedFingerprint, fingerprint)
		}
	}

	// 自签名验证
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return "", "", fmt.Errorf("meta.update_issuer_root_cert: 自签名验证失败: %w", err)
	}

	store := m.client.GetTrustRootStore()
	if store == nil {
		return "", "", fmt.Errorf("meta.update_issuer_root_cert: keystore 不支持信任根持久化")
	}
	if _, _, err := store.SaveIssuerRootCert(strings.TrimSpace(issuer), certPEM, fingerprint); err != nil {
		return "", "", fmt.Errorf("meta.update_issuer_root_cert: 持久化失败: %w", err)
	}
	m.client.ReloadTrustedRoots()

	return certPEM, fingerprint, nil
}

// ── 便利函数（URL 解析） ──────────────────────────────────

// ParseGatewayHost 从 gateway URL 提取 host(:port) 部分。
func ParseGatewayHost(gatewayURL string) string {
	u, err := url.Parse(strings.TrimSpace(gatewayURL))
	if err != nil {
		return ""
	}
	return u.Host
}
