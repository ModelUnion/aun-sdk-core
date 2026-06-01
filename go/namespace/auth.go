package namespace

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ClientInterface 定义 AuthNamespace 所需的客户端接口
// 避免直接依赖 AUNClient 导致的循环引用
type ClientInterface interface {
	GetGatewayURL() string
	CacheDiscoveredGatewayURL(url string)
	GetAID() string
	SetAID(aid string)
	GetConfigDiscoveryPort() int
	GetConfigVerifySSL() bool
	Call(ctx context.Context, method string, params map[string]any) (any, error)

	// 认证流程所需方法
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
	AuthLoadCert(aid string) (string, error)
}

// AuthNamespace 认证命名空间
// 封装 AID 创建、认证、证书管理等操作。
// 与 Python SDK namespaces/auth_namespace.py 对应。
type AuthNamespace struct {
	client ClientInterface
}

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

// NewAuthNamespace 创建认证命名空间
func NewAuthNamespace(client ClientInterface) *AuthNamespace {
	return &AuthNamespace{client: client}
}

// CreateAIDWithName 是 RegisterAIDWithName 的兼容别名。
func (a *AuthNamespace) CreateAIDWithName(ctx context.Context, aid string) (map[string]any, error) {
	return a.RegisterAIDWithName(ctx, aid)
}

// CreateAID 是 RegisterAID 的兼容别名。
func (a *AuthNamespace) CreateAID(ctx context.Context, params map[string]any) (map[string]any, error) {
	return a.RegisterAID(ctx, params)
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
		a.client.CacheDiscoveredGatewayURL(cached)
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

// RegisterAIDWithName 类型安全的便捷方法，通过 AID 名称注册身份。
// 内部构造 map 并调用 RegisterAID。
func (a *AuthNamespace) RegisterAIDWithName(ctx context.Context, aid string) (out map[string]any, err error) {
	tStart := time.Now()
	pkgLogAuth().Debug("RegisterAIDWithName enter: aid=%s", aid)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("RegisterAIDWithName exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("RegisterAIDWithName exit: aid=%s elapsed=%dms", aid, time.Since(tStart).Milliseconds())
		}
	}()
	return a.RegisterAID(ctx, map[string]any{"aid": aid})
}

// RegisterAID 已从 AUNClient/AuthNamespace 移除；新注册流程必须通过 AIDStore.Register。
func (a *AuthNamespace) RegisterAID(ctx context.Context, params map[string]any) (out map[string]any, err error) {
	tStart := time.Now()
	aid, _ := params["aid"].(string)
	pkgLogAuth().Debug("RegisterAID enter: aid=%s", aid)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("RegisterAID exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("RegisterAID exit: aid=%s elapsed=%dms", aid, time.Since(tStart).Milliseconds())
		}
	}()
	if aid == "" {
		err = fmt.Errorf("auth.register_aid 需要 'aid' 参数")
		return nil, err
	}
	return nil, fmt.Errorf("auth.register_aid is not available on AUNClient; use AIDStore.Register")
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
	a.client.CacheDiscoveredGatewayURL(gatewayURL)

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

// LoadIdentity 只读加载本地已注册身份（密钥对 + 证书 + 实例状态）。无副作用，不触发网络请求。
func (a *AuthNamespace) LoadIdentity(aid string) (map[string]any, error) {
	targetAID := strings.TrimSpace(aid)
	if targetAID == "" {
		targetAID = a.client.GetAID()
	}
	identity := a.client.AuthLoadIdentityOrNil(targetAID)
	if identity == nil {
		return nil, fmt.Errorf("identity not found for aid: %s", targetAID)
	}
	return identity, nil
}

// LoadIdentityOrNil 只读加载本地已注册身份，不存在时返回 nil。
func (a *AuthNamespace) LoadIdentityOrNil(aid string) map[string]any {
	targetAID := strings.TrimSpace(aid)
	if targetAID == "" {
		targetAID = a.client.GetAID()
	}
	return a.client.AuthLoadIdentityOrNil(targetAID)
}

// FetchPeerCert 获取对端 AID 的证书 PEM（本地缓存优先，未命中走 PKI HTTP + 链验证）。
func (a *AuthNamespace) FetchPeerCert(ctx context.Context, aid string, certFingerprint string) (string, error) {
	targetAID := strings.TrimSpace(aid)
	if targetAID == "" {
		return "", fmt.Errorf("auth.FetchPeerCert requires non-empty aid")
	}
	certBytes, err := a.client.AuthFetchPeerCert(ctx, targetAID, strings.TrimSpace(certFingerprint))
	if err != nil {
		return "", err
	}
	return string(certBytes), nil
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

	certPEM, certErr := a.client.AuthLoadCert(aid)

	privateKeyPresent := false
	publicKeyPresent := false
	if identity != nil {
		if pkPem, _ := identity["private_key_pem"].(string); strings.TrimSpace(pkPem) != "" {
			privateKeyPresent = true
		}
		if pubDer, _ := identity["public_key_der_b64"].(string); strings.TrimSpace(pubDer) != "" {
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

// checkRemoteAIDRegistration 通过 PKI 证书检查远程注册状态。
func (a *AuthNamespace) checkRemoteAIDRegistration(ctx context.Context, aid string) map[string]any {
	cert, err := a.client.AuthFetchPeerCert(ctx, aid, "")
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "not found") {
			return map[string]any{
				"status":     "available",
				"registered": false,
				"available":  true,
				"source":     "pki_cert",
			}
		}
		return map[string]any{
			"status":     "unknown",
			"registered": nil,
			"available":  nil,
			"source":     "pki_cert",
			"error":      errStr,
		}
	}
	return map[string]any{
		"status":     "registered",
		"registered": true,
		"available":  false,
		"source":     "pki_cert",
		"cert_bytes": len(cert),
	}
}
