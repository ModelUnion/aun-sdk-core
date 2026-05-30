package aun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// AIDInfo 列出身份时的摘要信息
type AIDInfo struct {
	Aid             string
	CertNotAfter    interface{} // time.Time
	CertIssuer      string
	CertFingerprint string
}

// AIDStoreResolveOptions 控制 Resolve 行为。
type AIDStoreResolveOptions struct {
	ForceRefresh bool
	SkipAgentMD  bool
}

// AIDStoreResolveSource 说明 Resolve 的数据来源。
type AIDStoreResolveSource struct {
	CertFromCache  bool
	AgentMDFetched bool
}

// AIDStoreResolveResult 是 Resolve 的返回结果。
type AIDStoreResolveResult struct {
	AID     *AID
	AgentMD *AgentMDInfo
	Source  AIDStoreResolveSource
}

// AIDStoreDiagnoseResult 汇总本地身份与远端注册状态。
type AIDStoreDiagnoseResult struct {
	AID              string
	Status           string
	LocalValid       bool
	RemoteRegistered bool
	Suggestions      []string
	Local            map[string]any
	Remote           map[string]any
}

// AIDStoreRenewCertResult 描述续签结果。
type AIDStoreRenewCertResult struct {
	Renewed         bool
	NewCertNotAfter time.Time
	NewFingerprint  string
}

// AIDStoreRekeyResult 描述换钥结果。
type AIDStoreRekeyResult struct {
	Rekeyed         bool
	NewCertNotAfter time.Time
	NewFingerprint  string
}

// AIDStore 管理本地 AID 身份，提供离线加载和联网注册/解析能力。
// 与 Python SDK aid_store.py 的 AIDStore 对应。
type AIDStore struct {
	aunPath        string
	encryptionSeed string
	deviceID       string
	slotID         string
	// 内部组件（复用 AUNClient 的基础设施）
	client *AUNClient
}

// AIDStoreOptions 创建 AIDStore 的可选参数，与 Python/JS SDK 对齐。
type AIDStoreOptions struct {
	DeviceID      string // 设备 ID，空时自动生成
	SlotID        string // 密钥槽 ID，默认 "default"
	VerifySSL     *bool  // 是否校验 TLS 证书，nil 时默认 false
	DiscoveryPort int    // 自定义 discovery 端口，0 时使用默认值
	Debug         bool   // 开启调试日志
}

// NewAIDStore 创建 AIDStore 实例。
// aunPath 为 AUN 数据目录，encryptionSeed 为密钥加密种子。
// opts 为可选参数，与 Python/JS SDK AIDStore 构造参数对齐。
func NewAIDStore(aunPath, encryptionSeed string, opts ...AIDStoreOptions) *AIDStore {
	var o AIDStoreOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.SlotID == "" {
		o.SlotID = "default"
	}
	verifySSL := false
	if o.VerifySSL != nil {
		verifySSL = *o.VerifySSL
	}
	c := NewAUNClient(AUNClientOptions{
		AUNPath:       aunPath,
		SeedPassword:  encryptionSeed,
		VerifySSL:     &verifySSL,
		DiscoveryPort: o.DiscoveryPort,
		Debug:         o.Debug,
	})
	return &AIDStore{
		aunPath:        aunPath,
		encryptionSeed: encryptionSeed,
		deviceID:       o.DeviceID,
		slotID:         o.SlotID,
		client:         c,
	}
}

// Close 释放资源
func (s *AIDStore) Close() {
	_ = s.client.Close()
}

// SetGatewayURL 显式设置后续联网方法使用的 Gateway URL。
// 主要用于测试容器或调用方已完成 discovery 的场景；未设置时仍按 AID issuer 自动发现。
func (s *AIDStore) SetGatewayURL(gatewayURL string) {
	s.client.SetGatewayURL(strings.TrimSpace(gatewayURL))
}

// aidStoreErr 创建带字符串错误码的 AUNError，供 Load() 内部使用。
func aidStoreErr(code, msg string, cause ...error) *AUNError {
	e := &AUNError{Message: msg, Code: -1, StringCode: code}
	if len(cause) > 0 {
		e.Cause = cause[0]
	}
	return e
}

// Load 从本地 keystore 加载 AID 身份（离线操作）。
// 与 Python SDK aid_store.py load() 对应。
func (s *AIDStore) Load(aid string) (*AID, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, aidStoreErr(ErrCodeCertNotFound, "aid is empty")
	}

	// 加载证书
	certPEM, err := s.client.keyStore.LoadCert(target)
	if err != nil || certPEM == "" {
		return nil, aidStoreErr(ErrCodeCertNotFound, fmt.Sprintf("certificate not found for aid: %s", target))
	}

	certObj, err := parsePEMCertificate(certPEM)
	if err != nil {
		return nil, aidStoreErr(ErrCodeCertParseError, fmt.Sprintf("certificate parse failed for aid: %s", target))
	}

	// 检查证书时间有效性
	switch certTimeError(certObj) {
	case "expired":
		return nil, aidStoreErr(ErrCodeCertExpired, fmt.Sprintf("certificate expired for aid: %s", target))
	case "not_yet_valid":
		return nil, aidStoreErr(ErrCodeCertNotYetValid, fmt.Sprintf("certificate not yet valid for aid: %s", target))
	}

	// CN 匹配检查
	if cn := certObj.Subject.CommonName; cn != "" && cn != target {
		return nil, aidStoreErr(ErrCodeCertChainBroken, fmt.Sprintf("certificate CN mismatch: expected %s, got %s", target, cn))
	}

	// 加载密钥对
	keyPair, err := s.client.keyStore.LoadKeyPair(target)
	if err != nil {
		return nil, aidStoreErr(ErrCodePrivateKeyParseError, fmt.Sprintf("private key load failed for aid: %s", target), err)
	}

	// 无私钥：仅证书有效
	if keyPair == nil || authGetStr(keyPair, "private_key_pem") == "" {
		return newAID(target, s.aunPath, certPEM, certObj, nil, true, false, s.deviceID, s.slotID), nil
	}

	// 解析私钥
	privPEM := authGetStr(keyPair, "private_key_pem")
	privKey, parseErr := parseECPrivateKeyPEM(privPEM)
	if parseErr != nil {
		return nil, aidStoreErr(ErrCodePrivateKeyParseError, fmt.Sprintf("private key parse failed for aid: %s", target), parseErr)
	}

	// 公钥匹配校验
	certPubDER, err := x509.MarshalPKIXPublicKey(certObj.PublicKey)
	if err != nil {
		return nil, aidStoreErr(ErrCodeKeypairMismatch, fmt.Sprintf("failed to marshal cert public key for aid: %s", target))
	}
	privPubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, aidStoreErr(ErrCodeKeypairMismatch, fmt.Sprintf("failed to marshal private key public key for aid: %s", target))
	}
	if !authBytesEqual(certPubDER, privPubDER) {
		return nil, aidStoreErr(ErrCodeKeypairMismatch, fmt.Sprintf("private key does not match certificate for aid: %s", target))
	}

	// 声明公钥匹配检查（如果 keyPair 中有 public_key_der_b64）
	if declaredB64 := authGetStr(keyPair, "public_key_der_b64"); declaredB64 != "" {
		declaredDER, decErr := base64.StdEncoding.DecodeString(declaredB64)
		if decErr == nil && !authBytesEqual(declaredDER, certPubDER) {
			return nil, aidStoreErr(ErrCodeKeypairMismatch, fmt.Sprintf("keypair public key mismatch for aid: %s", target))
		}
	}

	// 自测签名
	probe := []byte("aun-aidstore-private-key-self-test")
	sig, signErr := aidSignBytes(privKey, probe)
	if signErr != nil {
		return nil, aidStoreErr(ErrCodeKeypairMismatch, fmt.Sprintf("keypair self-test failed for aid: %s", target), signErr)
	}
	if verifyErr := verifySignature(certObj.PublicKey, sig, probe); verifyErr != nil {
		return nil, fmt.Errorf("%s: keypair self-test failed for aid: %s: %w", ErrCodeKeypairMismatch, target, verifyErr)
	}

	return newAID(target, s.aunPath, certPEM, certObj, privKey, true, true, s.deviceID, s.slotID), nil
}

// List 列出本地所有具有有效私钥的身份摘要（离线操作）。
func (s *AIDStore) List() ([]*AIDInfo, error) {
	type lister interface {
		ListIdentities() ([]string, error)
	}
	ks, ok := s.client.keyStore.(lister)
	if !ok {
		return nil, nil
	}
	aids, err := ks.ListIdentities()
	if err != nil {
		return nil, fmt.Errorf("list identities failed: %w", err)
	}
	var result []*AIDInfo
	for _, aid := range aids {
		loaded, loadErr := s.Load(aid)
		if loadErr != nil || !loaded.IsPrivateKeyValid() {
			continue
		}
		result = append(result, &AIDInfo{
			Aid:             loaded.Aid,
			CertNotAfter:    loaded.CertNotAfter,
			CertIssuer:      loaded.CertIssuer,
			CertFingerprint: loaded.CertFingerprint,
		})
	}
	return result, nil
}

// ChangeSeed 迁移所有本地私钥的加密种子（离线操作）。
// 返回迁移的私钥数量。
func (s *AIDStore) ChangeSeed(oldSeed, newSeed string) (int, error) {
	if strings.TrimSpace(oldSeed) == "" {
		return 0, fmt.Errorf("%s: change_seed requires a non-empty old_seed", ErrCodePrivateKeyParseError)
	}
	if strings.TrimSpace(newSeed) == "" {
		return 0, fmt.Errorf("%s: change_seed requires a non-empty new_seed", ErrCodePrivateKeyParseError)
	}
	if oldSeed == newSeed {
		return 0, fmt.Errorf("%s: new_seed must differ from old_seed", ErrCodePrivateKeyParseError)
	}
	type seedChanger interface {
		ChangeSeed(oldSeed, newSeed string) (keystore.SeedChangeResult, error)
	}
	changer, ok := s.client.keyStore.(seedChanger)
	if !ok {
		return 0, fmt.Errorf("keystore does not support seed migration")
	}
	result, err := changer.ChangeSeed(oldSeed, newSeed)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", ErrCodePrivateKeyParseError, err)
	}
	s.encryptionSeed = newSeed
	return result.PrivateKeysMigrated, nil
}

// Register 在服务端注册新 AID（联网操作）。
func (s *AIDStore) Register(ctx context.Context, aid string) error {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return fmt.Errorf("%s: %w", ErrCodeInvalidAIDFormat, err)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrCodeNetworkError, err)
	}
	_, err = s.client.auth.RegisterAID(ctx, gatewayURL, target)
	if err != nil {
		return err
	}
	return nil
}

// Exists 检查 AID 是否已在服务端注册（联网操作）。
func (s *AIDStore) Exists(ctx context.Context, aid string) (bool, error) {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return false, fmt.Errorf("%s: %w", ErrCodeInvalidAIDFormat, err)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return false, fmt.Errorf("%s: %w", ErrCodeNetworkError, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, buildCertURL(gatewayURL, target, ""), nil)
	if err != nil {
		return false, fmt.Errorf("%s: %w", ErrCodeNetworkError, err)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return false, fmt.Errorf("%s: %w", ErrCodeNetworkError, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("%s: unexpected PKI HEAD status %d", ErrCodeNetworkError, resp.StatusCode)
	}
}

// Resolve 一站式解析对端 AID：本地缓存/PKI 证书 + 可选 agent.md。
func (s *AIDStore) Resolve(ctx context.Context, aid string, opts ...AIDStoreResolveOptions) (*AIDStoreResolveResult, error) {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeInvalidAIDFormat, err)
	}
	var opt AIDStoreResolveOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	peer, err := s.Load(target)
	certFromCache := err == nil && !opt.ForceRefresh
	if !certFromCache {
		gatewayURL, gwErr := s.resolveGateway(ctx, target)
		if gwErr != nil {
			return nil, fmt.Errorf("%s: %w", ErrCodeNetworkError, gwErr)
		}
		s.client.SetGatewayURL(gatewayURL)
		certBytes, fetchErr := s.client.AuthFetchPeerCert(ctx, target, "")
		if fetchErr != nil {
			// 404（证书不存在）映射为 CERT_NOT_FOUND，其余网络错误映射为 NETWORK_ERROR
			// 对齐 Python aid_store.py:267-268
			if errors.Is(fetchErr, errCertNotFound) {
				return nil, fmt.Errorf("%s: certificate not found for aid: %s", ErrCodeCertNotFound, target)
			}
			return nil, fmt.Errorf("%s: %w", ErrCodeNetworkError, fetchErr)
		}
		if strings.TrimSpace(string(certBytes)) == "" {
			return nil, fmt.Errorf("%s: certificate not found for aid: %s", ErrCodeCertNotFound, target)
		}
		if saveErr := s.client.keyStore.SaveCert(target, string(certBytes)); saveErr != nil {
			return nil, fmt.Errorf("%s: save peer certificate failed: %w", ErrCodeServerError, saveErr)
		}
		peer, err = s.Load(target)
		if err != nil {
			return nil, err
		}
	}

	result := &AIDStoreResolveResult{
		AID: peer,
		Source: AIDStoreResolveSource{
			CertFromCache: certFromCache,
		},
	}
	if opt.SkipAgentMD {
		return result, nil
	}
	agentMD, err := s.FetchAgentMD(ctx, target)
	if err != nil {
		return nil, err
	}
	result.AgentMD = agentMD
	result.Source.AgentMDFetched = true
	return result, nil
}

// FetchAgentMD 下载 agent.md 并自动验签。
func (s *AIDStore) FetchAgentMD(ctx context.Context, aid string) (*AgentMDInfo, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, fmt.Errorf("%s: fetch agent.md requires aid", ErrCodeInvalidAIDFormat)
	}
	return s.client.fetchAgentMD(ctx, target)
}

// FetchAgentMd 是 FetchAgentMD 的跨语言命名别名。
func (s *AIDStore) FetchAgentMd(ctx context.Context, aid string) (*AgentMDInfo, error) {
	return s.FetchAgentMD(ctx, aid)
}

// HeadAgentMD 通过 HEAD 获取 agent.md 元数据。
func (s *AIDStore) HeadAgentMD(ctx context.Context, aid string) (map[string]any, error) {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, fmt.Errorf("%s: head agent.md requires aid", ErrCodeInvalidAIDFormat)
	}
	return s.client.authNamespace.HeadAgentMD(ctx, target)
}

// HeadAgentMd 是 HeadAgentMD 的跨语言命名别名。
func (s *AIDStore) HeadAgentMd(ctx context.Context, aid string) (map[string]any, error) {
	return s.HeadAgentMD(ctx, aid)
}

// CheckAgentMD 比对本地缓存与远端 agent.md ETag。
func (s *AIDStore) CheckAgentMD(ctx context.Context, aid string, maxUnsyncedDays ...float64) (*AgentMDCheckResult, error) {
	return s.client.checkAgentMD(ctx, aid, maxUnsyncedDays...)
}

// CheckAgentMd 是 CheckAgentMD 的跨语言命名别名。
func (s *AIDStore) CheckAgentMd(ctx context.Context, aid string, maxUnsyncedDays ...float64) (*AgentMDCheckResult, error) {
	return s.CheckAgentMD(ctx, aid, maxUnsyncedDays...)
}

// Diagnose 汇总本地身份有效性与远端注册状态。
func (s *AIDStore) Diagnose(ctx context.Context, aid string) (*AIDStoreDiagnoseResult, error) {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeInvalidAIDFormat, err)
	}
	loaded, loadErr := s.Load(target)
	exists, existsErr := s.Exists(ctx, target)

	localCert := loaded != nil && loaded.IsCertValid()
	localPrivateKey := loaded != nil && loaded.IsPrivateKeyValid()
	localValid := localCert && localPrivateKey
	remoteChecked := existsErr == nil
	suggestions := make([]string, 0, 3)
	if !localValid {
		suggestions = append(suggestions, "load or register a local identity with a valid private key")
	}
	if remoteChecked && !exists {
		suggestions = append(suggestions, "register the AID before using it on the network")
	}
	if existsErr != nil {
		suggestions = append(suggestions, fmt.Sprintf("remote registration check failed: %v", existsErr))
	}

	status := "unknown"
	if localPrivateKey && exists {
		status = "ready"
	} else if !localPrivateKey && remoteChecked && !exists {
		status = "available"
	} else if exists {
		status = "registered_remote"
	}

	local := map[string]any{
		"cert":        localCert,
		"private_key": localPrivateKey,
	}
	if loadErr != nil {
		local["error"] = loadErr.Error()
	}
	remote := map[string]any{
		"checked": remoteChecked,
		"exists":  nil,
	}
	if remoteChecked {
		remote["exists"] = exists
	}
	if existsErr != nil {
		remote["error"] = existsErr.Error()
	}

	return &AIDStoreDiagnoseResult{
		AID:              target,
		Status:           status,
		LocalValid:       localValid,
		RemoteRegistered: remoteChecked && exists,
		Suggestions:      suggestions,
		Local:            local,
		Remote:           remote,
	}, nil
}

// RenewCert 续签本地 AID 证书并写回 keystore。
func (s *AIDStore) RenewCert(ctx context.Context, aid string) (*AIDStoreRenewCertResult, error) {
	target := strings.TrimSpace(aid)
	loaded, err := s.Load(target)
	if err != nil || loaded == nil || !loaded.IsPrivateKeyValid() {
		return nil, fmt.Errorf("%s: private key required for aid: %s", ErrCodePrivateKeyRequired, target)
	}
	identity := s.client.AuthLoadIdentityOrNil(target)
	privateKeyPEM := strings.TrimSpace(authGetStr(identity, "private_key_pem"))
	certPEM := strings.TrimSpace(authGetStr(identity, "cert"))
	if privateKeyPEM == "" || certPEM == "" {
		return nil, fmt.Errorf("%s: private key required for aid: %s", ErrCodePrivateKeyRequired, target)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeNetworkError, err)
	}
	clientNonce := s.client.auth.crypto.NewClientNonce()
	phase1, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.aid_login1", map[string]any{
		"aid":          target,
		"cert":         certPEM,
		"client_nonce": clientNonce,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeCertRenewalFailed, err)
	}
	if err := s.client.auth.verifyPhase1Response(ctx, gatewayURL, phase1, clientNonce); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeCertRenewalFailed, err)
	}
	nonce := authGetStr(phase1, "nonce")
	signature, clientTime, err := s.client.auth.crypto.SignLoginNonce(privateKeyPEM, nonce, "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeCertRenewalFailed, err)
	}
	response, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.renew_cert", map[string]any{
		"aid":         target,
		"request_id":  phase1["request_id"],
		"nonce":       nonce,
		"client_time": clientTime,
		"signature":   signature,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeCertRenewalFailed, err)
	}
	newCert := strings.TrimSpace(authGetStr(response, "cert"))
	if newCert == "" {
		newCert = strings.TrimSpace(authGetStr(response, "cert_pem"))
	}
	if newCert == "" {
		return nil, fmt.Errorf("%s: server response missing certificate", ErrCodeCertRenewalFailed)
	}
	if err := s.client.keyStore.SaveCert(target, newCert); err != nil {
		return nil, fmt.Errorf("%s: save renewed certificate failed: %w", ErrCodeCertRenewalFailed, err)
	}
	refreshed, err := s.Load(target)
	if err != nil {
		return nil, fmt.Errorf("%s: renewed certificate reload failed: %w", ErrCodeCertRenewalFailed, err)
	}
	return &AIDStoreRenewCertResult{
		Renewed:         true,
		NewCertNotAfter: refreshed.CertNotAfter,
		NewFingerprint:  refreshed.CertFingerprint,
	}, nil
}

// Rekey 生成新密钥对并请求服务端换发证书，然后写回 keystore。
func (s *AIDStore) Rekey(ctx context.Context, aid string) (*AIDStoreRekeyResult, error) {
	target := strings.TrimSpace(aid)
	loaded, err := s.Load(target)
	if err != nil || loaded == nil || !loaded.IsPrivateKeyValid() {
		return nil, fmt.Errorf("%s: private key required for aid: %s", ErrCodePrivateKeyRequired, target)
	}
	identity := s.client.AuthLoadIdentityOrNil(target)
	certPEM := strings.TrimSpace(authGetStr(identity, "cert"))
	if certPEM == "" {
		return nil, fmt.Errorf("%s: private key required for aid: %s", ErrCodePrivateKeyRequired, target)
	}
	newIdentity, err := s.client.auth.crypto.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeRekeyFailed, err)
	}
	newPublicKey := strings.TrimSpace(authGetStr(newIdentity, "public_key_der_b64"))
	if newPublicKey == "" {
		return nil, fmt.Errorf("%s: generated identity missing public key", ErrCodeRekeyFailed)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeNetworkError, err)
	}
	clientNonce := s.client.auth.crypto.NewClientNonce()
	phase1, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.aid_login1", map[string]any{
		"aid":          target,
		"cert":         certPEM,
		"client_nonce": clientNonce,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeRekeyFailed, err)
	}
	if err := s.client.auth.verifyPhase1Response(ctx, gatewayURL, phase1, clientNonce); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeRekeyFailed, err)
	}
	nonce := authGetStr(phase1, "nonce")
	signature, err := loaded.Sign([]byte(nonce + newPublicKey))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeRekeyFailed, err)
	}
	response, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.rekey", map[string]any{
		"aid":            target,
		"request_id":     phase1["request_id"],
		"nonce":          nonce,
		"new_public_key": newPublicKey,
		"signature":      signature,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrCodeRekeyFailed, err)
	}
	newCert := strings.TrimSpace(authGetStr(response, "cert"))
	if newCert == "" {
		newCert = strings.TrimSpace(authGetStr(response, "cert_pem"))
	}
	if newCert == "" {
		return nil, fmt.Errorf("%s: server response missing certificate", ErrCodeRekeyFailed)
	}
	newIdentity["aid"] = target
	newIdentity["cert"] = newCert
	if err := s.client.keyStore.SaveIdentity(target, newIdentity); err != nil {
		return nil, fmt.Errorf("%s: save rekeyed identity failed: %w", ErrCodeRekeyFailed, err)
	}
	refreshed, err := s.Load(target)
	if err != nil {
		return nil, fmt.Errorf("%s: rekeyed identity reload failed: %w", ErrCodeRekeyFailed, err)
	}
	return &AIDStoreRekeyResult{
		Rekeyed:         true,
		NewCertNotAfter: refreshed.CertNotAfter,
		NewFingerprint:  refreshed.CertFingerprint,
	}, nil
}

func (s *AIDStore) httpClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if s.client.configModel != nil && !s.client.configModel.VerifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// resolveGateway 解析 AID 对应的 Gateway URL
func (s *AIDStore) resolveGateway(ctx context.Context, aid string) (string, error) {
	if explicit := strings.TrimSpace(s.client.GetGatewayURL()); explicit != "" {
		return explicit, nil
	}
	// 先查缓存
	if cached := s.client.auth.LoadCachedGatewayURL(aid); cached != "" {
		return cached, nil
	}
	// 通过 well-known 发现
	parts := strings.SplitN(aid, ".", 2)
	issuer := aid
	if len(parts) > 1 {
		issuer = parts[1]
	}
	wellKnownURL := fmt.Sprintf("https://gateway.%s/.well-known/aun-gateway", issuer)
	discovered, err := s.client.discovery.Discover(ctx, wellKnownURL, 0)
	if err != nil {
		return "", err
	}
	s.client.auth.PersistGatewayURL(aid, discovered)
	return discovered, nil
}
