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
	Timeout      time.Duration // 默认 10s
}

// LoadResult Load 方法的返回结构。
type LoadResult struct{ AID *AID }

// ListResult List 方法的返回结构。
type ListResult struct{ Identities []*AIDInfo }

// RegisterResult Register 方法的返回结构。
type RegisterResult struct{ Registered bool }

// ExistsResult Exists 方法的返回结构。
type ExistsResult struct{ Exists bool }

// HeadAgentMdResult HeadAgentMD 方法的返回结构。
type HeadAgentMdResult struct {
	AID           string
	Found         bool
	Etag          string
	LastModified  string
	ContentLength int
}

// CheckAgentMdResult CheckAgentMD 方法的返回结构。
type CheckAgentMdResult struct {
	AID         string
	LocalFound  bool
	RemoteFound bool
	LocalEtag   string
	RemoteEtag  string
	NeedsUpdate bool
	TtlDays     int
}

// ChangeSeedResult ChangeSeed 方法的返回结构。
type ChangeSeedResult struct {
	Changed bool
	Count   int
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
	verifySSL      bool
	rootCaPath     string
	debug          bool
	// 内部组件（复用 AUNClient 的基础设施）
	client *AUNClient
}

// AIDStoreOptions 创建 AIDStore 的可选参数，与 Python/JS SDK 对齐。
type AIDStoreOptions struct {
	DeviceID   string // 设备 ID，空时自动生成
	SlotID     string // 密钥槽 ID，默认 "default"
	VerifySSL  *bool  // 是否校验 TLS 证书，nil 时默认 false
	RootCaPath string // 自定义根证书路径，私有部署使用
	Debug      bool   // 开启调试日志
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
	c := newClientForStore(aunPath, encryptionSeed, verifySSL, o.RootCaPath, o.Debug)
	return &AIDStore{
		aunPath:        aunPath,
		encryptionSeed: encryptionSeed,
		deviceID:       o.DeviceID,
		slotID:         o.SlotID,
		verifySSL:      verifySSL,
		rootCaPath:     o.RootCaPath,
		debug:          o.Debug,
		client:         c,
	}
}

// Close 释放资源
func (s *AIDStore) Close() {
	_ = s.client.Close()
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
func (s *AIDStore) Load(aid string) Result[LoadResult] {
	target := strings.TrimSpace(aid)
	if target == "" {
		return ResultErr[LoadResult](ErrCodeCertNotFound, "aid is empty")
	}

	// 加载证书
	certPEM, err := s.client.keyStore.LoadCert(target)
	if err != nil || certPEM == "" {
		return ResultErr[LoadResult](ErrCodeCertNotFound, fmt.Sprintf("certificate not found for aid: %s", target))
	}

	certObj, err := parsePEMCertificate(certPEM)
	if err != nil {
		return ResultErr[LoadResult](ErrCodeCertParseError, fmt.Sprintf("certificate parse failed for aid: %s", target))
	}

	// 检查证书时间有效性
	switch certTimeError(certObj) {
	case "expired":
		return ResultErr[LoadResult](ErrCodeCertExpired, fmt.Sprintf("certificate expired for aid: %s", target))
	case "not_yet_valid":
		return ResultErr[LoadResult](ErrCodeCertNotYetValid, fmt.Sprintf("certificate not yet valid for aid: %s", target))
	}

	// CN 匹配检查
	if cn := certObj.Subject.CommonName; cn != "" && cn != target {
		return ResultErr[LoadResult](ErrCodeCertChainBroken, fmt.Sprintf("certificate CN mismatch: expected %s, got %s", target, cn))
	}

	// 加载密钥对
	keyPair, err := s.client.keyStore.LoadKeyPair(target)
	if err != nil {
		return ResultErr[LoadResult](ErrCodePrivateKeyParseError, fmt.Sprintf("private key load failed for aid: %s", target), err)
	}

	// 无私钥：仅证书有效
	if keyPair == nil || authGetStr(keyPair, "private_key_pem") == "" {
		return ResultOk(LoadResult{AID: newAID(target, s.aunPath, certPEM, certObj, nil, true, false, s.deviceID, s.slotID, s.verifySSL, s.rootCaPath, s.debug)})
	}

	// 解析私钥
	privPEM := authGetStr(keyPair, "private_key_pem")
	privKey, parseErr := parseECPrivateKeyPEM(privPEM)
	if parseErr != nil {
		return ResultErr[LoadResult](ErrCodePrivateKeyParseError, fmt.Sprintf("private key parse failed for aid: %s", target), parseErr)
	}

	// 公钥匹配校验
	certPubDER, err := x509.MarshalPKIXPublicKey(certObj.PublicKey)
	if err != nil {
		return ResultErr[LoadResult](ErrCodeKeypairMismatch, fmt.Sprintf("failed to marshal cert public key for aid: %s", target))
	}
	privPubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return ResultErr[LoadResult](ErrCodeKeypairMismatch, fmt.Sprintf("failed to marshal private key public key for aid: %s", target))
	}
	if !authBytesEqual(certPubDER, privPubDER) {
		return ResultErr[LoadResult](ErrCodeKeypairMismatch, fmt.Sprintf("private key does not match certificate for aid: %s", target))
	}

	// 声明公钥匹配检查（如果 keyPair 中有 public_key_der_b64）
	if declaredB64 := authGetStr(keyPair, "public_key_der_b64"); declaredB64 != "" {
		declaredDER, decErr := base64.StdEncoding.DecodeString(declaredB64)
		if decErr == nil && !authBytesEqual(declaredDER, certPubDER) {
			return ResultErr[LoadResult](ErrCodeKeypairMismatch, fmt.Sprintf("keypair public key mismatch for aid: %s", target))
		}
	}

	// 自测签名
	probe := []byte("aun-aidstore-private-key-self-test")
	sig, signErr := aidSignBytes(privKey, probe)
	if signErr != nil {
		return ResultErr[LoadResult](ErrCodeKeypairMismatch, fmt.Sprintf("keypair self-test failed for aid: %s", target), signErr)
	}
	if verifyErr := verifySignature(certObj.PublicKey, sig, probe); verifyErr != nil {
		return ResultErr[LoadResult](ErrCodeKeypairMismatch, fmt.Sprintf("keypair self-test failed for aid: %s: %v", target, verifyErr))
	}

	return ResultOk(LoadResult{AID: newAID(target, s.aunPath, certPEM, certObj, privKey, true, true, s.deviceID, s.slotID, s.verifySSL, s.rootCaPath, s.debug)})
}

// List 列出本地所有具有有效私钥的身份摘要（离线操作）。
func (s *AIDStore) List() Result[ListResult] {
	type lister interface {
		ListIdentities() ([]string, error)
	}
	ks, ok := s.client.keyStore.(lister)
	if !ok {
		return ResultOk(ListResult{})
	}
	aids, err := ks.ListIdentities()
	if err != nil {
		return ResultErr[ListResult]("LIST_FAILED", fmt.Sprintf("list identities failed: %v", err), err)
	}
	var identities []*AIDInfo
	for _, aid := range aids {
		r := s.Load(aid)
		if !r.Ok || !r.Data.AID.IsPrivateKeyValid() {
			continue
		}
		loaded := r.Data.AID
		identities = append(identities, &AIDInfo{
			Aid:             loaded.Aid,
			CertNotAfter:    loaded.CertNotAfter,
			CertIssuer:      loaded.CertIssuer,
			CertFingerprint: loaded.CertFingerprint,
		})
	}
	return ResultOk(ListResult{Identities: identities})
}

// ChangeSeed 迁移所有本地私钥的加密种子（离线操作）。
func (s *AIDStore) ChangeSeed(oldSeed, newSeed string) Result[ChangeSeedResult] {
	if strings.TrimSpace(oldSeed) == "" {
		return ResultErr[ChangeSeedResult](ErrCodePrivateKeyParseError, "change_seed requires a non-empty old_seed")
	}
	if strings.TrimSpace(newSeed) == "" {
		return ResultErr[ChangeSeedResult](ErrCodePrivateKeyParseError, "change_seed requires a non-empty new_seed")
	}
	if oldSeed == newSeed {
		return ResultErr[ChangeSeedResult](ErrCodePrivateKeyParseError, "new_seed must differ from old_seed")
	}
	type seedChanger interface {
		ChangeSeed(oldSeed, newSeed string) (keystore.SeedChangeResult, error)
	}
	changer, ok := s.client.keyStore.(seedChanger)
	if !ok {
		return ResultErr[ChangeSeedResult]("NOT_SUPPORTED", "keystore does not support seed migration")
	}
	result, err := changer.ChangeSeed(oldSeed, newSeed)
	if err != nil {
		return ResultErr[ChangeSeedResult](ErrCodePrivateKeyParseError, err.Error(), err)
	}
	s.encryptionSeed = newSeed
	return ResultOk(ChangeSeedResult{Changed: result.PrivateKeysMigrated > 0, Count: result.PrivateKeysMigrated})
}

// Register 在服务端注册新 AID（联网操作）。
func (s *AIDStore) Register(ctx context.Context, aid string) Result[RegisterResult] {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return ResultErr[RegisterResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return ResultErr[RegisterResult](ErrCodeNetworkError, err.Error(), err)
	}
	_, err = s.client.auth.RegisterAID(ctx, gatewayURL, target)
	if err != nil {
		return ResultErr[RegisterResult](ErrCodeNetworkError, err.Error(), err)
	}
	return ResultOk(RegisterResult{Registered: true})
}

// Exists 检查 AID 是否已在服务端注册（联网操作）。
func (s *AIDStore) Exists(ctx context.Context, aid string) Result[ExistsResult] {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return ResultErr[ExistsResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return ResultErr[ExistsResult](ErrCodeNetworkError, err.Error(), err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, buildCertURL(gatewayURL, target, ""), nil)
	if err != nil {
		return ResultErr[ExistsResult](ErrCodeNetworkError, err.Error(), err)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return ResultErr[ExistsResult](ErrCodeNetworkError, err.Error(), err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return ResultOk(ExistsResult{Exists: true})
	case http.StatusNotFound:
		return ResultOk(ExistsResult{Exists: false})
	default:
		return ResultErr[ExistsResult](ErrCodeNetworkError, fmt.Sprintf("unexpected PKI HEAD status %d", resp.StatusCode))
	}
}

// Resolve 一站式解析对端 AID：本地缓存/PKI 证书 + 可选 agent.md。
func (s *AIDStore) Resolve(ctx context.Context, aid string, opts ...AIDStoreResolveOptions) Result[AIDStoreResolveResult] {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return ResultErr[AIDStoreResolveResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	var opt AIDStoreResolveOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// 应用 Timeout
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	loadR := s.Load(target)
	certFromCache := loadR.Ok && !opt.ForceRefresh
	var peer *AID
	if certFromCache {
		peer = loadR.Data.AID
	} else {
		gatewayURL, gwErr := s.resolveGateway(resolveCtx, target)
		if gwErr != nil {
			return ResultErr[AIDStoreResolveResult](ErrCodeNetworkError, gwErr.Error(), gwErr)
		}
		s.client.setGatewayURL(gatewayURL)
		certBytes, fetchErr := s.client.AuthFetchPeerCert(resolveCtx, target, "")
		if fetchErr != nil {
			if errors.Is(fetchErr, errCertNotFound) {
				return ResultErr[AIDStoreResolveResult](ErrCodeCertNotFound, fmt.Sprintf("certificate not found for aid: %s", target))
			}
			return ResultErr[AIDStoreResolveResult](ErrCodeNetworkError, fetchErr.Error(), fetchErr)
		}
		if strings.TrimSpace(string(certBytes)) == "" {
			return ResultErr[AIDStoreResolveResult](ErrCodeCertNotFound, fmt.Sprintf("certificate not found for aid: %s", target))
		}
		if saveErr := s.client.keyStore.SaveCert(target, string(certBytes)); saveErr != nil {
			return ResultErr[AIDStoreResolveResult](ErrCodeServerError, fmt.Sprintf("save peer certificate failed: %v", saveErr), saveErr)
		}
		r2 := s.Load(target)
		if !r2.Ok {
			return ResultErr[AIDStoreResolveResult](r2.Error.Code, r2.Error.Message, r2.Error.Cause)
		}
		peer = r2.Data.AID
	}

	result := AIDStoreResolveResult{
		AID: peer,
		Source: AIDStoreResolveSource{
			CertFromCache: certFromCache,
		},
	}
	if opt.SkipAgentMD {
		return ResultOk(result)
	}
	mdR := s.FetchAgentMD(resolveCtx, target)
	if !mdR.Ok {
		return ResultErr[AIDStoreResolveResult](mdR.Error.Code, mdR.Error.Message, mdR.Error.Cause)
	}
	result.AgentMD = &mdR.Data
	result.Source.AgentMDFetched = true
	return ResultOk(result)
}

// FetchAgentMD 下载 agent.md 并自动验签。
func (s *AIDStore) FetchAgentMD(ctx context.Context, aid string) Result[AgentMDInfo] {
	target := strings.TrimSpace(aid)
	if target == "" {
		return ResultErr[AgentMDInfo](ErrCodeInvalidAIDFormat, "fetch agent.md requires aid")
	}
	info, err := s.client.fetchAgentMD(ctx, target)
	if err != nil {
		return ResultErr[AgentMDInfo](ErrCodeNetworkError, err.Error(), err)
	}
	return ResultOk(*info)
}

// FetchAgentMd 是 FetchAgentMD 的跨语言命名别名。
func (s *AIDStore) FetchAgentMd(ctx context.Context, aid string) Result[AgentMDInfo] {
	return s.FetchAgentMD(ctx, aid)
}

// HeadAgentMD 通过 HEAD 获取 agent.md 元数据。
func (s *AIDStore) HeadAgentMD(ctx context.Context, aid string) Result[HeadAgentMdResult] {
	target := strings.TrimSpace(aid)
	if target == "" {
		return ResultErr[HeadAgentMdResult](ErrCodeInvalidAIDFormat, "head agent.md requires aid")
	}
	raw, err := s.client.authNamespace.HeadAgentMD(ctx, target)
	if err != nil {
		return ResultErr[HeadAgentMdResult](ErrCodeNetworkError, err.Error(), err)
	}
	found, _ := raw["found"].(bool)
	etag, _ := raw["etag"].(string)
	lastModified, _ := raw["last_modified"].(string)
	contentLength := 0
	if v, ok := raw["content_length"].(float64); ok {
		contentLength = int(v)
	}
	return ResultOk(HeadAgentMdResult{
		AID:           target,
		Found:         found,
		Etag:          etag,
		LastModified:  lastModified,
		ContentLength: contentLength,
	})
}

// HeadAgentMd 是 HeadAgentMD 的跨语言命名别名。
func (s *AIDStore) HeadAgentMd(ctx context.Context, aid string) Result[HeadAgentMdResult] {
	return s.HeadAgentMD(ctx, aid)
}

// CheckAgentMD 比对本地缓存与远端 agent.md ETag。
func (s *AIDStore) CheckAgentMD(ctx context.Context, aid string, maxUnsyncedDays ...float64) Result[CheckAgentMdResult] {
	r, err := s.client.checkAgentMD(ctx, aid, maxUnsyncedDays...)
	if err != nil {
		return ResultErr[CheckAgentMdResult](ErrCodeNetworkError, err.Error(), err)
	}
	return ResultOk(CheckAgentMdResult{
		AID:         r.AID,
		LocalFound:  r.LocalFound,
		RemoteFound: r.RemoteFound,
		LocalEtag:   r.LocalEtag,
		RemoteEtag:  r.RemoteEtag,
		NeedsUpdate: !r.InSync,
	})
}

// CheckAgentMd 是 CheckAgentMD 的跨语言命名别名。
func (s *AIDStore) CheckAgentMd(ctx context.Context, aid string, maxUnsyncedDays ...float64) Result[CheckAgentMdResult] {
	return s.CheckAgentMD(ctx, aid, maxUnsyncedDays...)
}

// Diagnose 汇总本地身份有效性与远端注册状态。
func (s *AIDStore) Diagnose(ctx context.Context, aid string) Result[AIDStoreDiagnoseResult] {
	target := strings.TrimSpace(aid)
	if err := validateAIDName(target); err != nil {
		return ResultErr[AIDStoreDiagnoseResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	loadR := s.Load(target)
	existsR := s.Exists(ctx, target)

	var loaded *AID
	if loadR.Ok {
		loaded = loadR.Data.AID
	}
	localCert := loaded != nil && loaded.IsCertValid()
	localPrivateKey := loaded != nil && loaded.IsPrivateKeyValid()
	localValid := localCert && localPrivateKey
	remoteChecked := existsR.Ok
	exists := existsR.Ok && existsR.Data.Exists

	suggestions := make([]string, 0, 3)
	if !localValid {
		suggestions = append(suggestions, "load or register a local identity with a valid private key")
	}
	if remoteChecked && !exists {
		suggestions = append(suggestions, "register the AID before using it on the network")
	}
	if !remoteChecked {
		suggestions = append(suggestions, fmt.Sprintf("remote registration check failed: %s", existsR.Error.Message))
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
	if !loadR.Ok {
		local["error"] = loadR.Error.Message
	}
	remote := map[string]any{
		"checked": remoteChecked,
		"exists":  nil,
	}
	if remoteChecked {
		remote["exists"] = exists
	}
	if !remoteChecked {
		remote["error"] = existsR.Error.Message
	}

	return ResultOk(AIDStoreDiagnoseResult{
		AID:              target,
		Status:           status,
		LocalValid:       localValid,
		RemoteRegistered: remoteChecked && exists,
		Suggestions:      suggestions,
		Local:            local,
		Remote:           remote,
	})
}

// RenewCert 续签本地 AID 证书并写回 keystore。
func (s *AIDStore) RenewCert(ctx context.Context, aid string) Result[AIDStoreRenewCertResult] {
	target := strings.TrimSpace(aid)
	loadR := s.Load(target)
	if !loadR.Ok || !loadR.Data.AID.IsPrivateKeyValid() {
		return ResultErr[AIDStoreRenewCertResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	identity := s.client.AuthLoadIdentityOrNil(target)
	privateKeyPEM := strings.TrimSpace(authGetStr(identity, "private_key_pem"))
	certPEM := strings.TrimSpace(authGetStr(identity, "cert"))
	if privateKeyPEM == "" || certPEM == "" {
		return ResultErr[AIDStoreRenewCertResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeNetworkError, err.Error(), err)
	}
	clientNonce := s.client.auth.crypto.NewClientNonce()
	phase1, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.aid_login1", map[string]any{
		"aid":          target,
		"cert":         certPEM,
		"client_nonce": clientNonce,
	})
	if err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, err.Error(), err)
	}
	if err := s.client.auth.verifyPhase1Response(ctx, gatewayURL, phase1, clientNonce); err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, err.Error(), err)
	}
	nonce := authGetStr(phase1, "nonce")
	signature, clientTime, err := s.client.auth.crypto.SignLoginNonce(privateKeyPEM, nonce, "")
	if err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, err.Error(), err)
	}
	response, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.renew_cert", map[string]any{
		"aid":         target,
		"request_id":  phase1["request_id"],
		"nonce":       nonce,
		"client_time": clientTime,
		"signature":   signature,
	})
	if err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, err.Error(), err)
	}
	newCert := strings.TrimSpace(authGetStr(response, "cert"))
	if newCert == "" {
		newCert = strings.TrimSpace(authGetStr(response, "cert_pem"))
	}
	if newCert == "" {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, "server response missing certificate")
	}
	if err := s.client.keyStore.SaveCert(target, newCert); err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, fmt.Sprintf("save renewed certificate failed: %v", err), err)
	}
	r2 := s.Load(target)
	if !r2.Ok {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, fmt.Sprintf("renewed certificate reload failed: %s", r2.Error.Message))
	}
	refreshed := r2.Data.AID
	return ResultOk(AIDStoreRenewCertResult{
		Renewed:         true,
		NewCertNotAfter: refreshed.CertNotAfter,
		NewFingerprint:  refreshed.CertFingerprint,
	})
}

// Rekey 生成新密钥对并请求服务端换发证书，然后写回 keystore。
func (s *AIDStore) Rekey(ctx context.Context, aid string) Result[AIDStoreRekeyResult] {
	target := strings.TrimSpace(aid)
	loadR := s.Load(target)
	if !loadR.Ok || !loadR.Data.AID.IsPrivateKeyValid() {
		return ResultErr[AIDStoreRekeyResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	loaded := loadR.Data.AID
	identity := s.client.AuthLoadIdentityOrNil(target)
	certPEM := strings.TrimSpace(authGetStr(identity, "cert"))
	if certPEM == "" {
		return ResultErr[AIDStoreRekeyResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	newIdentity, err := s.client.auth.crypto.GenerateIdentity()
	if err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	newPublicKey := strings.TrimSpace(authGetStr(newIdentity, "public_key_der_b64"))
	if newPublicKey == "" {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, "generated identity missing public key")
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeNetworkError, err.Error(), err)
	}
	clientNonce := s.client.auth.crypto.NewClientNonce()
	phase1, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.aid_login1", map[string]any{
		"aid":          target,
		"cert":         certPEM,
		"client_nonce": clientNonce,
	})
	if err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	if err := s.client.auth.verifyPhase1Response(ctx, gatewayURL, phase1, clientNonce); err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	nonce := authGetStr(phase1, "nonce")
	signature, err := loaded.Sign([]byte(nonce + newPublicKey))
	if err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	response, err := s.client.auth.shortRPC(ctx, gatewayURL, "auth.rekey", map[string]any{
		"aid":            target,
		"request_id":     phase1["request_id"],
		"nonce":          nonce,
		"new_public_key": newPublicKey,
		"signature":      signature,
	})
	if err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	newCert := strings.TrimSpace(authGetStr(response, "cert"))
	if newCert == "" {
		newCert = strings.TrimSpace(authGetStr(response, "cert_pem"))
	}
	if newCert == "" {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, "server response missing certificate")
	}
	newIdentity["aid"] = target
	newIdentity["cert"] = newCert
	if err := s.client.keyStore.SaveIdentity(target, newIdentity); err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, fmt.Sprintf("save rekeyed identity failed: %v", err), err)
	}
	r2 := s.Load(target)
	if !r2.Ok {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, fmt.Sprintf("rekeyed identity reload failed: %s", r2.Error.Message))
	}
	refreshed := r2.Data.AID
	return ResultOk(AIDStoreRekeyResult{
		Rekeyed:         true,
		NewCertNotAfter: refreshed.CertNotAfter,
		NewFingerprint:  refreshed.CertFingerprint,
	})
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
