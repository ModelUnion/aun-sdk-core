package aun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	keyStore       *keystore.LocalIdentityStore
	tokenStore     *keystore.LocalTokenStore
	registerFlow   *RegisterFlow
	discovery      *GatewayDiscovery
	dnsNet         *DnsResilientNet
	gatewayURL     string
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
	dnsNet := NewDnsResilientNet(aunPath, verifySSL)
	ks, err := keystore.NewLocalIdentityStore(aunPath, nil, encryptionSeed)
	if err != nil {
		pkgLogKeystore().Warn("创建 LocalIdentityStore 失败: %v, 使用空种子", err)
		ks, _ = keystore.NewLocalIdentityStore(aunPath, nil, "")
	}
	ts, err := keystore.NewLocalTokenStore(aunPath, nil, encryptionSeed)
	if err != nil {
		pkgLogKeystore().Warn("创建 LocalTokenStore 失败: %v, 使用空种子", err)
		ts, _ = keystore.NewLocalTokenStore(aunPath, nil, "")
	}
	rf := NewRegisterFlow(RegisterFlowConfig{
		Keystore:  ks,
		VerifySSL: verifySSL,
		DnsNet:    dnsNet,
	})
	store := &AIDStore{
		aunPath:        aunPath,
		encryptionSeed: encryptionSeed,
		deviceID:       o.DeviceID,
		slotID:         o.SlotID,
		verifySSL:      verifySSL,
		rootCaPath:     o.RootCaPath,
		debug:          o.Debug,
		keyStore:       ks,
		tokenStore:     ts,
		registerFlow:   rf,
		discovery:      NewGatewayDiscovery(verifySSL, dnsNet),
		dnsNet:         dnsNet,
	}
	return store
}

// Close 释放资源
func (s *AIDStore) Close() {
	if s.keyStore != nil {
		s.keyStore.Close()
	}
	if s.tokenStore != nil {
		s.tokenStore.Close()
	}
	if s.dnsNet != nil {
		s.dnsNet.Close()
	}
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
	certPEM, err := s.keyStore.LoadCert(target)
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
	keyPair, err := s.keyStore.LoadKeyPair(target)
	if err != nil {
		return ResultErr[LoadResult](ErrCodePrivateKeyParseError, fmt.Sprintf("private key load failed for aid: %s", target), err)
	}

	// 无私钥：仅证书有效
	if keyPair == nil || authGetStr(keyPair, "private_key_pem") == "" {
		return ResultOk(LoadResult{AID: newAID(target, s.aunPath, certPEM, certObj, nil, true, false, s.deviceID, s.slotID, s.verifySSL, s.rootCaPath, s.debug, "")})
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

	return ResultOk(LoadResult{AID: newAID(target, s.aunPath, certPEM, certObj, privKey, true, true, s.deviceID, s.slotID, s.verifySSL, s.rootCaPath, s.debug, privPEM)})
}

// List 列出本地所有具有有效私钥的身份摘要（离线操作）。
func (s *AIDStore) List() Result[ListResult] {
	aids, err := s.keyStore.ListIdentities()
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
	result, err := s.keyStore.ChangeSeed(oldSeed, newSeed)
	if err != nil {
		return ResultErr[ChangeSeedResult](ErrCodePrivateKeyParseError, err.Error(), err)
	}
	s.encryptionSeed = newSeed
	return ResultOk(ChangeSeedResult{Changed: result.PrivateKeysMigrated > 0, Count: result.PrivateKeysMigrated})
}

// Register 在服务端注册新 AID（联网操作）。
func (s *AIDStore) Register(ctx context.Context, aid string) Result[RegisterResult] {
	target := strings.TrimSpace(aid)
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
		return ResultErr[RegisterResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return ResultErr[RegisterResult](ErrCodeNetworkError, err.Error(), err)
	}
	result, err := s.registerFlow.RegisterAID(ctx, gatewayURL, target)
	if err != nil {
		return ResultErr[RegisterResult](ErrCodeNetworkError, err.Error(), err)
	}
	if result.Cert != "" {
		if saveErr := s.keyStore.SaveCert(target, result.Cert); saveErr != nil {
			return ResultErr[RegisterResult](ErrCodeNetworkError, saveErr.Error(), saveErr)
		}
	}
	if saveErr := s.keyStore.SaveKeyPair(target, map[string]any{
		"private_key_pem":    result.PrivateKeyPEM,
		"public_key_der_b64": result.PublicKeyDerB64,
		"curve":              result.Curve,
	}); saveErr != nil {
		return ResultErr[RegisterResult](ErrCodeNetworkError, saveErr.Error(), saveErr)
	}
	_ = s.keyStore.SetMetadataValue(target, "gateway_url", gatewayURL)
	return ResultOk(RegisterResult{Registered: true})
}

// Exists 检查 AID 是否已在服务端注册（联网操作）。
func (s *AIDStore) Exists(ctx context.Context, aid string) Result[ExistsResult] {
	target := strings.TrimSpace(aid)
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
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
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
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
		certPEM, fetchErr := s.registerFlow.FetchPeerCert(resolveCtx, gatewayURL, target)
		if fetchErr != nil {
			if errors.Is(fetchErr, errCertNotFound) {
				return ResultErr[AIDStoreResolveResult](ErrCodeCertNotFound, fmt.Sprintf("certificate not found for aid: %s", target))
			}
			return ResultErr[AIDStoreResolveResult](ErrCodeNetworkError, fetchErr.Error(), fetchErr)
		}
		if strings.TrimSpace(certPEM) == "" {
			return ResultErr[AIDStoreResolveResult](ErrCodeCertNotFound, fmt.Sprintf("certificate not found for aid: %s", target))
		}
		if saveErr := s.keyStore.SaveCert(target, certPEM); saveErr != nil {
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
	mdR := s.DownloadAgentMD(resolveCtx, target)
	if !mdR.Ok {
		return ResultErr[AIDStoreResolveResult](mdR.Error.Code, mdR.Error.Message, mdR.Error.Cause)
	}
	result.AgentMD = &mdR.Data
	result.Source.AgentMDFetched = true
	return ResultOk(result)
}

func (s *AIDStore) agentMDRoot() string {
	root := filepath.Join(s.aunPath, "AIDs")
	_ = os.MkdirAll(root, 0o755)
	return root
}

func (s *AIDStore) agentMDFilePath(aid string) (string, error) {
	safe, err := agentMDSafeAID(aid)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.agentMDRoot(), safe, "agent.md"), nil
}

func (s *AIDStore) agentMDMetaPath(aid string) (string, error) {
	safe, err := agentMDSafeAID(aid)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.agentMDRoot(), safe, "agentmd.json"), nil
}

func (s *AIDStore) readAgentMDRecord(aid string) *keystore.AgentMDCacheRecord {
	metaPath, err := s.agentMDMetaPath(aid)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	return agentMDMapToRecord(aid, raw)
}

func (s *AIDStore) writeAgentMDRecord(aid string, rec *keystore.AgentMDCacheRecord) error {
	metaPath, err := s.agentMDMetaPath(aid)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(agentMDRecordToMap(rec), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteText(metaPath, data)
}

func (s *AIDStore) loadAgentMDRecord(aid string) *keystore.AgentMDCacheRecord {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil
	}
	rec := s.readAgentMDRecord(target)
	p, err := s.agentMDFilePath(target)
	if err != nil {
		return rec
	}
	data, readErr := os.ReadFile(p)
	if readErr != nil {
		return rec
	}
	if rec == nil {
		rec = &keystore.AgentMDCacheRecord{AID: target}
	}
	rec.Content = string(data)
	rec.LocalEtag = agentMDContentEtag(rec.Content)
	return rec
}

func (s *AIDStore) saveAgentMDRecord(aid string, fields keystore.AgentMDCacheUpsert) *keystore.AgentMDCacheRecord {
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil
	}
	if fields.Content != nil {
		p, err := s.agentMDFilePath(target)
		if err != nil {
			return nil
		}
		if err := atomicWriteText(p, []byte(*fields.Content)); err != nil {
			return nil
		}
		if fields.LocalEtag == nil {
			fields.LocalEtag = agentMDStringPtr(agentMDContentEtag(*fields.Content))
		}
		if fields.FetchedAt == nil {
			fields.FetchedAt = agentMDInt64Ptr(time.Now().UnixMilli())
		}
	}
	rec := s.readAgentMDRecord(target)
	if rec == nil {
		rec = &keystore.AgentMDCacheRecord{AID: target}
	}
	applyAgentMDCacheUpsert(rec, fields)
	rec.Content = ""
	rec.UpdatedAt = time.Now().UnixMilli()
	if err := s.writeAgentMDRecord(target, rec); err != nil {
		return nil
	}
	loaded := cloneAgentMDRecord(rec)
	if fields.Content != nil {
		loaded.Content = *fields.Content
	}
	return loaded
}

func (s *AIDStore) resolveAgentMDURL(ctx context.Context, aid string) (string, error) {
	gatewayURL, err := s.resolveGateway(ctx, aid)
	if err != nil {
		return "", err
	}
	return agentMDURLFromGateway(gatewayURL, aid, 0), nil
}

func (s *AIDStore) publicAIDFromCert(aid, certPEM string) (*AID, error) {
	target := strings.TrimSpace(aid)
	certObj, err := parsePEMCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	if tErr := certTimeError(certObj); tErr != "" {
		return nil, fmt.Errorf("certificate is %s for aid: %s", tErr, target)
	}
	if cn := strings.TrimSpace(certObj.Subject.CommonName); cn != "" && cn != target {
		return nil, fmt.Errorf("certificate CN mismatch: expected %s, got %s", target, cn)
	}
	return newAID(target, s.aunPath, certPEM, certObj, nil, true, false, s.deviceID, s.slotID, s.verifySSL, s.rootCaPath, s.debug, ""), nil
}

func (s *AIDStore) resolveAgentMDPeer(ctx context.Context, aid string) (*AID, error) {
	target := strings.TrimSpace(aid)
	certPEM, err := s.keyStore.LoadCert(target)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(certPEM) == "" {
		gatewayURL, err := s.resolveGateway(ctx, target)
		if err != nil {
			return nil, err
		}
		certPEM, err = s.registerFlow.FetchPeerCert(ctx, gatewayURL, target)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(certPEM) == "" {
			return nil, errCertNotFound
		}
		if err := s.keyStore.SaveCert(target, certPEM); err != nil {
			return nil, err
		}
	}
	return s.publicAIDFromCert(target, certPEM)
}

func (s *AIDStore) authIdentityFromAID(aid *AID) map[string]any {
	return map[string]any{
		"aid":                aid.Aid,
		"private_key_pem":    aid.PrivateKeyPem,
		"public_key_der_b64": aid.PublicKey,
		"cert":               aid.CertPem,
	}
}

func (s *AIDStore) uploadAgentMDToken(ctx context.Context, aid *AID, gatewayURL string) (string, error) {
	auth := NewAuthFlow(AuthFlowConfig{
		TokenStore: s.tokenStore,
		Crypto:     &CryptoProvider{},
		AID:        aid.Aid,
		VerifySSL:  s.verifySSL,
		RootCAPath: s.rootCaPath,
		DnsNet:     s.dnsNet,
	})
	auth.SetInstanceContext(s.deviceID, s.slotID)
	auth.SetIdentity(s.authIdentityFromAID(aid))
	result, err := auth.Authenticate(ctx, gatewayURL, aid.Aid)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(stringFromAny(result["access_token"]))
	if token == "" {
		token = strings.TrimSpace(stringFromAny(result["token"]))
	}
	if token == "" {
		token = strings.TrimSpace(stringFromAny(result["kite_token"]))
	}
	if token == "" {
		return "", fmt.Errorf("authenticate did not return access_token")
	}
	return token, nil
}

// UploadAgentMD 读取本地 agent.md 或使用传入正文，签名后上传到服务端。
func (s *AIDStore) UploadAgentMD(ctx context.Context, aid string, contentArg ...string) Result[map[string]any] {
	target := strings.TrimSpace(aid)
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
		return ResultErr[map[string]any](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	loadR := s.Load(target)
	if !loadR.Ok {
		return ResultErr[map[string]any](loadR.Error.Code, loadR.Error.Message, loadR.Error.Cause)
	}
	current := loadR.Data.AID
	if current == nil || !current.IsPrivateKeyValid() || strings.TrimSpace(current.PrivateKeyPem) == "" {
		return ResultErr[map[string]any](ErrCodePrivateKeyNotValid, fmt.Sprintf("UploadAgentMD requires local AID with a valid private key: %s", target))
	}

	content := ""
	if len(contentArg) > 0 {
		content = contentArg[0]
	} else {
		p, err := s.agentMDFilePath(target)
		if err != nil {
			return ResultErr[map[string]any](ErrCodeInvalidAIDFormat, err.Error(), err)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return ResultErr[map[string]any](ErrCodeNetworkError, fmt.Sprintf("UploadAgentMD read default agent.md: %v", err), err)
		}
		content = string(data)
	}
	if strings.TrimSpace(content) == "" {
		return ResultErr[map[string]any](ErrCodeInvalidAIDFormat, "UploadAgentMD requires non-empty content")
	}
	signed, err := current.SignAgentMd(content)
	if err != nil {
		return ResultErr[map[string]any](ErrCodeSignatureOperationError, err.Error(), err)
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return ResultErr[map[string]any](ErrCodeNetworkError, err.Error(), err)
	}
	token, err := s.uploadAgentMDToken(ctx, current, gatewayURL)
	if err != nil {
		return ResultErr[map[string]any](ErrCodeNetworkError, err.Error(), err)
	}
	result, err := agentMDUploadHTTP(ctx, s.httpClient(), agentMDURLFromGateway(gatewayURL, target, 0), token, signed)
	if err != nil {
		code := ErrCodeNetworkError
		if strings.Contains(err.Error(), "agent.md endpoint not found") {
			code = ErrCodeAgentMdNotFound
		}
		return ResultErr[map[string]any](code, err.Error(), err)
	}
	remoteEtag := strings.TrimSpace(stringFromAny(result["etag"]))
	lastModified := strings.TrimSpace(stringFromAny(result["last_modified"]))
	if lastModified == "" {
		lastModified = strings.TrimSpace(stringFromAny(result["lastModified"]))
	}
	remoteStatus := "unknown"
	if remoteEtag != "" {
		remoteStatus = "found"
	}
	s.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
		Content:      agentMDStringPtr(signed),
		LocalEtag:    agentMDStringPtr(agentMDContentEtag(signed)),
		RemoteEtag:   agentMDStringPtr(remoteEtag),
		LastModified: agentMDStringPtr(lastModified),
		FetchedAt:    agentMDInt64Ptr(time.Now().UnixMilli()),
		CheckedAt:    agentMDInt64Ptr(time.Now().UnixMilli()),
		RemoteStatus: agentMDStringPtr(remoteStatus),
		LastError:    agentMDStringPtr(""),
	})
	return ResultOk(result)
}

// UploadAgentMd 是 UploadAgentMD 的跨语言命名别名。
func (s *AIDStore) UploadAgentMd(ctx context.Context, aid string, contentArg ...string) Result[map[string]any] {
	return s.UploadAgentMD(ctx, aid, contentArg...)
}

// DownloadAgentMD 下载 agent.md 并自动验签。
func (s *AIDStore) DownloadAgentMD(ctx context.Context, aid string) Result[AgentMDInfo] {
	target := strings.TrimSpace(aid)
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
		return ResultErr[AgentMDInfo](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	url, err := s.resolveAgentMDURL(ctx, target)
	if err != nil {
		return ResultErr[AgentMDInfo](ErrCodeNetworkError, err.Error(), err)
	}
	var downloaded agentMDDownloadResult
	if rec := s.loadAgentMDRecord(target); rec != nil && rec.Content != "" {
		cachedEtag := strings.TrimSpace(rec.RemoteEtag)
		if cachedEtag == "" {
			cachedEtag = strings.TrimSpace(rec.LocalEtag)
		}
		downloaded, err = agentMDDownloadHTTP(ctx, s.httpClient(), url, target, agentMDDownloadCache{
			Content:      rec.Content,
			Etag:         cachedEtag,
			LastModified: rec.LastModified,
		})
	} else {
		downloaded, err = agentMDDownloadHTTP(ctx, s.httpClient(), url, target)
	}
	if err != nil {
		code := ErrCodeNetworkError
		if strings.Contains(err.Error(), ErrCodeAgentMdNotFound) {
			code = ErrCodeAgentMdNotFound
		}
		return ResultErr[AgentMDInfo](code, err.Error(), err)
	}
	peer, err := s.resolveAgentMDPeer(ctx, target)
	if err != nil {
		return ResultErr[AgentMDInfo](ErrCodeNetworkError, err.Error(), err)
	}
	verifyResult, err := peer.VerifyAgentMd(downloaded.Content)
	if err != nil {
		return ResultErr[AgentMDInfo](ErrCodeNetworkError, err.Error(), err)
	}
	sig := verifyAgentMDResultToMap(verifyResult, peer.CertPem)
	info := AgentMDInfo{
		AID:          target,
		Content:      downloaded.Content,
		Signature:    sig,
		CertPem:      peer.CertPem,
		Etag:         strings.TrimSpace(downloaded.Etag),
		LastModified: strings.TrimSpace(downloaded.LastModified),
	}
	if status, ok := sig["status"].(string); ok {
		verification := map[string]any{"status": status}
		if reason, ok := sig["reason"].(string); ok && reason != "" {
			verification["reason"] = reason
		}
		info.Verification = verification
	}
	localEtag := agentMDContentEtag(downloaded.Content)
	s.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
		Content:      agentMDStringPtr(downloaded.Content),
		LocalEtag:    agentMDStringPtr(localEtag),
		RemoteEtag:   agentMDStringPtr(info.Etag),
		LastModified: agentMDStringPtr(info.LastModified),
		FetchedAt:    agentMDInt64Ptr(time.Now().UnixMilli()),
		RemoteStatus: agentMDStringPtr("found"),
		VerifyStatus: agentMDStringPtr(strings.TrimSpace(stringFromAny(sig["status"]))),
		VerifyError:  agentMDStringPtr(strings.TrimSpace(stringFromAny(sig["reason"]))),
		LastError:    agentMDStringPtr(""),
	})
	if p, err := s.agentMDFilePath(target); err == nil {
		info.SavedTo = p
	}
	return ResultOk(info)
}

// DownloadAgentMd 是 DownloadAgentMD 的跨语言命名别名。
func (s *AIDStore) DownloadAgentMd(ctx context.Context, aid string) Result[AgentMDInfo] {
	return s.DownloadAgentMD(ctx, aid)
}

// CheckAgentMD 比对本地缓存与远端 agent.md ETag。
func (s *AIDStore) CheckAgentMD(ctx context.Context, aid string, maxUnsyncedDays ...float64) Result[CheckAgentMdResult] {
	target := strings.TrimSpace(aid)
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
		return ResultErr[CheckAgentMdResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	before := s.loadAgentMDRecord(target)
	localFound := false
	localEtag := ""
	if before != nil {
		localEtag = strings.TrimSpace(before.LocalEtag)
		localFound = strings.TrimSpace(before.Content) != "" || localEtag != ""
	}
	url, err := s.resolveAgentMDURL(ctx, target)
	if err != nil {
		return ResultErr[CheckAgentMdResult](ErrCodeNetworkError, err.Error(), err)
	}
	r, err := agentMDHeadHTTP(ctx, s.httpClient(), url, target)
	if err != nil {
		return ResultErr[CheckAgentMdResult](ErrCodeNetworkError, err.Error(), err)
	}
	remoteFound, _ := r["found"].(bool)
	remoteEtag := strings.TrimSpace(stringFromAny(r["etag"]))
	lastModified := strings.TrimSpace(stringFromAny(r["last_modified"]))
	remoteStatus := "missing"
	if remoteFound {
		remoteStatus = "found"
	}
	s.saveAgentMDRecord(target, keystore.AgentMDCacheUpsert{
		RemoteEtag:   agentMDStringPtr(map[bool]string{true: remoteEtag, false: ""}[remoteFound]),
		LastModified: agentMDStringPtr(lastModified),
		CheckedAt:    agentMDInt64Ptr(time.Now().UnixMilli()),
		RemoteStatus: agentMDStringPtr(remoteStatus),
		LastError:    agentMDStringPtr(""),
	})
	ttlDays := 0
	if len(maxUnsyncedDays) > 0 && maxUnsyncedDays[0] > 0 {
		ttlDays = int(maxUnsyncedDays[0])
	}
	needsUpdate := remoteFound && (!localFound || localEtag == "" || remoteEtag == "" || localEtag != remoteEtag)
	return ResultOk(CheckAgentMdResult{
		AID:         target,
		LocalFound:  localFound,
		RemoteFound: remoteFound,
		LocalEtag:   localEtag,
		RemoteEtag:  remoteEtag,
		NeedsUpdate: needsUpdate,
		TtlDays:     ttlDays,
	})
}

// CheckAgentMd 是 CheckAgentMD 的跨语言命名别名。
func (s *AIDStore) CheckAgentMd(ctx context.Context, aid string, maxUnsyncedDays ...float64) Result[CheckAgentMdResult] {
	return s.CheckAgentMD(ctx, aid, maxUnsyncedDays...)
}

// Diagnose 汇总本地身份有效性与远端注册状态。
func (s *AIDStore) Diagnose(ctx context.Context, aid string) Result[AIDStoreDiagnoseResult] {
	target := strings.TrimSpace(aid)
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
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
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	loadR := s.Load(target)
	if !loadR.Ok || !loadR.Data.AID.IsPrivateKeyValid() {
		return ResultErr[AIDStoreRenewCertResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	loaded := loadR.Data.AID
	privateKeyPEM := strings.TrimSpace(loaded.PrivateKeyPem)
	certPEM := strings.TrimSpace(loaded.CertPem)
	if privateKeyPEM == "" || certPEM == "" {
		return ResultErr[AIDStoreRenewCertResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	gatewayURL, err := s.resolveGateway(ctx, target)
	if err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeNetworkError, err.Error(), err)
	}
	clientNonce := s.registerFlow.NewClientNonce()
	phase1, err := s.registerFlow.ShortRPC(ctx, gatewayURL, "auth.aid_login1", map[string]any{
		"aid":          target,
		"cert":         certPEM,
		"client_nonce": clientNonce,
	})
	if err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, err.Error(), err)
	}
	if err := s.registerFlow.VerifyPhase1Response(ctx, gatewayURL, phase1, clientNonce); err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, err.Error(), err)
	}
	nonce := authGetStr(phase1, "nonce")
	signature, clientTime, err := s.registerFlow.SignLoginNonce(privateKeyPEM, nonce, "")
	if err != nil {
		return ResultErr[AIDStoreRenewCertResult](ErrCodeCertRenewalFailed, err.Error(), err)
	}
	response, err := s.registerFlow.ShortRPC(ctx, gatewayURL, "auth.renew_cert", map[string]any{
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
	if err := s.keyStore.SaveCert(target, newCert); err != nil {
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
	if err := s.registerFlow.ValidateAIDName(target); err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeInvalidAIDFormat, err.Error(), err)
	}
	loadR := s.Load(target)
	if !loadR.Ok || !loadR.Data.AID.IsPrivateKeyValid() {
		return ResultErr[AIDStoreRekeyResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	loaded := loadR.Data.AID
	certPEM := strings.TrimSpace(loaded.CertPem)
	if certPEM == "" {
		return ResultErr[AIDStoreRekeyResult](ErrCodePrivateKeyRequired, fmt.Sprintf("private key required for aid: %s", target))
	}
	newIdentity, err := s.registerFlow.GenerateIdentity()
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
	clientNonce := s.registerFlow.NewClientNonce()
	phase1, err := s.registerFlow.ShortRPC(ctx, gatewayURL, "auth.aid_login1", map[string]any{
		"aid":          target,
		"cert":         certPEM,
		"client_nonce": clientNonce,
	})
	if err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	if err := s.registerFlow.VerifyPhase1Response(ctx, gatewayURL, phase1, clientNonce); err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	nonce := authGetStr(phase1, "nonce")
	signature, err := loaded.Sign([]byte(nonce + newPublicKey))
	if err != nil {
		return ResultErr[AIDStoreRekeyResult](ErrCodeRekeyFailed, err.Error(), err)
	}
	response, err := s.registerFlow.ShortRPC(ctx, gatewayURL, "auth.rekey", map[string]any{
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
	if err := s.keyStore.SaveIdentity(target, newIdentity); err != nil {
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
	if !s.verifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// resolveGateway 解析 AID 对应的 Gateway URL
func (s *AIDStore) resolveGateway(ctx context.Context, aid string) (string, error) {
	if explicit := strings.TrimSpace(s.gatewayURL); explicit != "" {
		return explicit, nil
	}
	// 先查缓存
	if cached := strings.TrimSpace(s.keyStore.GetMetadataValue(aid, "gateway_url")); cached != "" {
		return cached, nil
	}
	// 通过 well-known 发现
	parts := strings.SplitN(aid, ".", 2)
	issuer := aid
	if len(parts) > 1 {
		issuer = parts[1]
	}
	wellKnownURL := fmt.Sprintf("https://gateway.%s/.well-known/aun-gateway", issuer)
	discovered, err := s.discovery.Discover(ctx, wellKnownURL, 0)
	if err != nil {
		return "", err
	}
	if s.hasLocalIdentityMaterial(aid) {
		_ = s.keyStore.SetMetadataValue(aid, "gateway_url", discovered)
	}
	return discovered, nil
}

func (s *AIDStore) hasLocalIdentityMaterial(aid string) bool {
	if cert, err := s.keyStore.LoadCert(aid); err == nil && strings.TrimSpace(cert) != "" {
		return true
	}
	keyPair, err := s.keyStore.LoadKeyPair(aid)
	if err != nil || keyPair == nil {
		return false
	}
	return strings.TrimSpace(authGetStr(keyPair, "private_key_pem")) != "" ||
		strings.TrimSpace(authGetStr(keyPair, "public_key_der_b64")) != ""
}
