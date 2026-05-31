package aun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"nhooyr.io/websocket"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

type pendingIdentityKeyStore interface {
	keystore.FullKeyStore
	keystore.PendingIdentityKeyStore
}

// AIDRegisterResult RegisterAID 的返回结构，包含完整密钥材料供 AIDStore 保存。
type AIDRegisterResult struct {
	AID             string
	Cert            string
	PrivateKeyPEM   string
	PublicKeyDerB64 string
	Curve           string
}

// RegisterFlowConfig RegisterFlow 配置
type RegisterFlowConfig struct {
	Keystore  keystore.FullKeyStore
	Crypto    *CryptoProvider
	VerifySSL bool
	DnsNet    *DnsResilientNet
}

// RegisterFlow 处理 AID 注册流程，独立于 AuthFlow。
// 与 TS SDK RegisterFlow 对应。
type RegisterFlow struct {
	keystore          keystore.FullKeyStore
	crypto            *CryptoProvider
	verifySsl         bool
	dnsNet            *DnsResilientNet
	connectionFactory ConnectionFactory
}

// NewRegisterFlow 创建 RegisterFlow 实例
func NewRegisterFlow(cfg RegisterFlowConfig) *RegisterFlow {
	return &RegisterFlow{
		keystore:  cfg.Keystore,
		crypto:    cfg.Crypto,
		verifySsl: cfg.VerifySSL,
		dnsNet:    cfg.DnsNet,
	}
}

// RegisterAID 注册新 AID，返回完整密钥材料（私钥由调用方通过 SaveKeyPair 保存）。
func (r *RegisterFlow) RegisterAID(ctx context.Context, gatewayURL, aid string) (result AIDRegisterResult, err error) {
	tStart := time.Now()
	pkgLogAuth().Debug("RegisterFlow.RegisterAID enter: aid=%s gateway=%s", aid, gatewayURL)
	defer func() {
		if err != nil {
			pkgLogAuth().Debug("RegisterFlow.RegisterAID exit (error): aid=%s elapsed=%dms err=%v", aid, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogAuth().Debug("RegisterFlow.RegisterAID exit: aid=%s elapsed=%dms", aid, time.Since(tStart).Milliseconds())
		}
	}()

	if err = validateAIDName(aid); err != nil {
		return AIDRegisterResult{}, err
	}

	pendingStore, pendingOK := r.keystore.(pendingIdentityKeyStore)
	if !pendingOK {
		return AIDRegisterResult{}, NewAuthError("keystore does not support pending registration")
	}

	// Step 1: 本地已有身份的幂等/恢复检查
	existing, _ := r.keystore.LoadIdentity(aid)
	if existing != nil {
		hasPriv := authGetStr(existing, "private_key_pem") != ""
		hasPub := authGetStr(existing, "public_key_der_b64") != ""
		hasCert := authGetStr(existing, "cert") != ""
		if hasPriv && hasPub {
			localPubB64 := authGetStr(existing, "public_key_der_b64")
			if hasCert {
				// 本地完整身份 → 幂等校验服务端公钥匹配
				pkgLogAuth().Debug("RegisterFlow.RegisterAID: local identity complete, checking server: aid=%s", aid)
				serverCertPEM, dlErr := r.downloadRegisteredCert(ctx, gatewayURL, aid)
				if dlErr != nil {
					return AIDRegisterResult{}, dlErr
				}
				if serverCertPEM == "" {
					return AIDRegisterResult{}, NewIdentityConflictError(fmt.Sprintf(
						"AID '%s' has local keypair+cert but is not registered on server. "+
							"Remove AIDs/%s/ directory to retry registration cleanly.", aid, aid))
				}
				if !authCertMatchesPubKey(serverCertPEM, localPubB64) {
					return AIDRegisterResult{}, NewIdentityConflictError(fmt.Sprintf(
						"AID '%s' is registered by another party on server (public key mismatch). "+
							"Choose a different name.", aid))
				}
				pkgLogAuth().Info("RegisterFlow.RegisterAID: idempotent return for already-registered AID: aid=%s", aid)
				return AIDRegisterResult{
					AID:             aid,
					Cert:            authGetStr(existing, "cert"),
					PrivateKeyPEM:   authGetStr(existing, "private_key_pem"),
					PublicKeyDerB64: authGetStr(existing, "public_key_der_b64"),
					Curve:           authGetStrDefault(existing, "curve", "P-256"),
				}, nil
			}
			// 本地有 keypair 但无 cert — 尝试从服务端恢复
			pkgLogAuth().Debug("RegisterFlow.RegisterAID: local keypair exists without cert, attempting recovery: aid=%s", aid)
			serverCertPEM, dlErr := r.downloadRegisteredCert(ctx, gatewayURL, aid)
			if dlErr != nil {
				return AIDRegisterResult{}, dlErr
			}
			if serverCertPEM != "" {
				if !authCertMatchesPubKey(serverCertPEM, localPubB64) {
					return AIDRegisterResult{}, NewIdentityConflictError(fmt.Sprintf(
						"AID '%s' is registered by another party on server (public key mismatch). "+
							"Choose a different name.", aid))
				}
				// 公钥匹配 → 保存证书
				if persistErr := r.persistCert(aid, serverCertPEM); persistErr != nil {
					return AIDRegisterResult{}, persistErr
				}
				pkgLogAuth().Info("RegisterFlow.RegisterAID: recovered cert from server for half-state AID: aid=%s", aid)
				return AIDRegisterResult{
					AID:             aid,
					Cert:            serverCertPEM,
					PrivateKeyPEM:   authGetStr(existing, "private_key_pem"),
					PublicKeyDerB64: localPubB64,
					Curve:           authGetStrDefault(existing, "curve", "P-256"),
				}, nil
			}
			// 服务端未注册 → 用现有 keypair 发起注册
			pkgLogAuth().Debug("RegisterFlow.RegisterAID: server has no record, registering with existing keypair: aid=%s", aid)
			created, createErr := r.createAIDRemote(ctx, gatewayURL, existing)
			if createErr != nil {
				if authIsConflictError(createErr) {
					return AIDRegisterResult{}, NewIdentityConflictError(fmt.Sprintf("AID %s is already registered", aid))
				}
				return AIDRegisterResult{}, createErr
			}
			existing["cert"] = created["cert"]
			if assertErr := r.assertCertMatchesLocalKeypair(existing); assertErr != nil {
				return AIDRegisterResult{}, assertErr
			}
			if persistErr := r.persistCert(aid, authGetStr(existing, "cert")); persistErr != nil {
				return AIDRegisterResult{}, persistErr
			}
			return AIDRegisterResult{
				AID:             aid,
				Cert:            authGetStr(existing, "cert"),
				PrivateKeyPEM:   authGetStr(existing, "private_key_pem"),
				PublicKeyDerB64: localPubB64,
				Curve:           authGetStrDefault(existing, "curve", "P-256"),
			}, nil
		}
	}

	// Step 2: 检查 pending 残留（崩溃恢复）
	if recovered, recErr := r.tryRecoverPendingRegistration(ctx, pendingStore, gatewayURL, aid); recErr != nil {
		return AIDRegisterResult{}, recErr
	} else if recovered != nil {
		return *recovered, nil
	}

	// Step 3: 先查服务端确认未注册
	certPEM, err := r.downloadRegisteredCert(ctx, gatewayURL, aid)
	if err != nil {
		return AIDRegisterResult{}, err
	}
	if certPEM != "" {
		return AIDRegisterResult{}, NewIdentityConflictError(fmt.Sprintf("AID %s is already registered", aid))
	}

	crypto := r.crypto
	if crypto == nil {
		crypto = &CryptoProvider{}
	}
	identity, err := crypto.GenerateIdentity()
	if err != nil {
		return AIDRegisterResult{}, NewAuthError(fmt.Sprintf("failed to generate identity: %v", err))
	}
	identity["aid"] = aid

	pendingDir, err := pendingStore.PendingIdentityDir(aid)
	if err != nil {
		return AIDRegisterResult{}, err
	}
	if err := pendingStore.SavePendingKeyPair(pendingDir, aid, identity); err != nil {
		return AIDRegisterResult{}, err
	}

	created, err := r.createAIDRemote(ctx, gatewayURL, identity)
	if err != nil {
		if authIsConflictError(err) {
			return AIDRegisterResult{}, NewIdentityConflictError(fmt.Sprintf("AID %s is already registered", aid))
		}
		return AIDRegisterResult{}, err
	}
	identity["cert"] = created["cert"]
	if err = r.assertCertMatchesLocalKeypair(identity); err != nil {
		return AIDRegisterResult{}, err
	}
	if err = pendingStore.SavePendingCert(pendingDir, authGetStr(identity, "cert")); err != nil {
		return AIDRegisterResult{}, err
	}
	if _, err = pendingStore.PromotePendingIdentity(pendingDir, aid); err != nil {
		return AIDRegisterResult{}, NewIdentityConflictError(fmt.Sprintf(
			"AID '%s' was created by another process during registration; pending record kept for cleanup.", aid))
	}
	// 只保存证书与非私钥字段
	if err = r.persistCert(aid, authGetStr(identity, "cert")); err != nil {
		return AIDRegisterResult{}, err
	}
	return AIDRegisterResult{
		AID:             aid,
		Cert:            authGetStr(identity, "cert"),
		PrivateKeyPEM:   authGetStr(identity, "private_key_pem"),
		PublicKeyDerB64: authGetStr(identity, "public_key_der_b64"),
		Curve:           authGetStrDefault(identity, "curve", "P-256"),
	}, nil
}

func (r *RegisterFlow) tryRecoverPendingRegistration(ctx context.Context, store pendingIdentityKeyStore, gatewayURL, aid string) (*AIDRegisterResult, error) {
	handles, err := store.ListPendingIdentityDirs(aid)
	if err != nil {
		return nil, err
	}
	for _, pendingDir := range handles {
		keyPair, kpErr := store.LoadPendingKeyPair(pendingDir, aid)
		if kpErr != nil {
			return nil, kpErr
		}
		if keyPair == nil {
			_ = store.DiscardPendingIdentity(pendingDir)
			continue
		}
		privateKeyPEM := authGetStr(keyPair, "private_key_pem")
		publicKeyDerB64 := authGetStr(keyPair, "public_key_der_b64")
		if privateKeyPEM == "" || publicKeyDerB64 == "" {
			_ = store.DiscardPendingIdentity(pendingDir)
			continue
		}
		serverCertPEM, dlErr := r.downloadRegisteredCert(ctx, gatewayURL, aid)
		if dlErr != nil {
			return nil, dlErr
		}
		if serverCertPEM == "" {
			_ = store.DiscardPendingIdentity(pendingDir)
			return nil, nil
		}
		if !authCertMatchesPubKey(serverCertPEM, publicKeyDerB64) {
			_ = store.DiscardPendingIdentity(pendingDir)
			return nil, NewIdentityConflictError(fmt.Sprintf(
				"AID '%s' has been registered by another party while local pending registration was incomplete; local pending key discarded.", aid))
		}
		identity := map[string]any{
			"aid":                aid,
			"cert":               serverCertPEM,
			"private_key_pem":    privateKeyPEM,
			"public_key_der_b64": publicKeyDerB64,
			"curve":              authGetStrDefault(keyPair, "curve", "P-256"),
		}
		if err := store.SavePendingKeyPair(pendingDir, aid, identity); err != nil {
			return nil, err
		}
		if err := store.SavePendingCert(pendingDir, serverCertPEM); err != nil {
			return nil, err
		}
		if _, err := store.PromotePendingIdentity(pendingDir, aid); err != nil {
			return nil, NewIdentityConflictError(fmt.Sprintf(
				"AID '%s' was created by another process during recovery; pending record kept for cleanup.", aid))
		}
		if err := r.persistCert(aid, serverCertPEM); err != nil {
			return nil, err
		}
		return &AIDRegisterResult{
			AID:             aid,
			Cert:            serverCertPEM,
			PrivateKeyPEM:   privateKeyPEM,
			PublicKeyDerB64: publicKeyDerB64,
			Curve:           authGetStrDefault(keyPair, "curve", "P-256"),
		}, nil
	}
	return nil, nil
}

// persistCert 只保存证书，不写私钥字段
func (r *RegisterFlow) persistCert(aid, certPEM string) error {
	return r.keystore.SaveCert(aid, certPEM)
}

// createAIDRemote 通过 shortRPC 在服务端注册 AID
func (r *RegisterFlow) createAIDRemote(ctx context.Context, gatewayURL string, identity map[string]any) (map[string]any, error) {
	response, err := r.shortRPC(ctx, gatewayURL, "auth.create_aid", map[string]any{
		"aid":        identity["aid"],
		"public_key": identity["public_key_der_b64"],
		"curve":      authGetStrDefault(identity, "curve", "P-256"),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"cert": response["cert"]}, nil
}

// downloadRegisteredCert 下载已注册 AID 的证书；404 表示未注册，返回空字符串。
func (r *RegisterFlow) downloadRegisteredCert(ctx context.Context, gatewayURL string, aid string) (string, error) {
	certURL := authGatewayHTTPURL(gatewayURL, fmt.Sprintf("/pki/cert/%s", aid))
	client := r.httpClient()
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, certURL, nil)
	if err != nil {
		return "", NewAuthError(fmt.Sprintf("failed to create certificate request for %s", aid))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", NewAuthError(fmt.Sprintf("failed to download certificate for %s: %v", aid, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", NewAuthError(fmt.Sprintf("failed to download certificate for %s: HTTP %d", aid, resp.StatusCode))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", NewAuthError(fmt.Sprintf("failed to read certificate response for %s", aid))
	}
	certPEM := string(body)
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		return "", nil
	}
	return certPEM, nil
}

// assertCertMatchesLocalKeypair 验证证书公钥与本地 public_key_der_b64 一致。
func (r *RegisterFlow) assertCertMatchesLocalKeypair(identity map[string]any) error {
	aid := authGetStr(identity, "aid")
	certPEM := authGetStr(identity, "cert")
	if certPEM == "" {
		return NewAuthError(fmt.Sprintf("certificate missing for %s", aid))
	}
	localPubB64 := authGetStr(identity, "public_key_der_b64")
	if localPubB64 == "" {
		return NewAuthError(fmt.Sprintf("local public key missing for %s", aid))
	}
	cert, err := authParsePEMCertificate(certPEM)
	if err != nil {
		return NewAuthError(fmt.Sprintf("failed to parse downloaded certificate for %s", aid))
	}
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return NewAuthError("failed to marshal downloaded certificate public key")
	}
	localPubDER, err := base64.StdEncoding.DecodeString(localPubB64)
	if err != nil {
		return NewAuthError("failed to decode local public key")
	}
	if !authBytesEqual(certPubDER, localPubDER) {
		return NewAuthError(fmt.Sprintf(
			"downloaded certificate public key does not match local key pair for %s. "+
				"The server has a different key registered - this AID cannot be recovered with the current key.", aid))
	}
	return nil
}

// shortRPC 开启临时 WebSocket，接收 challenge，发送 JSON-RPC 请求，接收响应，关闭。
func (r *RegisterFlow) shortRPC(ctx context.Context, gatewayURL string, method string, params map[string]any) (map[string]any, error) {
	conn, err := r.dialWebSocket(ctx, gatewayURL)
	if err != nil {
		return nil, NewConnectionError(fmt.Sprintf("shortRPC connection failed: %v", err))
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	rCtx, rCancel := context.WithTimeout(ctx, 10*time.Second)
	defer rCancel()
	if _, _, err = conn.Read(rCtx); err != nil {
		return nil, NewConnectionError(fmt.Sprintf("shortRPC failed to receive challenge: %v", err))
	}

	request := map[string]any{
		"jsonrpc": "2.0",
		"id":      fmt.Sprintf("pre-%s", method),
		"method":  method,
		"params":  params,
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, NewSerializationError(fmt.Sprintf("shortRPC failed to serialize request: %v", err))
	}
	pkgLogAuth().Debug("RegisterFlow short RPC request: %s", string(data))
	wCtx, wCancel := context.WithTimeout(ctx, 5*time.Second)
	defer wCancel()
	if err := conn.Write(wCtx, websocket.MessageText, data); err != nil {
		return nil, NewConnectionError(fmt.Sprintf("shortRPC failed to send request: %v", err))
	}

	rCtx2, rCancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer rCancel2()
	_, respData, err := conn.Read(rCtx2)
	if err != nil {
		return nil, NewConnectionError(fmt.Sprintf("shortRPC failed to receive response: %v", err))
	}

	var message map[string]any
	if err := json.Unmarshal(respData, &message); err != nil {
		return nil, NewSerializationError("shortRPC response is not valid JSON")
	}
	pkgLogAuth().Debug("RegisterFlow short RPC response: method=%s %s", method, string(respData))

	if errData, ok := message["error"]; ok {
		if errMap, ok := errData.(map[string]any); ok {
			return nil, MapRemoteError(errMap)
		}
	}
	result, ok := message["result"].(map[string]any)
	if !ok {
		return nil, NewValidationError(fmt.Sprintf("invalid pre-auth response for %s", method))
	}
	if success, ok := result["success"]; ok {
		if s, ok := success.(bool); ok && !s {
			errMsg := fmt.Sprintf("%s failed", method)
			if e, ok := result["error"].(string); ok {
				errMsg = e
			}
			return nil, NewAuthError(errMsg)
		}
	}
	return result, nil
}

// dialWebSocket 建立临时 WebSocket 连接
func (r *RegisterFlow) dialWebSocket(ctx context.Context, gatewayURL string) (*websocket.Conn, error) {
	if r.connectionFactory != nil {
		return r.connectionFactory(ctx, gatewayURL)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	opts := &websocket.DialOptions{}
	if !r.verifySsl {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	conn, _, err := websocket.Dial(dialCtx, gatewayURL, opts)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// httpClient 创建 HTTP 客户端
func (r *RegisterFlow) httpClient() *http.Client {
	transport := &http.Transport{}
	if !r.verifySsl {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: transport}
}
