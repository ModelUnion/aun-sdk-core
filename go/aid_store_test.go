package aun

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"nhooyr.io/websocket"
)

// genAIDIdentity 生成测试用身份：CN==aid 的自签名证书 + P-256 私钥。
// 返回 (certPEM, privPEM, pubB64)。
func genAIDIdentity(t *testing.T, aid string, notBefore, notAfter time.Time) (string, string, string) {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: aid},
		Issuer:       pkix.Name{CommonName: "test-ca"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		t.Fatalf("编码私钥失败: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	pubDER, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)
	return certPEM, privPEM, pubB64
}

// newTestAIDStore 创建带临时目录的 AIDStore。
func newTestAIDStore(t *testing.T) *AIDStore {
	t.Helper()
	dir := t.TempDir()
	s := NewAIDStore(dir, "test-seed")
	t.Cleanup(func() { s.Close() })
	return s
}

// saveTestIdentity 将身份保存到 AIDStore 的 keystore。
func saveTestIdentity(t *testing.T, s *AIDStore, aid, certPEM, privPEM, pubB64 string) {
	t.Helper()
	ks := s.keyStore
	if err := ks.SaveIdentity(aid, map[string]any{
		"aid":                aid,
		"private_key_pem":    privPEM,
		"public_key_der_b64": pubB64,
		"curve":              "P-256",
		"cert":               certPEM,
	}); err != nil {
		t.Fatalf("保存身份失败: %v", err)
	}
}

// genAIDCertForPublicKey 使用指定公钥签发测试证书，模拟服务端为 group_aid 返回的证书。
func genAIDCertForPublicKey(t *testing.T, aid, publicKeyDerB64 string) string {
	t.Helper()
	publicKeyDER, err := base64.StdEncoding.DecodeString(publicKeyDerB64)
	if err != nil {
		t.Fatalf("测试公钥不是有效 base64: %v", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		t.Fatalf("测试公钥 DER 解析失败: %v", err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("生成测试 CA 密钥失败: %v", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.Add(time.Nanosecond).UnixNano()),
		Subject:      pkix.Name{CommonName: aid},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, tmpl, caTmpl, publicKey, caKey)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func TestAIDStoreRegisterPersistenceKeepsPrivateKeyMaterial(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "register-persist.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	// 注册路径：私钥由 AIDStore 通过 SaveKeyPair 单独保存，persistIdentity 不写私钥
	ks := s.keyStore
	if err := ks.SaveKeyPair(aid, map[string]any{
		"private_key_pem":    privPEM,
		"public_key_der_b64": pubB64,
		"curve":              "P-256",
	}); err != nil {
		t.Fatalf("SaveKeyPair 失败: %v", err)
	}
	if err := s.keyStore.SaveCert(aid, certPEM); err != nil {
		t.Fatalf("AIDStore 注册持久化失败: %v", err)
	}

	r := s.Load(aid)
	if !r.Ok {
		t.Fatalf("持久化后 Load 失败: %v", r.Error.Message)
	}
	if !r.Data.AID.IsPrivateKeyValid() {
		t.Fatal("AIDStore 注册路径必须保留私钥材料，供 AUNClient(AID) 后续连接使用")
	}
}

func TestAIDStoreImportGroupIdentitySuccess(t *testing.T) {
	s := newTestAIDStore(t)
	groupAID := "team-import.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, groupAID, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	result := s.ImportGroupIdentity(groupAID, AIDStoreImportGroupIdentityOptions{
		PrivateKeyPEM:   privPEM,
		PublicKeyDerB64: pubB64,
		Curve:           "P-256",
		CertPEM:         certPEM,
	})
	if !result.Ok {
		t.Fatalf("导入群身份失败: %s", result.Error.Message)
	}
	if !result.Data.Imported || result.Data.AID != groupAID {
		t.Fatalf("导入结果不正确: %#v", result.Data)
	}

	loaded := s.Load(groupAID)
	if !loaded.Ok {
		t.Fatalf("导入后 Load 失败: %s", loaded.Error.Message)
	}
	if _, err := loaded.Data.AID.Sign([]byte("group identity self-test")); err != nil {
		t.Fatalf("导入后的群身份必须能签名: %v", err)
	}
}

func TestAIDStoreImportGroupIdentityRejectsCNMismatch(t *testing.T) {
	s := newTestAIDStore(t)
	groupAID := "team-cn.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, "other-team.aid.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	result := s.ImportGroupIdentity(groupAID, AIDStoreImportGroupIdentityOptions{
		PrivateKeyPEM:   privPEM,
		PublicKeyDerB64: pubB64,
		CertPEM:         certPEM,
	})
	if result.Ok {
		t.Fatal("证书 CN 与 aid 不一致时应拒绝导入")
	}
	if result.Error.Code != ErrCodeCertChainBroken {
		t.Fatalf("错误码应为 %s，实际: %s", ErrCodeCertChainBroken, result.Error.Code)
	}
}

func TestAIDStoreImportGroupIdentityRejectsPublicKeyMismatch(t *testing.T) {
	s := newTestAIDStore(t)
	groupAID := "team-key.aid.com"
	certPEM, privPEM, _ := genAIDIdentity(t, groupAID, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	_, _, otherPubB64 := genAIDIdentity(t, "other-key.aid.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	result := s.ImportGroupIdentity(groupAID, AIDStoreImportGroupIdentityOptions{
		PrivateKeyPEM:   privPEM,
		PublicKeyDerB64: otherPubB64,
		CertPEM:         certPEM,
	})
	if result.Ok {
		t.Fatal("证书公钥与 public_key_der_b64 不一致时应拒绝导入")
	}
	if result.Error.Code != ErrCodeKeypairMismatch {
		t.Fatalf("错误码应为 %s，实际: %s", ErrCodeKeypairMismatch, result.Error.Code)
	}
}

func TestAIDStoreImportGroupIdentitySaveIdentityFailureUsesDedicatedErrorCode(t *testing.T) {
	s := newTestAIDStore(t)
	groupAID := "team-save-fail.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, groupAID, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	s.keyStore.Close()
	aidsRoot := filepath.Join(s.aunPath, "AIDs")
	if err := os.RemoveAll(aidsRoot); err != nil {
		t.Fatalf("清理 AIDs 目录失败: %v", err)
	}
	if err := os.WriteFile(aidsRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("创建阻塞文件失败: %v", err)
	}

	result := s.ImportGroupIdentity(groupAID, AIDStoreImportGroupIdentityOptions{
		PrivateKeyPEM:   privPEM,
		PublicKeyDerB64: pubB64,
		CertPEM:         certPEM,
	})
	if result.Ok {
		t.Fatal("SaveIdentity 失败时不应导入成功")
	}
	if result.Error.Code != ErrCodeSaveIdentityFailed {
		t.Fatalf("错误码应为 %s，实际: %s", ErrCodeSaveIdentityFailed, result.Error.Code)
	}
}

// ── AIDStore.Load ─────────────────────────────────────────────

func TestAIDStoreLoad_Success(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "alice.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)

	r := s.Load(aid)
	if !r.Ok {
		t.Fatalf("Load 失败: %v", r.Error.Message)
	}
	loaded := r.Data.AID
	if loaded.Aid != aid {
		t.Errorf("Aid 不匹配: 预期 %s 实际 %s", aid, loaded.Aid)
	}
	if !loaded.IsCertValid() {
		t.Error("证书应有效")
	}
	if !loaded.IsPrivateKeyValid() {
		t.Error("私钥应有效")
	}
	if loaded.CertSubject != aid {
		t.Errorf("CertSubject 不匹配: %s", loaded.CertSubject)
	}
	if !strings.HasPrefix(loaded.CertFingerprint, "sha256:") {
		t.Errorf("CertFingerprint 应以 sha256: 开头: %s", loaded.CertFingerprint)
	}
	if loaded.PublicKey != pubB64 {
		t.Error("PublicKey 应与证书公钥一致")
	}
}

func TestAIDStoreLoad_CertNotFound(t *testing.T) {
	s := newTestAIDStore(t)
	r := s.Load("ghost.aid.com")
	if r.Ok {
		t.Fatal("不存在的 AID 应返回错误")
	}
	if r.Error.Code != ErrCodeCertNotFound {
		t.Errorf("错误码应为 CERT_NOT_FOUND: %v", r.Error.Code)
	}
}

func TestAIDStoreLoad_CertExpired(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "expired.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)

	r := s.Load(aid)
	if r.Ok {
		t.Fatal("过期证书应返回错误")
	}
	if r.Error.Code != ErrCodeCertExpired {
		t.Errorf("错误码应为 CERT_EXPIRED: %v", r.Error.Code)
	}
}

func TestAIDStoreLoad_CertNotYetValid(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "future.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)

	r := s.Load(aid)
	if r.Ok {
		t.Fatal("尚未生效的证书应返回错误")
	}
	if r.Error.Code != ErrCodeCertNotYetValid {
		t.Errorf("错误码应为 CERT_NOT_YET_VALID: %v", r.Error.Code)
	}
}

func TestAIDStoreLoad_CertOnly(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "certonly.aid.com"
	certPEM, _, _ := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	// 仅保存证书，不保存私钥
	if err := s.keyStore.SaveCert(aid, certPEM); err != nil {
		t.Fatalf("保存证书失败: %v", err)
	}

	r := s.Load(aid)
	if !r.Ok {
		t.Fatalf("Load 失败: %v", r.Error.Message)
	}
	loaded := r.Data.AID
	if !loaded.IsCertValid() {
		t.Error("证书应有效")
	}
	if loaded.IsPrivateKeyValid() {
		t.Error("无私钥时 IsPrivateKeyValid 应为 false")
	}
}

// ── AID.Sign / Verify ─────────────────────────────────────────

func TestAIDSignVerify_RoundTrip(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "bob.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)

	r := s.Load(aid)
	if !r.Ok {
		t.Fatalf("Load 失败: %v", r.Error.Message)
	}
	loaded := r.Data.AID

	payload := []byte("hello aun")
	sig, err := loaded.Sign(payload)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}
	if sig == "" {
		t.Fatal("签名不应为空")
	}

	valid, err := loaded.Verify(payload, sig)
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	if !valid {
		t.Error("有效签名应验证通过")
	}

	// 篡改 payload
	invalid, err := loaded.Verify([]byte("tampered"), sig)
	if err != nil {
		t.Fatalf("Verify 篡改 payload 不应报错: %v", err)
	}
	if invalid {
		t.Error("篡改 payload 后应验证失败")
	}
}

func TestAIDSign_NoPrivateKey(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "nopk.aid.com"
	certPEM, _, _ := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := s.keyStore.SaveCert(aid, certPEM); err != nil {
		t.Fatalf("保存证书失败: %v", err)
	}
	r := s.Load(aid)
	if !r.Ok {
		t.Fatalf("Load 失败: %v", r.Error.Message)
	}
	loaded := r.Data.AID
	if _, err := loaded.Sign([]byte("x")); err == nil {
		t.Fatal("无私钥时 Sign 应报错")
	} else if !strings.Contains(err.Error(), ErrCodePrivateKeyNotValid) {
		t.Errorf("错误码应为 PRIVATE_KEY_NOT_VALID: %v", err)
	}
}

// ── AID.SignAgentMd / VerifyAgentMd ───────────────────────────

func TestAIDAgentMd_RoundTrip(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "carol.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)

	r := s.Load(aid)
	if !r.Ok {
		t.Fatalf("Load 失败: %v", r.Error.Message)
	}
	loaded := r.Data.AID

	content := "---\naid: carol.aid.com\n---\n# Carol Agent\n"
	signed, err := loaded.SignAgentMd(content)
	if err != nil {
		t.Fatalf("SignAgentMd 失败: %v", err)
	}
	if !strings.Contains(signed, "AUN-SIGNATURE") {
		t.Error("签名后内容应包含 AUN-SIGNATURE 块")
	}

	result, err := loaded.VerifyAgentMd(signed)
	if err != nil {
		t.Fatalf("VerifyAgentMd 失败: %v", err)
	}
	if result.Status != "verified" {
		t.Errorf("验签状态应为 verified, 实际: %s (reason=%s)", result.Status, result.Reason)
	}
	if result.AID != aid {
		t.Errorf("验签 AID 不匹配: %s", result.AID)
	}
}

func TestAIDVerifyAgentMd_Unsigned(t *testing.T) {
	s := newTestAIDStore(t)
	aid := "dave.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)

	loaded := s.Load(aid).Data.AID
	result, err := loaded.VerifyAgentMd("# plain content\n")
	if err != nil {
		t.Fatalf("VerifyAgentMd 失败: %v", err)
	}
	if result.Status != "unsigned" {
		t.Errorf("无签名内容状态应为 unsigned, 实际: %s", result.Status)
	}
}

// ── AIDStore.List ─────────────────────────────────────────────

func TestAIDStoreList(t *testing.T) {
	s := newTestAIDStore(t)
	for _, aid := range []string{"u1.aid.com", "u2.aid.com"} {
		certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)
	}
	listR := s.List()
	if !listR.Ok {
		t.Fatalf("List 失败: %v", listR.Error.Message)
	}
	if len(listR.Data.Identities) != 2 {
		t.Errorf("应列出 2 个身份, 实际: %d", len(listR.Data.Identities))
	}
}

// ── AIDStore.Resolve 错误码映射 ──────────────────────────────

// TestAIDStoreResolve_CertNotFound 验证：当 PKI 证书端点返回 404 时，
// Resolve 应将错误映射为 CERT_NOT_FOUND，而非笼统的 NETWORK_ERROR。
// 对齐 Python aid_store.py:267-268。
func TestAIDStoreResolve_CertNotFound(t *testing.T) {
	// mock 一个对所有 /pki/cert/ 请求返回 404 的 HTTPS server。
	// buildCertURL 会强制 https scheme，而 NewAIDStore 设置 VerifySSL=false
	// （InsecureSkipVerify），因此用 TLS server 才能被客户端接受。
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("certificate not found"))
	}))
	defer server.Close()

	s := newTestAIDStore(t)
	// 测试专用：直接设置内部 gateway，跳过 discovery
	s.gatewayURL = server.URL

	// 解析一个本地未缓存的 AID，强制走 PKI 拉取路径
	r := s.Resolve(context.Background(), "ghost.aid.com", AIDStoreResolveOptions{SkipAgentMD: true})
	if r.Ok {
		t.Fatal("证书 404 时 Resolve 应返回错误")
	}
	if r.Error.Code != ErrCodeCertNotFound {
		t.Errorf("证书 404 应映射为 %s, 实际错误码: %s", ErrCodeCertNotFound, r.Error.Code)
	}
}

func TestAIDStoreRenewCertSignsRawNonce(t *testing.T) {
	aid := "renew-sign.aid.com"
	certPEM, privPEM, pubB64 := genAIDIdentity(t, aid, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	s := newTestAIDStore(t)
	saveTestIdentity(t, s, aid, certPEM, privPEM, pubB64)

	authCertPEM, authPrivPEM, _ := genAIDIdentity(t, "auth.aid.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	authKey := parseTestPrivateKey(t, authPrivPEM)
	renewNonce := "renew-nonce"
	renewedCertPEM := certPEM

	var (
		mu              sync.Mutex
		renewParamsSeen map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusOK)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("接受 WebSocket 失败: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		if err := conn.Write(r.Context(), websocket.MessageText, []byte(`{"jsonrpc":"2.0","method":"challenge","params":{"nonce":"test"}}`)); err != nil {
			t.Errorf("发送 challenge 失败: %v", err)
			return
		}
		_, data, err := conn.Read(r.Context())
		if err != nil {
			t.Errorf("读取 shortRPC 请求失败: %v", err)
			return
		}
		var request map[string]any
		if err := json.Unmarshal(data, &request); err != nil {
			t.Errorf("解析 shortRPC 请求失败: %v", err)
			return
		}
		method := authGetStr(request, "method")
		params, _ := request["params"].(map[string]any)
		if params == nil {
			params = map[string]any{}
		}

		var result map[string]any
		switch method {
		case "auth.aid_login1":
			clientNonce := authGetStr(params, "client_nonce")
			sig, err := aidSignBytes(authKey, []byte(clientNonce))
			if err != nil {
				t.Errorf("签名 client_nonce 失败: %v", err)
				return
			}
			result = map[string]any{
				"success":                true,
				"request_id":             "renew-rid",
				"nonce":                  renewNonce,
				"auth_cert":              authCertPEM,
				"client_nonce_signature": base64.StdEncoding.EncodeToString(sig),
			}
		case "auth.renew_cert":
			mu.Lock()
			renewParamsSeen = cloneTestMap(params)
			mu.Unlock()
			result = map[string]any{"success": true, "cert": renewedCertPEM}
		default:
			t.Errorf("收到未预期方法: %s", method)
			result = map[string]any{"success": false, "error": "unexpected method"}
		}

		response, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      request["id"],
			"result":  result,
		})
		if err != nil {
			t.Errorf("序列化 shortRPC 响应失败: %v", err)
			return
		}
		if err := conn.Write(r.Context(), websocket.MessageText, response); err != nil {
			t.Errorf("发送 shortRPC 响应失败: %v", err)
		}
	}))
	defer server.Close()
	s.gatewayURL = gatewayWSURL(server)

	result := s.RenewCert(context.Background(), aid)
	if !result.Ok {
		t.Fatalf("RenewCert 失败: %s", result.Error.Message)
	}

	mu.Lock()
	params := cloneTestMap(renewParamsSeen)
	mu.Unlock()
	if params == nil {
		t.Fatal("未捕获 auth.renew_cert 请求")
	}
	if _, ok := params["client_time"]; ok {
		t.Fatal("auth.renew_cert 不应发送 client_time")
	}
	if got := authGetStr(params, "nonce"); got != renewNonce {
		t.Fatalf("renew nonce 不匹配: got=%q want=%q", got, renewNonce)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(authGetStr(params, "signature"))
	if err != nil {
		t.Fatalf("续期签名不是有效 base64: %v", err)
	}
	cert, err := authParsePEMCertificate(certPEM)
	if err != nil {
		t.Fatalf("解析测试证书失败: %v", err)
	}
	if err := verifySignature(cert.PublicKey, sigBytes, []byte(renewNonce)); err != nil {
		t.Fatalf("续期签名必须覆盖 raw nonce: %v", err)
	}
	if err := verifySignature(cert.PublicKey, sigBytes, []byte(renewNonce+":1234567890.0")); err == nil {
		t.Fatal("续期签名不应覆盖 nonce:client_time")
	}
}

func parseTestPrivateKey(t *testing.T, privateKeyPEM string) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		t.Fatal("测试私钥 PEM 解析失败")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("测试私钥解析失败: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("测试私钥类型错误: %T", key)
	}
	return ecKey
}

func cloneTestMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

var _ = keystore.AgentMDCacheRecord{}
