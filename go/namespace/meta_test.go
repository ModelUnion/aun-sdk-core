package namespace

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// ── Mock 客户端 ──────────────────────────────────────────

type mockMetaClient struct {
	gatewayURL       string
	discoveryPort    int
	verifySSL        bool
	keyStoreRootPath string
	callMethod       string
	callResult       any
	callErr          error
	trustRootStore   keystore.TrustRootStore
	reloadCount      int
}

func (m *mockMetaClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
	m.callMethod = method
	return m.callResult, m.callErr
}

func (m *mockMetaClient) GetGatewayURL() string {
	return m.gatewayURL
}

func (m *mockMetaClient) GetConfigDiscoveryPort() int {
	return m.discoveryPort
}

func (m *mockMetaClient) GetConfigVerifySSL() bool {
	return m.verifySSL
}

func (m *mockMetaClient) GetKeyStoreRootPath() string {
	return m.keyStoreRootPath
}

func (m *mockMetaClient) GetTrustRootStore() keystore.TrustRootStore {
	return m.trustRootStore
}

func (m *mockMetaClient) ReloadTrustedRoots() int {
	m.reloadCount++
	return m.reloadCount
}

// ── TestMetaPingStatusTrustRoots ──────────────────────────

func TestMetaPingStatusTrustRoots(t *testing.T) {
	client := &mockMetaClient{
		callResult: map[string]any{"status": "ok"},
	}
	meta := NewMetaNamespace(client)
	ctx := context.Background()

	// Ping
	result, err := meta.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping 失败: %v", err)
	}
	if client.callMethod != "meta.ping" {
		t.Fatalf("Ping 调用方法不正确: %s", client.callMethod)
	}
	resultMap, ok := result.(map[string]any)
	if !ok || resultMap["status"] != "ok" {
		t.Fatalf("Ping 返回值不正确: %v", result)
	}

	// Status
	client.callResult = map[string]any{"connected": true}
	result, err = meta.Status(ctx)
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if client.callMethod != "meta.status" {
		t.Fatalf("Status 调用方法不正确: %s", client.callMethod)
	}

	// TrustRoots
	client.callResult = map[string]any{"roots": []any{}}
	result, err = meta.TrustRoots(ctx)
	if err != nil {
		t.Fatalf("TrustRoots 失败: %v", err)
	}
	if client.callMethod != "meta.trust_roots" {
		t.Fatalf("TrustRoots 调用方法不正确: %s", client.callMethod)
	}
}

// ── TestMetaIssuerURLs ──────────────────────────────────

func TestMetaIssuerURLs(t *testing.T) {
	tests := []struct {
		issuer    string
		wantTrust string
		wantCert  string
	}{
		{
			issuer:    "aid.com",
			wantTrust: "https://pki.aid.com/trust-root.json",
			wantCert:  "https://pki.aid.com/root.crt",
		},
		{
			issuer:    "example.org",
			wantTrust: "https://pki.example.org/trust-root.json",
			wantCert:  "https://pki.example.org/root.crt",
		},
	}

	for _, tt := range tests {
		gotTrust := IssuerTrustRootURL(tt.issuer)
		if gotTrust != tt.wantTrust {
			t.Errorf("IssuerTrustRootURL(%q) = %q, want %q", tt.issuer, gotTrust, tt.wantTrust)
		}
		gotCert := IssuerRootCertURL(tt.issuer)
		if gotCert != tt.wantCert {
			t.Errorf("IssuerRootCertURL(%q) = %q, want %q", tt.issuer, gotCert, tt.wantCert)
		}
	}
}

// ── TestMetaGatewayTrustRootsURL ──────────────────────────

func TestMetaGatewayTrustRootsURL(t *testing.T) {
	tests := []struct {
		gatewayURL string
		want       string
	}{
		{
			gatewayURL: "wss://gateway.aid.com/ws",
			want:       "https://gateway.aid.com/pki/trust-roots.json",
		},
		{
			gatewayURL: "ws://localhost:8080/ws",
			want:       "http://localhost:8080/pki/trust-roots.json",
		},
		{
			gatewayURL: "wss://gateway.example.org:443/aun",
			want:       "https://gateway.example.org:443/pki/trust-roots.json",
		},
		{
			gatewayURL: "ws://127.0.0.1:9000",
			want:       "http://127.0.0.1:9000/pki/trust-roots.json",
		},
	}

	for _, tt := range tests {
		got := GatewayTrustRootsURL(tt.gatewayURL)
		if got != tt.want {
			t.Errorf("GatewayTrustRootsURL(%q) = %q, want %q", tt.gatewayURL, got, tt.want)
		}
	}
}

// ── TestMetaVerifyRejectsUnsigned ──────────────────────────

func TestMetaVerifyRejectsUnsigned(t *testing.T) {
	meta := NewMetaNamespace(&mockMetaClient{})

	// 缺少 roots 字段
	_, err := meta.VerifyTrustRoots(map[string]any{}, nil)
	if err == nil {
		t.Fatal("应拒绝缺少 roots 字段的 trust_list")
	}
	if !strings.Contains(err.Error(), "roots") {
		t.Fatalf("错误信息应包含 'roots': %v", err)
	}

	// roots 格式无效
	_, err = meta.VerifyTrustRoots(map[string]any{"roots": "invalid"}, nil)
	if err == nil {
		t.Fatal("应拒绝 roots 格式无效的 trust_list")
	}

	// 无效 PEM
	_, err = meta.VerifyTrustRoots(map[string]any{
		"roots": []any{
			map[string]any{"id": "bad", "cert_pem": "not-a-pem"},
		},
	}, nil)
	if err == nil {
		t.Fatal("应拒绝无效 PEM 的根证书")
	}
}

// ── TestMetaVerifyValidSelfSignedRoot ──────────────────────

func TestMetaVerifyValidSelfSignedRoot(t *testing.T) {
	// 生成自签名根证书
	certPEM, _ := generateSelfSignedCert(t)

	meta := NewMetaNamespace(&mockMetaClient{})
	trustList := map[string]any{
		"version": float64(1),
		"roots": []any{
			map[string]any{
				"id":       "test-root",
				"cert_pem": certPEM,
			},
		},
	}

	verified, err := meta.VerifyTrustRoots(trustList, nil)
	if err != nil {
		t.Fatalf("验证自签名根证书失败: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("期望 1 个已验证证书，实际 %d", len(verified))
	}
	if verified[0]["id"] != "test-root" {
		t.Fatalf("已验证证书 ID 不正确: %s", verified[0]["id"])
	}
	if !strings.HasPrefix(verified[0]["fingerprint"], "sha256:") {
		t.Fatalf("指纹格式不正确: %s", verified[0]["fingerprint"])
	}
}

// ── TestMetaDownloadTrustRoots ──────────────────────────

func TestMetaDownloadTrustRoots(t *testing.T) {
	trustData := map[string]any{
		"version": 1,
		"roots":   []any{},
	}
	body, _ := json.Marshal(trustData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pki/trust-roots.json" {
			t.Errorf("请求路径不正确: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()

	client := &mockMetaClient{
		gatewayURL: strings.Replace(server.URL, "http://", "ws://", 1),
		verifySSL:  false,
	}
	meta := NewMetaNamespace(client)

	result, err := meta.DownloadTrustRoots(context.Background(), nil)
	if err != nil {
		t.Fatalf("DownloadTrustRoots 失败: %v", err)
	}
	if result["version"] == nil {
		t.Fatal("返回结果缺少 version 字段")
	}
}

// ── TestMetaDownloadIssuerRootCert ──────────────────────────

func TestMetaDownloadIssuerRootCert(t *testing.T) {
	certPEM, _ := generateSelfSignedCert(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(certPEM))
	}))
	defer server.Close()

	client := &mockMetaClient{verifySSL: false}
	meta := NewMetaNamespace(client)

	result, err := meta.DownloadIssuerRootCert(context.Background(), "aid.com", &DownloadIssuerRootCertOptions{
		URL: server.URL + "/root.crt",
	})
	if err != nil {
		t.Fatalf("DownloadIssuerRootCert 失败: %v", err)
	}
	if !strings.Contains(result, "BEGIN CERTIFICATE") {
		t.Fatal("返回结果不包含 PEM 证书")
	}
}

// ── TestMetaVerifyFingerprintMismatch ──────────────────────

func TestMetaVerifyFingerprintMismatch(t *testing.T) {
	certPEM, _ := generateSelfSignedCert(t)

	meta := NewMetaNamespace(&mockMetaClient{})
	trustList := map[string]any{
		"roots": []any{
			map[string]any{
				"id":       "test-root",
				"cert_pem": certPEM,
			},
		},
	}

	// 使用错误的期望指纹
	_, err := meta.VerifyTrustRoots(trustList, &VerifyTrustRootsOptions{
		ExpectedFingerprints: []string{"sha256:0000000000000000000000000000000000000000000000000000000000000000"},
	})
	if err == nil {
		t.Fatal("应拒绝指纹不匹配的根证书")
	}
	if !strings.Contains(err.Error(), "不在期望列表中") {
		t.Fatalf("错误信息应包含指纹不匹配提示: %v", err)
	}
}

// ── TestMetaVerifySignatureRejectsInvalid ──────────────────

func TestMetaVerifySignatureRejectsInvalid(t *testing.T) {
	certPEM, _ := generateSelfSignedCert(t)

	meta := NewMetaNamespace(&mockMetaClient{})
	trustList := map[string]any{
		"roots": []any{
			map[string]any{
				"id":       "test-root",
				"cert_pem": certPEM,
			},
		},
		"signature":       hex.EncodeToString([]byte("fake-signature")),
		"signer_cert_pem": certPEM,
		"signed_data":     "some-data-to-sign",
	}

	// 签名无效应报错
	_, err := meta.VerifyTrustRoots(trustList, nil)
	if err == nil {
		t.Fatal("应拒绝无效签名的 trust_list")
	}
	if !strings.Contains(err.Error(), "签名验证失败") {
		t.Fatalf("错误信息应包含签名验证失败: %v", err)
	}
}

// ── 辅助函数 ──────────────────────────────────────────────

// generateSelfSignedCert 生成自签名 P-256 根证书，返回 (certPEM, keyPEM)
func generateSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM)
}

// generateSignedTrustList 生成带有效签名的 trust list（用于正向测试）
func generateSignedTrustList(t *testing.T) (map[string]any, string) {
	t.Helper()

	certPEM, keyPEM := generateSelfSignedCert(t)

	signedData := `{"roots":[{"id":"test"}]}`
	hash := sha256.Sum256([]byte(signedData))

	block, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}

	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	trustList := map[string]any{
		"version": float64(1),
		"roots": []any{
			map[string]any{
				"id":       "test-root",
				"cert_pem": certPEM,
			},
		},
		"signature":       hex.EncodeToString(sig),
		"signer_cert_pem": certPEM,
		"signed_data":     signedData,
	}

	return trustList, certPEM
}

// TestMetaVerifyValidSignature 验证有效签名的 trust list 通过
func TestMetaVerifyValidSignature(t *testing.T) {
	trustList, _ := generateSignedTrustList(t)

	meta := NewMetaNamespace(&mockMetaClient{})
	verified, err := meta.VerifyTrustRoots(trustList, nil)
	if err != nil {
		t.Fatalf("验证有效签名的 trust_list 失败: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("期望 1 个已验证证书，实际 %d", len(verified))
	}
}

func TestMetaImportTrustRootsPersistsAndReloads(t *testing.T) {
	trustList, _ := generateSignedTrustList(t)

	root := t.TempDir()
	ks, err := keystore.NewFileKeyStore(root, nil, "")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	client := &mockMetaClient{trustRootStore: ks}
	meta := NewMetaNamespace(client)

	verified, err := meta.ImportTrustRoots(trustList, nil)
	if err != nil {
		t.Fatalf("ImportTrustRoots 失败: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("期望导入 1 个根证书，实际 %d", len(verified))
	}
	if client.reloadCount != 1 {
		t.Fatalf("期望 reload 1 次，实际 %d", client.reloadCount)
	}

	for _, name := range []string{"trust-roots.json", "trust-roots.pem"} {
		if _, err := os.Stat(filepath.Join(root, "CA", "root", name)); err != nil {
			t.Fatalf("期望写入 %s: %v", name, err)
		}
	}
}

func TestMetaImportTrustRootsRejectsVersionRollback(t *testing.T) {
	trustList, _ := generateSignedTrustList(t)
	trustList["version"] = float64(2)

	root := t.TempDir()
	ks, err := keystore.NewFileKeyStore(root, nil, "")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	meta := NewMetaNamespace(&mockMetaClient{trustRootStore: ks})

	if _, err := meta.ImportTrustRoots(trustList, nil); err != nil {
		t.Fatalf("首次 ImportTrustRoots 失败: %v", err)
	}

	rollback := map[string]any{}
	for k, v := range trustList {
		rollback[k] = v
	}
	rollback["version"] = float64(1)
	if _, err := meta.ImportTrustRoots(rollback, nil); err == nil {
		t.Fatalf("版本回退应被拒绝")
	}
}

func TestMetaUpdateIssuerRootCertPersistsAndReloads(t *testing.T) {
	certPEM, _ := generateSelfSignedCert(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(certPEM))
	}))
	defer srv.Close()

	root := t.TempDir()
	ks, err := keystore.NewFileKeyStore(root, nil, "")
	if err != nil {
		t.Fatalf("创建 FileKeyStore 失败: %v", err)
	}
	client := &mockMetaClient{trustRootStore: ks}
	meta := NewMetaNamespace(client)

	_, fingerprint, err := meta.UpdateIssuerRootCert(context.Background(), "example.com", &UpdateIssuerRootCertOptions{
		URL: srv.URL,
	})
	if err != nil {
		t.Fatalf("UpdateIssuerRootCert 失败: %v", err)
	}
	if !strings.HasPrefix(fingerprint, "sha256:") {
		t.Fatalf("fingerprint 格式不正确: %s", fingerprint)
	}
	if client.reloadCount != 1 {
		t.Fatalf("期望 reload 1 次，实际 %d", client.reloadCount)
	}
	if _, err := os.Stat(filepath.Join(root, "CA", "root", "issuers", "example.com.root.crt")); err != nil {
		t.Fatalf("期望写入 issuer 根证书: %v", err)
	}
}
