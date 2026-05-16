package namespace

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mockAuthClient struct {
	gatewayURL            string
	aid                   string
	discoveryPort         int
	verifySSL             bool
	identity              map[string]any
	authResult            map[string]any
	authAuthenticateCalls int
	discoverGatewayResult string
	discoverGatewayErr    error
	fetchPeerCertResult   []byte
	fetchPeerCertErr      error
	fetchPeerCertCalls    int
	cachedGatewayURL      string
	persistedGatewayURL   string
	persistGatewayCalls   int
	loadCachedGatewayCalls int
}

func (m *mockAuthClient) GetGatewayURL() string {
	return m.gatewayURL
}

func (m *mockAuthClient) SetGatewayURL(url string) {
	m.gatewayURL = url
}

func (m *mockAuthClient) GetAID() string {
	return m.aid
}

func (m *mockAuthClient) SetAID(aid string) {
	m.aid = aid
}

func (m *mockAuthClient) GetConfigDiscoveryPort() int {
	return m.discoveryPort
}

func (m *mockAuthClient) GetConfigVerifySSL() bool {
	return m.verifySSL
}

func (m *mockAuthClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
	return nil, nil
}

func (m *mockAuthClient) AuthCreateAID(ctx context.Context, gatewayURL, aid string) (map[string]any, error) {
	return nil, nil
}

func (m *mockAuthClient) AuthAuthenticate(ctx context.Context, gatewayURL, aid string) (map[string]any, error) {
	m.authAuthenticateCalls++
	return m.authResult, nil
}

func (m *mockAuthClient) AuthLoadIdentityOrNil(aid string) map[string]any {
	return m.identity
}

func (m *mockAuthClient) AuthFetchPeerCert(ctx context.Context, aid, certFingerprint string) ([]byte, error) {
	m.fetchPeerCertCalls++
	return m.fetchPeerCertResult, m.fetchPeerCertErr
}

func (m *mockAuthClient) DiscoverGateway(ctx context.Context, wellKnownURL string, timeout time.Duration) (string, error) {
	return m.discoverGatewayResult, m.discoverGatewayErr
}

func (m *mockAuthClient) SetIdentity(identity map[string]any) {
	m.identity = identity
}

func (m *mockAuthClient) AuthLoadCachedGatewayURL(aid string) string {
	m.loadCachedGatewayCalls++
	return m.cachedGatewayURL
}

func (m *mockAuthClient) AuthPersistGatewayURL(aid, gatewayURL string) {
	m.persistGatewayCalls++
	m.persistedGatewayURL = gatewayURL
}

func makeIdentity(t *testing.T, aid string) map[string]any {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	certPEM := makeSelfSignedCert(t, privateKey, aid)
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key failed: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	return map[string]any{
		"aid":             aid,
		"private_key_pem": string(privateKeyPEM),
		"cert":            certPEM,
		"cert_pem":        certPEM,
	}
}

func makeSelfSignedCert(t *testing.T, privateKey *ecdsa.PrivateKey, cn string) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate failed: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestUploadAgentMDUsesCachedAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/agent.md" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer cached-token" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "text/markdown") {
			t.Fatalf("unexpected content-type: %s", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body failed: %v", err)
		}
		if string(body) != "# Alice\n" {
			t.Fatalf("unexpected body: %s", string(body))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"aid": r.Host, "etag": "\"etag-1\""})
	}))
	defer server.Close()

	client := &mockAuthClient{
		gatewayURL: "ws://gateway.example.com/aun",
		aid:        strings.TrimPrefix(server.URL, "http://"),
		verifySSL:  true,
		identity: map[string]any{
			"aid":                     strings.TrimPrefix(server.URL, "http://"),
			"access_token":            "cached-token",
			"access_token_expires_at": float64(time.Now().Add(time.Hour).Unix()),
		},
	}

	ns := NewAuthNamespace(client)
	result, err := ns.UploadAgentMD(context.Background(), "# Alice\n")
	if err != nil {
		t.Fatalf("UploadAgentMD failed: %v", err)
	}
	if client.authAuthenticateCalls != 0 {
		t.Fatalf("unexpected authenticate calls: %d", client.authAuthenticateCalls)
	}
	if got, _ := result["etag"].(string); got != "\"etag-1\"" {
		t.Fatalf("unexpected etag: %v", result["etag"])
	}
}

func TestUploadAgentMDFallsBackToAuthenticate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fresh-token" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"aid": r.Host, "etag": "\"etag-2\""})
	}))
	defer server.Close()

	aid := strings.TrimPrefix(server.URL, "http://")
	client := &mockAuthClient{
		gatewayURL: "ws://gateway.example.com/aun",
		aid:        aid,
		verifySSL:  true,
		identity: map[string]any{
			"aid": aid,
		},
		authResult: map[string]any{
			"aid":          aid,
			"access_token": "fresh-token",
			"gateway":      "ws://gateway.example.com/aun",
		},
	}

	ns := NewAuthNamespace(client)
	result, err := ns.UploadAgentMD(context.Background(), "# Alice\n")
	if err != nil {
		t.Fatalf("UploadAgentMD failed: %v", err)
	}
	if client.authAuthenticateCalls != 1 {
		t.Fatalf("expected authenticate once, got %d", client.authAuthenticateCalls)
	}
	if got, _ := result["etag"].(string); got != "\"etag-2\"" {
		t.Fatalf("unexpected etag: %v", result["etag"])
	}
}

func TestDownloadAgentMDIsAnonymous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("authorization header should be empty, got %s", got)
		}
		if got := r.Header.Get("Accept"); got != "text/markdown" {
			t.Fatalf("unexpected accept header: %s", got)
		}
		_, _ = w.Write([]byte("# Bob\n"))
	}))
	defer server.Close()

	client := &mockAuthClient{
		gatewayURL: "ws://gateway.example.com/aun",
		verifySSL:  true,
	}

	ns := NewAuthNamespace(client)
	agentMD, err := ns.DownloadAgentMD(context.Background(), strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("DownloadAgentMD failed: %v", err)
	}
	if agentMD != "# Bob\n" {
		t.Fatalf("unexpected agent.md: %s", agentMD)
	}
}

func TestAgentMDHTTPClientIsReused(t *testing.T) {
	client := &mockAuthClient{verifySSL: true}
	ns := NewAuthNamespace(client)

	httpClient1 := ns.agentMDHTTPClient()
	httpClient2 := ns.agentMDHTTPClient()

	if httpClient1 == nil || httpClient2 == nil {
		t.Fatal("agentMDHTTPClient returned nil")
	}
	if httpClient1 != httpClient2 {
		t.Fatal("agentMDHTTPClient should reuse the same client instance")
	}
}

func sampleAgentMD(aid string) string {
	return "---\n" +
		"aid: \"" + aid + "\"\n" +
		"name: \"Alice\"\n" +
		"type: \"assistant\"\n" +
		"version: \"1.0.0\"\n" +
		"description: \"Alice\"\n" +
		"---\n\n" +
		"# Alice\n"
}

func TestSignAgentMDAppendsTailSignature(t *testing.T) {
	identity := makeIdentity(t, "alice.agentid.pub")
	client := &mockAuthClient{
		aid:      identity["aid"].(string),
		identity: identity,
	}
	ns := NewAuthNamespace(client)

	signed, err := ns.SignAgentMD(context.Background(), sampleAgentMD(identity["aid"].(string)), nil)
	if err != nil {
		t.Fatalf("SignAgentMD failed: %v", err)
	}
	if !strings.HasPrefix(signed, sampleAgentMD(identity["aid"].(string))) {
		t.Fatalf("signed content should keep payload prefix: %s", signed)
	}
	if strings.Count(signed, "<!-- AUN-SIGNATURE") != 1 {
		t.Fatalf("expected one signature block, got: %s", signed)
	}
	if !strings.HasSuffix(strings.TrimSpace(signed), "-->") {
		t.Fatalf("signature block should be tail block: %s", signed)
	}
}

func TestVerifyAgentMDUnsignedReturnsUnsigned(t *testing.T) {
	client := &mockAuthClient{}
	ns := NewAuthNamespace(client)

	result, err := ns.VerifyAgentMD(context.Background(), sampleAgentMD("alice.agentid.pub"), nil)
	if err != nil {
		t.Fatalf("VerifyAgentMD failed: %v", err)
	}
	if got, _ := result["status"].(string); got != "unsigned" {
		t.Fatalf("unexpected status: %#v", result["status"])
	}
	if got, _ := result["verified"].(bool); got {
		t.Fatalf("unsigned result should not be verified: %#v", result["verified"])
	}
}

func TestVerifyAgentMDRoundTrip(t *testing.T) {
	identity := makeIdentity(t, "alice.agentid.pub")
	client := &mockAuthClient{
		aid:      identity["aid"].(string),
		identity: identity,
	}
	ns := NewAuthNamespace(client)

	payload := sampleAgentMD(identity["aid"].(string))
	signed, err := ns.SignAgentMD(context.Background(), payload, nil)
	if err != nil {
		t.Fatalf("SignAgentMD failed: %v", err)
	}

	result, err := ns.VerifyAgentMD(context.Background(), signed, &AgentMDVerifyOptions{
		AID:     identity["aid"].(string),
		CertPEM: identity["cert"].(string),
	})
	if err != nil {
		t.Fatalf("VerifyAgentMD failed: %v", err)
	}
	if got, _ := result["status"].(string); got != "verified" {
		t.Fatalf("unexpected status: %#v", result["status"])
	}
	if got, _ := result["verified"].(bool); !got {
		t.Fatalf("verified result should be true: %#v", result["verified"])
	}
	if got, _ := result["payload"].(string); got != payload {
		t.Fatalf("unexpected payload: %q", got)
	}
}

func TestVerifyAgentMDRejectsTamper(t *testing.T) {
	identity := makeIdentity(t, "alice.agentid.pub")
	client := &mockAuthClient{
		aid:      identity["aid"].(string),
		identity: identity,
	}
	ns := NewAuthNamespace(client)

	payload := sampleAgentMD(identity["aid"].(string))
	signed, err := ns.SignAgentMD(context.Background(), payload, nil)
	if err != nil {
		t.Fatalf("SignAgentMD failed: %v", err)
	}
	tampered := strings.Replace(signed, "Alice", "Mallory", 1)

	result, err := ns.VerifyAgentMD(context.Background(), tampered, &AgentMDVerifyOptions{
		AID:     identity["aid"].(string),
		CertPEM: identity["cert"].(string),
	})
	if err != nil {
		t.Fatalf("VerifyAgentMD failed: %v", err)
	}
	if got, _ := result["status"].(string); got != "invalid" {
		t.Fatalf("unexpected status: %#v", result["status"])
	}
}

func TestSignAgentMDReplacesExistingSignature(t *testing.T) {
	identity := makeIdentity(t, "alice.agentid.pub")
	client := &mockAuthClient{
		aid:      identity["aid"].(string),
		identity: identity,
	}
	ns := NewAuthNamespace(client)

	payload := sampleAgentMD(identity["aid"].(string))
	signedOnce, err := ns.SignAgentMD(context.Background(), payload, nil)
	if err != nil {
		t.Fatalf("SignAgentMD failed: %v", err)
	}
	signedTwice, err := ns.SignAgentMD(context.Background(), signedOnce, nil)
	if err != nil {
		t.Fatalf("SignAgentMD failed: %v", err)
	}
	if strings.Count(signedTwice, "<!-- AUN-SIGNATURE") != 1 {
		t.Fatalf("expected one signature block, got: %s", signedTwice)
	}
}

func TestVerifyAgentMDFetchesPeerCert(t *testing.T) {
	identity := makeIdentity(t, "alice.agentid.pub")
	client := &mockAuthClient{
		aid:                 identity["aid"].(string),
		identity:            identity,
		fetchPeerCertResult: []byte(identity["cert"].(string)),
	}
	ns := NewAuthNamespace(client)

	payload := sampleAgentMD(identity["aid"].(string))
	signed, err := ns.SignAgentMD(context.Background(), payload, nil)
	if err != nil {
		t.Fatalf("SignAgentMD failed: %v", err)
	}

	result, err := ns.VerifyAgentMD(context.Background(), signed, &AgentMDVerifyOptions{AID: identity["aid"].(string)})
	if err != nil {
		t.Fatalf("VerifyAgentMD failed: %v", err)
	}
	if got, _ := result["status"].(string); got != "verified" {
		t.Fatalf("unexpected status: %#v", result["status"])
	}
	if client.fetchPeerCertCalls != 1 {
		t.Fatalf("expected fetchPeerCert to be called once, got %d", client.fetchPeerCertCalls)
	}
}
