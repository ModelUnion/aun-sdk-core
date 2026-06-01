package namespace

import (
	"context"
	"strings"
	"testing"
	"time"
)

type mockAuthClient struct {
	gatewayURL             string
	aid                    string
	discoveryPort          int
	verifySSL              bool
	identity               map[string]any
	authResult             map[string]any
	authAuthenticateCalls  int
	discoverGatewayResult  string
	discoverGatewayErr     error
	fetchPeerCertResult    []byte
	fetchPeerCertErr       error
	fetchPeerCertCalls     int
	cachedGatewayURL       string
	persistedGatewayURL    string
	persistGatewayCalls    int
	loadCachedGatewayCalls int
}

func (m *mockAuthClient) GetGatewayURL() string {
	return m.gatewayURL
}

func (m *mockAuthClient) setGatewayURL(url string) {
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

func (m *mockAuthClient) CacheDiscoveredGatewayURL(url string) {
	m.cachedGatewayURL = url
}

func (m *mockAuthClient) AuthPersistGatewayURL(aid, gatewayURL string) {
	m.persistGatewayCalls++
	m.persistedGatewayURL = gatewayURL
}

func (m *mockAuthClient) AuthLoadCert(aid string) (string, error) {
	if m.identity == nil {
		return "", nil
	}
	cert, _ := m.identity["cert"].(string)
	return cert, nil
}

func TestCreateAIDCompatAliasRequiresAIDStore(t *testing.T) {
	client := &mockAuthClient{
		gatewayURL: "ws://gateway.example.com/aun",
		identity:   map[string]any{"aid": "alice.agentid.pub"},
	}
	ns := NewAuthNamespace(client)

	_, err := ns.CreateAID(context.Background(), map[string]any{"aid": "alice.agentid.pub"})
	if err == nil {
		t.Fatal("CreateAID 应提示改用 AIDStore.Register")
	}
	if !strings.Contains(err.Error(), "AIDStore.Register") {
		t.Fatalf("unexpected error: %v", err)
	}
}
