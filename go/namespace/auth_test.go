package namespace

import (
	"context"
	"encoding/json"
	"io"
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

func (m *mockAuthClient) DiscoverGateway(ctx context.Context, wellKnownURL string, timeout time.Duration) (string, error) {
	return m.discoverGatewayResult, m.discoverGatewayErr
}

func (m *mockAuthClient) SetIdentity(identity map[string]any) {
	m.identity = identity
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
