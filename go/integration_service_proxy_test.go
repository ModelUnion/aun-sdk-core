//go:build integration

package aun

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

const serviceProxyIntegrationExpectedRequests = 7

func TestIntegrationServiceProxySingleDomainDockerE2E(t *testing.T) {
	issuer := envOrDefault("AUN_TEST_ISSUER", "agentid.pub")
	preflightIntegrationServiceProxy(t, issuer)
	rid := runID()
	providerAID := fmt.Sprintf("go-sp-%s.%s", rid, issuer)
	aunClient := makeClient(t)
	defer aunClient.Close()
	ensureConnected(t, aunClient, providerAID)

	backend := startIntegrationServiceProxyBackend(t, providerAID)
	proxyClient := NewServiceProxyClient(ServiceProxyClientOptions{ProviderAID: providerAID, AUNClient: aunClient})
	registerIntegrationServiceProxyServices(t, proxyClient, backend.baseHTTP, backend.baseWS)

	serveCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	resultCh := make(chan integrationServiceProxyResult, 1)
	go func() {
		result, err := proxyClient.ServeOnce(serveCtx, serviceProxyIntegrationExpectedRequests)
		resultCh <- integrationServiceProxyResult{result: result, err: err}
	}()
	defer proxyClient.Stop()

	waitIntegrationServiceProxyRegistered(t, issuer, 4, resultCh)
	runIntegrationServiceProxyVisitorChecks(t, providerAID, issuer)
	result := waitIntegrationServiceProxyServeResult(t, resultCh, 10*time.Second)
	if intFromAny(result["registered"]) != 4 || intFromAny(result["handled_requests"]) != serviceProxyIntegrationExpectedRequests {
		t.Fatalf("ServeOnce 返回异常: %+v", result)
	}
}

func TestFederationServiceProxyDoesNotRouteAcrossIssuerBoundary(t *testing.T) {
	localIssuer := envOrDefault("LOCAL_ISSUER", envOrDefault("AUN_TEST_ISSUER_A", "aid.com"))
	remoteIssuer := envOrDefault("REMOTE_ISSUER", envOrDefault("AUN_TEST_ISSUER_B", "aid.net"))
	preflightIntegrationServiceProxy(t, localIssuer)
	preflightIntegrationServiceProxy(t, remoteIssuer)
	rid := federationRunID()
	providerAID := fmt.Sprintf("go-sp-fed-%s.%s", rid, localIssuer)
	aunClient := makeFederationClient(t)
	defer aunClient.Close()
	ensureFederationConnected(t, aunClient, providerAID)

	backend := startIntegrationServiceProxyBackend(t, providerAID)
	proxyClient := NewServiceProxyClient(ServiceProxyClientOptions{ProviderAID: providerAID, AUNClient: aunClient})
	registerIntegrationServiceProxyServices(t, proxyClient, backend.baseHTTP, backend.baseWS)

	serveCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	resultCh := make(chan integrationServiceProxyResult, 1)
	go func() {
		result, err := proxyClient.ServeOnce(serveCtx, serviceProxyIntegrationExpectedRequests)
		resultCh <- integrationServiceProxyResult{result: result, err: err}
	}()
	defer proxyClient.Stop()

	waitIntegrationServiceProxyRegistered(t, localIssuer, 4, resultCh)
	runIntegrationServiceProxyVisitorChecks(t, providerAID, localIssuer)
	runIntegrationServiceProxyRemoteBoundaryCheck(t, providerAID, remoteIssuer)
	result := waitIntegrationServiceProxyServeResult(t, resultCh, 10*time.Second)
	if intFromAny(result["registered"]) != 4 || intFromAny(result["handled_requests"]) != serviceProxyIntegrationExpectedRequests {
		t.Fatalf("ServeOnce 返回异常: %+v", result)
	}
}

type integrationServiceProxyResult struct {
	result map[string]any
	err    error
}

type integrationServiceProxyBackend struct {
	baseHTTP string
	baseWS   string
	server   *http.Server
}

func startIntegrationServiceProxyBackend(t *testing.T, providerAID string) integrationServiceProxyBackend {
	t.Helper()
	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	mux.HandleFunc("/http/headers", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		payload := map[string]any{
			"provider_aid":       providerAID,
			"method":             r.Method,
			"path_qs":            r.URL.RequestURI(),
			"x_trace_id":         r.Header.Get("x-trace-id"),
			"x_aun_spoof":        r.Header.Get("x-aun-spoof"),
			"x_aun_provider_aid": r.Header.Get("x-aun-provider-aid"),
			"x_aun_service_name": r.Header.Get("x-aun-service-name"),
			"x_forwarded_prefix": r.Header.Get("x-forwarded-prefix"),
			"x_forwarded_host":   r.Header.Get("x-forwarded-host"),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Header-Check", "ok")
		_ = json.NewEncoder(w).Encode(payload)
	})
	mux.HandleFunc("/sse/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(fmt.Sprintf("data: %s:one\n\ndata: %s:two\n\n", providerAID, providerAID)))
	})
	mux.HandleFunc("/files/download/report.bin", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=report.bin")
		_, _ = w.Write([]byte("report-bytes"))
	})
	mux.HandleFunc("/ws/socket", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"chat.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		for {
			msgType, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if msgType == websocket.MessageText {
				_ = conn.Write(r.Context(), websocket.MessageText, []byte(providerAID+":echo:"+string(data)))
			} else {
				_ = conn.Write(r.Context(), websocket.MessageBinary, append([]byte(providerAID+":"), data...))
			}
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/http/status/404" {
			w.Header().Set("X-Backend-Status", "missing")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("missing"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Provider-Aid", providerAID)
		_, _ = w.Write([]byte(fmt.Sprintf("%s:%s:%s:%s", providerAID, r.Method, r.URL.RequestURI(), string(body))))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动测试后端失败: %v", err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	addr := listener.Addr().String()
	return integrationServiceProxyBackend{
		baseHTTP: "http://" + addr,
		baseWS:   "ws://" + addr,
		server:   server,
	}
}

func registerIntegrationServiceProxyServices(t *testing.T, client *ServiceProxyClient, baseHTTP, baseWS string) {
	t.Helper()
	defs := []struct {
		name        string
		endpoint    string
		serviceType string
	}{
		{"fileshare", baseHTTP + "/http", "http"},
		{"events", baseHTTP + "/sse", "sse"},
		{"files", baseHTTP + "/files", "file"},
		{"chat", baseWS + "/ws", "websocket"},
	}
	for _, def := range defs {
		if _, err := client.RegisterService(def.name, def.endpoint, WithServiceProxyServiceType(def.serviceType), WithServiceProxyVisibility("public")); err != nil {
			t.Fatalf("注册测试服务失败: %s: %v", def.name, err)
		}
	}
}

func preflightIntegrationServiceProxy(t *testing.T, issuer string) {
	t.Helper()
	resp := integrationHTTP(t, http.MethodGet, integrationServiceProxyBase(issuer)+"/health", "", nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("%s service_proxy health HTTP %d: %s", issuer, resp.status, string(resp.body))
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.body, &payload); err != nil || payload["module"] != "service_proxy" {
		t.Fatalf("%s service_proxy health 响应异常: err=%v body=%s", issuer, err, string(resp.body))
	}
}

func waitIntegrationServiceProxyRegistered(t *testing.T, issuer string, expected int, resultCh <-chan integrationServiceProxyResult) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	last := ""
	for time.Now().Before(deadline) {
		select {
		case result := <-resultCh:
			if result.err != nil {
				t.Fatalf("service-proxy-client 隧道任务提前失败: %v", result.err)
			}
			t.Fatalf("service-proxy-client 隧道任务提前结束: %+v", result.result)
		default:
		}
		resp := integrationHTTP(t, http.MethodGet, integrationServiceProxyBase(issuer)+"/health", "", nil, nil)
		last = string(resp.body)
		var payload map[string]any
		if err := json.Unmarshal(resp.body, &payload); err == nil {
			if intFromAny(asMap(payload["connections"])["services"]) >= expected {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("service-proxy-client 未完成服务注册，最后 health=%s", last)
}

func runIntegrationServiceProxyVisitorChecks(t *testing.T, providerAID, issuer string) {
	t.Helper()
	user := strings.SplitN(providerAID, ".", 2)[0]
	proxyHost := "proxy." + issuer
	proxyBase := integrationServiceProxyBase(issuer)
	resp := integrationHTTP(t, http.MethodGet, proxyBase+"/"+user+"/fileshare/health?x=1", proxyHost, nil, nil)
	assertIntegrationHTTP(t, resp, http.StatusOK, providerAID+":GET:/http/health?x=1:", "canonical GET")

	resp = integrationHTTP(t, http.MethodPost, proxyBase+"/"+user+"/fileshare/upload?token=abc", proxyHost, nil, []byte("payload"))
	assertIntegrationHTTP(t, resp, http.StatusOK, providerAID+":POST:/http/upload?token=abc:payload", "canonical POST")

	resp = integrationHTTP(t, http.MethodGet, proxyBase+"/"+user+"/fileshare/headers", proxyHost, map[string]string{
		"x-trace-id":  "trace-go-e2e",
		"x-aun-spoof": "must-not-forward",
	}, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("header check HTTP %d: %s", resp.status, string(resp.body))
	}
	var headerPayload map[string]any
	if err := json.Unmarshal(resp.body, &headerPayload); err != nil {
		t.Fatalf("header check JSON 解析失败: %v body=%s", err, string(resp.body))
	}
	if headerPayload["x_trace_id"] != "trace-go-e2e" ||
		headerPayload["x_aun_spoof"] != "" ||
		headerPayload["x_aun_provider_aid"] != providerAID ||
		headerPayload["x_aun_service_name"] != "fileshare" ||
		headerPayload["x_forwarded_prefix"] != "/"+user+"/fileshare" {
		t.Fatalf("header check 响应异常: %+v", headerPayload)
	}

	resp = integrationHTTP(t, http.MethodGet, proxyBase+"/"+user+"/events/live", proxyHost, nil, nil)
	assertIntegrationHTTP(t, resp, http.StatusOK, fmt.Sprintf("data: %s:one\n\ndata: %s:two\n\n", providerAID, providerAID), "SSE")
	if resp.headers.Get("x-stream-type") != "sse" {
		t.Fatalf("SSE x-stream-type 异常: %s", resp.headers.Get("x-stream-type"))
	}

	resp = integrationHTTP(t, http.MethodGet, proxyBase+"/"+user+"/files/download/report.bin", proxyHost, nil, nil)
	assertIntegrationHTTP(t, resp, http.StatusOK, "report-bytes", "file")
	if resp.headers.Get("x-stream-type") != "file" {
		t.Fatalf("file x-stream-type 异常: %s", resp.headers.Get("x-stream-type"))
	}

	runIntegrationServiceProxyWebSocketCheck(t, integrationServiceProxyWSBase(issuer)+"/"+user+"/chat/socket", providerAID)

	redirect := integrationHTTP(t, http.MethodGet, "https://"+issuer+"/proxy/fileshare/from-ns?y=2", providerAID, nil, nil)
	switch redirect.status {
	case http.StatusFound:
		location := redirect.headers.Get("location")
		redirectURL := integrationProxyURLFromLocation(t, location, proxyBase)
		resp = integrationHTTP(t, http.MethodGet, redirectURL, proxyHost, nil, nil)
		assertIntegrationHTTP(t, resp, http.StatusOK, providerAID+":GET:/http/from-ns?y=2:", "NameService redirected GET")
	case http.StatusOK:
		assertIntegrationHTTP(t, redirect, http.StatusOK, providerAID+":GET:/http/from-ns?y=2:", "NameService direct GET")
	default:
		t.Fatalf("NameService redirect HTTP %d: %s", redirect.status, string(redirect.body))
	}
}

func runIntegrationServiceProxyRemoteBoundaryCheck(t *testing.T, providerAID, remoteIssuer string) {
	t.Helper()
	user := strings.SplitN(providerAID, ".", 2)[0]
	resp := integrationHTTP(t, http.MethodGet, integrationServiceProxyBase(remoteIssuer)+"/"+user+"/fileshare/direct?x=remote", "proxy."+remoteIssuer, nil, nil)
	var payload map[string]any
	_ = json.Unmarshal(resp.body, &payload)
	errorCode := stringFromAny(payload["error"])
	allowed := (resp.status == http.StatusServiceUnavailable && (errorCode == "provider_offline" || errorCode == "provider_wakeup_failed" || errorCode == "provider_wakeup_timeout")) ||
		(resp.status == http.StatusNotFound && (errorCode == "provider_aid_not_found" || errorCode == "provider_not_found"))
	if !allowed {
		t.Fatalf("REMOTE issuer 不应命中本域 provider: status=%d body=%s", resp.status, string(resp.body))
	}
}

func waitIntegrationServiceProxyServeResult(t *testing.T, resultCh <-chan integrationServiceProxyResult, timeout time.Duration) map[string]any {
	t.Helper()
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("ServeOnce 失败: %v", result.err)
		}
		return result.result
	case <-time.After(timeout):
		t.Fatalf("等待 ServeOnce 结束超时")
	}
	return nil
}

func runIntegrationServiceProxyWebSocketCheck(t *testing.T, targetURL, providerAID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, targetURL, &websocket.DialOptions{
		Subprotocols: []string{"chat.v1"},
		HTTPClient:   integrationHTTPClient(),
	})
	if err != nil {
		t.Fatalf("WebSocket 连接失败: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	if conn.Subprotocol() != "chat.v1" {
		t.Fatalf("WS subprotocol 异常: %q", conn.Subprotocol())
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatalf("发送 WS text 失败: %v", err)
	}
	msgType, data, err := conn.Read(ctx)
	if err != nil || msgType != websocket.MessageText || string(data) != providerAID+":echo:hello" {
		t.Fatalf("WS text echo 异常: type=%v data=%q err=%v", msgType, string(data), err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("bin")); err != nil {
		t.Fatalf("发送 WS binary 失败: %v", err)
	}
	msgType, data, err = conn.Read(ctx)
	if err != nil || msgType != websocket.MessageBinary || !bytes.Equal(data, []byte(providerAID+":bin")) {
		t.Fatalf("WS binary echo 异常: type=%v data=%v err=%v", msgType, data, err)
	}
}

type integrationHTTPResponse struct {
	status  int
	headers http.Header
	body    []byte
}

func integrationHTTP(t *testing.T, method, targetURL, host string, headers map[string]string, body []byte) integrationHTTPResponse {
	t.Helper()
	req, err := http.NewRequest(method, targetURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("创建 HTTP 请求失败: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := integrationHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("HTTP 请求失败 %s %s: %v", method, targetURL, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return integrationHTTPResponse{status: resp.StatusCode, headers: resp.Header, body: data}
}

func integrationHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 本地 Docker 测试证书
			Proxy:           nil,
		},
	}
}

func assertIntegrationHTTP(t *testing.T, resp integrationHTTPResponse, wantStatus int, wantBody string, label string) {
	t.Helper()
	if resp.status != wantStatus || string(resp.body) != wantBody {
		t.Fatalf("%s 失败: status=%d body=%q", label, resp.status, string(resp.body))
	}
}

func integrationProxyURLFromLocation(t *testing.T, location, proxyBase string) string {
	t.Helper()
	parsed, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		t.Fatalf("解析 Location 失败: %q: %v", location, err)
	}
	return proxyBase + parsed.URL.RequestURI()
}

func integrationServiceProxyBase(issuer string) string {
	return fmt.Sprintf("https://proxy.%s:%s", issuer, envOrDefault("AUN_SERVICE_PROXY_PORT", "19890"))
}

func integrationServiceProxyWSBase(issuer string) string {
	return fmt.Sprintf("wss://proxy.%s:%s", issuer, envOrDefault("AUN_SERVICE_PROXY_PORT", "19890"))
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func getenv(name string) string {
	return strings.TrimSpace(strings.Trim(os.Getenv(name), "\x00"))
}
