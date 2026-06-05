package aun

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

type proxyFakeCall struct {
	Method string
	Params map[string]any
}

type proxyFakeGatewayClient struct {
	calls []proxyFakeCall
}

func (f *proxyFakeGatewayClient) Call(_ context.Context, method string, params map[string]any) (any, error) {
	f.calls = append(f.calls, proxyFakeCall{Method: method, Params: params})
	return map[string]any{"ok": true}, nil
}

type proxyFakeAuthClient struct {
	authenticateCalls int
}

func (f *proxyFakeAuthClient) Authenticate(_ context.Context, _ ...ConnectOptions) (map[string]any, error) {
	f.authenticateCalls++
	return map[string]any{
		"access_token": "fresh-token",
		"expires_at":   float64(time.Now().Add(time.Hour).Unix()),
	}, nil
}

func TestServiceProxyRegistrySummariesSanitizeMetadataAndEndpoint(t *testing.T) {
	registry := NewEmbeddedServiceRegistry(nil)

	record, err := registry.Register(
		"fileshare",
		"http://127.0.0.1:8080/root",
		WithServiceProxyServiceType("http"),
		WithServiceProxyVisibility("public"),
		WithServiceProxyMetadata(map[string]any{
			"title":    "Files",
			"endpoint": "http://127.0.0.1:8080/root",
			"token":    "SECRET",
			"nested":   map[string]any{"access_token": "SECRET", "label": "ok"},
			"items":    []any{map[string]any{"password": "SECRET", "name": "one"}},
		}),
	)
	if err != nil {
		t.Fatalf("注册服务失败: %v", err)
	}
	if record.Endpoint != "http://127.0.0.1:8080/root" {
		t.Fatalf("本地 record 应保留 endpoint，实际: %s", record.Endpoint)
	}

	summaries := registry.ListSummaries()
	if len(summaries) != 1 {
		t.Fatalf("服务摘要数量错误: %d", len(summaries))
	}
	summary := summaries[0]
	if summary.ServiceName != "fileshare" || summary.ServiceType != "http" || summary.Visibility != "public" {
		t.Fatalf("服务摘要字段错误: %+v", summary)
	}
	if _, ok := summary.Metadata["endpoint"]; ok {
		t.Fatalf("服务摘要不能暴露 endpoint: %+v", summary.Metadata)
	}
	if _, ok := summary.Metadata["token"]; ok {
		t.Fatalf("服务摘要不能暴露 token: %+v", summary.Metadata)
	}
	nested, _ := summary.Metadata["nested"].(map[string]any)
	if nested["access_token"] != nil || nested["label"] != "ok" {
		t.Fatalf("嵌套 metadata 清理错误: %+v", nested)
	}
	items, _ := summary.Metadata["items"].([]any)
	item, _ := items[0].(map[string]any)
	if item["password"] != nil || item["name"] != "one" {
		t.Fatalf("数组 metadata 清理错误: %+v", item)
	}
}

func TestServiceProxyEndpointPolicyMatchesPythonDefault(t *testing.T) {
	policy := NewEndpointPolicy()
	if !policy.IsAllowed("http://127.0.0.1:8080") {
		t.Fatal("默认策略应允许 IPv4 loopback")
	}
	if !policy.IsAllowed("wss://localhost:8765/ws") {
		t.Fatal("默认策略应允许 localhost")
	}
	for _, endpoint := range []string{
		"http://[::1]:8080",
		"http://10.0.0.1:8080",
		"file:///tmp/service.sock",
	} {
		if policy.IsAllowed(endpoint) {
			t.Fatalf("默认策略不应允许 endpoint: %s", endpoint)
		}
	}

	explicit := NewEndpointPolicy("service.internal")
	if !explicit.IsAllowed("http://service.internal:8080") {
		t.Fatal("显式 allowlist 主机应被允许")
	}
	registry := NewEmbeddedServiceRegistry(nil)
	_, err := registry.Register("api", "http://127.0.0.1:8080")
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("保留服务名应返回 ValidationError，实际: %v", err)
	}
}

func TestServiceProxyGatewayControlPlaneCallsProxyMethods(t *testing.T) {
	fake := &proxyFakeGatewayClient{}
	client := NewServiceProxyClient(ServiceProxyClientOptions{
		ProviderAID: "alice.agentid.pub",
		AUNClient:   fake,
	})
	if _, err := client.RegisterService(
		"fileshare",
		"http://127.0.0.1:8080/root",
		WithServiceProxyVisibility("public"),
		WithServiceProxyMetadata(map[string]any{
			"title":    "Files",
			"endpoint": "http://127.0.0.1:8080/root",
		}),
	); err != nil {
		t.Fatalf("注册本地服务失败: %v", err)
	}

	if _, err := client.RegisterServicesWithGateway(context.Background(), nil); err != nil {
		t.Fatalf("Gateway 注册失败: %v", err)
	}
	if _, err := client.UnregisterServicesFromGateway(context.Background(), "fileshare"); err != nil {
		t.Fatalf("Gateway 注销失败: %v", err)
	}
	if _, err := client.ListGatewayServices(context.Background()); err != nil {
		t.Fatalf("Gateway 查询失败: %v", err)
	}

	if len(fake.calls) != 3 {
		t.Fatalf("Gateway 调用次数错误: %d", len(fake.calls))
	}
	if fake.calls[0].Method != "proxy.register_services" {
		t.Fatalf("注册方法错误: %s", fake.calls[0].Method)
	}
	if fake.calls[1].Method != "proxy.unregister_services" {
		t.Fatalf("注销方法错误: %s", fake.calls[1].Method)
	}
	if fake.calls[2].Method != "proxy.list_services" {
		t.Fatalf("查询方法错误: %s", fake.calls[2].Method)
	}
	services, _ := fake.calls[0].Params["services"].([]any)
	service, _ := services[0].(map[string]any)
	metadata, _ := service["metadata"].(map[string]any)
	if fake.calls[0].Params["provider_aid"] != "alice.agentid.pub" || service["service_name"] != "fileshare" {
		t.Fatalf("注册参数错误: %+v", fake.calls[0].Params)
	}
	if _, ok := metadata["endpoint"]; ok {
		t.Fatalf("Gateway 注册参数不应包含 endpoint: %+v", metadata)
	}
}

func TestServiceProxyConnectOnceUsesBearerTokenAndTunnelProtocol(t *testing.T) {
	mux := http.NewServeMux()
	var server *httptest.Server
	var mu sync.Mutex
	var authorization string
	var messages []map[string]any

	mux.HandleFunc("/.well-known/aun-proxy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		wsURL := "wss" + strings.TrimPrefix(server.URL, "https") + "/ws/client"
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "agentid.pub", "ws_url": wsURL})
	})
	mux.HandleFunc("/ws/client", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authorization = r.Header.Get("Authorization")
		mu.Unlock()
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		for {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var message map[string]any
			if err := json.Unmarshal(data, &message); err != nil {
				return
			}
			mu.Lock()
			messages = append(messages, message)
			mu.Unlock()
			switch stringFromAny(message["type"]) {
			case "service_proxy_auth":
				writeProxyTestMessage(t, r.Context(), conn, map[string]any{"type": "service_proxy_auth_response", "request_id": message["request_id"], "ok": true})
			case "register_services":
				writeProxyTestMessage(t, r.Context(), conn, map[string]any{"type": "register_services_ack", "request_id": message["request_id"], "ok": true, "count": 1})
			case "heartbeat":
				writeProxyTestMessage(t, r.Context(), conn, map[string]any{"type": "heartbeat_ack", "request_id": message["request_id"], "ok": true})
			}
		}
	})
	server = httptest.NewTLSServer(mux)
	defer server.Close()

	auth := &proxyFakeAuthClient{}
	client := NewServiceProxyClient(ServiceProxyClientOptions{
		ProviderAID:              "alice.agentid.pub",
		AUNClient:                auth,
		ProxyDiscoveryHTTPClient: server.Client(),
		ProxyDiscoveryURLOverride: func(_ string) []string {
			return []string{server.URL + "/.well-known/aun-proxy"}
		},
		ProxyWebSocketDialer: func(ctx context.Context, targetURL string, headers http.Header) (*websocket.Conn, error) {
			return dialProxyTestWebSocket(ctx, targetURL, headers, server.Client())
		},
	})
	if _, err := client.RegisterService("fileshare", "http://127.0.0.1:8080/root"); err != nil {
		t.Fatalf("注册本地服务失败: %v", err)
	}

	result, err := client.ConnectOnce(context.Background(), "hb")
	if err != nil {
		t.Fatalf("connectOnce 失败: %v", err)
	}
	if result["registered"] != 1 || result["heartbeat"] != true {
		t.Fatalf("connectOnce 返回错误: %+v", result)
	}
	if auth.authenticateCalls != 1 {
		t.Fatalf("应通过 authenticate 获取一次 token，实际: %d", auth.authenticateCalls)
	}

	mu.Lock()
	defer mu.Unlock()
	if authorization != "Bearer fresh-token" {
		t.Fatalf("Authorization header 错误: %q", authorization)
	}
	if len(messages) != 3 {
		t.Fatalf("tunnel 消息数量错误: %+v", messages)
	}
	if stringFromAny(messages[0]["type"]) != "service_proxy_auth" || stringFromAny(messages[0]["client_version"]) != "go" {
		t.Fatalf("认证消息错误: %+v", messages[0])
	}
	if stringFromAny(messages[1]["type"]) != "register_services" || stringFromAny(messages[2]["type"]) != "heartbeat" {
		t.Fatalf("tunnel 消息顺序错误: %+v", messages)
	}
}

func TestServiceProxyServeOnceLocalTunnelForwardsHTTPStreamAndWebSocket(t *testing.T) {
	mux := http.NewServeMux()
	var server *httptest.Server
	errCh := make(chan error, 1)

	mux.HandleFunc("/.well-known/aun-proxy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		wsURL := "wss" + strings.TrimPrefix(server.URL, "https") + "/ws/client"
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "agentid.pub", "ws_url": wsURL})
	})
	mux.HandleFunc("/http/headers", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend", "ok")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method":   r.Method,
			"path":     r.URL.Path,
			"query":    r.URL.Query().Get("x"),
			"body":     string(body),
			"provider": r.Header.Get("x-aun-provider-aid"),
			"service":  r.Header.Get("x-aun-service-name"),
			"trace":    r.Header.Get("x-trace-id"),
			"spoof":    r.Header.Get("x-aun-spoof"),
		})
	})
	mux.HandleFunc("/sse/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: one\n\ndata: two\n\n"))
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
				_ = conn.Write(r.Context(), websocket.MessageText, []byte("echo:"+string(data)))
			} else {
				_ = conn.Write(r.Context(), websocket.MessageBinary, append([]byte("echo:"), data...))
			}
		}
	})
	serveCtx, serveCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer serveCancel()

	mux.HandleFunc("/ws/client", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			proxyTestSendErr(errCh, fmt.Errorf("Authorization header 错误: %q", r.Header.Get("Authorization")))
			return
		}
		if err := driveServiceProxyLocalTunnel(r.Context(), conn); err != nil {
			proxyTestSendErr(errCh, err)
		}
		serveCancel()
	})
	server = httptest.NewTLSServer(mux)
	defer server.Close()

	auth := &proxyFakeAuthClient{}
	client := NewServiceProxyClient(ServiceProxyClientOptions{
		ProviderAID:              "alice.agentid.pub",
		AUNClient:                auth,
		HTTPClient:               server.Client(),
		ProxyDiscoveryHTTPClient: server.Client(),
		ProxyDiscoveryURLOverride: func(_ string) []string {
			return []string{server.URL + "/.well-known/aun-proxy"}
		},
		ProxyWebSocketDialer: func(ctx context.Context, targetURL string, headers http.Header) (*websocket.Conn, error) {
			return dialProxyTestWebSocket(ctx, targetURL, headers, server.Client())
		},
		BackendWebSocketDialer: func(ctx context.Context, targetURL string, subprotocols []string, headers http.Header) (*websocket.Conn, error) {
			conn, _, err := websocket.Dial(ctx, targetURL, &websocket.DialOptions{
				HTTPHeader:   headers,
				HTTPClient:   server.Client(),
				Subprotocols: subprotocols,
			})
			return conn, err
		},
	})
	for _, item := range []struct {
		name        string
		endpoint    string
		serviceType string
	}{
		{name: "rest", endpoint: server.URL + "/http", serviceType: "http"},
		{name: "events", endpoint: server.URL + "/sse", serviceType: "sse"},
		{name: "files", endpoint: server.URL + "/files", serviceType: "file"},
		{name: "chat", endpoint: "wss" + strings.TrimPrefix(server.URL, "https") + "/ws", serviceType: "websocket"},
	} {
		if _, err := client.RegisterService(item.name, item.endpoint, WithServiceProxyServiceType(item.serviceType), WithServiceProxyVisibility("public")); err != nil {
			t.Fatalf("注册本地服务失败: %v", err)
		}
	}

	result, err := client.ServeOnce(serveCtx, 4)
	if err != nil {
		t.Fatalf("ServeOnce 失败: %v", err)
	}
	select {
	case driveErr := <-errCh:
		t.Fatalf("fake proxy tunnel 驱动失败: %v", driveErr)
	default:
	}
	if result["registered"] != 4 || result["handled_requests"] != 4 {
		t.Fatalf("ServeOnce 返回错误: %+v", result)
	}
}

func writeProxyTestMessage(t *testing.T, ctx context.Context, conn *websocket.Conn, payload map[string]any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化测试消息失败: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("发送测试消息失败: %v", err)
	}
}

func dialProxyTestWebSocket(ctx context.Context, targetURL string, headers http.Header, client *http.Client) (*websocket.Conn, error) {
	conn, _, err := websocket.Dial(ctx, targetURL, &websocket.DialOptions{
		HTTPHeader: headers,
		HTTPClient: client,
	})
	return conn, err
}

func proxyTestSendErr(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func driveServiceProxyLocalTunnel(ctx context.Context, conn *websocket.Conn) error {
	auth, err := readProxyTestTunnelMessage(ctx, conn)
	if err != nil {
		return err
	}
	if stringFromAny(auth["type"]) != "service_proxy_auth" || stringFromAny(auth["client_version"]) != "go" {
		return fmt.Errorf("认证消息错误: %+v", auth)
	}
	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "service_proxy_auth_response", "request_id": auth["request_id"], "ok": true}); err != nil {
		return err
	}
	registered, err := readProxyTestTunnelMessage(ctx, conn)
	if err != nil {
		return err
	}
	if stringFromAny(registered["type"]) != "register_services" {
		return fmt.Errorf("注册消息错误: %+v", registered)
	}
	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "register_services_ack", "request_id": registered["request_id"], "ok": true, "count": 4}); err != nil {
		return err
	}

	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{
		"type":         "service_proxy_request",
		"request_id":   "req-http",
		"service_name": "rest",
		"method":       "POST",
		"path":         "/headers",
		"query_string": "x=1",
		"headers": map[string]any{
			"x-trace-id":         "trace-1",
			"x-aun-provider-aid": "alice.agentid.pub",
			"x-aun-service-name": "rest",
		},
		"body_base64": base64.StdEncoding.EncodeToString([]byte("payload")),
	}); err != nil {
		return err
	}
	httpResp, err := readProxyTestTunnelMessage(ctx, conn)
	if err != nil {
		return err
	}
	if stringFromAny(httpResp["type"]) != "service_proxy_response" || intFromAny(httpResp["status"]) != 202 {
		return fmt.Errorf("HTTP 响应错误: %+v", httpResp)
	}
	bodyBytes, _ := base64.StdEncoding.DecodeString(stringFromAny(httpResp["body_base64"]))
	var body map[string]any
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return err
	}
	if body["provider"] != "alice.agentid.pub" || body["service"] != "rest" || body["spoof"] != "" || body["body"] != "payload" {
		return fmt.Errorf("HTTP 后端 header/body 错误: %+v", body)
	}

	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "service_proxy_request", "request_id": "req-sse", "service_name": "events", "method": "GET", "path": "/live", "headers": map[string]any{"accept": "text/event-stream"}}); err != nil {
		return err
	}
	sse, err := readProxyTestTunnelUntil(ctx, conn, func(message map[string]any) bool {
		return stringFromAny(message["type"]) == "service_proxy_stream" && stringFromAny(message["request_id"]) == "req-sse" && boolFromAny(message["done"])
	})
	if err != nil {
		return err
	}
	if asMap(sse["headers"])["x-stream-type"] != "sse" {
		return fmt.Errorf("SSE stream type 错误: %+v", sse)
	}
	sseData, _ := base64.StdEncoding.DecodeString(stringFromAny(sse["data_base64"]))
	if string(sseData) != "data: one\n\ndata: two\n\n" {
		return fmt.Errorf("SSE 数据错误: %q", string(sseData))
	}

	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "service_proxy_request", "request_id": "req-file", "service_name": "files", "method": "GET", "path": "/download/report.bin"}); err != nil {
		return err
	}
	file, err := readProxyTestTunnelUntil(ctx, conn, func(message map[string]any) bool {
		return stringFromAny(message["type"]) == "service_proxy_stream" && stringFromAny(message["request_id"]) == "req-file" && boolFromAny(message["done"])
	})
	if err != nil {
		return err
	}
	if asMap(file["headers"])["x-stream-type"] != "file" || asMap(file["headers"])["content-disposition"] != "attachment; filename=report.bin" {
		return fmt.Errorf("File headers 错误: %+v", file)
	}
	fileData, _ := base64.StdEncoding.DecodeString(stringFromAny(file["data_base64"]))
	if string(fileData) != "report-bytes" {
		return fmt.Errorf("File 数据错误: %q", string(fileData))
	}

	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "ws_connect", "connection_id": "ws-1", "service_name": "chat", "path": "/socket", "subprotocols": []any{"chat.v1"}}); err != nil {
		return err
	}
	connected, err := readProxyTestTunnelMessage(ctx, conn)
	if err != nil {
		return err
	}
	if stringFromAny(connected["type"]) != "ws_connected" || stringFromAny(connected["subprotocol"]) != "chat.v1" {
		return fmt.Errorf("WS connected 错误: %+v", connected)
	}
	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "ws_message", "connection_id": "ws-1", "text": "hello"}); err != nil {
		return err
	}
	wsText, err := readProxyTestTunnelUntil(ctx, conn, func(message map[string]any) bool {
		return stringFromAny(message["type"]) == "ws_message" && stringFromAny(message["connection_id"]) == "ws-1" && stringFromAny(message["text"]) == "echo:hello"
	})
	if err != nil {
		return err
	}
	if stringFromAny(wsText["text"]) != "echo:hello" {
		return fmt.Errorf("WS text 错误: %+v", wsText)
	}
	if err := writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "ws_message", "connection_id": "ws-1", "data_base64": base64.StdEncoding.EncodeToString([]byte{1, 2})}); err != nil {
		return err
	}
	wsBinary, err := readProxyTestTunnelUntil(ctx, conn, func(message map[string]any) bool {
		return stringFromAny(message["type"]) == "ws_message" && stringFromAny(message["connection_id"]) == "ws-1" && stringFromAny(message["data_base64"]) != ""
	})
	if err != nil {
		return err
	}
	data, _ := base64.StdEncoding.DecodeString(stringFromAny(wsBinary["data_base64"]))
	if string(data) != "echo:\x01\x02" {
		return fmt.Errorf("WS binary 错误: %v", data)
	}
	return writeProxyTestTunnelMessage(ctx, conn, map[string]any{"type": "ws_close", "connection_id": "ws-1", "code": 1000, "reason": ""})
}

func readProxyTestTunnelUntil(ctx context.Context, conn *websocket.Conn, predicate func(map[string]any) bool) (map[string]any, error) {
	for {
		message, err := readProxyTestTunnelMessage(ctx, conn)
		if err != nil {
			return nil, err
		}
		if predicate(message) {
			return message, nil
		}
	}
}

func readProxyTestTunnelMessage(ctx context.Context, conn *websocket.Conn) (map[string]any, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var message map[string]any
	if err := json.Unmarshal(data, &message); err != nil {
		return nil, err
	}
	return message, nil
}

func writeProxyTestTunnelMessage(ctx context.Context, conn *websocket.Conn, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}
