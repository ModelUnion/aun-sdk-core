package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	aun "github.com/modelunion/aun-sdk-core/go"
	"nhooyr.io/websocket"
)

func main() {
	providerAID := envFirst("AUN_PROXY_PROVIDER_AID", "AUN_SERVICE_PROXY_PROVIDER_AID", "PROVIDER_AID")
	if providerAID == "" {
		exitf("必须通过 AUN_PROXY_PROVIDER_AID 指定 provider AID")
	}
	aunPath := envFirst("AUN_PROXY_PROVIDER_AUN_PATH", "AUN_SERVICE_PROXY_PROVIDER_AUN_PATH")
	if aunPath == "" {
		home, _ := os.UserHomeDir()
		aunPath = filepath.Join(home, ".aun", "service-proxy-holder-go", safeName(providerAID))
	}
	seed := envFirst("AUN_SEED_PASSWORD", "AUN_PROXY_SEED")
	connectionMode := envFirst("AUN_SERVICE_PROXY_CONNECTION_MODE")
	if connectionMode == "" {
		connectionMode = "persistent"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	backend, err := startBackend(providerAID)
	if err != nil {
		exitf("启动测试后端失败: %v", err)
	}
	defer backend.close()

	store := aun.NewAIDStore(aunPath, seed)
	defer store.Close()
	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	if rr := store.Register(regCtx, providerAID); !rr.Ok {
		if lr := store.Load(providerAID); !lr.Ok {
			regCancel()
			exitf("注册 AID 失败且本地无可用身份: %s", rr.Error.Message)
		}
	}
	regCancel()
	lr := store.Load(providerAID)
	if !lr.Ok {
		exitf("加载 AID 失败: %s", lr.Error.Message)
	}
	aunClient := aun.NewAUNClient(lr.Data.AID)
	connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
	if err := aunClient.Connect(connectCtx, aun.ConnectionOptions{AutoReconnect: boolPtr(false)}); err != nil {
		connectCancel()
		exitf("连接 AUN Gateway 失败: %v", err)
	}
	connectCancel()
	defer aunClient.Close()

	proxyClient := aun.NewServiceProxyClient(aun.ServiceProxyClientOptions{ProviderAID: providerAID, AUNClient: aunClient})
	mustRegister(proxyClient, "rest", backend.baseHTTP+"/http", "http")
	mustRegister(proxyClient, "events", backend.baseHTTP+"/sse", "sse")
	mustRegister(proxyClient, "files", backend.baseHTTP+"/files", "file")
	mustRegister(proxyClient, "chat", backend.baseWS+"/ws", "websocket")
	defer proxyClient.Stop()

	printURLs(providerAID)
	result, err := proxyClient.ServeForever(ctx, aun.ServiceProxyServeForeverOptions{
		ConnectionMode: connectionMode,
		ReconnectDelay: time.Second,
	})
	if err != nil && ctx.Err() == nil {
		exitf("Service Proxy holder 失败: %v", err)
	}
	fmt.Printf("Service Proxy holder 退出: %+v\n", result)
}

type backendServer struct {
	baseHTTP string
	baseWS   string
	server   *http.Server
	listener net.Listener
}

func startBackend(providerAID string) (*backendServer, error) {
	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	mux.HandleFunc("/http/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			w,
			`{"provider_aid":%q,"method":%q,"path_qs":%q,"x_trace_id":%q,"x_aun_provider_aid":%q,"x_aun_service_name":%q,"x_forwarded_prefix":%q}`,
			providerAID,
			r.Method,
			r.URL.RequestURI(),
			r.Header.Get("x-trace-id"),
			r.Header.Get("x-aun-provider-aid"),
			r.Header.Get("x-aun-service-name"),
			r.Header.Get("x-forwarded-prefix"),
		)
	})
	mux.HandleFunc("/sse/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s:one\n\ndata: %s:two\n\n", providerAID, providerAID)
	})
	mux.HandleFunc("/files/download/report.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment; filename=report.txt")
		_, _ = fmt.Fprintf(w, "Service Proxy report from %s\n", providerAID)
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
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "%s:%s:%s:%s", providerAID, r.Method, r.URL.RequestURI(), string(body))
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() { _ = server.Serve(listener) }()
	addr := listener.Addr().String()
	return &backendServer{baseHTTP: "http://" + addr, baseWS: "ws://" + addr, server: server, listener: listener}, nil
}

func (b *backendServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = b.server.Shutdown(ctx)
}

func mustRegister(client *aun.ServiceProxyClient, name, endpoint, serviceType string) {
	if _, err := client.RegisterService(name, endpoint, aun.WithServiceProxyServiceType(serviceType), aun.WithServiceProxyVisibility("public")); err != nil {
		exitf("注册服务失败: %s: %v", name, err)
	}
}

func printURLs(providerAID string) {
	user := strings.SplitN(providerAID, ".", 2)[0]
	issuer := strings.TrimPrefix(providerAID, user+".")
	base := "https://proxy." + issuer + ":19890/" + user
	fmt.Printf("Go Service Proxy holder 已启动: %s\n", providerAID)
	fmt.Printf("REST: %s/rest/headers\n", base)
	fmt.Printf("SSE : %s/events/live\n", base)
	fmt.Printf("File: %s/files/download/report.txt\n", base)
	fmt.Printf("WS  : wss://proxy.%s:19890/%s/chat/socket\n", issuer, user)
}

func envFirst(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func safeName(text string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return replacer.Replace(text)
}

func boolPtr(v bool) *bool { return &v }

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
