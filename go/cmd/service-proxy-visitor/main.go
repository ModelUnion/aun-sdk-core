package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

func main() {
	providerAID := envFirst("AUN_PROXY_PROVIDER_AID", "AUN_SERVICE_PROXY_PROVIDER_AID", "PROVIDER_AID")
	if providerAID == "" {
		exitf("必须通过 AUN_PROXY_PROVIDER_AID 指定 provider AID")
	}
	user := strings.SplitN(providerAID, ".", 2)[0]
	issuer := strings.TrimPrefix(providerAID, user+".")
	proxyBase := envFirst("AUN_PROXY_BASE", "AUN_SERVICE_PROXY_PUBLIC_BASE")
	if proxyBase == "" {
		proxyBase = "https://proxy." + issuer + ":19890"
	}
	proxyHost := strings.TrimPrefix(proxyBase, "https://")
	proxyHost = strings.TrimPrefix(proxyHost, "http://")

	checkHTTP(http.MethodGet, proxyBase+"/"+user+"/rest/headers", proxyHost, map[string]string{"x-trace-id": "go-visitor"}, nil)
	checkHTTP(http.MethodGet, proxyBase+"/"+user+"/events/live", proxyHost, map[string]string{"accept": "text/event-stream"}, nil)
	checkHTTP(http.MethodGet, proxyBase+"/"+user+"/files/download/report.txt", proxyHost, nil, nil)
	checkWS(strings.Replace(proxyBase, "https://", "wss://", 1) + "/" + user + "/chat/socket")
	fmt.Println("Go Service Proxy visitor 检查完成: PASS")
}

func checkHTTP(method, targetURL, host string, headers map[string]string, body []byte) {
	req, err := http.NewRequest(method, targetURL, bytes.NewReader(body))
	if err != nil {
		exitf("创建 HTTP 请求失败: %v", err)
	}
	req.Host = host
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		exitf("HTTP 请求失败 %s: %v", targetURL, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		exitf("HTTP %s 返回 %d: %s", targetURL, resp.StatusCode, string(data))
	}
	fmt.Printf("%s %s -> %s\n", method, targetURL, truncate(string(data), 160))
}

func checkWS(targetURL string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, targetURL, &websocket.DialOptions{
		Subprotocols: []string{"chat.v1"},
		HTTPClient:   httpClient(),
	})
	if err != nil {
		exitf("WebSocket 连接失败: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		exitf("WebSocket 发送失败: %v", err)
	}
	msgType, data, err := conn.Read(ctx)
	if err != nil || msgType != websocket.MessageText || !strings.Contains(string(data), "echo:hello") {
		exitf("WebSocket echo 异常: type=%v data=%q err=%v", msgType, string(data), err)
	}
	fmt.Printf("WS %s -> %s\n", targetURL, string(data))
}

func httpClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 本地 Docker 测试证书
			Proxy:           nil,
		},
	}
}

func envFirst(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max]
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
