package aun

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync/atomic"
	"time"
)

// GatewayDiscovery Gateway 自动发现
// 通过 well-known URL 获取可用的 Gateway 列表并按优先级排序。
// 与 Python SDK discovery.py 对应。
type GatewayDiscovery struct {
	verifySSL   bool
	lastHealthy atomic.Pointer[bool] // nil = 尚未检查
	net         *DnsResilientNet
}

// NewGatewayDiscovery 创建 Gateway 发现器
func NewGatewayDiscovery(verifySSL bool, net ...*DnsResilientNet) *GatewayDiscovery {
	d := &GatewayDiscovery{verifySSL: verifySSL}
	if len(net) > 0 {
		d.net = net[0]
	}
	return d
}

// gatewayEntry well-known 返回的单条 Gateway 信息
type gatewayEntry struct {
	URL      string `json:"url"`
	Priority int    `json:"priority"`
}

func (d *GatewayDiscovery) httpClient() *http.Client {
	transport := &http.Transport{}
	if !d.verifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: transport}
}

// LastHealthy 返回最近一次 health check 结果，nil 表示尚未检查。
func (d *GatewayDiscovery) LastHealthy() *bool {
	return d.lastHealthy.Load()
}

// CheckHealth 向 gatewayURL 对应的 /health 端点发送 GET 请求，检查网关可用性。
func (d *GatewayDiscovery) CheckHealth(ctx context.Context, gatewayURL string, timeout time.Duration) (ok bool) {
	tStart := time.Now()
	pkgLogDiscovery().Debug("CheckHealth enter: gateway=%s timeout=%v", gatewayURL, timeout)
	defer func() {
		pkgLogDiscovery().Debug("CheckHealth exit: gateway=%s ok=%v elapsed=%dms", gatewayURL, ok, time.Since(tStart).Milliseconds())
	}()
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	healthURL := gatewayURL
	if parsed, parseErr := url.Parse(gatewayURL); parseErr == nil {
		if parsed.Scheme == "wss" {
			parsed.Scheme = "https"
		} else {
			parsed.Scheme = "http"
		}
		parsed.Path = "/health"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		healthURL = parsed.String()
	}

	if d.net != nil {
		ok = d.net.HTTPGetOK(ctx, healthURL, timeout)
	} else {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, healthURL, nil)
		if err == nil {
			resp, err := d.httpClient().Do(req)
			if err == nil {
				resp.Body.Close()
				ok = resp.StatusCode == http.StatusOK
			} else {
				pkgLogDiscovery().Warn("health check request failed: url=%s err=%v", healthURL, err)
			}
		}
	}
	if ok {
		pkgLogDiscovery().Debug("health check passed: gateway=%s", gatewayURL)
	} else {
		pkgLogDiscovery().Warn("health check failed: gateway=%s", gatewayURL)
	}
	d.lastHealthy.Store(&ok)
	return ok
}

// Discover 从 well-known URL 发现 Gateway
// 返回优先级最高的 Gateway WebSocket URL
func (d *GatewayDiscovery) Discover(ctx context.Context, wellKnownURL string, timeout time.Duration) (gatewayURL string, err error) {
	urls, err := d.DiscoverAll(ctx, wellKnownURL, timeout)
	if err != nil {
		return "", err
	}
	return urls[0], nil
}

// DiscoverAll 从 well-known URL 发现所有 Gateway（按 priority 排序）
func (d *GatewayDiscovery) DiscoverAll(ctx context.Context, wellKnownURL string, timeout time.Duration) (urls []string, err error) {
	tStart := time.Now()
	pkgLogDiscovery().Debug("DiscoverAll enter: well_known=%s timeout=%v", wellKnownURL, timeout)
	defer func() {
		if err != nil {
			pkgLogDiscovery().Debug("DiscoverAll exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogDiscovery().Debug("DiscoverAll exit: urls=%v elapsed=%dms", urls, time.Since(tStart).Milliseconds())
		}
	}()
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	var body []byte
	if d.net != nil {
		body, err = d.net.HTTPGet(ctx, wellKnownURL, timeout)
		if err != nil {
			pkgLogDiscovery().Error("gateway discovery failed: url=%s err=%v", wellKnownURL, err)
			return nil, NewConnectionError(
				fmt.Sprintf("gateway discovery failed (%s): %v", wellKnownURL, err),
				WithRetryable(true),
			)
		}
	} else {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, wellKnownURL, nil)
		if reqErr != nil {
			pkgLogDiscovery().Error("gateway discovery request creation failed: url=%s err=%v", wellKnownURL, reqErr)
			return nil, NewConnectionError(
				fmt.Sprintf("gateway discovery request creation failed (%s): %v", wellKnownURL, reqErr),
				WithRetryable(true),
			)
		}

		resp, doErr := d.httpClient().Do(req)
		if doErr != nil {
			pkgLogDiscovery().Error("gateway discovery request failed: url=%s err=%v", wellKnownURL, doErr)
			return nil, NewConnectionError(
				fmt.Sprintf("gateway discovery failed (%s): %v", wellKnownURL, doErr),
				WithRetryable(true),
			)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			pkgLogDiscovery().Error("gateway discovery returned non-200 status: url=%s status=%d", wellKnownURL, resp.StatusCode)
			return nil, NewConnectionError(
				fmt.Sprintf("gateway discovery failed (%s): HTTP %d", wellKnownURL, resp.StatusCode),
				WithRetryable(true),
			)
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			pkgLogDiscovery().Error("failed to read gateway discovery response: url=%s err=%v", wellKnownURL, err)
			return nil, NewConnectionError(
				fmt.Sprintf("failed to read gateway discovery response (%s): %v", wellKnownURL, err),
				WithRetryable(true),
			)
		}
	}

	var payload struct {
		Gateways []gatewayEntry `json:"gateways"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		pkgLogDiscovery().Error("failed to parse well-known response: url=%s err=%v", wellKnownURL, err)
		return nil, NewValidationError(fmt.Sprintf("failed to parse well-known response: %v", err))
	}

	if len(payload.Gateways) == 0 {
		pkgLogDiscovery().Error("well-known returned empty gateways list: url=%s", wellKnownURL)
		return nil, NewValidationError("well-known returned empty gateways list")
	}

	// 按 priority 排序（升序）
	sort.Slice(payload.Gateways, func(i, j int) bool {
		pi := payload.Gateways[i].Priority
		pj := payload.Gateways[j].Priority
		if pi == 0 {
			pi = 999
		}
		if pj == 0 {
			pj = 999
		}
		return pi < pj
	})

	for _, gw := range payload.Gateways {
		if gw.URL != "" {
			urls = append(urls, gw.URL)
		}
	}
	if len(urls) == 0 {
		pkgLogDiscovery().Error("well-known missing gateway url: source=%s", wellKnownURL)
		return nil, NewValidationError("well-known missing gateway url")
	}

	pkgLogDiscovery().Debug("gateway discovery succeeded: urls=%v (%d candidates)", urls, len(urls))

	// 发现后异步触发 health check（不阻塞）
	go d.CheckHealth(context.Background(), urls[0], timeout)

	return urls, nil
}
