package aun

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DnsResilientNet 统一 DNS 容灾网络层。
// 使用独立的 SQLite 文件 `{aun_path}/dns_cache.db` 持久化 DNS 缓存。
type DnsResilientNet struct {
	db        *sql.DB
	mu        sync.Mutex
	verifySSL bool
}

// NewDnsResilientNet 创建 DNS 容灾网络层
func NewDnsResilientNet(aunPath string, verifySSL bool) *DnsResilientNet {
	n := &DnsResilientNet{verifySSL: verifySSL}
	if aunPath != "" {
		dbPath := aunPath + "/dns_cache.db"
		db, err := sql.Open("sqlite", dbPath)
		if err == nil {
			_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS dns_cache (
				hostname TEXT PRIMARY KEY,
				ip TEXT NOT NULL,
				port INTEGER NOT NULL DEFAULT 443,
				updated_at INTEGER NOT NULL
			)`)
			_, _ = db.Exec("PRAGMA journal_mode=WAL")
			n.db = db
		}
	}
	return n
}

// Close 关闭数据库连接
func (n *DnsResilientNet) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.db == nil {
		return
	}
	_ = n.db.Close()
	n.db = nil
}

func (n *DnsResilientNet) saveDNSCache(hostname, ip string, port int) {
	if n.db == nil || hostname == "" || ip == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, _ = n.db.Exec(
		"INSERT OR REPLACE INTO dns_cache (hostname, ip, port, updated_at) VALUES (?, ?, ?, ?)",
		hostname, ip, port, time.Now().Unix(),
	)
}

func (n *DnsResilientNet) loadDNSCache(hostname string) (ip string, port int, ok bool) {
	if n.db == nil || hostname == "" {
		return "", 0, false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	row := n.db.QueryRow("SELECT ip, port FROM dns_cache WHERE hostname = ?", hostname)
	if err := row.Scan(&ip, &port); err != nil {
		return "", 0, false
	}
	return ip, port, true
}

func (n *DnsResilientNet) refreshDNSCacheAfterSuccess(rawURL string) {
	hostname, port := parseHostPort(rawURL)
	if hostname == "" {
		return
	}
	ip := resolveIP(hostname)
	if ip != "" {
		n.saveDNSCache(hostname, ip, port)
	}
}

// HTTPGet DNS 容灾 HTTP GET
func (n *DnsResilientNet) HTTPGet(ctx context.Context, targetURL string, timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	hostname, port := parseHostPort(targetURL)

	// 1. 正常请求（域名）
	body, err := n.doHTTPGet(ctx, targetURL, "", timeout)
	if err == nil {
		n.refreshDNSCacheAfterSuccess(targetURL)
		return body, nil
	}
	if !isDNSError(err) {
		return nil, err
	}

	// 2. DNS 失败 → fallback 到缓存 IP
	cachedIP, cachedPort, ok := n.loadDNSCache(hostname)
	if !ok {
		return nil, fmt.Errorf("DNS failed and no cached IP for %s: %w", hostname, err)
	}
	_ = cachedPort
	ipURL := replaceHostWithIP(targetURL, cachedIP, port)
	return n.doHTTPGet(ctx, ipURL, hostname, timeout)
}

// HTTPGetJSON DNS 容灾 HTTP GET JSON
func (n *DnsResilientNet) HTTPGetJSON(ctx context.Context, targetURL string, timeout time.Duration) (map[string]any, error) {
	body, err := n.HTTPGet(ctx, targetURL, timeout)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s: %w", targetURL, err)
	}
	return payload, nil
}

// HTTPGetOK DNS 容灾 HTTP GET 状态检查
func (n *DnsResilientNet) HTTPGetOK(ctx context.Context, targetURL string, timeout time.Duration) bool {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	hostname, port := parseHostPort(targetURL)

	ok, err := n.doHTTPGetOK(ctx, targetURL, "", timeout)
	if err == nil && ok {
		n.refreshDNSCacheAfterSuccess(targetURL)
		return true
	}
	if err != nil && !isDNSError(err) {
		return false
	}

	cachedIP, _, cached := n.loadDNSCache(hostname)
	if !cached {
		return false
	}
	ipURL := replaceHostWithIP(targetURL, cachedIP, port)
	ok, _ = n.doHTTPGetOK(ctx, ipURL, hostname, timeout)
	return ok
}

func (n *DnsResilientNet) httpClient(serverName string) *http.Client {
	transport := &http.Transport{}
	if !n.verifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else if serverName != "" {
		transport.TLSClientConfig = &tls.Config{ServerName: serverName}
	}
	return &http.Client{Transport: transport}
}

func (n *DnsResilientNet) doHTTPGet(ctx context.Context, targetURL, sniHostname string, timeout time.Duration) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	if sniHostname != "" {
		req.Host = sniHostname
	}

	client := n.httpClient(sniHostname)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, targetURL)
	}
	return io.ReadAll(resp.Body)
}

func (n *DnsResilientNet) doHTTPGetOK(ctx context.Context, targetURL, sniHostname string, timeout time.Duration) (bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return false, err
	}
	if sniHostname != "" {
		req.Host = sniHostname
	}

	client := n.httpClient(sniHostname)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// ── 工具函数 ──────────────────────────────────────────────

func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "name or service not known") ||
		strings.Contains(msg, "server misbehaving") ||
		strings.Contains(msg, "i/o timeout") && strings.Contains(msg, "lookup")
}

func parseHostPort(rawURL string) (string, int) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", 443
	}
	hostname := parsed.Hostname()
	port := 443
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	} else if parsed.Scheme == "http" || parsed.Scheme == "ws" {
		port = 80
	}
	return hostname, port
}

func replaceHostWithIP(rawURL, ip string, port int) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	hostPart := ip
	if strings.Contains(ip, ":") {
		hostPart = "[" + ip + "]"
	}
	if parsed.Port() != "" {
		parsed.Host = fmt.Sprintf("%s:%s", hostPart, parsed.Port())
	} else {
		parsed.Host = hostPart
	}
	return parsed.String()
}

func resolveIP(hostname string) string {
	ips, err := net.LookupHost(hostname)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}
