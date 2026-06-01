package aun

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type agentMDDownloadResult struct {
	AID          string
	Content      string
	Etag         string
	LastModified string
	Status       int
}

type agentMDDownloadCache struct {
	Content      string
	Etag         string
	LastModified string
}

func newAgentMDHTTPClient(verifySSL bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	}
	if !verifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func agentMDSchemeFromGatewayURL(gatewayURL string) string {
	lower := strings.ToLower(strings.TrimSpace(gatewayURL))
	switch {
	case strings.HasPrefix(lower, "ws://"), strings.HasPrefix(lower, "http://"):
		return "http"
	default:
		return "https"
	}
}

func agentMDAuthorityForAID(aid string, discoveryPort int) string {
	host := strings.TrimSpace(aid)
	if host == "" {
		return ""
	}
	if discoveryPort > 0 && !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, discoveryPort)
	}
	return host
}

func agentMDURLFromGateway(gatewayURL, aid string, discoveryPort int) string {
	return fmt.Sprintf(
		"%s://%s/agent.md",
		agentMDSchemeFromGatewayURL(gatewayURL),
		agentMDAuthorityForAID(aid, discoveryPort),
	)
}

func agentMDDownloadHTTP(ctx context.Context, httpClient *http.Client, url, aid string, cached ...agentMDDownloadCache) (agentMDDownloadResult, error) {
	type httpResult struct {
		status       int
		body         []byte
		etag         string
		lastModified string
	}
	doGet := func() (httpResult, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return httpResult{}, err
		}
		req.Header.Set("Accept", "text/markdown")
		resp, err := httpClient.Do(req)
		if err != nil {
			return httpResult{}, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return httpResult{}, err
		}
		return httpResult{
			status:       resp.StatusCode,
			body:         body,
			etag:         strings.TrimSpace(resp.Header.Get("ETag")),
			lastModified: strings.TrimSpace(resp.Header.Get("Last-Modified")),
		}, nil
	}

	r, err := doGet()
	if err != nil {
		return agentMDDownloadResult{}, err
	}
	if r.status == http.StatusNotModified {
		if len(cached) > 0 {
			cache := cached[0]
			etag := strings.TrimSpace(r.etag)
			if etag == "" {
				etag = strings.TrimSpace(cache.Etag)
			}
			lastModified := strings.TrimSpace(r.lastModified)
			if lastModified == "" {
				lastModified = strings.TrimSpace(cache.LastModified)
			}
			return agentMDDownloadResult{
				AID:          aid,
				Content:      cache.Content,
				Etag:         etag,
				LastModified: lastModified,
				Status:       r.status,
			}, nil
		}
		r, err = doGet()
		if err != nil {
			return agentMDDownloadResult{}, err
		}
	}
	if r.status == http.StatusNotFound {
		return agentMDDownloadResult{}, fmt.Errorf("%s: agent.md not found for aid: %s", ErrCodeAgentMdNotFound, aid)
	}
	if r.status < 200 || r.status >= 300 {
		message := strings.TrimSpace(string(r.body))
		if message != "" {
			return agentMDDownloadResult{}, fmt.Errorf("download agent.md failed: HTTP %d - %s", r.status, message)
		}
		return agentMDDownloadResult{}, fmt.Errorf("download agent.md failed: HTTP %d", r.status)
	}

	return agentMDDownloadResult{
		AID:          aid,
		Content:      string(r.body),
		Etag:         strings.TrimSpace(r.etag),
		LastModified: strings.TrimSpace(r.lastModified),
		Status:       r.status,
	}, nil
}

func agentMDHeadHTTP(ctx context.Context, httpClient *http.Client, url, aid string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/markdown")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := map[string]any{
		"aid":           aid,
		"found":         resp.StatusCode >= 200 && resp.StatusCode < 300,
		"etag":          strings.TrimSpace(resp.Header.Get("ETag")),
		"last_modified": strings.TrimSpace(resp.Header.Get("Last-Modified")),
		"status":        resp.StatusCode,
	}
	if resp.StatusCode == http.StatusNotFound {
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("head agent.md failed: HTTP %d", resp.StatusCode)
	}
	return result, nil
}

func agentMDUploadHTTP(ctx context.Context, httpClient *http.Client, url, token, content string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/markdown; charset=utf-8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("agent.md endpoint not found")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		if message != "" {
			return nil, fmt.Errorf("upload agent.md failed: HTTP %d - %s", resp.StatusCode, message)
		}
		return nil, fmt.Errorf("upload agent.md failed: HTTP %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("upload agent.md failed: invalid JSON response: %w", err)
	}
	return result, nil
}
