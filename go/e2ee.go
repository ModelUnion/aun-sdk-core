package aun

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
)

var protectedHeaderKeyPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

// ProtectedHeaders 是端到端保护的信封元数据，语义接近 HTTP headers。
// V2 路由会把它规范化为普通 map 后交给 go/v2/e2ee。
type ProtectedHeaders struct {
	items map[string]string
}

// NewProtectedHeaders 创建 protected headers 包装对象。
func NewProtectedHeaders(values map[string]any) (*ProtectedHeaders, error) {
	headers := &ProtectedHeaders{items: map[string]string{}}
	for key, value := range values {
		if err := headers.Set(key, value); err != nil {
			return nil, err
		}
	}
	return headers, nil
}

func normalizeProtectedHeaderKey(key any) (string, error) {
	value := strings.ToLower(strings.TrimSpace(fmt.Sprint(key)))
	if value == "" || !protectedHeaderKeyPattern.MatchString(value) {
		return "", fmt.Errorf("protected header key must match [a-z0-9_-]+")
	}
	if value == "_auth" {
		return "", fmt.Errorf("protected header key is reserved")
	}
	return value, nil
}

// Set 设置或覆盖一个 protected header。
func (h *ProtectedHeaders) Set(key string, value any) error {
	if h.items == nil {
		h.items = map[string]string{}
	}
	normalized, err := normalizeProtectedHeaderKey(key)
	if err != nil {
		return err
	}
	if value == nil {
		h.items[normalized] = ""
	} else {
		h.items[normalized] = fmt.Sprint(value)
	}
	return nil
}

// Get 获取一个 protected header。
func (h *ProtectedHeaders) Get(key string) (string, bool) {
	if h == nil {
		return "", false
	}
	normalized, err := normalizeProtectedHeaderKey(key)
	if err != nil {
		return "", false
	}
	value, ok := h.items[normalized]
	return value, ok
}

// Remove 移除一个 protected header。
func (h *ProtectedHeaders) Remove(key string) error {
	if h == nil {
		return nil
	}
	normalized, err := normalizeProtectedHeaderKey(key)
	if err != nil {
		return err
	}
	delete(h.items, normalized)
	return nil
}

// ToMap 返回普通 map 副本。
func (h *ProtectedHeaders) ToMap() map[string]string {
	out := make(map[string]string)
	if h == nil {
		return out
	}
	for key, value := range h.items {
		out[key] = value
	}
	return out
}

// parseECPrivateKeyPEM 从 PEM 解析 EC 私钥。
func parseECPrivateKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM format private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		ecKey, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: PKCS8=%v, EC=%v", err, err2)
		}
		return ecKey, nil
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key type is not ECDSA")
	}
	return ecKey, nil
}

// copyMapShallow 浅拷贝 map。
func copyMapShallow(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// getStr 从 map 获取字符串，不存在时返回默认值。
func getStr(m map[string]any, key, defaultVal string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return defaultVal
}

// toInt64 将 any 转换为 int64。
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

func int64OrDefault(values ...any) int64 {
	for _, value := range values {
		if converted := toInt64(value); converted != 0 {
			return converted
		}
	}
	return 0
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
