package e2ee

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// 与 Python _METADATA_KEY_DOMAIN / _PROTECTED_HEADERS_DOMAIN / _PROTECTED_CONTEXT_DOMAIN 对齐。
var (
	metadataKeyDomain      = []byte("aun-envelope-metadata-key-v1")
	protectedHeadersDomain = []byte("aun-protected-headers-v1")
	protectedContextDomain = []byte("aun-protected-context-v1")
)

// metadataAuthTag 计算 HMAC-SHA256 签名标签。
//
// 与 Python `_metadata_auth_tag(key, domain, body)` 字节级对齐：
//   - metadata_key = HMAC-SHA256(key, "aun-envelope-metadata-key-v1")
//   - sign_input = domain + "\0" + canonical_json(body)
//   - tag = HMAC-SHA256(metadata_key, sign_input)
func metadataAuthTag(key []byte, domain []byte, body map[string]any) []byte {
	// 派生 metadata_key
	mac := hmac.New(sha256.New, key)
	mac.Write(metadataKeyDomain)
	metadataKey := mac.Sum(nil)

	// 构造 sign_input = domain + \0 + canonical_json(body)
	bodyJSON := crypto.CanonicalJSON(body)
	signInput := make([]byte, 0, len(domain)+1+len(bodyJSON))
	signInput = append(signInput, domain...)
	signInput = append(signInput, 0)
	signInput = append(signInput, bodyJSON...)

	// 计算 tag
	mac2 := hmac.New(sha256.New, metadataKey)
	mac2.Write(signInput)
	return mac2.Sum(nil)
}

// withMetadataAuth 为 metadata dict 添加 _auth HMAC 签名字段。
//
// 与 Python `_with_metadata_auth(metadata, key=..., domain=...)` 对齐：
//   - 过滤掉 "_auth" 键
//   - 如果剩余为空，返回 nil
//   - 否则计算 HMAC tag，追加 _auth: {alg, tag}
func withMetadataAuth(metadata map[string]any, key []byte, domain []byte) map[string]any {
	// 过滤 _auth
	body := make(map[string]any, len(metadata))
	for k, v := range metadata {
		if k != "_auth" {
			body[k] = v
		}
	}
	if len(body) == 0 {
		return nil
	}

	tag := metadataAuthTag(key, domain, body)

	result := make(map[string]any, len(body)+1)
	for k, v := range body {
		result[k] = v
	}
	result["_auth"] = map[string]any{
		"alg": "HMAC-SHA256",
		"tag": base64.StdEncoding.EncodeToString(tag),
	}
	return result
}

// normalizeProtectedHeaderKey 与 Python ProtectedHeaders._normalize_key 对齐。
func normalizeProtectedHeaderKey(key string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(key))
	if value == "" {
		return "", fmt.Errorf("protected header key must match [a-z0-9_-]+")
	}
	if value == "_auth" {
		return "", fmt.Errorf("protected header key is reserved")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("protected header key must match [a-z0-9_-]+")
	}
	return value, nil
}

// pythonProtectedHeaderValueString 与 Python str(value) 的常见标量语义对齐。
func pythonProtectedHeaderValueString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(x)
	case int8:
		return strconv.FormatInt(int64(x), 10)
	case int16:
		return strconv.FormatInt(int64(x), 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint8:
		return strconv.FormatUint(uint64(x), 10)
	case uint16:
		return strconv.FormatUint(uint64(x), 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float32:
		return pythonProtectedHeaderFloatString(float64(x))
	case float64:
		return pythonProtectedHeaderFloatString(x)
	default:
		return fmt.Sprint(v)
	}
}

func pythonProtectedHeaderFloatString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}
