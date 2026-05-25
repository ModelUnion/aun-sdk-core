package e2ee

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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

func verifyMetadataAuth(metadata any, key []byte, domain []byte, fieldName string) error {
	if metadata == nil {
		return nil
	}
	obj, ok := metadata.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", fieldName)
	}
	body := make(map[string]any, len(obj))
	for k, v := range obj {
		if k != "_auth" {
			body[k] = v
		}
	}
	if len(body) == 0 {
		return nil
	}
	auth, ok := obj["_auth"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s missing _auth", fieldName)
	}
	if alg, _ := auth["alg"].(string); alg != "HMAC-SHA256" {
		return fmt.Errorf("%s unsupported _auth alg", fieldName)
	}
	tagB64, _ := auth["tag"].(string)
	if tagB64 == "" {
		return fmt.Errorf("%s missing _auth tag", fieldName)
	}
	actual, err := base64.StdEncoding.DecodeString(tagB64)
	if err != nil {
		return fmt.Errorf("%s invalid _auth tag: %w", fieldName, err)
	}
	expected := metadataAuthTag(key, domain, body)
	if !hmac.Equal(actual, expected) {
		return fmt.Errorf("%s _auth verification failed", fieldName)
	}
	return nil
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

// protectedHeaderValueString 使用语言无关规则把 header value 转为字符串：
// string 原样，nil 为空串，其它 JSON 值使用 canonical JSON。
func protectedHeaderValueString(v any) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	default:
		return string(crypto.CanonicalJSON(x)), nil
	}
}
