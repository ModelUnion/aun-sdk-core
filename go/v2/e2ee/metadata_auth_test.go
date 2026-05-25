package e2ee

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// TestMetadataAuthTag 验证 metadataAuthTag 与 Python _metadata_auth_tag 字节级一致。
func TestMetadataAuthTag(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	domain := []byte("aun-protected-headers-v1")
	body := map[string]any{
		"payload_type": "text",
		"priority":     "high",
	}

	tag := metadataAuthTag(key, domain, body)
	if len(tag) != 32 {
		t.Fatalf("tag 长度应为 32，实际 %d", len(tag))
	}

	// 手动重算验证
	mac1 := hmac.New(sha256.New, key)
	mac1.Write(metadataKeyDomain)
	metadataKey := mac1.Sum(nil)

	bodyJSON := crypto.CanonicalJSON(body)
	signInput := make([]byte, 0, len(domain)+1+len(bodyJSON))
	signInput = append(signInput, domain...)
	signInput = append(signInput, 0)
	signInput = append(signInput, bodyJSON...)

	mac2 := hmac.New(sha256.New, metadataKey)
	mac2.Write(signInput)
	expected := mac2.Sum(nil)

	if !hmac.Equal(tag, expected) {
		t.Fatalf("tag 不一致")
	}
}

// TestWithMetadataAuth 验证 withMetadataAuth 输出结构正确。
func TestWithMetadataAuth(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 10)
	}

	metadata := map[string]any{
		"payload_type": "text",
		"version":      "1.0",
	}

	result := withMetadataAuth(metadata, key, protectedHeadersDomain)
	if result == nil {
		t.Fatal("result 不应为 nil")
	}

	// 验证原始字段保留
	if result["payload_type"] != "text" {
		t.Fatalf("payload_type 丢失: %v", result["payload_type"])
	}
	if result["version"] != "1.0" {
		t.Fatalf("version 丢失: %v", result["version"])
	}

	// 验证 _auth 结构
	auth, ok := result["_auth"].(map[string]any)
	if !ok {
		t.Fatalf("_auth 字段缺失或类型错误: %v", result["_auth"])
	}
	if auth["alg"] != "HMAC-SHA256" {
		t.Fatalf("alg 错误: %v", auth["alg"])
	}
	tagB64, ok := auth["tag"].(string)
	if !ok || tagB64 == "" {
		t.Fatalf("tag 字段缺失或为空: %v", auth["tag"])
	}
	// 验证 tag 是合法 base64
	tagBytes, err := base64.StdEncoding.DecodeString(tagB64)
	if err != nil {
		t.Fatalf("tag base64 解码失败: %v", err)
	}
	if len(tagBytes) != 32 {
		t.Fatalf("tag 解码后长度应为 32，实际 %d", len(tagBytes))
	}
}

// TestWithMetadataAuthEmpty 空 metadata 返回 nil。
func TestWithMetadataAuthEmpty(t *testing.T) {
	key := make([]byte, 32)
	result := withMetadataAuth(map[string]any{}, key, protectedHeadersDomain)
	if result != nil {
		t.Fatalf("空 metadata 应返回 nil，实际: %v", result)
	}
}

// TestWithMetadataAuthFiltersAuth _auth 键应被过滤。
func TestWithMetadataAuthFiltersAuth(t *testing.T) {
	key := make([]byte, 32)
	metadata := map[string]any{
		"_auth": "should_be_filtered",
	}
	result := withMetadataAuth(metadata, key, protectedHeadersDomain)
	if result != nil {
		t.Fatalf("仅含 _auth 的 metadata 应返回 nil，实际: %v", result)
	}
}

func TestNormalizeProtectedHeadersCanonicalParity(t *testing.T) {
	got, err := normalizeProtectedHeaders(map[string]any{
		"Device_ID": "dev-a",
		"Slot_ID":   nil,
		"empty":     "",
		"flag":      true,
		"ratio":     1.0,
		"nested":    map[string]any{"b": 2, "a": 1},
	}, map[string]any{"type": "thought"})
	if err != nil {
		t.Fatalf("normalizeProtectedHeaders 失败: %v", err)
	}
	if got["device_id"] != "dev-a" {
		t.Fatalf("Device_ID 应归一化为 device_id: %#v", got)
	}
	if value, ok := got["slot_id"]; !ok || value != "" {
		t.Fatalf("nil value 应按 Python ProtectedHeaders 保留为空字符串: %#v", got)
	}
	if value, ok := got["empty"]; !ok || value != "" {
		t.Fatalf("空字符串 value 应保留: %#v", got)
	}
	if got["flag"] != "true" {
		t.Fatalf("bool value 应按 canonical JSON 输出 true: %#v", got)
	}
	if got["ratio"] != "1" {
		t.Fatalf("float value 应按 canonical JSON 输出 1: %#v", got)
	}
	if got["nested"] != `{"a":1,"b":2}` {
		t.Fatalf("object value 应按 canonical JSON 输出: %#v", got)
	}
	if got["payload_type"] != "thought" {
		t.Fatalf("payload_type 自动注入失败: %#v", got)
	}
	if got["sdk_lang"] != e2eeSDKLang {
		t.Fatalf("sdk_lang 自动注入失败: %#v", got)
	}
	if got["sdk_vesion"] != e2eeSDKVersion {
		t.Fatalf("sdk_vesion 自动注入失败: %#v", got)
	}
}

func TestNormalizeProtectedHeadersRejectsAuthKey(t *testing.T) {
	if _, err := normalizeProtectedHeaders(map[string]any{"_auth": "bad"}, nil); err == nil {
		t.Fatal("_auth 应作为 protected header 保留字段被拒绝")
	}
}

func TestDecryptRejectsTamperedProtectedHeaders(t *testing.T) {
	sender := makeTestSender(t)
	target, ikPriv, _ := makeTestRecipient(t, "peer", "aid_master", false)
	envelope, err := EncryptP2PMessage(
		sender,
		TargetSet{Targets: []Target{target}},
		map[string]any{"type": "text", "text": "metadata"},
		EncryptOptions{ProtectedHeaders: map[string]any{"trace_id": "trace-1"}},
	)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	headers := envelope["protected_headers"].(map[string]any)
	headers["trace_id"] = "trace-2"
	if _, err := DecryptMessage(envelope, target.AID, target.DeviceID, ikPriv, nil, sender.IKPubDER); err == nil {
		t.Fatal("篡改 protected_headers 后应解密失败")
	} else if !strings.Contains(err.Error(), "protected_headers _auth verification failed") {
		t.Fatalf("错误信息不准确: %v", err)
	}
}

// TestEncryptP2PWithProtectedHeaders 验证 P2P 加密带 protected_headers 时 envelope 包含签名字段。
func TestEncryptP2PWithProtectedHeaders(t *testing.T) {
	sender := makeTestSender(t)
	target, _, _ := makeTestRecipient(t, "peer", "aid_master", false)
	targetSet := TargetSet{Targets: []Target{target}}

	opts := EncryptOptions{
		ProtectedHeaders: map[string]any{
			"payload_type": "text",
			"priority":     "normal",
			"sdk_lang":     "spoofed",
			"sdk_vesion":   "0.0.0",
		},
		Context: map[string]any{
			"thread_id": "t-123",
			"reply_to":  "m-456",
		},
	}

	envelope, err := EncryptP2PMessage(sender, targetSet, map[string]any{"text": "hello"}, opts)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 验证 protected_headers 存在且含 _auth
	ph, ok := envelope["protected_headers"].(map[string]any)
	if !ok {
		t.Fatalf("envelope 缺少 protected_headers: %v", envelope["protected_headers"])
	}
	if ph["payload_type"] != "text" {
		t.Fatalf("protected_headers.payload_type 错误: %v", ph["payload_type"])
	}
	if ph["sdk_lang"] != e2eeSDKLang || ph["sdk_vesion"] != e2eeSDKVersion {
		t.Fatalf("protected_headers SDK 元信息错误: %v", ph)
	}
	phAuth, ok := ph["_auth"].(map[string]any)
	if !ok {
		t.Fatalf("protected_headers._auth 缺失: %v", ph["_auth"])
	}
	if phAuth["alg"] != "HMAC-SHA256" {
		t.Fatalf("protected_headers._auth.alg 错误: %v", phAuth["alg"])
	}

	// 验证 context 存在且含 _auth
	ctx, ok := envelope["context"].(map[string]any)
	if !ok {
		t.Fatalf("envelope 缺少 context: %v", envelope["context"])
	}
	if ctx["thread_id"] != "t-123" {
		t.Fatalf("context.thread_id 错误: %v", ctx["thread_id"])
	}
	ctxAuth, ok := ctx["_auth"].(map[string]any)
	if !ok {
		t.Fatalf("context._auth 缺失: %v", ctx["_auth"])
	}
	if ctxAuth["alg"] != "HMAC-SHA256" {
		t.Fatalf("context._auth.alg 错误: %v", ctxAuth["alg"])
	}
}

// TestEncryptP2PWithoutProtectedHeaders 不传 protected_headers 时 envelope 不含该字段。
func TestEncryptP2PWithoutProtectedHeaders(t *testing.T) {
	sender := makeTestSender(t)
	target, _, _ := makeTestRecipient(t, "peer", "aid_master", false)
	targetSet := TargetSet{Targets: []Target{target}}

	envelope, err := EncryptP2PMessage(sender, targetSet, map[string]any{"text": "hello"}, EncryptOptions{})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	ph, ok := envelope["protected_headers"].(map[string]any)
	if !ok {
		t.Fatalf("不传 ProtectedHeaders 时 envelope 仍应含 SDK protected_headers: %#v", envelope["protected_headers"])
	}
	if ph["sdk_lang"] != e2eeSDKLang || ph["sdk_vesion"] != e2eeSDKVersion {
		t.Fatalf("protected_headers SDK 元信息错误: %#v", ph)
	}
	if _, ok := envelope["context"]; ok {
		t.Fatalf("不传 Context 时 envelope 不应含 context 字段")
	}
}

// TestEncryptGroupWithProtectedHeaders 验证 Group 加密带 protected_headers。
func TestEncryptGroupWithProtectedHeaders(t *testing.T) {
	sender := makeTestSender(t)
	target, _, _ := makeTestRecipient(t, "member", "aid_master", false)

	opts := EncryptOptions{
		ProtectedHeaders: map[string]any{
			"payload_type": "image",
		},
	}

	envelope, err := EncryptGroupMessage(sender, "g-test.aid.com", 1,
		[]Target{target}, map[string]any{"url": "https://example.com/img.png"}, opts, nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	ph, ok := envelope["protected_headers"].(map[string]any)
	if !ok {
		t.Fatalf("envelope 缺少 protected_headers")
	}
	if ph["payload_type"] != "image" {
		t.Fatalf("protected_headers.payload_type 错误: %v", ph["payload_type"])
	}
	if ph["sdk_lang"] != e2eeSDKLang || ph["sdk_vesion"] != e2eeSDKVersion {
		t.Fatalf("protected_headers SDK 元信息错误: %v", ph)
	}
	phAuth, ok := ph["_auth"].(map[string]any)
	if !ok {
		t.Fatalf("protected_headers._auth 缺失")
	}
	if phAuth["alg"] != "HMAC-SHA256" {
		t.Fatalf("alg 错误: %v", phAuth["alg"])
	}
}
