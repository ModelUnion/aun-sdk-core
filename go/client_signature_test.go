package aun

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ── 测试辅助：生成 ECDSA 密钥对 + 自签名证书 ─────────────────

// genTestIdentity 生成测试用 ECDSA 密钥对和自签名证书，返回 PEM 编码的私钥、证书及原始私钥。
func genTestIdentity(t *testing.T) (privPEM string, certPEM string, privKey *ecdsa.PrivateKey) {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 密钥失败: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-aid@example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		t.Fatalf("创建自签名证书失败: %v", err)
	}

	// 私钥 PEM（PKCS8）
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		t.Fatalf("编码 PKCS8 私钥失败: %v", err)
	}
	privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}
	privPEM = string(pem.EncodeToMemory(privBlock))

	// 证书 PEM
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = string(pem.EncodeToMemory(certBlock))

	return privPEM, certPEM, pk
}

// ── 1. signedMethods 覆盖测试 ─────────────────────────────

func TestSignedMethodsCoverage(t *testing.T) {
	expected := []string{
		"group.send",
		"group.kick",
		"group.add_member",
		"group.leave",
		"group.remove_member",
		"group.update_rules",
		"group.update",
		"group.update_announcement",
		"group.update_join_requirements",
		"group.set_role",
		"group.transfer_owner",
		"group.review_join_request",
		"group.batch_review_join_request",
		"group.resources.put",
		"group.resources.update",
		"group.resources.delete",
		"group.resources.request_add",
		"group.resources.direct_add",
		"group.resources.approve_request",
		"group.resources.reject_request",
		"group.request_join",
		"group.use_invite_code",
	}

	if len(signedMethods) != len(expected) {
		t.Errorf("signedMethods 数量不匹配: 预期 %d, 实际 %d", len(expected), len(signedMethods))
	}

	for _, m := range expected {
		if !signedMethods[m] {
			t.Errorf("signedMethods 缺少方法: %s", m)
		}
	}
}

// ── 2. signClientOperation 产生 cert_fingerprint ──────────

func TestSignClientOperation_ContainsCertFingerprint(t *testing.T) {
	privPEM, certPEM, _ := genTestIdentity(t)

	c := &AUNClient{
		identity: map[string]any{
			"aid":             "test-aid@example.com",
			"private_key_pem": privPEM,
			"cert":            certPEM,
		},
		certCache: make(map[string]*cachedPeerCert),
	}

	params := map[string]any{
		"group_id": "g1",
		"content":  "hello",
	}
	c.signClientOperation("group.send", params)

	sig, ok := params["client_signature"].(map[string]any)
	if !ok {
		t.Fatal("client_signature 未生成或类型错误")
	}

	fp, ok := sig["cert_fingerprint"].(string)
	if !ok || fp == "" {
		t.Fatal("cert_fingerprint 缺失或为空")
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("cert_fingerprint 应以 sha256: 开头: %s", fp)
	}
	// sha256: + 64 个十六进制字符 = 71 字符
	hexPart := strings.TrimPrefix(fp, "sha256:")
	if len(hexPart) != 64 {
		t.Errorf("cert_fingerprint 的 hex 部分长度应为 64: 实际 %d (%s)", len(hexPart), hexPart)
	}

	// 验证其他必需字段
	for _, field := range []string{"aid", "timestamp", "params_hash", "signature"} {
		if sig[field] == nil {
			t.Errorf("client_signature 缺少字段: %s", field)
		}
	}
}

// ── 3. signClientOperation 排除内部字段 ───────────────────

func TestSignClientOperation_ExcludesInternalFields(t *testing.T) {
	privPEM, certPEM, _ := genTestIdentity(t)

	c := &AUNClient{
		identity: map[string]any{
			"aid":             "test-aid@example.com",
			"private_key_pem": privPEM,
			"cert":            certPEM,
		},
		certCache: make(map[string]*cachedPeerCert),
	}

	// 带内部字段的参数
	params1 := map[string]any{
		"group_id": "g1",
		"content":  "hello",
		"_auth":    "some_token",
		"_session": "sess123",
	}
	c.signClientOperation("group.send", params1)

	// 不带内部字段的参数
	params2 := map[string]any{
		"group_id": "g1",
		"content":  "hello",
	}
	c.signClientOperation("group.send", params2)

	sig1 := params1["client_signature"].(map[string]any)
	sig2 := params2["client_signature"].(map[string]any)

	hash1 := sig1["params_hash"].(string)
	hash2 := sig2["params_hash"].(string)

	if hash1 != hash2 {
		t.Errorf("_ 前缀字段不应参与 params_hash 计算: hash1=%s hash2=%s", hash1, hash2)
	}
}

// ── 4. signClientOperation identity 为 nil ────────────────

func TestSignClientOperation_NilIdentity(t *testing.T) {
	c := &AUNClient{
		identity:  nil,
		certCache: make(map[string]*cachedPeerCert),
	}

	params := map[string]any{
		"group_id": "g1",
	}
	c.signClientOperation("group.send", params)

	if _, ok := params["client_signature"]; ok {
		t.Error("identity 为 nil 时不应产生 client_signature")
	}
}

// ── 5. verifyEventSignature 有效签名 ──────────────────────

func TestVerifyEventSignature_ValidSignature(t *testing.T) {
	privPEM, certPEM, _ := genTestIdentity(t)
	aid := "test-aid@example.com"

	c := &AUNClient{
		identity: map[string]any{
			"aid":             aid,
			"private_key_pem": privPEM,
			"cert":            certPEM,
		},
		certCache: make(map[string]*cachedPeerCert),
	}

	// 使用 signClientOperation 生成真实签名
	params := map[string]any{
		"group_id": "g1",
		"content":  "hello",
	}
	c.signClientOperation("group.send", params)

	sig := params["client_signature"].(map[string]any)
	expectedFP, _ := sig["cert_fingerprint"].(string)

	// 将证书缓存到 certCache
	c.certCacheMu.Lock()
	c.certCache[certCacheKey(aid, expectedFP)] = &cachedPeerCert{
		certBytes:    []byte(certPEM),
		validatedAt:  float64(time.Now().Unix()),
		refreshAfter: float64(time.Now().Unix()) + peerCertCacheTTL,
	}
	c.certCacheMu.Unlock()

	// 构建 verifyEventSignature 所需的 cs map（包含 _method）
	cs := map[string]any{
		"aid":              sig["aid"],
		"cert_fingerprint": sig["cert_fingerprint"],
		"timestamp":        sig["timestamp"],
		"params_hash":      sig["params_hash"],
		"signature":        sig["signature"],
		"_method":          "group.send",
	}

	result := c.verifyEventSignature(cs)
	if result != true {
		t.Errorf("有效签名验签应返回 true, 实际: %v", result)
	}
}

// ── 6. verifyEventSignature 篡改 params_hash ─────────────

func TestVerifyEventSignature_TamperedHash(t *testing.T) {
	privPEM, certPEM, _ := genTestIdentity(t)
	aid := "test-aid@example.com"

	c := &AUNClient{
		identity: map[string]any{
			"aid":             aid,
			"private_key_pem": privPEM,
			"cert":            certPEM,
		},
		certCache: make(map[string]*cachedPeerCert),
	}

	params := map[string]any{
		"group_id": "g1",
		"content":  "hello",
	}
	c.signClientOperation("group.send", params)
	sig := params["client_signature"].(map[string]any)
	expectedFP, _ := sig["cert_fingerprint"].(string)

	// 缓存证书
	c.certCacheMu.Lock()
	c.certCache[certCacheKey(aid, expectedFP)] = &cachedPeerCert{
		certBytes:    []byte(certPEM),
		validatedAt:  float64(time.Now().Unix()),
		refreshAfter: float64(time.Now().Unix()) + peerCertCacheTTL,
	}
	c.certCacheMu.Unlock()

	// 篡改 params_hash
	cs := map[string]any{
		"aid":              sig["aid"],
		"cert_fingerprint": sig["cert_fingerprint"],
		"timestamp":        sig["timestamp"],
		"params_hash":      "0000000000000000000000000000000000000000000000000000000000000000",
		"signature":        sig["signature"],
		"_method":          "group.send",
	}

	result := c.verifyEventSignature(cs)
	if result != false {
		t.Errorf("篡改 params_hash 后验签应返回 false, 实际: %v", result)
	}
}

// ── 7. verifyEventSignature 错误 cert_fingerprint ────────

func TestVerifyEventSignature_WrongFingerprint(t *testing.T) {
	privPEM, certPEM, _ := genTestIdentity(t)
	aid := "test-aid@example.com"

	c := &AUNClient{
		identity: map[string]any{
			"aid":             aid,
			"private_key_pem": privPEM,
			"cert":            certPEM,
		},
		certCache: make(map[string]*cachedPeerCert),
	}

	params := map[string]any{
		"group_id": "g1",
		"content":  "hello",
	}
	c.signClientOperation("group.send", params)
	sig := params["client_signature"].(map[string]any)
	wrongFP := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// 缓存证书
	c.certCacheMu.Lock()
	c.certCache[certCacheKey(aid, wrongFP)] = &cachedPeerCert{
		certBytes:    []byte(certPEM),
		validatedAt:  float64(time.Now().Unix()),
		refreshAfter: float64(time.Now().Unix()) + peerCertCacheTTL,
	}
	c.certCacheMu.Unlock()

	// 错误的 cert_fingerprint
	cs := map[string]any{
		"aid":              sig["aid"],
		"cert_fingerprint": wrongFP,
		"timestamp":        sig["timestamp"],
		"params_hash":      sig["params_hash"],
		"signature":        sig["signature"],
		"_method":          "group.send",
	}

	result := c.verifyEventSignature(cs)
	if result != false {
		t.Errorf("错误 cert_fingerprint 验签应返回 false, 实际: %v", result)
	}
}

// ── 8. verifyEventSignature 无缓存证书 ───────────────────

func TestVerifyEventSignature_NoCachedCert(t *testing.T) {
	c := &AUNClient{
		certCache: make(map[string]*cachedPeerCert),
	}

	// 构建签名数据但不缓存证书
	fakeHash := fmt.Sprintf("%x", sha256.Sum256([]byte("fake")))
	cs := map[string]any{
		"aid":              "unknown-aid@example.com",
		"cert_fingerprint": "sha256:" + fakeHash,
		"timestamp":        "1700000000",
		"params_hash":      fakeHash,
		"signature":        base64.StdEncoding.EncodeToString([]byte("fake-sig")),
		"_method":          "group.send",
	}

	result := c.verifyEventSignature(cs)
	if result != "pending" {
		t.Errorf("无缓存证书验签应返回 \"pending\", 实际: %v", result)
	}
}
