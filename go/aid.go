package aun

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// AID 是 Agent Identity 的值对象，封装证书和可选私钥。
// 与 Python SDK aid.py 的 AID dataclass 对应。
type AID struct {
	Aid             string
	AunPath         string
	CertPem         string
	PublicKey       string // DER base64（SPKI 格式）
	CertSubject     string
	CertNotBefore   time.Time
	CertNotAfter    time.Time
	CertIssuer      string
	CertFingerprint string // "sha256:" + hex
	PublicKeyFingerprint string // "sha256:" + SPKI hex
	DeviceID        string // 设备 ID，由 AIDStore 注入
	SlotID          string // 密钥槽 ID，由 AIDStore 注入
	VerifySSL       bool   // 是否校验 TLS 证书，由 AIDStore 注入
	RootCaPath      string // 自定义根证书路径，由 AIDStore 注入
	Debug           bool   // 调试模式，由 AIDStore 注入
	// PrivateKeyPem 是 AIDStore 加载时注入的明文私钥 PEM，供 AUNClient 直接使用（无需 seed）
	PrivateKeyPem string

	// 私有字段
	certObj    *x509.Certificate
	privateKey crypto.PrivateKey // 可为 nil
	certValid  bool
	pkValid    bool
}

// newAID 内部构造函数，由 AIDStore.Load 调用。
func newAID(
	aid, aunPath, certPem string,
	certObj *x509.Certificate,
	privateKey crypto.PrivateKey,
	certValid, pkValid bool,
	deviceID, slotID string,
	verifySSL bool, rootCaPath string, debug bool,
	privateKeyPem string,
) *AID {
	a := &AID{
		Aid:           strings.TrimSpace(aid),
		AunPath:       strings.TrimSpace(aunPath),
		CertPem:       certPem,
		PrivateKeyPem: privateKeyPem,
		certObj:       certObj,
		privateKey:    privateKey,
		certValid:     certValid,
		pkValid:       pkValid,
	}
	a.DeviceID = deviceID
	a.SlotID = slotID
	a.VerifySSL = verifySSL
	a.RootCaPath = rootCaPath
	a.Debug = debug
	if certObj != nil {
		if der, err := x509.MarshalPKIXPublicKey(certObj.PublicKey); err == nil {
			a.PublicKey = base64.StdEncoding.EncodeToString(der)
			fp := sha256.Sum256(der)
			a.PublicKeyFingerprint = "sha256:" + fmt.Sprintf("%x", fp)
		}
		a.CertSubject = certObj.Subject.CommonName
		a.CertNotBefore = certObj.NotBefore
		a.CertNotAfter = certObj.NotAfter
		a.CertIssuer = certObj.Issuer.CommonName
		fp := sha256.Sum256(certObj.Raw)
		a.CertFingerprint = "sha256:" + fmt.Sprintf("%x", fp)
	}
	return a
}

// IsCertValid 证书是否有效（已加载且时间有效）
func (a *AID) IsCertValid() bool { return a.certValid }

// IsPrivateKeyValid 私钥是否有效（已加载且与证书匹配）
func (a *AID) IsPrivateKeyValid() bool { return a.pkValid }

// Sign 使用私钥对 payload 签名，返回 base64 编码的 DER 签名。
func (a *AID) Sign(payload []byte) (string, error) {
	if !a.pkValid || a.privateKey == nil {
		return "", fmt.Errorf("%s: private key is not valid", ErrCodePrivateKeyNotValid)
	}
	sig, err := aidSignBytes(a.privateKey, payload)
	if err != nil {
		return "", fmt.Errorf("%s: %w", ErrCodeSignatureOperationError, err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify 使用证书公钥验证签名，signature 为 base64 编码的 DER 签名。
func (a *AID) Verify(payload []byte, signature string) (bool, error) {
	if !a.certValid || a.certObj == nil {
		return false, fmt.Errorf("%s: certificate is not valid", ErrCodeCertNotValid)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("%s: invalid base64 signature", ErrCodeVerificationOperationError)
	}
	err = verifySignature(a.certObj.PublicKey, sigBytes, payload)
	if err != nil {
		// 签名不匹配（非系统错误）返回 false, nil
		if strings.Contains(err.Error(), "verification failed") {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", ErrCodeVerificationOperationError, err)
	}
	return true, nil
}

// SignAgentMd 对 agent.md 内容签名，返回附加签名块后的完整内容。
func (a *AID) SignAgentMd(content string) (string, error) {
	if !a.pkValid || a.privateKey == nil {
		return "", fmt.Errorf("%s: private key is not valid", ErrCodePrivateKeyNotValid)
	}
	payload := aidNormalizeAgentMdPayload(content)
	sig, err := aidSignBytes(a.privateKey, []byte(payload))
	if err != nil {
		return "", fmt.Errorf("%s: %w", ErrCodeSignatureOperationError, err)
	}
	block := aidBuildAgentMdSignatureBlock(
		a.CertFingerprint,
		a.PublicKeyFingerprint,
		time.Now().Unix(),
		base64.StdEncoding.EncodeToString(sig),
	)
	return payload + block, nil
}

// VerifyAgentMdResult VerifyAgentMd 的返回结果
type VerifyAgentMdResult struct {
	Status          string // "verified" | "unsigned" | "invalid"
	Payload         string
	AID             string
	CertFingerprint string
	PublicKeyFingerprint string
	Timestamp       int64
	Reason          string
}

// VerifyAgentMd 验证 agent.md 内容的签名。
func (a *AID) VerifyAgentMd(content string) (*VerifyAgentMdResult, error) {
	if !a.certValid || a.certObj == nil {
		return nil, fmt.Errorf("%s: certificate is not valid", ErrCodeCertNotValid)
	}
	payload, fields, parseErr := aidParseAgentMdTailSignature(content)
	if fields == nil {
		if parseErr == "" {
			return &VerifyAgentMdResult{Status: "unsigned", Payload: payload}, nil
		}
		return &VerifyAgentMdResult{Status: "invalid", Payload: payload, Reason: parseErr}, nil
	}
	// 规范化 payload（确保末尾换行），与 SignAgentMd 签名时一致
	normalizedPayload := payload
	if normalizedPayload != "" && !strings.HasSuffix(normalizedPayload, "\n") && !strings.HasSuffix(normalizedPayload, "\r") {
		normalizedPayload += "\n"
	}

	payloadAID := aidExtractAgentMdAID(payload)
	if payloadAID != "" && payloadAID != a.Aid {
		return &VerifyAgentMdResult{Status: "invalid", Payload: payload, AID: payloadAID, Reason: "aid mismatch"}, nil
	}
	if !matchCertFingerprint([]byte(a.CertPem), fields["cert_fingerprint"]) {
		return &VerifyAgentMdResult{Status: "invalid", Payload: payload, AID: a.Aid, Reason: "certificate fingerprint mismatch"}, nil
	}
	publicKeyFP := strings.TrimSpace(fields["public_key_fingerprint"])
	if publicKeyFP != "" && !matchPublicKeyFingerprint([]byte(a.CertPem), publicKeyFP) {
		return &VerifyAgentMdResult{Status: "invalid", Payload: payload, AID: a.Aid, Reason: "public key fingerprint mismatch"}, nil
	}

	sigBytes, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return &VerifyAgentMdResult{Status: "invalid", Payload: payload, AID: a.Aid, Reason: "invalid signature encoding"}, nil
	}
	if err := verifySignature(a.certObj.PublicKey, sigBytes, []byte(normalizedPayload)); err != nil {
		return &VerifyAgentMdResult{Status: "invalid", Payload: payload, AID: a.Aid, Reason: "signature verification failed"}, nil
	}

	ts := int64(0)
	fmt.Sscanf(fields["timestamp"], "%d", &ts)
	return &VerifyAgentMdResult{
		Status:          "verified",
		Payload:         payload,
		AID:             a.Aid,
		CertFingerprint: fields["cert_fingerprint"],
		PublicKeyFingerprint: publicKeyFP,
		Timestamp:       ts,
	}, nil
}

// ── 内部辅助函数 ──────────────────────────────────────────────

// aidSignBytes 使用私钥对 payload 签名（ECDSA P-256 SHA-256，DER 编码）
func aidSignBytes(key crypto.PrivateKey, payload []byte) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported curve: %v", ecKey.Curve)
	}
	h := sha256.Sum256(payload)
	return ecdsa.SignASN1(cryptorand.Reader, ecKey, h[:])
}

// aidNormalizeAgentMdPayload 规范化 agent.md payload（去签名块，确保末尾换行）
func aidNormalizeAgentMdPayload(content string) string {
	payload, _, _ := aidParseAgentMdTailSignature(content)
	if payload != "" && !strings.HasSuffix(payload, "\n") && !strings.HasSuffix(payload, "\r") {
		payload += "\n"
	}
	return payload
}

// aidBuildAgentMdSignatureBlock 构造 agent.md 签名块
func aidBuildAgentMdSignatureBlock(certFingerprint string, publicKeyFingerprint string, timestamp int64, signatureB64 string) string {
	lines := []string{
		"<!-- AUN-SIGNATURE",
		fmt.Sprintf("cert_fingerprint: %s", certFingerprint),
	}
	if strings.TrimSpace(publicKeyFingerprint) != "" {
		lines = append(lines, fmt.Sprintf("public_key_fingerprint: %s", publicKeyFingerprint))
	}
	lines = append(lines,
		fmt.Sprintf("timestamp: %d", timestamp),
		fmt.Sprintf("signature: %s", signatureB64),
		"-->",
	)
	return strings.Join(lines, "\n")
}

// aidParseAgentMdTailSignature 解析 agent.md 尾部签名块
// 返回 (payload, fields, parseError)；fields 为 nil 表示无签名块或解析失败
func aidParseAgentMdTailSignature(content string) (string, map[string]string, string) {
	marker := "<!-- AUN-SIGNATURE"
	idx := strings.LastIndex(content, marker)
	if idx < 0 {
		return content, nil, ""
	}
	if idx > 0 {
		prev := content[idx-1]
		if prev != '\n' && prev != '\r' {
			return content, nil, ""
		}
	}
	tail := content[idx:]
	end := strings.Index(tail, "-->")
	if end < 0 {
		return content[:idx], nil, "malformed signature block"
	}
	body := tail[len(marker):end]
	body = strings.TrimLeft(body, "\r\n")
	body = strings.TrimRight(body, "\r\n ")

	fields := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			return content[:idx], nil, "malformed signature field: " + line
		}
		k := strings.TrimSpace(strings.ToLower(line[:colon]))
		v := strings.TrimSpace(line[colon+1:])
		fields[k] = v
	}
	for _, req := range []string{"cert_fingerprint", "timestamp", "signature"} {
		if fields[req] == "" {
			return content[:idx], nil, "signature block missing " + req
		}
	}
	if normalizeFingerprintHex(fields["cert_fingerprint"]) == "" {
		return content[:idx], nil, "invalid cert_fingerprint"
	}
	if fields["public_key_fingerprint"] != "" && normalizeFingerprintHex(fields["public_key_fingerprint"]) == "" {
		return content[:idx], nil, "invalid public_key_fingerprint"
	}
	return content[:idx], fields, ""
}

// aidExtractAgentMdAID 从 agent.md frontmatter 提取 aid 字段
func aidExtractAgentMdAID(payload string) string {
	payload = strings.TrimPrefix(payload, "\xef\xbb\xbf")
	lines := strings.Split(payload, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return ""
	}
	for _, line := range lines[1:] {
		t := strings.TrimSpace(line)
		if t == "---" {
			break
		}
		if strings.HasPrefix(t, "aid:") {
			v := strings.TrimSpace(t[4:])
			if len(v) >= 2 && v[0] == v[len(v)-1] && (v[0] == '"' || v[0] == '\'') {
				v = v[1 : len(v)-1]
			}
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parsePEMCertificate 解析 PEM 证书（供 AIDStore 使用）
func parsePEMCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// certTimeError 检查证书时间有效性，返回 "" | "expired" | "not_yet_valid"
func certTimeError(cert *x509.Certificate) string {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return "not_yet_valid"
	}
	if now.After(cert.NotAfter) {
		return "expired"
	}
	return ""
}
