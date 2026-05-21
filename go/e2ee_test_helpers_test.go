package aun

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testGenerateECKeypair(t *testing.T) (*ecdsa.PrivateKey, string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("序列化公钥失败: %v", err)
	}
	return priv, privPEM, base64.StdEncoding.EncodeToString(pubDER)
}

func testMakeSelfSignedCert(t *testing.T, priv *ecdsa.PrivateKey, cn string) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func testBuildIdentity(aid, privPEM, pubB64, certPEM string) map[string]any {
	return map[string]any{
		"aid":                aid,
		"private_key_pem":    privPEM,
		"public_key_der_b64": pubB64,
		"curve":              "P-256",
		"cert":               certPEM,
	}
}
