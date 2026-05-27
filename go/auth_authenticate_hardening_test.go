package aun

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// 防线 A 测试：loadIdentityOrRaise 严格化

// stubKeystoreReturning 让 LoadIdentity 返回固定 map（半成品场景）。
type stubKeystoreReturning struct {
	keystore.KeyStore
	stub map[string]any
}

func (s *stubKeystoreReturning) LoadIdentity(aid string) (map[string]any, error) {
	if s.stub == nil {
		return nil, nil
	}
	out := make(map[string]any, len(s.stub))
	for k, v := range s.stub {
		out[k] = v
	}
	return out, nil
}

func newStubAuthFlow(t *testing.T, stub map[string]any) *AuthFlow {
	t.Helper()
	dir := t.TempDir()
	base, err := keystore.NewFileKeyStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	t.Cleanup(func() { base.Close() })
	ks := &stubKeystoreReturning{KeyStore: base, stub: stub}
	return NewAuthFlow(AuthFlowConfig{
		Keystore:  ks,
		Crypto:    &CryptoProvider{},
		VerifySSL: false,
	})
}

func TestLoadIdentityOrRaise_RejectsMissingPrivateKey(t *testing.T) {
	flow := newStubAuthFlow(t, map[string]any{
		"aid":                "missing-priv.example.com",
		"public_key_der_b64": "Zm9v",
		"gateway_url":        "wss://gw.example/aun",
	})
	_, err := flow.loadIdentityOrRaise("missing-priv.example.com")
	if err == nil {
		t.Fatal("expected StateError for missing private_key_pem, got nil")
	}
	if _, ok := err.(*StateError); !ok {
		t.Fatalf("expected *StateError, got %T: %v", err, err)
	}
}

func TestLoadIdentityOrRaise_RejectsMissingPublicKey(t *testing.T) {
	flow := newStubAuthFlow(t, map[string]any{
		"aid":             "missing-pub.example.com",
		"private_key_pem": "-----BEGIN PRIVATE KEY-----\nfoo\n-----END PRIVATE KEY-----",
	})
	_, err := flow.loadIdentityOrRaise("missing-pub.example.com")
	if err == nil {
		t.Fatal("expected StateError for missing public_key_der_b64, got nil")
	}
	if _, ok := err.(*StateError); !ok {
		t.Fatalf("expected *StateError, got %T: %v", err, err)
	}
}

// 防线 B 测试：assertCertMatchesLocalKeypair

func generateP256IdentityKeypair(t *testing.T) (privPEM string, pubB64 string, key *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("ecdsa GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubB64 = base64.StdEncoding.EncodeToString(pubDER)
	return privPEM, pubB64, k
}

func makeSelfSignedCertForKey(t *testing.T, signer *ecdsa.PrivateKey, subjectPubKey interface{}, cn string) string {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tpl, tpl, subjectPubKey, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAssertCertMatchesLocalKeypair_RejectsPubkeyMismatch(t *testing.T) {
	flow, _, _ := newCreateAIDTestFlow(t)
	_, localPubB64, _ := generateP256IdentityKeypair(t)
	// 用一组完全不同的 keypair 签 cert
	_, _, foreignKey := generateP256IdentityKeypair(t)
	foreignCert := makeSelfSignedCertForKey(t, foreignKey, &foreignKey.PublicKey, "mismatch.example.com")

	identity := map[string]any{
		"aid":                "mismatch.example.com",
		"public_key_der_b64": localPubB64,
		"cert":               foreignCert,
	}
	err := flow.assertCertMatchesLocalKeypair(identity)
	if err == nil {
		t.Fatal("expected AuthError when cert pubkey != local pubkey")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
}

func TestAssertCertMatchesLocalKeypair_PassesWhenMatching(t *testing.T) {
	flow, _, _ := newCreateAIDTestFlow(t)
	_, localPubB64, key := generateP256IdentityKeypair(t)
	matchingCert := makeSelfSignedCertForKey(t, key, &key.PublicKey, "ok.example.com")

	identity := map[string]any{
		"aid":                "ok.example.com",
		"public_key_der_b64": localPubB64,
		"cert":               matchingCert,
	}
	if err := flow.assertCertMatchesLocalKeypair(identity); err != nil {
		t.Fatalf("expected nil for matching pubkey, got: %v", err)
	}
}

func TestAssertCertMatchesLocalKeypair_RejectsMissingFields(t *testing.T) {
	flow, _, _ := newCreateAIDTestFlow(t)
	cases := []struct {
		name     string
		identity map[string]any
	}{
		{"missing cert", map[string]any{"aid": "x.example.com", "public_key_der_b64": "Zm9v"}},
		{"missing pubkey", map[string]any{"aid": "x.example.com", "cert": "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := flow.assertCertMatchesLocalKeypair(tc.identity)
			if err == nil {
				t.Fatal("expected AuthError for missing fields")
			}
			if _, ok := err.(*AuthError); !ok {
				t.Fatalf("expected *AuthError, got %T: %v", err, err)
			}
		})
	}
}
