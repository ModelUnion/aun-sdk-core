package aun

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func buildOCSPTestCert(t *testing.T, cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, ca bool, serial int64) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         ca,
	}
	if ca {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.BasicConstraintsValid = true
	}
	parent := tmpl
	signer := key
	if issuer != nil && issuerKey != nil {
		parent = issuer
		signer = issuerKey
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析测试证书失败: %v", err)
	}
	return key, cert
}

func TestFetchGatewayOCSPStatusUnknown(t *testing.T) {
	issuerKey, issuerCert := buildOCSPTestCert(t, "issuer.test", nil, nil, true, 1001)
	_, authCert := buildOCSPTestCert(t, "auth.identity", issuerCert, issuerKey, false, 1002)

	ocspDER, err := ocsp.CreateResponse(issuerCert, issuerCert, ocsp.Response{
		Status:       ocsp.Unknown,
		SerialNumber: authCert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(5 * time.Minute),
	}, issuerKey)
	if err != nil {
		t.Fatalf("生成 OCSP unknown 响应失败: %v", err)
	}
	serialHex := strings.ToLower(fmt.Sprintf("%x", authCert.SerialNumber))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pki/ocsp/"+serialHex {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":        "unknown",
			"ocsp_response": base64.StdEncoding.EncodeToString(ocspDER),
		})
	}))
	defer server.Close()

	flow := NewAuthFlow(AuthFlowConfig{VerifySSL: false})
	gatewayURL := "ws://" + strings.TrimPrefix(server.URL, "http://") + "/aun"
	entry, err := flow.fetchGatewayOCSPStatus(context.Background(), gatewayURL, authCert, issuerCert)
	if err != nil {
		t.Fatalf("fetchGatewayOCSPStatus returned error: %v", err)
	}
	if entry.Status != "unknown" {
		t.Fatalf("expected unknown OCSP status, got %s", entry.Status)
	}
}
