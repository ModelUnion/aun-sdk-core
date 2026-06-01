package aun

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// ── createAID 查重前置 + 落盘时机修复测试 ────────────────────
//
// 修复目标：
//   - 全新 AID 注册：先查重，命中抛 IdentityConflictError，绝不生成密钥落盘
//   - 服务端拒绝 / 网络失败：内存密钥被丢弃，不落盘
//   - LoadIdentity 对未存在的 AID 不产生副作用（不建空目录）

const _stubServerCertPEM = "-----BEGIN CERTIFICATE-----\nstub-server-cert\n-----END CERTIFICATE-----\n"

func newCreateAIDTestFlow(t *testing.T) (*RegisterFlow, *keystore.LocalIdentityStore, string) {
	t.Helper()
	dir := t.TempDir()
	ks, err := keystore.NewLocalIdentityStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("NewLocalIdentityStore failed: %v", err)
	}
	t.Cleanup(func() { ks.Close() })
	flow := NewRegisterFlow(RegisterFlowConfig{Keystore: ks, Crypto: &CryptoProvider{}, VerifySSL: false})
	return flow, ks, dir
}

// startGatewayWithCert 起一个 httptest 服务模拟 Gateway 的 /pki/cert/{aid}。
// 当 cert 为空字符串时返回 404；否则返回 200 + cert。
func startGatewayWithCert(t *testing.T, certPerAID map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pki/cert/", func(w http.ResponseWriter, r *http.Request) {
		aid := strings.TrimPrefix(r.URL.Path, "/pki/cert/")
		cert, ok := certPerAID[aid]
		if !ok || cert == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(cert))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func gatewayWSURL(server *httptest.Server) string {
	// authGatewayHTTPURL 把 ws:// → http://
	return strings.Replace(server.URL, "http://", "ws://", 1) + "/aun"
}

func aidDirExists(t *testing.T, dataRoot, aid string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dataRoot, "AIDs", aid))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatalf("stat AID dir failed: %v", err)
	return false
}

// 场景 A：AID 已注册时查重命中 → 抛 IdentityConflictError，本地不落盘
func TestRegisterAID_AbortsWhenAIDAlreadyRegistered(t *testing.T) {
	flow, _, dataRoot := newCreateAIDTestFlow(t)
	aid := "taken-create-aid.example.com"

	server := startGatewayWithCert(t, map[string]string{aid: _stubServerCertPEM})

	_, err := flow.RegisterAID(context.Background(), gatewayWSURL(server), aid)
	if err == nil {
		t.Fatal("expected IdentityConflictError, got nil")
	}
	if _, ok := err.(*IdentityConflictError); !ok {
		t.Fatalf("expected *IdentityConflictError, got %T: %v", err, err)
	}
	// 关键：本地完全没有该 AID 的痕迹（不应建目录）
	if aidDirExists(t, dataRoot, aid) {
		t.Fatalf("AID dir should not exist when conflict detected: aid=%s", aid)
	}
}

// 场景 D：查重 HTTP 失败（非 404，非 200）时保守失败，不生成密钥
func TestRegisterAID_CheckHTTPFailureDoesNotPersist(t *testing.T) {
	flow, _, dataRoot := newCreateAIDTestFlow(t)
	aid := "checkfail-create-aid.example.com"

	// 服务端永远 500
	mux := http.NewServeMux()
	mux.HandleFunc("/pki/cert/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	_, err := flow.RegisterAID(context.Background(), strings.Replace(server.URL, "http://", "ws://", 1)+"/aun", aid)
	if err == nil {
		t.Fatal("expected error when /pki/cert/ returns 500")
	}
	// 不应建目录
	if aidDirExists(t, dataRoot, aid) {
		t.Fatalf("AID dir should not exist when check fails: aid=%s", aid)
	}
}

// downloadRegisteredCert 单元行为：404 → ("", nil)；200 → cert；500 → err
func TestDownloadRegisteredCert_Behavior(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
		wantCert   bool
		wantErr    bool
	}{
		{"404 returns empty no error", http.StatusNotFound, "", false, false},
		{"200 returns cert", http.StatusOK, _stubServerCertPEM, true, false},
		{"200 with no cert marker returns empty", http.StatusOK, "garbage", false, false},
		{"500 returns error", http.StatusInternalServerError, "boom", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flow, _, _ := newCreateAIDTestFlow(t)
			mux := http.NewServeMux()
			mux.HandleFunc("/pki/cert/", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
				if tc.body != "" {
					_, _ = w.Write([]byte(tc.body))
				}
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			cert, err := flow.FetchPeerCert(context.Background(),
				strings.Replace(server.URL, "http://", "ws://", 1)+"/aun", "any.example.com")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil cert=%q", cert)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tc.wantCert && cert == "" {
				t.Fatal("expected cert, got empty")
			}
			if !tc.wantCert && cert != "" {
				t.Fatalf("expected empty cert, got %q", cert)
			}
		})
	}
}

// LoadIdentity 对从未注册的 AID 调用时，不应在本地建目录（只读保护）
func TestLoadIdentity_DoesNotCreateDirectoryForMissingAID(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.NewLocalIdentityStore(dir, nil, "test-seed")
	if err != nil {
		t.Fatalf("NewLocalIdentityStore failed: %v", err)
	}
	defer ks.Close()
	aid := "never-existed.example.com"

	loaded, err := ks.LoadIdentity(aid)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}
	if loaded != nil {
		t.Fatalf("expected nil identity for missing aid, got %#v", loaded)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "AIDs", aid)); statErr == nil {
		t.Fatalf("LoadIdentity should not create directory for missing AID: aid=%s", aid)
	}
}
