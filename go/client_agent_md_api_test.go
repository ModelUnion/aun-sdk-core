// Package aun: client.PublishAgentMD / client.FetchAgentMD 主 API 单测。
//
// 思路：在 client.go 上额外暴露一个 agentMDOps 接口字段，便于测试替换底层 Sign/Verify/Upload/Download。
// 这样既不破坏 client.Auth 公开 API（仍然是 *namespace.AuthNamespace），
// 又能在不依赖 HTTP server 的情况下直接验证主 API 的编排逻辑。

package aun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelunion/aun-sdk-core/go/namespace"
)

type fakeAgentMDOps struct {
	signFn     func(ctx context.Context, content string, opts *namespace.AgentMDSignOptions) (string, error)
	verifyFn   func(ctx context.Context, content string, opts *namespace.AgentMDVerifyOptions) (map[string]any, error)
	uploadFn   func(ctx context.Context, content string) (map[string]any, error)
	downloadFn func(ctx context.Context, aid string) (string, error)
}

func (f *fakeAgentMDOps) SignAgentMD(ctx context.Context, content string, opts *namespace.AgentMDSignOptions) (string, error) {
	return f.signFn(ctx, content, opts)
}
func (f *fakeAgentMDOps) VerifyAgentMD(ctx context.Context, content string, opts *namespace.AgentMDVerifyOptions) (map[string]any, error) {
	return f.verifyFn(ctx, content, opts)
}
func (f *fakeAgentMDOps) UploadAgentMD(ctx context.Context, content string) (map[string]any, error) {
	return f.uploadFn(ctx, content)
}
func (f *fakeAgentMDOps) DownloadAgentMD(ctx context.Context, aid string) (string, error) {
	return f.downloadFn(ctx, aid)
}

func newClientForTest(t *testing.T, aid string) *AUNClient {
	t.Helper()
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	c.aid = aid
	return c
}

// ── PublishAgentMD ──────────────────────────────────────────────────

func TestPublishAgentMD_EmptyPath(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	if _, err := c.PublishAgentMD(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestPublishAgentMD_FileNotFound(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	if _, err := c.PublishAgentMD(context.Background(), "/nope/agent.md"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestPublishAgentMD_SignsUploadsAndUpdatesEtag(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")

	dir := t.TempDir()
	p := filepath.Join(dir, "agent.md")
	body := "---\naid: alice.agentid.pub\n---\n# Alice\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var signedInput, uploaded string
	c.agentMDOps = &fakeAgentMDOps{
		signFn: func(_ context.Context, content string, _ *namespace.AgentMDSignOptions) (string, error) {
			signedInput = content
			return content + "\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n", nil
		},
		uploadFn: func(_ context.Context, content string) (map[string]any, error) {
			uploaded = content
			return map[string]any{"aid": "alice.agentid.pub"}, nil
		},
	}

	res, err := c.PublishAgentMD(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if res["aid"] != "alice.agentid.pub" {
		t.Fatalf("aid=%v", res["aid"])
	}
	if signedInput != body {
		t.Fatalf("sign got unexpected input: %q", signedInput)
	}
	sum := sha256.Sum256([]byte(uploaded))
	want := "\"" + hex.EncodeToString(sum[:]) + "\""
	c.agentMdMu.RLock()
	got := c.localAgentMDEtag
	c.agentMdMu.RUnlock()
	if got != want {
		t.Fatalf("etag got=%s want=%s", got, want)
	}
}

func TestPublishAgentMD_UploadErrorPropagates(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.md")
	if err := os.WriteFile(p, []byte("# A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.agentMDOps = &fakeAgentMDOps{
		signFn:   func(_ context.Context, content string, _ *namespace.AgentMDSignOptions) (string, error) { return content, nil },
		uploadFn: func(_ context.Context, _ string) (map[string]any, error) { return nil, errors.New("boom") },
	}
	if _, err := c.PublishAgentMD(context.Background(), p); err == nil {
		t.Fatal("expected error to propagate from upload")
	}
}

// ── FetchAgentMD ────────────────────────────────────────────────────

func TestFetchAgentMD_NoAidErrors(t *testing.T) {
	c := newClientForTest(t, "")
	if _, err := c.FetchAgentMD(context.Background(), "", ""); err == nil {
		t.Fatal("expected error when no aid")
	}
}

func TestFetchAgentMD_SelfAidUpdatesEtag(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	body := "---\naid: alice.agentid.pub\n---\n# Alice\n"

	c.agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, _ string) (string, error) { return body, nil },
		verifyFn: func(_ context.Context, _ string, _ *namespace.AgentMDVerifyOptions) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	info, err := c.FetchAgentMD(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if info.AID != "alice.agentid.pub" {
		t.Fatalf("aid=%s", info.AID)
	}
	if info.Signature["status"] != "unsigned" {
		t.Fatalf("signature=%v", info.Signature)
	}
	if info.InSync == nil {
		t.Fatal("InSync should not be nil for self aid")
	}

	sum := sha256.Sum256([]byte(body))
	want := "\"" + hex.EncodeToString(sum[:]) + "\""
	c.agentMdMu.RLock()
	got := c.localAgentMDEtag
	c.agentMdMu.RUnlock()
	if got != want {
		t.Fatalf("etag got=%s want=%s", got, want)
	}
}

func TestFetchAgentMD_OtherAidDoesNotUpdate(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	c.agentMdMu.Lock()
	c.localAgentMDEtag = "\"unchanged\""
	c.agentMdMu.Unlock()

	c.agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, _ string) (string, error) { return "---\naid: bob.agentid.pub\n---\n", nil },
		verifyFn: func(_ context.Context, _ string, _ *namespace.AgentMDVerifyOptions) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	info, err := c.FetchAgentMD(context.Background(), "bob.agentid.pub", "")
	if err != nil {
		t.Fatal(err)
	}
	if info.InSync != nil {
		t.Fatalf("InSync should be nil for foreign aid, got %v", *info.InSync)
	}
	c.agentMdMu.RLock()
	got := c.localAgentMDEtag
	c.agentMdMu.RUnlock()
	if got != "\"unchanged\"" {
		t.Fatalf("local etag should not change, got=%s", got)
	}
}

func TestFetchAgentMD_SavePathWritesFile(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	target := filepath.Join(t.TempDir(), "agent.md")

	c.agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, _ string) (string, error) { return "# A\n", nil },
		verifyFn: func(_ context.Context, _ string, _ *namespace.AgentMDVerifyOptions) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	info, err := c.FetchAgentMD(context.Background(), "", target)
	if err != nil {
		t.Fatal(err)
	}
	if info.SavedTo != target {
		t.Fatalf("SavedTo=%s", info.SavedTo)
	}
	if info.SaveError != "" {
		t.Fatalf("unexpected save_error=%s", info.SaveError)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "# A\n" {
		t.Fatalf("file content err=%v data=%q", err, data)
	}
}

func TestFetchAgentMD_InSyncTrueWhenEtagsMatch(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")

	body := "---\naid: alice.agentid.pub\n---\n# A\n"
	sum := sha256.Sum256([]byte(body))
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""
	c.agentMdMu.Lock()
	c.remoteAgentMDEtag = etag
	c.agentMdMu.Unlock()

	c.agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, _ string) (string, error) { return body, nil },
		verifyFn: func(_ context.Context, _ string, _ *namespace.AgentMDVerifyOptions) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	info, err := c.FetchAgentMD(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if info.InSync == nil || !*info.InSync {
		t.Fatalf("InSync should be true, got %v", info.InSync)
	}
}
