// Package aun: client.PublishAgentMD / client.FetchAgentMD 主 API 单测。
package aun

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"github.com/modelunion/aun-sdk-core/go/namespace"
)

type fakeAgentMDOps struct {
	signFn     func(ctx context.Context, content string, opts *namespace.AgentMDSignOptions) (string, error)
	verifyFn   func(ctx context.Context, content string, opts *namespace.AgentMDVerifyOptions) (map[string]any, error)
	uploadFn   func(ctx context.Context, content string) (map[string]any, error)
	downloadFn func(ctx context.Context, aid string) (string, error)
	headFn     func(ctx context.Context, aid string) (map[string]any, error)
}

func (f *fakeAgentMDOps) SignAgentMD(ctx context.Context, content string, opts *namespace.AgentMDSignOptions) (string, error) {
	if f.signFn == nil {
		return "", errors.New("signFn not configured")
	}
	return f.signFn(ctx, content, opts)
}
func (f *fakeAgentMDOps) VerifyAgentMD(ctx context.Context, content string, opts *namespace.AgentMDVerifyOptions) (map[string]any, error) {
	if f.verifyFn == nil {
		return nil, errors.New("verifyFn not configured")
	}
	return f.verifyFn(ctx, content, opts)
}
func (f *fakeAgentMDOps) UploadAgentMD(ctx context.Context, content string) (map[string]any, error) {
	if f.uploadFn == nil {
		return nil, errors.New("uploadFn not configured")
	}
	return f.uploadFn(ctx, content)
}
func (f *fakeAgentMDOps) DownloadAgentMD(ctx context.Context, aid string) (string, error) {
	if f.downloadFn == nil {
		return "", errors.New("downloadFn not configured")
	}
	return f.downloadFn(ctx, aid)
}
func (f *fakeAgentMDOps) HeadAgentMD(ctx context.Context, aid string) (map[string]any, error) {
	if f.headFn == nil {
		return nil, errors.New("headFn not configured")
	}
	return f.headFn(ctx, aid)
}

func newClientForTest(t *testing.T, aid string) *AUNClient {
	t.Helper()
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	c.aid = aid
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func writeAgentMDFile(t *testing.T, c *AUNClient, aid string, content string) string {
	t.Helper()
	p, err := c.agentMDFilePath(aid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func seedAgentMDLocalContent(t *testing.T, c *AUNClient, aids ...string) {
	t.Helper()
	for _, aid := range aids {
		content := "# " + aid + "\n"
		if rec := c.saveAgentMDRecord(aid, keystore.AgentMDCacheUpsert{Content: agentMDStringPtr(content)}); rec == nil {
			t.Fatalf("failed to seed local agent.md for %s", aid)
		}
	}
}
func waitAgentMDFetchesIdle(t *testing.T, c *AUNClient) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.agentMdMu.RLock()
		inflight := len(c.agentMDFetchInflight)
		c.agentMdMu.RUnlock()
		if inflight == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for agent.md fetches to finish, inflight=%d", inflight)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func readAgentMDListRecords(t *testing.T, c *AUNClient) map[string]map[string]any {
	t.Helper()
	data, err := os.ReadFile(c.agentMDListPath())
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Records map[string]map[string]any `json:"records"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Records
}

func TestAgentMDPathDefaultAndSet(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	want := filepath.Join(c.configModel.AUNPath, "AgentMDs")
	if c.agentMDRoot() != want {
		t.Fatalf("root=%s want=%s", c.agentMDRoot(), want)
	}
	custom := filepath.Join(t.TempDir(), "custom")
	if got := c.SetAgentMDPath(custom); got != custom {
		t.Fatalf("custom root=%s", got)
	}
	if got := c.SetAgentMdPath(""); got != want {
		t.Fatalf("default root=%s want=%s", got, want)
	}
}

func TestPublishAgentMDWithoutAidErrors(t *testing.T) {
	c := newClientForTest(t, "")
	if _, err := c.PublishAgentMD(context.Background()); err == nil {
		t.Fatal("expected error without local aid")
	}
}

func TestPublishAgentMDMissingDefaultFile(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	if _, err := c.PublishAgentMD(context.Background()); err == nil {
		t.Fatal("expected error for missing default agent.md")
	}
}

func TestPublishAgentMDSignsUploadsAndPersistsFileList(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	body := "---\naid: alice.agentid.pub\n---\n# Alice\n"
	writeAgentMDFile(t, c, "alice.agentid.pub", body)
	var signedInput, uploaded string
	remoteUploadEtag := "\"cloud-etag\""
	c.agentMDOps = &fakeAgentMDOps{
		signFn: func(_ context.Context, content string, _ *namespace.AgentMDSignOptions) (string, error) {
			signedInput = content
			return content + "\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n", nil
		},
		uploadFn: func(_ context.Context, content string) (map[string]any, error) {
			uploaded = content
			return map[string]any{"aid": "alice.agentid.pub", "etag": remoteUploadEtag, "last_modified": "Mon, 01 Jan 2024 00:00:00 GMT"}, nil
		},
	}

	res, err := c.PublishAgentMD(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res["aid"] != "alice.agentid.pub" || signedInput != body {
		t.Fatalf("unexpected publish result=%v signed=%q", res, signedInput)
	}
	saved, err := os.ReadFile(filepath.Join(c.agentMDRoot(), "alice.agentid.pub", "agent.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != uploaded {
		t.Fatalf("saved body mismatch")
	}
	want := agentMDContentEtag(uploaded)
	rec := readAgentMDListRecords(t, c)["alice.agentid.pub"]
	if _, ok := rec["content"]; ok || rec["local_etag"] != want || rec["remote_etag"] != remoteUploadEtag {
		t.Fatalf("bad list record: %#v", rec)
	}
}

func TestPublishAgentMDUploadErrorPropagates(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	writeAgentMDFile(t, c, "alice.agentid.pub", "# A\n")
	c.agentMDOps = &fakeAgentMDOps{
		signFn: func(_ context.Context, content string, _ *namespace.AgentMDSignOptions) (string, error) {
			return content, nil
		},
		uploadFn: func(_ context.Context, _ string) (map[string]any, error) { return nil, errors.New("boom") },
	}
	if _, err := c.PublishAgentMD(context.Background()); err == nil {
		t.Fatal("expected error to propagate from upload")
	}
}

func TestFetchAgentMDNoAidErrors(t *testing.T) {
	c := newClientForTest(t, "")
	if _, err := c.FetchAgentMD(context.Background(), ""); err == nil {
		t.Fatal("expected error when no aid")
	}
}

func TestFetchAgentMDSelfAidUpdatesEtagAndSavesFile(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	body := "---\naid: alice.agentid.pub\n---\n# Alice\n"
	etag := agentMDContentEtag(body)
	c.remoteAgentMDEtag = etag
	c.agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, _ string) (string, error) { return body, nil },
		verifyFn: func(_ context.Context, _ string, _ *namespace.AgentMDVerifyOptions) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	info, err := c.FetchAgentMD(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if info.AID != "alice.agentid.pub" || info.InSync == nil || !*info.InSync || info.SavedTo == "" {
		t.Fatalf("bad info: %#v", info)
	}
	if data, err := os.ReadFile(info.SavedTo); err != nil || string(data) != body {
		t.Fatalf("saved content err=%v", err)
	}
	if rec := readAgentMDListRecords(t, c)["alice.agentid.pub"]; rec["local_etag"] != etag {
		t.Fatalf("bad list record: %#v", rec)
	}
}

func TestFetchAgentMDOtherAidDoesNotUpdateLocalEtag(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	c.localAgentMDEtag = "\"unchanged\""
	body := "---\naid: bob.agentid.pub\n---\n# Bob\n"
	c.agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, _ string) (string, error) { return body, nil },
		verifyFn: func(_ context.Context, _ string, _ *namespace.AgentMDVerifyOptions) (map[string]any, error) {
			return map[string]any{"status": "verified"}, nil
		},
	}

	info, err := c.FetchAgentMD(context.Background(), "bob.agentid.pub")
	if err != nil {
		t.Fatal(err)
	}
	if info.InSync != nil || c.localAgentMDEtag != "\"unchanged\"" {
		t.Fatalf("unexpected local state info=%#v local=%s", info, c.localAgentMDEtag)
	}
	if rec := readAgentMDListRecords(t, c)["bob.agentid.pub"]; rec["local_etag"] != agentMDContentEtag(body) || rec["verify_status"] != "verified" {
		t.Fatalf("bad bob record: %#v", rec)
	}
}

func TestObserveRPCMetaAgentMDEtagsPersistToList(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	seedAgentMDLocalContent(t, c, "alice.agentid.pub", "bob.agentid.pub", "carol.agentid.pub", "dave.agentid.pub")
	c.observeRPCMeta(map[string]any{"agent_md_etag": "\"self-cloud\"", "agent_md_etags": map[string]any{"to": map[string]any{"aid": "bob.agentid.pub", "etag": "\"bob-cloud\""}, "target": map[string]any{"aid": "carol.agentid.pub", "etag": "\"carol-cloud\""}, "sender": map[string]any{"aid": "dave.agentid.pub", "etag": "\"dave-cloud\""}}})
	records := readAgentMDListRecords(t, c)
	if records["alice.agentid.pub"]["remote_etag"] != "\"self-cloud\"" || records["bob.agentid.pub"]["remote_etag"] != "\"bob-cloud\"" || records["carol.agentid.pub"]["remote_etag"] != "\"carol-cloud\"" || records["dave.agentid.pub"]["remote_etag"] != "\"dave-cloud\"" {
		t.Fatalf("bad records: %#v", records)
	}
}

func TestObserveRPCMetaAgentMDStructuredEtagsFetchesMissingLocal(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	fetched := make(chan string, 4)
	c.agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, aid string) (string, error) {
			fetched <- aid
			return "# " + aid + "\n", nil
		},
		verifyFn: func(_ context.Context, _ string, _ *namespace.AgentMDVerifyOptions) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	c.observeRPCMeta(map[string]any{
		"agent_md_etag": "\"alice-cloud\"",
		"agent_md_etags": map[string]any{
			"requester": map[string]any{"aid": "alice.agentid.pub", "etag": "\"alice-cloud-2\"", "last_modified": "Sun, 24 May 2026 00:00:00 GMT"},
			"receiver":  map[string]any{"aid": "bob.agentid.pub", "etag": "\"bob-cloud\"", "last_modified": "Sun, 24 May 2026 00:00:01 GMT"},
			"sender":    map[string]any{"aid": "dave.agentid.pub", "etag": "\"dave-cloud\""},
		},
	})

	got := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(got) < 3 {
		select {
		case aid := <-fetched:
			got[aid] = true
		case <-deadline:
			t.Fatalf("timed out waiting for auto fetch, got=%v", got)
		}
	}
	for _, aid := range []string{"alice.agentid.pub", "bob.agentid.pub", "dave.agentid.pub"} {
		if !got[aid] {
			t.Fatalf("missing fetched aid %s, got=%v", aid, got)
		}
	}

	var records map[string]map[string]any
	for deadline := time.Now().Add(2 * time.Second); ; {
		records = readAgentMDListRecords(t, c)
		if records["alice.agentid.pub"]["remote_etag"] == "\"alice-cloud-2\"" &&
			records["bob.agentid.pub"]["remote_etag"] == "\"bob-cloud\"" &&
			records["dave.agentid.pub"]["remote_etag"] == "\"dave-cloud\"" &&
			records["alice.agentid.pub"]["local_etag"] != "" &&
			records["bob.agentid.pub"]["local_etag"] != "" &&
			records["dave.agentid.pub"]["local_etag"] != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for list update: %#v", records)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitAgentMDFetchesIdle(t, c)
	if records["alice.agentid.pub"]["last_modified"] != "Sun, 24 May 2026 00:00:00 GMT" ||
		records["bob.agentid.pub"]["last_modified"] != "Sun, 24 May 2026 00:00:01 GMT" {
		t.Fatalf("last_modified not persisted: %#v", records)
	}
	for aid, rec := range records {
		if _, ok := rec["content"]; ok {
			t.Fatalf("content leaked into list for %s: %#v", aid, rec)
		}
	}
	p, err := c.agentMDFilePath("bob.agentid.pub")
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(p); err != nil || string(data) != "# bob.agentid.pub\n" {
		t.Fatalf("bob content not saved: data=%q err=%v", string(data), err)
	}
}

func TestTransportEventAndNotificationMetaAgentMDEtagsPersistToList(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	seedAgentMDLocalContent(t, c, "alice.agentid.pub", "bob.agentid.pub", "carol.agentid.pub", "dave.agentid.pub")
	c.transport.routeMessage(map[string]any{"method": "event/custom.notice", "params": map[string]any{}, "_meta": map[string]any{"agent_md_etags": map[string]any{"target": map[string]any{"aid": "carol.agentid.pub", "etag": "\"carol-cloud\""}}}})
	c.transport.routeMessage(map[string]any{"method": "custom.notice", "params": map[string]any{}, "_meta": map[string]any{"agent_md_etags": map[string]any{"sender": map[string]any{"aid": "dave.agentid.pub", "etag": "\"dave-cloud\""}}}})
	records := readAgentMDListRecords(t, c)
	if records["carol.agentid.pub"]["remote_etag"] != "\"carol-cloud\"" || records["dave.agentid.pub"]["remote_etag"] != "\"dave-cloud\"" {
		t.Fatalf("bad records: %#v", records)
	}
}

func TestCheckAgentMDComparesHeadAndPersistsToList(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	content := "---\naid: alice.agentid.pub\n---\n# Alice\n"
	etag := agentMDContentEtag(content)
	c.saveAgentMDRecord("alice.agentid.pub", keystore.AgentMDCacheUpsert{Content: agentMDStringPtr(content), LocalEtag: agentMDStringPtr(etag)})
	c.agentMDOps = &fakeAgentMDOps{headFn: func(_ context.Context, aid string) (map[string]any, error) {
		return map[string]any{"aid": aid, "found": true, "etag": etag, "last_modified": "Mon, 01 Jan 2024 00:00:00 GMT", "status": 200}, nil
	}}

	checked, err := c.CheckAgentMD(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !checked.LocalFound || !checked.RemoteFound || !checked.InSync || checked.RemoteEtag != etag {
		t.Fatalf("unexpected check result: %#v", checked)
	}
	if rec := readAgentMDListRecords(t, c)["alice.agentid.pub"]; rec["remote_etag"] != etag || rec["remote_status"] != "found" {
		t.Fatalf("bad list record: %#v", rec)
	}
}

func TestCheckAgentMDUsesFreshCachedMatchWithoutHead(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	content := "---\naid: bob.agentid.pub\n---\n# Bob\n"
	etag := agentMDContentEtag(content)
	c.saveAgentMDRecord("bob.agentid.pub", keystore.AgentMDCacheUpsert{
		Content:      agentMDStringPtr(content),
		LocalEtag:    agentMDStringPtr(etag),
		RemoteEtag:   agentMDStringPtr(etag),
		LastModified: agentMDStringPtr(time.Now().UTC().Format(http.TimeFormat)),
		VerifyStatus: agentMDStringPtr("valid"),
		VerifyError:  agentMDStringPtr(""),
	})
	c.agentMDOps = &fakeAgentMDOps{headFn: func(_ context.Context, _ string) (map[string]any, error) {
		t.Fatal("fresh cached CheckAgentMD should not HEAD")
		return nil, nil
	}}

	checked, err := c.CheckAgentMD(context.Background(), "bob.agentid.pub", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !checked.LocalFound || !checked.RemoteFound || !checked.InSync || !checked.Cached || checked.VerifyStatus != "valid" {
		t.Fatalf("unexpected cached result: %#v", checked)
	}
}

func TestDamagedListJSONRebuildsFromDiskAndInvalidatesMemory(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	body := "# Alice\n"
	writeAgentMDFile(t, c, "alice.agentid.pub", body)
	c.agentMDCache["alice.agentid.pub"] = &keystore.AgentMDCacheRecord{AID: "alice.agentid.pub", RemoteEtag: "\"cloud\""}
	c.agentMDCache["bob.agentid.pub"] = &keystore.AgentMDCacheRecord{AID: "bob.agentid.pub", RemoteEtag: "\"stale\""}
	if err := os.WriteFile(c.agentMDListPath(), []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := c.loadAgentMDRecord("alice.agentid.pub")
	if rec == nil || rec.Content != body || rec.LocalEtag != agentMDContentEtag(body) || rec.RemoteEtag != "" {
		t.Fatalf("bad rebuilt record: %#v", rec)
	}
	rebuilt := readAgentMDListRecords(t, c)["alice.agentid.pub"]
	if rebuilt["local_etag"] != agentMDContentEtag(body) {
		t.Fatalf("bad rebuilt list: %#v", rebuilt)
	}
	if _, ok := c.agentMDCache["bob.agentid.pub"]; ok {
		t.Fatalf("stale bob cache should be invalidated")
	}
}
