// Package aun: AUNClient agent.md 运行时内部逻辑与上传单测。
package aun

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

type fakeAgentMDOps struct {
	signFn     func(ctx context.Context, content string) (string, error)
	verifyFn   func(ctx context.Context, content string, aid string) (map[string]any, error)
	uploadFn   func(ctx context.Context, content string) (map[string]any, error)
	downloadFn func(ctx context.Context, aid string) (agentMDDownloadResult, error)
	headFn     func(ctx context.Context, aid string) (map[string]any, error)
}

func (f *fakeAgentMDOps) SignAgentMD(ctx context.Context, content string) (string, error) {
	if f.signFn == nil {
		return "", errors.New("signFn not configured")
	}
	return f.signFn(ctx, content)
}
func (f *fakeAgentMDOps) VerifyAgentMD(ctx context.Context, content string, aid string) (map[string]any, error) {
	if f.verifyFn == nil {
		return nil, errors.New("verifyFn not configured")
	}
	return f.verifyFn(ctx, content, aid)
}
func (f *fakeAgentMDOps) UploadAgentMD(ctx context.Context, content string) (map[string]any, error) {
	if f.uploadFn == nil {
		return nil, errors.New("uploadFn not configured")
	}
	return f.uploadFn(ctx, content)
}
func (f *fakeAgentMDOps) DownloadAgentMD(ctx context.Context, aid string) (agentMDDownloadResult, error) {
	if f.downloadFn == nil {
		return agentMDDownloadResult{}, errors.New("downloadFn not configured")
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
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	c.aid = aid
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func writeAgentMDFile(t *testing.T, c *AUNClient, aid string, content string) string {
	t.Helper()
	p, err := c.agentMD().agentMDFilePath(aid)
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
		if rec := c.agentMD().saveAgentMDRecord(aid, keystore.AgentMDCacheUpsert{Content: agentMDStringPtr(content)}); rec == nil {
			t.Fatalf("failed to seed local agent.md for %s", aid)
		}
	}
}
func waitAgentMDFetchesIdle(t *testing.T, c *AUNClient) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.agentMD().agentMdMu.RLock()
		inflight := len(c.agentMD().agentMDFetchInflight)
		c.agentMD().agentMdMu.RUnlock()
		if inflight == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for agent.md downloads to finish, inflight=%d", inflight)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func readAgentMDListRecords(t *testing.T, c *AUNClient) map[string]map[string]any {
	t.Helper()
	// 读取所有 per-AID agentmd.json 文件，模拟旧 list.json 的 records 结构
	result := make(map[string]map[string]any)
	entries, err := os.ReadDir(c.agentMD().agentMDRoot())
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		aid := entry.Name()
		metaPath := filepath.Join(c.agentMD().agentMDRoot(), aid, "agentmd.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("failed to parse agentmd.json for %s: %v", aid, err)
		}
		result[aid] = m
	}
	return result
}

func TestAgentMDDownloadHTTPUsesUnconditionalGET(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Accept"); got != "text/markdown" {
			t.Fatalf("unexpected accept header: %s", got)
		}
		if got := r.Header.Get("If-None-Match"); got != "" {
			t.Fatalf("download must not send If-None-Match, got %q", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != "" {
			t.Fatalf("download must not send If-Modified-Since, got %q", got)
		}
		w.Header().Set("ETag", "\"etag-1\"")
		_, _ = w.Write([]byte("# Bob\n"))
	}))
	defer server.Close()

	res, err := agentMDDownloadHTTP(context.Background(), server.Client(), server.URL+"/agent.md", "bob1.agentid.pub")
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 || res.Content != "# Bob\n" || res.Etag != "\"etag-1\"" {
		t.Fatalf("unexpected result hits=%d res=%#v", hits, res)
	}
}

func TestAgentMDDownloadHTTPRetriesUnconditionalGETOn304WithoutCache(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if got := r.Header.Get("If-None-Match"); got != "" {
			t.Fatalf("download must not send If-None-Match, got %q", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != "" {
			t.Fatalf("download must not send If-Modified-Since, got %q", got)
		}
		if hits == 1 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "\"fresh\"")
		_, _ = w.Write([]byte("# Bob fresh\n"))
	}))
	defer server.Close()

	res, err := agentMDDownloadHTTP(context.Background(), server.Client(), server.URL+"/agent.md", "bob1.agentid.pub")
	if err != nil {
		t.Fatal(err)
	}
	if hits != 2 || res.Content != "# Bob fresh\n" || res.Etag != "\"fresh\"" {
		t.Fatalf("unexpected result hits=%d res=%#v", hits, res)
	}
}

func TestAgentMDDownloadHTTPUsesCachedContentOn304(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if got := r.Header.Get("If-None-Match"); got != "" {
			t.Fatalf("download must not send If-None-Match, got %q", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != "" {
			t.Fatalf("download must not send If-Modified-Since, got %q", got)
		}
		w.Header().Set("ETag", "\"cached\"")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	res, err := agentMDDownloadHTTP(
		context.Background(),
		server.Client(),
		server.URL+"/agent.md",
		"bob1.agentid.pub",
		agentMDDownloadCache{Content: "# Bob cached\n", Etag: "\"cached\""},
	)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 || res.Content != "# Bob cached\n" || res.Etag != "\"cached\"" || res.Status != http.StatusNotModified {
		t.Fatalf("unexpected result hits=%d res=%#v", hits, res)
	}
}

func TestAgentMDPathDefaultAndSet(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	want := filepath.Join(c.configModel.AUNPath, "AIDs")
	if c.agentMD().agentMDRoot() != want {
		t.Fatalf("root=%s want=%s", c.agentMD().agentMDRoot(), want)
	}
	custom := filepath.Join(t.TempDir(), "custom")
	if got := c.agentMD().setAgentMDPath(custom); got != custom {
		t.Fatalf("custom root=%s", got)
	}
	if got := c.agentMD().setAgentMDPath(""); got != want {
		t.Fatalf("default root=%s want=%s", got, want)
	}
}

func TestUploadAgentMDWithoutAidErrors(t *testing.T) {
	c := newClientForTest(t, "")
	if _, err := c.agentMD().Upload(context.Background()); err == nil {
		t.Fatal("expected error without local aid")
	}
}

func TestUploadAgentMDMissingDefaultFile(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	if _, err := c.agentMD().Upload(context.Background()); err == nil {
		t.Fatal("expected error for missing default agent.md")
	}
}

func TestUploadAgentMDSignsUploadsAndPersistsFileList(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	body := "---\naid: alice.agentid.pub\n---\n# Alice\n"
	writeAgentMDFile(t, c, "alice.agentid.pub", body)
	var signedInput, uploaded string
	remoteUploadEtag := "\"cloud-etag\""
	c.agentMD().agentMDOps = &fakeAgentMDOps{
		signFn: func(_ context.Context, content string) (string, error) {
			signedInput = content
			return content + "\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000\ntimestamp: 1\nsignature: x\n-->\n", nil
		},
		uploadFn: func(_ context.Context, content string) (map[string]any, error) {
			uploaded = content
			return map[string]any{"aid": "alice.agentid.pub", "etag": remoteUploadEtag, "last_modified": "Mon, 01 Jan 2024 00:00:00 GMT"}, nil
		},
	}

	res, err := c.agentMD().Upload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res["aid"] != "alice.agentid.pub" || signedInput != body {
		t.Fatalf("unexpected upload result=%v signed=%q", res, signedInput)
	}
	saved, err := os.ReadFile(filepath.Join(c.agentMD().agentMDRoot(), "alice.agentid.pub", "agent.md"))
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

func TestUploadAgentMDUploadErrorPropagates(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	writeAgentMDFile(t, c, "alice.agentid.pub", "# A\n")
	c.agentMD().agentMDOps = &fakeAgentMDOps{
		signFn: func(_ context.Context, content string) (string, error) {
			return content, nil
		},
		uploadFn: func(_ context.Context, _ string) (map[string]any, error) { return nil, errors.New("boom") },
	}
	if _, err := c.agentMD().Upload(context.Background()); err == nil {
		t.Fatal("expected error to propagate from upload")
	}
}

func TestDownloadAgentMDNoAidErrors(t *testing.T) {
	c := newClientForTest(t, "")
	if _, err := c.agentMD().Download(context.Background(), ""); err == nil {
		t.Fatal("expected error when no aid")
	}
}

func TestDownloadAgentMDSelfAidUpdatesEtagAndSavesFile(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	body := "---\naid: alice.agentid.pub\n---\n# Alice\n"
	etag := agentMDContentEtag(body)
	c.agentMD().remoteAgentMDEtag = etag
	c.agentMD().agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, aid string) (agentMDDownloadResult, error) {
			return agentMDDownloadResult{AID: aid, Content: body, Etag: etag}, nil
		},
		verifyFn: func(_ context.Context, _ string, _ string) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	info, err := c.agentMD().Download(context.Background(), "")
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

func TestDownloadAgentMDOtherAidDoesNotUpdateLocalEtag(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	c.agentMD().localAgentMDEtag = "\"unchanged\""
	body := "---\naid: bob1.agentid.pub\n---\n# Bob\n"
	c.agentMD().agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, aid string) (agentMDDownloadResult, error) {
			return agentMDDownloadResult{AID: aid, Content: body}, nil
		},
		verifyFn: func(_ context.Context, _ string, _ string) (map[string]any, error) {
			return map[string]any{"status": "verified"}, nil
		},
	}

	info, err := c.agentMD().Download(context.Background(), "bob1.agentid.pub")
	if err != nil {
		t.Fatal(err)
	}
	if info.InSync != nil || c.agentMD().localAgentMDEtag != "\"unchanged\"" {
		t.Fatalf("unexpected local state info=%#v local=%s", info, c.agentMD().localAgentMDEtag)
	}
	if rec := readAgentMDListRecords(t, c)["bob1.agentid.pub"]; rec["local_etag"] != agentMDContentEtag(body) || rec["verify_status"] != "verified" {
		t.Fatalf("bad bob record: %#v", rec)
	}
}

func TestObserveRPCMetaAgentMDEtagsPersistToList(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	seedAgentMDLocalContent(t, c, "alice.agentid.pub", "bob1.agentid.pub", "carol.agentid.pub", "dave.agentid.pub", "team.group.agentid.pub")
	c.observeRPCMeta(map[string]any{"agent_md_etag": "\"self-cloud\"", "agent_md_etags": map[string]any{"to": map[string]any{"aid": "bob1.agentid.pub", "etag": "\"bob-cloud\""}, "target": map[string]any{"aid": "carol.agentid.pub", "etag": "\"carol-cloud\""}, "sender": map[string]any{"aid": "dave.agentid.pub", "etag": "\"dave-cloud\""}, "group": map[string]any{"aid": "team.group.agentid.pub", "etag": "\"group-cloud\"", "last_modified": "Sun, 24 May 2026 00:00:02 GMT"}}})
	records := readAgentMDListRecords(t, c)
	if records["alice.agentid.pub"]["remote_etag"] != "\"self-cloud\"" || records["bob1.agentid.pub"]["remote_etag"] != "\"bob-cloud\"" || records["carol.agentid.pub"]["remote_etag"] != "\"carol-cloud\"" || records["dave.agentid.pub"]["remote_etag"] != "\"dave-cloud\"" || records["team.group.agentid.pub"]["remote_etag"] != "\"group-cloud\"" {
		t.Fatalf("bad records: %#v", records)
	}
	if records["team.group.agentid.pub"]["last_modified"] != "Sun, 24 May 2026 00:00:02 GMT" {
		t.Fatalf("bad records: %#v", records)
	}
}

func TestObserveRPCMetaAgentMDStructuredEtagsFetchesMissingLocal(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	downloaded := make(chan string, 4)
	c.agentMD().agentMDOps = &fakeAgentMDOps{
		downloadFn: func(_ context.Context, aid string) (agentMDDownloadResult, error) {
			downloaded <- aid
			return agentMDDownloadResult{AID: aid, Content: "# " + aid + "\n"}, nil
		},
		verifyFn: func(_ context.Context, _ string, _ string) (map[string]any, error) {
			return map[string]any{"status": "unsigned"}, nil
		},
	}

	c.observeRPCMeta(map[string]any{
		"agent_md_etag": "\"alice-cloud\"",
		"agent_md_etags": map[string]any{
			"requester": map[string]any{"aid": "alice.agentid.pub", "etag": "\"alice-cloud-2\"", "last_modified": "Sun, 24 May 2026 00:00:00 GMT"},
			"group":     map[string]any{"aid": "team.group.agentid.pub", "etag": "\"group-cloud\"", "last_modified": "Sun, 24 May 2026 00:00:02 GMT"},
			"receiver":  map[string]any{"aid": "bob1.agentid.pub", "etag": "\"bob-cloud\"", "last_modified": "Sun, 24 May 2026 00:00:01 GMT"},
			"sender":    map[string]any{"aid": "dave.agentid.pub", "etag": "\"dave-cloud\""},
		},
	})

	got := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(got) < 4 {
		select {
		case aid := <-downloaded:
			got[aid] = true
		case <-deadline:
			t.Fatalf("timed out waiting for auto download, got=%v", got)
		}
	}
	for _, aid := range []string{"alice.agentid.pub", "bob1.agentid.pub", "team.group.agentid.pub", "dave.agentid.pub"} {
		if !got[aid] {
			t.Fatalf("missing downloaded aid %s, got=%v", aid, got)
		}
	}

	var records map[string]map[string]any
	for deadline := time.Now().Add(2 * time.Second); ; {
		records = readAgentMDListRecords(t, c)
		if records["alice.agentid.pub"]["remote_etag"] == "\"alice-cloud-2\"" &&
			records["bob1.agentid.pub"]["remote_etag"] == "\"bob-cloud\"" &&
			records["team.group.agentid.pub"]["remote_etag"] == "\"group-cloud\"" &&
			records["dave.agentid.pub"]["remote_etag"] == "\"dave-cloud\"" &&
			records["alice.agentid.pub"]["local_etag"] != "" &&
			records["bob1.agentid.pub"]["local_etag"] != "" &&
			records["team.group.agentid.pub"]["local_etag"] != "" &&
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
		records["bob1.agentid.pub"]["last_modified"] != "Sun, 24 May 2026 00:00:01 GMT" ||
		records["team.group.agentid.pub"]["last_modified"] != "Sun, 24 May 2026 00:00:02 GMT" {
		t.Fatalf("last_modified not persisted: %#v", records)
	}
	for aid, rec := range records {
		if _, ok := rec["content"]; ok {
			t.Fatalf("content leaked into list for %s: %#v", aid, rec)
		}
	}
	p, err := c.agentMD().agentMDFilePath("bob1.agentid.pub")
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(p); err != nil || string(data) != "# bob1.agentid.pub\n" {
		t.Fatalf("bob content not saved: data=%q err=%v", string(data), err)
	}
}

func TestObserveEnvelopeAgentMDGroupPersistsToList(t *testing.T) {
	c := newClientForTest(t, "bob.agentid.pub")
	seedAgentMDLocalContent(t, c, "alice.agentid.pub", "team.group.agentid.pub")
	c.observeAgentMDFromEnvelope(map[string]any{
		"group_aid": "team.group.agentid.pub",
		"agent_md": map[string]any{
			"sender": map[string]any{"aid": "alice.agentid.pub", "etag": "\"alice-cloud\""},
			"group": map[string]any{
				"etag":          "\"group-cloud\"",
				"last_modified": "Sun, 24 May 2026 00:00:02 GMT",
			},
		},
	})
	records := readAgentMDListRecords(t, c)
	if records["alice.agentid.pub"]["remote_etag"] != "\"alice-cloud\"" {
		t.Fatalf("sender etag not observed: %#v", records)
	}
	if records["team.group.agentid.pub"]["remote_etag"] != "\"group-cloud\"" ||
		records["team.group.agentid.pub"]["last_modified"] != "Sun, 24 May 2026 00:00:02 GMT" {
		t.Fatalf("group meta not observed: %#v", records)
	}
}

func TestTransportEventAndNotificationMetaAgentMDEtagsPersistToList(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	seedAgentMDLocalContent(t, c, "alice.agentid.pub", "bob1.agentid.pub", "carol.agentid.pub", "dave.agentid.pub")
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
	c.agentMD().saveAgentMDRecord("alice.agentid.pub", keystore.AgentMDCacheUpsert{Content: agentMDStringPtr(content), LocalEtag: agentMDStringPtr(etag)})
	c.agentMD().agentMDOps = &fakeAgentMDOps{headFn: func(_ context.Context, aid string) (map[string]any, error) {
		return map[string]any{"aid": aid, "found": true, "etag": etag, "last_modified": "Mon, 01 Jan 2024 00:00:00 GMT", "status": 200}, nil
	}}

	checked, err := c.agentMD().Check(context.Background(), "")
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
	content := "---\naid: bob1.agentid.pub\n---\n# Bob\n"
	etag := agentMDContentEtag(content)
	c.agentMD().saveAgentMDRecord("bob1.agentid.pub", keystore.AgentMDCacheUpsert{
		Content:      agentMDStringPtr(content),
		LocalEtag:    agentMDStringPtr(etag),
		RemoteEtag:   agentMDStringPtr(etag),
		LastModified: agentMDStringPtr(time.Now().UTC().Format(http.TimeFormat)),
		VerifyStatus: agentMDStringPtr("valid"),
		VerifyError:  agentMDStringPtr(""),
	})
	c.agentMD().agentMDOps = &fakeAgentMDOps{headFn: func(_ context.Context, _ string) (map[string]any, error) {
		t.Fatal("fresh cached CheckAgentMD should not HEAD")
		return nil, nil
	}}

	checked, err := c.agentMD().Check(context.Background(), "bob1.agentid.pub", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !checked.LocalFound || !checked.RemoteFound || !checked.InSync || !checked.Cached || checked.VerifyStatus != "valid" {
		t.Fatalf("unexpected cached result: %#v", checked)
	}
}

func TestDamagedAgentMDJsonReturnsNil(t *testing.T) {
	c := newClientForTest(t, "alice.agentid.pub")
	body := "# Alice\n"
	writeAgentMDFile(t, c, "alice.agentid.pub", body)
	// 写入损坏的 agentmd.json
	metaPath := filepath.Join(c.agentMD().agentMDRoot(), "alice.agentid.pub", "agentmd.json")
	if err := os.WriteFile(metaPath, []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := c.agentMD().loadAgentMDRecord("alice.agentid.pub")
	if rec != nil {
		t.Fatalf("expected nil for damaged agentmd.json, got: %#v", rec)
	}
}
