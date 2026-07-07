package aun

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fakeGroupIndexSigner struct {
	aid string
}

func (f fakeGroupIndexSigner) AID() string {
	return f.aid
}

func (f fakeGroupIndexSigner) Sign(payload []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(payload), nil
}

func (f fakeGroupIndexSigner) Verify(payload []byte, signature string) (bool, error) {
	return signature == base64.StdEncoding.EncodeToString(payload), nil
}

func TestGroupIndexComputesBodyHashAndEtagFromSortedCanonicalEntries(t *testing.T) {
	entries := []map[string]any{
		{"key": "rules.content", "source": "db", "etag": `"sha256:rules"`, "last_modified": 2},
		{"key": "announcement.content", "source": "db", "etag": `"sha256:ann"`, "last_modified": 1},
	}

	if got := ComputeGroupIndexBodyHash(entries); got != "sha256:88a4efec147e1d95d95a0868aca6f26447fd5f1f1d22b7c5a2ea5fd03ddbd30e" {
		t.Fatalf("body_hash 不匹配: %s", got)
	}
	if got := GroupIndexEtag(entries); got != `"sha256:88a4efec147e1d95d95a0868aca6f26447fd5f1f1d22b7c5a2ea5fd03ddbd30e"` {
		t.Fatalf("etag 不匹配: %s", got)
	}
}

func TestGroupIndexBuildsAndVerifiesSignedJSONL(t *testing.T) {
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}

	signed, err := BuildSignedGroupIndex(GroupIndexBuildOptions{
		GroupAID:     "g-team.example.test",
		Entries:      []map[string]any{{"key": "rules.content", "source": "db", "etag": `"sha256:rules"`, "last_modified": 2}},
		Signer:       signer,
		LastModified: 1000,
	})
	if err != nil {
		t.Fatalf("BuildSignedGroupIndex 失败: %v", err)
	}

	parsed, err := ParseGroupIndex(signed.Body)
	if err != nil {
		t.Fatalf("ParseGroupIndex 失败: %v", err)
	}
	if parsed.Meta["schema"] != GroupIndexSchema || parsed.Meta["signed_by"] != signer.aid || parsed.Meta["sig_alg"] != GroupIndexSigAlg {
		t.Fatalf("meta 不匹配: %#v", parsed.Meta)
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0]["key"] != "rules.content" {
		t.Fatalf("entries 不匹配: %#v", parsed.Entries)
	}

	verified, err := VerifyGroupIndex(signed.Body, signer)
	if err != nil {
		t.Fatalf("VerifyGroupIndex 失败: %v", err)
	}
	if !verified.Valid {
		t.Fatalf("签名应有效: %#v", verified)
	}
}

func TestPrepareGroupSettingsWithIndexMergesBaseIndex(t *testing.T) {
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	base, err := BuildSignedGroupIndex(GroupIndexBuildOptions{
		GroupAID: "g-team.example.test",
		Entries: []map[string]any{
			{"key": "rules.content", "source": "db", "etag": `"sha256:old"`, "last_modified": 1},
			{"key": "announcement.content", "source": "db", "etag": `"sha256:ann"`, "last_modified": 1},
		},
		Signer:       signer,
		LastModified: 1,
	})
	if err != nil {
		t.Fatalf("BuildSignedGroupIndex 失败: %v", err)
	}

	settings, err := PrepareGroupSettingsWithIndex(GroupSettingsWithIndexOptions{
		GroupAID:     "g-team.example.test",
		Settings:     map[string]any{"rules.content": "新群规"},
		Signer:       signer,
		LastModified: 2000,
		BaseIndex:    base,
	})
	if err != nil {
		t.Fatalf("PrepareGroupSettingsWithIndex 失败: %v", err)
	}
	if settings["rules.content"] != "新群规" {
		t.Fatalf("原设置丢失: %#v", settings)
	}
	parsed, err := ParseGroupIndex(settings[GroupIndexKey])
	if err != nil {
		t.Fatalf("ParseGroupIndex 失败: %v", err)
	}
	want := []map[string]any{
		{"key": "announcement.content", "source": "db", "etag": `"sha256:ann"`, "last_modified": float64(1)},
		{"key": "rules.content", "source": "db", "etag": `"sha256:c43beb3d1be3d5fb41b8bf8cd11248d49382f5138a033c8f1679c116be6fa97a"`, "last_modified": float64(2000)},
	}
	if !reflect.DeepEqual(parsed.Entries, want) {
		t.Fatalf("entries 不匹配:\n got=%#v\nwant=%#v", parsed.Entries, want)
	}
}

func TestPrepareGroupSettingsWithIndexReturnsJSONMapForRPCSigning(t *testing.T) {
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	settings, err := PrepareGroupSettingsWithIndex(GroupSettingsWithIndexOptions{
		GroupAID:     "g-team.example.test",
		Settings:     map[string]any{"rules.content": "新群规"},
		Signer:       signer,
		LastModified: 2000,
	})
	if err != nil {
		t.Fatalf("PrepareGroupSettingsWithIndex 失败: %v", err)
	}
	if _, ok := settings[GroupIndexKey].(map[string]any); !ok {
		t.Fatalf("group.index 应为 JSON map，避免 RPC 签名 hash 与序列化不一致: %#v", settings[GroupIndexKey])
	}
	if _, err := ParseGroupIndex(settings[GroupIndexKey]); err != nil {
		t.Fatalf("JSON map 形态仍应可解析: %v", err)
	}
}

func TestGroupIndexMetaCacheAndClientHelpers(t *testing.T) {
	cache := NewGroupIndexMetaCache()
	meta := map[string]any{
		"group_indexes": map[string]any{
			"g-team.example.test": map[string]any{"etag": `"one"`, "last_modified": 1, "schema": GroupIndexSchema},
		},
	}
	cache.ObserveRPCMeta(meta, "alice.example.test")
	if !cache.IsStale("alice.example.test", "g-team.example.test") {
		t.Fatal("远端 etag 与本地不一致时应标记 stale")
	}
	cache.MarkFresh("alice.example.test", "g-team.example.test", `"one"`)
	if cache.IsStale("alice.example.test", "g-team.example.test") {
		t.Fatal("MarkFresh 后不应 stale")
	}

	client := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = client.Close() }()
	client.aid = "alice.example.test"
	client.observeRPCMeta(meta)
	if !client.IsGroupIndexStale("g-team.example.test") {
		t.Fatal("AUNClient 应观察 group_indexes meta")
	}
	client.MarkGroupIndexFresh("g-team.example.test", `"one"`)
	if client.IsGroupIndexStale("g-team.example.test") {
		t.Fatal("AUNClient MarkGroupIndexFresh 后不应 stale")
	}
}

func TestGroupIndexMetaCachePersistsIndexJSONLAndCacheEnvelope(t *testing.T) {
	root := t.TempDir()
	cache := NewGroupIndexMetaCache(root)
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	signed, err := BuildSignedGroupIndex(GroupIndexBuildOptions{
		GroupAID:     "g-team.example.test",
		Entries:      []map[string]any{{"key": "rules.content", "source": "db", "etag": `"entry-v1"`, "last_modified": 1}},
		Signer:       signer,
		LastModified: 1,
	})
	if err != nil {
		t.Fatalf("BuildSignedGroupIndex 失败: %v", err)
	}
	entries := []map[string]any{{"key": "rules.content", "etag": `"entry-v1"`}}

	cache.ObserveRPCMeta(
		map[string]any{"group_indexes": map[string]any{"g-team.example.test": map[string]any{"etag": `"v1"`, "last_modified": int64(1), "schema": GroupIndexSchema}}},
		"alice.example.test",
	)
	cache.MarkFresh("alice.example.test", "g-team.example.test", `"v1"`)
	cache.CacheSettings("alice.example.test", "g-team.example.test", map[string]any{"rules.content": "缓存群规"}, entries, `"v1"`, signed)

	cacheDir := filepath.Join(root, "AIDs", "alice.example.test", "groups", "g-team.example.test")
	body, err := os.ReadFile(filepath.Join(cacheDir, "index.jsonl"))
	if err != nil {
		t.Fatalf("读取 index.jsonl 失败: %v", err)
	}
	if string(body) != signed.Body {
		t.Fatalf("index.jsonl 不匹配: %q", string(body))
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "group-index-cache.json")); err != nil {
		t.Fatalf("cache envelope 未写入: %v", err)
	}

	restored := NewGroupIndexMetaCache(root)
	if got := restored.LocalEtag("alice.example.test", "g-team.example.test"); got != `"v1"` {
		t.Fatalf("local etag 未恢复: %s", got)
	}
	if got := restored.CachedSettings("alice.example.test", "g-team.example.test", []string{"rules.content"}); got["rules.content"] != "缓存群规" {
		t.Fatalf("settings 未恢复: %#v", got)
	}
	cached, missing := restored.CachedSettingsByEntries("alice.example.test", "g-team.example.test", []string{"rules.content"}, entries)
	if cached["rules.content"] != "缓存群规" || len(missing) != 0 {
		t.Fatalf("entry etag cache 未恢复: cached=%#v missing=%#v", cached, missing)
	}
}
