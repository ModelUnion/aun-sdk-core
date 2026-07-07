package aun

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fakeGroupIndexRPCClient struct {
	calls            []storageCallRecord
	getResults       []any
	failFirstSet     bool
	remoteMeta       map[string]any
	localEtag        string
	stale            bool
	freshMarks       []map[string]string
	remoteSettings   map[string]any
	cachedSettings   map[string]any
	cachedEntryEtags map[string]string
	cachedGroupEtag  string
	cachedGroupIndex any
	cacheCalls       []string
}

func (f *fakeGroupIndexRPCClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
	f.calls = append(f.calls, storageCallRecord{method: method, params: params})
	switch method {
	case "group.get_settings":
		keys := toStringSlice(params["keys"])
		if len(keys) != 1 || keys[0] != GroupIndexKey {
			settings := []any{}
			for _, key := range keys {
				if f.remoteSettings != nil {
					if value, ok := f.remoteSettings[key]; ok {
						settings = append(settings, map[string]any{"key": key, "value": value})
					}
				}
			}
			return map[string]any{"group_id": params["group_id"], "group_aid": "g-team.example.test", "settings": settings}, nil
		}
		var value any
		if len(f.getResults) > 0 {
			value = f.getResults[0]
			f.getResults = f.getResults[1:]
			if signed, ok := value.(*SignedGroupIndex); ok {
				value = signedGroupIndexJSONValue(signed)
			}
		}
		settings := []any{}
		if value != nil {
			settings = append(settings, map[string]any{"key": GroupIndexKey, "value": value})
		}
		return map[string]any{"group_id": params["group_id"], "group_aid": "g-team.example.test", "settings": settings}, nil
	case "group.set_settings":
		if f.failFirstSet {
			f.failFirstSet = false
			return nil, fmt.Errorf("group.index etag conflict")
		}
		keys := []string{}
		if settings, ok := params["settings"].(map[string]any); ok {
			for key := range settings {
				keys = append(keys, key)
			}
		}
		return map[string]any{"group_id": params["group_id"], "updated_keys": keys}, nil
	default:
		return nil, fmt.Errorf("unexpected method %s", method)
	}
}

func (f *fakeGroupIndexRPCClient) IsGroupIndexStale(groupAID string) bool {
	return f.stale
}

func (f *fakeGroupIndexRPCClient) GroupIndexRemoteMeta(groupAID string) map[string]any {
	return f.remoteMeta
}

func (f *fakeGroupIndexRPCClient) GroupIndexLocalEtag(groupAID string) string {
	return f.localEtag
}

func (f *fakeGroupIndexRPCClient) MarkGroupIndexFresh(groupAID, etag string) {
	f.freshMarks = append(f.freshMarks, map[string]string{"group_aid": groupAID, "etag": etag})
	f.stale = false
	f.localEtag = etag
}

func (f *fakeGroupIndexRPCClient) GetGroupIndexCachedSettings(groupAID string, keys []string) map[string]any {
	for _, key := range keys {
		if f.cachedSettings == nil {
			return nil
		}
		if _, ok := f.cachedSettings[key]; !ok {
			return nil
		}
	}
	out := map[string]any{}
	for _, key := range keys {
		out[key] = f.cachedSettings[key]
	}
	return out
}

func (f *fakeGroupIndexRPCClient) GetGroupIndexCachedSettingsByEntries(groupAID string, keys []string, entries []map[string]any) (map[string]any, []string) {
	entryEtags := map[string]string{}
	for _, item := range entries {
		entryEtags[stringValue(item["key"])] = stringValue(item["etag"])
	}
	cached := map[string]any{}
	missing := []string{}
	for _, key := range keys {
		if f.cachedSettings != nil && f.cachedEntryEtags != nil && f.cachedEntryEtags[key] == entryEtags[key] {
			if value, ok := f.cachedSettings[key]; ok {
				cached[key] = value
				continue
			}
		}
		missing = append(missing, key)
	}
	return cached, missing
}

func (f *fakeGroupIndexRPCClient) CacheGroupIndexSettings(groupAID string, settings map[string]any, entries []map[string]any, etag string, groupIndex ...any) {
	f.cacheCalls = append(f.cacheCalls, groupAID)
	if f.cachedSettings == nil {
		f.cachedSettings = map[string]any{}
	}
	for key, value := range settings {
		f.cachedSettings[key] = value
	}
	if f.cachedEntryEtags == nil {
		f.cachedEntryEtags = map[string]string{}
	}
	for _, item := range entries {
		key := stringValue(item["key"])
		if key != "" {
			f.cachedEntryEtags[key] = stringValue(item["etag"])
		}
	}
	if etag != "" {
		f.cachedGroupEtag = etag
	}
	if len(groupIndex) > 0 {
		f.cachedGroupIndex = groupIndex[0]
	}
}

func (f *fakeGroupIndexRPCClient) ResolveGroupIndexSigner(ctx context.Context, aid string) (GroupIndexSigner, error) {
	return fakeGroupIndexSigner{aid: aid}, nil
}

func testBaseGroupIndex(t *testing.T, signer fakeGroupIndexSigner, seed string) *SignedGroupIndex {
	t.Helper()
	index, err := BuildSignedGroupIndex(GroupIndexBuildOptions{
		GroupAID:     "g-team.example.test",
		Entries:      []map[string]any{{"key": "rules.content", "source": "db", "etag": fmt.Sprintf(`"sha256:%s"`, seed), "last_modified": 1}},
		Signer:       signer,
		LastModified: 1,
	})
	if err != nil {
		t.Fatalf("BuildSignedGroupIndex 失败: %v", err)
	}
	return index
}

func tamperGroupIndex(t *testing.T, index *SignedGroupIndex) map[string]any {
	t.Helper()
	parsed, err := ParseGroupIndex(index.Body)
	if err != nil {
		t.Fatalf("ParseGroupIndex 失败: %v", err)
	}
	entry := cloneMap(parsed.Entries[0])
	entry["etag"] = `"sha256:tampered"`
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal tampered entry 失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(index.Body), "\n")
	lines[1] = string(entryBytes)
	value := signedGroupIndexJSONValue(index)
	value["body"] = strings.Join(lines, "\n") + "\n"
	return value
}

func testGroupIndexWithEntries(t *testing.T, signer fakeGroupIndexSigner, entries []map[string]any) *SignedGroupIndex {
	t.Helper()
	index, err := BuildSignedGroupIndex(GroupIndexBuildOptions{
		GroupAID:     "g-team.example.test",
		Entries:      entries,
		Signer:       signer,
		LastModified: 1,
	})
	if err != nil {
		t.Fatalf("BuildSignedGroupIndex 失败: %v", err)
	}
	return index
}

func TestGroupFacadeDoesNotExposeSetSettingsWithIndexAlias(t *testing.T) {
	if _, ok := reflect.TypeOf(&GroupFacade{}).MethodByName("SetSettingsWithIndex"); ok {
		t.Fatal("GroupFacade 不应继续暴露 SetSettingsWithIndex 别名")
	}
}

func TestGroupFacadeUpdateGroupIndexSendsExpectedEtagAndSignedIndex(t *testing.T) {
	ctx := context.Background()
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	oldIndex := testBaseGroupIndex(t, signer, "old")
	client := &fakeGroupIndexRPCClient{getResults: []any{oldIndex}}
	group := newGroupFacade(client)

	result, err := group.UpdateGroupIndex(ctx, map[string]any{
		"group_id":      "g-team.example.test",
		"settings":      map[string]any{"rules.content": "新群规"},
		"signer":        signer,
		"last_modified": 2000,
	})
	if err != nil {
		t.Fatalf("UpdateGroupIndex 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if !containsGroupIndexTestString(toStringSlice(resultMap["updated_keys"]), "rules.content") || !containsGroupIndexTestString(toStringSlice(resultMap["updated_keys"]), GroupIndexKey) {
		t.Fatalf("updated_keys 不匹配: %#v", resultMap["updated_keys"])
	}

	if len(client.calls) != 2 || client.calls[0].method != "group.get_settings" || client.calls[1].method != "group.set_settings" {
		t.Fatalf("调用顺序不匹配: %#v", client.calls)
	}
	setCall := client.calls[1].params
	parsedOld, _ := ParseGroupIndex(oldIndex.Body)
	if setCall["expected_index_etag"] != parsedOld.Meta["etag"] {
		t.Fatalf("expected_index_etag 不匹配: %#v", setCall)
	}
	settings := setCall["settings"].(map[string]any)
	if settings["rules.content"] != "新群规" || settings[GroupIndexKey] == nil {
		t.Fatalf("settings 不匹配: %#v", settings)
	}
	verified, err := VerifyGroupIndex(settings[GroupIndexKey], signer)
	if err != nil || !verified.Valid {
		t.Fatalf("签名 index 无效: %#v err=%v", verified, err)
	}
}

func TestGroupFacadeCheckGroupIndexReportsObservedRemoteMetaWithoutRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeGroupIndexRPCClient{
		stale:      true,
		localEtag:  `"sha256:local"`,
		remoteMeta: map[string]any{"etag": `"sha256:remote"`, "last_modified": int64(1234), "schema": GroupIndexSchema},
	}
	group := newGroupFacade(client)

	result, err := group.CheckGroupIndex(ctx, map[string]any{"group_aid": "g-team.example.test"})
	if err != nil {
		t.Fatalf("CheckGroupIndex 失败: %v", err)
	}
	resultMap := result.(map[string]any)
	if resultMap["group_aid"] != "g-team.example.test" ||
		resultMap["local_found"] != true ||
		resultMap["remote_found"] != true ||
		resultMap["local_etag"] != `"sha256:local"` ||
		resultMap["remote_etag"] != `"sha256:remote"` ||
		resultMap["in_sync"] != false ||
		resultMap["needs_update"] != true ||
		resultMap["last_modified"] != int64(1234) ||
		resultMap["status"] != 200 ||
		resultMap["cached"] != true {
		t.Fatalf("CheckGroupIndex 状态不匹配: %#v", resultMap)
	}
	if len(client.calls) != 0 {
		t.Fatalf("CheckGroupIndex 不应发 RPC: %#v", client.calls)
	}
}

func TestGroupFacadeGetGroupIndexFetchesRemoteIndexAndMarksFresh(t *testing.T) {
	ctx := context.Background()
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	remoteIndex := testBaseGroupIndex(t, signer, "remote")
	client := &fakeGroupIndexRPCClient{getResults: []any{remoteIndex}, stale: true}
	client.remoteSettings = map[string]any{"rules.content": "远端群规"}
	group := newGroupFacade(client)

	result, err := group.GetGroupIndex(ctx, map[string]any{"group_id": "g-team.example.test"})
	if err != nil {
		t.Fatalf("GetGroupIndex 失败: %v", err)
	}
	parsed, _ := ParseGroupIndex(remoteIndex.Body)
	resultMap := result.(map[string]any)
	if resultMap["group_id"] != "g-team.example.test" || resultMap["group_aid"] != "g-team.example.test" {
		t.Fatalf("GetGroupIndex group 字段不匹配: %#v", resultMap)
	}
	if !reflect.DeepEqual(resultMap["group_index"], signedGroupIndexJSONValue(remoteIndex)) {
		t.Fatalf("GetGroupIndex index 不匹配: %#v", resultMap["group_index"])
	}
	if !reflect.DeepEqual(resultMap["meta"], parsed.Meta) || !reflect.DeepEqual(resultMap["entries"], parsed.Entries) {
		t.Fatalf("GetGroupIndex 解析结果不匹配: %#v", resultMap)
	}
	if !reflect.DeepEqual(client.freshMarks, []map[string]string{{"group_aid": "g-team.example.test", "etag": stringValue(parsed.Meta["etag"])}}) {
		t.Fatalf("MarkFresh 不匹配: %#v", client.freshMarks)
	}
	if client.cachedSettings["rules.content"] != "远端群规" {
		t.Fatalf("cache 未同步: %#v", client.cachedSettings)
	}
	if !reflect.DeepEqual(client.cachedGroupIndex, signedGroupIndexJSONValue(remoteIndex)) {
		t.Fatalf("cache 未收到 group.index: %#v", client.cachedGroupIndex)
	}
	if len(client.calls) != 2 || client.calls[0].method != "group.get_settings" || client.calls[1].method != "group.get_settings" ||
		!reflect.DeepEqual(toStringSlice(client.calls[0].params["keys"]), []string{GroupIndexKey}) ||
		!reflect.DeepEqual(toStringSlice(client.calls[1].params["keys"]), []string{"rules.content"}) {
		t.Fatalf("调用顺序不匹配: %#v", client.calls)
	}
}

func TestGroupFacadeGetGroupIndexRejectsTamperedRemoteIndexBeforeCacheUpdate(t *testing.T) {
	ctx := context.Background()
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	remoteIndex := tamperGroupIndex(t, testBaseGroupIndex(t, signer, "remote"))
	client := &fakeGroupIndexRPCClient{
		getResults:     []any{remoteIndex},
		remoteSettings: map[string]any{"rules.content": "不应读取"},
	}
	group := newGroupFacade(client)

	_, err := group.GetGroupIndex(ctx, map[string]any{"group_id": "g-team.example.test"})
	if err == nil || !strings.Contains(err.Error(), "group.index") {
		t.Fatalf("GetGroupIndex 应拒绝篡改 index: %v", err)
	}
	if len(client.freshMarks) != 0 {
		t.Fatalf("不应 mark fresh: %#v", client.freshMarks)
	}
	if len(client.cachedSettings) != 0 {
		t.Fatalf("不应更新 cache: %#v", client.cachedSettings)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.get_settings" {
		t.Fatalf("不应 hydrate settings: %#v", client.calls)
	}
}

func TestGroupFacadeGetRulesReturnsCachedRulesEvenWhenGroupIndexIsStale(t *testing.T) {
	ctx := context.Background()
	client := &fakeGroupIndexRPCClient{
		stale: true,
		cachedSettings: map[string]any{
			"rules.content":     "缓存群规",
			"rules.attachments": []any{map[string]any{"uri": "groupfs://rules.pdf"}},
		},
	}
	group := newGroupFacade(client)

	result, err := group.GetRules(ctx, map[string]any{"group_id": "g-team.example.test"})
	if err != nil {
		t.Fatalf("GetRules 失败: %v", err)
	}
	resultMap := result.(map[string]any)
	rules := resultMap["rules"].(map[string]any)
	if rules["content"] != "缓存群规" || !reflect.DeepEqual(rules["attachments"], []any{map[string]any{"uri": "groupfs://rules.pdf"}}) {
		t.Fatalf("缓存 rules 不匹配: %#v", rules)
	}
	if len(client.calls) != 0 {
		t.Fatalf("fresh cache 命中时不应发 RPC: %#v", client.calls)
	}
}

func TestGroupFacadeGetRulesFetchesSettingsOnlyWhenLocalCacheIsMissing(t *testing.T) {
	ctx := context.Background()
	client := &fakeGroupIndexRPCClient{
		stale: true,
		remoteSettings: map[string]any{
			"rules.content":     "远端群规",
			"rules.attachments": []any{map[string]any{"uri": "groupfs://rules.pdf"}},
		},
	}
	group := newGroupFacade(client)

	result, err := group.GetRules(ctx, map[string]any{"group_id": "g-team.example.test"})
	if err != nil {
		t.Fatalf("GetRules 失败: %v", err)
	}
	rules := result.(map[string]any)["rules"].(map[string]any)
	if rules["content"] != "远端群规" || !reflect.DeepEqual(rules["attachments"], []any{map[string]any{"uri": "groupfs://rules.pdf"}}) {
		t.Fatalf("rules 不匹配: %#v", rules)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.get_settings" {
		t.Fatalf("调用顺序不匹配: %#v", client.calls)
	}
	if !reflect.DeepEqual(toStringSlice(client.calls[0].params["keys"]), []string{"rules.content", "rules.attachments"}) {
		t.Fatalf("按需 keys 不匹配: %#v", client.calls)
	}
	if len(client.freshMarks) != 0 {
		t.Fatalf("MarkFresh 不匹配: %#v", client.freshMarks)
	}
	if client.cachedSettings["rules.content"] != "远端群规" {
		t.Fatalf("cache 未更新: %#v", client.cachedSettings)
	}
}

func TestGroupFacadeGetRulesCachesSettingsUnderCanonicalAndRequestedGroupIDs(t *testing.T) {
	ctx := context.Background()
	client := &fakeGroupIndexRPCClient{
		remoteSettings: map[string]any{
			"rules.content":     "远端群规",
			"rules.attachments": []any{},
		},
	}
	group := newGroupFacade(client)

	_, err := group.GetRules(ctx, map[string]any{"group_id": "legacy.remote.example"})
	if err != nil {
		t.Fatalf("GetRules 失败: %v", err)
	}

	expected := []string{"g-team.example.test", "legacy.remote.example"}
	if !reflect.DeepEqual(client.cacheCalls, expected) {
		t.Fatalf("cache key 不匹配: got=%#v want=%#v", client.cacheCalls, expected)
	}
}

func TestGroupFacadeUpdateRulesRefreshesIndexedSettingsCacheAfterPush(t *testing.T) {
	ctx := context.Background()
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	oldIndex := testBaseGroupIndex(t, signer, "old")
	client := &fakeGroupIndexRPCClient{getResults: []any{oldIndex}}
	group := newGroupFacade(client)

	if _, err := group.UpdateRules(ctx, map[string]any{"group_id": "g-team.example.test", "content": "新群规", "signer": signer, "last_modified": 2000}); err != nil {
		t.Fatalf("UpdateRules 失败: %v", err)
	}
	if client.cachedSettings["rules.content"] != "新群规" || client.cachedGroupEtag == "" {
		t.Fatalf("cache 未刷新: settings=%#v etag=%s", client.cachedSettings, client.cachedGroupEtag)
	}
}

func TestGroupFacadeUpdateGroupIndexPullsMergesAndPushesWithCAS(t *testing.T) {
	ctx := context.Background()
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	oldIndex := testBaseGroupIndex(t, signer, "old")
	client := &fakeGroupIndexRPCClient{getResults: []any{oldIndex}}
	group := newGroupFacade(client)

	result, err := group.UpdateGroupIndex(ctx, map[string]any{
		"group_id":      "g-team.example.test",
		"settings":      map[string]any{"rules.content": "新群规"},
		"signer":        signer,
		"last_modified": 2000,
	})
	if err != nil {
		t.Fatalf("UpdateGroupIndex 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if !containsGroupIndexTestString(toStringSlice(resultMap["updated_keys"]), "rules.content") || !containsGroupIndexTestString(toStringSlice(resultMap["updated_keys"]), GroupIndexKey) {
		t.Fatalf("updated_keys 不匹配: %#v", resultMap["updated_keys"])
	}
	setCall := client.calls[1].params
	parsedOld, _ := ParseGroupIndex(oldIndex.Body)
	if setCall["expected_index_etag"] != parsedOld.Meta["etag"] {
		t.Fatalf("expected_index_etag 不匹配: %#v", setCall)
	}
	settings := setCall["settings"].(map[string]any)
	if settings["rules.content"] != "新群规" || settings[GroupIndexKey] == nil {
		t.Fatalf("settings 不匹配: %#v", settings)
	}
	verified, err := VerifyGroupIndex(settings[GroupIndexKey], signer)
	if err != nil || !verified.Valid {
		t.Fatalf("签名 index 无效: %#v err=%v", verified, err)
	}
}

func TestGroupFacadeUpdateGroupIndexMarksPushedIndexFresh(t *testing.T) {
	ctx := context.Background()
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	oldIndex := testBaseGroupIndex(t, signer, "old")
	client := &fakeGroupIndexRPCClient{getResults: []any{oldIndex}, stale: true}
	group := newGroupFacade(client)

	_, err := group.UpdateGroupIndex(ctx, map[string]any{
		"group_id":      "g-team.example.test",
		"settings":      map[string]any{"rules.content": "新群规"},
		"signer":        signer,
		"last_modified": 2000,
	})
	if err != nil {
		t.Fatalf("UpdateGroupIndex 失败: %v", err)
	}

	setCall := client.calls[1].params
	settings := setCall["settings"].(map[string]any)
	parsed, err := ParseGroupIndex(settings[GroupIndexKey])
	if err != nil {
		t.Fatalf("解析 pushed index 失败: %v", err)
	}
	want := []map[string]string{{"group_aid": "g-team.example.test", "etag": stringValue(parsed.Meta["etag"])}}
	if !reflect.DeepEqual(client.freshMarks, want) {
		t.Fatalf("MarkFresh 不匹配: %#v", client.freshMarks)
	}
	if client.stale {
		t.Fatal("UpdateGroupIndex 成功后本地 stale 应清除")
	}
}

func TestGroupFacadeUpdateGroupIndexRetriesAfterCASConflict(t *testing.T) {
	ctx := context.Background()
	signer := fakeGroupIndexSigner{aid: "owner.example.test"}
	oldIndex := testBaseGroupIndex(t, signer, "old")
	newerIndex := testBaseGroupIndex(t, signer, "newer")
	client := &fakeGroupIndexRPCClient{getResults: []any{oldIndex, newerIndex}, failFirstSet: true}
	group := newGroupFacade(client)

	_, err := group.UpdateGroupIndex(ctx, map[string]any{
		"group_id":      "g-team.example.test",
		"settings":      map[string]any{"rules.content": "我的版本"},
		"signer":        signer,
		"last_modified": 2000,
	})
	if err != nil {
		t.Fatalf("UpdateGroupIndex 失败: %v", err)
	}

	setCalls := []map[string]any{}
	for _, call := range client.calls {
		if call.method == "group.set_settings" {
			setCalls = append(setCalls, call.params)
		}
	}
	if len(setCalls) != 2 {
		t.Fatalf("应重试一次: %#v", client.calls)
	}
	parsedOld, _ := ParseGroupIndex(oldIndex.Body)
	parsedNewer, _ := ParseGroupIndex(newerIndex.Body)
	if setCalls[0]["expected_index_etag"] != parsedOld.Meta["etag"] || setCalls[1]["expected_index_etag"] != parsedNewer.Meta["etag"] {
		t.Fatalf("CAS etag 不匹配: %#v", setCalls)
	}
}

func TestIndexedSettingsHelpersUseUpdateGroupIndex(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		call        func(*GroupFacade, fakeGroupIndexSigner) (any, error)
		expectedKey string
	}{
		{"UpdateRules", func(group *GroupFacade, signer fakeGroupIndexSigner) (any, error) {
			return group.UpdateRules(ctx, map[string]any{"group_id": "g-team.example.test", "content": "新群规", "signer": signer, "last_modified": 2000})
		}, "rules.content"},
		{"UpdateAnnouncement", func(group *GroupFacade, signer fakeGroupIndexSigner) (any, error) {
			return group.UpdateAnnouncement(ctx, map[string]any{"group_id": "g-team.example.test", "content": "新公告", "signer": signer, "last_modified": 2000})
		}, "announcement.content"},
		{"UpdateJoinRequirements", func(group *GroupFacade, signer fakeGroupIndexSigner) (any, error) {
			return group.UpdateJoinRequirements(ctx, map[string]any{"group_id": "g-team.example.test", "mode": "approval", "signer": signer, "last_modified": 2000})
		}, "join.mode"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := fakeGroupIndexSigner{aid: "owner.example.test"}
			oldIndex := testBaseGroupIndex(t, signer, "old")
			client := &fakeGroupIndexRPCClient{getResults: []any{oldIndex}}
			group := newGroupFacade(client)

			if _, err := tc.call(group, signer); err != nil {
				t.Fatalf("%s 失败: %v", tc.name, err)
			}
			gotMethods := []string{}
			for _, call := range client.calls {
				gotMethods = append(gotMethods, call.method)
			}
			if !reflect.DeepEqual(gotMethods, []string{"group.get_settings", "group.set_settings"}) {
				t.Fatalf("调用顺序不匹配: %#v", gotMethods)
			}
			setCall := client.calls[1].params
			settings := setCall["settings"].(map[string]any)
			if settings[tc.expectedKey] == nil || settings[GroupIndexKey] == nil {
				t.Fatalf("settings 未包含 index 或目标 key: %#v", settings)
			}
			parsedOld, _ := ParseGroupIndex(oldIndex.Body)
			if setCall["expected_index_etag"] != parsedOld.Meta["etag"] {
				t.Fatalf("expected_index_etag 不匹配: %#v", setCall)
			}
		})
	}
}

func containsGroupIndexTestString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func toStringSlice(value any) []string {
	out := []string{}
	for _, item := range value.([]string) {
		out = append(out, item)
	}
	return out
}
