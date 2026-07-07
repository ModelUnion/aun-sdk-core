//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntegration_GroupIndexCASAndMeta(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("gi%s-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("gi%s-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	createResult, err := alice.Group().Create(ctx, map[string]any{
		"name":       fmt.Sprintf("group-index-%s", rid),
		"visibility": "public",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)

	if _, err := alice.Group().AddMember(ctx, map[string]any{"group_id": groupID, "aid": bobAID}); err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}
	if _, err := alice.Group().SetRole(ctx, map[string]any{"group_id": groupID, "aid": bobAID, "role": "admin"}); err != nil {
		t.Fatalf("设置 Bob admin 失败: %v", err)
	}

	first, err := alice.Group().UpdateGroupIndex(ctx, map[string]any{
		"group_id": groupID,
		"settings": map[string]any{"rules.content": fmt.Sprintf("群规 v1 %s", rid)},
	})
	if err != nil {
		t.Fatalf("UpdateGroupIndex 首次写入失败: %v", err)
	}
	firstMap, _ := mapFromAny(first)
	if !sliceContains(settingsToStringSlice(firstMap["updated_keys"]), GroupIndexKey) ||
		!sliceContains(settingsToStringSlice(firstMap["updated_keys"]), "rules.content") {
		t.Fatalf("updated_keys 缺少 group.index/rules.content: %v", firstMap["updated_keys"])
	}

	bobRead, err := bob.Group().GetSettings(ctx, map[string]any{"group_id": groupID, "keys": []string{GroupIndexKey}})
	if err != nil {
		t.Fatalf("Bob get_settings(group.index) 失败: %v", err)
	}
	bobReadMap, _ := mapFromAny(bobRead)
	groupAID := stringValue(bobReadMap["group_aid"])
	if groupAID == "" {
		groupAID = groupID
	}
	firstIndex := settingsToMap(anySlice(bobReadMap["settings"]))[GroupIndexKey]
	firstParsed, err := ParseGroupIndex(firstIndex)
	if err != nil {
		t.Fatalf("解析首次 group.index 失败: %v", err)
	}
	verified, err := VerifyGroupIndex(firstIndex, alice.CurrentAID())
	if err != nil || !verified.Valid {
		t.Fatalf("首次 group.index 验签失败: result=%#v err=%v", verified, err)
	}
	if !groupIndexEntriesContain(firstParsed.Entries, "rules.content") {
		t.Fatalf("首次 group.index 缺少 rules.content: %#v", firstParsed.Entries)
	}
	if !bob.IsGroupIndexStale(groupAID) {
		t.Fatalf("Bob 应观察到 group.index stale")
	}
	bob.MarkGroupIndexFresh(groupAID, stringValue(firstParsed.Meta["etag"]))
	if bob.IsGroupIndexStale(groupAID) {
		t.Fatalf("MarkGroupIndexFresh 后 stale 应清除")
	}

	_, err = alice.Group().SetSettings(ctx, map[string]any{
		"group_id": groupID,
		"settings": map[string]any{"rules.content": "裸写应失败"},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "group.index") {
		t.Fatalf("裸写 indexed settings 应被 group.index 约束拒绝，实际: %v", err)
	}

	baseIndex := firstIndex
	baseEtag := stringValue(firstParsed.Meta["etag"])
	aliceUpdate, err := PrepareGroupSettingsWithIndex(GroupSettingsWithIndexOptions{
		GroupAID:      groupAID,
		Settings:      map[string]any{"rules.content": fmt.Sprintf("群规 v2 %s", rid)},
		Signer:        alice.CurrentAID(),
		LastModified:  time.Now().UnixMilli(),
		BaseIndex:     baseIndex,
	})
	if err != nil {
		t.Fatalf("构造 Alice index 更新失败: %v", err)
	}
	if _, err := alice.Group().SetSettings(ctx, map[string]any{
		"group_id":            groupID,
		"settings":            aliceUpdate,
		"expected_index_etag": baseEtag,
	}); err != nil {
		t.Fatalf("Alice CAS 更新失败: %v", err)
	}

	staleBobUpdate, err := PrepareGroupSettingsWithIndex(GroupSettingsWithIndexOptions{
		GroupAID:      groupAID,
		Settings:      map[string]any{"announcement.content": fmt.Sprintf("公告 stale %s", rid)},
		Signer:        bob.CurrentAID(),
		LastModified:  time.Now().UnixMilli(),
		BaseIndex:     baseIndex,
	})
	if err != nil {
		t.Fatalf("构造 Bob stale index 更新失败: %v", err)
	}
	_, err = bob.Group().SetSettings(ctx, map[string]any{
		"group_id":            groupID,
		"settings":            staleBobUpdate,
		"expected_index_etag": baseEtag,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "etag conflict") {
		t.Fatalf("旧 etag CAS 应冲突，实际: %v", err)
	}

	retried, err := bob.Group().UpdateGroupIndex(ctx, map[string]any{
		"group_id": groupID,
		"settings": map[string]any{"announcement.content": fmt.Sprintf("公告 v2 %s", rid)},
	})
	if err != nil {
		t.Fatalf("Bob UpdateGroupIndex 重试路径失败: %v", err)
	}
	retriedMap, _ := mapFromAny(retried)
	if !sliceContains(settingsToStringSlice(retriedMap["updated_keys"]), "announcement.content") {
		t.Fatalf("重试更新缺少 announcement.content: %v", retriedMap["updated_keys"])
	}

	finalRead, err := alice.Group().GetSettings(ctx, map[string]any{
		"group_id": groupID,
		"keys":     []string{GroupIndexKey, "rules.content", "announcement.content"},
	})
	if err != nil {
		t.Fatalf("最终 get_settings 失败: %v", err)
	}
	finalMapRaw, _ := mapFromAny(finalRead)
	finalSettings := settingsToMap(anySlice(finalMapRaw["settings"]))
	finalParsed, err := ParseGroupIndex(finalSettings[GroupIndexKey])
	if err != nil {
		t.Fatalf("解析最终 group.index 失败: %v", err)
	}
	if stringValue(finalParsed.Meta["signed_by"]) != bobAID {
		t.Fatalf("最终 group.index 应由 Bob 签名，实际: %v", finalParsed.Meta["signed_by"])
	}
	if !groupIndexEntriesContain(finalParsed.Entries, "rules.content") ||
		!groupIndexEntriesContain(finalParsed.Entries, "announcement.content") {
		t.Fatalf("最终 group.index 缺少条目: %#v", finalParsed.Entries)
	}
	if finalSettings["rules.content"] != fmt.Sprintf("群规 v2 %s", rid) {
		t.Fatalf("rules.content 不匹配: %v", finalSettings["rules.content"])
	}
	if finalSettings["announcement.content"] != fmt.Sprintf("公告 v2 %s", rid) {
		t.Fatalf("announcement.content 不匹配: %v", finalSettings["announcement.content"])
	}
}

func groupIndexEntriesContain(entries []map[string]any, key string) bool {
	for _, entry := range entries {
		if stringValue(entry["key"]) == key {
			return true
		}
	}
	return false
}
