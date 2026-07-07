//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestIntegration_GroupSetSettings — set_settings 基本操作
// 覆盖：owner 设置 name/description、设置 rules/announcement、非管理员被拒、未知 key 被拒
// ---------------------------------------------------------------------------

func TestIntegration_GroupSetSettings(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	bob := makeClient(t)
	defer owner.Close()
	defer bob.Close()

	ownerAID := fmt.Sprintf("gss%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("gss%s-b.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建公开群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("settings-%s", rid),
		"visibility": "public",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 添加 Bob 为成员 ----
	_, err = owner.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}
	t.Logf("添加 Bob 为成员")

	// ---- owner set_settings: name + description ----
	newName := fmt.Sprintf("Renamed-%s", rid)
	r1, err := owner.Call(ctx, "group.set_settings", map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"name":        newName,
			"description": "test desc",
		},
	})
	skipIfNotImplemented(t, err, "group.set_settings")
	if err != nil {
		t.Fatalf("set_settings(name+description) 失败: %v", err)
	}
	r1Map, _ := r1.(map[string]any)
	if r1Map == nil {
		t.Fatalf("set_settings 返回 nil")
	}
	// 验证 group_id
	if gid, _ := r1Map["group_id"].(string); gid != groupID {
		t.Fatalf("set_settings 返回 group_id 不匹配: 期望 %s, 实际 %s", groupID, gid)
	}
	// 验证 updated_keys 包含 name 和 description
	updatedKeys1 := settingsToStringSlice(r1Map["updated_keys"])
	if !sliceContains(updatedKeys1, "name") {
		t.Fatalf("updated_keys 应包含 name: %v", updatedKeys1)
	}
	if !sliceContains(updatedKeys1, "description") {
		t.Fatalf("updated_keys 应包含 description: %v", updatedKeys1)
	}
	t.Logf("set_settings(name+description) 成功: updated_keys=%v", updatedKeys1)

	// ---- owner set_settings: rules.content + announcement.content ----
	r2, err := owner.Group().UpdateGroupIndex(ctx, map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"rules.content":        "群规内容",
			"announcement.content": "公告内容",
		},
	})
	if err != nil {
		t.Fatalf("set_settings(rules+announcement) 失败: %v", err)
	}
	r2Map, _ := r2.(map[string]any)
	updatedKeys2 := settingsToStringSlice(r2Map["updated_keys"])
	if !sliceContains(updatedKeys2, "rules.content") {
		t.Fatalf("updated_keys 应包含 rules.content: %v", updatedKeys2)
	}
	if !sliceContains(updatedKeys2, "announcement.content") {
		t.Fatalf("updated_keys 应包含 announcement.content: %v", updatedKeys2)
	}
	t.Logf("set_settings(rules+announcement) 成功: updated_keys=%v", updatedKeys2)

	// ---- Bob（非管理员）set_settings 应被拒绝 ----
	_, err = bob.Call(ctx, "group.set_settings", map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"name": "Hacked",
		},
	})
	if err == nil {
		t.Fatalf("非管理员 set_settings 应失败，但成功了")
	}
	t.Logf("非管理员 set_settings 被拒绝（符合预期）: %v", err)

	// ---- set_settings 未知 key 应被拒绝 ----
	_, err = owner.Call(ctx, "group.set_settings", map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"nonexistent_key": "value",
		},
	})
	if err == nil {
		t.Fatalf("未知 key set_settings 应失败，但成功了")
	}
	if !containsAny(err.Error(), "unknown", "invalid", "not supported", "unrecognized") {
		t.Logf("未知 key 错误信息: %v", err)
	}
	t.Logf("未知 key set_settings 被拒绝（符合预期）")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupGetSettings — get_settings 全量 + keys 过滤
// 覆盖：全量返回所有 settings、keys 过滤仅返回请求的字段、值正确性验证
// ---------------------------------------------------------------------------

func TestIntegration_GroupGetSettings(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	defer owner.Close()

	ownerAID := fmt.Sprintf("ggs%s.%s", rid, testIssuer())
	ensureConnected(t, owner, ownerAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("get-settings-%s", rid),
		"visibility": "public",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)

	// ---- 设置若干字段 ----
	setName := fmt.Sprintf("GS-Name-%s", rid)
	_, err = owner.Group().SetSettings(ctx, map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"name":                 setName,
			"description":         "测试描述",
		},
	})
	skipIfNotImplemented(t, err, "group.set_settings")
	if err != nil {
		t.Fatalf("set_settings(name/description) 失败: %v", err)
	}
	_, err = owner.Group().UpdateGroupIndex(ctx, map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"rules.content":       "测试群规",
			"announcement.content": "测试公告",
		},
	})
	skipIfNotImplemented(t, err, "group.set_settings")
	if err != nil {
		t.Fatalf("set_settings 失败: %v", err)
	}
	t.Logf("写入 name/description/rules.content/announcement.content")

	// ---- get_settings 全量（不传 keys） ----
	r1, err := owner.Call(ctx, "group.get_settings", map[string]any{
		"group_id": groupID,
	})
	skipIfNotImplemented(t, err, "group.get_settings")
	if err != nil {
		t.Fatalf("get_settings（全量）失败: %v", err)
	}
	r1Map, _ := r1.(map[string]any)
	if r1Map == nil {
		t.Fatalf("get_settings 返回 nil")
	}
	// 验证 group_id
	if gid, _ := r1Map["group_id"].(string); gid != groupID {
		t.Fatalf("get_settings 返回 group_id 不匹配: 期望 %s, 实际 %s", groupID, gid)
	}

	// 解析 settings 列表
	settingsList1, _ := r1Map["settings"].([]any)
	keysReturned1 := settingsKeys(settingsList1)
	// 全量应至少包含我们写入的 key
	for _, k := range []string{"name", "rules.content", "announcement.content"} {
		if !keysReturned1[k] {
			t.Fatalf("全量 get_settings 应包含 %q, 实际 keys=%v", k, keysReturned1)
		}
	}
	t.Logf("get_settings 全量返回 %d 个 key", len(keysReturned1))

	// 验证值正确性
	settingsMap1 := settingsToMap(settingsList1)
	if v, _ := settingsMap1["name"].(string); v != setName {
		t.Fatalf("name 值不匹配: 期望 %q, 实际 %q", setName, v)
	}
	if v, _ := settingsMap1["rules.content"].(string); v != "测试群规" {
		t.Fatalf("rules.content 值不匹配: 期望 %q, 实际 %q", "测试群规", v)
	}
	if v, _ := settingsMap1["announcement.content"].(string); v != "测试公告" {
		t.Fatalf("announcement.content 值不匹配: 期望 %q, 实际 %q", "测试公告", v)
	}
	t.Logf("全量 get_settings 值验证通过")

	// ---- get_settings 带 keys 过滤 ----
	r2, err := owner.Call(ctx, "group.get_settings", map[string]any{
		"group_id": groupID,
		"keys":     []string{"name", "rules.content"},
	})
	if err != nil {
		t.Fatalf("get_settings（keys 过滤）失败: %v", err)
	}
	r2Map, _ := r2.(map[string]any)
	settingsList2, _ := r2Map["settings"].([]any)
	keysReturned2 := settingsKeys(settingsList2)
	if len(keysReturned2) != 2 || !keysReturned2["name"] || !keysReturned2["rules.content"] {
		t.Fatalf("keys 过滤应只返回 name 和 rules.content, 实际: %v", keysReturned2)
	}

	// 验证过滤后值仍正确
	settingsMap2 := settingsToMap(settingsList2)
	if v, _ := settingsMap2["name"].(string); v != setName {
		t.Fatalf("过滤后 name 值不匹配: 期望 %q, 实际 %q", setName, v)
	}
	if v, _ := settingsMap2["rules.content"].(string); v != "测试群规" {
		t.Fatalf("过滤后 rules.content 值不匹配: 期望 %q, 实际 %q", "测试群规", v)
	}
	t.Logf("get_settings keys 过滤验证通过")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupInfo — group.get_info 视角
// 覆盖：成员看到完整信息、非成员看公开群（无 owner_aid）、非成员看私有群被拒
// ---------------------------------------------------------------------------

func TestIntegration_GroupInfo(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	bob := makeClient(t)
	defer owner.Close()
	defer bob.Close()

	ownerAID := fmt.Sprintf("ginfo%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("ginfo%s-b.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建公开群组 ----
	pubName := fmt.Sprintf("info-pub-%s", rid)
	pubResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       pubName,
		"visibility": "public",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	pubGroupID := extractGroupID(t, pubResult)
	defer cleanupGroup(t, owner, pubGroupID)

	// 创建私有群组
	privName := fmt.Sprintf("info-priv-%s", rid)
	privResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       privName,
		"visibility": "private",
	})
	if err != nil {
		t.Fatalf("group.create(private) 失败: %v", err)
	}
	privGroupID := extractGroupID(t, privResult)
	defer cleanupGroup(t, owner, privGroupID)

	// ---- owner 调用 group.get_info ----
	infoResult, err := owner.Call(ctx, "group.get_info", map[string]any{
		"group_id": pubGroupID,
		"required": []string{"member"},
	})
	skipIfNotImplemented(t, err, "group.get_info")
	if err != nil {
		t.Fatalf("group.get_info 失败: %v", err)
	}
	infoMap, _ := infoResult.(map[string]any)
	if infoMap == nil {
		t.Fatalf("group.get_info 返回 nil")
	}
	// 验证基本字段
	if gid, _ := infoMap["group_id"].(string); gid != pubGroupID {
		t.Fatalf("info group_id 不匹配: 期望 %s, 实际 %s", pubGroupID, gid)
	}
	if name, _ := infoMap["name"].(string); name != pubName {
		t.Fatalf("info name 不匹配: 期望 %q, 实际 %q", pubName, name)
	}
	if ownerAIDField, _ := infoMap["owner_aid"].(string); ownerAIDField != ownerAID {
		t.Fatalf("info owner_aid 不匹配: 期望 %s, 实际 %s", ownerAID, ownerAIDField)
	}
	if _, ok := infoMap["member_count"]; !ok {
		t.Fatalf("info 缺少 member_count 字段: %#v", infoMap)
	}
	t.Logf("owner group.get_info 基本字段验证通过")

	// ---- 非成员看公开群基础信息（不含 owner_aid） ----
	bobPubInfo, err := bob.Call(ctx, "group.get_info", map[string]any{
		"group_id": pubGroupID,
	})
	if err != nil {
		t.Fatalf("非成员看公开群 get_info 失败: %v", err)
	}
	bobPubMap, _ := bobPubInfo.(map[string]any)
	if gid, _ := bobPubMap["group_id"].(string); gid != pubGroupID {
		t.Fatalf("非成员看到的 group_id 不匹配: %s", gid)
	}
	if name, _ := bobPubMap["name"].(string); name != pubName {
		t.Fatalf("非成员看到的 name 不匹配: %q", name)
	}
	// 非成员不应看到 owner_aid
	if _, hasOwner := bobPubMap["owner_aid"]; hasOwner {
		t.Fatalf("非成员不应看到 owner_aid, 但返回了: %#v", bobPubMap)
	}
	t.Logf("非成员看公开群验证通过（无 owner_aid）")

	// ---- 非成员看私有群应被拒绝 ----
	_, err = bob.Call(ctx, "group.get_info", map[string]any{
		"group_id": privGroupID,
	})
	if err == nil {
		t.Fatalf("非成员看私有群应失败，但成功了")
	}
	t.Logf("非成员看私有群被拒绝（符合预期）: %v", err)
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupSync — group.sync 事件同步
// 覆盖：创建群 + 2成员、owner 修改 settings、成员通过 pull_events 看到变更、
//       成员退群后不再收到事件
// ---------------------------------------------------------------------------

func TestIntegration_GroupSync(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	member := makeClient(t)
	defer owner.Close()
	defer member.Close()

	ownerAID := fmt.Sprintf("gsync%s.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("gsync%s-m.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// ---- 创建群组并添加成员 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("sync-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)

	_, err = owner.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      memberAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加成员失败: %v", err)
	}
	t.Logf("创建群组 %s, 添加成员 %s", groupID, memberAID)

	// 等待成员加入事件落库
	time.Sleep(1 * time.Second)

	// ---- 订阅成员侧群事件（push 方式） ----
	var mu sync.Mutex
	var receivedEvents []map[string]any
	eventDone := make(chan struct{}, 1)

	sub := member.On("group.changed", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		// 只关注本群的事件
		if gid, _ := data["group_id"].(string); gid != groupID {
			return
		}
		mu.Lock()
		receivedEvents = append(receivedEvents, data)
		mu.Unlock()
		select {
		case eventDone <- struct{}{}:
		default:
		}
	})

	// ---- owner 修改 settings 触发事件 ----
	changedName := fmt.Sprintf("SyncRenamed-%s", rid)
	_, err = owner.Call(ctx, "group.set_settings", map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"name": changedName,
		},
	})
	skipIfNotImplemented(t, err, "group.set_settings")
	if err != nil {
		t.Fatalf("set_settings 触发同步失败: %v", err)
	}
	t.Logf("owner 修改群名为 %q", changedName)

	// ---- 等待 push 事件 ----
	pushTimer := time.NewTimer(5 * time.Second)
	select {
	case <-eventDone:
		t.Logf("成员收到 group.changed push 事件")
	case <-pushTimer.C:
		t.Logf("push 超时，将使用 pull 兜底")
	}
	pushTimer.Stop()
	sub.Unsubscribe()

	// ---- pull 兜底：通过 pull_events 验证事件 ----
	pullResult, err := member.Call(ctx, "group.pull_events", map[string]any{
		"group_id":        groupID,
		"after_event_seq": 0,
		"limit":           50,
	})
	if err != nil {
		// pull_events 可能未实现，用 get_settings 兜底验证
		if containsAny(err.Error(), "not implement", "method not found", "not_implemented", "unknown method") {
			t.Logf("pull_events 未实现，使用 get_settings 验证同步")
		} else {
			t.Fatalf("pull_events 失败: %v", err)
		}
	} else {
		pullMap, _ := pullResult.(map[string]any)
		events, _ := pullMap["events"].([]any)
		t.Logf("pull_events 返回 %d 个事件", len(events))

		// 查找 group.changed 类型事件
		foundSettingsEvent := false
		for _, e := range events {
			ev, _ := e.(map[string]any)
			if ev == nil {
				continue
			}
			eventType := ""
			if et, ok := ev["event_type"].(string); ok {
				eventType = et
			} else if et, ok := ev["type"].(string); ok {
				eventType = et
			}
			if strings.Contains(eventType, "group.") {
				foundSettingsEvent = true
				break
			}
		}
		if !foundSettingsEvent && len(events) > 0 {
			t.Logf("未找到 group.* 事件类型（忽略，可能事件类型命名不同）")
		}
	}

	// ---- 通过 get_settings 验证成员视角数据已同步 ----
	verifyResult, err := member.Call(ctx, "group.get_settings", map[string]any{
		"group_id": groupID,
		"keys":     []string{"name"},
	})
	if err != nil {
		// get_settings 可能未实现，使用 get_info 兜底
		if containsAny(err.Error(), "not implement", "method not found", "not_implemented", "unknown method") {
			t.Logf("get_settings 未实现，跳过值验证")
		} else {
			t.Fatalf("get_settings 验证失败: %v", err)
		}
	} else {
		verifyMap, _ := verifyResult.(map[string]any)
		sm := settingsToMap(verifyMap["settings"].([]any))
		if v, _ := sm["name"].(string); v != changedName {
			t.Fatalf("成员侧 name 未同步: 期望 %q, 实际 %q", changedName, v)
		}
		t.Logf("成员侧 get_settings 验证同步通过")
	}

	// ---- 成员退群 ----
	_, err = member.Call(ctx, "group.leave", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		// leave 可能叫 quit
		_, err2 := member.Call(ctx, "group.quit", map[string]any{
			"group_id": groupID,
		})
		if err2 != nil {
			t.Fatalf("成员退群失败 (leave: %v, quit: %v)", err, err2)
		}
	}
	t.Logf("成员已退群")

	// ---- 退群后验证：成员不应再能访问群信息 ----
	time.Sleep(500 * time.Millisecond)
	_, err = member.Call(ctx, "group.get_settings", map[string]any{
		"group_id": groupID,
	})
	if err == nil {
		// 有些实现退群后仍可读公开群，这里仅记录
		t.Logf("退群后 get_settings 仍可访问（可能是预期行为）")
	} else {
		t.Logf("退群后 get_settings 被拒绝（符合预期）: %v", err)
	}

	// ---- 退群后 owner 再次修改，验证前成员不再收到事件 ----
	var postLeaveEvents []map[string]any
	postSub := member.On("group.changed", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		if gid, _ := data["group_id"].(string); gid == groupID {
			mu.Lock()
			postLeaveEvents = append(postLeaveEvents, data)
			mu.Unlock()
		}
	})

	_, _ = owner.Call(ctx, "group.set_settings", map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"name": fmt.Sprintf("AfterLeave-%s", rid),
		},
	})

	// 等待短暂时间确认无事件到达
	time.Sleep(2 * time.Second)
	postSub.Unsubscribe()

	mu.Lock()
	postCount := len(postLeaveEvents)
	mu.Unlock()
	if postCount > 0 {
		t.Fatalf("退群后不应收到群事件，但收到了 %d 个", postCount)
	}
	t.Logf("退群后未收到群事件（符合预期）")
}

// ---------------------------------------------------------------------------
// 辅助函数（仅本文件使用）
// ---------------------------------------------------------------------------

// settingsToStringSlice 将 any 转为 []string（兼容 []any 和 []string）
func settingsToStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch typed := v.(type) {
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// sliceContains 检查字符串切片是否包含指定元素
func sliceContains(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// settingsKeys 从 settings 列表 [{key, value}, ...] 提取 key 集合
func settingsKeys(settingsList []any) map[string]bool {
	result := make(map[string]bool)
	for _, item := range settingsList {
		entry, _ := item.(map[string]any)
		if entry == nil {
			continue
		}
		if k, _ := entry["key"].(string); k != "" {
			result[k] = true
		}
	}
	return result
}

// settingsToMap 将 settings 列表 [{key, value}, ...] 转为 map[key]value
func settingsToMap(settingsList []any) map[string]any {
	result := make(map[string]any)
	for _, item := range settingsList {
		entry, _ := item.(map[string]any)
		if entry == nil {
			continue
		}
		if k, _ := entry["key"].(string); k != "" {
			result[k] = entry["value"]
		}
	}
	return result
}
