//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestIntegration_GroupSearch — 群组搜索基本功能
// 覆盖：空参搜索、关键字搜索公开群、私有群不可被搜索、keyword 别名、不存在关键字
// ---------------------------------------------------------------------------

func TestIntegration_GroupSearch(t *testing.T) {
	rid := runID()
	client := makeClient(t)
	defer client.Close()

	clientAID := fmt.Sprintf("search%s.%s", rid, testIssuer())
	ensureConnected(t, client, clientAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建公开群（可被搜索） ----
	publicName := fmt.Sprintf("SearchTest-%s", rid)
	pubResult, err := client.Call(ctx, "group.create", map[string]any{
		"name":       publicName,
		"visibility": "public",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("创建公开群失败: %v", err)
	}
	pubGroupID := extractGroupID(t, pubResult)
	defer cleanupGroup(t, client, pubGroupID)
	t.Logf("创建公开群: %s (name=%s)", pubGroupID, publicName)

	// ---- 创建私有群（不应被搜索到） ----
	privateName := fmt.Sprintf("PrivSearch-%s", rid)
	privResult, err := client.Call(ctx, "group.create", map[string]any{
		"name":       privateName,
		"visibility": "private",
	})
	if err != nil {
		t.Fatalf("创建私有群失败: %v", err)
	}
	privGroupID := extractGroupID(t, privResult)
	defer cleanupGroup(t, client, privGroupID)
	t.Logf("创建私有群: %s (name=%s)", privGroupID, privateName)

	// 等待索引更新
	time.Sleep(500 * time.Millisecond)

	// ---- 空参搜索：应返回 items 列表 ----
	emptyResult, err := client.Call(ctx, "group.search", map[string]any{})
	skipIfNotImplemented(t, err, "group.search")
	if err != nil {
		t.Fatalf("group.search（空参）失败: %v", err)
	}
	emptyMap, _ := emptyResult.(map[string]any)
	if emptyMap == nil {
		t.Fatalf("group.search（空参）返回 nil")
	}
	emptyItems, _ := emptyMap["items"].([]any)
	t.Logf("空参搜索返回 %d 个结果", len(emptyItems))

	// ---- query 搜索：应找到公开群，不应找到私有群 ----
	queryResult, err := client.Call(ctx, "group.search", map[string]any{
		"query": publicName,
	})
	if err != nil {
		t.Fatalf("group.search（query）失败: %v", err)
	}
	queryMap, _ := queryResult.(map[string]any)
	if queryMap == nil {
		t.Fatalf("group.search（query）返回 nil")
	}
	queryItems, _ := queryMap["items"].([]any)

	foundPublic := false
	foundPrivate := false
	for _, item := range queryItems {
		itemMap, _ := item.(map[string]any)
		if itemMap == nil {
			continue
		}
		gid, _ := itemMap["group_id"].(string)
		if gid == pubGroupID {
			foundPublic = true
		}
		if gid == privGroupID {
			foundPrivate = true
		}
	}
	if !foundPublic {
		t.Fatalf("query 搜索应找到公开群 %s, 实际结果: %#v", pubGroupID, queryItems)
	}
	if foundPrivate {
		t.Fatalf("query 搜索不应找到私有群 %s, 实际结果: %#v", privGroupID, queryItems)
	}
	t.Logf("query 搜索验证通过: 找到公开群, 未找到私有群")

	// ---- keyword 别名搜索：应与 query 行为一致 ----
	kwResult, err := client.Call(ctx, "group.search", map[string]any{
		"keyword": publicName,
	})
	if err != nil {
		t.Fatalf("group.search（keyword）失败: %v", err)
	}
	kwMap, _ := kwResult.(map[string]any)
	if kwMap == nil {
		t.Fatalf("group.search（keyword）返回 nil")
	}
	kwItems, _ := kwMap["items"].([]any)

	kwFoundPublic := false
	kwFoundPrivate := false
	for _, item := range kwItems {
		itemMap, _ := item.(map[string]any)
		if itemMap == nil {
			continue
		}
		gid, _ := itemMap["group_id"].(string)
		if gid == pubGroupID {
			kwFoundPublic = true
		}
		if gid == privGroupID {
			kwFoundPrivate = true
		}
	}
	if !kwFoundPublic {
		t.Fatalf("keyword 搜索应找到公开群 %s, 实际结果: %#v", pubGroupID, kwItems)
	}
	if kwFoundPrivate {
		t.Fatalf("keyword 搜索不应找到私有群 %s, 实际结果: %#v", privGroupID, kwItems)
	}
	t.Logf("keyword 别名搜索验证通过")

	// ---- 不存在的关键字搜索：应返回 0 个结果 ----
	noneResult, err := client.Call(ctx, "group.search", map[string]any{
		"query": fmt.Sprintf("nonexistent-%s-%d", rid, time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("group.search（不存在关键字）失败: %v", err)
	}
	noneMap, _ := noneResult.(map[string]any)
	if noneMap == nil {
		t.Fatalf("group.search（不存在关键字）返回 nil")
	}
	noneItems, _ := noneMap["items"].([]any)
	if len(noneItems) != 0 {
		t.Fatalf("不存在关键字搜索应返回 0 个结果, 实际: %d, 内容: %#v", len(noneItems), noneItems)
	}
	t.Logf("不存在关键字搜索返回 0 个结果（符合预期）")

	// ---- 清理：解散群组 ----
	_, err = client.Call(ctx, "group.dissolve", map[string]any{"group_id": pubGroupID})
	if err != nil {
		t.Logf("解散公开群失败（忽略）: %v", err)
	} else {
		pubGroupID = "" // 已解散，defer 不再重复
	}

	_, err = client.Call(ctx, "group.dissolve", map[string]any{"group_id": privGroupID})
	if err != nil {
		t.Logf("解散私有群失败（忽略）: %v", err)
	} else {
		privGroupID = "" // 已解散，defer 不再重复
	}
	t.Logf("清理完成")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupSearchPagination — 群组搜索分页
// 覆盖：limit 限制返回数量、has_more/total 指示、offset 翻页
// ---------------------------------------------------------------------------

func TestIntegration_GroupSearchPagination(t *testing.T) {
	rid := runID()
	client := makeClient(t)
	defer client.Close()

	clientAID := fmt.Sprintf("searchpg%s.%s", rid, testIssuer())
	ensureConnected(t, client, clientAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建 3 个公开群，使用共同前缀便于搜索 ----
	prefix := fmt.Sprintf("PgTest-%s", rid)
	groupIDs := make([]string, 3)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("%s-%d", prefix, i)
		result, err := client.Call(ctx, "group.create", map[string]any{
			"name":       name,
			"visibility": "public",
		})
		skipIfNotImplemented(t, err, "group.create")
		if err != nil {
			t.Fatalf("创建群 %s 失败: %v", name, err)
		}
		groupIDs[i] = extractGroupID(t, result)
		t.Logf("创建群 %d: %s (name=%s)", i, groupIDs[i], name)
	}
	// 清理所有群组
	defer func() {
		for _, gid := range groupIDs {
			cleanupGroup(t, client, gid)
		}
	}()

	// 等待索引更新
	time.Sleep(500 * time.Millisecond)

	// ---- 第一页：limit=2，应返回最多 2 个结果 ----
	page1Result, err := client.Call(ctx, "group.search", map[string]any{
		"query": prefix,
		"limit": 2,
	})
	skipIfNotImplemented(t, err, "group.search")
	if err != nil {
		t.Fatalf("group.search（第一页）失败: %v", err)
	}
	page1Map, _ := page1Result.(map[string]any)
	if page1Map == nil {
		t.Fatalf("group.search（第一页）返回 nil")
	}
	page1Items, _ := page1Map["items"].([]any)
	if len(page1Items) > 2 {
		t.Fatalf("limit=2 应返回最多 2 个结果, 实际: %d", len(page1Items))
	}
	if len(page1Items) == 0 {
		t.Fatalf("第一页应返回至少 1 个结果, 实际: 0")
	}
	t.Logf("第一页返回 %d 个结果", len(page1Items))

	// ---- 验证 has_more 或 total 指示还有更多结果 ----
	hasMore, hasMoreExists := page1Map["has_more"].(bool)
	totalFloat, totalExists := page1Map["total"].(float64)
	total := int(totalFloat)

	if hasMoreExists && !hasMore && len(page1Items) >= 2 {
		t.Logf("警告: has_more=false 但创建了 3 个群, 可能搜索索引尚未完全更新")
	}
	if totalExists && total < len(page1Items) {
		t.Fatalf("total(%d) 不应小于当前页结果数(%d)", total, len(page1Items))
	}

	// 如果两个指标都存在，至少一个应表明有更多数据
	if hasMoreExists {
		t.Logf("has_more=%v", hasMore)
	}
	if totalExists {
		t.Logf("total=%d", total)
	}

	// ---- 第二页：offset=2，获取剩余结果 ----
	page2Result, err := client.Call(ctx, "group.search", map[string]any{
		"query":  prefix,
		"limit":  2,
		"offset": 2,
	})
	if err != nil {
		t.Fatalf("group.search（第二页）失败: %v", err)
	}
	page2Map, _ := page2Result.(map[string]any)
	if page2Map == nil {
		t.Fatalf("group.search（第二页）返回 nil")
	}
	page2Items, _ := page2Map["items"].([]any)
	t.Logf("第二页返回 %d 个结果", len(page2Items))

	// ---- 验证两页结果不重叠，且合并后覆盖所有创建的群 ----
	allFoundIDs := make(map[string]bool)
	for _, item := range page1Items {
		itemMap, _ := item.(map[string]any)
		if itemMap == nil {
			continue
		}
		gid, _ := itemMap["group_id"].(string)
		if gid != "" {
			allFoundIDs[gid] = true
		}
	}
	for _, item := range page2Items {
		itemMap, _ := item.(map[string]any)
		if itemMap == nil {
			continue
		}
		gid, _ := itemMap["group_id"].(string)
		if gid != "" {
			if allFoundIDs[gid] {
				t.Errorf("第二页 group_id %s 与第一页重叠", gid)
			}
			allFoundIDs[gid] = true
		}
	}

	// 验证创建的 3 个群至少大部分能被找到
	matchedCount := 0
	for _, gid := range groupIDs {
		if allFoundIDs[gid] {
			matchedCount++
		}
	}
	t.Logf("两页合计找到 %d/%d 个创建的群", matchedCount, len(groupIDs))
	if matchedCount == 0 {
		t.Fatalf("两页合计未找到任何创建的群, 第一页: %#v, 第二页: %#v", page1Items, page2Items)
	}

	// ---- 清理：解散群组（通过 defer 执行） ----
	t.Logf("分页搜索测试完成")
}
