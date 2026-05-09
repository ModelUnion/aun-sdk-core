//go:build integration

package aun

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestIntegration_GroupResourcesDirectAdd
// 覆盖：direct_add + list + get_access + update + delete、权限拒绝、路径穿越拒绝
// ---------------------------------------------------------------------------

func TestIntegration_GroupResourcesDirectAdd(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	charlie := makeClient(t)
	defer alice.Close()
	defer bob.Close()
	defer charlie.Close()

	aliceAID := fmt.Sprintf("grpres%s-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("grpres%s-b.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("grpres%s-c.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建群组，添加 Bob 为成员（Charlie 不加入） ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("res-direct-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)
	t.Logf("创建群组: %s", groupID)

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}

	// ---- Alice 先上传一个私有对象到 storage ----
	bucket := fmt.Sprintf("grp-res-%s", rid)
	objectKey := fmt.Sprintf("owner/%s/guide.txt", rid)
	bodyText := fmt.Sprintf("owner-resource-%s", rid)
	contentB64 := base64.StdEncoding.EncodeToString([]byte(bodyText))

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   objectKey,
		"content":      contentB64,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Skipf("storage 服务不可用，跳过群资源测试: %v", err)
	}

	storageRef := map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": objectKey,
		"filename":   "guide.txt",
	}
	resourcePath := fmt.Sprintf("files/%s/guide.txt", rid)

	// ---- 非 owner (Bob) direct_add → 应被拒绝 ----
	_, err = bob.Call(ctx, "group.resources.direct_add", map[string]any{
		"group_id":      groupID,
		"resource_path": fmt.Sprintf("files/%s/not-owner.txt", rid),
		"resource_type": "file",
		"title":         "not owner",
		"storage_ref":   storageRef,
	})
	skipIfNotImplemented(t, err, "group.resources.direct_add")
	if err == nil {
		t.Fatalf("非 owner direct_add 应失败，但成功了")
	}
	t.Logf("非 owner direct_add 被拒绝（符合预期）: %v", err)

	// ---- 路径穿越 → 应被拒绝 ----
	_, err = alice.Call(ctx, "group.resources.direct_add", map[string]any{
		"group_id":      groupID,
		"resource_path": "../escape.txt",
		"resource_type": "file",
		"title":         "bad path",
		"storage_ref":   storageRef,
	})
	if err == nil {
		t.Fatalf("路径穿越 direct_add 应失败，但成功了")
	}
	t.Logf("路径穿越被拒绝（符合预期）: %v", err)

	// ---- Alice (owner) direct_add 正常添加资源 ----
	directResult, err := alice.Call(ctx, "group.resources.direct_add", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
		"resource_type": "file",
		"title":         "Guide",
		"storage_ref":   storageRef,
		"visibility":    "members_only",
		"tags":          []string{"docs"},
		"metadata":      map[string]any{"kind": "guide"},
	})
	if err != nil {
		t.Fatalf("direct_add 失败: %v", err)
	}
	directMap, _ := directResult.(map[string]any)
	resourceObj, _ := directMap["resource"].(map[string]any)
	if resourceObj == nil {
		t.Fatalf("direct_add 返回中缺少 resource: %#v", directMap)
	}
	gotPath, _ := resourceObj["resource_path"].(string)
	if gotPath != resourcePath {
		t.Fatalf("direct_add 返回 resource_path 不匹配: 期望 %q, 实际 %q", resourcePath, gotPath)
	}
	t.Logf("direct_add 成功: path=%s", gotPath)

	// ---- 非成员 (Charlie) list → 应被拒绝 ----
	_, err = charlie.Call(ctx, "group.resources.list", map[string]any{
		"group_id": groupID,
	})
	if err == nil {
		t.Fatalf("非成员 list 应失败，但成功了")
	}
	t.Logf("非成员 list 被拒绝（符合预期）: %v", err)

	// ---- Bob (成员) list 带过滤条件 → 应找到资源 ----
	listResult, err := bob.Call(ctx, "group.resources.list", map[string]any{
		"group_id": groupID,
		"prefix":   fmt.Sprintf("files/%s/", rid),
		"tags":     []string{"docs"},
	})
	if err != nil {
		t.Fatalf("Bob list 失败: %v", err)
	}
	listMap, _ := listResult.(map[string]any)
	items, _ := listMap["items"].([]any)
	foundResource := false
	for _, item := range items {
		itemMap, _ := item.(map[string]any)
		if itemMap != nil {
			if rp, _ := itemMap["resource_path"].(string); rp == resourcePath {
				foundResource = true
				break
			}
		}
	}
	if !foundResource {
		t.Fatalf("list 未找到资源 %s: %#v", resourcePath, listMap)
	}
	t.Logf("Bob list 找到资源（符合预期）")

	// ---- Bob get_access → 返回 download_url ----
	accessResult, err := bob.Call(ctx, "group.resources.get_access", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
	})
	if err != nil {
		t.Fatalf("get_access 失败: %v", err)
	}
	accessMap, _ := accessResult.(map[string]any)
	downloadObj, _ := accessMap["download"].(map[string]any)
	downloadURL := ""
	if downloadObj != nil {
		downloadURL, _ = downloadObj["download_url"].(string)
	}
	if downloadURL == "" {
		t.Fatalf("get_access 未返回 download_url: %#v", accessMap)
	}
	t.Logf("get_access 返回 download_url: %s", downloadURL)

	// ---- Alice update 资源标题 ----
	updateResult, err := alice.Call(ctx, "group.resources.update", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
		"title":         "Guide v2",
	})
	if err != nil {
		t.Fatalf("update 失败: %v", err)
	}
	updateMap, _ := updateResult.(map[string]any)
	updatedResource, _ := updateMap["resource"].(map[string]any)
	if updatedResource != nil {
		if title, _ := updatedResource["title"].(string); title != "Guide v2" {
			t.Fatalf("update 后 title 不匹配: 期望 Guide v2, 实际 %q", title)
		}
	}
	t.Logf("update 成功")

	// ---- Alice delete 资源 ----
	delResult, err := alice.Call(ctx, "group.resources.delete", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
	})
	if err != nil {
		t.Fatalf("delete 失败: %v", err)
	}
	delMap, _ := delResult.(map[string]any)
	if deleted, ok := delMap["deleted"].(bool); !ok || !deleted {
		t.Fatalf("delete 返回 deleted 应为 true: %#v", delMap)
	}
	t.Logf("delete 成功")

	// ---- 删除后 get_access → 应失败 ----
	_, err = bob.Call(ctx, "group.resources.get_access", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
	})
	if err == nil {
		t.Fatalf("删除后 get_access 应失败，但成功了")
	}
	t.Logf("删除后 get_access 被拒绝（符合预期）: %v", err)
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupResourcesRequestApproveReject — 审批流
// 覆盖：request_add、list_pending、approve_request、reject_request
// ---------------------------------------------------------------------------

func TestIntegration_GroupResourcesRequestApproveReject(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("grpreq%s-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("grpreq%s-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建群组，添加 Bob ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("res-request-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}

	// ---- Bob 上传对象到 storage ----
	bucket := fmt.Sprintf("grp-req-%s", rid)
	bobObjectKey := fmt.Sprintf("bob/%s/proposal.txt", rid)
	bobBody := fmt.Sprintf("bob-proposal-%s", rid)
	bobContentB64 := base64.StdEncoding.EncodeToString([]byte(bobBody))

	_, err = bob.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    bobAID,
		"bucket":       bucket,
		"object_key":   bobObjectKey,
		"content":      bobContentB64,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Skipf("storage 服务不可用: %v", err)
	}

	bobStorageRef := map[string]any{
		"owner_aid":  bobAID,
		"bucket":     bucket,
		"object_key": bobObjectKey,
		"filename":   "proposal.txt",
	}
	proposalPath := fmt.Sprintf("requests/%s/proposal.txt", rid)

	// ---- Bob (成员) request_add ----
	reqResult, err := bob.Call(ctx, "group.resources.request_add", map[string]any{
		"group_id":      groupID,
		"resource_path": proposalPath,
		"resource_type": "file",
		"title":         "Proposal",
		"storage_ref":   bobStorageRef,
		"visibility":    "members_only",
		"tags":          []string{"proposal"},
	})
	skipIfNotImplemented(t, err, "group.resources.request_add")
	if err != nil {
		t.Fatalf("request_add 失败: %v", err)
	}
	reqMap, _ := reqResult.(map[string]any)
	reqObj, _ := reqMap["request"].(map[string]any)
	if reqObj == nil {
		t.Fatalf("request_add 返回中缺少 request: %#v", reqMap)
	}
	requestID, _ := reqObj["request_id"].(string)
	if requestID == "" {
		t.Fatalf("request_add 返回中 request_id 为空: %#v", reqObj)
	}
	reqStatus, _ := reqObj["status"].(string)
	if reqStatus != "pending" {
		t.Fatalf("request_add 状态应为 pending, 实际: %q", reqStatus)
	}
	t.Logf("request_add 成功: request_id=%s", requestID)

	// ---- Alice (owner) list_pending ----
	pendingResult, err := alice.Call(ctx, "group.resources.list_pending", map[string]any{
		"group_id": groupID,
		"status":   "pending",
	})
	if err != nil {
		t.Fatalf("list_pending 失败: %v", err)
	}
	pendingMap, _ := pendingResult.(map[string]any)
	pendingItems, _ := pendingMap["items"].([]any)
	foundRequest := false
	for _, item := range pendingItems {
		itemMap, _ := item.(map[string]any)
		if itemMap != nil {
			if rid, _ := itemMap["request_id"].(string); rid == requestID {
				foundRequest = true
				break
			}
		}
	}
	if !foundRequest {
		t.Fatalf("list_pending 未找到请求 %s: %#v", requestID, pendingMap)
	}
	t.Logf("list_pending 找到请求（符合预期）")

	// ---- Alice 批准请求 ----
	approveResult, err := alice.Call(ctx, "group.resources.approve_request", map[string]any{
		"request_id": requestID,
	})
	if err != nil {
		t.Fatalf("approve_request 失败: %v", err)
	}
	approveMap, _ := approveResult.(map[string]any)
	approvedReq, _ := approveMap["request"].(map[string]any)
	if approvedReq != nil {
		if status, _ := approvedReq["status"].(string); status != "approved" {
			t.Fatalf("approve 后状态异常: 期望 approved, 实际 %q", status)
		}
	}
	t.Logf("approve_request 成功")

	// ---- 验证批准后的资源可访问 ----
	accessResult, err := alice.Call(ctx, "group.resources.get_access", map[string]any{
		"group_id":      groupID,
		"resource_path": proposalPath,
	})
	if err != nil {
		t.Fatalf("批准后 get_access 失败: %v", err)
	}
	accessMap, _ := accessResult.(map[string]any)
	downloadObj, _ := accessMap["download"].(map[string]any)
	if downloadObj == nil {
		t.Fatalf("批准后 get_access 未返回 download: %#v", accessMap)
	}
	downloadURL, _ := downloadObj["download_url"].(string)
	if downloadURL == "" {
		t.Fatalf("批准后 get_access 未返回 download_url: %#v", downloadObj)
	}
	t.Logf("批准后资源可访问: %s", downloadURL)

	// ---- Bob 再提交一个请求，Alice 拒绝 ----
	rejectObjectKey := fmt.Sprintf("bob/%s/reject.txt", rid)
	rejectContentB64 := base64.StdEncoding.EncodeToString([]byte("reject-me"))

	_, err = bob.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    bobAID,
		"bucket":       bucket,
		"object_key":   rejectObjectKey,
		"content":      rejectContentB64,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Fatalf("上传 reject 对象失败: %v", err)
	}

	rejectPath := fmt.Sprintf("requests/%s/reject.txt", rid)
	rejectReqResult, err := bob.Call(ctx, "group.resources.request_add", map[string]any{
		"group_id":      groupID,
		"resource_path": rejectPath,
		"resource_type": "file",
		"title":         "Reject",
		"storage_ref": map[string]any{
			"owner_aid":  bobAID,
			"bucket":     bucket,
			"object_key": rejectObjectKey,
			"filename":   "reject.txt",
		},
	})
	if err != nil {
		t.Fatalf("第二次 request_add 失败: %v", err)
	}
	rejectReqMap, _ := rejectReqResult.(map[string]any)
	rejectReqObj, _ := rejectReqMap["request"].(map[string]any)
	rejectRequestID, _ := rejectReqObj["request_id"].(string)
	if rejectRequestID == "" {
		t.Fatalf("第二次 request_add 未返回 request_id: %#v", rejectReqMap)
	}

	// ---- Alice 拒绝 ----
	rejectResult, err := alice.Call(ctx, "group.resources.reject_request", map[string]any{
		"request_id": rejectRequestID,
		"note":       "不符合要求",
	})
	if err != nil {
		t.Fatalf("reject_request 失败: %v", err)
	}
	rejectMap, _ := rejectResult.(map[string]any)
	rejectedReq, _ := rejectMap["request"].(map[string]any)
	if rejectedReq != nil {
		if status, _ := rejectedReq["status"].(string); status != "rejected" {
			t.Fatalf("reject 后状态异常: 期望 rejected, 实际 %q", status)
		}
	}
	t.Logf("reject_request 成功")

	// ---- 被拒绝的资源不可访问 ----
	_, err = bob.Call(ctx, "group.resources.get_access", map[string]any{
		"group_id":      groupID,
		"resource_path": rejectPath,
	})
	if err == nil {
		t.Fatalf("被拒绝资源 get_access 应失败，但成功了")
	}
	t.Logf("被拒绝资源不可访问（符合预期）: %v", err)
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupResourcesAccessTicket — access_ticket 一次性使用
// 覆盖：get_access 获取 ticket、resolve_access_ticket 一次成功、二次失败
// ---------------------------------------------------------------------------

func TestIntegration_GroupResourcesAccessTicket(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("grptkt%s-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("grptkt%s-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- 创建群组，添加 Bob ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("res-ticket-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}

	// ---- Alice 上传资源到 storage ----
	bucket := fmt.Sprintf("grp-tkt-%s", rid)
	objectKey := fmt.Sprintf("owner/%s/ticket-test.txt", rid)
	bodyText := fmt.Sprintf("ticket-resource-%s", rid)
	contentB64 := base64.StdEncoding.EncodeToString([]byte(bodyText))

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   objectKey,
		"content":      contentB64,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Skipf("storage 服务不可用: %v", err)
	}

	// ---- Alice direct_add 资源 ----
	resourcePath := fmt.Sprintf("files/%s/ticket-test.txt", rid)
	_, err = alice.Call(ctx, "group.resources.direct_add", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
		"resource_type": "file",
		"title":         "Ticket Test",
		"storage_ref": map[string]any{
			"owner_aid":  aliceAID,
			"bucket":     bucket,
			"object_key": objectKey,
			"filename":   "ticket-test.txt",
		},
		"visibility": "members_only",
	})
	skipIfNotImplemented(t, err, "group.resources.direct_add")
	if err != nil {
		t.Fatalf("direct_add 失败: %v", err)
	}
	t.Logf("direct_add 成功: %s", resourcePath)

	// ---- Bob get_access → 获取 access_ticket ----
	accessResult, err := bob.Call(ctx, "group.resources.get_access", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
	})
	if err != nil {
		t.Fatalf("get_access 失败: %v", err)
	}
	accessMap, _ := accessResult.(map[string]any)

	// 提取 access_ticket（可能在 access_ticket.ticket 或 access_token 中）
	ticket := ""
	if ticketObj, _ := accessMap["access_ticket"].(map[string]any); ticketObj != nil {
		ticket, _ = ticketObj["ticket"].(string)
	}
	if ticket == "" {
		// 回退：尝试顶层 access_token
		ticket, _ = accessMap["access_token"].(string)
	}
	if ticket == "" {
		t.Fatalf("get_access 未返回 access_ticket: %#v", accessMap)
	}
	t.Logf("获取 access_ticket: %s", ticket[:min(len(ticket), 20)])

	// ---- 第一次 resolve_access_ticket → 应成功 ----
	resolveResult, err := bob.Call(ctx, "group.resources.resolve_access_ticket", map[string]any{
		"access_ticket": ticket,
	})
	if err != nil {
		t.Fatalf("第一次 resolve_access_ticket 失败: %v", err)
	}
	resolveMap, _ := resolveResult.(map[string]any)
	resolveDownload, _ := resolveMap["download"].(map[string]any)
	resolvedURL := ""
	if resolveDownload != nil {
		resolvedURL, _ = resolveDownload["download_url"].(string)
	}
	if resolvedURL == "" {
		t.Fatalf("resolve_access_ticket 未返回 download_url: %#v", resolveMap)
	}
	t.Logf("第一次 resolve 成功: %s", resolvedURL)

	// ---- 第二次 resolve_access_ticket（同一 ticket）→ 应失败（一次性使用） ----
	_, err = bob.Call(ctx, "group.resources.resolve_access_ticket", map[string]any{
		"access_ticket": ticket,
	})
	if err == nil {
		t.Fatalf("access_ticket 二次使用应失败，但成功了")
	}
	if !containsAny(err.Error(), "expired", "invalid", "used", "consumed", "not found", "already") {
		// 即使错误信息不完全匹配预期关键词，只要返回了错误就说明一次性机制生效
		t.Logf("access_ticket 二次使用错误信息（非标准文本，但已拒绝）: %v", err)
	} else {
		t.Logf("access_ticket 二次使用被拒绝（符合预期）: %v", err)
	}
}
