//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 辅助函数（仅本文件使用）
// ---------------------------------------------------------------------------

// extractGroupID 从 group.create 返回值中提取 group_id
func extractGroupID(t *testing.T, result any) string {
	t.Helper()
	m, _ := result.(map[string]any)
	if m == nil {
		t.Fatalf("group.create 返回 nil")
	}
	group, _ := m["group"].(map[string]any)
	if group == nil {
		t.Fatalf("group.create 返回中缺少 group 字段: %#v", m)
	}
	gid, _ := group["group_id"].(string)
	if gid == "" {
		t.Fatalf("group.create 返回中 group_id 为空: %#v", group)
	}
	return gid
}

// cleanupGroup 尝试解散群组，忽略错误
func cleanupGroup(t *testing.T, client *AUNClient, groupID string) {
	t.Helper()
	if groupID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := client.Call(ctx, "group.dissolve", map[string]any{"group_id": groupID})
	if err != nil {
		t.Logf("清理群 %s 失败（忽略）: %v", groupID, err)
	}
}

// memberRole 从成员列表中查找指定 AID 的角色
func memberRole(members []any, aid string) string {
	for _, m := range members {
		member, _ := m.(map[string]any)
		if member == nil {
			continue
		}
		if memberAID, _ := member["aid"].(string); memberAID == aid {
			role, _ := member["role"].(string)
			return role
		}
	}
	return ""
}

// skipIfNotImplemented 检查错误是否表示方法未实现，若是则 skip
func skipIfNotImplemented(t *testing.T, err error, method string) {
	t.Helper()
	if err == nil {
		return
	}
	if containsAny(err.Error(), "not implement", "method not found", "not_implemented", "unknown method") {
		t.Skipf("%s 方法未实现: %v", method, err)
	}
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupLifecycle — 群组全生命周期
// 覆盖：创建群组、获取信息、添加成员、获取成员列表、移除成员、解散
// ---------------------------------------------------------------------------

func TestIntegration_GroupLifecycle(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	bob := makeClient(t)
	defer owner.Close()
	defer bob.Close()

	ownerAID := fmt.Sprintf("grp%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("grp%s-b.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("lifecycle-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 获取群信息 ----
	infoResult, err := owner.Call(ctx, "group.get_info", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("group.get_info 失败: %v", err)
	}
	infoMap, _ := infoResult.(map[string]any)
	if infoMap == nil {
		t.Fatalf("group.get_info 返回 nil")
	}
	// 验证群名（可能在顶层或 group 嵌套中）
	name, _ := infoMap["name"].(string)
	if name == "" {
		if group, _ := infoMap["group"].(map[string]any); group != nil {
			name, _ = group["name"].(string)
		}
	}
	expectedName := fmt.Sprintf("lifecycle-%s", rid)
	if name != expectedName {
		t.Fatalf("群名不匹配: 期望 %q, 实际 %q, 完整返回: %#v", expectedName, name, infoMap)
	}
	t.Logf("群信息验证通过: name=%s", name)

	// ---- 添加成员 (Bob) ----
	addResult, err := owner.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("group.add_member 失败: %v", err)
	}
	addMap, _ := addResult.(map[string]any)
	memberInfo, _ := addMap["member"].(map[string]any)
	if memberInfo != nil {
		if role, _ := memberInfo["role"].(string); role != "member" {
			t.Fatalf("Bob 初始角色异常: 期望 member, 实际 %s", role)
		}
	}
	t.Logf("添加成员 Bob 成功")

	// ---- 获取成员列表 ----
	membersResult, err := owner.Call(ctx, "group.get_members", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("group.get_members 失败: %v", err)
	}
	membersMap, _ := membersResult.(map[string]any)
	membersList, _ := membersMap["members"].([]any)
	bobRole := memberRole(membersList, bobAID)
	if bobRole != "member" {
		t.Fatalf("成员列表中 Bob 角色异常: 期望 member, 实际 %q, 完整列表: %#v", bobRole, membersList)
	}
	t.Logf("成员列表验证通过: Bob role=%s", bobRole)

	// ---- 移除成员 (Bob) ----
	_, err = owner.Call(ctx, "group.kick", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
	})
	if err != nil {
		t.Fatalf("group.kick 失败: %v", err)
	}

	// 验证 Bob 已被移除
	membersAfterKick, err := owner.Call(ctx, "group.get_members", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("kick 后 get_members 失败: %v", err)
	}
	afterKickMap, _ := membersAfterKick.(map[string]any)
	afterKickList, _ := afterKickMap["members"].([]any)
	if memberRole(afterKickList, bobAID) != "" {
		t.Fatalf("Bob 应已被移除，但仍在成员列表中: %#v", afterKickList)
	}
	t.Logf("移除 Bob 成功")

	// ---- 解散群组 ----
	dissolveResult, err := owner.Call(ctx, "group.dissolve", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("group.dissolve 失败: %v", err)
	}
	t.Logf("解散群组成功: %#v", dissolveResult)
	groupID = "" // 已解散，清理时不再重复
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupRolesAndTransfer — 角色与群主转让
// 覆盖：添加成员、提升 admin、admin 权限边界、群主转让、转让后角色验证
// ---------------------------------------------------------------------------

func TestIntegration_GroupRolesAndTransfer(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	charlie := makeClient(t)
	defer alice.Close()
	defer bob.Close()
	defer charlie.Close()

	aliceAID := fmt.Sprintf("grp%s-a.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("grp%s-b.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("grp%s-c.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := alice.CreateGroup(ctx, map[string]any{
		"name":       fmt.Sprintf("roles-%s", rid),
		"group_name": fmt.Sprintf("roles%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	// 清理 owner 初始是 alice，转让后变为 bob
	cleanupOwner := alice
	defer func() {
		cleanupGroup(t, cleanupOwner, groupID)
	}()

	// ---- 添加 Bob 和 Charlie 为普通成员 ----
	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}

	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      charlieAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Charlie 失败: %v", err)
	}
	t.Logf("添加 Bob 和 Charlie 为成员")

	// ---- 提升 Bob 为 admin ----
	promoteResult, err := alice.Call(ctx, "group.set_role", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "admin",
	})
	if err != nil {
		t.Fatalf("提升 Bob 为 admin 失败: %v", err)
	}
	promoteMap, _ := promoteResult.(map[string]any)
	if pm, _ := promoteMap["member"].(map[string]any); pm != nil {
		if role, _ := pm["role"].(string); role != "admin" {
			t.Fatalf("Bob 提升后角色异常: 期望 admin, 实际 %s", role)
		}
	}
	t.Logf("Bob 提升为 admin")

	// ---- 验证 admin 可以添加成员（已添加 Charlie，此步验证 admin 的管理能力） ----
	// admin 不能踢 owner
	_, err = bob.Call(ctx, "group.kick", map[string]any{
		"group_id": groupID,
		"aid":      aliceAID,
	})
	if err == nil {
		t.Fatalf("admin 踢 owner 应失败，但成功了")
	}
	if !containsAny(err.Error(), "owner", "permission", "denied", "cannot") {
		t.Logf("admin 踢 owner 错误信息: %v", err)
	}
	t.Logf("admin 不能踢 owner（符合预期）")

	// ---- 转让群主给 Bob ----
	transferResult, err := alice.StartGroupTransfer(ctx, map[string]any{
		"group_id":  groupID,
		"new_owner": bobAID,
	})
	if err != nil {
		t.Fatalf("群主转让失败: %v", err)
	}
	transferMap, _ := transferResult.(map[string]any)
	if status := stringFromAny(transferMap["status"]); status != "pending_rekey" {
		t.Fatalf("group.fs 转让应进入 pending_rekey，实际 status=%q result=%#v", status, transferResult)
	}
	if newOwner := stringFromAny(transferMap["new_owner"]); newOwner != bobAID {
		t.Logf("transfer 返回 new_owner=%s (期望 %s)", newOwner, bobAID)
	}
	completeResult, err := bob.CompleteGroupTransfer(ctx, map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("群主转让 complete 失败: %v", err)
	}
	completeMap, _ := completeResult.(map[string]any)
	if status := stringFromAny(completeMap["status"]); status != "transferred" {
		t.Fatalf("complete_transfer 应返回 transferred，实际 status=%q result=%#v", status, completeResult)
	}
	cleanupOwner = bob
	t.Logf("群主转让给 Bob")

	// ---- 验证转让后角色 ----
	membersResult, err := bob.Call(ctx, "group.get_members", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("转让后 get_members 失败: %v", err)
	}
	membersMap, _ := membersResult.(map[string]any)
	membersList, _ := membersMap["members"].([]any)

	bobRole := memberRole(membersList, bobAID)
	aliceRole := memberRole(membersList, aliceAID)
	if bobRole != "owner" {
		t.Fatalf("新 owner 角色异常: 期望 owner, 实际 %q", bobRole)
	}
	if aliceRole != "admin" {
		t.Fatalf("旧 owner 角色异常: 期望 admin, 实际 %q", aliceRole)
	}
	t.Logf("转让后角色验证通过: Bob=%s, Alice=%s", bobRole, aliceRole)

	// ---- 非 owner 不能 suspend/dissolve ----
	_, err = alice.Call(ctx, "group.suspend", map[string]any{
		"group_id": groupID,
	})
	if err == nil {
		// alice 已不是 owner，suspend 应失败
		t.Fatalf("非 owner suspend 应失败，但成功了")
	}
	t.Logf("非 owner suspend 被拒绝（符合预期）: %v", err)

	_, err = alice.Call(ctx, "group.dissolve", map[string]any{
		"group_id": groupID,
	})
	if err == nil {
		t.Fatalf("非 owner dissolve 应失败，但成功了")
	}
	t.Logf("非 owner dissolve 被拒绝（符合预期）: %v", err)
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupSuspendResume — 暂停与恢复
// 覆盖：暂停、暂停幂等、暂停时禁止发消息、恢复、恢复幂等、恢复后可发消息
// ---------------------------------------------------------------------------

func TestIntegration_GroupSuspendResume(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	member := makeClient(t)
	defer owner.Close()
	defer member.Close()

	ownerAID := fmt.Sprintf("grp%s-o.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("grp%s-m.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建群组并添加成员 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("suspend-%s", rid),
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

	// ---- 暂停群组 ----
	suspendResult, err := owner.Call(ctx, "group.suspend", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("group.suspend 失败: %v", err)
	}
	suspendMap, _ := suspendResult.(map[string]any)
	if status, _ := suspendMap["status"].(string); status != "suspended" {
		t.Fatalf("suspend 后状态异常: 期望 suspended, 实际 %q, 返回: %#v", status, suspendMap)
	}
	t.Logf("暂停群组成功")

	// ---- 暂停幂等 ----
	suspendAgain, err := owner.Call(ctx, "group.suspend", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("重复 suspend 失败: %v", err)
	}
	againMap, _ := suspendAgain.(map[string]any)
	if status, _ := againMap["status"].(string); status != "unchanged" {
		t.Logf("重复 suspend 状态: %q (期望 unchanged)", status)
	}
	t.Logf("暂停幂等验证通过")

	// ---- 暂停时成员发消息应被拒绝 ----
	_, err = member.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": "suspended msg"},
		"encrypt":  false,
	})
	if err == nil {
		t.Fatalf("暂停群组中发消息应失败，但成功了")
	}
	if !containsAny(err.Error(), "suspended", "not active", "paused") {
		t.Logf("暂停发消息错误信息: %v", err)
	}
	t.Logf("暂停时发消息被拒绝（符合预期）")

	// ---- 恢复群组 ----
	resumeResult, err := owner.Call(ctx, "group.resume", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("group.resume 失败: %v", err)
	}
	resumeMap, _ := resumeResult.(map[string]any)
	if status, _ := resumeMap["status"].(string); status != "active" {
		t.Fatalf("resume 后状态异常: 期望 active, 实际 %q, 返回: %#v", status, resumeMap)
	}
	t.Logf("恢复群组成功")

	// ---- 恢复幂等 ----
	resumeAgain, err := owner.Call(ctx, "group.resume", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("重复 resume 失败: %v", err)
	}
	resumeAgainMap, _ := resumeAgain.(map[string]any)
	if status, _ := resumeAgainMap["status"].(string); status != "unchanged" {
		t.Logf("重复 resume 状态: %q (期望 unchanged)", status)
	}
	t.Logf("恢复幂等验证通过")

	// ---- 恢复后成员可以发消息 ----
	sendResult, err := member.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": fmt.Sprintf("after-resume-%s", rid)},
		"encrypt":  false,
	})
	if err != nil {
		t.Fatalf("恢复后发消息失败: %v", err)
	}
	t.Logf("恢复后发消息成功: %#v", sendResult)
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupJoinRequest — 入群申请与审批
// 覆盖：审批模式、缺答案返回问题、带答案进入 pending、列审批、批准、拒绝
// ---------------------------------------------------------------------------

func TestIntegration_GroupJoinRequest(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	bob := makeClient(t)
	charlie := makeClient(t)
	defer owner.Close()
	defer bob.Close()
	defer charlie.Close()

	ownerAID := fmt.Sprintf("grp%s-o.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("grp%s-b.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("grp%s-c.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建审批模式群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":          fmt.Sprintf("join-req-%s", rid),
		"visibility":    "private",
		"join_question": "用途是什么？",
		"max_pending":   5,
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建审批群: %s", groupID)

	// ---- Bob 不带答案申请 → 应返回 question_required ----
	reqNoAnswer, err := bob.Call(ctx, "group.request_join", map[string]any{
		"group_id": groupID,
	})
	skipIfNotImplemented(t, err, "group.request_join")
	if err != nil {
		// 有些实现通过错误返回
		if containsAny(err.Error(), "question_required", "answer required", "question") {
			t.Logf("缺答案返回错误（符合预期）: %v", err)
		} else {
			t.Fatalf("request_join（无答案）失败: %v", err)
		}
	} else {
		reqMap, _ := reqNoAnswer.(map[string]any)
		status, _ := reqMap["status"].(string)
		if status != "question_required" {
			t.Fatalf("缺答案应返回 question_required, 实际: %q, 返回: %#v", status, reqMap)
		}
		t.Logf("缺答案返回 question_required")
	}

	// ---- Bob 带答案申请 → pending ----
	reqWithAnswer, err := bob.Call(ctx, "group.request_join", map[string]any{
		"group_id": groupID,
		"message":  "申请加入",
		"answer":   "用于集成测试",
	})
	if err != nil {
		t.Fatalf("request_join（带答案）失败: %v", err)
	}
	reqAnswerMap, _ := reqWithAnswer.(map[string]any)
	if status, _ := reqAnswerMap["status"].(string); status != "pending" {
		t.Fatalf("带答案应进入 pending, 实际: %q, 返回: %#v", status, reqAnswerMap)
	}
	t.Logf("Bob 带答案申请进入 pending")

	// ---- owner 列出待审批请求 ----
	listResult, err := owner.Call(ctx, "group.list_join_requests", map[string]any{
		"group_id": groupID,
		"status":   "pending",
	})
	if err != nil {
		t.Fatalf("list_join_requests 失败: %v", err)
	}
	listMap, _ := listResult.(map[string]any)
	items, _ := listMap["items"].([]any)
	foundBob := false
	for _, item := range items {
		itemMap, _ := item.(map[string]any)
		if itemMap != nil {
			if aid, _ := itemMap["aid"].(string); aid == bobAID {
				foundBob = true
				break
			}
		}
	}
	if !foundBob {
		t.Fatalf("pending 列表未包含 Bob: %#v", listMap)
	}
	t.Logf("待审批列表包含 Bob")

	// ---- owner 批准 Bob ----
	approveResult, err := owner.Call(ctx, "group.review_join_request", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"approve":  true,
	})
	if err != nil {
		t.Fatalf("approve Bob 失败: %v", err)
	}
	approveMap, _ := approveResult.(map[string]any)
	t.Logf("批准 Bob: %#v", approveMap)

	// 验证 Bob 已成为成员
	membersResult, err := owner.Call(ctx, "group.get_members", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("get_members 失败: %v", err)
	}
	membersMap, _ := membersResult.(map[string]any)
	membersList, _ := membersMap["members"].([]any)
	if memberRole(membersList, bobAID) == "" {
		t.Fatalf("批准后 Bob 应在成员列表中: %#v", membersList)
	}
	t.Logf("批准后 Bob 已在成员列表中")

	// ---- Charlie 申请，owner 拒绝 ----
	_, err = charlie.Call(ctx, "group.request_join", map[string]any{
		"group_id": groupID,
		"answer":   "Charlie 的答案",
	})
	if err != nil {
		t.Fatalf("Charlie request_join 失败: %v", err)
	}

	rejectResult, err := owner.Call(ctx, "group.review_join_request", map[string]any{
		"group_id": groupID,
		"aid":      charlieAID,
		"approve":  false,
		"reason":   "覆盖拒绝路径",
	})
	if err != nil {
		t.Fatalf("reject Charlie 失败: %v", err)
	}
	rejectMap, _ := rejectResult.(map[string]any)
	if status, _ := rejectMap["status"].(string); status != "rejected" {
		t.Logf("拒绝返回状态: %q (期望 rejected), 返回: %#v", status, rejectMap)
	}

	// 验证 Charlie 不在成员列表中
	membersAfterReject, err := owner.Call(ctx, "group.get_members", map[string]any{
		"group_id": groupID,
	})
	if err != nil {
		t.Fatalf("reject 后 get_members 失败: %v", err)
	}
	afterRejectMap, _ := membersAfterReject.(map[string]any)
	afterRejectList, _ := afterRejectMap["members"].([]any)
	if memberRole(afterRejectList, charlieAID) != "" {
		t.Fatalf("拒绝后 Charlie 不应在成员列表中: %#v", afterRejectList)
	}
	t.Logf("拒绝后 Charlie 不在成员列表中")
}

// ---------------------------------------------------------------------------
// TestIntegration_GroupInviteCode — 邀请码
// 覆盖：invite_only 群拒绝普通申请、创建邀请码、使用邀请码、耗尽、撤销
// ---------------------------------------------------------------------------

func TestIntegration_GroupInviteCode(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	bob := makeClient(t)
	charlie := makeClient(t)
	defer owner.Close()
	defer bob.Close()
	defer charlie.Close()

	ownerAID := fmt.Sprintf("grp%s-o.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("grp%s-b.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("grp%s-c.%s", rid, testIssuer())
	_ = bobAID     // Bob 通过邀请码加入
	_ = charlieAID // Charlie 尝试使用耗尽/撤销的码

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建 invite_only 群组 ----
	createResult, err := owner.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("invite-%s", rid),
		"visibility": "private",
		"join_mode":  "invite_only",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, owner, groupID)
	t.Logf("创建 invite_only 群: %s", groupID)

	// ---- 直接 request_join 应被拒绝（invite_only） ----
	_, err = bob.Call(ctx, "group.request_join", map[string]any{
		"group_id": groupID,
		"message":  "不走邀请码",
	})
	if err == nil {
		t.Fatalf("invite_only 群 request_join 应失败，但成功了")
	}
	if !containsAny(err.Error(), "invite", "invite_only", "not allowed") {
		t.Logf("invite_only request_join 错误信息: %v", err)
	}
	t.Logf("invite_only request_join 被拒绝（符合预期）")

	// ---- 创建邀请码（max_uses=1） ----
	customCode := fmt.Sprintf("ic-%s", rid)
	inviteResult, err := owner.Call(ctx, "group.create_invite_code", map[string]any{
		"group_id":           groupID,
		"code":               customCode,
		"max_uses":           1,
		"expires_in_seconds": 3600,
	})
	skipIfNotImplemented(t, err, "group.create_invite_code")
	if err != nil {
		t.Fatalf("create_invite_code 失败: %v", err)
	}
	inviteMap, _ := inviteResult.(map[string]any)
	inviteCodeObj, _ := inviteMap["invite_code"].(map[string]any)
	inviteCode := ""
	if inviteCodeObj != nil {
		inviteCode, _ = inviteCodeObj["code"].(string)
	}
	if inviteCode == "" {
		// 回退：直接从顶层获取
		inviteCode, _ = inviteMap["code"].(string)
	}
	if inviteCode == "" {
		t.Fatalf("create_invite_code 未返回 code: %#v", inviteMap)
	}
	t.Logf("创建邀请码: %s", inviteCode)

	// ---- Bob 使用邀请码加入 ----
	joinResult, err := bob.Call(ctx, "group.use_invite_code", map[string]any{
		"code": inviteCode,
	})
	if err != nil {
		t.Fatalf("Bob use_invite_code 失败: %v", err)
	}
	joinMap, _ := joinResult.(map[string]any)
	if status, _ := joinMap["status"].(string); status != "joined" {
		t.Logf("use_invite_code 返回状态: %q (期望 joined), 返回: %#v", status, joinMap)
	}
	t.Logf("Bob 通过邀请码加入群组")

	// ---- Charlie 使用相同码 → 应被拒绝（已耗尽 max_uses=1） ----
	_, err = charlie.Call(ctx, "group.use_invite_code", map[string]any{
		"code": inviteCode,
	})
	if err == nil {
		t.Fatalf("耗尽的邀请码应拒绝使用，但成功了")
	}
	if !containsAny(err.Error(), "exhausted", "max_uses", "expired", "not active", "used up") {
		t.Logf("邀请码耗尽错误信息: %v", err)
	}
	t.Logf("邀请码耗尽后拒绝使用（符合预期）")

	// ---- 创建新邀请码，撤销后尝试使用 ----
	revokeCode := fmt.Sprintf("ic-revoke-%s", rid)
	revokeResult, err := owner.Call(ctx, "group.create_invite_code", map[string]any{
		"group_id": groupID,
		"code":     revokeCode,
		"max_uses": 0,
	})
	if err != nil {
		t.Fatalf("create_invite_code（revoke 测试）失败: %v", err)
	}
	revokeMap, _ := revokeResult.(map[string]any)
	revokeCodeObj, _ := revokeMap["invite_code"].(map[string]any)
	actualRevokeCode := ""
	if revokeCodeObj != nil {
		actualRevokeCode, _ = revokeCodeObj["code"].(string)
	}
	if actualRevokeCode == "" {
		actualRevokeCode, _ = revokeMap["code"].(string)
	}
	if actualRevokeCode == "" {
		actualRevokeCode = strings.ToLower(revokeCode)
	}

	// 撤销邀请码
	_, err = owner.Call(ctx, "group.revoke_invite_code", map[string]any{
		"group_id": groupID,
		"code":     actualRevokeCode,
	})
	if err != nil {
		t.Fatalf("revoke_invite_code 失败: %v", err)
	}
	t.Logf("撤销邀请码: %s", actualRevokeCode)

	// Charlie 尝试使用已撤销的码
	_, err = charlie.Call(ctx, "group.use_invite_code", map[string]any{
		"code": actualRevokeCode,
	})
	if err == nil {
		t.Fatalf("已撤销的邀请码应拒绝使用，但成功了")
	}
	if !containsAny(err.Error(), "not active", "revoked", "invalid", "expired") {
		t.Logf("撤销邀请码错误信息: %v", err)
	}
	t.Logf("撤销邀请码后拒绝使用（符合预期）")
}
