//go:build integration

package aun

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func extractGroupIdentity(t *testing.T, result any) (string, string) {
	t.Helper()
	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		t.Fatalf("group.create 返回 nil")
	}
	groupMap, _ := resultMap["group"].(map[string]any)
	if groupMap == nil {
		t.Fatalf("group.create 返回中缺少 group 字段: %#v", resultMap)
	}
	groupID, _ := groupMap["group_id"].(string)
	groupAID, _ := groupMap["group_aid"].(string)
	if groupAID == "" {
		groupAID, _ = resultMap["group_aid"].(string)
	}
	if groupID == "" || groupAID == "" {
		t.Fatalf("group.create 未返回 group_id/group_aid: %#v", resultMap)
	}
	return groupID, groupAID
}

func mustMap(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	result, _ := value.(map[string]any)
	if result == nil {
		t.Fatalf("%s 返回非对象: %#v", label, value)
	}
	return result
}

func TestIntegration_GroupStoragePendingPipeline(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	member := makeClient(t)
	defer owner.Close()
	defer member.Close()

	ownerAID := fmt.Sprintf("gsto%s-o.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("gsto%s-m.%s", rid, testIssuer())

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	createResult, err := owner.CreateGroup(ctx, map[string]any{
		"name":       fmt.Sprintf("group-storage-go-%s", rid),
		"group_name": fmt.Sprintf("gstogo%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("CreateGroup 命名群失败: %v", err)
	}
	groupID, groupAID := extractGroupIdentity(t, createResult)
	defer cleanupGroup(t, owner, groupID)

	ownerStore := integrationStoreForPath(t, owner.configModel.AUNPath, integrationClientSlotID(owner))
	memberStore := integrationStoreForPath(t, member.configModel.AUNPath, integrationClientSlotID(member))

	addMember(t, owner, groupID, memberAID)

	namespaceResult, err := owner.Group().Resources().InitializeNamespace(ctx, map[string]any{
		"group_id":  groupID,
		"group_aid": groupAID,
		"aid_store": ownerStore,
	})
	if err != nil {
		t.Fatalf("InitializeNamespace 失败: %v", err)
	}
	namespaceMap := mustMap(t, namespaceResult, "InitializeNamespace")
	if ready, ok := namespaceMap["namespace_ready"].(bool); !ok || !ready {
		t.Fatalf("namespace_ready 返回异常: %#v", namespaceMap)
	}

	resourcePath := fmt.Sprintf("announce/go-e2e-%s.txt", rid)
	body := []byte(fmt.Sprintf("GO_GROUP_STORAGE_E2E_%s", rid))
	putResult, err := owner.Group().Resources().Put(ctx, map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
		"resource_type": "file",
		"title":         fmt.Sprintf("go-e2e-%s.txt", rid),
		"content":       base64.StdEncoding.EncodeToString(body),
		"content_type":  "text/plain",
		"visibility":    "members_only",
	})
	if err != nil {
		t.Fatalf("group.resources.put 失败: %v", err)
	}
	pending := mustMap(t, putResult, "group.resources.put")
	if pending["mode"] != "pending_ops" {
		t.Fatalf("put 应返回 pending_ops 模式: %#v", pending)
	}
	if ops, ok := pending["pending_ops"].([]any); !ok || len(ops) == 0 {
		t.Fatalf("put 未返回 pending_ops: %#v", pending)
	}
	pending["aid_store"] = ownerStore
	confirmedResult, err := owner.Group().Resources().ExecutePendingOps(ctx, pending)
	if err != nil {
		t.Fatalf("ExecutePendingOps 失败: %v", err)
	}
	confirmed := mustMap(t, confirmedResult, "ExecutePendingOps")
	confirmedPayload := mustMap(t, confirmed["confirmed"], "ExecutePendingOps.confirmed")
	if ok, _ := confirmedPayload["confirmed"].(bool); !ok {
		t.Fatalf("confirm 返回异常: %#v", confirmed)
	}

	accessResult, err := member.Group().Resources().GetAccess(ctx, map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
	})
	if err != nil {
		t.Fatalf("成员 get_access 失败: %v", err)
	}
	access := mustMap(t, accessResult, "GetAccess")
	download := mustMap(t, access["download"], "GetAccess.download")
	downloadURL, _ := download["download_url"].(string)
	if downloadURL == "" {
		t.Fatalf("get_access 未返回 download_url: %#v", access)
	}
	if got := storageDownloadBytes(t, downloadURL); string(got) != string(body) {
		t.Fatalf("下载内容不匹配: want=%q got=%q", string(body), string(got))
	}

	memberBody := []byte(fmt.Sprintf("GO_MEMBERDATA_%s", rid))
	memberPath := fmt.Sprintf("memberdata/%s/docs/self.txt", memberAID)
	memberPutResult, err := member.Group().Resources().Put(ctx, map[string]any{
		"group_id":      groupID,
		"resource_path": memberPath,
		"content":       base64.StdEncoding.EncodeToString(memberBody),
		"content_type":  "text/plain",
	})
	if err != nil {
		t.Fatalf("memberdata 透明写入失败: %v", err)
	}
	memberPut := mustMap(t, memberPutResult, "memberdata Put")
	expectedMemberObjectKey := memberAID + "/" + groupAID + "/docs/self.txt"
	if memberPut["object_key"] != expectedMemberObjectKey {
		t.Fatalf("memberdata 透明路由 object_key 异常: %#v", memberPut)
	}
	rawMemberGet, err := member.Call(ctx, "storage.get_object", map[string]any{
		"owner_aid":  memberAID,
		"object_key": expectedMemberObjectKey,
	})
	if err != nil {
		t.Fatalf("读取 memberdata 透明写入对象失败: %v", err)
	}
	memberGet := mustMap(t, rawMemberGet, "storage.get_object")
	content, _ := memberGet["content"].(string)
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		t.Fatalf("memberdata content base64 解码失败: %v", err)
	}
	if string(decoded) != string(memberBody) {
		t.Fatalf("memberdata 内容不匹配: want=%q got=%q", string(memberBody), string(decoded))
	}

	_ = memberStore
}
