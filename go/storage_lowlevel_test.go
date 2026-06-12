package aun

import (
	"context"
	"encoding/base64"
	"reflect"
	"testing"
)

func TestStorageLowLevelConvenienceRPCMappings(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	low := NewStorageLowLevel(client)
	expireInSeconds := 3600
	maxUses := 3
	expectedVersion := 7
	metadata := map[string]any{"k": "v"}

	if _, err := low.CreateShareLink(ctx, "alice.agentid.pub", "team", "docs/a.txt", []string{"bob.agentid.pub"}, &expireInSeconds, &maxUses); err != nil {
		t.Fatalf("CreateShareLink 失败: %v", err)
	}
	if _, err := low.ListShareLinks(ctx, "alice.agentid.pub", "team", "docs/a.txt"); err != nil {
		t.Fatalf("ListShareLinks 失败: %v", err)
	}
	if _, err := low.RevokeShareLink(ctx, "share-1"); err != nil {
		t.Fatalf("RevokeShareLink 失败: %v", err)
	}
	if _, err := low.GetByShare(ctx, "share-1"); err != nil {
		t.Fatalf("GetByShare 失败: %v", err)
	}
	if _, err := low.SetObjectMeta(ctx, "alice.agentid.pub", "team", "docs/a.txt", metadata, "text/plain", true, &expectedVersion); err != nil {
		t.Fatalf("SetObjectMeta 失败: %v", err)
	}
	if _, err := low.AppendObject(ctx, AppendObjectOptions{
		Owner:           "alice.agentid.pub",
		Bucket:          "team",
		ObjectKey:       "docs/a.txt",
		Content:         []byte("tail"),
		ContentType:     "text/plain",
		Metadata:        metadata,
		ExpectedVersion: &expectedVersion,
		IsPublic:        true,
	}); err != nil {
		t.Fatalf("AppendObject 失败: %v", err)
	}
	if _, err := low.ListChildren(ctx, ListChildrenOptions{
		Owner:           "alice.agentid.pub",
		Bucket:          "team",
		Path:            "/docs",
		NodeType:        "file",
		Page:            2,
		Size:            20,
		OrderBy:         "name",
		Order:           "asc",
		IncludeMetadata: storageLowLevelBoolPtr(true),
		IncludeURLs:     storageLowLevelBoolPtr(false),
	}); err != nil {
		t.Fatalf("ListChildren 失败: %v", err)
	}
	expiresAt := int64(123)
	if _, err := low.VolumeCreate(ctx, "alice.agentid.pub", "team", "vol-1", 4096, "volumes/vol-1", &expiresAt, nil, ""); err != nil {
		t.Fatalf("VolumeCreate 失败: %v", err)
	}
	if _, err := low.VolumeRenew(ctx, "alice.agentid.pub", "team", "vol-1", 999, "active"); err != nil {
		t.Fatalf("VolumeRenew 失败: %v", err)
	}
	now := int64(1000)
	if _, err := low.VolumeExpireDue(ctx, "alice.agentid.pub", "team", &now); err != nil {
		t.Fatalf("VolumeExpireDue 失败: %v", err)
	}
	if _, err := low.FSInvalidateMembership(ctx, "g-team.agentid.pub", "owner.agentid.pub", "alice.agentid.pub", "left", ""); err != nil {
		t.Fatalf("FSInvalidateMembership 失败: %v", err)
	}

	wantMethods := []string{
		"storage.create_share_link",
		"storage.list_share_links",
		"storage.revoke_share_link",
		"storage.get_by_share",
		"storage.set_object_meta",
		"storage.append_object",
		"storage.list_children",
		"storage.volume.create",
		"storage.volume.renew",
		"storage.volume.expire_due",
		"storage.fs.invalidate_membership",
	}
	if len(client.calls) != len(wantMethods) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(wantMethods), client.calls)
	}
	for i, method := range wantMethods {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}

	createParams := client.calls[0].params
	if createParams["owner_aid"] != "alice.agentid.pub" || createParams["bucket"] != "team" || createParams["object_key"] != "docs/a.txt" {
		t.Fatalf("create_share_link 基础参数不正确: %#v", createParams)
	}
	if createParams["expire_in_seconds"] != 3600 || createParams["max_uses"] != 3 {
		t.Fatalf("create_share_link 限制参数不正确: %#v", createParams)
	}
	if aids, ok := createParams["allowed_aids"].([]string); !ok || len(aids) != 1 || aids[0] != "bob.agentid.pub" {
		t.Fatalf("create_share_link allowed_aids 不正确: %#v", createParams)
	}

	listParams := client.calls[1].params
	if listParams["object_key"] != "docs/a.txt" || listParams["bucket"] != "team" {
		t.Fatalf("list_share_links 参数不正确: %#v", listParams)
	}
	if client.calls[2].params["share_id"] != "share-1" || client.calls[3].params["share_id"] != "share-1" {
		t.Fatalf("share_id 未正确透传: revoke=%#v get=%#v", client.calls[2].params, client.calls[3].params)
	}

	metaParams := client.calls[4].params
	if !reflect.DeepEqual(metaParams["metadata"], metadata) || metaParams["content_type"] != "text/plain" || metaParams["merge"] != true || metaParams["expected_version"] != 7 {
		t.Fatalf("set_object_meta 参数不正确: %#v", metaParams)
	}

	appendParams := client.calls[5].params
	if appendParams["content"] != base64.StdEncoding.EncodeToString([]byte("tail")) {
		t.Fatalf("append_object content 未 base64 编码: %#v", appendParams)
	}
	if appendParams["is_private"] != false || appendParams["expected_version"] != 7 || !reflect.DeepEqual(appendParams["metadata"], metadata) {
		t.Fatalf("append_object 参数不正确: %#v", appendParams)
	}

	childrenParams := client.calls[6].params
	if childrenParams["path"] != "/docs" || childrenParams["type"] != "file" || childrenParams["page"] != 2 || childrenParams["size"] != 20 {
		t.Fatalf("list_children 基础参数不正确: %#v", childrenParams)
	}
	if childrenParams["order_by"] != "name" || childrenParams["order"] != "asc" || childrenParams["include_metadata"] != true || childrenParams["include_urls"] != false {
		t.Fatalf("list_children 扩展参数不正确: %#v", childrenParams)
	}

	volumeCreateParams := client.calls[7].params
	if volumeCreateParams["owner_aid"] != "alice.agentid.pub" || volumeCreateParams["bucket"] != "team" || volumeCreateParams["volume_id"] != "vol-1" || volumeCreateParams["size_bytes"] != int64(4096) {
		t.Fatalf("volume.create 参数不正确: %#v", volumeCreateParams)
	}
	if volumeCreateParams["mount_point"] != "volumes/vol-1" || volumeCreateParams["expires_at"] != int64(123) {
		t.Fatalf("volume.create 扩展参数不正确: %#v", volumeCreateParams)
	}
	volumeRenewParams := client.calls[8].params
	if volumeRenewParams["volume_id"] != "vol-1" || volumeRenewParams["expires_at"] != int64(999) || volumeRenewParams["status"] != "active" {
		t.Fatalf("volume.renew 参数不正确: %#v", volumeRenewParams)
	}
	expireDueParams := client.calls[9].params
	if expireDueParams["owner_aid"] != "alice.agentid.pub" || expireDueParams["bucket"] != "team" || expireDueParams["now"] != int64(1000) {
		t.Fatalf("volume.expire_due 参数不正确: %#v", expireDueParams)
	}
	invalidateParams := client.calls[10].params
	if invalidateParams["group_id"] != "g-team.agentid.pub" || invalidateParams["group_owner_aid"] != "owner.agentid.pub" || invalidateParams["member_aid"] != "alice.agentid.pub" || invalidateParams["reason"] != "left" {
		t.Fatalf("fs.invalidate_membership 参数不正确: %#v", invalidateParams)
	}
}

func TestStorageLowLevelConvenienceOmitsNilOptionalParams(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	low := NewStorageLowLevel(client)

	if _, err := low.CreateShareLink(ctx, "", "", "docs/a.txt", nil, nil, nil); err != nil {
		t.Fatalf("CreateShareLink 失败: %v", err)
	}
	if _, err := low.ListShareLinks(ctx, "", "", ""); err != nil {
		t.Fatalf("ListShareLinks 失败: %v", err)
	}
	if _, err := low.SetObjectMeta(ctx, "", "", "docs/a.txt", map[string]any{"k": "v"}, "", false, nil); err != nil {
		t.Fatalf("SetObjectMeta 失败: %v", err)
	}
	if _, err := low.AppendObject(ctx, AppendObjectOptions{ObjectKey: "docs/a.txt", Content: []byte("tail")}); err != nil {
		t.Fatalf("AppendObject 失败: %v", err)
	}
	if _, err := low.ListChildren(ctx, ListChildrenOptions{Path: "/docs"}); err != nil {
		t.Fatalf("ListChildren 失败: %v", err)
	}

	createParams := client.calls[0].params
	if createParams["bucket"] != "default" || createParams["object_key"] != "docs/a.txt" {
		t.Fatalf("create_share_link 默认参数不正确: %#v", createParams)
	}
	if _, exists := createParams["owner_aid"]; exists {
		t.Fatalf("空 owner 不应传入 owner_aid: %#v", createParams)
	}
	if _, exists := createParams["allowed_aids"]; exists {
		t.Fatalf("nil allowed_aids 不应传入 RPC: %#v", createParams)
	}
	if _, exists := createParams["expire_in_seconds"]; exists {
		t.Fatalf("nil expire_in_seconds 不应传入 RPC: %#v", createParams)
	}
	if _, exists := createParams["max_uses"]; exists {
		t.Fatalf("nil max_uses 不应传入 RPC: %#v", createParams)
	}

	listParams := client.calls[1].params
	if listParams["bucket"] != "default" {
		t.Fatalf("list_share_links 默认 bucket 不正确: %#v", listParams)
	}
	if _, exists := listParams["object_key"]; exists {
		t.Fatalf("空 object_key 不应传入 RPC: %#v", listParams)
	}

	metaParams := client.calls[2].params
	if _, exists := metaParams["content_type"]; exists {
		t.Fatalf("空 content_type 不应传入 RPC: %#v", metaParams)
	}
	if _, exists := metaParams["expected_version"]; exists {
		t.Fatalf("nil expected_version 不应传入 RPC: %#v", metaParams)
	}
	if metaParams["merge"] != false {
		t.Fatalf("merge=false 应保留传入: %#v", metaParams)
	}

	appendParams := client.calls[3].params
	if appendParams["is_private"] != true {
		t.Fatalf("默认 AppendObject 应设置 is_private=true: %#v", appendParams)
	}
	if _, exists := appendParams["metadata"]; exists {
		t.Fatalf("nil metadata 不应传入 RPC: %#v", appendParams)
	}
	if _, exists := appendParams["content_type"]; exists {
		t.Fatalf("空 content_type 不应传入 RPC: %#v", appendParams)
	}

	childrenParams := client.calls[4].params
	if childrenParams["path"] != "/docs" || childrenParams["type"] != "all" || childrenParams["page"] != 1 || childrenParams["size"] != 50 {
		t.Fatalf("list_children 默认参数不正确: %#v", childrenParams)
	}
	if _, exists := childrenParams["include_metadata"]; exists {
		t.Fatalf("nil include_metadata 不应传入 RPC: %#v", childrenParams)
	}
	if _, exists := childrenParams["include_urls"]; exists {
		t.Fatalf("nil include_urls 不应传入 RPC: %#v", childrenParams)
	}
}

func storageLowLevelBoolPtr(value bool) *bool {
	return &value
}

func TestStorageLowLevelLegacyTreeRPCMappings(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	low := NewStorageLowLevel(client)
	expectedVersion := 5
	followSymlinks := false

	if _, err := low.ListObjects(ctx, "alice.agentid.pub", "team", "docs", 2, 10, "m1"); err != nil {
		t.Fatalf("ListObjects 失败: %v", err)
	}
	if _, err := low.ListPrefixes(ctx, "alice.agentid.pub", "team", "docs", 20); err != nil {
		t.Fatalf("ListPrefixes 失败: %v", err)
	}
	if _, err := low.DeleteObject(ctx, "alice.agentid.pub", "team", "docs/a.txt"); err != nil {
		t.Fatalf("DeleteObject 失败: %v", err)
	}
	if _, err := low.BatchDelete(ctx, "alice.agentid.pub", "team", []map[string]any{{"object_key": "docs/a.txt"}}, true); err != nil {
		t.Fatalf("BatchDelete 失败: %v", err)
	}
	if _, err := low.MoveObject(ctx, MoveObjectOptions{
		Owner: "alice.agentid.pub", Bucket: "team", Path: "docs/a.txt",
		DstParentPath: "archive", NewName: "a.txt", Overwrite: true,
		ExpectedVersion: &expectedVersion,
	}); err != nil {
		t.Fatalf("MoveObject 失败: %v", err)
	}
	if _, err := low.CopyObject(ctx, CopyObjectOptions{
		Owner: "alice.agentid.pub", Bucket: "team", SrcPath: "archive/a.txt", DstPath: "copy/a.txt",
	}); err != nil {
		t.Fatalf("CopyObject 失败: %v", err)
	}
	if _, err := low.CreateFolder(ctx, "alice.agentid.pub", "team", "docs", true); err != nil {
		t.Fatalf("CreateFolder 失败: %v", err)
	}
	if _, err := low.GetFolder(ctx, "alice.agentid.pub", "team", "docs"); err != nil {
		t.Fatalf("GetFolder 失败: %v", err)
	}
	if _, err := low.MoveFolder(ctx, MoveFolderOptions{
		Owner: "alice.agentid.pub", Bucket: "team", Path: "docs",
		DstParentPath: "archive", NewName: "docs2", ExpectedVersion: &expectedVersion,
	}); err != nil {
		t.Fatalf("MoveFolder 失败: %v", err)
	}
	if _, err := low.DeleteFolder(ctx, "alice.agentid.pub", "team", "archive/docs2", true); err != nil {
		t.Fatalf("DeleteFolder 失败: %v", err)
	}
	if _, err := low.ResolvePath(ctx, "alice.agentid.pub", "team", "link", "file", &followSymlinks); err != nil {
		t.Fatalf("ResolvePath 失败: %v", err)
	}

	wantMethods := []string{
		"storage.list_objects",
		"storage.list_prefixes",
		"storage.delete_object",
		"storage.batch_delete",
		"storage.move_object",
		"storage.copy_object",
		"storage.create_folder",
		"storage.get_folder",
		"storage.move_folder",
		"storage.delete_folder",
		"storage.resolve_path",
	}
	if len(client.calls) != len(wantMethods) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(wantMethods), client.calls)
	}
	for i, method := range wantMethods {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}
	if params := client.calls[0].params; params["prefix"] != "docs" || params["page"] != 2 || params["size"] != 10 || params["marker"] != "m1" {
		t.Fatalf("list_objects 参数不正确: %#v", params)
	}
	if params := client.calls[4].params; params["path"] != "docs/a.txt" || params["dst_parent_path"] != "archive" || params["new_name"] != "a.txt" || params["conflict_policy"] != "replace" || params["expected_version"] != 5 {
		t.Fatalf("move_object 参数不正确: %#v", params)
	}
	if params := client.calls[5].params; params["conflict_policy"] != "reject" {
		t.Fatalf("copy_object 默认冲突策略不正确: %#v", params)
	}
	if params := client.calls[6].params; params["path"] != "docs" || params["mkdirs"] != true {
		t.Fatalf("create_folder 参数不正确: %#v", params)
	}
	if params := client.calls[10].params; params["path"] != "link" || params["expected_type"] != "file" || params["follow_symlinks"] != false {
		t.Fatalf("resolve_path 参数不正确: %#v", params)
	}
}
