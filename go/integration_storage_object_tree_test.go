//go:build integration

package aun

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestIntegration_StorageLowLevelObjectTreeAndBatch(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("gotreea%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("gotreeb%s.%s", rid, testIssuer())
	bucket := fmt.Sprintf("go-tree-%s", rid)

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	low := NewStorageLowLevel(alice)
	bobLow := NewStorageLowLevel(bob)

	if _, err := bobLow.CreateFolder(ctx, aliceAID, bucket, "docs", true); err == nil {
		t.Fatalf("Bob 不应能为 Alice 创建 storage 目录")
	}

	folder, err := low.CreateFolder(ctx, aliceAID, bucket, "docs/sub", true)
	if err != nil {
		t.Skipf("storage 目录树 RPC 不可用: %v", err)
	}
	if storageString(folder["folder_id"], "") == "" || storageString(folder["path"], "") != "docs/sub" {
		t.Fatalf("CreateFolder 返回异常: %#v", folder)
	}

	if got, err := low.GetFolder(ctx, aliceAID, bucket, "docs/sub"); err != nil || storageString(got["folder_id"], "") == "" {
		t.Fatalf("GetFolder 返回异常: got=%#v err=%v", got, err)
	}

	created, err := low.AppendObject(ctx, AppendObjectOptions{
		Owner:       aliceAID,
		Bucket:      bucket,
		ObjectKey:   "docs/sub/a.txt",
		Content:     []byte("hello"),
		ContentType: "text/plain",
		Metadata:    map[string]any{"stage": "created"},
	})
	if err != nil {
		t.Fatalf("AppendObject 首次创建失败: %v", err)
	}
	firstVersion := int(storageInt64(created["version"]))
	if storageString(created["object_id"], "") == "" || storageString(created["path"], "") != "docs/sub/a.txt" {
		t.Fatalf("AppendObject 首次返回异常: %#v", created)
	}

	appended, err := low.AppendObject(ctx, AppendObjectOptions{
		Owner:           aliceAID,
		Bucket:          bucket,
		ObjectKey:       "docs/sub/a.txt",
		Content:         []byte(" world"),
		ContentType:     "text/plain",
		ExpectedVersion: &firstVersion,
	})
	if err != nil {
		t.Fatalf("AppendObject 追加失败: %v", err)
	}
	if int(storageInt64(appended["version"])) != firstVersion+1 {
		t.Fatalf("AppendObject 版本未递增: first=%d appended=%#v", firstVersion, appended)
	}

	read, err := low.GetObject(ctx, aliceAID, bucket, "docs/sub/a.txt", "", nil, nil)
	if err != nil {
		t.Fatalf("GetObject 追加后读取失败: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(storageString(read["content"], ""))
	if err != nil || string(decoded) != "hello world" {
		t.Fatalf("GetObject 内容异常: content=%q err=%v raw=%#v", string(decoded), err, read)
	}

	meta, err := low.SetObjectMeta(ctx, aliceAID, bucket, "docs/sub/a.txt", map[string]any{"stage": "final"}, "text/markdown", true, nil)
	if err != nil {
		t.Fatalf("SetObjectMeta 失败: %v", err)
	}
	if storageString(meta["content_type"], "") != "text/markdown" {
		t.Fatalf("SetObjectMeta content_type 异常: %#v", meta)
	}

	includeMetadata := true
	listed, err := low.ListChildren(ctx, ListChildrenOptions{
		Owner:           aliceAID,
		Bucket:          bucket,
		Path:            "docs/sub",
		IncludeMetadata: &includeMetadata,
	})
	if err != nil {
		t.Fatalf("ListChildren 失败: %v", err)
	}
	if !storageTreeItemsContain(listed["items"], "object", "a.txt") {
		t.Fatalf("ListChildren 未返回 a.txt: %#v", listed)
	}

	resolved, err := low.ResolvePath(ctx, aliceAID, bucket, "docs/sub/a.txt", "object", nil)
	if err != nil {
		t.Fatalf("ResolvePath 失败: %v", err)
	}
	objectID := storageString(resolved["object_id"], "")
	if objectID == "" {
		t.Fatalf("ResolvePath 未返回 object_id: %#v", resolved)
	}

	if _, err := low.CreateFolder(ctx, aliceAID, bucket, "archive", true); err != nil {
		t.Fatalf("CreateFolder archive 失败: %v", err)
	}
	copied, err := low.CopyObject(ctx, CopyObjectOptions{
		Owner:     aliceAID,
		Bucket:    bucket,
		SrcPath:   "docs/sub/a.txt",
		DstPath:   "archive/copy.txt",
		Overwrite: true,
	})
	if err != nil {
		t.Fatalf("CopyObject 失败: %v", err)
	}
	if storageString(copied["object_id"], "") == "" || storageString(copied["object_id"], "") == objectID {
		t.Fatalf("CopyObject object_id 异常: %#v", copied)
	}

	moved, err := low.MoveObject(ctx, MoveObjectOptions{
		Owner:         aliceAID,
		Bucket:        bucket,
		Path:          "docs/sub/a.txt",
		DstParentPath: "archive",
		NewName:       "moved.txt",
	})
	if err != nil {
		t.Fatalf("MoveObject 失败: %v", err)
	}
	if storageString(moved["object_id"], "") != objectID || storageString(moved["path"], "") != "archive/moved.txt" {
		t.Fatalf("MoveObject 返回异常: %#v", moved)
	}
	if _, err := low.ResolvePath(ctx, aliceAID, bucket, "docs/sub/a.txt", "object", nil); err == nil {
		t.Fatalf("MoveObject 后旧路径不应可解析")
	}

	deleted, err := low.BatchDelete(ctx, aliceAID, bucket, []map[string]any{
		{"type": "object", "path": "archive/copy.txt"},
		{"type": "object", "path": "archive/moved.txt"},
	}, false)
	if err != nil {
		t.Fatalf("BatchDelete 失败: %v", err)
	}
	if storageInt64(firstNonNil(deleted["deleted_count"], deleted["deleted"])) < 2 {
		t.Fatalf("BatchDelete 删除数量异常: %#v", deleted)
	}
	if _, err := low.ResolvePath(ctx, aliceAID, bucket, "archive/moved.txt", "object", nil); err == nil {
		t.Fatalf("BatchDelete 后 moved.txt 不应可解析")
	}

	if _, err := low.DeleteFolder(ctx, aliceAID, bucket, "docs", true); err != nil {
		t.Fatalf("DeleteFolder docs 失败: %v", err)
	}
	if _, err := low.DeleteFolder(ctx, aliceAID, bucket, "archive", true); err != nil {
		t.Fatalf("DeleteFolder archive 失败: %v", err)
	}
}

func storageTreeItemsContain(raw any, nodeType string, name string) bool {
	items, _ := raw.([]any)
	for _, item := range items {
		m := storageMap(item)
		if storageString(m["node_type"], "") == nodeType && storageString(m["name"], "") == name {
			return true
		}
	}
	return false
}
