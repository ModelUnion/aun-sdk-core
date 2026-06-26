//go:build integration

package aun

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntegration_StorageVFSP6(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	groupOwner := makeClient(t)
	defer alice.Close()
	defer groupOwner.Close()

	aliceAID := fmt.Sprintf("p6goa%s.%s", rid, testIssuer())
	groupAID := fmt.Sprintf("p6gog%s.%s", rid, testIssuer())
	root := fmt.Sprintf("/fs-p6-go-%s", rid)
	sourceDir := fmt.Sprintf("%s/source", root)
	mountDir := fmt.Sprintf("%s/memberdata/alice", root)
	body := []byte(fmt.Sprintf("hello-p6-go-%s", rid))
	writtenViaMount := []byte(fmt.Sprintf("write-p6-go-%s", rid))

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, groupOwner, groupAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_, _ = alice.Storage().Remove(cleanupCtx, root, &RemoveOptions{Owner: aliceAID, Recursive: true})
		_, _ = groupOwner.Storage().Remove(cleanupCtx, root, &RemoveOptions{Owner: groupAID, Recursive: true})
	}()

	if _, err := alice.Storage().WriteBytes(ctx, sourceDir+"/a.txt", body, &WriteBytesOptions{
		Owner:       aliceAID,
		ContentType: "text/plain",
	}); err != nil {
		t.Fatalf("source 写入失败: %v", err)
	}
	if _, err := alice.Storage().SetACL(ctx, sourceDir, SetACLOptions{
		Owner:      aliceAID,
		GranteeAID: groupAID,
		Perms:      "w",
	}); err != nil {
		t.Fatalf("source ACL 授权失败: %v", err)
	}
	if _, err := groupOwner.Storage().ReadBytes(ctx, sourceDir+"/a.txt", &ReadOptions{Owner: aliceAID}); err == nil {
		t.Fatalf("source 写 ACL 不应授予直接读取")
	}

	mounted, err := groupOwner.Storage().Mount(ctx, mountDir, &MountOptions{
		Owner:           groupAID,
		SourceAID:       aliceAID,
		SourcePath:      sourceDir,
		Readonly:        false,
		RequireApproval: true,
	})
	if err != nil {
		t.Fatalf("Mount 失败: %v", err)
	}
	if mounted.Type != "mount" || mounted.Path != mountDir {
		t.Fatalf("Mount NodeView 异常: %#v", mounted)
	}
	if !strings.Contains(mounted.MountSource, aliceAID) || !strings.Contains(mounted.MountSource, strings.TrimPrefix(sourceDir, "/")) {
		t.Fatalf("MountSource 异常: %#v", mounted)
	}
	if _, err := groupOwner.Storage().Stat(ctx, mountDir, &StatOptions{Owner: groupAID}); err == nil {
		t.Fatalf("pending mount 审批前不应可读")
	}
	approved, err := alice.Storage().ApproveMount(ctx, mountDir, &MountReviewOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("ApproveMount 失败: %v", err)
	}
	if storageBool(approved["approved"], false) != true || storageString(approved["status"], "") != "active" {
		t.Fatalf("ApproveMount 返回异常: %#v", approved)
	}

	lstat, err := groupOwner.Storage().Lstat(ctx, mountDir, &StatOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("Lstat 挂载点失败: %v", err)
	}
	stat, err := groupOwner.Storage().Stat(ctx, mountDir, &StatOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("Stat 挂载点失败: %v", err)
	}
	listed, err := groupOwner.Storage().List(ctx, mountDir, &ListOptions{Owner: groupAID, Long: true})
	if err != nil {
		t.Fatalf("List 挂载点失败: %v", err)
	}
	if lstat.Type != "mount" || stat.Type != "dir" || !hasStorageNodeName(listed, "a.txt") {
		t.Fatalf("挂载点解析异常: lstat=%#v stat=%#v listed=%#v", lstat, stat, listed)
	}
	groupRead, err := groupOwner.Storage().ReadBytes(ctx, mountDir+"/a.txt", &ReadOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("通过挂载点读取失败: %v", err)
	}
	if !bytes.Equal(groupRead, body) {
		t.Fatalf("通过挂载点读取内容不匹配: got=%q want=%q", string(groupRead), string(body))
	}

	if _, err := groupOwner.Storage().WriteBytes(ctx, mountDir+"/b.txt", writtenViaMount, &WriteBytesOptions{
		Owner:       groupAID,
		ContentType: "text/plain",
	}); err != nil {
		t.Fatalf("通过挂载点写入失败: %v", err)
	}
	sourceRead, err := alice.Storage().ReadBytes(ctx, sourceDir+"/b.txt", &ReadOptions{Owner: aliceAID})
	if err != nil {
		t.Fatalf("source 读取挂载写入失败: %v", err)
	}
	if !bytes.Equal(sourceRead, writtenViaMount) {
		t.Fatalf("挂载写入未落到 source: got=%q want=%q", string(sourceRead), string(writtenViaMount))
	}

	copied, err := groupOwner.Storage().Copy(ctx, mountDir+"/b.txt", mountDir+"/copied.txt", &CopyOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("通过挂载点 Copy 失败: %v", err)
	}
	if copied.Owner != aliceAID || copied.Path != sourceDir+"/copied.txt" {
		t.Fatalf("通过挂载点 Copy 返回异常: copied=%#v", copied)
	}
	if _, err := alice.Storage().Stat(ctx, sourceDir+"/copied.txt", &StatOptions{Owner: aliceAID}); err != nil {
		t.Fatalf("source stat 挂载 Copy 目标失败: %v; copied=%#v", err, copied)
	}
	if _, err := groupOwner.Storage().Stat(ctx, mountDir+"/copied.txt", &StatOptions{Owner: groupAID}); err != nil {
		t.Fatalf("通过挂载点 stat Copy 目标失败: %v; copied=%#v", err, copied)
	}
	renamed, err := groupOwner.Storage().Rename(ctx, mountDir+"/copied.txt", mountDir+"/renamed.txt", &RenameOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("通过挂载点 Rename 失败: %v", err)
	}
	removed, err := groupOwner.Storage().Remove(ctx, mountDir+"/renamed.txt", &RemoveOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("通过挂载点 Remove 失败: %v", err)
	}
	if renamed.Path != sourceDir+"/renamed.txt" || removed.RemovedCount != 1 {
		t.Fatalf("挂载点写操作返回异常: copied=%#v renamed=%#v removed=%#v", copied, renamed, removed)
	}
	if _, err := alice.Storage().Stat(ctx, sourceDir+"/renamed.txt", &StatOptions{Owner: aliceAID}); err == nil {
		t.Fatalf("renamed.txt 删除后不应仍可 stat")
	}

	unmounted, err := groupOwner.Storage().Unmount(ctx, mountDir, &UnmountOptions{Owner: groupAID})
	if err != nil {
		t.Fatalf("Unmount 失败: %v", err)
	}
	if !unmounted.Unmounted || unmounted.MountPath != mountDir {
		t.Fatalf("UnmountResult 异常: %#v", unmounted)
	}
	if _, err := groupOwner.Storage().Stat(ctx, mountDir, &StatOptions{Owner: groupAID}); err == nil {
		t.Fatalf("unmount 后挂载点不应仍可 stat")
	}
	sourceAfterUnmount, err := alice.Storage().ReadBytes(ctx, sourceDir+"/a.txt", &ReadOptions{Owner: aliceAID})
	if err != nil {
		t.Fatalf("unmount 后 source 读取失败: %v", err)
	}
	if !bytes.Equal(sourceAfterUnmount, body) {
		t.Fatalf("unmount 后 source 数据不匹配: got=%q want=%q", string(sourceAfterUnmount), string(body))
	}
}

func hasStorageNodeName(nodes []NodeView, name string) bool {
	for _, node := range nodes {
		if node.Name == name {
			return true
		}
	}
	return false
}
