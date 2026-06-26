//go:build integration

package aun

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegration_GroupFSFacadeRoundTrip(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	defer owner.Close()

	ownerAID := fmt.Sprintf("gofsowner%s.%s", rid, testIssuer())
	groupName := fmt.Sprintf("gofs%s", rid)

	ensureConnected(t, owner, ownerAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	created, err := owner.CreateGroup(ctx, map[string]any{
		"name":       fmt.Sprintf("go-group-fs-%s", rid),
		"group_name": groupName,
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("CreateGroup 失败: %v", err)
	}
	groupID, groupAID := extractGroupIdentity(t, created)
	defer cleanupGroup(t, owner, groupID)

	if _, err := owner.Call(ctx, "group.fs.namespace_ready", map[string]any{"group_id": groupID}); err != nil {
		t.Logf("group.fs.namespace_ready 不可用或无需显式调用: %v", err)
	}

	store := integrationStoreForPath(t, owner.configModel.AUNPath)
	opts := func() *GroupFSCpOptions {
		return &GroupFSCpOptions{SignAs: groupAID, AidStore: store}
	}
	mkdirOpts := &GroupFSMkdirOptions{Parents: true, SignAs: groupAID, AidStore: store}
	statOpts := &GroupFSStatOptions{SignAs: groupAID, AidStore: store}
	listOpts := &GroupFSListOptions{Long: true, SignAs: groupAID, AidStore: store}
	findOpts := &GroupFSFindOptions{Name: "renamed.txt", SignAs: groupAID, AidStore: store}
	rmOpts := &GroupFSRmOptions{Recursive: true, Force: true, SignAs: groupAID, AidStore: store}
	dfOpts := &GroupFSDfOptions{SignAs: groupAID, AidStore: store}

	baseDir := fmt.Sprintf("%s:/public/go-fs-%s", groupAID, rid)
	sourcePath := filepath.Join(t.TempDir(), "source.txt")
	downloadPath := filepath.Join(t.TempDir(), "download.txt")
	body := []byte(fmt.Sprintf("GROUP-FS-GO-%s", rid))
	if err := os.WriteFile(sourcePath, body, 0o600); err != nil {
		t.Fatalf("写本地源文件失败: %v", err)
	}

	defer func() {
		_, _ = owner.Group().FS().Rm(context.Background(), baseDir, rmOpts)
	}()

	dirNode, err := owner.Group().FS().Mkdir(ctx, baseDir, mkdirOpts)
	if err != nil {
		t.Fatalf("Group().FS().Mkdir 失败: %v", err)
	}
	if dirNode.Type != "dir" && dirNode.Type != "folder" {
		t.Fatalf("Mkdir 返回异常: %#v", dirNode)
	}

	remoteFile := baseDir + "/note.txt"
	uploaded, err := owner.Group().FS().Cp(ctx, sourcePath, remoteFile, opts())
	if err != nil {
		t.Fatalf("Group().FS().Cp 本地上传失败: %v", err)
	}
	if uploaded.Direction != "local_to_group" || uploaded.Node.Type != "file" {
		t.Fatalf("Cp 上传返回异常: %#v", uploaded)
	}

	listed, err := owner.Group().FS().Ls(ctx, baseDir, listOpts)
	if err != nil {
		t.Fatalf("Group().FS().Ls 失败: %v", err)
	}
	if !groupFSHasItem(listed.Items, "note.txt") {
		t.Fatalf("Ls 未返回上传文件: %#v", listed)
	}

	statNode, err := owner.Group().FS().Stat(ctx, remoteFile, statOpts)
	if err != nil {
		t.Fatalf("Group().FS().Stat 失败: %v", err)
	}
	if statNode.Type != "file" || statNode.Name != "note.txt" {
		t.Fatalf("Stat 返回异常: %#v", statNode)
	}

	if _, err := owner.Group().FS().Df(ctx, baseDir, dfOpts); err != nil {
		t.Fatalf("Group().FS().Df 失败: %v", err)
	}

	copiedPath := baseDir + "/copy.txt"
	copyOpts := opts()
	copyOpts.Force = true
	copied, err := owner.Group().FS().Cp(ctx, remoteFile, copiedPath, copyOpts)
	if err != nil {
		t.Fatalf("Group().FS().Cp 群内复制失败: %v", err)
	}
	if copied.Direction != "group_to_group" {
		t.Fatalf("群内复制 Direction 异常: %#v", copied)
	}

	renamedPath := baseDir + "/renamed.txt"
	mvOpts := &GroupFSMvOptions{Force: true, SignAs: groupAID, AidStore: store}
	moved, err := owner.Group().FS().Mv(ctx, copiedPath, renamedPath, mvOpts)
	if err != nil {
		t.Fatalf("Group().FS().Mv 失败: %v", err)
	}
	if moved.Name != "renamed.txt" {
		t.Fatalf("Mv 返回异常: %#v", moved)
	}

	found, err := owner.Group().FS().Find(ctx, baseDir, findOpts)
	if err != nil {
		t.Fatalf("Group().FS().Find 失败: %v", err)
	}
	if !groupFSHasItem(found.Items, "renamed.txt") {
		t.Fatalf("Find 未返回 renamed.txt: %#v", found)
	}

	downloadOpts := opts()
	downloadOpts.Force = true
	downloaded, err := owner.Group().FS().Cp(ctx, remoteFile, downloadPath, downloadOpts)
	if err != nil {
		t.Fatalf("Group().FS().Cp 下载失败: %v", err)
	}
	if downloaded.Direction != "group_to_local" || !bytes.Equal(downloaded.Download.Data, body) {
		t.Fatalf("Cp 下载返回异常: %#v", downloaded)
	}
	localRead, err := os.ReadFile(downloadPath)
	if err != nil || !bytes.Equal(localRead, body) {
		t.Fatalf("下载本地文件内容异常: got=%q err=%v", string(localRead), err)
	}

	removed, err := owner.Group().FS().Rm(ctx, baseDir, rmOpts)
	if err != nil {
		t.Fatalf("Group().FS().Rm 失败: %v", err)
	}
	if removed.RemovedCount < 1 {
		t.Fatalf("Rm 返回异常: %#v", removed)
	}
}

func TestIntegration_GroupFSAdminRoleACLGrantAndRevoke(t *testing.T) {
	rid := runID()
	owner := makeClient(t)
	defer owner.Close()
	admin := makeClient(t)
	defer admin.Close()

	ownerAID := fmt.Sprintf("gofsaclowner%s.%s", rid, testIssuer())
	adminAID := fmt.Sprintf("gofsacladmin%s.%s", rid, testIssuer())
	groupName := fmt.Sprintf("gofsacl%s", rid)

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, admin, adminAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	created, err := owner.CreateGroup(ctx, map[string]any{
		"name":       fmt.Sprintf("go-group-fs-acl-%s", rid),
		"group_name": groupName,
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("CreateGroup 失败: %v", err)
	}
	groupID, groupAID := extractGroupIdentity(t, created)
	defer cleanupGroup(t, owner, groupID)

	if _, err := owner.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      adminAID,
		"role":     "member",
	}); err != nil {
		t.Fatalf("group.add_member 失败: %v", err)
	}
	roleResult, err := owner.Call(ctx, "group.set_role", map[string]any{
		"group_id": groupID,
		"aid":      adminAID,
		"role":     "admin",
	})
	if err != nil {
		t.Fatalf("group.set_role 失败: %v", err)
	}
	if got := stringFromAny(rpcResultMap(roleResult)["new_role"]); got != "admin" {
		t.Fatalf("group.set_role 未返回 admin: %#v", roleResult)
	}
	if _, err := owner.Call(ctx, "group.fs.namespace_ready", map[string]any{"group_id": groupID}); err != nil {
		t.Logf("group.fs.namespace_ready 不可用或无需显式调用: %v", err)
	}

	baseDir := fmt.Sprintf("%s:/archive/go-acl-%s", groupAID, rid)
	before := filepath.Join(t.TempDir(), "before.txt")
	granted := filepath.Join(t.TempDir(), "granted.txt")
	after := filepath.Join(t.TempDir(), "after.txt")
	if err := os.WriteFile(before, []byte("before grant "+rid), 0o600); err != nil {
		t.Fatalf("写 before 文件失败: %v", err)
	}
	body := []byte("admin write after grant " + rid)
	if err := os.WriteFile(granted, body, 0o600); err != nil {
		t.Fatalf("写 granted 文件失败: %v", err)
	}
	if err := os.WriteFile(after, []byte("after revoke "+rid), 0o600); err != nil {
		t.Fatalf("写 after 文件失败: %v", err)
	}

	writeOpts := &GroupFSCpOptions{Force: true, Parents: true}
	if _, err := admin.Group().FS().Cp(ctx, before, baseDir+"/before.txt", writeOpts); err == nil {
		t.Fatalf("admin 在 role ACL 授权前不应能写群自有区")
	}
	grant, err := owner.Group().FS().SetACL(ctx, baseDir, &GroupFSAclOptions{GranteeAID: "role:admin", Perms: "rwx"})
	if err != nil {
		t.Fatalf("Group().FS().SetACL 失败: %v", err)
	}
	if storageString(grant["acl_action"], "") != "set_acl" {
		t.Fatalf("SetACL 返回异常: %#v", grant)
	}

	uploaded, err := admin.Group().FS().Cp(ctx, granted, baseDir+"/granted.txt", writeOpts)
	if err != nil {
		t.Fatalf("admin 授权后写入失败: %v", err)
	}
	if uploaded.Node.Type != "file" {
		t.Fatalf("admin 授权后写入返回异常: %#v", uploaded)
	}
	downloadPath := filepath.Join(t.TempDir(), "downloaded.txt")
	downloaded, err := owner.Group().FS().Cp(ctx, baseDir+"/granted.txt", downloadPath, &GroupFSCpOptions{Force: true})
	if err != nil {
		t.Fatalf("owner 读取 admin 写入失败: %v", err)
	}
	if !bytes.Equal(downloaded.Download.Data, body) {
		t.Fatalf("owner 读取 admin 写入内容异常: %#v", downloaded)
	}

	revoked, err := owner.Group().FS().RemoveACL(ctx, baseDir, &GroupFSAclOptions{GranteeAID: "role:admin"})
	if err != nil {
		t.Fatalf("Group().FS().RemoveACL 失败: %v", err)
	}
	if storageString(revoked["acl_action"], "") != "remove_acl" {
		t.Fatalf("RemoveACL 返回异常: %#v", revoked)
	}
	if _, err := admin.Group().FS().Cp(ctx, after, baseDir+"/after.txt", writeOpts); err == nil {
		t.Fatalf("admin 在 role ACL 撤销后不应能写群自有区")
	}
}

func extractGroupIdentity(t *testing.T, result any) (string, string) {
	t.Helper()
	m := rpcResultMap(result)
	group := rpcResultMap(m["group"])
	groupID := strings.TrimSpace(stringFromAny(firstNonNil(group["group_id"], m["group_id"])))
	groupAID := strings.TrimSpace(stringFromAny(firstNonNil(group["group_aid"], m["group_aid"])))
	if groupID == "" || groupAID == "" {
		t.Fatalf("CreateGroup 未返回 group_id/group_aid: %#v", result)
	}
	return groupID, groupAID
}

func groupFSHasItem(items []GroupFSNodeView, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return true
		}
	}
	return false
}
