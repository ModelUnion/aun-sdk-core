package aun

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

type storageCallRecord struct {
	method string
	params map[string]any
}

type fakeStorageClient struct {
	aid         string
	calls       []storageCallRecord
	failMethods map[string]error
}

func (f *fakeStorageClient) AID() string {
	return f.aid
}

func (f *fakeStorageClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
	f.calls = append(f.calls, storageCallRecord{method: method, params: params})
	if f.failMethods != nil {
		if err := f.failMethods[method]; err != nil {
			return nil, err
		}
	}
	switch method {
	case "group.get":
		return map[string]any{"group": map[string]any{"group_id": params["group_id"], "group_aid": "team.agentid.pub"}}, nil
	case "storage.check_upload":
		return map[string]any{"inline": false}, nil
	case "storage.get_limits":
		return map[string]any{"max_inline_bytes": 64}, nil
	case "storage.put_object":
		return map[string]any{"type": "file", "path": params["object_key"], "object_key": params["object_key"], "owner_aid": params["owner_aid"], "size_bytes": 5}, nil
	case "storage.get_object":
		return map[string]any{"content": base64.StdEncoding.EncodeToString([]byte("hello"))}, nil
	case "storage.fs.list":
		return map[string]any{"nodes": []any{map[string]any{"type": "file", "path": "docs/a.txt", "name": "a.txt", "owner_aid": params["owner_aid"], "mode": "0644"}}}, nil
	case "storage.fs.stat":
		return map[string]any{"type": "file", "path": params["path"], "owner_aid": params["owner_aid"], "mode": "0644"}, nil
	case "storage.fs.lstat":
		return map[string]any{"type": "symlink", "path": params["path"], "target": "/docs/a.txt", "owner_aid": params["owner_aid"], "mode": "0777"}, nil
	case "storage.fs.mkdir":
		return map[string]any{"node": map[string]any{"type": "dir", "path": params["path"], "owner_aid": params["owner_aid"], "mode": "0755"}}, nil
	case "storage.fs.remove":
		return map[string]any{"removed_count": 1}, nil
	case "storage.fs.rename":
		return map[string]any{"node": map[string]any{"type": "file", "path": params["dst"], "owner_aid": params["owner_aid"], "mode": "0644"}}, nil
	case "storage.fs.copy":
		return map[string]any{"node": map[string]any{"type": "file", "path": params["dst"], "owner_aid": firstNonNil(params["dst_owner_aid"], params["owner_aid"]), "mode": "0644"}}, nil
	case "storage.fs.find":
		return map[string]any{"items": []any{map[string]any{"type": "file", "path": "docs/a.txt", "name": "a.txt", "owner_aid": params["owner_aid"], "size": 5}}}, nil
	case "storage.fs.df":
		return map[string]any{"owner_aid": params["owner_aid"], "bucket": params["bucket"], "used_bytes": 5, "quota_bytes": 10, "object_count": 1}, nil
	case "storage.fs.mount":
		mountSource := ""
		if volumeID := storageString(params["volume_id"], ""); volumeID != "" {
			mountSource = "volume:" + volumeID
		} else {
			mountSource = params["source_aid"].(string) + ":/" + params["source_path"].(string)
		}
		return map[string]any{"mount": map[string]any{"type": "mount", "path": params["mount_path"], "owner_aid": params["owner_aid"], "mount_source": mountSource, "mode": "0755"}}, nil
	case "storage.fs.approve":
		return map[string]any{"approved": true, "path": params["mount_path"]}, nil
	case "storage.fs.reject":
		return map[string]any{"rejected": true, "path": params["mount_path"]}, nil
	case "storage.fs.unmount":
		return map[string]any{"unmounted": true, "path": params["mount_path"], "mount_path": params["mount_path"], "owner_aid": params["owner_aid"], "bucket": params["bucket"]}, nil
	case "storage.create_symlink":
		return map[string]any{"symlink": map[string]any{"type": "symlink", "path": params["path"], "target": params["target"], "owner_aid": params["owner_aid"], "mode": "0777"}}, nil
	case "storage.readlink":
		return map[string]any{"symlink": map[string]any{"type": "symlink", "path": params["path"], "target": "/docs/a.txt", "owner_aid": params["owner_aid"], "mode": "0777"}}, nil
	case "storage.atomic_repoint":
		return map[string]any{"symlink": map[string]any{"type": "symlink", "path": params["path"], "target": params["new_target"], "owner_aid": params["owner_aid"], "mode": "0777"}}, nil
	case "storage.rename_symlink":
		return map[string]any{"ok": true, "symlink": map[string]any{"type": "symlink", "path": params["new_path"], "target": "/docs/b.txt", "owner_aid": params["owner_aid"], "mode": "0777"}}, nil
	case "storage.set_acl":
		return map[string]any{"acl_id": "acl-1", "grantee_aid": params["grantee_aid"], "perms": params["perms"]}, nil
	case "storage.check_access":
		return map[string]any{"allowed": true, "operation": params["operation"], "path": params["path"]}, nil
	case "storage.issue_token":
		return map[string]any{"token": "tok-secret", "token_id": "tok-1"}, nil
	case "storage.get_quota":
		return map[string]any{"owner_aid": params["owner_aid"], "quota_bytes": 10, "used_bytes": 4, "object_count": 1}, nil
	default:
		return map[string]any{"ok": true}, nil
	}
}

func TestStorageVFSWriteBytesUsesServerLimits(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)

	node, err := storage.WriteBytes(ctx, "/docs/a.txt", []byte("hello"), nil)
	if err != nil {
		t.Fatalf("WriteBytes 失败: %v", err)
	}
	if node.Type != "file" || node.Path != "/docs/a.txt" {
		t.Fatalf("NodeView 不正确: %#v", node)
	}
	want := []string{"storage.check_upload", "storage.get_limits", "storage.put_object"}
	for i, method := range want {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}
	if client.calls[2].params["owner_aid"] != "alice.agentid.pub" {
		t.Fatalf("owner_aid 未默认使用客户端 AID: %#v", client.calls[2].params)
	}
	if client.calls[2].params["expected_version"] != nil {
		t.Fatalf("nil ExpectedVersion 不应传入 RPC: %#v", client.calls[2].params)
	}
	if _, exists := client.calls[2].params["overwrite"]; exists {
		t.Fatalf("默认 Overwrite 不应传入 RPC: %#v", client.calls[2].params)
	}
	if _, exists := client.calls[2].params["metadata"]; exists {
		t.Fatalf("nil Metadata 不应传入 RPC: %#v", client.calls[2].params)
	}
}

func TestStorageVFSReadListStatForwardToken(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)

	content, err := storage.ReadBytes(ctx, "/docs/a.txt", &ReadOptions{Token: "tok"})
	if err != nil {
		t.Fatalf("ReadBytes 失败: %v", err)
	}
	if !bytes.Equal(content, []byte("hello")) {
		t.Fatalf("读取内容不正确: %q", string(content))
	}
	if _, err := storage.List(ctx, "/docs", &ListOptions{Token: "tok", Long: true}); err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	if _, err := storage.Stat(ctx, "/docs/a.txt", &StatOptions{Token: "tok"}); err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}

	want := []string{"storage.get_object", "storage.fs.list", "storage.fs.stat"}
	for i, method := range want {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
		if client.calls[i].params["token"] != "tok" {
			t.Fatalf("token 未透传: %#v", client.calls[i].params)
		}
	}
}

func TestStorageVFSReadBytesForwardsRangeOptions(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)

	content, err := storage.ReadBytes(ctx, "/docs/a.txt", &ReadOptions{Token: "tok", Offset: intPtr(1), Limit: intPtr(3)})
	if err != nil {
		t.Fatalf("ReadBytes 失败: %v", err)
	}
	if !bytes.Equal(content, []byte("hello")) {
		t.Fatalf("读取内容不正确: %q", string(content))
	}
	if len(client.calls) != 1 || client.calls[0].method != "storage.get_object" {
		t.Fatalf("调用不正确: %#v", client.calls)
	}
	params := client.calls[0].params
	if params["offset"] != 1 || params["limit"] != 3 || params["token"] != "tok" {
		t.Fatalf("range 参数未透传: %#v", params)
	}
}

func TestStorageVFSFSMutationsAndSymlinkContracts(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)
	expectedVersion := 7

	folder, err := storage.Mkdir(ctx, "/docs/new", &MkdirOptions{Parents: true})
	if err != nil {
		t.Fatalf("Mkdir 失败: %v", err)
	}
	removed, err := storage.Remove(ctx, "/docs/old", &RemoveOptions{Recursive: true})
	if err != nil {
		t.Fatalf("Remove 失败: %v", err)
	}
	renamed, err := storage.Rename(ctx, "/docs/a.txt", "/docs/b.txt", &RenameOptions{Overwrite: true, ExpectedVersion: &expectedVersion})
	if err != nil {
		t.Fatalf("Rename 失败: %v", err)
	}
	copied, err := storage.Copy(ctx, "/docs/b.txt", "/docs/c.txt", &CopyOptions{Overwrite: true, FollowSymlinks: true})
	if err != nil {
		t.Fatalf("Copy 失败: %v", err)
	}
	link, err := storage.Symlink(ctx, "/docs/a.txt", "/links/current.txt", &SymlinkOptions{Overwrite: true})
	if err != nil {
		t.Fatalf("Symlink 失败: %v", err)
	}
	readlink, err := storage.Readlink(ctx, "/links/current.txt", nil)
	if err != nil {
		t.Fatalf("Readlink 失败: %v", err)
	}
	repointed, err := storage.Repoint(ctx, "/links/current.txt", "/docs/b.txt", &RepointOptions{ExpectedVersion: &expectedVersion})
	if err != nil {
		t.Fatalf("Repoint 失败: %v", err)
	}
	renamedLink, err := storage.RenameSymlink(ctx, "/links/current.txt", "/links/latest.txt", &RenameSymlinkOptions{Overwrite: true, ExpectedVersion: &expectedVersion})
	if err != nil {
		t.Fatalf("RenameSymlink 失败: %v", err)
	}

	if folder.Type != "dir" || removed.RemovedCount != 1 || renamed.Path != "/docs/b.txt" || copied.Path != "/docs/c.txt" {
		t.Fatalf("fs mutation 返回异常: folder=%#v removed=%#v renamed=%#v copied=%#v", folder, removed, renamed, copied)
	}
	if link.Type != "symlink" || link.Target != "/docs/a.txt" || readlink.Target != "/docs/a.txt" || repointed.Target != "/docs/b.txt" || renamedLink.Path != "/links/latest.txt" {
		t.Fatalf("symlink 返回异常: link=%#v readlink=%#v repointed=%#v renamed=%#v", link, readlink, repointed, renamedLink)
	}
	want := []string{
		"storage.fs.mkdir",
		"storage.fs.remove",
		"storage.fs.rename",
		"storage.fs.copy",
		"storage.create_symlink",
		"storage.readlink",
		"storage.atomic_repoint",
		"storage.rename_symlink",
	}
	for i, method := range want {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}
	if client.calls[2].params["expected_version"] != 7 || client.calls[6].params["expected_version"] != 7 {
		t.Fatalf("expected_version 未正确透传: rename=%#v repoint=%#v", client.calls[2].params, client.calls[6].params)
	}
	if client.calls[7].params["new_path"] != "links/latest.txt" || client.calls[7].params["overwrite"] != true || client.calls[7].params["expected_version"] != 7 {
		t.Fatalf("rename_symlink 参数不正确: %#v", client.calls[7].params)
	}
	if client.calls[3].params["follow_symlinks"] != true {
		t.Fatalf("follow_symlinks 未正确透传: %#v", client.calls[3].params)
	}
}

func TestStorageVFSCopySupportsDstOwner(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "bob.agentid.pub"}
	storage := NewStorageVFS(client)

	copied, err := storage.Copy(ctx, "/docs/a.txt", "/inbox/a.txt", &CopyOptions{Owner: "alice.agentid.pub", DstOwner: "bob.agentid.pub"})
	if err != nil {
		t.Fatalf("Copy 失败: %v", err)
	}
	if copied.Owner != "bob.agentid.pub" {
		t.Fatalf("目标 owner 不正确: %#v", copied)
	}
	if client.calls[0].params["owner_aid"] != "alice.agentid.pub" || client.calls[0].params["dst_owner_aid"] != "bob.agentid.pub" {
		t.Fatalf("跨 owner copy 参数不正确: %#v", client.calls[0].params)
	}
}

func TestStorageVFSFindAndDFContracts(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)

	nodes, err := storage.Find(ctx, "/docs", &FindOptions{
		Name:     "*.txt",
		NodeType: "f",
		Size:     "+3",
		MTime:    "-7",
		PageSize: 50,
		Token:    "tok",
	})
	if err != nil {
		t.Fatalf("Find 失败: %v", err)
	}
	usage, err := storage.DF(ctx, nil)
	if err != nil {
		t.Fatalf("DF 失败: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Path != "/docs/a.txt" {
		t.Fatalf("Find 返回异常: %#v", nodes)
	}
	if usage.UsedBytes != 5 || usage.AvailBytes != 5 {
		t.Fatalf("DF 返回异常: %#v", usage)
	}
	if client.calls[0].method != "storage.fs.find" || client.calls[1].method != "storage.fs.df" {
		t.Fatalf("RPC 方法不正确: %#v", client.calls)
	}
	findParams := client.calls[0].params
	if findParams["path"] != "docs" || findParams["name"] != "*.txt" || findParams["type"] != "f" || findParams["size"] != "+3" || findParams["mtime"] != "-7" || findParams["page_size"] != 50 || findParams["token"] != "tok" {
		t.Fatalf("Find 参数不正确: %#v", findParams)
	}
}

func TestStorageVFSAclTokenAndUsage(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)

	maxUses := 2
	if _, err := storage.SetACL(ctx, "/docs", SetACLOptions{GranteeAID: "bob.agentid.pub", Perms: "r", MaxUses: &maxUses}); err != nil {
		t.Fatalf("SetACL 失败: %v", err)
	}
	if _, err := storage.SetVisibility(ctx, "/docs/a.txt", VisibilityOptions{Visibility: "private", AllowRoles: []string{"admin"}}); err != nil {
		t.Fatalf("SetVisibility 失败: %v", err)
	}
	maxReads := 1
	if _, err := storage.IssueToken(ctx, "/docs/a.txt", IssueTokenOptions{MaxReads: &maxReads}); err != nil {
		t.Fatalf("IssueToken 失败: %v", err)
	}
	access, err := storage.CheckAccess(ctx, "/docs/a.txt", &CheckAccessOptions{Operation: "read"})
	if err != nil {
		t.Fatalf("CheckAccess 失败: %v", err)
	}
	usage, err := storage.GetUsage(ctx, nil)
	if err != nil {
		t.Fatalf("GetUsage 失败: %v", err)
	}
	if access["allowed"] != true {
		t.Fatalf("CheckAccess 返回异常: %#v", access)
	}
	if usage.AvailBytes != 6 {
		t.Fatalf("AvailBytes 不正确: %d", usage.AvailBytes)
	}
	if client.calls[0].params["grantee_aid"] != "bob.agentid.pub" || client.calls[0].params["max_uses"] != 2 {
		t.Fatalf("ACL 参数不正确: %#v", client.calls[0].params)
	}
	if client.calls[1].method != "storage.set_visibility" || client.calls[1].params["allow_roles"] == nil {
		t.Fatalf("visibility allow_roles 参数不正确: %#v", client.calls[1])
	}
	if client.calls[2].params["max_reads"] != 1 {
		t.Fatalf("token 参数不正确: %#v", client.calls[2].params)
	}
	if client.calls[3].method != "storage.check_access" || client.calls[3].params["operation"] != "read" || client.calls[3].params["follow_symlinks"] != true {
		t.Fatalf("check_access 参数不正确: %#v", client.calls[3])
	}
}

func TestStorageVFSMountUnmountContracts(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)
	expiresAt := int64(1893456000)

	mounted, err := storage.Mount(ctx, "/memberdata/alice", &MountOptions{
		Owner:           "g-team.agentid.pub",
		SourceAID:       "alice.agentid.pub",
		SourcePath:      "/group-data/g-team",
		Readonly:        false,
		ExpiresAt:       &expiresAt,
		RequireApproval: true,
	})
	if err != nil {
		t.Fatalf("Mount 失败: %v", err)
	}
	approved, err := storage.ApproveMount(ctx, "/memberdata/alice", &MountReviewOptions{Owner: "g-team.agentid.pub"})
	if err != nil {
		t.Fatalf("ApproveMount 失败: %v", err)
	}
	rejected, err := storage.RejectMount(ctx, "/memberdata/alice", &MountReviewOptions{Owner: "g-team.agentid.pub"})
	if err != nil {
		t.Fatalf("RejectMount 失败: %v", err)
	}
	unmounted, err := storage.Unmount(ctx, "/memberdata/alice", &UnmountOptions{Owner: "g-team.agentid.pub"})
	if err != nil {
		t.Fatalf("Unmount 失败: %v", err)
	}

	if mounted.Type != "mount" || mounted.Path != "/memberdata/alice" || mounted.MountSource != "alice.agentid.pub:/group-data/g-team" {
		t.Fatalf("Mount NodeView 异常: %#v", mounted)
	}
	if approved["approved"] != true || rejected["rejected"] != true {
		t.Fatalf("审批返回异常: approved=%#v rejected=%#v", approved, rejected)
	}
	if !unmounted.Unmounted || unmounted.MountPath != "/memberdata/alice" || unmounted.Owner != "g-team.agentid.pub" {
		t.Fatalf("UnmountResult 异常: %#v", unmounted)
	}
	if client.calls[0].method != "storage.fs.mount" || client.calls[1].method != "storage.fs.approve" || client.calls[2].method != "storage.fs.reject" || client.calls[3].method != "storage.fs.unmount" {
		t.Fatalf("mount/unmount RPC 方法不正确: %#v", client.calls)
	}
	mountParams := client.calls[0].params
	if mountParams["owner_aid"] != "g-team.agentid.pub" || mountParams["mount_path"] != "memberdata/alice" {
		t.Fatalf("挂载点参数不正确: %#v", mountParams)
	}
	if mountParams["source_aid"] != "alice.agentid.pub" || mountParams["source_bucket"] != "default" || mountParams["source_path"] != "group-data/g-team" {
		t.Fatalf("source 参数不正确: %#v", mountParams)
	}
	if mountParams["readonly"] != false || mountParams["expires_at"] != expiresAt || mountParams["require_approval"] != true {
		t.Fatalf("readonly/expires_at 未正确透传: %#v", mountParams)
	}
	if client.calls[1].params["mount_path"] != "memberdata/alice" || client.calls[2].params["mount_path"] != "memberdata/alice" || client.calls[3].params["mount_path"] != "memberdata/alice" {
		t.Fatalf("review/unmount mount_path 不正确: approve=%#v reject=%#v unmount=%#v", client.calls[1].params, client.calls[2].params, client.calls[3].params)
	}
}

func TestStorageVFSMountVolumeContract(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)

	node, err := storage.MountVolume(ctx, "vol-1", "/mnt/vol-1", &MountVolumeOptions{Owner: "alice.agentid.pub", Readonly: true, SourcePath: "/volumes/custom"})
	if err != nil {
		t.Fatalf("MountVolume 失败: %v", err)
	}
	if node.Type != "mount" || node.Path != "/mnt/vol-1" || node.MountSource != "volume:vol-1" {
		t.Fatalf("MountVolume NodeView 异常: %#v", node)
	}
	if len(client.calls) != 1 || client.calls[0].method != "storage.fs.mount" {
		t.Fatalf("RPC 方法不正确: %#v", client.calls)
	}
	params := client.calls[0].params
	if params["owner_aid"] != "alice.agentid.pub" || params["mount_path"] != "mnt/vol-1" || params["volume_id"] != "vol-1" || params["readonly"] != true || params["source_path"] != "volumes/custom" {
		t.Fatalf("MountVolume 参数不正确: %#v", params)
	}
}

func TestAUNClientStorageEntryIsLazy(t *testing.T) {
	client := NewAUNClient(nil)
	if client.Storage() == nil {
		t.Fatal("Storage() 返回 nil")
	}
	if client.Storage() != client.Storage() {
		t.Fatal("Storage() 应返回同一个惰性实例")
	}
}
