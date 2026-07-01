package aun

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	downloadURL string
	downloadSHA string
	checkUpload map[string]any
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
	case "group.get_info":
		return map[string]any{"group": map[string]any{"group_id": params["group_id"], "group_aid": "team.agentid.pub"}}, nil
	case "storage.check_upload":
		if f.checkUpload != nil {
			return f.checkUpload, nil
		}
		return map[string]any{"inline": true, "within_limit": true, "target_exists": false, "skip_upload": false}, nil
	case "storage.get_limits":
		return map[string]any{"max_inline_bytes": 64}, nil
	case "storage.put_object":
		return map[string]any{"type": "file", "path": params["object_key"], "object_key": params["object_key"], "owner_aid": params["owner_aid"], "size_bytes": 5}, nil
	case "storage.get_object":
		return map[string]any{"content": base64.StdEncoding.EncodeToString([]byte("hello"))}, nil
	case "storage.create_download_ticket":
		return map[string]any{"download_url": f.downloadURL, "sha256": f.downloadSHA, "size": 5}, nil
	case "storage.fs.list":
		return map[string]any{"nodes": []any{map[string]any{"type": "file", "path": "docs/a.txt", "name": "a.txt", "owner_aid": params["owner_aid"], "mode": "0644"}}}, nil
	case "storage.fs.stat":
		return map[string]any{"type": "file", "path": params["path"], "owner_aid": params["owner_aid"], "mode": "0644"}, nil
	case "storage.fs.lstat":
		return map[string]any{"type": "symlink", "path": params["path"], "target": "/docs/a.txt", "owner_aid": params["owner_aid"], "mode": "0777"}, nil
	case "storage.fs.mkdir":
		return map[string]any{"node": map[string]any{"type": "dir", "path": params["path"], "owner_aid": params["owner_aid"], "mode": "0755"}}, nil
	case "storage.fs.touch":
		return map[string]any{"node": map[string]any{"type": "file", "path": params["path"], "owner_aid": params["owner_aid"], "size": 0, "mode": "0644"}}, nil
	case "storage.fs.remove":
		return map[string]any{"removed_count": 1}, nil
	case "storage.fs.rename":
		return map[string]any{"node": map[string]any{"type": "file", "path": params["dst"], "owner_aid": params["owner_aid"], "mode": "0644"}}, nil
	case "storage.fs.copy":
		return map[string]any{"node": map[string]any{"type": "file", "path": params["dst"], "owner_aid": firstNonNil(params["dst_owner_aid"], params["owner_aid"]), "mode": "0644"}}, nil
	case "storage.fs.find":
		if params["name"] != nil || params["type"] != nil || params["size"] != nil || params["mtime"] != nil {
			return map[string]any{"items": []any{map[string]any{"type": "file", "path": "docs/a.txt", "name": "a.txt", "owner_aid": params["owner_aid"], "size": 5}}}, nil
		}
		return map[string]any{"items": []any{
			map[string]any{"type": "file", "path": "docs/a.txt", "name": "a.txt", "owner_aid": params["owner_aid"], "size": 5},
			map[string]any{"type": "dir", "path": "docs/sub", "name": "sub", "owner_aid": params["owner_aid"]},
			map[string]any{"type": "file", "path": "docs/sub/b.txt", "name": "b.txt", "owner_aid": params["owner_aid"], "size": 7},
			map[string]any{"type": "symlink", "path": "docs/current.txt", "name": "current.txt", "owner_aid": params["owner_aid"]},
		}}, nil
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
	case "collab.ls-files":
		return []map[string]any{{"doc": "a.md", "version": 1}}, nil
	case "collab.log":
		return []map[string]any{{"version": 1, "author": f.aid}}, nil
	case "collab.ls-remote":
		return []map[string]any{{"collab_root": "g.aid.com:/proj"}}, nil
	case "collab.reflog":
		return []map[string]any{{"action": "commit", "version": 1}}, nil
	case "collab.tag.list":
		return []map[string]any{{"version": "1.0.0"}}, nil
	default:
		return map[string]any{"ok": true}, nil
	}
}

func TestStorageVFSWriteBytesRefusesExistingTargetUnlessOverwrite(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{
		aid: "alice.agentid.pub",
		checkUpload: map[string]any{
			"inline":        true,
			"within_limit":  true,
			"target_exists": true,
			"target":        map[string]any{"path": "docs/a.txt", "version": 3, "size_bytes": 5, "sha256": "old"},
		},
	}
	storage := NewStorageVFS(client)

	_, err := storage.WriteBytes(ctx, "/docs/a.txt", []byte("hello"), nil)
	var existsErr *StorageExistsError
	if !errors.As(err, &existsErr) {
		t.Fatalf("默认覆盖已有目标应返回 StorageExistsError，got: %T %v", err, err)
	}
	if len(client.calls) != 1 || client.calls[0].method != "storage.check_upload" {
		t.Fatalf("默认拒绝覆盖时不应继续上传: %#v", client.calls)
	}

	overwrite := true
	if _, err := storage.WriteBytes(ctx, "/docs/a.txt", []byte("hello"), &WriteBytesOptions{Overwrite: &overwrite}); err != nil {
		t.Fatalf("Overwrite=true 应允许上传: %v", err)
	}
	if len(client.calls) != 3 || client.calls[2].method != "storage.put_object" || client.calls[2].params["overwrite"] != true {
		t.Fatalf("Overwrite=true 未透传到 put_object: %#v", client.calls)
	}
}

func TestStorageVFSWriteBytesUsesCheckUploadInline(t *testing.T) {
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
	want := []string{"storage.check_upload", "storage.put_object"}
	for i, method := range want {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}
	if client.calls[1].params["owner_aid"] != "alice.agentid.pub" {
		t.Fatalf("owner_aid 未默认使用客户端 AID: %#v", client.calls[1].params)
	}
	if client.calls[1].params["expected_version"] != nil {
		t.Fatalf("nil ExpectedVersion 不应传入 RPC: %#v", client.calls[1].params)
	}
	if client.calls[1].params["overwrite"] != false {
		t.Fatalf("默认 Overwrite 应为 false: %#v", client.calls[1].params)
	}
	if _, exists := client.calls[1].params["metadata"]; exists {
		t.Fatalf("nil Metadata 不应传入 RPC: %#v", client.calls[1].params)
	}
}

func TestStorageVFSUploadAndDownloadFile(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("下载 HTTP 方法不正确: %s", r.Method)
		}
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	client := &fakeStorageClient{
		aid:         "alice.agentid.pub",
		downloadURL: server.URL,
		downloadSHA: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
	}
	storage := NewStorageVFS(client)
	dir := t.TempDir()
	localUpload := filepath.Join(dir, "upload.txt")
	localDownload := filepath.Join(dir, "download.txt")
	if err := os.WriteFile(localUpload, []byte("hello"), 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}

	uploaded, err := storage.UploadFile(ctx, localUpload, "/docs/upload.txt", &WriteBytesOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("UploadFile 失败: %v", err)
	}
	downloaded, err := storage.DownloadFile(ctx, "/docs/a.txt", localDownload, &ReadOptions{Token: "tok"})
	if err != nil {
		t.Fatalf("DownloadFile 失败: %v", err)
	}
	body, err := os.ReadFile(localDownload)
	if err != nil {
		t.Fatalf("读取下载文件失败: %v", err)
	}

	if uploaded.Path != "/docs/upload.txt" || !bytes.Equal(body, []byte("hello")) {
		t.Fatalf("上传/下载结果不正确: uploaded=%#v body=%q", uploaded, string(body))
	}
	if downloaded.Path != "/docs/a.txt" || downloaded.LocalPath != localDownload || downloaded.Size != 5 || downloaded.Verified != true {
		t.Fatalf("DownloadResult 不正确: %#v", downloaded)
	}
	if len(downloaded.Data) != 0 {
		t.Fatalf("DownloadFile 写入本地文件时不应在结果中保留内存数据: %d bytes", len(downloaded.Data))
	}
	if client.calls[1].method != "storage.put_object" || client.calls[1].params["content_type"] != "text/plain" {
		t.Fatalf("UploadFile 未正确复用 WriteBytes: %#v", client.calls)
	}
	if client.calls[2].method != "storage.create_download_ticket" || client.calls[2].params["token"] != "tok" {
		t.Fatalf("DownloadFile 未正确创建下载 ticket: %#v", client.calls)
	}
}

func TestStorageVFSDownloadFileRefusesExistingLocalTargetUnlessOverwrite(t *testing.T) {
	ctx := context.Background()
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	client := &fakeStorageClient{
		aid:         "alice.agentid.pub",
		downloadURL: server.URL,
		downloadSHA: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
	}
	storage := NewStorageVFS(client)
	dir := t.TempDir()
	localDownload := filepath.Join(dir, "download.txt")
	if err := os.WriteFile(localDownload, []byte("old"), 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}

	_, err := storage.DownloadFile(ctx, "/docs/a.txt", localDownload, nil)
	var existsErr *StorageExistsError
	if !errors.As(err, &existsErr) {
		t.Fatalf("默认覆盖已有本地文件应返回 StorageExistsError，got: %T %v", err, err)
	}
	body, _ := os.ReadFile(localDownload)
	if string(body) != "old" || hits != 0 {
		t.Fatalf("默认拒绝覆盖时不应下载或改写: body=%q hits=%d", string(body), hits)
	}

	overwrite := true
	if _, err := storage.DownloadFile(ctx, "/docs/a.txt", localDownload, &ReadOptions{Overwrite: &overwrite}); err != nil {
		t.Fatalf("Overwrite=true 下载失败: %v", err)
	}
	body, _ = os.ReadFile(localDownload)
	if string(body) != "hello" || hits != 1 {
		t.Fatalf("Overwrite=true 应覆盖本地文件: body=%q hits=%d", string(body), hits)
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
	mtime := int64(1700000000)
	touched, err := storage.Touch(ctx, "/docs/empty.txt", &TouchOptions{Parents: true, NoCreate: true, MTime: &mtime, FollowSymlinks: true})
	if err != nil {
		t.Fatalf("Touch 失败: %v", err)
	}
	removed, err := storage.Remove(ctx, "/docs/old", &RemoveOptions{Recursive: true})
	if err != nil {
		t.Fatalf("Remove 失败: %v", err)
	}
	renamed, err := storage.Rename(ctx, "/docs/a.txt", "/docs/b.txt", &RenameOptions{Overwrite: true, ExpectedVersion: &expectedVersion})
	if err != nil {
		t.Fatalf("Rename 失败: %v", err)
	}
	copied, err := storage.Copy(ctx, "/docs/b.txt", "/docs/c.txt", &CopyOptions{Overwrite: true, FollowSymlinks: true, Recursive: true})
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

	if folder.Type != "dir" || touched.Path != "/docs/empty.txt" || touched.Size != 0 || removed.RemovedCount != 1 || renamed.Path != "/docs/b.txt" || copied.Path != "/docs/c.txt" {
		t.Fatalf("fs mutation 返回异常: folder=%#v touched=%#v removed=%#v renamed=%#v copied=%#v", folder, touched, removed, renamed, copied)
	}
	if link.Type != "symlink" || link.Target != "/docs/a.txt" || readlink.Target != "/docs/a.txt" || repointed.Target != "/docs/b.txt" || renamedLink.Path != "/links/latest.txt" {
		t.Fatalf("symlink 返回异常: link=%#v readlink=%#v repointed=%#v renamed=%#v", link, readlink, repointed, renamedLink)
	}
	want := []string{
		"storage.fs.mkdir",
		"storage.fs.touch",
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
	if client.calls[1].params["path"] != "docs/empty.txt" || client.calls[1].params["parents"] != true || client.calls[1].params["no_create"] != true || client.calls[1].params["mtime"] != mtime || client.calls[1].params["follow_symlinks"] != true {
		t.Fatalf("touch 参数不正确: %#v", client.calls[1].params)
	}
	if client.calls[3].params["expected_version"] != 7 || client.calls[7].params["expected_version"] != 7 {
		t.Fatalf("expected_version 未正确透传: rename=%#v repoint=%#v", client.calls[3].params, client.calls[7].params)
	}
	if client.calls[8].params["new_path"] != "links/latest.txt" || client.calls[8].params["overwrite"] != true || client.calls[8].params["expected_version"] != 7 {
		t.Fatalf("rename_symlink 参数不正确: %#v", client.calls[8].params)
	}
	if client.calls[4].params["follow_symlinks"] != true || client.calls[4].params["recursive"] != true {
		t.Fatalf("copy 参数未正确透传: %#v", client.calls[4].params)
	}
}

func TestStorageVFSCopySupportsDstOwner(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "bob1.agentid.pub"}
	storage := NewStorageVFS(client)

	copied, err := storage.Copy(ctx, "/docs/a.txt", "/inbox/a.txt", &CopyOptions{Owner: "alice.agentid.pub", DstOwner: "bob1.agentid.pub"})
	if err != nil {
		t.Fatalf("Copy 失败: %v", err)
	}
	if copied.Owner != "bob1.agentid.pub" {
		t.Fatalf("目标 owner 不正确: %#v", copied)
	}
	if client.calls[0].params["owner_aid"] != "alice.agentid.pub" || client.calls[0].params["dst_owner_aid"] != "bob1.agentid.pub" {
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
	maxDepth := 1
	du, err := storage.Du(ctx, "/docs", &DuOptions{MaxDepth: &maxDepth, PageSize: 25, Token: "tok"})
	if err != nil {
		t.Fatalf("Du 失败: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Path != "/docs/a.txt" {
		t.Fatalf("Find 返回异常: %#v", nodes)
	}
	if usage.UsedBytes != 5 || usage.AvailBytes != 5 {
		t.Fatalf("DF 返回异常: %#v", usage)
	}
	if du["path"] != "/docs" || du["size_bytes"] != int64(5) || du["file_count"] != 1 || du["dir_count"] != 1 || du["symlink_count"] != 1 || du["max_depth"] != 1 || du["truncated"] != true {
		t.Fatalf("Du 聚合结果不正确: %#v", du)
	}
	if client.calls[0].method != "storage.fs.find" || client.calls[1].method != "storage.fs.df" || client.calls[2].method != "storage.fs.find" {
		t.Fatalf("RPC 方法不正确: %#v", client.calls)
	}
	findParams := client.calls[0].params
	if findParams["path"] != "docs" || findParams["name"] != "*.txt" || findParams["type"] != "f" || findParams["size"] != "+3" || findParams["mtime"] != "-7" || findParams["page_size"] != 50 || findParams["token"] != "tok" {
		t.Fatalf("Find 参数不正确: %#v", findParams)
	}
	duParams := client.calls[2].params
	if duParams["path"] != "docs" || duParams["page"] != 1 || duParams["page_size"] != 25 || duParams["token"] != "tok" {
		t.Fatalf("Du Find 参数不正确: %#v", duParams)
	}
}

func TestStorageVFSAclTokenAndUsage(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	storage := NewStorageVFS(client)

	maxUses := 2
	if _, err := storage.SetACL(ctx, "/docs", SetACLOptions{GranteeAID: "bob1.agentid.pub", Perms: "r", MaxUses: &maxUses}); err != nil {
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
	if client.calls[0].params["grantee_aid"] != "bob1.agentid.pub" || client.calls[0].params["max_uses"] != 2 {
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
	approved, err := storage.ApproveMount(ctx, "/memberdata/alice", &MountReviewOptions{Owner: "g-team.agentid.pub", RequestID: "req-1"})
	if err != nil {
		t.Fatalf("ApproveMount 失败: %v", err)
	}
	rejected, err := storage.RejectMount(ctx, "/memberdata/alice", &MountReviewOptions{Owner: "g-team.agentid.pub", RequestID: "req-2"})
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
	if client.calls[1].params["request_id"] != "req-1" || client.calls[2].params["request_id"] != "req-2" {
		t.Fatalf("review request_id 未正确透传: approve=%#v reject=%#v", client.calls[1].params, client.calls[2].params)
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

func TestStorageHeadersFromAny_MapStringInterface(t *testing.T) {
	// JSON unmarshal 产出 map[string]interface{} — 必须正确转换
	raw := map[string]any{
		"Content-Type": "application/octet-stream",
		"X-Custom":     "value",
		"X-Numeric":    42, // 非 string 值应被跳过或转为字符串
	}
	result := storageHeadersFromAny(raw)
	if result["Content-Type"] != "application/octet-stream" {
		t.Fatalf("Content-Type 丢失: %#v", result)
	}
	if result["X-Custom"] != "value" {
		t.Fatalf("X-Custom 丢失: %#v", result)
	}
}

func TestStorageHeadersFromAny_MapStringString(t *testing.T) {
	// 已经是 map[string]string 的情况
	raw := map[string]string{"Content-Type": "text/plain"}
	result := storageHeadersFromAny(raw)
	if result["Content-Type"] != "text/plain" {
		t.Fatalf("直接 map[string]string 未正确传递: %#v", result)
	}
}

func TestStorageHeadersFromAny_Nil(t *testing.T) {
	result := storageHeadersFromAny(nil)
	if result == nil || len(result) != 0 {
		t.Fatalf("nil 输入应返回空 map: %#v", result)
	}
}

func TestMapStorageError_ClassifiesNotFound(t *testing.T) {
	err := &RPCError{Code: -32008, Message: "object not found"}
	mapped := MapStorageError(err, "/docs/a.txt")
	var nf *StorageNotFoundError
	if !errorAs(mapped, &nf) {
		t.Fatalf("code -32008 应映射为 StorageNotFoundError，got: %T", mapped)
	}
	if nf.Path != "/docs/a.txt" {
		t.Fatalf("Path 不正确: %s", nf.Path)
	}
}

func TestMapStorageError_ClassifiesConflict(t *testing.T) {
	err := &RPCError{Code: -32009, Message: "version conflict"}
	mapped := MapStorageError(err, "/docs/a.txt")
	var cf *StorageConflictError
	if !errorAs(mapped, &cf) {
		t.Fatalf("code -32009 应映射为 StorageConflictError，got: %T", mapped)
	}
}

func TestMapStorageError_ClassifiesAccessDenied(t *testing.T) {
	err := &RPCError{Code: -32004, Message: "permission denied"}
	mapped := MapStorageError(err, "/docs/a.txt")
	var ad *StorageAccessDeniedError
	if !errorAs(mapped, &ad) {
		t.Fatalf("code -32004 应映射为 StorageAccessDeniedError，got: %T", mapped)
	}
}

func TestMapStorageError_ClassifiesQuota(t *testing.T) {
	err := &RPCError{Code: -32099, Message: "quota exceeded"}
	mapped := MapStorageError(err, "/docs/a.txt")
	var qe *StorageQuotaError
	if !errorAs(mapped, &qe) {
		t.Fatalf("quota 消息应映射为 StorageQuotaError，got: %T", mapped)
	}
}

func TestMapStorageError_ClassifiesLoop(t *testing.T) {
	err := &RPCError{Code: -32031, Message: "too many symlink hops"}
	mapped := MapStorageError(err, "/link")
	var le *StorageLoopError
	if !errorAs(mapped, &le) {
		t.Fatalf("code -32031 应映射为 StorageLoopError，got: %T", mapped)
	}
}

func TestMapStorageError_GenericFallback(t *testing.T) {
	err := fmt.Errorf("some random error")
	mapped := MapStorageError(err, "/docs/a.txt")
	var se *StorageError
	if !errorAs(mapped, &se) {
		t.Fatalf("通用错误应映射为 StorageError，got: %T", mapped)
	}
}

// RPCError 模拟 SDK 中从服务端返回的错误
type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string  { return e.Message }
func (e *RPCError) ErrorCode() int { return e.Code }
func (e *RPCError) ErrorData() any { return nil }

func errorAs(err error, target any) bool {
	return errors.As(err, target)
}
