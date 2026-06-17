package aun

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGroupFSRemotePathDetectionKeepsWindowsPathsLocal(t *testing.T) {
	if !IsGroupRemotePath("g-team.agentid.pub:/docs/a.md") {
		t.Fatal("group aid 路径应识别为 group remote")
	}
	if !IsGroupRemotePath("https://g-team.agentid.pub/docs/a.md") {
		t.Fatal("https 路径应识别为 group remote")
	}
	if IsGroupRemotePath("D:/tmp/a.md") || IsGroupRemotePath("D:\\tmp\\a.md") {
		t.Fatal("Windows drive 路径不能误判为 group remote")
	}
	if IsGroupRemotePath("local:/tmp/a.md") || IsGroupRemotePath("relative/a.md") || IsGroupRemotePath("/tmp/a.md") {
		t.Fatal("普通本地路径不能误判为 group remote")
	}
}

func TestGroupFSEntryIsCachedAndExposesOnlyPOSIXMainMethods(t *testing.T) {
	client := NewAUNClientEmpty()
	defer func() { _ = client.Close() }()

	if first, second := client.Group().FS(), client.Group().FS(); first == nil || first != second {
		t.Fatal("Group().FS() 应惰性缓存同一实例")
	}

	fsType := reflect.TypeOf(client.Group().FS())
	for _, method := range []string{"Ls", "Find", "Stat", "Lstat", "Mkdir", "Rm", "Cp", "Mv", "Df", "Mount", "Umount"} {
		if _, ok := fsType.MethodByName(method); !ok {
			t.Fatalf("GroupFS 缺少 POSIX 方法: %s", method)
		}
	}
	for _, method := range []string{"Read", "Write", "Put", "Get"} {
		if _, ok := fsType.MethodByName(method); ok {
			t.Fatalf("GroupFS 不应暴露主入口方法: %s", method)
		}
	}
}

func TestGroupFSPosixMethodsCallGroupFSRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	fs := NewGroupFSVFS(client)

	if _, err := fs.Ls(ctx, "g-team.agentid.pub:/docs", &GroupFSListOptions{Page: 1, Size: 20}); err != nil {
		t.Fatalf("Ls 失败: %v", err)
	}
	if _, err := fs.Find(ctx, "g-team.agentid.pub:/docs", &GroupFSFindOptions{Pattern: "*.md"}); err != nil {
		t.Fatalf("Find 失败: %v", err)
	}
	if _, err := fs.Stat(ctx, "g-team.agentid.pub:/docs/a.md", nil); err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	if _, err := fs.Lstat(ctx, "g-team.agentid.pub:/docs/link", nil); err != nil {
		t.Fatalf("Lstat 失败: %v", err)
	}
	if _, err := fs.Mkdir(ctx, "g-team.agentid.pub:/docs/new", &GroupFSMkdirOptions{Parents: true}); err != nil {
		t.Fatalf("Mkdir 失败: %v", err)
	}
	if _, err := fs.Rm(ctx, "g-team.agentid.pub:/docs/old.md", &GroupFSRmOptions{Force: true}); err != nil {
		t.Fatalf("Rm 失败: %v", err)
	}
	if _, err := fs.Cp(ctx, "g-team.agentid.pub:/docs/a.md", "g-team.agentid.pub:/docs/b.md", &GroupFSCpOptions{Force: true}); err != nil {
		t.Fatalf("Cp 失败: %v", err)
	}
	if _, err := fs.Mv(ctx, "g-team.agentid.pub:/docs/b.md", "g-team.agentid.pub:/docs/c.md", nil); err != nil {
		t.Fatalf("Mv 失败: %v", err)
	}
	if _, err := fs.Df(ctx, "g-team.agentid.pub:/", nil); err != nil {
		t.Fatalf("Df 失败: %v", err)
	}
	if _, err := fs.Mount(ctx, "g-team.agentid.pub:/memberdata/alice.agentid.pub", nil); err != nil {
		t.Fatalf("Mount 失败: %v", err)
	}
	if _, err := fs.Umount(ctx, "g-team.agentid.pub:/memberdata/alice.agentid.pub", nil); err != nil {
		t.Fatalf("Umount 失败: %v", err)
	}

	wantMethods := []string{
		"group.fs.ls",
		"group.fs.find",
		"group.fs.stat",
		"group.fs.lstat",
		"group.fs.mkdir",
		"group.fs.rm",
		"group.fs.cp",
		"group.fs.mv",
		"group.fs.df",
		"group.fs.mount",
		"group.fs.umount",
	}
	if len(client.calls) != len(wantMethods) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(wantMethods), client.calls)
	}
	for i, method := range wantMethods {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}
	if client.calls[0].params["path"] != "g-team.agentid.pub:/docs" || client.calls[0].params["page"] != 1 || client.calls[0].params["size"] != 20 {
		t.Fatalf("Ls 参数不正确: %#v", client.calls[0].params)
	}
	if client.calls[4].params["path"] != "g-team.agentid.pub:/docs/new" || client.calls[4].params["parents"] != true {
		t.Fatalf("Mkdir 参数不正确: %#v", client.calls[4].params)
	}
	if client.calls[6].params["src"] != "g-team.agentid.pub:/docs/a.md" || client.calls[6].params["dst"] != "g-team.agentid.pub:/docs/b.md" || client.calls[6].params["force"] != true {
		t.Fatalf("Cp 参数不正确: %#v", client.calls[6].params)
	}
}

func TestGroupFSDoesNotMapMemberdataToGroupdataInSDK(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	fs := NewGroupFSVFS(client)

	if _, err := fs.Stat(ctx, "g-team.agentid.pub:/memberdata/me/logs/a.md", nil); err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}

	if len(client.calls) != 1 || client.calls[0].method != "group.fs.stat" {
		t.Fatalf("调用不正确: %#v", client.calls)
	}
	if client.calls[0].params["path"] != "g-team.agentid.pub:/memberdata/me/logs/a.md" {
		t.Fatalf("memberdata 路径未原样传递: %#v", client.calls[0].params)
	}
	if strings.Contains(fmt.Sprintf("%#v", client.calls), "groupdata") {
		t.Fatalf("Go SDK 不应新增真实 groupdata 映射: %#v", client.calls)
	}
}

func TestGroupFSCpLocalToGroupUsesUploadControlPlane(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("上传 HTTP 方法不正确: %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "text/markdown" {
			t.Fatalf("Content-Type 不正确: %s", got)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	dir := t.TempDir()
	localPath := filepath.Join(dir, "a.md")
	data := []byte("hello group")
	if err := os.WriteFile(localPath, data, 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	digest := sha256.Sum256(data)
	wantSHA := fmt.Sprintf("%x", digest[:])

	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.check_upload":          map[string]any{"target_exists": false, "within_limit": true},
			"group.fs.create_upload_session": map[string]any{"upload_url": server.URL, "session_id": "s1", "headers": map[string]any{"Content-Type": "text/markdown"}},
			"group.fs.complete_upload":       map[string]any{"type": "file", "path": "g-team.agentid.pub:/docs/a.md", "size": int64(len(data)), "sha256": wantSHA},
		},
	}
	fs := NewGroupFSVFS(client)

	result, err := fs.Cp(ctx, localPath, "g-team.agentid.pub:/docs/a.md", &GroupFSCpOptions{Force: true, Parents: true})
	if err != nil {
		t.Fatalf("Cp local->group 失败: %v", err)
	}
	if result.Node.Path != "g-team.agentid.pub:/docs/a.md" || result.Download.LocalPath != "" {
		t.Fatalf("CpResult 不正确: %#v", result)
	}
	wantMethods := []string{"group.fs.check_upload", "group.fs.create_upload_session", "group.fs.complete_upload"}
	if got := groupFSCallMethods(client.calls); !reflect.DeepEqual(got, wantMethods) {
		t.Fatalf("local->group 调用链不正确: got=%#v want=%#v calls=%#v", got, wantMethods, client.calls)
	}
	checkParams := client.calls[0].params
	if checkParams["path"] != "g-team.agentid.pub:/docs/a.md" || checkParams["size_bytes"] != len(data) || checkParams["sha256"] != wantSHA || checkParams["content_type"] != "text/markdown" || checkParams["force"] != true || checkParams["parents"] != true {
		t.Fatalf("check_upload 参数不正确: %#v", checkParams)
	}
	if client.calls[2].params["session_id"] != "s1" || client.calls[2].params["skip_blob"] != nil {
		t.Fatalf("complete_upload 参数不正确: %#v", client.calls[2].params)
	}
	if strings.Contains(fmt.Sprintf("%#v", client.calls), "groupdata") {
		t.Fatalf("Go SDK 不应新增真实 groupdata 映射: %#v", client.calls)
	}
}

func TestGroupFSCpLocalPrefixIsStrippedForLocalUploadAndDownload(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	localPath := filepath.Join(dir, "prefixed.md")
	data := []byte("hello local prefix")
	if err := os.WriteFile(localPath, data, 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	digest := sha256.Sum256(data)
	wantSHA := fmt.Sprintf("%x", digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
		case http.MethodGet:
			_, _ = w.Write(data)
		default:
			t.Fatalf("HTTP 方法不正确: %s", r.Method)
		}
	}))
	defer server.Close()

	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.check_upload":          map[string]any{"target_exists": false, "within_limit": true},
			"group.fs.create_upload_session": map[string]any{"upload_url": server.URL, "session_id": "s-local"},
			"group.fs.complete_upload":       map[string]any{"type": "file", "path": "g-team.agentid.pub:/docs/prefixed.md"},
			"group.fs.create_download_ticket": map[string]any{
				"download_url": server.URL,
				"sha256":       wantSHA,
				"file_name":    "prefixed.md",
			},
		},
	}
	fs := NewGroupFSVFS(client)

	if _, err := fs.Cp(ctx, "local:"+localPath, "g-team.agentid.pub:/docs/prefixed.md", nil); err != nil {
		t.Fatalf("local: 上传失败: %v", err)
	}
	targetDir := filepath.Join(dir, "download")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatalf("创建下载目录失败: %v", err)
	}
	result, err := fs.Cp(ctx, "g-team.agentid.pub:/docs/prefixed.md", "local:"+targetDir, nil)
	if err != nil {
		t.Fatalf("local: 下载失败: %v", err)
	}

	targetPath := filepath.Join(targetDir, "prefixed.md")
	body, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("读取下载结果失败: %v", err)
	}
	if string(body) != string(data) || result.Download.LocalPath != targetPath || !result.Download.Verified {
		t.Fatalf("local: 下载结果不正确: body=%q result=%#v", string(body), result)
	}
	wantMethods := []string{"group.fs.check_upload", "group.fs.create_upload_session", "group.fs.complete_upload", "group.fs.create_download_ticket"}
	if got := groupFSCallMethods(client.calls); !reflect.DeepEqual(got, wantMethods) {
		t.Fatalf("local: 调用链不正确: got=%#v want=%#v", got, wantMethods)
	}
}

func TestGroupFSCpLocalPrefixWinsOverSharedGroupID(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	localPath := filepath.Join(dir, "active.md")
	data := []byte("active local prefix")
	if err := os.WriteFile(localPath, data, 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	digest := sha256.Sum256(data)
	wantSHA := fmt.Sprintf("%x", digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
			return
		}
		t.Fatalf("HTTP 方法不正确: %s", r.Method)
	}))
	defer server.Close()

	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.check_upload":    map[string]any{"instant": true, "session_id": "same-1"},
			"group.fs.complete_upload": map[string]any{"type": "file", "path": "/docs/active.md"},
			"group.fs.create_download_ticket": map[string]any{
				"download_url": server.URL,
				"sha256":       wantSHA,
			},
		},
	}
	fs := NewGroupFSVFS(client)

	opts := &GroupFSCpOptions{GroupID: "group.example.test/team"}
	if _, err := fs.Cp(ctx, "local:"+localPath, "/docs/active.md", opts); err != nil {
		t.Fatalf("local: + group_id 上传失败: %v", err)
	}
	targetPath := filepath.Join(dir, "out.md")
	result, err := fs.Cp(ctx, "/docs/active.md", "local:"+targetPath, opts)
	if err != nil {
		t.Fatalf("local: + group_id 下载失败: %v", err)
	}

	body, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("读取下载结果失败: %v", err)
	}
	if string(body) != string(data) || result.Download.LocalPath != targetPath || !result.Download.Verified {
		t.Fatalf("local: + group_id 下载结果不正确: body=%q result=%#v", string(body), result)
	}
	wantMethods := []string{"group.fs.check_upload", "group.fs.complete_upload", "group.fs.create_download_ticket"}
	if got := groupFSCallMethods(client.calls); !reflect.DeepEqual(got, wantMethods) {
		t.Fatalf("local: + group_id 调用链不正确: got=%#v want=%#v calls=%#v", got, wantMethods, client.calls)
	}
	if client.calls[0].params["group_id"] != "group.example.test/team" || client.calls[2].params["group_id"] != "group.example.test/team" {
		t.Fatalf("group_id 未传递到上传/下载控制面: %#v", client.calls)
	}
}

func TestGroupFSCpLocalToGroupSkipsHTTPPutOnInstantUpload(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	localPath := filepath.Join(dir, "same.bin")
	data := []byte("same")
	if err := os.WriteFile(localPath, data, 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}

	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.check_upload":    map[string]any{"instant": true, "session_id": "instant-1"},
			"group.fs.complete_upload": map[string]any{"type": "file", "path": "g-team.agentid.pub:/same.bin"},
		},
	}
	fs := NewGroupFSVFS(client)

	if _, err := fs.Cp(ctx, localPath, "g-team.agentid.pub:/same.bin", nil); err != nil {
		t.Fatalf("Cp local->group instant 失败: %v", err)
	}
	wantMethods := []string{"group.fs.check_upload", "group.fs.complete_upload"}
	if got := groupFSCallMethods(client.calls); !reflect.DeepEqual(got, wantMethods) {
		t.Fatalf("instant upload 调用链不正确: got=%#v want=%#v", got, wantMethods)
	}
	if client.calls[1].params["skip_blob"] != true || client.calls[1].params["session_id"] != "instant-1" {
		t.Fatalf("instant complete 参数不正确: %#v", client.calls[1].params)
	}
}

func TestGroupFSCpLocalToGroupDefaultsParentsTrue(t *testing.T) {
	ctx := context.Background()
	localPath := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(localPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.check_upload":    map[string]any{"instant": true, "session_id": "instant-parents"},
			"group.fs.complete_upload": map[string]any{"type": "file", "path": "g-team.agentid.pub:/nested/a.txt"},
		},
	}
	fs := NewGroupFSVFS(client)

	if _, err := fs.Cp(ctx, localPath, "g-team.agentid.pub:/nested/a.txt", nil); err != nil {
		t.Fatalf("Cp local->group 默认 parents 失败: %v", err)
	}
	if client.calls[0].params["parents"] != true {
		t.Fatalf("Go group.fs local->group 默认 parents 应为 true: %#v", client.calls[0].params)
	}
}

func TestGroupFSCpLocalToGroupRejectsExistingTargetWithoutForce(t *testing.T) {
	ctx := context.Background()
	localPath := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(localPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.check_upload": map[string]any{
				"target_exists": true,
				"target":        map[string]any{"path": "g-team.agentid.pub:/a.txt"},
			},
		},
	}
	fs := NewGroupFSVFS(client)

	_, err := fs.Cp(ctx, localPath, "g-team.agentid.pub:/a.txt", nil)
	var existsErr *StorageExistsError
	if !errors.As(err, &existsErr) {
		t.Fatalf("目标存在且未 force 应返回 StorageExistsError，got: %T %v", err, err)
	}
	if got := groupFSCallMethods(client.calls); !reflect.DeepEqual(got, []string{"group.fs.check_upload"}) {
		t.Fatalf("不应继续创建上传 session: %#v", client.calls)
	}
}

func TestGroupFSCpGroupToLocalDownloadsTicketAndWritesFile(t *testing.T) {
	ctx := context.Background()
	data := []byte("downloaded")
	digest := sha256.Sum256(data)
	wantSHA := fmt.Sprintf("%x", digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("下载 HTTP 方法不正确: %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer viewer-token" {
			t.Fatalf("下载 HTTP Authorization 不正确: %q", got)
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "out", "a.md")
	client := &fakeGroupFSClient{
		aid:         "alice.agentid.pub",
		accessToken: "viewer-token",
		responses: map[string]any{
			"group.fs.create_download_ticket": map[string]any{"download_url": server.URL, "sha256": wantSHA, "file_name": "a.md"},
		},
	}
	fs := NewGroupFSVFS(client)

	result, err := fs.Cp(ctx, "g-team.agentid.pub:/docs/a.md", target, nil)
	if err != nil {
		t.Fatalf("Cp group->local 失败: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读取下载结果失败: %v", err)
	}
	if string(body) != string(data) || result.Download.LocalPath != target || !result.Download.Verified {
		t.Fatalf("下载结果不正确: result=%#v body=%q", result, string(body))
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.fs.create_download_ticket" || client.calls[0].params["path"] != "g-team.agentid.pub:/docs/a.md" {
		t.Fatalf("group->local 调用不正确: %#v", client.calls)
	}
}

func TestGroupFSCpGroupToLocalForceOverwritesExistingTarget(t *testing.T) {
	ctx := context.Background()
	data := []byte("new")
	digest := sha256.Sum256(data)
	wantSHA := fmt.Sprintf("%x", digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "a.md")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.create_download_ticket": map[string]any{"download_url": server.URL, "sha256": wantSHA},
		},
	}
	fs := NewGroupFSVFS(client)

	result, err := fs.Cp(ctx, "g-team.agentid.pub:/docs/a.md", target, &GroupFSCpOptions{Force: true})
	if err != nil {
		t.Fatalf("force group->local 失败: %v", err)
	}
	body, _ := os.ReadFile(target)
	if string(body) != "new" || !result.Download.Verified {
		t.Fatalf("force 应覆盖本地文件并校验 hash: body=%q result=%#v", string(body), result)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.fs.create_download_ticket" {
		t.Fatalf("force 下载调用不正确: %#v", client.calls)
	}
}

func TestGroupFSCpGroupToLocalDetectsSHA256Mismatch(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bad"))
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "a.md")
	client := &fakeGroupFSClient{
		aid: "alice.agentid.pub",
		responses: map[string]any{
			"group.fs.create_download_ticket": map[string]any{"download_url": server.URL, "sha256": strings.Repeat("0", 64)},
		},
	}
	fs := NewGroupFSVFS(client)

	_, err := fs.Cp(ctx, "g-team.agentid.pub:/docs/a.md", target, nil)
	var storageErr *StorageError
	if !errors.As(err, &storageErr) || storageErr.Code != "ECONFLICT" {
		t.Fatalf("sha256 mismatch 应返回 ECONFLICT StorageError，got: %T %v", err, err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("hash mismatch 时不应写入目标文件，statErr=%v", statErr)
	}
}

func TestGroupFSCpGroupToLocalRejectsExistingTargetWithoutForce(t *testing.T) {
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "a.md")
	if err := os.WriteFile(target, []byte("exists"), 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	client := &fakeGroupFSClient{aid: "alice.agentid.pub"}
	fs := NewGroupFSVFS(client)

	_, err := fs.Cp(ctx, "g-team.agentid.pub:/docs/a.md", target, nil)
	var existsErr *StorageExistsError
	if !errors.As(err, &existsErr) {
		t.Fatalf("已有目标默认应返回 StorageExistsError，got: %T %v", err, err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("本地目标已存在时不应创建下载 ticket: %#v", client.calls)
	}
	body, _ := os.ReadFile(target)
	if string(body) != "exists" {
		t.Fatalf("本地文件不应被覆盖: %q", string(body))
	}
}

func TestGroupFSMvRejectsLocalParticipation(t *testing.T) {
	ctx := context.Background()
	fs := NewGroupFSVFS(&fakeGroupFSClient{aid: "alice.agentid.pub"})

	if _, err := fs.Mv(ctx, filepath.Join(t.TempDir(), "local.txt"), "g-team.agentid.pub:/dst.txt", nil); err == nil {
		t.Fatal("本地 src 参与 mv 应失败")
	}
	if _, err := fs.Mv(ctx, "g-team.agentid.pub:/src.txt", filepath.Join(t.TempDir(), "local.txt"), nil); err == nil {
		t.Fatal("本地 dst 参与 mv 应失败")
	}
}

func TestGroupFSCpGroupToGroupUsesSingleRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeGroupFSClient{aid: "alice.agentid.pub"}
	fs := NewGroupFSVFS(client)

	if _, err := fs.Cp(ctx, "g-team.agentid.pub:/a.md", "g-team.agentid.pub:/b.md", &GroupFSCpOptions{Force: true, Recursive: true}); err != nil {
		t.Fatalf("Cp group->group 失败: %v", err)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.fs.cp" {
		t.Fatalf("group->group 应只调用 group.fs.cp: %#v", client.calls)
	}
	params := client.calls[0].params
	if params["src"] != "g-team.agentid.pub:/a.md" || params["dst"] != "g-team.agentid.pub:/b.md" || params["force"] != true || params["recursive"] != true {
		t.Fatalf("group.fs.cp 参数不正确: %#v", params)
	}
}

func TestGroupFSCpLocalToLocalIsRejected(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入本地测试文件失败: %v", err)
	}
	fs := NewGroupFSVFS(&fakeGroupFSClient{aid: "alice.agentid.pub"})

	_, err := fs.Cp(ctx, src, dst, nil)
	var storageErr *StorageError
	if !errors.As(err, &storageErr) || storageErr.Code != "EINVAL" {
		t.Fatalf("local->local 应返回 EINVAL StorageError，got: %T %v", err, err)
	}
}

type fakeGroupFSClient struct {
	aid         string
	accessToken string
	calls       []storageCallRecord
	responses   map[string]any
}

func (f *fakeGroupFSClient) AID() string {
	return f.aid
}

func (f *fakeGroupFSClient) AccessToken() string {
	return f.accessToken
}

func (f *fakeGroupFSClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
	f.calls = append(f.calls, storageCallRecord{method: method, params: params})
	if response := f.responses[method]; response != nil {
		return response, nil
	}
	switch method {
	case "group.fs.ls", "group.fs.find":
		return map[string]any{"items": []any{map[string]any{"type": "file", "path": "docs/a.md"}}}, nil
	case "group.fs.stat", "group.fs.lstat", "group.fs.mkdir", "group.fs.cp", "group.fs.mv", "group.fs.mount":
		return map[string]any{"type": "file", "path": firstNonNil(params["path"], params["dst"])}, nil
	case "group.fs.rm":
		return map[string]any{"removed_count": 1, "path": params["path"]}, nil
	case "group.fs.df":
		return map[string]any{"used_bytes": 1, "quota_bytes": 2, "object_count": 1}, nil
	case "group.fs.umount":
		return map[string]any{"unmounted": true, "path": params["path"], "mount_path": params["path"]}, nil
	case "group.fs.create_download_ticket":
		return map[string]any{"content": base64.StdEncoding.EncodeToString([]byte("unused"))}, nil
	default:
		return map[string]any{"ok": true}, nil
	}
}

func groupFSCallMethods(calls []storageCallRecord) []string {
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, call.method)
	}
	return out
}
