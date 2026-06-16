package aun

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeGroupStorageSignerClient struct {
	*fakeStorageClient
	connects []ConnectionOptions
	closed   bool
}

type callOverrideStorageClient struct {
	*fakeStorageClient
	call func(context.Context, string, map[string]any) (any, error)
}

func (c *callOverrideStorageClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
	return c.call(ctx, method, params)
}

func (f *fakeGroupStorageSignerClient) Connect(ctx context.Context, opts ...ConnectionOptions) error {
	if len(opts) > 0 {
		f.connects = append(f.connects, opts[0])
	} else {
		f.connects = append(f.connects, ConnectionOptions{})
	}
	return nil
}

func (f *fakeGroupStorageSignerClient) Close() error {
	f.closed = true
	return nil
}

func withGroupStorageSignerFactory(
	t *testing.T,
	signers map[string]*fakeGroupStorageSignerClient,
) *AIDStore {
	t.Helper()
	oldLoad := groupStorageLoadAIDFromStore
	oldFactory := groupStorageNewSignerClient
	groupStorageLoadAIDFromStore = func(store *AIDStore, aid string) (*AID, error) {
		return &AID{Aid: aid}, nil
	}
	groupStorageNewSignerClient = func(aid *AID) groupStorageSignerClient {
		signer := signers[aid.Aid]
		if signer == nil {
			t.Fatalf("未预期的 signer AID: %s", aid.Aid)
		}
		return signer
	}
	t.Cleanup(func() {
		groupStorageLoadAIDFromStore = oldLoad
		groupStorageNewSignerClient = oldFactory
	})
	return &AIDStore{}
}

func TestGroupResourcesRPCMappings(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	cases := []struct {
		name   string
		call   func() error
		method string
	}{
		{"put", func() error {
			_, err := resources.Put(ctx, map[string]any{"group_id": "g1", "resource_path": "docs/a.txt", "storage_ref": map[string]any{"owner_aid": "alice.agentid.pub"}})
			return err
		}, "group.resources.put"},
		{"create_folder", func() error {
			_, err := resources.CreateFolder(ctx, map[string]any{"group_id": "g1", "path": "docs", "mkdirs": true})
			return err
		}, "group.resources.create_folder"},
		{"list_children", func() error {
			_, err := resources.ListChildren(ctx, map[string]any{"group_id": "g1", "path": "docs", "size": 20})
			return err
		}, "group.resources.list_children"},
		{"rename", func() error {
			_, err := resources.Rename(ctx, map[string]any{"group_id": "g1", "resource_id": "r1", "new_name": "b.txt"})
			return err
		}, "group.resources.rename"},
		{"move", func() error {
			_, err := resources.Move(ctx, map[string]any{"group_id": "g1", "resource_id": "r1", "dst_parent_path": "archive"})
			return err
		}, "group.resources.move"},
		{"mount_object", func() error {
			_, err := resources.MountObject(ctx, map[string]any{"group_id": "g1", "path": "docs/a.txt", "storage_ref": map[string]any{"object_key": "a.txt"}})
			return err
		}, "group.resources.mount_object"},
		{"unmount", func() error {
			_, err := resources.Unmount(ctx, map[string]any{"group_id": "g1", "resource_id": "r1"})
			return err
		}, "group.resources.unmount"},
		{"resolve_path", func() error {
			_, err := resources.ResolvePath(ctx, map[string]any{"group_id": "g1", "path": "docs/a.txt"})
			return err
		}, "group.resources.resolve_path"},
		{"get", func() error {
			_, err := resources.Get(ctx, map[string]any{"group_id": "g1", "resource_id": "r1"})
			return err
		}, "group.resources.get"},
		{"list", func() error {
			_, err := resources.List(ctx, map[string]any{"group_id": "g1", "prefix": "docs"})
			return err
		}, "group.resources.list"},
		{"update", func() error {
			_, err := resources.Update(ctx, map[string]any{"group_id": "g1", "resource_id": "r1", "title": "A"})
			return err
		}, "group.resources.update"},
		{"get_access", func() error {
			_, err := resources.GetAccess(ctx, map[string]any{"group_id": "g1", "resource_id": "r1"})
			return err
		}, "group.resources.get_access"},
		{"resolve_access_ticket", func() error {
			_, err := resources.ResolveAccessTicket(ctx, map[string]any{"access_ticket": "ticket-1"})
			return err
		}, "group.resources.resolve_access_ticket"},
		{"delete", func() error {
			_, err := resources.Delete(ctx, map[string]any{"group_id": "g1", "resource_id": "r1", "recursive": true})
			return err
		}, "group.resources.delete"},
		{"namespace_ready", func() error {
			_, err := resources.NamespaceReady(ctx, map[string]any{"group_id": "g1", "folder_ids": map[string]any{"announce": "folder-announce"}})
			return err
		}, "group.resources.namespace_ready"},
		{"confirm", func() error {
			_, err := resources.Confirm(ctx, map[string]any{"group_id": "g1", "op_id": "op1"})
			return err
		}, "group.resources.confirm"},
		{"confirm_mount", func() error {
			_, err := resources.ConfirmMount(ctx, map[string]any{"group_id": "g1", "mount_id": "mnt1"})
			return err
		}, "group.resources.confirm_mount"},
		{"get_df", func() error {
			_, err := resources.GetDF(ctx, map[string]any{"group_id": "g1"})
			return err
		}, "group.resources.get_df"},
	}

	for _, tc := range cases {
		if err := tc.call(); err != nil {
			t.Fatalf("%s 调用失败: %v", tc.name, err)
		}
	}
	if len(client.calls) != len(cases) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(cases), client.calls)
	}
	for i, tc := range cases {
		if client.calls[i].method != tc.method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, tc.method)
		}
	}
	if params := client.calls[0].params; !reflect.DeepEqual(params, map[string]any{
		"group_id": "g1", "resource_path": "docs/a.txt", "storage_ref": map[string]any{"owner_aid": "alice.agentid.pub"},
	}) {
		t.Fatalf("put 参数不正确: %#v", params)
	}
	if params := client.calls[1].params; params["mkdirs"] != true {
		t.Fatalf("create_folder 参数不正确: %#v", params)
	}
	if params := client.calls[13].params; params["recursive"] != true {
		t.Fatalf("delete 参数不正确: %#v", params)
	}
	resourceType := reflect.TypeOf(resources)
	for _, method := range []string{
		"ListRefsByStorage",
		"CleanupByStorageRef",
		"RequestMountObject",
		"RequestAdd",
		"DirectAdd",
		"ListPending",
		"ApproveRequest",
		"RejectRequest",
	} {
		if _, exists := resourceType.MethodByName(method); exists {
			t.Fatalf("GroupResources 不应暴露 legacy 方法 %s", method)
		}
	}
}

func TestResolveMemberdataTarget(t *testing.T) {
	cases := []struct {
		name       string
		selfAID    string
		groupID    string
		path       string
		wantOK     bool
		wantOwner  string
		wantObject string
	}{
		{"映射子路径", "alice.agentid.pub", "g1", "memberdata/alice.agentid.pub/docs/a.txt", true, "alice.agentid.pub", "alice.agentid.pub/g1/docs/a.txt"},
		{"映射根路径", "alice.agentid.pub", "g1", "memberdata/alice.agentid.pub", true, "alice.agentid.pub", "alice.agentid.pub/g1"},
		{"带前后斜杠", "alice.agentid.pub", "/g1/", "/memberdata/alice.agentid.pub/x/", true, "alice.agentid.pub", "alice.agentid.pub/g1/x"},
		{"大小写不敏感", "Alice.AgentID.Pub", "g1", "memberdata/alice.agentid.pub/a.txt", true, "Alice.AgentID.Pub", "Alice.AgentID.Pub/g1/a.txt"},
		{"他人槽位返回nil", "alice.agentid.pub", "g1", "memberdata/bob.agentid.pub/a.txt", false, "", ""},
		{"群自有区announce返回nil", "alice.agentid.pub", "g1", "announce/a.txt", false, "", ""},
		{"群自有区public返回nil", "alice.agentid.pub", "g1", "public/a.txt", false, "", ""},
		{"群自有区archive返回nil", "alice.agentid.pub", "g1", "archive/a.txt", false, "", ""},
		{"仅memberdata一级返回nil", "alice.agentid.pub", "g1", "memberdata", false, "", ""},
		{"self为空返回nil", "", "g1", "memberdata/alice.agentid.pub/a.txt", false, "", ""},
		{"group_id为空返回nil", "alice.agentid.pub", "", "memberdata/alice.agentid.pub/a.txt", false, "", ""},
		{"空路径返回nil", "alice.agentid.pub", "g1", "", false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner, object, ok := resolveMemberdataTarget(tc.selfAID, tc.groupID, tc.path)
			if ok != tc.wantOK {
				t.Fatalf("ok 不正确: got=%v want=%v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if owner != tc.wantOwner || object != tc.wantObject {
				t.Fatalf("映射不正确: owner=%q object=%q want owner=%q object=%q", owner, object, tc.wantOwner, tc.wantObject)
			}
		})
	}
}

func TestGroupResourcesPutRoutesMemberdataToStorage(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.Put(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "memberdata/alice.agentid.pub/docs/a.txt",
		"content":       "hello",
		"content_type":  "text/plain",
	}); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if len(client.calls) != 2 || client.calls[0].method != "group.get" || client.calls[1].method != "storage.put_object" {
		t.Fatalf("Put 未路由到 storage.put_object: %#v", client.calls)
	}
	params := client.calls[1].params
	if params["owner_aid"] != "alice.agentid.pub" || params["object_key"] != "alice.agentid.pub/team.agentid.pub/docs/a.txt" {
		t.Fatalf("storage.put_object 目标不正确: %#v", params)
	}
	if params["content"] != "hello" || params["overwrite"] != false || params["content_type"] != "text/plain" {
		t.Fatalf("storage.put_object 参数不正确: %#v", params)
	}
}

func TestGroupResourcesMemberdataGroupAidCacheExpires(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()
	oldNow := groupStorageNow
	current := time.Unix(0, 0)
	groupStorageNow = func() time.Time { return current }
	t.Cleanup(func() {
		groupStorageNow = oldNow
	})

	for _, tc := range []struct {
		at   time.Duration
		path string
	}{
		{0, "memberdata/alice.agentid.pub/docs/a.txt"},
		{29 * time.Second, "memberdata/alice.agentid.pub/docs/b.txt"},
		{31 * time.Second, "memberdata/alice.agentid.pub/docs/c.txt"},
	} {
		current = time.Unix(0, 0).Add(tc.at)
		if _, err := resources.Put(ctx, map[string]any{
			"group_id":      "g1",
			"resource_path": tc.path,
			"content":       "hello",
		}); err != nil {
			t.Fatalf("Put 失败: %v", err)
		}
	}

	groupGetCount := 0
	for _, call := range client.calls {
		if call.method == "group.get" {
			groupGetCount++
		}
	}
	if groupGetCount != 2 {
		t.Fatalf("group_aid 缓存 TTL 未生效，group.get 次数=%d calls=%#v", groupGetCount, client.calls)
	}
}

func TestGroupResourcesMemberdataLookupFailureDoesNotFallbackToGroupID(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{
		aid:         "alice.agentid.pub",
		failMethods: map[string]error{"group.get": errors.New("lookup timeout")},
	}
	resources := newGroupFacade(client).Resources()

	_, err := resources.Put(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "memberdata/alice.agentid.pub/docs/a.txt",
		"content":       "hello",
	})

	if err == nil || !strings.Contains(err.Error(), "memberdata namespace lookup failed") {
		t.Fatalf("memberdata namespace lookup 应返回显式错误: %v", err)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.get" {
		t.Fatalf("lookup 失败后不应继续写入错误命名空间: %#v", client.calls)
	}
}

func TestGroupResourcesPutGroupOwnedAreaStaysOnGroupRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.Put(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "announce/a.txt",
		"content":       "hi",
	}); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.resources.put" {
		t.Fatalf("群自有区应走 group.resources.put: %#v", client.calls)
	}
}

func TestGroupResourcesPutOtherMemberSlotStaysOnGroupRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.Put(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "memberdata/bob.agentid.pub/a.txt",
		"content":       "hi",
	}); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.resources.put" {
		t.Fatalf("他人槽位应走 group.resources.put: %#v", client.calls)
	}
}

func TestGroupResourcesDeleteRoutesMemberdataToStorage(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.Delete(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "memberdata/alice.agentid.pub/docs",
		"recursive":     true,
	}); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	if len(client.calls) != 2 || client.calls[0].method != "group.get" || client.calls[1].method != "storage.fs.remove" {
		t.Fatalf("Delete 未路由到 storage.fs.remove: %#v", client.calls)
	}
	params := client.calls[1].params
	if params["owner_aid"] != "alice.agentid.pub" || params["path"] != "alice.agentid.pub/team.agentid.pub/docs" || params["recursive"] != true {
		t.Fatalf("storage.fs.remove 参数不正确: %#v", params)
	}
}

func TestGroupResourcesDeleteGroupOwnedAreaStaysOnGroupRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.Delete(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "announce/a.txt",
	}); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.resources.delete" {
		t.Fatalf("群自有区应走 group.resources.delete: %#v", client.calls)
	}
}

func TestGroupResourcesCreateFolderRoutesMemberdataToStorage(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.CreateFolder(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "memberdata/alice.agentid.pub/docs",
		"mkdirs":        false,
	}); err != nil {
		t.Fatalf("CreateFolder 失败: %v", err)
	}
	if len(client.calls) != 2 || client.calls[0].method != "group.get" || client.calls[1].method != "storage.fs.mkdir" {
		t.Fatalf("CreateFolder 未路由到 storage.fs.mkdir: %#v", client.calls)
	}
	params := client.calls[1].params
	if params["owner_aid"] != "alice.agentid.pub" || params["path"] != "alice.agentid.pub/team.agentid.pub/docs" || params["parents"] != false {
		t.Fatalf("storage.fs.mkdir 参数不正确: %#v", params)
	}
}

func TestGroupResourcesCreateFolderGroupOwnedAreaStaysOnGroupRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.CreateFolder(ctx, map[string]any{
		"group_id":      "g1",
		"resource_path": "public",
		"mkdirs":        true,
	}); err != nil {
		t.Fatalf("CreateFolder 失败: %v", err)
	}
	if len(client.calls) != 1 || client.calls[0].method != "group.resources.create_folder" {
		t.Fatalf("群自有区应走 group.resources.create_folder: %#v", client.calls)
	}
}

func TestGroupResourcesInitializeNamespaceCreatesBaselineAndConfirms(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "team.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	result, err := resources.InitializeNamespace(ctx, map[string]any{
		"group_id":  "g1",
		"group_aid": "team.agentid.pub",
	})
	if err != nil {
		t.Fatalf("InitializeNamespace 失败: %v", err)
	}
	if result == nil {
		t.Fatal("InitializeNamespace 返回 nil")
	}
	gotMethods := make([]string, 0, len(client.calls))
	for _, call := range client.calls {
		gotMethods = append(gotMethods, call.method)
	}
	wantMethods := []string{
		"storage.fs.mkdir",
		"storage.fs.mkdir",
		"storage.fs.mkdir",
		"storage.fs.mkdir",
		"storage.set_visibility",
		"group.resources.namespace_ready",
	}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("调用顺序不正确: got=%#v want=%#v", gotMethods, wantMethods)
	}
	wantPaths := []any{"announce", "public", "archive", "memberdata"}
	for i, path := range wantPaths {
		params := client.calls[i].params
		if params["owner_aid"] != "team.agentid.pub" || params["bucket"] != "default" || params["path"] != path || params["parents"] != true {
			t.Fatalf("mkdir 参数不正确: index=%d params=%#v", i, params)
		}
		if _, exists := params["sign_as"]; exists {
			t.Fatalf("同身份路径不应透传 sign_as: %#v", params)
		}
	}
	visibilityParams := client.calls[4].params
	if visibilityParams["owner_aid"] != "team.agentid.pub" || visibilityParams["bucket"] != "default" || visibilityParams["path"] != "public" || visibilityParams["visibility"] != "public" {
		t.Fatalf("set_visibility 参数不正确: %#v", visibilityParams)
	}
	confirmParams := client.calls[5].params
	if confirmParams["group_id"] != "g1" || confirmParams["group_aid"] != "team.agentid.pub" {
		t.Fatalf("namespace_ready 参数不正确: %#v", confirmParams)
	}
	if _, exists := confirmParams["sign_as"]; exists {
		t.Fatalf("namespace_ready 不应带 sign_as: %#v", confirmParams)
	}
	for _, extra := range []string{"bucket", "baseline_dirs", "folders"} {
		if _, exists := confirmParams[extra]; exists {
			t.Fatalf("namespace_ready 不应带 %s: %#v", extra, confirmParams)
		}
	}
	wantFolderIDs := map[string]any{}
	if !reflect.DeepEqual(confirmParams["folder_ids"], wantFolderIDs) {
		t.Fatalf("folder_ids 不正确: %#v", confirmParams["folder_ids"])
	}
}

func TestGroupResourcesInitializeNamespaceRequiresStoreBeforePartialWrites(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "owner.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	_, err := resources.InitializeNamespace(ctx, map[string]any{
		"group_id":  "g1",
		"group_aid": "team.agentid.pub",
	})

	if err == nil || !strings.Contains(err.Error(), "requires aid_store") {
		t.Fatalf("缺少 aid_store 应提前失败: %v", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("提前校验失败前不应产生部分 namespace 写入: %#v", client.calls)
	}
}

func TestGroupResourcesInitializeNamespaceRequiresAidStoreWhenSignerDiffers(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "owner.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	_, err := resources.InitializeNamespace(ctx, map[string]any{
		"group_id":  "g1",
		"group_aid": "team.agentid.pub",
	})
	if err == nil {
		t.Fatal("InitializeNamespace 缺少 aidStore 时应拒绝跨身份签名")
	}
	if len(client.calls) != 0 {
		t.Fatalf("失败路径不应发起 RPC: %#v", client.calls)
	}
}

func TestGroupResourcesInitializeNamespaceUsesAidStoreSignerClient(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "owner.agentid.pub"}
	signer := &fakeGroupStorageSignerClient{fakeStorageClient: &fakeStorageClient{aid: "team.agentid.pub"}}
	aidStore := withGroupStorageSignerFactory(t, map[string]*fakeGroupStorageSignerClient{
		"team.agentid.pub": signer,
	})
	resources := newGroupFacade(client).Resources()

	_, err := resources.InitializeNamespace(ctx, map[string]any{
		"group_id":      "g1",
		"group_aid":     "team.agentid.pub",
		"baseline_dirs": []any{"announce", "public"},
		"aid_store":     aidStore,
	})
	if err != nil {
		t.Fatalf("InitializeNamespace 失败: %v", err)
	}
	if len(signer.connects) != 1 {
		t.Fatalf("signer 未建立短连接: %#v", signer.connects)
	}
	if signer.connects[0].AutoReconnect == nil || *signer.connects[0].AutoReconnect {
		t.Fatalf("signer 默认应关闭自动重连: %#v", signer.connects[0])
	}
	if signer.connects[0].ConnectionKind != "short" || signer.connects[0].ShortTtlMs != 30_000 || signer.connects[0].HeartbeatInterval != 0 {
		t.Fatalf("signer 默认连接选项不正确: %#v", signer.connects[0])
	}
	if !signer.closed {
		t.Fatal("signer 未关闭")
	}
	gotSignerMethods := []string{}
	for _, call := range signer.calls {
		gotSignerMethods = append(gotSignerMethods, call.method)
	}
	if !reflect.DeepEqual(gotSignerMethods, []string{"storage.fs.mkdir", "storage.fs.mkdir", "storage.set_visibility", "group.resources.namespace_ready"}) {
		t.Fatalf("storage RPC 未走 signer: %#v", gotSignerMethods)
	}
	for _, call := range signer.calls[:3] {
		if call.params["owner_aid"] != "team.agentid.pub" {
			t.Fatalf("storage owner_aid 不正确: %#v", call.params)
		}
		if _, exists := call.params["sign_as"]; exists {
			t.Fatalf("aidStore 路径不应透传 sign_as 给 storage: %#v", call.params)
		}
	}
	if len(client.calls) != 0 {
		t.Fatalf("主 client 不应执行 namespace_ready: %#v", client.calls)
	}
	readyParams := signer.calls[3].params
	if readyParams["group_id"] != "g1" || readyParams["group_aid"] != "team.agentid.pub" {
		t.Fatalf("namespace_ready 参数不正确: %#v", readyParams)
	}
	if _, exists := readyParams["sign_as"]; exists {
		t.Fatalf("aidStore 路径 namespace_ready 不应带 sign_as: %#v", readyParams)
	}
}

func TestGroupResourcesInitializeNamespaceAllowsSignerConnectionOptions(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "owner.agentid.pub"}
	signer := &fakeGroupStorageSignerClient{fakeStorageClient: &fakeStorageClient{aid: "team.agentid.pub"}}
	aidStore := withGroupStorageSignerFactory(t, map[string]*fakeGroupStorageSignerClient{
		"team.agentid.pub": signer,
	})
	resources := newGroupFacade(client).Resources()

	_, err := resources.InitializeNamespace(ctx, map[string]any{
		"group_id":      "g1",
		"group_aid":     "team.agentid.pub",
		"baseline_dirs": []any{"announce"},
		"aid_store":     aidStore,
		"signer_connection_options": map[string]any{
			"short_ttl_ms":          120_000,
			"heartbeat_interval_ms": 5_000,
			"connect_timeout_ms":    2_500,
			"call_timeout_ms":       7_500,
			"auto_reconnect":        true,
		},
	})
	if err != nil {
		t.Fatalf("InitializeNamespace 失败: %v", err)
	}
	if len(signer.connects) != 1 {
		t.Fatalf("signer 未建立短连接: %#v", signer.connects)
	}
	got := signer.connects[0]
	if got.ConnectionKind != "short" || got.ShortTtlMs != 120_000 {
		t.Fatalf("signer TTL 覆盖失败: %#v", got)
	}
	if got.HeartbeatInterval != 5*time.Second || got.ConnectTimeout != 2500*time.Millisecond || got.CallTimeout != 7500*time.Millisecond {
		t.Fatalf("signer 超时选项覆盖失败: %#v", got)
	}
	if got.AutoReconnect == nil || !*got.AutoReconnect {
		t.Fatalf("signer 自动重连覆盖失败: %#v", got)
	}
}

func TestGroupResourcesExecutePendingOpsRunsInOrderAndConfirms(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "team.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	result, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":          "pending_ops",
		"group_id":      "g1",
		"group_aid":     "team.agentid.pub",
		"op_id":         "op1",
		"resource_path": "announce/a.txt",
		"confirm_rpc":   "group.resources.confirm",
		"pending_ops": []any{
			map[string]any{
				"rpc":         "storage.fs.mkdir",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce/docs", "parents": true},
				"sign_as":     "team.agentid.pub",
				"confirm_key": "mkdir",
			},
			map[string]any{
				"rpc":         "storage.fs.rename",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "src": "announce/tmp.txt", "dst": "announce/a.txt"},
				"confirm_key": "rename",
			},
		},
	})
	if err != nil {
		t.Fatalf("ExecutePendingOps 失败: %v", err)
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("ExecutePendingOps 返回不正确: %#v", result)
	}
	confirmed, ok := resultMap["confirmed"].(map[string]any)
	if !ok || confirmed["ok"] != true {
		t.Fatalf("ExecutePendingOps confirmed 不正确: %#v", result)
	}
	if _, exists := resultMap["confirm"]; exists {
		t.Fatalf("ExecutePendingOps 返回不应包含 confirm: %#v", result)
	}
	if _, ok := resultMap["storage_results"].(map[string]any); !ok {
		t.Fatalf("ExecutePendingOps storage_results 不正确: %#v", result)
	}
	gotMethods := []string{client.calls[0].method, client.calls[1].method, client.calls[2].method}
	wantMethods := []string{"storage.fs.mkdir", "storage.fs.rename", "group.resources.confirm"}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("调用顺序不正确: got=%#v want=%#v", gotMethods, wantMethods)
	}
	if _, exists := client.calls[0].params["sign_as"]; exists {
		t.Fatalf("同身份 pending op 不应透传 sign_as: %#v", client.calls[0].params)
	}
	if _, exists := client.calls[1].params["sign_as"]; exists {
		t.Fatalf("同身份 pending op 不应继承 sign_as: %#v", client.calls[1].params)
	}
	confirmParams := client.calls[2].params
	if confirmParams["group_id"] != "g1" || confirmParams["op_id"] != "op1" {
		t.Fatalf("confirm 参数不正确: %#v", confirmParams)
	}
	if _, exists := confirmParams["group_aid"]; exists {
		t.Fatalf("confirm 不应包含 group_aid: %#v", confirmParams)
	}
	if _, exists := confirmParams["resource_path"]; exists {
		t.Fatalf("confirm 不应包含 resource_path: %#v", confirmParams)
	}
	if _, exists := confirmParams["results"]; exists {
		t.Fatalf("confirm 不应包含 results: %#v", confirmParams)
	}
	storageResults, ok := confirmParams["storage_results"].(map[string]any)
	if !ok || storageResults["mkdir"] == nil || storageResults["rename"] == nil {
		t.Fatalf("confirm storage_results 不正确: %#v", confirmParams)
	}
	if confirmParams["storage_result"] == nil || confirmParams["confirm_key"] != "rename" {
		t.Fatalf("confirm 未携带 storage_result/confirm_key: %#v", confirmParams)
	}
}

func TestGroupResourcesExecutePendingOpsRunsLargeUploadHTTPPutAndComplete(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "team.agentid.pub"}
	clientProxy := &callOverrideStorageClient{
		fakeStorageClient: client,
		call: func(ctx context.Context, method string, params map[string]any) (any, error) {
			client.calls = append(client.calls, storageCallRecord{method: method, params: params})
			switch method {
			case "storage.create_upload_session":
				return map[string]any{
					"upload_url": "https://storage.agentid.pub/upload/s1",
					"session_id": "s1",
					"headers":    map[string]any{"X-Upload": "1"},
				}, nil
			case "storage.complete_upload":
				return map[string]any{"object_id": "o1", "status": "active"}, nil
			default:
				return map[string]any{"ok": true}, nil
			}
		},
	}
	resources := newGroupFacade(clientProxy).Resources()
	uploadData := []byte{1, 2, 3, 4}
	var httpPuts []map[string]any
	oldHTTPPut := groupStorageHTTPPut
	groupStorageHTTPPut = func(ctx context.Context, uploadURL string, data []byte, headers map[string]string) (map[string]any, error) {
		httpPuts = append(httpPuts, map[string]any{
			"url":     uploadURL,
			"data":    append([]byte(nil), data...),
			"headers": headers,
		})
		return map[string]any{"status": 200}, nil
	}
	t.Cleanup(func() {
		groupStorageHTTPPut = oldHTTPPut
	})

	result, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":        "pending_ops",
		"group_id":    "g1",
		"group_aid":   "team.agentid.pub",
		"op_id":       "op1",
		"confirm_rpc": "group.resources.confirm",
		"upload_data": uploadData,
		"confirm_params": map[string]any{
			"group_id":      "g1",
			"resource_path": "announce/a.bin",
			"resource_type": "file",
		},
		"pending_ops": []any{
			map[string]any{
				"rpc": "storage.create_upload_session",
				"params": map[string]any{
					"owner_aid":  "team.agentid.pub",
					"object_key": "announce/a.bin",
					"size_bytes": len(uploadData),
				},
				"confirm_key": "upload_session",
			},
			map[string]any{
				"rpc":    "storage.http_put",
				"params": map[string]any{"content_type": "application/octet-stream"},
				"params_from_results": map[string]any{
					"upload_url": "upload_session.upload_url",
					"headers":    "upload_session.headers",
				},
				"data_ref":    "upload_data",
				"confirm_key": "http_put",
			},
			map[string]any{
				"rpc": "storage.complete_upload",
				"params": map[string]any{
					"owner_aid":  "team.agentid.pub",
					"object_key": "announce/a.bin",
					"size_bytes": len(uploadData),
					"sha256":     strings.Repeat("a", 64),
				},
				"params_from_results": map[string]any{"session_id": "upload_session.session_id"},
				"confirm_key":         "upload",
			},
		},
	})
	if err != nil {
		t.Fatalf("ExecutePendingOps 失败: %v", err)
	}
	if len(httpPuts) != 1 {
		t.Fatalf("HTTP PUT 次数不正确: %#v", httpPuts)
	}
	if httpPuts[0]["url"] != "https://storage.agentid.pub/upload/s1" {
		t.Fatalf("HTTP PUT URL 不正确: %#v", httpPuts)
	}
	if !reflect.DeepEqual(httpPuts[0]["data"], uploadData) {
		t.Fatalf("HTTP PUT payload 不正确: %#v", httpPuts)
	}
	headers, ok := httpPuts[0]["headers"].(map[string]string)
	if !ok || headers["X-Upload"] != "1" || headers["Content-Type"] != "application/octet-stream" {
		t.Fatalf("HTTP PUT headers 不正确: %#v", httpPuts)
	}
	gotMethods := []string{client.calls[0].method, client.calls[1].method, client.calls[2].method}
	wantMethods := []string{"storage.create_upload_session", "storage.complete_upload", "group.resources.confirm"}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("调用顺序不正确: got=%v want=%v", gotMethods, wantMethods)
	}
	if client.calls[1].params["session_id"] != "s1" {
		t.Fatalf("complete_upload 未从 upload_session 映射 session_id: %#v", client.calls[1].params)
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("ExecutePendingOps 返回不正确: %#v", result)
	}
	storageResults, ok := resultMap["storage_results"].(map[string]any)
	if !ok || storageResults["http_put"] == nil {
		t.Fatalf("storage_results 缺少 http_put: %#v", result)
	}
	confirmResults, ok := client.calls[2].params["storage_results"].(map[string]any)
	if !ok || confirmResults["http_put"] == nil {
		t.Fatalf("confirm 未携带 http_put 结果: %#v", client.calls[2].params)
	}
}

func TestGroupResourcesExecutePendingOpsIndex0FailureRethrowsOriginalError(t *testing.T) {
	ctx := context.Background()
	firstErr := errors.New("first op failed")
	client := &fakeStorageClient{
		aid: "team.agentid.pub",
		failMethods: map[string]error{
			"storage.fs.mkdir": firstErr,
		},
	}
	resources := newGroupFacade(client).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":        "pending_ops",
		"group_id":    "g1",
		"group_aid":   "team.agentid.pub",
		"confirm_rpc": "group.resources.confirm",
		"pending_ops": []any{
			map[string]any{
				"rpc":         "storage.fs.mkdir",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce", "parents": true},
				"sign_as":     "team.agentid.pub",
				"confirm_key": "mkdir",
				"compensation": map[string]any{
					"rpc":         "storage.fs.remove",
					"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce", "recursive": true},
					"sign_as":     "team.agentid.pub",
					"confirm_key": "remove:announce",
				},
			},
		},
	})
	if !errors.Is(err, firstErr) {
		t.Fatalf("第 0 个 op 失败应直接返回原始错误: %T %v", err, err)
	}
	var partial *GroupPendingOpsPartialFailure
	if errors.As(err, &partial) {
		t.Fatalf("第 0 个 op 失败不应包装 partial failure: %#v", partial)
	}
	if len(client.calls) != 1 || client.calls[0].method != "storage.fs.mkdir" {
		t.Fatalf("第 0 个 op 失败后不应 confirm 或补偿: %#v", client.calls)
	}
}

func TestGroupResourcesExecutePendingOpsRejectsUnsupportedRPCs(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "team.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	cases := []struct {
		name string
		plan map[string]any
		want string
	}{
		{
			name: "pending",
			plan: map[string]any{
				"group_id":  "g1",
				"group_aid": "team.agentid.pub",
				"pending_ops": []any{
					map[string]any{"rpc": "group.dissolve", "params": map[string]any{}, "confirm_key": "bad"},
				},
			},
			want: "unsupported pending rpc",
		},
		{
			name: "confirm",
			plan: map[string]any{
				"group_id":    "g1",
				"group_aid":   "team.agentid.pub",
				"confirm_rpc": "group.dissolve",
				"pending_ops": []any{},
			},
			want: "unsupported confirm rpc",
		},
		{
			name: "compensation",
			plan: map[string]any{
				"mode":           "pending_ops",
				"failure_policy": "compensate_successful_ops_before_confirm",
				"group_id":       "g1",
				"group_aid":      "team.agentid.pub",
				"pending_ops": []any{
					map[string]any{
						"rpc":         "storage.fs.mkdir",
						"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce"},
						"confirm_key": "mkdir",
						"compensation": map[string]any{
							"rpc":         "group.dissolve",
							"params":      map[string]any{},
							"confirm_key": "bad",
						},
					},
					map[string]any{"rpc": "storage.set_acl", "params": map[string]any{"owner_aid": "team.agentid.pub", "path": "public"}, "confirm_key": "acl"},
				},
			},
			want: "unsupported compensation rpc",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resources.ExecutePendingOps(ctx, tc.plan)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got err=%v want contains %q", err, tc.want)
			}
		})
	}
}

func TestGroupResourcesExecutePendingOpsCompensatesAfterPartialFailure(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{
		aid: "team.agentid.pub",
		failMethods: map[string]error{
			"storage.set_acl": errors.New("storage failed"),
		},
	}
	resources := newGroupFacade(client).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":           "pending_ops",
		"failure_policy": "compensate_successful_ops_before_confirm",
		"group_id":       "g1",
		"group_aid":      "team.agentid.pub",
		"confirm_rpc":    "group.resources.confirm",
		"pending_ops": []any{
			map[string]any{
				"rpc":         "storage.fs.mkdir",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce", "parents": true},
				"sign_as":     "team.agentid.pub",
				"confirm_key": "mkdir",
				"compensation": map[string]any{
					"rpc":         "storage.fs.remove",
					"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce", "recursive": true},
					"sign_as":     "team.agentid.pub",
					"confirm_key": "remove:announce",
					"depends_on":  "mkdir",
				},
			},
			map[string]any{
				"rpc":         "storage.set_acl",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "public", "grantee_aid": "admin.agentid.pub", "perms": "rwx"},
				"sign_as":     "team.agentid.pub",
				"confirm_key": "acl:public",
			},
		},
	})
	if err == nil {
		t.Fatal("partial failure 应返回错误")
	}
	var partial *GroupPendingOpsPartialFailure
	if !errors.As(err, &partial) {
		t.Fatalf("错误类型不正确: %T %v", err, err)
	}
	if partial.FailedIndex != 1 {
		t.Fatalf("失败 index 不正确: %d", partial.FailedIndex)
	}
	if _, ok := partial.StorageResults["mkdir"]; !ok {
		t.Fatalf("storage_results 缺少成功项: %#v", partial.StorageResults)
	}
	if _, ok := partial.CompensationResults["remove:announce"]; !ok {
		t.Fatalf("compensation_results 缺少补偿项: %#v", partial.CompensationResults)
	}
	gotMethods := []string{client.calls[0].method, client.calls[1].method, client.calls[2].method}
	wantMethods := []string{"storage.fs.mkdir", "storage.set_acl", "storage.fs.remove"}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("调用顺序不正确: got=%v want=%v", gotMethods, wantMethods)
	}
}

func TestGroupResourcesExecutePendingOpsRecordsCompensationErrors(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "team.agentid.pub"}
	clientCall := func(ctx context.Context, method string, params map[string]any) (any, error) {
		client.calls = append(client.calls, storageCallRecord{method: method, params: params})
		if method == "storage.set_acl" && params["path"] == "public" {
			return nil, errors.New("storage failed")
		}
		if method == "storage.fs.remove" {
			return nil, errors.New("compensation failed")
		}
		if method == "storage.set_acl" {
			return map[string]any{"acl_id": "acl-announce"}, nil
		}
		return map[string]any{"method": method}, nil
	}
	clientProxy := &callOverrideStorageClient{fakeStorageClient: client, call: clientCall}
	resources := newGroupFacade(clientProxy).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":           "pending_ops",
		"failure_policy": "compensate_successful_ops_before_confirm",
		"group_id":       "g1",
		"group_aid":      "team.agentid.pub",
		"confirm_rpc":    "group.resources.confirm",
		"pending_ops": []any{
			map[string]any{
				"rpc":         "storage.set_acl",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce"},
				"confirm_key": "acl:announce",
				"compensation": map[string]any{
					"rpc":         "storage.fs.remove",
					"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce", "recursive": true},
					"confirm_key": "remove:announce",
				},
			},
			map[string]any{
				"rpc":         "storage.set_acl",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "public"},
				"confirm_key": "acl:public",
			},
		},
	})
	var partial *GroupPendingOpsPartialFailure
	if !errors.As(err, &partial) {
		t.Fatalf("错误类型不正确: %T %v", err, err)
	}
	if len(partial.CompensationResults) != 0 || len(partial.CompensationErrors) != 1 {
		t.Fatalf("补偿失败记录不正确: results=%#v errors=%#v", partial.CompensationResults, partial.CompensationErrors)
	}
	if partial.CompensationErrors[0]["confirm_key"] != "remove:announce" || partial.CompensationErrors[0]["error"] != "compensation failed" {
		t.Fatalf("补偿失败明细不正确: %#v", partial.CompensationErrors)
	}
	for _, call := range client.calls {
		if call.method == "group.resources.confirm" {
			t.Fatalf("补偿失败后不应 confirm: %#v", client.calls)
		}
	}
	encoded, marshalErr := json.Marshal(partial)
	if marshalErr != nil {
		t.Fatalf("MarshalJSON 失败: %v", marshalErr)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("MarshalJSON 输出不是 JSON object: %v", err)
	}
	if payload["failed_index"] == nil || payload["compensation_errors"] == nil {
		t.Fatalf("MarshalJSON 缺少 snake_case 键: %s", encoded)
	}
}

func TestGroupResourcesExecutePendingOpsCompensationParamsFromStorageResultsPrefix(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{
		aid: "alice.agentid.pub",
		failMethods: map[string]error{
			"storage.fs.mount": errors.New("mount failed"),
		},
	}
	resources := newGroupFacade(client).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":           "pending_ops",
		"failure_policy": "compensate_successful_ops_before_confirm",
		"group_id":       "g1",
		"group_aid":      "team.agentid.pub",
		"sign_as":        "alice.agentid.pub",
		"confirm_rpc":    "group.resources.confirm_mount",
		"pending_ops": []any{
			map[string]any{
				"rpc":         "storage.issue_token",
				"params":      map[string]any{"owner_aid": "alice.agentid.pub", "path": "team-data"},
				"sign_as":     "alice.agentid.pub",
				"confirm_key": "source_token",
				"compensation": map[string]any{
					"rpc":                 "storage.revoke_token",
					"params":              map[string]any{"owner_aid": "alice.agentid.pub", "path": "team-data"},
					"params_from_results": map[string]any{"token": "storage_results.source_token.token"},
					"confirm_key":         "revoke_source_token",
					"depends_on":          "source_token",
				},
			},
			map[string]any{
				"rpc":         "storage.fs.mount",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "mount_path": "memberdata/alice.agentid.pub"},
				"sign_as":     "alice.agentid.pub",
				"confirm_key": "mount",
			},
		},
	})
	if err == nil {
		t.Fatal("partial failure 应返回错误")
	}
	var partial *GroupPendingOpsPartialFailure
	if !errors.As(err, &partial) {
		t.Fatalf("错误类型不正确: %T %v", err, err)
	}
	if _, ok := partial.CompensationResults["revoke_source_token"]; !ok {
		t.Fatalf("compensation_results 缺少 revoke_source_token: %#v", partial.CompensationResults)
	}
	if len(client.calls) != 3 || client.calls[2].method != "storage.revoke_token" {
		t.Fatalf("未执行 revoke_token 补偿: %#v", client.calls)
	}
	if client.calls[2].params["token"] != "tok-secret" {
		t.Fatalf("补偿 token 参数未从 storage_results 前缀解析: %#v", client.calls[2].params)
	}
}

func TestGroupResourcesExecutePendingOpsRequiresAidStoreWhenSignerDiffers(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "owner.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"group_id":  "g1",
		"group_aid": "team.agentid.pub",
		"pending_ops": []any{
			map[string]any{
				"rpc":     "storage.fs.mkdir",
				"params":  map[string]any{"owner_aid": "team.agentid.pub", "path": "announce/docs", "parents": true},
				"sign_as": "team.agentid.pub",
			},
		},
	})
	if err == nil {
		t.Fatal("ExecutePendingOps 缺少 aidStore 时应拒绝跨身份签名")
	}
	if len(client.calls) != 0 {
		t.Fatalf("失败路径不应发起 RPC: %#v", client.calls)
	}
}

func TestGroupResourcesExecutePendingOpsUsesAidStoreSignerClients(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "owner.agentid.pub"}
	groupSigner := &fakeGroupStorageSignerClient{fakeStorageClient: &fakeStorageClient{aid: "team.agentid.pub"}}
	memberSigner := &fakeGroupStorageSignerClient{fakeStorageClient: &fakeStorageClient{aid: "alice.agentid.pub"}}
	aidStore := withGroupStorageSignerFactory(t, map[string]*fakeGroupStorageSignerClient{
		"team.agentid.pub":  groupSigner,
		"alice.agentid.pub": memberSigner,
	})
	resources := newGroupFacade(client).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"group_id":    "g1",
		"group_aid":   "team.agentid.pub",
		"confirm_rpc": "group.resources.confirm",
		"aid_store":   aidStore,
		"pending_ops": []any{
			map[string]any{
				"rpc":         "storage.fs.mkdir",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce/docs", "parents": true},
				"sign_as":     "team.agentid.pub",
				"confirm_key": "mkdir",
			},
			map[string]any{
				"rpc":         "storage.fs.mount",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "mount_path": "memberdata/alice.agentid.pub", "source_aid": "alice.agentid.pub", "source_path": "team-data"},
				"sign_as":     "alice.agentid.pub",
				"confirm_key": "mount",
			},
		},
	})
	if err != nil {
		t.Fatalf("ExecutePendingOps 失败: %v", err)
	}
	if len(groupSigner.calls) != 2 || groupSigner.calls[0].method != "storage.fs.mkdir" || groupSigner.calls[1].method != "group.resources.confirm" {
		t.Fatalf("群身份 signer 调用不正确: %#v", groupSigner.calls)
	}
	if len(memberSigner.calls) != 1 || memberSigner.calls[0].method != "storage.fs.mount" {
		t.Fatalf("成员身份 signer 调用不正确: %#v", memberSigner.calls)
	}
	if _, exists := groupSigner.calls[0].params["sign_as"]; exists {
		t.Fatalf("群身份 storage RPC 不应带 sign_as: %#v", groupSigner.calls[0].params)
	}
	if _, exists := groupSigner.calls[1].params["sign_as"]; exists {
		t.Fatalf("群身份 confirm RPC 不应带 sign_as: %#v", groupSigner.calls[1].params)
	}
	if _, exists := memberSigner.calls[0].params["sign_as"]; exists {
		t.Fatalf("成员 storage RPC 不应带 sign_as: %#v", memberSigner.calls[0].params)
	}
	if !groupSigner.closed || !memberSigner.closed {
		t.Fatalf("signer 未关闭: group=%v member=%v", groupSigner.closed, memberSigner.closed)
	}
	if len(client.calls) != 0 {
		t.Fatalf("aidStore 路径主 client 不应执行 confirm: %#v", client.calls)
	}
	if _, exists := groupSigner.calls[1].params["results"]; exists {
		t.Fatalf("confirm 不应包含 results: %#v", groupSigner.calls[1].params)
	}
	storageResults, ok := groupSigner.calls[1].params["storage_results"].(map[string]any)
	if !ok || storageResults["mkdir"] == nil || storageResults["mount"] == nil {
		t.Fatalf("confirm storage_results 不正确: %#v", groupSigner.calls[1].params)
	}
	if groupSigner.calls[1].params["storage_result"] == nil || groupSigner.calls[1].params["confirm_key"] != "mount" {
		t.Fatalf("confirm 未携带 storage_result/confirm_key: %#v", groupSigner.calls[1].params)
	}
}

func TestGroupResourcesExecutePendingOpsPreservesACLConfirmParams(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "team.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":        "pending_ops",
		"group_id":    "g1",
		"group_aid":   "team.agentid.pub",
		"op_id":       "acl-op1",
		"confirm_rpc": "group.resources.confirm",
		"confirm_params": map[string]any{
			"group_id":   "g1",
			"operation":  "acl",
			"path":       "announce",
			"member_aid": "admin.agentid.pub",
			"acl_action": "set_acl",
			"acl_paths":  []any{"announce", "public"},
		},
		"pending_ops": []any{
			map[string]any{
				"rpc":         "storage.set_acl",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "announce", "grantee_aid": "admin.agentid.pub", "perms": "rwx"},
				"sign_as":     "team.agentid.pub",
				"confirm_key": "acl:announce",
			},
			map[string]any{
				"rpc":         "storage.set_acl",
				"params":      map[string]any{"owner_aid": "team.agentid.pub", "path": "public", "grantee_aid": "admin.agentid.pub", "perms": "rwx"},
				"confirm_key": "acl:public",
			},
		},
	})
	if err != nil {
		t.Fatalf("ExecutePendingOps 失败: %v", err)
	}
	gotMethods := []string{client.calls[0].method, client.calls[1].method, client.calls[2].method}
	wantMethods := []string{"storage.set_acl", "storage.set_acl", "group.resources.confirm"}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("调用顺序不正确: got=%#v want=%#v", gotMethods, wantMethods)
	}
	confirmParams := client.calls[2].params
	if confirmParams["operation"] != "acl" || confirmParams["path"] != "announce" || confirmParams["member_aid"] != "admin.agentid.pub" || confirmParams["acl_action"] != "set_acl" {
		t.Fatalf("confirm_params 未保留 ACL 上下文: %#v", confirmParams)
	}
	if !reflect.DeepEqual(confirmParams["acl_paths"], []any{"announce", "public"}) {
		t.Fatalf("acl_paths 不正确: %#v", confirmParams["acl_paths"])
	}
	if _, exists := confirmParams["group_aid"]; exists {
		t.Fatalf("confirm 不应包含 group_aid: %#v", confirmParams)
	}
	if confirmParams["op_id"] != "acl-op1" {
		t.Fatalf("confirm 参数未补齐: %#v", confirmParams)
	}
	if _, exists := confirmParams["sign_as"]; exists {
		t.Fatalf("confirm 不应带 sign_as: %#v", confirmParams)
	}
	if _, exists := confirmParams["results"]; exists {
		t.Fatalf("confirm 不应包含 results: %#v", confirmParams)
	}
	storageResults, ok := confirmParams["storage_results"].(map[string]any)
	if !ok || storageResults["acl:announce"] == nil || storageResults["acl:public"] == nil {
		t.Fatalf("confirm storage_results 不正确: %#v", confirmParams)
	}
	if confirmParams["storage_result"] == nil || confirmParams["confirm_key"] != "acl:public" {
		t.Fatalf("confirm 未携带 storage_result/confirm_key: %#v", confirmParams)
	}
}

func TestGroupResourcesExecutePendingOpsRunsMemberMountAndConfirmsMount(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	_, err := resources.ExecutePendingOps(ctx, map[string]any{
		"mode":        "pending_ops",
		"group_id":    "g1",
		"group_aid":   "team.agentid.pub",
		"sign_as":     "alice.agentid.pub",
		"confirm_rpc": "group.resources.confirm_mount",
		"confirm_params": map[string]any{
			"group_id":    "g1",
			"group_aid":   "team.agentid.pub",
			"mount_path":  "memberdata/alice.agentid.pub",
			"source_aid":  "alice.agentid.pub",
			"source_path": "team-data",
		},
		"pending_ops": []any{
			map[string]any{
				"rpc": "storage.fs.mount",
				"params": map[string]any{
					"owner_aid":   "team.agentid.pub",
					"mount_path":  "memberdata/alice.agentid.pub",
					"source_aid":  "alice.agentid.pub",
					"source_path": "team-data",
				},
				"sign_as":     "alice.agentid.pub",
				"confirm_key": "mount",
			},
		},
	})
	if err != nil {
		t.Fatalf("ExecutePendingOps 失败: %v", err)
	}
	gotMethods := []string{client.calls[0].method, client.calls[1].method}
	wantMethods := []string{"storage.fs.mount", "group.resources.confirm_mount"}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("调用顺序不正确: got=%#v want=%#v", gotMethods, wantMethods)
	}
	if _, exists := client.calls[0].params["sign_as"]; exists {
		t.Fatalf("同身份成员挂载不应透传 sign_as: %#v", client.calls[0].params)
	}
	confirmParams := client.calls[1].params
	if confirmParams["group_id"] != "g1" || confirmParams["group_aid"] != "team.agentid.pub" || confirmParams["mount_path"] != "memberdata/alice.agentid.pub" {
		t.Fatalf("confirm_mount 参数不正确: %#v", confirmParams)
	}
	if confirmParams["source_aid"] != "alice.agentid.pub" || confirmParams["source_path"] != "team-data" {
		t.Fatalf("confirm_mount 未保留成员挂载上下文: %#v", confirmParams)
	}
	if _, exists := confirmParams["sign_as"]; exists {
		t.Fatalf("confirm_mount 不应带 sign_as: %#v", confirmParams)
	}
	if _, exists := confirmParams["results"]; exists {
		t.Fatalf("confirm_mount 不应包含 results: %#v", confirmParams)
	}
	storageResults, ok := confirmParams["storage_results"].(map[string]any)
	if !ok || storageResults["mount"] == nil {
		t.Fatalf("confirm_mount storage_results 不正确: %#v", confirmParams)
	}
	if confirmParams["storage_result"] == nil || confirmParams["confirm_key"] != "mount" {
		t.Fatalf("confirm_mount 未携带 storage_result/confirm_key: %#v", confirmParams)
	}
}

func TestGroupResourcesDoesNotExposeLegacyResourceMethods(t *testing.T) {
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	resourceType := reflect.TypeOf(resources)
	for _, method := range []string{
		"ListRefsByStorage",
		"CleanupByStorageRef",
		"RequestMountObject",
		"RequestAdd",
		"DirectAdd",
		"ListPending",
		"ApproveRequest",
		"RejectRequest",
	} {
		if _, exists := resourceType.MethodByName(method); exists {
			t.Fatalf("GroupResources 不应暴露 legacy 方法 %s", method)
		}
	}
}

func TestGroupResourcesOmitsNilParams(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	resources := newGroupFacade(client).Resources()

	if _, err := resources.Get(ctx, map[string]any{"group_id": "g1", "resource_id": nil, "resource_path": "docs/a.txt"}); err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if !reflect.DeepEqual(client.calls[0].params, map[string]any{"group_id": "g1", "resource_path": "docs/a.txt"}) {
		t.Fatalf("nil 参数未过滤: %#v", client.calls[0].params)
	}
}

func TestAUNClientGroupResourcesFacadeEntryIsCached(t *testing.T) {
	client := NewAUNClientEmpty()

	first := client.Group().Resources()
	second := client.Group().Resources()
	if first == nil {
		t.Fatal("Group().Resources 返回 nil")
	}
	if first != second {
		t.Fatal("Group().Resources 入口应缓存同一实例")
	}
}
