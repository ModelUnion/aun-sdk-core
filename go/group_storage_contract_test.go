package aun

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestGroupStorageContractOverRPCPipeline(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "storage.fs.mkdir":
			return map[string]any{"node": map[string]any{
				"type":      "dir",
				"id":        "folder-" + storageAnyToString(params["path"]),
				"path":      params["path"],
				"owner_aid": params["owner_aid"],
			}}
		case "storage.fs.rename":
			return map[string]any{"node": map[string]any{
				"type":      "file",
				"path":      params["dst"],
				"owner_aid": params["owner_aid"],
			}}
		case "group.resources.namespace_ready":
			return map[string]any{"ok": true, "namespace_ready": true}
		case "group.resources.confirm":
			return map[string]any{"ok": true, "confirmed": true, "op_id": params["op_id"]}
		case "group.get":
			return map[string]any{"group": map[string]any{"group_id": params["group_id"], "group_aid": "team.agentid.pub"}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	client := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = client.Close() }()
	client.SetAID("team.agentid.pub")
	connectClientToTestRPCServer(t, client, wsURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	initResult, err := client.Group().Resources().InitializeNamespace(ctx, map[string]any{
		"group_id":      "group-1",
		"group_aid":     "team.agentid.pub",
		"baseline_dirs": []any{"announce", "", "public"},
	})
	if err != nil {
		t.Fatalf("InitializeNamespace 失败: %v", err)
	}
	if initResult == nil {
		t.Fatal("InitializeNamespace 返回 nil")
	}

	planResult, err := client.Group().Resources().ExecutePendingOps(ctx, map[string]any{
		"group_id":      "group-1",
		"group_aid":     "team.agentid.pub",
		"op_id":         "op-1",
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
	planMap, ok := planResult.(map[string]any)
	if !ok {
		t.Fatalf("ExecutePendingOps 返回类型不正确: %#v", planResult)
	}
	if _, exists := planMap["confirm"]; exists {
		t.Fatalf("Go 返回不应包含旧 confirm 字段: %#v", planMap)
	}
	if _, ok := planMap["storage_results"].(map[string]any); !ok {
		t.Fatalf("storage_results 缺失或类型不正确: %#v", planMap)
	}
	confirmed, ok := planMap["confirmed"].(map[string]any)
	if !ok || confirmed["confirmed"] != true {
		t.Fatalf("confirmed 缺失或内容不正确: %#v", planMap)
	}

	calls := getCalls()
	methods := make([]string, 0, len(calls))
	for _, call := range calls {
		methods = append(methods, call.Method)
	}
	wantMethods := []string{
		"storage.fs.mkdir",
		"storage.fs.mkdir",
		"storage.set_visibility",
		"group.resources.namespace_ready",
		"storage.fs.mkdir",
		"storage.fs.rename",
		"group.resources.confirm",
	}
	if !reflect.DeepEqual(methods, wantMethods) {
		t.Fatalf("RPC 调用顺序不正确: got=%#v want=%#v", methods, wantMethods)
	}

	for i, wantPath := range []string{"announce", "public"} {
		params := calls[i].Params
		if params["owner_aid"] != "team.agentid.pub" || params["path"] != wantPath || params["parents"] != true {
			t.Fatalf("InitializeNamespace mkdir 参数不正确: index=%d params=%#v", i, params)
		}
		if _, exists := params["sign_as"]; exists {
			t.Fatalf("同身份 storage RPC 不应透传 sign_as: %#v", params)
		}
	}
	namespaceParams := calls[3].Params
	if namespaceParams["group_id"] != "group-1" || namespaceParams["group_aid"] != "team.agentid.pub" {
		t.Fatalf("namespace_ready 参数不正确: %#v", namespaceParams)
	}
	if !reflect.DeepEqual(namespaceParams["folder_ids"], map[string]any{
		"announce": "folder-announce",
		"public":   "folder-public",
	}) {
		t.Fatalf("folder_ids 应只包含服务端返回的 id: %#v", namespaceParams["folder_ids"])
	}
	for _, forbidden := range []string{"bucket", "baseline_dirs", "folders", "sign_as"} {
		if _, exists := namespaceParams[forbidden]; exists {
			t.Fatalf("namespace_ready 不应包含 %s: %#v", forbidden, namespaceParams)
		}
	}

	for _, index := range []int{4, 5} {
		if _, exists := calls[index].Params["sign_as"]; exists {
			t.Fatalf("同身份 pending op 不应透传 sign_as: index=%d params=%#v", index, calls[index].Params)
		}
	}
	confirmParams := calls[6].Params
	if confirmParams["group_id"] != "group-1" || confirmParams["op_id"] != "op-1" {
		t.Fatalf("confirm 参数主键不正确: %#v", confirmParams)
	}
	for _, forbidden := range []string{"group_aid", "resource_path", "results"} {
		if _, exists := confirmParams[forbidden]; exists {
			t.Fatalf("confirm 不应包含 %s: %#v", forbidden, confirmParams)
		}
	}
	if _, exists := confirmParams["sign_as"]; exists {
		t.Fatalf("confirm 不应透传 sign_as: %#v", confirmParams)
	}
	storageResults, ok := confirmParams["storage_results"].(map[string]any)
	if !ok || storageResults["mkdir"] == nil || storageResults["rename"] == nil {
		t.Fatalf("storage_results 不正确: %#v", confirmParams)
	}
	if confirmParams["storage_result"] == nil || confirmParams["confirm_key"] != "rename" {
		t.Fatalf("confirm 应携带最后一次 storage_result/confirm_key: %#v", confirmParams)
	}
}

func TestGroupStorageMemberdataContractOverRPCPipeline(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "group.get" {
			return map[string]any{"group": map[string]any{"group_id": params["group_id"], "group_aid": "team.agentid.pub"}}
		}
		return map[string]any{
			"ok":         true,
			"method":     method,
			"owner_aid":  params["owner_aid"],
			"object_key": params["object_key"],
			"path":       params["path"],
		}
	})
	defer closeServer()

	client := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = client.Close() }()
	client.SetAID("alice.agentid.pub")
	connectClientToTestRPCServer(t, client, wsURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.Group().Resources().Put(ctx, map[string]any{
		"group_id":      "group-1",
		"resource_path": "memberdata/alice.agentid.pub/docs/a.txt",
		"content":       "hello",
		"content_type":  "text/plain",
	}); err != nil {
		t.Fatalf("memberdata Put 失败: %v", err)
	}
	if _, err := client.Group().Resources().Delete(ctx, map[string]any{
		"group_id":      "group-1",
		"resource_path": "memberdata/alice.agentid.pub/docs",
		"recursive":     true,
	}); err != nil {
		t.Fatalf("memberdata Delete 失败: %v", err)
	}

	calls := getCalls()
	if len(calls) != 3 {
		t.Fatalf("调用次数不正确: %#v", calls)
	}
	if calls[0].Method != "group.get" || calls[1].Method != "storage.put_object" {
		t.Fatalf("memberdata Put 应先解析 group_aid 再重映射到 storage.put_object: %#v", calls)
	}
	putParams := calls[1].Params
	if putParams["owner_aid"] != "alice.agentid.pub" || putParams["object_key"] != "alice.agentid.pub/team.agentid.pub/docs/a.txt" ||
		putParams["content"] != "hello" || putParams["content_type"] != "text/plain" || putParams["overwrite"] != false {
		t.Fatalf("memberdata Put 参数不正确: %#v", putParams)
	}
	if calls[2].Method != "storage.fs.remove" {
		t.Fatalf("memberdata Delete 应复用 group_aid 缓存并重映射到 storage.fs.remove: %#v", calls)
	}
	delParams := calls[2].Params
	if delParams["owner_aid"] != "alice.agentid.pub" || delParams["path"] != "alice.agentid.pub/team.agentid.pub/docs" || delParams["recursive"] != true {
		t.Fatalf("memberdata Delete 参数不正确: %#v", delParams)
	}
}
