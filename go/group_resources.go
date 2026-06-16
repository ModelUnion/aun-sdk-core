package aun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var groupStorageBaselineDirs = []string{"announce", "public", "archive", "memberdata"}

var groupStorageAllowedPendingRPCs = map[string]bool{
	"storage.put_object":            true,
	"storage.create_upload_session": true,
	"storage.complete_upload":       true,
	"storage.http_put":              true,
	"storage.delete_object":         true,
	"storage.fs.mkdir":              true,
	"storage.fs.rename":             true,
	"storage.fs.remove":             true,
	"storage.fs.mount":              true,
	"storage.fs.unmount":            true,
	"storage.issue_token":           true,
	"storage.revoke_token":          true,
	"storage.set_acl":               true,
	"storage.remove_acl":            true,
	"storage.set_visibility":        true,
}

var groupStorageAllowedConfirmRPCs = map[string]bool{
	"group.resources.confirm":       true,
	"group.resources.confirm_mount": true,
}

var groupStorageAllowedCompensationRPCs = map[string]bool{
	"storage.delete_object": true,
	"storage.fs.remove":     true,
	"storage.fs.unmount":    true,
	"storage.revoke_token":  true,
	"storage.remove_acl":    true,
	"storage.set_acl":       true,
}

type groupStorageSignerClient interface {
	StorageRPCClient
	Connect(ctx context.Context, opts ...ConnectionOptions) error
	Close() error
	AID() string
}

var groupStorageLoadAIDFromStore = func(store *AIDStore, aid string) (*AID, error) {
	loaded := store.Load(aid)
	if !loaded.Ok {
		message := fmt.Sprintf("signer identity not found: %s", aid)
		if loaded.Error != nil && strings.TrimSpace(loaded.Error.Message) != "" {
			message = loaded.Error.Message
		}
		return nil, fmt.Errorf("%s", message)
	}
	if loaded.Data.AID == nil {
		return nil, fmt.Errorf("signer identity missing AID object: %s", aid)
	}
	return loaded.Data.AID, nil
}

var groupStorageNewSignerClient = func(aid *AID) groupStorageSignerClient {
	return NewAUNClient(aid)
}

type GroupResources struct {
	rpcFacade
	groupAidMu    sync.Mutex
	groupAidCache map[string]groupAidCacheEntry
}

type groupAidCacheEntry struct {
	groupAID  string
	expiresAt time.Time
}

const groupAidCacheTTL = 30 * time.Second

var groupStorageNow = time.Now

var groupStorageHTTPPut = func(ctx context.Context, uploadURL string, data []byte, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		if strings.TrimSpace(key) != "" {
			req.Header.Set(key, value)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP PUT failed: status=%d", resp.StatusCode)
	}
	return map[string]any{"status": resp.StatusCode, "upload_url": uploadURL, "size_bytes": len(data)}, nil
}

type GroupPendingOpsPartialFailure struct {
	Message             string
	FailedIndex         int
	FailedOp            map[string]any
	StorageResults      map[string]any
	OpResults           []any
	CompensationResults map[string]any
	CompensationErrors  []map[string]any
	Cause               error
}

func (e *GroupPendingOpsPartialFailure) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "pending ops partial failure"
}

func (e *GroupPendingOpsPartialFailure) Unwrap() error {
	return e.Cause
}

func (e *GroupPendingOpsPartialFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"failed_index":         e.FailedIndex,
		"failed_op":            e.FailedOp,
		"storage_results":      e.StorageResults,
		"op_results":           e.OpResults,
		"compensation_results": e.CompensationResults,
		"compensation_errors":  e.CompensationErrors,
	})
}

type groupStorageSignerConnectionOptions struct {
	ConnectionOptions
}

func NewGroupResources(client StorageRPCClient) *GroupResources {
	return &GroupResources{rpcFacade: newRPCFacade(client, "group.resources"), groupAidCache: map[string]groupAidCacheEntry{}}
}

// resolveMemberdataTarget 成员挂载区透明路由：memberdata/{self_aid}/{rest} → 成员自己 storage 空间。
//
// 协议约定：成员挂载区的源固定指向成员自己空间的 {self_aid}/{group_aid}/{rest}。命中本人槽位时返回
// (owner_aid=self_aid, object_key={self_aid}/{group_aid}/{rest}, true)；他人槽位或群自有区返回 ("", "", false)
// （不路由，由调用方走原 group.resources 流程）。匹配大小写不敏感。
func resolveMemberdataTarget(selfAID, groupKey, resourcePath string) (string, string, bool) {
	path := strings.Trim(strings.TrimSpace(resourcePath), "/")
	if path == "" {
		return "", "", false
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || !strings.EqualFold(parts[0], "memberdata") {
		return "", "", false
	}
	slotAID := strings.TrimSpace(parts[1])
	self := strings.TrimSpace(selfAID)
	if self == "" || !strings.EqualFold(slotAID, self) {
		return "", "", false
	}
	namespaceKey := strings.Trim(strings.TrimSpace(groupKey), "/")
	if namespaceKey == "" {
		return "", "", false
	}
	rest := strings.Trim(strings.Join(parts[2:], "/"), "/")
	objectKey := self + "/" + namespaceKey
	if rest != "" {
		objectKey = objectKey + "/" + rest
	}
	return self, objectKey, true
}

func isMemberdataSelfPath(selfAID, resourcePath string) bool {
	path := strings.Trim(strings.TrimSpace(resourcePath), "/")
	if path == "" {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || !strings.EqualFold(parts[0], "memberdata") {
		return false
	}
	return strings.TrimSpace(selfAID) != "" && strings.EqualFold(strings.TrimSpace(parts[1]), strings.TrimSpace(selfAID))
}

func (r *GroupResources) resolveMemberdataTargetForParams(ctx context.Context, params map[string]any) (string, string, bool, error) {
	resourcePath := storageAnyToString(firstNonNil(params["resource_path"], params["resourcePath"]))
	if !isMemberdataSelfPath(r.selfAID(), resourcePath) {
		return "", "", false, nil
	}
	groupKey, err := r.memberdataNamespaceKey(ctx, params)
	if err != nil {
		return "", "", false, err
	}
	owner, objectKey, ok := resolveMemberdataTarget(r.selfAID(), groupKey, resourcePath)
	return owner, objectKey, ok, nil
}

func (r *GroupResources) selfAID() string {
	return groupStorageClientAID(r.client)
}

func (r *GroupResources) memberdataNamespaceKey(ctx context.Context, params map[string]any) (string, error) {
	if value := strings.TrimSpace(storageAnyToString(firstNonNil(params["group_aid"], params["groupAid"]))); value != "" {
		return value, nil
	}
	groupID := strings.TrimSpace(storageAnyToString(firstNonNil(params["group_id"], params["groupId"])))
	if groupID == "" {
		return "", nil
	}
	r.groupAidMu.Lock()
	cached := r.groupAidCache[groupID]
	r.groupAidMu.Unlock()
	if cached.groupAID != "" && cached.expiresAt.After(groupStorageNow()) {
		return cached.groupAID, nil
	}
	result, err := r.client.Call(ctx, "group.get", facadeParams(map[string]any{"group_id": groupID}))
	if err != nil {
		return "", fmt.Errorf("memberdata namespace lookup failed: %w", err)
	}
	if root, ok := result.(map[string]any); ok {
		if group, ok := root["group"].(map[string]any); ok {
			if groupAID := strings.TrimSpace(storageAnyToString(group["group_aid"])); groupAID != "" {
				r.groupAidMu.Lock()
				r.groupAidCache[groupID] = groupAidCacheEntry{
					groupAID:  groupAID,
					expiresAt: groupStorageNow().Add(groupAidCacheTTL),
				}
				r.groupAidMu.Unlock()
				return groupAID, nil
			}
		}
	}
	return "", fmt.Errorf("memberdata namespace lookup failed: group_aid missing for %s", groupID)
}

func (r *GroupResources) Put(ctx context.Context, params map[string]any) (any, error) {
	if owner, objectKey, ok, err := r.resolveMemberdataTargetForParams(ctx, params); err != nil {
		return nil, err
	} else if ok {
		storageParams := map[string]any{
			"owner_aid":  owner,
			"object_key": objectKey,
			"content":    firstNonNil(params["content"], ""),
			"overwrite":  false,
		}
		if value := firstNonNil(params["overwrite"]); !isNilStorageParam(value) {
			storageParams["overwrite"] = value
		}
		for _, key := range []string{"content_type", "content_encoding", "metadata", "expected_version"} {
			if value := params[key]; !isNilStorageParam(value) {
				storageParams[key] = value
			}
		}
		return r.client.Call(ctx, "storage.put_object", facadeParams(storageParams))
	}
	return r.call(ctx, "put", params)
}

func (r *GroupResources) CreateFolder(ctx context.Context, params map[string]any) (any, error) {
	if owner, path, ok, err := r.resolveMemberdataTargetForParams(ctx, params); err != nil {
		return nil, err
	} else if ok {
		parents := storageBool(firstNonNil(params["mkdirs"], params["parents"]), true)
		return r.client.Call(ctx, "storage.fs.mkdir", facadeParams(map[string]any{
			"owner_aid": owner,
			"path":      path,
			"parents":   parents,
		}))
	}
	return r.call(ctx, "create_folder", params)
}

func (r *GroupResources) ListChildren(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "list_children", params)
}

func (r *GroupResources) Rename(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "rename", params)
}

func (r *GroupResources) Move(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "move", params)
}

func (r *GroupResources) MountObject(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "mount_object", params)
}

func (r *GroupResources) Unmount(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "unmount", params)
}

func (r *GroupResources) ResolvePath(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "resolve_path", params)
}

func (r *GroupResources) Get(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "get", params)
}

func (r *GroupResources) List(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "list", params)
}

func (r *GroupResources) Update(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "update", params)
}

func (r *GroupResources) GetAccess(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "get_access", params)
}

func (r *GroupResources) ResolveAccessTicket(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "resolve_access_ticket", params)
}

func (r *GroupResources) Delete(ctx context.Context, params map[string]any) (any, error) {
	if owner, path, ok, err := r.resolveMemberdataTargetForParams(ctx, params); err != nil {
		return nil, err
	} else if ok {
		recursive := storageBool(firstNonNil(params["recursive"]), false)
		// memberdata 下既可能是文件也可能是目录：统一用 fs.remove（服务端对文件/目录均支持）。
		return r.client.Call(ctx, "storage.fs.remove", facadeParams(map[string]any{
			"owner_aid": owner,
			"path":      path,
			"recursive": recursive,
		}))
	}
	return r.call(ctx, "delete", params)
}

func (r *GroupResources) NamespaceReady(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "namespace_ready", params)
}

func (r *GroupResources) Confirm(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "confirm", params)
}

func (r *GroupResources) ConfirmMount(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "confirm_mount", params)
}

func (r *GroupResources) GetDF(ctx context.Context, params map[string]any) (any, error) {
	return r.call(ctx, "get_df", params)
}

func (r *GroupResources) InitializeNamespace(ctx context.Context, params map[string]any) (any, error) {
	if params == nil {
		params = map[string]any{}
	}
	aidStore := groupStorageAIDStore(params)
	groupID := strings.TrimSpace(storageAnyToString(firstNonNil(params["group_id"], params["groupId"])))
	groupAID := strings.TrimSpace(storageAnyToString(firstNonNil(params["group_aid"], params["groupAid"], params["owner_aid"], params["owner"])))
	if groupID == "" {
		return nil, fmt.Errorf("InitializeNamespace requires group_id")
	}
	if groupAID == "" {
		return nil, fmt.Errorf("InitializeNamespace requires group_aid")
	}
	bucket := strings.TrimSpace(storageAnyToString(params["bucket"]))
	if bucket == "" {
		bucket = "default"
	}
	signAs := strings.TrimSpace(storageAnyToString(firstNonNil(params["sign_as"], params["signAs"], groupAID)))
	if !strings.EqualFold(signAs, r.selfAID()) && aidStore == nil {
		return nil, fmt.Errorf("InitializeNamespace requires aid_store to sign as %s", signAs)
	}
	signerOptions := groupStorageSignerOptions(params)
	dirs := groupStorageDirs(params)
	folderIDs := map[string]any{}
	signerCache := map[string]groupStorageSignerClient{}
	defer groupStorageCloseSigners(signerCache)
	storageClient, err := r.groupStorageSignerFor(ctx, signAs, aidStore, signerCache, signerOptions)
	if err != nil {
		return nil, err
	}
	for _, dir := range dirs {
		mkdirParams := map[string]any{
			"owner_aid": groupAID,
			"bucket":    bucket,
			"path":      dir,
			"parents":   true,
		}
		result, err := storageClient.Call(ctx, "storage.fs.mkdir", facadeParams(mkdirParams))
		if err != nil {
			return nil, err
		}
		if folderID := groupStorageFirstIDFromMap(result); folderID != "" {
			folderIDs[dir] = folderID
		}
	}
	if groupStorageContainsDir(dirs, "public") {
		visibilityParams := map[string]any{
			"owner_aid":  groupAID,
			"bucket":     bucket,
			"path":       "public",
			"visibility": "public",
		}
		if _, err := storageClient.Call(ctx, "storage.set_visibility", facadeParams(visibilityParams)); err != nil {
			return nil, err
		}
	}
	return storageClient.Call(ctx, "group.resources.namespace_ready", map[string]any{
		"group_id":   groupID,
		"group_aid":  groupAID,
		"folder_ids": folderIDs,
	})
}

func (r *GroupResources) ExecutePendingOps(ctx context.Context, plan map[string]any) (any, error) {
	if plan == nil {
		return nil, fmt.Errorf("ExecutePendingOps requires plan")
	}
	aidStore := groupStorageAIDStore(plan)
	pendingOps, err := groupStoragePendingOps(plan)
	if err != nil {
		return nil, err
	}
	confirmRPC := strings.TrimSpace(storageAnyToString(firstNonNil(plan["confirm_rpc"], plan["confirmRpc"])))
	if confirmRPC == "" {
		confirmRPC = "group.resources.confirm"
	}
	if !groupStorageAllowedConfirmRPCs[confirmRPC] {
		return nil, fmt.Errorf("unsupported confirm rpc: %s", confirmRPC)
	}
	for _, rawOp := range pendingOps {
		op, ok := rawOp.(map[string]any)
		if !ok {
			continue
		}
		rpc := strings.TrimSpace(storageAnyToString(firstNonNil(op["rpc"], op["method"])))
		if rpc != "" && !groupStorageAllowedPendingRPCs[rpc] {
			return nil, fmt.Errorf("unsupported pending rpc: %s", rpc)
		}
		if comp, ok := op["compensation"].(map[string]any); ok {
			compRPC := strings.TrimSpace(storageAnyToString(firstNonNil(comp["rpc"], comp["method"])))
			if compRPC != "" && !groupStorageAllowedCompensationRPCs[compRPC] {
				return nil, fmt.Errorf("unsupported compensation rpc: %s", compRPC)
			}
		}
	}
	defaultSignAs := strings.TrimSpace(storageAnyToString(firstNonNil(plan["sign_as"], plan["signAs"], plan["group_aid"], plan["groupAid"])))
	signerOptions := groupStorageSignerOptions(plan)
	results := map[string]any{}
	opResults := make([]any, 0, len(pendingOps))
	successfulOps := make([]map[string]any, 0, len(pendingOps))
	successfulKeys := make([]string, 0, len(pendingOps))
	lastConfirmKey := ""
	var lastResult any
	signerCache := map[string]groupStorageSignerClient{}
	defer groupStorageCloseSigners(signerCache)
	for index, rawOp := range pendingOps {
		op, ok := rawOp.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("pending op %d must be an object", index)
		}
		rpc := strings.TrimSpace(storageAnyToString(firstNonNil(op["rpc"], op["method"])))
		if rpc == "" {
			return nil, fmt.Errorf("pending op %d missing rpc", index)
		}
		if !groupStorageAllowedPendingRPCs[rpc] {
			return nil, fmt.Errorf("unsupported pending rpc: %s", rpc)
		}
		opParams, _ := op["params"].(map[string]any)
		callParams := map[string]any{}
		for key, value := range opParams {
			callParams[key] = value
		}
		groupStorageApplyResultMappings(callParams, op, results, opResults)
		if value := firstNonNil(op["data_ref"], op["dataRef"]); !isNilStorageParam(value) {
			if _, exists := callParams["data_ref"]; !exists {
				callParams["data_ref"] = value
			}
		}
		var result any
		var err error
		if rpc == "storage.http_put" {
			result, err = groupStorageRunHTTPPut(ctx, plan, callParams)
		} else {
			signAs := strings.TrimSpace(storageAnyToString(firstNonNil(op["sign_as"], op["signAs"], defaultSignAs)))
			storageClient, signerErr := r.groupStorageSignerFor(ctx, signAs, aidStore, signerCache, signerOptions)
			if signerErr != nil {
				return nil, signerErr
			}
			result, err = storageClient.Call(ctx, rpc, facadeParams(callParams))
		}
		if err != nil {
			compResults, compErrors := r.groupStorageRunCompensations(ctx, plan, successfulOps, successfulKeys, results, defaultSignAs, aidStore, signerCache, signerOptions)
			if len(successfulOps) == 0 && len(compResults) == 0 && len(compErrors) == 0 {
				return nil, err
			}
			return nil, &GroupPendingOpsPartialFailure{
				Message:             err.Error(),
				FailedIndex:         index,
				FailedOp:            op,
				StorageResults:      results,
				OpResults:           opResults,
				CompensationResults: compResults,
				CompensationErrors:  compErrors,
				Cause:               err,
			}
		}
		opResults = append(opResults, result)
		confirmKey := strings.TrimSpace(storageAnyToString(firstNonNil(op["confirm_key"], op["confirmKey"])))
		if confirmKey == "" {
			confirmKey = fmt.Sprintf("op_%d", index)
		}
		results[confirmKey] = result
		successfulOps = append(successfulOps, op)
		successfulKeys = append(successfulKeys, confirmKey)
		lastConfirmKey = confirmKey
		lastResult = result
	}
	confirmParams := groupStorageConfirmParams(plan)
	if _, exists := confirmParams["group_id"]; !exists {
		if value := firstNonNil(plan["group_id"], plan["groupId"]); !isNilStorageParam(value) {
			confirmParams["group_id"] = value
		}
	}
	if _, exists := confirmParams["op_id"]; !exists {
		if value := firstNonNil(plan["op_id"], plan["opId"]); !isNilStorageParam(value) {
			confirmParams["op_id"] = value
		}
	}
	confirmParams["op_results"] = opResults
	confirmParams["storage_results"] = results
	if lastResult != nil {
		confirmParams["storage_result"] = lastResult
	}
	if _, exists := confirmParams["confirm_key"]; !exists && lastConfirmKey != "" {
		confirmParams["confirm_key"] = lastConfirmKey
	}
	confirmParams = facadeParams(confirmParams)
	confirmSignAs := strings.TrimSpace(storageAnyToString(firstNonNil(
		plan["confirm_sign_as"],
		plan["confirmSignAs"],
		plan["sign_as"],
		plan["signAs"],
		plan["group_aid"],
		plan["groupAid"],
		defaultSignAs,
	)))
	confirmClient, err := r.groupStorageSignerFor(ctx, confirmSignAs, aidStore, signerCache, signerOptions)
	if err != nil {
		return nil, err
	}
	confirmResult, err := confirmClient.Call(ctx, confirmRPC, confirmParams)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"storage_results": results,
		"confirmed":       confirmResult,
	}, nil
}

func (r *GroupResources) groupStorageSignerFor(ctx context.Context, signAs string, aidStore *AIDStore, cache map[string]groupStorageSignerClient, options groupStorageSignerConnectionOptions) (StorageRPCClient, error) {
	signAs = strings.TrimSpace(signAs)
	if signAs == "" || groupStorageSameAID(groupStorageClientAID(r.client), signAs) {
		return r.client, nil
	}
	if aidStore == nil {
		return nil, fmt.Errorf("group resources operation requires aidStore to sign as %s", signAs)
	}
	if signer := cache[signAs]; signer != nil {
		return signer, nil
	}
	aidObj, err := groupStorageLoadAIDFromStore(aidStore, signAs)
	if err != nil {
		return nil, err
	}
	signer := groupStorageNewSignerClient(aidObj)
	err = signer.Connect(ctx, options.ConnectionOptions)
	if err != nil {
		_ = signer.Close()
		return nil, err
	}
	cache[signAs] = signer
	return signer, nil
}

func (r *GroupResources) groupStorageRunCompensations(
	ctx context.Context,
	plan map[string]any,
	successfulOps []map[string]any,
	successfulKeys []string,
	results map[string]any,
	defaultSignAs string,
	aidStore *AIDStore,
	signerCache map[string]groupStorageSignerClient,
	signerOptions groupStorageSignerConnectionOptions,
) (map[string]any, []map[string]any) {
	policy := strings.TrimSpace(storageAnyToString(firstNonNil(plan["failure_policy"], plan["failurePolicy"])))
	if policy != "compensate_successful_ops_before_confirm" {
		return map[string]any{}, nil
	}
	compResults := map[string]any{}
	compErrors := []map[string]any{}
	for i := len(successfulOps) - 1; i >= 0; i-- {
		op := successfulOps[i]
		key := successfulKeys[i]
		comp, ok := op["compensation"].(map[string]any)
		if !ok {
			continue
		}
		dependsOn := strings.TrimSpace(storageAnyToString(firstNonNil(comp["depends_on"], comp["dependsOn"])))
		if dependsOn == "" {
			dependsOn = key
		}
		if dependsOn != "" {
			if _, exists := results[dependsOn]; !exists {
				continue
			}
		}
		params := map[string]any{}
		if rawParams, ok := comp["params"].(map[string]any); ok {
			for paramKey, value := range rawParams {
				params[paramKey] = value
			}
		}
		if mappings, ok := firstNonNil(comp["params_from_results"], comp["paramsFromResults"]).(map[string]any); ok {
			for paramKey, pathValue := range mappings {
				context := map[string]any{
					"results":         results,
					"storage_results": results,
					"op_results":      make([]any, len(successfulOps)),
				}
				for resultKey, resultValue := range results {
					context[resultKey] = resultValue
				}
				for idx, resultKey := range successfulKeys {
					context["op_results"].([]any)[idx] = results[resultKey]
				}
				if value, found := groupStorageResultPathValue(context, storageAnyToString(pathValue)); found {
					params[paramKey] = value
				}
			}
		}
		rpc := strings.TrimSpace(storageAnyToString(firstNonNil(comp["rpc"], comp["method"])))
		if rpc == "" {
			continue
		}
		signAs := strings.TrimSpace(storageAnyToString(firstNonNil(comp["sign_as"], comp["signAs"], op["sign_as"], op["signAs"], defaultSignAs)))
		confirmKey := strings.TrimSpace(storageAnyToString(firstNonNil(comp["confirm_key"], comp["confirmKey"])))
		if confirmKey == "" {
			confirmKey = "compensate:" + key
		}
		client, err := r.groupStorageSignerFor(ctx, signAs, aidStore, signerCache, signerOptions)
		if err != nil {
			compErrors = append(compErrors, map[string]any{"confirm_key": confirmKey, "rpc": rpc, "error": err.Error()})
			continue
		}
		result, err := client.Call(ctx, rpc, facadeParams(params))
		if err != nil {
			compErrors = append(compErrors, map[string]any{"confirm_key": confirmKey, "rpc": rpc, "error": err.Error()})
			continue
		}
		compResults[confirmKey] = result
	}
	return compResults, compErrors
}

func groupStorageSignerOptions(params map[string]any) groupStorageSignerConnectionOptions {
	autoReconnect := false
	options := ConnectionOptions{
		AutoReconnect:     &autoReconnect,
		HeartbeatInterval: 0 * time.Second,
		ConnectionKind:    "short",
		ShortTtlMs:        30_000,
	}
	raw, _ := firstNonNil(params["signer_connection_options"], params["signerConnectionOptions"]).(map[string]any)
	if raw == nil {
		return groupStorageSignerConnectionOptions{ConnectionOptions: options}
	}
	if value := storageAnyToString(firstNonNil(raw["connection_kind"], raw["connectionKind"])); strings.TrimSpace(value) != "" {
		options.ConnectionKind = strings.TrimSpace(value)
	}
	if value, ok := groupStorageIntOption(raw, "short_ttl_ms", "shortTtlMs"); ok {
		options.ShortTtlMs = value
	}
	if value, ok := groupStorageDurationOption(raw, "heartbeat_interval_ms", "heartbeatIntervalMs"); ok {
		options.HeartbeatInterval = value
	}
	if value, ok := groupStorageDurationOption(raw, "connect_timeout_ms", "connectTimeoutMs"); ok {
		options.ConnectTimeout = value
	}
	if value, ok := groupStorageDurationOption(raw, "call_timeout_ms", "callTimeoutMs"); ok {
		options.CallTimeout = value
	}
	if value, ok := groupStorageBoolOption(raw, "auto_reconnect", "autoReconnect"); ok {
		options.AutoReconnect = &value
	}
	return groupStorageSignerConnectionOptions{ConnectionOptions: options}
}

func groupStorageIntOption(raw map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		value, exists := raw[key]
		if !exists || value == nil {
			continue
		}
		return int(storageInt64(value)), true
	}
	return 0, false
}

func groupStorageDurationOption(raw map[string]any, keys ...string) (time.Duration, bool) {
	value, ok := groupStorageIntOption(raw, keys...)
	if !ok {
		return 0, false
	}
	return time.Duration(value) * time.Millisecond, true
}

func groupStorageBoolOption(raw map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		value, exists := raw[key]
		if !exists || value == nil {
			continue
		}
		if boolValue, ok := value.(bool); ok {
			return boolValue, true
		}
	}
	return false, false
}

func groupStorageDirs(params map[string]any) []string {
	raw := firstNonNil(params["paths"], params["baseline_dirs"], params["baselineDirs"], params["directories"], params["dirs"])
	var dirs []string
	switch values := raw.(type) {
	case []string:
		dirs = append(dirs, values...)
	case []any:
		for _, value := range values {
			dirs = append(dirs, storageAnyToString(value))
		}
	}
	cleaned := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		normalized := strings.Trim(strings.ReplaceAll(strings.TrimSpace(dir), "\\", "/"), "/")
		if normalized != "" {
			cleaned = append(cleaned, normalized)
		}
	}
	if len(cleaned) == 0 {
		return append([]string{}, groupStorageBaselineDirs...)
	}
	return cleaned
}

func groupStorageContainsDir(dirs []string, target string) bool {
	target = strings.Trim(strings.ReplaceAll(strings.TrimSpace(target), "\\", "/"), "/")
	for _, dir := range dirs {
		if strings.Trim(strings.ReplaceAll(strings.TrimSpace(dir), "\\", "/"), "/") == target {
			return true
		}
	}
	return false
}

func groupStorageConfirmParams(plan map[string]any) map[string]any {
	raw := firstNonNil(plan["confirm_params"], plan["confirmParams"])
	params, ok := raw.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	result := map[string]any{}
	for key, value := range params {
		result[key] = value
	}
	return result
}

func groupStoragePendingOps(plan map[string]any) ([]any, error) {
	raw := firstNonNil(plan["pending_ops"], plan["pendingOps"])
	if raw == nil {
		return []any{}, nil
	}
	switch ops := raw.(type) {
	case []any:
		return ops, nil
	case []map[string]any:
		result := make([]any, 0, len(ops))
		for _, op := range ops {
			result = append(result, op)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("ExecutePendingOps requires pending_ops array")
	}
}

func groupStorageApplyResultMappings(params map[string]any, op map[string]any, results map[string]any, opResults []any) {
	mappings, ok := firstNonNil(op["params_from_results"], op["paramsFromResults"]).(map[string]any)
	if !ok {
		return
	}
	context := map[string]any{
		"results":         results,
		"storage_results": results,
		"op_results":      opResults,
	}
	for resultKey, resultValue := range results {
		context[resultKey] = resultValue
	}
	for paramKey, pathValue := range mappings {
		if value, found := groupStorageResultPathValue(context, storageAnyToString(pathValue)); found {
			params[paramKey] = value
		}
	}
}

func groupStorageRunHTTPPut(ctx context.Context, plan map[string]any, params map[string]any) (map[string]any, error) {
	uploadURL := strings.TrimSpace(storageAnyToString(firstNonNil(params["upload_url"], params["uploadUrl"], params["url"])))
	if uploadURL == "" {
		return nil, fmt.Errorf("storage.http_put requires upload_url")
	}
	dataRef := strings.TrimSpace(storageAnyToString(firstNonNil(params["data_ref"], params["dataRef"])))
	if dataRef == "" {
		dataRef = "upload_data"
	}
	rawData := firstNonNil(params["data"])
	if rawData == nil {
		if dataRef == "upload_data" {
			rawData = firstNonNil(plan["upload_data"], plan["uploadData"])
		} else {
			rawData = plan[dataRef]
		}
	}
	data, err := groupStorageBytes(rawData)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	if rawHeaders, ok := params["headers"].(map[string]any); ok {
		for key, value := range rawHeaders {
			headers[key] = storageAnyToString(value)
		}
	}
	if rawHeaders, ok := params["headers"].(map[string]string); ok {
		for key, value := range rawHeaders {
			headers[key] = value
		}
	}
	contentType := strings.TrimSpace(storageAnyToString(firstNonNil(params["content_type"], params["contentType"])))
	hasContentType := false
	for key := range headers {
		if strings.EqualFold(key, "Content-Type") {
			hasContentType = true
			break
		}
	}
	if contentType != "" && !hasContentType {
		headers["Content-Type"] = contentType
	}
	result, err := groupStorageHTTPPut(ctx, uploadURL, data, headers)
	if err != nil {
		return nil, err
	}
	if result == nil {
		result = map[string]any{}
	}
	if _, exists := result["status"]; !exists {
		result["status"] = 200
	}
	if _, exists := result["upload_url"]; !exists {
		result["upload_url"] = uploadURL
	}
	if _, exists := result["size_bytes"]; !exists {
		result["size_bytes"] = len(data)
	}
	return result, nil
}

func groupStorageBytes(value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return nil, fmt.Errorf("storage.http_put requires upload_data")
	case []byte:
		return typed, nil
	case string:
		return []byte(typed), nil
	case io.Reader:
		return io.ReadAll(typed)
	default:
		return nil, fmt.Errorf("storage.http_put requires upload_data bytes")
	}
}

func groupStorageResultPathValue(source map[string]any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	var current any = source
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch typed := current.(type) {
		case map[string]any:
			value, exists := typed[part]
			if !exists || value == nil {
				return nil, false
			}
			current = value
		case []any:
			index := int(storageInt64(part))
			if fmt.Sprintf("%d", index) != part || index < 0 || index >= len(typed) || typed[index] == nil {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func groupStorageAIDStore(params map[string]any) *AIDStore {
	raw := firstNonNil(params["aid_store"], params["aidStore"])
	store, _ := raw.(*AIDStore)
	return store
}

func groupStorageClientAID(client StorageRPCClient) string {
	if provider, ok := client.(interface{ AID() string }); ok {
		if value := strings.TrimSpace(provider.AID()); value != "" {
			return value
		}
	}
	if provider, ok := client.(interface{ GetAID() string }); ok {
		return strings.TrimSpace(provider.GetAID())
	}
	return ""
}

func groupStorageSameAID(left string, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	return left != "" && right != "" && strings.EqualFold(left, right)
}

func groupStorageCloseSigners(cache map[string]groupStorageSignerClient) {
	for _, signer := range cache {
		if signer != nil {
			_ = signer.Close()
		}
	}
}

func groupStorageFirstIDFromMap(value any) string {
	result, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"folder_id", "node_id", "resource_id", "object_id", "id"} {
		text := strings.TrimSpace(storageAnyToString(result[key]))
		if text != "" {
			return text
		}
	}
	return groupStorageFirstIDFromMap(result["node"])
}
