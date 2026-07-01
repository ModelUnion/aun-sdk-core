package aun

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
)

// CollabError 是 collab.* RPC 的本地错误基类。
type CollabError struct{ AUNError }

// CollabConflictError 表示 collab 提交/合并时的版本冲突。
type CollabConflictError struct {
	AUNError
	CurrentVersion *int
	CurrentTarget  string
	Hint           string
}

type CollabDocumentEntry struct {
	CollabRoot    string `json:"collab_root,omitempty"`
	Doc           string `json:"doc,omitempty"`
	Anchor        string `json:"anchor,omitempty"`
	Version       int    `json:"version,omitempty"`
	Author        string `json:"author,omitempty"`
	Target        string `json:"target,omitempty"`
	CurrentTarget string `json:"current_target,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`
}

type CollabDocumentResult struct {
	OK            bool   `json:"ok,omitempty"`
	CollabRoot    string `json:"collab_root,omitempty"`
	Doc           string `json:"doc,omitempty"`
	Anchor        string `json:"anchor,omitempty"`
	Version       int    `json:"version,omitempty"`
	Author        string `json:"author,omitempty"`
	Content       string `json:"content,omitempty"`
	CurrentTarget string `json:"current_target,omitempty"`
	Target        string `json:"target,omitempty"`
	Conflicts     bool   `json:"conflicts,omitempty"`
}

type CollabLogEntry struct {
	Version int    `json:"version,omitempty"`
	Author  string `json:"author,omitempty"`
	Target  string `json:"target,omitempty"`
	Time    int64  `json:"time,omitempty"`
	Message string `json:"message,omitempty"`
}

type CollabDiffResult struct {
	CollabRoot string `json:"collab_root,omitempty"`
	Doc        string `json:"doc,omitempty"`
	From       int    `json:"from,omitempty"`
	To         int    `json:"to,omitempty"`
	Diff       string `json:"diff,omitempty"`
}

type CollabRegistryEntry struct {
	GroupAID     string `json:"group_aid,omitempty"`
	AuthorityAID string `json:"authority_aid,omitempty"`
	CollabRoot   string `json:"collab_root,omitempty"`
}

type CollabActionResult struct {
	OK              bool   `json:"ok,omitempty"`
	Dest            string `json:"dest,omitempty"`
	CopiedObjects   int    `json:"copied_objects,omitempty"`
	NewRoot         string `json:"new_root,omitempty"`
	NewAuthorityAID string `json:"new_authority_aid,omitempty"`
	Pruned          int    `json:"pruned,omitempty"`
	Removed         int    `json:"removed,omitempty"`
}

type CollabTagEntry struct {
	Doc           string `json:"doc,omitempty"`
	Anchor        string `json:"anchor,omitempty"`
	Version       int    `json:"version,omitempty"`
	Target        string `json:"target,omitempty"`
	CurrentTarget string `json:"current_target,omitempty"`
}

type CollabTag struct {
	Version   string           `json:"version,omitempty"`
	Author    string           `json:"author,omitempty"`
	CreatedAt int64            `json:"created_at,omitempty"`
	Message   string           `json:"message,omitempty"`
	Entries   []CollabTagEntry `json:"entries,omitempty"`
}

type CollabTagDiffResult struct {
	VersionA string           `json:"version_a,omitempty"`
	VersionB string           `json:"version_b,omitempty"`
	Added    []CollabTagEntry `json:"added,omitempty"`
	Removed  []CollabTagEntry `json:"removed,omitempty"`
	Changed  []string         `json:"changed,omitempty"`
	Modified []CollabTagEntry `json:"modified,omitempty"`
}

type CollabTagRestoreResult struct {
	RestoredFrom       string `json:"restored_from,omitempty"`
	NewSnapshotVersion string `json:"new_snapshot_version,omitempty"`
	Warnings           []any  `json:"warnings,omitempty"`
	RestoredDocs       []any  `json:"restored_docs,omitempty"`
}

type CollabGCResult struct {
	Scanned      int   `json:"scanned,omitempty"`
	Garbage      int   `json:"garbage,omitempty"`
	Deleted      int   `json:"deleted,omitempty"`
	DryRun       bool  `json:"dry_run,omitempty"`
	GarbageBytes int64 `json:"garbage_bytes,omitempty"`
	DeletedBytes int64 `json:"deleted_bytes,omitempty"`
}

type CollabReflogEntry struct {
	Action       string `json:"action,omitempty"`
	CollabRoot   string `json:"collab_root,omitempty"`
	Doc          string `json:"doc,omitempty"`
	Version      any    `json:"version,omitempty"`
	BaseVersion  any    `json:"base_version,omitempty"`
	Target       string `json:"target,omitempty"`
	RequesterAID string `json:"requester_aid,omitempty"`
	Status       string `json:"status,omitempty"`
	ErrorCode    any    `json:"error_code,omitempty"`
	ErrorMsg     string `json:"error_msg,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
}

type CollabSetACLOptions struct {
	ExpiresAt *int64
	MaxUses   *int
}

type CollabFacade struct {
	client    StorageRPCClient
	tagOnce   sync.Once
	tagFacade *CollabTagFacade
}

func newCollabFacade(client StorageRPCClient) *CollabFacade {
	return &CollabFacade{client: client}
}

func (f *CollabFacade) call(ctx context.Context, name string, params map[string]any) (any, error) {
	raw, err := f.client.Call(ctx, name, params)
	if err != nil {
		return nil, mapCollabError(err)
	}
	return raw, nil
}

func (f *CollabFacade) Tag() *CollabTagFacade {
	f.tagOnce.Do(func() {
		f.tagFacade = &CollabTagFacade{parent: f}
	})
	return f.tagFacade
}

func (f *CollabFacade) LsFiles(ctx context.Context, collabRoot string) ([]CollabDocumentEntry, error) {
	raw, err := f.call(ctx, "collab.ls-files", map[string]any{"collab_root": collabRoot})
	if err != nil {
		return nil, err
	}
	return toTypedSlice[CollabDocumentEntry](raw)
}

func (f *CollabFacade) Create(ctx context.Context, collabRoot, doc, source string) (CollabDocumentResult, error) {
	return f.callDocument(ctx, "collab.create", map[string]any{"collab_root": collabRoot, "doc": doc, "source": source})
}

func (f *CollabFacade) Show(ctx context.Context, collabRoot, doc string, rev *int) (CollabDocumentResult, error) {
	params := map[string]any{"collab_root": collabRoot, "doc": doc}
	if rev != nil {
		params["rev"] = *rev
	}
	return f.callDocument(ctx, "collab.show", params)
}

func (f *CollabFacade) Commit(ctx context.Context, collabRoot, doc, source string, onto int, message string) (CollabDocumentResult, error) {
	params := map[string]any{
		"collab_root": collabRoot,
		"doc":         doc,
		"source":      source,
		"onto":        onto,
		"message":     message,
	}
	return f.callDocument(ctx, "collab.commit", params)
}

func (f *CollabFacade) Merge(ctx context.Context, collabRoot, doc, source string, onto int) (CollabDocumentResult, error) {
	return f.callDocument(ctx, "collab.merge", map[string]any{"collab_root": collabRoot, "doc": doc, "source": source, "onto": onto})
}

func (f *CollabFacade) Log(ctx context.Context, collabRoot, doc string) ([]CollabLogEntry, error) {
	raw, err := f.call(ctx, "collab.log", map[string]any{"collab_root": collabRoot, "doc": doc})
	if err != nil {
		return nil, err
	}
	return toTypedSlice[CollabLogEntry](raw)
}

func (f *CollabFacade) Diff(ctx context.Context, collabRoot, doc string, fromVersion, toVersion int) (CollabDiffResult, error) {
	params := map[string]any{"collab_root": collabRoot, "doc": doc, "from": fromVersion, "to": toVersion}
	raw, err := f.call(ctx, "collab.diff", params)
	if err != nil {
		return CollabDiffResult{}, err
	}
	return toTyped[CollabDiffResult](raw)
}

func (f *CollabFacade) Clone(ctx context.Context, src, dest string, reroot bool) (CollabActionResult, error) {
	return f.callAction(ctx, "collab.clone", map[string]any{"src": src, "dest": dest, "reroot": reroot})
}

func (f *CollabFacade) Prune(ctx context.Context, collabRoot, doc string) (CollabActionResult, error) {
	return f.callAction(ctx, "collab.prune", map[string]any{"collab_root": collabRoot, "doc": doc})
}

func (f *CollabFacade) GC(ctx context.Context, collabRoot string, dryRun bool) (CollabGCResult, error) {
	raw, err := f.call(ctx, "collab.gc", map[string]any{"collab_root": collabRoot, "dry_run": dryRun})
	if err != nil {
		return CollabGCResult{}, err
	}
	return toTyped[CollabGCResult](raw)
}

func (f *CollabFacade) Reflog(ctx context.Context, collabRoot string, doc string, limit int) ([]CollabReflogEntry, error) {
	params := map[string]any{"collab_root": collabRoot, "limit": limit}
	if doc != "" {
		params["doc"] = doc
	}
	raw, err := f.call(ctx, "collab.reflog", params)
	if err != nil {
		return nil, err
	}
	return toTypedSlice[CollabReflogEntry](raw)
}

func (f *CollabFacade) Revert(ctx context.Context, collabRoot string, doc string, rev int, message string) (CollabDocumentResult, error) {
	params := map[string]any{
		"collab_root": collabRoot,
		"doc":         doc,
		"rev":         rev,
		"message":     message,
	}
	return f.callDocument(ctx, "collab.revert", params)
}

func (f *CollabFacade) LsRemote(ctx context.Context, groupAID string) ([]CollabRegistryEntry, error) {
	raw, err := f.call(ctx, "collab.ls-remote", map[string]any{"group_aid": groupAID})
	if err != nil {
		return nil, err
	}
	return toTypedSlice[CollabRegistryEntry](raw)
}

func (f *CollabFacade) Unregister(ctx context.Context, groupAID, collabRoot string) (CollabActionResult, error) {
	return f.callAction(ctx, "collab.unregister", map[string]any{"group_aid": groupAID, "collab_root": collabRoot})
}

func (f *CollabFacade) SetACL(ctx context.Context, collabRoot, granteeAID, perms string, opts ...CollabSetACLOptions) (map[string]any, error) {
	if perms == "" {
		perms = "w"
	}
	params := map[string]any{
		"collab_root": collabRoot,
		"grantee_aid": granteeAID,
		"perms":       perms,
	}
	if len(opts) > 0 {
		if opts[0].ExpiresAt != nil {
			params["expires_at"] = *opts[0].ExpiresAt
		}
		if opts[0].MaxUses != nil {
			params["max_uses"] = *opts[0].MaxUses
		}
	}
	raw, err := f.call(ctx, "collab.set_acl", params)
	if err != nil {
		return nil, err
	}
	out, ok := raw.(map[string]any)
	if !ok {
		return map[string]any{}, nil
	}
	return out, nil
}

func (f *CollabFacade) RemoveACL(ctx context.Context, collabRoot, granteeAID string) (map[string]any, error) {
	raw, err := f.call(ctx, "collab.remove_acl", map[string]any{
		"collab_root": collabRoot,
		"grantee_aid": granteeAID,
	})
	if err != nil {
		return nil, err
	}
	out, ok := raw.(map[string]any)
	if !ok {
		return map[string]any{}, nil
	}
	return out, nil
}

func (f *CollabFacade) callDocument(ctx context.Context, name string, params map[string]any) (CollabDocumentResult, error) {
	raw, err := f.call(ctx, name, params)
	if err != nil {
		return CollabDocumentResult{}, err
	}
	return toTyped[CollabDocumentResult](raw)
}

func (f *CollabFacade) callAction(ctx context.Context, name string, params map[string]any) (CollabActionResult, error) {
	raw, err := f.call(ctx, name, params)
	if err != nil {
		return CollabActionResult{}, err
	}
	return toTyped[CollabActionResult](raw)
}

type CollabTagFacade struct {
	parent *CollabFacade
}

func (f *CollabTagFacade) Create(ctx context.Context, collabRoot, message string, major bool) (CollabTag, error) {
	params := map[string]any{
		"collab_root": collabRoot,
		"message":     message,
		"major":       major,
	}
	raw, err := f.parent.call(ctx, "collab.tag.create", params)
	if err != nil {
		return CollabTag{}, err
	}
	return toTyped[CollabTag](raw)
}

func (f *CollabTagFacade) List(ctx context.Context, collabRoot string) ([]CollabTag, error) {
	raw, err := f.parent.call(ctx, "collab.tag.list", map[string]any{"collab_root": collabRoot})
	if err != nil {
		return nil, err
	}
	return toTypedSlice[CollabTag](raw)
}

func (f *CollabTagFacade) Show(ctx context.Context, collabRoot, version string) (CollabTag, error) {
	raw, err := f.parent.call(ctx, "collab.tag.show", map[string]any{"collab_root": collabRoot, "version": version})
	if err != nil {
		return CollabTag{}, err
	}
	return toTyped[CollabTag](raw)
}

func (f *CollabTagFacade) Diff(ctx context.Context, collabRoot, versionA, versionB string) (CollabTagDiffResult, error) {
	params := map[string]any{"collab_root": collabRoot, "version_a": versionA, "version_b": versionB}
	raw, err := f.parent.call(ctx, "collab.tag.diff", params)
	if err != nil {
		return CollabTagDiffResult{}, err
	}
	return toTyped[CollabTagDiffResult](raw)
}

func (f *CollabTagFacade) Restore(ctx context.Context, collabRoot, version, message string) (CollabTagRestoreResult, error) {
	params := map[string]any{"collab_root": collabRoot, "version": version, "message": message}
	raw, err := f.parent.call(ctx, "collab.tag.restore", params)
	if err != nil {
		return CollabTagRestoreResult{}, err
	}
	return toTyped[CollabTagRestoreResult](raw)
}

func (f *CollabTagFacade) Rm(ctx context.Context, collabRoot, version string) (CollabActionResult, error) {
	raw, err := f.parent.call(ctx, "collab.tag.rm", map[string]any{"collab_root": collabRoot, "version": version})
	if err != nil {
		return CollabActionResult{}, err
	}
	return toTyped[CollabActionResult](raw)
}

func (f *CollabTagFacade) Prune(ctx context.Context, collabRoot string, before any, keepLast *int) (CollabActionResult, error) {
	params := map[string]any{"collab_root": collabRoot}
	if before != nil {
		// Dereference pointer types for before
		switch v := before.(type) {
		case *int:
			if v != nil {
				params["before"] = *v
			}
		case *string:
			if v != nil {
				params["before"] = *v
			}
		default:
			params["before"] = before
		}
	}
	if keepLast != nil {
		params["keep_last"] = *keepLast
	}
	raw, err := f.parent.call(ctx, "collab.tag.prune", params)
	if err != nil {
		return CollabActionResult{}, err
	}
	return toTyped[CollabActionResult](raw)
}

func mapCollabError(err error) error {
	// First check if it's already a specific error type with embedded AUNError
	var versionConflict *VersionConflictError
	if errors.As(err, &versionConflict) && versionConflict.Code == -32009 {
		data, ok := versionConflict.Data.(map[string]any)
		if !ok {
			return &CollabConflictError{AUNError: versionConflict.AUNError}
		}
		conflict := &CollabConflictError{AUNError: versionConflict.AUNError}
		conflict.CurrentVersion = collabVersionPtr(data["current_version"])
		if ct, ok := data["current_target"].(string); ok {
			conflict.CurrentTarget = ct
		}
		if h, ok := data["hint"].(string); ok {
			conflict.Hint = h
		}
		return conflict
	}

	// Fall back to generic AUNError check
	var aunErr *AUNError
	if !errors.As(err, &aunErr) {
		return err
	}
	if aunErr == nil || aunErr.Code != -32009 {
		return &CollabError{AUNError: *aunErr}
	}
	data, ok := aunErr.Data.(map[string]any)
	if !ok {
		return &CollabError{AUNError: *aunErr}
	}
	conflict := &CollabConflictError{AUNError: *aunErr}
	conflict.CurrentVersion = collabVersionPtr(data["current_version"])
	if ct, ok := data["current_target"].(string); ok {
		conflict.CurrentTarget = ct
	}
	if h, ok := data["hint"].(string); ok {
		conflict.Hint = h
	}
	return conflict
}

func collabVersionPtr(value any) *int {
	switch v := value.(type) {
	case int:
		return &v
	case int64:
		n := int(v)
		return &n
	case float64:
		n := int(v)
		return &n
	case json.Number:
		if i, err := v.Int64(); err == nil {
			n := int(i)
			return &n
		}
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return &n
		}
	}
	return nil
}

func toTyped[T any](raw any) (T, error) {
	var zero T
	data, err := json.Marshal(raw)
	if err != nil {
		return zero, err
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return zero, err
	}
	return result, nil
}

func toTypedSlice[T any](raw any) ([]T, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var result []T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
