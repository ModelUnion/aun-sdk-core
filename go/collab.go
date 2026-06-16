package aun

import (
	"context"
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
	Source        string `json:"source,omitempty"`
	Content       string `json:"content,omitempty"`
	Version       int    `json:"version,omitempty"`
	Author        string `json:"author,omitempty"`
	CurrentTarget string `json:"current_target,omitempty"`
	Conflicts     bool   `json:"conflicts,omitempty"`
}

type CollabHistoryEntry struct {
	Version int    `json:"version,omitempty"`
	Target  string `json:"target,omitempty"`
	Author  string `json:"author,omitempty"`
	Message string `json:"message,omitempty"`
	Time    int64  `json:"time,omitempty"`
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

type CollabSnapshotEntry struct {
	Doc           string `json:"doc,omitempty"`
	Anchor        string `json:"anchor,omitempty"`
	Version       int    `json:"version,omitempty"`
	Author        string `json:"author,omitempty"`
	CurrentTarget string `json:"current_target,omitempty"`
	Target        string `json:"target,omitempty"`
}

type CollabSnapshot struct {
	CollabRoot string                `json:"collab_root,omitempty"`
	Version    string                `json:"version,omitempty"`
	Message    string                `json:"message,omitempty"`
	CreatedAt  int64                 `json:"created_at,omitempty"`
	Major      bool                  `json:"major,omitempty"`
	Bump       string                `json:"bump,omitempty"`
	Changed    []string              `json:"changed,omitempty"`
	Entries    []CollabSnapshotEntry `json:"entries,omitempty"`
}

type CollabSnapshotDiffResult struct {
	CollabRoot string   `json:"collab_root,omitempty"`
	VersionA   string   `json:"version_a,omitempty"`
	VersionB   string   `json:"version_b,omitempty"`
	Added      []string `json:"added,omitempty"`
	Removed    []string `json:"removed,omitempty"`
	Changed    []string `json:"changed,omitempty"`
}

type CollabSnapshotRestoreResult struct {
	RestoredFrom       string   `json:"restored_from,omitempty"`
	NewSnapshotVersion string   `json:"new_snapshot_version,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
	Partial            bool     `json:"partial,omitempty"`
	RestoredDocs       []string `json:"restored_docs,omitempty"`
}

type CollabGCResult struct {
	Scanned    int `json:"scanned,omitempty"`
	Reachable  int `json:"reachable,omitempty"`
	Garbage    int `json:"garbage,omitempty"`
	Deleted    int `json:"deleted,omitempty"`
	FreedBytes int `json:"freed_bytes,omitempty"`
}

type CollabReflogEntry struct {
	Seq          int               `json:"seq,omitempty"`
	Action       string            `json:"action,omitempty"`
	Requester    string            `json:"requester,omitempty"`
	Doc          string            `json:"doc,omitempty"`
	Version      int               `json:"version,omitempty"`
	BaseVersion  int               `json:"base_version,omitempty"`
	Target       string            `json:"target,omitempty"`
	Status       string            `json:"status,omitempty"`
	ErrorCode    int               `json:"error_code,omitempty"`
	ErrorMsg     string            `json:"error_msg,omitempty"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
	Timestamp    int64             `json:"timestamp,omitempty"`
}

type CollabFacade struct {
	rpcFacade
	mu       sync.Mutex
	snapshot *CollabSnapshotFacade
}

func newCollabFacade(client StorageRPCClient) *CollabFacade {
	return &CollabFacade{rpcFacade: newRPCFacade(client, "collab")}
}

func (f *CollabFacade) call(ctx context.Context, name string, params map[string]any) (any, error) {
	result, err := f.rpcFacade.call(ctx, name, params)
	if err != nil {
		return nil, mapCollabError(err)
	}
	return result, nil
}

func (f *CollabFacade) Snapshot() *CollabSnapshotFacade {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapshot == nil {
		f.snapshot = &CollabSnapshotFacade{parent: f}
	}
	return f.snapshot
}

func (f *CollabFacade) LS(ctx context.Context, collabRoot string) ([]CollabDocumentEntry, error) {
	result, err := f.call(ctx, "ls", map[string]any{"collab_root": collabRoot})
	if err != nil {
		return nil, err
	}
	return collabDocumentEntriesFromAny(result), nil
}

func (f *CollabFacade) Ls(ctx context.Context, collabRoot string) ([]CollabDocumentEntry, error) {
	return f.LS(ctx, collabRoot)
}

func (f *CollabFacade) Create(ctx context.Context, collabRoot, doc, source string) (CollabDocumentResult, error) {
	return f.callDocument(ctx, "create", map[string]any{"collab_root": collabRoot, "doc": doc, "source": source})
}

func (f *CollabFacade) Read(ctx context.Context, collabRoot, doc string) (CollabDocumentResult, error) {
	return f.callDocument(ctx, "read", map[string]any{"collab_root": collabRoot, "doc": doc})
}

func (f *CollabFacade) Submit(ctx context.Context, collabRoot, doc, source string, baseVersion int, message string) (CollabDocumentResult, error) {
	return f.callDocument(ctx, "submit", map[string]any{
		"collab_root":  collabRoot,
		"doc":          doc,
		"source":       source,
		"base_version": baseVersion,
		"message":      message,
	})
}

func (f *CollabFacade) Merge(ctx context.Context, collabRoot, doc, source string, baseVersion int) (CollabDocumentResult, error) {
	return f.callDocument(ctx, "merge", map[string]any{"collab_root": collabRoot, "doc": doc, "source": source, "base_version": baseVersion})
}

func (f *CollabFacade) History(ctx context.Context, collabRoot, doc string) ([]CollabHistoryEntry, error) {
	result, err := f.call(ctx, "history", map[string]any{"collab_root": collabRoot, "doc": doc})
	if err != nil {
		return nil, err
	}
	return collabHistoryEntriesFromAny(result), nil
}

func (f *CollabFacade) Get(ctx context.Context, collabRoot, doc string, version int) (CollabDocumentResult, error) {
	return f.callDocument(ctx, "get", map[string]any{"collab_root": collabRoot, "doc": doc, "version": version})
}

func (f *CollabFacade) Diff(ctx context.Context, collabRoot, doc string, fromVersion, toVersion int) (CollabDiffResult, error) {
	result, err := f.call(ctx, "diff", map[string]any{"collab_root": collabRoot, "doc": doc, "from": fromVersion, "to": toVersion})
	if err != nil {
		return CollabDiffResult{}, err
	}
	return collabDiffResultFromAny(result), nil
}

func (f *CollabFacade) Export(ctx context.Context, collabRoot, dest string) (CollabActionResult, error) {
	return f.callAction(ctx, "export", map[string]any{"collab_root": collabRoot, "dest": dest})
}

func (f *CollabFacade) Adopt(ctx context.Context, src, newRoot string) (CollabActionResult, error) {
	return f.callAction(ctx, "adopt", map[string]any{"src": src, "new_root": newRoot})
}

func (f *CollabFacade) Prune(ctx context.Context, collabRoot, doc string) (CollabActionResult, error) {
	return f.callAction(ctx, "prune", map[string]any{"collab_root": collabRoot, "doc": doc})
}

func (f *CollabFacade) GC(ctx context.Context, collabRoot string, dryRun bool) (CollabGCResult, error) {
	result, err := f.call(ctx, "gc", map[string]any{"collab_root": collabRoot, "dry_run": dryRun})
	if err != nil {
		return CollabGCResult{}, err
	}
	return collabGCResultFromAny(result), nil
}

func (f *CollabFacade) Reflog(ctx context.Context, collabRoot string, doc string, limit int) ([]CollabReflogEntry, error) {
	params := map[string]any{"collab_root": collabRoot, "limit": limit}
	if doc != "" {
		params["doc"] = doc
	}
	result, err := f.call(ctx, "reflog", params)
	if err != nil {
		return nil, err
	}
	return collabReflogEntriesFromAny(result), nil
}

func (f *CollabFacade) Reset(ctx context.Context, collabRoot string, doc string, version int, message string) (CollabDocumentResult, error) {
	params := map[string]any{"collab_root": collabRoot, "doc": doc, "version": version}
	if message != "" {
		params["message"] = message
	}
	return f.callDocument(ctx, "reset", params)
}

func (f *CollabFacade) Discover(ctx context.Context, groupAID string) ([]CollabRegistryEntry, error) {
	result, err := f.call(ctx, "discover", map[string]any{"group_aid": groupAID})
	if err != nil {
		return nil, err
	}
	return collabRegistryEntriesFromAny(result), nil
}

func (f *CollabFacade) Unregister(ctx context.Context, groupAID, collabRoot string) (CollabActionResult, error) {
	return f.callAction(ctx, "unregister", map[string]any{"group_aid": groupAID, "collab_root": collabRoot})
}

func (f *CollabFacade) callDocument(ctx context.Context, name string, params map[string]any) (CollabDocumentResult, error) {
	result, err := f.call(ctx, name, params)
	if err != nil {
		return CollabDocumentResult{}, err
	}
	return collabDocumentResultFromAny(result), nil
}

func (f *CollabFacade) callAction(ctx context.Context, name string, params map[string]any) (CollabActionResult, error) {
	result, err := f.call(ctx, name, params)
	if err != nil {
		return CollabActionResult{}, err
	}
	return collabActionResultFromAny(result), nil
}

type CollabSnapshotFacade struct {
	parent *CollabFacade
}

func (f *CollabSnapshotFacade) Create(ctx context.Context, collabRoot, message string, major bool) (CollabSnapshot, error) {
	result, err := f.parent.call(ctx, "snapshot.create", map[string]any{"collab_root": collabRoot, "message": message, "major": major})
	if err != nil {
		return CollabSnapshot{}, err
	}
	return collabSnapshotFromAny(result), nil
}

func (f *CollabSnapshotFacade) List(ctx context.Context, collabRoot string) ([]CollabSnapshot, error) {
	result, err := f.parent.call(ctx, "snapshot.list", map[string]any{"collab_root": collabRoot})
	if err != nil {
		return nil, err
	}
	return collabSnapshotsFromAny(result), nil
}

func (f *CollabSnapshotFacade) Show(ctx context.Context, collabRoot, version string) (CollabSnapshot, error) {
	result, err := f.parent.call(ctx, "snapshot.show", map[string]any{"collab_root": collabRoot, "version": version})
	if err != nil {
		return CollabSnapshot{}, err
	}
	return collabSnapshotFromAny(result), nil
}

func (f *CollabSnapshotFacade) Diff(ctx context.Context, collabRoot, versionA, versionB string) (CollabSnapshotDiffResult, error) {
	result, err := f.parent.call(ctx, "snapshot.diff", map[string]any{"collab_root": collabRoot, "version_a": versionA, "version_b": versionB})
	if err != nil {
		return CollabSnapshotDiffResult{}, err
	}
	return collabSnapshotDiffResultFromAny(result), nil
}

func (f *CollabSnapshotFacade) Restore(ctx context.Context, collabRoot, version, message string) (CollabSnapshotRestoreResult, error) {
	result, err := f.parent.call(ctx, "snapshot.restore", map[string]any{"collab_root": collabRoot, "version": version, "message": message})
	if err != nil {
		return CollabSnapshotRestoreResult{}, err
	}
	return collabSnapshotRestoreResultFromAny(result), nil
}

func (f *CollabSnapshotFacade) Remove(ctx context.Context, collabRoot, version string) (CollabActionResult, error) {
	return f.parent.callAction(ctx, "snapshot.rm", map[string]any{"collab_root": collabRoot, "version": version})
}

func (f *CollabSnapshotFacade) Rm(ctx context.Context, collabRoot, version string) (CollabActionResult, error) {
	return f.Remove(ctx, collabRoot, version)
}

func (f *CollabSnapshotFacade) Prune(ctx context.Context, collabRoot string, before any, keepLast *int) (CollabActionResult, error) {
	params := map[string]any{"collab_root": collabRoot}
	if value, ok := collabOptionalValue(before); ok {
		params["before"] = value
	}
	if keepLast != nil {
		params["keep_last"] = *keepLast
	}
	return f.parent.callAction(ctx, "snapshot.prune", params)
}

func collabDocumentEntriesFromAny(value any) []CollabDocumentEntry {
	rows := collabMapList(value)
	out := make([]CollabDocumentEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, CollabDocumentEntry{
			CollabRoot:    storageString(row["collab_root"], ""),
			Doc:           storageString(row["doc"], ""),
			Anchor:        storageString(row["anchor"], ""),
			Version:       int(storageInt64(row["version"])),
			Author:        storageString(row["author"], ""),
			Target:        storageString(row["target"], ""),
			CurrentTarget: storageString(row["current_target"], ""),
			UpdatedAt:     storageInt64(row["updated_at"]),
		})
	}
	return out
}

func collabDocumentResultFromAny(value any) CollabDocumentResult {
	row := storageMap(value)
	return CollabDocumentResult{
		OK:            storageBool(row["ok"], false),
		CollabRoot:    storageString(row["collab_root"], ""),
		Doc:           storageString(row["doc"], ""),
		Anchor:        storageString(row["anchor"], ""),
		Source:        storageString(row["source"], ""),
		Content:       storageString(row["content"], ""),
		Version:       int(storageInt64(row["version"])),
		Author:        storageString(row["author"], ""),
		CurrentTarget: storageString(row["current_target"], ""),
		Conflicts:     storageBool(row["conflicts"], false),
	}
}

func collabHistoryEntriesFromAny(value any) []CollabHistoryEntry {
	rows := collabMapList(value)
	out := make([]CollabHistoryEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, CollabHistoryEntry{
			Version: int(storageInt64(row["version"])),
			Target:  storageString(row["target"], ""),
			Author:  storageString(row["author"], ""),
			Message: storageString(row["message"], ""),
			Time:    storageInt64(row["time"]),
		})
	}
	return out
}

func collabDiffResultFromAny(value any) CollabDiffResult {
	row := storageMap(value)
	return CollabDiffResult{
		CollabRoot: storageString(row["collab_root"], ""),
		Doc:        storageString(row["doc"], ""),
		From:       int(storageInt64(row["from"])),
		To:         int(storageInt64(row["to"])),
		Diff:       storageString(row["diff"], ""),
	}
}

func collabRegistryEntriesFromAny(value any) []CollabRegistryEntry {
	rows := collabMapList(value)
	out := make([]CollabRegistryEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, CollabRegistryEntry{
			GroupAID:     storageString(row["group_aid"], ""),
			AuthorityAID: storageString(row["authority_aid"], ""),
			CollabRoot:   storageString(row["collab_root"], ""),
		})
	}
	return out
}

func collabGCResultFromAny(value any) CollabGCResult {
	row := storageMap(value)
	return CollabGCResult{
		Scanned:    int(storageInt64(row["scanned"])),
		Reachable:  int(storageInt64(row["reachable"])),
		Garbage:    int(storageInt64(row["garbage"])),
		Deleted:    int(storageInt64(row["deleted"])),
		FreedBytes: int(storageInt64(row["freed_bytes"])),
	}
}

func collabReflogEntriesFromAny(value any) []CollabReflogEntry {
	rows := collabMapList(value)
	out := make([]CollabReflogEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, CollabReflogEntry{
			Seq:         int(storageInt64(row["seq"])),
			Action:      storageString(row["action"], ""),
			Requester:   storageString(row["requester"], ""),
			Doc:         storageString(row["doc"], ""),
			Version:     int(storageInt64(row["version"])),
			BaseVersion: int(storageInt64(row["base_version"])),
			Target:      storageString(row["target"], ""),
			Status:      storageString(row["status"], ""),
			ErrorCode:   int(storageInt64(row["error_code"])),
			ErrorMsg:    storageString(row["error_msg"], ""),
			Metadata:    storageMap(row["metadata"]),
			Timestamp:   storageInt64(row["timestamp"]),
		})
	}
	return out
}

func collabActionResultFromAny(value any) CollabActionResult {
	row := storageMap(value)
	return CollabActionResult{
		OK:              storageBool(row["ok"], false),
		Dest:            storageString(row["dest"], ""),
		CopiedObjects:   int(storageInt64(row["copied_objects"])),
		NewRoot:         storageString(row["new_root"], ""),
		NewAuthorityAID: storageString(row["new_authority_aid"], ""),
		Pruned:          int(storageInt64(row["pruned"])),
		Removed:         int(storageInt64(row["removed"])),
	}
}

func collabSnapshotFromAny(value any) CollabSnapshot {
	row := storageMap(value)
	return CollabSnapshot{
		CollabRoot: storageString(row["collab_root"], ""),
		Version:    storageString(row["version"], ""),
		Message:    storageString(row["message"], ""),
		CreatedAt:  storageInt64(row["created_at"]),
		Major:      storageBool(row["major"], false),
		Bump:       storageString(row["bump"], ""),
		Changed:    collabStringList(row["changed"]),
		Entries:    collabSnapshotEntriesFromAny(row["entries"]),
	}
}

func collabSnapshotsFromAny(value any) []CollabSnapshot {
	rows := collabMapList(value)
	out := make([]CollabSnapshot, 0, len(rows))
	for _, row := range rows {
		out = append(out, collabSnapshotFromAny(row))
	}
	return out
}

func collabSnapshotEntriesFromAny(value any) []CollabSnapshotEntry {
	rows := collabMapList(value)
	out := make([]CollabSnapshotEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, CollabSnapshotEntry{
			Doc:           storageString(row["doc"], ""),
			Anchor:        storageString(row["anchor"], ""),
			Version:       int(storageInt64(row["version"])),
			Author:        storageString(row["author"], ""),
			CurrentTarget: storageString(row["current_target"], ""),
			Target:        storageString(row["target"], ""),
		})
	}
	return out
}

func collabSnapshotDiffResultFromAny(value any) CollabSnapshotDiffResult {
	row := storageMap(value)
	return CollabSnapshotDiffResult{
		CollabRoot: storageString(row["collab_root"], ""),
		VersionA:   storageString(row["version_a"], ""),
		VersionB:   storageString(row["version_b"], ""),
		Added:      collabStringList(row["added"]),
		Removed:    collabStringList(row["removed"]),
		Changed:    collabStringList(row["changed"]),
	}
}

func collabSnapshotRestoreResultFromAny(value any) CollabSnapshotRestoreResult {
	row := storageMap(value)
	return CollabSnapshotRestoreResult{
		RestoredFrom:       storageString(row["restored_from"], ""),
		NewSnapshotVersion: storageString(row["new_snapshot_version"], ""),
		Warnings:           collabStringList(row["warnings"]),
		Partial:            storageBool(row["partial"], false),
		RestoredDocs:       collabStringList(row["restored_docs"]),
	}
}

func collabMapList(value any) []map[string]any {
	switch rows := value.(type) {
	case []map[string]any:
		return rows
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, item := range rows {
			out = append(out, storageMap(item))
		}
		return out
	default:
		return nil
	}
}

func collabStringList(value any) []string {
	switch rows := value.(type) {
	case []string:
		return rows
	case []any:
		out := make([]string, 0, len(rows))
		for _, item := range rows {
			out = append(out, storageString(item, ""))
		}
		return out
	default:
		return nil
	}
}

func collabOptionalValue(value any) (any, bool) {
	switch v := value.(type) {
	case nil:
		return nil, false
	case *int:
		if v == nil {
			return nil, false
		}
		return *v, true
	case *string:
		if v == nil {
			return nil, false
		}
		return *v, true
	default:
		return v, true
	}
}

func mapCollabError(err error) error {
	if err == nil {
		return nil
	}
	var collabConflict *CollabConflictError
	if errors.As(err, &collabConflict) {
		return err
	}

	var versionConflict *VersionConflictError
	if errors.As(err, &versionConflict) {
		return newCollabConflictError(versionConflict.Message, versionConflict.Code, versionConflict.Data, versionConflict.TraceID, err)
	}

	var aunErr *AUNError
	if errors.As(err, &aunErr) && aunErr.Code == -32009 {
		return newCollabConflictError(aunErr.Message, aunErr.Code, aunErr.Data, aunErr.TraceID, err)
	}

	return err
}

func newCollabConflictError(message string, code int, data any, traceID string, cause error) *CollabConflictError {
	if message == "" {
		message = "collab version conflict"
	}
	if code == 0 {
		code = -32009
	}
	payload := collabDataMap(data)
	var currentVersion *int
	if v, ok := collabInt(payload["current_version"]); ok {
		currentVersion = intPtr(v)
	}
	return &CollabConflictError{
		AUNError: AUNError{
			Message:   message,
			Code:      code,
			Data:      data,
			Retryable: false,
			TraceID:   traceID,
			Cause:     cause,
		},
		CurrentVersion: currentVersion,
		CurrentTarget:  stringFromAny(payload["current_target"]),
		Hint:           stringFromAny(payload["hint"]),
	}
}

func collabDataMap(data any) map[string]any {
	if data == nil {
		return map[string]any{}
	}
	if m, ok := data.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func collabInt(value any) (int, bool) {
	if n, ok := toInt(value); ok {
		return n, true
	}
	if s, ok := value.(string); ok && s != "" {
		n, err := strconv.Atoi(s)
		return n, err == nil
	}
	return 0, false
}
