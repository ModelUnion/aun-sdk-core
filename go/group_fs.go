package aun

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type GroupFSVFS struct {
	client StorageRPCClient
	low    *StorageLowLevel
}

type GroupFSStorageRef struct {
	OwnerAID string `json:"owner_aid"`
	Bucket   string `json:"bucket"`
	Path     string `json:"path"`
}

type GroupFSNodeView struct {
	NodeView
	GroupID   string            `json:"group_id"`
	GroupAID  string            `json:"group_aid"`
	Area      string            `json:"area"`
	MemberAID string            `json:"member_aid,omitempty"`
	MemberRef string            `json:"member_ref,omitempty"`
	Storage   GroupFSStorageRef `json:"storage"`
	Raw       map[string]any    `json:"raw,omitempty"`
}

type GroupFSListResult struct {
	Path     string            `json:"path"`
	GroupID  string            `json:"group_id"`
	GroupAID string            `json:"group_aid"`
	Items    []GroupFSNodeView `json:"items"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	Size     int               `json:"size"`
	Raw      map[string]any    `json:"raw,omitempty"`
}

type GroupFSFindResult struct {
	Path     string            `json:"path"`
	GroupID  string            `json:"group_id"`
	GroupAID string            `json:"group_aid"`
	Items    []GroupFSNodeView `json:"items"`
	Total    int64             `json:"total"`
	Raw      map[string]any    `json:"raw,omitempty"`
}

type GroupFSRemoveResult struct {
	Path         string            `json:"path"`
	GroupID      string            `json:"group_id"`
	GroupAID     string            `json:"group_aid"`
	Area         string            `json:"area"`
	RemovedCount int64             `json:"removed_count"`
	Storage      GroupFSStorageRef `json:"storage"`
	Raw          map[string]any    `json:"raw,omitempty"`
}

type GroupFSUsageResult struct {
	UsageView
	Path     string            `json:"path"`
	GroupID  string            `json:"group_id"`
	GroupAID string            `json:"group_aid"`
	Area     string            `json:"area"`
	Storage  GroupFSStorageRef `json:"storage"`
	Raw      map[string]any    `json:"raw,omitempty"`
}

type GroupFSUnmountResult struct {
	UnmountResult
	GroupID   string            `json:"group_id"`
	GroupAID  string            `json:"group_aid"`
	Area      string            `json:"area"`
	MemberAID string            `json:"member_aid,omitempty"`
	Storage   GroupFSStorageRef `json:"storage"`
	Raw       map[string]any    `json:"raw,omitempty"`
}

type GroupFSListOptions struct {
	Page      int
	Size      int
	Marker    string
	Token     string
	Long      bool
	Recursive bool
	SignAs    string
	AidStore  *AIDStore
	Extra     map[string]any
}

type GroupFSFindOptions struct {
	Pattern  string
	Name     string
	NodeType string
	Size     string
	MTime    string
	Page     int
	PageSize int
	Token    string
	SignAs   string
	AidStore *AIDStore
	Extra    map[string]any
}

type GroupFSStatOptions struct {
	Token    string
	SignAs   string
	AidStore *AIDStore
	Extra    map[string]any
}

type GroupFSMkdirOptions struct {
	Parents  bool
	SignAs   string
	AidStore *AIDStore
	Extra    map[string]any
}

type GroupFSAclOptions struct {
	GranteeAID string
	Perms      string
	SignAs     string
	AidStore   *AIDStore
	Extra      map[string]any
}

type GroupFSRmOptions struct {
	Recursive bool
	Force     bool
	SignAs    string
	AidStore  *AIDStore
	Extra     map[string]any
}

type GroupFSMvOptions struct {
	Force      bool
	GroupID    string
	SrcGroupID string
	DstGroupID string
	SignAs     string
	AidStore   *AIDStore
	Extra      map[string]any
}

type GroupFSDfOptions struct {
	GroupID  string
	Bucket   string
	SignAs   string
	AidStore *AIDStore
	Extra    map[string]any
}

type GroupFSMountOptions struct {
	Readonly        *bool
	RequireApproval bool
	SourceBucket    string
	ExpiresAt       *int64
	VolumeID        string
	SignAs          string
	AidStore        *AIDStore
	Extra           map[string]any
}

type GroupFSUmountOptions struct {
	SignAs   string
	AidStore *AIDStore
	Extra    map[string]any
}

type GroupFSCpOptions struct {
	Force           bool
	Recursive       bool
	Parents         bool
	FollowSymlinks  *bool
	ContentType     string
	Metadata        map[string]any
	ExpectedVersion *int
	VerifyHash      *bool
	GroupID         string
	SrcGroupID      string
	DstGroupID      string
	SignAs          string
	AidStore        *AIDStore
	Extra           map[string]any
}

type GroupFSCpResult struct {
	Direction string          `json:"direction"`
	Raw       map[string]any  `json:"raw,omitempty"`
	Node      GroupFSNodeView `json:"node,omitempty"`
	Download  DownloadResult  `json:"download,omitempty"`
}

func NewGroupFSVFS(client StorageRPCClient) *GroupFSVFS {
	return &GroupFSVFS{client: client, low: NewStorageLowLevel(client)}
}

func IsGroupRemotePath(value string) bool {
	text := strings.TrimSpace(value)
	if text == "" {
		return false
	}
	if groupFSIsExplicitLocalPath(text) {
		return false
	}
	if len(text) >= 3 && text[1] == ':' && (text[2] == '/' || text[2] == '\\') {
		first := text[0]
		if (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') {
			return false
		}
	}
	if strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://") {
		return true
	}
	colon := strings.IndexByte(text, ':')
	if colon <= 0 || colon+1 >= len(text) || text[colon+1] != '/' {
		return false
	}
	prefix := text[:colon]
	return !strings.ContainsAny(prefix, `/\`)
}

func groupFSIsExplicitLocalPath(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "local:")
}

func groupFSStripLocalPathPrefix(value string) string {
	text := strings.TrimSpace(value)
	if groupFSIsExplicitLocalPath(text) {
		return text[len("local:"):]
	}
	return text
}

func groupFSIsRemoteCopyPath(value string, groupHints ...string) bool {
	if groupFSIsExplicitLocalPath(value) {
		return false
	}
	if IsGroupRemotePath(value) {
		return true
	}
	for _, hint := range groupHints {
		if strings.TrimSpace(hint) != "" {
			return true
		}
	}
	return false
}

func (v *GroupFSVFS) Ls(ctx context.Context, p string, opts *GroupFSListOptions) (GroupFSListResult, error) {
	params := map[string]any{"path": p}
	if opts != nil {
		if opts.Page > 0 {
			params["page"] = opts.Page
		}
		if opts.Size > 0 {
			params["size"] = opts.Size
		}
		if opts.Marker != "" {
			params["marker"] = opts.Marker
		}
		if opts.Token != "" {
			params["token"] = opts.Token
		}
		if opts.Long {
			params["long"] = true
		}
		if opts.Recursive {
			params["recursive"] = true
		}
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	raw, err := v.call(ctx, "group.fs.ls", params, p)
	if err != nil {
		return GroupFSListResult{}, err
	}
	return groupFSListResultFromRaw(raw), nil
}

func (v *GroupFSVFS) Find(ctx context.Context, p string, opts *GroupFSFindOptions) (GroupFSFindResult, error) {
	params := map[string]any{"path": p}
	if opts != nil {
		if opts.Pattern != "" {
			params["pattern"] = opts.Pattern
		}
		if opts.Name != "" {
			params["name"] = opts.Name
		}
		if opts.NodeType != "" {
			params["type"] = opts.NodeType
		}
		if opts.Size != "" {
			params["size"] = opts.Size
		}
		if opts.MTime != "" {
			params["mtime"] = opts.MTime
		}
		if opts.Page > 0 {
			params["page"] = opts.Page
		}
		if opts.PageSize > 0 {
			params["page_size"] = opts.PageSize
		}
		if opts.Token != "" {
			params["token"] = opts.Token
		}
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	raw, err := v.call(ctx, "group.fs.find", params, p)
	if err != nil {
		return GroupFSFindResult{}, err
	}
	return groupFSFindResultFromRaw(raw), nil
}

func (v *GroupFSVFS) Stat(ctx context.Context, p string, opts *GroupFSStatOptions) (GroupFSNodeView, error) {
	raw, err := v.call(ctx, "group.fs.stat", groupFSStatParams(p, opts), p)
	if err != nil {
		return GroupFSNodeView{}, err
	}
	return GroupFSNodeViewFromAny(raw), nil
}

func (v *GroupFSVFS) Lstat(ctx context.Context, p string, opts *GroupFSStatOptions) (GroupFSNodeView, error) {
	raw, err := v.call(ctx, "group.fs.lstat", groupFSStatParams(p, opts), p)
	if err != nil {
		return GroupFSNodeView{}, err
	}
	return GroupFSNodeViewFromAny(raw), nil
}

func (v *GroupFSVFS) Mkdir(ctx context.Context, p string, opts *GroupFSMkdirOptions) (GroupFSNodeView, error) {
	params := map[string]any{"path": p, "parents": false}
	if opts != nil {
		params["parents"] = opts.Parents
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	raw, err := v.call(ctx, "group.fs.mkdir", params, p)
	if err != nil {
		return GroupFSNodeView{}, err
	}
	return GroupFSNodeViewFromAny(raw), nil
}

func (v *GroupFSVFS) SetACL(ctx context.Context, p string, opts *GroupFSAclOptions) (map[string]any, error) {
	params := map[string]any{"path": p, "grantee_aid": "role:admin", "perms": "rwx"}
	if opts != nil {
		if opts.GranteeAID != "" {
			params["grantee_aid"] = opts.GranteeAID
		}
		if opts.Perms != "" {
			params["perms"] = opts.Perms
		}
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	return v.call(ctx, "group.fs.set_acl", params, p)
}

func (v *GroupFSVFS) RemoveACL(ctx context.Context, p string, opts *GroupFSAclOptions) (map[string]any, error) {
	params := map[string]any{"path": p, "grantee_aid": "role:admin"}
	if opts != nil {
		if opts.GranteeAID != "" {
			params["grantee_aid"] = opts.GranteeAID
		}
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	return v.call(ctx, "group.fs.remove_acl", params, p)
}

func (v *GroupFSVFS) Rm(ctx context.Context, p string, opts *GroupFSRmOptions) (GroupFSRemoveResult, error) {
	params := map[string]any{"path": p, "recursive": false, "force": false}
	if opts != nil {
		params["recursive"] = opts.Recursive
		params["force"] = opts.Force
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	raw, err := v.call(ctx, "group.fs.rm", params, p)
	if err != nil {
		return GroupFSRemoveResult{}, err
	}
	return groupFSRemoveResultFromRaw(raw), nil
}

func (v *GroupFSVFS) Cp(ctx context.Context, src, dst string, opts *GroupFSCpOptions) (GroupFSCpResult, error) {
	if opts == nil {
		opts = &GroupFSCpOptions{}
	}
	srcRemote := groupFSIsRemoteCopyPath(src, opts.SrcGroupID, opts.GroupID)
	dstRemote := groupFSIsRemoteCopyPath(dst, opts.DstGroupID, opts.GroupID)
	switch {
	case srcRemote && dstRemote:
		raw, err := v.copyGroupToGroup(ctx, src, dst, opts)
		if err != nil {
			return GroupFSCpResult{}, err
		}
		return GroupFSCpResult{Direction: "group_to_group", Raw: raw, Node: GroupFSNodeViewFromAny(raw)}, nil
	case !srcRemote && dstRemote:
		raw, err := v.uploadLocalFile(ctx, src, dst, opts)
		if err != nil {
			return GroupFSCpResult{}, err
		}
		return GroupFSCpResult{Direction: "local_to_group", Raw: raw, Node: GroupFSNodeViewFromAny(raw)}, nil
	case srcRemote && !dstRemote:
		download, err := v.downloadRemoteFile(ctx, src, dst, opts)
		if err != nil {
			return GroupFSCpResult{}, err
		}
		return GroupFSCpResult{Direction: "group_to_local", Download: download}, nil
	default:
		return GroupFSCpResult{}, &StorageError{Message: "local-to-local copy is not handled by group.fs", Code: "EINVAL", Path: src}
	}
}

func (v *GroupFSVFS) Mv(ctx context.Context, src, dst string, opts *GroupFSMvOptions) (GroupFSNodeView, error) {
	if opts == nil {
		opts = &GroupFSMvOptions{}
	}
	if !groupFSIsRemoteCopyPath(src, opts.SrcGroupID, opts.GroupID) ||
		!groupFSIsRemoteCopyPath(dst, opts.DstGroupID, opts.GroupID) {
		return GroupFSNodeView{}, &StorageError{Message: "group.fs.mv only supports group remote paths", Code: "EINVAL", Path: src}
	}
	params := map[string]any{"src": src, "dst": dst}
	if opts.Force {
		params["force"] = true
	}
	groupFSAddGroupParams(params, opts.GroupID, opts.SrcGroupID, opts.DstGroupID)
	params = groupFSParams(params, opts.Extra)
	groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	raw, err := v.call(ctx, "group.fs.mv", params, src)
	if err != nil {
		return GroupFSNodeView{}, err
	}
	return GroupFSNodeViewFromAny(raw), nil
}

func (v *GroupFSVFS) Df(ctx context.Context, pathOrGroup string, opts *GroupFSDfOptions) (GroupFSUsageResult, error) {
	params := map[string]any{}
	if pathOrGroup != "" {
		params["path"] = pathOrGroup
	}
	if opts != nil {
		if opts.GroupID != "" {
			params["group_id"] = opts.GroupID
		}
		if opts.Bucket != "" {
			params["bucket"] = opts.Bucket
		}
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	raw, err := v.call(ctx, "group.fs.df", params, pathOrGroup)
	if err != nil {
		return GroupFSUsageResult{}, err
	}
	return groupFSUsageResultFromRaw(raw), nil
}

func (v *GroupFSVFS) Mount(ctx context.Context, p string, opts *GroupFSMountOptions) (GroupFSNodeView, error) {
	params := map[string]any{"path": p}
	if opts != nil {
		if opts.Readonly != nil {
			params["readonly"] = *opts.Readonly
		}
		if opts.RequireApproval {
			params["require_approval"] = true
		}
		if opts.SourceBucket != "" {
			params["source_bucket"] = opts.SourceBucket
		}
		if opts.ExpiresAt != nil {
			params["expires_at"] = *opts.ExpiresAt
		}
		if opts.VolumeID != "" {
			params["volume_id"] = opts.VolumeID
		}
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	raw, err := v.call(ctx, "group.fs.mount", params, p)
	if err != nil {
		return GroupFSNodeView{}, err
	}
	return GroupFSNodeViewFromAny(raw), nil
}

func (v *GroupFSVFS) Umount(ctx context.Context, p string, opts *GroupFSUmountOptions) (GroupFSUnmountResult, error) {
	params := map[string]any{"path": p}
	if opts != nil {
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	raw, err := v.call(ctx, "group.fs.umount", params, p)
	if err != nil {
		return GroupFSUnmountResult{}, err
	}
	return groupFSUnmountResultFromRaw(raw), nil
}

func (v *GroupFSVFS) call(ctx context.Context, method string, params map[string]any, p string) (map[string]any, error) {
	payload := facadeParams(params)
	if err := v.applySigningIdentity(payload); err != nil {
		return nil, MapStorageError(err, p)
	}
	result, err := v.client.Call(ctx, method, payload)
	if err != nil {
		return nil, MapStorageError(err, p)
	}
	if m, ok := result.(map[string]any); ok {
		return m, nil
	}
	if m, ok := result.(map[string]interface{}); ok {
		return map[string]any(m), nil
	}
	return map[string]any{"result": result}, nil
}

func (v *GroupFSVFS) copyGroupToGroup(ctx context.Context, src, dst string, opts *GroupFSCpOptions) (map[string]any, error) {
	params := map[string]any{"src": src, "dst": dst}
	if opts.Force {
		params["force"] = true
	}
	if opts.Recursive {
		params["recursive"] = true
	}
	if opts.FollowSymlinks != nil {
		params["follow_symlinks"] = *opts.FollowSymlinks
	}
	groupFSAddGroupParams(params, opts.GroupID, opts.SrcGroupID, opts.DstGroupID)
	params = groupFSParams(params, opts.Extra)
	groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	return v.call(ctx, "group.fs.cp", params, src)
}

func (v *GroupFSVFS) uploadLocalFile(ctx context.Context, localPath, groupPath string, opts *GroupFSCpOptions) (map[string]any, error) {
	localPath = groupFSStripLocalPathPrefix(localPath)
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, &StorageIsADirectoryError{StorageError{Message: "directory upload is not supported by group.fs.cp yet", Code: "EISDIR", Path: localPath}}
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	shaHex := fmt.Sprintf("%x", sum[:])
	contentTyp := firstNonEmpty(opts.ContentType, groupFSContentTypeForPath(localPath))
	baseParams := map[string]any{
		"path":         groupPath,
		"size_bytes":   len(data),
		"sha256":       shaHex,
		"content_type": contentTyp,
		"force":        opts.Force,
		"parents":      true,
		"metadata":     opts.Metadata,
	}
	if opts.ExpectedVersion != nil {
		baseParams["expected_version"] = *opts.ExpectedVersion
	}
	if opts.GroupID != "" || opts.DstGroupID != "" {
		groupFSAddGroupParams(baseParams, opts.GroupID, "", opts.DstGroupID)
	}
	baseParams = groupFSParams(baseParams, opts.Extra)
	groupFSAddSigningParams(baseParams, opts.SignAs, opts.AidStore)

	check, err := v.call(ctx, "group.fs.check_upload", mapCopy(baseParams), groupPath)
	if err != nil {
		return nil, err
	}
	if storageBool(check["within_limit"], true) == false {
		return nil, &StorageError{Message: "file size exceeds group fs upload limit", Code: "E2BIG", Path: groupPath, Data: check}
	}
	if storageBool(check["target_exists"], false) && !opts.Force && opts.ExpectedVersion == nil {
		return nil, &StorageExistsError{StorageError{Message: "group fs target already exists", Code: "EEXIST", Path: groupPath, Data: check["target"]}}
	}
	if groupFSInstantUpload(check) {
		completeParams := mapCopy(baseParams)
		completeParams["skip_blob"] = true
		if sessionID := storageString(check["session_id"], ""); sessionID != "" {
			completeParams["session_id"] = sessionID
		}
		return v.call(ctx, "group.fs.complete_upload", completeParams, groupPath)
	}

	session, err := v.call(ctx, "group.fs.create_upload_session", mapCopy(baseParams), groupPath)
	if err != nil {
		return nil, err
	}
	uploadURL := storageString(firstNonNil(session["upload_url"], session["url"]), "")
	if uploadURL == "" {
		return nil, &StorageError{Message: fmt.Sprintf("group.fs.create_upload_session did not return upload_url: %v", session), Code: "ESTORAGE", Path: groupPath}
	}
	headers := storageHeadersFromAny(session["headers"])
	if _, exists := headers["Content-Type"]; !exists {
		headers["Content-Type"] = contentTyp
	}
	if err := v.low.HTTPPut(ctx, uploadURL, data, headers); err != nil {
		return nil, MapStorageError(err, groupPath)
	}
	completeParams := mapCopy(baseParams)
	if sessionID := storageString(firstNonNil(session["session_id"], session["id"]), ""); sessionID != "" {
		completeParams["session_id"] = sessionID
	}
	return v.call(ctx, "group.fs.complete_upload", completeParams, groupPath)
}

func (v *GroupFSVFS) downloadRemoteFile(ctx context.Context, groupPath, localPath string, opts *GroupFSCpOptions) (DownloadResult, error) {
	targetPath := groupFSStripLocalPathPrefix(localPath)
	if info, statErr := os.Stat(targetPath); statErr == nil {
		if !info.IsDir() && !opts.Force {
			return DownloadResult{}, &StorageExistsError{StorageError{Message: "local path already exists", Code: "EEXIST", Path: targetPath}}
		}
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return DownloadResult{}, statErr
	}

	ticketParams := map[string]any{"path": groupPath}
	if opts.GroupID != "" || opts.SrcGroupID != "" {
		groupFSAddGroupParams(ticketParams, opts.GroupID, opts.SrcGroupID, "")
	}
	ticketParams = groupFSParams(ticketParams, opts.Extra)
	groupFSAddSigningParams(ticketParams, opts.SignAs, opts.AidStore)
	ticket, err := v.call(ctx, "group.fs.create_download_ticket", ticketParams, groupPath)
	if err != nil {
		return DownloadResult{}, err
	}
	downloadURL := storageString(firstNonNil(ticket["download_url"], ticket["url"]), "")
	if downloadURL == "" {
		return DownloadResult{}, &StorageError{Message: fmt.Sprintf("group.fs.create_download_ticket did not return download_url: %v", ticket), Code: "ESTORAGE", Path: groupPath}
	}
	if info, statErr := os.Stat(targetPath); statErr == nil && info.IsDir() {
		fileName := storageString(firstNonNil(ticket["file_name"], ticket["name"]), "")
		if fileName == "" {
			fileName = filepath.Base(groupPath)
		}
		if strings.TrimSpace(fileName) == "" || fileName == "." || fileName == string(filepath.Separator) {
			fileName = "download"
		}
		targetPath = filepath.Join(targetPath, fileName)
		if _, err := os.Stat(targetPath); err == nil && !opts.Force {
			return DownloadResult{}, &StorageExistsError{StorageError{Message: "local path already exists", Code: "EEXIST", Path: targetPath}}
		} else if err != nil && !os.IsNotExist(err) {
			return DownloadResult{}, err
		}
	}

	data, err := v.low.HTTPGet(ctx, downloadURL, groupFSBearerHeaders(v.client))
	if err != nil {
		return DownloadResult{}, MapStorageError(err, groupPath)
	}
	expectedSHA := strings.ToLower(storageString(ticket["sha256"], ""))
	actualSum := sha256.Sum256(data)
	actualSHA := fmt.Sprintf("%x", actualSum[:])
	verifyHash := true
	if opts.VerifyHash != nil {
		verifyHash = *opts.VerifyHash
	}
	verified := !verifyHash || expectedSHA == "" || expectedSHA == actualSHA
	if verifyHash && !verified {
		return DownloadResult{}, &StorageError{Message: "download hash verification failed", Code: "ECONFLICT", Path: groupPath, Data: ticket}
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return DownloadResult{}, err
	}
	if opts.Force {
		if err := os.WriteFile(targetPath, data, 0o600); err != nil {
			return DownloadResult{}, err
		}
	} else {
		file, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				return DownloadResult{}, &StorageExistsError{StorageError{Message: "local path already exists", Code: "EEXIST", Path: targetPath}}
			}
			return DownloadResult{}, err
		}
		if _, err := file.Write(data); err != nil {
			_ = file.Close()
			return DownloadResult{}, err
		}
		if err := file.Close(); err != nil {
			return DownloadResult{}, err
		}
	}
	return DownloadResult{
		Path:      groupPath,
		LocalPath: targetPath,
		Size:      int64(len(data)),
		SHA256:    firstNonEmpty(expectedSHA, actualSHA),
		Verified:  verified,
		Data:      data,
	}, nil
}

func groupFSParams(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range base {
		if !isNilStorageParam(value) {
			out[key] = value
		}
	}
	for key, value := range extra {
		if !isNilStorageParam(value) {
			out[key] = value
		}
	}
	return out
}

func groupFSStatParams(p string, opts *GroupFSStatOptions) map[string]any {
	params := map[string]any{"path": p}
	if opts != nil {
		if opts.Token != "" {
			params["token"] = opts.Token
		}
		params = groupFSParams(params, opts.Extra)
		groupFSAddSigningParams(params, opts.SignAs, opts.AidStore)
	}
	return params
}

func groupFSListResultFromRaw(raw map[string]any) GroupFSListResult {
	itemsRaw, _ := firstNonNil(raw["items"], raw["nodes"]).([]any)
	items := make([]GroupFSNodeView, 0, len(itemsRaw))
	for _, item := range itemsRaw {
		items = append(items, GroupFSNodeViewFromAny(item))
	}
	return GroupFSListResult{
		Path:     storageString(raw["path"], ""),
		GroupID:  storageString(raw["group_id"], ""),
		GroupAID: storageString(raw["group_aid"], ""),
		Items:    items,
		Total:    storageInt64(firstNonNil(raw["total"], len(items))),
		Page:     int(storageInt64(raw["page"])),
		Size:     int(storageInt64(raw["size"])),
		Raw:      raw,
	}
}

func groupFSFindResultFromRaw(raw map[string]any) GroupFSFindResult {
	itemsRaw, _ := firstNonNil(raw["items"], raw["nodes"]).([]any)
	items := make([]GroupFSNodeView, 0, len(itemsRaw))
	for _, item := range itemsRaw {
		items = append(items, GroupFSNodeViewFromAny(item))
	}
	return GroupFSFindResult{
		Path:     storageString(raw["path"], ""),
		GroupID:  storageString(raw["group_id"], ""),
		GroupAID: storageString(raw["group_aid"], ""),
		Items:    items,
		Total:    storageInt64(firstNonNil(raw["total"], len(items))),
		Raw:      raw,
	}
}

func groupFSRemoveResultFromRaw(raw map[string]any) GroupFSRemoveResult {
	return GroupFSRemoveResult{
		Path:         storageString(raw["path"], ""),
		GroupID:      storageString(raw["group_id"], ""),
		GroupAID:     storageString(raw["group_aid"], ""),
		Area:         storageString(raw["area"], ""),
		RemovedCount: storageInt64(firstNonNil(raw["removed_count"], raw["deleted_count"])),
		Storage:      groupFSStorageRefFromAny(raw["storage"]),
		Raw:          raw,
	}
}

func groupFSUsageResultFromRaw(raw map[string]any) GroupFSUsageResult {
	return GroupFSUsageResult{
		UsageView: UsageViewFromAny(raw, storageString(raw["group_aid"], "")),
		Path:      storageString(raw["path"], ""),
		GroupID:   storageString(raw["group_id"], ""),
		GroupAID:  storageString(raw["group_aid"], ""),
		Area:      storageString(raw["area"], ""),
		Storage:   groupFSStorageRefFromAny(raw["storage"]),
		Raw:       raw,
	}
}

func groupFSUnmountResultFromRaw(raw map[string]any) GroupFSUnmountResult {
	pathValue := storageKeyToPath(firstNonNil(raw["mount_path"], raw["path"]))
	return GroupFSUnmountResult{
		UnmountResult: UnmountResult{
			Unmounted: storageBool(raw["unmounted"], false),
			Owner:     storageString(firstNonNil(raw["owner"], raw["owner_aid"]), ""),
			Bucket:    storageString(raw["bucket"], ""),
			Path:      pathValue,
			MountPath: pathValue,
		},
		GroupID:   storageString(raw["group_id"], ""),
		GroupAID:  storageString(raw["group_aid"], ""),
		Area:      storageString(raw["area"], ""),
		MemberAID: storageString(raw["member_aid"], ""),
		Storage:   groupFSStorageRefFromAny(raw["storage"]),
		Raw:       raw,
	}
}

func GroupFSNodeViewFromAny(value any) GroupFSNodeView {
	raw := storageMap(value)
	node := NodeViewFromAny(raw)
	if p := storageString(raw["path"], ""); p != "" {
		node.Path = p
	}
	return GroupFSNodeView{
		NodeView:  node,
		GroupID:   storageString(raw["group_id"], ""),
		GroupAID:  storageString(raw["group_aid"], ""),
		Area:      storageString(raw["area"], ""),
		MemberAID: storageString(raw["member_aid"], ""),
		MemberRef: storageString(raw["member_ref"], ""),
		Storage:   groupFSStorageRefFromAny(raw["storage"]),
		Raw:       raw,
	}
}

func groupFSStorageRefFromAny(value any) GroupFSStorageRef {
	raw := storageMap(value)
	return GroupFSStorageRef{
		OwnerAID: storageString(firstNonNil(raw["owner_aid"], raw["owner"]), ""),
		Bucket:   storageString(raw["bucket"], ""),
		Path:     storageString(raw["path"], ""),
	}
}

func groupFSAddGroupParams(params map[string]any, groupID, srcGroupID, dstGroupID string) {
	if groupID != "" {
		params["group_id"] = groupID
	}
	if srcGroupID != "" {
		params["src_group_id"] = srcGroupID
	}
	if dstGroupID != "" {
		params["dst_group_id"] = dstGroupID
	}
}

func groupFSAddSigningParams(params map[string]any, signAs string, aidStore *AIDStore) {
	if strings.TrimSpace(signAs) != "" {
		params["sign_as"] = strings.TrimSpace(signAs)
	}
	if aidStore != nil {
		params["aid_store"] = aidStore
	}
}

func (v *GroupFSVFS) applySigningIdentity(params map[string]any) error {
	signAs := strings.TrimSpace(storageAnyToString(firstNonNil(params["sign_as"], params["signAs"])))
	rawStore := firstNonNil(params["aid_store"], params["aidStore"])
	delete(params, "sign_as")
	delete(params, "signAs")
	delete(params, "aid_store")
	delete(params, "aidStore")
	if signAs == "" {
		return nil
	}
	if groupFSSameAID(groupFSClientAID(v.client), signAs) {
		return nil
	}
	aidStore, _ := rawStore.(*AIDStore)
	if aidStore == nil {
		return fmt.Errorf("group.fs operation requires aidStore to sign as %s", signAs)
	}
	loaded := aidStore.Load(signAs)
	if !loaded.Ok || loaded.Data.AID == nil {
		message := fmt.Sprintf("signer identity not found: %s", signAs)
		if loaded.Error != nil && strings.TrimSpace(loaded.Error.Message) != "" {
			message = loaded.Error.Message
		}
		return fmt.Errorf("%s", message)
	}
	if !loaded.Data.AID.IsPrivateKeyValid() || strings.TrimSpace(loaded.Data.AID.PrivateKeyPem) == "" {
		return fmt.Errorf("signer identity missing private key: %s", signAs)
	}
	params["_client_signature_identity"] = loaded.Data.AID
	return nil
}

func groupFSClientAID(client StorageRPCClient) string {
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

func groupFSBearerHeaders(client StorageRPCClient) map[string]string {
	token := groupFSAccessToken(client)
	if token == "" {
		return nil
	}
	return map[string]string{"Authorization": "Bearer " + token}
}

func groupFSAccessToken(client StorageRPCClient) string {
	if provider, ok := client.(interface{ AccessToken() string }); ok {
		if token := strings.TrimSpace(provider.AccessToken()); token != "" {
			return token
		}
	}
	aunClient, ok := client.(*AUNClient)
	if !ok || aunClient == nil {
		return ""
	}
	aunClient.mu.RLock()
	defer aunClient.mu.RUnlock()
	if token := strings.TrimSpace(storageString(aunClient.identity["access_token"], "")); token != "" {
		return token
	}
	return strings.TrimSpace(storageString(aunClient.sessionParams["access_token"], ""))
}

func groupFSSameAID(left string, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	return left != "" && right != "" && strings.EqualFold(left, right)
}

func groupFSInstantUpload(check map[string]any) bool {
	for _, key := range []string{"instant", "dedup_hit", "skip_upload"} {
		if storageBool(check[key], false) {
			return true
		}
	}
	return false
}

func groupFSContentTypeForPath(localPath string) string {
	switch strings.ToLower(filepath.Ext(localPath)) {
	case ".md", ".markdown":
		return "text/markdown"
	default:
		return contentTypeForPath(localPath)
	}
}

func mapCopy(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
