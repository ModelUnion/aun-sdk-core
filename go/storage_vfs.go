package aun

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
)

type storageAIDProvider interface {
	AID() string
}

type StorageVFS struct {
	client  StorageRPCClient
	low     *StorageLowLevel
	useFS   bool
	ownerMu sync.RWMutex
}

type WriteBytesOptions struct {
	Owner           string
	Bucket          string
	ContentType     string
	Overwrite       *bool
	ExpectedVersion *int
	Public          bool
	Metadata        map[string]any
}

type ReadOptions struct {
	Owner  string
	Bucket string
	Token  string
	Offset *int
	Limit  *int
}

type ListOptions struct {
	Owner     string
	Bucket    string
	Page      int
	Size      int
	Marker    string
	Long      bool
	Recursive bool
	Token     string
}

type StatOptions struct {
	Owner  string
	Bucket string
	Token  string
}

type MkdirOptions struct {
	Owner   string
	Bucket  string
	Parents bool
}

type RemoveOptions struct {
	Owner     string
	Bucket    string
	Recursive bool
}

type RenameOptions struct {
	Owner           string
	Bucket          string
	Overwrite       bool
	ExpectedVersion *int
}

type CopyOptions struct {
	Owner          string
	Bucket         string
	DstOwner       string
	DstBucket      string
	Overwrite      bool
	FollowSymlinks bool
}

type FindOptions struct {
	Owner    string
	Bucket   string
	Name     string
	NodeType string
	Size     string
	MTime    string
	Page     int
	PageSize int
	Token    string
}

type SymlinkOptions struct {
	Owner     string
	Bucket    string
	Overwrite bool
}

type ReadlinkOptions struct {
	Owner  string
	Bucket string
}

type RepointOptions struct {
	Owner           string
	Bucket          string
	ExpectedVersion *int
}

type RenameSymlinkOptions struct {
	Owner           string
	Bucket          string
	Overwrite       bool
	ExpectedVersion *int
}

type MountOptions struct {
	Owner           string
	Bucket          string
	SourceAID       string
	SourceBucket    string
	SourcePath      string
	Readonly        bool
	ExpiresAt       *int64
	RequireApproval bool
}

type MountVolumeOptions struct {
	Owner           string
	Bucket          string
	SourcePath      string
	Readonly        bool
	ExpiresAt       *int64
	RequireApproval bool
}

type UnmountOptions struct {
	Owner  string
	Bucket string
}

type MountReviewOptions struct {
	Owner   string
	Bucket  string
	MountID string
}

type SetACLOptions struct {
	Owner      string
	Bucket     string
	GranteeAID string
	Perms      string
	ExpiresAt  *int64
	MaxUses    *int
}

type IssueTokenOptions struct {
	Owner     string
	Bucket    string
	ExpiresAt *int64
	MaxReads  *int
}

type RemoveACLOptions struct {
	Owner      string
	Bucket     string
	GranteeAID string
}

type VisibilityOptions struct {
	Owner      string
	Bucket     string
	Visibility string
	AllowRoles []string
}

type CheckAccessOptions struct {
	Owner          string
	Bucket         string
	Operation      string
	Token          string
	FollowSymlinks *bool
}

type RevokeTokenOptions struct {
	Owner  string
	Bucket string
	Token  string
}

type UsageOptions struct {
	Owner  string
	Bucket string
}

func NewStorageVFS(client StorageRPCClient) *StorageVFS {
	return &StorageVFS{client: client, low: NewStorageLowLevel(client), useFS: true}
}

func (v *StorageVFS) defaultOwner() string {
	if provider, ok := v.client.(storageAIDProvider); ok {
		return provider.AID()
	}
	return ""
}

func (v *StorageVFS) owner(value string) string {
	if value != "" {
		return value
	}
	return v.defaultOwner()
}

func bucket(value string) string {
	if value == "" {
		return "default"
	}
	return value
}

func (v *StorageVFS) WriteBytes(ctx context.Context, p string, data []byte, opts *WriteBytesOptions) (NodeView, error) {
	if opts == nil {
		opts = &WriteBytesOptions{}
	}
	owner := v.owner(opts.Owner)
	b := bucket(opts.Bucket)
	objectKey := StoragePathToKey(p)
	sum := sha256.Sum256(data)
	shaHex := fmt.Sprintf("%x", sum[:])
	check, err := v.low.CheckUpload(ctx, owner, b, objectKey, len(data), shaHex)
	if err != nil {
		return NodeView{}, err
	}
	if storageBool(firstNonNil(check["dedup_hit"], check["skip_upload"], check["exists"]), false) {
		raw, err := v.low.CompleteUpload(ctx, owner, b, objectKey, "", len(data), shaHex, contentType(opts.ContentType), opts.Metadata, opts.Public, opts.ExpectedVersion, true)
		if err != nil {
			return NodeView{}, err
		}
		return NodeViewFromAny(raw), nil
	}
	limits, err := v.low.GetLimits(ctx, owner, b)
	if err != nil {
		return NodeView{}, err
	}
	maxInline := storageInt64(firstNonNil(limits["max_inline_bytes"], limits["inline_max"]))
	if maxInline == 0 {
		maxInline = 65536
	}
	if storageBool(check["inline"], false) || int64(len(data)) <= maxInline {
		raw, err := v.low.PutObject(ctx, PutObjectOptions{
			Owner: owner, Bucket: b, ObjectKey: objectKey, Content: data,
			ContentType: contentType(opts.ContentType), Metadata: opts.Metadata,
			IsPublic: opts.Public, ExpectedVersion: opts.ExpectedVersion, Overwrite: opts.Overwrite,
		})
		if err != nil {
			return NodeView{}, err
		}
		return NodeViewFromAny(raw), nil
	}
	session, err := v.low.CreateUploadSession(ctx, owner, b, objectKey, len(data), opts.ContentType, opts.ExpectedVersion)
	if err != nil {
		return NodeView{}, err
	}
	uploadURL := storageString(session["upload_url"], "")
	if uploadURL == "" {
		return NodeView{}, &StorageError{Message: "create_upload_session did not return upload_url", Code: "ESTORAGE", Path: p}
	}
	headers := map[string]string{}
	if rawHeaders, ok := session["headers"].(map[string]string); ok {
		headers = rawHeaders
	}
	if err := v.low.HTTPPut(ctx, uploadURL, data, headers); err != nil {
		return NodeView{}, MapStorageError(err, p)
	}
	raw, err := v.low.CompleteUpload(ctx, owner, b, objectKey, storageString(session["session_id"], ""), len(data), shaHex, opts.ContentType, opts.Metadata, opts.Public, opts.ExpectedVersion, false)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(raw), nil
}

func contentType(value string) string {
	if strings.TrimSpace(value) == "" {
		return "application/octet-stream"
	}
	return value
}

func (v *StorageVFS) ReadBytes(ctx context.Context, p string, opts *ReadOptions) ([]byte, error) {
	if opts == nil {
		opts = &ReadOptions{}
	}
	owner := v.owner(opts.Owner)
	b := bucket(opts.Bucket)
	objectKey := StoragePathToKey(p)
	raw, err := v.low.GetObject(ctx, owner, b, objectKey, opts.Token, opts.Offset, opts.Limit)
	if err == nil {
		return base64.StdEncoding.DecodeString(storageString(raw["content"], ""))
	}
	if opts.Offset != nil || opts.Limit != nil {
		return nil, err
	}
	if !strings.Contains(strings.ToLower(err.Error()), "inline") && !strings.Contains(err.Error(), "超过") {
		return nil, err
	}
	ticket, err := v.low.CreateDownloadTicket(ctx, owner, b, objectKey, opts.Token)
	if err != nil {
		return nil, err
	}
	downloadURL := storageString(ticket["download_url"], "")
	if downloadURL == "" {
		return nil, &StorageError{Message: "create_download_ticket did not return download_url", Code: "ESTORAGE", Path: p}
	}
	return v.low.HTTPGet(ctx, downloadURL, nil)
}

func (v *StorageVFS) List(ctx context.Context, p string, opts *ListOptions) ([]NodeView, error) {
	if opts == nil {
		opts = &ListOptions{}
	}
	if opts.Recursive {
		result := []NodeView{}
		pending := []string{p}
		for len(pending) > 0 {
			current := pending[0]
			pending = pending[1:]
			nextOpts := *opts
			nextOpts.Recursive = false
			children, err := v.List(ctx, current, &nextOpts)
			if err != nil {
				return nil, err
			}
			result = append(result, children...)
			for _, child := range children {
				if child.Type == "dir" {
					pending = append(pending, child.Path)
				}
			}
		}
		return result, nil
	}
	page := opts.Page
	if page == 0 {
		page = 1
	}
	size := opts.Size
	if size == 0 {
		size = 100
	}
	raw, err := v.low.FSList(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), page, size, opts.Marker, opts.Token)
	if err != nil {
		return nil, err
	}
	items, _ := firstNonNil(raw["nodes"], raw["items"]).([]any)
	nodes := make([]NodeView, 0, len(items))
	for _, item := range items {
		nodes = append(nodes, NodeViewFromAny(item))
	}
	return nodes, nil
}

func (v *StorageVFS) Stat(ctx context.Context, p string, opts *StatOptions) (NodeView, error) {
	if opts == nil {
		opts = &StatOptions{}
	}
	raw, err := v.low.FSStat(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.Token)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(raw), nil
}

func (v *StorageVFS) Lstat(ctx context.Context, p string, opts *StatOptions) (NodeView, error) {
	if opts == nil {
		opts = &StatOptions{}
	}
	raw, err := v.low.FSLstat(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.Token)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(raw), nil
}

func (v *StorageVFS) Mkdir(ctx context.Context, p string, opts *MkdirOptions) (NodeView, error) {
	if opts == nil {
		opts = &MkdirOptions{}
	}
	raw, err := v.low.FSMkdir(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.Parents)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["node"], raw)), nil
}

func (v *StorageVFS) Remove(ctx context.Context, p string, opts *RemoveOptions) (RemoveResult, error) {
	if opts == nil {
		opts = &RemoveOptions{}
	}
	raw, err := v.low.FSRemove(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.Recursive)
	if err != nil {
		return RemoveResult{}, err
	}
	return RemoveResult{
		Path:         NormalizeStoragePath(p),
		RemovedCount: storageInt64(firstNonNil(raw["removed_count"], raw["deleted_count"])),
	}, nil
}

func (v *StorageVFS) Rename(ctx context.Context, src, dst string, opts *RenameOptions) (NodeView, error) {
	if opts == nil {
		opts = &RenameOptions{}
	}
	raw, err := v.low.FSRename(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(src), StoragePathToKey(dst), opts.Overwrite, opts.ExpectedVersion)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["node"], raw)), nil
}

func (v *StorageVFS) Copy(ctx context.Context, src, dst string, opts *CopyOptions) (NodeView, error) {
	if opts == nil {
		opts = &CopyOptions{}
	}
	raw, err := v.low.FSCopy(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(src), StoragePathToKey(dst), opts.Overwrite, opts.FollowSymlinks, opts.DstOwner, opts.DstBucket)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["node"], raw)), nil
}

func (v *StorageVFS) Find(ctx context.Context, p string, opts *FindOptions) ([]NodeView, error) {
	if opts == nil {
		opts = &FindOptions{}
	}
	raw, err := v.low.FSFind(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.Name, opts.NodeType, opts.Size, opts.MTime, opts.Page, opts.PageSize, opts.Token)
	if err != nil {
		return nil, err
	}
	items, _ := firstNonNil(raw["nodes"], raw["items"]).([]any)
	nodes := make([]NodeView, 0, len(items))
	for _, item := range items {
		nodes = append(nodes, NodeViewFromAny(item))
	}
	return nodes, nil
}

func (v *StorageVFS) DF(ctx context.Context, opts *UsageOptions) (UsageView, error) {
	if opts == nil {
		opts = &UsageOptions{}
	}
	raw, err := v.low.FSDF(ctx, v.owner(opts.Owner), bucket(opts.Bucket))
	if err != nil {
		return UsageView{}, err
	}
	return UsageViewFromAny(raw, v.owner(opts.Owner)), nil
}

func (v *StorageVFS) Symlink(ctx context.Context, target, linkPath string, opts *SymlinkOptions) (NodeView, error) {
	if opts == nil {
		opts = &SymlinkOptions{}
	}
	raw, err := v.low.CreateSymlink(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(linkPath), target, opts.Overwrite)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["symlink"], raw)), nil
}

func (v *StorageVFS) Readlink(ctx context.Context, p string, opts *ReadlinkOptions) (NodeView, error) {
	if opts == nil {
		opts = &ReadlinkOptions{}
	}
	raw, err := v.low.Readlink(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p))
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["symlink"], raw)), nil
}

func (v *StorageVFS) Repoint(ctx context.Context, p, newTarget string, opts *RepointOptions) (NodeView, error) {
	if opts == nil {
		opts = &RepointOptions{}
	}
	raw, err := v.low.AtomicRepoint(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), newTarget, opts.ExpectedVersion)
	if err != nil {
		return NodeView{}, err
	}
	if ok, exists := raw["ok"].(bool); exists && !ok {
		return NodeView{}, &StorageError{Message: "symlink version conflict", Code: "ECONFLICT", Path: p, Data: raw}
	}
	return NodeViewFromAny(firstNonNil(raw["symlink"], raw)), nil
}

func (v *StorageVFS) RenameSymlink(ctx context.Context, src, dst string, opts *RenameSymlinkOptions) (NodeView, error) {
	if opts == nil {
		opts = &RenameSymlinkOptions{}
	}
	raw, err := v.low.RenameSymlink(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(src), StoragePathToKey(dst), opts.Overwrite, opts.ExpectedVersion)
	if err != nil {
		return NodeView{}, err
	}
	if ok, exists := raw["ok"].(bool); exists && !ok {
		return NodeView{}, &StorageError{Message: "symlink version conflict", Code: "ECONFLICT", Path: src, Data: raw}
	}
	return NodeViewFromAny(firstNonNil(raw["symlink"], raw)), nil
}

func (v *StorageVFS) Mount(ctx context.Context, mountPath string, opts *MountOptions) (NodeView, error) {
	if opts == nil {
		opts = &MountOptions{}
	}
	raw, err := v.low.FSMount(
		ctx,
		v.owner(opts.Owner),
		bucket(opts.Bucket),
		StoragePathToKey(mountPath),
		v.owner(opts.SourceAID),
		bucket(opts.SourceBucket),
		StoragePathToKey(opts.SourcePath),
		opts.Readonly,
		opts.ExpiresAt,
		opts.RequireApproval,
		"",
	)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["mount"], raw)), nil
}

func (v *StorageVFS) MountVolume(ctx context.Context, volumeID, mountPath string, opts *MountVolumeOptions) (NodeView, error) {
	if opts == nil {
		opts = &MountVolumeOptions{}
	}
	raw, err := v.low.FSMount(
		ctx,
		v.owner(opts.Owner),
		bucket(opts.Bucket),
		StoragePathToKey(mountPath),
		"",
		"",
		StoragePathToKey(opts.SourcePath),
		opts.Readonly,
		opts.ExpiresAt,
		opts.RequireApproval,
		volumeID,
	)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["mount"], raw)), nil
}

func (v *StorageVFS) ApproveMount(ctx context.Context, mountPath string, opts *MountReviewOptions) (map[string]any, error) {
	if opts == nil {
		opts = &MountReviewOptions{}
	}
	return v.low.FSApprove(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(mountPath), opts.MountID)
}

func (v *StorageVFS) RejectMount(ctx context.Context, mountPath string, opts *MountReviewOptions) (map[string]any, error) {
	if opts == nil {
		opts = &MountReviewOptions{}
	}
	return v.low.FSReject(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(mountPath), opts.MountID)
}

func (v *StorageVFS) Unmount(ctx context.Context, mountPath string, opts *UnmountOptions) (UnmountResult, error) {
	if opts == nil {
		opts = &UnmountOptions{}
	}
	raw, err := v.low.FSUnmount(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(mountPath))
	if err != nil {
		return UnmountResult{}, err
	}
	pathValue := storageKeyToPath(firstNonNil(raw["mount_path"], raw["path"], StoragePathToKey(mountPath)))
	return UnmountResult{
		Unmounted: storageBool(raw["unmounted"], false),
		Owner:     storageString(firstNonNil(raw["owner"], raw["owner_aid"]), v.owner(opts.Owner)),
		Bucket:    storageString(raw["bucket"], bucket(opts.Bucket)),
		Path:      pathValue,
		MountPath: pathValue,
	}, nil
}

func (v *StorageVFS) SetACL(ctx context.Context, p string, opts SetACLOptions) (map[string]any, error) {
	return v.low.SetACL(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.GranteeAID, opts.Perms, opts.ExpiresAt, opts.MaxUses)
}

func (v *StorageVFS) RemoveACL(ctx context.Context, p string, opts RemoveACLOptions) (map[string]any, error) {
	return v.low.RemoveACL(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.GranteeAID)
}

func (v *StorageVFS) ListACL(ctx context.Context, p string, opts *UsageOptions) (map[string]any, error) {
	if opts == nil {
		opts = &UsageOptions{}
	}
	return v.low.ListACL(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p))
}

func (v *StorageVFS) SetVisibility(ctx context.Context, p string, opts VisibilityOptions) (NodeView, error) {
	raw, err := v.low.SetVisibility(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.Visibility, opts.AllowRoles)
	if err != nil {
		return NodeView{}, err
	}
	return NodeViewFromAny(firstNonNil(raw["node"], raw)), nil
}

func (v *StorageVFS) CheckAccess(ctx context.Context, p string, opts *CheckAccessOptions) (map[string]any, error) {
	if opts == nil {
		opts = &CheckAccessOptions{}
	}
	operation := opts.Operation
	if operation == "" {
		operation = "read"
	}
	follow := true
	if opts.FollowSymlinks != nil {
		follow = *opts.FollowSymlinks
	}
	return v.low.CheckAccess(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), operation, opts.Token, follow)
}

func (v *StorageVFS) IssueToken(ctx context.Context, p string, opts IssueTokenOptions) (map[string]any, error) {
	return v.low.IssueToken(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.ExpiresAt, opts.MaxReads)
}

func (v *StorageVFS) RevokeToken(ctx context.Context, p string, opts RevokeTokenOptions) (map[string]any, error) {
	return v.low.RevokeToken(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p), opts.Token)
}

func (v *StorageVFS) ListTokens(ctx context.Context, p string, opts *UsageOptions) (map[string]any, error) {
	if opts == nil {
		opts = &UsageOptions{}
	}
	return v.low.ListTokens(ctx, v.owner(opts.Owner), bucket(opts.Bucket), StoragePathToKey(p))
}

func (v *StorageVFS) GetUsage(ctx context.Context, opts *UsageOptions) (UsageView, error) {
	if opts == nil {
		opts = &UsageOptions{}
	}
	owner := v.owner(opts.Owner)
	raw, err := v.low.GetQuota(ctx, owner, bucket(opts.Bucket))
	if err != nil {
		return UsageView{}, err
	}
	return UsageViewFromAny(raw, owner), nil
}
