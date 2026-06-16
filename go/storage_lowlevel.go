package aun

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"reflect"
)

type StorageRPCClient interface {
	Call(ctx context.Context, method string, params map[string]any) (any, error)
}

type StorageLowLevel struct {
	client StorageRPCClient
}

func NewStorageLowLevel(client StorageRPCClient) *StorageLowLevel {
	return &StorageLowLevel{client: client}
}

func storageParams(owner, bucket string, extra map[string]any) map[string]any {
	if bucket == "" {
		bucket = "default"
	}
	out := map[string]any{"bucket": bucket}
	if owner != "" {
		out["owner_aid"] = owner
	}
	for key, value := range extra {
		if !isNilStorageParam(value) {
			out[key] = value
		}
	}
	return out
}

func isNilStorageParam(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func (l *StorageLowLevel) call(ctx context.Context, method string, params map[string]any, p string) (map[string]any, error) {
	result, err := l.client.Call(ctx, method, params)
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

func (l *StorageLowLevel) GetLimits(ctx context.Context, owner, bucket string) (map[string]any, error) {
	return l.call(ctx, "storage.get_limits", storageParams(owner, bucket, nil), "")
}

func (l *StorageLowLevel) GetQuota(ctx context.Context, owner, bucket string) (map[string]any, error) {
	return l.call(ctx, "storage.get_quota", storageParams(owner, bucket, nil), "")
}

func (l *StorageLowLevel) CheckUpload(ctx context.Context, owner, bucket, objectKey string, size int, sha256 string) (map[string]any, error) {
	return l.call(ctx, "storage.check_upload", storageParams(owner, bucket, map[string]any{
		"object_key": objectKey,
		"size_bytes": size,
		"sha256":     sha256,
	}), objectKey)
}

type PutObjectOptions struct {
	Owner           string
	Bucket          string
	ObjectKey       string
	Content         []byte
	ContentType     string
	Metadata        map[string]any
	IsPublic        bool
	ExpectedVersion *int
	Overwrite       *bool
}

func (l *StorageLowLevel) PutObject(ctx context.Context, opts PutObjectOptions) (map[string]any, error) {
	extra := map[string]any{
		"object_key":   opts.ObjectKey,
		"content":      base64.StdEncoding.EncodeToString(opts.Content),
		"content_type": opts.ContentType,
		"metadata":     opts.Metadata,
		"is_private":   !opts.IsPublic,
	}
	if opts.ExpectedVersion != nil {
		extra["expected_version"] = *opts.ExpectedVersion
	}
	if opts.Overwrite != nil {
		extra["overwrite"] = *opts.Overwrite
	}
	return l.call(ctx, "storage.put_object", storageParams(opts.Owner, opts.Bucket, extra), opts.ObjectKey)
}

func (l *StorageLowLevel) GetObject(ctx context.Context, owner, bucket, objectKey, token string, offset, limit *int) (map[string]any, error) {
	extra := map[string]any{
		"object_key": objectKey,
		"token":      emptyToNil(token),
	}
	if offset != nil {
		extra["offset"] = *offset
	}
	if limit != nil {
		extra["limit"] = *limit
	}
	return l.call(ctx, "storage.get_object", storageParams(owner, bucket, extra), objectKey)
}

func (l *StorageLowLevel) HeadObject(ctx context.Context, owner, bucket, objectKey, token string) (map[string]any, error) {
	return l.call(ctx, "storage.head_object", storageParams(owner, bucket, map[string]any{
		"object_key": objectKey,
		"token":      emptyToNil(token),
	}), objectKey)
}

func (l *StorageLowLevel) CreateUploadSession(ctx context.Context, owner, bucket, objectKey string, size int, contentType string, expectedVersion *int, overwrite *bool) (map[string]any, error) {
	extra := map[string]any{"object_key": objectKey, "size_bytes": size, "content_type": emptyToNil(contentType)}
	if expectedVersion != nil {
		extra["expected_version"] = *expectedVersion
	}
	if overwrite != nil {
		extra["overwrite"] = *overwrite
	}
	return l.call(ctx, "storage.create_upload_session", storageParams(owner, bucket, extra), objectKey)
}

func (l *StorageLowLevel) CompleteUpload(ctx context.Context, owner, bucket, objectKey, sessionID string, size int, sha256, contentType string, metadata map[string]any, isPublic bool, expectedVersion *int, skipBlob bool, overwrite *bool) (map[string]any, error) {
	extra := map[string]any{
		"object_key":   objectKey,
		"session_id":   emptyToNil(sessionID),
		"size_bytes":   size,
		"sha256":       sha256,
		"content_type": emptyToNil(contentType),
		"metadata":     metadata,
		"is_private":   !isPublic,
		"skip_blob":    skipBlob,
	}
	if expectedVersion != nil {
		extra["expected_version"] = *expectedVersion
	}
	if overwrite != nil {
		extra["overwrite"] = *overwrite
	}
	return l.call(ctx, "storage.complete_upload", storageParams(owner, bucket, extra), objectKey)
}

func (l *StorageLowLevel) CreateDownloadTicket(ctx context.Context, owner, bucket, objectKey, token string) (map[string]any, error) {
	return l.call(ctx, "storage.create_download_ticket", storageParams(owner, bucket, map[string]any{
		"object_key": objectKey,
		"token":      emptyToNil(token),
	}), objectKey)
}

func (l *StorageLowLevel) ListObjects(ctx context.Context, owner, bucket, prefix string, page, size int, marker string) (map[string]any, error) {
	if page == 0 {
		page = 1
	}
	if size == 0 {
		size = 100
	}
	return l.call(ctx, "storage.list_objects", storageParams(owner, bucket, map[string]any{
		"prefix": prefix,
		"page":   page,
		"size":   size,
		"marker": emptyToNil(marker),
	}), prefix)
}

func (l *StorageLowLevel) ListPrefixes(ctx context.Context, owner, bucket, prefix string, size int) (map[string]any, error) {
	if size == 0 {
		size = 100
	}
	return l.call(ctx, "storage.list_prefixes", storageParams(owner, bucket, map[string]any{
		"prefix": prefix,
		"size":   size,
	}), prefix)
}

func (l *StorageLowLevel) DeleteObject(ctx context.Context, owner, bucket, objectKey string) (map[string]any, error) {
	return l.call(ctx, "storage.delete_object", storageParams(owner, bucket, map[string]any{
		"object_key": objectKey,
	}), objectKey)
}

func (l *StorageLowLevel) CreateShareLink(ctx context.Context, owner, bucket, objectKey string, allowedAIDs []string, expireInSeconds, maxUses *int) (map[string]any, error) {
	extra := map[string]any{
		"object_key":        objectKey,
		"allowed_aids":      allowedAIDs,
		"expire_in_seconds": expireInSeconds,
		"max_uses":          maxUses,
	}
	if expireInSeconds != nil {
		extra["expire_in_seconds"] = *expireInSeconds
	}
	if maxUses != nil {
		extra["max_uses"] = *maxUses
	}
	return l.call(ctx, "storage.create_share_link", storageParams(owner, bucket, extra), objectKey)
}

func (l *StorageLowLevel) ListShareLinks(ctx context.Context, owner, bucket, objectKey string) (map[string]any, error) {
	return l.call(ctx, "storage.list_share_links", storageParams(owner, bucket, map[string]any{
		"object_key": emptyToNil(objectKey),
	}), objectKey)
}

func (l *StorageLowLevel) RevokeShareLink(ctx context.Context, shareID string) (map[string]any, error) {
	return l.call(ctx, "storage.revoke_share_link", map[string]any{"share_id": shareID}, "")
}

func (l *StorageLowLevel) GetByShare(ctx context.Context, shareID string) (map[string]any, error) {
	return l.call(ctx, "storage.get_by_share", map[string]any{"share_id": shareID}, "")
}

func (l *StorageLowLevel) HTTPPut(ctx context.Context, url string, data []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP PUT failed: status=%d", resp.StatusCode)
	}
	return nil
}

func (l *StorageLowLevel) HTTPGet(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP GET failed: status=%d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (l *StorageLowLevel) FSList(ctx context.Context, owner, bucket, p string, page, size int, marker, token string) (map[string]any, error) {
	return l.call(ctx, "storage.fs.list", storageParams(owner, bucket, map[string]any{
		"path":   p,
		"page":   page,
		"size":   size,
		"marker": emptyToNil(marker),
		"token":  emptyToNil(token),
	}), p)
}

func (l *StorageLowLevel) FSStat(ctx context.Context, owner, bucket, p, token string) (map[string]any, error) {
	return l.call(ctx, "storage.fs.stat", storageParams(owner, bucket, map[string]any{"path": p, "token": emptyToNil(token)}), p)
}

func (l *StorageLowLevel) FSLstat(ctx context.Context, owner, bucket, p, token string) (map[string]any, error) {
	return l.call(ctx, "storage.fs.lstat", storageParams(owner, bucket, map[string]any{"path": p, "token": emptyToNil(token)}), p)
}

func (l *StorageLowLevel) FSMkdir(ctx context.Context, owner, bucket, p string, parents bool) (map[string]any, error) {
	return l.call(ctx, "storage.fs.mkdir", storageParams(owner, bucket, map[string]any{"path": p, "parents": parents}), p)
}

func (l *StorageLowLevel) FSRemove(ctx context.Context, owner, bucket, p string, recursive bool) (map[string]any, error) {
	return l.call(ctx, "storage.fs.remove", storageParams(owner, bucket, map[string]any{"path": p, "recursive": recursive}), p)
}

func (l *StorageLowLevel) FSRename(ctx context.Context, owner, bucket, src, dst string, overwrite bool, expectedVersion *int) (map[string]any, error) {
	extra := map[string]any{"src": src, "dst": dst, "overwrite": overwrite}
	if expectedVersion != nil {
		extra["expected_version"] = *expectedVersion
	}
	return l.call(ctx, "storage.fs.rename", storageParams(owner, bucket, extra), src)
}

func (l *StorageLowLevel) FSCopy(ctx context.Context, owner, bucket, src, dst string, overwrite, followSymlinks, recursive bool, dstOwner, dstBucket string) (map[string]any, error) {
	extra := map[string]any{
		"src": src, "dst": dst, "overwrite": overwrite, "follow_symlinks": followSymlinks, "recursive": recursive,
	}
	if dstOwner != "" {
		extra["dst_owner_aid"] = dstOwner
	}
	if dstBucket != "" {
		extra["dst_bucket"] = dstBucket
	}
	return l.call(ctx, "storage.fs.copy", storageParams(owner, bucket, extra), src)
}

func (l *StorageLowLevel) FSFind(ctx context.Context, owner, bucket, p, name, nodeType, sizeExpr, mtimeExpr string, page, pageSize int, token string) (map[string]any, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 1000
	}
	extra := map[string]any{"path": p, "page": page, "page_size": pageSize}
	if name != "" {
		extra["name"] = name
	}
	if nodeType != "" {
		extra["type"] = nodeType
	}
	if sizeExpr != "" {
		extra["size"] = sizeExpr
	}
	if mtimeExpr != "" {
		extra["mtime"] = mtimeExpr
	}
	if token != "" {
		extra["token"] = token
	}
	return l.call(ctx, "storage.fs.find", storageParams(owner, bucket, extra), p)
}

func (l *StorageLowLevel) FSDF(ctx context.Context, owner, bucket string) (map[string]any, error) {
	return l.call(ctx, "storage.fs.df", storageParams(owner, bucket, nil), "")
}

func (l *StorageLowLevel) FSMount(ctx context.Context, owner, bucket, mountPath, sourceAID, sourceBucket, sourcePath string, readonly bool, expiresAt *int64, requireApproval bool, volumeID string) (map[string]any, error) {
	extra := map[string]any{
		"mount_path":       mountPath,
		"source_aid":       sourceAID,
		"source_bucket":    sourceBucket,
		"source_path":      sourcePath,
		"readonly":         readonly,
		"require_approval": requireApproval,
		"volume_id":        emptyToNil(volumeID),
	}
	if expiresAt != nil {
		extra["expires_at"] = *expiresAt
	}
	return l.call(ctx, "storage.fs.mount", storageParams(owner, bucket, extra), mountPath)
}

func (l *StorageLowLevel) FSApprove(ctx context.Context, owner, bucket, mountPath, mountID, requestID string) (map[string]any, error) {
	extra := map[string]any{}
	if mountPath != "" {
		extra["mount_path"] = mountPath
	}
	if mountID != "" {
		extra["mount_id"] = mountID
	}
	if requestID != "" {
		extra["request_id"] = requestID
	}
	return l.call(ctx, "storage.fs.approve", storageParams(owner, bucket, extra), firstNonEmpty(mountPath, mountID, requestID))
}

func (l *StorageLowLevel) FSReject(ctx context.Context, owner, bucket, mountPath, mountID, requestID string) (map[string]any, error) {
	extra := map[string]any{}
	if mountPath != "" {
		extra["mount_path"] = mountPath
	}
	if mountID != "" {
		extra["mount_id"] = mountID
	}
	if requestID != "" {
		extra["request_id"] = requestID
	}
	return l.call(ctx, "storage.fs.reject", storageParams(owner, bucket, extra), firstNonEmpty(mountPath, mountID, requestID))
}

func (l *StorageLowLevel) FSUnmount(ctx context.Context, owner, bucket, mountPath string) (map[string]any, error) {
	return l.call(ctx, "storage.fs.unmount", storageParams(owner, bucket, map[string]any{
		"mount_path": mountPath,
	}), mountPath)
}

func (l *StorageLowLevel) FSInvalidateMembership(ctx context.Context, groupID, groupOwnerAID, memberAID, reason, status string) (map[string]any, error) {
	extra := map[string]any{
		"group_id":        groupID,
		"group_owner_aid": groupOwnerAID,
		"member_aid":      emptyToNil(memberAID),
		"reason":          reason,
		"status":          emptyToNil(status),
	}
	return l.call(ctx, "storage.fs.invalidate_membership", extra, "")
}

func (l *StorageLowLevel) VolumeCreate(ctx context.Context, owner, bucket, volumeID string, sizeBytes int64, mountPoint string, expiresAt *int64, usedBytes *int64, status string) (map[string]any, error) {
	extra := map[string]any{
		"volume_id":   emptyToNil(volumeID),
		"size_bytes":  sizeBytes,
		"mount_point": emptyToNil(mountPoint),
		"status":      emptyToNil(status),
	}
	if expiresAt != nil {
		extra["expires_at"] = *expiresAt
	}
	if usedBytes != nil {
		extra["used_bytes"] = *usedBytes
	}
	return l.call(ctx, "storage.volume.create", storageParams(owner, bucket, extra), "")
}

func (l *StorageLowLevel) VolumeRenew(ctx context.Context, owner, bucket, volumeID string, expiresAt int64, status string) (map[string]any, error) {
	return l.call(ctx, "storage.volume.renew", storageParams(owner, bucket, map[string]any{
		"volume_id":  volumeID,
		"expires_at": expiresAt,
		"status":     emptyToNil(status),
	}), "")
}

func (l *StorageLowLevel) VolumeExpireDue(ctx context.Context, owner, bucket string, now *int64) (map[string]any, error) {
	extra := map[string]any{}
	if now != nil {
		extra["now"] = *now
	}
	return l.call(ctx, "storage.volume.expire_due", storageParams(owner, bucket, extra), "")
}

func (l *StorageLowLevel) CreateSymlink(ctx context.Context, owner, bucket, p, target string, overwrite bool) (map[string]any, error) {
	return l.call(ctx, "storage.create_symlink", storageParams(owner, bucket, map[string]any{"path": p, "target": target, "overwrite": overwrite}), p)
}

func (l *StorageLowLevel) Readlink(ctx context.Context, owner, bucket, p string) (map[string]any, error) {
	return l.call(ctx, "storage.readlink", storageParams(owner, bucket, map[string]any{"path": p}), p)
}

func (l *StorageLowLevel) DeleteSymlink(ctx context.Context, owner, bucket, p string) (map[string]any, error) {
	return l.call(ctx, "storage.delete_symlink", storageParams(owner, bucket, map[string]any{"path": p}), p)
}

func (l *StorageLowLevel) AtomicRepoint(ctx context.Context, owner, bucket, p, newTarget string, expectedVersion *int) (map[string]any, error) {
	extra := map[string]any{"path": p, "new_target": newTarget}
	if expectedVersion != nil {
		extra["expected_version"] = *expectedVersion
	}
	return l.call(ctx, "storage.atomic_repoint", storageParams(owner, bucket, extra), p)
}

func (l *StorageLowLevel) RenameSymlink(ctx context.Context, owner, bucket, p, newPath string, overwrite bool, expectedVersion *int) (map[string]any, error) {
	extra := map[string]any{"path": p, "new_path": newPath, "overwrite": overwrite}
	if expectedVersion != nil {
		extra["expected_version"] = *expectedVersion
	}
	return l.call(ctx, "storage.rename_symlink", storageParams(owner, bucket, extra), p)
}

func (l *StorageLowLevel) SetACL(ctx context.Context, owner, bucket, p, granteeAID, perms string, expiresAt *int64, maxUses *int) (map[string]any, error) {
	extra := map[string]any{"path": p, "grantee_aid": granteeAID, "perms": perms}
	if expiresAt != nil {
		extra["expires_at"] = *expiresAt
	}
	if maxUses != nil {
		extra["max_uses"] = *maxUses
	}
	return l.call(ctx, "storage.set_acl", storageParams(owner, bucket, extra), p)
}

func (l *StorageLowLevel) RemoveACL(ctx context.Context, owner, bucket, p, granteeAID string) (map[string]any, error) {
	return l.call(ctx, "storage.remove_acl", storageParams(owner, bucket, map[string]any{
		"path":        p,
		"grantee_aid": granteeAID,
	}), p)
}

func (l *StorageLowLevel) ListACL(ctx context.Context, owner, bucket, p string) (map[string]any, error) {
	return l.call(ctx, "storage.list_acl", storageParams(owner, bucket, map[string]any{"path": p}), p)
}

func (l *StorageLowLevel) SetObjectMeta(ctx context.Context, owner, bucket, objectKey string, metadata map[string]any, contentType string, merge bool, expectedVersion *int) (map[string]any, error) {
	extra := map[string]any{
		"object_key":   objectKey,
		"metadata":     metadata,
		"content_type": emptyToNil(contentType),
		"merge":        merge,
	}
	if expectedVersion != nil {
		extra["expected_version"] = *expectedVersion
	}
	return l.call(ctx, "storage.set_object_meta", storageParams(owner, bucket, extra), objectKey)
}

type AppendObjectOptions struct {
	Owner           string
	Bucket          string
	ObjectKey       string
	Content         []byte
	ContentType     string
	Metadata        map[string]any
	ExpectedVersion *int
	IsPublic        bool
}

func (l *StorageLowLevel) AppendObject(ctx context.Context, opts AppendObjectOptions) (map[string]any, error) {
	extra := map[string]any{
		"object_key":   opts.ObjectKey,
		"content":      base64.StdEncoding.EncodeToString(opts.Content),
		"content_type": emptyToNil(opts.ContentType),
		"metadata":     opts.Metadata,
		"is_private":   !opts.IsPublic,
	}
	if opts.ExpectedVersion != nil {
		extra["expected_version"] = *opts.ExpectedVersion
	}
	return l.call(ctx, "storage.append_object", storageParams(opts.Owner, opts.Bucket, extra), opts.ObjectKey)
}

type ListChildrenOptions struct {
	Owner           string
	Bucket          string
	Path            string
	NodeType        string
	Page            int
	Size            int
	OrderBy         string
	Order           string
	IncludeMetadata *bool
	IncludeURLs     *bool
}

func (l *StorageLowLevel) ListChildren(ctx context.Context, opts ListChildrenOptions) (map[string]any, error) {
	nodeType := opts.NodeType
	if nodeType == "" {
		nodeType = "all"
	}
	page := opts.Page
	if page == 0 {
		page = 1
	}
	size := opts.Size
	if size == 0 {
		size = 50
	}
	extra := map[string]any{
		"path":             opts.Path,
		"type":             nodeType,
		"page":             page,
		"size":             size,
		"order_by":         emptyToNil(opts.OrderBy),
		"order":            emptyToNil(opts.Order),
		"include_metadata": opts.IncludeMetadata,
		"include_urls":     opts.IncludeURLs,
	}
	if opts.IncludeMetadata != nil {
		extra["include_metadata"] = *opts.IncludeMetadata
	}
	if opts.IncludeURLs != nil {
		extra["include_urls"] = *opts.IncludeURLs
	}
	return l.call(ctx, "storage.list_children", storageParams(opts.Owner, opts.Bucket, extra), opts.Path)
}

func (l *StorageLowLevel) BatchDelete(ctx context.Context, owner, bucket string, items []map[string]any, recursive bool) (map[string]any, error) {
	return l.call(ctx, "storage.batch_delete", storageParams(owner, bucket, map[string]any{
		"items":     items,
		"recursive": recursive,
	}), "")
}

type MoveObjectOptions struct {
	Owner           string
	Bucket          string
	Path            string
	DstParentPath   string
	NewName         string
	Overwrite       bool
	ExpectedVersion *int
}

func (l *StorageLowLevel) MoveObject(ctx context.Context, opts MoveObjectOptions) (map[string]any, error) {
	conflictPolicy := "reject"
	if opts.Overwrite {
		conflictPolicy = "replace"
	}
	extra := map[string]any{
		"path":            opts.Path,
		"dst_parent_path": opts.DstParentPath,
		"new_name":        opts.NewName,
		"conflict_policy": conflictPolicy,
	}
	if opts.ExpectedVersion != nil {
		extra["expected_version"] = *opts.ExpectedVersion
	}
	return l.call(ctx, "storage.move_object", storageParams(opts.Owner, opts.Bucket, extra), opts.Path)
}

type CopyObjectOptions struct {
	Owner     string
	Bucket    string
	SrcPath   string
	DstPath   string
	Overwrite bool
}

func (l *StorageLowLevel) CopyObject(ctx context.Context, opts CopyObjectOptions) (map[string]any, error) {
	conflictPolicy := "reject"
	if opts.Overwrite {
		conflictPolicy = "replace"
	}
	return l.call(ctx, "storage.copy_object", storageParams(opts.Owner, opts.Bucket, map[string]any{
		"src_path":        opts.SrcPath,
		"dst_path":        opts.DstPath,
		"conflict_policy": conflictPolicy,
	}), opts.SrcPath)
}

func (l *StorageLowLevel) CreateFolder(ctx context.Context, owner, bucket, p string, parents bool) (map[string]any, error) {
	return l.call(ctx, "storage.create_folder", storageParams(owner, bucket, map[string]any{
		"path":   p,
		"mkdirs": parents,
	}), p)
}

func (l *StorageLowLevel) GetFolder(ctx context.Context, owner, bucket, p string) (map[string]any, error) {
	return l.call(ctx, "storage.get_folder", storageParams(owner, bucket, map[string]any{"path": p}), p)
}

type MoveFolderOptions struct {
	Owner           string
	Bucket          string
	Path            string
	DstParentPath   string
	NewName         string
	ExpectedVersion *int
}

func (l *StorageLowLevel) MoveFolder(ctx context.Context, opts MoveFolderOptions) (map[string]any, error) {
	extra := map[string]any{
		"path":            opts.Path,
		"dst_parent_path": opts.DstParentPath,
		"new_name":        opts.NewName,
	}
	if opts.ExpectedVersion != nil {
		extra["expected_version"] = *opts.ExpectedVersion
	}
	return l.call(ctx, "storage.move_folder", storageParams(opts.Owner, opts.Bucket, extra), opts.Path)
}

func (l *StorageLowLevel) DeleteFolder(ctx context.Context, owner, bucket, p string, recursive bool) (map[string]any, error) {
	return l.call(ctx, "storage.delete_folder", storageParams(owner, bucket, map[string]any{
		"path":      p,
		"recursive": recursive,
	}), p)
}

func (l *StorageLowLevel) ResolvePath(ctx context.Context, owner, bucket, p, expectedType string, followSymlinks *bool) (map[string]any, error) {
	if expectedType == "" {
		expectedType = "any"
	}
	follow := true
	if followSymlinks != nil {
		follow = *followSymlinks
	}
	return l.call(ctx, "storage.resolve_path", storageParams(owner, bucket, map[string]any{
		"path":            p,
		"expected_type":   expectedType,
		"follow_symlinks": follow,
	}), p)
}

func (l *StorageLowLevel) SetVisibility(ctx context.Context, owner, bucket, p, visibility string, allowRoles []string) (map[string]any, error) {
	extra := map[string]any{
		"path":       p,
		"visibility": visibility,
	}
	if allowRoles != nil {
		extra["allow_roles"] = allowRoles
	}
	return l.call(ctx, "storage.set_visibility", storageParams(owner, bucket, extra), p)
}

func (l *StorageLowLevel) CheckAccess(ctx context.Context, owner, bucket, p, operation, token string, followSymlinks bool) (map[string]any, error) {
	extra := map[string]any{
		"path":            p,
		"operation":       operation,
		"follow_symlinks": followSymlinks,
	}
	if token != "" {
		extra["token"] = token
	}
	return l.call(ctx, "storage.check_access", storageParams(owner, bucket, extra), p)
}

func (l *StorageLowLevel) IssueToken(ctx context.Context, owner, bucket, p string, expiresAt *int64, maxReads *int) (map[string]any, error) {
	extra := map[string]any{"path": p}
	if expiresAt != nil {
		extra["expires_at"] = *expiresAt
	}
	if maxReads != nil {
		extra["max_reads"] = *maxReads
	}
	return l.call(ctx, "storage.issue_token", storageParams(owner, bucket, extra), p)
}

func (l *StorageLowLevel) RevokeToken(ctx context.Context, owner, bucket, p, token string) (map[string]any, error) {
	return l.call(ctx, "storage.revoke_token", storageParams(owner, bucket, map[string]any{
		"path":  p,
		"token": token,
	}), p)
}

func (l *StorageLowLevel) ListTokens(ctx context.Context, owner, bucket, p string) (map[string]any, error) {
	return l.call(ctx, "storage.list_tokens", storageParams(owner, bucket, map[string]any{"path": p}), p)
}

func emptyToNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}
