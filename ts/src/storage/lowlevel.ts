import { mapStorageError, StorageError } from './errors.js';
import type { StorageRaw } from './types.js';

export interface StorageRpcClient {
  aid?: string | null;
  call(method: string, params?: Record<string, unknown>): Promise<unknown>;
}

export interface LowLevelBaseOptions {
  owner?: string | null;
  bucket?: string;
}

function stripUndefined(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
}

function params(owner?: string | null, bucket = 'default', extra: Record<string, unknown> = {}): Record<string, unknown> {
  return stripUndefined({
    owner_aid: owner || undefined,
    bucket,
    ...extra,
  });
}

function bytesToBase64(data: Uint8Array): string {
  const bufferCtor = (globalThis as unknown as { Buffer?: { from(data: Uint8Array): { toString(enc: string): string } } }).Buffer;
  if (bufferCtor) return bufferCtor.from(data).toString('base64');
  let binary = '';
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const bufferCtor = (globalThis as unknown as { Buffer?: { from(data: string, enc: string): Uint8Array } }).Buffer;
  if (bufferCtor) return new Uint8Array(bufferCtor.from(value, 'base64'));
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export { base64ToBytes, bytesToBase64 };

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}

export class StorageLowLevel {
  private readonly client: StorageRpcClient;

  constructor(client: StorageRpcClient) {
    this.client = client;
  }

  async call(method: string, callParams?: Record<string, unknown>, path = ''): Promise<StorageRaw> {
    try {
      const result = await this.client.call(method, callParams ?? {});
      return (result && typeof result === 'object') ? result as StorageRaw : { result };
    } catch (exc) {
      throw mapStorageError(exc, path);
    }
  }

  getLimits(options: LowLevelBaseOptions = {}): Promise<StorageRaw> {
    return this.call('storage.get_limits', params(options.owner, options.bucket));
  }

  getQuota(options: LowLevelBaseOptions = {}): Promise<StorageRaw> {
    return this.call('storage.get_quota', params(options.owner, options.bucket));
  }

  checkUpload(options: LowLevelBaseOptions & { objectKey: string; size: number; sha256?: string }): Promise<StorageRaw> {
    return this.call('storage.check_upload', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      size_bytes: options.size,
      sha256: options.sha256,
    }), options.objectKey);
  }

  putObject(options: LowLevelBaseOptions & {
    objectKey: string;
    content: Uint8Array;
    contentType?: string;
    metadata?: StorageRaw;
    isPublic?: boolean;
    expectedVersion?: number;
    overwrite?: boolean;
  }): Promise<StorageRaw> {
    return this.call('storage.put_object', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      content: bytesToBase64(options.content),
      content_type: options.contentType,
      metadata: options.metadata,
      is_private: !(options.isPublic ?? false),
      expected_version: options.expectedVersion,
      overwrite: options.overwrite ?? true,
    }), options.objectKey);
  }

  getObject(options: LowLevelBaseOptions & { objectKey: string; token?: string; offset?: number; limit?: number }): Promise<StorageRaw> {
    return this.call('storage.get_object', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      token: options.token,
      offset: options.offset,
      limit: options.limit,
    }), options.objectKey);
  }

  createUploadSession(options: LowLevelBaseOptions & { objectKey: string; size: number; contentType?: string; expectedVersion?: number }): Promise<StorageRaw> {
    return this.call('storage.create_upload_session', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      size_bytes: options.size,
      content_type: options.contentType,
      expected_version: options.expectedVersion,
    }), options.objectKey);
  }

  completeUpload(options: LowLevelBaseOptions & {
    objectKey: string;
    sessionId?: string;
    size: number;
    sha256: string;
    contentType?: string;
    metadata?: StorageRaw;
    isPublic?: boolean;
    expectedVersion?: number;
    skipBlob?: boolean;
  }): Promise<StorageRaw> {
    return this.call('storage.complete_upload', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      session_id: options.sessionId,
      size_bytes: options.size,
      sha256: options.sha256,
      content_type: options.contentType,
      metadata: options.metadata,
      is_private: !(options.isPublic ?? false),
      expected_version: options.expectedVersion,
      skip_blob: options.skipBlob,
    }), options.objectKey);
  }

  createDownloadTicket(options: LowLevelBaseOptions & { objectKey: string; token?: string }): Promise<StorageRaw> {
    return this.call('storage.create_download_ticket', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      token: options.token,
    }), options.objectKey);
  }

  createShareLink(options: LowLevelBaseOptions & {
    objectKey: string;
    allowedAids?: string[];
    expireInSeconds?: number;
    maxUses?: number;
  }): Promise<StorageRaw> {
    return this.call('storage.create_share_link', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      allowed_aids: options.allowedAids,
      expire_in_seconds: options.expireInSeconds,
      max_uses: options.maxUses,
    }), options.objectKey);
  }

  listShareLinks(options: LowLevelBaseOptions & { objectKey?: string } = {}): Promise<StorageRaw> {
    return this.call('storage.list_share_links', params(options.owner, options.bucket, {
      object_key: options.objectKey,
    }), options.objectKey ?? '');
  }

  revokeShareLink(options: { shareId: string }): Promise<StorageRaw> {
    return this.call('storage.revoke_share_link', { share_id: options.shareId });
  }

  getByShare(options: { shareId: string }): Promise<StorageRaw> {
    return this.call('storage.get_by_share', { share_id: options.shareId });
  }

  async httpPut(url: string, data: Uint8Array, headers?: Record<string, string>): Promise<void> {
    const response = await fetch(url, { method: 'PUT', body: toArrayBuffer(data), headers });
    if (!response.ok) throw new StorageError(`HTTP PUT failed: status=${response.status}`, response.status);
  }

  async httpGet(url: string, headers?: Record<string, string>): Promise<Uint8Array> {
    const response = await fetch(url, { method: 'GET', headers });
    if (!response.ok) throw new StorageError(`HTTP GET failed: status=${response.status}`, response.status);
    return new Uint8Array(await response.arrayBuffer());
  }

  headObject(options: LowLevelBaseOptions & { objectKey: string; token?: string }): Promise<StorageRaw> {
    return this.call('storage.head_object', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      token: options.token,
    }), options.objectKey);
  }

  listObjects(options: LowLevelBaseOptions & { prefix?: string; page?: number; size?: number; marker?: string } = {}): Promise<StorageRaw> {
    return this.call('storage.list_objects', params(options.owner, options.bucket, {
      prefix: options.prefix ?? '',
      page: options.page ?? 1,
      size: options.size ?? 100,
      marker: options.marker,
    }), options.prefix ?? '');
  }

  listPrefixes(options: LowLevelBaseOptions & { prefix?: string; size?: number } = {}): Promise<StorageRaw> {
    return this.call('storage.list_prefixes', params(options.owner, options.bucket, {
      prefix: options.prefix ?? '',
      size: options.size ?? 100,
    }), options.prefix ?? '');
  }

  deleteObject(options: LowLevelBaseOptions & { objectKey: string }): Promise<StorageRaw> {
    return this.call('storage.delete_object', params(options.owner, options.bucket, {
      object_key: options.objectKey,
    }), options.objectKey);
  }

  setObjectMeta(options: LowLevelBaseOptions & {
    objectKey: string;
    metadata: StorageRaw;
    contentType?: string;
    merge?: boolean;
    expectedVersion?: number;
  }): Promise<StorageRaw> {
    return this.call('storage.set_object_meta', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      metadata: options.metadata,
      content_type: options.contentType,
      merge: options.merge ?? true,
      expected_version: options.expectedVersion,
    }), options.objectKey);
  }

  appendObject(options: LowLevelBaseOptions & {
    objectKey: string;
    content: Uint8Array;
    contentType?: string;
    metadata?: StorageRaw;
    expectedVersion?: number;
    isPublic?: boolean;
  }): Promise<StorageRaw> {
    return this.call('storage.append_object', params(options.owner, options.bucket, {
      object_key: options.objectKey,
      content: bytesToBase64(options.content),
      content_type: options.contentType,
      metadata: options.metadata,
      expected_version: options.expectedVersion,
      is_private: !(options.isPublic ?? false),
    }), options.objectKey);
  }

  batchDelete(options: LowLevelBaseOptions & { items: StorageRaw[]; recursive?: boolean }): Promise<StorageRaw> {
    return this.call('storage.batch_delete', params(options.owner, options.bucket, {
      items: options.items,
      recursive: options.recursive ?? false,
    }));
  }

  moveObject(options: LowLevelBaseOptions & {
    path: string;
    dstParentPath: string;
    newName: string;
    overwrite?: boolean;
    expectedVersion?: number;
  }): Promise<StorageRaw> {
    return this.call('storage.move_object', params(options.owner, options.bucket, {
      path: options.path,
      dst_parent_path: options.dstParentPath,
      new_name: options.newName,
      conflict_policy: (options.overwrite ?? false) ? 'replace' : 'reject',
      expected_version: options.expectedVersion,
    }), options.path);
  }

  copyObject(options: LowLevelBaseOptions & { srcPath: string; dstPath: string; overwrite?: boolean }): Promise<StorageRaw> {
    return this.call('storage.copy_object', params(options.owner, options.bucket, {
      src_path: options.srcPath,
      dst_path: options.dstPath,
      conflict_policy: (options.overwrite ?? false) ? 'replace' : 'reject',
    }), options.srcPath);
  }

  createFolder(options: LowLevelBaseOptions & { path: string; parents?: boolean }): Promise<StorageRaw> {
    return this.call('storage.create_folder', params(options.owner, options.bucket, {
      path: options.path,
      mkdirs: options.parents ?? false,
    }), options.path);
  }

  getFolder(options: LowLevelBaseOptions & { path: string }): Promise<StorageRaw> {
    return this.call('storage.get_folder', params(options.owner, options.bucket, {
      path: options.path,
    }), options.path);
  }

  listChildren(options: LowLevelBaseOptions & {
    path: string;
    nodeType?: string;
    page?: number;
    size?: number;
    orderBy?: string;
    order?: string;
    includeMetadata?: boolean;
    includeUrls?: boolean;
  }): Promise<StorageRaw> {
    return this.call('storage.list_children', params(options.owner, options.bucket, {
      path: options.path,
      type: options.nodeType ?? 'all',
      page: options.page ?? 1,
      size: options.size ?? 50,
      order_by: options.orderBy,
      order: options.order,
      include_metadata: options.includeMetadata,
      include_urls: options.includeUrls,
    }), options.path);
  }

  moveFolder(options: LowLevelBaseOptions & {
    path: string;
    dstParentPath: string;
    newName: string;
    expectedVersion?: number;
  }): Promise<StorageRaw> {
    return this.call('storage.move_folder', params(options.owner, options.bucket, {
      path: options.path,
      dst_parent_path: options.dstParentPath,
      new_name: options.newName,
      expected_version: options.expectedVersion,
    }), options.path);
  }

  deleteFolder(options: LowLevelBaseOptions & { path: string; recursive?: boolean }): Promise<StorageRaw> {
    return this.call('storage.delete_folder', params(options.owner, options.bucket, {
      path: options.path,
      recursive: options.recursive ?? false,
    }), options.path);
  }

  createSymlink(options: LowLevelBaseOptions & { path: string; target: string; overwrite?: boolean }): Promise<StorageRaw> {
    return this.call('storage.create_symlink', params(options.owner, options.bucket, {
      path: options.path,
      target: options.target,
      overwrite: options.overwrite ?? false,
    }), options.path);
  }

  readlink(options: LowLevelBaseOptions & { path: string }): Promise<StorageRaw> {
    return this.call('storage.readlink', params(options.owner, options.bucket, { path: options.path }), options.path);
  }

  atomicRepoint(options: LowLevelBaseOptions & { path: string; newTarget: string; expectedVersion?: number }): Promise<StorageRaw> {
    return this.call('storage.atomic_repoint', params(options.owner, options.bucket, {
      path: options.path,
      new_target: options.newTarget,
      expected_version: options.expectedVersion,
    }), options.path);
  }

  renameSymlink(options: LowLevelBaseOptions & { path: string; newPath: string; overwrite?: boolean; expectedVersion?: number }): Promise<StorageRaw> {
    return this.call('storage.rename_symlink', params(options.owner, options.bucket, {
      path: options.path,
      new_path: options.newPath,
      overwrite: options.overwrite ?? false,
      expected_version: options.expectedVersion,
    }), options.path);
  }

  deleteSymlink(options: LowLevelBaseOptions & { path: string }): Promise<StorageRaw> {
    return this.call('storage.delete_symlink', params(options.owner, options.bucket, { path: options.path }), options.path);
  }

  setAcl(options: LowLevelBaseOptions & { path: string; granteeAid: string; perms: string; expiresAt?: number; maxUses?: number }): Promise<StorageRaw> {
    return this.call('storage.set_acl', params(options.owner, options.bucket, {
      path: options.path,
      grantee_aid: options.granteeAid,
      perms: options.perms,
      expires_at: options.expiresAt,
      max_uses: options.maxUses,
    }), options.path);
  }

  removeAcl(options: LowLevelBaseOptions & { path: string; granteeAid: string }): Promise<StorageRaw> {
    return this.call('storage.remove_acl', params(options.owner, options.bucket, {
      path: options.path,
      grantee_aid: options.granteeAid,
    }), options.path);
  }

  listAcl(options: LowLevelBaseOptions & { path: string }): Promise<StorageRaw> {
    return this.call('storage.list_acl', params(options.owner, options.bucket, { path: options.path }), options.path);
  }

  setVisibility(options: LowLevelBaseOptions & { path: string; visibility: string; allowRoles?: string[] }): Promise<StorageRaw> {
    return this.call('storage.set_visibility', params(options.owner, options.bucket, {
      path: options.path,
      visibility: options.visibility,
      allow_roles: options.allowRoles,
    }), options.path);
  }

  checkAccess(options: LowLevelBaseOptions & { path: string; operation?: string; token?: string; followSymlinks?: boolean }): Promise<StorageRaw> {
    return this.call('storage.check_access', params(options.owner, options.bucket, {
      path: options.path,
      operation: options.operation ?? 'read',
      token: options.token,
      follow_symlinks: options.followSymlinks ?? true,
    }), options.path);
  }

  issueToken(options: LowLevelBaseOptions & { path: string; expiresAt?: number; maxReads?: number }): Promise<StorageRaw> {
    return this.call('storage.issue_token', params(options.owner, options.bucket, {
      path: options.path,
      expires_at: options.expiresAt,
      max_reads: options.maxReads,
    }), options.path);
  }

  revokeToken(options: LowLevelBaseOptions & { path: string; token: string }): Promise<StorageRaw> {
    return this.call('storage.revoke_token', params(options.owner, options.bucket, {
      path: options.path,
      token: options.token,
    }), options.path);
  }

  listTokens(options: LowLevelBaseOptions & { path: string }): Promise<StorageRaw> {
    return this.call('storage.list_tokens', params(options.owner, options.bucket, { path: options.path }), options.path);
  }

  resolvePath(options: LowLevelBaseOptions & { path: string; expectedType?: string; followSymlinks?: boolean }): Promise<StorageRaw> {
    return this.call('storage.resolve_path', params(options.owner, options.bucket, {
      path: options.path,
      expected_type: options.expectedType ?? 'any',
      follow_symlinks: options.followSymlinks ?? true,
    }), options.path);
  }

  fsList(options: LowLevelBaseOptions & { path?: string; page?: number; size?: number; marker?: string; token?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.list', params(options.owner, options.bucket, {
      path: options.path ?? '',
      page: options.page ?? 1,
      size: options.size ?? 100,
      marker: options.marker,
      token: options.token,
    }), options.path ?? '');
  }

  fsStat(options: LowLevelBaseOptions & { path: string; token?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.stat', params(options.owner, options.bucket, {
      path: options.path,
      token: options.token,
    }), options.path);
  }

  fsLstat(options: LowLevelBaseOptions & { path: string; token?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.lstat', params(options.owner, options.bucket, {
      path: options.path,
      token: options.token,
    }), options.path);
  }

  fsMkdir(options: LowLevelBaseOptions & { path: string; parents?: boolean }): Promise<StorageRaw> {
    return this.call('storage.fs.mkdir', params(options.owner, options.bucket, {
      path: options.path,
      parents: options.parents ?? false,
    }), options.path);
  }

  fsRemove(options: LowLevelBaseOptions & { path: string; recursive?: boolean }): Promise<StorageRaw> {
    return this.call('storage.fs.remove', params(options.owner, options.bucket, {
      path: options.path,
      recursive: options.recursive ?? false,
    }), options.path);
  }

  fsRename(options: LowLevelBaseOptions & { src: string; dst: string; overwrite?: boolean; expectedVersion?: number }): Promise<StorageRaw> {
    return this.call('storage.fs.rename', params(options.owner, options.bucket, {
      src: options.src,
      dst: options.dst,
      overwrite: options.overwrite ?? false,
      expected_version: options.expectedVersion,
    }), options.src);
  }

  fsCopy(options: LowLevelBaseOptions & { src: string; dst: string; overwrite?: boolean; followSymlinks?: boolean; recursive?: boolean; dstOwner?: string | null; dstBucket?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.copy', params(options.owner, options.bucket, {
      src: options.src,
      dst: options.dst,
      overwrite: options.overwrite ?? false,
      follow_symlinks: options.followSymlinks ?? false,
      recursive: options.recursive ?? false,
      dst_owner_aid: options.dstOwner,
      dst_bucket: options.dstBucket,
    }), options.src);
  }

  fsFind(options: LowLevelBaseOptions & { path: string; name?: string; nodeType?: string; size?: string; mtime?: string; page?: number; pageSize?: number; token?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.find', params(options.owner, options.bucket, {
      path: options.path,
      name: options.name,
      type: options.nodeType,
      size: options.size,
      mtime: options.mtime,
      page: options.page ?? 1,
      page_size: options.pageSize ?? 1000,
      token: options.token,
    }), options.path);
  }

  fsDf(options: LowLevelBaseOptions = {}): Promise<StorageRaw> {
    return this.call('storage.fs.df', params(options.owner, options.bucket));
  }

  fsMount(options: LowLevelBaseOptions & {
    mountPath: string;
    sourceAid?: string;
    sourceBucket?: string;
    sourcePath?: string;
    readonly?: boolean;
    expiresAt?: number;
    requireApproval?: boolean;
    volumeId?: string;
  }): Promise<StorageRaw> {
    return this.call('storage.fs.mount', params(options.owner, options.bucket, {
      mount_path: options.mountPath,
      source_aid: options.sourceAid,
      source_bucket: options.sourceBucket,
      source_path: options.sourcePath,
      readonly: options.readonly ?? true,
      expires_at: options.expiresAt,
      require_approval: options.requireApproval ?? false,
      volume_id: options.volumeId,
    }), options.mountPath);
  }

  fsApprove(options: LowLevelBaseOptions & { mountPath?: string; mountId?: string; requestId?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.approve', params(options.owner, options.bucket, {
      mount_path: options.mountPath,
      mount_id: options.mountId,
      request_id: options.requestId,
    }), options.mountPath ?? options.mountId ?? options.requestId ?? '');
  }

  fsReject(options: LowLevelBaseOptions & { mountPath?: string; mountId?: string; requestId?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.reject', params(options.owner, options.bucket, {
      mount_path: options.mountPath,
      mount_id: options.mountId,
      request_id: options.requestId,
    }), options.mountPath ?? options.mountId ?? options.requestId ?? '');
  }

  fsUnmount(options: LowLevelBaseOptions & { mountPath: string }): Promise<StorageRaw> {
    return this.call('storage.fs.unmount', params(options.owner, options.bucket, {
      mount_path: options.mountPath,
    }), options.mountPath);
  }

  fsInvalidateMembership(options: { groupId: string; groupOwnerAid: string; memberAid?: string; reason?: string; status?: string }): Promise<StorageRaw> {
    return this.call('storage.fs.invalidate_membership', stripUndefined({
      group_id: options.groupId,
      group_owner_aid: options.groupOwnerAid,
      member_aid: options.memberAid,
      reason: options.reason ?? 'membership_changed',
      status: options.status,
    }));
  }

  volumeCreate(options: LowLevelBaseOptions & { volumeId?: string; sizeBytes: number; mountPoint?: string; expiresAt?: number; usedBytes?: number; status?: string }): Promise<StorageRaw> {
    return this.call('storage.volume.create', params(options.owner, options.bucket, {
      volume_id: options.volumeId,
      size_bytes: options.sizeBytes,
      mount_point: options.mountPoint,
      expires_at: options.expiresAt,
      used_bytes: options.usedBytes,
      status: options.status,
    }));
  }

  volumeRenew(options: LowLevelBaseOptions & { volumeId: string; expiresAt: number; status?: string }): Promise<StorageRaw> {
    return this.call('storage.volume.renew', params(options.owner, options.bucket, {
      volume_id: options.volumeId,
      expires_at: options.expiresAt,
      status: options.status,
    }));
  }

  volumeExpireDue(options: LowLevelBaseOptions & { now?: number } = {}): Promise<StorageRaw> {
    return this.call('storage.volume.expire_due', params(options.owner, options.bucket, {
      now: options.now,
    }));
  }
}
