import { mapStorageError, StorageConflictError, StorageError, StorageExistsError } from './errors.js';
import { base64ToBytes, StorageLowLevel, type StorageRpcClient } from './lowlevel.js';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, join } from 'node:path';
import {
  nodeFromAny,
  pathToKey,
  type DownloadResult,
  type NodeView,
  type RemoveResult,
  type StorageRaw,
  type UnmountResult,
  type UsageView,
  unmountFromAny,
  usageFromAny,
} from './types.js';

export { StorageLowLevel } from './lowlevel.js';
export * from './errors.js';
export * from './types.js';

async function sha256Hex(data: Uint8Array): Promise<string> {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.digest) throw new StorageError('SHA-256 unavailable', 'EUNSUPPORTED');
  const digest = await subtle.digest('SHA-256', copy.buffer);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function toBytes(data: Uint8Array | ArrayBuffer | string): Uint8Array {
  if (typeof data === 'string') return new TextEncoder().encode(data);
  if (data instanceof Uint8Array) return data;
  return new Uint8Array(data);
}

function contentTypeForPath(path: string): string {
  const ext = extname(path).toLowerCase();
  const known: Record<string, string> = {
    '.txt': 'text/plain',
    '.json': 'application/json',
    '.md': 'text/markdown',
    '.html': 'text/html',
    '.csv': 'text/csv',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.pdf': 'application/pdf',
  };
  return known[ext] ?? 'application/octet-stream';
}

function textValue(value: unknown): string {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function isInlineFallbackError(error: StorageError): boolean {
  const code = String(error.code).toUpperCase();
  if (['EINLINE', 'EINLINE_LIMIT', 'ERR_INLINE_LIMIT', 'INLINE_LIMIT', '-32033'].includes(code)) return true;
  // 当前服务端把 inline 过大映射为通用 -32602；只保留协议术语 inline 兜底，不再依赖中文文案。
  return error.code === -32602 && error.message.toLowerCase().includes('inline');
}

async function statOrNull(path: string) {
  try {
    return await stat(path);
  } catch (exc) {
    if ((exc as NodeJS.ErrnoException)?.code === 'ENOENT') return null;
    throw exc;
  }
}

export interface StorageOptions {
  owner?: string | null;
  bucket?: string;
}

export interface WriteBytesOptions extends StorageOptions {
  contentType?: string;
  overwrite?: boolean;
  expectedVersion?: number;
  public?: boolean;
  metadata?: StorageRaw;
}

export interface ReadOptions extends StorageOptions {
  token?: string;
  offset?: number;
  limit?: number;
  overwrite?: boolean;
}

export interface ListOptions extends StorageOptions {
  page?: number;
  size?: number;
  marker?: string;
  long?: boolean;
  recursive?: boolean;
  token?: string;
}

export interface StatOptions extends StorageOptions {
  token?: string;
}

export interface StoragePathRef {
  owner?: string | null;
  path: string;
}

export type StoragePathLike = string | StoragePathRef;

export interface MountOptions extends StorageOptions {
  sourceOwner?: string | null;
  sourceBucket?: string;
  readonly?: boolean;
  expires?: number;
  expiresAt?: number;
  requireApproval?: boolean;
}

function parsePathLike(input: StoragePathLike, fallbackOwner: string | null | undefined): { owner: string | null; path: string } {
  if (typeof input !== 'string') {
    return { owner: input.owner ?? fallbackOwner ?? null, path: input.path };
  }
  const match = input.match(/^([^:]+):(\/.*)$/);
  if (match) {
    return { owner: match[1], path: match[2] };
  }
  return { owner: fallbackOwner ?? null, path: input };
}

export class StorageVFS {
  readonly lowlevel: StorageLowLevel;
  useFsRpc: boolean;
  private readonly client: StorageRpcClient;

  constructor(client: StorageRpcClient, options: { lowlevel?: StorageLowLevel; useFsRpc?: boolean } = {}) {
    this.client = client;
    this.lowlevel = options.lowlevel ?? new StorageLowLevel(client);
    this.useFsRpc = options.useFsRpc ?? true;
  }

  get defaultOwner(): string | null {
    return this.client.aid ?? null;
  }

  private owner(owner?: string | null): string | null {
    return owner || this.defaultOwner;
  }

  async writeBytes(path: string, input: Uint8Array | ArrayBuffer | string, options: WriteBytesOptions = {}): Promise<NodeView> {
    const data = toBytes(input);
    const owner = this.owner(options.owner);
    const bucket = options.bucket ?? 'default';
    const objectKey = pathToKey(path);
    const sha256 = await sha256Hex(data);
    const overwrite = options.overwrite ?? false;
    try {
      const check = await this.lowlevel.checkUpload({ owner, bucket, objectKey, size: data.length, sha256 });
      if (check.within_limit === false) {
        throw new StorageError(`file size exceeds max_file_size_bytes: ${data.length}`, 'E2BIG', path, check);
      }
      if (check.target_exists && !overwrite && options.expectedVersion === undefined) {
        throw new StorageExistsError(`remote path already exists: ${path}`, 'EEXIST', path, check.target);
      }
      if (check.dedup_hit || check.skip_upload) {
        const completed = await this.lowlevel.completeUpload({
          owner,
          bucket,
          objectKey,
          size: data.length,
          sha256,
          contentType: options.contentType ?? 'application/octet-stream',
          metadata: options.metadata,
          isPublic: options.public ?? false,
          expectedVersion: options.expectedVersion,
          skipBlob: true,
          overwrite,
        });
        return nodeFromAny(completed);
      }
      if (check.inline === true) {
        return nodeFromAny(await this.lowlevel.putObject({
          owner,
          bucket,
          objectKey,
          content: data,
          contentType: options.contentType ?? 'application/octet-stream',
          metadata: options.metadata,
          isPublic: options.public ?? false,
          expectedVersion: options.expectedVersion,
          overwrite,
        }));
      }
      const session = await this.lowlevel.createUploadSession({
        owner,
        bucket,
        objectKey,
        size: data.length,
        contentType: options.contentType,
        expectedVersion: options.expectedVersion,
        overwrite,
      });
      const uploadUrl = String(session.upload_url ?? '');
      if (!uploadUrl) throw new StorageError(`create_upload_session did not return upload_url`, 'ESTORAGE', path);
      await this.lowlevel.httpPut(uploadUrl, data, session.headers as Record<string, string> | undefined);
      return nodeFromAny(await this.lowlevel.completeUpload({
        owner,
        bucket,
        objectKey,
        sessionId: String(session.session_id ?? ''),
        size: data.length,
        sha256,
        contentType: options.contentType,
        metadata: options.metadata,
        isPublic: options.public ?? false,
        expectedVersion: options.expectedVersion,
        overwrite,
      }));
    } catch (exc) {
      throw mapStorageError(exc, path);
    }
  }

  async uploadFile(localPath: string, remotePath: string, options: WriteBytesOptions = {}): Promise<NodeView> {
    const data = await readFile(localPath);
    return this.writeBytes(remotePath, data, {
      ...options,
      contentType: options.contentType ?? contentTypeForPath(localPath),
    });
  }

  async readBytes(path: string, options: ReadOptions = {}): Promise<Uint8Array> {
    return (await this.readBytesWithMetadata(path, options)).data;
  }

  private async readBytesWithMetadata(path: string, options: ReadOptions = {}): Promise<{ data: Uint8Array; sha256: string }> {
    const owner = this.owner(options.owner);
    const bucket = options.bucket ?? 'default';
    const objectKey = pathToKey(path);
    try {
      const result = await this.lowlevel.getObject({ owner, bucket, objectKey, token: options.token, offset: options.offset, limit: options.limit });
      return {
        data: base64ToBytes(String(result.content ?? '')),
        sha256: textValue(result.sha256),
      };
    } catch (exc) {
      const mapped = mapStorageError(exc, path);
      if (options.offset !== undefined || options.limit !== undefined) throw mapped;
      if (!isInlineFallbackError(mapped)) throw mapped;
    }
    const ticket = await this.lowlevel.createDownloadTicket({ owner, bucket, objectKey, token: options.token });
    const downloadUrl = String(ticket.download_url ?? '');
    if (!downloadUrl) throw new StorageError(`create_download_ticket did not return download_url`, 'ESTORAGE', path);
    return {
      data: await this.lowlevel.httpGet(downloadUrl),
      sha256: textValue(ticket.sha256),
    };
  }

  async downloadFile(path: string, options?: ReadOptions & { verifyHash?: boolean }): Promise<DownloadResult>;
  async downloadFile(path: string, localPath: string, options?: ReadOptions & { verifyHash?: boolean }): Promise<DownloadResult>;
  async downloadFile(path: string, localPathOrOptions: string | (ReadOptions & { verifyHash?: boolean }) = {}, maybeOptions: ReadOptions & { verifyHash?: boolean } = {}): Promise<DownloadResult> {
    if (typeof localPathOrOptions === 'string') {
      const localPath = localPathOrOptions;
      const options = maybeOptions;
      const owner = this.owner(options.owner);
      const bucket = options.bucket ?? 'default';
      const objectKey = pathToKey(path);
      const ticket = await this.lowlevel.createDownloadTicket({ owner, bucket, objectKey, token: options.token });
      const downloadUrl = String(ticket.download_url ?? '');
      if (!downloadUrl) throw new StorageError(`create_download_ticket did not return download_url`, 'ESTORAGE', path);
      let targetPath = localPath;
      const localInfo = await statOrNull(targetPath);
      if (localInfo?.isDirectory()) {
        targetPath = join(targetPath, textValue(ticket.file_name) || basename(objectKey));
      }
      const targetInfo = await statOrNull(targetPath);
      const overwrite = options.overwrite ?? false;
      if (targetInfo) {
        if (targetInfo.isDirectory()) throw new StorageError(`local path is a directory: ${targetPath}`, 'EISDIR', targetPath);
        if (!overwrite) throw new StorageExistsError(`local path already exists: ${targetPath}`, 'EEXIST', targetPath);
      }
      const data = await this.lowlevel.httpGet(downloadUrl);
      const actualSha = await sha256Hex(data);
      const expectedSha = textValue(ticket.sha256);
      const expected = expectedSha.toLowerCase();
      const verified = !expected || actualSha.toLowerCase() === expected;
      if (!verified && (options.verifyHash ?? true)) {
        throw new StorageError(
          `hash mismatch: expected=${expected} actual=${actualSha.toLowerCase()}`,
          'EHASH', path,
        );
      }
      await mkdir(dirname(targetPath), { recursive: true });
      try {
        await writeFile(targetPath, data, { flag: overwrite ? 'w' : 'wx' });
      } catch (exc) {
        if (!overwrite && (exc as NodeJS.ErrnoException)?.code === 'EEXIST') {
          throw new StorageExistsError(`local path already exists: ${targetPath}`, 'EEXIST', targetPath);
        }
        throw exc;
      }
      return {
        path,
        localPath: targetPath,
        size: data.length,
        sha256: expectedSha || actualSha,
        verified,
      };
    }
    const options = localPathOrOptions;
    const { data, sha256: expectedSha } = await this.readBytesWithMetadata(path, options);
    const actualSha = await sha256Hex(data);
    const expected = expectedSha.toLowerCase();
    const verified = Boolean(expected) && actualSha.toLowerCase() === expected;
    if (!verified && expected && (options.verifyHash ?? true)) {
      throw new StorageError(
        `hash mismatch: expected=${expected} actual=${actualSha.toLowerCase()}`,
        'EHASH', path,
      );
    }
    return {
      path,
      size: data.length,
      sha256: expectedSha || actualSha,
      verified,
      data,
    };
  }

  async list(path: string, options: ListOptions = {}): Promise<NodeView[]> {
    if (options.recursive) {
      const result: NodeView[] = [];
      const pending = [path];
      while (pending.length) {
        const current = pending.shift()!;
        const children = await this.list(current, { ...options, recursive: false });
        result.push(...children);
        pending.push(...children.filter((node) => node.type === 'dir').map((node) => node.path));
      }
      return result;
    }
    const owner = this.owner(options.owner);
    const bucket = options.bucket ?? 'default';
    const key = pathToKey(path);
    const raw = await this.lowlevel.fsList({
      owner,
      bucket,
      path: key,
      page: options.page,
      size: options.size,
      marker: options.marker,
      token: options.token,
    });
    const items = (raw.nodes ?? raw.items ?? []) as unknown[];
    return items.map((item) => nodeFromAny(item));
  }

  async stat(path: string, options: StatOptions = {}): Promise<NodeView> {
    const owner = this.owner(options.owner);
    const raw = await this.lowlevel.fsStat({ owner, bucket: options.bucket ?? 'default', path: pathToKey(path), token: options.token });
    return nodeFromAny(raw);
  }

  async lstat(path: string, options: StatOptions = {}): Promise<NodeView> {
    const owner = this.owner(options.owner);
    const raw = await this.lowlevel.fsLstat({ owner, bucket: options.bucket ?? 'default', path: pathToKey(path), token: options.token });
    return nodeFromAny(raw);
  }

  async mkdir(path: string, options: StorageOptions & { parents?: boolean } = {}): Promise<NodeView> {
    const raw = await this.lowlevel.fsMkdir({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path), parents: options.parents });
    return nodeFromAny(raw.node ?? raw);
  }

  async remove(path: string, options: StorageOptions & { recursive?: boolean } = {}): Promise<RemoveResult> {
    const raw = await this.lowlevel.fsRemove({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path), recursive: options.recursive });
    return { path, removedCount: Number(raw.removed_count ?? raw.deleted_count ?? 0) };
  }

  async rename(src: string, dst: string, options: StorageOptions & { overwrite?: boolean; expectedVersion?: number } = {}): Promise<NodeView> {
    const raw = await this.lowlevel.fsRename({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', src: pathToKey(src), dst: pathToKey(dst), overwrite: options.overwrite, expectedVersion: options.expectedVersion });
    return nodeFromAny(raw.node ?? raw);
  }

  async copy(src: string, dst: string, options: StorageOptions & { overwrite?: boolean; followSymlinks?: boolean; recursive?: boolean; dstOwner?: string | null; dstBucket?: string } = {}): Promise<NodeView> {
    const raw = await this.lowlevel.fsCopy({
      owner: this.owner(options.owner),
      bucket: options.bucket ?? 'default',
      src: pathToKey(src),
      dst: pathToKey(dst),
      overwrite: options.overwrite,
      followSymlinks: options.followSymlinks,
      recursive: options.recursive,
      dstOwner: options.dstOwner,
      dstBucket: options.dstBucket,
    });
    return nodeFromAny(raw.node ?? raw);
  }

  async find(path: string, options: StorageOptions & { name?: string; nodeType?: string; size?: string; mtime?: string; page?: number; pageSize?: number; token?: string } = {}): Promise<NodeView[]> {
    const raw = await this.lowlevel.fsFind({
      owner: this.owner(options.owner),
      bucket: options.bucket ?? 'default',
      path: pathToKey(path),
      name: options.name,
      nodeType: options.nodeType,
      size: options.size,
      mtime: options.mtime,
      page: options.page,
      pageSize: options.pageSize,
      token: options.token,
    });
    const items = (raw.nodes ?? raw.items ?? []) as unknown[];
    return items.map((item) => nodeFromAny(item));
  }

  async df(options: StorageOptions = {}): Promise<UsageView> {
    const owner = this.owner(options.owner);
    const raw = await this.lowlevel.fsDf({ owner, bucket: options.bucket ?? 'default' });
    return usageFromAny(raw, owner ?? undefined);
  }

  async mount(source: StoragePathLike, mountPath: StoragePathLike, options: MountOptions = {}): Promise<NodeView> {
    const owner = this.owner(options.owner);
    const mountRef = parsePathLike(mountPath, owner);
    const sourceRef = parsePathLike(source, options.sourceOwner ?? this.defaultOwner);
    const raw = await this.lowlevel.fsMount({
      owner: mountRef.owner,
      bucket: options.bucket ?? 'default',
      mountPath: pathToKey(mountRef.path),
      sourceAid: String(sourceRef.owner ?? ''),
      sourceBucket: options.sourceBucket,
      sourcePath: pathToKey(sourceRef.path),
      readonly: options.readonly,
      expiresAt: options.expiresAt ?? options.expires,
      requireApproval: options.requireApproval,
    });
    return nodeFromAny(raw.node ?? raw.mount ?? raw);
  }

  async mountVolume(volumeId: string, mountPath: StoragePathLike, options: MountOptions = {}): Promise<NodeView> {
    const owner = this.owner(options.owner);
    const mountRef = parsePathLike(mountPath, owner);
    const raw = await this.lowlevel.fsMount({
      owner: mountRef.owner,
      bucket: options.bucket ?? 'default',
      mountPath: pathToKey(mountRef.path),
      readonly: options.readonly,
      expiresAt: options.expiresAt ?? options.expires,
      requireApproval: options.requireApproval,
      volumeId,
    });
    return nodeFromAny(raw.node ?? raw.mount ?? raw);
  }

  approveMount(mountPath: StoragePathLike, options: StorageOptions & { mountId?: string; requestId?: string } = {}): Promise<StorageRaw> {
    const owner = this.owner(options.owner);
    const mountRef = parsePathLike(mountPath, owner);
    return this.lowlevel.fsApprove({
      owner: mountRef.owner,
      bucket: options.bucket ?? 'default',
      mountPath: pathToKey(mountRef.path),
      mountId: options.mountId,
      requestId: options.requestId,
    });
  }

  rejectMount(mountPath: StoragePathLike, options: StorageOptions & { mountId?: string; requestId?: string } = {}): Promise<StorageRaw> {
    const owner = this.owner(options.owner);
    const mountRef = parsePathLike(mountPath, owner);
    return this.lowlevel.fsReject({
      owner: mountRef.owner,
      bucket: options.bucket ?? 'default',
      mountPath: pathToKey(mountRef.path),
      mountId: options.mountId,
      requestId: options.requestId,
    });
  }

  async unmount(mountPath: StoragePathLike, options: StorageOptions = {}): Promise<UnmountResult> {
    const owner = this.owner(options.owner);
    const mountRef = parsePathLike(mountPath, owner);
    const raw = await this.lowlevel.fsUnmount({
      owner: mountRef.owner,
      bucket: options.bucket ?? 'default',
      mountPath: pathToKey(mountRef.path),
    });
    return unmountFromAny(raw, {
      owner: mountRef.owner,
      bucket: options.bucket ?? 'default',
      mountPath: pathToKey(mountRef.path),
    });
  }

  async symlink(target: string, linkPath: string, options: StorageOptions & { overwrite?: boolean } = {}): Promise<NodeView> {
    const raw = await this.lowlevel.createSymlink({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(linkPath), target, overwrite: options.overwrite });
    return nodeFromAny(raw.symlink ?? raw);
  }

  async readlink(path: string, options: StorageOptions = {}): Promise<NodeView> {
    const raw = await this.lowlevel.readlink({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path) });
    return nodeFromAny(raw.symlink ?? raw);
  }

  async repoint(path: string, newTarget: string, options: StorageOptions & { expectedVersion?: number } = {}): Promise<NodeView> {
    const raw = await this.lowlevel.atomicRepoint({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path), newTarget, expectedVersion: options.expectedVersion });
    if (raw.ok === false) throw new StorageConflictError('symlink version conflict', 'ECONFLICT', path, raw);
    return nodeFromAny(raw.symlink ?? raw);
  }

  async renameSymlink(src: string, dst: string, options: StorageOptions & { overwrite?: boolean; expectedVersion?: number } = {}): Promise<NodeView> {
    const raw = await this.lowlevel.renameSymlink({
      owner: this.owner(options.owner),
      bucket: options.bucket ?? 'default',
      path: pathToKey(src),
      newPath: pathToKey(dst),
      overwrite: options.overwrite,
      expectedVersion: options.expectedVersion,
    });
    if (raw.ok === false) throw new StorageConflictError('symlink version conflict', 'ECONFLICT', src, raw);
    return nodeFromAny(raw.symlink ?? raw);
  }

  setAcl(path: string, options: StorageOptions & { granteeAid: string; perms: string; expiresAt?: number; maxUses?: number }): Promise<StorageRaw> {
    return this.lowlevel.setAcl({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path), granteeAid: options.granteeAid, perms: options.perms, expiresAt: options.expiresAt, maxUses: options.maxUses });
  }

  removeAcl(path: string, options: StorageOptions & { granteeAid: string }): Promise<StorageRaw> {
    return this.lowlevel.removeAcl({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path), granteeAid: options.granteeAid });
  }

  listAcl(path: string, options: StorageOptions = {}): Promise<StorageRaw> {
    return this.lowlevel.listAcl({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path) });
  }

  async setVisibility(path: string, options: StorageOptions & { visibility: string; allowRoles?: string[] }): Promise<NodeView> {
    const raw = await this.lowlevel.setVisibility({
      owner: this.owner(options.owner),
      bucket: options.bucket ?? 'default',
      path: pathToKey(path),
      visibility: options.visibility,
      allowRoles: options.allowRoles,
    });
    return nodeFromAny(raw.node ?? raw);
  }

  checkAccess(path: string, options: StorageOptions & { operation?: string; token?: string; followSymlinks?: boolean } = {}): Promise<StorageRaw> {
    return this.lowlevel.checkAccess({
      owner: this.owner(options.owner),
      bucket: options.bucket ?? 'default',
      path: pathToKey(path),
      operation: options.operation ?? 'read',
      token: options.token,
      followSymlinks: options.followSymlinks ?? true,
    });
  }

  issueToken(path: string, options: StorageOptions & { expiresAt?: number; maxReads?: number } = {}): Promise<StorageRaw> {
    return this.lowlevel.issueToken({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path), expiresAt: options.expiresAt, maxReads: options.maxReads });
  }

  revokeToken(path: string, options: StorageOptions & { token: string }): Promise<StorageRaw> {
    return this.lowlevel.revokeToken({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path), token: options.token });
  }

  listTokens(path: string, options: StorageOptions = {}): Promise<StorageRaw> {
    return this.lowlevel.listTokens({ owner: this.owner(options.owner), bucket: options.bucket ?? 'default', path: pathToKey(path) });
  }

  async getUsage(options: StorageOptions = {}): Promise<UsageView> {
    const owner = this.owner(options.owner);
    const raw = await this.lowlevel.getQuota({ owner, bucket: options.bucket ?? 'default' });
    return usageFromAny(raw, owner ?? '');
  }
}
