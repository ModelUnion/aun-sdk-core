import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, join } from 'node:path';

import { mapStorageError, StorageConflictError, StorageError, StorageExistsError, StorageIsADirectoryError } from './storage/errors.js';
import { StorageLowLevel } from './storage/lowlevel.js';
import type { DownloadResult, StorageRaw } from './storage/types.js';
import type { RpcParams, RpcResult } from './types.js';

export interface GroupFSRpcClient {
  aid?: string | null;
  call(method: string, params?: RpcParams): Promise<RpcResult>;
}

type GroupFSAuthClient = GroupFSRpcClient & {
  accessToken?: string | null;
  access_token?: string | null;
  getAccessToken?: () => string | null | undefined;
  _identity?: Record<string, unknown> | null;
  _sessionParams?: Record<string, unknown> | null;
};
type GroupFSSigningAID = { aid?: string; privateKeyPem?: string; certPem?: string };
type GroupFSAIDStoreResult = {
  ok?: boolean;
  data?: { aid?: GroupFSSigningAID };
  error?: { message?: string };
};
type GroupFSAIDStore = {
  load?: (aid: string) => GroupFSAIDStoreResult | Promise<GroupFSAIDStoreResult>;
  loadAsync?: (aid: string) => Promise<GroupFSAIDStoreResult>;
};

export interface GroupFSLowLevel {
  httpPut(url: string, data: Uint8Array, headers?: Record<string, string>): Promise<void>;
  httpGet(url: string, headers?: Record<string, string>): Promise<Uint8Array>;
}

export type GroupFSCopySource = string;
export type GroupFSCopyDestination = string;
export type GroupFSDownloadResult = DownloadResult;

export interface GroupFSCopyOptions {
  [key: string]: unknown;
  force?: boolean;
  overwrite?: boolean;
  recursive?: boolean;
  parents?: boolean;
  followSymlinks?: boolean;
  follow_symlinks?: boolean;
  contentType?: string;
  content_type?: string;
  metadata?: StorageRaw;
  expectedVersion?: number;
  expected_version?: number;
  verifyHash?: boolean;
  verify_hash?: boolean;
  progress?: (loaded: number, total: number) => void;
  onProgress?: (loaded: number, total: number) => void;
  on_progress?: (loaded: number, total: number) => void;
  groupId?: string;
  group_id?: string;
  srcGroupId?: string;
  src_group_id?: string;
  dstGroupId?: string;
  dst_group_id?: string;
  signAs?: string;
  sign_as?: string;
  aidStore?: GroupFSAIDStore;
  aid_store?: GroupFSAIDStore;
}

export type GroupFSParams = Record<string, unknown>;

const WINDOWS_DRIVE_RE = /^[A-Za-z]:[\\/]/;
const GROUP_REF_RE = /^[^:/\\][^:]*:\//;
const LOCAL_PREFIX = 'local:';

function isExplicitLocalPath(value: string): boolean {
  return String(value || '').trim().toLowerCase().startsWith(LOCAL_PREFIX);
}

function stripLocalPathPrefix(value: string): string {
  const text = String(value || '').trim();
  return text.toLowerCase().startsWith(LOCAL_PREFIX) ? text.slice(LOCAL_PREFIX.length) : text;
}

function isGroupRemoteCopyPath(value: string, ...groupHints: string[]): boolean {
  if (isExplicitLocalPath(value)) return false;
  return isGroupRemotePath(value) || groupHints.some(Boolean);
}

export function isGroupRemotePath(value: string): boolean {
  const text = String(value || '').trim();
  if (!text) return false;
  if (isExplicitLocalPath(text)) return false;
  if (WINDOWS_DRIVE_RE.test(text)) return false;
  if (text.startsWith('http://') || text.startsWith('https://')) return true;
  return GROUP_REF_RE.test(text);
}

function stripNil(params: Record<string, unknown> = {}): RpcParams {
  const out: RpcParams = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) out[key] = value as RpcParams[string];
  }
  return out;
}

async function loadSigningAID(store: GroupFSAIDStore, signAs: string): Promise<GroupFSSigningAID> {
  const loaded = store.load
    ? await store.load(signAs)
    : store.loadAsync
      ? await store.loadAsync(signAs)
      : null;
  if (!loaded?.ok || !loaded.data?.aid) {
    throw new Error(loaded?.error?.message || `signer identity not found: ${signAs}`);
  }
  if (!loaded.data.aid.privateKeyPem) {
    throw new Error(`signer identity missing private key: ${signAs}`);
  }
  return loaded.data.aid;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stringValue(value: unknown): string {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function accessTokenFromClient(client: GroupFSRpcClient): string {
  const authClient = client as GroupFSAuthClient;
  if (typeof authClient.getAccessToken === 'function') {
    const token = stringValue(authClient.getAccessToken());
    if (token) return token;
  }
  const directToken = stringValue(authClient.accessToken ?? authClient.access_token);
  if (directToken) return directToken;
  const identityToken = stringValue(authClient._identity?.access_token);
  if (identityToken) return identityToken;
  return stringValue(authClient._sessionParams?.access_token);
}

function bearerHeaders(client: GroupFSRpcClient): Record<string, string> | undefined {
  const token = accessTokenFromClient(client);
  return token ? { Authorization: `Bearer ${token}` } : undefined;
}

function boolValue(value: unknown, fallback = false): boolean {
  if (value === undefined || value === null) return fallback;
  return Boolean(value);
}

function intValue(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : undefined;
}

function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
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

function filenameFromGroupPath(path: string): string {
  const cleaned = String(path || '').replace(/\\/g, '/').replace(/\/+$/g, '');
  const last = cleaned.split('/').pop();
  return last && !last.includes(':') ? last : 'download';
}

async function bytesFromSource(source: GroupFSCopySource): Promise<{ data: Uint8Array; contentType?: string; localPath?: string }> {
  const localPath = stripLocalPathPrefix(source);
  const info = await stat(localPath);
  if (info.isDirectory()) {
    throw new StorageIsADirectoryError('directory upload is not supported by group.fs.cp yet', 'EISDIR', localPath);
  }
  return { data: new Uint8Array(await readFile(localPath)), localPath };
}

async function statOrNull(path: string) {
  try {
    return await stat(path);
  } catch (exc) {
    if ((exc as NodeJS.ErrnoException)?.code === 'ENOENT') return null;
    throw exc;
  }
}

function callbackFromOptions(options: GroupFSCopyOptions): ((loaded: number, total: number) => void) | undefined {
  return options.progress ?? options.onProgress ?? options.on_progress;
}

function remainingCopyOptions(options: GroupFSCopyOptions): Record<string, unknown> {
  const {
    force: _force,
    overwrite: _overwrite,
    recursive: _recursive,
    parents: _parents,
    followSymlinks: _followSymlinks,
    follow_symlinks: _follow_symlinks,
    contentType: _contentType,
    content_type: _content_type,
    metadata: _metadata,
    expectedVersion: _expectedVersion,
    expected_version: _expected_version,
    verifyHash: _verifyHash,
    verify_hash: _verify_hash,
    progress: _progress,
    onProgress: _onProgress,
    on_progress: _on_progress,
    groupId: _groupId,
    group_id: _group_id,
    srcGroupId: _srcGroupId,
    src_group_id: _src_group_id,
    dstGroupId: _dstGroupId,
    dst_group_id: _dst_group_id,
    ...rest
  } = options;
  return rest;
}

export class GroupFSVFS {
  lowlevel: GroupFSLowLevel;
  private readonly client: GroupFSRpcClient;

  constructor(client: GroupFSRpcClient, options: { lowlevel?: GroupFSLowLevel } = {}) {
    this.client = client;
    this.lowlevel = options.lowlevel ?? new StorageLowLevel(client);
  }

  private async call(method: string, params?: GroupFSParams | null, path = ''): Promise<RpcResult> {
    try {
      return await this.client.call(method, await this.prepareParams(params ?? {}));
    } catch (exc) {
      throw mapStorageError(exc, path);
    }
  }

  private async prepareParams(params: Record<string, unknown>): Promise<RpcParams> {
    const next: Record<string, unknown> = { ...params };
    const signAs = stringValue(next.sign_as ?? next.signAs);
    const aidStore = (next.aid_store ?? next.aidStore) as GroupFSAIDStore | undefined;
    delete next.sign_as;
    delete next.signAs;
    delete next.aid_store;
    delete next.aidStore;
    if (signAs) {
      const currentAid = stringValue(this.client.aid ?? (this.client as unknown as { _aid?: string })._aid);
      if (currentAid.toLowerCase() !== signAs.toLowerCase()) {
        if (!aidStore) {
          throw new Error(`group.fs operation requires aidStore to sign as ${signAs}`);
        }
        (next as Record<string, unknown>)._client_signature_identity = await loadSigningAID(aidStore, signAs);
      }
    }
    return stripNil(next);
  }

  ls(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.ls', { ...options, path }, path);
  }

  find(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.find', { ...options, path }, path);
  }

  stat(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.stat', { ...options, path }, path);
  }

  lstat(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.lstat', { ...options, path }, path);
  }

  mkdir(path: string, options: GroupFSParams & { parents?: boolean } = {}): Promise<RpcResult> {
    return this.call('group.fs.mkdir', { ...options, path, parents: options.parents ?? false }, path);
  }

  setAcl(path: string, options: GroupFSParams & { granteeAid?: string; grantee_aid?: string; perms?: string } = {}): Promise<RpcResult> {
    const grantee = options.grantee_aid ?? options.granteeAid ?? 'role:admin';
    const { granteeAid: _granteeAid, ...rest } = options;
    return this.call('group.fs.set_acl', { ...rest, path, grantee_aid: grantee, perms: options.perms ?? 'rwx' }, path);
  }

  removeAcl(path: string, options: GroupFSParams & { granteeAid?: string; grantee_aid?: string } = {}): Promise<RpcResult> {
    const grantee = options.grantee_aid ?? options.granteeAid ?? 'role:admin';
    const { granteeAid: _granteeAid, ...rest } = options;
    return this.call('group.fs.remove_acl', { ...rest, path, grantee_aid: grantee }, path);
  }

  getAcl(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.get_acl', { ...options, path }, path);
  }

  listAcl(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.list_acl', { ...options, path }, path);
  }

  rm(path: string, options: GroupFSParams & { recursive?: boolean; force?: boolean } = {}): Promise<RpcResult> {
    return this.call('group.fs.rm', {
      ...options,
      path,
      recursive: options.recursive ?? false,
      force: options.force ?? false,
    }, path);
  }

  async cp(src: GroupFSCopySource, dst: GroupFSCopyDestination, options: GroupFSCopyOptions = {}): Promise<RpcResult | GroupFSDownloadResult> {
    const sharedGroupId = stringValue(options.group_id ?? options.groupId);
    const srcGroupId = stringValue(options.src_group_id ?? options.srcGroupId);
    const dstGroupId = stringValue(options.dst_group_id ?? options.dstGroupId);
    const force = Boolean(options.force ?? options.overwrite ?? false);
    const srcRemote = isGroupRemoteCopyPath(src, srcGroupId, sharedGroupId);
    const dstRemote = isGroupRemoteCopyPath(dst, dstGroupId, sharedGroupId);
    const rest = remainingCopyOptions(options);

    if (srcRemote && dstRemote) {
      const params: RpcParams = { ...rest, src, dst };
      if (sharedGroupId) params.group_id = sharedGroupId;
      if (srcGroupId) params.src_group_id = srcGroupId;
      if (dstGroupId) params.dst_group_id = dstGroupId;
      if (force) params.force = true;
      if (options.recursive) params.recursive = true;
      const follow = options.follow_symlinks ?? options.followSymlinks;
      if (follow !== undefined && follow !== null) params.follow_symlinks = Boolean(follow);
      return this.call('group.fs.cp', params, src);
    }

    if (!srcRemote && dstRemote) {
      return this.uploadSource(src, dst, {
        ...rest,
        group_id: dstGroupId || sharedGroupId || undefined,
        force,
        parents: options.parents ?? true,
        content_type: options.content_type ?? options.contentType,
        metadata: options.metadata,
        expected_version: options.expected_version ?? options.expectedVersion,
        onProgress: callbackFromOptions(options),
      });
    }

    if (srcRemote && !dstRemote) {
      return this.downloadRemote(src, dst, {
        ...rest,
        group_id: srcGroupId || sharedGroupId || undefined,
        force,
        verify_hash: options.verify_hash ?? options.verifyHash ?? true,
        onProgress: callbackFromOptions(options),
      });
    }

    throw new StorageError('local-to-local copy is not handled by group.fs', 'EINVAL', src);
  }

  async mv(src: string, dst: string, options: GroupFSParams & {
    force?: boolean;
    overwrite?: boolean;
    groupId?: string;
    group_id?: string;
    srcGroupId?: string;
    src_group_id?: string;
    dstGroupId?: string;
    dst_group_id?: string;
  } = {}): Promise<RpcResult> {
    const sharedGroupId = stringValue(options.group_id ?? options.groupId);
    const srcGroupId = stringValue(options.src_group_id ?? options.srcGroupId);
    const dstGroupId = stringValue(options.dst_group_id ?? options.dstGroupId);
    const force = Boolean(options.force ?? options.overwrite ?? false);
    const srcRemote = isGroupRemoteCopyPath(src, srcGroupId, sharedGroupId);
    const dstRemote = isGroupRemoteCopyPath(dst, dstGroupId, sharedGroupId);
    if (!srcRemote || !dstRemote) {
      throw new StorageError('group.fs.mv only supports group remote paths', 'EINVAL', src);
    }
    const rest = remainingCopyOptions(options as GroupFSCopyOptions);
    const params: RpcParams = { ...rest, src, dst };
    if (sharedGroupId) params.group_id = sharedGroupId;
    if (srcGroupId) params.src_group_id = srcGroupId;
    if (dstGroupId) params.dst_group_id = dstGroupId;
    if (force) params.force = true;
    return this.call('group.fs.mv', params, src);
  }

  df(pathOrGroup?: string | null, options: GroupFSParams = {}): Promise<RpcResult> {
    const params: RpcParams = stripNil(options);
    if (pathOrGroup !== undefined && pathOrGroup !== null) params.path = pathOrGroup;
    return this.call('group.fs.df', params, pathOrGroup ?? '');
  }

  mount(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.mount', { ...options, path }, path);
  }

  umount(path: string, options: GroupFSParams = {}): Promise<RpcResult> {
    return this.call('group.fs.umount', { ...options, path }, path);
  }

  private async uploadSource(
    source: GroupFSCopySource,
    groupPath: string,
    options: Record<string, unknown> & {
      force: boolean;
      parents: boolean;
      content_type?: unknown;
      metadata?: StorageRaw;
      expected_version?: unknown;
      onProgress?: (loaded: number, total: number) => void;
    },
  ): Promise<RpcResult> {
    const { data, contentType: sourceContentType, localPath } = await bytesFromSource(source);
    const digest = sha256Hex(data);
    const contentType = stringValue(options.content_type)
      || sourceContentType
      || (localPath ? contentTypeForPath(localPath) : 'application/octet-stream');
    const baseParams: RpcParams = stripNil({
      ...options,
      path: groupPath,
      size_bytes: data.byteLength,
      sha256: digest,
      content_type: contentType,
      force: options.force,
      parents: options.parents,
      metadata: options.metadata,
      expected_version: options.expected_version,
      onProgress: undefined,
    });

    const check = await this.call('group.fs.check_upload', { ...baseParams }, groupPath);
    if (isRecord(check)) {
      if (check.within_limit === false) {
        throw new StorageError('file size exceeds group fs upload limit', 'E2BIG', groupPath, check);
      }
      if (check.target_exists && !options.force && options.expected_version === undefined) {
        throw new StorageExistsError('group fs target already exists', 'EEXIST', groupPath, check.target);
      }
      if (boolValue(check.instant) || boolValue(check.dedup_hit) || boolValue(check.skip_upload)) {
        const completeParams: RpcParams = { ...baseParams, skip_blob: true };
        const sessionId = check.session_id;
        if (sessionId !== undefined && sessionId !== null) completeParams.session_id = sessionId as RpcParams[string];
        return this.call('group.fs.complete_upload', completeParams, groupPath);
      }
    }

    const session = await this.call('group.fs.create_upload_session', { ...baseParams }, groupPath);
    if (!isRecord(session)) {
      throw new StorageError(`group.fs.create_upload_session returned invalid response`, 'ESTORAGE', groupPath, session);
    }
    const uploadUrl = stringValue(session.upload_url ?? session.url);
    if (!uploadUrl) {
      throw new StorageError('group.fs.create_upload_session did not return upload_url', 'ESTORAGE', groupPath, session);
    }
    const headers: Record<string, string> = {};
    if (isRecord(session.headers)) {
      for (const [key, value] of Object.entries(session.headers)) {
        if (value !== undefined && value !== null) headers[key] = String(value);
      }
    }
    if (!Object.keys(headers).some((key) => key.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = contentType;
    }
    await this.lowlevel.httpPut(uploadUrl, data, headers);
    options.onProgress?.(data.byteLength, data.byteLength);

    const completeParams: RpcParams = { ...baseParams };
    const sessionId = session.session_id ?? session.id;
    if (sessionId !== undefined && sessionId !== null) completeParams.session_id = sessionId as RpcParams[string];
    return this.call('group.fs.complete_upload', completeParams, groupPath);
  }

  private async downloadRemote(
    groupPath: string,
    localPath: GroupFSCopyDestination,
    options: Record<string, unknown> & {
      force: boolean;
      verify_hash: boolean;
      onProgress?: (loaded: number, total: number) => void;
    },
  ): Promise<GroupFSDownloadResult> {
    const initialTargetPath = stripLocalPathPrefix(localPath);
    const existing = await statOrNull(initialTargetPath);
    if (existing && !existing.isDirectory() && !options.force) {
      throw new StorageExistsError(`local path already exists: ${initialTargetPath}`, 'EEXIST', initialTargetPath);
    }

    const ticketParams = stripNil({
      ...options,
      path: groupPath,
      force: undefined,
      verify_hash: undefined,
      onProgress: undefined,
    });
    const ticket = await this.call('group.fs.create_download_ticket', ticketParams, groupPath);
    if (!isRecord(ticket)) {
      throw new StorageError('group.fs.create_download_ticket returned invalid response', 'ESTORAGE', groupPath, ticket);
    }
    const downloadUrl = stringValue(ticket.download_url ?? ticket.url);
    if (!downloadUrl) {
      throw new StorageError('group.fs.create_download_ticket did not return download_url', 'ESTORAGE', groupPath, ticket);
    }

    let targetPath = initialTargetPath;
    const targetInfo = await statOrNull(targetPath);
    if (targetInfo?.isDirectory()) {
      const fileName = stringValue(ticket.file_name ?? ticket.name) || filenameFromGroupPath(groupPath);
      targetPath = join(targetPath, fileName);
      const fileInfo = await statOrNull(targetPath);
      if (fileInfo && !options.force) {
        throw new StorageExistsError(`local path already exists: ${targetPath}`, 'EEXIST', targetPath);
      }
    }

    const data = await this.lowlevel.httpGet(downloadUrl, bearerHeaders(this.client));
    options.onProgress?.(data.byteLength, data.byteLength);
    const expectedSha = stringValue(ticket.sha256);
    const actualSha = sha256Hex(data);
    const verified = !options.verify_hash || !expectedSha || actualSha.toLowerCase() === expectedSha.toLowerCase();
    if (options.verify_hash && !verified) {
      throw new StorageConflictError('download hash verification failed', 'ECONFLICT', groupPath, ticket);
    }

    await mkdir(dirname(targetPath), { recursive: true });
    if (options.force) {
      const tempPath = join(dirname(targetPath), `.${basename(targetPath)}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`);
      try {
        await writeFile(tempPath, data);
        try {
          await unlink(targetPath);
        } catch (exc) {
          if ((exc as NodeJS.ErrnoException)?.code !== 'ENOENT') throw exc;
        }
        await rename(tempPath, targetPath);
      } finally {
        try {
          await unlink(tempPath);
        } catch (exc) {
          if ((exc as NodeJS.ErrnoException)?.code !== 'ENOENT') throw exc;
        }
      }
    } else {
      try {
        await writeFile(targetPath, data, { flag: 'wx' });
      } catch (exc) {
        if ((exc as NodeJS.ErrnoException)?.code === 'EEXIST') {
          throw new StorageExistsError(`local path already exists: ${targetPath}`, 'EEXIST', targetPath);
        }
        throw exc;
      }
    }

    return {
      path: groupPath,
      localPath: targetPath,
      size: data.byteLength,
      sha256: expectedSha || actualSha,
      verified,
    };
  }
}
