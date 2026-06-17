import { StorageConflictError, StorageError, StorageExistsError, mapStorageError } from './storage/errors.js';
import { StorageLowLevel, type StorageRpcClient } from './storage/lowlevel.js';
import type { RpcParams } from './types.js';

export interface GroupFSRpcClient {
  aid?: string | null;
  call(method: string, params?: RpcParams): Promise<unknown>;
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

export type GroupFSParams = Record<string, unknown>;
export type GroupFSBinarySource = Uint8Array | ArrayBuffer | ArrayBufferView | Blob;
export type GroupFSCpSource = string | GroupFSBinarySource;
export type GroupFSCpDestination = string | { type?: 'blob' | 'bytes'; path?: string; localPath?: string };

export interface GroupFSCpOptions extends GroupFSParams {
  force?: boolean;
  recursive?: boolean;
  parents?: boolean;
  followSymlinks?: boolean | null;
  follow_symlinks?: boolean | null;
  contentType?: string | null;
  content_type?: string | null;
  metadata?: Record<string, unknown> | null;
  expectedVersion?: number | null;
  expected_version?: number | null;
  verifyHash?: boolean;
  verify_hash?: boolean;
  groupId?: string | null;
  group_id?: string | null;
  srcGroupId?: string | null;
  src_group_id?: string | null;
  dstGroupId?: string | null;
  dst_group_id?: string | null;
  sourceType?: 'data' | 'path';
  source_type?: 'data' | 'path';
  localPath?: boolean;
  local_path?: boolean;
  signAs?: string;
  sign_as?: string;
  aidStore?: GroupFSAIDStore;
  aid_store?: GroupFSAIDStore;
}

export interface GroupFSDownloadResult {
  path: string;
  localPath?: string;
  size: number;
  sha256: string;
  verified: boolean;
  data: Uint8Array;
  blob?: Blob;
  wroteLocalFile?: boolean;
}

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

function isGroupRemoteCopyPath(value: string, ...groupHints: unknown[]): boolean {
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

function stripNil(params?: GroupFSParams | null): GroupFSParams {
  const out: GroupFSParams = {};
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== null) out[key] = value;
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

function text(value: unknown): string {
  return value === undefined || value === null ? '' : String(value).trim();
}

function accessTokenFromClient(client: GroupFSRpcClient): string {
  const authClient = client as GroupFSAuthClient;
  if (typeof authClient.getAccessToken === 'function') {
    const token = text(authClient.getAccessToken());
    if (token) return token;
  }
  const directToken = text(authClient.accessToken ?? authClient.access_token);
  if (directToken) return directToken;
  const identityToken = text(authClient._identity?.access_token);
  if (identityToken) return identityToken;
  return text(authClient._sessionParams?.access_token);
}

function bearerHeaders(client: GroupFSRpcClient): Record<string, string> | undefined {
  const token = accessTokenFromClient(client);
  return token ? { Authorization: `Bearer ${token}` } : undefined;
}

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.digest) throw new StorageError('SHA-256 unavailable', 'EUNSUPPORTED');
  const digest = await subtle.digest('SHA-256', toExactArrayBuffer(data));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function blobToBytes(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === 'function') {
    return new Uint8Array(await blob.arrayBuffer());
  }
  if (typeof blob.stream === 'function' && typeof Response !== 'undefined') {
    return new Uint8Array(await new Response(blob).arrayBuffer());
  }
  if (typeof FileReader !== 'undefined') {
    return await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
      reader.onerror = () => reject(reader.error ?? new StorageError('Blob read failed', 'ESTORAGE'));
      reader.readAsArrayBuffer(blob);
    });
  }
  if (typeof blob.text === 'function') {
    return new TextEncoder().encode(await blob.text());
  }
  throw new StorageError('Blob reads are unavailable in this JavaScript runtime', 'EUNSUPPORTED');
}

async function toBytes(source: GroupFSBinarySource | string): Promise<Uint8Array> {
  if (typeof source === 'string') return new TextEncoder().encode(source);
  if (source instanceof Uint8Array) return source;
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  if (typeof Blob !== 'undefined' && source instanceof Blob) {
    return blobToBytes(source);
  }
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  throw new StorageError('unsupported group fs upload source', 'EUNSUPPORTED');
}

async function importNodeModule<T>(specifier: string): Promise<T | null> {
  if (typeof document !== 'undefined') return null;
  const getBuiltinModule = (globalThis as unknown as {
    process?: { getBuiltinModule?: (name: string) => T };
  }).process?.getBuiltinModule;
  if (typeof getBuiltinModule === 'function' && specifier.startsWith('node:')) {
    try {
      return getBuiltinModule(specifier.slice('node:'.length));
    } catch {
      // 回退到动态 import。
    }
  }
  try {
    const requireFn = Function('return typeof require !== "undefined" ? require : undefined') as () => ((name: string) => T) | undefined;
    const requireModule = requireFn();
    if (requireModule) return requireModule(specifier);
  } catch {
    // 回退到动态 import。
  }
  try {
    const dynamicImport = Function(`return import(${JSON.stringify(specifier)})`) as () => Promise<T>;
    return await dynamicImport();
  } catch {
    return null;
  }
}

async function readLocalFile(path: string): Promise<Uint8Array> {
  const fs = await importNodeModule<{ readFile(path: string): Promise<Uint8Array> }>('node:fs/promises');
  if (!fs?.readFile) throw new StorageError('local file reads are unavailable in this JavaScript runtime', 'EUNSUPPORTED', path);
  return new Uint8Array(await fs.readFile(path));
}

async function writeLocalFile(path: string, data: Uint8Array, force: boolean): Promise<boolean> {
  const fs = await importNodeModule<{
    mkdir(path: string, options?: { recursive?: boolean }): Promise<void>;
    writeFile(path: string, data: Uint8Array, options?: { flag?: string }): Promise<void>;
  }>('node:fs/promises');
  const pathMod = await importNodeModule<{ dirname(path: string): string }>('node:path');
  if (!fs?.writeFile || !pathMod?.dirname) return false;
  await fs.mkdir(pathMod.dirname(path), { recursive: true });
  try {
    await fs.writeFile(path, data, force ? undefined : { flag: 'wx' });
    return true;
  } catch (exc) {
    const code = text((exc as { code?: unknown }).code);
    if (code === 'EEXIST') throw new StorageExistsError(`local path already exists: ${path}`, 'EEXIST', path);
    throw exc;
  }
}

async function localFileStatus(path: string): Promise<'file' | 'dir' | 'missing' | 'unavailable'> {
  const fs = await importNodeModule<{ stat(path: string): Promise<{ isDirectory(): boolean }> }>('node:fs/promises');
  if (!fs?.stat) return 'unavailable';
  try {
    const info = await fs.stat(path);
    return info.isDirectory() ? 'dir' : 'file';
  } catch (exc) {
    const code = text((exc as { code?: unknown }).code);
    if (code === 'ENOENT') return 'missing';
    throw exc;
  }
}

function guessContentType(path: string): string {
  const lower = path.toLowerCase();
  if (lower.endsWith('.md')) return 'text/markdown';
  if (lower.endsWith('.txt')) return 'text/plain';
  if (lower.endsWith('.json')) return 'application/json';
  if (lower.endsWith('.html') || lower.endsWith('.htm')) return 'text/html';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  return 'application/octet-stream';
}

function downloadTarget(dst: GroupFSCpDestination): { mode: 'blob' | 'bytes' | 'local'; localPath?: string } {
  if (typeof dst === 'string') {
    if (dst === 'blob:') return { mode: 'blob' };
    if (dst === 'bytes:') return { mode: 'bytes' };
    return { mode: 'local', localPath: stripLocalPathPrefix(dst) };
  }
  const mode = dst.type === 'blob' ? 'blob' : dst.type === 'bytes' ? 'bytes' : dst.path || dst.localPath ? 'local' : 'bytes';
  const localPath = dst.path ?? dst.localPath;
  return { mode, localPath: localPath ? stripLocalPathPrefix(localPath) : localPath };
}

export class GroupFSVFS {
  readonly lowlevel: StorageLowLevel;
  private readonly client: GroupFSRpcClient;

  constructor(client: GroupFSRpcClient, options: { lowlevel?: StorageLowLevel } = {}) {
    this.client = client;
    this.lowlevel = options.lowlevel ?? new StorageLowLevel(client as StorageRpcClient);
  }

  private async call(method: string, params?: GroupFSParams | null, path = ''): Promise<unknown> {
    try {
      return await this.client.call(method, await this.prepareParams(params));
    } catch (exc) {
      throw mapStorageError(exc, path);
    }
  }

  private async prepareParams(params?: GroupFSParams | null): Promise<RpcParams> {
    const next: GroupFSParams = { ...(params ?? {}) };
    const signAs = text(next.sign_as ?? next.signAs);
    const aidStore = (next.aid_store ?? next.aidStore) as GroupFSAIDStore | undefined;
    delete next.sign_as;
    delete next.signAs;
    delete next.aid_store;
    delete next.aidStore;
    if (signAs) {
      const currentAid = text(this.client.aid ?? (this.client as unknown as { _aid?: string })._aid);
      if (currentAid.toLowerCase() !== signAs.toLowerCase()) {
        if (!aidStore) {
          throw new Error(`group.fs operation requires aidStore to sign as ${signAs}`);
        }
        next._client_signature_identity = await loadSigningAID(aidStore, signAs);
      }
    }
    return stripNil(next) as RpcParams;
  }

  ls(path: string, options: GroupFSParams = {}): Promise<unknown> {
    return this.call('group.fs.ls', { path, ...options }, path);
  }

  find(path: string, options: GroupFSParams = {}): Promise<unknown> {
    return this.call('group.fs.find', { path, ...options }, path);
  }

  stat(path: string, options: GroupFSParams = {}): Promise<unknown> {
    return this.call('group.fs.stat', { path, ...options }, path);
  }

  lstat(path: string, options: GroupFSParams = {}): Promise<unknown> {
    return this.call('group.fs.lstat', { path, ...options }, path);
  }

  mkdir(path: string, options: GroupFSParams & { parents?: boolean } = {}): Promise<unknown> {
    return this.call('group.fs.mkdir', { path, parents: options.parents ?? false, ...options }, path);
  }

  rm(path: string, options: GroupFSParams & { recursive?: boolean; force?: boolean } = {}): Promise<unknown> {
    return this.call('group.fs.rm', {
      path,
      recursive: options.recursive ?? false,
      force: options.force ?? false,
      ...options,
    }, path);
  }

  async cp(src: GroupFSCpSource, dst: GroupFSCpDestination, options: GroupFSCpOptions = {}): Promise<unknown> {
    const groupId = options.group_id ?? options.groupId;
    const srcGroupId = options.src_group_id ?? options.srcGroupId;
    const dstGroupId = options.dst_group_id ?? options.dstGroupId;
    const srcRemote = typeof src === 'string' && isGroupRemoteCopyPath(src, srcGroupId, groupId);
    const dstRemote = typeof dst === 'string' && isGroupRemoteCopyPath(dst, dstGroupId, groupId);

    if (srcRemote && dstRemote) return this.copyRemoteToRemote(src as string, dst as string, options);
    if (!srcRemote && dstRemote) return this.uploadToGroup(src, dst as string, options);
    if (srcRemote && !dstRemote) return this.downloadFromGroup(src as string, dst, options);
    throw new StorageError('local-to-local copy is not handled by group.fs', 'EINVAL', typeof src === 'string' ? src : '');
  }

  async mv(src: string, dst: string, options: GroupFSCpOptions = {}): Promise<unknown> {
    const groupId = options.group_id ?? options.groupId;
    const srcGroupId = options.src_group_id ?? options.srcGroupId;
    const dstGroupId = options.dst_group_id ?? options.dstGroupId;
    if (!isGroupRemoteCopyPath(src, srcGroupId, groupId) || !isGroupRemoteCopyPath(dst, dstGroupId, groupId)) {
      throw new StorageError('group.fs.mv only supports group remote paths', 'EINVAL', src);
    }
    const params = this.remoteCopyParams(src, dst, options);
    return this.call('group.fs.mv', params, src);
  }

  df(pathOrGroup?: string | null, options: GroupFSParams = {}): Promise<unknown> {
    const params: GroupFSParams = { ...options };
    if (pathOrGroup !== undefined && pathOrGroup !== null) params.path = pathOrGroup;
    return this.call('group.fs.df', params, pathOrGroup ?? '');
  }

  mount(path: string, options: GroupFSParams = {}): Promise<unknown> {
    return this.call('group.fs.mount', { path, ...options }, path);
  }

  umount(path: string, options: GroupFSParams = {}): Promise<unknown> {
    return this.call('group.fs.umount', { path, ...options }, path);
  }

  private remoteCopyParams(src: string, dst: string, options: GroupFSCpOptions): GroupFSParams {
    const params: GroupFSParams = { ...options, src, dst };
    delete params.contentType;
    delete params.content_type;
    delete params.metadata;
    delete params.expectedVersion;
    delete params.expected_version;
    delete params.parents;
    delete params.verifyHash;
    delete params.verify_hash;
    delete params.sourceType;
    delete params.source_type;
    delete params.localPath;
    delete params.local_path;
    if (options.groupId !== undefined) params.group_id = options.groupId;
    if (options.srcGroupId !== undefined) params.src_group_id = options.srcGroupId;
    if (options.dstGroupId !== undefined) params.dst_group_id = options.dstGroupId;
    if (options.followSymlinks !== undefined) params.follow_symlinks = options.followSymlinks;
    delete params.followSymlinks;
    if (!options.force) delete params.force;
    if (!options.recursive) delete params.recursive;
    return stripNil(params);
  }

  private copyRemoteToRemote(src: string, dst: string, options: GroupFSCpOptions): Promise<unknown> {
    return this.call('group.fs.cp', this.remoteCopyParams(src, dst, options), src);
  }

  private async sourceBytes(src: GroupFSCpSource, options: GroupFSCpOptions): Promise<{ data: Uint8Array; contentType: string }> {
    if (typeof src === 'string') {
      const sourceType = text(options.source_type ?? options.sourceType);
      if (isExplicitLocalPath(src) || sourceType === 'path' || options.localPath === true || options.local_path === true) {
        const localPath = stripLocalPathPrefix(src);
        return { data: await readLocalFile(localPath), contentType: guessContentType(localPath) };
      }
      return { data: await toBytes(src), contentType: 'text/plain;charset=utf-8' };
    }
    const data = await toBytes(src);
    const blobType = typeof Blob !== 'undefined' && src instanceof Blob ? text(src.type) : '';
    const fileName = text((src as { name?: unknown }).name);
    return { data, contentType: blobType || (fileName ? guessContentType(fileName) : 'application/octet-stream') };
  }

  private async uploadToGroup(src: GroupFSCpSource, dst: string, options: GroupFSCpOptions): Promise<unknown> {
    const { data, contentType } = await this.sourceBytes(src, options);
    const digest = await sha256Hex(data);
    const baseParams = stripNil({
      ...options,
      path: dst,
      group_id: options.group_id ?? options.groupId ?? options.dst_group_id ?? options.dstGroupId,
      size_bytes: data.byteLength,
      sha256: digest,
      content_type: options.content_type ?? options.contentType ?? contentType,
      force: options.force ?? false,
      parents: options.parents ?? true,
      metadata: options.metadata,
      expected_version: options.expected_version ?? options.expectedVersion,
    });
    delete baseParams.groupId;
    delete baseParams.dstGroupId;
    delete baseParams.dst_group_id;
    delete baseParams.srcGroupId;
    delete baseParams.src_group_id;
    delete baseParams.contentType;
    delete baseParams.expectedVersion;
    delete baseParams.verifyHash;
    delete baseParams.verify_hash;
    delete baseParams.recursive;
    delete baseParams.followSymlinks;
    delete baseParams.follow_symlinks;
    delete baseParams.sourceType;
    delete baseParams.source_type;
    delete baseParams.localPath;
    delete baseParams.local_path;

    const check = await this.call('group.fs.check_upload', baseParams, dst);
    if (check && typeof check === 'object') {
      const raw = check as Record<string, unknown>;
      if (raw.within_limit === false) throw new StorageError('file size exceeds group fs upload limit', 'E2BIG', dst, raw);
      if (raw.target_exists && !options.force && options.expected_version === undefined && options.expectedVersion === undefined) {
        throw new StorageExistsError('group fs target already exists', 'EEXIST', dst, raw.target);
      }
      if (raw.instant || raw.dedup_hit || raw.skip_upload) {
        return this.call('group.fs.complete_upload', {
          ...baseParams,
          skip_blob: true,
          session_id: raw.session_id,
        }, dst);
      }
    }

    const session = await this.call('group.fs.create_upload_session', baseParams, dst);
    if (!session || typeof session !== 'object') {
      throw new StorageError(`group.fs.create_upload_session returned invalid response`, 'ESTORAGE', dst, session);
    }
    const rawSession = session as Record<string, unknown>;
    const uploadUrl = text(rawSession.upload_url ?? rawSession.url);
    if (!uploadUrl) throw new StorageError('group.fs.create_upload_session did not return upload_url', 'ESTORAGE', dst, session);
    const headers: Record<string, string> = {};
    if (rawSession.headers && typeof rawSession.headers === 'object' && !Array.isArray(rawSession.headers)) {
      for (const [key, value] of Object.entries(rawSession.headers as Record<string, unknown>)) {
        if (value !== undefined && value !== null) headers[key] = String(value);
      }
    }
    if (!Object.keys(headers).some((key) => key.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = text(baseParams.content_type) || 'application/octet-stream';
    }
    await this.lowlevel.httpPut(uploadUrl, data, headers);
    return this.call('group.fs.complete_upload', {
      ...baseParams,
      session_id: rawSession.session_id ?? rawSession.id,
    }, dst);
  }

  private async downloadFromGroup(src: string, dst: GroupFSCpDestination, options: GroupFSCpOptions): Promise<GroupFSDownloadResult> {
    const target = downloadTarget(dst);
    if (target.mode === 'local' && target.localPath) {
      const status = await localFileStatus(target.localPath);
      if (status === 'file' && !options.force) {
        throw new StorageExistsError(`local path already exists: ${target.localPath}`, 'EEXIST', target.localPath);
      }
    }

    const params = stripNil({
      ...options,
      path: src,
      group_id: options.group_id ?? options.groupId ?? options.src_group_id ?? options.srcGroupId,
    });
    delete params.groupId;
    delete params.srcGroupId;
    delete params.src_group_id;
    delete params.dstGroupId;
    delete params.dst_group_id;
    delete params.force;
    delete params.recursive;
    delete params.parents;
    delete params.contentType;
    delete params.content_type;
    delete params.expectedVersion;
    delete params.expected_version;
    delete params.verifyHash;
    delete params.verify_hash;
    delete params.sourceType;
    delete params.source_type;
    delete params.localPath;
    delete params.local_path;

    const ticket = await this.call('group.fs.create_download_ticket', params, src);
    if (!ticket || typeof ticket !== 'object') {
      throw new StorageError('group.fs.create_download_ticket returned invalid response', 'ESTORAGE', src, ticket);
    }
    const rawTicket = ticket as Record<string, unknown>;
    const downloadUrl = text(rawTicket.download_url ?? rawTicket.url);
    if (!downloadUrl) throw new StorageError('group.fs.create_download_ticket did not return download_url', 'ESTORAGE', src, ticket);
    const data = await this.lowlevel.httpGet(downloadUrl, bearerHeaders(this.client));
    const expectedSha = text(rawTicket.sha256);
    const verifyHash = options.verify_hash ?? options.verifyHash ?? true;
    const verified = !verifyHash || !expectedSha || (await sha256Hex(data)) === expectedSha.toLowerCase();
    if (verifyHash && !verified) {
      throw new StorageConflictError('download hash verification failed', 'ECONFLICT', src, ticket);
    }

    if (target.mode === 'local' && target.localPath) {
      const status = await localFileStatus(target.localPath);
      if (status === 'dir') {
        throw new StorageError('directory download target is not supported in this JavaScript runtime', 'EISDIR', target.localPath);
      }
      if (status === 'file' && !options.force) {
        throw new StorageExistsError(`local path already exists: ${target.localPath}`, 'EEXIST', target.localPath);
      }
    }

    const result: GroupFSDownloadResult = {
      path: src,
      localPath: target.localPath,
      size: data.byteLength,
      sha256: expectedSha,
      verified,
      data,
    };
    if (target.mode === 'blob' && typeof Blob !== 'undefined') {
      result.blob = new Blob([toExactArrayBuffer(data)], { type: text(rawTicket.content_type) || 'application/octet-stream' });
    }
    if (target.mode === 'local' && target.localPath) {
      result.wroteLocalFile = await writeLocalFile(target.localPath, data, Boolean(options.force));
    }
    return result;
  }
}
