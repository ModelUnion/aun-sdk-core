export type StorageRaw = Record<string, unknown>;

function text(value: unknown, fallback = ''): string {
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function intValue(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : fallback;
}

function boolValue(value: unknown, fallback = false): boolean {
  if (value === null || value === undefined) return fallback;
  return Boolean(value);
}

function mountSourceFromRaw(raw: StorageRaw): string {
  const explicit = text(raw.mount_source);
  if (explicit) return explicit;
  const sourceAid = text(raw.source_aid);
  if (!sourceAid) return '';
  return `${sourceAid}:${keyToPath(raw.source_path)}`;
}

export function normalizePath(path: string): string {
  let raw = String(path || '/').replace(/\\/g, '/').trim();
  if (!raw.startsWith('/')) raw = `/${raw}`;
  raw = raw.replace(/\/+/g, '/');
  const parts: string[] = [];
  for (const part of raw.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      parts.pop();
      continue;
    }
    parts.push(part);
  }
  return parts.length ? `/${parts.join('/')}` : '/';
}

export function pathToKey(path: string): string {
  const normalized = normalizePath(path);
  return normalized === '/' ? '' : normalized.slice(1);
}

export function keyToPath(key: unknown): string {
  return normalizePath(text(key));
}

export function nameFromPath(path: string): string {
  const cleaned = normalizePath(path).replace(/\/+$/g, '');
  if (!cleaned || cleaned === '/') return '/';
  return cleaned.split('/').pop() || '/';
}

export interface NodeView {
  type: string;
  path: string;
  name: string;
  owner: string;
  bucket: string;
  size: number;
  mtime: number;
  contentType: string;
  version: number;
  mode: string;
  isPublic: boolean;
  objectId: string;
  folderId: string;
  target: string;
  mountSource: string;
  metadata: StorageRaw;
  sha256?: string;
  etag?: string;
}

export interface DownloadResult {
  path: string;
  localPath?: string;
  size: number;
  sha256: string;
  verified: boolean;
  data?: Uint8Array;
}

export interface RemoveResult {
  path: string;
  removedCount: number;
}

export interface UnmountResult {
  unmounted: boolean;
  owner: string;
  bucket: string;
  path: string;
  mountPath: string;
}

export interface UsageView {
  owner: string;
  quotaBytes: number;
  usedBytes: number;
  availBytes: number;
  objectCount: number;
}

function baseNode(raw: StorageRaw, type: string, path: string): NodeView {
  return {
    type,
    path,
    name: text(raw.name) || nameFromPath(path),
    owner: text(raw.owner ?? raw.owner_aid),
    bucket: text(raw.bucket, 'default') || 'default',
    size: intValue(raw.size ?? raw.size_bytes),
    mtime: intValue(raw.mtime ?? raw.updated_at),
    contentType: text(raw.content_type),
    version: intValue(raw.version),
    mode: text(raw.mode),
    isPublic: !boolValue(raw.is_private, true),
    objectId: text(raw.object_id),
    folderId: text(raw.folder_id),
    target: text(raw.target),
    mountSource: mountSourceFromRaw(raw),
    metadata: (raw.metadata && typeof raw.metadata === 'object' && !Array.isArray(raw.metadata)) ? raw.metadata as StorageRaw : {},
  };
}

export function nodeFromAny(input: unknown): NodeView {
  const raw = (input && typeof input === 'object') ? input as StorageRaw : {};
  const nodeType = text(raw.type ?? raw.node_type).toLowerCase();
  if (['folder', 'dir', 'directory'].includes(nodeType)) return baseNode(raw, 'dir', keyToPath(raw.path));
  if (['symlink', 'link'].includes(nodeType)) return baseNode(raw, 'symlink', keyToPath(raw.path));
  if (nodeType === 'mount') return baseNode(raw, 'mount', keyToPath(raw.path));
  const path = keyToPath(raw.path ?? raw.object_key);
  return {
    ...baseNode(raw, 'file', path),
    sha256: text(raw.sha256),
    etag: text(raw.etag),
  };
}

export function usageFromAny(input: unknown, ownerFallback = ''): UsageView {
  const raw = (input && typeof input === 'object') ? input as StorageRaw : {};
  const quota = intValue(raw.quota_bytes ?? raw.quota_total_bytes);
  const used = intValue(raw.used_bytes ?? raw.quota_used_bytes);
  return {
    owner: text(raw.owner ?? raw.owner_aid, ownerFallback),
    quotaBytes: quota,
    usedBytes: used,
    availBytes: quota ? Math.max(0, quota - used) : 0,
    objectCount: intValue(raw.object_count),
  };
}

export function unmountFromAny(input: unknown, fallback: { owner?: string | null; bucket?: string; mountPath: string }): UnmountResult {
  const raw = (input && typeof input === 'object') ? input as StorageRaw : {};
  const path = keyToPath(raw.mount_path ?? raw.path ?? fallback.mountPath);
  return {
    unmounted: boolValue(raw.unmounted),
    owner: text(raw.owner ?? raw.owner_aid, fallback.owner ?? ''),
    bucket: text(raw.bucket, fallback.bucket ?? 'default') || (fallback.bucket ?? 'default'),
    path,
    mountPath: path,
  };
}
