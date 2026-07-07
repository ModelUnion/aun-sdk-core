import { resultErr, resultOk, type Result } from './result.js';
import { canonicalJson } from './v2/crypto/canonical.js';

export const GROUP_INDEX_SCHEMA = 'aun.group.index.v1';
export const GROUP_INDEX_KEY = 'group.index';
export const GROUP_INDEX_SIG_ALG = 'ECDSA-P256-SHA256';

export interface GroupIndexEntry {
  key: string;
  source: string;
  etag: string;
  last_modified: number;
  [key: string]: unknown;
}

export interface GroupIndexMeta {
  type: 'index_meta';
  group_aid: string;
  etag: string;
  last_modified: number;
  schema: string;
  body_hash: string;
  signed_by: string;
  sig_alg: string;
  signature?: string;
  [key: string]: unknown;
}

export interface SignedGroupIndex {
  body: string;
  meta: GroupIndexMeta;
  entries: GroupIndexEntry[];
}

export interface GroupIndexSigner {
  aid: string;
  sign(payload: Uint8Array | string): Promise<Result<{ signature: string }>>;
  verify(payload: Uint8Array | string, signature: string): Promise<Result<{ valid: boolean }>>;
}

export class GroupIndexMetaCache {
  private readonly remote = new Map<string, Record<string, unknown>>();
  private readonly localEtags = new Map<string, string>();
  private readonly stale = new Set<string>();
  private readonly settings = new Map<string, Record<string, unknown>>();
  private readonly entryEtags = new Map<string, Record<string, string>>();

  observeRpcMeta(meta: Record<string, unknown>, options: { localAid: string }): void {
    const groupIndexes = isRecord(meta?.group_indexes) ? meta.group_indexes : null;
    if (!groupIndexes) return;
    const local = String(options.localAid ?? '');
    for (const [groupAid, value] of Object.entries(groupIndexes)) {
      if (!isRecord(value)) continue;
      const key = this.key(local, groupAid);
      const remoteMeta: Record<string, unknown> = {};
      for (const name of ['etag', 'last_modified', 'schema']) {
        if (value[name] !== undefined && value[name] !== null) remoteMeta[name] = value[name];
      }
      this.remote.set(key, remoteMeta);
      const remoteEtag = String(remoteMeta.etag ?? '');
      if (remoteEtag && this.localEtags.get(key) !== remoteEtag) this.stale.add(key);
    }
  }

  markFresh(localAid: string, groupAid: string, options: { etag: string }): void {
    const key = this.key(localAid, groupAid);
    this.localEtags.set(key, String(options.etag ?? ''));
    this.stale.delete(key);
  }

  isStale(localAid: string, groupAid: string): boolean {
    return this.stale.has(this.key(localAid, groupAid));
  }

  remoteMeta(localAid: string, groupAid: string): Record<string, unknown> | null {
    const value = this.remote.get(this.key(localAid, groupAid));
    return value ? { ...value } : null;
  }

  localEtag(localAid: string, groupAid: string): string {
    return this.localEtags.get(this.key(localAid, groupAid)) ?? '';
  }

  cachedSettings(localAid: string, groupAid: string, keys: string[]): Record<string, unknown> | null {
    const value = this.settings.get(this.key(localAid, groupAid)) ?? {};
    if (!keys.every((item) => item in value)) return null;
    return Object.fromEntries(keys.map((item) => [item, value[item]]));
  }

  cachedSettingsByEntries(
    localAid: string,
    groupAid: string,
    keys: string[],
    entries: GroupIndexEntry[],
  ): { cached: Record<string, unknown>; missing: string[] } {
    const key = this.key(localAid, groupAid);
    const value = this.settings.get(key) ?? {};
    const localEntryEtags = this.entryEtags.get(key) ?? {};
    const remoteEntryEtags = Object.fromEntries(entries.map((item) => [String(item.key ?? ''), String(item.etag ?? '')]));
    const cached: Record<string, unknown> = {};
    const missing: string[] = [];
    for (const item of keys) {
      if (item in value && localEntryEtags[item] === remoteEntryEtags[item]) {
        cached[item] = value[item];
      } else {
        missing.push(item);
      }
    }
    return { cached, missing };
  }

  cacheSettings(
    localAid: string,
    groupAid: string,
    settings: Record<string, unknown>,
    options?: { entries?: GroupIndexEntry[]; etag?: string },
  ): void {
    const key = this.key(localAid, groupAid);
    this.settings.set(key, { ...(this.settings.get(key) ?? {}), ...settings });
    if (options?.entries) {
      const nextEntryEtags = { ...(this.entryEtags.get(key) ?? {}) };
      for (const item of options.entries) {
        const entryKey = String(item.key ?? '');
        if (entryKey) nextEntryEtags[entryKey] = String(item.etag ?? '');
      }
      this.entryEtags.set(key, nextEntryEtags);
    }
    if (options?.etag) this.markFresh(localAid, groupAid, { etag: options.etag });
  }

  restore(
    localAid: string,
    groupAid: string,
    record: {
      remote_meta?: Record<string, unknown>;
      local_etag?: string;
      settings?: Record<string, unknown>;
      entry_etags?: Record<string, unknown>;
    },
  ): void {
    const key = this.key(localAid, groupAid);
    if (isRecord(record.remote_meta)) this.remote.set(key, { ...record.remote_meta });
    if (record.local_etag !== undefined && record.local_etag !== null) {
      this.localEtags.set(key, String(record.local_etag ?? ''));
    }
    if (isRecord(record.settings)) this.settings.set(key, { ...(this.settings.get(key) ?? {}), ...record.settings });
    if (isRecord(record.entry_etags)) {
      this.entryEtags.set(key, {
        ...(this.entryEtags.get(key) ?? {}),
        ...Object.fromEntries(Object.entries(record.entry_etags).map(([entryKey, entryEtag]) => [entryKey, String(entryEtag ?? '')])),
      });
    }
    const remoteEtag = String(this.remote.get(key)?.etag ?? '');
    if (remoteEtag && this.localEtags.get(key) !== remoteEtag) this.stale.add(key);
    if (remoteEtag && this.localEtags.get(key) === remoteEtag) this.stale.delete(key);
  }

  private key(localAid: string, groupAid: string): string {
    return `${String(localAid ?? '')}\x00${String(groupAid ?? '')}`;
  }
}

export async function computeGroupIndexBodyHash(entries: GroupIndexEntry[]): Promise<string> {
  return `sha256:${await sha256Hex(entriesBytes(entries))}`;
}

export async function groupIndexEtag(entries: GroupIndexEntry[]): Promise<string> {
  return `"sha256:${await sha256Hex(entriesBytes(entries))}"`;
}

export function groupIndexSigningPayload(meta: Record<string, unknown>, entries: GroupIndexEntry[]): Uint8Array {
  const metaWithoutSignature: Record<string, unknown> = { ...meta };
  delete metaWithoutSignature.signature;
  const lines = [canonicalStringify(metaWithoutSignature)];
  lines.push(...canonicalEntries(entries).map((item) => canonicalStringify(item)));
  return encode(`${lines.join('\n')}\n`);
}

export async function buildSignedGroupIndex(options: {
  groupAid: string;
  entries: GroupIndexEntry[];
  signer: GroupIndexSigner;
  lastModified: number;
  schema?: string;
}): Promise<SignedGroupIndex> {
  const entries = canonicalEntries(options.entries);
  const meta: GroupIndexMeta = {
    type: 'index_meta',
    group_aid: String(options.groupAid),
    etag: await groupIndexEtag(entries),
    last_modified: Math.trunc(Number(options.lastModified)),
    schema: String(options.schema ?? GROUP_INDEX_SCHEMA),
    body_hash: await computeGroupIndexBodyHash(entries),
    signed_by: options.signer.aid,
    sig_alg: GROUP_INDEX_SIG_ALG,
  };
  const signed = await options.signer.sign(groupIndexSigningPayload(meta, entries));
  if (!signed.ok) throw new Error(signed.error.message || 'group index signing failed');
  meta.signature = signed.data.signature;
  const body = [canonicalStringify(meta), ...entries.map((item) => canonicalStringify(item))].join('\n') + '\n';
  return { body, meta, entries };
}

export function parseGroupIndex(body: string | { body?: unknown }): { meta: GroupIndexMeta; entries: GroupIndexEntry[] } {
  const text = typeof body === 'string' ? body : String(body?.body ?? '');
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  if (lines.length === 0) throw new Error('group index body is empty');
  const meta = JSON.parse(lines[0]) as GroupIndexMeta;
  const entries = lines.slice(1).map((line) => JSON.parse(line) as GroupIndexEntry);
  if (meta.type !== 'index_meta') throw new Error('first group index line must be index_meta');
  return { meta, entries };
}

export async function verifyGroupIndex(
  body: string | { body?: unknown },
  signer: GroupIndexSigner,
): Promise<Result<{ valid: false; reason: string } | { valid: true; meta: GroupIndexMeta; entries: GroupIndexEntry[] }>> {
  try {
    const parsed = parseGroupIndex(body);
    const signature = String(parsed.meta.signature ?? '');
    if (!signature) return resultOk({ valid: false, reason: 'signature missing' });
    if (String(parsed.meta.signed_by ?? '') !== signer.aid) return resultOk({ valid: false, reason: 'signed_by mismatch' });
    if (String(parsed.meta.sig_alg ?? '') !== GROUP_INDEX_SIG_ALG) return resultOk({ valid: false, reason: 'unsupported sig_alg' });
    if (String(parsed.meta.body_hash ?? '') !== await computeGroupIndexBodyHash(parsed.entries)) {
      return resultOk({ valid: false, reason: 'body_hash mismatch' });
    }
    if (String(parsed.meta.etag ?? '') !== await groupIndexEtag(parsed.entries)) {
      return resultOk({ valid: false, reason: 'etag mismatch' });
    }
    const verified = await signer.verify(groupIndexSigningPayload(parsed.meta, parsed.entries), signature);
    if (!verified.ok) return resultErr(verified.error.code, verified.error.message || 'group index verify failed', verified.error.cause);
    if (!verified.data.valid) return resultOk({ valid: false, reason: 'signature verification failed' });
    return resultOk({ valid: true, meta: parsed.meta, entries: canonicalEntries(parsed.entries) });
  } catch (exc) {
    return resultErr('GROUP_INDEX_VERIFY_ERROR', String(exc), exc);
  }
}

export async function prepareGroupSettingsWithIndex(options: {
  groupAid: string;
  settings: Record<string, unknown>;
  signer: GroupIndexSigner;
  lastModified: number;
  baseIndex?: string | { body?: unknown } | null;
}): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = { ...options.settings };
  const updatedEntries: GroupIndexEntry[] = [];
  for (const [key, value] of Object.entries(options.settings)) {
    if (key !== GROUP_INDEX_KEY) updatedEntries.push(await settingEntry(key, value, options.lastModified));
  }
  const updatedKeys = new Set(updatedEntries.map((item) => item.key));
  const entries: GroupIndexEntry[] = [];
  if (options.baseIndex) {
    const parsed = parseGroupIndex(options.baseIndex);
    entries.push(...parsed.entries.filter((item) => !updatedKeys.has(String(item.key))).map((item) => ({ ...item })));
  }
  entries.push(...updatedEntries);
  result[GROUP_INDEX_KEY] = await buildSignedGroupIndex({
    groupAid: options.groupAid,
    entries,
    signer: options.signer,
    lastModified: options.lastModified,
  });
  return result;
}

async function settingEntry(key: string, value: unknown, lastModified: number): Promise<GroupIndexEntry> {
  const digest = await sha256Hex(encode(canonicalStringify(value)));
  return {
    key,
    source: 'db',
    etag: `"sha256:${digest}"`,
    last_modified: Math.trunc(Number(lastModified)),
  };
}

function canonicalEntries(entries: GroupIndexEntry[]): GroupIndexEntry[] {
  return entries.map((item) => ({ ...item })).sort((a, b) => compareCodePoints(String(a.key ?? ''), String(b.key ?? '')));
}

function entriesBytes(entries: GroupIndexEntry[]): Uint8Array {
  const lines = canonicalEntries(entries).map((item) => canonicalStringify(item));
  return encode(lines.length ? `${lines.join('\n')}\n` : '');
}

function canonicalStringify(value: unknown): string {
  return new TextDecoder().decode(canonicalJson(value));
}

function encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', exactArrayBuffer(data));
  return bytesToHex(new Uint8Array(digest));
}

function exactArrayBuffer(data: Uint8Array): ArrayBuffer {
  if (data.byteOffset === 0 && data.byteLength === data.buffer.byteLength && data.buffer instanceof ArrayBuffer) {
    return data.buffer;
  }
  return data.slice().buffer as ArrayBuffer;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function compareCodePoints(a: string, b: string): number {
  const ac = Array.from(a);
  const bc = Array.from(b);
  const n = Math.min(ac.length, bc.length);
  for (let i = 0; i < n; i++) {
    const av = ac[i].codePointAt(0) ?? 0;
    const bv = bc[i].codePointAt(0) ?? 0;
    if (av !== bv) return av - bv;
  }
  return ac.length - bc.length;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
