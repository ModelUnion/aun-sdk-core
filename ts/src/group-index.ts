import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import { resultErr, resultOk, type Result } from './result.js';
import { canonicalStringify } from './v2/crypto/canonical.js';

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
  sign(payload: Buffer | Uint8Array | string): Result<{ signature: string }>;
  verify(payload: Buffer | Uint8Array | string, signature: string): Result<{ valid: boolean }>;
}

export class GroupIndexMetaCache {
  private readonly aunPath: string;
  private readonly remote = new Map<string, Record<string, unknown>>();
  private readonly localEtags = new Map<string, string>();
  private readonly stale = new Set<string>();
  private readonly settings = new Map<string, Record<string, unknown>>();
  private readonly entryEtags = new Map<string, Record<string, string>>();

  constructor(aunPath = '') {
    this.aunPath = String(aunPath ?? '').trim();
  }

  observeRpcMeta(meta: Record<string, unknown>, options: { localAid: string }): void {
    const groupIndexes = isRecord(meta?.group_indexes) ? meta.group_indexes : null;
    if (!groupIndexes) return;
    const local = String(options.localAid ?? '');
    for (const [groupAid, value] of Object.entries(groupIndexes)) {
      if (!isRecord(value)) continue;
      const key = this.key(local, groupAid);
      this.loadKey(local, groupAid);
      const remoteMeta: Record<string, unknown> = {};
      for (const name of ['etag', 'last_modified', 'schema']) {
        if (value[name] !== undefined && value[name] !== null) remoteMeta[name] = value[name];
      }
      this.remote.set(key, remoteMeta);
      const remoteEtag = String(remoteMeta.etag ?? '');
      if (remoteEtag && this.localEtags.get(key) !== remoteEtag) this.stale.add(key);
      this.saveKey(local, groupAid);
    }
  }

  markFresh(localAid: string, groupAid: string, options: { etag: string }): void {
    const key = this.key(localAid, groupAid);
    this.loadKey(localAid, groupAid);
    this.localEtags.set(key, String(options.etag ?? ''));
    this.stale.delete(key);
    this.saveKey(localAid, groupAid);
  }

  isStale(localAid: string, groupAid: string): boolean {
    this.loadKey(localAid, groupAid);
    return this.stale.has(this.key(localAid, groupAid));
  }

  remoteMeta(localAid: string, groupAid: string): Record<string, unknown> | null {
    this.loadKey(localAid, groupAid);
    const value = this.remote.get(this.key(localAid, groupAid));
    return value ? { ...value } : null;
  }

  localEtag(localAid: string, groupAid: string): string {
    this.loadKey(localAid, groupAid);
    return this.localEtags.get(this.key(localAid, groupAid)) ?? '';
  }

  cachedSettings(localAid: string, groupAid: string, keys: string[]): Record<string, unknown> | null {
    this.loadKey(localAid, groupAid);
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
    this.loadKey(localAid, groupAid);
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
    options?: { entries?: GroupIndexEntry[]; etag?: string; groupIndex?: string | { body?: unknown } | SignedGroupIndex },
  ): void {
    this.loadKey(localAid, groupAid);
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
    else this.saveKey(localAid, groupAid);
    this.saveGroupIndexBody(localAid, groupAid, options?.groupIndex);
  }

  private key(localAid: string, groupAid: string): string {
    return `${String(localAid ?? '')}\x00${String(groupAid ?? '')}`;
  }

  private cacheDir(localAid: string, groupAid: string): string {
    const local = this.safePart(localAid);
    const group = this.safePart(groupAid);
    if (!this.aunPath || !local || !group) return '';
    return path.join(this.aunPath, 'AIDs', local, 'groups', group);
  }

  private safePart(value: string): string {
    const text = String(value ?? '').trim();
    if (!text || text.includes('/') || text.includes('\\') || text.includes('\0')) return '';
    return text;
  }

  private loadKey(localAid: string, groupAid: string): void {
    const key = this.key(localAid, groupAid);
    if (this.remote.has(key) || this.localEtags.has(key) || this.settings.has(key)) return;
    const dir = this.cacheDir(localAid, groupAid);
    if (!dir) return;
    const file = path.join(dir, 'group-index-cache.json');
    if (!fs.existsSync(file)) return;
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<string, unknown>;
      if (isRecord(data.remote_meta)) this.remote.set(key, { ...data.remote_meta });
      const localEtag = String(data.local_etag ?? '');
      if (localEtag) this.localEtags.set(key, localEtag);
      if (isRecord(data.settings)) this.settings.set(key, { ...data.settings });
      if (isRecord(data.entry_etags)) {
        this.entryEtags.set(key, Object.fromEntries(Object.entries(data.entry_etags).map(([k, v]) => [String(k), String(v ?? '')])));
      }
      const remoteEtag = String(this.remote.get(key)?.etag ?? '');
      if (remoteEtag && this.localEtags.get(key) !== remoteEtag) this.stale.add(key);
    } catch {
      // Ignore damaged cache; the next successful pull rewrites it.
    }
  }

  private saveKey(localAid: string, groupAid: string): void {
    const key = this.key(localAid, groupAid);
    const dir = this.cacheDir(localAid, groupAid);
    if (!dir) return;
    const payload = {
      local_aid: String(localAid ?? ''),
      group_aid: String(groupAid ?? ''),
      remote_meta: this.remote.get(key) ?? {},
      local_etag: this.localEtags.get(key) ?? '',
      settings: this.settings.get(key) ?? {},
      entry_etags: this.entryEtags.get(key) ?? {},
    };
    this.atomicWrite(path.join(dir, 'group-index-cache.json'), `${JSON.stringify(payload, null, 2)}\n`);
  }

  private saveGroupIndexBody(localAid: string, groupAid: string, groupIndex?: string | { body?: unknown } | SignedGroupIndex): void {
    if (!groupIndex) return;
    const body = typeof groupIndex === 'string' ? groupIndex : String((groupIndex as { body?: unknown }).body ?? '');
    if (!body) return;
    const dir = this.cacheDir(localAid, groupAid);
    if (!dir) return;
    this.atomicWrite(path.join(dir, 'index.jsonl'), body.endsWith('\n') ? body : `${body}\n`);
  }

  private atomicWrite(file: string, content: string): void {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
    fs.writeFileSync(tmp, content, 'utf-8');
    fs.renameSync(tmp, file);
  }
}

export function computeGroupIndexBodyHash(entries: GroupIndexEntry[]): string {
  return `sha256:${sha256Hex(entriesBytes(entries))}`;
}

export function groupIndexEtag(entries: GroupIndexEntry[]): string {
  return `"sha256:${sha256Hex(entriesBytes(entries))}"`;
}

export function groupIndexSigningPayload(meta: Record<string, unknown>, entries: GroupIndexEntry[]): Buffer {
  const metaWithoutSignature: Record<string, unknown> = { ...meta };
  delete metaWithoutSignature.signature;
  const lines = [canonicalStringify(metaWithoutSignature)];
  lines.push(...canonicalEntries(entries).map((item) => canonicalStringify(item)));
  return Buffer.from(`${lines.join('\n')}\n`, 'utf-8');
}

export function buildSignedGroupIndex(options: {
  groupAid: string;
  entries: GroupIndexEntry[];
  signer: GroupIndexSigner;
  lastModified: number;
  schema?: string;
}): SignedGroupIndex {
  const entries = canonicalEntries(options.entries);
  const meta: GroupIndexMeta = {
    type: 'index_meta',
    group_aid: String(options.groupAid),
    etag: groupIndexEtag(entries),
    last_modified: Math.trunc(Number(options.lastModified)),
    schema: String(options.schema ?? GROUP_INDEX_SCHEMA),
    body_hash: computeGroupIndexBodyHash(entries),
    signed_by: options.signer.aid,
    sig_alg: GROUP_INDEX_SIG_ALG,
  };
  const signed = options.signer.sign(groupIndexSigningPayload(meta, entries));
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

export function verifyGroupIndex(
  body: string | { body?: unknown },
  signer: GroupIndexSigner,
): Result<{ valid: false; reason: string } | { valid: true; meta: GroupIndexMeta; entries: GroupIndexEntry[] }> {
  try {
    const parsed = parseGroupIndex(body);
    const signature = String(parsed.meta.signature ?? '');
    if (!signature) return resultOk({ valid: false, reason: 'signature missing' });
    if (String(parsed.meta.signed_by ?? '') !== signer.aid) return resultOk({ valid: false, reason: 'signed_by mismatch' });
    if (String(parsed.meta.sig_alg ?? '') !== GROUP_INDEX_SIG_ALG) return resultOk({ valid: false, reason: 'unsupported sig_alg' });
    if (String(parsed.meta.body_hash ?? '') !== computeGroupIndexBodyHash(parsed.entries)) {
      return resultOk({ valid: false, reason: 'body_hash mismatch' });
    }
    if (String(parsed.meta.etag ?? '') !== groupIndexEtag(parsed.entries)) {
      return resultOk({ valid: false, reason: 'etag mismatch' });
    }
    const verified = signer.verify(groupIndexSigningPayload(parsed.meta, parsed.entries), signature);
    if (!verified.ok) return resultErr(verified.error.code, verified.error.message || 'group index verify failed', verified.error.cause);
    if (!verified.data.valid) return resultOk({ valid: false, reason: 'signature verification failed' });
    return resultOk({ valid: true, meta: parsed.meta, entries: canonicalEntries(parsed.entries) });
  } catch (exc) {
    return resultErr('GROUP_INDEX_VERIFY_ERROR', String(exc), exc);
  }
}

export function prepareGroupSettingsWithIndex(options: {
  groupAid: string;
  settings: Record<string, unknown>;
  signer: GroupIndexSigner;
  lastModified: number;
  baseIndex?: string | { body?: unknown } | null;
}): Record<string, unknown> {
  const result: Record<string, unknown> = { ...options.settings };
  const updatedEntries = Object.entries(options.settings)
    .filter(([key]) => key !== GROUP_INDEX_KEY)
    .map(([key, value]) => settingEntry(key, value, options.lastModified));
  const updatedKeys = new Set(updatedEntries.map((item) => item.key));
  const entries: GroupIndexEntry[] = [];
  if (options.baseIndex) {
    const parsed = parseGroupIndex(options.baseIndex);
    entries.push(...parsed.entries.filter((item) => !updatedKeys.has(String(item.key))).map((item) => ({ ...item })));
  }
  entries.push(...updatedEntries);
  result[GROUP_INDEX_KEY] = buildSignedGroupIndex({
    groupAid: options.groupAid,
    entries,
    signer: options.signer,
    lastModified: options.lastModified,
  });
  return result;
}

function settingEntry(key: string, value: unknown, lastModified: number): GroupIndexEntry {
  const digest = sha256Hex(Buffer.from(canonicalStringify(value), 'utf-8'));
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

function entriesBytes(entries: GroupIndexEntry[]): Buffer {
  const lines = canonicalEntries(entries).map((item) => canonicalStringify(item));
  return Buffer.from(lines.length ? `${lines.join('\n')}\n` : '', 'utf-8');
}

function sha256Hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
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
