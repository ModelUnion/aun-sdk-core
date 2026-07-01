// ── IndexedDB 共享基础设施（内部模块，不对外导出）──────────────────

import { pemToArrayBuffer } from '../crypto.js';
import { normalizeInstanceId, slotIsolationKey } from '../config.js';
import type { ModuleLogger } from '../logger.js';
import type { AgentMdCacheRecord, AgentMdCacheUpsert, GroupStateRecord } from './index.js';
import {
  isJsonObject,
  type JsonObject,
  type KeyPairRecord,
  type MetadataRecord,
} from '../types.js';

export const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

// ── 对象仓库名称 ──────────────────────────────────────────────────
export const STORE_KEY_PAIRS = 'key_pairs';
export const STORE_CERTS = 'certs';
export const STORE_METADATA = 'metadata';
export const STORE_INSTANCE_STATE = 'instance_state';
export const STORE_GROUP_STATE = 'group_state';
export const STORE_AGENT_MD_CACHE = 'agent_md_cache';
export const STORE_PENDING_IDENTITIES = 'pending_identities';
export const STORE_PENDING_BINDS = 'pending_binds';

const DB_NAME = 'aun-keystore';
const DB_VERSION = 8;

// ── 工具函数 ──────────────────────────────────────────────────────

export function safeAid(aid: string): string {
  return aid.replace(/[/\\:]/g, '_');
}

export function encodePart(value: string): string {
  return encodeURIComponent(value);
}

export function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function isRecord(value: unknown): value is JsonObject {
  return isJsonObject(value as JsonObject | object | null | undefined);
}

export function toBufferSource(bytes: Uint8Array): BufferSource {
  return bytes.slice().buffer;
}

export function randomHex(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function metadataStoreKey(aid: string): string {
  return safeAid(aid);
}

export function normalizeCertFingerprint(certFingerprint?: string): string {
  const normalized = String(certFingerprint ?? '').trim().toLowerCase();
  if (!normalized) return '';
  if (!normalized.startsWith('sha256:')) return '';
  const hexPart = normalized.slice(7);
  if (hexPart.length !== 64 || /[^0-9a-f]/.test(hexPart)) return '';
  return normalized;
}

export async function fingerprintFromCertPem(certPem: string): Promise<string> {
  try {
    const der = pemToArrayBuffer(certPem);
    const hash = await crypto.subtle.digest('SHA-256', der);
    const hex = Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
    return `sha256:${hex}`;
  } catch {
    return '';
  }
}

export function certStoreKey(aid: string, certFingerprint?: string): string {
  const normalized = normalizeCertFingerprint(certFingerprint);
  if (!normalized) return safeAid(aid);
  return `${safeAid(aid)}|${encodePart(normalized)}`;
}

export function instanceStateStoreKey(aid: string, deviceId: string, slotId = ''): string {
  const normalizedDevice = normalizeInstanceId(deviceId, 'device_id');
  const slotKey = slotIsolationKey(slotId) || '_singleton';
  return `${safeAid(aid)}|${encodePart(normalizedDevice)}|${encodePart(slotKey)}`;
}

export function seqTrackerPrefix(aid: string, deviceId: string, slotId: string): string {
  const normalizedDevice = normalizeInstanceId(deviceId, 'device_id');
  const slotKey = slotIsolationKey(slotId) || '_singleton';
  return `_seq_|${safeAid(aid)}|${encodePart(normalizedDevice)}|${encodePart(slotKey)}|`;
}

export function seqTrackerStoreKey(aid: string, deviceId: string, slotId: string, namespace: string): string {
  return `${seqTrackerPrefix(aid, deviceId, slotId)}${encodePart(namespace)}`;
}

export function agentMdCachePrefix(ownerAid: string): string {
  return `${safeAid(ownerAid)}|`;
}

export function agentMdCacheStoreKey(ownerAid: string, targetAid: string): string {
  return `${agentMdCachePrefix(ownerAid)}${encodePart(targetAid)}`;
}

export function pendingIdentityPrefix(aid: string): string {
  return `${safeAid(aid)}-`;
}

export function stripStructuredFields(metadata: MetadataRecord): MetadataRecord {
  return deepClone(metadata);
}

export function defaultAgentMdCacheRecord(aid: string): AgentMdCacheRecord {
  return {
    aid,
    content: '',
    local_etag: '',
    remote_etag: '',
    last_modified: '',
    fetched_at: 0,
    observed_at: 0,
    checked_at: 0,
    remote_status: '',
    verify_status: '',
    verify_error: '',
    last_error: '',
    updated_at: 0,
  };
}

export function normalizeAgentMdCacheRecord(aid: string, value: unknown): AgentMdCacheRecord | null {
  if (!isRecord(value)) return null;
  const out = defaultAgentMdCacheRecord(aid);
  for (const key of ['content', 'local_etag', 'remote_etag', 'last_modified', 'remote_status', 'verify_status', 'verify_error', 'last_error'] as const) {
    out[key] = String(value[key] ?? '');
  }
  for (const key of ['fetched_at', 'observed_at', 'checked_at', 'updated_at'] as const) {
    const n = Number(value[key] ?? 0);
    out[key] = Number.isFinite(n) ? Math.trunc(n) : 0;
  }
  out.aid = String(value.aid ?? aid).trim() || aid;
  return out;
}

export function mergeAgentMdCacheRecord(aid: string, current: AgentMdCacheRecord | null, fields: AgentMdCacheUpsert): AgentMdCacheRecord {
  const out = current ? { ...current } : defaultAgentMdCacheRecord(aid);
  out.aid = aid;
  for (const key of ['content', 'local_etag', 'remote_etag', 'last_modified', 'remote_status', 'verify_status', 'verify_error', 'last_error'] as const) {
    if (Object.prototype.hasOwnProperty.call(fields, key) && fields[key] !== undefined && fields[key] !== null) {
      out[key] = String(fields[key] ?? '');
    }
  }
  for (const key of ['fetched_at', 'observed_at', 'checked_at'] as const) {
    if (Object.prototype.hasOwnProperty.call(fields, key) && fields[key] !== undefined && fields[key] !== null) {
      const n = Number(fields[key] ?? 0);
      out[key] = Number.isFinite(n) ? Math.trunc(n) : 0;
    }
  }
  out.updated_at = Date.now();
  return out;
}

// ── 私钥字段级加密 (AES-256-GCM + PBKDF2) ──────────────────────
const _ENC_ALGO = 'AES-GCM';
const _PBKDF2_ITERATIONS = 100_000;

export interface EncryptedEnvelope {
  ct: string;
  iv: string;
  salt: string;
}

function _uint8ToBase64(bytes: Uint8Array): string {
  let b = '';
  for (let i = 0; i < bytes.length; i++) b += String.fromCharCode(bytes[i]);
  return btoa(b);
}

function _base64ToUint8(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function _deriveEncKey(seed: string, salt: Uint8Array): Promise<CryptoKey> {
  const raw = new TextEncoder().encode(seed);
  const base = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: _PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base, { name: _ENC_ALGO, length: 256 }, false, ['encrypt', 'decrypt'],
  );
}

export async function encryptPEM(pem: string, seed: string): Promise<EncryptedEnvelope> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await _deriveEncKey(seed, salt);
  const ct = await crypto.subtle.encrypt({ name: _ENC_ALGO, iv: iv as BufferSource }, key, new TextEncoder().encode(pem));
  return {
    ct: _uint8ToBase64(new Uint8Array(ct)),
    iv: _uint8ToBase64(iv),
    salt: _uint8ToBase64(salt),
  };
}

export async function decryptPEM(enc: EncryptedEnvelope, seed: string): Promise<string> {
  const salt = _base64ToUint8(enc.salt);
  const iv = _base64ToUint8(enc.iv);
  const ct = _base64ToUint8(enc.ct);
  const key = await _deriveEncKey(seed, salt);
  const pt = await crypto.subtle.decrypt({ name: _ENC_ALGO, iv: toBufferSource(iv) }, key, toBufferSource(ct));
  return new TextDecoder().decode(pt);
}

export function hasEncryptionSeed(seed: string | undefined): seed is string {
  return seed !== undefined;
}

// ── IndexedDB 连接管理 ────────────────────────────────────────────

let _cachedDB: IDBDatabase | null = null;
let _openDBPromise: Promise<IDBDatabase> | null = null;

export function openDB(): Promise<IDBDatabase> {
  if (_cachedDB) return Promise.resolve(_cachedDB);
  if (_openDBPromise) return _openDBPromise;
  _openDBPromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      for (const name of [
        STORE_KEY_PAIRS, STORE_CERTS, STORE_METADATA, STORE_INSTANCE_STATE,
        STORE_GROUP_STATE, STORE_AGENT_MD_CACHE, STORE_PENDING_IDENTITIES, STORE_PENDING_BINDS,
      ]) {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name);
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        _cachedDB = null;
        _openDBPromise = null;
        try { db.close(); } catch { /* ignore */ }
      };
      db.onclose = () => { _cachedDB = null; };
      _cachedDB = db;
      _openDBPromise = null;
      resolve(db);
    };
    request.onerror = () => {
      _openDBPromise = null;
      reject(new Error(
        'IndexedDB 不可用（可能处于隐私模式或 IndexedDB 被禁用）。' +
        '请使用本地 split store (Node.js) 或在浏览器中允许 IndexedDB。',
      ));
    };
    request.onblocked = () => {
      _openDBPromise = null;
      reject(new Error('IndexedDB 升级被其它 tab 阻塞，请关闭其它页面后重试'));
    };
  });
  return _openDBPromise;
}

// ── IndexedDB CRUD 工具 ───────────────────────────────────────────

export async function idbGet<T>(storeName: string, key: string): Promise<T | undefined> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(key);
    tx.oncomplete = () => { resolve(req.result ?? null); };
    tx.onerror = () => { reject(tx.error ?? new Error(`读取 ${storeName} 失败`)); };
    tx.onabort = () => { reject(tx.error ?? new Error(`读取 ${storeName} 被中止`)); };
  });
}

export async function idbGetAll<T>(storeName: string): Promise<Array<{ key: string; value: T }>> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const valuesReq = store.getAll();
    const keysReq = store.getAllKeys();
    tx.oncomplete = () => {
      const values = valuesReq.result ?? [];
      const keys = keysReq.result ?? [];
      resolve(keys.map((key, index) => ({
        key: typeof key === 'string' ? key : String(key),
        value: values[index],
      })));
    };
    tx.onerror = () => { reject(tx.error ?? new Error(`读取 ${storeName} 全量数据失败`)); };
    tx.onabort = () => { reject(tx.error ?? new Error(`读取 ${storeName} 全量数据被中止`)); };
  });
}

export async function idbGetAllByPrefix<T>(storeName: string, prefix: string): Promise<Array<{ key: string; value: T }>> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const range = IDBKeyRange.bound(prefix, `${prefix}￿`, false, false);
    const result: Array<{ key: string; value: T }> = [];
    const req = store.openCursor(range);
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor) return;
      result.push({
        key: typeof cursor.key === 'string' ? cursor.key : String(cursor.key),
        value: cursor.value,
      });
      cursor.continue();
    };
    tx.oncomplete = () => { resolve(result); };
    tx.onerror = () => { reject(tx.error ?? new Error(`按前缀读取 ${storeName} 失败`)); };
    tx.onabort = () => { reject(tx.error ?? new Error(`按前缀读取 ${storeName} 被中止`)); };
  });
}

export async function idbPut<T>(storeName: string, key: string, value: T): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(value, key);
    tx.oncomplete = () => { resolve(); };
    tx.onerror = () => { reject(tx.error ?? new Error(`写入 ${storeName} 失败`)); };
    tx.onabort = () => { reject(tx.error ?? new Error(`写入 ${storeName} 被中止`)); };
  });
}

export async function idbDelete(storeName: string, key: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => { resolve(); };
    tx.onerror = () => { reject(tx.error ?? new Error(`删除 ${storeName} 失败`)); };
    tx.onabort = () => { reject(tx.error ?? new Error(`删除 ${storeName} 被中止`)); };
  });
}

// ── SPKI 提取（证书公钥一致性校验用）────────────────────────────

export function extractSpkiB64FromCertPem(certPem: string): string {
  try {
    const der = new Uint8Array(pemToArrayBuffer(certPem));
    const tlv = (d: Uint8Array, o: number): [number, number] => {
      let lo = o + 1, len: number;
      if (d[lo] & 0x80) { const n = d[lo] & 0x7f; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | d[lo + 1 + i]; lo += 1 + n; } else { len = d[lo]; lo += 1; }
      return [lo, len];
    };
    const skip = (d: Uint8Array, o: number): number => { const [vs, vl] = tlv(d, o); return vs + vl; };
    let [vs] = tlv(der, 0);
    let pos = vs;
    const [tbsVs] = tlv(der, pos);
    pos = tbsVs;
    if (der[pos] === 0xa0) pos = skip(der, pos);
    for (let i = 0; i < 5; i++) pos = skip(der, pos);
    const spkiEnd = skip(der, pos);
    const spkiBytes = der.slice(pos, spkiEnd);
    let b = ''; for (let i = 0; i < spkiBytes.length; i++) b += String.fromCharCode(spkiBytes[i]);
    return btoa(b);
  } catch {
    return '';
  }
}

export type PendingIdentityRecord = {
  aid: string;
  key_pair?: JsonObject;
  cert?: string;
  created_at: number;
  updated_at: number;
};

// 重新导出类型，方便实现文件使用
export type {
  JsonObject,
  KeyPairRecord,
  MetadataRecord,
};
