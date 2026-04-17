// ── IndexedDB KeyStore 实现 ──────────────────────────────

import { pemToArrayBuffer } from '../crypto.js';
import { normalizeInstanceId } from '../config.js';
import type { KeyStore } from './index.js';
import {
  isJsonObject,
  type GroupOldEpochRecord,
  type GroupSecretMap,
  type GroupSecretRecord,
  type IdentityRecord,
  type JsonObject,
  type KeyPairRecord,
  type MetadataRecord,
  type PrekeyMap,
  type PrekeyRecord,
  type SessionRecord,
} from '../types.js';

/** AID 安全化（替换路径分隔符） */
function safeAid(aid: string): string {
  return aid.replace(/[/\\:]/g, '_');
}

/** 从 cert PEM 中提取 SPKI 公钥的 base64（纯 ASN.1 DER 解析，浏览器兼容） */
function extractSpkiB64FromCertPem(certPem: string): string {
  try {
    const der = new Uint8Array(pemToArrayBuffer(certPem));
    // 最小 ASN.1 TLV 读取
    const tlv = (d: Uint8Array, o: number): [number, number] => {
      let lo = o + 1, len: number;
      if (d[lo] & 0x80) { const n = d[lo] & 0x7f; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | d[lo + 1 + i]; lo += 1 + n; } else { len = d[lo]; lo += 1; }
      return [lo, len]; // [valueStart, valueLen]
    };
    const skip = (d: Uint8Array, o: number): number => { const [vs, vl] = tlv(d, o); return vs + vl; };
    // Certificate → SEQUENCE
    let [vs] = tlv(der, 0);
    // TBSCertificate → SEQUENCE
    let pos = vs;
    const [tbsVs] = tlv(der, pos);
    pos = tbsVs;
    // version [0] EXPLICIT (optional)
    if (der[pos] === 0xa0) pos = skip(der, pos);
    // serialNumber, signatureAlgorithm, issuer, validity, subject — 跳过 5 个字段
    for (let i = 0; i < 5; i++) pos = skip(der, pos);
    // SubjectPublicKeyInfo — 就是当前位置
    const spkiEnd = skip(der, pos);
    const spkiBytes = der.slice(pos, spkiEnd);
    // base64 编码
    let b = ''; for (let i = 0; i < spkiBytes.length; i++) b += String.fromCharCode(spkiBytes[i]);
    return btoa(b);
  } catch {
    return '';
  }
}

function encodePart(value: string): string {
  return encodeURIComponent(value);
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function isRecord(value: JsonObject | object | null | undefined): value is JsonObject {
  return isJsonObject(value);
}

function sameJson(a: JsonObject | string | number | boolean | null | undefined, b: JsonObject | string | number | boolean | null | undefined): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

// ── IndexedDB 工具 ──────────────────────────────────────

const DB_NAME = 'aun-keystore';
const DB_VERSION = 4;

/** 对象仓库名称 */
const STORE_KEY_PAIRS = 'key_pairs';
const STORE_CERTS = 'certs';
const STORE_METADATA = 'metadata';
const STORE_INSTANCE_STATE = 'instance_state';
const STORE_PREKEYS = 'prekeys';
const STORE_GROUP_CURRENT = 'group_current';
const STORE_GROUP_OLD_EPOCHS = 'group_old_epochs';
const STORE_SESSIONS = 'e2ee_sessions';

const STRUCTURED_RECOVERY_RETENTION_MS = 7 * 24 * 3600 * 1000;
const CRITICAL_METADATA_KEYS = [] as const;

function metadataStoreKey(aid: string): string {
  return safeAid(aid);
}

function normalizeCertFingerprint(certFingerprint?: string): string {
  const normalized = String(certFingerprint ?? '').trim().toLowerCase();
  if (!normalized) return '';
  if (!normalized.startsWith('sha256:')) return '';
  const hexPart = normalized.slice(7);
  if (hexPart.length !== 64 || /[^0-9a-f]/.test(hexPart)) return '';
  return normalized;
}

async function fingerprintFromCertPem(certPem: string): Promise<string> {
  try {
    const der = pemToArrayBuffer(certPem);
    const hash = await crypto.subtle.digest('SHA-256', der);
    const hex = Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
    return `sha256:${hex}`;
  } catch {
    return '';
  }
}

function certStoreKey(aid: string, certFingerprint?: string): string {
  const normalized = normalizeCertFingerprint(certFingerprint);
  if (!normalized) return safeAid(aid);
  return `${safeAid(aid)}|${encodePart(normalized)}`;
}

function instanceStateStoreKey(aid: string, deviceId: string, slotId = ''): string {
  const normalizedDevice = normalizeInstanceId(deviceId, 'device_id');
  const normalizedSlot = normalizeInstanceId(slotId, 'slot_id', { allowEmpty: true }) || '_singleton';
  return `${safeAid(aid)}|${encodePart(normalizedDevice)}|${encodePart(normalizedSlot)}`;
}

function prekeyPrefix(aid: string): string {
  return `${safeAid(aid)}|`;
}

function prekeyStoreKey(aid: string, prekeyId: string, deviceId = ''): string {
  const normalizedDeviceId = String(deviceId ?? '').trim();
  if (!normalizedDeviceId) {
    return `${safeAid(aid)}|${encodePart(prekeyId)}`;
  }
  return `${safeAid(aid)}|${encodePart(normalizedDeviceId)}|${encodePart(prekeyId)}`;
}

function groupCurrentPrefix(aid: string): string {
  return `${safeAid(aid)}|`;
}

function groupCurrentStoreKey(aid: string, groupId: string): string {
  return `${safeAid(aid)}|${encodePart(groupId)}`;
}

function groupOldPrefix(aid: string, groupId?: string): string {
  const base = `${safeAid(aid)}|`;
  if (groupId === undefined) return base;
  return `${base}${encodePart(groupId)}|`;
}

function groupOldStoreKey(aid: string, groupId: string, epoch: number): string {
  return `${safeAid(aid)}|${encodePart(groupId)}|${epoch}`;
}

function sessionPrefix(aid: string): string {
  return `${safeAid(aid)}|`;
}

function sessionStoreKey(aid: string, sessionId: string): string {
  return `${safeAid(aid)}|${encodePart(sessionId)}`;
}

function seqTrackerPrefix(aid: string, deviceId: string, slotId: string): string {
  const normalizedDevice = normalizeInstanceId(deviceId, 'device_id');
  const normalizedSlot = normalizeInstanceId(slotId, 'slot_id', { allowEmpty: true }) || '_singleton';
  return `_seq_|${safeAid(aid)}|${encodePart(normalizedDevice)}|${encodePart(normalizedSlot)}|`;
}

function seqTrackerStoreKey(aid: string, deviceId: string, slotId: string, namespace: string): string {
  return `${seqTrackerPrefix(aid, deviceId, slotId)}${encodePart(namespace)}`;
}

function stripStructuredFields(metadata: MetadataRecord): MetadataRecord {
  const plain = deepClone(metadata);
  delete plain.e2ee_prekeys;
  delete plain.group_secrets;
  delete plain.e2ee_sessions;
  return plain;
}

/** 打开或升级数据库 */
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_KEY_PAIRS)) {
        db.createObjectStore(STORE_KEY_PAIRS);
      }
      if (!db.objectStoreNames.contains(STORE_CERTS)) {
        db.createObjectStore(STORE_CERTS);
      }
      if (!db.objectStoreNames.contains(STORE_METADATA)) {
        db.createObjectStore(STORE_METADATA);
      }
      if (!db.objectStoreNames.contains(STORE_INSTANCE_STATE)) {
        db.createObjectStore(STORE_INSTANCE_STATE);
      }
      if (!db.objectStoreNames.contains(STORE_PREKEYS)) {
        db.createObjectStore(STORE_PREKEYS);
      }
      if (!db.objectStoreNames.contains(STORE_GROUP_CURRENT)) {
        db.createObjectStore(STORE_GROUP_CURRENT);
      }
      if (!db.objectStoreNames.contains(STORE_GROUP_OLD_EPOCHS)) {
        db.createObjectStore(STORE_GROUP_OLD_EPOCHS);
      }
      if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
        db.createObjectStore(STORE_SESSIONS);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('打开 IndexedDB 失败'));
  });
}

/** 从指定仓库读取一条记录 */
async function idbGet<T>(storeName: string, key: string): Promise<T | undefined> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const req = store.get(key);

    tx.oncomplete = () => {
      db.close();
      resolve(req.result ?? null);
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error(`读取 ${storeName} 失败`));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error(`读取 ${storeName} 被中止`));
    };
  });
}

/** 读取仓库内全部记录 */
async function idbGetAll<T>(storeName: string): Promise<Array<{ key: string; value: T }>> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const valuesReq = store.getAll();
    const keysReq = store.getAllKeys();

    tx.oncomplete = () => {
      db.close();
      const values = valuesReq.result ?? [];
      const keys = keysReq.result ?? [];
      resolve(keys.map((key, index) => ({
        key: typeof key === 'string' ? key : String(key),
        value: values[index],
      })));
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error(`读取 ${storeName} 全量数据失败`));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error(`读取 ${storeName} 全量数据被中止`));
    };
  });
}

async function idbGetAllByPrefix<T>(storeName: string, prefix: string): Promise<Array<{ key: string; value: T }>> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const range = IDBKeyRange.bound(prefix, `${prefix}\uffff`, false, false);
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

    tx.oncomplete = () => {
      db.close();
      resolve(result);
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error(`按前缀读取 ${storeName} 失败`));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error(`按前缀读取 ${storeName} 被中止`));
    };
  });
}

/** 向指定仓库写入一条记录 */
async function idbPut<T>(storeName: string, key: string, value: T): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(value, key);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error(`写入 ${storeName} 失败`));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error(`写入 ${storeName} 被中止`));
    };
  });
}

/** 从指定仓库删除一条记录 */
async function idbDelete(storeName: string, key: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error(`删除 ${storeName} 失败`));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error(`删除 ${storeName} 被中止`));
    };
  });
}

// ── KeyStore 实现 ───────────────────────────────────────

/**
 * 基于 IndexedDB 的密钥存储实现。
 *
 * 设计语义：
 * - metadata 只保存普通 metadata 字段；
 * - e2ee_prekeys / group_secrets 只保存到结构化 store；
 * - loadMetadata() 返回的是运行时拼出来的 merged view；
 * - 若检测到旧版本把结构化数据写进了 metadata，会自动迁移到结构化 store。
 */
export class IndexedDBKeyStore implements KeyStore {
  private static _aidTails = new Map<string, Promise<void>>();

  private async _withAidLock<T>(aid: string, fn: () => Promise<T>): Promise<T> {
    const key = safeAid(aid);
    const previous = IndexedDBKeyStore._aidTails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.catch(() => undefined).then(() => current);
    IndexedDBKeyStore._aidTails.set(
      key,
      tail,
    );

    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
      if (IndexedDBKeyStore._aidTails.get(key) === tail) {
        IndexedDBKeyStore._aidTails.delete(key);
      }
    }
  }

  // ── 密钥对 ──────────────────────────────────────────

  async loadKeyPair(aid: string): Promise<KeyPairRecord | null> {
    const data = await idbGet<JsonObject>(STORE_KEY_PAIRS, metadataStoreKey(aid));
    return isRecord(data) ? deepClone(data) : null;
  }

  async saveKeyPair(aid: string, keyPair: KeyPairRecord): Promise<void> {
    await idbPut(STORE_KEY_PAIRS, metadataStoreKey(aid), deepClone(keyPair));
  }

  // ── 证书 ──────────────────────────────────────────

  async loadCert(aid: string, certFingerprint?: string): Promise<string | null> {
    const normalized = normalizeCertFingerprint(certFingerprint);
    if (normalized) {
      const versioned = await idbGet(STORE_CERTS, certStoreKey(aid, normalized));
      if (typeof versioned === 'string') return versioned;
      const active = await idbGet(STORE_CERTS, certStoreKey(aid));
      if (typeof active === 'string' && await fingerprintFromCertPem(active) === normalized) {
        return active;
      }
      return null;
    }
    const data = await idbGet(STORE_CERTS, certStoreKey(aid));
    return typeof data === 'string' ? data : null;
  }

  async saveCert(
    aid: string,
    certPem: string,
    certFingerprint?: string,
    opts?: { makeActive?: boolean },
  ): Promise<void> {
    const normalized = normalizeCertFingerprint(certFingerprint);
    if (normalized) {
      await idbPut(STORE_CERTS, certStoreKey(aid, normalized), certPem);
      if (opts?.makeActive) {
        await idbPut(STORE_CERTS, certStoreKey(aid), certPem);
      }
      return;
    }
    await idbPut(STORE_CERTS, certStoreKey(aid), certPem);
  }

  // ── 实例态 ──────────────────────────────────────────

  async loadInstanceState(aid: string, deviceId: string, slotId = ''): Promise<MetadataRecord | null> {
    return this._withAidLock(aid, async () => {
      const data = await idbGet<JsonObject>(STORE_INSTANCE_STATE, instanceStateStoreKey(aid, deviceId, slotId));
      return isRecord(data) ? deepClone(data) : null;
    });
  }

  async saveInstanceState(aid: string, deviceId: string, slotId: string, state: MetadataRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      await idbPut(STORE_INSTANCE_STATE, instanceStateStoreKey(aid, deviceId, slotId), deepClone(state));
    });
  }

  async updateInstanceState(
    aid: string,
    deviceId: string,
    slotId: string,
    updater: (state: MetadataRecord) => MetadataRecord | void,
  ): Promise<MetadataRecord> {
    return this._withAidLock(aid, async () => {
      const currentRaw = await idbGet<JsonObject>(STORE_INSTANCE_STATE, instanceStateStoreKey(aid, deviceId, slotId));
      const current = isRecord(currentRaw) ? deepClone(currentRaw) : {};
      const working = deepClone(current);
      const updated = updater(working) ?? working;
      await idbPut(STORE_INSTANCE_STATE, instanceStateStoreKey(aid, deviceId, slotId), deepClone(updated));
      return deepClone(updated);
    });
  }

  // ── 身份信息（组合操作） ──────────────────────────

  async loadIdentity(aid: string): Promise<IdentityRecord | null> {
    return this._withAidLock(aid, async () => {
      const [keyPair, cert] = await Promise.all([
        this._loadKeyPairUnlocked(aid),
        this._loadCertUnlocked(aid),
      ]);
      // 直接读取 metadata KV（含旧数据迁移）
      const metadataOnly = await this._migrateLegacyStructuredStateUnlocked(aid);
      const hasMeta = Object.keys(metadataOnly).length > 0;

      if (!keyPair && !cert && !hasMeta) return null;

      const identity: IdentityRecord = {};
      if (hasMeta) Object.assign(identity, metadataOnly);
      if (keyPair) Object.assign(identity, keyPair);
      if (cert) {
        // key/cert 公钥一致性校验：防止 cert 被意外覆盖
        const localPubB64 = keyPair?.public_key_der_b64;
        if (typeof localPubB64 === 'string' && localPubB64) {
          const certSpkiB64 = extractSpkiB64FromCertPem(cert);
          if (certSpkiB64 && certSpkiB64 !== localPubB64) {
            console.error(`[keystore] 身份 ${aid} 的 key 公钥与 cert 公钥不匹配，丢弃 cert`);
          } else {
            identity.cert = cert;
          }
        } else {
          identity.cert = cert;
        }
      }
      return identity;
    });
  }

  async saveIdentity(aid: string, identity: IdentityRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      const keyPairFields: KeyPairRecord = {};
      for (const key of ['private_key_pem', 'public_key_der_b64', 'curve']) {
        if (key in identity) keyPairFields[key] = identity[key];
      }
      if (Object.keys(keyPairFields).length > 0) {
        await this._saveKeyPairUnlocked(aid, keyPairFields);
      }

      const cert = identity.cert;
      if (typeof cert === 'string' && cert) {
        await this._saveCertUnlocked(aid, cert);
      }

      const metadataFields: MetadataRecord = {};
      for (const [key, value] of Object.entries(identity)) {
        if (!['private_key_pem', 'public_key_der_b64', 'curve', 'cert'].includes(key)) {
          metadataFields[key] = value;
        }
      }

      // 增量保存 metadata 字段
      if (Object.keys(metadataFields).length > 0) {
        await this._replaceStructuredStateUnlocked(aid, metadataFields);
        const plain = stripStructuredFields(metadataFields);
        if (Object.keys(plain).length > 0) {
          const current = await this._migrateLegacyStructuredStateUnlocked(aid);
          Object.assign(current, plain);
          await this._saveMetadataOnlyUnlocked(aid, current);
        }
      }
    });
  }

  // ── 结构化 prekeys ───────────────────────────────────

  async loadE2EEPrekeys(aid: string): Promise<PrekeyMap> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._loadPrekeysUnlocked(aid, '');
    });
  }

  async loadE2EEPrekeysForDevice(aid: string, deviceId: string): Promise<PrekeyMap> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._loadPrekeysUnlocked(aid, String(deviceId ?? '').trim());
    });
  }

  async saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const record = deepClone(prekeyData);
      record.prekey_id = prekeyId;
      await idbPut(STORE_PREKEYS, prekeyStoreKey(aid, prekeyId, ''), record);
    });
  }

  async saveE2EEPrekeyForDevice(aid: string, deviceId: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const record = deepClone(prekeyData);
      record.prekey_id = prekeyId;
      const normalizedDeviceId = String(deviceId ?? '').trim();
      if (normalizedDeviceId) {
        record.device_id = normalizedDeviceId;
      } else {
        delete record.device_id;
      }
      const targetKey = prekeyStoreKey(aid, prekeyId, normalizedDeviceId);
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_PREKEYS, prekeyPrefix(aid))) {
        if (!isRecord(item.value)) continue;
        const existingPrekeyId = typeof item.value.prekey_id === 'string'
          ? item.value.prekey_id
          : '';
        const existingDeviceId = String(item.value.device_id ?? '').trim();
        if (existingPrekeyId === prekeyId && existingDeviceId === normalizedDeviceId && item.key !== targetKey) {
          await idbDelete(STORE_PREKEYS, item.key);
        }
      }
      await idbPut(STORE_PREKEYS, targetKey, record);
    });
  }

  async cleanupE2EEPrekeys(aid: string, cutoffMs: number, keepLatest = 7): Promise<string[]> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const prekeys = await this._loadPrekeysUnlocked(aid, '');
      const retainedIds = new Set(
        Object.entries(prekeys)
          .sort((left, right) => {
            const leftMarker = Number(left[1].created_at ?? left[1].updated_at ?? left[1].expires_at ?? 0);
            const rightMarker = Number(right[1].created_at ?? right[1].updated_at ?? right[1].expires_at ?? 0);
            if (rightMarker !== leftMarker) return rightMarker - leftMarker;
            return right[0].localeCompare(left[0]);
          })
          .slice(0, keepLatest)
          .map(([prekeyId]) => prekeyId),
      );
      const removed = Object.entries(prekeys)
        .filter(
          ([prekeyId, data]) =>
            Number(data.created_at ?? data.updated_at ?? data.expires_at ?? 0) < cutoffMs
            && !retainedIds.has(prekeyId),
        )
        .map(([prekeyId]) => prekeyId);
      const removedIds = new Set(removed);
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_PREKEYS, prekeyPrefix(aid))) {
        if (!isRecord(item.value)) continue;
        const recordDeviceId = String(item.value.device_id ?? '').trim();
        if (recordDeviceId !== '') continue;
        const prekeyId = typeof item.value.prekey_id === 'string' ? item.value.prekey_id : '';
        if (removedIds.has(prekeyId)) await idbDelete(STORE_PREKEYS, item.key);
      }
      return removed;
    });
  }

  async cleanupE2EEPrekeysForDevice(aid: string, deviceId: string, cutoffMs: number, keepLatest = 7): Promise<string[]> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const normalizedDeviceId = String(deviceId ?? '').trim();
      const prekeys = await this._loadPrekeysUnlocked(aid, normalizedDeviceId);
      const retainedIds = new Set(
        Object.entries(prekeys)
          .sort((left, right) => {
            const leftMarker = Number(left[1].created_at ?? left[1].updated_at ?? left[1].expires_at ?? 0);
            const rightMarker = Number(right[1].created_at ?? right[1].updated_at ?? right[1].expires_at ?? 0);
            if (rightMarker !== leftMarker) return rightMarker - leftMarker;
            return right[0].localeCompare(left[0]);
          })
          .slice(0, keepLatest)
          .map(([prekeyId]) => prekeyId),
      );
      const removed = Object.entries(prekeys)
        .filter(
          ([prekeyId, data]) =>
            Number(data.created_at ?? data.updated_at ?? data.expires_at ?? 0) < cutoffMs
            && !retainedIds.has(prekeyId),
        )
        .map(([prekeyId]) => prekeyId);
      const removedIds = new Set(removed);
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_PREKEYS, prekeyPrefix(aid))) {
        if (!isRecord(item.value)) continue;
        const recordDeviceId = String(item.value.device_id ?? '').trim();
        if (recordDeviceId !== normalizedDeviceId) continue;
        const prekeyId = typeof item.value.prekey_id === 'string' ? item.value.prekey_id : '';
        if (removedIds.has(prekeyId)) await idbDelete(STORE_PREKEYS, item.key);
      }
      return removed;
    });
  }

  // ── 结构化群组密钥 ─────────────────────────────────

  async loadGroupSecretState(aid: string, groupId: string): Promise<GroupSecretRecord | null> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const groups = await this._loadGroupEntriesUnlocked(aid);
      return deepClone(groups[groupId] ?? null);
    });
  }

  async loadAllGroupSecretStates(aid: string): Promise<GroupSecretMap> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._loadGroupEntriesUnlocked(aid);
    });
  }

  async saveGroupSecretState(aid: string, groupId: string, entry: GroupSecretRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      await this._saveSingleGroupEntryUnlocked(aid, groupId, entry);
    });
  }

  async cleanupGroupOldEpochsState(aid: string, groupId: string, cutoffMs: number): Promise<number> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const groups = await this._loadGroupEntriesUnlocked(aid);
      const entry = groups[groupId];
      if (!entry) return 0;

      const oldEpochs = Array.isArray(entry.old_epochs)
        ? entry.old_epochs as GroupOldEpochRecord[]
        : [];
      const remaining = oldEpochs.filter((old) => Number(old.updated_at ?? old.expires_at ?? 0) >= cutoffMs);
      const removed = oldEpochs.length - remaining.length;

      if (removed > 0) {
        entry.old_epochs = remaining;
        await this._saveSingleGroupEntryUnlocked(aid, groupId, entry);
      }
      return removed;
    });
  }

  // ── E2EE Sessions ─────────────────────────────────────

  async loadE2EESessions(aid: string): Promise<SessionRecord[]> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacySessionsUnlocked(aid);
      return this._loadSessionsUnlocked(aid);
    });
  }

  async saveE2EESession(aid: string, sessionId: string, data: SessionRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      await this._migrateLegacySessionsUnlocked(aid);
      const record = deepClone(data);
      record.session_id = sessionId;
      await idbPut(STORE_SESSIONS, sessionStoreKey(aid, sessionId), record);
    });
  }

  // ── 内部辅助 ─────────────────────────────────────────

  private async _loadKeyPairUnlocked(aid: string): Promise<KeyPairRecord | null> {
    const data = await idbGet<JsonObject>(STORE_KEY_PAIRS, metadataStoreKey(aid));
    return isRecord(data) ? deepClone(data) : null;
  }

  private async _saveKeyPairUnlocked(aid: string, keyPair: KeyPairRecord): Promise<void> {
    await idbPut(STORE_KEY_PAIRS, metadataStoreKey(aid), deepClone(keyPair));
  }

  private async _loadCertUnlocked(aid: string): Promise<string | null> {
    const data = await idbGet(STORE_CERTS, certStoreKey(aid));
    return typeof data === 'string' ? data : null;
  }

  private async _saveCertUnlocked(aid: string, certPem: string): Promise<void> {
    await idbPut(STORE_CERTS, certStoreKey(aid), certPem);
  }

  private async _loadMetadataOnlyUnlocked(aid: string): Promise<MetadataRecord | null> {
    const data = await idbGet<JsonObject>(STORE_METADATA, metadataStoreKey(aid));
    return isRecord(data) ? deepClone(data) : null;
  }

  private async _replaceStructuredStateUnlocked(aid: string, metadata: MetadataRecord): Promise<void> {
    // 增量保存：只处理传入的字段，不删除未传入的
    if ('e2ee_prekeys' in metadata && isRecord(metadata.e2ee_prekeys)) {
      await this._replacePrekeysUnlocked(aid, metadata.e2ee_prekeys as PrekeyMap, '');
    }

    if ('group_secrets' in metadata && isRecord(metadata.group_secrets)) {
      await this._replaceGroupEntriesUnlocked(aid, metadata.group_secrets as GroupSecretMap);
    }

    if ('e2ee_sessions' in metadata && Array.isArray(metadata.e2ee_sessions)) {
      await this._replaceSessionsUnlocked(aid, metadata.e2ee_sessions as SessionRecord[]);
    }
  }

  private async _saveMetadataOnlyUnlocked(aid: string, metadata: MetadataRecord): Promise<void> {
    const plain = stripStructuredFields(metadata);
    await idbPut(STORE_METADATA, metadataStoreKey(aid), plain);
  }

  private async _migrateLegacyStructuredStateUnlocked(aid: string): Promise<MetadataRecord> {
    const metadataOnly = (await this._loadMetadataOnlyUnlocked(aid)) ?? {};
    const hasLegacyPrekeys = isRecord(metadataOnly.e2ee_prekeys);
    const hasLegacyGroups = isRecord(metadataOnly.group_secrets);
    const hasLegacySessions = Array.isArray(metadataOnly.e2ee_sessions) && metadataOnly.e2ee_sessions.length > 0;

    if (!hasLegacyPrekeys && !hasLegacyGroups && !hasLegacySessions) {
      return metadataOnly;
    }

    const cleaned = deepClone(metadataOnly);

    if (hasLegacyPrekeys) {
      const legacyPrekeys = metadataOnly.e2ee_prekeys;
      const structuredPrekeys = await this._loadPrekeysUnlocked(aid);
      let changed = false;
      if (isRecord(legacyPrekeys)) {
        for (const [prekeyId, rawData] of Object.entries(legacyPrekeys)) {
          if (!isRecord(rawData) || structuredPrekeys[prekeyId]) continue;
          if (!this._isPrekeyRecoverable(rawData)) continue;
          structuredPrekeys[prekeyId] = deepClone(rawData);
          changed = true;
        }
      }
      if (changed) {
        await this._replacePrekeysUnlocked(aid, structuredPrekeys);
      }
      delete cleaned.e2ee_prekeys;
    }

    if (hasLegacyGroups) {
      const legacyGroups = metadataOnly.group_secrets;
      const structuredGroups = await this._loadGroupEntriesUnlocked(aid);
      let changed = false;
      if (isRecord(legacyGroups)) {
        for (const [groupId, rawEntry] of Object.entries(legacyGroups)) {
          if (!isRecord(rawEntry)) continue;
          const merged = this._mergeGroupEntryFromLegacy(structuredGroups[groupId], rawEntry);
          if (!sameJson(structuredGroups[groupId] ?? null, merged)) {
            if (Object.keys(merged).length > 0) {
              structuredGroups[groupId] = merged;
              changed = true;
            }
          }
        }
      }
      if (changed) {
        await this._replaceGroupEntriesUnlocked(aid, structuredGroups);
      }
      delete cleaned.group_secrets;
    }

    if (hasLegacySessions) {
      const legacySessions = metadataOnly.e2ee_sessions as SessionRecord[];
      for (const session of legacySessions) {
        const sid = typeof session.session_id === 'string' ? session.session_id : '';
        if (!sid) continue;
        const record = deepClone(session);
        record.session_id = sid;
        await idbPut(STORE_SESSIONS, sessionStoreKey(aid, sid), record);
      }
      delete cleaned.e2ee_sessions;
    }

    await this._saveMetadataOnlyUnlocked(aid, cleaned);
    return cleaned;
  }

  private async _loadPrekeysUnlocked(aid: string, deviceId = ''): Promise<PrekeyMap> {
    const items = await idbGetAllByPrefix<JsonObject>(STORE_PREKEYS, prekeyPrefix(aid));
    const prefix = prekeyPrefix(aid);
    const result: PrekeyMap = {};
    const normalizedDeviceId = String(deviceId ?? '').trim();

    for (const item of items) {
      if (!item.key.startsWith(prefix) || !isRecord(item.value)) continue;
      const recordDeviceId = String(item.value.device_id ?? '').trim();
      if (recordDeviceId !== normalizedDeviceId) continue;
      const prekeyId = typeof item.value.prekey_id === 'string'
        ? item.value.prekey_id
        : item.key.slice(prefix.length);
      const record = deepClone(item.value);
      delete record.prekey_id;
      delete record.device_id;
      const canonicalKey = prekeyStoreKey(aid, prekeyId, normalizedDeviceId);
      if (!(prekeyId in result) || item.key === canonicalKey) {
        result[prekeyId] = record;
      }
    }

    return result;
  }

  private async _replacePrekeysUnlocked(
    aid: string,
    prekeys: PrekeyMap,
    deviceId = '',
  ): Promise<void> {
    const desired = new Set(Object.keys(prekeys));
    const normalizedDeviceId = String(deviceId ?? '').trim();
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_PREKEYS, prekeyPrefix(aid))) {
      if (!isRecord(item.value)) continue;
      const recordDeviceId = String(item.value.device_id ?? '').trim();
      if (recordDeviceId !== normalizedDeviceId) continue;
      const prekeyId = typeof item.value.prekey_id === 'string'
        ? item.value.prekey_id
        : '';
      const canonicalKey = prekeyStoreKey(aid, prekeyId, normalizedDeviceId);
      if (!desired.has(prekeyId) || item.key !== canonicalKey) {
        await idbDelete(STORE_PREKEYS, item.key);
      }
    }
    for (const [prekeyId, prekeyData] of Object.entries(prekeys)) {
      const record = deepClone(prekeyData);
      if (normalizedDeviceId) {
        record.device_id = normalizedDeviceId;
      } else {
        delete record.device_id;
      }
      await idbPut(STORE_PREKEYS, prekeyStoreKey(aid, prekeyId, normalizedDeviceId), {
        ...record,
        prekey_id: prekeyId,
      });
    }
  }

  private async _loadGroupEntriesUnlocked(aid: string): Promise<GroupSecretMap> {
    const result: GroupSecretMap = {};

    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_CURRENT, groupCurrentPrefix(aid))) {
      if (!isRecord(item.value)) continue;
      const groupId = typeof item.value.group_id === 'string'
        ? item.value.group_id
        : item.key.slice(groupCurrentPrefix(aid).length);
      const record = deepClone(item.value);
      delete record.group_id;
      result[groupId] = record;
    }

    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid))) {
      if (!isRecord(item.value)) continue;
      const groupId = typeof item.value.group_id === 'string'
        ? item.value.group_id
        : '';
      if (!groupId) continue;
      const record = deepClone(item.value);
      delete record.group_id;
      const entry = result[groupId] ?? {};
      const oldEpochs = Array.isArray(entry.old_epochs)
        ? entry.old_epochs as GroupOldEpochRecord[]
        : [];
      oldEpochs.push(record);
      oldEpochs.sort((a, b) => Number(a.epoch ?? 0) - Number(b.epoch ?? 0));
      entry.old_epochs = oldEpochs;
      result[groupId] = entry;
    }

    return result;
  }

  private async _replaceGroupEntriesUnlocked(
    aid: string,
    groups: GroupSecretMap,
  ): Promise<void> {
    const desiredGroups = new Set(Object.keys(groups));
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_CURRENT, groupCurrentPrefix(aid))) {
      const groupId = isRecord(item.value) && typeof item.value.group_id === 'string'
        ? item.value.group_id
        : item.key.slice(groupCurrentPrefix(aid).length);
      if (!desiredGroups.has(groupId)) {
        await idbDelete(STORE_GROUP_CURRENT, item.key);
      }
    }
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid))) {
      if (!isRecord(item.value)) continue;
      const groupId = typeof item.value.group_id === 'string' ? item.value.group_id : '';
      if (!groupId || desiredGroups.has(groupId)) continue;
      await idbDelete(STORE_GROUP_OLD_EPOCHS, item.key);
    }
    for (const [groupId, rawEntry] of Object.entries(groups)) {
      if (!isRecord(rawEntry)) continue;
      await this._saveSingleGroupEntryUnlocked(aid, groupId, rawEntry);
    }
  }

  private async _saveSingleGroupEntryUnlocked(
    aid: string,
    groupId: string,
    entry: GroupSecretRecord,
  ): Promise<void> {
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid, groupId))) {
      if (!isRecord(item.value)) continue;
      const existingGroupId = typeof item.value.group_id === 'string' ? item.value.group_id : '';
      if (existingGroupId === groupId) {
        await idbDelete(STORE_GROUP_OLD_EPOCHS, item.key);
      }
    }

    const current = deepClone(entry);
    const oldEpochs = Array.isArray(current.old_epochs)
      ? current.old_epochs as GroupOldEpochRecord[]
      : [];
    delete current.old_epochs;

    if (typeof current.epoch === 'number') {
      await idbPut(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId), {
        ...current,
        group_id: groupId,
      });
    } else {
      await idbDelete(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId));
    }

    for (const oldEpoch of oldEpochs) {
      if (!isRecord(oldEpoch) || typeof oldEpoch.epoch !== 'number') continue;
      await idbPut(STORE_GROUP_OLD_EPOCHS, groupOldStoreKey(aid, groupId, oldEpoch.epoch), {
        ...deepClone(oldEpoch),
        group_id: groupId,
      });
    }
  }

  private _mergeGroupEntryFromLegacy(
    existing: GroupSecretRecord | undefined,
    incoming: GroupSecretRecord,
  ): GroupSecretRecord {
    const oldByEpoch = new Map<number, GroupOldEpochRecord>();
    let current = existing && typeof existing.epoch === 'number'
      ? deepClone(Object.fromEntries(
        Object.entries(existing).filter(([key]) => key !== 'old_epochs'),
      ))
      : null;

    if (existing && Array.isArray(existing.old_epochs)) {
      for (const rawOld of existing.old_epochs as GroupOldEpochRecord[]) {
        if (typeof rawOld.epoch !== 'number') continue;
        oldByEpoch.set(rawOld.epoch, deepClone(rawOld));
      }
    }

    if (typeof incoming.epoch === 'number' && this._isGroupEpochRecoverable(incoming)) {
      const incomingCurrent = deepClone(Object.fromEntries(
        Object.entries(incoming).filter(([key]) => key !== 'old_epochs'),
      ));
      if (!current) {
        current = incomingCurrent;
      } else if ((incomingCurrent.epoch as number) > (current.epoch as number)) {
        oldByEpoch.set(
          current.epoch as number,
          this._preferNewerGroupEpochRecord(
            oldByEpoch.get(current.epoch as number),
            current,
          ),
        );
        current = incomingCurrent;
      } else if ((incomingCurrent.epoch as number) === (current.epoch as number)) {
        current = this._preferNewerGroupEpochRecord(current, incomingCurrent);
      } else {
        oldByEpoch.set(
          incomingCurrent.epoch as number,
          this._preferNewerGroupEpochRecord(
            oldByEpoch.get(incomingCurrent.epoch as number),
            incomingCurrent,
          ),
        );
      }
    }

    const incomingOldEpochs = Array.isArray(incoming.old_epochs)
      ? incoming.old_epochs as GroupOldEpochRecord[]
      : [];
    for (const rawOld of incomingOldEpochs) {
      if (typeof rawOld.epoch !== 'number' || !this._isGroupEpochRecoverable(rawOld)) continue;
      oldByEpoch.set(
        rawOld.epoch,
        this._preferNewerGroupEpochRecord(oldByEpoch.get(rawOld.epoch), rawOld),
      );
    }

    const merged: GroupSecretRecord = current ? deepClone(current) : {};
    if (current && typeof current.epoch === 'number') {
      oldByEpoch.delete(current.epoch);
    }
    if (oldByEpoch.size > 0) {
      merged.old_epochs = [...oldByEpoch.entries()]
        .sort(([a], [b]) => a - b)
        .map(([, value]) => deepClone(value));
    }
    return merged;
  }

  private _preferNewerGroupEpochRecord(
    existing: GroupOldEpochRecord | undefined | null,
    incoming: GroupOldEpochRecord,
  ): GroupOldEpochRecord {
    if (!existing) return deepClone(incoming);
    return Number(incoming.updated_at ?? 0) > Number(existing.updated_at ?? 0)
      ? deepClone(incoming)
      : deepClone(existing);
  }

  private _isUnexpiredRecord(record: JsonObject, fallbackKey: string): boolean {
    const expiresAt = typeof record.expires_at === 'number' ? record.expires_at : null;
    if (expiresAt !== null) return expiresAt >= Date.now();
    const marker = typeof record[fallbackKey] === 'number' ? record[fallbackKey] as number : null;
    return marker !== null && marker + STRUCTURED_RECOVERY_RETENTION_MS >= Date.now();
  }

  private _isPrekeyRecoverable(record: PrekeyRecord): boolean {
    return this._isUnexpiredRecord(record, 'created_at');
  }

  private _isGroupEpochRecoverable(record: GroupOldEpochRecord | GroupSecretRecord): boolean {
    return this._isUnexpiredRecord(record, 'updated_at');
  }

  // ── Sessions 内部辅助 ─────────────────────────────────

  private async _loadSessionsUnlocked(aid: string): Promise<SessionRecord[]> {
    const items = await idbGetAllByPrefix<JsonObject>(STORE_SESSIONS, sessionPrefix(aid));
    const result: SessionRecord[] = [];
    for (const item of items) {
      if (!isRecord(item.value)) continue;
      result.push(deepClone(item.value) as SessionRecord);
    }
    return result;
  }

  private async _replaceSessionsUnlocked(aid: string, sessions: SessionRecord[]): Promise<void> {
    const desired = new Set<string>();
    for (const session of sessions) {
      const sid = typeof session.session_id === 'string' ? session.session_id : '';
      if (!sid) continue;
      desired.add(sid);
      const record = deepClone(session);
      record.session_id = sid;
      await idbPut(STORE_SESSIONS, sessionStoreKey(aid, sid), record);
    }
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_SESSIONS, sessionPrefix(aid))) {
      if (!isRecord(item.value)) continue;
      const sid = typeof item.value.session_id === 'string'
        ? item.value.session_id
        : item.key.slice(sessionPrefix(aid).length);
      if (!desired.has(sid)) {
        await idbDelete(STORE_SESSIONS, item.key);
      }
    }
  }

  private async _migrateLegacySessionsUnlocked(aid: string): Promise<void> {
    const metadataOnly = (await this._loadMetadataOnlyUnlocked(aid)) ?? {};
    if (!Array.isArray(metadataOnly.e2ee_sessions) || metadataOnly.e2ee_sessions.length === 0) {
      return;
    }
    for (const session of metadataOnly.e2ee_sessions as SessionRecord[]) {
      const sid = typeof session.session_id === 'string' ? session.session_id : '';
      if (!sid) continue;
      const record = deepClone(session);
      record.session_id = sid;
      await idbPut(STORE_SESSIONS, sessionStoreKey(aid, sid), record);
    }
    const cleaned = deepClone(metadataOnly);
    delete cleaned.e2ee_sessions;
    await this._saveMetadataOnlyUnlocked(aid, cleaned);
  }

  // ── Seq Tracker ─────────────────────────────────────────

  async saveSeq(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): Promise<void> {
    const key = seqTrackerStoreKey(aid, deviceId, slotId, namespace);
    await idbPut(STORE_INSTANCE_STATE, key, { contiguous_seq: contiguousSeq, updated_at: Date.now() });
  }

  async loadSeq(aid: string, deviceId: string, slotId: string, namespace: string): Promise<number> {
    const key = seqTrackerStoreKey(aid, deviceId, slotId, namespace);
    const data = await idbGet<{ contiguous_seq: number }>(STORE_INSTANCE_STATE, key);
    return data?.contiguous_seq ?? 0;
  }

  async loadAllSeqs(aid: string, deviceId: string, slotId: string): Promise<Record<string, number>> {
    const prefix = seqTrackerPrefix(aid, deviceId, slotId);
    const items = await idbGetAllByPrefix<{ contiguous_seq: number }>(STORE_INSTANCE_STATE, prefix);
    const result: Record<string, number> = {};
    for (const item of items) {
      if (!item.key.startsWith(prefix)) continue;
      const ns = decodeURIComponent(item.key.slice(prefix.length));
      if (ns && typeof item.value?.contiguous_seq === 'number') {
        result[ns] = item.value.contiguous_seq;
      }
    }
    return result;
  }
}

