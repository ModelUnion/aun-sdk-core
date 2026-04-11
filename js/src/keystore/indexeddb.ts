// ── IndexedDB KeyStore 实现 ──────────────────────────────

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
} from '../types.js';

/** AID 安全化（替换路径分隔符） */
function safeAid(aid: string): string {
  return aid.replace(/[/\\:]/g, '_');
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
const DB_VERSION = 2;

/** 对象仓库名称 */
const STORE_KEY_PAIRS = 'key_pairs';
const STORE_CERTS = 'certs';
const STORE_METADATA = 'metadata';
const STORE_PREKEYS = 'prekeys';
const STORE_GROUP_CURRENT = 'group_current';
const STORE_GROUP_OLD_EPOCHS = 'group_old_epochs';

const STRUCTURED_RECOVERY_RETENTION_MS = 7 * 24 * 3600 * 1000;
const CRITICAL_METADATA_KEYS = ['e2ee_sessions'] as const;

function metadataStoreKey(aid: string): string {
  return safeAid(aid);
}

function prekeyPrefix(aid: string): string {
  return `${safeAid(aid)}|`;
}

function prekeyStoreKey(aid: string, prekeyId: string): string {
  return `${safeAid(aid)}|${encodePart(prekeyId)}`;
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

function stripStructuredFields(metadata: MetadataRecord): MetadataRecord {
  const plain = deepClone(metadata);
  delete plain.e2ee_prekeys;
  delete plain.group_secrets;
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
      if (!db.objectStoreNames.contains(STORE_PREKEYS)) {
        db.createObjectStore(STORE_PREKEYS);
      }
      if (!db.objectStoreNames.contains(STORE_GROUP_CURRENT)) {
        db.createObjectStore(STORE_GROUP_CURRENT);
      }
      if (!db.objectStoreNames.contains(STORE_GROUP_OLD_EPOCHS)) {
        db.createObjectStore(STORE_GROUP_OLD_EPOCHS);
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
    IndexedDBKeyStore._aidTails.set(
      key,
      previous.catch(() => undefined).then(() => current),
    );

    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
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

  async loadCert(aid: string): Promise<string | null> {
    const data = await idbGet(STORE_CERTS, metadataStoreKey(aid));
    return typeof data === 'string' ? data : null;
  }

  async saveCert(aid: string, certPem: string): Promise<void> {
    await idbPut(STORE_CERTS, metadataStoreKey(aid), certPem);
  }

  // ── Metadata ──────────────────────────────────────

  async loadMetadata(aid: string): Promise<MetadataRecord | null> {
    return this._withAidLock(aid, async () => this._buildMergedMetadataUnlocked(aid));
  }

  async saveMetadata(aid: string, metadata: MetadataRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      const current = (await this._buildMergedMetadataUnlocked(aid)) ?? {};
      const merged = deepClone(metadata);

      for (const key of CRITICAL_METADATA_KEYS) {
        if (current[key] && !(key in merged)) {
          console.warn(`saveMetadata: 传入数据缺少 '${key}' (aid=${aid})，自动合并已有数据`);
          if (key === 'e2ee_sessions') {
            merged.e2ee_sessions = Array.isArray(current.e2ee_sessions)
              ? deepClone(current.e2ee_sessions)
              : [];
          }
        }
      }

      if ('e2ee_prekeys' in merged) {
        const prekeys = isRecord(merged.e2ee_prekeys)
          ? merged.e2ee_prekeys as PrekeyMap
          : {};
        await this._replacePrekeysUnlocked(aid, prekeys);
      }

      if ('group_secrets' in merged) {
        const groups = isRecord(merged.group_secrets)
          ? merged.group_secrets as GroupSecretMap
          : {};
        await this._replaceGroupEntriesUnlocked(aid, groups);
      }

      await this._saveMetadataOnlyUnlocked(aid, stripStructuredFields(merged));
    });
  }

  async updateMetadata(
    aid: string,
    updater: (metadata: MetadataRecord) => MetadataRecord | void,
  ): Promise<MetadataRecord> {
    return this._withAidLock(aid, async () => {
      const current = (await this._buildMergedMetadataUnlocked(aid)) ?? {};
      const working = deepClone(current);
      const updated = updater(working) ?? working;

      if ('e2ee_prekeys' in updated) {
        const prekeys = isRecord(updated.e2ee_prekeys)
          ? updated.e2ee_prekeys as PrekeyMap
          : {};
        await this._replacePrekeysUnlocked(aid, prekeys);
      }

      if ('group_secrets' in updated) {
        const groups = isRecord(updated.group_secrets)
          ? updated.group_secrets as GroupSecretMap
          : {};
        await this._replaceGroupEntriesUnlocked(aid, groups);
      }

      const plain = stripStructuredFields(updated);
      for (const key of CRITICAL_METADATA_KEYS) {
        if (current[key] && !(key in plain)) {
          if (key === 'e2ee_sessions') {
            plain.e2ee_sessions = Array.isArray(current.e2ee_sessions)
              ? deepClone(current.e2ee_sessions)
              : [];
          }
        }
      }
      await this._saveMetadataOnlyUnlocked(aid, plain);
      return deepClone(updated);
    });
  }

  // ── 身份信息（组合操作） ──────────────────────────

  async loadIdentity(aid: string): Promise<IdentityRecord | null> {
    return this._withAidLock(aid, async () => {
      const [keyPair, cert, metadata] = await Promise.all([
        this._loadKeyPairUnlocked(aid),
        this._loadCertUnlocked(aid),
        this._buildMergedMetadataUnlocked(aid),
      ]);

      if (!keyPair && !cert && !metadata) return null;

      const identity: IdentityRecord = {};
      if (metadata) Object.assign(identity, metadata);
      if (keyPair) Object.assign(identity, keyPair);
      if (cert) identity.cert = cert;
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

      const current = (await this._buildMergedMetadataUnlocked(aid)) ?? {};
      const updated = deepClone(current);
      Object.assign(updated, metadataFields);

      if ('e2ee_prekeys' in updated) {
        const prekeys = isRecord(updated.e2ee_prekeys)
          ? updated.e2ee_prekeys as PrekeyMap
          : {};
        await this._replacePrekeysUnlocked(aid, prekeys);
      }

      if ('group_secrets' in updated) {
        const groups = isRecord(updated.group_secrets)
          ? updated.group_secrets as GroupSecretMap
          : {};
        await this._replaceGroupEntriesUnlocked(aid, groups);
      }

      const plain = stripStructuredFields(updated);
      for (const key of CRITICAL_METADATA_KEYS) {
        if (current[key] && !(key in plain)) {
          if (key === 'e2ee_sessions') {
            plain.e2ee_sessions = Array.isArray(current.e2ee_sessions)
              ? deepClone(current.e2ee_sessions)
              : [];
          }
        }
      }
      await this._saveMetadataOnlyUnlocked(aid, plain);
    });
  }

  // ── 结构化 prekeys ───────────────────────────────────

  async loadE2EEPrekeys(aid: string): Promise<PrekeyMap> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._loadPrekeysUnlocked(aid);
    });
  }

  async saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void> {
    await this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const record = deepClone(prekeyData);
      record.prekey_id = prekeyId;
      await idbPut(STORE_PREKEYS, prekeyStoreKey(aid, prekeyId), record);
    });
  }

  async cleanupE2EEPrekeys(aid: string, cutoffMs: number, keepLatest = 7): Promise<string[]> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const prekeys = await this._loadPrekeysUnlocked(aid);
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
      for (const prekeyId of removed) {
        await idbDelete(STORE_PREKEYS, prekeyStoreKey(aid, prekeyId));
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

  // ── 内部辅助 ─────────────────────────────────────────

  private async _loadKeyPairUnlocked(aid: string): Promise<KeyPairRecord | null> {
    const data = await idbGet<JsonObject>(STORE_KEY_PAIRS, metadataStoreKey(aid));
    return isRecord(data) ? deepClone(data) : null;
  }

  private async _saveKeyPairUnlocked(aid: string, keyPair: KeyPairRecord): Promise<void> {
    await idbPut(STORE_KEY_PAIRS, metadataStoreKey(aid), deepClone(keyPair));
  }

  private async _loadCertUnlocked(aid: string): Promise<string | null> {
    const data = await idbGet(STORE_CERTS, metadataStoreKey(aid));
    return typeof data === 'string' ? data : null;
  }

  private async _saveCertUnlocked(aid: string, certPem: string): Promise<void> {
    await idbPut(STORE_CERTS, metadataStoreKey(aid), certPem);
  }

  private async _loadMetadataOnlyUnlocked(aid: string): Promise<MetadataRecord | null> {
    const data = await idbGet<JsonObject>(STORE_METADATA, metadataStoreKey(aid));
    return isRecord(data) ? deepClone(data) : null;
  }

  private async _saveMetadataOnlyUnlocked(aid: string, metadata: MetadataRecord): Promise<void> {
    const plain = stripStructuredFields(metadata);
    await idbPut(STORE_METADATA, metadataStoreKey(aid), plain);
  }

  private async _buildMergedMetadataUnlocked(aid: string): Promise<MetadataRecord | null> {
    const metadataOnly = await this._migrateLegacyStructuredStateUnlocked(aid);
    const merged = deepClone(metadataOnly);

    const prekeys = await this._loadPrekeysUnlocked(aid);
    if (Object.keys(prekeys).length > 0) {
      merged.e2ee_prekeys = prekeys;
    }

    const groups = await this._loadGroupEntriesUnlocked(aid);
    if (Object.keys(groups).length > 0) {
      merged.group_secrets = groups;
    }

    return Object.keys(merged).length > 0 ? merged : null;
  }

  private async _migrateLegacyStructuredStateUnlocked(aid: string): Promise<MetadataRecord> {
    const metadataOnly = (await this._loadMetadataOnlyUnlocked(aid)) ?? {};
    const hasLegacyPrekeys = isRecord(metadataOnly.e2ee_prekeys);
    const hasLegacyGroups = isRecord(metadataOnly.group_secrets);

    if (!hasLegacyPrekeys && !hasLegacyGroups) {
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

    await this._saveMetadataOnlyUnlocked(aid, cleaned);
    return cleaned;
  }

  private async _loadPrekeysUnlocked(aid: string): Promise<PrekeyMap> {
    const items = await idbGetAll<JsonObject>(STORE_PREKEYS);
    const prefix = prekeyPrefix(aid);
    const result: PrekeyMap = {};

    for (const item of items) {
      if (!item.key.startsWith(prefix) || !isRecord(item.value)) continue;
      const prekeyId = typeof item.value.prekey_id === 'string'
        ? item.value.prekey_id
        : item.key.slice(prefix.length);
      const record = deepClone(item.value);
      delete record.prekey_id;
      result[prekeyId] = record;
    }

    return result;
  }

  private async _replacePrekeysUnlocked(
    aid: string,
    prekeys: PrekeyMap,
  ): Promise<void> {
    for (const [prekeyId, prekeyData] of Object.entries(prekeys)) {
      await idbPut(STORE_PREKEYS, prekeyStoreKey(aid, prekeyId), {
        ...deepClone(prekeyData),
        prekey_id: prekeyId,
      });
    }
  }

  private async _loadGroupEntriesUnlocked(aid: string): Promise<GroupSecretMap> {
    const result: GroupSecretMap = {};

    for (const item of await idbGetAll<JsonObject>(STORE_GROUP_CURRENT)) {
      if (!item.key.startsWith(groupCurrentPrefix(aid)) || !isRecord(item.value)) continue;
      const groupId = typeof item.value.group_id === 'string'
        ? item.value.group_id
        : item.key.slice(groupCurrentPrefix(aid).length);
      const record = deepClone(item.value);
      delete record.group_id;
      result[groupId] = record;
    }

    for (const item of await idbGetAll<JsonObject>(STORE_GROUP_OLD_EPOCHS)) {
      if (!item.key.startsWith(groupOldPrefix(aid)) || !isRecord(item.value)) continue;
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
    for (const [groupId, rawEntry] of Object.entries(groups)) {
      if (!isRecord(rawEntry)) continue;
      const entry = deepClone(rawEntry);
      const oldEpochs = Array.isArray(entry.old_epochs)
        ? entry.old_epochs as GroupOldEpochRecord[]
        : [];
      delete entry.old_epochs;

      if (typeof entry.epoch === 'number') {
        await idbPut(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId), {
          ...entry,
          group_id: groupId,
        });
      }

      for (const oldEpoch of oldEpochs) {
        if (!isRecord(oldEpoch) || typeof oldEpoch.epoch !== 'number') continue;
        await idbPut(STORE_GROUP_OLD_EPOCHS, groupOldStoreKey(aid, groupId, oldEpoch.epoch), {
          ...deepClone(oldEpoch),
          group_id: groupId,
        });
      }
    }
  }

  private async _saveSingleGroupEntryUnlocked(
    aid: string,
    groupId: string,
    entry: GroupSecretRecord,
  ): Promise<void> {
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
}

