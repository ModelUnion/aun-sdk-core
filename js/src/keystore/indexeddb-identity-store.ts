// ── IndexedDBIdentityStore — 含私钥操作的 KeyStore 实现 ──────────
//
// 持有方：AIDStore / RegisterFlow。
// 负责：密钥对、完整身份、pending 注册、证书、metadata KV、信任根。
//
// 不含 prekeys/群组密钥/sessions/seq/agent.md 缓存等会话侧操作。

import type { ModuleLogger } from '../logger.js';
import type { KeyStore } from './index.js';
import {
  _noopLog,
  STORE_KEY_PAIRS,
  STORE_CERTS,
  STORE_METADATA,
  STORE_PENDING_IDENTITIES,
  safeAid,
  deepClone,
  isRecord,
  metadataStoreKey,
  normalizeCertFingerprint,
  fingerprintFromCertPem,
  certStoreKey,
  stripStructuredFields,
  pendingIdentityPrefix,
  randomHex,
  extractSpkiB64FromCertPem,
  encryptPEM,
  decryptPEM,
  hasEncryptionSeed,
  idbGet,
  idbGetAll,
  idbGetAllByPrefix,
  idbPut,
  idbDelete,
  type EncryptedEnvelope,
  type JsonObject,
  type KeyPairRecord,
  type MetadataRecord,
  type PendingIdentityRecord,
} from './indexeddb-shared.js';
import type { IdentityRecord } from '../types.js';

export class SeedMigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SeedMigrationError';
  }
}

export interface SeedChangeResult {
  migrated: number;
  skipped: number;
  errors: number;
  privateKeysVerified: number;
  privateKeysMigrated: number;
}

/**
 * 基于 IndexedDB 的身份存储实现（含私钥）。
 * AIDStore / RegisterFlow 持有此类型。
 */
export class IndexedDBIdentityStore implements KeyStore {
  private _log: ModuleLogger = _noopLog;
  setLogger(log: ModuleLogger): void { this._log = log; }

  private static _aidTails = new Map<string, Promise<void>>();

  /** 私钥加密种子；空字符串也是有效 seed，默认不再写入明文私钥。 */
  private _encryptionSeed: string | undefined;

  constructor(opts?: { encryptionSeed?: string }) {
    this._encryptionSeed = opts?.encryptionSeed ?? '';
  }

  static async changeSeed(oldSeed: string, newSeed: string): Promise<SeedChangeResult> {
    if (oldSeed === '.seed') {
      throw new SeedMigrationError('JS IndexedDB keystore does not support file .seed migration');
    }
    const rows = await idbGetAll<JsonObject>(STORE_KEY_PAIRS);
    const migrations: Array<{ key: string; value: JsonObject; privateKeyPem: string }> = [];
    for (const row of rows) {
      if (!isRecord(row.value)) continue;
      const envelope = row.value._encrypted_pk;
      if (!isRecord(envelope)) {
        const plain = row.value.private_key_pem;
        if (typeof plain === 'string' && plain) {
          migrations.push({ key: row.key, value: deepClone(row.value), privateKeyPem: plain });
        }
        continue;
      }
      try {
        const privateKeyPem = await decryptPEM(envelope as unknown as EncryptedEnvelope, oldSeed);
        migrations.push({ key: row.key, value: deepClone(row.value), privateKeyPem });
      } catch {
        throw new SeedMigrationError(`seed migration refused: private key is not encrypted by old seed: aid=${row.key}`);
      }
    }
    if (migrations.length === 0) {
      throw new SeedMigrationError('seed migration refused: no encrypted private key verified with old seed');
    }

    const result: SeedChangeResult = {
      migrated: 0,
      skipped: 0,
      errors: 0,
      privateKeysVerified: migrations.length,
      privateKeysMigrated: 0,
    };
    for (const item of migrations) {
      const next = deepClone(item.value);
      next._encrypted_pk = await encryptPEM(item.privateKeyPem, newSeed) as unknown as JsonObject;
      const verified = await decryptPEM(next._encrypted_pk as unknown as EncryptedEnvelope, newSeed);
      if (verified !== item.privateKeyPem) {
        throw new SeedMigrationError(`new seed verification failed for private key: aid=${item.key}`);
      }
      delete next.private_key_pem;
      await idbPut(STORE_KEY_PAIRS, item.key, next);
      result.migrated += 1;
      result.privateKeysMigrated += 1;
    }
    return result;
  }

  async changeSeed(oldSeed: string, newSeed: string): Promise<SeedChangeResult> {
    const result = await IndexedDBIdentityStore.changeSeed(oldSeed, newSeed);
    this._encryptionSeed = newSeed;
    return result;
  }

  private async _withAidLock<T>(aid: string, fn: () => Promise<T>): Promise<T> {
    const key = safeAid(aid);
    const previous = IndexedDBIdentityStore._aidTails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.catch(() => undefined).then(() => current);
    IndexedDBIdentityStore._aidTails.set(key, tail);

    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
      if (IndexedDBIdentityStore._aidTails.get(key) === tail) {
        IndexedDBIdentityStore._aidTails.delete(key);
      }
    }
  }

  async listIdentities(): Promise<string[]> {
    const tStart = Date.now();
    this._log.debug('listIdentities enter');
    try {
      const records = await idbGetAll<JsonObject | string>(STORE_METADATA);
      const aids = new Set<string>();
      for (const item of records) {
        if (item.key.startsWith('_seq_|')) continue;
        const value = item.value;
        const aid = typeof value === 'object' && value !== null && isRecord(value) && typeof value.aid === 'string' && value.aid
          ? value.aid
          : item.key;
        aids.add(String(aid));
      }
      for (const item of await idbGetAll<JsonObject>(STORE_KEY_PAIRS)) {
        if (!item.key.startsWith('_seq_|')) aids.add(item.key);
      }
      for (const item of await idbGetAll<string>(STORE_CERTS)) {
        if (item.key.startsWith('_seq_|')) continue;
        const [safe] = item.key.split('|', 1);
        if (safe) aids.add(safe);
      }
      const result = [...aids].sort();
      this._log.debug(`listIdentities exit: elapsed=${Date.now() - tStart}ms count=${result.length}`);
      return result;
    } catch (err) {
      this._log.debug(`listIdentities exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 密钥对 ──────────────────────────────────────────

  async loadKeyPair(aid: string): Promise<KeyPairRecord | null> {
    const data = await idbGet<JsonObject>(STORE_KEY_PAIRS, metadataStoreKey(aid));
    if (!isRecord(data)) return null;
    const result = deepClone(data);
    const epk = result._encrypted_pk;
    if (epk && typeof epk === 'object' && !Array.isArray(epk) && hasEncryptionSeed(this._encryptionSeed)) {
      try {
        const envelope = epk as unknown as EncryptedEnvelope;
        result.private_key_pem = await decryptPEM(envelope, this._encryptionSeed);
        delete result._encrypted_pk;
      } catch {
        this._log.error(`[keystore] decrypt ${aid} private key failed, maybe encryptionSeed mismatch`);
        throw new Error(`private key decrypt failed for aid ${aid}: seed_password mismatch or IndexedDB record corrupted`);
      }
    } else if (!epk && typeof result.private_key_pem === 'string' && hasEncryptionSeed(this._encryptionSeed)) {
      await this.saveKeyPair(aid, result);
    }
    return result;
  }

  async saveKeyPair(aid: string, keyPair: KeyPairRecord): Promise<void> {
    const record = deepClone(keyPair);
    if (hasEncryptionSeed(this._encryptionSeed) && typeof record.private_key_pem === 'string') {
      (record as JsonObject)._encrypted_pk = await encryptPEM(record.private_key_pem, this._encryptionSeed) as unknown as JsonObject;
      delete record.private_key_pem;
    }
    await idbPut(STORE_KEY_PAIRS, metadataStoreKey(aid), record);
  }

  // ── RegisterAID pending 身份 ─────────────────────────

  async pendingIdentityDir(aid: string): Promise<string> {
    const handle = `${pendingIdentityPrefix(aid)}${randomHex(4)}-${Math.floor(Date.now() / 1000)}`;
    const now = Date.now();
    await idbPut<PendingIdentityRecord>(STORE_PENDING_IDENTITIES, handle, {
      aid,
      created_at: now,
      updated_at: now,
    });
    return handle;
  }

  async listPendingIdentityDirs(aid: string): Promise<string[]> {
    const prefix = pendingIdentityPrefix(aid);
    const rows = await idbGetAllByPrefix<PendingIdentityRecord>(STORE_PENDING_IDENTITIES, prefix);
    return rows
      .filter((row) => row.key.startsWith(prefix) && isRecord(row.value) && String(row.value.aid ?? '') === aid)
      .sort((a, b) => Number(b.value.updated_at ?? 0) - Number(a.value.updated_at ?? 0))
      .map((row) => row.key);
  }

  async savePendingKeyPair(handle: string, aid: string, keyPair: KeyPairRecord): Promise<void> {
    const current = await this._loadPendingRecord(handle, aid);
    if (!current) throw new Error(`pending identity not found: ${handle}`);
    const record = deepClone(keyPair);
    const privateKeyPem = record.private_key_pem;
    if (typeof privateKeyPem !== 'string' || !privateKeyPem) {
      throw new Error('savePendingKeyPair requires private_key_pem');
    }
    record._encrypted_pk = await encryptPEM(privateKeyPem, this._encryptionSeed ?? '') as unknown as JsonObject;
    delete record.private_key_pem;
    await idbPut<PendingIdentityRecord>(STORE_PENDING_IDENTITIES, handle, {
      ...current,
      aid,
      key_pair: record,
      updated_at: Date.now(),
    });
  }

  async loadPendingKeyPair(handle: string, aid: string): Promise<KeyPairRecord | null> {
    const current = await this._loadPendingRecord(handle, aid, false);
    if (!current || !isRecord(current.key_pair)) return null;
    const result = deepClone(current.key_pair) as KeyPairRecord;
    const encrypted = (result as JsonObject)._encrypted_pk;
    if (isRecord(encrypted)) {
      try {
        const envelope = encrypted as unknown as EncryptedEnvelope;
        result.private_key_pem = await decryptPEM(envelope, this._encryptionSeed ?? '');
        delete (result as JsonObject)._encrypted_pk;
        return result;
      } catch {
        this._log.error(`[keystore] decrypt pending ${aid} private key failed, maybe encryptionSeed mismatch`);
        throw new Error(`pending identity private key decrypt failed for aid ${aid}: seed_password mismatch or IndexedDB record corrupted`);
      }
    }
    if (typeof result.private_key_pem === 'string' && result.private_key_pem) {
      await this.savePendingKeyPair(handle, aid, result);
      return result;
    }
    return result;
  }

  async savePendingCert(handle: string, certPem: string): Promise<void> {
    const current = await this._loadPendingRecord(handle, undefined);
    if (!current) throw new Error(`pending identity not found: ${handle}`);
    await idbPut<PendingIdentityRecord>(STORE_PENDING_IDENTITIES, handle, {
      ...current,
      cert: certPem,
      updated_at: Date.now(),
    });
  }

  async promotePendingIdentity(handle: string, aid: string): Promise<string> {
    return this._withAidLock(aid, async () => {
      const current = await this._loadPendingRecord(handle, aid);
      if (!current) throw new Error(`pending identity not found: ${handle}`);
      if (!isRecord(current.key_pair)) {
        throw new Error(`promotePendingIdentity: missing pending key pair: ${handle}`);
      }
      const targetKey = metadataStoreKey(aid);
      const [existingKeyPair, existingCert] = await Promise.all([
        idbGet<JsonObject>(STORE_KEY_PAIRS, targetKey),
        idbGet<string>(STORE_CERTS, certStoreKey(aid)),
      ]);
      if (existingKeyPair || existingCert) {
        throw new Error(`promotePendingIdentity: target exists: ${targetKey}`);
      }
      const keyPair = await this._protectedPendingKeyPair(current, aid);
      await idbPut(STORE_KEY_PAIRS, targetKey, keyPair);
      if (typeof current.cert === 'string' && current.cert) {
        await idbPut(STORE_CERTS, certStoreKey(aid), current.cert);
      }
      await idbDelete(STORE_PENDING_IDENTITIES, handle);
      return targetKey;
    });
  }

  async discardPendingIdentity(handle: string): Promise<void> {
    await idbDelete(STORE_PENDING_IDENTITIES, handle);
  }

  async cleanupPendingDirs(maxAgeMs: number = 600_000): Promise<number> {
    const rows = await idbGetAll<PendingIdentityRecord>(STORE_PENDING_IDENTITIES);
    const now = Date.now();
    let removed = 0;
    for (const row of rows) {
      if (!isRecord(row.value)) continue;
      const updatedAt = Number(row.value.updated_at ?? row.value.created_at ?? 0);
      if (updatedAt && now - updatedAt < maxAgeMs) continue;
      await idbDelete(STORE_PENDING_IDENTITIES, row.key);
      removed++;
    }
    return removed;
  }

  // ── 证书 ──────────────────────────────────────────

  async loadCert(aid: string, certFingerprint?: string): Promise<string | null> {
    const normalized = normalizeCertFingerprint(certFingerprint);
    if (normalized) {
      const versioned = await idbGet(STORE_CERTS, certStoreKey(aid, normalized));
      if (typeof versioned === 'string') return versioned;
      const active = await idbGet(STORE_CERTS, certStoreKey(aid));
      if (typeof active === 'string' && await fingerprintFromCertPem(active) === normalized) return active;
      return null;
    }
    const data = await idbGet(STORE_CERTS, certStoreKey(aid));
    return typeof data === 'string' ? data as string : null;
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

  // ── 身份信息（组合操作） ──────────────────────────

  async loadIdentity(aid: string): Promise<IdentityRecord | null> {
    const tStart = Date.now();
    this._log.debug(`loadIdentity enter: aid=${aid}`);
    try {
      const result = await this._withAidLock(aid, async () => {
        const [keyPair, cert] = await Promise.all([
          this._loadKeyPairUnlocked(aid),
          this._loadCertUnlocked(aid),
        ]);
        const metadataOnly = await this._loadMetadataOnlyUnlocked(aid) ?? {};
        const hasMeta = Object.keys(metadataOnly).length > 0;

        if (!keyPair && !cert && !hasMeta) return null;

        const identity: IdentityRecord = {};
        if (hasMeta) Object.assign(identity, metadataOnly);
        if (keyPair) Object.assign(identity, keyPair);
        if (cert) {
          const localPubB64 = keyPair?.public_key_der_b64;
          if (typeof localPubB64 === 'string' && localPubB64) {
            const certSpkiB64 = extractSpkiB64FromCertPem(cert);
            if (certSpkiB64 && certSpkiB64 !== localPubB64) {
              this._log.error(`[keystore] identity ${aid} key public key mismatches cert public key, discard cert`);
            } else {
              identity.cert = cert;
            }
          } else {
            identity.cert = cert;
          }
        }
        return identity;
      });
      this._log.debug(`loadIdentity exit: elapsed=${Date.now() - tStart}ms aid=${aid} found=${result !== null}`);
      return result;
    } catch (err) {
      this._log.debug(`loadIdentity exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async saveIdentity(aid: string, identity: IdentityRecord): Promise<void> {
    const tStart = Date.now();
    this._log.debug(`saveIdentity enter: aid=${aid} has_cert=${!!identity.cert}`);
    try {
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

        if (Object.keys(metadataFields).length > 0) {
          const plain = stripStructuredFields(metadataFields);
          if (Object.keys(plain).length > 0) {
            const current = (await this._loadMetadataOnlyUnlocked(aid)) ?? {};
            Object.assign(current, plain);
            await this._saveMetadataOnlyUnlocked(aid, current);
          }
        }
      });
      this._log.debug(`saveIdentity exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
    } catch (err) {
      this._log.debug(`saveIdentity exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── Metadata KV（gateway_url 等）────────────────────────

  async getMetadata(aid: string, key: string): Promise<string> {
    if (!key) return '';
    return this._withAidLock(aid, async () => {
      const md = (await this._loadMetadataOnlyUnlocked(aid)) ?? {};
      const value = (md as Record<string, unknown>)[key];
      if (typeof value === 'string') return value;
      if (value === null || value === undefined) return '';
      return String(value);
    });
  }

  async setMetadata(aid: string, key: string, value: string): Promise<void> {
    if (!key) return;
    await this._withAidLock(aid, async () => {
      const current = (await this._loadMetadataOnlyUnlocked(aid)) ?? {};
      const next = deepClone(current) as Record<string, unknown>;
      if (value === '' || value === undefined || value === null) {
        delete next[key];
      } else {
        next[key] = value;
      }
      await this._saveMetadataOnlyUnlocked(aid, next as MetadataRecord);
    });
  }

  // ── 内部辅助 ─────────────────────────────────────────

  private async _loadPendingRecord(handle: string, aid?: string, required = true): Promise<PendingIdentityRecord | null> {
    const data = await idbGet<PendingIdentityRecord>(STORE_PENDING_IDENTITIES, handle);
    if (!isRecord(data)) {
      if (required) throw new Error(`pending identity not found: ${handle}`);
      return null;
    }
    const record = deepClone(data) as unknown as PendingIdentityRecord;
    if (aid !== undefined && String(record.aid ?? '') !== aid) {
      throw new Error(`pending identity aid mismatch: ${handle}`);
    }
    return record;
  }

  private async _protectedPendingKeyPair(current: PendingIdentityRecord, aid: string): Promise<JsonObject> {
    if (!isRecord(current.key_pair)) {
      throw new Error(`pending identity missing key pair for ${aid}`);
    }
    const keyPair = deepClone(current.key_pair);
    const privateKeyPem = keyPair.private_key_pem;
    if (typeof privateKeyPem === 'string' && privateKeyPem) {
      throw new Error(`pending identity private key is plaintext for ${aid}`);
    }
    if (!isRecord(keyPair._encrypted_pk)) {
      throw new Error(`pending identity private key is not encrypted for ${aid}`);
    }
    return keyPair;
  }

  private async _loadKeyPairUnlocked(aid: string): Promise<KeyPairRecord | null> {
    const data = await idbGet<JsonObject>(STORE_KEY_PAIRS, metadataStoreKey(aid));
    if (!isRecord(data)) return null;
    const result = deepClone(data);
    if (isRecord(result._encrypted_pk) && hasEncryptionSeed(this._encryptionSeed)) {
      try {
        const envelope = result._encrypted_pk as unknown as EncryptedEnvelope;
        result.private_key_pem = await decryptPEM(envelope, this._encryptionSeed);
        delete result._encrypted_pk;
      } catch {
        this._log.error(`[keystore] decrypt ${aid} private key failed, maybe encryptionSeed mismatch`);
        throw new Error(`private key decrypt failed for aid ${aid}: seed_password mismatch or IndexedDB record corrupted`);
      }
    } else if (!isRecord(result._encrypted_pk) && typeof result.private_key_pem === 'string' && hasEncryptionSeed(this._encryptionSeed)) {
      await this._saveKeyPairUnlocked(aid, result);
    }
    return result;
  }

  private async _saveKeyPairUnlocked(aid: string, keyPair: KeyPairRecord): Promise<void> {
    const record = deepClone(keyPair);
    if (hasEncryptionSeed(this._encryptionSeed) && typeof record.private_key_pem === 'string') {
      (record as JsonObject)._encrypted_pk = await encryptPEM(record.private_key_pem, this._encryptionSeed) as unknown as JsonObject;
      delete record.private_key_pem;
    }
    await idbPut(STORE_KEY_PAIRS, metadataStoreKey(aid), record);
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

  private async _saveMetadataOnlyUnlocked(aid: string, metadata: MetadataRecord): Promise<void> {
    const plain = stripStructuredFields(metadata);
    await idbPut(STORE_METADATA, metadataStoreKey(aid), plain);
  }
}
