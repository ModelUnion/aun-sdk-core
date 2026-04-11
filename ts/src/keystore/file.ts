/**
 * 基于文件系统的 KeyStore 实现
 *
 * 与 Python SDK 的 FileKeyStore 完全对齐：
 * - 目录结构：{root}/AIDs/{safeAid}/private/key.json, public/cert.pem, tokens/meta.json
 * - safeAid：将 /, \, : 替换为 _
 * - 敏感字段（access_token, refresh_token, kite_token）通过 SecretStore 保护
 * - e2ee_prekeys 的 private_key_pem 通过 SecretStore 保护
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  chmodSync,
} from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

import type { KeyStore } from './index.js';
import type { SecretStore } from '../secret-store/index.js';
import type { SQLiteBackup } from './sqlite-backup.js';
import { createDefaultSecretStore } from '../secret-store/index.js';
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
  type SecretRecord,
} from '../types.js';

/** 需要通过 SecretStore 保护的 token 字段 */
const SENSITIVE_TOKEN_FIELDS = ['access_token', 'refresh_token', 'kite_token'] as const;

/** 关键 metadata 键（防御性合并） */
const CRITICAL_METADATA_KEYS = ['e2ee_prekeys', 'e2ee_sessions', 'group_secrets'] as const;
const STRUCTURED_RECOVERY_RETENTION_MS = 7 * 24 * 3600 * 1000;
const PREKEY_MIN_KEEP_COUNT = 7;

/** 在 Unix 系统上将文件权限设为 0o600（仅属主可读写） */
function secureFilePermissions(path: string): void {
  if (process.platform !== 'win32') {
    try {
      chmodSync(path, 0o600);
    } catch {
      // 平台兼容 fallback
    }
  }
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export class FileKeyStore implements KeyStore {
  private static _aidLockDepths = new Map<string, number>();
  private _root: string;
  private _aidsRoot: string;
  private _secretStore: SecretStore;
  private _backup: SQLiteBackup | null;

  constructor(
    root?: string,
    opts?: {
      secretStore?: SecretStore;
      encryptionSeed?: string;
      sqliteBackup?: SQLiteBackup;
    },
  ) {
    const preferred = root ?? join(homedir(), '.aun');
    const fallback = join(process.cwd(), '.aun');
    const resolvedRoot = this._prepareRoot(preferred, fallback);

    this._backup = opts?.sqliteBackup ?? null;
    this._secretStore = opts?.secretStore ?? createDefaultSecretStore(resolvedRoot, opts?.encryptionSeed, this._backup ?? undefined);
    this._root = resolvedRoot;
    this._aidsRoot = join(this._root, 'AIDs');
    mkdirSync(this._aidsRoot, { recursive: true });
  }

  close(): void {
    this._backup?.close();
  }

  private _withAidLock<T>(aid: string, fn: () => T): T {
    const key = FileKeyStore._safeAid(aid);
    const depth = FileKeyStore._aidLockDepths.get(key) ?? 0;
    FileKeyStore._aidLockDepths.set(key, depth + 1);
    try {
      return fn();
    } finally {
      const nextDepth = (FileKeyStore._aidLockDepths.get(key) ?? 1) - 1;
      if (nextDepth <= 0) {
        FileKeyStore._aidLockDepths.delete(key);
      } else {
        FileKeyStore._aidLockDepths.set(key, nextDepth);
      }
    }
  }

  // ── 公开接口 ────────────────────────────────────────────

  loadIdentity(aid: string): IdentityRecord | null {
    return this._withAidLock(aid, () => {
      const identity = this._loadIdentityFromSplitFiles(aid);
      if (identity !== null) return identity;
      return null;
    });
  }

  saveIdentity(aid: string, identity: IdentityRecord): void {
    this._withAidLock(aid, () => {
      // 保存密钥对
      const keyPairKeys = ['private_key_pem', 'public_key_der_b64', 'curve'] as const;
      const keyPair: KeyPairRecord = {};
      let hasKeyPair = false;
      for (const k of keyPairKeys) {
        if (k in identity) {
          keyPair[k] = identity[k];
          hasKeyPair = true;
        }
      }
      if (hasKeyPair) this.saveKeyPair(aid, keyPair);

      // 保存证书
      const cert = identity.cert;
      if (typeof cert === 'string' && cert) this.saveCert(aid, cert);

      // 合并 metadata 而非覆盖
      const excludeKeys = new Set(['private_key_pem', 'public_key_der_b64', 'curve', 'cert']);
      const newFields: MetadataRecord = {};
      for (const [key, value] of Object.entries(identity)) {
        if (!excludeKeys.has(key)) newFields[key] = value;
      }
      this.updateMetadata(aid, existing => {
        Object.assign(existing, newFields);
        return existing;
      });
    });
  }

  loadE2EEPrekeys(aid: string): PrekeyMap {
    const metaOnly = this._loadMetaJsonOnly(aid) ?? {};
    this._syncStructuredStateFromMeta(aid, metaOnly);
    if (this._backup?.available) {
      return this._backup.loadPrekeys(aid);
    }
    return deepClone((metaOnly.e2ee_prekeys as PrekeyMap) ?? {});
  }

  saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: PrekeyRecord): void {
    let existing: PrekeyMap = {};
    if (this._backup?.available) {
      const metaOnly = this._loadMetaJsonOnly(aid) ?? {};
      this._syncStructuredStateFromMeta(aid, metaOnly);
      existing = this._backup.loadPrekeys(aid);
    }
    existing[prekeyId] = deepClone(prekeyData);
    if (this._backup?.available) {
      this._backup.replacePrekeys(aid, existing);
    }
    this._updateMetaJsonOnly(aid, metadata => {
      const prekeys = (metadata.e2ee_prekeys as PrekeyMap | undefined) ?? {};
      prekeys[prekeyId] = deepClone(prekeyData);
      metadata.e2ee_prekeys = prekeys;
      return metadata;
    });
  }

  cleanupE2EEPrekeys(aid: string, cutoffMs: number, keepLatest = PREKEY_MIN_KEEP_COUNT): string[] {
    const metaOnly = this._loadMetaJsonOnly(aid) ?? {};
    this._syncStructuredStateFromMeta(aid, metaOnly);
    let removed: string[] = [];
    if (this._backup?.available) {
      removed = this._backup.cleanupPrekeysBefore(aid, cutoffMs, keepLatest);
    } else {
      const prekeys = (metaOnly.e2ee_prekeys as PrekeyMap | undefined) ?? {};
      const retainedIds = this._latestPrekeyIds(prekeys, keepLatest);
      for (const [prekeyId, prekeyData] of Object.entries(prekeys)) {
        const marker = Number(prekeyData.expires_at ?? prekeyData.created_at ?? prekeyData.updated_at ?? 0);
        if (marker < cutoffMs && !retainedIds.has(prekeyId)) removed.push(prekeyId);
      }
    }
    if (removed.length > 0) {
      this._updateMetaJsonOnly(aid, metadata => {
        const prekeys = (metadata.e2ee_prekeys as PrekeyMap | undefined) ?? {};
        for (const prekeyId of removed) delete prekeys[prekeyId];
        metadata.e2ee_prekeys = prekeys;
        return metadata;
      });
    }
    return removed;
  }

  loadGroupSecretState(aid: string, groupId: string): GroupSecretRecord | null {
    const metaOnly = this._loadMetaJsonOnly(aid) ?? {};
    this._syncStructuredStateFromMeta(aid, metaOnly);
    if (this._backup?.available) {
      return deepClone(this._backup.loadGroupEntries(aid)[groupId] ?? null);
    }
    return deepClone(((metaOnly.group_secrets as GroupSecretMap | undefined) ?? {})[groupId] ?? null);
  }

  loadAllGroupSecretStates(aid: string): GroupSecretMap {
    const metaOnly = this._loadMetaJsonOnly(aid) ?? {};
    this._syncStructuredStateFromMeta(aid, metaOnly);
    if (this._backup?.available) {
      return deepClone(this._backup.loadGroupEntries(aid));
    }
    return deepClone((metaOnly.group_secrets as GroupSecretMap | undefined) ?? {});
  }

  saveGroupSecretState(aid: string, groupId: string, entry: GroupSecretRecord): void {
    if (this._backup?.available) {
      const metaOnly = this._loadMetaJsonOnly(aid) ?? {};
      this._syncStructuredStateFromMeta(aid, metaOnly);
      const current = this._backup.loadGroupEntries(aid);
      current[groupId] = deepClone(entry);
      this._backup.replaceGroupEntries(aid, current);
    }
    this._updateMetaJsonOnly(aid, metadata => {
      const groups = (metadata.group_secrets as GroupSecretMap | undefined) ?? {};
      groups[groupId] = deepClone(entry);
      metadata.group_secrets = groups;
      return metadata;
    });
  }

  cleanupGroupOldEpochsState(aid: string, groupId: string, cutoffMs: number): number {
    const metaOnly = this._loadMetaJsonOnly(aid) ?? {};
    this._syncStructuredStateFromMeta(aid, metaOnly);
    let removedEpochs: number[] = [];
    if (this._backup?.available) {
      removedEpochs = this._backup.cleanupGroupOldEpochs(aid, groupId, cutoffMs);
    } else {
      const groups = (metaOnly.group_secrets as GroupSecretMap | undefined) ?? {};
      const entry = groups[groupId];
      const oldEpochs = Array.isArray(entry?.old_epochs) ? entry.old_epochs as GroupOldEpochRecord[] : [];
      removedEpochs = oldEpochs
        .filter((old) => Number(old.updated_at ?? old.expires_at ?? 0) < cutoffMs)
        .map((old) => Number(old.epoch))
        .filter((epoch) => Number.isFinite(epoch));
    }
    if (removedEpochs.length > 0) {
      this._updateMetaJsonOnly(aid, metadata => {
        const groups = (metadata.group_secrets as GroupSecretMap | undefined) ?? {};
        const entry = groups[groupId];
        if (entry && Array.isArray(entry.old_epochs)) {
          entry.old_epochs = (entry.old_epochs as GroupOldEpochRecord[])
            .filter((old) => !removedEpochs.includes(Number(old.epoch)));
        }
        metadata.group_secrets = groups;
        return metadata;
      });
    }
    return removedEpochs.length;
  }

  loadKeyPair(aid: string): KeyPairRecord | null {
    return this._withAidLock(aid, () => {
      const path = this._keyPairPath(aid);
      if (existsSync(path)) {
        const keyPair = JSON.parse(readFileSync(path, 'utf-8'));
        // 双读：文件有，确保 SQLite 也有
        this._backupKeyPairToSQLite(aid, path);
        return this._restoreKeyPair(aid, keyPair);
      }
      // fallback: 从 SQLite 恢复
      return this._restoreKeyPairFromSQLite(aid);
    });
  }

  saveKeyPair(aid: string, keyPair: KeyPairRecord): void {
    this._withAidLock(aid, () => {
      const path = this._keyPairPath(aid);
      mkdirSync(join(path, '..'), { recursive: true });

      // 深拷贝后保护私钥
      const protected_ = { ...keyPair };
      const scope = FileKeyStore._safeAid(aid);
      const privateKeyPem = protected_.private_key_pem;
      delete protected_.private_key_pem;

      if (typeof privateKeyPem === 'string' && privateKeyPem) {
        const protection = this._secretStore.protect(
          scope,
          'identity/private_key',
          Buffer.from(privateKeyPem, 'utf-8'),
        );
        if (!protection.persisted) {
          throw new Error(
            `SecretStore 无法持久化私钥 (scheme=${protection.scheme})。` +
            `私钥必须能跨进程重启保留，请检查密钥存储配置。`,
          );
        }
        protected_.private_key_protection = protection;
      }

      writeFileSync(path, JSON.stringify(protected_, null, 2), 'utf-8');
      secureFilePermissions(path);
      // 双写：备份到 SQLite
      this._backupKeyPairToSQLite(aid, path);
    });
  }

  loadCert(aid: string): string | null {
    return this._withAidLock(aid, () => {
      const path = this._certPath(aid);
      if (existsSync(path)) {
        const cert = readFileSync(path, 'utf-8');
        // 双读：文件有，确保 SQLite 也有
        this._backupCertToSQLite(aid, cert);
        return cert;
      }
      // fallback: 从 SQLite 恢复
      return this._restoreCertFromSQLite(aid);
    });
  }

  saveCert(aid: string, certPem: string): void {
    this._withAidLock(aid, () => {
      const path = this._certPath(aid);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, certPem, 'utf-8');
      // 双写：备份到 SQLite
      this._backupCertToSQLite(aid, certPem);
    });
  }

  loadMetadata(aid: string): MetadataRecord | null {
    return this._withAidLock(aid, () => this._buildMergedMetadata(aid));
  }

  saveMetadata(aid: string, metadata: MetadataRecord): void {
    this._withAidLock(aid, () => {
      const current = this._buildMergedMetadata(aid) ?? {};
      const merged = deepClone(metadata);
      for (const key of CRITICAL_METADATA_KEYS) {
        if (current[key] && !(key in merged)) {
          console.warn(`save_metadata: 传入数据缺少 '${key}' (aid=${aid})，自动合并已有数据`);
          if (key === 'e2ee_prekeys') {
            merged.e2ee_prekeys = deepClone(current.e2ee_prekeys ?? {});
          } else if (key === 'e2ee_sessions') {
            merged.e2ee_sessions = deepClone(current.e2ee_sessions ?? []);
          } else if (key === 'group_secrets') {
            merged.group_secrets = deepClone(current.group_secrets ?? {});
          }
        }
      }

      if (this._backup?.available) {
        if (merged.e2ee_prekeys && typeof merged.e2ee_prekeys === 'object' && !Array.isArray(merged.e2ee_prekeys)) {
          this._backup.replacePrekeys(aid, deepClone(merged.e2ee_prekeys as PrekeyMap));
        }
        if (merged.group_secrets && typeof merged.group_secrets === 'object' && !Array.isArray(merged.group_secrets)) {
          this._backup.replaceGroupEntries(aid, deepClone(merged.group_secrets as GroupSecretMap));
        }
      }

      this._saveMetaJsonOnly(aid, merged);
    });
  }

  updateMetadata(
    aid: string,
    updater: (metadata: MetadataRecord) => MetadataRecord | void,
  ): MetadataRecord {
    return this._withAidLock(aid, () => {
      const metadata = this._buildMergedMetadata(aid) ?? {};
      const working = deepClone(metadata);
      const updated = updater(working) ?? working;
      this.saveMetadata(aid, updated);
      return updated;
    });
  }

  /**
   * 扫描所有已存储的身份，返回第一个可用的。
   */
  loadAnyIdentity(): IdentityRecord | null {
    if (!existsSync(this._aidsRoot)) return null;
    const candidates: string[] = [];
    try {
      for (const entry of readdirSync(this._aidsRoot, { withFileTypes: true })) {
        if (entry.isDirectory()) candidates.push(entry.name);
      }
    } catch {
      return null;
    }
    for (const aid of candidates.sort()) {
      const identity = this.loadIdentity(aid);
      if (identity !== null) return identity;
    }
    return null;
  }

  // ── 路径计算 ────────────────────────────────────────────

  static _safeAid(aid: string): string {
    return aid.replace(/[/\\:]/g, '_');
  }

  private _identityDir(aid: string): string {
    return join(this._aidsRoot, FileKeyStore._safeAid(aid));
  }

  private _keyPairPath(aid: string): string {
    return join(this._identityDir(aid), 'private', 'key.json');
  }

  private _certPath(aid: string): string {
    return join(this._identityDir(aid), 'public', 'cert.pem');
  }

  private _metadataPath(aid: string): string {
    return join(this._identityDir(aid), 'tokens', 'meta.json');
  }

  // ── 内部辅助 ────────────────────────────────────────────

  private _loadIdentityFromSplitFiles(aid: string): IdentityRecord | null {
    const keyPair = this.loadKeyPair(aid);
    const cert = this.loadCert(aid);
    const metadata = this.loadMetadata(aid);
    if (keyPair === null && cert === null && metadata === null) return null;

    const identity: IdentityRecord = {};
    if (metadata) Object.assign(identity, metadata);
    if (keyPair) Object.assign(identity, keyPair);
    if (cert) identity.cert = cert;
    return identity;
  }

  private _restoreKeyPair(aid: string, keyPair: KeyPairRecord): KeyPairRecord {
    const restored = { ...keyPair };
    const scope = FileKeyStore._safeAid(aid);
    const record = restored.private_key_protection;
    if (record && typeof record === 'object') {
      const value = this._secretStore.reveal(scope, 'identity/private_key', record as SecretRecord);
      if (value !== null) {
        restored.private_key_pem = value.toString('utf-8');
      } else {
        delete restored.private_key_pem;
      }
    }
    return restored;
  }

  private _protectMetadata(aid: string, metadata: MetadataRecord): MetadataRecord {
    const protected_: MetadataRecord = { ...metadata };
    const scope = FileKeyStore._safeAid(aid);

    // 保护 token 字段
    for (const field of SENSITIVE_TOKEN_FIELDS) {
      const value = protected_[field];
      delete protected_[field];
      if (typeof value === 'string' && value) {
        protected_[`${field}_protection`] = this._secretStore.protect(scope, field, Buffer.from(value, 'utf-8'));
      }
    }

    // 保护 e2ee_sessions 中的 key
    const sessions = protected_.e2ee_sessions;
    if (Array.isArray(sessions)) {
      const sanitized: JsonObject[] = [];
      for (const raw of sessions) {
        if (!isJsonObject(raw)) continue;
        const session: JsonObject = { ...raw };
        const secretName = this._sessionSecretName(session);
        const key = session.key;
        delete session.key;
        if (typeof key === 'string' && key && secretName) {
          session.key_protection = this._secretStore.protect(scope, secretName, Buffer.from(key, 'utf-8'));
        }
        sanitized.push(session);
      }
      protected_.e2ee_sessions = sanitized;
    }

    // 保护 prekey 私钥
    const prekeys = protected_.e2ee_prekeys;
    if (prekeys && typeof prekeys === 'object' && !Array.isArray(prekeys)) {
      const sanitized: PrekeyMap = {};
      for (const [prekeyId, prekeyData] of Object.entries(prekeys as JsonObject)) {
        if (!isJsonObject(prekeyData)) continue;
        const prekey: PrekeyRecord = { ...prekeyData };
        const secretName = `e2ee_prekeys/${prekeyId}/private_key`;
        const val = prekey.private_key_pem;
        delete prekey.private_key_pem;
        if (typeof val === 'string' && val) {
          prekey.private_key_protection = this._secretStore.protect(scope, secretName, Buffer.from(val, 'utf-8'));
        }
        sanitized[prekeyId] = prekey;
      }
      protected_.e2ee_prekeys = sanitized;
    }

    // 保护 group_secret
    const groupSecrets = protected_.group_secrets;
    if (groupSecrets && typeof groupSecrets === 'object' && !Array.isArray(groupSecrets)) {
      const sanitized: GroupSecretMap = {};
      for (const [groupId, groupData] of Object.entries(groupSecrets as JsonObject)) {
        if (!isJsonObject(groupData)) continue;
        const group: GroupSecretRecord = { ...groupData };
        const secretName = `group_secrets/${groupId}/secret`;
        const val = group.secret;
        delete group.secret;
        if (typeof val === 'string' && val) {
          group.secret_protection = this._secretStore.protect(scope, secretName, Buffer.from(val, 'utf-8'));
        }

        // 保护 old_epochs 中的 secret
        const oldEpochs = group.old_epochs;
        if (Array.isArray(oldEpochs)) {
          const sanitizedOld: GroupOldEpochRecord[] = [];
          for (const oldData of oldEpochs) {
            if (!isJsonObject(oldData)) continue;
            const old: GroupOldEpochRecord = { ...oldData };
            const oldEpoch = old.epoch ?? '?';
            const oldSecretName = `group_secrets/${groupId}/old/${oldEpoch}`;
            const oldValue = old.secret;
            delete old.secret;
            if (typeof oldValue === 'string' && oldValue) {
              old.secret_protection = this._secretStore.protect(scope, oldSecretName, Buffer.from(oldValue, 'utf-8'));
            }
            sanitizedOld.push(old);
          }
          group.old_epochs = sanitizedOld;
        }
        sanitized[groupId] = group;
      }
      protected_.group_secrets = sanitized;
    }

    return protected_;
  }

  private _restoreMetadata(aid: string, metadata: MetadataRecord): MetadataRecord {
    const restored: MetadataRecord = { ...metadata };
    const scope = FileKeyStore._safeAid(aid);

    // 恢复 token 字段
    for (const field of SENSITIVE_TOKEN_FIELDS) {
      const record = restored[`${field}_protection`];
      if (record && typeof record === 'object') {
        const value = this._secretStore.reveal(scope, field, record as SecretRecord);
        if (value !== null) {
          restored[field] = value.toString('utf-8');
        } else {
          delete restored[field];
        }
      }
    }

    // 恢复 e2ee_sessions 中的 key
    const sessions = restored.e2ee_sessions;
    if (Array.isArray(sessions)) {
      for (const raw of sessions) {
        if (!isJsonObject(raw)) continue;
        const session = raw;
        const record = session.key_protection;
        const secretName = this._sessionSecretName(session);
        if (record && typeof record === 'object' && secretName) {
          const value = this._secretStore.reveal(scope, secretName, record as SecretRecord);
          if (value !== null) {
            session.key = value.toString('utf-8');
          } else {
            delete session.key;
          }
        }
      }
    }

    // 恢复 prekey 私钥
    const prekeys = restored.e2ee_prekeys;
    if (prekeys && typeof prekeys === 'object' && !Array.isArray(prekeys)) {
      for (const [prekeyId, prekeyData] of Object.entries(prekeys as PrekeyMap)) {
        if (!isJsonObject(prekeyData)) continue;
        const record = prekeyData.private_key_protection;
        const secretName = `e2ee_prekeys/${prekeyId}/private_key`;
        if (record && typeof record === 'object') {
          const value = this._secretStore.reveal(scope, secretName, record as SecretRecord);
          if (value !== null) {
            prekeyData.private_key_pem = value.toString('utf-8');
          } else {
            delete prekeyData.private_key_pem;
          }
        }
      }
    }

    // 恢复 group_secret
    const groupSecrets = restored.group_secrets;
    if (groupSecrets && typeof groupSecrets === 'object' && !Array.isArray(groupSecrets)) {
      for (const [groupId, groupData] of Object.entries(groupSecrets as GroupSecretMap)) {
        if (!isJsonObject(groupData)) continue;
        const record = groupData.secret_protection;
        const secretName = `group_secrets/${groupId}/secret`;
        if (record && typeof record === 'object') {
          const value = this._secretStore.reveal(scope, secretName, record as SecretRecord);
          if (value !== null) {
            groupData.secret = value.toString('utf-8');
          } else {
            delete groupData.secret;
          }
        }

        // 恢复 old_epochs 中的 secret
        const oldEpochs = groupData.old_epochs;
        if (Array.isArray(oldEpochs)) {
          for (const oldData of oldEpochs) {
            if (!isJsonObject(oldData)) continue;
            const old = oldData;
            const oldRecord = old.secret_protection;
            const oldEpoch = old.epoch ?? '?';
            const oldSecretName = `group_secrets/${groupId}/old/${oldEpoch}`;
            if (oldRecord && typeof oldRecord === 'object') {
              const oldValue = this._secretStore.reveal(scope, oldSecretName, oldRecord as SecretRecord);
              if (oldValue !== null) {
                old.secret = oldValue.toString('utf-8');
              } else {
                delete old.secret;
              }
            }
          }
        }
      }
    }

    return restored;
  }

  private _sessionSecretName(session: JsonObject): string | null {
    const sessionId = String(session.session_id ?? '');
    if (!sessionId) return null;
    return `e2ee_sessions/${sessionId}/key`;
  }

  private _prepareRoot(preferred: string, fallback: string): string {
    try {
      mkdirSync(preferred, { recursive: true });
      return preferred;
    } catch {
      mkdirSync(fallback, { recursive: true });
      return fallback;
    }
  }

  // ── SQLite 双写双读辅助方法 ────────────────────────────────

  private _loadMetaJsonOnly(aid: string): MetadataRecord | null {
    const path = this._metadataPath(aid);
    if (existsSync(path)) {
      const result = this._restoreMetadata(aid, JSON.parse(readFileSync(path, 'utf-8')));
      this._backupMetadataToSQLite(aid, path);
      return result;
    }
    return this._restoreMetadataFromSQLite(aid);
  }

  private _buildMergedMetadata(aid: string): MetadataRecord | null {
    const metadata = this._loadMetaJsonOnly(aid) ?? {};
    this._syncStructuredStateFromMeta(aid, metadata);
    if (this._backup?.available) {
      delete metadata.e2ee_prekeys;
      delete metadata.group_secrets;
      const prekeys = this._backup.loadPrekeys(aid);
      if (Object.keys(prekeys).length) metadata.e2ee_prekeys = deepClone(prekeys);
      const groups = this._backup.loadGroupEntries(aid);
      if (Object.keys(groups).length) metadata.group_secrets = deepClone(groups);
    }
    return Object.keys(metadata).length ? metadata : null;
  }

  private _saveMetaJsonOnly(aid: string, metadata: MetadataRecord): void {
    const path = this._metadataPath(aid);
    mkdirSync(join(path, '..'), { recursive: true });
    const protected_ = this._protectMetadata(aid, metadata);
    writeFileSync(path, JSON.stringify(protected_, null, 2), 'utf-8');
    secureFilePermissions(path);
    this._backupMetadataToSQLite(aid, path);
  }

  private _updateMetaJsonOnly(
    aid: string,
    updater: (metadata: MetadataRecord) => MetadataRecord,
  ): void {
    const current = this._loadMetaJsonOnly(aid) ?? {};
    const updated = updater(deepClone(current));
    this._saveMetaJsonOnly(aid, updated);
  }

  private _syncStructuredStateFromMeta(aid: string, metadata: MetadataRecord): void {
    if (!this._backup?.available) return;

    const metaPrekeys = metadata.e2ee_prekeys;
    if (metaPrekeys && typeof metaPrekeys === 'object' && !Array.isArray(metaPrekeys)) {
      const latestIds = this._latestPrekeyIds(
        metaPrekeys as PrekeyMap,
        PREKEY_MIN_KEEP_COUNT,
      );
      const sqlitePrekeys = this._backup.loadPrekeys(aid);
      let changed = false;
      for (const [prekeyId, prekeyData] of Object.entries(metaPrekeys as PrekeyMap)) {
        if (sqlitePrekeys[prekeyId]) continue;
        if (!this._isPrekeyRecoverable(prekeyData, latestIds.has(prekeyId))) continue;
        sqlitePrekeys[prekeyId] = deepClone(prekeyData);
        changed = true;
      }
      if (changed) this._backup.replacePrekeys(aid, sqlitePrekeys);
    }

    const metaGroups = metadata.group_secrets;
    if (metaGroups && typeof metaGroups === 'object' && !Array.isArray(metaGroups)) {
      const sqliteGroups = this._backup.loadGroupEntries(aid);
      let changed = false;
      for (const [groupId, incoming] of Object.entries(metaGroups as GroupSecretMap)) {
        const merged = this._mergeGroupEntryFromMeta(sqliteGroups[groupId], incoming);
        if (JSON.stringify(sqliteGroups[groupId] ?? null) !== JSON.stringify(merged)) {
          sqliteGroups[groupId] = merged;
          changed = true;
        }
      }
      if (changed) this._backup.replaceGroupEntries(aid, sqliteGroups);
    }
  }

  private _isUnexpiredRecord(record: JsonObject, fallbackKey: string, keepBecauseLatest: boolean = false): boolean {
    const expiresAt = typeof record.expires_at === 'number' ? record.expires_at : null;
    if (expiresAt !== null) return expiresAt >= Date.now();
    const marker = typeof record[fallbackKey] === 'number' ? record[fallbackKey] as number : null;
    if (keepBecauseLatest) return marker !== null;
    return marker !== null && marker + STRUCTURED_RECOVERY_RETENTION_MS >= Date.now();
  }

  private _isPrekeyRecoverable(record: PrekeyRecord, keepBecauseLatest: boolean = false): boolean {
    return this._isUnexpiredRecord(record, 'created_at', keepBecauseLatest);
  }

  private _isGroupEpochRecoverable(record: GroupOldEpochRecord | GroupSecretRecord): boolean {
    return this._isUnexpiredRecord(record, 'updated_at');
  }

  private _latestPrekeyIds(
    prekeys: PrekeyMap,
    keepLatest: number,
  ): Set<string> {
    if (keepLatest <= 0) return new Set();
    return new Set(
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
  }

  private _mergeGroupEntryFromMeta(
    existing: GroupSecretRecord | undefined,
    incoming: GroupSecretRecord,
  ): GroupSecretRecord {
    const oldByEpoch = new Map<number, GroupOldEpochRecord>();
    let current = existing && typeof existing.epoch === 'number'
      ? deepClone(Object.fromEntries(Object.entries(existing).filter(([key]) => key !== 'old_epochs')))
      : null;

    if (existing && Array.isArray(existing.old_epochs)) {
      for (const old of existing.old_epochs as GroupOldEpochRecord[]) {
        if (typeof old.epoch === 'number') oldByEpoch.set(old.epoch, deepClone(old));
      }
    }

    if (typeof incoming.epoch === 'number' && this._isGroupEpochRecoverable(incoming)) {
      const incomingCurrent = deepClone(Object.fromEntries(Object.entries(incoming).filter(([key]) => key !== 'old_epochs')));
      if (!current) {
        current = incomingCurrent;
      } else if ((incomingCurrent.epoch as number) > (current.epoch as number)) {
        oldByEpoch.set(current.epoch as number, this._preferNewerGroupEpochRecord(oldByEpoch.get(current.epoch as number), current));
        current = incomingCurrent;
      } else if ((incomingCurrent.epoch as number) === (current.epoch as number)) {
        current = this._preferNewerGroupEpochRecord(current, incomingCurrent);
      } else {
        oldByEpoch.set(incomingCurrent.epoch as number, this._preferNewerGroupEpochRecord(oldByEpoch.get(incomingCurrent.epoch as number), incomingCurrent));
      }
    }

    for (const old of Array.isArray(incoming.old_epochs) ? incoming.old_epochs as GroupOldEpochRecord[] : []) {
      if (typeof old.epoch !== 'number' || !this._isGroupEpochRecoverable(old)) continue;
      oldByEpoch.set(old.epoch, this._preferNewerGroupEpochRecord(oldByEpoch.get(old.epoch), old));
    }

    const merged: GroupSecretRecord = current ? deepClone(current) : {};
    if (current && typeof current.epoch === 'number') oldByEpoch.delete(current.epoch);
    if (oldByEpoch.size) {
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

  private _backupKeyPairToSQLite(aid: string, path: string): void {
    if (!this._backup?.available) return;
    try {
      this._backup.backupKeyPair(aid, readFileSync(path, 'utf-8'));
    } catch { /* ignore */ }
  }

  private _restoreKeyPairFromSQLite(aid: string): KeyPairRecord | null {
    if (!this._backup?.available) return null;
    const data = this._backup.restoreKeyPair(aid);
    if (!data) return null;
    console.log(`从 SQLite 恢复 key_pair (aid=${aid})`);
    try {
      const keyPair = JSON.parse(data);
      const path = this._keyPairPath(aid);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, data, 'utf-8');
      secureFilePermissions(path);
      return this._restoreKeyPair(aid, keyPair);
    } catch {
      return null;
    }
  }

  private _backupCertToSQLite(aid: string, cert: string): void {
    if (!this._backup?.available) return;
    try {
      this._backup.backupCert(aid, cert);
    } catch { /* ignore */ }
  }

  private _restoreCertFromSQLite(aid: string): string | null {
    if (!this._backup?.available) return null;
    const cert = this._backup.restoreCert(aid);
    if (!cert) return null;
    console.log(`从 SQLite 恢复 cert (aid=${aid})`);
    try {
      const path = this._certPath(aid);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, cert, 'utf-8');
      return cert;
    } catch {
      return null;
    }
  }

  private _backupMetadataToSQLite(aid: string, path: string): void {
    if (!this._backup?.available) return;
    try {
      this._backup.backupMetadata(aid, readFileSync(path, 'utf-8'));
    } catch { /* ignore */ }
  }

  private _restoreMetadataFromSQLite(aid: string): MetadataRecord | null {
    if (!this._backup?.available) return null;
    const data = this._backup.restoreMetadata(aid);
    if (!data) return null;
    console.log(`从 SQLite 恢复 metadata (aid=${aid})`);
    try {
      const protected_ = JSON.parse(data);
      const path = this._metadataPath(aid);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, data, 'utf-8');
      secureFilePermissions(path);
      return this._restoreMetadata(aid, protected_);
    } catch {
      return null;
    }
  }
}
