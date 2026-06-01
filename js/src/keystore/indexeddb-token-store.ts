// ── IndexedDB TokenStore 实现 ──────────────────────────────
// 不含私钥操作：证书、实例态、seq、prekeys、群组密钥、sessions、信任根、metadata。
// AUNClient / AuthFlow 持有此类型。
//
// 与 IndexedDBIdentityStore 共用同一 IndexedDB 数据库（aun-keystore），
// 但二者之间无任何代码依赖——共享基础设施集中在 indexeddb-shared.ts。

import type { ModuleLogger } from '../logger.js';
import { pemToArrayBuffer } from '../crypto.js';
import type { AgentMdCacheRecord, AgentMdCacheUpsert, TokenStore, GroupStateRecord } from './index.js';
import {
  _noopLog,
  STORE_CERTS,
  STORE_METADATA,
  STORE_INSTANCE_STATE,
  STORE_PREKEYS,
  STORE_GROUP_CURRENT,
  STORE_GROUP_OLD_EPOCHS,
  STORE_SESSIONS,
  STORE_GROUP_STATE,
  STORE_AGENT_MD_CACHE,
  STRUCTURED_RECOVERY_RETENTION_MS,
  safeAid,
  encodePart,
  deepClone,
  isRecord,
  sameJson,
  metadataStoreKey,
  normalizeCertFingerprint,
  fingerprintFromCertPem,
  certStoreKey,
  instanceStateStoreKey,
  prekeyPrefix,
  prekeyStoreKey,
  groupCurrentPrefix,
  groupCurrentStoreKey,
  groupOldPrefix,
  groupOldStoreKey,
  sessionPrefix,
  sessionStoreKey,
  seqTrackerPrefix,
  seqTrackerStoreKey,
  agentMdCachePrefix,
  agentMdCacheStoreKey,
  stripStructuredFields,
  normalizeAgentMdCacheRecord,
  mergeAgentMdCacheRecord,
  idbGet,
  idbGetAllByPrefix,
  idbPut,
  idbDelete,
  type LegacyGroupSecretMap,
  type GroupOldEpochRecord,
  type GroupSecretRecord,
  type JsonObject,
  type MetadataRecord,
  type PrekeyMap,
  type PrekeyRecord,
  type SessionRecord,
} from './indexeddb-shared.js';

/**
 * 基于 IndexedDB 的 TokenStore 实现（不含私钥操作）。
 *
 * 设计语义：
 * - metadata 只保存普通 metadata 字段；
 * - e2ee_prekeys / group_secrets 只保存到结构化 store；
 * - 若检测到旧版本把结构化数据写进了 metadata，会自动迁移到结构化 store。
 */
export class IndexedDBTokenStore implements TokenStore {
  private _log: ModuleLogger = _noopLog;
  setLogger(log: ModuleLogger): void { this._log = log; }

  private static _aidTails = new Map<string, Promise<void>>();

  private async _withAidLock<T>(aid: string, fn: () => Promise<T>): Promise<T> {
    const key = safeAid(aid);
    const previous = IndexedDBTokenStore._aidTails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.catch(() => undefined).then(() => current);
    IndexedDBTokenStore._aidTails.set(key, tail);

    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
      if (IndexedDBTokenStore._aidTails.get(key) === tail) {
        IndexedDBTokenStore._aidTails.delete(key);
      }
    }
  }

  // ── 证书 ──────────────────────────────────────────

  async loadCert(aid: string, certFingerprint?: string): Promise<string | null> {
    const tStart = Date.now();
    this._log.debug(`loadCert enter: aid=${aid} fingerprint=${certFingerprint ?? '<none>'}`);
    try {
      const normalized = normalizeCertFingerprint(certFingerprint);
      if (normalized) {
        const versioned = await idbGet(STORE_CERTS, certStoreKey(aid, normalized));
        if (typeof versioned === 'string') {
          this._log.debug(`loadCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} found=true source=versioned`);
          return versioned;
        }
        const active = await idbGet(STORE_CERTS, certStoreKey(aid));
        if (typeof active === 'string' && await fingerprintFromCertPem(active) === normalized) {
          this._log.debug(`loadCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} found=true source=active`);
          return active;
        }
        this._log.debug(`loadCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} found=false`);
        return null;
      }
      const data = await idbGet(STORE_CERTS, certStoreKey(aid));
      const found = typeof data === 'string';
      this._log.debug(`loadCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} found=${found}`);
      return found ? data as string : null;
    } catch (err) {
      this._log.debug(`loadCert exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async saveCert(
    aid: string,
    certPem: string,
    certFingerprint?: string,
    opts?: { makeActive?: boolean },
  ): Promise<void> {
    const tStart = Date.now();
    this._log.debug(`saveCert enter: aid=${aid} fingerprint=${certFingerprint ?? '<none>'} make_active=${opts?.makeActive ?? false}`);
    try {
      const normalized = normalizeCertFingerprint(certFingerprint);
      if (normalized) {
        await idbPut(STORE_CERTS, certStoreKey(aid, normalized), certPem);
        if (opts?.makeActive) {
          await idbPut(STORE_CERTS, certStoreKey(aid), certPem);
        }
        this._log.debug(`saveCert exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
        return;
      }
      await idbPut(STORE_CERTS, certStoreKey(aid), certPem);
      this._log.debug(`saveCert exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
    } catch (err) {
      this._log.debug(`saveCert exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
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

  // ── 结构化 prekeys ───────────────────────────────────

  async loadE2EEPrekeys(aid: string, deviceId?: string): Promise<PrekeyMap> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._loadPrekeysUnlocked(aid, String(deviceId ?? '').trim());
    });
  }

  /**
   * 按 prekey_id 单点查询本地 prekey（O(log N) IndexedDB primary-key 查找）。
   *
   * 解密入站消息时，envelope 里只带 prekey_id，没有 device_id。优先用 IndexedDB
   * 主键直查；命中则 O(log N)，未命中再回退到前缀扫描，保证跨 device_id 也能找到。
   */
  async loadE2EEPrekeyById(aid: string, prekeyId: string): Promise<Record<string, unknown> | null> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._loadPrekeyByIdUnlocked(aid, prekeyId);
    });
  }

  async saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: PrekeyRecord, deviceId?: string): Promise<void> {
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

  async cleanupE2EEPrekeys(aid: string, cutoffMs: number, keepLatest = 7, deviceId?: string): Promise<string[]> {
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

  async listGroupSecretIds(aid: string): Promise<string[]> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const ids = new Set<string>();
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_CURRENT, groupCurrentPrefix(aid))) {
        const [, encodedGroupId] = item.key.split('|');
        if (encodedGroupId) ids.add(decodeURIComponent(encodedGroupId));
      }
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid))) {
        const [, encodedGroupId] = item.key.split('|');
        if (encodedGroupId) ids.add(decodeURIComponent(encodedGroupId));
      }
      return [...ids].sort();
    });
  }

  async cleanupGroupOldEpochsState(aid: string, groupId: string, cutoffMs: number): Promise<number> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      let removed = 0;
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid, groupId))) {
        if (!isRecord(item.value)) continue;
        if (Number(item.value.updated_at ?? 0) <= cutoffMs) {
          await idbDelete(STORE_GROUP_OLD_EPOCHS, item.key);
          removed += 1;
        }
      }
      return removed;
    });
  }

  async loadGroupSecretEpoch(aid: string, groupId: string, epoch?: number | null): Promise<GroupSecretRecord | null> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const current = await idbGet<JsonObject>(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId));
      if (isRecord(current)) {
        const record = deepClone(current) as GroupSecretRecord;
        delete record.group_id;
        if (epoch === undefined || epoch === null || Number(record.epoch ?? 0) === Number(epoch)) {
          return record;
        }
      } else if (epoch === undefined || epoch === null) {
        return null;
      }
      const old = await idbGet<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldStoreKey(aid, groupId, Number(epoch)));
      if (!isRecord(old)) return null;
      const record = deepClone(old) as GroupSecretRecord;
      delete record.group_id;
      return record;
    });
  }

  async loadGroupSecretEpochs(aid: string, groupId: string): Promise<GroupSecretRecord[]> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      const result: GroupSecretRecord[] = [];
      const current = await idbGet<JsonObject>(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId));
      if (isRecord(current)) {
        const record = deepClone(current) as GroupSecretRecord;
        delete record.group_id;
        result.push(record);
      }
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid, groupId))) {
        if (!isRecord(item.value)) continue;
        const record = deepClone(item.value) as GroupSecretRecord;
        delete record.group_id;
        result.push(record);
      }
      return result;
    });
  }

  async storeGroupSecretTransition(
    aid: string,
    groupId: string,
    opts: {
      epoch: number;
      secret: string;
      commitment: string;
      memberAids: string[];
      epochChain?: string;
      pendingRotationId?: string;
      epochChainUnverified?: boolean | null;
      epochChainUnverifiedReason?: string | null;
      oldEpochRetentionMs: number;
    },
  ): Promise<boolean> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._storeGroupSecretTransitionUnlocked(aid, groupId, opts);
    });
  }

  async storeGroupSecretEpoch(
    aid: string,
    groupId: string,
    opts: {
      epoch: number;
      secret: string;
      commitment: string;
      memberAids: string[];
      epochChain?: string;
      pendingRotationId?: string;
      epochChainUnverified?: boolean | null;
      epochChainUnverifiedReason?: string | null;
      oldEpochRetentionMs: number;
    },
  ): Promise<boolean> {
    return this._withAidLock(aid, async () => {
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._storeGroupSecretEpochUnlocked(aid, groupId, opts);
    });
  }

  async discardPendingGroupSecretState(aid: string, groupId: string, epoch: number, rotationId: string): Promise<boolean> {
    return this._withAidLock(aid, async () => {
      const rid = String(rotationId ?? '').trim();
      if (!rid) return false;
      await this._migrateLegacyStructuredStateUnlocked(aid);
      return this._discardPendingGroupSecretUnlocked(aid, groupId, epoch, rid);
    });
  }

  async deleteGroupSecretState(aid: string, groupId: string): Promise<void> {
    await this._withAidLock(aid, async () => {
      await idbDelete(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId));
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid, groupId))) {
        await idbDelete(STORE_GROUP_OLD_EPOCHS, item.key);
      }
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

  /**
   * 读取单个 metadata KV（如 gateway_url 等跨进程缓存项）。
   * 不存在时返回空字符串，与 Python keystore 的 get_metadata 语义保持一致。
   */
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

  /**
   * 写入单个 metadata KV。空字符串视为删除该字段。
   * 与 _saveMetadataOnlyUnlocked 不同，本方法只更新指定 key，不影响其他字段。
   */
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

  async deleteSeq(aid: string, deviceId: string, slotId: string, namespace: string): Promise<void> {
    const key = seqTrackerStoreKey(aid, deviceId, slotId, namespace);
    await idbDelete(STORE_INSTANCE_STATE, key);
  }

  // ── agent.md Cache ───────────────────────────────────────

  async loadAgentMdCache(ownerAid: string, targetAid: string): Promise<AgentMdCacheRecord | null> {
    const owner = String(ownerAid ?? '').trim();
    const target = String(targetAid ?? '').trim();
    if (!owner || !target) return null;
    const data = await idbGet<JsonObject>(STORE_AGENT_MD_CACHE, agentMdCacheStoreKey(owner, target));
    const record = normalizeAgentMdCacheRecord(target, data);
    return record ? deepClone(record) : null;
  }

  async upsertAgentMdCache(ownerAid: string, targetAid: string, fields: AgentMdCacheUpsert): Promise<AgentMdCacheRecord> {
    const owner = String(ownerAid ?? '').trim();
    const target = String(targetAid ?? '').trim();
    if (!owner || !target) {
      throw new Error('upsertAgentMdCache requires ownerAid and targetAid');
    }
    const current = await this.loadAgentMdCache(owner, target);
    const record = mergeAgentMdCacheRecord(target, current, fields ?? {});
    await idbPut(STORE_AGENT_MD_CACHE, agentMdCacheStoreKey(owner, target), record);
    return deepClone(record);
  }

  async listAgentMdContentAids(agentMdPath: string): Promise<string[]> {
    const root = String(agentMdPath ?? '').trim();
    if (!root) return [];
    const prefix = agentMdCachePrefix(root);
    const suffix = '/agent.md';
    const aids = new Set<string>();
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_AGENT_MD_CACHE, prefix)) {
      const encodedTarget = item.key.slice(prefix.length);
      let target = '';
      try {
        target = decodeURIComponent(encodedTarget);
      } catch {
        target = encodedTarget;
      }
      if (!target.endsWith(suffix)) continue;
      const aid = target.slice(0, -suffix.length).trim();
      if (aid) aids.add(aid);
    }
    return [...aids].sort();
  }

  // ── Group State（群组状态快照） ─────────────────────────────

  async saveGroupState(groupId: string, state: GroupStateRecord): Promise<void> {
    const key = encodePart(groupId);
    await idbPut(STORE_GROUP_STATE, key, {
      group_id: groupId,
      state_version: state.state_version,
      state_hash: state.state_hash,
      key_epoch: state.key_epoch,
      membership_json: state.membership_json,
      policy_json: state.policy_json,
      updated_at: state.updated_at ?? Date.now(),
    });
  }

  async loadGroupState(groupId: string): Promise<GroupStateRecord | null> {
    const key = encodePart(groupId);
    const data = await idbGet<GroupStateRecord>(STORE_GROUP_STATE, key);
    if (!data || typeof data.state_version !== 'number') return null;
    return {
      group_id: groupId,
      state_version: data.state_version,
      state_hash: data.state_hash ?? '',
      key_epoch: data.key_epoch ?? 0,
      membership_json: data.membership_json ?? '[]',
      policy_json: data.policy_json ?? '{}',
      updated_at: data.updated_at ?? 0,
    };
  }

  // ── Trust Root Storage（信任根证书存储） ─────────────────
  // 浏览器环境无文件系统，统一存入 STORE_INSTANCE_STATE 并以特定前缀的 key 区分。
  // 对外返回的"路径"为虚拟标识（indexeddb://...），仅用于日志/兼容字段。

  private static readonly _TRUST_LIST_KEY = '__trust_roots:list';
  private static readonly _TRUST_BUNDLE_KEY = '__trust_roots:bundle';
  private static readonly _TRUST_CERT_PREFIX = '__trust_roots:cert:';
  private static readonly _TRUST_ISSUER_PREFIX = '__trust_roots:issuer:';

  /** 计算 PEM 证书的 SHA-256 指纹（hex，无冒号） */
  private async _pemFingerprint(pem: string): Promise<string> {
    try {
      const der = new Uint8Array(pemToArrayBuffer(pem));
      const hash = await crypto.subtle.digest('SHA-256', der);
      return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    } catch {
      const enc = new TextEncoder().encode(pem);
      const hash = await crypto.subtle.digest('SHA-256', enc);
      return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    }
  }

  /** 拆分 bundle PEM 文本为单个 PEM 证书数组 */
  private _splitPemBundle(bundleText: string): string[] {
    return bundleText
      .split(/(?<=-----END CERTIFICATE-----)\s*/)
      .map(s => s.trim())
      .filter(s => s.startsWith('-----BEGIN CERTIFICATE-----'));
  }

  async saveTrustRoots(
    trustList: Record<string, unknown>,
    rootCerts: Array<{ id?: string; cert_pem: string; fingerprint_sha256?: string }>,
  ): Promise<string> {
    for (let i = 0; i < rootCerts.length; i++) {
      const item = rootCerts[i];
      const certId = item.id || item.fingerprint_sha256 || `root-${i + 1}`;
      const safeName = certId.replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120);
      await idbPut(STORE_INSTANCE_STATE, IndexedDBTokenStore._TRUST_CERT_PREFIX + safeName, item.cert_pem);
    }

    const bundle = rootCerts.map(i => i.cert_pem.trim()).join('\n') + '\n';
    await idbPut(STORE_INSTANCE_STATE, IndexedDBTokenStore._TRUST_BUNDLE_KEY, bundle);

    await idbPut(STORE_INSTANCE_STATE, IndexedDBTokenStore._TRUST_LIST_KEY, deepClone(trustList));

    return 'indexeddb://trust-roots/bundle';
  }

  async saveIssuerRootCert(
    issuer: string,
    certPem: string,
    fingerprintSha256: string = '',
  ): Promise<[string, string]> {
    const safeIssuer = (issuer || 'issuer').replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120);
    const certKey = IndexedDBTokenStore._TRUST_ISSUER_PREFIX + safeIssuer;
    const normalizedPem = certPem.trim() + '\n';

    await idbPut(STORE_INSTANCE_STATE, certKey, normalizedPem);

    const existingPems = new Map<string, string>();
    const existingBundle = await idbGet<string>(STORE_INSTANCE_STATE, IndexedDBTokenStore._TRUST_BUNDLE_KEY);
    if (typeof existingBundle === 'string' && existingBundle) {
      for (const pem of this._splitPemBundle(existingBundle)) {
        const fp = await this._pemFingerprint(pem);
        existingPems.set(fp, pem);
      }
    }

    let newFp = await this._pemFingerprint(normalizedPem);
    if (fingerprintSha256) {
      newFp = fingerprintSha256.toLowerCase().replace(/^sha256:/, '');
    }
    existingPems.set(newFp, normalizedPem);

    const merged = Array.from(existingPems.values()).map(p => p.trim()).join('\n') + '\n';
    await idbPut(STORE_INSTANCE_STATE, IndexedDBTokenStore._TRUST_BUNDLE_KEY, merged);

    return [`indexeddb://trust-roots/issuers/${safeIssuer}`, 'indexeddb://trust-roots/bundle'];
  }

  async loadTrustRoots(): Promise<Record<string, unknown> | null> {
    const data = await idbGet<JsonObject>(STORE_INSTANCE_STATE, IndexedDBTokenStore._TRUST_LIST_KEY);
    if (!isRecord(data)) return null;
    return deepClone(data);
  }

  // ── 内部辅助 ─────────────────────────────────────────

  private async _loadMetadataOnlyUnlocked(aid: string): Promise<MetadataRecord | null> {
    const data = await idbGet<JsonObject>(STORE_METADATA, metadataStoreKey(aid));
    return isRecord(data) ? deepClone(data) : null;
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

  private async _loadPrekeyByIdUnlocked(aid: string, prekeyId: string): Promise<Record<string, unknown> | null> {
    if (!prekeyId) return null;
    const directKey = prekeyStoreKey(aid, prekeyId, '');
    const direct = await idbGet<JsonObject>(STORE_PREKEYS, directKey);
    if (isRecord(direct)) {
      const record = deepClone(direct);
      delete record.prekey_id;
      delete record.device_id;
      return record;
    }
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_PREKEYS, prekeyPrefix(aid))) {
      if (!isRecord(item.value)) continue;
      const itemPrekeyId = typeof item.value.prekey_id === 'string' ? item.value.prekey_id : '';
      if (itemPrekeyId !== prekeyId) continue;
      const record = deepClone(item.value);
      delete record.prekey_id;
      delete record.device_id;
      return record;
    }
    return null;
  }

  private async _replacePrekeysUnlocked(aid: string, prekeys: PrekeyMap, deviceId = ''): Promise<void> {
    const desired = new Set(Object.keys(prekeys));
    const normalizedDeviceId = String(deviceId ?? '').trim();
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_PREKEYS, prekeyPrefix(aid))) {
      if (!isRecord(item.value)) continue;
      const recordDeviceId = String(item.value.device_id ?? '').trim();
      if (recordDeviceId !== normalizedDeviceId) continue;
      const prekeyId = typeof item.value.prekey_id === 'string' ? item.value.prekey_id : '';
      const canonicalKey = prekeyStoreKey(aid, prekeyId, normalizedDeviceId);
      if (!desired.has(prekeyId) || item.key !== canonicalKey) {
        await idbDelete(STORE_PREKEYS, item.key);
      }
    }
    for (const [prekeyId, prekeyData] of Object.entries(prekeys)) {
      const record = deepClone(prekeyData);
      if (normalizedDeviceId) { record.device_id = normalizedDeviceId; } else { delete record.device_id; }
      await idbPut(STORE_PREKEYS, prekeyStoreKey(aid, prekeyId, normalizedDeviceId), { ...record, prekey_id: prekeyId });
    }
  }

  private async _loadGroupEntriesUnlocked(aid: string): Promise<LegacyGroupSecretMap> {
    const result: LegacyGroupSecretMap = {};
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
      const groupId = typeof item.value.group_id === 'string' ? item.value.group_id : '';
      if (!groupId) continue;
      const record = deepClone(item.value);
      delete record.group_id;
      const entry = result[groupId] ?? {};
      const oldEpochs = Array.isArray(entry.old_epochs) ? entry.old_epochs as GroupOldEpochRecord[] : [];
      oldEpochs.push(record);
      oldEpochs.sort((a, b) => Number(a.epoch ?? 0) - Number(b.epoch ?? 0));
      entry.old_epochs = oldEpochs;
      result[groupId] = entry;
    }
    return result;
  }

  private async _replaceGroupEntriesUnlocked(aid: string, groups: LegacyGroupSecretMap): Promise<void> {
    const desiredGroups = new Set(Object.keys(groups));
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_CURRENT, groupCurrentPrefix(aid))) {
      const groupId = isRecord(item.value) && typeof item.value.group_id === 'string'
        ? item.value.group_id
        : item.key.slice(groupCurrentPrefix(aid).length);
      if (!desiredGroups.has(groupId)) await idbDelete(STORE_GROUP_CURRENT, item.key);
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

  private async _saveSingleGroupEntryUnlocked(aid: string, groupId: string, entry: GroupSecretRecord): Promise<void> {
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid, groupId))) {
      if (!isRecord(item.value)) continue;
      if (typeof item.value.group_id === 'string' && item.value.group_id === groupId) {
        await idbDelete(STORE_GROUP_OLD_EPOCHS, item.key);
      }
    }
    const current = deepClone(entry);
    const oldEpochs = Array.isArray(current.old_epochs) ? current.old_epochs as GroupOldEpochRecord[] : [];
    delete current.old_epochs;
    if (typeof current.epoch === 'number') {
      await idbPut(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId), { ...current, group_id: groupId });
    } else {
      await idbDelete(STORE_GROUP_CURRENT, groupCurrentStoreKey(aid, groupId));
    }
    for (const oldEpoch of oldEpochs) {
      if (!isRecord(oldEpoch) || typeof oldEpoch.epoch !== 'number') continue;
      await idbPut(STORE_GROUP_OLD_EPOCHS, groupOldStoreKey(aid, groupId, oldEpoch.epoch), {
        ...deepClone(oldEpoch), group_id: groupId,
      });
    }
  }

  private async _storeGroupSecretTransitionUnlocked(
    aid: string,
    groupId: string,
    opts: {
      epoch: number;
      secret: string;
      commitment: string;
      memberAids: string[];
      epochChain?: string;
      pendingRotationId?: string;
      epochChainUnverified?: boolean | null;
      epochChainUnverifiedReason?: string | null;
      oldEpochRetentionMs: number;
    },
  ): Promise<boolean> {
    const currentKey = groupCurrentStoreKey(aid, groupId);
    const currentRaw = await idbGet<JsonObject>(STORE_GROUP_CURRENT, currentKey);
    const now = Date.now();
    const epoch = Number(opts.epoch);
    const members = [...(opts.memberAids ?? [])].map((item) => String(item)).sort();
    const pendingRotationId = String(opts.pendingRotationId ?? '').trim();

    if (isRecord(currentRaw)) {
      const current = deepClone(currentRaw) as GroupSecretRecord;
      delete current.group_id;
      const localEpoch = Number(current.epoch ?? 0);
      if (epoch < localEpoch) return false;
      if (epoch === localEpoch && typeof current.secret === 'string') {
        if (current.secret !== opts.secret) {
          if (String(current.pending_rotation_id ?? '').trim()) {
            await idbPut(STORE_GROUP_CURRENT, currentKey, {
              ...this._buildGroupCurrentRecord(groupId, opts, members, now),
            });
            return true;
          }
          return false;
        }

        const updated: GroupSecretRecord = { ...current };
        let changed = false;
        const oldMembers = Array.isArray(updated.member_aids) ? updated.member_aids.map(String).sort() : [];
        if (members.length > 0 && JSON.stringify(oldMembers) !== JSON.stringify(members)) {
          updated.member_aids = members;
          updated.commitment = opts.commitment;
          updated.updated_at = now;
          changed = true;
        }
        if (opts.epochChain !== undefined && updated.epoch_chain !== opts.epochChain) {
          updated.epoch_chain = opts.epochChain;
          updated.updated_at = now;
          changed = true;
        }
        if (opts.epochChainUnverified === true) {
          if (updated.epoch_chain_unverified !== true) {
            updated.epoch_chain_unverified = true;
            changed = true;
          }
          if (opts.epochChainUnverifiedReason && updated.epoch_chain_unverified_reason !== opts.epochChainUnverifiedReason) {
            updated.epoch_chain_unverified_reason = opts.epochChainUnverifiedReason;
            changed = true;
          }
        } else if (opts.epochChainUnverified === false) {
          if ('epoch_chain_unverified' in updated || 'epoch_chain_unverified_reason' in updated) {
            delete updated.epoch_chain_unverified;
            delete updated.epoch_chain_unverified_reason;
            changed = true;
          }
        }
        if (pendingRotationId && updated.pending_rotation_id !== pendingRotationId) {
          updated.pending_rotation_id = pendingRotationId;
          updated.pending_created_at = now;
          changed = true;
        }
        if (!pendingRotationId && updated.pending_rotation_id) {
          delete updated.pending_rotation_id;
          delete updated.pending_created_at;
          changed = true;
        }
        if (changed) {
          await idbPut(STORE_GROUP_CURRENT, currentKey, { ...updated, group_id: groupId });
        }
        return true;
      }

      if (localEpoch !== epoch) {
        const oldEntry = { ...current };
        oldEntry.expires_at = Number(current.updated_at ?? now) + opts.oldEpochRetentionMs;
        await idbPut(STORE_GROUP_OLD_EPOCHS, groupOldStoreKey(aid, groupId, localEpoch), {
          ...oldEntry,
          group_id: groupId,
        });
      } else {
        const merged = { ...current, ...this._buildGroupCurrentRecord(groupId, opts, members, now) };
        if (!opts.epochChain && current.epoch_chain) {
          merged.epoch_chain = current.epoch_chain;
        }
        if (current.pending_rotation_id && !opts.pendingRotationId) {
          merged.pending_rotation_id = current.pending_rotation_id;
          if (current.pending_created_at) merged.pending_created_at = current.pending_created_at;
        }
        await idbPut(STORE_GROUP_CURRENT, currentKey, merged);
        return true;
      }
    }

    await idbPut(STORE_GROUP_CURRENT, currentKey, {
      ...this._buildGroupCurrentRecord(groupId, opts, members, now),
    });
    return true;
  }

  private async _storeGroupSecretEpochUnlocked(
    aid: string,
    groupId: string,
    opts: {
      epoch: number;
      secret: string;
      commitment: string;
      memberAids: string[];
      epochChain?: string;
      pendingRotationId?: string;
      epochChainUnverified?: boolean | null;
      epochChainUnverifiedReason?: string | null;
      oldEpochRetentionMs: number;
    },
  ): Promise<boolean> {
    const now = Date.now();
    const epoch = Number(opts.epoch);
    const members = [...(opts.memberAids ?? [])].map((item) => String(item)).sort();
    const pendingRotationId = String(opts.pendingRotationId ?? '').trim();
    const currentKey = groupCurrentStoreKey(aid, groupId);
    const currentRaw = await idbGet<JsonObject>(STORE_GROUP_CURRENT, currentKey);
    const newRecord = this._buildGroupCurrentRecord(groupId, opts, members, now);

    if (!isRecord(currentRaw)) {
      await idbPut(STORE_GROUP_CURRENT, currentKey, newRecord);
      return true;
    }

    const current = deepClone(currentRaw) as GroupSecretRecord;
    delete current.group_id;
    const localEpoch = Number(current.epoch ?? 0);
    if (epoch > localEpoch) {
      const expiresAt = Date.now() + (opts.oldEpochRetentionMs ?? 604800_000);
      const oldRecord = { ...current, group_id: groupId, expires_at: expiresAt };
      const oldKey = groupOldStoreKey(aid, groupId, localEpoch);
      await idbPut(STORE_GROUP_OLD_EPOCHS, oldKey, oldRecord);
      await idbPut(STORE_GROUP_CURRENT, currentKey, newRecord);
      return true;
    }

    if (epoch === localEpoch) {
      if (typeof current.secret === 'string' && current.secret !== opts.secret) {
        if (!String(current.pending_rotation_id ?? '').trim()) return false;
        await idbPut(STORE_GROUP_CURRENT, currentKey, newRecord);
        return true;
      }
      const updated: GroupSecretRecord = { ...current };
      let changed = false;
      const oldMembers = Array.isArray(updated.member_aids) ? updated.member_aids.map(String).sort() : [];
      if (members.length > 0 && JSON.stringify(oldMembers) !== JSON.stringify(members)) {
        updated.member_aids = members;
        updated.commitment = opts.commitment;
        updated.updated_at = now;
        changed = true;
      }
      if (opts.epochChain !== undefined && updated.epoch_chain !== opts.epochChain) {
        updated.epoch_chain = opts.epochChain;
        updated.updated_at = now;
        changed = true;
      }
      if (opts.epochChainUnverified === true) {
        if (updated.epoch_chain_unverified !== true) {
          updated.epoch_chain_unverified = true;
          changed = true;
        }
        if (opts.epochChainUnverifiedReason && updated.epoch_chain_unverified_reason !== opts.epochChainUnverifiedReason) {
          updated.epoch_chain_unverified_reason = opts.epochChainUnverifiedReason;
          changed = true;
        }
      } else if (opts.epochChainUnverified === false) {
        if ('epoch_chain_unverified' in updated || 'epoch_chain_unverified_reason' in updated) {
          delete updated.epoch_chain_unverified;
          delete updated.epoch_chain_unverified_reason;
          changed = true;
        }
      }
      if (pendingRotationId && updated.pending_rotation_id !== pendingRotationId) {
        updated.pending_rotation_id = pendingRotationId;
        updated.pending_created_at = now;
        changed = true;
      }
      if (!pendingRotationId && updated.pending_rotation_id) {
        delete updated.pending_rotation_id;
        delete updated.pending_created_at;
        changed = true;
      }
      if (changed) await idbPut(STORE_GROUP_CURRENT, currentKey, { ...updated, group_id: groupId });
      return true;
    }

    const oldKey = groupOldStoreKey(aid, groupId, epoch);
    const oldRaw = await idbGet<JsonObject>(STORE_GROUP_OLD_EPOCHS, oldKey);
    if (isRecord(oldRaw)) {
      const old = deepClone(oldRaw) as GroupSecretRecord;
      if (typeof old.secret === 'string' && old.secret !== opts.secret) return false;
    }
    await idbPut(STORE_GROUP_OLD_EPOCHS, oldKey, {
      ...newRecord,
      epoch,
      expires_at: now + opts.oldEpochRetentionMs,
    });
    return true;
  }

  private async _discardPendingGroupSecretUnlocked(
    aid: string,
    groupId: string,
    epoch: number,
    rotationId: string,
  ): Promise<boolean> {
    const currentKey = groupCurrentStoreKey(aid, groupId);
    const currentRaw = await idbGet<JsonObject>(STORE_GROUP_CURRENT, currentKey);
    if (!isRecord(currentRaw)) return false;
    const current = deepClone(currentRaw) as GroupSecretRecord;
    if (Number(current.epoch ?? 0) !== Number(epoch)) return false;
    if (String(current.pending_rotation_id ?? '').trim() !== rotationId) return false;

    let restored: GroupSecretRecord | null = null;
    let restoredKey = '';
    for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid, groupId))) {
      if (!isRecord(item.value)) continue;
      const old = deepClone(item.value) as GroupSecretRecord;
      const oldEpoch = Number(old.epoch ?? 0);
      if (oldEpoch >= Number(epoch) || !old.secret) continue;
      if (!restored || oldEpoch > Number(restored.epoch ?? 0)) {
        restored = old;
        restoredKey = item.key;
      }
    }
    if (!restored) {
      await idbDelete(STORE_GROUP_CURRENT, currentKey);
      for (const item of await idbGetAllByPrefix<JsonObject>(STORE_GROUP_OLD_EPOCHS, groupOldPrefix(aid, groupId))) {
        await idbDelete(STORE_GROUP_OLD_EPOCHS, item.key);
      }
      return true;
    }
    delete restored.group_id;
    delete restored.expires_at;
    await idbPut(STORE_GROUP_CURRENT, currentKey, { ...restored, group_id: groupId, updated_at: Date.now() });
    if (restoredKey) await idbDelete(STORE_GROUP_OLD_EPOCHS, restoredKey);
    return true;
  }

  private _buildGroupCurrentRecord(
    groupId: string,
    opts: {
      epoch: number;
      secret: string;
      commitment: string;
      pendingRotationId?: string;
      epochChain?: string;
      epochChainUnverified?: boolean | null;
      epochChainUnverifiedReason?: string | null;
    },
    memberAids: string[],
    now: number,
  ): GroupSecretRecord {
    const record: GroupSecretRecord = {
      group_id: groupId,
      epoch: opts.epoch,
      secret: opts.secret,
      commitment: opts.commitment,
      member_aids: memberAids,
      updated_at: now,
    };
    if (opts.epochChain !== undefined) record.epoch_chain = opts.epochChain;
    const pendingRotationId = String(opts.pendingRotationId ?? '').trim();
    if (pendingRotationId) {
      record.pending_rotation_id = pendingRotationId;
      record.pending_created_at = now;
    }
    if (opts.epochChainUnverified === true) {
      record.epoch_chain_unverified = true;
      if (opts.epochChainUnverifiedReason) record.epoch_chain_unverified_reason = opts.epochChainUnverifiedReason;
    }
    return record;
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
          this._preferNewerGroupEpochRecord(oldByEpoch.get(current.epoch as number), current),
        );
        current = incomingCurrent;
      } else if ((incomingCurrent.epoch as number) === (current.epoch as number)) {
        current = this._preferNewerGroupEpochRecord(current, incomingCurrent);
      } else {
        oldByEpoch.set(
          incomingCurrent.epoch as number,
          this._preferNewerGroupEpochRecord(oldByEpoch.get(incomingCurrent.epoch as number), incomingCurrent),
        );
      }
    }

    const incomingOldEpochs = Array.isArray(incoming.old_epochs) ? incoming.old_epochs as GroupOldEpochRecord[] : [];
    for (const rawOld of incomingOldEpochs) {
      if (typeof rawOld.epoch !== 'number' || !this._isGroupEpochRecoverable(rawOld)) continue;
      oldByEpoch.set(rawOld.epoch, this._preferNewerGroupEpochRecord(oldByEpoch.get(rawOld.epoch), rawOld));
    }

    const merged: GroupSecretRecord = current ? deepClone(current) : {};
    if (current && typeof current.epoch === 'number') {
      oldByEpoch.delete(current.epoch);
    }
    if (oldByEpoch.size > 0) {
      merged.old_epochs = [...oldByEpoch.entries()].sort(([a], [b]) => a - b).map(([, value]) => deepClone(value));
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
    const secret = record.secret;
    if (!secret || (typeof secret === 'string' && secret.length === 0)) return false;
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
}
