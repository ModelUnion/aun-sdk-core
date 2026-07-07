// ── IndexedDB TokenStore 实现 ──────────────────────────────
// 不含私钥操作：证书、实例态、seq、信任根、metadata、agent.md 缓存和群组状态。
// AUNClient / AuthFlow 持有此类型。
//
// 与 IndexedDBIdentityStore 共用同一 IndexedDB 数据库（aun-keystore），
// 但二者之间无任何代码依赖——共享基础设施集中在 indexeddb-shared.ts。

import type { ModuleLogger } from '../logger.js';
import { pemToArrayBuffer } from '../crypto.js';
import { convertToGroupAid } from '../group-id.js';
import type { AgentMdCacheRecord, AgentMdCacheUpsert, GroupIndexCacheRecord, GroupIndexCacheUpsert, TokenStore, GroupStateRecord } from './index.js';
import {
  _noopLog,
  STORE_CERTS,
  STORE_METADATA,
  STORE_INSTANCE_STATE,
  STORE_GROUP_STATE,
  STORE_AGENT_MD_CACHE,
  STORE_GROUP_INDEX_CACHE,
  safeAid,
  encodePart,
  deepClone,
  isRecord,
  metadataStoreKey,
  normalizeCertFingerprint,
  fingerprintFromCertPem,
  certStoreKey,
  instanceStateStoreKey,
  seqTrackerPrefix,
  seqTrackerStoreKey,
  agentMdCachePrefix,
  agentMdCacheStoreKey,
  groupIndexCacheStoreKey,
  stripStructuredFields,
  normalizeAgentMdCacheRecord,
  mergeAgentMdCacheRecord,
  normalizeGroupIndexCacheRecord,
  mergeGroupIndexCacheRecord,
  idbGet,
  idbGetAllByPrefix,
  idbPut,
  idbDelete,
  type JsonObject,
  type MetadataRecord,
} from './indexeddb-shared.js';

function groupLookupCandidates(groupId: string, localIssuer = ''): string[] {
  const raw = String(groupId ?? '').trim();
  if (!raw) return [];
  const normalized = convertToGroupAid(raw, { localIssuer });
  const candidates: string[] = [];
  const add = (value: string) => {
    const trimmed = String(value ?? '').trim();
    if (trimmed && !candidates.includes(trimmed)) candidates.push(trimmed);
  };
  add(raw);
  add(normalized);
  const dotIdx = normalized.indexOf('.');
  if (dotIdx > 0 && dotIdx < normalized.length - 1) {
    const base = normalized.slice(0, dotIdx);
    const issuer = normalized.slice(dotIdx + 1);
    add(`group.${issuer}/${base}`);
    add(`${base}@${issuer}`);
    if (localIssuer && issuer === localIssuer.replace(/^\.+|\.+$/g, '').toLowerCase()) add(base);
  }
  return candidates;
}

/**
 * 基于 IndexedDB 的 TokenStore 实现（不含私钥操作）。
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

  // ── group.index Cache ───────────────────────────────────

  async loadGroupIndexCache(localAid: string, groupAid: string): Promise<GroupIndexCacheRecord | null> {
    const local = String(localAid ?? '').trim();
    const group = String(groupAid ?? '').trim();
    if (!local || !group) return null;
    const data = await idbGet<JsonObject>(STORE_GROUP_INDEX_CACHE, groupIndexCacheStoreKey(local, group));
    const record = normalizeGroupIndexCacheRecord(local, group, data);
    return record ? deepClone(record) : null;
  }

  async upsertGroupIndexCache(localAid: string, groupAid: string, fields: GroupIndexCacheUpsert): Promise<GroupIndexCacheRecord> {
    const local = String(localAid ?? '').trim();
    const group = String(groupAid ?? '').trim();
    if (!local || !group) {
      throw new Error('upsertGroupIndexCache requires localAid and groupAid');
    }
    const current = await this.loadGroupIndexCache(local, group);
    const record = mergeGroupIndexCacheRecord(local, group, current, fields ?? {});
    await idbPut(STORE_GROUP_INDEX_CACHE, groupIndexCacheStoreKey(local, group), record);
    return deepClone(record);
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
    for (const candidate of groupLookupCandidates(groupId)) {
      const key = encodePart(candidate);
      const data = await idbGet<GroupStateRecord>(STORE_GROUP_STATE, key);
      if (!data || typeof data.state_version !== 'number') continue;
      const storedGroupId = typeof data.group_id === 'string' ? data.group_id : candidate;
      return {
        group_id: storedGroupId,
        group_aid: convertToGroupAid(storedGroupId),
        state_version: data.state_version,
        state_hash: data.state_hash ?? '',
        key_epoch: data.key_epoch ?? 0,
        membership_json: data.membership_json ?? '[]',
        policy_json: data.policy_json ?? '{}',
        updated_at: data.updated_at ?? 0,
      };
    }
    return null;
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

}
