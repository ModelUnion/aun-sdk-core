// ── KeyStore 接口定义 ──────────────────────────────────────

import type {
  GroupSecretMap,
  GroupSecretRecord,
  IdentityRecord,
  KeyPairRecord,
  MetadataRecord,
  PrekeyMap,
  PrekeyRecord,
  SessionRecord,
} from '../types.js';

/**
 * 密钥存储接口（浏览器版本 — 所有方法均为异步）。
 *
 * 与 Python SDK 的 KeyStore Protocol 等价，但由于 IndexedDB
 * 的异步特性，所有方法返回 Promise。
 */
export interface KeyStore {
  /** 列出本地已有身份 */
  listIdentities?(): Promise<string[]>;
  /** 加载密钥对 */
  loadKeyPair(aid: string): Promise<KeyPairRecord | null>;
  /** 保存密钥对 */
  saveKeyPair(aid: string, keyPair: KeyPairRecord): Promise<void>;
  /** 加载证书 PEM */
  loadCert(aid: string, certFingerprint?: string): Promise<string | null>;
  /** 保存证书 PEM */
  saveCert(
    aid: string,
    certPem: string,
    certFingerprint?: string,
    opts?: { makeActive?: boolean },
  ): Promise<void>;
  /** 加载完整身份信息 */
  loadIdentity(aid: string): Promise<IdentityRecord | null>;
  /** 保存完整身份信息 */
  saveIdentity(aid: string, identity: IdentityRecord): Promise<void>;
  /** 加载实例级状态 */
  loadInstanceState?(aid: string, deviceId: string, slotId?: string): Promise<MetadataRecord | null>;
  /** 保存实例级状态 */
  saveInstanceState?(aid: string, deviceId: string, slotId: string, state: MetadataRecord): Promise<void>;
  /** 原子更新实例级状态 */
  updateInstanceState?(
    aid: string,
    deviceId: string,
    slotId: string,
    updater: (state: MetadataRecord) => MetadataRecord | void,
  ): Promise<MetadataRecord>;

  /** 加载结构化 prekeys 主存 */
  loadE2EEPrekeys?(aid: string): Promise<PrekeyMap>;
  /** 按 device_id 加载结构化 prekeys 主存 */
  loadE2EEPrekeysForDevice?(aid: string, deviceId: string): Promise<PrekeyMap>;
  /** 保存单个结构化 prekey 主存记录 */
  saveE2EEPrekey?(aid: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void>;
  /** 按 device_id 保存单个结构化 prekey 主存记录 */
  saveE2EEPrekeyForDevice?(aid: string, deviceId: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void>;
  /** 清理过期结构化 prekeys */
  cleanupE2EEPrekeys?(aid: string, cutoffMs: number, keepLatest?: number): Promise<string[]>;
  /** 按 device_id 清理过期结构化 prekeys */
  cleanupE2EEPrekeysForDevice?(aid: string, deviceId: string, cutoffMs: number, keepLatest?: number): Promise<string[]>;

  /** 加载单个群组结构化密钥状态 */
  loadGroupSecretState?(aid: string, groupId: string): Promise<GroupSecretRecord | null>;
  /** 加载全部群组结构化密钥状态 */
  loadAllGroupSecretStates?(aid: string): Promise<GroupSecretMap>;
  /** 保存单个群组结构化密钥状态 */
  saveGroupSecretState?(aid: string, groupId: string, entry: GroupSecretRecord): Promise<void>;
  /** 清理单个群组过期 old epochs */
  cleanupGroupOldEpochsState?(aid: string, groupId: string, cutoffMs: number): Promise<number>;

  /** 加载全部 E2EE sessions */
  loadE2EESessions?(aid: string): Promise<SessionRecord[]>;
  /** 保存单个 E2EE session */
  saveE2EESession?(aid: string, sessionId: string, data: SessionRecord): Promise<void>;

  /** 保存单个 namespace 的 contiguous_seq */
  saveSeq?(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): Promise<void>;
  /** 加载单个 namespace 的 contiguous_seq */
  loadSeq?(aid: string, deviceId: string, slotId: string, namespace: string): Promise<number>;
  /** 加载某 device+slot 下所有 namespace 的 contiguous_seq */
  loadAllSeqs?(aid: string, deviceId: string, slotId: string): Promise<Record<string, number>>;
}
