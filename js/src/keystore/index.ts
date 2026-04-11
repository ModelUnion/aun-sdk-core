// ── KeyStore 接口定义 ──────────────────────────────────────

import type {
  GroupSecretMap,
  GroupSecretRecord,
  IdentityRecord,
  KeyPairRecord,
  MetadataRecord,
  PrekeyMap,
  PrekeyRecord,
} from '../types.js';

/**
 * 密钥存储接口（浏览器版本 — 所有方法均为异步）。
 *
 * 与 Python SDK 的 KeyStore Protocol 等价，但由于 IndexedDB
 * 的异步特性，所有方法返回 Promise。
 */
export interface KeyStore {
  /** 加载密钥对 */
  loadKeyPair(aid: string): Promise<KeyPairRecord | null>;
  /** 保存密钥对 */
  saveKeyPair(aid: string, keyPair: KeyPairRecord): Promise<void>;
  /** 加载证书 PEM */
  loadCert(aid: string): Promise<string | null>;
  /** 保存证书 PEM */
  saveCert(aid: string, certPem: string): Promise<void>;
  /** 加载 metadata */
  loadMetadata(aid: string): Promise<MetadataRecord | null>;
  /** 保存 metadata */
  saveMetadata(aid: string, metadata: MetadataRecord): Promise<void>;
  /** 加载完整身份信息 */
  loadIdentity(aid: string): Promise<IdentityRecord | null>;
  /** 保存完整身份信息 */
  saveIdentity(aid: string, identity: IdentityRecord): Promise<void>;

  /** 加载结构化 prekeys 主存 */
  loadE2EEPrekeys?(aid: string): Promise<PrekeyMap>;
  /** 保存单个结构化 prekey 主存记录 */
  saveE2EEPrekey?(aid: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void>;
  /** 清理过期结构化 prekeys */
  cleanupE2EEPrekeys?(aid: string, cutoffMs: number, keepLatest?: number): Promise<string[]>;

  /** 加载单个群组结构化密钥状态 */
  loadGroupSecretState?(aid: string, groupId: string): Promise<GroupSecretRecord | null>;
  /** 加载全部群组结构化密钥状态 */
  loadAllGroupSecretStates?(aid: string): Promise<GroupSecretMap>;
  /** 保存单个群组结构化密钥状态 */
  saveGroupSecretState?(aid: string, groupId: string, entry: GroupSecretRecord): Promise<void>;
  /** 清理单个群组过期 old epochs */
  cleanupGroupOldEpochsState?(aid: string, groupId: string, cutoffMs: number): Promise<number>;
}
