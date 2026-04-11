/**
 * KeyStore 接口定义
 *
 * 与 Python SDK 的 KeyStore Protocol 完全对齐。
 */

import type {
  GroupSecretMap,
  GroupSecretRecord,
  IdentityRecord,
  KeyPairRecord,
  MetadataRecord,
  PrekeyMap,
  PrekeyRecord,
} from '../types.js';

export interface KeyStore {
  /** 加载密钥对 */
  loadKeyPair(aid: string): KeyPairRecord | null;
  /** 保存密钥对 */
  saveKeyPair(aid: string, keyPair: KeyPairRecord): void;
  /** 加载证书 */
  loadCert(aid: string): string | null;
  /** 保存证书 */
  saveCert(aid: string, certPem: string): void;
  /** 加载元数据 */
  loadMetadata(aid: string): MetadataRecord | null;
  /** 保存元数据 */
  saveMetadata(aid: string, metadata: MetadataRecord): void;
  /** 加载完整身份信息 */
  loadIdentity(aid: string): IdentityRecord | null;
  /** 保存完整身份信息 */
  saveIdentity(aid: string, identity: IdentityRecord): void;

  /** 加载结构化 prekeys 主存 */
  loadE2EEPrekeys?(aid: string): PrekeyMap;
  /** 保存单个结构化 prekey 主存记录 */
  saveE2EEPrekey?(aid: string, prekeyId: string, prekeyData: PrekeyRecord): void;
  /** 清理过期结构化 prekeys */
  cleanupE2EEPrekeys?(aid: string, cutoffMs: number, keepLatest?: number): string[];

  /** 加载单个群组结构化密钥状态 */
  loadGroupSecretState?(aid: string, groupId: string): GroupSecretRecord | null;
  /** 加载全部群组结构化密钥状态 */
  loadAllGroupSecretStates?(aid: string): GroupSecretMap;
  /** 保存单个群组结构化密钥状态 */
  saveGroupSecretState?(aid: string, groupId: string, entry: GroupSecretRecord): void;
  /** 清理单个群组过期 old epochs */
  cleanupGroupOldEpochsState?(aid: string, groupId: string, cutoffMs: number): number;
}
