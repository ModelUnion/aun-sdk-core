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
  SessionRecord,
} from '../types.js';

export interface KeyStore {
  /** 加载密钥对 */
  loadKeyPair(aid: string): KeyPairRecord | null;
  /** 保存密钥对 */
  saveKeyPair(aid: string, keyPair: KeyPairRecord): void;
  /** 加载证书 */
  loadCert(aid: string, certFingerprint?: string): string | null;
  /** 保存证书 */
  saveCert(
    aid: string,
    certPem: string,
    certFingerprint?: string,
    opts?: { makeActive?: boolean },
  ): void;
  /** 加载完整身份信息 */
  loadIdentity(aid: string): IdentityRecord | null;
  /** 保存完整身份信息 */
  saveIdentity(aid: string, identity: IdentityRecord): void;
  /** 加载实例级状态 */
  loadInstanceState?(aid: string, deviceId: string, slotId?: string): MetadataRecord | null;
  /** 保存实例级状态 */
  saveInstanceState?(aid: string, deviceId: string, slotId: string, state: MetadataRecord): void;
  /** 原子更新实例级状态 */
  updateInstanceState?(
    aid: string,
    deviceId: string,
    slotId: string,
    updater: (state: MetadataRecord) => MetadataRecord | void,
  ): MetadataRecord;

  /** 加载结构化 prekeys，deviceId 为空时等价于全局 */
  loadE2EEPrekeys?(aid: string, deviceId?: string): PrekeyMap;
  /** 保存单个 prekey，deviceId 为空时等价于全局 */
  saveE2EEPrekey?(aid: string, prekeyId: string, prekeyData: PrekeyRecord, deviceId?: string): void;
  /** 清理过期 prekeys，deviceId 为空时等价于全局 */
  cleanupE2EEPrekeys?(aid: string, cutoffMs: number, keepLatest?: number, deviceId?: string): string[];

  /** 加载单个群组结构化密钥状态 */
  loadGroupSecretState?(aid: string, groupId: string): GroupSecretRecord | null;
  /** 加载全部群组结构化密钥状态 */
  loadAllGroupSecretStates?(aid: string): GroupSecretMap;
  /** 保存单个群组结构化密钥状态 */
  saveGroupSecretState?(aid: string, groupId: string, entry: GroupSecretRecord): void;
  /** 清理单个群组过期 old epochs */
  cleanupGroupOldEpochsState?(aid: string, groupId: string, cutoffMs: number): number;
  /** 删除单个群组的所有密钥状态（群组解散时使用） */
  deleteGroupSecretState?(aid: string, groupId: string): void;

  /** 加载全部 E2EE sessions */
  loadE2EESessions?(aid: string): Array<Record<string, unknown>>;
  /** 保存单个 E2EE session */
  saveE2EESession?(aid: string, sessionId: string, data: Record<string, unknown>): void;

  /** 保存单个 namespace 的 contiguous_seq */
  saveSeq?(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): void;
  /** 加载单个 namespace 的 contiguous_seq */
  loadSeq?(aid: string, deviceId: string, slotId: string, namespace: string): number;
  /** 加载某 device+slot 下所有 namespace 的 contiguous_seq */
  loadAllSeqs?(aid: string, deviceId: string, slotId: string): Record<string, number>;

  // S2: 最近 ack seq（用作 SeqTracker 首条消息 baseline）。
  // 默认实现可直接复用 loadSeq/saveSeq（语义等价），实现方如已有独立字段可覆盖。
  /** 读取最近 ack seq，供 SeqTracker 作 baseline 使用 */
  getLastAckSeq?(aid: string, deviceId: string, slotId: string, namespace: string): number;
  /** 写入最近 ack seq */
  setLastAckSeq?(aid: string, deviceId: string, slotId: string, namespace: string, seq: number): void;

  /** 列出所有已存储的 AID（对齐 Python list_identities） */
  listIdentities?(): string[];
  /** 加载指定 AID 的元数据（对齐 Python load_metadata） */
  loadMetadata?(aid: string): Record<string, unknown> | null;
}
