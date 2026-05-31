/**
 * KeyStore / TokenStore 接口定义
 *
 * TokenStore — 不含私钥操作，AuthFlow / AUNClient 持有此类型。
 * KeyStore   — 仅包含私钥/完整身份操作，AIDStore / RegisterFlow 持有。
 */

import type {
  IdentityRecord,
  KeyPairRecord,
  MetadataRecord,
} from '../types.js';


/** 不含私钥操作的存储接口，AuthFlow / AUNClient 持有此类型。 */
export interface TokenStore {
  /** 加载证书 */
  loadCert(aid: string, certFingerprint?: string): string | null;
  /** 保存证书 */
  saveCert(
    aid: string,
    certPem: string,
    certFingerprint?: string,
    opts?: { makeActive?: boolean },
  ): void;
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

  /** 保存单个 namespace 的 contiguous_seq */
  saveSeq?(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): void;
  /** 加载单个 namespace 的 contiguous_seq */
  loadSeq?(aid: string, deviceId: string, slotId: string, namespace: string): number;
  /** 加载某 device+slot 下所有 namespace 的 contiguous_seq */
  loadAllSeqs?(aid: string, deviceId: string, slotId: string): Record<string, number>;
  /** 删除单个 namespace 的 contiguous_seq 行 */
  deleteSeq?(aid: string, deviceId: string, slotId: string, namespace: string): void;

  /** 读取最近 ack seq */
  getLastAckSeq?(aid: string, deviceId: string, slotId: string, namespace: string): number;
  /** 写入最近 ack seq */
  setLastAckSeq?(aid: string, deviceId: string, slotId: string, namespace: string, seq: number): void;

  /** 加载指定 AID 的元数据 */
  loadMetadata?(aid: string): Record<string, unknown> | null;
  /** 保存指定 AID 的元数据 */
  saveMetadata?(aid: string, metadata: Record<string, unknown>): void;

  /** 保存群组状态（state_hash 链） */
  saveGroupState?(groupId: string, stateVersion: number, stateHash: string, keyEpoch: number, membershipJson: string, policyJson: string): void;
  /** 加载群组状态 */
  loadGroupState?(groupId: string): { group_id: string; state_version: number; state_hash: string; key_epoch: number; membership_json: string; policy_json: string; updated_at: number } | null;

  /** 返回信任根证书存储目录路径 */
  trustRootDir?(): string;
  /** 返回信任根证书 bundle 路径 */
  trustRootBundlePath?(): string;
  /** 保存信任根列表和根证书，返回 bundle 路径 */
  saveTrustRoots?(trustList: Record<string, unknown>, rootCerts: Array<{ id?: string; cert_pem: string; fingerprint_sha256?: string }>): string;
  /** 保存 issuer 根证书并合并到 bundle，返回 [证书路径, bundle 路径] */
  saveIssuerRootCert?(issuer: string, certPem: string, fingerprintSha256?: string): [string, string];
}

/** 私钥/完整身份存储接口，仅 AIDStore / RegisterFlow 持有。 */
export interface KeyStore {
  /** 加载密钥对 */
  loadKeyPair(aid: string): KeyPairRecord | null;
  /** 保存密钥对 */
  saveKeyPair(aid: string, keyPair: KeyPairRecord): void;
  /** 创建注册 pending 身份记录 */
  pendingIdentityDir?(aid: string): string;
  /** 列出指定 AID 的 pending 身份记录 */
  listPendingIdentityDirs?(aid: string): string[];
  /** 保存 pending 密钥对 */
  savePendingKeyPair?(handle: string, aid: string, keyPair: KeyPairRecord): void;
  /** 加载 pending 密钥对 */
  loadPendingKeyPair?(handle: string, aid: string): KeyPairRecord | null;
  /** 保存 pending 证书 */
  savePendingCert?(handle: string, certPem: string): void;
  /** 将 pending 身份转正 */
  promotePendingIdentity?(handle: string, aid: string): string;
  /** 删除指定 pending 身份 */
  discardPendingIdentity?(handle: string): void;
  /** 清理超龄 pending 身份 */
  cleanupPendingDirs?(maxAgeMs?: number): number;
  /** 加载完整身份信息（含私钥） */
  loadIdentity(aid: string): IdentityRecord | null;
  /** 保存完整身份信息（允许写入私钥字段） */
  saveIdentity(aid: string, identity: IdentityRecord): void;
  /** 列出所有已存储的 AID */
  listIdentities?(): string[];
}

/** 物理实现通常同时实现 TokenStore 与 KeyStore；注册流程显式要求组合类型。 */
export type FullKeyStore = TokenStore & KeyStore;
