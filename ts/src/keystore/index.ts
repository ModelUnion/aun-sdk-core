/**
 * KeyStore 接口定义
 *
 * 与 Python SDK 的 KeyStore Protocol 完全对齐。
 */

import type {
  IdentityRecord,
  KeyPairRecord,
  MetadataRecord,
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

  /** 保存单个 namespace 的 contiguous_seq */
  saveSeq?(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): void;
  /** 加载单个 namespace 的 contiguous_seq */
  loadSeq?(aid: string, deviceId: string, slotId: string, namespace: string): number;
  /** 加载某 device+slot 下所有 namespace 的 contiguous_seq */
  loadAllSeqs?(aid: string, deviceId: string, slotId: string): Record<string, number>;
  /** 删除单个 namespace 的 contiguous_seq 行 */
  deleteSeq?(aid: string, deviceId: string, slotId: string, namespace: string): void;

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
