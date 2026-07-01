/**
 * KeyStore / TokenStore 接口定义（浏览器版本 — 所有方法均为异步）。
 *
 * TokenStore — 不含私钥操作，AuthFlow / AUNClient 持有此类型。
 * KeyStore   — 仅包含私钥/完整身份操作，AIDStore / RegisterFlow 持有。
 */

import type {
  IdentityRecord,
  KeyPairRecord,
  MetadataRecord,
} from '../types.js';
export interface AgentMdCacheRecord {
  aid: string;
  content: string;
  local_etag: string;
  remote_etag: string;
  last_modified: string;
  fetched_at: number;
  observed_at: number;
  checked_at: number;
  remote_status: string;
  verify_status: string;
  verify_error: string;
  last_error: string;
  updated_at: number;
}

export type AgentMdCacheUpsert = Partial<Omit<AgentMdCacheRecord, 'aid' | 'updated_at'>>;

/**
 * 不含私钥操作的存储接口（浏览器版本 — 所有方法均为异步）。
 * AuthFlow / AUNClient 持有此类型。
 */
export interface TokenStore {
  /** 加载证书 PEM */
  loadCert(aid: string, certFingerprint?: string): Promise<string | null>;
  /** 保存证书 PEM */
  saveCert(
    aid: string,
    certPem: string,
    certFingerprint?: string,
    opts?: { makeActive?: boolean },
  ): Promise<void>;
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

  /** 保存单个 namespace 的 contiguous_seq */
  saveSeq?(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): Promise<void>;
  /** 加载单个 namespace 的 contiguous_seq */
  loadSeq?(aid: string, deviceId: string, slotId: string, namespace: string): Promise<number>;
  /** 加载某 device+slot 下所有 namespace 的 contiguous_seq */
  loadAllSeqs?(aid: string, deviceId: string, slotId: string): Promise<Record<string, number>>;
  /** 删除单个 namespace 的 contiguous_seq 行 */
  deleteSeq?(aid: string, deviceId: string, slotId: string, namespace: string): Promise<void>;
  /** 加载身份元数据（可选） */
  loadMetadata?(aid: string): Promise<Record<string, unknown> | null>;
  /** 读取单个 metadata KV（可选） */
  getMetadata?(aid: string, key: string): Promise<string>;
  /** 写入单个 metadata KV（可选；空值视为删除） */
  setMetadata?(aid: string, key: string, value: string): Promise<void>;

  /** 保存信任根列表和根证书，返回 bundle 标识 */
  saveTrustRoots?(trustList: Record<string, unknown>, rootCerts: Array<{ id?: string; cert_pem: string; fingerprint_sha256?: string }>): Promise<string>;
  /** 保存 issuer 根证书并合并到 bundle，返回 [证书标识, bundle 标识] */
  saveIssuerRootCert?(issuer: string, certPem: string, fingerprintSha256?: string): Promise<[string, string]>;
  /** 加载已存储的信任根列表 JSON */
  loadTrustRoots?(): Promise<Record<string, unknown> | null>;

  /** 加载本地持久化的某个远端/自身 agent.md 缓存记录 */
  loadAgentMdCache?(ownerAid: string, targetAid: string): Promise<AgentMdCacheRecord | null>;
  /** 更新本地持久化的某个远端/自身 agent.md 缓存记录 */
  upsertAgentMdCache?(ownerAid: string, targetAid: string, fields: AgentMdCacheUpsert): Promise<AgentMdCacheRecord>;
  /** 列出指定 AIDs 逻辑根目录下已有正文文件对应的 aid */
  listAgentMdContentAids?(agentMdPath: string): Promise<string[]>;
  /** 保存群组状态快照 */
  saveGroupState?(groupId: string, state: GroupStateRecord): Promise<void>;
  /** 加载群组状态快照 */
  loadGroupState?(groupId: string): Promise<GroupStateRecord | null>;
}

/** 群组状态记录 */
export interface GroupStateRecord {
  group_id: string;
  group_aid?: string;
  state_version: number;
  state_hash: string;
  key_epoch: number;
  membership_json: string;
  policy_json: string;
  updated_at: number;
}

/** 私钥/完整身份存储接口，仅 AIDStore / RegisterFlow 持有。 */
export interface KeyStore {
  /** 加载证书 PEM */
  loadCert(aid: string, certFingerprint?: string): Promise<string | null>;
  /** 保存证书 PEM */
  saveCert(
    aid: string,
    certPem: string,
    certFingerprint?: string,
    opts?: { makeActive?: boolean },
  ): Promise<void>;
  /** 加载密钥对 */
  loadKeyPair(aid: string): Promise<KeyPairRecord | null>;
  /** 保存密钥对 */
  saveKeyPair(aid: string, keyPair: KeyPairRecord): Promise<void>;
  /** 创建注册 pending 身份记录（返回 pending handle） */
  pendingIdentityDir?(aid: string): Promise<string>;
  /** 列出指定 AID 的注册 pending 记录 */
  listPendingIdentityDirs?(aid: string): Promise<string[]>;
  /** 保存 pending 密钥对；实现必须加密私钥字段 */
  savePendingKeyPair?(handle: string, aid: string, keyPair: KeyPairRecord): Promise<void>;
  /** 加载 pending 密钥对（返回时在内存中还原私钥） */
  loadPendingKeyPair?(handle: string, aid: string): Promise<KeyPairRecord | null>;
  /** 保存 pending 证书 */
  savePendingCert?(handle: string, certPem: string): Promise<void>;
  /** 将 pending 身份转正 */
  promotePendingIdentity?(handle: string, aid: string): Promise<string>;
  /** 删除指定 pending 身份 */
  discardPendingIdentity?(handle: string): Promise<void>;
  /** 清理超龄 pending 身份 */
  cleanupPendingDirs?(maxAgeMs?: number): Promise<number>;
  /** 加载完整身份信息（含私钥） */
  loadIdentity(aid: string): Promise<IdentityRecord | null>;
  /** 保存完整身份信息（允许写入私钥字段） */
  saveIdentity(aid: string, identity: IdentityRecord): Promise<void>;
  /** 列出所有已存储的 AID */
  listIdentities?(): Promise<string[]>;
  /** 迁移 IndexedDB 中由 seed 加密的私钥 */
  changeSeed?(oldSeed: string, newSeed: string): Promise<{ migrated: number; privateKeysMigrated: number }>;
}
