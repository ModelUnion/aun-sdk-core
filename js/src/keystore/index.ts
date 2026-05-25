// ── KeyStore 接口定义 ──────────────────────────────────────

import type {
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

  /** 加载结构化 prekeys（deviceId 可选，不传等价于 deviceId=''） */
  loadE2EEPrekeys?(aid: string, deviceId?: string): Promise<PrekeyMap>;
  /**
   * 按 prekey_id 单点查询（O(log N)），跳过全量扫描。
   *
   * 解密入站消息时，envelope 只带 prekey_id，没有 device_id。直接走单查可省去
   * 全量加载的开销。未命中时调用方应回退到 `loadE2EEPrekeys`，保持兼容。
   */
  loadE2EEPrekeyById?(aid: string, prekeyId: string): Promise<Record<string, unknown> | null>;
  /** 保存单个 prekey（deviceId 可选，不传等价于 deviceId=''） */
  saveE2EEPrekey?(aid: string, prekeyId: string, prekeyData: PrekeyRecord, deviceId?: string): Promise<void>;
  /** 清理过期 prekeys（deviceId 可选，不传等价于 deviceId=''） */
  cleanupE2EEPrekeys?(aid: string, cutoffMs: number, keepLatest?: number, deviceId?: string): Promise<string[]>;

  /** 列出本地已存储群组密钥的 group_id */
  listGroupSecretIds?(aid: string): Promise<string[]>;
  /** 清理单个群组过期 old epochs */
  cleanupGroupOldEpochsState?(aid: string, groupId: string, cutoffMs: number): Promise<number>;
  /** 按 row 加载当前或指定 epoch 的群组密钥 */
  loadGroupSecretEpoch?(aid: string, groupId: string, epoch?: number | null): Promise<GroupSecretRecord | null>;
  /** 按 row 加载某个群组的当前和历史 epoch 密钥 */
  loadGroupSecretEpochs?(aid: string, groupId: string): Promise<GroupSecretRecord[]>;
  /** 事务化保存群组密钥状态转移 */
  storeGroupSecretTransition?(
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
  ): Promise<boolean>;
  /** 事务化保存指定 epoch 密钥；低于 current 时写入 old epoch row */
  storeGroupSecretEpoch?(
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
  ): Promise<boolean>;
  /** 事务化丢弃指定 pending rotation */
  discardPendingGroupSecretState?(aid: string, groupId: string, epoch: number, rotationId: string): Promise<boolean>;
  /** 删除单个群组的所有密钥状态（群组解散时使用） */
  deleteGroupSecretState?(aid: string, groupId: string): Promise<void>;

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
  /** 删除单个 namespace 的 contiguous_seq 行 */
  deleteSeq?(aid: string, deviceId: string, slotId: string, namespace: string): Promise<void>;
  /** 列出已存储的所有身份 AID（可选） */
  listIdentities?(): Promise<string[]>;
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
  /** 列出指定 AgentMDs 逻辑根目录下已有正文文件对应的 aid */
  listAgentMdContentAids?(agentMdPath: string): Promise<string[]>;
  /** 保存群组状态快照 */
  saveGroupState?(groupId: string, state: GroupStateRecord): Promise<void>;
  /** 加载群组状态快照 */
  loadGroupState?(groupId: string): Promise<GroupStateRecord | null>;
}

/** 群组状态记录 */
export interface GroupStateRecord {
  group_id: string;
  state_version: number;
  state_hash: string;
  key_epoch: number;
  membership_json: string;
  policy_json: string;
  updated_at: number;
}
