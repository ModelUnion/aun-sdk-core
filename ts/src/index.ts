/**
 * @aun/core-node — AUN Protocol Core SDK for Node.js
 *
 * 包入口：统一导出所有公开 API。
 */

export { VERSION } from './version.js';

// ── 主客户端 ─────────────────────────────────────────────────
export { AUNClient, type ConnectionOptions, type NotifyOptions } from './client.js';
export { AID, type VerifyResult } from './aid.js';
export { AIDStore, type AIDInfo, type ResolveOpts, type ImportGroupIdentityOptions, type ImportGroupIdentityResult } from './aid-store.js';
export { type Result, type ErrorInfo, resultOk, resultErr } from './result.js';

// ── 配置 ─────────────────────────────────────────────────────
export { getDeviceId, type AUNConfig, defaultConfig, configFromMap } from './config.js';

// ── 错误类型 ─────────────────────────────────────────────────
export {
  AUNError,
  ConnectionError,
  TimeoutError,
  AuthError,
  PermissionError,
  ValidationError,
  NotFoundError,
  RateLimitError,
  StateError,
  SerializationError,
  SessionError,
  GroupError,
  GroupNotFoundError,
  GroupStateError,
  E2EEError,
  E2EEDecryptFailedError,
  CertificateRevokedError,
  E2EEDegradedError,
  ClientSignatureError,
  mapRemoteError,
} from './errors.js';

// ── 校验工具 ─────────────────────────────────────────────────
export { validateAIDFormat, validateGroupAIDFormat, validateGroupIDFormat } from './validators.js';
export {
  convertToGroupAid,
  normalizeGroupAid,
  normalizeGroupId,
  splitGroupId,
  buildDiscoveryHost,
} from './group-id.js';
export {
  GROUP_INDEX_KEY,
  GROUP_INDEX_SCHEMA,
  GROUP_INDEX_SIG_ALG,
  GroupIndexMetaCache,
  buildSignedGroupIndex,
  computeGroupIndexBodyHash,
  groupIndexEtag,
  groupIndexSigningPayload,
  parseGroupIndex,
  prepareGroupSettingsWithIndex,
  verifyGroupIndex,
  type GroupIndexEntry,
  type GroupIndexMeta,
  type GroupIndexSigner,
  type SignedGroupIndex,
} from './group-index.js';

// ── 事件 ─────────────────────────────────────────────────────
export { EventDispatcher, Subscription, type EventHandler } from './events.js';

// ── 类型 ─────────────────────────────────────────────────────
export {
  ConnectionState,
  type JsonValue,
  type JsonObject,
  type RpcParams,
  type RpcResult,
  type RpcErrorObject,
  type RpcMessage,
  type GatewayEntry,
  type GatewayDiscoveryDocument,
  type KeyPairRecord,
  type MetadataRecord,
  type IdentityRecord,
  type SecretRecord,
  type Message,
  type GroupMessage,
  type GroupInfo,
  type GroupMemberInfo,
  type SendResult,
  type AckResult,
  type PullResult,
  isJsonObject,
} from './types.js';

// ── 密码学 ───────────────────────────────────────────────────
export { CryptoProvider, type IdentityKeyPair } from './crypto.js';

// ── KeyStore ─────────────────────────────────────────────────
export type { KeyStore, TokenStore } from './keystore/index.js';
export { LocalIdentityStore } from './keystore/local-identity-store.js';
export { LocalTokenStore } from './keystore/local-token-store.js';

// ── SecretStore ──────────────────────────────────────────────
export type { SecretStore } from './secret-store/index.js';
export { createDefaultSecretStore } from './secret-store/index.js';
export { FileSecretStore, SeedMigrationError, type SeedChangeResult } from './secret-store/file-store.js';

// ── 传输层 ───────────────────────────────────────────────────
export { RPCTransport } from './transport.js';

// ── Service Proxy ───────────────────────────────────────────
export {
  EmbeddedServiceRegistry,
  EndpointPolicy,
  ServiceProxyClient,
  ServiceRecord,
  type ServiceProxyClientOptions,
  type ServiceSummary,
} from './service-proxy.js';

// ── Storage VFS ─────────────────────────────────────────────
export {
  StorageVFS,
  StorageLowLevel,
  StorageError,
  StorageNotFoundError,
  StorageAccessDeniedError,
  StorageConflictError,
  StorageLoopError,
  StorageDanglingSymlinkError,
  type NodeView,
  type UsageView,
  type DownloadResult,
  type RemoveResult,
  type UnmountResult,
} from './storage/index.js';

// ── Collab 协作层 ───────────────────────────────────────────
export {
  CollabClient,
  CollabTagClient,
  CollabError,
  CollabConflictError,
  mapCollabError,
  type CollabRaw,
  type CollabRpcClient,
  type CollabDocumentEntry,
  type CollabDocumentResult,
  type CollabHistoryEntry,
  type CollabDiffResult,
  type CollabRegistryEntry,
  type CollabTagEntry,
  type CollabTag,
  type CollabTagDiffResult,
  type CollabTagPruneOptions,
  type CollabTagRestoreResult,
  type CollabSnapshotEntry,
  type CollabSnapshot,
  type CollabSnapshotDiffResult,
  type CollabSnapshotPruneOptions,
  type CollabSnapshotRestoreResult,
} from './collab/index.js';

// ── Service plane facades ───────────────────────────────────
export {
  MessageFacade,
  MessageThoughtFacade,
  GroupFacade,
  GroupThoughtFacade,
  StreamFacade,
  type FacadeParams,
  type FacadeRpcClient,
} from './facades.js';
export {
  GroupFSVFS,
  isGroupRemotePath,
  type GroupFSCopyDestination,
  type GroupFSCopyOptions,
  type GroupFSCopySource,
  type GroupFSDownloadResult,
  type GroupFSRpcClient,
} from './group-fs.js';

// ── Gateway 发现 ─────────────────────────────────────────────
export { GatewayDiscovery } from './discovery.js';

// ── 认证流程 ─────────────────────────────────────────────────
export { AuthFlow } from './auth.js';
export { RegisterFlow, type RegisterResult } from './register-flow.js';

// ── E2EE ─────────────────────────────────────────────────────
export { ProtectedHeaders } from './protected-headers.js';
export type { ProtectedHeadersInput } from './protected-headers.js';

// ── E2EE V2 ──────────────────────────────────────────────────
export {
  encryptP2PMessage,
  encryptGroupMessage,
  decryptMessage,
} from './v2/e2ee/index.js';
export type {
  Sender,
  Target,
  TargetSet,
  EncryptOptions,
  StateCommitmentAAD,
} from './v2/e2ee/index.js';
export { V2Session, V2KeyStore } from './v2/session/index.js';
export type { CallFn } from './v2/session/index.js';
export { computeStateCommitment, STATE_PREFIX } from './v2/state/index.js';
