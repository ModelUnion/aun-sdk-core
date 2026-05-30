// ── @agentunion/fastaun-browser 包入口 ──────────────────────────────

export { VERSION as __version__ } from './version.js';

// 客户端
export { AUNClient, type ConnectionOptions } from './client.js';
export { AID, type VerifyResult } from './aid.js';
export { AIDStore, type AIDInfo } from './aid-store.js';
export { type Result, type ErrorInfo, resultOk, resultErr } from './result.js';

// 配置
export { getDeviceId, createConfig, type AUNConfig } from './config.js';

// 错误类型
export {
  AUNError,
  ConnectionError,
  TimeoutError,
  AuthError,
  IdentityConflictError,
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
  E2EEGroupSecretMissingError,
  E2EEGroupEpochMismatchError,
  E2EEGroupCommitmentInvalidError,
  E2EEGroupNotMemberError,
  E2EEGroupDecryptFailedError,
  CertificateRevokedError,
  E2EEDegradedError,
  ClientSignatureError,
  mapRemoteError,
} from './errors.js';

// 类型
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
  type PrekeyRecord,
  type PrekeyMap,
  type GroupOldEpochRecord,
  type GroupSecretRecord,
  type MetadataRecord,
  type IdentityRecord,
  type SecretRecord,
  type Message,
  type SendResult,
  type AckResult,
  type PullResult,
  isJsonObject,
} from './types.js';

// 事件
export { EventDispatcher, Subscription, type EventHandler } from './events.js';

// 密码学
export { CryptoProvider } from './crypto.js';

// 传输层
export { RPCTransport } from './transport.js';

// 发现
export { GatewayDiscovery } from './discovery.js';

// 密钥存储
export type { KeyStore } from './keystore/index.js';
export { IndexedDBKeyStore, SeedMigrationError, type SeedChangeResult } from './keystore/indexeddb.js';

// 密钥保护存储
export type { SecretStore } from './secret-store/index.js';
export { createDefaultSecretStore } from './secret-store/index.js';
export { IndexedDBSecretStore } from './secret-store/indexeddb-store.js';

// 认证
export { AuthFlow } from './auth.js';

// E2EE V2-only 公开 API
export { ProtectedHeaders } from './protected-headers.js';
export type { ProtectedHeadersInput } from './protected-headers.js';
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

// 根证书
export { ROOT_CA_PEM } from './certs/root.js';
