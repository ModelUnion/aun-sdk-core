/**
 * @aun/core-node — AUN Protocol Core SDK for Node.js
 *
 * 包入口：统一导出所有公开 API。
 */

export const VERSION = '0.3.2';

// ── 主客户端 ─────────────────────────────────────────────────
export { AUNClient } from './client.js';

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
  E2EEGroupCommitmentInvalidError,
  E2EEGroupNotMemberError,
  E2EEGroupDecryptFailedError,
  CertificateRevokedError,
  E2EEDegradedError,
  ClientSignatureError,
  mapRemoteError,
} from './errors.js';

// ── 事件 ─────────────────────────────────────────────────────
export { EventDispatcher, Subscription, type EventHandler } from './events.js';

// ── 类型 ─────────────────────────────────────────────────────
export {
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
  type SendResult,
  type AckResult,
  type PullResult,
  isJsonObject,
} from './types.js';

// ── 密码学 ───────────────────────────────────────────────────
export { CryptoProvider, type IdentityKeyPair } from './crypto.js';

// ── KeyStore ─────────────────────────────────────────────────
export type { KeyStore } from './keystore/index.js';
export { FileKeyStore } from './keystore/file.js';

// ── SecretStore ──────────────────────────────────────────────
export type { SecretStore } from './secret-store/index.js';
export { createDefaultSecretStore } from './secret-store/index.js';
export { FileSecretStore } from './secret-store/file-store.js';

// ── 传输层 ───────────────────────────────────────────────────
export { RPCTransport } from './transport.js';

// ── Gateway 发现 ─────────────────────────────────────────────
export { GatewayDiscovery } from './discovery.js';

// ── 认证流程 ─────────────────────────────────────────────────
export { AuthFlow } from './auth.js';
export { CustodyNamespace } from './namespaces/custody.js';
export { MetaNamespace } from './namespaces/meta.js';

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
