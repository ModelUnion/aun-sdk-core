// ── AUNClient（SDK 主入口 — 浏览器完整实现）──────────────────
// 对标 Python client.py，浏览器环境适配：
//   - 所有密码学操作异步（SubtleCrypto）
//   - HTTP 使用 fetch() 而非 Node http
//   - 无文件系统（IndexedDB via keystore）
//   - 后台任务使用 setTimeout/setInterval

import { createConfig, getDeviceId, normalizeSlotId, type AUNConfig } from './config.js';
import { EventDispatcher, type EventPayload, type EventHandler, type Subscription } from './events.js';
import { normalizeGroupId } from './group-id.js';
import { validateAIDFormat, validateGroupIDFormat } from './validators.js';
import { GatewayDiscovery } from './discovery.js';
import { AIDStore } from './aid-store.js';
import { RPCTransport } from './transport.js';
import { AuthFlow } from './auth.js';
import { SeqTracker } from './seq-tracker.js';
import { ClientRuntime } from './client/runtime.js';
import { MessageDeliveryEngine } from './client/delivery.js';
import { IdentityRuntimeManager } from './client/identity.js';
import { LifecycleController } from './client/lifecycle.js';
import { PeerDirectory } from './client/peers.js';
import { RpcPipeline } from './client/rpc-pipeline.js';
import { GroupFacade, MessageFacade, StreamFacade } from './facades.js';
import { StorageVFS } from './storage/vfs.js';
import { CollabClient } from './collab/client.js';
import { V2E2EECoordinator } from './client/v2-e2ee.js';
import { GroupStateCoordinator } from './client/group-state.js';
import {
  CryptoProvider,
  base64ToUint8,
  pemToArrayBuffer,
  certificateSha256Fingerprint,
  ecdsaVerifyDer,
  importCertPublicKeyEcdsa,
} from './crypto.js';
import type { ProtectedHeadersInput } from './protected-headers.js';
import { IndexedDBTokenStore } from './keystore/indexeddb-token-store.js';
import type { GroupIndexCacheUpsert, TokenStore } from './keystore/index.js';
import { V2Session, V2KeyStore, type CallFn } from './v2/session/index.js';
import {
  decryptMessage,
  type Target,
} from './v2/e2ee/index.js';
import { ecdsaVerifyRaw } from './v2/crypto/ecdsa.js';
import { AUNLogger, type ModuleLogger } from './logger.js';
import { AgentMdManager } from './agent-md.js';
import { GroupIndexMetaCache } from './group-index.js';
import { certMatchesFingerprint, normalizeFingerprintHex } from './cert-utils.js';
import {
  AUNError,
  AuthError,
  ConnectionError,
  E2EEError,
  NotFoundError,
  PermissionError,
  StateError,
  TimeoutError,
  ValidationError,
} from './errors.js';
import {
  isJsonObject,
  ConnectionState,
  STATE_TO_PUBLIC,
  type IdentityRecord,
  type JsonObject,
  type JsonValue,
  type KeyPairRecord,
  type RpcParams,
  type RpcResult,
} from './types.js';
import { AID } from './aid.js';

function getV2DeviceId(dev: Record<string, unknown>): { present: boolean; value: string } {
  if (Object.prototype.hasOwnProperty.call(dev, 'device_id')) {
    return { present: true, value: String(dev.device_id ?? '').trim() };
  }
  if (Object.prototype.hasOwnProperty.call(dev, 'owner_device_id')) {
    return { present: true, value: String(dev.owner_device_id ?? '').trim() };
  }
  return { present: false, value: '' };
}

function isAIDObject(value: unknown): value is AID {
  const candidate = value as Partial<AID> | null;
  return Boolean(
    candidate
      && typeof candidate === 'object'
      && typeof candidate.aid === 'string'
      && typeof candidate.aunPath === 'string'
      && typeof candidate.isPrivateKeyValid === 'function',
  );
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function attachGatewayProximity(message: JsonObject, source: Record<string, unknown>): void {
  if (isJsonObject(source.proximity as JsonValue | object | null | undefined)) {
    message.proximity = { ...(source.proximity as JsonObject) };
  }
  for (const key of ['same_device', 'same_network', 'same_egress_ip'] as const) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      message[key] = source[key] as JsonValue;
    }
  }
}

function groupIndexBodyText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && !Array.isArray(value) && 'body' in value) {
    return String((value as { body?: unknown }).body ?? '');
  }
  return '';
}

/** 默认会话选项 */
interface SessionRetryOptions extends JsonObject {
  initial_delay: number;
  max_delay: number;
  /** M25: 最大重试次数，0 表示无限（与 Go/Python 对齐） */
  max_attempts: number;
}

interface SessionTimeoutOptions extends JsonObject {
  connect: number;
  call: number;
  http: number;
}

interface SessionOptions extends JsonObject {
  auto_reconnect: boolean;
  heartbeat_interval: number;
  token_refresh_before: number;
  retry: SessionRetryOptions;
  timeouts: SessionTimeoutOptions;
  connection_kind?: string;
  short_ttl_ms?: number;
  background_sync?: boolean;
}

export interface ConnectionOptions {
  auto_reconnect?: boolean;
  connect_timeout?: number;
  retry?: JsonObject;
  retry_initial_delay?: number;
  retry_max_delay?: number;
  retry_max_attempts?: number;
  heartbeat_interval?: number;
  call_timeout?: number;
  connection_kind?: string;
  short_ttl_ms?: number;
  delivery_mode?: JsonObject;
  extra_info?: JsonObject;
  background_sync?: boolean;
}

export interface NotifyOptions {
  to?: string;
  group_aid?: string;
  groupAid?: string;
  group_id?: string;
  groupId?: string;
  device_id?: string;
  deviceId?: string;
  slot_id?: string;
  slotId?: string;
  ttl_ms?: number;
  ttlMs?: number;
}

export interface BindGroupAidOptions {
  aidStore?: AIDStore;
}

export interface CompleteGroupTransferOptions {
  aidStore?: AIDStore;
}

interface ConnectParams extends RpcParams {
  access_token?: string;
  gateway?: string;
  device_id?: string;
  slot_id?: string;
  delivery_mode?: JsonObject;
  queue_routing?: string;
  affinity_ttl_ms?: number;
  topology?: JsonObject;
  auto_reconnect?: boolean;
  heartbeat_interval?: number;
  token_refresh_before?: number;
  retry?: JsonObject;
  timeouts?: JsonObject;
  connection_kind?: string;
  short_ttl_ms?: number;
  extra_info?: JsonObject;
}

interface AuthContext extends JsonObject {
  identity?: IdentityRecord;
  token?: string;
  hello?: JsonObject;
}

const DEFAULT_SESSION_OPTIONS: SessionOptions = {
  auto_reconnect: true,
  heartbeat_interval: 30.0,
  token_refresh_before: 1800.0,
  retry: {
    initial_delay: 1.0,
    max_delay: 64.0,
    // M25: 0 表示无限重试，与 Go/Python 对齐
    max_attempts: 0,
  },
  timeouts: {
    connect: 5.0,
    call: 35.0,
    http: 30.0,
  },
};

const RECONNECT_MIN_BASE_DELAY_SECONDS = 1.0;
const RECONNECT_MAX_BASE_DELAY_SECONDS = 64.0;
const TOKEN_REFRESH_CHECK_INTERVAL_MS = 30_000;
const MAX_NOTIFY_PAYLOAD_SIZE = 64 * 1024;

// 心跳间隔下/上限（秒）。0 = 关闭心跳；负值视为 0；其余值 clamp 到 [10, 600]。
// 服务端通过 hello.heartbeat_interval 与 meta.ping pong 中的同名字段下发。
const HEARTBEAT_MIN_INTERVAL_SECONDS = 10;
const HEARTBEAT_MAX_INTERVAL_SECONDS = 600;

function clampHeartbeatInterval(value: unknown): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  if (n < HEARTBEAT_MIN_INTERVAL_SECONDS) return HEARTBEAT_MIN_INTERVAL_SECONDS;
  if (n > HEARTBEAT_MAX_INTERVAL_SECONDS) return HEARTBEAT_MAX_INTERVAL_SECONDS;
  return n;
}

// P1-23: 非幂等方法使用更长超时（35s），避免 SDK 10s 超时 < gateway 30s 处理时间
const NON_IDEMPOTENT_TIMEOUT = 35;
const NON_IDEMPOTENT_METHODS = new Set([
  'message.send', 'group.send', 'group.create', 'group.invite',
  'group.kick', 'group.remove_member', 'group.leave', 'group.dissolve',
  'group.set_settings',
  'group.update_announcement', 'group.update_rules',
  'storage.put_object', 'storage.delete_object',
  'storage.create_share_link', 'storage.revoke_share_link',
  'storage.get_by_share',
  'storage.create_upload_session', 'storage.complete_upload',
  'storage.create_folder', 'storage.rename_folder', 'storage.move_folder',
  'storage.delete_folder', 'storage.move_object', 'storage.copy_object',
  'storage.batch_delete', 'storage.set_object_meta', 'storage.append_object',
  'storage.set_acl', 'storage.remove_acl', 'storage.set_visibility',
  'storage.issue_token', 'storage.revoke_token',
  'storage.create_symlink', 'storage.atomic_repoint',
  'storage.rename_symlink', 'storage.delete_symlink',
  'storage.fs.mkdir', 'storage.fs.remove', 'storage.fs.rename', 'storage.fs.copy',
  'storage.fs.mount', 'storage.fs.approve', 'storage.fs.reject', 'storage.fs.unmount',
  'storage.fs.invalidate_membership',
  'storage.volume.create', 'storage.volume.renew', 'storage.volume.expire_due',
  'auth.create_aid', 'auth.renew_cert', 'auth.rekey',
  'message.thought.put', 'group.thought.put',
  'group.add_member', 'group.bind_group_aid', 'group.complete_transfer',
  'group.fs.mkdir', 'group.fs.rm', 'group.fs.cp', 'group.fs.mv',
  'group.fs.set_acl', 'group.fs.remove_acl',
  'group.fs.mount', 'group.fs.umount',
  'group.fs.check_upload', 'group.fs.create_upload_session',
  'group.fs.complete_upload', 'group.fs.create_download_ticket',
  'collab.create', 'collab.commit', 'collab.clone',
  'collab.prune', 'collab.unregister',
  'collab.tag.create', 'collab.tag.restore',
  'collab.tag.rm', 'collab.tag.prune',
]);

/** 需要客户端签名的关键方法。运行时逻辑已迁入 RpcPipeline，此处保留给源码审计测试。 */
const SIGNED_METHODS = new Set([
  'message.send',
  'message.v2.put_peer_pk', 'message.v2.bootstrap',
  'message.v2.group_bootstrap', 'message.v2.pull',
  'message.v2.ack',
  'group.send',
  'group.v2.put_group_pk', 'group.v2.bootstrap',
  'group.v2.send', 'group.v2.pull', 'group.v2.ack',
  'group.v2.propose_state', 'group.v2.confirm_state',
  'group.v2.get_proposal',
  'group.kick', 'group.add_member',
  'group.leave', 'group.remove_member',
  'group.update',
  'group.set_role',
  'group.transfer_owner', 'group.bind_group_aid', 'group.complete_transfer',
  'group.review_join_request',
  'group.batch_review_join_request',
  'group.request_join', 'group.use_invite_code',
  'group.thought.put',
  'message.thought.put',
  'group.set_settings',
  'group.update_announcement',
  'group.update_rules',
  'group.fs.mkdir', 'group.fs.rm', 'group.fs.cp', 'group.fs.mv',
  'group.fs.set_acl', 'group.fs.remove_acl',
  'group.fs.mount', 'group.fs.umount',
  'group.fs.check_upload', 'group.fs.create_upload_session',
  'group.fs.complete_upload', 'group.fs.create_download_ticket',
  'storage.put_object', 'storage.delete_object',
  'storage.create_share_link', 'storage.revoke_share_link',
  'storage.get_by_share',
  'storage.create_upload_session', 'storage.complete_upload',
  'storage.create_folder', 'storage.rename_folder', 'storage.move_folder',
  'storage.delete_folder', 'storage.move_object', 'storage.copy_object',
  'storage.batch_delete', 'storage.set_object_meta', 'storage.append_object',
  'storage.set_acl', 'storage.remove_acl', 'storage.set_visibility',
  'storage.check_access',
  'storage.issue_token', 'storage.revoke_token',
  'storage.create_symlink', 'storage.atomic_repoint',
  'storage.rename_symlink', 'storage.delete_symlink',
  'storage.fs.mkdir', 'storage.fs.remove', 'storage.fs.rename', 'storage.fs.copy',
  'storage.fs.mount', 'storage.fs.approve', 'storage.fs.reject', 'storage.fs.unmount',
  'storage.fs.invalidate_membership',
  'storage.volume.create', 'storage.volume.renew', 'storage.volume.expire_due',
  'collab.create', 'collab.commit', 'collab.clone',
  'collab.prune', 'collab.unregister',
  'collab.tag.create', 'collab.tag.restore',
  'collab.tag.rm', 'collab.tag.prune',
  'group.commit_state',
  'group.ban', 'group.unban',
  'group.dissolve', 'group.suspend', 'group.resume',
]);

function clampReconnectDelaySeconds(
  value: unknown,
  fallback: number,
  upper = RECONNECT_MAX_BASE_DELAY_SECONDS,
): number {
  const parsed = Number(value);
  const seconds = Number.isFinite(parsed) ? parsed : fallback;
  return Math.min(Math.max(seconds, RECONNECT_MIN_BASE_DELAY_SECONDS), upper);
}

function reconnectSleepDelaySeconds(baseDelay: number, maxBaseDelay: number): number {
  return baseDelay + Math.random() * maxBaseDelay;
}

/** 对端证书缓存 TTL（秒） */
const PEER_CERT_CACHE_TTL = 3600;

/** 缓存的对端证书 */
interface CachedPeerCert {
  certPem: string;
  validatedAt: number;
  refreshAfter: number;
}

/**
 * 将 WebSocket URL 转为对应的 HTTP URL
 */
function gatewayHttpUrl(gatewayUrl: string, path: string): string {
  try {
    const parsed = new URL(gatewayUrl);
    const scheme = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    return `${scheme}//${parsed.host}${path}`;
  } catch {
    const httpUrl = gatewayUrl
      .replace(/^wss:/, 'https:')
      .replace(/^ws:/, 'http:');
    const urlObj = new URL(httpUrl);
    urlObj.pathname = path;
    urlObj.search = '';
    urlObj.hash = '';
    return urlObj.toString();
  }
}

function certCacheKey(aid: string, certFingerprint?: string): string {
  const normalized = String(certFingerprint ?? '').trim().toLowerCase();
  return normalized ? `${aid}#${normalized}` : aid;
}

function buildCertUrl(gatewayUrl: string, aid: string, certFingerprint?: string): string {
  const url = new URL(gatewayHttpUrl(gatewayUrl, `/pki/cert/${encodeURIComponent(aid)}`));
  const normalized = String(certFingerprint ?? '').trim().toLowerCase();
  if (normalized) {
    url.searchParams.set('cert_fingerprint', normalized);
  }
  return url.toString();
}

function createAgentMdManagerForRuntime(opts: {
  config: () => AUNConfig;
  logger: () => ModuleLogger;
  ownerAid: () => string | null;
  currentAid: () => AID | null;
  gateway: {
    resolve: (aid: string) => Promise<string>;
    set: (gatewayUrl: string) => void;
    get: () => string | null;
  };
  identity: {
    get: () => IdentityRecord | null;
    set: (identity: IdentityRecord | null) => void;
  };
  auth: () => AuthFlow;
  tokenStore: () => TokenStore;
  fetchPeerCert: (aid: string, certFingerprint?: string | null) => Promise<string>;
}): AgentMdManager {
  return new AgentMdManager({
    aunPath: opts.config().aunPath,
    tokenStore: opts.tokenStore(),
    logger: opts.logger(),
    ownerAidGetter: opts.ownerAid,
    currentAidGetter: opts.currentAid,
    gatewayResolver: async (aid) => {
      const gatewayUrl = await opts.gateway.resolve(aid);
      opts.gateway.set(gatewayUrl);
      return gatewayUrl;
    },
    accessTokenResolver: async (aid, gatewayUrl) => {
      const target = String(aid ?? '').trim();
      let identity = await opts.auth().loadIdentityOrNone(target);
      if (!identity && opts.identity.get() && String(opts.identity.get()?.aid ?? '') === target) {
        identity = opts.identity.get();
      }
      if (!identity) {
        throw new StateError('no local identity found, register or load an AID first');
      }

      const auth = opts.auth();
      const cachedToken = String(identity.access_token ?? '');
      const expiresAt = auth.getAccessTokenExpiry(identity);
      if (cachedToken && (expiresAt === null || expiresAt > Date.now() / 1000 + 30)) {
        return cachedToken;
      }

      if (identity.refresh_token) {
        try {
          const refreshed = await auth.refreshCachedTokens(gatewayUrl, identity);
          const refreshedToken = String(refreshed.access_token ?? '');
          const refreshedExpiry = auth.getAccessTokenExpiry(refreshed);
          if (refreshedToken && (refreshedExpiry === null || refreshedExpiry > Date.now() / 1000 + 30)) {
            opts.identity.set(refreshed);
            return refreshedToken;
          }
        } catch {
          // refresh 失败时回退到完整 authenticate。
        }
      }

      const result = await auth.authenticate(gatewayUrl, target);
      const token = String(result.access_token ?? '');
      if (!token) throw new StateError('authenticate did not return access_token');
      const fallbackIdentity: IdentityRecord = {
        ...identity,
        access_token: token,
        refresh_token: String(result.refresh_token ?? identity.refresh_token ?? ''),
      };
      const fallbackExpiresAt = Number(result.expires_at ?? identity.expires_at ?? NaN);
      if (Number.isFinite(fallbackExpiresAt)) fallbackIdentity.expires_at = fallbackExpiresAt;
      opts.identity.set(await auth.loadIdentityOrNone(target) ?? fallbackIdentity);
      return token;
    },
    peerResolver: async (aid, certFingerprint) => {
      const target = String(aid ?? '').trim();
      const expectedFp = String(certFingerprint ?? '').trim().toLowerCase();
      const current = opts.currentAid();
      if (current?.aid === target) {
        if (!expectedFp || await certMatchesFingerprint(current.certPem, expectedFp)) return current;
        throw new StateError(`current AID certificate fingerprint mismatch for ${target}`);
      }
      if (!opts.gateway.get()) {
        try { opts.gateway.set(await opts.gateway.resolve(target)); } catch { /* best effort */ }
      }
      const certPem = String(await opts.fetchPeerCert(target, expectedFp || undefined) ?? '').trim();
      if (!certPem) throw new NotFoundError(`certificate not found for aid: ${target}`);
      return await AID.create({
        aid: target,
        aunPath: opts.config().aunPath,
        certPem,
        privateKeyPem: null,
        certValid: true,
        privateKeyValid: false,
      });
    },
  });
}

/**
 * 跨域时将 Gateway URL 替换为 peer 所在域的 Gateway URL。
 *
 * 例: local=wss://gateway.aid.com:20001/aun, peer=bob.aid.net
 * → wss://gateway.aid.net:20001/aun
 */
function resolvePeerGatewayUrl(localGatewayUrl: string, peerAid: string): string {
  if (!peerAid.includes('.')) return localGatewayUrl;
  const peerIssuer = peerAid.split('.').slice(1).join('.');
  const match = localGatewayUrl.match(/gateway\.([^:/]+)/);
  if (!match) return localGatewayUrl;
  const localIssuer = match[1];
  if (localIssuer === peerIssuer) return localGatewayUrl;
  return localGatewayUrl.replace(`gateway.${localIssuer}`, `gateway.${peerIssuer}`);
}

/** V2 P2P bootstrap 缓存条目（缓存 peer_devices + audit_recipients） */
interface V2BootstrapEntry {
  devices: Array<Record<string, unknown>>;
  auditRecipients: Array<Record<string, unknown>>;
  cachedAt: number;
  epoch?: number;
  stateCommitment?: { state_version: number; state_hash: string; state_chain: string };
  wrapPolicy?: V2WrapPolicy;
}

interface V2WrapPolicy {
  protocol?: '1DH' | '3DH';
  scope?: 'aid' | 'device';
}

interface V2SenderIKPendingEntry {
  msg: Record<string, unknown>;
  fromAid: string;
  senderDeviceId: string;
  groupId: string;
  createdAt: number;
}

/** Base64 (标准) → Uint8Array */
function _v2B64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function _v2B64ToBytesStrict(s: string): Uint8Array {
  const text = String(s ?? '').trim();
  if (!text || text.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new Error('invalid base64');
  }
  return _v2B64ToBytes(text);
}

function _v2BytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function _v2ConcatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function formatCaughtError(error: any): Error | string {
  return error instanceof Error ? error : String(error);
}

const RELOGIN_REFRESH_ERRORS = new Set([
  'missing refresh_token',
  'invalid_or_expired_refresh_token',
  'refresh not supported',
]);

function authErrorRequiresRelogin(error: AuthError): boolean {
  const data = error.data;
  if (isJsonObject(data)) {
    if (data.relogin_required === true) return true;
    const code = String(data.error ?? '').trim().toLowerCase();
    if (RELOGIN_REFRESH_ERRORS.has(code)) return true;
  }
  return RELOGIN_REFRESH_ERRORS.has(error.message.trim().toLowerCase());
}

function v2E2eeMeta(envelope: Record<string, unknown>): Record<string, unknown> {
  const suite = String(envelope.suite ?? '');
  const modeSuite = String(envelope.suite ?? 'unknown');
  const meta: Record<string, unknown> = {
    version: 'v2',
    suite,
    encryption_mode: `v2_${modeSuite}`,
    forward_secrecy: true,
  };
  const protectedHeaders = metadataWithoutAuth(envelope.protected_headers);
  if (protectedHeaders && Object.keys(protectedHeaders).length > 0) {
    meta.protected_headers = protectedHeaders;
  }
  const payloadType = String(envelope.payload_type ?? protectedHeaders?.payload_type ?? '').trim();
  if (payloadType) {
    meta.payload_type = payloadType;
  }
  const context = metadataWithoutAuth(envelope.context);
  if (context && Object.keys(context).length > 0) {
    meta.context = context;
  }
  const agentMd = metadataWithoutAuth(envelope.agent_md);
  if (agentMd && Object.keys(agentMd).length > 0) {
    meta.agent_md = agentMd;
  }
  return meta;
}

function attachV2EnvelopeMetadata(message: Record<string, unknown>, meta: Record<string, unknown> | null | undefined): void {
  if (!meta) return;
  const payloadType = typeof meta.payload_type === 'string' ? meta.payload_type.trim() : '';
  if (payloadType) message.payload_type = payloadType;
  if (isJsonObject(meta.protected_headers)) {
    message.protected_headers = { ...meta.protected_headers };
  }
  if (isJsonObject(meta.agent_md)) {
    message.agent_md = { ...meta.agent_md };
  }
}

function attachV2EnvelopeMetadataFromSource(message: Record<string, unknown>, source: unknown): void {
  const envelope = extractV2EnvelopeFromSource(source);
  if (envelope) attachV2EnvelopeMetadata(message, v2E2eeMeta(envelope));
}

function extractV2EnvelopeFromSource(source: unknown): Record<string, unknown> | null {
  if (!isJsonObject(source)) return null;
  if (isJsonObject(source.payload)) return source.payload as Record<string, unknown>;
  if (typeof source.envelope_json === 'string' && source.envelope_json) {
    try {
      const parsed = JSON.parse(source.envelope_json) as unknown;
      if (isJsonObject(parsed)) return parsed as Record<string, unknown>;
    } catch {
      return null;
    }
  }
  return null;
}

function metadataWithoutAuth(value: unknown): Record<string, unknown> | null {
  if (!isJsonObject(value)) return null;
  const body: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (key !== '_auth') body[key] = item;
  }
  return body;
}

function normalizeDeliveryModeConfig(
  raw: JsonValue | object | undefined,
  opts: {
    defaultMode?: string;
    defaultRouting?: string;
    defaultAffinityTtlMs?: number;
  } = {},
): JsonObject {
  const defaultMode = String(opts.defaultMode ?? 'fanout').trim().toLowerCase() || 'fanout';
  const defaultRouting = String(opts.defaultRouting ?? 'round_robin').trim().toLowerCase() || 'round_robin';
  const defaultAffinityTtlMs = Number(opts.defaultAffinityTtlMs ?? 0);
  let candidate: JsonObject;
  if (typeof raw === 'string') {
    candidate = { mode: raw };
  } else if (isJsonObject(raw)) {
    candidate = { ...raw };
  } else {
    candidate = {};
  }
  const mode = String(candidate.mode ?? defaultMode).trim().toLowerCase() || 'fanout';
  if (mode !== 'fanout' && mode !== 'queue') {
    throw new ValidationError("delivery_mode must be 'fanout' or 'queue'");
  }
  let routing = String(candidate.routing ?? (mode === 'queue' ? defaultRouting : '')).trim().toLowerCase();
  if (mode !== 'queue') {
    routing = '';
  } else if (routing && routing !== 'round_robin' && routing !== 'sender_affinity') {
    throw new ValidationError("queue_routing must be 'round_robin' or 'sender_affinity'");
  } else if (!routing) {
    routing = 'round_robin';
  }
  const ttlRaw = candidate.affinity_ttl_ms ?? (mode === 'queue' ? defaultAffinityTtlMs : 0);
  const affinityTtlMs = Math.max(0, Number(ttlRaw ?? 0));
  if (!Number.isFinite(affinityTtlMs)) {
    throw new ValidationError('affinity_ttl_ms must be an integer');
  }
  return {
    mode,
    routing,
    affinity_ttl_ms: affinityTtlMs,
  };
}

/**
 * AUN Core SDK 客户端 — 浏览器版本。
 *
 * 职责：
 *   - 连接管理（WebSocket + 自动重连 + 指数退避）
 *   - 认证（token 初始化 / 多策略认证 / token 刷新）
 *   - RPC 调用（JSON-RPC 2.0）
 *   - E2EE 自动编排（加密/解密/密钥管理/group 生命周期）
 *   - 事件分发与管道
 *   - 后台任务（心跳、token 刷新、V2 缓存清理）
 *
 */
export class AUNClient {
  /** SDK 配置模型 */
  readonly configModel: AUNConfig;
  /** 原始配置字典 */
  readonly config: RpcParams;

  private _aid: string | null = null;
  private _identity: IdentityRecord | null = null;
  private _state: string = 'idle';
  private _currentAid: AID | null = null;
  private _instanceProtectedHeaders: Record<string, string> | null = null;
  private _gatewayUrl: string | null = null;
  private _deviceId: string;
  private _slotId: string;
  private _connectedAt: number = 0;
  private _connectDeliveryMode: JsonObject;
  private _defaultConnectDeliveryMode: JsonObject;
  private _closing = false;
  private _sessionParams: ConnectParams | null = null;
  private _sessionOptions: SessionOptions = { ...DEFAULT_SESSION_OPTIONS };

  private _dispatcher: EventDispatcher;
  private _discovery: GatewayDiscovery;
  private _tokenStore: TokenStore;
  private _auth: AuthFlow;
  private _transport: RPCTransport;

  // E2EE 编排状态（内存缓存）
  private _certCache: Map<string, CachedPeerCert> = new Map();

  // 后台任务 handle（浏览器 setInterval/setTimeout）
  private _heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private _heartbeatCount = 0;
  private _tokenRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private _tokenRefreshFailures = 0;
  private _cacheCleanupTimer: ReturnType<typeof setInterval> | null = null;

  // V2 E2EE 状态
  private _v2Session?: V2Session;
  private _v2KeyStore?: V2KeyStore;
  private _v2SessionInitInFlight: Promise<void> | null = null;
  private _v2RuntimeGeneration = 0;
  private _v2BootstrapCache: Map<string, V2BootstrapEntry> = new Map();
  private _v2SenderIKPending: Map<string, V2SenderIKPendingEntry> = new Map();
  private _v2SenderIKFetching: Set<string> = new Set();
  private static readonly V2_BOOTSTRAP_TTL_MS = 60 * 60 * 1000;
  /** V2 state 签名验证缓存：cacheKey(hex) → expiry_unix_ms */
  private _v2SigCache: Map<string, number> = new Map();
  /** V2 state chain 本地记录：group_id → [state_version, chain_hash] */
  private _v2StateChains: Map<string, [number, string]> = new Map();
  /** 群安全等级追踪（变化时发布 group.v2.security_level 事件） */
  private _v2GroupSecurityLevels: Map<string, string> = new Map();
  /** 同一 group 的 V2 自动提案串行化，避免并发重复提交同一 state_version。 */
  private _v2AutoProposeInflight: Map<string, Promise<void>> = new Map();
  /** 同一 group 在运行中的自动提案期间收到的新触发，结束后至多再补跑一次。 */
  private _v2AutoProposePending: Set<string> = new Set();
  /** 最近一次已成功确认的 membership_snapshot；相同快照直接跳过。 */
  private _v2AutoProposeLastSnapshot: Map<string, string> = new Map();
  private _v2LazyProposeTriggered: Map<string, number> = new Map();
  /** agent.md 运行时管理器，负责上传、下载、缓存和 RPC 元数据观察。 */
  private _agentMdManager!: AgentMdManager;
  private _groupIndexMetaCache: GroupIndexMetaCache = new GroupIndexMetaCache();
  private _groupIndexCacheLoaded: Set<string> = new Set();
  /** 消息序列号跟踪器（群消息 + P2P 空洞检测） */
  private _seqTracker: SeqTracker = new SeqTracker();
  private _seqTrackerContext: string | null = null;
  /** 补洞去重：已完成/进行中的 key 集合，防止重复 pull 同一区间 */
  private _gapFillDone: Set<string> = new Set();
  /** 已发布到应用层的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发 */
  private _pushedSeqs: Map<string, Set<number>> = new Map();
  /** 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq） */
  private _pendingOrderedMsgs: Map<string, Map<number, { event: string; payload: EventPayload }>> = new Map();
  /** push 处理队列：按 P2P / group namespace 串行化异步解密与有序投递。 */
  private _pushProcessQueues: Map<string, Promise<void>> = new Map();
  /** Lazy group sync：首次发送群消息前自动拉取历史 */
  private _groupSynced: Set<string> = new Set();
  /** P2P 撤回去重：原始 message_id -> 时间戳，保证应用层只回调一次 */
  _messageRecallSeen: Map<string, number> = new Map();
  /** 群撤回去重：group_id|sorted(message_ids) -> 时间戳，保证应用层只回调一次 */
  _groupRecallSeen: Map<string, number> = new Map();
  /** 在线未读 hint 队列：同一 group 只保留最后一条，延迟 drain 降低登录瞬时拉取压力。 */
  private _onlineUnreadHintQueue: Map<string, JsonObject> = new Map();
  private _onlineUnreadHintTimer: ReturnType<typeof setTimeout> | null = null;
  private _onlineUnreadHintDrainActive = false;
  private _onlineUnreadHintInitialDelayMs = 750;
  private _onlineUnreadHintIntervalMs = 50;
  /** gap fill 来源标记：true 表示当前正在补洞（pull 触发），false 表示非补洞 */
  private _gapFillActive = false;
  private _backgroundRpcDepth = 0;
  // Pull Gate：序列化同一 key 的并发 pull 操作，防止重复拉取
  private _pullGates: Map<string, { inflight: boolean; startedAt: number; token: number }> = new Map();
  // 重连相关
  private _reconnectActive = false;
  private _reconnectAbort: AbortController | null = null;
  private _serverKicked = false;
  // 重连状态追踪（对齐 Python client.py）
  private _nextRetryAt: Date | null = null;
  private _retryAttempt: number = 0;
  private _retryMaxAttempts: number = 0;
  private _lastError: Error | null = null;
  private _lastErrorCode: string | null = null;
  /** 对端 AID 缓存（aid string → AID 对象） */
  private _peerCache = new Map<string, AID>();
  /**
   * 缓存最近一次服务端 gateway.disconnect 信息（含 code/reason/detail），
   * 让后续 connection.state(terminal_failed) 也能携带 detail（如配额超限信息）。
   */
  private _lastDisconnectInfo: { code?: any; reason?: string; detail?: Record<string, any> } | null = null;
  // Logger（per-client 单例 + 各模块子 logger）
  private _logger!: AUNLogger;
  private _clientLog!: ModuleLogger;
  private _logAuth!: ModuleLogger;
  private _logTransport!: ModuleLogger;
  private _tokenStoreLog!: ModuleLogger;
  private _logDiscovery!: ModuleLogger;
  private _logEvents!: ModuleLogger;
  private _runtime!: ClientRuntime;
  private _identityRuntime!: IdentityRuntimeManager;
  private _peerDirectory!: PeerDirectory;
  private _lifecycle!: LifecycleController;
  private _rpcPipeline!: RpcPipeline;
  private _delivery!: MessageDeliveryEngine;
  private _v2E2EE!: V2E2EECoordinator;
  private _groupState!: GroupStateCoordinator;
  private _storage?: StorageVFS;
  private _collab?: CollabClient;
  private _messageFacade?: MessageFacade;
  private _groupFacade?: GroupFacade;
  private _streamFacade?: StreamFacade;

  constructor(aid?: AID) {
    if (aid !== null && aid !== undefined && !isAIDObject(aid)) {
      throw new ValidationError('AUNClient only accepts an AID object or no argument');
    }
    const inputAid = aid ?? null;
    const rawConfig: RpcParams = {};
    if (inputAid) rawConfig.aun_path = inputAid.aunPath;
    const _debug = inputAid ? inputAid.debug : false;
    this.configModel = createConfig(rawConfig as Partial<AUNConfig>);
    const initAid = (inputAid && inputAid.isPrivateKeyValid()) ? inputAid.aid : null;
    this.config = {
      aun_path: this.configModel.aunPath,
      root_ca_path: this.configModel.rootCaPem,
      seed_password: this.configModel.seedPassword,
    };
    this._deviceId = (inputAid?.deviceId) || getDeviceId();

    // Logger 必须最早初始化（其他子模块构造时通过 logger 输出）
    this._logger = new AUNLogger({ debug: _debug, aunPath: this.configModel.aunPath });
    this._logger.bindDeviceId(this._deviceId);
    this._clientLog = this._logger.for('aun_core.client');
    this._logAuth = this._logger.for('aun_core.auth');
    this._logTransport = this._logger.for('aun_core.transport');
    this._tokenStoreLog = this._logger.for('aun_core.keystore');
    this._logDiscovery = this._logger.for('aun_core.discovery');
    this._logEvents = this._logger.for('aun_core.events');
    this._clientLog.info(`AUNClient initialized: debug=${_debug} aunPath=${this.configModel.aunPath} aid=${initAid ?? '-'}`);

    this._dispatcher = new EventDispatcher();
    this._discovery = new GatewayDiscovery();
    this._tokenStore = new IndexedDBTokenStore();
    this._slotId = inputAid?.slotId || 'default';
    this._connectDeliveryMode = normalizeDeliveryModeConfig({ mode: 'fanout' });
    this._defaultConnectDeliveryMode = { ...this._connectDeliveryMode };
    this._auth = new AuthFlow({
      tokenStore: this._tokenStore,
      crypto: new CryptoProvider(),
      aid: initAid,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPem: this.configModel.rootCaPem,
      verifySsl: this.configModel.verifySsl,
    });
    this._aid = initAid;
    this._agentMdManager = createAgentMdManagerForRuntime({
      config: () => this.configModel,
      logger: () => this._logger.for('aun_core.agent_md'),
      ownerAid: () => this._aid,
      currentAid: () => this._currentAid,
      gateway: {
        resolve: (target) => this._resolveGatewayForAid(target),
        get: () => this._gatewayUrl,
        set: (gatewayUrl) => { this._gatewayUrl = gatewayUrl; },
      },
      identity: {
        get: () => this._identity,
        set: (identity) => { this._identity = identity; },
      },
      auth: () => this._auth,
      tokenStore: () => this._tokenStore,
      fetchPeerCert: (target, certFingerprint) => this._fetchPeerCert(target, certFingerprint || undefined),
    });
    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: DEFAULT_SESSION_OPTIONS.timeouts.call,
      onDisconnect: (error, closeCode) => this._handleTransportDisconnect(error, closeCode),
    });
    this._transport.setMetaObserver((meta) =>
      this._observeRpcMeta(meta).catch((exc) => {
        this._clientLog.debug(`rpc meta observer skipped: ${String(exc)}`);
      }),
    );
    this._runtime = new ClientRuntime(this);
    this._identityRuntime = new IdentityRuntimeManager(this._runtime);
    this._peerDirectory = new PeerDirectory(this._runtime);
    this._lifecycle = new LifecycleController(this._runtime);
    this._rpcPipeline = new RpcPipeline(this._runtime);
    this._delivery = new MessageDeliveryEngine(this._runtime);
    this._v2E2EE = new V2E2EECoordinator(this._runtime);
    this._groupState = new GroupStateCoordinator(this._runtime);

    if (inputAid) {
      if (inputAid.isPrivateKeyValid()) {
        this._currentAid = inputAid;
        this._identity = {
          aid: inputAid.aid,
          private_key_pem: inputAid.privateKeyPem,
          public_key_der_b64: inputAid.publicKey,
          cert: inputAid.certPem,
        };
        this._auth.setIdentity(this._identity);
        this._state = 'standby';
      }
    }

    // 注入 logger 到各子模块（构造时未传 logger，构造后通过 setLogger 注入）
    this._auth.setLogger(this._logAuth);
    this._transport.setLogger(this._logTransport);
    this._dispatcher.setLogger(this._logEvents);
    if (typeof (this._discovery as any).setLogger === 'function') {
      (this._discovery as any).setLogger(this._logger.for('aun_core.discovery'));
    }
    if (typeof (this._tokenStore as any).setLogger === 'function') {
      (this._tokenStore as any).setLogger(this._tokenStoreLog);
    }

    // 内部订阅：推送消息 re-publish 给用户（V2 加密消息走 _raw.peer.v2.message_received）
    this._dispatcher.subscribe('_raw.message.received', (data) => {
      this._onRawMessageReceived(data);
    });
    this._dispatcher.subscribe('_raw.message.recalled', (data) => {
      this._safeAsync(this._onRawMessageRecalled(data));
    });
    // 群组消息推送：re-publish（V2 加密消息走 V2 push 路径）
    this._dispatcher.subscribe('_raw.group.message_created', (data) => {
      this._onRawGroupMessageCreated(data);
    });
    // 群组消息撤回推送：在线 push 通道，与 pull 双 tombstone 兜底互补（SDK 去重只回调一次）
    this._dispatcher.subscribe('_raw.group.message_recalled', (data) => {
      this._safeAsync(this._onRawGroupMessageRecalled(data));
    });
    // 群组变更事件：验签 + 透传 + gap 检测 + V2 state/SPK 维护
    this._dispatcher.subscribe('_raw.group.changed', (data) => {
      this._onRawGroupChanged(data);
    });
    // V2 P2P / 群组服务平面事件：统一在构造期订阅，避免重连或重复初始化时重复注册。
    this._dispatcher.subscribe('_raw.peer.v2.message_received', (data) => {
      this._safeAsync(this._onV2PushNotification(data));
    });
    this._dispatcher.subscribe('_raw.group.v2.message_created', (data) => {
      this._safeAsync(this._onRawGroupV2MessageCreated(data));
    });
    this._dispatcher.subscribe('_raw.group.v2.state_proposed', (data) => {
      this._safeAsync(this._onV2StateProposed(data));
    });
    this._dispatcher.subscribe('_raw.group.v2.state_retry_needed', (data) => {
      this._safeAsync(this._onV2StateRetryNeeded(data));
    });
    this._dispatcher.subscribe('_raw.group.v2.state_confirmed', (data) => {
      this._safeAsync(this._onV2StateConfirmed(data));
    });
    // 群组状态提交事件：验证 state_hash 链并更新本地存储
    this._dispatcher.subscribe('_raw.group.state_committed', (data) => {
      this._safeAsync(this._onGroupStateCommitted(data));
    });
    // 其他事件直接透传
    for (const evt of ['message.ack', 'storage.object_changed']) {
      this._dispatcher.subscribe(`_raw.${evt}`, (data) => {
        this._dispatcher.publish(evt, data);
      });
    }
    // 服务端主动断开通知：记录日志并标记不重连
    this._dispatcher.subscribe('_raw.gateway.disconnect', async (data) => {
      await this._onGatewayDisconnect(data);
    });
  }

  // ── 属性 ──────────────────────────────────────────

  get aid(): string | null {
    return this._aid;
  }

  /** AUN Storage VFS 入口 */
  get storage(): StorageVFS {
    if (!this._storage) this._storage = new StorageVFS(this);
    return this._storage;
  }

  /** AUN collab 协作层入口 */
  get collab(): CollabClient {
    if (!this._collab) this._collab = new CollabClient(this);
    return this._collab;
  }

  /** Message RPC facade 入口 */
  get message(): MessageFacade {
    if (!this._messageFacade) this._messageFacade = new MessageFacade(this);
    return this._messageFacade;
  }

  /** Group RPC facade 入口 */
  get group(): GroupFacade {
    if (!this._groupFacade) this._groupFacade = new GroupFacade(this);
    return this._groupFacade;
  }

  /** Stream RPC facade 入口 */
  get stream(): StreamFacade {
    if (!this._streamFacade) this._streamFacade = new StreamFacade(this);
    return this._streamFacade;
  }

  private async _observeAgentMdFromEnvelope(envelope: unknown): Promise<void> {
    await this._agentMdManager.observeEnvelope(envelope);
  }

  /** transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。 */
  private async _observeRpcMeta(meta: JsonObject): Promise<void> {
    const groupIndexes = isJsonObject(meta.group_indexes as JsonValue | object | null | undefined)
      ? meta.group_indexes as Record<string, unknown>
      : {};
    for (const groupAid of Object.keys(groupIndexes)) {
      await this._loadGroupIndexCache(groupAid);
    }
    this._groupIndexMetaCache.observeRpcMeta(meta, { localAid: this._aid ?? '' });
    await this._agentMdManager.observeRpcMeta(meta, this._aid);
    for (const groupAid of Object.keys(groupIndexes)) {
      await this._persistGroupIndexCache(groupAid, {
        remote_meta: this._groupIndexMetaCache.remoteMeta(this._aid ?? '', groupAid) ?? {},
        local_etag: this._groupIndexMetaCache.localEtag(this._aid ?? '', groupAid),
      });
    }
  }

  isGroupIndexStale(groupAid: string): boolean {
    return this._groupIndexMetaCache.isStale(this._aid ?? '', groupAid);
  }

  markGroupIndexFresh(groupAid: string, options: { etag: string }): void {
    this._groupIndexMetaCache.markFresh(this._aid ?? '', groupAid, options);
    void this._persistGroupIndexCache(groupAid, { local_etag: String(options.etag ?? '') });
  }

  getGroupIndexRemoteMeta(groupAid: string): Record<string, unknown> | null {
    return this._groupIndexMetaCache.remoteMeta(this._aid ?? '', groupAid);
  }

  getGroupIndexLocalEtag(groupAid: string): string {
    return this._groupIndexMetaCache.localEtag(this._aid ?? '', groupAid);
  }

  async getGroupIndexCachedSettings(groupAid: string, keys: string[]): Promise<Record<string, unknown> | null> {
    await this._loadGroupIndexCache(groupAid);
    return this._groupIndexMetaCache.cachedSettings(this._aid ?? '', groupAid, keys.map((item) => String(item)));
  }

  async getGroupIndexCachedSettingsByEntries(groupAid: string, keys: string[], entries: Array<Record<string, unknown>>) {
    await this._loadGroupIndexCache(groupAid);
    return this._groupIndexMetaCache.cachedSettingsByEntries(
      this._aid ?? '',
      groupAid,
      keys.map((item) => String(item)),
      entries as any,
    );
  }

  cacheGroupIndexSettings(
    groupAid: string,
    settings: Record<string, unknown>,
    options?: { entries?: Array<Record<string, unknown>>; etag?: string; groupIndex?: unknown },
  ): Promise<void> {
    this._groupIndexMetaCache.cacheSettings(this._aid ?? '', groupAid, settings, options as any);
    const entryEtags: Record<string, string> = {};
    for (const item of options?.entries ?? []) {
      const key = String(item.key ?? '');
      if (key) entryEtags[key] = String(item.etag ?? '');
    }
    const fields: GroupIndexCacheUpsert = {
      settings,
      entry_etags: entryEtags,
      remote_meta: this._groupIndexMetaCache.remoteMeta(this._aid ?? '', groupAid) ?? {},
      local_etag: String(options?.etag ?? this._groupIndexMetaCache.localEtag(this._aid ?? '', groupAid) ?? ''),
    };
    const indexJsonl = groupIndexBodyText(options?.groupIndex);
    if (indexJsonl) fields.index_jsonl = indexJsonl;
    return this._persistGroupIndexCache(groupAid, fields);
  }

  private _groupIndexCacheKey(groupAid: string): string {
    return `${this._aid ?? ''}\x00${String(groupAid ?? '')}`;
  }

  private async _loadGroupIndexCache(groupAid: string): Promise<void> {
    const localAid = String(this._aid ?? '').trim();
    const group = String(groupAid ?? '').trim();
    if (!localAid || !group || typeof this._tokenStore.loadGroupIndexCache !== 'function') return;
    const key = this._groupIndexCacheKey(group);
    if (this._groupIndexCacheLoaded.has(key)) return;
    this._groupIndexCacheLoaded.add(key);
    const record = await this._tokenStore.loadGroupIndexCache(localAid, group);
    if (!record) return;
    this._groupIndexMetaCache.restore(localAid, group, {
      remote_meta: record.remote_meta,
      local_etag: record.local_etag,
      settings: record.settings,
      entry_etags: record.entry_etags,
    });
  }

  private async _persistGroupIndexCache(groupAid: string, fields: GroupIndexCacheUpsert): Promise<void> {
    const localAid = String(this._aid ?? '').trim();
    const group = String(groupAid ?? '').trim();
    if (!localAid || !group || typeof this._tokenStore.upsertGroupIndexCache !== 'function') return;
    const record = await this._tokenStore.upsertGroupIndexCache(localAid, group, fields);
    this._groupIndexCacheLoaded.add(this._groupIndexCacheKey(group));
    this._groupIndexMetaCache.restore(localAid, group, {
      remote_meta: record.remote_meta,
      local_etag: record.local_etag,
      settings: record.settings,
      entry_etags: record.entry_etags,
    });
  }

  get state(): ConnectionState {
    return this._publicState(this._state);
  }

  private _publicState(state: string): ConnectionState {
    return STATE_TO_PUBLIC[state] ?? (state as ConnectionState);
  }

  get currentAid(): AID | null {
    return this._currentAid;
  }

  get hasIdentity(): boolean {
    return this._currentAid !== null && this.state !== ConnectionState.CLOSED;
  }

  get canSign(): boolean {
    return this.hasIdentity && !!this._currentAid?.isPrivateKeyValid();
  }

  get canConnect(): boolean {
    return this.hasIdentity && this.state !== ConnectionState.CLOSED;
  }

  get canSend(): boolean {
    return this.state === ConnectionState.READY;
  }

  get isReady(): boolean { return this.canSend; }
  get isOnline(): boolean {
    return this.state === ConnectionState.READY
      || this.state === ConnectionState.RECONNECTING
      || this.state === ConnectionState.RETRY_BACKOFF;
  }
  get isClosed(): boolean { return this.state === ConnectionState.CLOSED; }
  get aunPath(): string | null { return this.hasIdentity ? this._currentAid?.aunPath ?? this.configModel.aunPath : null; }

  /** 下次重连时间（仅在 retry_backoff 状态时非 null，对齐 Python next_retry_at） */
  get nextRetryAt(): Date | null {
    return this.state === ConnectionState.RETRY_BACKOFF ? this._nextRetryAt : null;
  }

  /** 距下次重连的剩余秒数（仅在 retry_backoff 状态时非 null，对齐 Python next_retry_in_seconds） */
  get nextRetryInSeconds(): number | null {
    const t = this.nextRetryAt;
    if (t === null) return null;
    return Math.max(0, (t.getTime() - Date.now()) / 1000);
  }

  /** 当前重连尝试次数（对齐 Python retry_attempt） */
  get retryAttempt(): number { return this._retryAttempt; }

  /** 最大重连次数（0 = 无限，对齐 Python retry_max_attempts） */
  get retryMaxAttempts(): number { return this._retryMaxAttempts; }

  /** 最近一次错误（对齐 Python last_error） */
  get lastError(): Error | null { return this._lastError; }

  /** 最近一次错误码（对齐 Python last_error_code） */
  get lastErrorCode(): string | null { return this._lastErrorCode; }

  private _v2SessionMatchesIdentity(): boolean {
    if (!this._v2Session) return false;
    const session = this._v2Session as { aid?: string; deviceId?: string; currentIkPubDer?: unknown };
    if (session.currentIkPubDer === undefined) return true;
    return session.aid === this._aid && session.deviceId === this._deviceId;
  }

  private _resetV2IdentityRuntime(): void {
    this._v2RuntimeGeneration += 1;
    const keyStore = this._v2KeyStore as (V2KeyStore & { close?: () => void }) | undefined;
    try {
      keyStore?.close?.();
    } catch (exc) {
      this._clientLog?.debug?.(`V2 keystore cleanup skipped: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
    this._v2Session = undefined;
    this._v2KeyStore = undefined;
    this._v2SessionInitInFlight = null;
    this._v2BootstrapCache.clear();
    this._v2SenderIKPending.clear();
    this._v2SenderIKFetching.clear();
    this._v2SigCache.clear();
    this._v2StateChains.clear();
    this._v2GroupSecurityLevels.clear();
    this._v2AutoProposeInflight.clear();
    this._v2AutoProposePending.clear();
    this._v2AutoProposeLastSnapshot.clear();
    this._v2LazyProposeTriggered.clear();
    this._v2PullInflight = false;
    this._v2PullPending = false;
  }

  private _applyAidRuntimeContext(aid: AID): void {
    const oldTransport = this._transport as unknown as { close?: () => Promise<void> | void } | undefined;
    try {
      const closeResult = oldTransport?.close?.();
      if (closeResult && typeof (closeResult as Promise<void>).catch === 'function') {
        void (closeResult as Promise<void>).catch((exc: unknown) => {
          this._clientLog.debug(`old transport cleanup skipped: ${exc instanceof Error ? exc.message : String(exc)}`);
        });
      }
    } catch (exc) {
      this._clientLog.debug(`old transport cleanup skipped: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
    this._resetV2IdentityRuntime();

    const nextConfig = createConfig({
      aunPath: aid.aunPath,
      rootCaPem: aid.rootCaPath,
      verifySsl: aid.verifySsl,
    });
    Object.assign(this.configModel, nextConfig);
    this.config.aun_path = nextConfig.aunPath;
    this.config.root_ca_path = nextConfig.rootCaPem;
    this.config.seed_password = nextConfig.seedPassword;
    this._peerCache.clear();
    this._certCache.clear();
    this._gatewayUrl = null;

    this._deviceId = aid.deviceId || getDeviceId();
    this._slotId = aid.slotId || 'default';

    this._logger = new AUNLogger({ debug: aid.debug, aunPath: nextConfig.aunPath });
    this._logger.bindDeviceId(this._deviceId);
    this._clientLog = this._logger.for('aun_core.client');
    this._logAuth = this._logger.for('aun_core.auth');
    this._logTransport = this._logger.for('aun_core.transport');
    this._tokenStoreLog = this._logger.for('aun_core.keystore');
    this._logDiscovery = this._logger.for('aun_core.discovery');
    this._logEvents = this._logger.for('aun_core.events');

    this._discovery = new GatewayDiscovery();
    this._tokenStore = new IndexedDBTokenStore();
    this._auth = new AuthFlow({
      tokenStore: this._tokenStore,
      crypto: new CryptoProvider(),
      aid: aid.aid,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPem: nextConfig.rootCaPem,
      verifySsl: nextConfig.verifySsl,
    });
    this._agentMdManager = createAgentMdManagerForRuntime({
      config: () => this.configModel,
      logger: () => this._logger.for('aun_core.agent_md'),
      ownerAid: () => this._aid,
      currentAid: () => this._currentAid,
      gateway: {
        resolve: (target) => this._resolveGatewayForAid(target),
        get: () => this._gatewayUrl,
        set: (gatewayUrl) => { this._gatewayUrl = gatewayUrl; },
      },
      identity: {
        get: () => this._identity,
        set: (identity) => { this._identity = identity; },
      },
      auth: () => this._auth,
      tokenStore: () => this._tokenStore,
      fetchPeerCert: (target, certFingerprint) => this._fetchPeerCert(target, certFingerprint || undefined),
    });
    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: DEFAULT_SESSION_OPTIONS.timeouts.call,
      onDisconnect: (error, closeCode) => this._handleTransportDisconnect(error, closeCode),
    });
    this._transport.setMetaObserver((meta) =>
      this._observeRpcMeta(meta).catch((exc) => {
        this._clientLog.debug(`rpc meta observer skipped: ${String(exc)}`);
      }),
    );
    this._auth.setLogger(this._logAuth);
    this._transport.setLogger(this._logTransport);
    this._dispatcher.setLogger(this._logEvents);
    if (typeof (this._discovery as any).setLogger === 'function') {
      (this._discovery as any).setLogger(this._logDiscovery);
    }
    if (typeof (this._tokenStore as any).setLogger === 'function') {
      (this._tokenStore as any).setLogger(this._tokenStoreLog);
    }
  }

  loadIdentity(aid: AID): void {
    this._identityRuntime.loadIdentity(aid);
  }

  setProtectedHeaders(headers: Record<string, unknown> | null): void {
    if (!headers) {
      this._instanceProtectedHeaders = null;
      return;
    }
    const cleaned: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (key === '_auth') continue;
      cleaned[String(key)] = String(value);
    }
    this._instanceProtectedHeaders = Object.keys(cleaned).length ? cleaned : null;
  }

  getProtectedHeaders(): Record<string, string> | null {
    return this._instanceProtectedHeaders ? { ...this._instanceProtectedHeaders } : null;
  }

  cachePeer(aid: AID): AID {
    return this._peerDirectory.cachePeer(aid);
  }

  getPeer(aid: string): AID | null {
    return this._peerDirectory.getPeer(aid);
  }

  async lookupPeer(aid: string): Promise<AID> {
    return this._peerDirectory.lookupPeer(aid);
  }

  peers(): AID[] {
    return this._peerDirectory.peers();
  }

  get gatewayUrl(): string | null {
    return this._gatewayUrl;
  }

  get discovery(): GatewayDiscovery {
    return this._discovery;
  }

  /** 最近一次 health check 结果，null 表示尚未检查 */
  get gatewayHealth(): boolean | null {
    return this._discovery.lastHealthy;
  }

  // ── 生命周期 ──────────────────────────────────────

  /** 仅认证当前身份，获取/刷新 token，但不建立长连接。 */
  async authenticate(options: RpcParams = {}): Promise<Record<string, unknown>> {
    return this._lifecycle.authenticate(options);
  }

  /** 连接到 Gateway；身份来自构造函数或 loadIdentity(aid)，认证由 SDK 内部自动完成。 */
  async connect(opts?: ConnectionOptions): Promise<void> {
    return this._lifecycle.connect(opts);
  }

  /** 断开连接但保留本地状态，可再次 connect */
  async disconnect(): Promise<void> {
    return this._lifecycle.disconnect();
  }

  /** 关闭连接 */
  async close(): Promise<void> {
    return this._lifecycle.close();
  }


  // ── RPC ───────────────────────────────────────────

  /**
   * 发起 RPC 调用。
   *
   * 自动拦截内部方法、自动加密 message.send/group.send、
   * 自动解密 message.pull/group.pull、Group E2EE 生命周期编排。
   */
  async call(
    method: string,
    params?: RpcParams,
  ): Promise<RpcResult> {
    try {
      return await this._rpcPipeline.call(method, params);
    } catch (err) {
      await this._maybeHandleHalfOpenRpcFailure(err);
      throw err;
    }
  }

  private async _maybeHandleHalfOpenRpcFailure(err: unknown): Promise<void> {
    if (this._closing || this.state !== ConnectionState.READY) return;
    if (!this._sessionOptions?.auto_reconnect || this._reconnectActive) return;
    if (!(err instanceof ConnectionError) && !(err instanceof TimeoutError)) return;
    await this._handleTransportDisconnect(err);
  }

  async createGroup(params: RpcParams = {}): Promise<RpcResult> {
    if (!isJsonObject(params)) {
      throw new ValidationError('createGroup params must be an object');
    }
    const payload: RpcParams = { ...params };
    const groupName = String(payload.group_name ?? payload.groupName ?? '').trim();
    if (!groupName) {
      return await this.call('group.create', payload);
    }

    const keyPair = await new CryptoProvider().generateIdentity();
    payload.public_key = keyPair.public_key_der_b64;
    payload.curve = keyPair.curve;
    const result = await this.call('group.create', payload);

    const resultMap = isJsonObject(result) ? result : {};
    const group = isJsonObject(resultMap.group) ? resultMap.group : {};
    const aidCert = isJsonObject(resultMap.aid_cert) ? resultMap.aid_cert : {};
    const groupAid = String(group.group_aid ?? resultMap.group_aid ?? '').trim();
    const certPem = String(aidCert.cert ?? aidCert.cert_pem ?? resultMap.cert ?? resultMap.cert_pem ?? '').trim();
    if (!groupAid || !certPem) {
      throw new ValidationError('group.create named group response missing group.group_aid or aid_cert.cert');
    }

    const store = new AIDStore({
      aunPath: this.configModel.aunPath,
      encryptionSeed: this.configModel.seedPassword ?? '',
      slotId: this._slotId,
      rootCaPem: this.configModel.rootCaPem,
      verifySsl: this.configModel.verifySsl,
    });
    try {
      const imported = await store.importGroupIdentity(groupAid, {
        private_key_pem: keyPair.private_key_pem,
        public_key_der_b64: keyPair.public_key_der_b64,
        curve: keyPair.curve,
        cert_pem: certPem,
      });
      if (!imported.ok) {
        throw new ValidationError(imported.error.message);
      }
    } finally {
      store.close();
    }
    return result;
  }

  async bindGroupAid(params: RpcParams = {}, options: BindGroupAidOptions = {}): Promise<RpcResult> {
    if (!isJsonObject(params)) {
      throw new ValidationError('bindGroupAid params must be an object');
    }
    const store = options.aidStore;
    if (!store) {
      throw new ValidationError('bindGroupAid requires aidStore');
    }

    const groupId = String(params.group_id ?? params.group_aid ?? '').trim();
    const keystore = (store as any)._keystore;
    let keyPair: KeyPairRecord | null = null;

    // 优先复用 pending 槽位中已暂存的待绑定密钥（崩溃/重试幂等）
    if (groupId && keystore && typeof keystore.loadPendingGroupBind === 'function') {
      keyPair = await keystore.loadPendingGroupBind(groupId);
    }

    if (!keyPair || !keyPair.public_key_der_b64 || !keyPair.private_key_pem) {
      // 未命中 pending，生成新密钥
      const generated = await new CryptoProvider().generateIdentity();
      keyPair = {
        private_key_pem: generated.private_key_pem,
        public_key_der_b64: generated.public_key_der_b64,
        curve: generated.curve,
      };
      // 发 RPC 前先落盘暂存，确保崩溃后重试能复用同一密钥
      if (groupId && keystore && typeof keystore.savePendingGroupBind === 'function') {
        await keystore.savePendingGroupBind(groupId, keyPair);
      }
    }

    if (!keyPair) {
      throw new ValidationError('bindGroupAid: failed to generate or load key pair');
    }

    const payload: RpcParams = { ...params };
    if (!String(payload.group_id ?? '').trim() && groupId) {
      payload.group_id = groupId;
    }
    payload.public_key = keyPair.public_key_der_b64;
    payload.curve = keyPair.curve;
    const result = await this.call('group.bind_group_aid', payload);

    const resultMap = isJsonObject(result) ? result : {};
    const group = isJsonObject(resultMap.group) ? resultMap.group : {};
    const aidCert = isJsonObject(resultMap.aid_cert) ? resultMap.aid_cert : {};
    const groupAid = String(group.group_aid ?? resultMap.group_aid ?? '').trim();
    const certPem = String(aidCert.cert ?? aidCert.cert_pem ?? resultMap.cert ?? resultMap.cert_pem ?? '').trim();
    if (!groupAid || !certPem) {
      throw new ValidationError('group.bind_group_aid response missing group.group_aid or aid_cert.cert');
    }

    const imported = await store.importGroupIdentity(groupAid, {
      private_key_pem: keyPair.private_key_pem,
      public_key_der_b64: keyPair.public_key_der_b64,
      curve: keyPair.curve,
      cert_pem: certPem,
    });
    if (!imported.ok) {
      throw new ValidationError(imported.error.message);
    }
    // 落盘成功，清除 pending 槽位
    if (groupId && keystore && typeof keystore.clearPendingGroupBind === 'function') {
      await keystore.clearPendingGroupBind(groupId);
    }
    return result;
  }

  async renewGroupAid(params: RpcParams = {}, options: BindGroupAidOptions = {}): Promise<RpcResult> {
    if (!isJsonObject(params)) {
      throw new ValidationError('renewGroupAid params must be an object');
    }
    const store = options.aidStore;
    if (!store) {
      throw new ValidationError('renewGroupAid requires aidStore');
    }
    const groupId = String(params.group_id ?? params.group_aid ?? '').trim();
    if (!groupId) {
      throw new ValidationError('renewGroupAid requires group_id or group_aid');
    }
    let groupAid = String(params.group_aid ?? '').trim();
    if (!groupAid) {
      const info = await this.call('group.get_info', { group_id: groupId, required: ['member'] });
      groupAid = String((info as any)?.group_aid ?? '').trim();
    }
    if (!groupAid) {
      throw new ValidationError('renewGroupAid: unable to determine group_aid');
    }

    const loaded = await store.load(groupAid);
    if (!loaded.ok || !loaded.data) {
      throw new ValidationError(`renewGroupAid: group_aid identity not found: ${groupAid}`);
    }
    const oldAidObj = loaded.data.aid;
    if (!oldAidObj.isPrivateKeyValid() || !oldAidObj.privateKeyPem) {
      throw new ValidationError(`renewGroupAid: group_aid has no private key: ${groupAid}`);
    }
    const oldPublicKey = oldAidObj.publicKey;
    if (!oldPublicKey) {
      throw new ValidationError(`renewGroupAid: cannot determine old public key for ${groupAid}`);
    }

    const newKeyPair = await new CryptoProvider().generateIdentity();
    const newPublicKey = newKeyPair.public_key_der_b64;
    const newPrivateKey = newKeyPair.private_key_pem;
    const curve = newKeyPair.curve || 'P-256';
    if (!newPublicKey || !newPrivateKey) {
      throw new ValidationError('renewGroupAid: generated incomplete group identity');
    }

    const nonce = globalThis.crypto.randomUUID().replace(/-/g, '');
    const issuedMs = Date.now();
    const oldHash = bytesToHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(oldPublicKey))));
    const newHash = bytesToHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(newPublicKey))));
    const canonical = [
      'aun-group-aid-renew-v1',
      groupId.toLowerCase(),
      groupAid.toLowerCase(),
      oldHash,
      newHash,
      nonce,
      String(issuedMs),
    ].join('|');
    const signed = await oldAidObj.sign(canonical);
    if (!signed.ok) {
      throw new ValidationError(`renewGroupAid: sign failed: ${signed.error.message}`);
    }

    const payload: RpcParams = { ...params };
    if (!String(payload.group_id ?? '').trim()) {
      payload.group_id = groupId;
    }
    payload.group_aid = groupAid;
    payload.old_public_key = oldPublicKey;
    payload.new_public_key = newPublicKey;
    payload.curve = curve;
    payload.renew_proof = { nonce, issued_ms: issuedMs, signature: signed.data.signature };

    const result = await this.call('group.renew_group_aid', payload);
    const resultMap = isJsonObject(result) ? result : {};
    const group = isJsonObject(resultMap.group) ? resultMap.group : {};
    const aidCert = isJsonObject(resultMap.aid_cert) ? resultMap.aid_cert : {};
    const returnedGroupAid = String(group.group_aid ?? resultMap.group_aid ?? groupAid).trim();
    const certPem = String(aidCert.cert ?? aidCert.cert_pem ?? resultMap.cert ?? resultMap.cert_pem ?? '').trim();
    if (!returnedGroupAid || !certPem) {
      throw new ValidationError('renewGroupAid response missing group.group_aid or aid_cert.cert');
    }

    const imported = await store.importGroupIdentity(returnedGroupAid, {
      private_key_pem: newPrivateKey,
      public_key_der_b64: newPublicKey,
      curve,
      cert_pem: certPem,
    });
    if (!imported.ok) {
      throw new ValidationError(`renewGroupAid failed to persist group identity: ${imported.error.message}`);
    }
    return result;
  }

  async startGroupTransfer(params: RpcParams = {}, options: CompleteGroupTransferOptions = {}): Promise<RpcResult> {
    if (!isJsonObject(params)) {
      throw new ValidationError('startGroupTransfer params must be an object');
    }
    const store = options.aidStore;
    if (!store) {
      throw new ValidationError('startGroupTransfer requires aidStore');
    }
    const groupId = String(params.group_id ?? '').trim();
    const newOwner = String(params.new_owner ?? '').trim();
    if (!groupId || !newOwner) {
      throw new ValidationError('startGroupTransfer requires group_id and new_owner');
    }
    let groupAid = String(params.group_aid ?? '').trim();
    if (!groupAid) {
      const info = await this.call('group.get_info', { group_id: groupId, required: ['member'] });
      groupAid = String((info as any)?.group_aid ?? '').trim();
    }
    if (!groupAid) {
      throw new ValidationError('startGroupTransfer: unable to determine group_aid');
    }
    const loaded = await store.load(groupAid);
    if (!loaded.ok || !loaded.data) {
      throw new ValidationError(`startGroupTransfer: group_aid identity not found: ${groupAid}`);
    }
    const aidObj = loaded.data.aid;
    if (!aidObj.isPrivateKeyValid() || !aidObj.privateKeyPem) {
      throw new ValidationError(`startGroupTransfer: group_aid private key not found: ${groupAid}`);
    }
    const nonce = globalThis.crypto.randomUUID().replace(/-/g, '');
    const issuedMs = Date.now();
    const canonical = [
      'aun-group-owner-transfer-v1',
      groupId.toLowerCase(),
      groupAid.toLowerCase(),
      newOwner.toLowerCase(),
      nonce,
      String(issuedMs),
    ].join('|');
    const signed = await aidObj.sign(canonical);
    if (!signed.ok) {
      throw new ValidationError(`startGroupTransfer: sign failed: ${signed.error.message}`);
    }
    const payload: RpcParams = { ...params, group_aid: groupAid };
    payload.transfer_auth = { nonce, issued_ms: issuedMs, signature: signed.data.signature };
    return await this.call('group.transfer_owner', payload);
  }

  async completeGroupTransfer(params: RpcParams = {}, options: CompleteGroupTransferOptions = {}): Promise<RpcResult> {
    if (!isJsonObject(params)) {
      throw new ValidationError('completeGroupTransfer params must be an object');
    }
    const store = options.aidStore;
    if (!store) {
      throw new ValidationError('completeGroupTransfer requires aidStore');
    }

    const keyPair = await new CryptoProvider().generateIdentity();
    const payload: RpcParams = { ...params };
    const groupId = String(params.group_id ?? '').trim();
    if (!groupId) {
      throw new ValidationError('completeGroupTransfer requires group_id');
    }
    let groupAid = String(params.group_aid ?? '').trim();
    if (!groupAid) {
      const info = await this.call('group.get_info', { group_id: groupId, required: ['member'] });
      groupAid = String((info as any)?.group_aid ?? '').trim();
    }
    if (!groupAid) {
      throw new ValidationError('completeGroupTransfer: unable to determine group_aid');
    }
    const current = this.currentAid;
    const newOwner = String(current?.aid ?? '').trim();
    if (!current || !newOwner || !current.isPrivateKeyValid()) {
      throw new ValidationError('completeGroupTransfer requires current new-owner AID with private key');
    }
    const nonce = globalThis.crypto.randomUUID().replace(/-/g, '');
    const issuedMs = Date.now();
    const publicKeyHash = bytesToHex(new Uint8Array(
      await globalThis.crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(keyPair.public_key_der_b64),
      ),
    ));
    const canonical = [
      'aun-group-owner-transfer-accept-v1',
      groupId.toLowerCase(),
      groupAid.toLowerCase(),
      newOwner.toLowerCase(),
      publicKeyHash,
      nonce,
      String(issuedMs),
    ].join('|');
    const signed = await current.sign(canonical);
    if (!signed.ok) {
      throw new ValidationError(`completeGroupTransfer: accept sign failed: ${signed.error.message}`);
    }
    payload.group_aid = groupAid;
    payload.public_key = keyPair.public_key_der_b64;
    payload.curve = keyPair.curve;
    payload.transfer_accept = { nonce, issued_ms: issuedMs, signature: signed.data.signature };
    const result = await this.call('group.complete_transfer', payload);

    const resultMap = isJsonObject(result) ? result : {};
    const group = isJsonObject(resultMap.group) ? resultMap.group : {};
    const aidCert = isJsonObject(resultMap.aid_cert) ? resultMap.aid_cert : {};
    const returnedGroupAid = String(group.group_aid ?? resultMap.group_aid ?? '').trim();
    const certPem = String(aidCert.cert ?? aidCert.cert_pem ?? resultMap.cert ?? resultMap.cert_pem ?? '').trim();
    if (!returnedGroupAid || !certPem) {
      throw new ValidationError('group.complete_transfer response missing group.group_aid or aid_cert.cert');
    }

    const imported = await store.importGroupIdentity(returnedGroupAid, {
      private_key_pem: keyPair.private_key_pem,
      public_key_der_b64: keyPair.public_key_der_b64,
      curve: keyPair.curve,
      cert_pem: certPem,
    });
    if (!imported.ok) {
      throw new ValidationError(imported.error.message);
    }
    return result;
  }

  private static _notifyParamsSizeOk(params: RpcParams): boolean {
    return new TextEncoder().encode(JSON.stringify(params)).length <= MAX_NOTIFY_PAYLOAD_SIZE;
  }

  private static _validateNotifyEventMethod(method: string): string {
    const normalized = String(method ?? '').trim();
    if (!normalized.startsWith('event/app.') || normalized.length <= 'event/app.'.length) {
      throw new ValidationError('routed notify method must be event/app.*');
    }
    return normalized;
  }

  private static _normalizeNotifyTtl(value: unknown): number | undefined {
    if (value === undefined || value === null) return undefined;
    const ttl = Number(value);
    if (!Number.isInteger(ttl)) {
      throw new ValidationError('ttl_ms must be an integer');
    }
    if (ttl < 0 || ttl > 60000) {
      throw new ValidationError('ttl_ms must be between 0 and 60000');
    }
    return ttl;
  }

  /**
   * 发送轻量在线通知，不走离线存储、seq/pull 或 ack。
   */
  async notify(method: string, params?: RpcParams, options: NotifyOptions = {}): Promise<void> {
    if (params !== undefined && params !== null && !isJsonObject(params)) {
      throw new ValidationError('notify params must be an object');
    }
    const payload: RpcParams = { ...(params ?? {}) };
    if (!AUNClient._notifyParamsSizeOk(payload)) {
      throw new ValidationError('notify payload is too large');
    }

    const targetAid = String(options.to ?? '').trim();
    const targetGroupId = String(options.group_aid ?? options.groupAid ?? options.group_id ?? options.groupId ?? '').trim();
    const targetDeviceId = String(options.device_id ?? options.deviceId ?? '').trim();
    const targetSlotId = String(options.slot_id ?? options.slotId ?? '').trim();
    const ttl = AUNClient._normalizeNotifyTtl(options.ttl_ms ?? options.ttlMs);

    if (targetAid && targetGroupId) {
      throw new ValidationError('notify() cannot set both to and group_id');
    }
    if (targetSlotId && !targetDeviceId) {
      throw new ValidationError('slot_id requires device_id for notify target');
    }

    if (targetAid) {
      const eventMethod = AUNClient._validateNotifyEventMethod(method);
      // 校验目标 AID 格式（拒绝 __system__ 等非法格式）
      validateAIDFormat(targetAid, 'notify.to');
      const target: JsonObject = { type: 'aid', aid: targetAid };
      if (targetDeviceId) target.device_id = targetDeviceId;
      if (targetSlotId) target.slot_id = targetSlotId;
      const routeParams: RpcParams = {
        target,
        deliver: { method: eventMethod, params: payload },
      };
      if (ttl !== undefined) routeParams.ttl_ms = ttl;
      await this._transport.notify('notification/route', routeParams);
      return;
    }

    if (targetGroupId) {
      const eventMethod = AUNClient._validateNotifyEventMethod(method);
      // 校验目标 Group ID 格式
      validateGroupIDFormat(targetGroupId, 'notify.group_id');
      const normalizedGroupId = normalizeGroupId(targetGroupId);
      if (!normalizedGroupId) {
        throw new ValidationError('group_id is required for group notify');
      }
      const routeParams: RpcParams = {
        group_aid: normalizedGroupId,
        group_id: normalizedGroupId,
        deliver: { method: eventMethod, params: payload },
      };
      if (ttl !== undefined) routeParams.ttl_ms = ttl;
      await this._transport.notify('notification/group.route', routeParams);
      return;
    }

    if (targetDeviceId || targetSlotId) {
      throw new ValidationError('device_id and slot_id require to');
    }
    const directMethod = String(method ?? '').trim();
    if (!directMethod.startsWith('notification/')) {
      throw new ValidationError('direct notify method must start with notification/');
    }
    await this._transport.notify(directMethod, payload);
  }

  private async _callRawV2Rpc(method: string, params?: RpcParams): Promise<RpcResult> {
    const p: RpcParams = { ...(params ?? {}) };
    const rpcBackground = Boolean((p as Record<string, unknown>)._rpc_background) || this._backgroundRpcDepth > 0;
    delete (p as Record<string, unknown>)._rpc_background;
    delete (p as Record<string, unknown>)._pull_gate_locked;
    delete (p as Record<string, unknown>)._skip_auto_ack;
    delete (p as Record<string, unknown>).skip_auto_ack;
    delete (p as Record<string, unknown>)._group_cursor_params;
    if (method.startsWith('group.') && p.group_aid !== undefined && p.group_aid !== null) {
      p.group_aid = normalizeGroupId(String(p.group_aid)) || String(p.group_aid);
    } else if (method.startsWith('group.') && p.group_id !== undefined && p.group_id !== null) {
      p.group_aid = normalizeGroupId(String(p.group_id)) || String(p.group_id);
    }
    if (method.startsWith('group.') && p.device_id === undefined) {
      p.device_id = this._deviceId;
    }
    if (method.startsWith('group.') && p.slot_id === undefined) {
      p.slot_id = this._slotId;
    }
    return await this._rpcPipeline.rawCall(method, p, { background: rpcBackground }) as RpcResult;
  }

  // ── 事件 ──────────────────────────────────────────

  /**
   * 订阅事件。
   *
   * 注意：off() 使用引用相等（===）匹配 handler，匿名函数将无法通过
   * off() 取消订阅。建议使用返回的 Subscription 对象调用 unsubscribe()。
   */
  on(event: string, handler: EventHandler): Subscription {
    return this._dispatcher.subscribe(event, handler);
  }

  /** 取消订阅事件 */
  off(event: string, handler: EventHandler): void {
    this._dispatcher.unsubscribe(event, handler);
  }

  // ── 事件管道：消息解密 ────────────────────────────

  private _isEncryptedPushMessage(msg: Record<string, unknown>): boolean {
    return this._v2E2EE.isEncryptedPushMessage(msg);
  }

  private _attachV2EnvelopeMetadataFromSource(message: Record<string, unknown>, source: unknown): void {
    attachV2EnvelopeMetadataFromSource(message, source);
  }

  /** 处理 transport 层推送的原始消息：re-publish 给用户（V2 加密消息走 _raw.peer.v2.message_received） */
  private _onRawMessageReceived(data: EventPayload): void {
    this._delivery.onRawMessageReceived(data);
  }

  private async _onRawMessageRecalled(data: EventPayload): Promise<void> {
    return this._delivery.onRawMessageRecalled(data);
  }

  /** 处理群组消息推送：re-publish（V2 加密消息走 V2 push 路径） */
  private _onRawGroupMessageCreated(data: EventPayload): void {
    return this._delivery.onRawGroupMessageCreated(data);
  }

  private async _onRawGroupMessageRecalled(data: EventPayload): Promise<void> {
    return this._delivery.onRawGroupMessageRecalled(data);
  }

  /** 处理 V2 群消息通知：主动 pull V2 envelope，由 pullGroupV2 解密并发布。 */
  private async _onRawGroupV2MessageCreated(data: EventPayload): Promise<void> {
    return this._delivery.onRawGroupV2MessageCreated(data);
  }

  private async _publishEncryptedPushMessage(
    normalEvent: string,
    undecryptableEvent: string,
    ns: string,
    seq: unknown,
    msg: Record<string, unknown>,
    group: boolean,
  ): Promise<boolean> {
    return await this._v2E2EE.publishEncryptedPushMessage(normalEvent, undecryptableEvent, ns, seq, msg, group);
  }

  private async _decryptV2PushMessage(data: EventPayload): Promise<Record<string, unknown> | null> {
    return await this._v2E2EE.decryptV2PushMessage(data);
  }

  /** 后台补齐 P2P 消息空洞 */
  private async _fillP2pGap(): Promise<void> {
    return this._delivery.fillP2pGap();
  }

  private _markPublishedSeq(ns: string, seq: number): void {
    this._delivery.markPublishedSeq(ns, seq);
  }

  private async _publishAppEvent(event: string, payload: EventPayload): Promise<void> {
    await this._delivery.publishAppEvent(event, payload);
  }

  private _echoTimestamp(): string {
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');
    const ms = String(now.getMilliseconds()).padStart(3, '0');
    return `${hh}:${mm}:${ss}.${ms}`;
  }

  private _isEchoPayload(payload: unknown): payload is { text: string; [k: string]: unknown } {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
    const text = (payload as Record<string, unknown>).text;
    if (typeof text !== 'string' || text.length > 4096) return false;
    return text.split('\n', 1)[0].toLowerCase().includes('echo');
  }

  private _maybeAppendEchoTraceSend(params: Record<string, unknown>): void {
    const payload = params.payload;
    if (!this._isEchoPayload(payload)) return;
    const uptime = this._connectedAt ? Math.floor((Date.now() - this._connectedAt) / 1000) : 0;
    const trace = `${this._echoTimestamp()} [AUN-SDK.send] aid=${this._aid ?? '-'} conn_uptime=${uptime}s`;
    params.payload = { ...payload, text: payload.text + '\n' + trace };
  }

  private _shouldSkipEventSignature(event: JsonObject): boolean {
    if (event.encrypted || event.encrypt) return false;
    return this._isEchoPayload(event.payload);
  }

  private _maybeAppendEchoTraceReceive(msg: Record<string, unknown>): void {
    if (msg.encrypted) return;
    const payload = msg.payload;
    if (!this._isEchoPayload(payload)) return;
    const uptime = this._connectedAt ? Math.floor((Date.now() - this._connectedAt) / 1000) : 0;
    const trace = `${this._echoTimestamp()} [AUN-SDK.receive] aid=${this._aid ?? '-'} conn_uptime=${uptime}s`;
    msg.payload = { ...payload, text: payload.text + '\n' + trace };
  }

  private async _drainOrderedMessages(ns: string, beforeSeq?: number): Promise<void> {
    await this._delivery.drainOrderedMessages(ns, beforeSeq);
  }

  private async _publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    return this._delivery.publishOrderedMessage(event, ns, seq, payload);
  }

  private async _publishPulledMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    return this._delivery.publishPulledMessage(event, ns, seq, payload);
  }

  private _extractGroupIdFromResult(result: JsonObject): string {
    const group = isJsonObject(result.group) ? result.group : null;
    const gid = group ? String(group.group_aid ?? group.group_id ?? '') : '';
    if (gid) return gid;
    const directGid = String(result.group_aid ?? result.group_id ?? '');
    if (directGid) return directGid;
    const member = isJsonObject(result.member) ? result.member : null;
    return member ? String(member.group_aid ?? member.group_id ?? '') : '';
  }

  private async _onRawGroupChanged(data: EventPayload): Promise<void> {
    const tStart = Date.now();
    const action = String((data as any)?.action ?? '');
    const groupIdInit = String((data as any)?.group_aid ?? (data as any)?.group_id ?? '');
    this._clientLog.debug(`_onRawGroupChanged enter: group_id=${groupIdInit} action=${action}`);
    try {
      if (isJsonObject(data)) {
        const d = data;
        // 验签：有 client_signature 就验，没有默认安全
        const cs = d.client_signature;
        if (cs && isJsonObject(cs)) {
          if (this._shouldSkipEventSignature(d)) {
            delete d.client_signature;
          } else {
            const verified = await this._verifyEventSignature(d, cs);
            d._verified = this._isEventSignatureVerified(verified);
          }
        }
        const groupId = (d.group_aid ?? d.group_id ?? '') as string;

        await this._delivery.handleGroupChangedEventSeq(d, groupId);
      } else {
        // data 非对象也透传给用户（兼容旧版）
        await this._dispatcher.publish('group.changed', data);
      }
      this._clientLog.debug(`_onRawGroupChanged exit: elapsed=${Date.now() - tStart}ms group_id=${groupIdInit}`);
    } catch (err) {
      this._clientLog.debug(`_onRawGroupChanged exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 处理 event/group.state_committed：验证 state_hash 链并更新本地存储。
   * 当 prev_state_hash 与本地不连续时回源 group.get_state，并对回源数据做 hash 验证。
   */
  private async _onGroupStateCommitted(data: EventPayload): Promise<void> {
    return this._groupState.onGroupStateCommitted(data);
  }

  /**
   * 群组解散后清理本地状态：
   * - keystore 中的 epoch key 数据
   * - seq_tracker 中的群消息和群事件 seq 记录
   * - 补洞去重缓存中的相关条目
   * - 推送 seq 去重缓存
   */
  private _cleanupDissolvedGroup(groupId: string): void {
    // 1. 清理 seq_tracker 中的群消息和群事件命名空间
    this._v2E2EE.deleteBootstrapCacheEntry(`group:${groupId}`);
    this._v2GroupSecurityLevels.delete(groupId);
    this._v2StateChains.delete(groupId);
    const groupNs = `group:${groupId}`;
    const groupEventNs = `group_event:${groupId}`;
    this._seqTracker.removeNamespace(groupNs);
    this._seqTracker.removeNamespace(groupEventNs);
    this._persistRepairedSeq(groupNs);
    this._persistRepairedSeq(groupEventNs);
    void this._saveSeqTrackerState();

    // 2. 清理补洞去重缓存中的相关条目
    for (const key of this._gapFillDone.keys()) {
      if (key.includes(groupId)) {
        this._gapFillDone.delete(key);
      }
    }

    // 3. 清理推送 seq 去重缓存
    this._pushedSeqs.delete(groupNs);
    this._pushedSeqs.delete(groupEventNs);
    this._pendingOrderedMsgs.delete(groupNs);
    this._pendingOrderedMsgs.delete(groupEventNs);

    this._clientLog.info(`cleanup dissolved group ${groupId}  local state`);
  }

  private async _verifyEventSignature(_event: JsonObject, cs: JsonObject): Promise<boolean | 'pending'> {
    const sigAid = String(cs.aid ?? '');
    const method = String(cs._method ?? '');
    const expectedFP = String(cs.cert_fingerprint ?? '').trim().toLowerCase();
    if (!sigAid || !method) return 'pending';
    const cached = this._certCache.get(certCacheKey(sigAid, expectedFP || undefined));
    if (!cached || !cached.certPem) {
      this._safeAsync(this._fetchPeerCert(sigAid, expectedFP || undefined));
      return 'pending';
    }

    try {
      if (expectedFP) {
        if (!(await certMatchesFingerprint(cached.certPem, expectedFP))) {
          this._clientLog.warn(`group event sig verify failed: cert fingerprint mismatch aid=%s${String(sigAid)}`)
          return false;
        }
      }

      const paramsHash = String(cs.params_hash ?? '');
      const timestamp = String(cs.timestamp ?? '');
      const sigB64 = String(cs.signature ?? '');
      if (!paramsHash || !timestamp || !sigB64) {
        return false;
      }

      const pubKey = await importCertPublicKeyEcdsa(cached.certPem);
      const signData = new TextEncoder().encode(`${method}|${sigAid}|${timestamp}|${paramsHash}`);
      const sigBytes = base64ToUint8(sigB64);
      const ok = await ecdsaVerifyDer(pubKey, sigBytes, signData);
      if (!ok) {
        this._clientLog.warn(`group event sig verify failed aid=%s method=%s${sigAid} ${method}`)
        // P1-16: 签名失败统一发布事件
        this._dispatcher.publish('signature.verification_failed', {
          aid: sigAid, method, error: 'ECDSA verification failed',
        });
      }
      return ok;
    } catch (exc) {
      this._clientLog.warn(`group event sig verify exception:${String(exc)}`)
      // P1-16: 签名失败统一发布事件
      this._dispatcher.publish('signature.verification_failed', {
        aid: sigAid, method, error: String(exc),
      });
      return false;
    }
  }

  private _isEventSignatureVerified(value: unknown): value is true {
    return value === true;
  }

  private _protectedHeadersFromParams(params: RpcParams): ProtectedHeadersInput {
    const value = params.protected_headers ?? params.headers;
    if (value == null) return null;
    if (isJsonObject(value)) return value;
    if (typeof value === 'object' && typeof (value as { toObject?: () => unknown }).toObject === 'function') {
      return value as unknown as ProtectedHeadersInput;
    }
    return null;
  }

  private async _certFingerprint(certPem: string): Promise<string> {
    const certBytes = pemToArrayBuffer(certPem);
    const digest = await crypto.subtle.digest('SHA-256', certBytes);
    return 'sha256:' + Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  private async _decryptGroupThoughts(result: JsonObject): Promise<JsonObject> {
    return await this._v2E2EE.decryptGroupThoughts(result);
  }

  private async _decryptMessageThoughts(result: JsonObject): Promise<JsonObject> {
    return await this._v2E2EE.decryptMessageThoughts(result);
  }

  // ── E2EE 编排：证书与客户端签名 ──────────────────────

  /**
   * 获取对方证书（带缓存 + 完整 PKI 验证：链 + CRL + OCSP + AID 绑定）。
   * 跨域时自动将请求路由到 peer 所在域的 Gateway。
   */
  private async _fetchPeerCert(aid: string, certFingerprint?: string, timeoutMs = 5000): Promise<string> {
    const tStart = Date.now();
    this._clientLog.debug(`_fetchPeerCert enter: aid=${aid} fingerprint=${certFingerprint ?? '<none>'}`);
    try {
      const cacheKey = certCacheKey(aid, certFingerprint);
      const cached = this._certCache.get(cacheKey);
      const now = Date.now() / 1000;
      if (cached && now < cached.refreshAfter) {
        this._clientLog.debug(`_fetchPeerCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} source=cache`);
        return cached.certPem;
      }

      const gatewayUrl = this._gatewayUrl;
      if (!gatewayUrl) {
        throw new ValidationError('gateway url unavailable for e2ee cert fetch');
      }

      // 跨域时用 peer 所在域的 Gateway URL
      const peerGatewayUrl = resolvePeerGatewayUrl(gatewayUrl, aid);
      let certPem: string;
      const certUrl = buildCertUrl(peerGatewayUrl, aid, certFingerprint);
      // 兼容旧浏览器，不使用 AbortSignal.timeout（Chrome 103+ 才支持）
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const resp = await fetch(certUrl, { signal: controller.signal });
        if (!resp.ok) throw new ValidationError(`failed to fetch peer cert for ${aid}: HTTP ${resp.status}`);
        certPem = await resp.text();
      } finally {
        clearTimeout(timeoutId);
      }

      // H7: 严格校验指纹（DER SHA-256 或 SPKI SHA-256 任一匹配即可）
      if (certFingerprint) {
        const expectedFP = String(certFingerprint).trim().toLowerCase();
        if (!normalizeFingerprintHex(expectedFP)) {
          throw new ValidationError(
            `unsupported cert_fingerprint format for ${aid}: ${expectedFP.slice(0, 24)}`,
          );
        }
        if (!(await certMatchesFingerprint(certPem, expectedFP))) {
          throw new ValidationError(
            `peer cert fingerprint mismatch for ${aid}: expected=${expectedFP.slice(0, 24)}...`,
          );
        }
      }

      // 完整 PKI 验证：链 + CRL + OCSP + AID 绑定
      try {
        await this._auth.verifyPeerCertificate(peerGatewayUrl, certPem, aid);
      } catch (exc) {
        throw new ValidationError(`peer cert verification failed for ${aid}: ${exc}`);
      }

      this._certCache.set(cacheKey, {
        certPem,
        validatedAt: now,
        refreshAfter: now + PEER_CERT_CACHE_TTL,
      });

      try {
        // peer 证书只存版本目录，不覆盖 cert.pem
        await this._tokenStore.saveCert(aid, certPem, certFingerprint, { makeActive: false });
      } catch (exc) {
        this._clientLog.error(`write cert to keystore failed (aid=${aid}): ${String(exc)}`, exc instanceof Error ? exc : undefined);
      }

      this._clientLog.debug(`_fetchPeerCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} source=fetched`);
      return certPem;
    } catch (err) {
      this._clientLog.debug(`_fetchPeerCert exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 客户端操作签名 ────────────────────────────────

  /**
   * 为关键操作附加客户端 ECDSA 签名（_client_signature 字段）。
   * 使用 SubtleCrypto 异步签名。
   */
  private async _signClientOperation(method: string, params: RpcParams): Promise<void> {
    await this._rpcPipeline.signClientOperation(method, params);
  }

  // ── 内部：连接 ────────────────────────────────────

  private async _connectOnce(params: ConnectParams, allowReauth: boolean): Promise<void> {
    const tStart = Date.now();
    this._clientLog.debug(`_connectOnce enter: allow_reauth=${allowReauth}`);
    try {
      const gatewayUrl = this._resolveGateway(params);
      this._gatewayUrl = gatewayUrl;
      this._slotId = String(params.slot_id ?? '');
      this._connectDeliveryMode = { ...(params.delivery_mode ?? this._connectDeliveryMode) };
      this._auth.setInstanceContext({ deviceId: this._deviceId, slotId: this._slotId });

      this._state = 'connecting';

      // 前置 restore：在 _transport.connect 启动 reader 之前完成，
      // 避免 reader 把积压 push 交给空 tracker 的 handler，触发 S2 历史 gap 误补拉。
      this._refreshSeqTrackerContext();
      await this._restoreSeqTrackerState();

      try {
        const challenge = await this._transport.connect(gatewayUrl);

        this._state = 'authenticating';
        if (allowReauth) {
          const authContext = await this._auth.connectSession(
            this._transport,
            challenge,
            gatewayUrl,
            {
              accessToken: params.access_token as string | undefined,
              deviceId: this._deviceId,
              slotId: this._slotId,
              deliveryMode: this._connectDeliveryMode,
              connectionKind: String(params.connection_kind ?? 'long'),
              shortTtlMs: Number(params.short_ttl_ms ?? 0),
              extraInfo: params.extra_info,
            },
          );
          if (isJsonObject(authContext)) {
            const auth = authContext as AuthContext;
            const identity = auth.identity;
            if (identity && isJsonObject(identity)) {
              this._identity = identity;
              this._aid = String(identity.aid ?? this._aid ?? '');
              if (this._sessionParams) {
                this._sessionParams.access_token = String(auth.token ?? params.access_token ?? '');
              }
            }
            if (isJsonObject(auth.hello) && 'heartbeat_interval' in auth.hello) {
              this._applyServerHeartbeatInterval(auth.hello.heartbeat_interval, 'auth');
            }
          }
        } else {
          const hello = await this._auth.initializeWithToken(
            this._transport,
            challenge,
            String(params.access_token),
            {
              deviceId: this._deviceId,
              slotId: this._slotId,
              deliveryMode: this._connectDeliveryMode,
              connectionKind: String(params.connection_kind ?? 'long'),
              shortTtlMs: Number(params.short_ttl_ms ?? 0),
              extraInfo: params.extra_info,
            },
          );
          await this._syncIdentityAfterConnect(String(params.access_token));
          if (isJsonObject(hello) && 'heartbeat_interval' in hello) {
            this._applyServerHeartbeatInterval(hello.heartbeat_interval, 'auth');
          }
        }
      } catch (err) {
        // P1-19: 首连失败时重置状态，避免半连接残留
        this._state = 'standby';
        try { await this._transport.close(); } catch { /* 忽略关闭错误 */ }
        throw err;
      }

      this._state = 'connected';
      this._connectedAt = Date.now();
      await this._dispatcher.publish('state_change', {
        state: this._publicState(this._state),
        gateway: gatewayUrl,
      });
      if (this._seqTrackerContext !== this._currentSeqTrackerContext()) {
        this._refreshSeqTrackerContext();
        await this._restoreSeqTrackerState();
      }

      this._startBackgroundTasks();

      const connectionKind = String(params.connection_kind ?? 'long');
      const isShortConnection = connectionKind === 'short';
      const hasExplicitBackgroundSync = Object.prototype.hasOwnProperty.call(params, 'background_sync');
      const backgroundSyncEnabled = this._sessionOptions?.background_sync !== false
        && (!isShortConnection || hasExplicitBackgroundSync);
      if (!isShortConnection) {
        await this._v2E2EE.onConnected({ backgroundSync: backgroundSyncEnabled });
      } else {
        this._clientLog.debug('V2 session init deferred for short connection');
      }

      // connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压
      if (backgroundSyncEnabled) {
        this._safeAsync(this._fillP2pGap());
      }
      this._clientLog.debug(`_connectOnce exit: elapsed=${Date.now() - tStart}ms aid=${this._aid ?? '-'}`);
    } catch (err) {
      this._clientLog.debug(`_connectOnce exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private _resolveGateway(params: ConnectParams): string {
    const gateways = this._resolveGateways(params);
    return gateways[0];
  }

  private async _resolveGatewayForAid(aid: string): Promise<string> {
    const target = String(aid ?? this._aid ?? '').trim();
    if (!target) throw new StateError('gateway discovery requires a loaded AID');
    if (this._gatewayUrl) return this._gatewayUrl;

    try {
      const getMetadata = (this._tokenStore as unknown as { getMetadata?: (aid: string, key: string) => Promise<string> }).getMetadata;
      const raw = typeof getMetadata === 'function'
        ? String(await getMetadata.call(this._tokenStore, target, 'gateway_url') ?? '').trim()
        : '';
      if (raw) {
        const gateway = raw.startsWith('"') && raw.endsWith('"') ? String(JSON.parse(raw)).trim() : raw;
        if (gateway) {
          this._gatewayUrl = gateway;
          return gateway;
        }
      }
    } catch {
      // 缓存读取失败不影响发现流程。
    }

    const dotIdx = target.indexOf('.');
    const issuerDomain = dotIdx >= 0 ? target.slice(dotIdx + 1) : target;
    const portSuffix = '';
    const candidates = [
      `https://${target}${portSuffix}/.well-known/aun-gateway`,
      `https://gateway.${issuerDomain}${portSuffix}/.well-known/aun-gateway`,
    ];
    let lastError: unknown = null;
    for (const url of candidates) {
      try {
        const gateway = await this._discovery.discover(url);
        this._gatewayUrl = gateway;
        try {
          const setMetadata = (this._tokenStore as unknown as { setMetadata?: (aid: string, key: string, value: string) => Promise<void> }).setMetadata;
          if (typeof setMetadata === 'function') {
            await setMetadata.call(this._tokenStore, target, 'gateway_url', gateway);
          }
        } catch {
          // 缓存写入失败不影响连接。
        }
        return gateway;
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError instanceof Error ? lastError : new ConnectionError(`gateway discovery failed for ${target}`);
  }

  private _resolveGateways(params: ConnectParams): string[] {
    const topology = isJsonObject(params.topology) ? params.topology : null;
    if (topology) {
      const mode = String(topology.mode ?? 'gateway');
      if (mode === 'peer') {
        throw new ValidationError('peer topology is not implemented in the Browser SDK');
      }
      if (mode === 'relay') {
        throw new ValidationError('relay topology is not implemented in the Browser SDK');
      }
    }
    const gw = params.gateway ?? (params as any).gateways;
    if (Array.isArray(gw)) {
      const urls = gw.map((g: any) => String(g ?? '')).filter((u: string) => u.length > 0);
      if (urls.length > 0) return urls;
    }
    const gateway = String(gw ?? this._gatewayUrl ?? '');
    if (!gateway) throw new StateError('missing gateway in connect params');
    return [gateway];
  }

  private async _syncIdentityAfterConnect(accessToken: string): Promise<void> {
    const identity = this._identity;
    if (!identity) {
      return;
    }
    identity.access_token = accessToken;
    this._identity = identity;
    this._aid = String(identity.aid ?? this._aid ?? '');
    if (identity.aid) {
      const persistIdentity = (this._auth as unknown as {
        _persistIdentity?: (value: IdentityRecord) => Promise<void>;
      })._persistIdentity;
      if (typeof persistIdentity === 'function') {
        await persistIdentity.call(this._auth, identity);
      }
    }
  }

  // ── 内部：参数处理 ────────────────────────────────

  private _normalizeConnectParams(params: RpcParams): ConnectParams {
    const request: ConnectParams = { ...params };
    const accessToken = String(request.access_token ?? '');
    const gateway = String(request.gateway ?? this._gatewayUrl ?? '');
    if (!gateway) throw new StateError('connect requires non-empty gateway');
    if (accessToken) request.access_token = accessToken;
    else delete request.access_token;
    request.gateway = gateway;
    request.device_id = this._deviceId;
    request.slot_id = normalizeSlotId(request.slot_id ?? this._slotId, this._slotId || 'default');
    let deliveryModeRaw: JsonValue | object | undefined = request.delivery_mode;
    if (deliveryModeRaw == null) {
      deliveryModeRaw = { ...this._defaultConnectDeliveryMode };
    } else if (!isJsonObject(deliveryModeRaw)) {
      deliveryModeRaw = { mode: deliveryModeRaw };
    } else {
      deliveryModeRaw = { ...deliveryModeRaw };
    }
    if ('queue_routing' in request) {
      (deliveryModeRaw as JsonObject).routing = request.queue_routing as JsonValue;
    }
    if ('affinity_ttl_ms' in request) {
      (deliveryModeRaw as JsonObject).affinity_ttl_ms = request.affinity_ttl_ms as JsonValue;
    }
    request.delivery_mode = normalizeDeliveryModeConfig(deliveryModeRaw);

    if (request.topology !== undefined && !isJsonObject(request.topology)) {
      throw new ValidationError('topology must be an object');
    }
    if (request.retry !== undefined && !isJsonObject(request.retry)) {
      throw new ValidationError('retry must be an object');
    }
    if (request.timeouts !== undefined && !isJsonObject(request.timeouts)) {
      throw new ValidationError('timeouts must be an object');
    }

    // 长短连接选项：默认 long，向后兼容
    const kindRaw = request.connection_kind;
    if (kindRaw == null) {
      request.connection_kind = 'long';
    } else {
      request.connection_kind = String(kindRaw).trim().toLowerCase();
    }
    if (request.connection_kind !== 'long' && request.connection_kind !== 'short') {
      throw new ValidationError("connection_kind must be 'long' or 'short'");
    }
    try {
      request.short_ttl_ms = Math.max(0, Math.floor(Number(request.short_ttl_ms) || 0));
    } catch {
      throw new ValidationError('short_ttl_ms must be a non-negative integer');
    }
    if (request.connection_kind !== 'short') {
      request.short_ttl_ms = 0;
    }

    return request;
  }

  private _buildSessionOptions(params: ConnectParams): SessionOptions {
    const connectionKind = String(params.connection_kind ?? 'long');
    const options: SessionOptions = {
      auto_reconnect: DEFAULT_SESSION_OPTIONS.auto_reconnect,
      heartbeat_interval: DEFAULT_SESSION_OPTIONS.heartbeat_interval,
      token_refresh_before: DEFAULT_SESSION_OPTIONS.token_refresh_before,
      retry: { ...DEFAULT_SESSION_OPTIONS.retry },
      timeouts: { ...DEFAULT_SESSION_OPTIONS.timeouts },
      connection_kind: connectionKind,
      short_ttl_ms: Number(params.short_ttl_ms ?? 0),
    };
    if ('auto_reconnect' in params) {
      options.auto_reconnect = Boolean(params.auto_reconnect);
    }
    if ('heartbeat_interval' in params) {
      options.heartbeat_interval = Number(params.heartbeat_interval);
    }
    if ('token_refresh_before' in params) {
      options.token_refresh_before = Number(params.token_refresh_before);
    }
    if (isJsonObject(params.retry)) {
      Object.assign(options.retry, params.retry);
    }
    if (isJsonObject(params.timeouts)) {
      Object.assign(options.timeouts, params.timeouts);
    }
    if ('background_sync' in params) options.background_sync = Boolean(params.background_sync);
    return options;
  }

  // ── 内部：后台任务 ────────────────────────────────

  private _startBackgroundTasks(): void {
    // 短连接不启动 heartbeat 与 token 刷新（生命周期短，不需要长期会话维护）；
    // auto_reconnect 仍允许，由 _sessionOptions.auto_reconnect 决定
    if (this._sessionOptions?.connection_kind !== 'short') {
      this._startHeartbeat();
      this._startTokenRefresh();
    }
    // V2 内存缓存定时清理（每小时扫描过期条目）
    if (this._cacheCleanupTimer === null) {
      this._cacheCleanupTimer = setInterval(() => {
        const nowSec = Date.now() / 1000;
        for (const [k, v] of this._certCache) {
          if (nowSec >= v.refreshAfter) this._certCache.delete(k);
        }
        if (this._gapFillDone.size > 10000) {
          const arr = [...this._gapFillDone];
          this._gapFillDone = new Set(arr.slice(arr.length - 5000));
        }
        const now = Date.now();
        this._v2E2EE.pruneExpiredBootstrapCache(AUNClient.V2_BOOTSTRAP_TTL_MS, now);
        for (const [key, exp] of this._v2SigCache) {
          if (exp <= now) this._v2SigCache.delete(key);
        }
        this._auth.cleanExpiredCaches();
      }, 3600_000);
    }
  }

  private _stopBackgroundTasks(): void {
    if (this._heartbeatTimer !== null) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
    if (this._tokenRefreshTimer !== null) {
      clearTimeout(this._tokenRefreshTimer);
      this._tokenRefreshTimer = null;
    }
    if (this._cacheCleanupTimer !== null) {
      clearInterval(this._cacheCleanupTimer);
      this._cacheCleanupTimer = null;
    }
  }

  /** 心跳定时器 */
  private _startHeartbeat(): void {
    if (this._heartbeatTimer !== null) return;
    const interval = clampHeartbeatInterval(
      this._sessionOptions.heartbeat_interval ?? DEFAULT_SESSION_OPTIONS.heartbeat_interval,
    );
    if (interval <= 0) return;

    // M25: 把连续失败阈值从 3 次收窄到 2 次。既能容忍一次网络抖动/GC 暂停，
    // 又把半开连接的检测延迟从 3 个心跳周期降到 2 个，避免 RPC 长时间挂起。
    // 真正的 socket 死亡由 ws.on('close') 立即触发 _handleTransportDisconnect，
    // 不依赖此心跳路径。
    let consecutiveFailures = 0;
    const maxFailures = 2;

    this._heartbeatTimer = setInterval(async () => {
      if (this.state !== ConnectionState.READY || this._closing) return;
      try {
        const pong = await this._transport.call('meta.ping', {});
        this._heartbeatCount++;
        consecutiveFailures = 0;
        // 服务端可在 pong 中下发新的 heartbeat_interval（秒，0=关闭）
        if (isJsonObject(pong) && 'heartbeat_interval' in pong) {
          this._applyServerHeartbeatInterval((pong as JsonObject).heartbeat_interval, 'pong');
        }
      } catch (exc) {
        consecutiveFailures++;
        this._clientLog.warn(`heartbeat failed (${consecutiveFailures}/${maxFailures}): ${String(exc)}`)
        this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) });
        if (consecutiveFailures >= maxFailures) {
          this._clientLog.warn(`consecutive ${maxFailures}  heartbeat failed, trigger disconnect reconnect`);
          this._handleTransportDisconnect(exc instanceof Error ? exc : new Error(String(exc)));
        }
      }
    }, interval * 1000);
  }

  /** 服务端通过 hello/pong 下发 heartbeat_interval；clamp 后写入 session_options 并按需重启心跳。 */
  private _applyServerHeartbeatInterval(raw: unknown, source: 'auth' | 'pong'): void {
    const newInterval = clampHeartbeatInterval(raw);
    const oldInterval = clampHeartbeatInterval(this._sessionOptions.heartbeat_interval);
    if (newInterval === oldInterval) return;
    this._sessionOptions.heartbeat_interval = newInterval;
    this._clientLog.debug(`heartbeat_interval updated by ${source}: ${oldInterval} -> ${newInterval}`);
    // 重启定时器以应用新间隔（关闭/启动通过定时器有/无区分）
    if (this._heartbeatTimer !== null) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
    if (newInterval > 0 && this.state === ConnectionState.READY && !this._closing) {
      this._startHeartbeat();
    }
  }

  /** Token 刷新定时器 */
  private _startTokenRefresh(): void {
    if (this._tokenRefreshTimer !== null) return;
    const rawLead = Number(this._sessionOptions.token_refresh_before ?? DEFAULT_SESSION_OPTIONS.token_refresh_before);
    const lead = Number.isFinite(rawLead) && rawLead > 0
      ? rawLead
      : DEFAULT_SESSION_OPTIONS.token_refresh_before;

    const scheduleRefresh = (delayMs = TOKEN_REFRESH_CHECK_INTERVAL_MS) => {
      if (this._closing) return;

      this._tokenRefreshTimer = globalThis.setTimeout(async () => {
        if (this._closing) return;
        this._tokenRefreshTimer = null;
        if (this.state !== ConnectionState.READY || !this._gatewayUrl) {
          scheduleRefresh();
          return;
        }

        let identity = this._identity;
        if (!identity) {
          scheduleRefresh();
          return;
        }

        const expiresAt = this._auth.getAccessTokenExpiry(identity);
        if (expiresAt === null) {
          scheduleRefresh();
          return;
        }
        if ((expiresAt - Date.now() / 1000) > lead) {
          scheduleRefresh();
          return;
        }

        if (this.state !== ConnectionState.READY || !this._gatewayUrl || this._closing) {
          scheduleRefresh();
          return;
        }
        try {
          identity = await this._auth.refreshCachedTokens(this._gatewayUrl!, identity!);
          // 刷新期间可能已断线，复检状态，避免写回 stale identity
          if (this.state !== ConnectionState.READY) { scheduleRefresh(); return; }
          this._identity = identity;
          if (this._sessionParams && identity.access_token) {
            this._sessionParams.access_token = identity.access_token;
          }
          await this._dispatcher.publish('token.refreshed', {
            aid: identity.aid,
            expires_at: identity.access_token_expires_at,
          });
          this._tokenRefreshFailures = 0;
        } catch (exc) {
          if (exc instanceof AuthError) {
            if (authErrorRequiresRelogin(exc)) {
              this._clientLog.warn(`token refresh requires relogin, stopping refresh loop and triggering reconnect: ${exc.message}`);
              await this._dispatcher.publish('token.refresh_exhausted', {
                aid: this._identity?.aid ?? null,
                consecutive_failures: 1,
                last_error: String(exc),
                relogin_required: true,
              });
              this._tokenRefreshFailures = 0;
              await this._handleTransportDisconnect(new Error('token refresh relogin required, triggering reconnect'));
              return;
            }
            this._tokenRefreshFailures++;
            if (this._tokenRefreshFailures >= 3) {
              this._clientLog.warn(`token refresh failed ${this._tokenRefreshFailures} consecutive times, stopping refresh loop and triggering reconnect`);
              await this._dispatcher.publish('token.refresh_exhausted', {
                aid: this._identity?.aid ?? null,
                consecutive_failures: this._tokenRefreshFailures,
                last_error: String(exc),
              });
              this._tokenRefreshFailures = 0;
              await this._handleTransportDisconnect(new Error('token refresh exhausted, triggering reconnect'));
              return;
            }
            this._clientLog.warn(`token refresh failed (${this._tokenRefreshFailures}/3), next retry: ${String(exc)}`);
          } else {
            this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) });
          }
        }
        scheduleRefresh();
      }, delayMs);
    };

    scheduleRefresh(0);
  }

  private _validateMessageRecipient(toAid: JsonValue | object | undefined): void {
    this._rpcPipeline.validateMessageRecipient(toAid);
  }

  // ── 内部：断线重连 ────────────────────────────────

  /** 不重连 close code 集合：认证失败/权限错误/被踢等，重连无意义 */
  private static readonly _NO_RECONNECT_CODES = new Set([4001, 4003, 4008, 4009, 4010, 4011, 4012, 4013, 4014, 4015]);

  /** 处理服务端主动断开通知 event/gateway.disconnect
   *
   * 服务端可能附带结构化 detail 字段（如配额超限时含 aid/device_id/slot_id/quota_kind/evicted_by）。
   * 透传到应用层可订阅事件 'gateway.disconnect'，方便业务定位被踢原因。
   */
  private async _onGatewayDisconnect(data: any): Promise<void> {
    const obj = (data && typeof data === 'object') ? data : {};
    const code = obj.code;
    const reason = obj.reason ?? '';
    const detail = (obj.detail && typeof obj.detail === 'object') ? obj.detail : {};
    this._clientLog.warn(
      `server initiated disconnect: code=${code}, reason=${reason}, detail=${JSON.stringify(detail)}`,
    );
    this._serverKicked = true;
    // 缓存最近一次 disconnect 信息，让后续 connection.state(terminal_failed) 也能带 detail
    this._lastDisconnectInfo = { code, reason, detail };
    // 透传给应用层订阅者
    try {
      await this._dispatcher.publish('gateway.disconnect', { code, reason, detail });
    } catch (exc) {
      this._clientLog.debug(`publish gateway.disconnect failed: ${(exc as Error)?.message ?? exc}`);
    }
  }

  private async _handleTransportDisconnect(error: Error | null, closeCode?: number): Promise<void> {
    if (this._closing || this._state === 'closed') return;
    this._state = 'standby';
    // 先停止后台任务，避免心跳/token刷新在重连期间继续触发
    this._stopBackgroundTasks();
    void this._transport.close().catch((exc) => {
      this._clientLog.debug(`transport cleanup skipped: ${formatCaughtError(exc)}`);
    });
    await this._dispatcher.publish('state_change', {
      state: this._publicState(this._state),
      error,
    });

    if (!this._sessionOptions.auto_reconnect) return;
    if (this._reconnectActive) return;

    // 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
    if (this._serverKicked || (closeCode !== undefined && AUNClient._NO_RECONNECT_CODES.has(closeCode))) {
      this._state = 'terminal_failed';
      const reason = this._serverKicked ? 'server kicked' : `close code ${closeCode}`;
      this._clientLog.warn(`suppress auto-reconnect: ${reason}`);
      const disconnectInfo = this._lastDisconnectInfo ?? {};
      const eventPayload: Record<string, any> = {
        state: this._publicState(this._state), error, reason,
      };
      // 把服务端附带的结构化 detail（如配额超限信息）也带给应用层
      const detail = (disconnectInfo as any).detail;
      if (detail && typeof detail === 'object' && Object.keys(detail).length > 0) {
        eventPayload.detail = detail;
      }
      if ((disconnectInfo as any).code !== undefined && (disconnectInfo as any).code !== null) {
        eventPayload.code = (disconnectInfo as any).code;
      }
      await this._dispatcher.publish('state_change', eventPayload);
      return;
    }

    // 1000 = 正常关闭, 1006 = 网络异常断开（无 close frame），其他 code = 服务端主动关闭
    const serverInitiated = closeCode !== undefined && closeCode !== 1000 && closeCode !== 1006;

    this._reconnectActive = true;
    this._reconnectAbort = new AbortController();
    this._safeAsync(this._reconnectLoop(serverInitiated));
  }

  /** 指数退避 + 固定上限抖动重连循环（默认无限重试，仅在不可重试错误或 close() 或 max_attempts 耗尽时终止） */
  private async _reconnectLoop(serverInitiated = false): Promise<void> {
    const retry = { ...this._sessionOptions.retry };
    const maxBaseDelay = clampReconnectDelaySeconds(
      retry.max_delay,
      RECONNECT_MAX_BASE_DELAY_SECONDS,
    );
    // M25: max_attempts=0 表示无限重试（与 Go/Python 对齐）
    const maxAttemptsRaw = Number(retry.max_attempts ?? 0);
    const maxAttempts = Number.isFinite(maxAttemptsRaw) && maxAttemptsRaw > 0 ? Math.floor(maxAttemptsRaw) : 0;
    // 服务端主动关闭时从 16s 起跳，避免重连风暴；网络断开从 initial_delay 起跳
    let delay = clampReconnectDelaySeconds(
      serverInitiated ? 16.0 : retry.initial_delay,
      serverInitiated ? 16.0 : 1.0,
      maxBaseDelay,
    );

    this._retryAttempt = 0;
    this._retryMaxAttempts = maxAttempts;

    for (let attempt = 1; !this._reconnectAbort?.signal.aborted; attempt++) {
      // R1 fix: max_attempts 检查在循环顶部，覆盖所有路径（含 health-fail）
      if (maxAttempts > 0 && attempt > maxAttempts) {
        this._state = 'terminal_failed';
        this._nextRetryAt = null;
        this._reconnectActive = false;
        this._reconnectAbort = null;
        await this._dispatcher.publish('state_change', {
          state: this._publicState(this._state),
          attempt: attempt - 1,
          reason: 'max_attempts_exhausted',
        });
        return;
      }

      // 先进入 retry_backoff 状态（对齐 Python：先退避再重连）
      this._retryAttempt = attempt;
      const sleepMs = reconnectSleepDelaySeconds(delay, maxBaseDelay) * 1000;
      this._nextRetryAt = new Date(Date.now() + sleepMs);
      this._state = 'retry_backoff';
      await this._dispatcher.publish('state_change', {
        state: this._publicState(this._state),
        attempt,
        next_retry_at: this._nextRetryAt.getTime() / 1000,
      });

      try {
        await this._sleep(sleepMs);
        this._nextRetryAt = null;
        if (this._reconnectAbort?.signal.aborted) {
          this._reconnectActive = false;
          return;
        }

        // 退避结束，进入 reconnecting 状态
        this._state = 'reconnecting';
        await this._dispatcher.publish('state_change', {
          state: this._publicState(this._state),
          attempt,
        });

        // 重连前先 GET /health 探测，不健康则跳过本轮
        if (this._gatewayUrl) {
          const healthy = await this._discovery.checkHealth(this._gatewayUrl, 5000);
          if (!healthy) {
            this._lastError = new Error('gateway health check failed');
            this._lastErrorCode = 'gateway_unhealthy';
            delay = Math.min(delay * 2, maxBaseDelay);
            continue;
          }
        }
        await this._transport.close();
        if (!this._sessionParams) {
          throw new StateError('missing connect params for reconnect');
        }
        // 重连前同步 identity 里的 token 状态到 sessionParams，防止用过期 token 死循环 4001
        {
          const identity = this._identity;
          if (identity) {
            const cachedToken = String(identity.access_token ?? '');
            const expiresAt = this._auth.getAccessTokenExpiry(identity);
            if (cachedToken && (expiresAt === null || expiresAt > Date.now() / 1000 + 30)) {
              this._sessionParams.access_token = cachedToken;
            } else {
              this._clientLog.debug(`reconnect: cached token expired or missing for aid=${this._aid ?? ''}, clearing to trigger re-login`);
              this._sessionParams.access_token = '';
            }
          } else {
            this._sessionParams.access_token = '';
          }
        }
        await this._connectOnce(this._sessionParams, true);
        this._lastError = null;
        this._lastErrorCode = null;
        this._nextRetryAt = null;
        this._reconnectActive = false;
        this._reconnectAbort = null;
        return;
      } catch (exc) {
        this._lastError = exc instanceof Error ? exc : new Error(String(exc));
        this._lastErrorCode = 'reconnect_failed';
        await this._dispatcher.publish('connection.error', {
          error: formatCaughtError(exc),
          attempt,
        });
        if (!this._shouldRetryReconnect(exc as Error)) {
          this._state = 'terminal_failed';
          this._nextRetryAt = null;
          this._reconnectActive = false;
          this._reconnectAbort = null;
          await this._dispatcher.publish('state_change', {
            state: this._publicState(this._state),
            error: formatCaughtError(exc),
            attempt,
          });
          return;
        }
        delay = Math.min(delay * 2, maxBaseDelay);
      }
    }

    this._reconnectActive = false;
    this._reconnectAbort = null;
  }

  /** 判断是否应重试重连 */
  private _shouldRetryReconnect(error: Error): boolean {
    if (error instanceof AuthError) {
      const message = String(error.message ?? '').toLowerCase();
      if (message.includes('aid_login1_failed') || message.includes('aid_login2_failed')) {
        return true;
      }
      return false;
    }
    if (error instanceof PermissionError
      || error instanceof ValidationError || error instanceof StateError) {
      return false;
    }
    if (error instanceof ConnectionError) return true;
    if (error instanceof AUNError) return error.retryable;
    // 网络相关错误默认重试
    return true;
  }

  // ── 内部：工具方法 ────────────────────────────────

  /** 从 keystore 恢复 SeqTracker 状态（真正可 await，确保在 transport.connect 前完成） */
  private async _restoreSeqTrackerState(): Promise<void> {
    return this._delivery.restoreSeqTrackerState();
  }

  private _currentSeqTrackerContext(): string | null {
    if (!this._aid) return null;
    return JSON.stringify([this._aid, this._deviceId, this._slotId]);
  }

  private _resetSeqTrackingState(): void {
    void this._saveSeqTrackerState();
    this._resetV2IdentityRuntime();
    this._seqTracker = new SeqTracker();
    this._seqTrackerContext = null;
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
    this._v2SenderIKPending.clear();
    this._v2SenderIKFetching.clear();
    this._groupSynced.clear();
    this._onlineUnreadHintQueue.clear();
    if (this._onlineUnreadHintTimer) {
      clearTimeout(this._onlineUnreadHintTimer);
      this._onlineUnreadHintTimer = null;
    }
    this._onlineUnreadHintDrainActive = false;
  }

  private _refreshSeqTrackerContext(): void {
    const nextContext = this._currentSeqTrackerContext();
    if (nextContext === this._seqTrackerContext) return;
    void this._saveSeqTrackerState();
    this._seqTracker = new SeqTracker();
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
    this._v2SenderIKPending.clear();
    this._v2SenderIKFetching.clear();
    this._groupSynced.clear();
    this._onlineUnreadHintQueue.clear();
    if (this._onlineUnreadHintTimer) {
      clearTimeout(this._onlineUnreadHintTimer);
      this._onlineUnreadHintTimer = null;
    }
    this._onlineUnreadHintDrainActive = false;
    this._seqTrackerContext = nextContext;
  }

  /** 将 SeqTracker 状态保存到 keystore */
  private _saveSeqTrackerState(): Promise<void> {
    return this._delivery.saveSeqTrackerState();
  }

  private _persistSeq(ns: string, forceSeq?: number): void {
    return this._delivery.persistSeq(ns, forceSeq);
  }

  private _persistRepairedSeq(ns: string): void {
    return this._delivery.persistRepairedSeq(ns);
  }

  private _clampAckSeq(method: string, field: string, ns: string, seq: number): number {
    return this._delivery.clampAckSeq(method, field, ns, seq);
  }

  private _clampAckParams(method: string, params: RpcParams): RpcParams {
    return this._delivery.clampAckParams(method, params);
  }

  private _repairPushContiguousBound(ns: string, pushSeq: number, hasPayload: boolean, label: string): number {
    if (!ns || !Number.isFinite(pushSeq) || pushSeq <= 0) {
      return ns ? this._seqTracker.getContiguousSeq(ns) : 0;
    }
    const contig = this._seqTracker.getContiguousSeq(ns);
    const shouldRepair = contig > pushSeq;
    if (!shouldRepair) return contig;
    const repairedTo = Math.max(0, pushSeq - 1);
    this._seqTracker.repairContiguousSeq(ns, repairedTo);
    const repaired = this._seqTracker.getContiguousSeq(ns);
    this._persistRepairedSeq(ns);
    this._clientLog.warn(
      `${label} push repaired contiguous_seq: ns=${ns} payload=${hasPayload} push_seq=${pushSeq} contiguous=${contig}->${repaired}`,
    );
    return repaired;
  }

  private async _ensureV2SessionReady(method: string, errorMessage?: string): Promise<void> {
    if (!this._v2SessionMatchesIdentity()) {
      if (!this._v2SessionInitInFlight) {
        this._v2SessionInitInFlight = this._initV2Session()
          .finally(() => {
            this._v2SessionInitInFlight = null;
          });
      }
      await this._v2SessionInitInFlight;
    }
    if (!this._v2SessionMatchesIdentity()) {
      throw new StateError(errorMessage ?? `V2 session not initialized; encrypted ${method} requires E2EE V2`);
    }
  }

  private _v2CallFn(): CallFn {
    return async (method, params) =>
      this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
  }

  // ── V2 E2EE API（async，与 Python `client.py` `_init_v2_session` / `send_v2` / `pull_v2` / `ack_v2` 对齐） ──

  /**
   * 初始化 V2 session：从 AID PEM 私钥提取 raw scalar + DER 公钥，
   * 打开 V2 KeyStore（IndexedDB），构造 V2Session 并注册当前设备 SPK。
   *
   * connect 成功后自动调用，可幂等手动调用。
   */
  private async _initV2Session(): Promise<void> {
    return this._v2E2EE.initV2Session();
  }

  private async _v2TrustedIKPubDer(aid: string): Promise<Uint8Array> {
    const normalizedAid = String(aid ?? '').trim();
    if (!normalizedAid) throw new E2EEError('spk_aid_missing');
    if (this._aid && normalizedAid === this._aid) {
      if (!this._v2Session) throw new E2EEError('V2 session not initialized');
      return this._v2Session.currentIkPubDer;
    }
    const certPem = await this._fetchPeerCert(normalizedAid);
    const pubKey = await importCertPublicKeyEcdsa(certPem);
    return new Uint8Array(await crypto.subtle.exportKey('spki', pubKey));
  }

  private _v2SPKTimestampText(value: unknown, aid: string, deviceId: string, spkId: string): string {
    if (value === null || value === undefined || value === '') {
      throw new E2EEError(`spk_timestamp_missing: aid=${aid} device_id=${deviceId} spk_id=${spkId}`);
    }
    if (typeof value === 'boolean') {
      throw new E2EEError(`spk_timestamp_invalid: aid=${aid} device_id=${deviceId} spk_id=${spkId}`);
    }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) {
        throw new E2EEError(`spk_timestamp_invalid: aid=${aid} device_id=${deviceId} spk_id=${spkId}`);
      }
      return String(value);
    }
    const text = String(value).trim();
    if (!/^\d+$/.test(text)) {
      throw new E2EEError(`spk_timestamp_invalid: aid=${aid} device_id=${deviceId} spk_id=${spkId}`);
    }
    return BigInt(text).toString();
  }

  private async _v2VerifySPKDevice(args: {
    dev: Record<string, unknown>;
    aid: string;
    deviceId: string;
    ikPkDer: Uint8Array;
    spkPkDer?: Uint8Array;
    keySource: string;
  }): Promise<void> {
    if (!this._v2Session) throw new E2EEError('V2 session not initialized');
    const spkId = String(args.dev.spk_id ?? '').trim();
    if (!spkId) return;
    if (args.keySource !== 'peer_device_prekey' && args.keySource !== 'group_device_prekey') {
      throw new E2EEError(`spk_key_source_invalid: aid=${args.aid} device_id=${args.deviceId} spk_id=${spkId} key_source=${args.keySource}`);
    }
    if (!args.spkPkDer || args.spkPkDer.length === 0) {
      throw new E2EEError(`spk_public_key_missing: aid=${args.aid} device_id=${args.deviceId} spk_id=${spkId}`);
    }
    const spkHash = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', exactArrayBuffer(args.spkPkDer))));
    const expectedSpkId = `sha256:${spkHash.substring(0, 16)}`;
    if (spkId !== expectedSpkId) {
      throw new E2EEError(`spk_id_mismatch: aid=${args.aid} device_id=${args.deviceId} spk_id=${spkId} expected=${expectedSpkId}`);
    }
    const trustedIK = await this._v2TrustedIKPubDer(args.aid);
    if (!_v2BytesEqual(trustedIK, args.ikPkDer)) {
      throw new E2EEError(`spk_ik_mismatch: aid=${args.aid} device_id=${args.deviceId} spk_id=${spkId}`);
    }
    if (_v2BytesEqual(args.spkPkDer, trustedIK)) {
      this._v2Session.markPeerSPKVerified(args.aid, args.deviceId, spkId);
      return;
    }
    const sigB64 = String(args.dev.spk_signature ?? '').trim();
    if (!sigB64) {
      throw new E2EEError(`spk_signature_missing: aid=${args.aid} device_id=${args.deviceId} spk_id=${spkId}`);
    }
    let signature: Uint8Array;
    try {
      signature = _v2B64ToBytesStrict(sigB64);
    } catch {
      throw new E2EEError(`spk_signature_invalid_base64: aid=${args.aid} device_id=${args.deviceId} spk_id=${spkId}`);
    }
    const encoder = new TextEncoder();
    const tsText = this._v2SPKTimestampText(args.dev.spk_timestamp, args.aid, args.deviceId, spkId);
    const signData = _v2ConcatBytes(args.spkPkDer, encoder.encode(spkId), encoder.encode(tsText));
    if (!(await ecdsaVerifyRaw(trustedIK, signature, signData))) {
      throw new E2EEError(`spk_signature_invalid: aid=${args.aid} device_id=${args.deviceId} spk_id=${spkId}`);
    }
    this._v2Session.markPeerSPKVerified(args.aid, args.deviceId, spkId);
  }

  private async _v2BuildTargetFromDevice(args: {
    dev: Record<string, unknown>;
    aid: string;
    deviceId: string;
    role: string;
    defaultKeySource: string;
  }): Promise<Target | null> {
    const aid = String(args.aid ?? '').trim();
    const devId = getV2DeviceId(args.dev);
    const deviceId = devId.present ? devId.value : String(args.deviceId ?? '').trim();
    const ikPk = String(args.dev.ik_pk ?? '').trim();
    if (!aid || !devId.present || !ikPk) return null;
    const ikPkDer = _v2B64ToBytes(ikPk);
    const spkPkDer = args.dev.spk_pk ? _v2B64ToBytes(String(args.dev.spk_pk)) : undefined;
    const keySource = String(args.dev.key_source ?? args.defaultKeySource).trim() || args.defaultKeySource;
    await this._v2VerifySPKDevice({ dev: args.dev, aid, deviceId, ikPkDer, spkPkDer, keySource });
    this._v2Session?.cachePeerIK(aid, deviceId, ikPkDer);
    return {
      aid,
      deviceId,
      role: args.role,
      keySource,
      ikPkDer,
      spkPkDer,
      spkId: String(args.dev.spk_id ?? '').trim(),
    };
  }

  private async _getV2SenderPubDer(
    fromAid: string,
    senderDeviceId: string,
    certFingerprint?: string,
  ): Promise<Uint8Array | null> {
    return await this._v2E2EE.getV2SenderPubDer(fromAid, senderDeviceId, certFingerprint);
  }

  private _cacheV2PeerIKFromDevice(dev: unknown, fallbackAid = ''): void {
    const session = this._v2Session;
    if (!session || !isJsonObject(dev)) return;
    const device = dev as Record<string, unknown>;
    const devId = getV2DeviceId(device);
    const aid = String(device.aid ?? fallbackAid ?? '').trim();
    const ikPk = String(device.ik_pk ?? '').trim();
    if (!devId.present || !aid || !ikPk) return;
    try {
      session.cachePeerIK(aid, devId.value, _v2B64ToBytes(ikPk));
    } catch (exc) {
      this._clientLog.debug(`V2 sender IK cache from bootstrap skipped aid=${aid} dev=${devId.value}: ${String(formatCaughtError(exc))}`);
    }
  }

  private _scheduleV2SenderIKPending(args: {
    msg: Record<string, unknown>;
    fromAid: string;
    senderDeviceId: string;
    groupId: string;
  }): void {
    return this._v2E2EE.scheduleSenderIKPending(args);
  }

  /**
   * V2 P2P 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。
   *
   * @param to 目标 AID
   * @param payload 业务 payload（将被加密）
   * @param opts 可选 messageId / timestamp（与 Python 行为一致）
   * @returns 服务端响应
   */
  private async _sendV2(
    to: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: Record<string, unknown>; context?: Record<string, unknown> },
  ): Promise<unknown> {
    return await this._v2E2EE.sendV2(to, payload, opts);
  }
  /**
   * 拉取并解密 V2 P2P 消息。
   *
   * @param afterSeq 从此 seq 之后开始拉取（0/省略 = 从当前 contiguous 开始）
   * @param limit 最多拉取条数
   */
  private async _pullV2(afterSeq: number = 0, limit: number = 50, opts?: { force?: boolean }): Promise<unknown[]> {
    return await this._v2E2EE.pullV2(afterSeq, limit, opts);
  }
  /**
   * 确认 V2 消息已消费 + 自检销毁旧 SPK（PFS）。
   *
   * @param upToSeq 确认到此 seq；省略则用当前 contiguous
   */
  private async _ackV2(upToSeq?: number): Promise<unknown> {
    return await this._v2E2EE.ackV2(upToSeq);
  }
  /** 解密单条 V2 消息（与 Python `_decrypt_v2_message` 对齐）。缺 sender IK 时先入 pending，后台补齐后重试。 */
  private async _decryptV2Message(msg: Record<string, unknown>, allowPending = true): Promise<Record<string, unknown> | null> {
    const session = this._v2Session;
    if (!session) return null;
    const envJson = msg.envelope_json;
    if (!envJson || typeof envJson !== 'string') return null;
    let envelope: Record<string, unknown>;
    try {
      envelope = JSON.parse(envJson) as Record<string, unknown>;
    } catch {
      this._clientLog.warn(`V2 decrypt: invalid envelope_json for msg seq=${String(msg.seq)}`);
      return null;
    }
    const e2eeMeta = v2E2eeMeta(envelope);
    await this._observeAgentMdFromEnvelope(envelope);

    // 确定 spk_id 和 recipient_key_source
    let spkId = '';
    let recipientKeySource = '';
    const recipientObj = envelope.recipient as Record<string, unknown> | undefined;
    if (recipientObj && typeof recipientObj === 'object') {
      spkId = String(recipientObj.spk_id ?? '');
      recipientKeySource = String(recipientObj.key_source ?? '');
    } else if (Array.isArray(envelope.recipients)) {
      spkId = String(msg.spk_id ?? '');
      // 从 recipients 数组中查找本设备的 row 以获取 key_source
      if (!spkId) {
        for (const row of envelope.recipients) {
          if (Array.isArray(row) && row.length >= 6 && row[0] === this._aid && (row[1] === this._deviceId || row[1] === '')) {
            spkId = String(row[5] ?? '');
            recipientKeySource = row.length > 3 ? String(row[3] ?? '') : '';
            break;
          }
        }
      } else {
        for (const row of envelope.recipients) {
          if (Array.isArray(row) && row.length >= 6 && row[0] === this._aid && (row[1] === this._deviceId || row[1] === '')) {
            recipientKeySource = row.length > 3 ? String(row[3] ?? '') : '';
            break;
          }
        }
      }
    }

    // group_id 只表示群上下文；getGroupDecryptKeys 内部必须按 group SPK -> P2P device SPK -> IK fallback 查找。
    const aad = isJsonObject(envelope.aad) ? envelope.aad as Record<string, unknown> : {};
    const groupIdForKeys = String(msg.group_id ?? aad.group_id ?? envelope.group_id ?? '').trim();
    const undecryptableEvent = groupIdForKeys ? 'group.message_undecryptable' : 'message.undecryptable';
    let ikPriv: Uint8Array;
    let spkPriv: Uint8Array | undefined;
    try {
      if (groupIdForKeys) {
        const keys = await session.getGroupDecryptKeys(groupIdForKeys, spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv;
      } else {
        const keys = await session.getDecryptKeys(spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv;
      }
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt: SPK lookup failed seq=${String(msg.seq)} spk_id=${spkId}: ${String(exc)}`);
      try {
        const event: JsonObject = {
          message_id:     String(msg.message_id ?? ''),
          from:           String(msg.from_aid ?? ''),
          to:             String(msg.to ?? ''),
          seq:            msg.seq as JsonValue,
          timestamp:      (msg.t_server ?? msg.timestamp) as JsonValue,
          device_id:      String(msg.device_id ?? ''),
          slot_id:        String(msg.slot_id ?? ''),
          _decrypt_error: String(exc),
          _decrypt_stage: 'spk_lookup',
          _envelope_type: String(envelope.type ?? ''),
          _suite:         String(envelope.suite ?? ''),
          _spk_id:        spkId,
        };
        attachV2EnvelopeMetadata(event, e2eeMeta);
        await this._dispatcher.publish(undecryptableEvent, event);
      } catch { /* publish 异常不影响主流程 */ }
      return null;
    }

    const fromAid = String(msg.from_aid ?? '');
    const senderDeviceId = String(aad.from_device ?? '');
    const senderCertFingerprint = String(envelope.sender_cert_fingerprint ?? '').trim().toLowerCase();
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId, senderCertFingerprint);
    if (!senderPubDer) {
      this._clientLog.warn(`V2 decrypt: no sender IK for ${fromAid} device=${senderDeviceId}`);
      if (allowPending) {
        this._scheduleV2SenderIKPending({ msg, fromAid, senderDeviceId, groupId: groupIdForKeys });
        return null;
      }
      try {
        const event: JsonObject = {
          message_id:        String(msg.message_id ?? ''),
          from:              fromAid,
          to:                String(msg.to ?? ''),
          seq:               msg.seq as JsonValue,
          timestamp:         (msg.t_server ?? msg.timestamp) as JsonValue,
          device_id:         String(msg.device_id ?? ''),
          slot_id:           String(msg.slot_id ?? ''),
          _decrypt_error:    'sender_ik_not_found',
          _decrypt_stage:    'sender_ik',
          _envelope_type:    String(envelope.type ?? ''),
          _suite:            String(envelope.suite ?? ''),
        };
        attachV2EnvelopeMetadata(event, e2eeMeta);
        await this._dispatcher.publish(undecryptableEvent, event);
      } catch { /* publish 异常不影响主流程 */ }
      return null;
    }

    let plaintext: Record<string, unknown> | null;
    try {
      plaintext = await decryptMessage(
        envelope,
        this._aid ?? '',
        this._deviceId,
        ikPriv,
        spkPriv,
        senderPubDer,
      );
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt failed for msg seq=${String(msg.seq)}: ${String(exc)}`);
      try {
        const event: JsonObject = {
          message_id:        String(msg.message_id ?? ''),
          from:              fromAid,
          to:                String(msg.to ?? ''),
          seq:               msg.seq as JsonValue,
          timestamp:         (msg.t_server ?? msg.timestamp) as JsonValue,
          device_id:         String(msg.device_id ?? ''),
          slot_id:           String(msg.slot_id ?? ''),
          _decrypt_error:    String(exc),
          _decrypt_stage:    'decrypt',
          _envelope_type:    String(envelope.type ?? ''),
          _suite:            String(envelope.suite ?? ''),
        };
        attachV2EnvelopeMetadata(event, e2eeMeta);
        await this._dispatcher.publish(undecryptableEvent, event);
      } catch { /* publish 异常不影响主流程 */ }
      return null;
    }
    if (plaintext == null) return null;

    // 消费触发 SPK 轮换（fire-and-forget，不阻塞消息处理）
    if (groupIdForKeys && recipientKeySource === 'group_device_prekey' && session.isLastUploadedGroupSPK(groupIdForKeys, spkId)) {
      this._v2E2EE.scheduleGroupSpkRotation(groupIdForKeys, { reason: 'group_spk_consumed' });
    } else if (groupIdForKeys && recipientKeySource === 'peer_device_prekey') {
      this._v2E2EE.scheduleGroupSpkRegistrationAfterPeerFallback(groupIdForKeys);
    } else if (!groupIdForKeys && session.isLastUploadedSPK(spkId)) {
      const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
      session.rotateSPK(callFn).catch(exc => {
        this._clientLog.debug(`V2 SPK rotation failed (non-fatal): ${exc}`);
      });
    }

    const e2ee = v2E2eeMeta(envelope);
    const result: JsonObject = {
      message_id: String(msg.message_id ?? ''),
      from: fromAid,
      to: this._aid ?? '',
      seq: msg.seq as JsonValue,
      t_server: msg.t_server as JsonValue,
      payload: plaintext as JsonValue,
      encrypted: true,
      e2ee: e2ee as JsonValue,
    };
    const explicitDirection = String(msg.direction ?? '').trim();
    result.direction = explicitDirection || (fromAid && fromAid === this._aid ? 'outbound_sync' : 'inbound');
    if (msg.device_id !== undefined) result.device_id = msg.device_id as JsonValue;
    if (msg.slot_id !== undefined) result.slot_id = msg.slot_id as JsonValue;
    attachGatewayProximity(result, msg);
    attachV2EnvelopeMetadata(result, e2ee);
    return result;
  }

  /**
   * V2 Group 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。
   *
   * @param groupId 群 ID
   * @param payload 业务 payload（将被加密）
   * @param opts 可选 messageId / timestamp
   * @returns 服务端响应
   */
  private async _sendGroupV2(
    groupId: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: Record<string, unknown>; context?: Record<string, unknown> },
  ): Promise<unknown> {
    return await this._v2E2EE.sendGroupV2(groupId, payload, opts);
  }

  private async _pullGroupV2Internal(params: { group_id: string; after_seq: number; limit: number }): Promise<void> {
    return await this._v2E2EE.pullGroupV2Internal(params);
  }

  /**
   * 拉取并解密 V2 Group 消息。
   *
   * @param groupId 群 ID
   * @param afterSeq 从此 seq 之后开始拉取（0/省略 = 从当前 contiguous 开始）
   * @param limit 最多拉取条数
   */
  private async _pullGroupV2(
    groupId: string,
    afterSeq: number = 0,
    limit: number = 50,
    opts?: { explicitAfterSeq?: boolean; cursorParams?: RpcParams; ownsCursor?: boolean; wireGroupId?: string },
  ): Promise<unknown[]> {
    return await this._v2E2EE.pullGroupV2(groupId, afterSeq, limit, opts);
  }

  private async _rawGroupAckMessages(params: RpcParams): Promise<RpcResult> {
    const p: RpcParams = { ...params };
    return await this._callRawV2Rpc('group.ack_messages', p);
  }

  /**
   * 确认 V2 群消息已消费。
   *
   * @param groupId 群 ID
   * @param upToSeq 确认到此 seq；省略则用当前 contiguous
   */
  private async _ackGroupV2(groupId: string, upToSeq?: number): Promise<unknown> {
    return await this._v2E2EE.ackGroupV2(groupId, upToSeq);
  }
  /**
   * V2 P2P 多设备 wrap envelope 构造（不发送）。
   * thought.put 复用此函数构造与 message.send 相同的 V2 envelope。
   * 与 Python `_build_v2_p2p_envelope` 对齐。
   */
  private async _buildV2P2PEnvelope(opts: {
    to: string;
    payload: Record<string, unknown>;
    messageId?: string;
    timestamp?: number;
    useCache?: boolean;
    protectedHeaders?: Record<string, unknown>;
    context?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    return await this._v2E2EE.buildV2P2PEnvelope(opts);
  }
  /**
   * V2 P2P thought.put：使用 V2 多设备 wrap envelope。
   * 服务端仍走 message.thought.put（内存 KV），envelope 透传，由接收端单设备解密。
   * 与 Python `_put_message_thought_encrypted_v2` 对齐。
   */
  private async _putMessageThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    return await this._v2E2EE.putMessageThoughtEncryptedV2(params);
  }

  /**
   * V2 Group 多设备 wrap envelope 构造（不发送）。
   * 与 Python `_build_v2_group_envelope` 对齐。
   */
  private async _buildV2GroupEnvelope(opts: {
    groupId: string;
    payload: Record<string, unknown>;
    messageId?: string;
    timestamp?: number;
    useCache?: boolean;
    protectedHeaders?: Record<string, unknown>;
    context?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    return await this._v2E2EE.buildV2GroupEnvelope(opts);
  }

  /**
   * V2 Group thought.put：多设备 wrap envelope。
   * 与 Python `_put_group_thought_encrypted_v2` 对齐。
   */
  private async _putGroupThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    return await this._v2E2EE.putGroupThoughtEncryptedV2(params);
  }

  /**
   * 解密一个 V2 thought envelope（P2P 或 Group），返回 payload dict。
   * 与 _decryptV2Message 不同：不依赖 envelope_json 包装；失败返回 null，不发布 undecryptable 事件。
   * 与 Python `_decrypt_v2_envelope_for_thought` 对齐。
   */
  private async _decryptV2EnvelopeForThought(opts: {
    envelope: Record<string, unknown>;
    fromAid: string;
  }): Promise<Record<string, unknown> | null> {
    return await this._v2E2EE.decryptV2EnvelopeForThought(opts);
  }

  // ── V2 State 验签 / Fork 检测 / Auto-propose（Phase 3b.3 + 3b.4）──────

  private async _publishV2GroupSecurityLevel(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    return this._groupState.publishV2GroupSecurityLevel(groupId, bootstrap);
  }

  /**
   * 验证 owner/admin 对 state 的 ECDSA 签名（防服务端篡改 bootstrap 字段）。
   * 与 Python SDK 对齐：证书获取或验签失败时拒绝信任 bootstrap。
   */
  private async _v2VerifyStateSignature(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    return this._groupState.verifyStateSignature(groupId, bootstrap);
  }

  /**
   * 分叉检测：比对服务端 state_chain 与本地存储。
   */
  private async _v2CheckFork(groupId: string, serverChain: string): Promise<void> {
    return this._groupState.checkFork(groupId, serverChain);
  }

  private _v2MaybeTriggerAutoPropose(groupId: string): void {
    this._groupState.maybeTriggerAutoPropose(groupId);
  }

  /**
   * 成员变更后自动 propose state（仅 owner/admin 执行）。
   */
  private async _v2AutoProposeState(groupId: string, options?: { leaderDelay?: boolean }): Promise<void> {
    return this._groupState.autoProposeState(groupId, options);
  }

  private async _v2LeaderDelayMs(input: string): Promise<number> {
    return this._groupState.leaderDelayMs(input);
  }

  private async _v2AutoProposeLeaderDelay(groupId: string): Promise<boolean> {
    return this._groupState.autoProposeLeaderDelay(groupId);
  }

  private async _doV2AutoProposeState(groupId: string): Promise<void> {
    return this._groupState.doAutoProposeState(groupId);
  }

  private async _v2ConfirmPendingProposal(groupId: string): Promise<boolean> {
    return this._groupState.confirmPendingProposal(groupId);
  }

  /**
   * Owner 上线时自动检查并签名确认 pending state proposals。
   */
  private async _v2AutoConfirmPendingProposals(): Promise<void> {
    return this._groupState.autoConfirmPendingProposals();
  }

  private async _onV2StateProposed(data: EventPayload): Promise<void> {
    return this._groupState.onV2StateProposed(data);
  }

  private async _onV2StateRetryNeeded(data: EventPayload): Promise<void> {
    return this._groupState.onV2StateRetryNeeded(data);
  }

  private async _onV2StateConfirmed(data: EventPayload): Promise<void> {
    return this._groupState.onV2StateConfirmed(data);
  }

  /**
   * 处理 V2 push 通知：自动 pull + decrypt + emit。
   */
  private _v2PullInflight = false;
  private _v2PullPending = false;

  private async _onV2PushNotification(data: EventPayload): Promise<void> {
    return this._delivery.onV2PushNotification(data);
  }

  /** 安全执行异步操作（不阻塞调用方，错误打 warning 便于排障） */
  private _safeAsync(promise: Promise<RpcResult | void>): void {
    promise.catch((exc) => {
      this._clientLog.warn(`background task exception:${String(exc)}`)
    });
  }

  private _explicitGroupCursorParams(params: RpcParams): RpcParams {
    const value = (params as Record<string, unknown>)._group_cursor_params;
    if (!isJsonObject(value as JsonValue | object | null | undefined)) return {};
    return { ...(value as RpcParams) };
  }

  private _groupCursorTargetsCurrentInstance(params: RpcParams): boolean {
    const deviceId = String(params.device_id ?? '').trim();
    const slotId = String(params.slot_id ?? '').trim();
    return (!deviceId || deviceId === (this._deviceId ?? ''))
      && (!slotId || slotId === (this._slotId ?? ''));
  }

  // ── Pull Gate（序列化同一 key 的并发 pull）──────────────────

  private async _withBackgroundRpc<T>(operation: () => Promise<T> | T): Promise<T> {
    this._backgroundRpcDepth += 1;
    try {
      return await operation();
    } finally {
      this._backgroundRpcDepth = Math.max(0, this._backgroundRpcDepth - 1);
    }
  }

  private async _runPullSerialized<T>(key: string, operation: () => Promise<T>): Promise<T> {
    return await this._rpcPipeline.runPullSerialized(key, operation);
  }

  /** 可取消的 sleep */
  private _sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      globalThis.setTimeout(resolve, ms);
    });
  }
}
