// ── AUNClient（SDK 主入口 — 浏览器完整实现）──────────────────
// 对标 Python client.py，浏览器环境适配：
//   - 所有密码学操作异步（SubtleCrypto）
//   - HTTP 使用 fetch() 而非 Node http
//   - 无文件系统（IndexedDB via keystore）
//   - 后台任务使用 setTimeout/setInterval

import { createConfig, getDeviceId, normalizeInstanceId, normalizeSlotId, slotIsolationKey, type AUNConfig } from './config.js';
import { EventDispatcher, type EventPayload, type EventHandler, type Subscription } from './events.js';
import { normalizeGroupId } from './group-id.js';
import { GatewayDiscovery } from './discovery.js';
import { RPCTransport } from './transport.js';
import { AuthFlow } from './auth.js';
import { SeqTracker } from './seq-tracker.js';
import {
  CryptoProvider,
  uint8ToBase64,
  base64ToUint8,
  pemToArrayBuffer,
  p1363ToDer,
  certificateSha256Fingerprint,
  ecdsaSignDer,
  ecdsaVerifyDer,
  importCertPublicKeyEcdsa,
  importPrivateKeyEcdsa,
} from './crypto.js';
import type { ProtectedHeadersInput } from './protected-headers.js';
import { IndexedDBKeyStore } from './keystore/indexeddb.js';
import type { KeyStore, GroupStateRecord } from './keystore/index.js';
import { V2Session, V2KeyStore, type CallFn } from './v2/session/index.js';
import {
  encryptP2PMessage, encryptGroupMessage, decryptMessage,
  type Target, type StateCommitmentAAD,
} from './v2/e2ee/index.js';
import { ecdsaVerifyRaw } from './v2/crypto/ecdsa.js';
import { computeStateCommitment } from './v2/state/index.js';
import { AUNLogger, type ModuleLogger } from './logger.js';
import {
  AUNError,
  AuthError,
  ConnectionError,
  E2EEError,
  NotFoundError,
  PermissionError,
  StateError,
  ValidationError,
} from './errors.js';
import {
  isJsonObject,
  ConnectionState,
  STATE_TO_PUBLIC,
  type IdentityRecord,
  type JsonObject,
  type JsonValue,
  type Message,
  type RpcParams,
  type RpcResult,
} from './types.js';
import { AID } from './aid.js';

/**
 * 递归排序键的 JSON 序列化（Canonical JSON for AUN）
 * 等价于 Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
 * 非 ASCII 字符直接以 UTF-8 输出。
 */
function stableStringify(obj: JsonValue | object | undefined): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(v => stableStringify(v)).join(',') + ']';
  }
  if (isJsonObject(obj)) {
    const keys = Object.keys(obj).sort();
    const entries = keys.map(k => stableStringify(k) + ':' + stableStringify(obj[k]));
    return '{' + entries.join(',') + '}';
  }
  return JSON.stringify(obj);
}

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

function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortObjectKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

function uint64BE(value: number): Uint8Array {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(value), false);
  return new Uint8Array(buf);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (!clean) return new Uint8Array(0);
  if (clean.length % 2 !== 0) throw new ValidationError('invalid hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function computeStateHash(params: {
  groupId: string;
  stateVersion: number;
  keyEpoch: number;
  members: Array<{ aid: string; role: string }>;
  policy: Record<string, unknown>;
  prevStateHash: string;
}): Promise<string> {
  const sortedMembers = [...params.members].sort((a, b) => a.aid.localeCompare(b.aid));
  const membershipBlock = sortedMembers.map((m) => `${m.aid}:${m.role}`).join('|');
  const policyBlock = Object.keys(params.policy).length > 0
    ? JSON.stringify(sortObjectKeys(params.policy))
    : '';
  const prevBytes = params.prevStateHash ? hexToBytes(params.prevStateHash) : new Uint8Array(32);
  const sep = new Uint8Array([0x00]);
  const encoder = new TextEncoder();
  const chunks = [
    encoder.encode(params.groupId), sep,
    uint64BE(params.stateVersion), sep,
    uint64BE(params.keyEpoch), sep,
    encoder.encode(membershipBlock), sep,
    encoder.encode(policyBlock), sep,
    prevBytes,
  ];
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const data = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.length;
  }
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

/** 内部专用方法（禁止用户直接调用） */
const INTERNAL_ONLY_METHODS = new Set([
  'auth.login1',
  'auth.aid_login1',
  'auth.login2',
  'auth.aid_login2',
  'auth.connect',
  'auth.refresh_token',
  'initialize',
]);

/** 已移除的旧版 E2EE RPC。 */
const REMOVED_E2EE_METHODS = new Set([
  'group.rotate_epoch',
]);

/** 需要客户端签名的关键方法 */
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
  'group.leave', 'group.remove_member', 'group.update_rules',
  'group.update', 'group.update_announcement',
  'group.update_join_requirements', 'group.set_role',
  'group.transfer_owner', 'group.review_join_request',
  'group.batch_review_join_request',
  'group.request_join', 'group.use_invite_code',
  'group.thought.put',
  'message.thought.put',
  'group.set_settings',
  'group.resources.put', 'group.resources.update',
  'group.resources.delete', 'group.resources.request_add',
  'group.resources.direct_add', 'group.resources.approve_request',
  'group.resources.reject_request',
  'group.commit_state',
  'group.ban', 'group.unban',
  'group.dissolve', 'group.suspend', 'group.resume',
]);

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

interface MemberRecord extends JsonObject {
  aid?: string;
}

interface GroupRecord extends JsonObject {
  group_id?: string;
}

interface GroupBatchReviewResult extends JsonObject {
  ok?: boolean;
  status?: string;
  aid?: string;
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

const PUBLIC_CONNECTION_OPTION_KEYS = new Set([
  'auto_reconnect',
  'connect_timeout',
  'retry_initial_delay',
  'retry_max_delay',
  'retry_max_attempts',
  'heartbeat_interval',
  'call_timeout',
  'connection_kind',
  'short_ttl_ms',
  'delivery_mode',
  'extra_info',
  'background_sync',
]);

const PROTECTED_HEADERS_METHODS = new Set([
  'message.send',
  'group.send',
  'message.thought.put',
  'group.thought.put',
]);

const RECONNECT_MIN_BASE_DELAY_SECONDS = 1.0;
const RECONNECT_MAX_BASE_DELAY_SECONDS = 64.0;
const TOKEN_REFRESH_CHECK_INTERVAL_MS = 30_000;
const PUSHED_SEQS_LIMIT = 50_000;
const PENDING_ORDERED_LIMIT = 50_000;

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
  'group.update_name', 'group.update_avatar', 'group.update_announcement',
  'group.update_settings',
  'storage.upload', 'storage.complete_upload', 'storage.delete',
  'auth.create_aid', 'auth.renew_cert', 'auth.rekey',
  'message.thought.put', 'group.thought.put',
  'group.add_member',
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
const PEER_PREKEYS_CACHE_TTL = 3600;
const AGENT_MD_HTTP_TIMEOUT_MS = 30_000;

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

function agentMdHttpScheme(gatewayUrl: string): string {
  const raw = String(gatewayUrl ?? '').trim().toLowerCase();
  return raw.startsWith('ws://') ? 'http' : 'https';
}

function agentMdAuthority(aid: string): string {
  return String(aid ?? '').trim();
}

async function fetchWithTimeout(
  input: string,
  init: RequestInit,
  timeoutMs = AGENT_MD_HTTP_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new AUNError(`agent.md request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timer);
  }
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

function isGroupServiceAid(value: JsonValue | object | undefined): boolean {
  const text = String(value ?? '').trim();
  if (!text.includes('.')) return false;
  const [name, ...issuerParts] = text.split('.');
  return name === 'group' && issuerParts.join('.').length > 0;
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

function normalizeV2WrapPolicy(raw: unknown): V2WrapPolicy | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const obj = raw as Record<string, unknown>;
  let protocol = String(obj.protocol ?? '').trim().toUpperCase();
  let scope = String(obj.scope ?? '').trim().toLowerCase();
  if (scope !== 'aid' && scope !== 'device') {
    if (obj.per_aid_wrap === true) scope = 'aid';
    else if (obj.per_device_wrap === true) scope = 'device';
    else scope = '';
  }
  if (protocol !== '1DH' && protocol !== '3DH') protocol = '';
  if (scope === 'aid') protocol = '1DH';
  if (!protocol && !scope) return undefined;
  return {
    protocol: protocol ? protocol as '1DH' | '3DH' : undefined,
    scope: scope ? scope as 'aid' | 'device' : undefined,
  };
}

function v2WrapCapabilities(): JsonObject {
  return {
    version: 'v2.1',
    protocols: ['1DH', '3DH'],
    scopes: ['aid', 'device'],
    per_aid_wrap: true,
    per_device_wrap: true,
  };
}

function applyV2WrapPolicyToTargets(targets: Target[], policy?: V2WrapPolicy): Target[] {
  if (!policy) return targets;
  const normalized = targets.map((target) => {
    const row: Target = { ...target };
    if (policy.protocol === '1DH') {
      row.keySource = 'aid_master';
      row.spkPkDer = undefined;
      row.spkId = '';
    }
    return row;
  });
  if (policy.scope !== 'aid') return normalized;
  const collapsed = new Map<string, Target>();
  for (const target of normalized) {
    const key = `${target.aid}\u0000${target.role}`;
    if (!collapsed.has(key)) {
      collapsed.set(key, { ...target, deviceId: '' });
    }
  }
  return Array.from(collapsed.values());
}

interface V2SenderIKPendingEntry {
  msg: Record<string, unknown>;
  fromAid: string;
  senderDeviceId: string;
  groupId: string;
  createdAt: number;
}

/** 32 字节左侧零填充（用于 P-256 私钥 scalar 规范化） */
function _v2LeftPad32(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  if (b.length > 32) return b.subarray(b.length - 32);
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
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

function _v2LengthPrefixedTextKey(...parts: string[]): string {
  const enc = new TextEncoder();
  return parts.map((part) => `${enc.encode(part).length}:${part};`).join('');
}

function _v2LengthPrefixedBytes(...parts: Uint8Array[]): Uint8Array {
  const enc = new TextEncoder();
  const framed: Uint8Array[] = [];
  for (const part of parts) {
    framed.push(enc.encode(`${part.length}:`), part, enc.encode(';'));
  }
  return _v2ConcatBytes(...framed);
}

/** Base64URL → Uint8Array（兼容缺失 padding） */
function _v2B64uToBytes(s: string): Uint8Array {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = std.length % 4 === 0 ? '' : '='.repeat(4 - (std.length % 4));
  return _v2B64ToBytes(std + pad);
}

function formatCaughtError(error: any): Error | string {
  return error instanceof Error ? error : String(error);
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

function truthyBool(value: unknown): boolean {
  if (value === true || value === 1) return true;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on';
  }
  return false;
}

function isEncryptedEnvelopePayload(payload: unknown): payload is Record<string, unknown> {
  if (!isJsonObject(payload)) return false;
  const payloadType = String(payload.type ?? '').trim();
  if (payloadType.startsWith('e2ee.')) return true;
  if (!String(payload.ciphertext ?? '').trim()) return false;
  return payload.nonce !== undefined
    || payload.tag !== undefined
    || payload.recipient !== undefined
    || payload.recipients !== undefined
    || payload.wrapped_key !== undefined
    || payload.recipients_digest !== undefined;
}

function encryptedPushEnvelope(msg: Record<string, unknown>): Record<string, unknown> | null {
  if (isEncryptedEnvelopePayload(msg.payload)) return msg.payload;
  if (typeof msg.envelope_json === 'string' && msg.envelope_json.trim()) {
    try {
      const parsed = JSON.parse(msg.envelope_json) as unknown;
      if (isEncryptedEnvelopePayload(parsed)) return parsed;
    } catch {
      return null;
    }
  }
  return null;
}

function isEncryptedPushMessage(msg: Record<string, unknown>): boolean {
  if (truthyBool(msg.encrypted)) return true;
  return encryptedPushEnvelope(msg) !== null;
}

function isV2EncryptedEnvelopePayload(envelope: Record<string, unknown> | null): envelope is Record<string, unknown> {
  if (!envelope) return false;
  const payloadType = String(envelope.type ?? '').trim();
  if (payloadType === 'e2ee.p2p_encrypted' || payloadType === 'e2ee.group_encrypted') return true;
  return String(envelope.version ?? '').trim().toLowerCase() === 'v2' && payloadType.startsWith('e2ee.');
}

function safeUndecryptablePushEvent(msg: Record<string, unknown>, group: boolean): Record<string, unknown> {
  const event: Record<string, unknown> = {
    message_id: msg.message_id ?? null,
    from: msg.from ?? null,
    seq: msg.seq ?? null,
    timestamp: msg.timestamp ?? msg.t_server ?? null,
    device_id: msg.device_id ?? null,
    slot_id: msg.slot_id ?? null,
    _decrypt_error: 'encrypted push payload is not decryptable on raw push path',
    _decrypt_stage: 'push_envelope',
  };
  if (group) {
    event.group_id = msg.group_id ?? null;
  } else {
    event.to = msg.to ?? null;
  }
  const envelope = encryptedPushEnvelope(msg);
  if (envelope) {
    event._envelope_type = String(envelope.type ?? '');
    event._suite = String(envelope.suite ?? '');
    if (isV2EncryptedEnvelopePayload(envelope)) {
      attachV2EnvelopeMetadata(event, v2E2eeMeta(envelope));
    }
  }
  return event;
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
  private _keystore: KeyStore;
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
  private _v2BootstrapCache: Map<string, V2BootstrapEntry> = new Map();
  private _v2SenderIKPending: Map<string, V2SenderIKPendingEntry> = new Map();
  private _v2SenderIKFetching: Set<string> = new Set();
  private static readonly V2_BOOTSTRAP_TTL_MS = 60 * 60 * 1000;
  private static readonly V2_RETRYABLE_CODES = new Set([-33011, -33012, -33050, -33052, -33054]);
  /** V2 state 签名验证缓存：cacheKey(hex) → expiry_unix_ms */
  private _v2SigCache: Map<string, number> = new Map();
  private static readonly _V2_SIG_CACHE_TTL = 60 * 60 * 1000;
  private static readonly _V2_SIG_CACHE_MAX = 16384;
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
  /**
   * 本地 agent.md 内容对应的 etag（quoted sha256 hex，与服务端 _agent_md_etag 一致）。
   *
   * 由 publishAgentMd() / fetchAgentMd(自身 aid) 写入；用于跟服务端 RPC 注入的 _meta.agent_md_etag
   * 比对，触发"本地未发布到服务端"或"服务端版本更新"的 UI 提示。
   */
  private _localAgentMdEtag: string = '';
  /** gateway 在 RPC envelope._meta.agent_md_etag 注入的服务端 etag；纯观察，无下游依赖。 */
  private _remoteAgentMdEtag: string = '';
  /** 浏览器侧 AIDs 逻辑根目录，正文映射到 IndexedDB 里的 {aid}/agent.md。 */
  private _agentMdPath: string = '';
  private _agentMdCache: Map<string, Record<string, unknown>> = new Map();
  private _agentMdFetchInflight: Set<string> = new Set();
  private _agentMdLock: Promise<unknown> = Promise.resolve();
  /** 消息序列号跟踪器（群消息 + P2P 空洞检测） */
  private _seqTracker: SeqTracker = new SeqTracker();
  private _seqTrackerContext: string | null = null;
  /** 补洞去重：已完成/进行中的 key 集合，防止重复 pull 同一区间 */
  private _gapFillDone: Set<string> = new Set();
  /** 已发布到应用层的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发 */
  private _pushedSeqs: Map<string, Set<number>> = new Map();
  /** 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq） */
  private _pendingOrderedMsgs: Map<string, Map<number, { event: string; payload: EventPayload }>> = new Map();
  /** Lazy group sync：首次发送群消息前自动拉取历史 */
  private _groupSynced: Set<string> = new Set();
  /** gap fill 来源标记：true 表示当前正在补洞（pull 触发），false 表示非补洞 */
  private _gapFillActive = false;
  // Pull Gate：序列化同一 key 的并发 pull 操作，防止重复拉取
  private _pullGates: Map<string, { inflight: boolean; startedAt: number; token: number }> = new Map();
  private static readonly _PULL_GATE_STALE_MS = 30000;
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
  private _logKeystore!: ModuleLogger;
  private _logDiscovery!: ModuleLogger;
  private _logEvents!: ModuleLogger;

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
    this._agentMdPath = this._agentMdDefaultRoot();
    this._deviceId = (inputAid?.deviceId) || getDeviceId();

    // Logger 必须最早初始化（其他子模块构造时通过 logger 输出）
    this._logger = new AUNLogger({ debug: _debug, aunPath: this.configModel.aunPath });
    this._logger.bindDeviceId(this._deviceId);
    this._clientLog = this._logger.for('aun_core.client');
    this._logAuth = this._logger.for('aun_core.auth');
    this._logTransport = this._logger.for('aun_core.transport');
    this._logKeystore = this._logger.for('aun_core.keystore');
    this._logDiscovery = this._logger.for('aun_core.discovery');
    this._logEvents = this._logger.for('aun_core.events');
    this._clientLog.info(`AUNClient initialized: debug=${_debug} aunPath=${this.configModel.aunPath} aid=${initAid ?? '-'}`);

    this._dispatcher = new EventDispatcher();
    this._discovery = new GatewayDiscovery();
    this._keystore = new IndexedDBKeyStore({});
    this._slotId = inputAid?.slotId || 'default';
    this._connectDeliveryMode = normalizeDeliveryModeConfig({ mode: 'fanout' });
    this._defaultConnectDeliveryMode = { ...this._connectDeliveryMode };
    this._auth = new AuthFlow({
      keystore: this._keystore,
      crypto: new CryptoProvider(),
      aid: initAid,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPem: this.configModel.rootCaPem,
      verifySsl: this.configModel.verifySsl,
    });
    this._aid = initAid;
    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: DEFAULT_SESSION_OPTIONS.timeouts.call,
      onDisconnect: (error, closeCode) => this._handleTransportDisconnect(error, closeCode),
    });
    this._transport.setMetaObserver((meta) => {
      void this._observeRpcMeta(meta).catch((exc) => {
        this._clientLog.debug(`agent.md meta observer skipped: ${String(exc)}`);
      });
    });

    if (inputAid) {
      if (inputAid.isPrivateKeyValid()) {
        this._currentAid = inputAid;
        this._identity = {
          aid: inputAid.aid,
          private_key_pem: inputAid.privateKeyPem,
          public_key_der_b64: inputAid.publicKey,
          cert: inputAid.certPem,
        };
        this._state = 'disconnected';
      }
    }

    // 注入 logger 到各子模块（构造时未传 logger，构造后通过 setLogger 注入）
    this._auth.setLogger(this._logAuth);
    this._transport.setLogger(this._logTransport);
    this._dispatcher.setLogger(this._logEvents);
    if (typeof (this._discovery as any).setLogger === 'function') {
      (this._discovery as any).setLogger(this._logger.for('aun_core.discovery'));
    }
    if (typeof (this._keystore as any).setLogger === 'function') {
      (this._keystore as any).setLogger(this._logKeystore);
    }

    // 内部订阅：推送消息 re-publish 给用户（V2 加密消息走 _raw.peer.v2.message_received）
    this._dispatcher.subscribe('_raw.message.received', (data) => {
      this._onRawMessageReceived(data);
    });
    // 群组消息推送：re-publish（V2 加密消息走 V2 push 路径）
    this._dispatcher.subscribe('_raw.group.message_created', (data) => {
      this._onRawGroupMessageCreated(data);
    });
    // 群组变更事件：验签 + 透传 + gap 检测
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
    this._dispatcher.subscribe('_raw.group.v2.epoch_rotated', (data) => {
      this._safeAsync(this._onV2EpochRotated(data));
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
    for (const evt of ['message.recalled', 'message.ack', 'storage.object_changed']) {
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

  private _setAgentMdRoot(root?: string | null): string {
    const next = String(root ?? '').trim() || this._agentMdDefaultRoot();
    this._agentMdPath = next;
    this._agentMdCache.clear();
    return next;
  }

  private async _resolveAgentMdUrl(aid: string): Promise<string> {
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('agent.md requires non-empty aid');
    let gatewayUrl = String(this._gatewayUrl ?? '').trim();
    if (!gatewayUrl) {
      try {
        gatewayUrl = await this._resolveGatewayForAid(target);
      } catch {
        gatewayUrl = '';
      }
    }
    const authority = agentMdAuthority(target);
    return `${agentMdHttpScheme(gatewayUrl)}://${authority}/agent.md`;
  }

  private async _ensureAgentMdUploadToken(aid: string, gatewayUrl: string): Promise<string> {
    let identity = await this._auth.loadIdentityOrNone(aid);
    if (!identity && this._identity && String(this._identity.aid ?? '') === aid) {
      identity = this._identity;
    }
    if (!identity) {
      throw new StateError('no local identity found, register or load an AID first');
    }

    const cachedToken = String(identity.access_token ?? '');
    const expiresAt = this._auth.getAccessTokenExpiry(identity);
    if (cachedToken && (expiresAt === null || expiresAt > Date.now() / 1000 + 30)) {
      return cachedToken;
    }

    if (identity.refresh_token) {
      try {
        const refreshed = await this._auth.refreshCachedTokens(gatewayUrl, identity);
        const refreshedToken = String(refreshed.access_token ?? '');
        const refreshedExpiry = this._auth.getAccessTokenExpiry(refreshed);
        if (refreshedToken && (refreshedExpiry === null || refreshedExpiry > Date.now() / 1000 + 30)) {
          this._identity = refreshed;
          return refreshedToken;
        }
      } catch {
        // refresh 失败时回退到完整 authenticate。
      }
    }

    const result = await this._auth.authenticate(gatewayUrl, aid);
    const token = String(result.access_token ?? '');
    if (!token) throw new StateError('authenticate did not return access_token');
    const fallbackIdentity: IdentityRecord = {
      ...identity,
      access_token: token,
      refresh_token: String(result.refresh_token ?? identity.refresh_token ?? ''),
    };
    const fallbackExpiresAt = Number(result.expires_at ?? identity.expires_at ?? NaN);
    if (Number.isFinite(fallbackExpiresAt)) fallbackIdentity.expires_at = fallbackExpiresAt;
    this._identity = await this._auth.loadIdentityOrNone(aid) ?? fallbackIdentity;
    return token;
  }

  private async _uploadAgentMd(content: string): Promise<Record<string, unknown>> {
    const target = String(this._aid ?? this._currentAid?.aid ?? '').trim();
    if (!target) throw new StateError('uploadAgentMd requires local AID');
    const gatewayUrl = await this._resolveGatewayForAid(target);
    this._gatewayUrl = gatewayUrl;
    const token = await this._ensureAgentMdUploadToken(target, gatewayUrl);
    const response = await fetchWithTimeout(await this._resolveAgentMdUrl(target), {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'text/markdown; charset=utf-8',
      },
      body: content,
    });

    if (response.status === 404) {
      throw new NotFoundError(`agent.md endpoint not found for aid: ${target}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(`upload agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`);
    }
    const payload = await response.json() as JsonValue;
    if (!isJsonObject(payload)) throw new AUNError('upload agent.md returned invalid JSON payload');
    return payload as Record<string, unknown>;
  }

  private async _downloadAgentMd(aid: string): Promise<string> {
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('downloadAgentMd requires non-empty aid');
    const cached = this._agentMdCache.get(target);
    const url = await this._resolveAgentMdUrl(target);
    const response = await fetchWithTimeout(url, {
      method: 'GET',
      headers: { Accept: 'text/markdown' },
      redirect: 'follow',
    });
    if (response.status === 304 && typeof cached?.text === 'string') {
      return String(cached.text);
    }
    if (response.status === 404) {
      throw new NotFoundError(`agent.md not found for aid: ${target}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(`download agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`);
    }
    const text = await response.text();
    const etag = String(response.headers?.get('ETag') ?? response.headers?.get('etag') ?? '').trim();
    const lastModified = String(response.headers?.get('Last-Modified') ?? response.headers?.get('last-modified') ?? '').trim();
    this._agentMdCache.set(target, {
      ...(cached ?? {}),
      text,
      etag,
      lastModified,
      remote_etag: etag,
      last_modified: lastModified,
    });
    return text;
  }

  private async _headAgentMd(aid: string): Promise<Record<string, unknown>> {
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('headAgentMd requires non-empty aid');
    const response = await fetchWithTimeout(await this._resolveAgentMdUrl(target), {
      method: 'HEAD',
      headers: { Accept: 'text/markdown' },
    });
    const etag = String(response.headers?.get('ETag') ?? response.headers?.get('etag') ?? '').trim();
    const lastModified = String(response.headers?.get('Last-Modified') ?? response.headers?.get('last-modified') ?? '').trim();
    if (response.status === 404) {
      return { aid: target, found: false, etag: '', last_modified: '', status: 404 };
    }
    if (!response.ok) {
      throw new AUNError(`head agent.md failed: HTTP ${response.status}`);
    }
    const cached = this._agentMdCache.get(target) ?? {};
    this._agentMdCache.set(target, {
      ...cached,
      etag,
      lastModified,
      remote_etag: etag,
      last_modified: lastModified,
    });
    return { aid: target, found: true, etag, last_modified: lastModified, status: response.status };
  }

  private async _verifyAgentMd(content: string, aid: string): Promise<Record<string, unknown>> {
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('verifyAgentMd requires non-empty aid');
    let peer = target === this._currentAid?.aid ? this._currentAid : null;
    if (!peer) {
      let certPem = String(await this._keystore.loadCert(target) ?? '').trim();
      if (!certPem) {
        certPem = String(await this._fetchPeerCert(target) ?? '').trim();
      }
      if (!certPem) throw new NotFoundError(`certificate not found for aid: ${target}`);
      peer = await AID.create({
        aid: target,
        aunPath: this.configModel.aunPath,
        certPem,
        privateKeyPem: null,
        certValid: true,
        privateKeyValid: false,
      });
    }
    const result = await peer.verifyAgentMd(content);
    if (!result.ok) throw new AUNError(result.error.message);
    return { ...result.data, verified: result.data.status === 'verified' };
  }

  /**
   * 浏览器版本 publishAgentMd。默认从 {agentMdPath}/{self_aid}/agent.md 的等价 IndexedDB 正文读取，
   * 然后签名、上传，并刷新 agentmd.json 元数据。
   *
   * 兼容旧浏览器调用：传入 content 时会先写入等价正文，再从该正文发布。
   */
  async publishAgentMd(content?: string | null): Promise<Record<string, unknown>> {
    const target = this._agentMdOwnerAid();
    if (!target || !this._currentAid) {
      throw new ValidationError('publishAgentMd requires local AID');
    }
    if (content !== undefined && content !== null) {
      const text = String(content ?? '');
      if (text.length === 0) {
        throw new ValidationError('publishAgentMd requires non-empty content');
      }
      await this._saveAgentMdRecord(target, {
        content: text,
        local_etag: await this._agentMdContentEtag(text),
        fetched_at: Date.now(),
      });
    }
    const localContent = await this._readAgentMdContent(target);
    if (localContent === null || localContent.length === 0) {
      throw new ValidationError('publishAgentMd requires local agent.md content');
    }
    const signedResult = await this._currentAid?.signAgentMd(localContent);
    if (!signedResult?.ok) {
      throw new StateError(signedResult?.error.message ?? 'publishAgentMd requires a valid local AID private key');
    }
    const signed = signedResult.data.signed;
    const result = await this._uploadAgentMd(signed);
    this._localAgentMdEtag = await this._agentMdContentEtag(signed);
    const remoteEtag = isJsonObject(result) ? String(result.etag ?? '').trim() : '';
    if (remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    await this._saveAgentMdRecord(target, {
      content: signed,
      local_etag: this._localAgentMdEtag,
      remote_etag: remoteEtag || undefined,
      last_modified: isJsonObject(result) ? String(result.last_modified ?? '').trim() : '',
      fetched_at: Date.now(),
      remote_status: remoteEtag ? 'found' : 'unknown',
      last_error: '',
    });
    return result as Record<string, unknown>;
  }

  /**
   * 浏览器版本 fetchAgentMd。aid 缺省时取自身；下载后的正文固定写入
   * {agentMdPath}/{aid}/agent.md 的等价 IndexedDB 正文，agentmd.json 只保存元数据。
   */
  private async _fetchAgentMdCache(aid?: string | null): Promise<{
    aid: string;
    content: string;
    signature: Record<string, unknown>;
    in_sync: boolean | null;
  }> {
    const target = String(aid ?? this._aid ?? '').trim();
    if (!target) {
      throw new ValidationError('fetchAgentMd requires aid (or local AID)');
    }
    const content = await this._downloadAgentMd(target);
    const signature = await this._verifyAgentMd(content, target);

    const isSelf = target === (this._aid ?? '');
    const localEtag = await this._agentMdContentEtag(content);
    const cacheMeta = this._agentMdAuthCacheMeta(target);
    const remoteEtag = String(cacheMeta.etag ?? '').trim();
    const lastModified = String(cacheMeta.lastModified ?? cacheMeta.last_modified ?? '').trim();
    if (isSelf) {
      this._localAgentMdEtag = localEtag;
      if (remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    }
    await this._saveAgentMdRecord(target, {
      content,
      local_etag: localEtag,
      remote_etag: remoteEtag || undefined,
      last_modified: lastModified || undefined,
      fetched_at: Date.now(),
      remote_status: 'found',
      verify_status: isJsonObject(signature) ? String(signature.status ?? '') : '',
      verify_error: isJsonObject(signature) ? String(signature.reason ?? '') : '',
      last_error: '',
    });
    let in_sync: boolean | null = null;
    if (isSelf) {
      const remote = remoteEtag || this._remoteAgentMdEtag || '';
      in_sync = localEtag && remote ? localEtag === remote : false;
    }
    return {
      aid: target,
      content,
      signature: signature as Record<string, unknown>,
      in_sync,
    };
  }

  getLocalAgentMdEtag(): string {
    return this._localAgentMdEtag;
  }

  getRemoteAgentMdEtag(): string {
    return this._remoteAgentMdEtag;
  }

  private async _agentMdContentEtag(content: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(content ?? '')));
    const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    return `"${hex}"`;
  }

  private _agentMdOwnerAid(): string {
    return String(this._aid ?? '').trim();
  }

  private _agentMdDefaultRoot(): string {
    return this._joinAgentMdPath(this.configModel.aunPath || '.', 'AIDs');
  }

  private _joinAgentMdPath(base: string, name: string): string {
    const left = String(base ?? '').trim().replace(/[\\/]+$/g, '');
    return left ? `${left}/${name}` : name;
  }

  private _agentMdRoot(): string {
    return this._agentMdPath || this._agentMdDefaultRoot();
  }

  private _agentMdSafeAid(aid: string): string {
    const target = String(aid ?? '').trim();
    if (!target || target.includes('/') || target.includes('\\') || target.includes('\0')) {
      throw new ValidationError('agent.md aid is empty or contains path separators');
    }
    return target;
  }

  private _agentMdMetaKey(aid: string): string {
    return `${this._agentMdSafeAid(aid)}/agentmd.json`;
  }

  private _agentMdContentKey(aid: string): string {
    return `${this._agentMdSafeAid(aid)}/agent.md`;
  }

  private async _readAgentMdStorage(logicalKey: string): Promise<string | null> {
    const key = String(logicalKey ?? '').trim();
    if (!key) return null;
    const load = this._keystore.loadAgentMdCache;
    if (typeof load !== 'function') {
      throw new Error('IndexedDB agent.md storage unavailable');
    }
    const record = await load.call(this._keystore, this._agentMdRoot(), key);
    if (record && Object.prototype.hasOwnProperty.call(record, 'content')) {
      return String(record.content ?? '');
    }
    return null;
  }

  private async _writeAgentMdStorage(logicalKey: string, content: string): Promise<void> {
    const key = String(logicalKey ?? '').trim();
    if (!key) return;
    const save = this._keystore.upsertAgentMdCache;
    if (typeof save !== 'function') {
      throw new Error('IndexedDB agent.md storage unavailable');
    }
    const text = String(content ?? '');
    await save.call(this._keystore, this._agentMdRoot(), key, {
      content: text,
      local_etag: await this._agentMdContentEtag(text),
      fetched_at: Date.now(),
    });
  }

  private async _withAgentMdLock<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this._agentMdLock.catch(() => undefined);
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    this._agentMdLock = previous.then(() => current);
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  private _normalizeAgentMdRecord(aid: string, data: unknown): Record<string, unknown> {
    if (!isJsonObject(data as JsonValue | object | null | undefined)) return {};
    const record: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (key !== 'content') record[key] = value;
    }
    record.aid = this._agentMdSafeAid(String(record.aid ?? aid));
    for (const key of ['fetched_at', 'observed_at', 'checked_at', 'updated_at']) {
      record[key] = Number(record[key] ?? 0) || 0;
    }
    return record;
  }

  private async _writeAgentMdRecordUnlocked(aid: string, record: Record<string, unknown>): Promise<void> {
    const payload: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record)) {
      if (key !== 'content' && value !== undefined && value !== null) payload[key] = value;
    }
    payload.aid = this._agentMdSafeAid(aid);
    await this._writeAgentMdStorage(this._agentMdMetaKey(aid), `${JSON.stringify(payload, null, 2)}\n`);
  }

  private async _readAgentMdRecordUnlocked(aid: string): Promise<Record<string, unknown>> {
    const raw = await this._readAgentMdStorage(this._agentMdMetaKey(aid));
    if (raw === null) return {};
    try {
      return this._normalizeAgentMdRecord(aid, JSON.parse(raw));
    } catch (err) {
      this._clientLog.warn(`agent.md metadata damaged, ignoring: aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      return {};
    }
  }

  private async _readAgentMdContent(aid: string): Promise<string | null> {
    return await this._readAgentMdStorage(this._agentMdContentKey(aid));
  }

  private async _writeAgentMdContent(aid: string, content: string): Promise<void> {
    await this._writeAgentMdStorage(this._agentMdContentKey(aid), String(content ?? ''));
  }

  private _agentMdAuthCacheMeta(aid: string): Record<string, unknown> {
    try {
      const record = this._agentMdCache.get(String(aid ?? '').trim());
      return record && typeof record === 'object' ? { ...record } : {};
    } catch {
      return {};
    }
  }

  private async _loadAgentMdRecord(aid: string): Promise<Record<string, unknown> | null> {
    const target = String(aid ?? '').trim();
    if (!target) return null;
    try {
      const loaded = await this._withAgentMdLock(async () => {
        const record = await this._readAgentMdRecordUnlocked(target);
        const next: Record<string, unknown> = Object.keys(record).length > 0 ? { ...record, aid: target } : { aid: target };
        try {
          const content = await this._readAgentMdContent(target);
          if (content !== null) {
            next.content = content;
            next.local_etag = await this._agentMdContentEtag(content);
          } else {
            // 元数据存在但正文缺失
            const metaRaw = await this._readAgentMdStorage(this._agentMdMetaKey(target));
            if (metaRaw !== null) {
              this._clientLog.warn(`agent.md content read failed: aid=${target}`);
            }
          }
        } catch (err) {
          this._clientLog.warn(`agent.md content read failed: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
        }
        return next;
      });
      if (Object.keys(loaded).length <= 1) return null;
      this._agentMdCache.set(target, { ...loaded });
      return { ...loaded };
    } catch (err) {
      this._clientLog.debug(`agent.md cache load skipped: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
    }
    return null;
  }

  private async _saveAgentMdRecord(aid: string, fields: Record<string, unknown>): Promise<Record<string, unknown>> {
    const target = String(aid ?? '').trim();
    if (!target) return {};
    try {
      const inputFields: Record<string, unknown> = { ...fields };
      const hasContent = Object.prototype.hasOwnProperty.call(inputFields, 'content') && inputFields.content !== undefined && inputFields.content !== null;
      if (hasContent) {
        const text = String(inputFields.content ?? '');
        await this._writeAgentMdContent(target, text);
        if (!inputFields.local_etag) inputFields.local_etag = await this._agentMdContentEtag(text);
        if (!inputFields.fetched_at) inputFields.fetched_at = Date.now();
      }
      delete inputFields.content;
      const record = await this._withAgentMdLock(async () => {
        const next: Record<string, unknown> = { ...(await this._readAgentMdRecordUnlocked(target)), aid: target };
        for (const [key, value] of Object.entries(inputFields)) {
          if (value !== undefined && value !== null) next[key] = value;
        }
        next.updated_at = Date.now();
        await this._writeAgentMdRecordUnlocked(target, next);
        return next;
      });
      const loaded: Record<string, unknown> = { ...record };
      if (hasContent) loaded.content = String(fields.content ?? '');
      this._agentMdCache.set(target, { ...loaded });
      const owner = this._agentMdOwnerAid();
      if (target === owner) {
        const localEtag = String(loaded.local_etag ?? '').trim();
        const remoteEtag = String(loaded.remote_etag ?? '').trim();
        if (localEtag) this._localAgentMdEtag = localEtag;
        if (remoteEtag) this._remoteAgentMdEtag = remoteEtag;
      }
      return { ...loaded };
    } catch (err) {
      this._clientLog.debug(`agent.md cache save skipped: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
    }
    return {};
  }

  private async _agentMdHasLocalContent(aid: string, record?: Record<string, unknown> | null): Promise<boolean> {
    if (record && typeof record.content === 'string' && record.content.length > 0) return true;
    try {
      return (await this._readAgentMdContent(aid)) !== null;
    } catch {
      return false;
    }
  }

  private _agentMdCheckedAtFresh(checkedAtMs: number, maxUnsyncedDays: number): boolean {
    const days = Number(maxUnsyncedDays || 0);
    if (!Number.isFinite(days) || days <= 0) return false;
    if (!Number.isFinite(checkedAtMs) || checkedAtMs <= 0) return false;
    return Date.now() - checkedAtMs <= days * 86400000;
  }

  private _agentMdLastModifiedFresh(lastModified: string, maxUnsyncedDays: number): boolean {
    const days = Number(maxUnsyncedDays || 0);
    if (!Number.isFinite(days) || days <= 0) return false;
    const ts = Date.parse(String(lastModified ?? '').trim());
    if (!Number.isFinite(ts)) return false;
    return Date.now() <= ts + days * 86400000;
  }

  private async _scheduleAgentMdFetchIfMissing(aid: string, record?: Record<string, unknown> | null, source = ''): Promise<void> {
    const target = String(aid ?? '').trim();
    if (!target || await this._agentMdHasLocalContent(target, record)) return;
    if (this._agentMdFetchInflight.has(target)) return;
    this._agentMdFetchInflight.add(target);
    try {
      await this._fetchAgentMdCache(target);
    } catch (err) {
      await this._saveAgentMdRecord(target, {
        last_error: err instanceof Error ? err.message : String(err),
        remote_status: 'found',
      });
      this._clientLog.debug(`agent.md auto fetch failed: aid=${target} source=${source || '-'} err=${err instanceof Error ? err.message : String(err)}`);
    } finally {
      this._agentMdFetchInflight.delete(target);
    }
  }

  private async _observeAgentMdMeta(aid: string, etag = '', lastModified = '', source = ''): Promise<void> {
    const target = String(aid ?? '').trim();
    const remoteEtag = String(etag ?? '').trim();
    const remoteLastModified = String(lastModified ?? '').trim();
    if (!target || (!remoteEtag && !remoteLastModified)) return;
    let before = this._agentMdCache.get(target);
    if (!before || typeof before !== 'object') before = await this._loadAgentMdRecord(target) ?? {};
    const same =
      (!remoteEtag || String(before.remote_etag ?? '').trim() === remoteEtag) &&
      (!remoteLastModified || String(before.last_modified ?? '').trim() === remoteLastModified);
    let record: Record<string, unknown> = { ...before };
    if (!same || Object.keys(before).length === 0) {
      const fields: Record<string, unknown> = {
        observed_at: Date.now(),
        remote_status: 'found',
      };
      if (remoteEtag) fields.remote_etag = remoteEtag;
      if (remoteLastModified) fields.last_modified = remoteLastModified;
      record = await this._saveAgentMdRecord(target, fields) || record;
    }
    if (target === this._agentMdOwnerAid() && remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    await this._scheduleAgentMdFetchIfMissing(target, record, source);
    this._clientLog.debug(`agent.md meta observed: aid=${target} etag=${remoteEtag || '-'} last_modified=${remoteLastModified || '-'} source=${source || '-'}`);
  }

  private async _observeAgentMdEtag(aid: string, etag: string, source = ''): Promise<void> {
    await this._observeAgentMdMeta(aid, etag, '', source);
  }

  private async _observeAgentMdFromEnvelope(envelope: unknown): Promise<void> {
    if (!isJsonObject(envelope)) return;
    const env = envelope as JsonObject;
    if (!isJsonObject(env.agent_md)) return;
    const agentMd = env.agent_md as JsonObject;
    if (!isJsonObject(agentMd.sender)) return;
    const sender = agentMd.sender as JsonObject;
    let senderAid = String(sender.aid ?? '').trim();
    if (!senderAid) {
      const aad = isJsonObject(env.aad) ? env.aad as JsonObject : {};
      senderAid = String(aad.from ?? env.from ?? '').trim();
    }
    await this._observeAgentMdMeta(
      senderAid,
      String(sender.etag ?? '').trim(),
      String(sender.last_modified ?? sender.lastModified ?? '').trim(),
      'envelope',
    );
  }

  private async _checkAgentMdCache(aid?: string | null, maxUnsyncedDays = 0): Promise<Record<string, unknown>> {
    const target = String(aid ?? this._aid ?? '').trim();
    if (!target) throw new ValidationError('checkAgentMd requires aid (or local AID)');
    const before = await this._loadAgentMdRecord(target) ?? {};
    const localEtag = String(before.local_etag ?? '').trim();
    const localFound = !!(Object.keys(before).length > 0 && (String(before.content ?? '') || localEtag));
    const remoteEtagCached = String(before.remote_etag ?? '').trim();
    const lastModifiedCached = String(before.last_modified ?? '').trim();
    const checkedAtCached = Number(before.checked_at ?? 0);
    const cachedInSync = !!(localFound && localEtag && remoteEtagCached && localEtag === remoteEtagCached);
    // max_unsynced_days > 0 且距上次 HEAD 在窗口内 → 直接返回缓存；否则强制 HEAD。
    if (cachedInSync && this._agentMdCheckedAtFresh(checkedAtCached, maxUnsyncedDays)) {
      return {
        aid: target,
        local_found: true,
        remote_found: true,
        local_etag: localEtag,
        remote_etag: remoteEtagCached,
        in_sync: true,
        last_modified: lastModifiedCached,
        status: 200,
        cached: true,
        verify_status: String(before.verify_status ?? ''),
        verify_error: String(before.verify_error ?? ''),
      };
    }

    const now = Date.now();
    let remote: Record<string, unknown>;
    try {
      remote = await this._headAgentMd(target);
    } catch (err) {
      await this._saveAgentMdRecord(target, { checked_at: now, remote_status: 'error', last_error: err instanceof Error ? err.message : String(err) });
      throw err;
    }
    const remoteFound = !!remote.found;
    const remoteEtag = String(remote.etag ?? '').trim();
    const lastModified = String(remote.last_modified ?? remote.lastModified ?? '').trim();
    const saved = await this._saveAgentMdRecord(target, {
      remote_etag: remoteFound ? remoteEtag : '',
      last_modified: lastModified,
      checked_at: now,
      remote_status: remoteFound ? 'found' : 'missing',
      last_error: '',
    });
    if (target === this._agentMdOwnerAid() && remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    const inSync = !!(localFound && remoteFound && localEtag && remoteEtag && localEtag === remoteEtag);
    return {
      aid: target,
      local_found: localFound,
      remote_found: remoteFound,
      local_etag: localEtag,
      remote_etag: remoteEtag,
      in_sync: inSync,
      last_modified: lastModified,
      status: Number(remote.status ?? (remoteFound ? 200 : 404)),
      cached: false,
      verify_status: String(saved.verify_status ?? before.verify_status ?? ''),
      verify_error: String(saved.verify_error ?? before.verify_error ?? ''),
    };
  }

  /** transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。 */
  private async _observeRpcMeta(meta: JsonObject): Promise<void> {
    if (!isJsonObject(meta)) return;
    const etag = String(meta.agent_md_etag ?? '').trim();
    if (etag) {
      this._remoteAgentMdEtag = etag;
      await this._observeAgentMdMeta(this._aid ?? '', etag, '', 'rpc.self');
    }
    const etags = meta.agent_md_etags;
    if (isJsonObject(etags)) {
      // role key 优先级：requester / peer 是新规范，其余是兼容旧 SDK 的别名。
      for (const key of ['requester', 'peer', 'receiver', 'target', 'to', 'sender', 'from']) {
        const item = (etags as JsonObject)[key];
        if (!isJsonObject(item)) continue;
        await this._observeAgentMdMeta(
          String((item as JsonObject).aid ?? ''),
          String((item as JsonObject).etag ?? ''),
          String((item as JsonObject).last_modified ?? (item as JsonObject).lastModified ?? ''),
          `rpc.${key}`,
        );
      }
    }
  }  get state(): ConnectionState {
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

  private _applyAidRuntimeContext(aid: AID): void {
    const nextConfig = createConfig({
      aunPath: aid.aunPath,
      rootCaPem: aid.rootCaPath,
      verifySsl: aid.verifySsl,
    });
    Object.assign(this.configModel, nextConfig);
    this.config.aun_path = nextConfig.aunPath;
    this.config.root_ca_path = nextConfig.rootCaPem;
    this.config.seed_password = nextConfig.seedPassword;
    this._agentMdPath = this._agentMdDefaultRoot();
    this._agentMdCache.clear();
    this._agentMdFetchInflight.clear();
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
    this._logKeystore = this._logger.for('aun_core.keystore');
    this._logDiscovery = this._logger.for('aun_core.discovery');
    this._logEvents = this._logger.for('aun_core.events');

    this._discovery = new GatewayDiscovery();
    this._keystore = new IndexedDBKeyStore({});
    this._auth = new AuthFlow({
      keystore: this._keystore,
      crypto: new CryptoProvider(),
      aid: aid.aid,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPem: nextConfig.rootCaPem,
      verifySsl: nextConfig.verifySsl,
    });
    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: DEFAULT_SESSION_OPTIONS.timeouts.call,
      onDisconnect: (error, closeCode) => this._handleTransportDisconnect(error, closeCode),
    });
    this._transport.setMetaObserver((meta) => {
      void this._observeRpcMeta(meta).catch((exc) => {
        this._clientLog.debug(`agent.md meta observer skipped: ${String(exc)}`);
      });
    });
    this._auth.setLogger(this._logAuth);
    this._transport.setLogger(this._logTransport);
    this._dispatcher.setLogger(this._logEvents);
    if (typeof (this._discovery as any).setLogger === 'function') {
      (this._discovery as any).setLogger(this._logDiscovery);
    }
    if (typeof (this._keystore as any).setLogger === 'function') {
      (this._keystore as any).setLogger(this._logKeystore);
    }
  }

  loadIdentity(aid: AID): void {
    if (!aid?.isPrivateKeyValid()) throw new StateError('loadIdentity requires an AID with a valid private key');
    const publicState = this.state;
    if (publicState !== ConnectionState.NO_IDENTITY && publicState !== ConnectionState.CLOSED) {
      throw new StateError(`loadIdentity not allowed in state ${publicState}`);
    }
    this._applyAidRuntimeContext(aid);
    this._currentAid = aid;
    this._aid = aid.aid;
    this._identity = {
      aid: aid.aid,
      private_key_pem: aid.privateKeyPem,
      public_key_der_b64: aid.publicKey,
      cert: aid.certPem,
    };
    this._state = 'disconnected';
    this._closing = false;
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
    if (!this.hasIdentity) throw new StateError('cachePeer requires a loaded identity');
    if (!aid.isCertValid()) throw new ValidationError('cachePeer requires an AID with a valid certificate');
    this._peerCache.set(aid.aid, aid);
    return aid;
  }

  getPeer(aid: string): AID | null {
    if (!this.hasIdentity) throw new StateError('getPeer requires a loaded identity');
    return this._peerCache.get(String(aid ?? '').trim()) ?? null;
  }

  async lookupPeer(aid: string): Promise<AID> {
    if (!this.hasIdentity) throw new StateError('lookupPeer requires a loaded identity');
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('lookupPeer requires non-empty aid');
    const cached = this._peerCache.get(target);
    if (cached) return cached;
    throw new NotFoundError(`peer not found in cache: ${target}`);
  }

  peers(): AID[] {
    if (!this.hasIdentity) throw new StateError('peers requires a loaded identity');
    return [...this._peerCache.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, v]) => v);
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
    const tStart = Date.now();
    const target = this._currentAid?.aid ?? this._aid ?? '';
    if (!target || !this._currentAid?.isPrivateKeyValid()) {
      throw new StateError('authenticate requires a loaded AID with a valid private key');
    }
    const publicState = this.state;
    if (publicState !== ConnectionState.STANDBY) {
      throw new StateError(`authenticate not allowed in state ${publicState}`);
    }
    if ('aid' in options || 'access_token' in options || 'token' in options || 'kite_token' in options) {
      throw new ValidationError('authenticate options must not include aid or token fields; load an AID object first');
    }
    this._state = 'connecting';
    try {
      const gateway = String(options.gateway ?? this._gatewayUrl ?? await this._resolveGatewayForAid(target)).trim();
      const result = await this._auth.authenticate(gateway, target);
      this._gatewayUrl = String(result.gateway ?? gateway);
      this._identity = await this._auth.loadIdentityOrNone(target);
      this._state = 'authenticated';
      this._clientLog.debug(`authenticate exit: elapsed=${Date.now() - tStart}ms aid=${target}`);
      return result as Record<string, unknown>;
    } catch (err) {
      this._state = 'disconnected';
      this._clientLog.debug(`authenticate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 连接到 Gateway；身份来自构造函数或 loadIdentity(aid)，认证由 SDK 内部自动完成。 */
  async connect(opts?: ConnectionOptions): Promise<void> {
    const tStart = Date.now();
    if (opts !== undefined && opts !== null && typeof opts === 'object') {
      const raw = opts as Record<string, unknown>;
      const invalid = Object.keys(raw).filter((key) => !PUBLIC_CONNECTION_OPTION_KEYS.has(key)).sort();
      if (invalid.length > 0) {
        throw new ValidationError(`connect options contain unsupported field(s): ${invalid.join(', ')}`);
      }
    }
    const target = this._currentAid?.aid ?? this._aid ?? '';
    if (!target || !this._currentAid?.isPrivateKeyValid()) {
      throw new StateError('connect requires a loaded AID with a valid private key');
    }
    const options: RpcParams = {};
    if (opts?.auto_reconnect !== undefined) options.auto_reconnect = opts.auto_reconnect;
    if (opts?.heartbeat_interval !== undefined) options.heartbeat_interval = opts.heartbeat_interval;
    if (opts?.connect_timeout !== undefined || opts?.call_timeout !== undefined) {
      options.timeouts = {
        ...(opts.connect_timeout !== undefined ? { connect: opts.connect_timeout } : {}),
        ...(opts.call_timeout !== undefined ? { call: opts.call_timeout } : {}),
      };
    }
    if (opts?.retry_initial_delay !== undefined || opts?.retry_max_delay !== undefined || opts?.retry_max_attempts !== undefined) {
      options.retry = {
        initial_delay: opts.retry_initial_delay ?? 1,
        max_delay: opts.retry_max_delay ?? 64,
        max_attempts: opts.retry_max_attempts ?? 0,
      };
    }
    if (opts?.connection_kind !== undefined) options.connection_kind = opts.connection_kind;
    if (opts?.short_ttl_ms !== undefined) options.short_ttl_ms = opts.short_ttl_ms;
    if (opts?.delivery_mode !== undefined) options.delivery_mode = opts.delivery_mode;
    if (opts?.extra_info !== undefined) options.extra_info = opts.extra_info;
    if (opts?.background_sync !== undefined) options.background_sync = opts.background_sync;
    this._clientLog.debug(`connect enter: state=${this._state} aid=${this._aid ?? '-'}`);
    const publicState = this.state;
    const allowed = new Set<ConnectionState>([
      ConnectionState.STANDBY,
      ConnectionState.AUTHENTICATED,
      ConnectionState.RETRY_BACKOFF,
      ConnectionState.CONNECTION_FAILED,
    ]);
    if (!allowed.has(publicState)) {
      this._clientLog.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=invalid_state state=${this._state}`);
      throw new StateError(`connect not allowed in state ${publicState}`);
    }
    // gateway 来自 authenticate() 缓存的 this._gatewayUrl；未认证则自动 authenticate()
    if (!this._gatewayUrl) {
      await this.authenticate();
    }
    this._state = 'connecting';

    const gateway = String(this._gatewayUrl ?? '').trim();
    const params = { ...options, gateway };
    const normalized = this._normalizeConnectParams(params);
    this._sessionParams = normalized;
    this._sessionOptions = this._buildSessionOptions(normalized);
    this._transport.setTimeout(this._sessionOptions.timeouts.call);
    this._closing = false;

    const gateways = this._resolveGateways(normalized);
    let lastErr: unknown = null;
    for (const gw of gateways) {
      try {
        const gwParams = { ...normalized, gateway: gw };
        await this._connectOnce(gwParams, true);
        this._clientLog.debug(`connect exit: elapsed=${Date.now() - tStart}ms state=${this._state}`);
        return;
      } catch (err) {
        lastErr = err;
        if (gateways.length > 1) {
          this._clientLog.warn(`connect: gateway ${gw} failed, trying next: ${err instanceof Error ? err.message : String(err)}`);
        }
        if (this._state === 'connecting' || this._state === 'authenticating') {
          this._state = 'connecting';
        }
      }
    }
    if (this._state === 'connecting' || this._state === 'authenticating') {
      this._state = 'terminal_failed';
    }
    this._clientLog.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);
    throw lastErr;
  }

  /** 断开连接但保留本地状态，可再次 connect */
  async disconnect(): Promise<void> {
    const tStart = Date.now();
    this._clientLog.debug(`disconnect enter: state=${this._state}`);
    if (this._state !== 'connected' && this._state !== 'reconnecting') {
      this._clientLog.debug(`disconnect exit: elapsed=${Date.now() - tStart}ms reason=not_connected`);
      return;
    }

    this._saveSeqTrackerState();
    this._stopBackgroundTasks();

    if (this._reconnectAbort) {
      this._reconnectAbort.abort();
      this._reconnectAbort = null;
      this._reconnectActive = false;
    }

    await this._transport.close();
    this._state = 'disconnected';
    await this._dispatcher.publish('state_change', { state: this._publicState(this._state) });
    this._clientLog.debug(`disconnect exit: elapsed=${Date.now() - tStart}ms`);
  }

  /** 关闭连接 */
  async close(): Promise<void> {
    const tStart = Date.now();
    this._clientLog.debug(`close enter: state=${this._state}`);
    this._closing = true;
    this._saveSeqTrackerState();
    this._stopBackgroundTasks();

    // 取消进行中的重连
    if (this._reconnectAbort) {
      this._reconnectAbort.abort();
      this._reconnectAbort = null;
      this._reconnectActive = false;
    }

    if (this._state === 'idle' || this._state === 'closed') {
      this._state = 'closed';
      this._resetSeqTrackingState();
      this._clientLog.debug(`close exit: elapsed=${Date.now() - tStart}ms reason=already_idle`);
      return;
    }

    // 关闭前通知服务端主动退出（best-effort，失败不阻塞）
    try {
      await this._transport.call('auth.logout', {});
    } catch {
      // auth.logout 失败不影响关闭流程
    }

    await this._transport.close();
    this._state = 'closed';
    await this._dispatcher.publish('state_change', { state: this._publicState(this._state) });
    this._resetSeqTrackingState();
    this._clientLog.debug(`close exit: elapsed=${Date.now() - tStart}ms`);
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
    const tStart = Date.now();
    this._clientLog.debug(`call enter: method=${method}`);
    try {
      const result = await this._callImpl(method, params);
      this._clientLog.debug(`call exit: elapsed=${Date.now() - tStart}ms method=${method}`);
      return result;
    } catch (err) {
      this._clientLog.debug(`call exit (error): elapsed=${Date.now() - tStart}ms method=${method} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async _callImpl(
    method: string,
    params?: RpcParams,
  ): Promise<RpcResult> {
    if (this._state !== 'connected') {
      throw new ConnectionError('client is not connected');
    }
    if (INTERNAL_ONLY_METHODS.has(method)) {
      throw new PermissionError(`method is internal_only: ${method}`);
    }
    if (method.startsWith('message.e2ee.') || method.startsWith('group.e2ee.') || REMOVED_E2EE_METHODS.has(method)) {
      throw new PermissionError(`legacy E2EE method is removed in this SDK: ${method}`);
    }

    const p = { ...(params ?? {}) };
    if (this._instanceProtectedHeaders && PROTECTED_HEADERS_METHODS.has(method)) {
      const existing = isJsonObject(p.protected_headers) ? p.protected_headers : {};
      p.protected_headers = { ...this._instanceProtectedHeaders, ...existing };
    }
    if (method === 'message.send' || method === 'group.send') {
      this._normalizeOutboundMessagePayload(p, method);
    }
    this._validateOutboundCall(method, p);
    this._injectMessageCursorContext(method, p);
    if (method.startsWith('group.')
      && !('_group_cursor_params' in (p as Record<string, unknown>))
      && !Boolean((p as Record<string, unknown>)._pull_gate_locked)) {
      const explicitCursorParams = this._groupCursorParams(p);
      if (Object.keys(explicitCursorParams).length > 0) {
        (p as Record<string, unknown>)._group_cursor_params = explicitCursorParams;
      }
    }

    // group.* 方法的 group_id 归一化为 canonical 格式（兼容老/污染数据）
    if (method.startsWith('group.') && p.group_id !== undefined && p.group_id !== null) {
      const rawGroupId = String(p.group_id);
      const normalizedGroupId = normalizeGroupId(rawGroupId);
      if (normalizedGroupId && normalizedGroupId !== rawGroupId) {
        this._clientLog.debug(`call group_id normalized: ${rawGroupId} -> ${normalizedGroupId} method=${method}`);
      }
      p.group_id = normalizedGroupId;
    }

    // group.* 方法注入 device_id（服务端用于多设备消息路由）
    if (method.startsWith('group.') && p.device_id === undefined) {
      p.device_id = this._deviceId;
    }
    if (method.startsWith('group.') && p.slot_id === undefined) {
      p.slot_id = this._slotId;
    }

    // 自动加密：message.send 默认加密（encrypt 默认 true）— V2-only
    if (method === 'message.send') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await this._ensureV2SessionReady(
          'message.send',
          'V2 session not initialized; encrypted message.send requires V2 (V1 E2EE removed)',
        );
        this._clientLog.debug('call route: message.send → V2 encrypted send');
        return await this._sendV2(String(p.to ?? ''), p.payload as Record<string, unknown> ?? {}, {
          messageId: String(p.message_id ?? '') || undefined,
          timestamp: p.timestamp as number | undefined,
          protectedHeaders: this._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
          context: isJsonObject(p.context) ? p.context : undefined,
        }) as RpcResult;
      }
      // encrypt=false：明文走通用 RPC 路径；protected_headers/headers 是信封元数据，加密与否都保留
      this._maybeAppendEchoTraceSend(p);
    }

    // 自动加密：group.send 默认加密（encrypt 默认 true）— V2-only
    if (method === 'group.send') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await this._ensureV2SessionReady(
          'group.send',
          'V2 session not initialized; encrypted group.send requires V2 (V1 E2EE removed)',
        );
        this._clientLog.debug('call route: group.send → V2 encrypted send');
        return await this._sendGroupV2(String(p.group_id ?? ''), p.payload as Record<string, unknown> ?? {}, {
          messageId: String(p.message_id ?? '') || undefined,
          timestamp: p.timestamp as number | undefined,
          protectedHeaders: this._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
          context: isJsonObject(p.context) ? p.context : undefined,
        }) as RpcResult;
      }
      this._maybeAppendEchoTraceSend(p);
    }
    if (method === 'group.thought.put') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await this._ensureV2SessionReady(
          'group.thought.put',
          'V2 session not initialized; encrypted group.thought.put requires V2 (V1 E2EE removed)',
        );
        this._clientLog.debug('call route: group.thought.put → V2 encrypted put');
        return this._putGroupThoughtEncryptedV2(p);
      }
    }
    if (method === 'message.thought.put') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await this._ensureV2SessionReady(
          'message.thought.put',
          'V2 session not initialized; encrypted message.thought.put requires V2 (V1 E2EE removed)',
        );
        this._clientLog.debug('call route: message.thought.put → V2 encrypted put');
        return this._putMessageThoughtEncryptedV2(p);
      }
    }

    // Pull Gate：序列化同一 key 的 pull 操作，防止并发重复拉取
    const pullGateKey = this._pullGateKeyForCall(method, p);
    if (pullGateKey) {
      return await this._runPullSerialized(pullGateKey, async () => {
        return await this._callImplInner(method, p);
      });
    }

    return await this._callImplInner(method, p);
  }

  /**
   * _callImpl 的内层：pull gate 之后的实际 RPC 分发逻辑。
   * 拆分出来以便 pull gate 包裹整个操作。
   */
  private async _callImplInner(
    method: string,
    p: RpcParams,
  ): Promise<RpcResult> {
    // message.pull：V2-only，按需初始化后走 V2 pull
    if (method === 'message.pull') {
      await this._ensureV2SessionReady('message.pull');
      this._clientLog.debug('call route: message.pull → V2 pull');
      const messages = await this._pullV2(Number(p.after_seq ?? 0) || 0, Number(p.limit ?? 50) || 50, { force: p.force === true });
      return { messages } as RpcResult;
    }

    // message.ack：V2-only，按需初始化后走 V2 ack
    if (method === 'message.ack') {
      await this._ensureV2SessionReady('message.ack');
      this._clientLog.debug('call route: message.ack → V2 ack');
      return await this._ackV2(Number(p.seq ?? p.up_to_seq ?? 0) || undefined) as RpcResult;
    }

    // group.pull：V2-only，按需初始化后走 V2 pull
    if (method === 'group.pull' && p.group_id) {
      await this._ensureV2SessionReady('group.pull');
      this._clientLog.debug('call route: group.pull → V2 pull');
      const hasExplicitAfterSeq = 'after_seq' in p || 'after_message_seq' in p;
      const cursorParams = this._explicitGroupCursorParams(p);
      const ownsCursor = Object.keys(cursorParams).length === 0 || this._groupCursorTargetsCurrentInstance(cursorParams);
      const pullOpts: { explicitAfterSeq?: boolean; cursorParams?: RpcParams; ownsCursor?: boolean } = {};
      if (hasExplicitAfterSeq) pullOpts.explicitAfterSeq = true;
      if (Object.keys(cursorParams).length > 0) pullOpts.cursorParams = cursorParams;
      if (!ownsCursor) pullOpts.ownsCursor = false;
      const messages = await this._pullGroupV2(
        String(p.group_id),
        Number(p.after_seq ?? p.after_message_seq ?? 0) || 0,
        Number(p.limit ?? 50) || 50,
        Object.keys(pullOpts).length > 0 ? pullOpts : undefined,
      );
      return { messages } as RpcResult;
    }

    // group.ack_messages：V2-only，按需初始化后走 V2 ack
    if (method === 'group.ack_messages' && p.group_id) {
      await this._ensureV2SessionReady('group.ack_messages');
      this._clientLog.debug('call route: group.ack_messages → V2 ack');
      const cursorParams = this._explicitGroupCursorParams(p);
      const ownsCursor = Object.keys(cursorParams).length === 0 || this._groupCursorTargetsCurrentInstance(cursorParams);
      if (!ownsCursor) {
        return await this._rawGroupAckMessages(p) as RpcResult;
      }
      return await this._ackGroupV2(
        String(p.group_id),
        Number(p.seq ?? p.msg_seq ?? p.up_to_seq ?? 0) || undefined,
      ) as RpcResult;
    }

    // 关键操作自动附加客户端签名
    if (SIGNED_METHODS.has(method)) {
      if (this._shouldSkipClientSignature(method, p)) {
        delete p.client_signature;
      } else {
        await this._signClientOperation(method, p);
      }
    }

    // P1-23: 非幂等方法使用更长超时
    const callTimeout = NON_IDEMPOTENT_METHODS.has(method) ? NON_IDEMPOTENT_TIMEOUT : undefined;
    let result = callTimeout
      ? await this._transport.call(method, p, callTimeout)
      : await this._transport.call(method, p);

    if (method === 'group.thought.get' && isJsonObject(result)) {
      result = await this._decryptGroupThoughts(result);
    }
    if (method === 'message.thought.get' && isJsonObject(result)) {
      result = await this._decryptMessageThoughts(result);
    }

    // V2-only 群状态编排：建群/成员变更后同步 propose+confirm state。
    const membershipMethods = new Set([
      'group.create', 'group.add_member', 'group.kick', 'group.remove_member', 'group.leave',
      'group.review_join_request', 'group.batch_review_join_request',
      'group.use_invite_code', 'group.request_join',
    ]);
    if (membershipMethods.has(method) && isJsonObject(result) && !('error' in result) && this._v2Session) {
      const groupId = this._extractGroupIdFromResult(result) || String(p.group_id ?? '');
      if (groupId) {
        try {
          await this._v2AutoProposeState(groupId);
        } catch (exc) {
          this._clientLog.debug(`V2 post-membership propose failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
        }
        // group.create / group.use_invite_code 成功后注册 group SPK
        if (method === 'group.create' || method === 'group.use_invite_code') {
          const callFn: CallFn = async (m, ps) => this.call(m, ps as RpcParams) as unknown as Record<string, unknown>;
          this._v2Session.ensureGroupRegistered?.(groupId, callFn)?.catch(exc => {
            this._clientLog.debug(`group SPK registration after ${method} failed (non-fatal): group=${groupId} err=${exc}`);
          });
        }
      }
    }

    // message.pull 返回后的 seq 跟踪（V2 路径已在 call() 开头路由，此处为 plaintext pull 的 seq 跟踪）
    if (method === 'message.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      const rawMessages = (Array.isArray(messages) ? messages : []).filter(isJsonObject) as Message[];
      if (this._aid) {
        const ns = `p2p:${this._aid}`;
        if (rawMessages.length) {
          const pullAfterSeq = Number(p.after_seq ?? 0) || 0;
          this._seqTracker.onPullResult(ns, rawMessages, pullAfterSeq);
        }
        // ⚠️ 逻辑边界 L1/L3：P2P retention floor 通道 = server_ack_seq
        const serverAck = Number(r.server_ack_seq ?? 0);
        if (serverAck > 0) {
          const contig = this._seqTracker.getContiguousSeq(ns);
          if (contig < serverAck) {
            this._clientLog.info('message.pull retention-floor advance: ns=' + ns + ' contiguous=' + contig + ' -> server_ack_seq=' + serverAck);
            this._seqTracker.forceContiguousSeq(ns, serverAck);
          }
        }
        this._saveSeqTrackerState();
        // auto-ack 延迟到 publish 完成后（由 _fillP2pGap 负责）
      }
    }

    // group.pull 返回后的 seq 跟踪（V2 路径已在 call() 开头路由，此处为 plaintext pull 的 seq 跟踪）
    if (method === 'group.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      const rawMessages = (Array.isArray(messages) ? messages : []).filter(isJsonObject) as Message[];
      const gid = (p.group_id ?? '') as string;
      if (gid) {
        const ns = `group:${gid}`;
        if (rawMessages.length) {
          const pullAfterSeq = Number(p.after_message_seq ?? p.after_seq ?? 0) || 0;
          this._seqTracker.onPullResult(ns, rawMessages, pullAfterSeq);
        }
        // ⚠️ 逻辑边界 L4：group retention floor 通道 = cursor.current_seq
        const cursor = isJsonObject(r.cursor) ? r.cursor : null;
        if (cursor) {
          const serverAck = Number(cursor.current_seq ?? 0);
          if (serverAck > 0) {
            const contig = this._seqTracker.getContiguousSeq(ns);
            if (contig < serverAck) {
              this._clientLog.info('group.pull retention-floor advance: ns=' + ns + ' contiguous=' + contig + ' -> cursor.current_seq=' + serverAck);
              this._seqTracker.forceContiguousSeq(ns, serverAck);
            }
          }
        }
        this._saveSeqTrackerState();
        // auto-ack 延迟到 publish 完成后（由 _fillGroupGap 负责）
      }
    }

    // ── Group E2EE 自动编排已移除（V2-only：由 group.v2.bootstrap 驱动）────────

    return result;
  }

  private async _callRawV2Rpc(method: string, params?: RpcParams): Promise<RpcResult> {
    const p: RpcParams = { ...(params ?? {}) };
    delete (p as Record<string, unknown>)._pull_gate_locked;
    delete (p as Record<string, unknown>)._skip_auto_ack;
    delete (p as Record<string, unknown>).skip_auto_ack;
    delete (p as Record<string, unknown>)._group_cursor_params;
    if (method.startsWith('group.') && p.group_id !== undefined && p.group_id !== null) {
      p.group_id = normalizeGroupId(String(p.group_id)) || String(p.group_id);
    }
    if (method.startsWith('group.') && p.device_id === undefined) {
      p.device_id = this._deviceId;
    }
    if (method.startsWith('group.') && p.slot_id === undefined) {
      p.slot_id = this._slotId;
    }
    if (SIGNED_METHODS.has(method)) {
      if (this._shouldSkipClientSignature(method, p)) {
        delete p.client_signature;
      } else {
        await this._signClientOperation(method, p);
      }
    }
    return await this._transport.call(method, p);
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

  /** 处理 transport 层推送的原始消息：re-publish 给用户（V2 加密消息走 _raw.peer.v2.message_received） */
  private _onRawMessageReceived(data: EventPayload): void {
    this._clientLog.debug(`_onRawMessageReceived enter: from=${(data as any)?.from ?? '-'} mid=${(data as any)?.message_id ?? '-'} seq=${(data as any)?.seq ?? '-'}`);
    this._safeAsync(this._processAndPublishMessage(data));
    this._clientLog.debug(`_onRawMessageReceived exit: elapsed=0ms (dispatched async)`);
  }

  /** 实际处理推送消息的异步任务（V2-only：明文消息直接透传，V2 加密消息走 _onV2PushNotification） */
  private async _processAndPublishMessage(data: EventPayload): Promise<void> {
    try {
      if (!isJsonObject(data)) {
        await this._publishAppEvent('message.received', data);
        return;
      }
      const msg: Message = { ...data };
      if (!this._messageTargetsCurrentInstance(msg)) {
        return;
      }

      // P2P 空洞检测
      const seq = msg.seq as number | undefined;
      const encryptedPush = isEncryptedPushMessage(msg);
      if (seq !== undefined && seq !== null && this._aid) {
        const ns = `p2p:${this._aid}`;
        // Push 修上界：先更新 maxSeenSeq
        if (seq > 0) this._seqTracker.updateMaxSeen(ns, seq);
        const contigBefore = this._seqTracker.getContiguousSeq(ns);
        const seqNeedsPull = this._seqTracker.onMessageSeq(ns, seq);
        const published = encryptedPush
          ? await this._publishEncryptedPushMessage('message.received', 'message.undecryptable', ns, seq, msg, false)
          : await this._publishOrderedMessage('message.received', ns, seq, msg);
        const contigAfter = this._seqTracker.getContiguousSeq(ns);
        const needPull = seqNeedsPull && !published;
        if (needPull) {
          this._safeAsync(this._fillP2pGap());
        }
        // auto-ack contiguous_seq
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig > 0) {
          const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
          const ackSeq = maxSeen > 0 ? Math.min(contig, maxSeen) : contig;
          this._transport.call('message.ack', {
            seq: ackSeq,
            device_id: this._deviceId,
            slot_id: this._slotId,
          }).catch((e) => { this._clientLog.warn(`P2P auto-ack failed:${String(e)}`) });
        }
        // 即时持久化 cursor，异常断连后不回退
        if (contigAfter !== contigBefore) this._saveSeqTrackerState();
        if (encryptedPush) return;
      } else {
        if (encryptedPush) {
          await this._publishEncryptedPushMessage('message.received', 'message.undecryptable', '', seq ?? 0, msg, false);
          return;
        }
        await this._publishAppEvent('message.received', msg);
      }
    } catch (exc) {
      this._clientLog.warn(`P2P push processing failed:${String(exc)}`)
      if (isJsonObject(data)) {
        const src = data as Record<string, unknown>;
        const safeEvent: { [key: string]: JsonValue } = {
          message_id: (src.message_id ?? null) as JsonValue,
          from: (src.from ?? null) as JsonValue,
          to: (src.to ?? null) as JsonValue,
          seq: (src.seq ?? null) as JsonValue,
          timestamp: (src.timestamp ?? null) as JsonValue,
          _decrypt_error: String(exc),
        };
        attachV2EnvelopeMetadataFromSource(safeEvent, data);
        await this._publishAppEvent('message.undecryptable', safeEvent);
      }
    }
  }

  /** 处理群组消息推送：re-publish（V2 加密消息走 V2 push 路径） */
  private _onRawGroupMessageCreated(data: EventPayload): void {
    this._clientLog.debug(`_onRawGroupMessageCreated enter: group_id=${(data as any)?.group_id ?? '-'} from=${(data as any)?.from ?? '-'} seq=${(data as any)?.seq ?? '-'}`);
    this._safeAsync(this._processAndPublishGroupMessage(data));
    this._clientLog.debug(`_onRawGroupMessageCreated exit: elapsed=0ms (dispatched async)`);
  }

  /** 处理 V2 群消息通知：主动 pull V2 envelope，由 pullGroupV2 解密并发布。 */
  private async _onRawGroupV2MessageCreated(data: EventPayload): Promise<void> {
    const tStart = Date.now();
    if (!isJsonObject(data)) {
      this._clientLog.debug(`_onRawGroupV2MessageCreated skipped: non-object type=${typeof data}`);
      return;
    }

    const groupId = String(data.group_id ?? '').trim();
    const seq = Number(data.seq ?? 0) || 0;
    const messageId = String(data.message_id ?? '').trim();
    const senderAid = String(data.sender_aid ?? '').trim();
    this._clientLog.debug(`_onRawGroupV2MessageCreated group=${groupId} seq=${seq} message_id=${messageId} sender=${senderAid}`);

    if (!groupId || seq <= 0) {
      this._clientLog.debug('_onRawGroupV2MessageCreated skipped: missing group_id or seq');
      return;
    }
    if (!this._v2Session) {
      this._clientLog.debug('_onRawGroupV2MessageCreated skipped: V2 session not initialized');
      return;
    }

    try {
      const ns = `group:${groupId}`;
      // Push 修上界：先更新 maxSeenSeq
      this._seqTracker.updateMaxSeen(ns, seq);
      const contigBefore = this._seqTracker.getContiguousSeq(ns);
      if (contigBefore === seq) {
        this._clientLog.debug(`_onRawGroupV2MessageCreated duplicate push already covered: group=${groupId} seq=${seq}`);
        return;
      }
      const afterSeq = this._repairPushContiguousBound(
        ns,
        seq,
        false,
        '_raw.group.v2.message_created',
      );
      // per-namespace 去重：同一 group namespace 只允许 1 个 in-flight pull
      const dedupKey = `group_pull:${ns}`;
      if (this._gapFillDone.has(dedupKey)) {
        this._clientLog.debug(`_onRawGroupV2MessageCreated skipped: dedupKey=${dedupKey} in flight`);
        return;
      }
      this._gapFillDone.add(dedupKey);
      try {
        this._clientLog.debug(`_onRawGroupV2MessageCreated -> group.v2.pull group=${groupId} after_seq=${afterSeq}`);
        const messages = await this._pullGroupV2(groupId, afterSeq, 50);
        this._clientLog.debug(`_onRawGroupV2MessageCreated pulled ${messages.length} msgs for group=${groupId}`);
      } finally {
        this._gapFillDone.delete(dedupKey);
      }
    } catch (exc) {
      this._clientLog.warn(`_onRawGroupV2MessageCreated pull failed group=${groupId}: ${String(exc)}`);
    } finally {
      this._clientLog.debug(`_onRawGroupV2MessageCreated exit: elapsed=${Date.now() - tStart}ms`);
    }
  }

  /**
   * 处理群组推送消息的异步任务（V2-only：明文消息直接透传）。
   *
   * 带 payload 的事件（消息推送）：直接 re-publish。
   * 不带 payload 的事件（通知）：自动 pull 最新消息。
   */
  private async _processAndPublishGroupMessage(data: EventPayload): Promise<void> {
    try {
      if (!isJsonObject(data)) {
        await this._publishAppEvent('group.message_created', data);
        return;
      }
      const msg: Message = { ...data };
      const groupId = (msg.group_id ?? '') as string;
      const seq = msg.seq as number | undefined;
      const payload = msg.payload;

      // 推送路径收到群消息 → 标记已同步，后续发送无需再 lazySyncGroup
      if (groupId) {
        this._groupSynced.add(groupId);
      }

      if (payload === undefined || payload === null
        || (typeof payload === 'object' && Object.keys(payload as object).length === 0)) {
        // 不带 payload 的通知
        await this._autoPullGroupMessages(msg);
        return;
      }

      // seq 跟踪 + auto-ack
      const encryptedPush = isEncryptedPushMessage(msg);
      if (groupId && seq !== undefined && seq !== null) {
        const ns = `group:${groupId}`;
        // Push 修上界：先更新 maxSeenSeq
        if (seq > 0) this._seqTracker.updateMaxSeen(ns, seq);
        const contigBefore = this._seqTracker.getContiguousSeq(ns);
        const seqNeedsPull = this._seqTracker.onMessageSeq(ns, seq);
        const published = encryptedPush
          ? await this._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', ns, seq, msg, true)
          : await this._publishOrderedMessage('group.message_created', ns, seq, msg);
        const contigAfter = this._seqTracker.getContiguousSeq(ns);
        const needPull = seqNeedsPull && !published;
        if (needPull) {
          this._safeAsync(this._fillGroupGap(groupId));
        }
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig > 0) {
          const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
          const ackSeq = maxSeen > 0 ? Math.min(contig, maxSeen) : contig;
          this._transport.call('group.ack_messages', {
            group_id: groupId,
            msg_seq: ackSeq,
            device_id: this._deviceId,
            slot_id: this._slotId,
          }).catch((e) => { this._clientLog.warn('group message auto-ack failed: group=' + groupId, e); });
        }
        if (contigAfter !== contigBefore) this._saveSeqTrackerState();
        if (encryptedPush) return;
      } else {
        if (encryptedPush) {
          await this._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', '', seq ?? 0, msg, true);
          return;
        }
        await this._publishAppEvent('group.message_created', msg);
      }
    } catch (exc) {
      this._clientLog.warn(`group push processing failed:${String(exc)}`)
      if (isJsonObject(data)) {
        const src = data as Record<string, unknown>;
        const safeEvent: { [key: string]: JsonValue } = {
          message_id: (src.message_id ?? null) as JsonValue,
          group_id: (src.group_id ?? null) as JsonValue,
          from: (src.from ?? null) as JsonValue,
          seq: (src.seq ?? null) as JsonValue,
          timestamp: (src.timestamp ?? null) as JsonValue,
          _decrypt_error: String(exc),
        };
        attachV2EnvelopeMetadataFromSource(safeEvent, data);
        await this._publishAppEvent('group.message_undecryptable', safeEvent);
      }
    }
  }

  private async _decryptEncryptedPushPayload(msg: Record<string, unknown>, group: boolean): Promise<Record<string, unknown> | null> {
    const envelope = encryptedPushEnvelope(msg);
    if (!isV2EncryptedEnvelopePayload(envelope)) return null;
    const aad = isJsonObject(envelope.aad) ? envelope.aad as Record<string, unknown> : {};
    const fromAid = String(msg.from_aid ?? msg.from ?? msg.sender_aid ?? aad.from ?? '').trim();
    const plaintext = await this._decryptV2EnvelopeForThought({ envelope, fromAid });
    if (!plaintext) return null;
    const e2eeMeta = v2E2eeMeta(envelope);
    const result: Record<string, unknown> = {
      message_id: String(msg.message_id ?? ''),
      from: fromAid,
      seq: msg.seq ?? null,
      timestamp: msg.t_server ?? msg.timestamp ?? null,
      payload: plaintext,
      encrypted: true,
      e2ee: e2eeMeta,
    };
    result.direction = fromAid && fromAid === this._aid ? 'outbound_sync' : 'inbound';
    if (msg.t_server !== undefined) result.t_server = msg.t_server;
    if (msg.device_id !== undefined) result.device_id = msg.device_id;
    if (msg.slot_id !== undefined) result.slot_id = msg.slot_id;
    if (group) {
      result.group_id = msg.group_id ?? aad.group_id ?? envelope.group_id ?? null;
    } else {
      result.to = msg.to ?? this._aid ?? '';
    }
    attachV2EnvelopeMetadata(result, e2eeMeta);
    return result;
  }

  private async _publishEncryptedPushAsUndecryptable(
    event: string,
    ns: string,
    seq: unknown,
    msg: Record<string, unknown>,
    group: boolean,
  ): Promise<boolean> {
    const safeEvent = safeUndecryptablePushEvent(msg, group) as EventPayload;
    if (ns) {
      return this._publishOrderedMessage(event, ns, seq, safeEvent);
    }
    await this._publishAppEvent(event, safeEvent);
    return true;
  }

  private async _publishEncryptedPushMessage(
    normalEvent: string,
    undecryptableEvent: string,
    ns: string,
    seq: unknown,
    msg: Record<string, unknown>,
    group: boolean,
  ): Promise<boolean> {
    const decrypted = await this._decryptEncryptedPushPayload(msg, group);
    if (decrypted) {
      if (ns) return this._publishOrderedMessage(normalEvent, ns, seq, decrypted as EventPayload);
      await this._publishAppEvent(normalEvent, decrypted as EventPayload);
      return true;
    }
    return this._publishEncryptedPushAsUndecryptable(undecryptableEvent, ns, seq, msg, group);
  }

  /** 收到不带 payload 的 group.message_created 通知后，自动 pull 最新消息 */
  private async _autoPullGroupMessages(notification: Message): Promise<void> {
    const groupId = (notification.group_id ?? '') as string;
    if (!groupId) {
      await this._publishAppEvent('group.message_created', notification);
      return;
    }
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    try {
      // V2-only 模式：走 group.v2.pull（合并 V1 明文 + V2 密文并自动解密）
      if (this._v2Session) {
        await this._pullGroupV2Internal({ group_id: groupId, after_seq: afterSeq, limit: 50 });
        return;
      }
      const result = await this.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        device_id: this._deviceId,
        limit: 50,
      });
      if (isJsonObject(result)) {
        const messages = result.messages;
        if (Array.isArray(messages)) {
          // ⚠️ 不再重复调用 onPullResult：call('group.pull') 拦截器已在内部调用过一次
          const pushed = this._pushedSeqs.get(ns);
          for (const msg of messages) {
            if (isJsonObject(msg)) {
              const s = (msg as Record<string, unknown>).seq as number | undefined;
              if (pushed && s !== undefined && s !== null && pushed.has(s)) {
                continue; // 已发布到应用层，跳过
              }
              if (s !== undefined && s !== null) {
                await this._publishPulledMessage('group.message_created', ns, s, msg);
              } else {
                await this._publishAppEvent('group.message_created', msg);
              }
            }
          }
          this._prunePushedSeqs(ns);
          return;
        }
      }
    } catch (exc) {
      this._clientLog.warn(`auto pull group message failed:${String(exc)}`)
    }
    // pull 失败时仍透传原始通知
    await this._publishAppEvent('group.message_created', notification);
  }

  /** 后台补齐群消息空洞 */
  private async _fillGroupGap(groupId: string): Promise<void> {
    // 状态保护：非 connected 或正在关闭时跳过（与 Python 对齐）
    if (this._state !== 'connected' || this._closing) return;
    groupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!groupId) return;
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // per-namespace 去重：同一 group namespace 只允许 1 个 in-flight pull
    const dedupKey = `group_pull:${ns}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.add(dedupKey);
    this._gapFillActive = true;
    let filled = 0;
    try {
      const messages = await this._pullGroupV2(groupId, afterSeq, 50);
      filled = messages.length;
      this._prunePushedSeqs(ns);
    } catch (exc) {
      this._clientLog.warn(`group message gap-fill failed:${String(exc)}`)
    } finally {
      // S1: 成功 / 失败路径都必须清理飞行标记
      this._gapFillDone.delete(dedupKey);
      this._gapFillActive = false;
      if (filled > 0 && this._seqTracker.getContiguousSeq(ns) > afterSeq) {
        this._safeAsync(this._fillGroupGap(groupId));
      }
    }
  }

  /** 后台补齐群事件空洞 */
  private async _fillGroupEventGap(groupId: string): Promise<void> {
    // 状态保护：非 connected 或正在关闭时跳过（与 Python 对齐）
    if (this._state !== 'connected' || this._closing) return;
    const ns = `group_event:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // per-namespace 去重：同一 group_event namespace 只允许 1 个 in-flight pull
    const dedupKey = `group_event_pull:${ns}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.add(dedupKey);
    this._gapFillActive = true;
    try {
      let nextAfterSeq = afterSeq;
      const maxPages = 100;
      let pageCount = 0;
      while (pageCount < maxPages) {
        pageCount += 1;
        const result = await this.call('group.pull_events', {
          group_id: groupId,
          after_event_seq: nextAfterSeq,
          device_id: this._deviceId,
          limit: 50,
        });
        if (!isJsonObject(result)) return;
        const events = result.events;
        if (!Array.isArray(events)) return;
        const pageContigBefore = this._seqTracker.getContiguousSeq(ns);
        const eventObjects = events.filter(isJsonObject);
        if (eventObjects.length > 0) {
          this._seqTracker.onPullResult(ns, eventObjects, nextAfterSeq);
        }
        const cursor = isJsonObject(result.cursor) ? result.cursor : null;
        const serverAck = cursor ? Number(cursor.current_seq ?? 0) : 0;
        if (serverAck > 0) {
          const contigBeforeFloor = this._seqTracker.getContiguousSeq(ns);
          if (contigBeforeFloor < serverAck) {
            this._clientLog.info('group.pull_events retention-floor advance: ns=' + ns + ' contiguous=' + contigBeforeFloor + ' -> cursor.current_seq=' + serverAck);
            this._seqTracker.forceContiguousSeq(ns, serverAck);
          }
        }
        const eventSeqs: number[] = [];
        for (const evt of eventObjects) {
          const eventSeq = Number(evt.event_seq ?? 0);
          if (Number.isFinite(eventSeq) && eventSeq > 0) eventSeqs.push(eventSeq);
          evt._from_gap_fill = true;
          const et = String(evt.event_type ?? '');
          // 消息事件由 _fillGroupGap 负责，事件补洞不重复投递
          if (et === 'group.message_created') continue;
          // 验签：有 client_signature 就验（与实时事件路径对齐）
          const cs = evt.client_signature;
          if (cs && typeof cs === 'object') {
            if (this._shouldSkipEventSignature(evt)) {
              delete evt.client_signature;
            } else {
              evt._verified = await this._verifyEventSignature(evt, cs as JsonObject);
            }
          }
          // group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
          await this._dispatcher.publish('group.changed', evt);
        }
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig !== pageContigBefore) {
          this._saveSeqTrackerState();
        }
        if (eventObjects.length > 0 && contig > 0 && contig !== pageContigBefore) {
          const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
          const ackSeq = maxSeen > 0 ? Math.min(contig, maxSeen) : contig;
          this._transport.call('group.ack_events', {
            group_id: groupId,
            event_seq: ackSeq,
            device_id: this._deviceId,
            slot_id: this._slotId,
          }).catch((e) => { this._clientLog.warn('group event auto-ack failed: group=' + groupId, e); });
        }
        const nextAfter = Math.max(eventSeqs.length > 0 ? Math.max(...eventSeqs) : nextAfterSeq, nextAfterSeq);
        if (eventObjects.length === 0 || nextAfter <= nextAfterSeq || result.has_more === false) break;
        nextAfterSeq = nextAfter;
      }
      if (pageCount >= maxPages) {
        this._clientLog.warn(`group event gap fill reached max_pages=${maxPages} group=${groupId} after_seq=${nextAfterSeq}`);
      }
    } catch (exc) {
      this._clientLog.warn(`group event gap-fill failed:${String(exc)}`)
    } finally {
      // S1: 成功 / 失败路径都必须清理飞行标记
      this._gapFillDone.delete(dedupKey);
      this._gapFillActive = false;
    }
  }

  /** 后台补齐 P2P 消息空洞 */
  private async _fillP2pGap(): Promise<void> {
    // 状态保护：非 connected 或正在关闭时跳过（与 Python 对齐）
    if (this._state !== 'connected' || this._closing) return;
    if (!this._aid) return;
    const ns = `p2p:${this._aid}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // per-namespace 去重：同一 namespace 只允许 1 个 in-flight pull
    const dedupKey = `p2p_pull:${ns}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.add(dedupKey);
    this._gapFillActive = true;
    let filled = 0;
    try {
      const messages = await this._pullV2(afterSeq, 50);
      filled = messages.length;
      this._prunePushedSeqs(ns);
    } catch (exc) {
      this._clientLog.warn(`P2P message gap-fill failed:${String(exc)}`)
    } finally {
      // S1: 成功 / 失败路径都必须清理飞行标记
      this._gapFillDone.delete(dedupKey);
      this._gapFillActive = false;
      if (filled > 0 && this._seqTracker.getContiguousSeq(ns) > afterSeq) {
        this._safeAsync(this._fillP2pGap());
      }
    }
  }

  /** 只按硬上限裁剪 published guard，不能按 contiguousSeq 清理。 */
  private _prunePushedSeqs(ns: string): void {
    const pushed = this._pushedSeqs.get(ns);
    if (!pushed) return;
    if (pushed.size > PUSHED_SEQS_LIMIT) {
      const keep = [...pushed].sort((a, b) => a - b).slice(-PUSHED_SEQS_LIMIT);
      this._pushedSeqs.set(ns, new Set(keep));
    }
  }

  private _markPublishedSeq(ns: string, seq: number): void {
    let pushed = this._pushedSeqs.get(ns);
    if (!pushed) {
      pushed = new Set<number>();
      this._pushedSeqs.set(ns, pushed);
    }
    pushed.add(seq);
    if (pushed.size > PUSHED_SEQS_LIMIT) {
      const keep = [...pushed].sort((a, b) => a - b).slice(-PUSHED_SEQS_LIMIT);
      this._pushedSeqs.set(ns, new Set(keep));
    }
  }

  private _enqueueOrderedMessage(ns: string, event: string, seq: number, payload: EventPayload): void {
    let queue = this._pendingOrderedMsgs.get(ns);
    if (!queue) {
      queue = new Map();
      this._pendingOrderedMsgs.set(ns, queue);
    }
    queue.set(seq, { event, payload });
    if (queue.size > PENDING_ORDERED_LIMIT) {
      const drop = [...queue.keys()].sort((a, b) => a - b).slice(0, queue.size - PENDING_ORDERED_LIMIT);
      for (const oldSeq of drop) queue.delete(oldSeq);
    }
  }

  private _isInstanceScopedMessageEvent(event: string): boolean {
    return event === 'message.received'
      || event === 'message.undecryptable'
      || event === 'group.message_created'
      || event === 'group.message_undecryptable';
  }

  private _attachCurrentInstanceContext(payload: EventPayload): EventPayload {
    if (!isJsonObject(payload)) return payload;
    const result: JsonObject = { ...payload };
    if (!('device_id' in result)) {
      result.device_id = this._deviceId;
    }
    if (!('slot_id' in result)) {
      result.slot_id = this._slotId;
    }
    return result;
  }

  private _normalizePublishedMessagePayload(event: string, payload: EventPayload): EventPayload {
    if (!this._isInstanceScopedMessageEvent(event)) return payload;
    return this._attachCurrentInstanceContext(payload);
  }

  private async _publishAppEvent(event: string, payload: EventPayload): Promise<void> {
    if ((event === 'message.received' || event === 'group.message_created') && isJsonObject(payload)) {
      this._maybeAppendEchoTraceReceive(payload as Record<string, unknown>);
    }
    // 注入本地/远端 agent.md etag，让应用层判断版本一致性；失败不影响业务。
    if (isJsonObject(payload)) {
      try {
        const localEtag = this._localAgentMdEtag || '';
        const remoteEtag = this._remoteAgentMdEtag || '';
        if ((localEtag || remoteEtag) && (payload as Record<string, unknown>)._agent_md === undefined) {
          (payload as Record<string, unknown>)._agent_md = {
            local_etag: localEtag,
            remote_etag: remoteEtag,
          };
        }
      } catch (exc) {
        this._clientLog.debug(`agent_md etag inject skipped: ${String(exc)}`);
      }
    }
    await this._dispatcher.publish(event, this._normalizePublishedMessagePayload(event, payload));
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

  private _shouldSkipClientSignature(method: string, params: RpcParams): boolean {
    if (method !== 'message.send' && method !== 'group.send') return false;
    if (params.encrypted || params.encrypt) return false;
    return this._isEchoPayload(params.payload);
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

  private _messageTargetsCurrentInstance(message: EventPayload): boolean {
    if (!isJsonObject(message)) return true;
    if ('device_id' in message) {
      const targetDeviceId = String(message.device_id ?? '').trim();
      if (targetDeviceId !== this._deviceId) {
        return false;
      }
    }
    if ('slot_id' in message) {
      const targetSlotId = String(message.slot_id ?? '').trim();
      if (slotIsolationKey(targetSlotId) !== slotIsolationKey(this._slotId)) {
        return false;
      }
    }
    return true;
  }

  private async _drainOrderedMessages(ns: string, beforeSeq?: number): Promise<void> {
    const queue = this._pendingOrderedMsgs.get(ns);
    if (!queue || queue.size === 0) return;
    const contig = this._seqTracker.getContiguousSeq(ns);
    const ready = [...queue.keys()]
      .filter((seq) => seq <= contig && (beforeSeq === undefined || seq < beforeSeq))
      .sort((a, b) => a - b);
    for (const seq of ready) {
      const item = queue.get(seq);
      queue.delete(seq);
      if (!item || this._pushedSeqs.get(ns)?.has(seq)) continue;
      await this._publishAppEvent(item.event, item.payload);
      this._markPublishedSeq(ns, seq);
    }
    if (queue.size === 0) this._pendingOrderedMsgs.delete(ns);
  }

  private async _publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) {
      await this._publishAppEvent(event, payload);
      return true;
    }
    if (this._pushedSeqs.get(ns)?.has(seqNum)) {
      const queue = this._pendingOrderedMsgs.get(ns);
      queue?.delete(seqNum);
      if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
      return false;
    }

    const contig = this._seqTracker.getContiguousSeq(ns);
    if (seqNum > contig) {
      this._enqueueOrderedMessage(ns, event, seqNum, payload);
      return false;
    }

    await this._drainOrderedMessages(ns, seqNum);
    if (this._pushedSeqs.get(ns)?.has(seqNum)) return false;
    const queue = this._pendingOrderedMsgs.get(ns);
    queue?.delete(seqNum);
    if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
    await this._publishAppEvent(event, payload);
    this._markPublishedSeq(ns, seqNum);
    await this._drainOrderedMessages(ns);
    return true;
  }

  private async _publishPulledMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0 || !ns) {
      await this._publishAppEvent(event, payload);
      return true;
    }
    const queue = this._pendingOrderedMsgs.get(ns);
    if (this._pushedSeqs.get(ns)?.has(seqNum)) {
      queue?.delete(seqNum);
      if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
      return false;
    }
    queue?.delete(seqNum);
    if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
    await this._publishAppEvent(event, payload);
    this._markPublishedSeq(ns, seqNum);
    return true;
  }

  private _extractGroupIdFromResult(result: JsonObject): string {
    const group = isJsonObject(result.group) ? result.group : null;
    const gid = group ? String(group.group_id ?? '') : '';
    if (gid) return gid;
    const directGid = String(result.group_id ?? '');
    if (directGid) return directGid;
    const member = isJsonObject(result.member) ? result.member : null;
    return member ? String(member.group_id ?? '') : '';
  }

  private async _onRawGroupChanged(data: EventPayload): Promise<void> {
    const tStart = Date.now();
    const action = String((data as any)?.action ?? '');
    const groupIdInit = String((data as any)?.group_id ?? '');
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
            d._verified = await this._verifyEventSignature(d, cs);
          }
        }
        await this._dispatcher.publish('group.changed', d);

        const groupId = (d.group_id ?? '') as string;

        // V2 bootstrap 缓存失效：成员变更可能导致 epoch 递增或设备列表变化
        if (groupId) {
          this._v2BootstrapCache.delete(`group:${groupId}`);
        }

        // Group SPK 编排：成员变更触发注册/轮换
        const membershipActions = new Set([
          'member_added', 'member_left', 'member_removed', 'role_changed',
          'owner_transferred', 'joined', 'join_approved', 'invite_code_used',
        ]);
        if (this._v2Session && groupId) {
          if (membershipActions.has(action)) {
            const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
            const joinedAid = String(d.joined_aid ?? d.member_aid ?? d.aid ?? '').trim();
            const actorAid = String(d.actor_aid ?? '').trim();
            const selfAid = String(this._aid ?? '').trim();
            const joinActions = new Set(['member_added', 'joined', 'join_approved', 'invite_code_used']);
            const isSelfJoin = joinActions.has(action) && !!selfAid && (
              joinedAid === selfAid ||
              (!joinedAid && (action === 'joined' || action === 'invite_code_used') && actorAid === selfAid)
            );
            if (isSelfJoin) {
              this._v2Session.ensureGroupRegistered?.(groupId, callFn)?.catch(exc => {
                this._clientLog.debug(`group SPK registration failed (non-fatal): group=${groupId} action=${action} err=${exc}`);
              });
            } else {
              this._v2Session.rotateGroupSPK?.(groupId, callFn)?.catch(exc => {
                this._clientLog.debug(`group SPK rotation failed (non-fatal): group=${groupId} action=${action} err=${exc}`);
              });
            }
          }
        }

        if (groupId && this._v2Session && (action === 'upsert' || membershipActions.has(action))) {
          this._safeAsync(this._v2AutoProposeState(groupId, { leaderDelay: true }));
        }

        // event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq。
        let needPull = false;
        const rawEventSeq = d.event_seq;
        if (rawEventSeq != null && groupId) {
          const es = Number(rawEventSeq);
          if (Number.isFinite(es) && es > 0) {
            needPull = this._seqTracker.onMessageSeq(`group_event:${groupId}`, es);
          }
        }

        // 仅在真实 event gap 时才触发补拉（补洞回来的事件不再触发新补洞）
        if (needPull && groupId && !d._from_gap_fill) {
          this._safeAsync(this._fillGroupEventGap(groupId));
        }

        // 群组解散 → 清理本地 seq_tracker、补洞去重缓存
        if (d.action === 'dissolved') {
          if (groupId) {
            this._cleanupDissolvedGroup(groupId);
          }
        }
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
    const tStart = Date.now();
    const groupIdInit = String((data as any)?.group_id ?? '');
    this._clientLog.debug(`_onGroupStateCommitted enter: group_id=${groupIdInit} state_version=${String((data as any)?.state_version ?? '-')}`);
    try {
      if (!isJsonObject(data)) {
        this._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms reason=non_object`);
        return;
      }
      const d = data;
      const groupId = String(d.group_id ?? '').trim();
      if (!groupId) {
        this._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms reason=no_group_id`);
        return;
      }
      await this._onGroupStateCommittedImpl(d, groupId);
      this._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms group_id=${groupId}`);
    } catch (err) {
      this._clientLog.debug(`_onGroupStateCommitted exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async _onGroupStateCommittedImpl(d: JsonObject, groupId: string): Promise<void> {

    // 提交者签名验证
    const cs = d.client_signature;
    if (cs && isJsonObject(cs)) {
      if (this._shouldSkipEventSignature(d)) {
        delete d.client_signature;
      } else {
        const verified = await this._verifyEventSignature(d, cs);
        if (verified === false) {
          this._clientLog.warn(`state_committed committer signature verify failed group=%s${String(groupId)}`)
          return;
        }
        d._verified = verified;
      }
    }

    const stateVersion = Number(d.state_version ?? 0);
    const stateHash = String(d.state_hash ?? '').trim();
    const prevStateHash = String(d.prev_state_hash ?? '').trim();
    const keyEpoch = Number(d.key_epoch ?? 0);
    const membershipSnapshot = String(d.membership_snapshot ?? '').trim();
    const policySnapshot = String(d.policy_snapshot ?? '').trim();

    // 1. 验证 prev_state_hash 连续性
    const loadFn = (this._keystore as any).loadGroupState;
    const localState: GroupStateRecord | null = loadFn
      ? await loadFn.call(this._keystore, groupId)
      : null;

    if (localState && localState.state_hash && localState.state_hash !== prevStateHash) {
      this._clientLog.warn(
        '[aun_core] state_hash 链不连续 group=%s local_sv=%d event_sv=%d',
        groupId, localState.state_version, stateVersion,
      );
      // 回源同步
      try {
        const serverState = await this._transport.call('group.get_state', { group_id: groupId });
        if (serverState && typeof (serverState as any).state_version !== 'undefined') {
          const sv = Number((serverState as any).state_version);
          const sHash = String((serverState as any).state_hash ?? '');
          const sEpoch = Number((serverState as any).key_epoch ?? 0);
          const sMembersJson = String((serverState as any).membership_snapshot ?? '');
          const sPolicyJson = String((serverState as any).policy_snapshot ?? '');
          const sPrev = String((serverState as any).prev_state_hash ?? '');

          // 回源也做 hash 验证
          if (sMembersJson && sHash) {
            const sMembers: Array<{ aid: string; role: string }> = sMembersJson ? JSON.parse(sMembersJson) : [];
            const sPolicy: Record<string, unknown> = sPolicyJson ? JSON.parse(sPolicyJson) : {};
            const computed = await computeStateHash({
              groupId, stateVersion: sv, keyEpoch: sEpoch,
              members: sMembers, policy: sPolicy, prevStateHash: sPrev,
            });
            if (computed !== sHash) {
              this._clientLog.warn(
                '[aun_core] 回源 state_hash 验证失败 group=%s sv=%d expected=%s got=%s',
                groupId, sv, sHash, computed,
              );
              return;
            }
          }

          const saveFn = (this._keystore as any).saveGroupState;
          if (saveFn) {
            await saveFn.call(this._keystore, groupId, {
              group_id: groupId,
              state_version: sv,
              state_hash: sHash,
              key_epoch: sEpoch,
              membership_json: sMembersJson || membershipSnapshot,
              policy_json: sPolicyJson || policySnapshot,
              updated_at: Date.now(),
            } as GroupStateRecord);
          }
        }
      } catch (exc) {
        this._clientLog.warn(`state pull-back failed group=%s:${groupId} ${exc}`)
      }
      return;
    }

    // 2. 本地重算验证
    const members: Array<{ aid: string; role: string }> = membershipSnapshot ? JSON.parse(membershipSnapshot) : [];
    const policy: Record<string, unknown> = policySnapshot ? JSON.parse(policySnapshot) : {};
    const computed = await computeStateHash({
      groupId, stateVersion, keyEpoch,
      members, policy, prevStateHash,
    });
    if (computed !== stateHash) {
      this._clientLog.warn(
        '[aun_core] state_hash 重算不匹配 group=%s sv=%d expected=%s got=%s',
        groupId, stateVersion, stateHash, computed,
      );
      return;
    }

    // 3. 更新本地存储
    const saveFn = (this._keystore as any).saveGroupState;
    if (saveFn) {
      await saveFn.call(this._keystore, groupId, {
        group_id: groupId,
        state_version: stateVersion,
        state_hash: stateHash,
        key_epoch: keyEpoch,
        membership_json: membershipSnapshot,
        policy_json: policySnapshot,
        updated_at: Date.now(),
      } as GroupStateRecord);
    }
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
    this._v2BootstrapCache.delete(`group:${groupId}`);
    this._v2GroupSecurityLevels.delete(groupId);
    this._v2StateChains.delete(groupId);
    this._seqTracker.removeNamespace(`group:${groupId}`);
    this._seqTracker.removeNamespace(`group_event:${groupId}`);
    this._saveSeqTrackerState();

    // 2. 清理补洞去重缓存中的相关条目
    for (const key of this._gapFillDone.keys()) {
      if (key.includes(groupId)) {
        this._gapFillDone.delete(key);
      }
    }

    // 3. 清理推送 seq 去重缓存
    this._pushedSeqs.delete(`group:${groupId}`);
    this._pushedSeqs.delete(`group_event:${groupId}`);
    this._pendingOrderedMsgs.delete(`group:${groupId}`);

    this._clientLog.info(`cleanup dissolved group ${groupId}  local state`);
  }

  private async _verifyEventSignature(_event: JsonObject, cs: JsonObject): Promise<string | boolean> {
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
        const actualFP = await certificateSha256Fingerprint(cached.certPem);
        if (actualFP !== expectedFP) {
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

  /**
   * 从 X.509 DER 证书中提取 SubjectPublicKeyInfo 并计算其 SHA-256 指纹。
   * 返回 "sha256:<hex>"，提取失败返回空串。
   * 用于 H7 指纹校验（DER 证书指纹 OR SPKI 指纹任一匹配）。
   */
  private async _spkiFingerprint(certPem: string): Promise<string> {
    try {
      const der = new Uint8Array(pemToArrayBuffer(certPem));
      // X.509: Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
      // tbsCertificate ::= SEQUENCE { version?, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
      // 逐级解析 SEQUENCE 并定位 SPKI (第 7 个或第 6 个子元素，取决于 version 是否 [0] explicit)。
      const readLen = (buf: Uint8Array, pos: number): { len: number; next: number } => {
        const first = buf[pos];
        if (first < 0x80) return { len: first, next: pos + 1 };
        const n = first & 0x7f;
        let len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | buf[pos + 1 + i];
        return { len, next: pos + 1 + n };
      };
      // 外层 SEQUENCE
      if (der[0] !== 0x30) return '';
      const outer = readLen(der, 1);
      // tbsCertificate SEQUENCE 起点
      const tbsStart = outer.next;
      if (der[tbsStart] !== 0x30) return '';
      const tbsLen = readLen(der, tbsStart + 1);
      let p = tbsLen.next;
      const tbsEnd = tbsLen.next + tbsLen.len;
      // 跳过 [0] EXPLICIT Version（可选）
      if (der[p] === 0xa0) {
        const lv = readLen(der, p + 1);
        p = lv.next + lv.len;
      }
      // 跳过 serialNumber (INTEGER)
      if (der[p] !== 0x02) return '';
      let lv = readLen(der, p + 1);
      p = lv.next + lv.len;
      // 跳过 signature (SEQUENCE)
      if (der[p] !== 0x30) return '';
      lv = readLen(der, p + 1);
      p = lv.next + lv.len;
      // 跳过 issuer (SEQUENCE)
      if (der[p] !== 0x30) return '';
      lv = readLen(der, p + 1);
      p = lv.next + lv.len;
      // 跳过 validity (SEQUENCE)
      if (der[p] !== 0x30) return '';
      lv = readLen(der, p + 1);
      p = lv.next + lv.len;
      // 跳过 subject (SEQUENCE)
      if (der[p] !== 0x30) return '';
      lv = readLen(der, p + 1);
      p = lv.next + lv.len;
      // subjectPublicKeyInfo (SEQUENCE) — 连同 tag+length+value 全部即 SPKI DER
      if (der[p] !== 0x30 || p >= tbsEnd) return '';
      const spkiStart = p;
      const spkiLV = readLen(der, p + 1);
      const spkiEnd = spkiLV.next + spkiLV.len;
      const spkiDer = der.subarray(spkiStart, spkiEnd);
      const digest = await crypto.subtle.digest('SHA-256', spkiDer);
      return 'sha256:' + Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    } catch {
      return '';
    }
  }

  private async _decryptGroupThoughts(result: JsonObject): Promise<JsonObject> {
    if (!result.found) {
      return { ...result, thoughts: [] };
    }
    const items = (Array.isArray(result.thoughts) ? result.thoughts : []).filter(isJsonObject);
    if (!items.length) {
      return { ...result, thoughts: [] };
    }
    const groupId = String(result.group_id ?? '');
    const senderAid = String(result.sender_aid ?? '');
    const thoughts = [];
    for (const item of items) {
      const payload = isJsonObject(item.payload) ? item.payload : null;
      const thoughtId = String(item.thought_id ?? item.message_id ?? '');
      // V2 群 thought envelope：per-device wrap
      const isV2Envelope = payload !== null
        && payload.type === 'e2ee.group_encrypted'
        && (payload.version === 'v2' || Array.isArray(payload.recipients));
      let decryptedPayload: unknown = payload;
      let e2eeMeta: unknown = null;
      let decryptFailed = false;
      if (isV2Envelope) {
        e2eeMeta = v2E2eeMeta(payload as Record<string, unknown>);
        const plaintext = await this._decryptV2EnvelopeForThought({
          envelope: payload as Record<string, unknown>,
          fromAid: senderAid,
        });
        if (plaintext === null) {
          this._clientLog.warn(`group.thought.decrypt v2 failed thought_id=${thoughtId}`);
          decryptFailed = true;
          decryptedPayload = payload;
        } else {
          decryptedPayload = plaintext;
          const e2eeObj = e2eeMeta as Record<string, unknown>;
          // 暴露 protected_headers（去 _auth）
          const ph = (payload as JsonObject).protected_headers;
          if (isJsonObject(ph)) {
            const phBody: Record<string, unknown> = {};
            for (const [k, v] of Object.entries(ph)) { if (k !== '_auth') phBody[k] = v; }
            if (Object.keys(phBody).length > 0) e2eeObj.protected_headers = phBody;
          }
          // 暴露 context（去 _auth）
          const ctx = (payload as JsonObject).context;
          if (isJsonObject(ctx)) {
            const ctxBody: Record<string, unknown> = {};
            for (const [k, v] of Object.entries(ctx)) { if (k !== '_auth') ctxBody[k] = v; }
            if (Object.keys(ctxBody).length > 0) e2eeObj.context = ctxBody;
          }
          e2eeMeta = e2eeObj;
        }
      } else if (payload?.type === 'e2ee.group_encrypted') {
        decryptFailed = true;
        decryptedPayload = payload;
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        payload: decryptedPayload as JsonValue,
        created_at: item.created_at,
        e2ee: e2eeMeta as JsonValue,
      };
      if (isJsonObject(e2eeMeta)) attachV2EnvelopeMetadata(thought, e2eeMeta);
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      thoughts.push(thought);
    }
    return { ...result, thoughts };
  }

  private async _decryptMessageThoughts(result: JsonObject): Promise<JsonObject> {
    if (!result.found) {
      return { ...result, thoughts: [] };
    }
    const items = (Array.isArray(result.thoughts) ? result.thoughts : []).filter(isJsonObject);
    if (!items.length) {
      return { ...result, thoughts: [] };
    }
    const senderAid = String(result.sender_aid ?? '');
    const peerAid = String(result.peer_aid ?? '');
    const thoughts = [];
    for (const item of items) {
      const payload = isJsonObject(item.payload) ? item.payload : null;
      const thoughtId = String(item.thought_id ?? item.message_id ?? '');
      const fromAid = String(item.from ?? senderAid);
      const toAid = String(item.to ?? peerAid);
      const message = {
        from: fromAid,
        to: toAid,
        message_id: thoughtId,
        payload: payload ?? {},
        encrypted: item.encrypted !== false,
        timestamp: Number(item.created_at ?? 0),
      } as Message;
      if (isJsonObject(item.context)) message.context = item.context;
      let decrypted: Message | null = message;
      let decryptFailed = false;
      // V2 P2P thought envelope：per-device wrap，本设备解密自己的 row
      if (payload?.type === 'e2ee.p2p_encrypted') {
        const e2eeObj = v2E2eeMeta(payload as Record<string, unknown>);
        message.e2ee = e2eeObj as JsonObject;
        const plaintext = await this._decryptV2EnvelopeForThought({
          envelope: payload as Record<string, unknown>,
          fromAid,
        });
        if (plaintext === null) {
          this._clientLog.warn(`p2p.thought.decrypt v2 failed thought_id=${thoughtId}`);
          decryptFailed = true;
        } else {
          decrypted = { ...message };
          decrypted.payload = plaintext as JsonObject;
          // 暴露 protected_headers（去 _auth）
          const ph = (payload as JsonObject).protected_headers;
          if (isJsonObject(ph)) {
            const phBody: Record<string, unknown> = {};
            for (const [k, v] of Object.entries(ph)) { if (k !== '_auth') phBody[k] = v; }
            if (Object.keys(phBody).length > 0) e2eeObj.protected_headers = phBody;
          }
          // 暴露 context（去 _auth）
          const ctx = (payload as JsonObject).context;
          if (isJsonObject(ctx)) {
            const ctxBody: Record<string, unknown> = {};
            for (const [k, v] of Object.entries(ctx)) { if (k !== '_auth') ctxBody[k] = v; }
            if (Object.keys(ctxBody).length > 0) e2eeObj.context = ctxBody;
          }
          decrypted.e2ee = e2eeObj as JsonObject;
        }
      } else if (payload?.type === 'e2ee.encrypted') {
        decryptFailed = true;
      }
      const exposedE2ee = (decrypted ?? message).e2ee;
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        from: fromAid,
        to: toAid,
        payload: (decrypted ?? message).payload,
        created_at: item.created_at,
        e2ee: exposedE2ee,
      };
      if (isJsonObject(exposedE2ee)) attachV2EnvelopeMetadata(thought, exposedE2ee);
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      thoughts.push(thought);
    }
    return { ...result, thoughts };
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
      try {
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
      } catch (exc) {
        if (!certFingerprint) {
          throw exc;
        }
        // 兼容旧浏览器，不使用 AbortSignal.timeout（Chrome 103+ 才支持）
        const fallbackController = new AbortController();
        const fallbackTimeoutId = setTimeout(() => fallbackController.abort(), timeoutMs);
        try {
          const fallbackResp = await fetch(buildCertUrl(peerGatewayUrl, aid), { signal: fallbackController.signal });
          if (!fallbackResp.ok) {
            throw exc;
          }
          certPem = await fallbackResp.text();
        } finally {
          clearTimeout(fallbackTimeoutId);
        }
      }

      // H7: 严格校验指纹（DER SHA-256 或 SPKI SHA-256 任一匹配即可）
      if (certFingerprint) {
        const expectedFP = String(certFingerprint).trim().toLowerCase();
        if (!expectedFP.startsWith('sha256:')) {
          throw new ValidationError(
            `unsupported cert_fingerprint format for ${aid}: ${expectedFP.slice(0, 24)}`,
          );
        }
        const derFP = await this._certFingerprint(certPem);
        if (derFP !== expectedFP) {
          const spkiFP = await this._spkiFingerprint(certPem);
          if (!spkiFP || spkiFP !== expectedFP) {
            throw new ValidationError(
              `peer cert fingerprint mismatch for ${aid}: expected=${expectedFP.slice(0, 24)}...`,
            );
          }
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
        await this._keystore.saveCert(aid, certPem, certFingerprint, { makeActive: false });
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

  /** 确保发送方证书在本地可用且未过期 */
  private async _ensureSenderCertCached(aid: string, certFingerprint?: string): Promise<boolean> {
    const cacheKey = certCacheKey(aid, certFingerprint);
    const cached = this._certCache.get(cacheKey);
    const now = Date.now() / 1000;
    if (cached && now < cached.refreshAfter) return true;
    const localCert = await this._keystore.loadCert(aid, certFingerprint);
    if (localCert) {
      if (certFingerprint) {
        const actualFingerprint = await this._certFingerprint(localCert);
        if (actualFingerprint === String(certFingerprint).trim().toLowerCase()) {
          this._certCache.set(cacheKey, {
            certPem: localCert,
            validatedAt: now,
            refreshAfter: now + PEER_CERT_CACHE_TTL,
          });
          return true;
        }
      } else {
        this._certCache.set(cacheKey, {
          certPem: localCert,
          validatedAt: now,
          refreshAfter: now + PEER_CERT_CACHE_TTL,
        });
        return true;
      }
    }
    try {
      const certPem = await this._fetchPeerCert(aid, certFingerprint);
      // peer 证书只存版本目录，不覆盖 cert.pem
      await this._keystore.saveCert(aid, certPem, certFingerprint, { makeActive: false });
      return true;
    } catch (exc) {
      // 刷新失败时：若缓存有 PKI 验证过的证书（2 倍 TTL 内）则继续用
      if (cached && now < cached.validatedAt + PEER_CERT_CACHE_TTL * 2) {
        this._clientLog.warn(`refresh sender ${aid} cert failed, continue using verified memory cache: ${String(exc)}`)
        return true;
      }
      this._clientLog.warn(`fetch sender ${aid} cert failed and no verify cache, reject trust: ${String(exc)}`)
      return false;
    }
  }

  /**
   * 获取经过 PKI 验证的 peer 证书（仅信任内存缓存中已验证的证书）。
   * 零信任要求：不直接信任 keystore 中可能由恶意服务端注入的证书。
   */
  private _getVerifiedPeerCert(aid: string, certFingerprint?: string): string | null {
    let cached = this._certCache.get(certCacheKey(aid, certFingerprint));
    // 带 fingerprint 查不到时，降级用 aid 再查一次
    if (!cached && certFingerprint) {
      cached = this._certCache.get(certCacheKey(aid, undefined));
    }
    const now = Date.now() / 1000;
    if (cached && now < cached.validatedAt + PEER_CERT_CACHE_TTL * 2) {
      return cached.certPem;
    }
    return null;
  }

  // ── 客户端操作签名 ────────────────────────────────

  /**
   * 为关键操作附加客户端 ECDSA 签名（_client_signature 字段）。
   * 使用 SubtleCrypto 异步签名。
   */
  private async _signClientOperation(method: string, params: RpcParams): Promise<void> {
    const currentAid = this._currentAid;
    if (!currentAid?.privateKeyPem) return;

    try {
      const aid = currentAid.aid;
      const ts = String(Math.floor(Date.now() / 1000));

      // 计算 params hash：覆盖所有非 _ 前缀且非 client_signature 的业务字段
      const paramsForHash: RpcParams = {};
      for (const [k, v] of Object.entries(params)) {
        if (k !== 'client_signature' && !k.startsWith('_')) {
          paramsForHash[k] = v;
        }
      }
      const paramsJson = stableStringify(paramsForHash);

      // SHA-256 hash
      const paramsHashBuf = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(paramsJson),
      );
      const paramsHash = Array.from(new Uint8Array(paramsHashBuf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      const signData = new TextEncoder().encode(`${method}|${aid}|${ts}|${paramsHash}`);

      // 导入私钥并签名
      const pkcs8 = pemToArrayBuffer(currentAid.privateKeyPem);
      const cryptoKey = await crypto.subtle.importKey(
        'pkcs8', pkcs8,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, ['sign'],
      );
      const sigP1363 = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        cryptoKey, signData,
      );

      // P1363 → DER 格式（与 Python 兼容）
      const sigDer = p1363ToDer(new Uint8Array(sigP1363));

      // 证书指纹
      let certFingerprint = '';
      const certPem = currentAid.certPem;
      if (certPem) {
        const certDer = pemToArrayBuffer(certPem);
        const fpBuf = await crypto.subtle.digest('SHA-256', certDer);
        certFingerprint = 'sha256:' + Array.from(new Uint8Array(fpBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
      }

      params.client_signature = {
        aid,
        cert_fingerprint: certFingerprint,
        timestamp: ts,
        params_hash: paramsHash,
        signature: uint8ToBase64(sigDer),
      };
    } catch (exc) {
      throw new E2EEError(`客户端签名失败: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
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
        this._state = 'disconnected';
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
      if (!isShortConnection) {
        // V2 E2EE: 长连接上线时初始化 session 并注册设备 SPK（与 Python `_init_v2_session` 对齐）
        try {
          await this._initV2Session();
        } catch (exc) {
          this._clientLog.warn(`V2 session init failed (non-fatal): ${String(exc)}`);
        }
      } else {
        this._clientLog.debug('V2 session init deferred for short connection');
      }

      // connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压
      const hasExplicitBackgroundSync = Object.prototype.hasOwnProperty.call(params, 'background_sync');
      const backgroundSyncEnabled = this._sessionOptions?.background_sync !== false
        && (!isShortConnection || hasExplicitBackgroundSync);
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
      const getMetadata = (this._keystore as unknown as { getMetadata?: (aid: string, key: string) => Promise<string> }).getMetadata;
      const raw = typeof getMetadata === 'function'
        ? String(await getMetadata.call(this._keystore, target, 'gateway_url') ?? '').trim()
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
          const setMetadata = (this._keystore as unknown as { setMetadata?: (aid: string, key: string, value: string) => Promise<void> }).setMetadata;
          if (typeof setMetadata === 'function') {
            await setMetadata.call(this._keystore, target, 'gateway_url', gateway);
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
    let identity: IdentityRecord | null = null;
    try {
      identity = await this._auth.loadIdentityOrNone(this._aid ?? undefined);
    } catch { /* 忽略 */ }
    if (!identity) {
      this._identity = null;
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
      } else {
        await this._keystore.saveIdentity(String(identity.aid), identity);
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
        for (const [key, entry] of this._v2BootstrapCache) {
          if (now - entry.cachedAt >= AUNClient.V2_BOOTSTRAP_TTL_MS) {
            this._v2BootstrapCache.delete(key);
          }
        }
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
      if (this._state !== 'connected' || this._closing) return;
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
    if (newInterval > 0 && this._state === 'connected' && !this._closing) {
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
        if (this._state !== 'connected' || !this._gatewayUrl) {
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

        if (this._state !== 'connected' || !this._gatewayUrl || this._closing) {
          scheduleRefresh();
          return;
        }
        try {
          identity = await this._auth.refreshCachedTokens(this._gatewayUrl!, identity!);
          // 刷新期间可能已断线，复检状态，避免写回 stale identity
          if (this._state !== 'connected') { scheduleRefresh(); return; }
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
            this._tokenRefreshFailures++;
            if (this._tokenRefreshFailures >= 3) {
              this._clientLog.warn(`token refreshconsecutivefailed ${this._tokenRefreshFailures}  , stop refresh loop and trigger reconnect`);
              this._dispatcher.publish('token.refresh_exhausted', {
                aid: this._identity?.aid ?? null,
                consecutive_failures: this._tokenRefreshFailures,
                last_error: String(exc),
              });
              this._tokenRefreshFailures = 0;
              this._handleTransportDisconnect(new Error('token refresh exhausted, triggering reconnect'));
              return;
            }
            this._clientLog.warn(`token refresh failed (${this._tokenRefreshFailures}/3), next retry: ${String(exc)}`)
          } else {
            this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) });
          }
        }
        scheduleRefresh();
      }, delayMs);
    };

    scheduleRefresh(0);
  }

  private _normalizeOutboundMessagePayload(params: RpcParams, method = ''): void {
    if (!Object.prototype.hasOwnProperty.call(params, 'payload') && Object.prototype.hasOwnProperty.call(params, 'content')) {
      params.payload = params.content;
      delete params.content;
    }
    const payload = params.payload;
    if (isJsonObject(payload) && !Object.prototype.hasOwnProperty.call(payload, 'type') && typeof payload.text === 'string') {
      params.payload = { type: 'text', ...payload } as JsonObject;
    }
  }
  private _validateMessageRecipient(toAid: JsonValue | object | undefined): void {
    if (isGroupServiceAid(toAid)) {
      throw new ValidationError('message.send receiver cannot be group.{issuer}; use group.send instead');
    }
  }

  private _validateOutboundCall(method: string, params: RpcParams): void {
    if (method === 'message.send') {
      this._validateMessageRecipient(params.to);
      if ('persist' in params) {
        throw new ValidationError("message.send no longer accepts 'persist'; configure delivery_mode during connect");
      }
      if ('delivery_mode' in params || 'queue_routing' in params || 'affinity_ttl_ms' in params) {
        throw new ValidationError('message.send does not accept delivery_mode; configure delivery_mode during connect');
      }
    }
    if (method === 'group.send') {
      if ('persist' in params) {
        throw new ValidationError("group.send does not accept 'persist'; group messages are always fanout");
      }
      if ('delivery_mode' in params || 'queue_routing' in params || 'affinity_ttl_ms' in params) {
        throw new ValidationError('group.send does not accept delivery_mode; group messages are always fanout');
      }
    }
    if (
      method === 'group.thought.put' || method === 'group.thought.get'
      || method === 'message.thought.put' || method === 'message.thought.get'
    ) {
      const context = isJsonObject(params.context) ? params.context : null;
      const contextType = String(context?.type ?? '').trim();
      const contextId = String(context?.id ?? '').trim();
      const hasContext = contextType.length > 0 && contextId.length > 0;
      if (!hasContext) {
        throw new ValidationError(`${method} requires context.type + context.id`);
      }
    }
    if (method === 'group.thought.get' && !String(params.sender_aid ?? '').trim()) {
      throw new ValidationError('group.thought.get requires sender_aid');
    }
    if (method === 'message.thought.put') {
      this._validateMessageRecipient(params.to);
      if (!String(params.to ?? '').trim()) {
        throw new ValidationError('message.thought.put requires to');
      }
    }
    if (method === 'message.thought.get' && !String(params.sender_aid ?? '').trim()) {
      throw new ValidationError('message.thought.get requires sender_aid');
    }
  }

  private _currentMessageDeliveryMode(): JsonObject {
    return { ...this._connectDeliveryMode };
  }

  private _injectMessageCursorContext(method: string, params: RpcParams): void {
    if (method !== 'message.pull' && method !== 'message.ack') {
      return;
    }
    if ('device_id' in params && String(params.device_id ?? '').trim() !== this._deviceId) {
      throw new ValidationError('message.pull/message.ack device_id must match the current client instance');
    }
    const slotId = normalizeInstanceId(params.slot_id ?? this._slotId, 'slot_id', { allowEmpty: true });
    if (slotId !== this._slotId) {
      throw new ValidationError('message.pull/message.ack slot_id must match the current client instance');
    }
    params.device_id = this._deviceId;
    params.slot_id = this._slotId;
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
    this._state = 'disconnected';
    // 先停止后台任务，避免心跳/token刷新在重连期间继续触发
    this._stopBackgroundTasks();
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

  // ── Named Group（命名群）高层 API ────────────────────────────

  /**
   * 创建命名群：本地生成 P-256 keypair，调用 group.create 传入 public_key，
   * 服务端签发群 AID 证书，返回后将证书和私钥存入 keystore。
   */
  private async createNamedGroup(groupName: string, opts: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const tStart = Date.now();
    this._clientLog.debug(`createNamedGroup enter: name=${groupName}`);
    try {
      const cp = new CryptoProvider();
      const identity = await cp.generateIdentity();
      const params: Record<string, JsonValue> = {};
      for (const [k, v] of Object.entries(opts)) {
        params[k] = v as JsonValue;
      }
      params.group_name = groupName;
      params.public_key = identity.public_key_der_b64;
      params.curve = 'P-256';

      const result = await this.call('group.create', params) as Record<string, unknown>;

      const groupInfo = result?.group as Record<string, unknown> | undefined;
      const aidCert = result?.aid_cert as Record<string, unknown> | undefined;
      const groupAid = String(groupInfo?.group_aid ?? '');
      if (groupAid && aidCert) {
        await this._keystore.saveIdentity(groupAid, {
          private_key_pem: identity.private_key_pem,
          public_key: identity.public_key_der_b64,
          curve: 'P-256',
          type: 'group_identity',
        });
        const certPem = String(aidCert.cert ?? '');
        if (certPem) {
          await this._keystore.saveCert(groupAid, certPem);
        }
      }
      this._clientLog.debug(`createNamedGroup exit: elapsed=${Date.now() - tStart}ms group_aid=${groupAid}`);
      return result;
    } catch (err) {
      this._clientLog.debug(`createNamedGroup exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 为已有普通群绑定命名 AID（升级为命名群）。
   */
  private async bindGroupAid(groupId: string, groupName: string): Promise<Record<string, unknown>> {
    const tStart = Date.now();
    this._clientLog.debug(`bindGroupAid enter: group_id=${groupId} name=${groupName}`);
    try {
      const cp = new CryptoProvider();
      const identity = await cp.generateIdentity();
      const params: Record<string, JsonValue> = {
        group_id: groupId,
        group_name: groupName,
        public_key: identity.public_key_der_b64,
        curve: 'P-256',
      };

      const result = await this.call('group.bind_aid', params) as Record<string, unknown>;

      const groupInfo = result?.group as Record<string, unknown> | undefined;
      const aidCert = result?.aid_cert as Record<string, unknown> | undefined;
      const groupAid = String(groupInfo?.group_aid ?? '');
      if (groupAid && aidCert) {
        await this._keystore.saveIdentity(groupAid, {
          private_key_pem: identity.private_key_pem,
          public_key: identity.public_key_der_b64,
          curve: 'P-256',
          type: 'group_identity',
        });
        const certPem = String(aidCert.cert ?? '');
        if (certPem) {
          await this._keystore.saveCert(groupAid, certPem);
        }
      }
      this._clientLog.debug(`bindGroupAid exit: elapsed=${Date.now() - tStart}ms group_aid=${groupAid}`);
      return result;
    } catch (err) {
      this._clientLog.debug(`bindGroupAid exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
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
    if (!this._aid) return;
    const context = this._seqTrackerContext;
    if (!context) return;
    const aid = this._aid;
    const deviceId = this._deviceId;
    const slotId = this._slotId;
    try {
      // 优先从 seq_tracker 表按行读取
      const loadAll = this._keystore.loadAllSeqs?.bind(this._keystore);
      if (typeof loadAll === 'function') {
        let state = await loadAll(aid, deviceId, slotId);
        if (this._seqTrackerContext !== context) return;
        if (state && typeof state === 'object' && Object.keys(state).length > 0) {
          state = await this._migrateSeqStateGroupIds(state);
          this._seqTracker.restoreState(state);
        }
        return;
      }
      // fallback: 从旧 instance_state JSON blob 恢复
      const loader = this._keystore.loadInstanceState?.bind(this._keystore);
      if (typeof loader !== 'function') return;
      const stateHolder = await loader(aid, deviceId, slotId);
      if (this._seqTrackerContext !== context) return;
      if (stateHolder && typeof stateHolder === 'object') {
        const state = (stateHolder as Record<string, JsonValue>).seq_tracker_state;
        if (isJsonObject(state)) {
          const migrated = await this._migrateSeqStateGroupIds(state as Record<string, number>);
          this._seqTracker.restoreState(migrated);
        }
      }
    } catch (exc) {
      this._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'restore',
        aid,
        device_id: deviceId,
        slot_id: slotId,
        error: String(exc),
      }).catch(() => {});
    }
  }

  /**
   * 把 seq_tracker state 里 group_event:/group_msg: 前缀的老/污染 group_id 归一化。
   * 冲突取 max；同时落盘删除老 ns、写入新 ns。
   */
  private async _migrateSeqStateGroupIds(state: Record<string, number>): Promise<Record<string, number>> {
    if (!state || Object.keys(state).length === 0) return state;
    const renameMap: Record<string, string> = {};
    for (const ns of Object.keys(state)) {
      for (const prefix of ['group_event:', 'group_msg:']) {
        if (ns.startsWith(prefix)) {
          const oldGid = ns.slice(prefix.length);
          const newGid = normalizeGroupId(oldGid);
          if (newGid && newGid !== oldGid) {
            renameMap[ns] = `${prefix}${newGid}`;
          }
          break;
        }
      }
    }
    if (Object.keys(renameMap).length === 0) return state;
    const newState: Record<string, number> = { ...state };
    for (const [oldNs, newNs] of Object.entries(renameMap)) {
      const oldVal = Number(newState[oldNs] ?? 0);
      const curVal = Number(newState[newNs] ?? 0);
      delete newState[oldNs];
      newState[newNs] = Math.max(oldVal, curVal);
    }
    if (!this._aid) return newState;
    const aid = this._aid;
    const deviceId = this._deviceId;
    const slotId = this._slotId;
    const saver = this._keystore.saveSeq?.bind(this._keystore);
    const deleter = (this._keystore as KeyStore & {
      deleteSeq?: (aid: string, deviceId: string, slotId: string, namespace: string) => void | Promise<void>;
    }).deleteSeq?.bind(this._keystore);
    if (typeof saver === 'function') {
      for (const [oldNs, newNs] of Object.entries(renameMap)) {
        if (typeof deleter === 'function') {
          try { await deleter(aid, deviceId, slotId, oldNs); } catch (e) {
            this._dispatcher.publish('seq_tracker.persist_error', {
              phase: 'migrate_delete', aid, device_id: deviceId, slot_id: slotId,
              ns: oldNs, error: String(e),
            }).catch(() => {});
          }
        }
        try { await saver(aid, deviceId, slotId, newNs, newState[newNs]); } catch (e) {
          this._dispatcher.publish('seq_tracker.persist_error', {
            phase: 'migrate_save', aid, device_id: deviceId, slot_id: slotId,
            ns: newNs, error: String(e),
          }).catch(() => {});
        }
      }
    }
    return newState;
  }

  private _currentSeqTrackerContext(): string | null {
    if (!this._aid) return null;
    return JSON.stringify([this._aid, this._deviceId, this._slotId]);
  }

  private _resetSeqTrackingState(): void {
    this._seqTracker = new SeqTracker();
    this._seqTrackerContext = null;
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
    this._v2SenderIKPending.clear();
    this._v2SenderIKFetching.clear();
    this._groupSynced.clear();
  }

  private _refreshSeqTrackerContext(): void {
    const nextContext = this._currentSeqTrackerContext();
    if (nextContext === this._seqTrackerContext) return;
    this._seqTracker = new SeqTracker();
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
    this._v2SenderIKPending.clear();
    this._v2SenderIKFetching.clear();
    this._groupSynced.clear();
    this._seqTrackerContext = nextContext;
  }

  /** 将 SeqTracker 状态保存到 keystore */
  private _saveSeqTrackerState(): void {
    if (!this._aid) return;
    const state = this._seqTracker.exportState();
    if (Object.keys(state).length === 0) return;
    try {
      // 优先按行写入 seq_tracker 表
      const saveFn = this._keystore.saveSeq?.bind(this._keystore);
      if (typeof saveFn === 'function') {
        for (const [ns, seq] of Object.entries(state)) {
          saveFn(this._aid, this._deviceId, this._slotId, ns, seq).catch((exc) => {
            this._dispatcher.publish('seq_tracker.persist_error', {
              phase: 'save',
              aid: this._aid,
              device_id: this._deviceId,
              slot_id: this._slotId,
              error: String(exc),
            }).catch(() => {});
          });
        }
        return;
      }
      // fallback: 旧版 updateInstanceState JSON blob
      if (typeof this._keystore.updateInstanceState === 'function') {
        this._keystore.updateInstanceState(this._aid, this._deviceId, this._slotId, (current) => {
          (current as Record<string, JsonValue>).seq_tracker_state = state as unknown as JsonValue;
          return current;
        }).catch((exc) => {
          this._dispatcher.publish('seq_tracker.persist_error', {
            phase: 'save',
            aid: this._aid,
            device_id: this._deviceId,
            slot_id: this._slotId,
            error: String(exc),
          }).catch(() => {});
        });
      }
    } catch (exc) {
      this._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'save',
        aid: this._aid,
        device_id: this._deviceId,
        slot_id: this._slotId,
        error: String(exc),
      }).catch(() => {});
    }
  }

  private _persistRepairedSeq(ns: string): void {
    if (!this._aid || !ns) return;
    const seq = this._seqTracker.getContiguousSeq(ns);
    try {
      if (seq > 0 && typeof this._keystore.saveSeq === 'function') {
        this._keystore.saveSeq(this._aid, this._deviceId, this._slotId, ns, seq).catch((exc) => {
          this._clientLog.debug(`persist repaired seq failed: ns=${ns} err=${formatCaughtError(exc)}`);
        });
        return;
      }
      const deleteSeq = this._keystore.deleteSeq;
      if (seq <= 0 && typeof deleteSeq === 'function') {
        deleteSeq.call(this._keystore, this._aid, this._deviceId, this._slotId, ns).catch((exc) => {
          this._clientLog.debug(`delete repaired seq failed: ns=${ns} err=${formatCaughtError(exc)}`);
        });
        return;
      }
      if (seq > 0) {
        this._saveSeqTrackerState();
      }
    } catch (exc) {
      this._clientLog.debug(`persist repaired seq failed: ns=${ns} err=${formatCaughtError(exc)}`);
    }
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
    if (!this._v2Session) {
      if (!this._v2SessionInitInFlight) {
        this._v2SessionInitInFlight = this._initV2Session()
          .finally(() => {
            this._v2SessionInitInFlight = null;
          });
      }
      await this._v2SessionInitInFlight;
    }
    if (!this._v2Session) {
      throw new StateError(errorMessage ?? `V2 session not initialized; encrypted ${method} requires E2EE V2`);
    }
  }

  // ── V2 E2EE API（async，与 Python `client.py` `_init_v2_session` / `send_v2` / `pull_v2` / `ack_v2` 对齐） ──

  /**
   * 初始化 V2 session：从 AID PEM 私钥提取 raw scalar + DER 公钥，
   * 打开 V2 KeyStore（IndexedDB），构造 V2Session 并注册当前设备 SPK。
   *
   * connect 成功后自动调用，可幂等手动调用。
   */
  private async _initV2Session(): Promise<void> {
    if (!this._aid) return;
    // 私钥由 AIDStore 管理，直接从 _currentAid 读取明文私钥
    const currentAid = this._currentAid;
    if (!currentAid?.privateKeyPem) {
      this._clientLog.warn('V2 session init skipped: no AID private key');
      return;
    }
    if (this._v2Session) return;

    // 1. PEM → DER PKCS8（去掉 header/footer 后 base64 解码）
    const pem = currentAid.privateKeyPem.trim();
    const pemBody = pem
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
    const pkcs8Der = _v2B64ToBytes(pemBody);

    // 2. 用 WebCrypto 导入 PKCS8 → 导出 jwk → 从 d 拿到 raw scalar
    const privKey = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8Der.slice().buffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    const jwk = await crypto.subtle.exportKey('jwk', privKey) as JsonWebKey;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
      throw new Error('AID private key must be EC P-256');
    }
    if (!jwk.d || !jwk.x || !jwk.y) {
      throw new Error('AID private key jwk missing d/x/y');
    }
    const aidPriv = _v2LeftPad32(_v2B64uToBytes(jwk.d));

    // 3. 从 jwk 公钥导出 SPKI DER
    const pubKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    const aidPubDer = new Uint8Array(await crypto.subtle.exportKey('spki', pubKey));

    // 4. 打开 V2 KeyStore（IndexedDB）
    if (!this._v2KeyStore) {
      this._v2KeyStore = await V2KeyStore.open();
    }

    this._v2Session = new V2Session(
      this._v2KeyStore,
      this._deviceId,
      this._aid,
      aidPriv,
      aidPubDer,
    );

    const callFn: CallFn = async (method, params) => {
      return this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
    };

    await this._v2Session.ensureRegistered(callFn);
    this._clientLog.debug(`V2 session initialized aid=${this._aid} device=${this._deviceId}`);

    // 上线时自动确认 pending state proposals
    this._safeAsync(this._v2AutoConfirmPendingProposals());
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
    const spkHash = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', args.spkPkDer.slice().buffer)));
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

  private async _getV2SenderPubDer(fromAid: string, senderDeviceId: string): Promise<Uint8Array | null> {
    const session = this._v2Session;
    if (!session || !fromAid) return null;

    let senderPubDer: Uint8Array | null = session.getPeerIK(fromAid, senderDeviceId);
    if (senderPubDer) return senderPubDer;

    try {
      const certPem = await this._fetchPeerCert(fromAid, undefined, 3000);
      const pubKey = await importCertPublicKeyEcdsa(certPem);
      senderPubDer = new Uint8Array(await crypto.subtle.exportKey('spki', pubKey));
      session.cachePeerIK(fromAid, senderDeviceId, senderPubDer);
      this._clientLog.debug(`V2 decrypt: sender IK fallback from PKI cert for ${fromAid}`);
      return senderPubDer;
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt: PKI cert sender IK fallback failed for ${fromAid}: ${String(formatCaughtError(exc))}`);
      return null;
    }
  }

  private _v2PendingSenderIKMessageKey(msg: Record<string, unknown>, groupId: string): string {
    const messageId = String(msg.message_id ?? '').trim();
    const seq = String(msg.seq ?? '').trim();
    const prefix = groupId ? `group:${groupId}` : `p2p:${this._aid ?? ''}`;
    return `${prefix}:${messageId || seq || Math.random().toString(36).slice(2)}`;
  }

  private _v2PendingSenderIKFetchKey(fromAid: string, senderDeviceId: string, groupId: string): string {
    return `${fromAid}#${senderDeviceId}#${groupId || ''}`;
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
    const fromAid = String(args.fromAid ?? '').trim();
    if (!fromAid) return;
    const senderDeviceId = String(args.senderDeviceId ?? '');
    const groupId = String(args.groupId ?? '').trim();
    const messageKey = this._v2PendingSenderIKMessageKey(args.msg, groupId);
    this._v2SenderIKPending.set(messageKey, {
      msg: { ...args.msg },
      fromAid,
      senderDeviceId,
      groupId,
      createdAt: Date.now(),
    });
    this._clientLog.debug(`V2 decrypt pending sender IK: key=${messageKey} from=${fromAid} device=${senderDeviceId || '-'} group=${groupId || '<p2p>'} pending=${this._v2SenderIKPending.size}`);
    this._scheduleV2SenderIKFetch(fromAid, senderDeviceId, groupId);
  }

  private _scheduleV2SenderIKFetch(fromAid: string, senderDeviceId: string, groupId: string): void {
    const fetchKey = this._v2PendingSenderIKFetchKey(fromAid, senderDeviceId, groupId);
    if (!fromAid || this._v2SenderIKFetching.has(fetchKey)) return;
    this._v2SenderIKFetching.add(fetchKey);
    this._safeAsync(this._resolveV2SenderIKPending(fromAid, senderDeviceId, groupId, fetchKey));
  }

  private async _resolveV2SenderIKPending(fromAid: string, senderDeviceId: string, groupId: string, fetchKey: string): Promise<void> {
    try {
      const session = this._v2Session;
      if (session && fromAid) {
        try {
          const bs = await this.call('message.v2.bootstrap', {
            peer_aid: fromAid,
            e2ee_wrap_capabilities: v2WrapCapabilities(),
          }) as Record<string, unknown>;
          const peers = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
          for (const dev of peers) this._cacheV2PeerIKFromDevice(dev, fromAid);
        } catch (exc) {
          this._clientLog.warn(`V2 sender IK pending bootstrap failed peer=${fromAid}: ${String(formatCaughtError(exc))}`);
        }
        if (groupId) {
          try {
            const gbs = await this.call('group.v2.bootstrap', {
              group_id: groupId,
              e2ee_wrap_capabilities: v2WrapCapabilities(),
            }) as Record<string, unknown>;
            const devices = (Array.isArray(gbs?.devices) ? gbs.devices : []) as Array<Record<string, unknown>>;
            const audit = (Array.isArray(gbs?.audit_recipients) ? gbs.audit_recipients : []) as Array<Record<string, unknown>>;
            for (const dev of devices) this._cacheV2PeerIKFromDevice(dev);
            for (const dev of audit) this._cacheV2PeerIKFromDevice(dev);
          } catch (exc) {
            this._clientLog.warn(`V2 sender IK pending group bootstrap failed group=${groupId}: ${String(formatCaughtError(exc))}`);
          }
        }
        if (!session.getPeerIK(fromAid, senderDeviceId)) {
          await this._getV2SenderPubDer(fromAid, senderDeviceId);
        }
      }

      const pendingItems = [...this._v2SenderIKPending.entries()].filter(([, entry]) =>
        entry.fromAid === fromAid && entry.senderDeviceId === senderDeviceId && entry.groupId === groupId);
      for (const [key, entry] of pendingItems) {
        let plaintext: Record<string, unknown> | null = null;
        try {
          plaintext = await this._decryptV2Message(entry.msg, false);
        } catch (exc) {
          this._clientLog.warn(`V2 sender IK pending retry raised: key=${key} err=${String(formatCaughtError(exc))}`);
        }
        this._v2SenderIKPending.delete(key);
        if (plaintext === null) {
          this._clientLog.debug(`V2 sender IK pending retry failed: key=${key}`);
          continue;
        }
        const seq = Number(entry.msg.seq ?? 0);
        if (entry.groupId) {
          plaintext.group_id = entry.groupId;
          await this._publishPulledMessage('group.message_created', `group:${entry.groupId}`, seq, plaintext as EventPayload);
        } else {
          await this._publishPulledMessage('message.received', `p2p:${this._aid ?? ''}`, seq, plaintext as EventPayload);
        }
        this._clientLog.debug(`V2 sender IK pending retry delivered: key=${key}`);
      }
    } finally {
      this._v2SenderIKFetching.delete(fetchKey);
    }
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
    if (!this._v2Session) {
      throw new StateError('V2 session not initialized (not connected?)');
    }

    const toAid = String(to ?? '').trim();
    if (!toAid) throw new ValidationError("message.send requires 'to'");
    if (!isJsonObject(payload)) throw new ValidationError('message.send payload must be a dict for V2 encryption');

    const attempt = async (useCache: boolean): Promise<unknown> => {
      const envelope = await this._buildV2P2PEnvelope({
        to: toAid,
        payload,
        messageId: opts?.messageId,
        timestamp: opts?.timestamp,
        protectedHeaders: opts?.protectedHeaders,
        context: opts?.context,
        useCache,
      });
      return this.call('message.send', {
        to: toAid,
        payload: envelope as JsonObject,
        encrypt: false,
      });
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = (exc as any)?.code;
      if (AUNClient.V2_RETRYABLE_CODES.has(excCode)) {
        this._clientLog.debug(`V2 P2P speculative send rejected (code=${excCode}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(toAid);
        return attempt(false);
      }
      throw exc;
    }
  }

  /**
   * 拉取并解密 V2 P2P 消息。
   *
   * @param afterSeq 从此 seq 之后开始拉取（0/省略 = 从当前 contiguous 开始）
   * @param limit 最多拉取条数
   */
  private async _pullV2(afterSeq: number = 0, limit: number = 50, opts?: { force?: boolean }): Promise<unknown[]> {
    if (!this._v2Session) {
      throw new StateError('V2 session not initialized (not connected?)');
    }
    const ns = this._aid ? `p2p:${this._aid}` : '';
    const decrypted: unknown[] = [];
    let nextAfterSeq = opts?.force ? afterSeq : (afterSeq || (ns ? this._seqTracker.getContiguousSeq(ns) : 0));
    let pageCount = 0;
    const maxPages = 100;

    while (pageCount < maxPages) {
      pageCount += 1;
      const result = await this._callRawV2Rpc('message.v2.pull', {
        after_seq: nextAfterSeq,
        limit,
        ...(opts?.force ? { force: true } : {}),
      }) as Record<string, unknown>;
      const messages = (Array.isArray(result?.messages) ? result.messages : []) as Array<Record<string, unknown>>;
      const seqs = messages
        .map((msg) => Number(msg.seq ?? 0))
        .filter((seq) => Number.isFinite(seq) && seq > 0);
      const pageContigBefore = ns ? this._seqTracker.getContiguousSeq(ns) : 0;
      const pageMaxSeq = seqs.length > 0 ? Math.max(...seqs) : nextAfterSeq;
      if (ns && seqs.length > 0) {
        this._seqTracker.forceContiguousSeq(ns, pageMaxSeq);
      }

      for (const msg of messages) {
        const seq = Number(msg.seq ?? 0);
        if (!Number.isFinite(seq) || seq <= 0) continue;

        const version = String(msg.version ?? 'v2');
        if (version === 'v1') {
          const legacy = isJsonObject(msg.legacy_v1 as JsonValue | object | null | undefined) ? msg.legacy_v1 as JsonObject : {};
          const legacyPayload = legacy.payload;
          const payloadType = isJsonObject(legacyPayload as JsonValue | object | null | undefined)
            ? String((legacyPayload as JsonObject).type ?? '').trim()
            : '';
          if (legacyPayload !== undefined && legacyPayload !== null
            && payloadType !== 'e2ee.encrypted' && payloadType !== 'e2ee.group_encrypted') {
            const v1Msg: Record<string, unknown> = {
              message_id: String(msg.message_id ?? ''),
              from: String(msg.from_aid ?? ''),
              to: String(legacy.to ?? this._aid ?? ''),
              seq: msg.seq as JsonValue,
              type: String(msg.type ?? ''),
              timestamp: msg.t_server as JsonValue,
              payload: legacyPayload as JsonValue,
              encrypted: false,
            };
            if (ns) await this._publishPulledMessage('message.received', ns, seq, v1Msg as EventPayload);
            else await this._publishAppEvent('message.received', v1Msg as EventPayload);
            decrypted.push(v1Msg);
          } else {
            this._clientLog.debug(`message.v2.pull skipping V1 envelope seq=${seq} payload_type=${payloadType || '<none>'} (V1 E2EE removed)`);
          }
          continue;
        }

        if (version !== 'v2') {
          this._clientLog.debug(`message.v2.pull skipping non-V2 row seq=${seq} version=${String(msg.version ?? '')}`);
          continue;
        }

        // 跟踪每个旧 SPK 引用的最大 seq（用于消费后销毁）
        const msgSpkId = String(msg.spk_id ?? '');
        if (msgSpkId && this._v2Session && !this._v2Session.isCurrentSPK(msgSpkId)) {
          this._v2Session.trackOldSPKMaxSeq(msgSpkId, seq);
        }
        const plaintext = await this._decryptV2Message(msg);
        if (plaintext === null) continue;
        if (ns) {
          await this._publishPulledMessage('message.received', ns, seq, plaintext as EventPayload);
          decrypted.push(plaintext);
        } else {
          await this._publishAppEvent('message.received', plaintext as EventPayload);
          decrypted.push(plaintext);
        }
      }

      const hasServerAckSeq = Object.prototype.hasOwnProperty.call(result, 'server_ack_seq');
      const serverAckSeq = Number(result.server_ack_seq ?? 0);
      if (ns && Number.isFinite(serverAckSeq) && serverAckSeq > 0) {
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig < serverAckSeq) {
          this._clientLog.info(`message.v2.pull retention-floor advance: ns=${ns} contiguous=${contig} -> server_ack_seq=${serverAckSeq}`);
          this._seqTracker.forceContiguousSeq(ns, serverAckSeq);
        }
      }

      if (ns) {
        const ackSeq = this._seqTracker.getContiguousSeq(ns);
        const contigAdvanced = ackSeq !== pageContigBefore;
        if (contigAdvanced) {
          await this._drainOrderedMessages(ns);
          this._saveSeqTrackerState();
        }
        const ackNeeded = messages.length > 0
          && ackSeq > 0
          && (contigAdvanced || (hasServerAckSeq && ackSeq > serverAckSeq));
        if (ackNeeded) {
          this._safeAsync(this._ackV2(ackSeq).then(() => undefined));
        }
      }

      const nextAfter = Math.max(pageMaxSeq, nextAfterSeq);
      if (messages.length === 0 || nextAfter <= nextAfterSeq || result.has_more === false) break;
      nextAfterSeq = nextAfter;
    }

    if (pageCount >= maxPages) {
      this._clientLog.warn(`message.v2.pull reached max_pages=${maxPages} after_seq=${nextAfterSeq}`);
    }
    return decrypted;
  }

  /**
   * 确认 V2 消息已消费 + 自检销毁旧 SPK（PFS）。
   *
   * @param upToSeq 确认到此 seq；省略则用当前 contiguous
   */
  private async _ackV2(upToSeq?: number): Promise<unknown> {
    const ns = this._aid ? `p2p:${this._aid}` : '';
    let seq = upToSeq ?? (ns ? this._seqTracker.getContiguousSeq(ns) : 0);
    if (seq <= 0) return { acked: 0 };
    // ack clamp：永远不发送超过 maxSeenSeq 的 up_to_seq
    if (ns) {
      const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
      if (maxSeen > 0 && seq > maxSeen) {
        this._clientLog.warn(`ackV2 clamp: up_to_seq=${seq} > max_seen=${maxSeen}, clamp`);
        seq = maxSeen;
      }
    }
    const raw = await this._callRawV2Rpc('message.v2.ack', { up_to_seq: seq });
    const result: JsonObject = isJsonObject(raw as JsonValue | object | null | undefined)
      ? { ...(raw as JsonObject) }
      : { result: raw as JsonValue };
    let actualAckSeq = seq;
    if ('effective_ack_seq' in result) actualAckSeq = Number(result.effective_ack_seq ?? 0);
    else if ('ack_seq' in result) actualAckSeq = Number(result.ack_seq ?? 0);
    else if ('cursor' in result) actualAckSeq = Number(result.cursor ?? 0);
    if (!Number.isFinite(actualAckSeq)) actualAckSeq = seq;
    result.ack_seq = actualAckSeq;
    result.success = true;
    if (Number(result.acked ?? 0) === 0) result.acked = actualAckSeq;
    if (this._v2Session) {
      try {
        const destroyed = await this._v2Session.maybeDestroyOldSPKs(actualAckSeq);
        if (destroyed.length > 0) {
          this._clientLog.info(`V2 destroyed old SPKs after ack: ${destroyed.slice(0, 3)} (PFS)`);
        }
      } catch (exc) {
        this._clientLog.debug(`V2 SPK destroy failed (non-fatal): ${String(exc)}`);
      }
    }
    return result;
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
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId);
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
          _sender_device_id: String(aad.from_device ?? ''),
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
          _sender_device_id: String(aad.from_device ?? ''),
        };
        attachV2EnvelopeMetadata(event, e2eeMeta);
        await this._dispatcher.publish(undecryptableEvent, event);
      } catch { /* publish 异常不影响主流程 */ }
      return null;
    }
    if (plaintext == null) return null;

    // 消费触发 SPK 轮换（fire-and-forget，不阻塞消息处理）
    if (groupIdForKeys && recipientKeySource === 'group_device_prekey' && session.isLastUploadedGroupSPK(groupIdForKeys, spkId)) {
      const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
      session.rotateGroupSPK(groupIdForKeys, callFn).catch(exc => {
        this._clientLog.debug(`V2 group SPK rotation failed (non-fatal): group=${groupIdForKeys} err=${exc}`);
      });
    } else if (groupIdForKeys && recipientKeySource === 'peer_device_prekey') {
      const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
      session.ensureGroupRegistered(groupIdForKeys, callFn).catch(exc => {
        this._clientLog.debug(`V2 group SPK registration after peer fallback failed (non-fatal): group=${groupIdForKeys} err=${exc}`);
      });
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
    if (!this._v2Session) {
      throw new StateError('V2 session not initialized (not connected?)');
    }

    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError("group.send requires 'group_id'");
    if (!isJsonObject(payload)) throw new ValidationError('group.send payload must be a dict for V2 encryption');

    const attempt = async (useCache: boolean): Promise<unknown> => {
      const envelope = await this._buildV2GroupEnvelope({
        groupId: gid,
        payload,
        messageId: opts?.messageId,
        timestamp: opts?.timestamp,
        protectedHeaders: opts?.protectedHeaders,
        context: opts?.context,
        useCache,
      });
      return this.call('group.v2.send', {
        group_id: gid,
        envelope: envelope as JsonObject,
      });
    };

    try {
      const result = await attempt(true);
      // 发送成功后记录自己发的消息 seq，保证 SeqTracker 连续 + push 时去重
      if (isJsonObject(result)) {
        const seq = Number((result as JsonObject).seq ?? 0);
        if (seq > 0) {
          const ns = `group:${gid}`;
          this._seqTracker.onMessageSeq(ns, seq);
          this._markPublishedSeq(ns, seq);
          this._saveSeqTrackerState();
        }
      }
      return result;
    } catch (exc) {
      const excCode = (exc as any)?.code;
      if (AUNClient.V2_RETRYABLE_CODES.has(excCode)) {
        this._clientLog.debug(`V2 group speculative send rejected (code=${excCode}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(`group:${gid}`);
        const result = await attempt(false);
        if (isJsonObject(result)) {
          const seq = Number((result as JsonObject).seq ?? 0);
          if (seq > 0) {
            const ns = `group:${gid}`;
            this._seqTracker.onMessageSeq(ns, seq);
            this._markPublishedSeq(ns, seq);
            this._saveSeqTrackerState();
          }
        }
        return result;
      }
      throw exc;
    }
  }

  private async _pullGroupV2Internal(params: { group_id: string; after_seq: number; limit: number }): Promise<void> {
    await this._pullGroupV2(params.group_id, params.after_seq, params.limit);
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
    opts?: { explicitAfterSeq?: boolean; cursorParams?: RpcParams; ownsCursor?: boolean },
  ): Promise<unknown[]> {
    if (!this._v2Session) {
      throw new StateError('V2 session not initialized (not connected?)');
    }
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.pull requires group_id');
    const ns = `group:${gid}`;
    const decrypted: unknown[] = [];
    const cursorParams = opts?.cursorParams ?? {};
    const ownsCursor = opts?.ownsCursor !== false;
    let nextAfterSeq = opts?.explicitAfterSeq ? afterSeq : (afterSeq || this._seqTracker.getContiguousSeq(ns));
    let pageCount = 0;
    const maxPages = 100;

    while (pageCount < maxPages) {
      pageCount += 1;
      const result = await this._callRawV2Rpc('group.v2.pull', {
        group_id: gid,
        after_seq: nextAfterSeq,
        limit,
        ...cursorParams,
      }) as Record<string, unknown>;
      const messages = (Array.isArray(result?.messages) ? result.messages : []) as Array<Record<string, unknown>>;
      const seqs = messages
        .map((msg) => Number(msg.seq ?? 0))
        .filter((seq) => Number.isFinite(seq) && seq > 0);
      const pageContigBefore = this._seqTracker.getContiguousSeq(ns);
      const pageMaxSeq = seqs.length > 0 ? Math.max(...seqs) : nextAfterSeq;
      if (seqs.length > 0) {
        this._seqTracker.forceContiguousSeq(ns, pageMaxSeq);
      }

      for (const msg of messages) {
        const seq = Number(msg.seq ?? 0);
        if (!Number.isFinite(seq) || seq <= 0) continue;

        const version = String(msg.version ?? 'v2');
        if (version === 'v1') {
          const payload = msg.payload;
          const payloadObj = isJsonObject(payload as JsonValue | object | null | undefined) ? payload as JsonObject : null;
          if (payloadObj) {
            const payloadType = String(payloadObj.type ?? '').trim();
            if (payloadType !== 'e2ee.encrypted' && payloadType !== 'e2ee.group_encrypted') {
              const v1Msg: Record<string, unknown> = {
                message_id: String(msg.message_id ?? ''),
                from: String(msg.from_aid ?? ''),
                group_id: gid,
                seq: msg.seq as JsonValue,
                type: String(msg.type ?? ''),
                timestamp: msg.t_server as JsonValue,
                payload,
                encrypted: false,
              };
              await this._publishPulledMessage('group.message_created', ns, seq, v1Msg as EventPayload);
              decrypted.push(v1Msg);
              continue;
            }
          } else if (payload !== undefined && payload !== null) {
            const v1Msg: Record<string, unknown> = {
              message_id: String(msg.message_id ?? ''),
              from: String(msg.from_aid ?? ''),
              group_id: gid,
              seq: msg.seq as JsonValue,
              type: String(msg.type ?? ''),
              timestamp: msg.t_server as JsonValue,
              payload,
              encrypted: false,
            };
            await this._publishPulledMessage('group.message_created', ns, seq, v1Msg as EventPayload);
            decrypted.push(v1Msg);
            continue;
          }
          this._clientLog.debug(`group.v2.pull skipping V1 envelope group=${gid} seq=${seq} payload_type=${payloadObj ? String(payloadObj.type ?? '') : '<none>'} (V1 E2EE removed)`);
          continue;
        }

        if (version !== 'v2') {
          this._clientLog.debug(`group.v2.pull skipping non-V2 row group=${gid} seq=${seq} version=${String(msg.version ?? '')}`);
          continue;
        }

        const plaintext = await this._decryptV2Message(msg);
        if (plaintext === null) continue;
        (plaintext as Record<string, unknown>).group_id = gid;
        await this._publishPulledMessage('group.message_created', ns, seq, plaintext as EventPayload);
        decrypted.push(plaintext);
      }

      const cursor = isJsonObject(result.cursor as JsonValue | object | null | undefined) ? result.cursor as JsonObject : null;
      const hasServerCursor = cursor !== null && Object.prototype.hasOwnProperty.call(cursor, 'current_seq');
      const serverAckSeq = Number(cursor?.current_seq ?? 0);
      if (Number.isFinite(serverAckSeq) && serverAckSeq > 0) {
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig < serverAckSeq) {
          this._clientLog.info(`group.v2.pull retention-floor advance: ns=${ns} contiguous=${contig} -> cursor.current_seq=${serverAckSeq}`);
          this._seqTracker.forceContiguousSeq(ns, serverAckSeq);
        }
      }

      const ackSeq = this._seqTracker.getContiguousSeq(ns);
      const contigAdvanced = ackSeq !== pageContigBefore;
      if (contigAdvanced) {
        await this._drainOrderedMessages(ns);
        this._saveSeqTrackerState();
      }
      const ackNeeded = messages.length > 0
        && ackSeq > 0
        && ownsCursor
        && (contigAdvanced || (hasServerCursor && ackSeq > serverAckSeq));
      if (ackNeeded) {
        this._safeAsync(this._ackGroupV2(gid, ackSeq).then(() => undefined));
      }

      const nextAfter = Math.max(pageMaxSeq, nextAfterSeq);
      if (!ownsCursor) break;
      if (messages.length === 0 || nextAfter <= nextAfterSeq || result.has_more === false) break;
      nextAfterSeq = nextAfter;
    }

    if (pageCount >= maxPages) {
      this._clientLog.warn(`group.v2.pull reached max_pages=${maxPages} group=${gid} after_seq=${nextAfterSeq}`);
    }
    return decrypted;
  }

  private _groupCursorParams(params: RpcParams): RpcParams {
    const cursorParams: RpcParams = {};
    for (const key of ['device_id', 'slot_id', 'device_name', 'device_type']) {
      const value = params[key];
      if (value !== undefined && value !== null) cursorParams[key] = value as JsonValue;
    }
    return cursorParams;
  }

  private _explicitGroupCursorParams(params: RpcParams): RpcParams {
    const value = (params as Record<string, unknown>)._group_cursor_params;
    if (!isJsonObject(value)) return {};
    return { ...(value as RpcParams) };
  }

  private _groupCursorTargetsCurrentInstance(params: RpcParams): boolean {
    const deviceId = String(params.device_id ?? '').trim();
    const slotId = String(params.slot_id ?? '').trim();
    return (!deviceId || deviceId === (this._deviceId ?? ''))
      && (!slotId || slotId === (this._slotId ?? ''));
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
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.ack_messages requires group_id');
    const ns = `group:${gid}`;
    let seq = upToSeq ?? this._seqTracker.getContiguousSeq(ns);
    if (seq <= 0) return { acked: 0 };
    // ack clamp：永远不发送超过 maxSeenSeq 的 up_to_seq
    const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
    if (maxSeen > 0 && seq > maxSeen) {
      this._clientLog.warn(`ackGroupV2 clamp: group=${gid} up_to_seq=${seq} > max_seen=${maxSeen}, clamp`);
      seq = maxSeen;
    }
    return this._callRawV2Rpc('group.v2.ack', { group_id: gid, up_to_seq: seq });
  }

  // ── V2 thought（per-device wrap，服务端透传，不持久化）──────────

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
    if (!this._v2Session) {
      throw new StateError('V2 session not initialized');
    }
    const session = this._v2Session;
    const to = opts.to;
    const useCache = opts.useCache !== false;

    let peerDevices: Array<Record<string, unknown>> = [];
    let auditRaw: Array<Record<string, unknown>> = [];
    let wrapPolicy: V2WrapPolicy | undefined;
    const cached = useCache ? this._v2BootstrapCache.get(to) : undefined;
    if (cached && (Date.now() - cached.cachedAt) < AUNClient.V2_BOOTSTRAP_TTL_MS) {
      peerDevices = cached.devices;
      auditRaw = cached.auditRecipients;
      wrapPolicy = cached.wrapPolicy;
    } else {
      const bs = await this.call('message.v2.bootstrap', {
        peer_aid: to,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      peerDevices = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
      auditRaw = (Array.isArray(bs?.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      wrapPolicy = normalizeV2WrapPolicy(bs?.e2ee_wrap_policy);
      if (peerDevices.length > 0) {
        this._v2BootstrapCache.set(to, {
          devices: peerDevices,
          auditRecipients: auditRaw,
          cachedAt: Date.now(),
          wrapPolicy,
        });
      }
    }

    if (peerDevices.length === 0) {
      throw new E2EEError(`V2 bootstrap: no devices found for ${to}`);
    }

    const targets: Target[] = [];
    for (const dev of peerDevices) {
      const devId = getV2DeviceId(dev);
      const target = await this._v2BuildTargetFromDevice({
        dev,
        aid: to,
        deviceId: devId.value,
        role: 'peer',
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }
    for (const dev of auditRaw) {
      const target = await this._v2BuildTargetFromDevice({
        dev,
        aid: String(dev.aid ?? ''),
        deviceId: String(dev.device_id ?? ''),
        role: 'audit',
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }

    // self-sync：自己其它设备
    if (this._aid && this._aid !== to) {
      try {
        const selfCached = this._v2BootstrapCache.get(this._aid);
        let selfDevices: Array<Record<string, unknown>> = [];
        if (selfCached && (Date.now() - selfCached.cachedAt) < AUNClient.V2_BOOTSTRAP_TTL_MS) {
          selfDevices = selfCached.devices;
        } else {
          const selfBs = await this.call('message.v2.bootstrap', {
            peer_aid: this._aid,
            e2ee_wrap_capabilities: v2WrapCapabilities(),
          }) as Record<string, unknown>;
          selfDevices = (Array.isArray(selfBs?.peer_devices) ? selfBs.peer_devices : []) as Array<Record<string, unknown>>;
          if (selfDevices.length > 0) {
            this._v2BootstrapCache.set(this._aid, {
              devices: selfDevices,
              auditRecipients: [],
              cachedAt: Date.now(),
            });
          }
        }
        for (const dev of selfDevices) {
          const devId = getV2DeviceId(dev);
          if (!devId.present || devId.value === this._deviceId) continue;
          const target = await this._v2BuildTargetFromDevice({
            dev,
            aid: this._aid,
            deviceId: devId.value,
            role: 'self_sync',
            defaultKeySource: 'peer_device_prekey',
          });
          if (target) targets.push(target);
        }
      } catch (exc) {
        this._clientLog.debug(`V2 thought self-sync bootstrap failed (non-fatal): ${String(exc)}`);
      }
    }

    const sender = await session.getSenderIdentity();
    const sendTargets = applyV2WrapPolicyToTargets(targets, wrapPolicy);
    const envelope = await encryptP2PMessage(
      sender,
      { targets: sendTargets, auditRecipients: [] },
      opts.payload,
      { messageId: opts.messageId, timestamp: opts.timestamp, protectedHeaders: opts.protectedHeaders, context: opts.context },
    );
    return envelope;
  }

  /**
   * V2 P2P thought.put：使用 V2 多设备 wrap envelope。
   * 服务端仍走 message.thought.put（内存 KV），envelope 透传，由接收端单设备解密。
   * 与 Python `_put_message_thought_encrypted_v2` 对齐。
   */
  private async _putMessageThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    const toAid = String(params.to ?? '').trim();
    this._validateMessageRecipient(toAid);
    const payload = isJsonObject(params.payload) ? params.payload : null;
    if (!toAid) {
      throw new ValidationError('message.thought.put requires to');
    }
    if (payload === null) {
      throw new ValidationError('message.thought.put payload must be an object when encrypt=true');
    }
    const thoughtId = String(params.thought_id ?? '') || `mt-${_uuidV4()}`;
    const timestamp = Number(params.timestamp ?? Date.now());

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
      const envelopeContext = (params.context && typeof params.context === 'object' && !Array.isArray(params.context))
        ? params.context as Record<string, unknown> : undefined;
      const envelope = await this._buildV2P2PEnvelope({
        to: toAid,
        payload,
        messageId: thoughtId,
        timestamp,
        useCache,
        context: envelopeContext,
      });
      const sendParams: RpcParams = {
        to: toAid,
        payload: envelope as JsonObject,
        encrypted: true,
        thought_id: thoughtId,
        timestamp,
      };
      if ('context' in params) sendParams.context = params.context;
      await this._signClientOperation('message.thought.put', sendParams);
      return this._transport.call('message.thought.put', sendParams);
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = (exc as any)?.code;
      if (AUNClient.V2_RETRYABLE_CODES.has(excCode)) {
        this._clientLog.debug(`V2 P2P thought put speculative rejected (code=${excCode}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(toAid);
        return attempt(false);
      }
      throw exc;
    }
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
    if (!this._v2Session) {
      throw new StateError('V2 session not initialized');
    }
    const session = this._v2Session;
    const groupId = normalizeGroupId(opts.groupId) || String(opts.groupId ?? '').trim();
    if (!groupId) throw new ValidationError("group.send requires 'group_id'");
    const useCache = opts.useCache !== false;
    const cacheKey = `group:${groupId}`;

    let allDevices: Array<Record<string, unknown>> = [];
    let epoch = 0;
    let stateCommitment: Partial<StateCommitmentAAD> = { state_version: 0, state_hash: '', state_chain: '' };
    let auditRecipientsRaw: Array<Record<string, unknown>> = [];
    let wrapPolicy: V2WrapPolicy | undefined;

    const cached = useCache ? this._v2BootstrapCache.get(cacheKey) : undefined;
    if (cached && (Date.now() - cached.cachedAt) < AUNClient.V2_BOOTSTRAP_TTL_MS) {
      allDevices = cached.devices;
      epoch = cached.epoch ?? 0;
      stateCommitment = cached.stateCommitment ?? { state_version: 0, state_hash: '', state_chain: '' };
      auditRecipientsRaw = cached.auditRecipients;
      wrapPolicy = cached.wrapPolicy;
    } else {
      const bs = await this.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      allDevices = (Array.isArray(bs?.devices) ? bs.devices : []) as Array<Record<string, unknown>>;
      epoch = Number(bs?.epoch ?? 0);
      auditRecipientsRaw = (Array.isArray(bs?.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      wrapPolicy = normalizeV2WrapPolicy(bs?.e2ee_wrap_policy);
      await this._v2CheckFork(groupId, String(bs?.state_chain ?? ''));
      await this._v2VerifyStateSignature(groupId, bs);
      await this._publishV2GroupSecurityLevel(groupId, bs);
      stateCommitment = {
        state_version: Number(bs?.state_version ?? 0) || 0,
        state_hash: String(bs?.state_hash_signed ?? bs?.state_hash ?? ''),
        state_chain: String(bs?.state_chain ?? ''),
      };
      if (allDevices.length > 0) {
        this._v2BootstrapCache.set(cacheKey, {
          devices: allDevices,
          auditRecipients: auditRecipientsRaw,
          cachedAt: Date.now(),
          epoch,
          stateCommitment: stateCommitment as { state_version: number; state_hash: string; state_chain: string },
          wrapPolicy,
        });
      }
      // lazy sync 触发：发现 pending members 时异步发起提案
      const pendingAdds = Array.isArray(bs?.pending_adds) ? bs.pending_adds : [];
      if (pendingAdds.length > 0 && this._v2Session) {
        this._v2MaybeTriggerAutoPropose(groupId);
      }
    }

    if (allDevices.length === 0) {
      throw new E2EEError(`V2 group bootstrap: no devices for ${groupId}`);
    }

    const targets: Target[] = [];
    for (const dev of allDevices) {
      const devAid = String(dev.aid ?? '');
      const devId = getV2DeviceId(dev);
      if (devAid === this._aid && devId.present && devId.value === this._deviceId) continue;
      const role = devAid === this._aid ? 'self_sync' : 'member';
      const target = await this._v2BuildTargetFromDevice({
        dev,
        aid: devAid,
        deviceId: devId.value,
        role,
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }
    for (const dev of auditRecipientsRaw) {
      const target = await this._v2BuildTargetFromDevice({
        dev,
        aid: String(dev.aid ?? ''),
        deviceId: String(dev.device_id ?? ''),
        role: 'audit',
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }
    if (targets.length === 0) {
      throw new E2EEError(`V2 group: no target devices for ${groupId}`);
    }

    const sender = await session.getSenderIdentity();
    const sendTargets = applyV2WrapPolicyToTargets(targets, wrapPolicy);
    const envelope = await encryptGroupMessage(
      sender,
      groupId,
      epoch,
      sendTargets,
      opts.payload,
      { messageId: opts.messageId, timestamp: opts.timestamp, protectedHeaders: opts.protectedHeaders, context: opts.context },
      stateCommitment,
    );
    return envelope;
  }

  private async _publishV2GroupSecurityLevel(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    const level = String(bootstrap.e2ee_security_level ?? '').trim() || 'end_to_end';
    const previous = this._v2GroupSecurityLevels.get(groupId);
    if (previous === level) return;
    this._v2GroupSecurityLevels.set(groupId, level);
    await this._dispatcher.publish('group.v2.security_level', {
      group_id: groupId,
      level,
      warning: String(bootstrap.e2ee_security_warning ?? ''),
      previous_level: previous ?? null,
    });
  }

  /**
   * V2 Group thought.put：多设备 wrap envelope。
   * 与 Python `_put_group_thought_encrypted_v2` 对齐。
   */
  private async _putGroupThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    const groupId = String(params.group_id ?? '').trim();
    const payload = isJsonObject(params.payload) ? params.payload : null;
    if (!groupId) {
      throw new ValidationError('group.thought.put requires group_id');
    }
    if (payload === null) {
      throw new ValidationError('group.thought.put payload must be an object when encrypt=true');
    }
    const thoughtId = String(params.thought_id ?? '') || `gt-${_uuidV4()}`;
    const timestamp = Number(params.timestamp ?? Date.now());

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
      const envelopeContext = (params.context && typeof params.context === 'object' && !Array.isArray(params.context))
        ? params.context as Record<string, unknown> : undefined;
      const envelope = await this._buildV2GroupEnvelope({
        groupId,
        payload,
        messageId: thoughtId,
        timestamp,
        useCache,
        context: envelopeContext,
      });
      const sendParams: RpcParams = {
        group_id: groupId,
        payload: envelope as JsonObject,
        encrypted: true,
        thought_id: thoughtId,
        timestamp,
      };
      if ('context' in params) sendParams.context = params.context;
      await this._signClientOperation('group.thought.put', sendParams);
      return this._transport.call('group.thought.put', sendParams);
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = (exc as any)?.code;
      if (AUNClient.V2_RETRYABLE_CODES.has(excCode)) {
        this._clientLog.debug(`V2 group thought put speculative rejected (code=${excCode}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(`group:${groupId}`);
        return attempt(false);
      }
      throw exc;
    }
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
    const session = this._v2Session;
    if (!session || !opts.envelope) return null;

    // 找到本设备所引用的 spk_id 和 key_source：根据 envelope.recipients 中 [aid, device_id, ..., spk_id]
    let spkId = '';
    let recipientKeySource = '';
    const recipients = opts.envelope.recipients;
    if (Array.isArray(recipients)) {
      for (const row of recipients) {
        if (Array.isArray(row) && row.length >= 6) {
          if (row[0] === this._aid && (row[1] === this._deviceId || row[1] === '')) {
            spkId = String(row[5] ?? '');
            recipientKeySource = row.length > 3 ? String(row[3] ?? '') : '';
            break;
          }
        }
      }
    }

    const aad = (opts.envelope.aad as Record<string, unknown> | undefined) ?? {};
    const groupIdForKeys = String(aad.group_id ?? opts.envelope.group_id ?? '').trim();
    let ikPriv: Uint8Array;
    let spkPriv: Uint8Array | undefined;
    // group_id 只表示群上下文；group lookup 内部按 group SPK -> P2P device SPK -> IK fallback。
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
      this._clientLog.warn(`V2 thought decrypt: SPK lookup failed from=${opts.fromAid}, group=${groupIdForKeys || '<p2p>'}, spk_id=${spkId || '<empty>'}: ${exc}`);
      return null;
    }

    const fromAid = String(opts.fromAid || aad.from || '').trim();
    const senderDeviceId = String(aad.from_device ?? '');
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId);
    if (!senderPubDer) {
      this._clientLog.warn(`V2 thought decrypt: no sender IK for ${fromAid} device=${senderDeviceId}`);
      this._scheduleV2SenderIKFetch(fromAid, senderDeviceId, groupIdForKeys);
      return null;
    }

    try {
      const plaintext = await decryptMessage(
        opts.envelope,
        this._aid ?? '',
        this._deviceId,
        ikPriv,
        spkPriv,
        senderPubDer,
      );
      // 消费触发 SPK 轮换（与 _decryptV2Message 对齐）
      if (plaintext != null) {
        if (groupIdForKeys && recipientKeySource === 'group_device_prekey' && session.isLastUploadedGroupSPK(groupIdForKeys, spkId)) {
          const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
          session.rotateGroupSPK(groupIdForKeys, callFn).catch(exc => {
            this._clientLog.debug(`V2 thought group SPK rotation failed (non-fatal): group=${groupIdForKeys} err=${exc}`);
          });
        } else if (groupIdForKeys && recipientKeySource === 'peer_device_prekey') {
          const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
          session.ensureGroupRegistered(groupIdForKeys, callFn).catch(exc => {
            this._clientLog.debug(`V2 thought group SPK registration after peer fallback failed (non-fatal): group=${groupIdForKeys} err=${exc}`);
          });
        }
      }
      return plaintext;
    } catch (exc) {
      this._clientLog.warn(`V2 thought decrypt failed from=${fromAid}: ${String(exc)}`);
      return null;
    }
  }

  // ── V2 State 验签 / Fork 检测 / Auto-propose（Phase 3b.3 + 3b.4）──────

  /**
   * 验证 owner/admin 对 state 的 ECDSA 签名（防服务端篡改 bootstrap 字段）。
   * 与 Python SDK 对齐：证书获取或验签失败时拒绝信任 bootstrap。
   */
  private async _v2VerifyStateSignature(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    if (!bootstrap) return;
    const stateSignature = String(bootstrap.state_signature ?? '');
    const actorAid = String(bootstrap.state_actor_aid ?? '');
    const stateHashSigned = String(bootstrap.state_hash_signed ?? '');
    const membershipSnapshot = String(bootstrap.state_membership_snapshot ?? '');
    const stateVersion = Number(bootstrap.state_version ?? 0) || 0;
    if (stateVersion === 0 || !stateSignature || !actorAid) return;

    try {
      // 重构签名 payload（与服务端 propose_state 中的格式一致）
      const signPayloadObj = {
        group_id: groupId,
        membership_snapshot: membershipSnapshot,
        state_hash: stateHashSigned,
        state_version: stateVersion,
      };
      const signPayload = stableStringify(signPayloadObj);
      const signPayloadBytes = new TextEncoder().encode(signPayload);
      const sigBytes = base64ToUint8(stateSignature);

      // 验签缓存检查
      const cacheData = _v2LengthPrefixedBytes(
        new TextEncoder().encode(actorAid),
        signPayloadBytes,
        sigBytes,
      );
      const cacheHashBuf = await crypto.subtle.digest('SHA-256', cacheData.slice().buffer);
      const cacheHashArr = new Uint8Array(cacheHashBuf);
      let cacheKey = '';
      for (let i = 0; i < cacheHashArr.length; i++) cacheKey += cacheHashArr[i].toString(16).padStart(2, '0');

      const now = Date.now();
      const cachedExp = this._v2SigCache.get(cacheKey);
      if (cachedExp !== undefined && cachedExp > now) {
        this._clientLog.debug(`V2 state signature cache hit: group=${groupId} sv=${stateVersion}`);
      } else {
        // 获取 actor 证书（通过 HTTP PKI 端点，不走 ca.get_cert RPC）
        const certPem = await this._fetchPeerCert(actorAid);
        if (!certPem) {
          this._clientLog.warn(`V2 state verify: no cert for actor=${actorAid}, group=${groupId}`);
          throw new E2EEError(`V2 state verify: cannot fetch actor cert for ${actorAid}`);
        }

        const pubKey = await importCertPublicKeyEcdsa(certPem);
        const ok = await ecdsaVerifyDer(pubKey, sigBytes, signPayloadBytes);
        if (!ok) {
          this._clientLog.warn(`V2 state signature verification FAILED: group=${groupId} sv=${stateVersion} actor=${actorAid}`);
          throw new E2EEError('V2 state signature verification failed');
        }

        // 写入缓存
        this._v2SigCache.set(cacheKey, now + AUNClient._V2_SIG_CACHE_TTL);
        if (this._v2SigCache.size > AUNClient._V2_SIG_CACHE_MAX) {
          const stale: string[] = [];
          for (const [k, exp] of this._v2SigCache) {
            if (exp <= now) stale.push(k);
          }
          for (const k of stale) this._v2SigCache.delete(k);
          if (this._v2SigCache.size > AUNClient._V2_SIG_CACHE_MAX) {
            // 淘汰最旧的 1/4
            const entries = [...this._v2SigCache.entries()].sort((a, b) => a[1] - b[1]);
            const evictCount = Math.floor(AUNClient._V2_SIG_CACHE_MAX / 4);
            for (let i = 0; i < evictCount && i < entries.length; i++) {
              this._v2SigCache.delete(entries[i][0]);
            }
          }
        }
        this._clientLog.debug(`V2 state signature verified: group=${groupId} sv=${stateVersion} actor=${actorAid}`);
      }

      // 验证 member_aids 在签名快照中（best-effort）
      try {
        if (membershipSnapshot.startsWith('[')) {
          const signedSnapshot: string[] = JSON.parse(membershipSnapshot);
          const serverMembers = new Set(
            Array.isArray(bootstrap.member_aids) ? (bootstrap.member_aids as string[]) : [],
          );
          const signedMembers = new Set(signedSnapshot);
          const extra: string[] = [];
          for (const m of serverMembers) {
            if (!signedMembers.has(m)) extra.push(m);
          }
          if (extra.length > 0) {
            let mode = '';
            try {
              const reqResp = await this.call('group.get_join_requirements', { group_id: groupId }) as Record<string, unknown> | null;
              mode = isJsonObject(reqResp as JsonValue | object | null | undefined)
                ? String((reqResp as JsonObject).mode ?? '').trim()
                : '';
            } catch {
              mode = '';
            }
            if (mode !== 'open' && mode !== 'invite_code' && mode !== 'invite_only') {
              this._clientLog.warn(`V2 state tamper detected: group=${groupId} pending_extra=${extra.sort().join(',')} mode=${mode}`);
              await this._dispatcher.publish('group.v2.state_tampered', {
                group_id: groupId,
                pending_extra: extra.sort(),
                mode,
              });
            }
          }
        }
      } catch {
        // snapshot 解析失败不阻断
      }
    } catch (exc) {
      if (exc instanceof E2EEError) throw exc;
      this._clientLog.warn(`V2 state signature verification failed: group=${groupId} err=${formatCaughtError(exc)}`);
      throw new E2EEError(`V2 state signature verification failed: ${String(formatCaughtError(exc))}`);
    }
  }

  /**
   * 分叉检测：比对服务端 state_chain 与本地存储。
   */
  private async _v2CheckFork(groupId: string, serverChain: string): Promise<void> {
    if (!serverChain) return;
    try {
      const local = this._v2StateChains.get(groupId);
      if (local === undefined) {
        this._v2StateChains.set(groupId, [0, serverChain]);
        return;
      }
      const [localSv, localChain] = local;
      if (localChain === serverChain) return;

      // 不一致：尝试通过 get_state 判断是正常推进还是分叉
      try {
        const stateResp = await this.call('group.get_state', { group_id: groupId }) as Record<string, unknown> | null;
        if (stateResp) {
          const serverSv = Number(stateResp.state_version ?? 0);
          if (serverSv > localSv) {
            // 正常推进
            this._v2StateChains.set(groupId, [serverSv, serverChain]);
            return;
          }
          if (serverSv < localSv) {
            this._clientLog.warn(`V2 state chain rollback detected: group=${groupId} server_sv=${serverSv} local_sv=${localSv}`);
          }
        }
      } catch {
        // get_state 失败不阻断
      }

      // 告警：分叉
      this._clientLog.warn(`V2 state chain fork detected: group=${groupId} local_chain=${localChain.slice(0, 16)}... server_chain=${serverChain.slice(0, 16)}...`);
      this._dispatcher.publish('group.v2.fork_detected', {
        group_id: groupId,
        local_chain: localChain,
        server_chain: serverChain,
      });
    } catch (exc) {
      this._clientLog.debug(`V2 fork check failed (non-fatal): ${exc}`);
    }
  }

  private _v2MaybeTriggerAutoPropose(groupId: string): void {
    const now = Date.now();
    const last = this._v2LazyProposeTriggered.get(groupId) ?? 0;
    if (now - last < 10000) return;
    this._v2LazyProposeTriggered.set(groupId, now);
    this._safeAsync(this._v2AutoProposeState(groupId, { leaderDelay: true }));
  }

  /**
   * 成员变更后自动 propose state（仅 owner/admin 执行）。
   */
  private async _v2AutoProposeState(groupId: string, options?: { leaderDelay?: boolean }): Promise<void> {
    const normalizedGroupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!normalizedGroupId) return;
    if (options?.leaderDelay) {
      const shouldContinue = await this._v2AutoProposeLeaderDelay(normalizedGroupId);
      if (!shouldContinue) return;
    }
    const inflight = this._v2AutoProposeInflight.get(normalizedGroupId);
    if (inflight) {
      this._v2AutoProposePending.add(normalizedGroupId);
      await inflight;
      return;
    }

    let resolveTask!: () => void;
    let rejectTask!: (error: unknown) => void;
    const task = new Promise<void>((resolve, reject) => {
      resolveTask = resolve;
      rejectTask = reject;
    });
    this._v2AutoProposeInflight.set(normalizedGroupId, task);
    void (async () => {
      try {
        do {
          this._v2AutoProposePending.delete(normalizedGroupId);
          await this._doV2AutoProposeState(normalizedGroupId);
        } while (this._v2AutoProposePending.delete(normalizedGroupId));
        resolveTask();
      } catch (exc) {
        rejectTask(exc);
      } finally {
        if (this._v2AutoProposeInflight.get(normalizedGroupId) === task) {
          this._v2AutoProposeInflight.delete(normalizedGroupId);
        }
        this._v2AutoProposePending.delete(normalizedGroupId);
      }
    })();
    try {
      await task;
    } finally {
      if (this._v2AutoProposeInflight.get(normalizedGroupId) === task) {
        this._v2AutoProposeInflight.delete(normalizedGroupId);
      }
      this._v2AutoProposePending.delete(normalizedGroupId);
    }
  }

  private async _v2LeaderDelayMs(input: string): Promise<number> {
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)),
    );
    const first32 = new DataView(digest.buffer, digest.byteOffset, digest.byteLength)
      .getUint32(0, false);
    return 2000 + (first32 % 4000);
  }

  private async _v2AutoProposeLeaderDelay(groupId: string): Promise<boolean> {
    try {
      const membersResp = await this.call('group.get_online_members', { group_id: groupId }) as Record<string, unknown>;
      const members = (Array.isArray(membersResp?.members) ? membersResp.members
        : Array.isArray(membersResp?.items) ? membersResp.items
          : Array.isArray(membersResp?.online_members) ? membersResp.online_members : []) as Array<Record<string, unknown>>;
      const myAid = this._aid ?? '';
      let myRole = '';
      const onlineAdminAids = new Set<string>();
      for (const member of members) {
        const aid = String(member.aid ?? '').trim();
        const role = String(member.role ?? '').trim();
        if (!aid) continue;
        if ('online' in member && !Boolean(member.online)) continue;
        if (role === 'owner' || role === 'admin') onlineAdminAids.add(aid);
        if (aid === myAid) myRole = role;
      }
      if (myRole !== 'owner' && myRole !== 'admin') return false;

      const bootstrapResp = await this.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      const devices = (Array.isArray(bootstrapResp?.devices) ? bootstrapResp.devices : []) as Array<Record<string, unknown>>;
      const candidates: string[] = [];
      for (const dev of devices) {
        const aid = String(dev.aid ?? '').trim();
        const hasDeviceId = 'device_id' in dev;
        const deviceId = String(dev.device_id ?? '').trim();
        if (aid && hasDeviceId && onlineAdminAids.has(aid)) {
          candidates.push(`${aid}\x1f${deviceId}`);
        }
      }
      if (candidates.length === 0) {
        for (const aid of [...onlineAdminAids].sort()) candidates.push(`${aid}\x1f`);
      }
      const myKey = `${myAid}\x1f${this._deviceId ?? ''}`;
      if (!candidates.includes(myKey)) candidates.push(myKey);
      const leader = [...new Set(candidates)].sort()[0];
      if (leader === myKey) {
        this._clientLog.debug(`V2 auto propose leader elected: group=${groupId} leader=${leader}`);
        return true;
      }

      const delayMs = await this._v2LeaderDelayMs(_v2LengthPrefixedTextKey(groupId, myKey));
      this._clientLog.debug(`V2 auto propose non-leader delay: group=${groupId} leader=${leader} self=${myKey} delay_ms=${delayMs}`);
      await this._sleep(delayMs);
      return true;
    } catch (exc) {
      this._clientLog.debug(`V2 auto propose leader check failed, fallback immediate: group=${groupId} err=${formatCaughtError(exc)}`);
      return true;
    }
  }

  private async _v2VerifyCommittedStateBase(groupId: string, stateResp: JsonObject): Promise<boolean> {
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    if (currentSv <= 0) return true;
    const currentSh = String(stateResp.state_hash ?? '').trim();
    const membershipSnapshot = String(stateResp.membership_snapshot ?? '').trim();
    if (!currentSh || !membershipSnapshot) {
      this._clientLog.warn(`V2 committed state base incomplete: group=${groupId} sv=${currentSv}`);
      return false;
    }
    try {
      const parsed = JSON.parse(membershipSnapshot) as unknown;
      if (!isJsonObject(parsed)) {
        this._clientLog.warn(`V2 committed state base snapshot is not object: group=${groupId} sv=${currentSv}`);
        return false;
      }
      const computed = await computeStateCommitment(groupId, currentSv, parsed);
      if (computed !== currentSh) {
        this._clientLog.warn(`V2 committed state base hash mismatch: group=${groupId} sv=${currentSv}`);
        return false;
      }
      return true;
    } catch (exc) {
      this._clientLog.warn(`V2 committed state base verification failed: group=${groupId} sv=${currentSv} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  private async _doV2AutoProposeState(groupId: string): Promise<void> {
    try {
      // 获取当前成员列表 + 角色
      const membersResp = await this.call('group.get_members', { group_id: groupId }) as Record<string, unknown>;
      const members = (Array.isArray(membersResp?.members) ? membersResp.members
        : Array.isArray(membersResp?.items) ? membersResp.items : []) as Array<Record<string, unknown>>;
      const myAid = this._aid ?? '';
      let myRole = '';
      const memberAids: string[] = [];
      const adminAids: string[] = [];
      for (const m of members) {
        const aid = String(m.aid ?? '').trim();
        const role = String(m.role ?? '').trim();
        if (aid) {
          memberAids.push(aid);
          if (role === 'owner' || role === 'admin') adminAids.push(aid);
        }
        if (aid === myAid) myRole = role;
      }

      if (myRole !== 'owner' && myRole !== 'admin') return;

      // 前置检查：如果已有 pending proposal，先尝试 confirm 而非重复 propose
      const proposalResp = await this.call('group.v2.get_proposal', { group_id: groupId }) as Record<string, unknown> | null;
      if (proposalResp && typeof proposalResp === 'object') {
        const pendingProposal = proposalResp.proposal as Record<string, unknown> | null;
        if (pendingProposal && typeof pendingProposal === 'object' && String(pendingProposal.proposal_id ?? '').trim()) {
          const confirmed = await this._v2ConfirmPendingProposal(groupId);
          if (confirmed) return;
          const autoConfirmAt = Number(pendingProposal.auto_confirm_at ?? 0) || 0;
          const nowMs = Date.now();
          if (autoConfirmAt > nowMs) {
            const waitMs = Math.min(autoConfirmAt - nowMs + 500, 35000);
            this._clientLog.debug(`V2 auto propose: pending proposal exists, waiting ${waitMs}ms group=${groupId}`);
            await new Promise((r) => setTimeout(r, waitMs));
          }
        }
      }

      // 获取群所有成员的设备列表（V2 bootstrap）
      const bootstrapResp = await this.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      const allDevices = (Array.isArray(bootstrapResp?.devices) ? bootstrapResp.devices : []) as Array<Record<string, unknown>>;
      const auditRecipients = (Array.isArray(bootstrapResp?.audit_recipients) ? bootstrapResp.audit_recipients : []) as Array<Record<string, unknown>>;
      const auditAidsList = [...new Set(
        auditRecipients.map(r => String(r.aid ?? '').trim()).filter(Boolean),
      )].sort();

      // 按 aid 分组设备
      const membersWithDevices: Record<string, Array<{ device_id: string; ik_fp: string }>> = {};
      for (const aid of memberAids) membersWithDevices[aid] = [];
      for (const dev of allDevices) {
        const devAid = String(dev.aid ?? '').trim();
        if (devAid in membersWithDevices) {
          membersWithDevices[devAid].push({
            device_id: String(dev.device_id ?? ''),
            ik_fp: String(dev.ik_fp ?? ''),
          });
        }
      }

      const membersPayload = Object.entries(membersWithDevices).map(([aid, devices]) => ({
        aid,
        devices,
      }));

      const statePayload: Record<string, unknown> = {
        members: membersPayload,
        audit_aids: auditAidsList,
        admin_set: { admin_aids: adminAids.sort(), threshold: 1 },
        join_policy_hash: null,
        recovery_quorum: null,
        history_policy: 'recent_7_days',
        wrap_protocol: '3DH',
      };

      // 获取当前 state
      const stateResp = await this.call('group.get_state', { group_id: groupId }) as Record<string, unknown> | null;
      if (!stateResp) return;
      if (!isJsonObject(stateResp)) return;
      if (!(await this._v2VerifyCommittedStateBase(groupId, stateResp))) return;
      const currentSv = Number(stateResp.state_version ?? 0);
      const currentSh = String(stateResp.state_hash ?? '');
      const keyEpoch = Number(stateResp.key_epoch ?? 0);

      // 用完整 commitment 算 state_hash
      const stateHash = await computeStateCommitment(groupId, currentSv + 1, statePayload);

      // 签名 state proposal
      const membershipSnapshot = stableStringify(statePayload);
      const lastMembershipSnapshot = this._v2AutoProposeLastSnapshot.get(groupId);
      if (lastMembershipSnapshot === membershipSnapshot) {
        return;
      }
      const currentMembershipSnapshot = String(stateResp.membership_snapshot ?? '');
      if (currentMembershipSnapshot && currentMembershipSnapshot === membershipSnapshot) {
        this._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
        return;
      }
      let signature = '';
      const currentAid = this._currentAid;
      if (currentAid?.privateKeyPem) {
        try {
          const signPayloadObj = {
            group_id: groupId,
            membership_snapshot: membershipSnapshot,
            state_hash: stateHash,
            state_version: currentSv + 1,
          };
          const signPayload = stableStringify(signPayloadObj);
          const signPayloadBytes = new TextEncoder().encode(signPayload);
          const privKey = await importPrivateKeyEcdsa(currentAid.privateKeyPem);
          const sigBytes = await ecdsaSignDer(privKey, signPayloadBytes);
          signature = uint8ToBase64(sigBytes);
        } catch (sigExc) {
          this._clientLog.debug(`propose_state signature failed: ${sigExc}`);
        }
      }

      const proposeResult = await this.call('group.v2.propose_state', {
        group_id: groupId,
        state_version: currentSv + 1,
        key_epoch: keyEpoch,
        state_hash: stateHash,
        prev_state_hash: currentSh,
        membership_snapshot: membershipSnapshot,
        signature,
        reason: 'membership_changed',
        auto_confirm_seconds: 30,
      });
      this._clientLog.debug(`V2 auto propose_state: group=${groupId} sv=${currentSv + 1}`);
      const proposalId = isJsonObject(proposeResult) ? String(proposeResult.proposal_id ?? '').trim() : '';
      if (proposalId) {
        try {
          await this.call('group.v2.confirm_state', { proposal_id: proposalId });
          this._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
          this._clientLog.debug(`V2 auto confirm_state: group=${groupId} proposal=${proposalId}`);
        } catch (confirmExc) {
          this._clientLog.debug(`V2 auto confirm_state failed (non-fatal): group=${groupId} err=${confirmExc}`);
        }
      }
    } catch (exc) {
      this._clientLog.debug(`V2 auto propose_state failed (non-fatal): group=${groupId} err=${exc}`);
    }
  }

  private async _v2VerifyPendingProposalAgainstBase(groupId: string, proposal: JsonObject, stateResp: JsonObject): Promise<boolean> {
    if (!(await this._v2VerifyCommittedStateBase(groupId, stateResp))) return false;
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    const currentSh = String(stateResp.state_hash ?? '').trim();
    const proposalSv = Number(proposal.state_version ?? 0) || 0;
    const proposalHash = String(proposal.state_hash ?? '').trim();
    const proposalPrev = String(proposal.prev_state_hash ?? '').trim();
    const membershipSnapshot = String(proposal.membership_snapshot ?? '').trim();
    if (proposalSv !== currentSv + 1 || proposalPrev !== currentSh || !proposalHash || !membershipSnapshot) {
      this._clientLog.warn(`V2 pending proposal base mismatch: group=${groupId} current_sv=${currentSv} proposal_sv=${proposalSv}`);
      return false;
    }
    try {
      const parsed = JSON.parse(membershipSnapshot) as unknown;
      if (!isJsonObject(parsed)) return false;
      const computed = await computeStateCommitment(groupId, proposalSv, parsed);
      if (computed !== proposalHash) {
        this._clientLog.warn(`V2 pending proposal hash mismatch: group=${groupId} proposal_sv=${proposalSv}`);
        return false;
      }
      return true;
    } catch (exc) {
      this._clientLog.warn(`V2 pending proposal verification failed: group=${groupId} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  private async _v2ConfirmPendingProposal(groupId: string): Promise<boolean> {
    const proposalResp = await this.call('group.v2.get_proposal', { group_id: groupId }) as Record<string, unknown>;
    const proposal = isJsonObject(proposalResp?.proposal) ? proposalResp.proposal : null;
    const proposalId = proposal ? String(proposal.proposal_id ?? '').trim() : '';
    if (!proposal || !proposalId) return false;

    const stateResp = await this.call('group.get_state', { group_id: groupId }) as Record<string, unknown>;
    if (!isJsonObject(stateResp)) return false;
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    const proposalSv = Number(proposal.state_version ?? 0) || 0;
    if (proposalSv <= currentSv) {
      this._clientLog.debug(`V2 pending proposal already settled: group=${groupId} current_sv=${currentSv} proposal_sv=${proposalSv}`);
      return false;
    }
    if (!(await this._v2VerifyPendingProposalAgainstBase(groupId, proposal, stateResp))) return false;

    await this.call('group.v2.confirm_state', { proposal_id: proposalId });
    this._clientLog.info(`V2 confirmed pending proposal: group=${groupId} proposal=${proposalId}`);
    return true;
  }

  /**
   * Owner 上线时自动检查并签名确认 pending state proposals。
   */
  private async _v2AutoConfirmPendingProposals(): Promise<void> {
    try {
      const myAid = this._aid ?? '';
      if (!myAid) return;
      const groupsResp = await this.call('group.list_my', {}) as Record<string, unknown>;
      const groups = (Array.isArray(groupsResp?.groups) ? groupsResp.groups
        : Array.isArray(groupsResp?.items) ? groupsResp.items : []) as Array<Record<string, unknown>>;
      for (const g of groups) {
        const gid = String(g.group_id ?? '').trim();
        const myRole = String(g.role ?? g.my_role ?? '').trim();
        if (!gid || (myRole !== 'owner' && myRole !== 'admin')) continue;
        try {
          const confirmed = await this._v2ConfirmPendingProposal(gid);
          if (!confirmed) {
            await this._v2AutoProposeState(gid);
          }
        } catch (exc) {
          this._clientLog.debug(`V2 auto confirm/propose failed (non-fatal): group=${gid} err=${exc}`);
        }
      }
    } catch (exc) {
      this._clientLog.debug(`V2 auto confirm pending proposals failed (non-fatal): ${exc}`);
    }
  }

  private async _onV2StateProposed(data: EventPayload): Promise<void> {
    if (!isJsonObject(data) || !this._v2Session) return;
    const groupId = String(data.group_id ?? '').trim();
    if (!groupId) return;
    await this._dispatcher.publish('group.v2.state_proposed', data);
    try {
      await this._v2ConfirmPendingProposal(groupId);
    } catch (exc) {
      this._clientLog.debug(`V2 state_proposed handling failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  private async _onV2StateRetryNeeded(data: EventPayload): Promise<void> {
    if (!isJsonObject(data) || !this._v2Session) return;
    const groupId = String(data.group_id ?? '').trim();
    if (!groupId) return;
    await this._dispatcher.publish('group.v2.state_retry_needed', data);
    try {
      await this._v2AutoProposeState(groupId, { leaderDelay: true });
    } catch (exc) {
      this._clientLog.debug(`V2 state_retry_needed handling failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  private async _onV2StateConfirmed(data: EventPayload): Promise<void> {
    if (!isJsonObject(data)) return;
    const groupId = String(data.group_id ?? '').trim();
    if (groupId) {
      this._v2BootstrapCache.delete(`group:${groupId}`);
      this._v2AutoProposeLastSnapshot.delete(groupId);
    }
    await this._dispatcher.publish('group.v2.state_confirmed', data);
  }

  /**
   * 处理 V2 push 通知：自动 pull + decrypt + emit。
   */
  private _v2PullInflight = false;
  private _v2PullPending = false;

  private async _onV2PushNotification(data: EventPayload): Promise<void> {
    if (!this._v2Session) return;

    // 提取 push 通知中的元数据
    const pushSeq = isJsonObject(data) ? Number(data.seq ?? 0) || 0 : 0;
    const pushFrom = isJsonObject(data) ? String(data.from_aid ?? '') : '';
    const pushMsgId = isJsonObject(data) ? String(data.message_id ?? '') : '';
    const envelopeJson = isJsonObject(data) ? data.envelope_json : undefined;
    const hasPayload = !!envelopeJson;

    const ns = this._aid ? `p2p:${this._aid}` : '';
    let contigBefore = ns ? this._seqTracker.getContiguousSeq(ns) : 0;

    this._clientLog.debug(
      `_onV2PushNotification: push_seq=${pushSeq || 'null'} push_from=${pushFrom} push_msg_id=${pushMsgId} has_payload=${hasPayload} contiguous_seq=${contigBefore}`
    );

    // ── Push 修上界：只更新 maxSeenSeq，不动 contiguousSeq ──
    if (pushSeq > 0 && ns) {
      this._seqTracker.updateMaxSeen(ns, pushSeq);
      if (contigBefore === pushSeq) {
        this._clientLog.debug(
          `_onV2PushNotification: push seq=${pushSeq} already covered by contiguous_seq=${contigBefore}, ignore duplicate push`
        );
        return;
      }
      contigBefore = this._repairPushContiguousBound(
        ns,
        pushSeq,
        hasPayload,
        '_raw.peer.v2.message_received',
      );
    }

    // ── 带 payload 的 push：尝试就地解密 ──
    if (hasPayload && pushSeq > 0 && ns) {
      try {
        const decrypted = await this._decryptV2Message(data as Record<string, unknown>);
        if (decrypted) {
          // 解密成功：把 pushSeq 加入 receivedSeqs，让 _tryAdvance 自然推进
          const needPull = this._seqTracker.onMessageSeq(ns, pushSeq);
          const published = await this._publishOrderedMessage('message.received', ns, pushSeq, decrypted as EventPayload);
          const newContig = this._seqTracker.getContiguousSeq(ns);
          if (newContig !== contigBefore) {
            this._saveSeqTrackerState();
          }
          if (newContig > 0 && newContig !== contigBefore) {
            const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
            const ackSeq = maxSeen > 0 ? Math.min(newContig, maxSeen) : newContig;
            this._callRawV2Rpc('message.v2.ack', { up_to_seq: ackSeq })
              .catch(e => this._clientLog.debug(`V2 P2P push-ack failed: ${e}`));
          }
          this._clientLog.debug(
            `_onV2PushNotification: push 带 payload 解密成功, contiguous_seq=${contigBefore}->${newContig} push_seq=${pushSeq}`
          );
          if (!needPull && (published || newContig >= pushSeq || pushSeq <= contigBefore)) {
            return;
          }
          this._clientLog.debug(
            `_onV2PushNotification: payload push seq=${pushSeq} 因空洞挂起，继续 pull 补齐 after_seq=${newContig}`
          );
        }
      } catch (exc) {
        this._clientLog.debug(`_onV2PushNotification: push payload 解密失败, fallback to pull: ${exc}`);
      }
    }

    // ── 不带 payload 或解密失败：触发 pull ──
    // 关键：push 通知只表示"服务端有 seq=pushSeq 的新消息"，
    // 此时消息内容尚未到达本地，绝不能调用 onMessageSeq() 推进 contiguousSeq
    // （那会让随后的 pull 用 after_seq=pushSeq，跳过这条消息本身导致拉空）。
    // 正确做法：保持 contiguousSeq 不变，用它作为 pull 的 after_seq；
    // pull 成功 + 解密成功后再由 pull 路径推进 contiguousSeq。
    if (pushSeq > 0 && ns) {
      // 纯通知：不更新 contiguousSeq，由 pull 结果驱动推进
      this._clientLog.debug(
        `_onV2PushNotification: 纯通知 push_seq=${pushSeq} > contiguous_seq=${contigBefore}, 触发 pull(after_seq=${contigBefore})`
      );
    }

    // only one in flight + drain pending
    if (this._v2PullInflight) {
      this._v2PullPending = true;
      return;
    }
    this._v2PullInflight = true;
    const dedupKey = `p2p_pull:${ns}`;
    this._gapFillDone.add(dedupKey);
    try {
      do {
        this._v2PullPending = false;
        await this._pullV2();
        const newContig = ns ? this._seqTracker.getContiguousSeq(ns) : -1;
        this._clientLog.debug(
          `_onV2PushNotification pull done: contiguous_seq=${contigBefore}->${newContig} (push_seq=${pushSeq || 'null'})`
        );
      } while (this._v2PullPending);
    } catch (exc) {
      const newContig = ns ? this._seqTracker.getContiguousSeq(ns) : -1;
      this._clientLog.warn(
        `V2 push auto-pull failed: contiguous_seq=${contigBefore}->${newContig} err=${exc}`
      );
    } finally {
      this._v2PullInflight = false;
      this._gapFillDone.delete(dedupKey);
    }
  }

  /**
   * 处理 V2 epoch 轮换事件：清除 bootstrap 缓存 + 触发 SPK rotation。
   */
  private async _onV2EpochRotated(data: EventPayload): Promise<void> {
    if (!data || typeof data !== 'object') return;
    const groupId = String((data as Record<string, unknown>).group_id ?? '').trim();
    if (!groupId) return;
    const newEpoch = (data as Record<string, unknown>).epoch ?? 0;
    this._clientLog.debug(`_onV2EpochRotated: group=${groupId} epoch=${newEpoch}`);
    // 清除 bootstrap 缓存
    this._v2BootstrapCache.delete(`group:${groupId}`);
    // 触发 SPK rotation
    if (this._v2Session) {
      try {
        const callFn: CallFn = async (method, params) => {
          return this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
        };
        await this._v2Session.rotateSPK(callFn);
        this._clientLog.info(`SPK rotated after epoch change: group=${groupId} epoch=${newEpoch}`);
      } catch (exc) {
        this._clientLog.debug(`SPK rotation after epoch change failed (non-fatal): ${exc}`);
      }
    }
  }

  /** 安全执行异步操作（不阻塞调用方，错误打 warning 便于排障） */
  private _safeAsync(promise: Promise<RpcResult | void>): void {
    promise.catch((exc) => {
      this._clientLog.warn(`background task exception:${String(exc)}`)
    });
  }

  // ── Pull Gate（序列化同一 key 的并发 pull）──────────────────

  private _pullGateKeyForCall(method: string, params: RpcParams): string {
    if (method === 'message.pull' || method === 'message.v2.pull') {
      return this._aid ? `p2p:${this._aid}` : '';
    }
    if (method === 'group.pull' || method === 'group.v2.pull') {
      const gid = String(params.group_id ?? '').trim();
      return gid ? `group:${gid}` : '';
    }
    if (method === 'group.pull_events') {
      const gid = String(params.group_id ?? '').trim();
      return gid ? `group_event:${gid}` : '';
    }
    return '';
  }

  private _tryAcquirePullGate(key: string): number | null {
    if (!key) return 0;
    const now = Date.now();
    const gate = this._pullGates.get(key) ?? { inflight: false, startedAt: 0, token: 0 };
    if (gate.inflight && now - gate.startedAt <= AUNClient._PULL_GATE_STALE_MS) {
      return null;
    }
    if (gate.inflight) {
      this._clientLog.warn(`pull in-flight stale reset: key=${key} age=${now - gate.startedAt}ms`);
    }
    gate.token += 1;
    gate.inflight = true;
    gate.startedAt = now;
    this._pullGates.set(key, gate);
    return gate.token;
  }

  private _releasePullGate(key: string, token: number | null): void {
    if (!key || token == null) return;
    const gate = this._pullGates.get(key);
    if (!gate || gate.token !== token) return;
    gate.inflight = false;
    gate.startedAt = 0;
  }

  private async _runPullSerialized<T>(key: string, operation: () => Promise<T>): Promise<T> {
    let token = this._tryAcquirePullGate(key);
    if (token === null) {
      const deadline = Date.now() + AUNClient._PULL_GATE_STALE_MS + 100;
      while (token === null && Date.now() <= deadline) {
        await this._sleep(25);
        token = this._tryAcquirePullGate(key);
      }
      if (token === null) {
        throw new StateError(`pull already in-flight for ${key}`);
      }
    }
    try {
      return await operation();
    } finally {
      this._releasePullGate(key, token);
    }
  }

  /** 可取消的 sleep */
  private _sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      globalThis.setTimeout(resolve, ms);
    });
  }
}

// ── 内部工具 ────────────────────────────────────────

/** 生成 UUID v4 */
function _uuidV4(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}


